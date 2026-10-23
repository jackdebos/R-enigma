//! Private complete-neighborhood strict ascent with bound scoring and shared accounting.

use crate::attack_blocks::OuterBlock;
use crate::attack_control::{AttackControl, CounterObserver, CounterOverflow};
use crate::attack_evaluator::{
    validated_trial_board, RunPreparation, TrialEvaluationError, TrialEvaluator,
};
#[cfg(test)]
use crate::attack_neighborhood::NeighborhoodCursor;
use crate::attack_neighborhood::NeighborhoodWalker;
use crate::attack_result::AttackRunErrorData;
use crate::{
    AttackPlugboardDomain, BoundResource, Direction, FixedScore, MeasureId, MeasuredScore,
    ResolvedConfiguration,
};
use std::ops::ControlFlow;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

type MutableBoard = Vec<(char, char)>;

/// Owned initial key facts remain separate from the committed mutable remainder.
#[derive(Debug)]
pub(crate) struct DirectOuterOutcome {
    pub(crate) initial: ResolvedConfiguration,
    pub(crate) outer_index: u128,
    pub(crate) start_index: u128,
    pub(crate) climb: ClimbOutcome,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProjectionError {
    MissingCommittedBoard,
    Board(crate::attack_evaluator::TrialBoardError),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCommittedBoard => f.write_str("accepted best has no committed board"),
            Self::Board(source) => source.fmt(f),
        }
    }
}

impl std::error::Error for ProjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Board(source) => Some(source),
            Self::MissingCommittedBoard => None,
        }
    }
}

impl DirectOuterOutcome {
    fn project(
        self,
        domain: &AttackPlugboardDomain,
        measure: MeasureId,
    ) -> Result<crate::AttackBest, ProjectionError> {
        let current = self
            .climb
            .current
            .ok_or(ProjectionError::MissingCommittedBoard)?;
        let complete = validated_trial_board(&self.initial, domain, &current.board)
            .map_err(ProjectionError::Board)?;
        let alphabet = complete.alphabet();
        let mut mutable_plugboard = current.board;
        for (left, right) in &mut mutable_plugboard {
            if alphabet.index_of(*left) > alphabet.index_of(*right) {
                std::mem::swap(left, right);
            }
        }
        mutable_plugboard.sort_by_key(|&(a, b)| (alphabet.index_of(a), alphabet.index_of(b)));
        let mut pairs = Vec::new();
        for &left in &alphabet.symbols {
            let right = complete.map(left).expect("validated alphabet mapping");
            if alphabet.index_of(left) < alphabet.index_of(right) {
                pairs.push((left, right));
            }
        }
        let slots = self
            .initial
            .topology()
            .slots()
            .iter()
            .map(|slot| {
                crate::SlotConfiguration::new(slot.id(), slot.wheel(), slot.position(), slot.ring())
            })
            .collect();
        Ok(crate::AttackBest {
            configuration: crate::TransformConfiguration::new(slots, pairs),
            mutable_plugboard,
            plaintext: current.plaintext,
            score: current.score,
            measure,
            outer_index: self.outer_index,
            start_index: self.start_index,
            incomplete: self.climb.cancelled || self.climb.incomplete,
            final_objective_ascent: self.climb.final_objective_ascent,
            neighborhood_exhausted: self.climb.neighborhood_exhausted,
            stages: Vec::new(),
        })
    }
}

/// Capacity one deliberately keeps raw selection and terminal projection timing.
struct DirectAcceptance(Option<crate::attack_hold::AttackHold>);

impl DirectAcceptance {
    fn new(capacity: usize) -> Self {
        Self((capacity > 1).then(|| crate::attack_hold::AttackHold::new(capacity)))
    }

    fn accept(
        &mut self,
        outcome: DirectOuterOutcome,
        domain: &AttackPlugboardDomain,
        measure: MeasureId,
    ) -> Result<Option<DirectOuterOutcome>, ProjectionError> {
        match &mut self.0 {
            None => Ok(Some(outcome)),
            Some(hold) => {
                // N > 1 validates every eligible offer, including eventual losers.
                hold.offer(outcome.project(domain, measure)?);
                Ok(None)
            }
        }
    }

    #[cfg(test)]
    fn finish(
        self,
        run: Result<DirectRunOutcome, Box<ControlledDirectError>>,
        counters: crate::attack_control::CounterSnapshot,
        domain: &AttackPlugboardDomain,
        measure: MeasureId,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        let result = match run {
            Ok(outcome) => outcome.project_public(counters, domain, measure),
            Err(error) => Err(error.project(domain, measure)),
        };
        attach_held(result, self.0)
    }
}

/// Without a hold (capacity one) the raw projection stands; otherwise the ranked
/// head replaces the success best (or a present error best) and the tail moves.
fn attach_held(
    result: Result<crate::AttackResult, crate::AttackRunError>,
    hold: Option<crate::attack_hold::AttackHold>,
) -> Result<crate::AttackResult, crate::AttackRunError> {
    let Some(hold) = hold else { return result };
    let (head, tail) = hold.into_head_tail();
    match result {
        Ok(mut result) => {
            result.best = head;
            result.held_tail = tail;
            Ok(result)
        }
        Err(error) => Err(error.with_held(head, tail)),
    }
}

struct ProgressObserver<F>(F);

impl<F: FnMut(crate::AttackProgress)> CounterObserver for ProgressObserver<F> {
    fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
        (self.0)(crate::AttackProgress(snapshot));
    }
}

/// One lifecycle boundary around all fallible scheduling, projection and stages.
/// Terminal delivery uses the live control even when an inner `?` returns early.
fn observed_run<O: CounterObserver>(
    control: &mut AttackControl,
    observer: &mut O,
    run: impl FnOnce(&mut AttackControl, &mut O) -> Result<crate::AttackResult, crate::AttackRunError>,
) -> Result<crate::AttackResult, crate::AttackRunError> {
    control.notify(observer);
    let result = run(control, observer);
    control.notify(observer);
    result
}

impl crate::AttackRequest {
    /// Run this resource-bound owner with fresh accounting and latched cancellation.
    ///
    /// Observation is synchronous, infallible and counter-only; duplicate snapshots
    /// are allowed. Cancellation is independently polled at safe boundaries, never
    /// mid-evaluation. HC and PE reuse their validated same-owner schedulers.
    pub fn run(
        &self,
        observe: impl FnMut(crate::AttackProgress),
        cancel_requested: impl FnMut() -> bool,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        self.run_with(crate::ExecutionOptions::serial(), observe, cancel_requested)
    }

    /// [`run`](Self::run) under host `options`; the public outcome of a completed run
    /// does not depend on them.
    ///
    /// With more than one thread the outer blocks run on scoped worker threads, each
    /// with its own preparation; `observe` and `cancel_requested` are still called
    /// only on the calling thread, which merges finished blocks in key order. Stages
    /// run afterwards on the calling thread.
    pub fn run_with(
        &self,
        options: crate::ExecutionOptions,
        observe: impl FnMut(crate::AttackProgress),
        cancel_requested: impl FnMut() -> bool,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        self.run_pooled(options, &PoolHooks::default(), observe, cancel_requested)
    }

    fn run_pooled(
        &self,
        options: crate::ExecutionOptions,
        hooks: &PoolHooks,
        observe: impl FnMut(crate::AttackProgress),
        mut cancel_requested: impl FnMut() -> bool,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut control = AttackControl::with_progress_every(self.settings().progress_every());
        let mut observer = ProgressObserver(observe);
        observed_run(&mut control, &mut observer, |control, observer| {
            // The serial outer phase fills this preparation; pool workers own theirs.
            // Stages only reuse it as a cache, so their results do not depend on it.
            let preparation = RunPreparation::new(self);
            let result = self.run_block_phase(
                options,
                hooks,
                &preparation,
                &mut allowance,
                control,
                observer,
                &mut cancel_requested,
            )?;
            let mut result = result;
            let completed = crate::AttackTermination::Completed;
            let staged = !self.settings().stages().is_empty();
            if staged && result.termination == completed && result.best.is_some() {
                let accounting = &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control,
                    observer,
                };
                result = stages_over_hold(result, |result| {
                    self.finalist_stages_prepared(
                        &preparation,
                        result,
                        accounting,
                        &mut cancel_requested,
                    )
                })?;
            }
            Ok(result)
        })
    }

    /// Runs every listed stage on `result.best` alone; unprocessed finalists ride
    /// in `held_tail` only so a stage error still returns them.
    #[cfg(test)]
    fn finalist_stages(
        &self,
        result: crate::AttackResult,
        accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
        cancel_requested: impl FnMut() -> bool,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        self.finalist_stages_prepared(
            &RunPreparation::new(self),
            result,
            accounting,
            cancel_requested,
        )
    }

    fn finalist_stages_prepared(
        &self,
        preparation: &RunPreparation<'_>,
        mut result: crate::AttackResult,
        accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
        mut cancel_requested: impl FnMut() -> bool,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        use crate::attack_result::RunPayload;
        for stage in self.settings().stages() {
            if (accounting.control).poll_cancellation(cancel_requested()) {
                result.termination = crate::AttackTermination::Cancelled;
                break;
            }
            // Bind only fixed facts; mutable pairs belong solely to the trial.
            let best = result.best.as_ref().expect("completed run has best");
            let initial = crate::TransformConfiguration::new(
                best.configuration.slots().to_vec(),
                self.domain().fixed_pairs().to_vec(),
            )
            .resolve(self.definition());
            // Resolution failure surfaces only after the stage's first admission.
            let initial = || {
                (initial.as_ref())
                    .map_err(|_| RunPayload::Invariant("winning slots failed to resolve"))
            };
            let outer_index = best.outer_index;
            let evaluator = |initial, measure| preparation.evaluator(initial, outer_index, measure);
            result = if let crate::space::AttackStage::Reswapping { measure } = *stage {
                // Retain one lazy scorer for this resolved stage/finalist. Construction
                // does no traversal; resolution errors still surface after admission.
                let scorer = initial().ok().map(|initial| evaluator(initial, measure));
                crate::attack_reswapping::reswapping_stage(
                    result,
                    measure,
                    self.definition().alphabet(),
                    self.domain(),
                    accounting,
                    &mut cancel_requested,
                    (
                        |board| {
                            initial()?;
                            scorer
                                .as_ref()
                                .expect("resolved stage scorer")
                                .evaluate_score(board)
                                .map_err(RunPayload::Evaluation)
                        },
                        // Neighbors of a scored, hence resolved and valid, board.
                        |mapping| {
                            initial()?;
                            scorer
                                .as_ref()
                                .expect("resolved stage scorer")
                                .evaluate_score_mapped(mapping)
                                .map_err(RunPayload::Evaluation)
                        },
                        // Only a scored, hence resolved, commit is ever replayed.
                        |board| {
                            let scorer = scorer.as_ref();
                            let scorer =
                                scorer.ok_or(RunPayload::Invariant("missing replay scorer"))?;
                            scorer.replay_plaintext(board).map_err(RunPayload::from)
                        },
                    ),
                )?
            } else {
                let (_, measure, base_measure) = scoring_stage_metadata(*stage);
                scoring_stage(result, *stage, accounting, |best| {
                    let initial = initial()?;
                    let evaluator = |measure| evaluator(initial, measure);
                    let scorer = evaluator(measure);
                    let evaluation = if matches!(stage, crate::space::AttackStage::Trie { .. }) {
                        scorer.evaluate_trie(
                            &best.mutable_plugboard,
                            base_measure.map(evaluator).as_ref(),
                            best.score.ranking(),
                        )
                    } else {
                        scorer.evaluate(&best.mutable_plugboard)
                    };
                    evaluation.map_err(RunPayload::Evaluation)
                })?
            };
            if result.termination != crate::AttackTermination::Completed {
                break;
            }
        }
        Ok(result)
    }
}

/// Stages finalists best-first on one shared allowance; a stop ends every later
/// one. Polished, partial and unpolished entries are then reranked (§10.5).
fn stages_over_hold(
    mut result: crate::AttackResult,
    mut stage: impl FnMut(crate::AttackResult) -> Result<crate::AttackResult, crate::AttackRunError>,
) -> Result<crate::AttackResult, crate::AttackRunError> {
    let completed = crate::AttackTermination::Completed;
    let (mut polished, mut partial, mut unpolished) = (Vec::new(), None, Vec::new());
    loop {
        result = match stage(result) {
            Ok(result) => result,
            Err(error) => return Err(error.with_staged_hold(polished)),
        };
        let mut finalist = result.best.take().expect("staged finalist");
        finalist.stages = std::mem::take(&mut result.stages);
        if result.termination != completed {
            // Any history means a stage started, even if it then stopped.
            if finalist.stages.is_empty() {
                unpolished.push(finalist);
            } else {
                partial = Some(finalist);
            }
            break;
        }
        polished.push(finalist);
        if result.held_tail.is_empty() {
            break;
        }
        result.best = Some(result.held_tail.remove(0));
    }
    unpolished.append(&mut result.held_tail);
    let ranked = crate::attack_hold::rerank_after_stages(polished, partial, unpolished);
    let mut ranked = ranked.into_iter();
    let mut head = ranked.next().expect("rerank keeps the first finalist");
    result.stages = std::mem::take(&mut head.stages);
    result.best = Some(head);
    result.held_tail = ranked.collect();
    Ok(result)
}

fn scoring_stage_metadata(
    stage: crate::space::AttackStage,
) -> (&'static str, MeasureId, Option<MeasureId>) {
    match stage {
        crate::space::AttackStage::Measure { measure } => ("measure", measure, None),
        crate::space::AttackStage::Trie { base_measure } => ("trie", MeasureId::Trie, base_measure),
        _ => unreachable!("reswapping has its own stage"),
    }
}

/// Admission is the start boundary; failures retain the previously committed best.
fn scoring_stage(
    mut result: crate::AttackResult,
    stage: crate::space::AttackStage,
    accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
    evaluate: impl FnOnce(
        &crate::AttackBest,
    ) -> Result<(String, MeasuredScore), crate::attack_result::RunPayload>,
) -> Result<crate::AttackResult, crate::AttackRunError> {
    use crate::attack_result::RunPayload;
    let (pass, measure, base_measure) = scoring_stage_metadata(stage);
    let before = accounting.allowance.used;
    let evaluation = match accounting.admit() {
        Ok(()) => {
            evaluate(result.best.as_ref().expect("completed run has best")).and_then(|value| {
                accounting.complete()?;
                Ok(value)
            })
        }
        Err(error) => Err(RunPayload::from(error)),
    };
    result.evaluations_used = accounting.allowance.used;
    result.counters = crate::AttackProgress(accounting.control.snapshot());
    result.stages.push(crate::AttackStageResult {
        pass,
        measure,
        base_measure,
        score: evaluation.as_ref().ok().map(|(_, score)| *score),
        evaluations_used: accounting.allowance.used - before,
        completed: evaluation.is_ok(),
    });
    match evaluation {
        Ok((plaintext, score)) => {
            let best = result.best.as_mut().expect("completed run has best");
            best.plaintext = plaintext;
            best.score = score;
            best.measure = measure;
            Ok(result)
        }
        Err(source) => Err(crate::AttackRunError::new(AttackRunErrorData {
            outer_index: result.best.as_ref().map(|best| best.outer_index),
            start_index: result.best.as_ref().map(|best| best.start_index),
            source: crate::AttackRunSource(source),
            held_tail: result.held_tail,
            stages: result.stages,
            evaluations_used: result.evaluations_used,
            counters: result.counters,
            best: Ok(result.best),
        })),
    }
}

impl DirectRunOutcome {
    // Bridge a fallible success projection without losing terminal accounting.
    fn project_public(
        self,
        counters: crate::attack_control::CounterSnapshot,
        domain: &AttackPlugboardDomain,
        measure: MeasureId,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        let evaluations_used = self.evaluations_used;
        let indices = self
            .best
            .as_ref()
            .map(|best| (best.outer_index, best.start_index));
        self.project(counters, domain, measure).map_err(|error| {
            crate::AttackRunError::new(AttackRunErrorData {
                held_tail: Vec::new(),
                stages: Vec::new(),
                source: crate::AttackRunSource(crate::attack_result::RunPayload::Invariant(
                    "accepted best projection failed",
                )),
                outer_index: indices.map(|(outer, _)| outer),
                start_index: indices.map(|(_, start)| start),
                evaluations_used,
                counters: crate::AttackProgress(counters),
                best: Err(Box::new(error)),
            })
        })
    }

    fn project(
        self,
        counters: crate::attack_control::CounterSnapshot,
        domain: &AttackPlugboardDomain,
        measure: MeasureId,
    ) -> Result<crate::AttackResult, ProjectionError> {
        use crate::AttackTermination;
        let termination = match self.termination {
            DirectRunTermination::Completed => AttackTermination::Completed,
            DirectRunTermination::OuterSliceEnd => AttackTermination::OuterSliceEnd,
            DirectRunTermination::Cancelled => AttackTermination::Cancelled,
        };
        Ok(crate::AttackResult {
            held_tail: Vec::new(),
            stages: Vec::new(),
            termination,
            counters: crate::AttackProgress(counters),
            evaluations_used: self.evaluations_used,
            best: self
                .best
                .map(|best| best.project(domain, measure))
                .transpose()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectClimbError {
    UnsupportedPass,
    MissingStart,
    Evaluation(TrialEvaluationError),
}

// Legacy direct-adapter diagnostics remain available to regression tests.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct IndexedDirectClimbError {
    pub(crate) outer_index: u128,
    pub(crate) evaluations_used: u64,
    pub(crate) source: DirectClimbError,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectRunTermination {
    OuterSliceEnd,
    Completed,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct DirectRunOutcome {
    pub(crate) termination: DirectRunTermination,
    #[cfg(test)]
    pub(crate) outer_completed: u128,
    #[cfg(test)]
    pub(crate) climbs_started: u128,
    #[cfg(test)]
    pub(crate) climbs_completed: u128,
    pub(crate) evaluations_used: u64,
    /// Owns initial fixed facts and the final-scored committed board with its flags.
    pub(crate) best: Option<DirectOuterOutcome>,
}

#[derive(Debug)]
pub(crate) enum DirectRunError {
    Resolution(Vec<crate::SearchDiagnostic>),
    Climb(DirectClimbError),
    Counter(CounterOverflow),
    #[cfg(test)]
    MissingOuter,
    Projection(ProjectionError),
}

impl From<ObservedClimbError> for DirectRunError {
    fn from(error: ObservedClimbError) -> Self {
        match error {
            ObservedClimbError::Evaluation(source) => {
                Self::Climb(DirectClimbError::Evaluation(source))
            }
            ObservedClimbError::Counter(source) => Self::Counter(source),
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct IndexedDirectRunError {
    /// None only for fail-closed pass rejection before enumeration.
    pub(crate) outer_index: Option<u128>,
    pub(crate) evaluations_used: u64,
    pub(crate) source: DirectRunError,
}

// Legacy partial-path carriers support adapter and scheduler regression tests.
/// Single resolved outer only; seed completion is independent of winner flags.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct PartialOuterOutcome {
    pub(crate) initial: ResolvedConfiguration,
    pub(crate) outer_index: u128,
    pub(crate) seeds: SeedRunOutcome,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PartialClimbError {
    UnsupportedPass,
    Evaluation(TrialEvaluationError),
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct IndexedPartialClimbError {
    pub(crate) outer_index: u128,
    pub(crate) evaluations_used: u64,
    pub(crate) source: PartialClimbError,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PartialRunTermination {
    OuterSliceEnd,
    Completed,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct PartialRunOutcome {
    pub(crate) termination: PartialRunTermination,
    pub(crate) outer_completed: u128,
    pub(crate) climbs_started: u128,
    pub(crate) climbs_completed: u128,
    pub(crate) evaluations_used: u64,
    /// Owns initial fixed facts and the independently final-scored seed winner.
    pub(crate) best: Option<PartialOuterOutcome>,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) enum PartialRunError {
    Resolution(Vec<crate::SearchDiagnostic>),
    Climb(PartialClimbError),
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct IndexedPartialRunError {
    /// None only for pass rejection before enumeration or evaluation.
    pub(crate) outer_index: Option<u128>,
    pub(crate) evaluations_used: u64,
    pub(crate) source: PartialRunError,
}

#[derive(Debug)]
struct ControlledPartialOutcome {
    initial: ResolvedConfiguration,
    outer_index: u128,
    seeds: ControlledSeedOutcome,
    /// Outer-local projected seeds; present only for capacities above one.
    held: Option<crate::attack_hold::AttackHold>,
}

#[derive(Debug, PartialEq, Eq)]
enum ControlledPartialSource {
    UnsupportedPass,
    Climb(ObservedClimbError),
    /// Eager seed projection invariant, distinct from evaluation failures.
    Projection(ProjectionError),
}

#[derive(Debug)]
struct ControlledPartialError {
    outer_index: u128,
    seed_index: Option<u128>,
    source: ControlledPartialSource,
    best: Option<Box<(ResolvedConfiguration, SeedBest)>>,
    /// Earlier eligible seeds of the failing outer; capacities above one only.
    held: Option<Box<crate::attack_hold::AttackHold>>,
}

impl ControlledPartialError {
    fn from_seed(
        outer_index: u128,
        initial: ResolvedConfiguration,
        error: ControlledSeedError,
    ) -> Self {
        Self {
            outer_index,
            seed_index: error.seed_index,
            source: ControlledPartialSource::Climb(error.source),
            best: error.best.map(|best| Box::new((initial, *best))),
            held: None,
        }
    }
}

/// Offers outer-local entries in enumeration order; `offer` keeps earlier duplicates.
fn merge_held(
    global: &mut Option<crate::attack_hold::AttackHold>,
    local: Option<crate::attack_hold::AttackHold>,
) {
    match (global.as_mut(), local) {
        (Some(global), Some(local)) => {
            local
                .into_entries()
                .into_iter()
                .for_each(|e| global.offer(e));
        }
        (_, local) => *global = global.take().or(local),
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum ControlledPartialTermination {
    OuterSliceEnd,
    Completed,
    Cancelled,
}

#[cfg(test)]
#[derive(Debug)]
struct ControlledPartialRun {
    termination: ControlledPartialTermination,
    outer_completed: u128,
    climbs_started: u128,
    climbs_completed: u128,
    evaluations_used: u64,
    best: Option<ControlledPartialOutcome>,
    held: Option<crate::attack_hold::AttackHold>,
}

#[derive(Debug)]
enum ControlledPartialRunSource {
    Resolution(Vec<crate::SearchDiagnostic>),
    Climb(ControlledPartialSource),
    #[cfg(test)]
    MissingOuter,
}

#[derive(Debug)]
struct ControlledPartialRunError {
    outer_index: Option<u128>,
    seed_index: Option<u128>,
    evaluations_used: u64,
    source: ControlledPartialRunSource,
    best: Option<DirectOuterOutcome>,
    counters: crate::attack_control::CounterSnapshot,
    held: Option<crate::attack_hold::AttackHold>,
}

impl SeedBest {
    fn into_direct(self, initial: ResolvedConfiguration, outer_index: u128) -> DirectOuterOutcome {
        DirectOuterOutcome {
            initial,
            outer_index,
            start_index: self.seed_index,
            climb: ClimbOutcome {
                current: Some(self.current),
                incomplete: self.incomplete,
                cancelled: false,
                final_objective_ascent: self.final_objective_ascent,
                neighborhood_exhausted: self.neighborhood_exhausted,
            },
        }
    }
}

impl ControlledPartialOutcome {
    fn into_direct(self) -> DirectOuterOutcome {
        match self.seeds.seeds.best {
            Some(seed) => seed.into_direct(self.initial, self.outer_index),
            None => DirectOuterOutcome {
                initial: self.initial,
                outer_index: self.outer_index,
                start_index: 0,
                climb: ClimbOutcome {
                    current: None,
                    incomplete: false,
                    cancelled: false,
                    final_objective_ascent: false,
                    neighborhood_exhausted: false,
                },
            },
        }
    }
}

#[cfg(test)]
impl ControlledPartialRun {
    fn project_public(
        self,
        counters: crate::attack_control::CounterSnapshot,
        domain: &AttackPlugboardDomain,
        measure: MeasureId,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        if let Some(best) = &self.best {
            if best.seeds.seeds.best.is_none() {
                return Err(crate::AttackRunError::new(AttackRunErrorData {
                    held_tail: Vec::new(),
                    stages: Vec::new(),
                    source: crate::AttackRunSource(crate::attack_result::RunPayload::Invariant(
                        "accepted best projection failed",
                    )),
                    outer_index: Some(best.outer_index),
                    start_index: None,
                    evaluations_used: self.evaluations_used,
                    counters: crate::AttackProgress(counters),
                    best: Err(Box::new(ProjectionError::MissingCommittedBoard)),
                }));
            }
        }
        let termination = match self.termination {
            ControlledPartialTermination::Completed => DirectRunTermination::Completed,
            ControlledPartialTermination::OuterSliceEnd => DirectRunTermination::OuterSliceEnd,
            ControlledPartialTermination::Cancelled => DirectRunTermination::Cancelled,
        };
        let run = DirectRunOutcome {
            termination,
            outer_completed: self.outer_completed,
            climbs_started: self.climbs_started,
            climbs_completed: self.climbs_completed,
            evaluations_used: self.evaluations_used,
            best: self.best.map(ControlledPartialOutcome::into_direct),
        };
        attach_held(run.project_public(counters, domain, measure), self.held)
    }
}

impl ControlledPartialRunError {
    fn project(self, domain: &AttackPlugboardDomain, measure: MeasureId) -> crate::AttackRunError {
        use crate::attack_result::RunPayload;
        let mut projection_error = None;
        let source = match self.source {
            ControlledPartialRunSource::Climb(ControlledPartialSource::Projection(error)) => {
                projection_error = Some(error);
                RunPayload::Invariant("seed projection failed")
            }
            ControlledPartialRunSource::Resolution(diagnostics) => {
                RunPayload::Resolution(diagnostics)
            }
            #[cfg(test)]
            ControlledPartialRunSource::MissingOuter => {
                RunPayload::Invariant("missing selected outer")
            }
            ControlledPartialRunSource::Climb(ControlledPartialSource::UnsupportedPass) => {
                RunPayload::Invariant("unsupported partial pass")
            }
            ControlledPartialRunSource::Climb(ControlledPartialSource::Climb(source)) => {
                RunPayload::from(source)
            }
        };
        let error = crate::AttackRunError::new(AttackRunErrorData {
            held_tail: Vec::new(),
            stages: Vec::new(),
            source: crate::AttackRunSource(source),
            outer_index: self.outer_index,
            start_index: self.seed_index,
            evaluations_used: self.evaluations_used,
            counters: crate::AttackProgress(self.counters),
            best: if let Some(error) = projection_error {
                Err(Box::new(error))
            } else {
                self.best
                    .map(|best| best.project(domain, measure))
                    .transpose()
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            },
        });
        attach_held(Err(error), self.held).unwrap_err()
    }
}

impl crate::AttackRequest {
    #[cfg(test)]
    fn schedule_partial_outers_controlled(
        &self,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        requested: impl FnMut() -> bool,
    ) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
        self.schedule_partial_outers_using(
            &mut EvaluationAllowance { used: 0 },
            control,
            observer,
            requested,
            1,
        )
    }

    /// Capacity one keeps raw strict-best selection; larger capacities hold seeds.
    #[cfg(test)]
    fn schedule_partial_outers_using(
        &self,
        allowance: &mut EvaluationAllowance,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        requested: impl FnMut() -> bool,
        capacity: usize,
    ) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
        self.schedule_partial_blocks(
            &RunPreparation::new(self),
            allowance,
            control,
            observer,
            requested,
            capacity,
        )
    }

    #[cfg(test)]
    fn schedule_partial_blocks(
        &self,
        preparation: &RunPreparation<'_>,
        allowance: &mut EvaluationAllowance,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        mut requested: impl FnMut() -> bool,
        capacity: usize,
    ) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
        let result = if self.settings().kind() != crate::AttackKind::PartialExhaustion {
            Err(Box::new(ControlledPartialRunError {
                outer_index: None,
                seed_index: None,
                evaluations_used: 0,
                source: ControlledPartialRunSource::Climb(ControlledPartialSource::UnsupportedPass),
                best: None,
                counters: control.snapshot(),
                held: None,
            }))
        } else {
            let plan = self.outer_plan();
            schedule_controlled_partial_prepared(
                self,
                preparation,
                self.gate().outer_selected(),
                plan.blocks().flat_map(|block| plan.keys(block)),
                &mut ObservedAccounting {
                    allowance,
                    control,
                    observer,
                },
                &mut requested,
                capacity,
            )
        };
        result
    }

    #[cfg(test)]
    fn climb_partial_outer_controlled<O: CounterObserver, F: FnMut() -> bool>(
        &self,
        initial: ResolvedConfiguration,
        outer_index: u128,
        accounting: &mut ObservedAccounting<'_, O>,
        requested: &mut F,
    ) -> Result<ControlledPartialOutcome, ControlledPartialError> {
        let backtrack_pairs = self.settings().backtrack_pairs();
        self.climb_partial_outer_controlled_with(
            initial,
            outer_index,
            accounting,
            requested,
            1,
            |scoring, _, board, accounting, requested| {
                scoring.climb_cancellable(board, backtrack_pairs, accounting, requested)
            },
        )
    }

    #[cfg(test)]
    fn climb_partial_outer_controlled_with<O: CounterObserver, F: FnMut() -> bool>(
        &self,
        initial: ResolvedConfiguration,
        outer_index: u128,
        accounting: &mut ObservedAccounting<'_, O>,
        requested: &mut F,
        capacity: usize,
        climb: impl FnMut(
            &BoundClimbScoring<'_>,
            u128,
            MutableBoard,
            &mut ObservedAccounting<'_, O>,
            &mut F,
        ) -> Result<ClimbOutcome, ObservedClimbError>,
    ) -> Result<ControlledPartialOutcome, ControlledPartialError> {
        self.climb_partial_outer_prepared(
            &RunPreparation::new(self),
            (initial, outer_index),
            accounting,
            requested,
            capacity,
            climb,
        )
    }

    // F is climb-local context: serial adapters forward their stop callback;
    // worker adapters use (), so no cancellation callback enters worker code.
    fn climb_partial_outer_prepared<A: SeedAccounting, F>(
        &self,
        preparation: &RunPreparation<'_>,
        outer: (ResolvedConfiguration, u128),
        accounting: &mut A,
        requested: &mut F,
        capacity: usize,
        mut climb: impl FnMut(
            &BoundClimbScoring<'_>,
            u128,
            MutableBoard,
            &mut A,
            &mut F,
        ) -> Result<ClimbOutcome, ObservedClimbError>,
    ) -> Result<ControlledPartialOutcome, ControlledPartialError> {
        let (initial, outer_index) = outer;
        let result = (|| {
            let settings = self.settings();
            if settings.kind() != crate::AttackKind::PartialExhaustion {
                return Err(ControlledPartialError {
                    outer_index,
                    seed_index: None,
                    source: ControlledPartialSource::UnsupportedPass,
                    best: None,
                    held: None,
                });
            }
            let first = settings.initial_measure();
            let last = settings.final_measure();
            let scoring = BoundClimbScoring::new(
                &initial,
                self.domain(),
                self.text(),
                (first, self.bound_resource(first)),
                (last, self.bound_resource(last)),
                settings.switch_pairs(),
            )
            .with_preparation(preparation, outer_index);
            let mut held = (capacity > 1).then(|| crate::attack_hold::AttackHold::new(capacity));
            let mut fault = None;
            let seeds = scoring
                .climb_seeds_controlled_with(
                    settings
                        .seed_policy()
                        .expect("validated PE settings have seeds"),
                    accounting,
                    requested,
                    |seed, board, accounting, requested| {
                        climb(&scoring, seed, board, accounting, requested)
                    },
                    |seed| {
                        let Some(hold) = &mut held else {
                            return ControlFlow::Continue(Some(seed));
                        };
                        let seed_index = seed.seed_index;
                        // N > 1 validates every eligible seed, including eventual losers.
                        match seed
                            .into_direct(initial.clone(), outer_index)
                            .project(self.domain(), last)
                        {
                            Ok(best) => hold.offer(best),
                            Err(source) => {
                                fault = Some((seed_index, source));
                                return ControlFlow::Break(());
                            }
                        }
                        ControlFlow::Continue(None)
                    },
                )
                .map_err(|error| ControlledPartialError {
                    held: held.take().map(Box::new),
                    ..ControlledPartialError::from_seed(outer_index, initial.clone(), error)
                })?;
            if let Some((seed_index, source)) = fault {
                return Err(ControlledPartialError {
                    outer_index,
                    seed_index: Some(seed_index),
                    source: ControlledPartialSource::Projection(source),
                    best: None,
                    held: held.map(Box::new),
                });
            }
            Ok(ControlledPartialOutcome {
                initial,
                outer_index,
                seeds,
                held,
            })
        })();
        result
    }

    // Legacy request adapters preserve route-equivalence regression coverage.
    /// Same-owner projection supplies absolute indices and fresh independent seeds.
    #[cfg(test)]
    pub(crate) fn schedule_partial_outers(
        &self,
    ) -> Result<PartialRunOutcome, IndexedPartialRunError> {
        if self.settings().kind() != crate::AttackKind::PartialExhaustion {
            return Err(IndexedPartialRunError {
                outer_index: None,
                evaluations_used: 0,
                source: PartialRunError::Climb(PartialClimbError::UnsupportedPass),
            });
        }
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut result = PartialRunOutcome {
            termination: PartialRunTermination::OuterSliceEnd,
            outer_completed: 0,
            climbs_started: 0,
            climbs_completed: 0,
            evaluations_used: 0,
            best: None,
        };
        for (index, initial) in self.outer_candidates() {
            let initial = initial.map_err(|source| IndexedPartialRunError {
                outer_index: Some(index),
                evaluations_used: allowance.used,
                source: PartialRunError::Resolution(source),
            })?;
            let outcome = self
                .climb_partial_outer(initial, index, &mut allowance)
                .map_err(|error| IndexedPartialRunError {
                    outer_index: Some(error.outer_index),
                    evaluations_used: error.evaluations_used,
                    source: PartialRunError::Climb(error.source),
                })?;
            result.evaluations_used = allowance.used;
            // Defensive checked arithmetic: admitted starts each charge at least
            // one evaluation, so realistic request totals are bounded by u64 usage.
            result.climbs_started = result
                .climbs_started
                .checked_add(outcome.seeds.climbs_started)
                .expect("charged starts fit u128");
            result.climbs_completed = result
                .climbs_completed
                .checked_add(outcome.seeds.climbs_completed)
                .expect("completed climbs cannot exceed charged starts");
            result.outer_completed = result
                .outer_completed
                .checked_add(1)
                .expect("completed outers cannot exceed charged starts");
            if let Some(seed) = &outcome.seeds.best {
                if result.best.as_ref().is_none_or(|best| {
                    seed.current.score.ranking().units()
                        > best
                            .seeds
                            .best
                            .as_ref()
                            .expect("best has committed seed")
                            .current
                            .score
                            .ranking()
                            .units()
                }) {
                    result.best = Some(outcome);
                }
            }
            result.termination = PartialRunTermination::Completed;
        }
        Ok(result)
    }

    /// Caller supplies a resolved initial/index from this owner's outer projection.
    /// This private adapter retains that index but does not validate provenance.
    #[cfg(test)]
    pub(crate) fn climb_partial_outer(
        &self,
        initial: ResolvedConfiguration,
        outer_index: u128,
        allowance: &mut EvaluationAllowance,
    ) -> Result<PartialOuterOutcome, IndexedPartialClimbError> {
        let settings = self.settings();
        if settings.kind() != crate::AttackKind::PartialExhaustion {
            return Err(IndexedPartialClimbError {
                outer_index,
                evaluations_used: allowance.used,
                source: PartialClimbError::UnsupportedPass,
            });
        }
        let first = settings.initial_measure();
        let last = settings.final_measure();
        let scoring = BoundClimbScoring::new(
            &initial,
            self.domain(),
            self.text(),
            (first, self.bound_resource(first)),
            (last, self.bound_resource(last)),
            settings.switch_pairs(),
        );
        let seeds = scoring
            .climb_seeds(
                settings
                    .seed_policy()
                    .expect("validated PE settings have seeds"),
                settings.backtrack_pairs(),
                allowance,
            )
            .map_err(|source| IndexedPartialClimbError {
                outer_index,
                evaluations_used: allowance.used,
                source: PartialClimbError::Evaluation(source),
            })?;
        Ok(PartialOuterOutcome {
            initial,
            outer_index,
            seeds,
        })
    }

    /// Same-owner lazy projection closes the adapter's key/index provenance precondition.
    #[cfg(test)]
    fn schedule_direct_outers_controlled(
        &self,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        requested: impl FnMut() -> bool,
    ) -> Result<DirectRunOutcome, Box<ControlledDirectError>> {
        self.schedule_direct_outers_using(
            &mut EvaluationAllowance { used: 0 },
            control,
            observer,
            requested,
            |outcome| Ok(Some(outcome)),
        )
    }

    #[cfg(test)]
    fn schedule_direct_outers_using(
        &self,
        allowance: &mut EvaluationAllowance,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        requested: impl FnMut() -> bool,
        accept: impl FnMut(DirectOuterOutcome) -> Result<Option<DirectOuterOutcome>, ProjectionError>,
    ) -> Result<DirectRunOutcome, Box<ControlledDirectError>> {
        self.schedule_direct_blocks(
            &RunPreparation::new(self),
            allowance,
            control,
            observer,
            requested,
            accept,
        )
    }

    #[cfg(test)]
    fn schedule_direct_blocks(
        &self,
        preparation: &RunPreparation<'_>,
        allowance: &mut EvaluationAllowance,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        mut requested: impl FnMut() -> bool,
        accept: impl FnMut(DirectOuterOutcome) -> Result<Option<DirectOuterOutcome>, ProjectionError>,
    ) -> Result<DirectRunOutcome, Box<ControlledDirectError>> {
        let result = if self.settings().kind() != crate::AttackKind::HillClimb {
            Err(Box::new(ControlledDirectError {
                outer_index: None,
                evaluations_used: 0,
                source: DirectRunError::Climb(DirectClimbError::UnsupportedPass),
                best: None,
                counters: control.snapshot(),
            }))
        } else {
            let plan = self.outer_plan();
            schedule_controlled_direct(
                self.gate().outer_selected(),
                plan.blocks().flat_map(|block| plan.keys(block)),
                &mut ObservedAccounting {
                    allowance,
                    control,
                    observer,
                },
                &mut requested,
                |initial, index, accounting, requested| {
                    let (scoring, start) = self
                        .direct_scoring(&initial)
                        .map_err(DirectRunError::Climb)?;
                    let scoring = scoring.with_preparation(preparation, index);
                    let climb = scoring
                        .climb_cancellable(
                            start,
                            self.settings().backtrack_pairs(),
                            accounting,
                            requested,
                        )
                        .map_err(DirectRunError::from)?;
                    Ok(DirectOuterOutcome {
                        initial,
                        outer_index: index,
                        start_index: 0,
                        climb,
                    })
                },
                accept,
            )
        };
        result
    }

    /// Both direct entry points bind the same owner, objectives and owned start.
    fn direct_scoring<'a>(
        &'a self,
        initial: &'a ResolvedConfiguration,
    ) -> Result<(BoundClimbScoring<'a>, MutableBoard), DirectClimbError> {
        let settings = self.settings();
        if settings.kind() != crate::AttackKind::HillClimb {
            return Err(DirectClimbError::UnsupportedPass);
        }
        let start = settings
            .start()
            .ok_or(DirectClimbError::MissingStart)?
            .to_vec();
        let first = settings.initial_measure();
        let last = settings.final_measure();
        Ok((
            BoundClimbScoring::new(
                initial,
                self.domain(),
                self.text(),
                (first, self.bound_resource(first)),
                (last, self.bound_resource(last)),
                settings.switch_pairs(),
            ),
            start,
        ))
    }

    #[cfg(test)]
    pub(crate) fn schedule_direct_outers(&self) -> Result<DirectRunOutcome, IndexedDirectRunError> {
        if self.settings().kind() != crate::AttackKind::HillClimb {
            return Err(IndexedDirectRunError {
                outer_index: None,
                evaluations_used: 0,
                source: DirectRunError::Climb(DirectClimbError::UnsupportedPass),
            });
        }
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut result = DirectRunOutcome {
            termination: DirectRunTermination::OuterSliceEnd,
            outer_completed: 0,
            climbs_started: 0,
            climbs_completed: 0,
            evaluations_used: 0,
            best: None,
        };
        for (index, initial) in self.outer_candidates() {
            let initial = initial.map_err(|source| IndexedDirectRunError {
                outer_index: Some(index),
                evaluations_used: allowance.used,
                source: DirectRunError::Resolution(source),
            })?;
            let outcome = self
                .climb_direct_outer(initial, index, &mut allowance)
                .map_err(|error| IndexedDirectRunError {
                    outer_index: Some(error.outer_index),
                    evaluations_used: error.evaluations_used,
                    source: DirectRunError::Climb(error.source),
                })?;
            result.evaluations_used = allowance.used;
            let interrupted = outcome.climb.incomplete;
            if let Some(current) = &outcome.climb.current {
                result.climbs_started = result
                    .climbs_started
                    .checked_add(1)
                    .expect("started climbs are bounded by checked outer total");
                if !interrupted {
                    result.climbs_completed = result
                        .climbs_completed
                        .checked_add(1)
                        .expect("completed climbs cannot exceed started climbs");
                    result.outer_completed = result
                        .outer_completed
                        .checked_add(1)
                        .expect("completed outers are bounded by checked outer total");
                }
                if result.best.as_ref().is_none_or(|best| {
                    current.score.ranking().units()
                        > best
                            .climb
                            .current
                            .as_ref()
                            .expect("best has committed board")
                            .score
                            .ranking()
                            .units()
                }) {
                    result.best = Some(outcome);
                }
            }
            result.termination = DirectRunTermination::Completed;
        }
        Ok(result)
    }

    /// Internal caller must supply an initial key/index from THIS owner's private
    /// outer projection. This adapter does not validate provenance or schedule outers.
    #[cfg(test)]
    pub(crate) fn climb_direct_outer(
        &self,
        initial: ResolvedConfiguration,
        outer_index: u128,
        allowance: &mut EvaluationAllowance,
    ) -> Result<DirectOuterOutcome, IndexedDirectClimbError> {
        let settings = self.settings();
        let mut run = || -> Result<ClimbOutcome, DirectClimbError> {
            let (scoring, start) = self.direct_scoring(&initial)?;
            scoring
                .climb(start, settings.backtrack_pairs(), allowance)
                .map_err(DirectClimbError::Evaluation)
        };
        let climb = run().map_err(|source| IndexedDirectClimbError {
            outer_index,
            evaluations_used: allowance.used,
            source,
        })?;
        Ok(DirectOuterOutcome {
            initial,
            outer_index,
            start_index: 0,
            climb,
        })
    }
}

/// Known cardinality establishes exhaustion without resolving a speculative next outer.
/// The adapter seam also permits deterministic indexed resolution/scoring fault tests.
#[cfg(test)]
fn schedule_controlled_partial<O: CounterObserver, F: FnMut() -> bool>(
    owner: &crate::AttackRequest,
    selected: u128,
    outers: impl Iterator<
        Item = (
            u128,
            Result<ResolvedConfiguration, Vec<crate::SearchDiagnostic>>,
        ),
    >,
    accounting: &mut ObservedAccounting<'_, O>,
    requested: &mut F,
    capacity: usize,
) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
    schedule_controlled_partial_prepared(
        owner,
        &RunPreparation::new(owner),
        selected,
        outers,
        accounting,
        requested,
        capacity,
    )
}

#[cfg(test)]
fn schedule_controlled_partial_prepared<O: CounterObserver, F: FnMut() -> bool>(
    owner: &crate::AttackRequest,
    preparation: &RunPreparation<'_>,
    selected: u128,
    outers: impl Iterator<
        Item = (
            u128,
            Result<ResolvedConfiguration, Vec<crate::SearchDiagnostic>>,
        ),
    >,
    accounting: &mut ObservedAccounting<'_, O>,
    requested: &mut F,
    capacity: usize,
) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
    let backtrack_pairs = owner.settings().backtrack_pairs();
    schedule_controlled_partial_with_climb(
        selected,
        outers,
        accounting,
        requested,
        |initial, index, accounting, requested| {
            owner.climb_partial_outer_prepared(
                preparation,
                (initial, index),
                accounting,
                requested,
                capacity,
                |scoring, _, board, accounting, requested| {
                    scoring.climb_cancellable(board, backtrack_pairs, accounting, requested)
                },
            )
        },
    )
}

#[cfg(test)]
fn schedule_controlled_partial_with_climb<O: CounterObserver, F: FnMut() -> bool>(
    selected: u128,
    mut outers: impl Iterator<
        Item = (
            u128,
            Result<ResolvedConfiguration, Vec<crate::SearchDiagnostic>>,
        ),
    >,
    accounting: &mut ObservedAccounting<'_, O>,
    requested: &mut F,
    mut climb: impl FnMut(
        ResolvedConfiguration,
        u128,
        &mut ObservedAccounting<'_, O>,
        &mut F,
    ) -> Result<ControlledPartialOutcome, ControlledPartialError>,
) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
    let run = (|| -> Result<_, Box<ControlledPartialRunError>> {
        let before = accounting.control.snapshot();
        let mut result = ControlledPartialRun {
            termination: ControlledPartialTermination::OuterSliceEnd,
            outer_completed: 0,
            climbs_started: 0,
            climbs_completed: 0,
            evaluations_used: accounting.allowance.used,
            best: None,
            held: None,
        };
        for _ in 0..selected {
            if accounting.control.poll_cancellation(requested()) {
                result.termination = ControlledPartialTermination::Cancelled;
                break;
            }
            let (index, initial) = outers.next().ok_or_else(|| {
                Box::new(ControlledPartialRunError {
                    outer_index: None,
                    seed_index: None,
                    evaluations_used: accounting.allowance.used,
                    source: ControlledPartialRunSource::MissingOuter,
                    best: result
                        .best
                        .take()
                        .map(ControlledPartialOutcome::into_direct),
                    counters: accounting.control.snapshot(),
                    held: result.held.take(),
                })
            })?;
            let initial = initial.map_err(|source| ControlledPartialRunError {
                outer_index: Some(index),
                seed_index: None,
                evaluations_used: accounting.allowance.used,
                source: ControlledPartialRunSource::Resolution(source),
                best: result
                    .best
                    .take()
                    .map(ControlledPartialOutcome::into_direct),
                counters: accounting.control.snapshot(),
                held: result.held.take(),
            })?;
            let execution = execute_outer(
                accounting.allowance.clone(),
                accounting.control.clone(),
                accounting.observer,
                |local| {
                    let outcome = climb(initial, index, local, requested)?;
                    // Only whole seed exhaustion completes an outer, not winner flags.
                    if !outcome.seeds.cancelled {
                        local
                            .transition(AttackControl::record_outer_completed)
                            .map_err(|source| ControlledPartialError {
                                outer_index: index,
                                seed_index: None,
                                source: ControlledPartialSource::Climb(source),
                                best: None,
                                held: None,
                            })?;
                    }
                    Ok::<_, ControlledPartialError>(outcome)
                },
            );
            let outcome = execution.commit(accounting);
            let mut outcome = outcome.map_err(|error| {
                let mut best = result
                    .best
                    .take()
                    .map(ControlledPartialOutcome::into_direct);
                if let Some(retained) = error.best {
                    let (initial, seed) = *retained;
                    let candidate = seed.into_direct(initial, error.outer_index);
                    if best.as_ref().is_none_or(|prior| {
                        candidate
                            .climb
                            .current
                            .as_ref()
                            .expect("retained seed")
                            .score
                            .ranking()
                            .units()
                            > prior
                                .climb
                                .current
                                .as_ref()
                                .expect("accepted seed")
                                .score
                                .ranking()
                                .units()
                    }) {
                        best = Some(candidate);
                    }
                }
                merge_held(&mut result.held, error.held.map(|held| *held));
                ControlledPartialRunError {
                    outer_index: Some(error.outer_index),
                    seed_index: error.seed_index,
                    evaluations_used: accounting.allowance.used,
                    source: ControlledPartialRunSource::Climb(error.source),
                    best,
                    counters: accounting.control.snapshot(),
                    held: result.held.take(),
                }
            })?;
            let cancelled = outcome.seeds.cancelled;
            let now = accounting.control.snapshot();
            result.outer_completed = now.outers_completed - before.outers_completed;
            result.climbs_started = now.climbs_started - before.climbs_started;
            result.climbs_completed = now.climbs_completed - before.climbs_completed;
            result.evaluations_used = accounting.allowance.used;
            // Accepted outers merge in order; equal-capacity local holds lose nothing.
            merge_held(&mut result.held, outcome.held.take());
            if let Some(seed) = &outcome.seeds.seeds.best {
                if result.best.as_ref().is_none_or(|best| {
                    seed.current.score.ranking().units()
                        > best
                            .seeds
                            .seeds
                            .best
                            .as_ref()
                            .expect("committed seed")
                            .current
                            .score
                            .ranking()
                            .units()
                }) {
                    result.best = Some(outcome);
                }
            }
            if cancelled {
                result.termination = ControlledPartialTermination::Cancelled;
                break;
            }
            result.termination = ControlledPartialTermination::Completed;
        }
        Ok(result)
    })();
    run
}

#[derive(Debug)]
struct ControlledDirectError {
    outer_index: Option<u128>,
    evaluations_used: u64,
    source: DirectRunError,
    best: Option<DirectOuterOutcome>,
    counters: crate::attack_control::CounterSnapshot,
}

impl ControlledDirectError {
    fn project(self, domain: &AttackPlugboardDomain, measure: MeasureId) -> crate::AttackRunError {
        use crate::attack_result::RunPayload;
        let start_index = match &self.source {
            DirectRunError::Resolution(_) => None,
            #[cfg(test)]
            DirectRunError::MissingOuter => None,
            _ => self.outer_index.map(|_| 0),
        };
        let mut projection_error = None;
        let source = match self.source {
            DirectRunError::Projection(error) => {
                projection_error = Some(error);
                RunPayload::Invariant("accepted best projection failed")
            }
            DirectRunError::Resolution(diagnostics) => RunPayload::Resolution(diagnostics),
            DirectRunError::Climb(DirectClimbError::Evaluation(source)) => source.into(),
            DirectRunError::Counter(source) => RunPayload::Counter(source),
            #[cfg(test)]
            DirectRunError::MissingOuter => RunPayload::Invariant("missing selected outer"),
            DirectRunError::Climb(DirectClimbError::MissingStart) => {
                RunPayload::Invariant("missing direct start")
            }
            DirectRunError::Climb(DirectClimbError::UnsupportedPass) => {
                RunPayload::Invariant("unsupported direct pass")
            }
        };
        crate::AttackRunError::new(AttackRunErrorData {
            held_tail: Vec::new(),
            stages: Vec::new(),
            source: crate::AttackRunSource(source),
            outer_index: self.outer_index,
            start_index,
            evaluations_used: self.evaluations_used,
            counters: crate::AttackProgress(self.counters),
            best: if let Some(error) = projection_error {
                Err(Box::new(error))
            } else {
                self.best
                    .map(|best| best.project(domain, measure))
                    .transpose()
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            },
        })
    }
}

#[cfg(test)]
fn schedule_controlled_direct<O: CounterObserver, F: FnMut() -> bool>(
    selected: u128,
    mut outers: impl Iterator<
        Item = (
            u128,
            Result<ResolvedConfiguration, Vec<crate::SearchDiagnostic>>,
        ),
    >,
    accounting: &mut ObservedAccounting<'_, O>,
    requested: &mut F,
    mut climb: impl FnMut(
        ResolvedConfiguration,
        u128,
        &mut ObservedAccounting<'_, O>,
        &mut F,
    ) -> Result<DirectOuterOutcome, DirectRunError>,
    mut accept: impl FnMut(DirectOuterOutcome) -> Result<Option<DirectOuterOutcome>, ProjectionError>,
) -> Result<DirectRunOutcome, Box<ControlledDirectError>> {
    let before = accounting.control.snapshot();
    let mut result = DirectRunOutcome {
        termination: DirectRunTermination::OuterSliceEnd,
        outer_completed: 0,
        climbs_started: 0,
        climbs_completed: 0,
        evaluations_used: accounting.allowance.used,
        best: None,
    };
    let run = (|| {
        for _ in 0..selected {
            if accounting.control.poll_cancellation(requested()) {
                result.termination = DirectRunTermination::Cancelled;
                break;
            }
            let (index, initial) = outers.next().ok_or(IndexedDirectRunError {
                outer_index: None,
                evaluations_used: accounting.allowance.used,
                source: DirectRunError::MissingOuter,
            })?;
            let execution = execute_outer(
                accounting.allowance.clone(),
                accounting.control.clone(),
                accounting.observer,
                |local| {
                    let initial = initial.map_err(DirectRunError::Resolution)?;
                    let outcome = climb(initial, index, local, requested)?;
                    if outcome.climb.neighborhood_exhausted {
                        local
                            .transition(AttackControl::record_outer_completed)
                            .map_err(DirectRunError::from)?;
                    }
                    Ok(outcome)
                },
            );
            let outcome = execution
                .commit(accounting)
                .map_err(|source| IndexedDirectRunError {
                    outer_index: Some(index),
                    evaluations_used: accounting.allowance.used,
                    source,
                })?;
            let cancelled = outcome.climb.cancelled;
            let now = accounting.control.snapshot();
            // These counters only increase; subtraction retains prior caller facts without reset.
            result.climbs_started = now.climbs_started - before.climbs_started;
            result.climbs_completed = now.climbs_completed - before.climbs_completed;
            result.outer_completed = now.outers_completed - before.outers_completed;
            result.evaluations_used = accounting.allowance.used;
            let outcome = if outcome.climb.current.is_some() {
                accept(outcome).map_err(|source| IndexedDirectRunError {
                    outer_index: Some(index),
                    evaluations_used: accounting.allowance.used,
                    source: DirectRunError::Projection(source),
                })?
            } else {
                None
            };
            if let Some(outcome) = outcome {
                let current = outcome.climb.current.as_ref().expect("accepted board");
                if result.best.as_ref().is_none_or(|best| {
                    current.score.ranking().units()
                        > best
                            .climb
                            .current
                            .as_ref()
                            .expect("best has committed board")
                            .score
                            .ranking()
                            .units()
                }) {
                    result.best = Some(outcome);
                }
            }
            if cancelled {
                result.termination = DirectRunTermination::Cancelled;
                break;
            }
            result.termination = DirectRunTermination::Completed;
        }
        Ok(())
    })();
    run.map_err(|error: IndexedDirectRunError| {
        Box::new(ControlledDirectError {
            outer_index: error.outer_index,
            evaluations_used: error.evaluations_used,
            source: error.source,
            best: result.best.take(),
            counters: accounting.control.snapshot(),
        })
    })?;
    Ok(result)
}

/// Lazy empty/single mutable remainders. Fixed knowledge stays in the bound domain.
struct SeedCursor<'a> {
    symbols: Vec<char>,
    policy: &'a crate::AttackSeedPolicy,
    next_pair: (usize, usize),
    next_index: u128,
    empty_pending: bool,
    singles_allowed: bool,
}

impl<'a> SeedCursor<'a> {
    /// Inputs come from validated domain/settings; snapshot validation checks binding.
    fn new(
        initial: &ResolvedConfiguration,
        domain: &AttackPlugboardDomain,
        policy: &'a crate::AttackSeedPolicy,
    ) -> Result<Self, crate::attack_evaluator::TrialBoardError> {
        validated_trial_board(initial, domain, &[])?;
        // Linear storage only, in runtime alphabet order, never declaration order.
        let symbols = initial
            .topology()
            .alphabet()
            .symbols
            .iter()
            .copied()
            .filter(|symbol| domain.symbols().contains(symbol))
            .filter(|symbol| {
                !domain
                    .fixed_pairs()
                    .iter()
                    .any(|&(a, b)| a == *symbol || b == *symbol)
            })
            .collect();
        Ok(Self {
            symbols,
            policy,
            next_pair: (0, 1),
            next_index: 0,
            empty_pending: true,
            singles_allowed: domain.fixed_pairs().len() < domain.max_pairs(),
        })
    }

    fn indexed(&mut self, board: MutableBoard) -> (u128, MutableBoard) {
        let index = self.next_index;
        // Match the gate's u128 start counts. A scalar alphabet has at most
        // 1,112,064 members, so 1 + choose(n, 2) fits even u64; checked u128
        // increment documents the invariant without relying on usize width.
        self.next_index = index.checked_add(1).expect("scalar seed count fits u128");
        (index, board)
    }
}

impl Iterator for SeedCursor<'_> {
    type Item = (u128, MutableBoard);

    fn next(&mut self) -> Option<Self::Item> {
        if self.empty_pending {
            self.empty_pending = false;
            return Some(self.indexed(vec![]));
        }
        if !self.singles_allowed {
            return None;
        }
        loop {
            let (a, b) = self.next_pair;
            if b >= self.symbols.len() {
                return None;
            }
            self.next_pair = if b + 1 < self.symbols.len() {
                (a, b + 1)
            } else {
                (a + 1, a + 2)
            };
            let pair = (self.symbols[a], self.symbols[b]);
            let selected = match self.policy {
                crate::AttackSeedPolicy::All => true,
                crate::AttackSeedPolicy::Touching(mask) => {
                    mask.contains(&pair.0) || mask.contains(&pair.1)
                }
            };
            if selected {
                // Filtering precedes numbering; both masked endpoints still emit once.
                return Some(self.indexed(vec![pair]));
            }
        }
    }
}

/// Checked cumulative admissions, never reset by a scan.
#[derive(Clone, Debug)]
pub(super) struct EvaluationAllowance {
    pub(super) used: u64,
}

impl EvaluationAllowance {
    fn admit(&mut self) -> Result<(), CounterOverflow> {
        self.used = self
            .used
            .checked_add(1)
            .ok_or(CounterOverflow::EvaluationsAdmitted)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ObservedClimbError {
    Evaluation(TrialEvaluationError),
    Counter(CounterOverflow),
}

impl From<TrialEvaluationError> for ObservedClimbError {
    fn from(error: TrialEvaluationError) -> Self {
        Self::Evaluation(error)
    }
}

/// One accounting path for all scoring phases.
pub(super) trait EvaluationAccounting {
    type Error: From<TrialEvaluationError>;
    fn cancelled(&mut self) -> bool {
        false
    }
    fn admit(&mut self) -> Result<(), Self::Error>;
    fn transition(
        &mut self,
        _record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn complete(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn evaluate(
        &mut self,
        evaluator: &TrialEvaluator<'_>,
        board: &[(char, char)],
    ) -> Result<(String, MeasuredScore), Self::Error> {
        self.admit()?;
        let result = evaluator.evaluate(board)?;
        self.complete()?;
        Ok(result)
    }
    /// [`Self::evaluate`] with the same accounting over a walker-guaranteed valid
    /// full mapping; plaintext only when materialized.
    fn evaluate_score_mapped(
        &mut self,
        evaluator: &TrialEvaluator<'_>,
        mapping: &[usize],
    ) -> Result<(Option<String>, MeasuredScore), Self::Error> {
        self.admit()?;
        let result = evaluator.evaluate_score_mapped(mapping)?;
        self.complete()?;
        Ok(result)
    }
}

// Legacy adapters use the same checked accounting as controlled runs.
#[cfg(test)]
impl EvaluationAccounting for EvaluationAllowance {
    type Error = TrialEvaluationError;
    fn admit(&mut self) -> Result<(), Self::Error> {
        EvaluationAllowance::admit(self)
            .map_err(|_| TrialEvaluationError::Invariant("evaluation admission counter overflow"))
    }
}

/// Only seed scheduling needs cumulative admission usage in addition to the
/// evaluator interface. Both serial observed and worker-local accounting reuse it.
trait SeedAccounting: EvaluationAccounting<Error = ObservedClimbError> {
    fn evaluations_used(&self) -> u64;
}

impl<O: CounterObserver> SeedAccounting for ObservedAccounting<'_, O> {
    fn evaluations_used(&self) -> u64 {
        self.allowance.used
    }
}

/// No observer, cadence or stop latch: cancellation's default is constant false
/// and completion records a fact only. The optimized evaluation loop therefore
/// has no progress or cancellation dispatch in worker code.
#[derive(Default)]
struct BlockAccounting {
    control: AttackControl,
    used: u64,
}

impl EvaluationAccounting for BlockAccounting {
    type Error = ObservedClimbError;
    fn admit(&mut self) -> Result<(), Self::Error> {
        self.used = self.used.checked_add(1).ok_or(ObservedClimbError::Counter(
            CounterOverflow::EvaluationsAdmitted,
        ))?;
        self.transition(AttackControl::record_evaluation_admitted)
    }
    fn complete(&mut self) -> Result<(), Self::Error> {
        self.transition(AttackControl::record_evaluation_completed)
    }
    fn transition(
        &mut self,
        record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
    ) -> Result<(), Self::Error> {
        record(&mut self.control).map_err(ObservedClimbError::Counter)
    }
}

impl SeedAccounting for BlockAccounting {
    fn evaluations_used(&self) -> u64 {
        self.used
    }
}

#[derive(Debug)]
enum BlockFailure<E> {
    Resolution(Vec<crate::SearchDiagnostic>),
    Climb(E),
    Counter(ObservedClimbError),
}

/// Every successful outer, in key order, followed by the first failure (if any).
/// Error accounting includes the failing admission but no failed completion.
struct BlockOutcome<T, E> {
    outers: Vec<T>,
    error: Option<(u128, BlockFailure<E>)>,
    accounting: BlockAccounting,
}

fn run_worker_block<T, E>(
    keys: impl Iterator<
        Item = (
            u128,
            Result<ResolvedConfiguration, Vec<crate::SearchDiagnostic>>,
        ),
    >,
    mut climb: impl FnMut(ResolvedConfiguration, u128, &mut BlockAccounting) -> Result<T, E>,
) -> BlockOutcome<T, E> {
    let mut outcome = BlockOutcome {
        outers: Vec::new(),
        error: None,
        accounting: BlockAccounting::default(),
    };
    for (index, initial) in keys {
        let result = initial
            .map_err(BlockFailure::Resolution)
            .and_then(|initial| {
                let outer =
                    climb(initial, index, &mut outcome.accounting).map_err(BlockFailure::Climb)?;
                outcome
                    .accounting
                    .transition(AttackControl::record_outer_completed)
                    .map_err(BlockFailure::Counter)?;
                Ok(outer)
            });
        match result {
            Ok(outer) => outcome.outers.push(outer),
            Err(error) => {
                outcome.error = Some((index, error));
                break;
            }
        }
    }
    outcome
}

/// A worker's finished block, owned until the coordinator commits it in key order.
enum PhaseBlock {
    Direct(BlockOutcome<DirectOuterOutcome, DirectRunError>),
    Partial(BlockOutcome<ControlledPartialOutcome, ControlledPartialError>),
}

impl PhaseBlock {
    fn failed(&self) -> bool {
        match self {
            Self::Direct(outcome) => outcome.error.is_some(),
            Self::Partial(outcome) => outcome.error.is_some(),
        }
    }
}

/// Test seams around each finished block; empty outside tests. `ran` sees a block
/// before the coordinator can receive it, `sent` after it was handed over.
#[derive(Default)]
struct PoolHooks {
    #[cfg(test)]
    ran: Option<RanHook>,
    #[cfg(test)]
    sent: Option<Box<dyn Fn(usize, OuterBlock) + Send + Sync>>,
}

#[cfg(test)]
type RanHook = Box<dyn Fn(usize, OuterBlock, &mut PhaseBlock) + Send + Sync>;

impl PoolHooks {
    #[cfg_attr(not(test), allow(unused_variables))]
    fn ran(&self, worker: usize, block: OuterBlock, outcome: &mut PhaseBlock) {
        #[cfg(test)]
        if let Some(hook) = &self.ran {
            hook(worker, block, outcome);
        }
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn sent(&self, worker: usize, block: OuterBlock) {
        #[cfg(test)]
        if let Some(hook) = &self.sent {
            hook(worker, block);
        }
    }
}

struct Dispatch {
    blocks: crate::attack_blocks::OuterBlocks,
    handed: u128,
    committed: u128,
    stop: bool,
}

/// Blocks are handed out in key order, at most `window` ahead of the next commit,
/// so the coordinator's reorder buffer stays bounded. Workers touch the lock and
/// the stop latch only between blocks, never per evaluation.
struct BlockQueue {
    state: Mutex<Dispatch>,
    changed: Condvar,
    window: u128,
}

impl BlockQueue {
    fn lock(&self) -> MutexGuard<'_, Dispatch> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next block, or `None` once stopped or exhausted.
    fn take(&self) -> Option<OuterBlock> {
        let mut state = self.lock();
        loop {
            if state.stop {
                return None;
            }
            if state.handed < state.committed.saturating_add(self.window) {
                let block = state.blocks.next()?;
                state.handed += 1;
                return Some(block);
            }
            state = (self.changed.wait(state)).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn update(&self, change: impl FnOnce(&mut Dispatch)) {
        change(&mut self.lock());
        self.changed.notify_all();
    }
}

/// A panicking worker releases the others instead of leaving them waiting for a
/// block that will never be committed; the scope then propagates the panic.
struct StopOnPanic<'a>(&'a BlockQueue);

impl Drop for StopOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.update(|state| state.stop = true);
        }
    }
}

impl crate::AttackRequest {
    /// Runs the outer blocks and commits each one in key order through `commit` on
    /// the calling thread. One thread (or a single block) keeps the serial loop.
    #[allow(clippy::too_many_arguments)]
    fn drive_blocks(
        &self,
        options: crate::ExecutionOptions,
        hooks: &PoolHooks,
        preparation: &RunPreparation<'_>,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        control: &mut AttackControl,
        requested: &mut impl FnMut() -> bool,
        commit: &mut impl FnMut(
            &mut AttackControl,
            OuterBlock,
            PhaseBlock,
        ) -> Result<(), crate::AttackRunError>,
    ) -> Result<DirectRunTermination, crate::AttackRunError> {
        let blocks = usize::try_from(plan.block_count()).unwrap_or(usize::MAX);
        let workers = options.threads().get().min(blocks);
        if workers > 1 {
            return self.drive_pool(workers, hooks, plan, control, requested, commit);
        }
        let mut termination = DirectRunTermination::OuterSliceEnd;
        for block in plan.blocks() {
            if control.poll_cancellation(requested()) {
                return Ok(DirectRunTermination::Cancelled);
            }
            let mut outcome = self.run_phase_block(preparation, plan, block);
            hooks.ran(0, block, &mut outcome);
            commit(control, block, outcome)?;
            hooks.sent(0, block);
            termination = DirectRunTermination::Completed;
        }
        Ok(termination)
    }

    /// Worker pool. Each worker owns its preparation and pulls the next block in key
    /// order; the coordinator (this thread) buffers finished blocks, commits them in
    /// key order, emits progress and polls cancellation. A stop or a known error ends
    /// the hand-out; every block already handed out still finishes and, up to the
    /// first error, is committed, so a stop always keeps a key-order prefix.
    fn drive_pool(
        &self,
        workers: usize,
        hooks: &PoolHooks,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        control: &mut AttackControl,
        requested: &mut impl FnMut() -> bool,
        commit: &mut impl FnMut(
            &mut AttackControl,
            OuterBlock,
            PhaseBlock,
        ) -> Result<(), crate::AttackRunError>,
    ) -> Result<DirectRunTermination, crate::AttackRunError> {
        if control.poll_cancellation(requested()) {
            return Ok(DirectRunTermination::Cancelled);
        }
        let count = plan.block_count();
        let queue = BlockQueue {
            state: Mutex::new(Dispatch {
                blocks: plan.blocks(),
                handed: 0,
                committed: 0,
                stop: false,
            }),
            changed: Condvar::new(),
            window: 2 * workers as u128,
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut next = 0;
        std::thread::scope(|scope| {
            for worker in 0..workers {
                let (queue, sender) = (&queue, sender.clone());
                scope.spawn(move || {
                    let _release = StopOnPanic(queue);
                    let preparation = RunPreparation::new(self);
                    while let Some(block) = queue.take() {
                        let mut outcome = self.run_phase_block(&preparation, plan, block);
                        hooks.ran(worker, block, &mut outcome);
                        if outcome.failed() {
                            queue.update(|state| state.stop = true);
                        }
                        if sender.send((block, outcome)).is_err() {
                            break;
                        }
                        hooks.sent(worker, block);
                    }
                });
            }
            drop(sender);
            let mut pending = std::collections::BTreeMap::new();
            let mut cancelled = false;
            for (block, outcome) in &receiver {
                pending.insert(block.index, (block, outcome));
                while let Some((block, outcome)) = pending.remove(&next) {
                    if let Err(error) = commit(control, block, outcome) {
                        queue.update(|state| state.stop = true);
                        return Err(error);
                    }
                    next += 1;
                    queue.update(|state| state.committed = next);
                }
                if !cancelled && next < count && control.poll_cancellation(requested()) {
                    cancelled = true;
                    queue.update(|state| state.stop = true);
                }
            }
            Ok(())
        })?;
        Ok(if next == count {
            DirectRunTermination::Completed
        } else {
            DirectRunTermination::Cancelled
        })
    }

    fn run_phase_block(
        &self,
        preparation: &RunPreparation<'_>,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        block: OuterBlock,
    ) -> PhaseBlock {
        if self.settings().kind() == crate::AttackKind::PartialExhaustion {
            PhaseBlock::Partial(self.run_partial_block(preparation, plan, block))
        } else {
            PhaseBlock::Direct(self.run_direct_block(preparation, plan, block))
        }
    }

    /// Ordered reduction: block counters merge checked (an overflow discards the
    /// whole block, reported at its first key), hold and winner offers follow key
    /// order, and the first error in key order ends the run.
    #[allow(clippy::too_many_arguments)]
    fn run_block_phase(
        &self,
        options: crate::ExecutionOptions,
        hooks: &PoolHooks,
        preparation: &RunPreparation<'_>,
        allowance: &mut EvaluationAllowance,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        requested: &mut impl FnMut() -> bool,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        let plan = self.outer_plan();
        let measure = self.settings().final_measure();
        let mut acceptance = DirectAcceptance::new(self.settings().hold_capacity());
        let mut best = None;
        let run = (|| {
            let mut commit = |control: &mut AttackControl, block: OuterBlock, outcome| {
                let (accounting, candidates, error) = match outcome {
                    PhaseBlock::Partial(outcome) => {
                        let mut candidates = Vec::new();
                        for mut outer in outcome.outers {
                            merge_held(&mut acceptance.0, outer.held.take());
                            candidates.push(outer.into_direct());
                        }
                        let error = outcome.error.map(|(index, error)| {
                            let (seed_index, source, retained, held) = match error {
                                BlockFailure::Resolution(source) => (
                                    None,
                                    ControlledPartialRunSource::Resolution(source),
                                    None,
                                    None,
                                ),
                                BlockFailure::Climb(error) => {
                                    debug_assert_eq!(error.outer_index, index);
                                    (
                                        error.seed_index,
                                        ControlledPartialRunSource::Climb(error.source),
                                        error.best,
                                        error.held,
                                    )
                                }
                                BlockFailure::Counter(source) => (
                                    None,
                                    ControlledPartialRunSource::Climb(
                                        ControlledPartialSource::Climb(source),
                                    ),
                                    None,
                                    None,
                                ),
                            };
                            (index, seed_index, source, retained, held)
                        });
                        (outcome.accounting, candidates, error.map(Err))
                    }
                    PhaseBlock::Direct(outcome) => {
                        let error = outcome.error.map(|(index, error)| {
                            let source = match error {
                                BlockFailure::Resolution(source) => {
                                    DirectRunError::Resolution(source)
                                }
                                BlockFailure::Climb(source) => source,
                                BlockFailure::Counter(source) => DirectRunError::from(source),
                            };
                            Ok((index, source))
                        });
                        (outcome.accounting, outcome.outers, error)
                    }
                };
                let merged = allowance
                    .used
                    .checked_add(accounting.used)
                    .ok_or(CounterOverflow::EvaluationsAdmitted)
                    .and_then(|used| {
                        control.merge_block(accounting.control.snapshot())?;
                        allowance.used = used;
                        Ok(())
                    });
                if let Err(source) = merged {
                    return Err(ControlledDirectError {
                        outer_index: Some(block.start),
                        evaluations_used: allowance.used,
                        source: DirectRunError::Counter(source),
                        best: best.take(),
                        counters: control.snapshot(),
                    }
                    .project(self.domain(), measure));
                }
                for candidate in candidates {
                    if candidate.climb.current.is_none() {
                        continue;
                    }
                    let index = candidate.outer_index;
                    // PE has already projected its seed offers into the local hold.
                    let candidate =
                        if self.settings().kind() == crate::AttackKind::PartialExhaustion {
                            Some(candidate)
                        } else {
                            acceptance
                                .accept(candidate, self.domain(), measure)
                                .map_err(|source| {
                                    ControlledDirectError {
                                        outer_index: Some(index),
                                        evaluations_used: allowance.used,
                                        source: DirectRunError::Projection(source),
                                        best: best.take(),
                                        counters: control.snapshot(),
                                    }
                                    .project(self.domain(), measure)
                                })?
                        };
                    if let Some(candidate) = candidate {
                        keep_strict_best(&mut best, candidate);
                    }
                }
                control.block_progress(observer);
                if let Some(error) = error {
                    return Err(match error {
                        Ok((index, source)) => ControlledDirectError {
                            outer_index: Some(index),
                            evaluations_used: allowance.used,
                            source,
                            best: best.take(),
                            counters: control.snapshot(),
                        }
                        .project(self.domain(), measure),
                        Err((index, seed_index, source, retained, held)) => {
                            if let Some(retained) = retained {
                                let (initial, seed) = *retained;
                                keep_strict_best(&mut best, seed.into_direct(initial, index));
                            }
                            merge_held(&mut acceptance.0, held.map(|held| *held));
                            ControlledPartialRunError {
                                outer_index: Some(index),
                                seed_index,
                                evaluations_used: allowance.used,
                                source,
                                best: best.take(),
                                counters: control.snapshot(),
                                held: None,
                            }
                            .project(self.domain(), measure)
                        }
                    });
                }
                Ok(())
            };
            let termination = self.drive_blocks(
                options,
                hooks,
                preparation,
                &plan,
                control,
                requested,
                &mut commit,
            )?;
            let counters = control.snapshot();
            DirectRunOutcome {
                termination,
                #[cfg(test)]
                outer_completed: counters.outers_completed,
                #[cfg(test)]
                climbs_started: counters.climbs_started,
                #[cfg(test)]
                climbs_completed: counters.climbs_completed,
                evaluations_used: allowance.used,
                best: best.take(),
            }
            .project_public(counters, self.domain(), measure)
        })();
        attach_held(run, acceptance.0)
    }

    /// `preparation` belongs to this worker and is reused between its blocks;
    /// neither the coordinator nor another worker borrows its mutable cells.
    fn run_direct_block(
        &self,
        preparation: &RunPreparation<'_>,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        block: crate::attack_blocks::OuterBlock,
    ) -> BlockOutcome<DirectOuterOutcome, DirectRunError> {
        run_worker_block(plan.keys(block), |initial, index, accounting| {
            let (scoring, start) = self
                .direct_scoring(&initial)
                .map_err(DirectRunError::Climb)?;
            let climb = scoring
                .with_preparation(preparation, index)
                .climb_accounted(start, self.settings().backtrack_pairs(), accounting)
                .map_err(DirectRunError::from)?;
            Ok(DirectOuterOutcome {
                initial,
                outer_index: index,
                start_index: 0,
                climb,
            })
        })
    }

    fn run_partial_block(
        &self,
        preparation: &RunPreparation<'_>,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        block: crate::attack_blocks::OuterBlock,
    ) -> BlockOutcome<ControlledPartialOutcome, ControlledPartialError> {
        run_worker_block(plan.keys(block), |initial, index, accounting| {
            self.climb_partial_outer_prepared(
                preparation,
                (initial, index),
                accounting,
                &mut (),
                self.settings().hold_capacity(),
                |scoring, _, board, accounting, _| {
                    scoring.climb_accounted(board, self.settings().backtrack_pairs(), accounting)
                },
            )
        })
    }
}

fn keep_strict_best(best: &mut Option<DirectOuterOutcome>, candidate: DirectOuterOutcome) {
    let score = |outcome: &DirectOuterOutcome| {
        outcome
            .climb
            .current
            .as_ref()
            .expect("scored candidate")
            .score
            .ranking()
            .units()
    };
    if best
        .as_ref()
        .is_none_or(|prior| score(&candidate) > score(prior))
    {
        *best = Some(candidate);
    }
}

/// A one-outer worker's owned outcome, including accounting on the first error.
/// The serial adapter seeds cumulative facts to preserve overflow, cadence and
/// cancellation semantics. Future workers can start from fresh local accounting.
#[cfg(test)]
struct OuterExecution<T, E> {
    result: Result<T, E>,
    allowance: EvaluationAllowance,
    control: AttackControl,
}

#[cfg(test)]
impl<T, E> OuterExecution<T, E> {
    fn commit<O>(self, accounting: &mut ObservedAccounting<'_, O>) -> Result<T, E> {
        *accounting.allowance = self.allowance;
        *accounting.control = self.control;
        self.result
    }
}

/// All evaluation mutations stay local until ordered commit. Callbacks remain
/// synchronous in this serial adapter: buffering them would change cancellation
/// when a progress callback requests a stop (T6/T7 change those boundaries).
#[cfg(test)]
fn execute_outer<T, E, O: CounterObserver>(
    mut allowance: EvaluationAllowance,
    mut control: AttackControl,
    observer: &mut O,
    run: impl FnOnce(&mut ObservedAccounting<'_, O>) -> Result<T, E>,
) -> OuterExecution<T, E> {
    let result = run(&mut ObservedAccounting {
        allowance: &mut allowance,
        control: &mut control,
        observer,
    });
    OuterExecution {
        result,
        allowance,
        control,
    }
}

const _: fn() = || {
    fn assert_sync<T: Sync>() {}
    fn assert_send<T: Send>() {}
    assert_sync::<crate::AttackRequest>();
    assert_sync::<crate::BoundResource>();
    assert_sync::<crate::NgramModel>();
    assert_sync::<crate::TrieModel>();
    assert_sync::<crate::attack_blocks::OuterPlan<'_>>();
    assert_send::<BlockOutcome<DirectOuterOutcome, DirectRunError>>();
    assert_send::<BlockOutcome<ControlledPartialOutcome, ControlledPartialError>>();
};

pub(super) struct ObservedAccounting<'a, O> {
    pub(super) allowance: &'a mut EvaluationAllowance,
    pub(super) control: &'a mut AttackControl,
    pub(super) observer: &'a mut O,
}

impl<O: CounterObserver> EvaluationAccounting for ObservedAccounting<'_, O> {
    type Error = ObservedClimbError;
    fn admit(&mut self) -> Result<(), Self::Error> {
        self.allowance
            .admit()
            .map_err(ObservedClimbError::Counter)?;
        self.transition(AttackControl::record_evaluation_admitted)
    }
    fn transition(
        &mut self,
        record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
    ) -> Result<(), Self::Error> {
        record(self.control).map_err(ObservedClimbError::Counter)
    }
    fn complete(&mut self) -> Result<(), Self::Error> {
        self.control
            .complete(self.observer)
            .map_err(ObservedClimbError::Counter)
    }
}

/// Request polling is independent of counter notification and sticks in the control.
#[cfg(test)]
struct CancellableAccounting<'a, 'b, O, F> {
    observed: &'a mut ObservedAccounting<'b, O>,
    requested: F,
}

#[cfg(test)]
impl<O: CounterObserver, F: FnMut() -> bool> EvaluationAccounting
    for CancellableAccounting<'_, '_, O, F>
{
    type Error = ObservedClimbError;

    fn cancelled(&mut self) -> bool {
        self.observed.control.poll_cancellation((self.requested)())
    }

    fn admit(&mut self) -> Result<(), Self::Error> {
        self.observed.admit()
    }

    fn transition(
        &mut self,
        record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
    ) -> Result<(), Self::Error> {
        self.observed.transition(record)
    }

    fn complete(&mut self) -> Result<(), Self::Error> {
        self.observed.complete()
    }
}

/// Both evaluators share immutable machine, domain, input and decrypt direction.
struct BoundClimbScoring<'a> {
    initial: &'a ResolvedConfiguration,
    domain: &'a AttackPlugboardDomain,
    initial_evaluator: TrialEvaluator<'a>,
    final_evaluator: TrialEvaluator<'a>,
    identical: bool,
    switch_pairs: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScoredBoard {
    pub(crate) board: MutableBoard,
    pub(crate) plaintext: String,
    pub(crate) score: MeasuredScore,
}

struct ScoringState<'c, 'a> {
    context: &'c BoundClimbScoring<'a>,
    current: ScoredBoard,
    final_phase: bool,
    known_final: bool,
}

#[derive(Debug)]
pub(crate) struct ClimbOutcome {
    pub(crate) current: Option<ScoredBoard>,
    pub(crate) incomplete: bool,
    pub(crate) cancelled: bool,
    pub(crate) final_objective_ascent: bool,
    pub(crate) neighborhood_exhausted: bool,
}

#[derive(Debug)]
pub(crate) struct SeedBest {
    pub(crate) seed_index: u128,
    pub(crate) current: ScoredBoard,
    pub(crate) incomplete: bool,
    pub(crate) final_objective_ascent: bool,
    pub(crate) neighborhood_exhausted: bool,
}

#[derive(Debug)]
pub(crate) struct SeedRunOutcome {
    /// Cumulative usage of the borrowed allowance, including earlier work.
    pub(crate) evaluations_used: u64,
    pub(crate) climbs_started: u128,
    pub(crate) climbs_completed: u128,
    pub(crate) best: Option<SeedBest>,
}

#[derive(Debug)]
struct ControlledSeedOutcome {
    seeds: SeedRunOutcome,
    cancelled: bool,
}

#[derive(Debug)]
struct ControlledSeedError {
    seed_index: Option<u128>,
    source: ObservedClimbError,
    best: Option<Box<SeedBest>>,
}

impl<'a> BoundClimbScoring<'a> {
    #[cfg(test)]
    fn climb_seeds_controlled<O: CounterObserver, F: FnMut() -> bool>(
        &self,
        policy: &crate::AttackSeedPolicy,
        backtrack_pairs: usize,
        accounting: &mut ObservedAccounting<'_, O>,
        requested: &mut F,
    ) -> Result<ControlledSeedOutcome, ControlledSeedError> {
        self.climb_seeds_controlled_with(
            policy,
            accounting,
            requested,
            |_, board, accounting, requested| {
                self.climb_cancellable(board, backtrack_pairs, accounting, requested)
            },
            |seed| ControlFlow::Continue(Some(seed)),
        )
    }

    fn climb_seeds_controlled_with<A: SeedAccounting, F>(
        &self,
        policy: &crate::AttackSeedPolicy,
        accounting: &mut A,
        requested: &mut F,
        mut climb: impl FnMut(
            u128,
            MutableBoard,
            &mut A,
            &mut F,
        ) -> Result<ClimbOutcome, ObservedClimbError>,
        // Continue(Some) keeps raw strict-best selection; Break stops before later seeds.
        mut accept: impl FnMut(SeedBest) -> ControlFlow<(), Option<SeedBest>>,
    ) -> Result<ControlledSeedOutcome, ControlledSeedError> {
        let run = (|| {
            let seeds = SeedCursor::new(self.initial, self.domain, policy).map_err(|source| {
                ControlledSeedError {
                    seed_index: None,
                    source: TrialEvaluationError::Board(source).into(),
                    best: None,
                }
            })?;
            let mut result = ControlledSeedOutcome {
                seeds: SeedRunOutcome {
                    evaluations_used: accounting.evaluations_used(),
                    climbs_started: 0,
                    climbs_completed: 0,
                    best: None,
                },
                cancelled: false,
            };
            for (seed_index, board) in seeds {
                let outcome =
                    climb(seed_index, board, accounting, &mut *requested).map_err(|source| {
                        ControlledSeedError {
                            seed_index: Some(seed_index),
                            source,
                            best: result.seeds.best.take().map(Box::new),
                        }
                    })?;
                result.cancelled = outcome.cancelled;
                if let Some(current) = outcome.current {
                    result.seeds.climbs_started += 1;
                    if outcome.neighborhood_exhausted {
                        result.seeds.climbs_completed += 1;
                    }
                    let seed = SeedBest {
                        seed_index,
                        current,
                        incomplete: outcome.cancelled || outcome.incomplete,
                        final_objective_ascent: outcome.final_objective_ascent,
                        neighborhood_exhausted: outcome.neighborhood_exhausted,
                    };
                    match accept(seed) {
                        ControlFlow::Break(()) => break,
                        ControlFlow::Continue(Some(seed))
                            if result.seeds.best.as_ref().is_none_or(|best| {
                                seed.current.score.ranking().units()
                                    > best.current.score.ranking().units()
                            }) =>
                        {
                            result.seeds.best = Some(seed);
                        }
                        ControlFlow::Continue(_) => {}
                    }
                }
                if outcome.cancelled {
                    break;
                }
            }
            result.seeds.evaluations_used = accounting.evaluations_used();
            Ok(result)
        })();
        run
    }

    // Legacy scoring wrappers retain route-equivalence regression coverage.
    #[cfg(test)]
    fn climb_seeds(
        &self,
        policy: &crate::AttackSeedPolicy,
        backtrack_pairs: usize,
        allowance: &mut EvaluationAllowance,
    ) -> Result<SeedRunOutcome, TrialEvaluationError> {
        let seeds = SeedCursor::new(self.initial, self.domain, policy)
            .map_err(TrialEvaluationError::Board)?;
        let mut result = SeedRunOutcome {
            evaluations_used: allowance.used,
            climbs_started: 0,
            climbs_completed: 0,
            best: None,
        };
        for (seed_index, board) in seeds {
            let outcome = self.climb(board, backtrack_pairs, allowance)?;
            let Some(current) = outcome.current else {
                break;
            };
            // Each counter is bounded by SeedCursor's scalar pair count, fits
            // u128 like the gate, and never narrows to a platform-sized index.
            result.climbs_started = result
                .climbs_started
                .checked_add(1)
                .expect("scalar seed count fits u128");
            if outcome.neighborhood_exhausted && !outcome.incomplete {
                result.climbs_completed = result
                    .climbs_completed
                    .checked_add(1)
                    .expect("completed climbs cannot exceed scalar seed count");
            }
            if result.best.as_ref().is_none_or(|best| {
                current.score.ranking().units() > best.current.score.ranking().units()
            }) {
                result.best = Some(SeedBest {
                    seed_index,
                    current,
                    incomplete: outcome.incomplete,
                    final_objective_ascent: outcome.final_objective_ascent,
                    neighborhood_exhausted: outcome.neighborhood_exhausted,
                });
            }
            if outcome.incomplete {
                break;
            }
        }
        result.evaluations_used = allowance.used;
        Ok(result)
    }

    #[cfg(test)]
    fn climb(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        allowance: &mut EvaluationAllowance,
    ) -> Result<ClimbOutcome, TrialEvaluationError> {
        self.climb_accounted(board, backtrack_pairs, allowance)
    }

    #[cfg(test)]
    fn climb_cancellable(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
        requested: impl FnMut() -> bool,
    ) -> Result<ClimbOutcome, ObservedClimbError> {
        self.climb_accounted(
            board,
            backtrack_pairs,
            &mut CancellableAccounting {
                observed: accounting,
                requested,
            },
        )
    }

    fn climb_accounted<A: EvaluationAccounting>(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        allowance: &mut A,
    ) -> Result<ClimbOutcome, A::Error> {
        let mut cancelled = allowance.cancelled();
        if cancelled {
            return Ok(ClimbOutcome {
                current: None,
                incomplete: true,
                cancelled,
                final_objective_ascent: false,
                neighborhood_exhausted: false,
            });
        }
        let mut state = self.start(board, allowance)?;
        allowance.transition(AttackControl::record_climb_started)?;
        allowance.cancelled();
        let mut final_objective_ascent = false;
        let neighborhood_exhausted = loop {
            // Build from this state's context, never an independently bound evaluator.
            let selection = NeighborhoodSelection {
                initial: self.initial,
                domain: self.domain,
                evaluator: if state.final_phase {
                    &self.final_evaluator
                } else {
                    &self.initial_evaluator
                },
                backtrack_pairs,
            };
            let outcome = selection.scan(
                &state.current.board,
                state.current.score.ranking(),
                allowance,
            )?;
            match outcome {
                ScanOutcome::Cancelled => {
                    cancelled = true;
                    break false;
                }
                ScanOutcome::Complete(winner) => {
                    final_objective_ascent |= state.final_phase || self.identical;
                    let Some(winner) = winner else { break true };
                    state = state.commit_trial(winner, allowance)?;
                    allowance.cancelled();
                }
            }
        };
        // Final rescoring is required even after cancellation; errors still propagate.
        // Consuming finalization cannot run twice.
        let current = state.finalize(allowance)?;
        if neighborhood_exhausted {
            allowance.transition(AttackControl::record_climb_completed)?;
        }
        Ok(ClimbOutcome {
            current: Some(current),
            incomplete: !neighborhood_exhausted,
            cancelled,
            final_objective_ascent,
            neighborhood_exhausted,
        })
    }

    fn new(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        input: &'a str,
        first: (MeasureId, Option<&'a BoundResource>),
        last: (MeasureId, Option<&'a BoundResource>),
        switch_pairs: usize,
    ) -> Self {
        let same_resource = match (first.1, last.1) {
            (None, None) => true,
            (Some(a), Some(b)) => std::ptr::eq(a, b),
            _ => false,
        };
        Self {
            initial,
            domain,
            initial_evaluator: TrialEvaluator::new(
                initial,
                domain,
                input,
                Direction::Decrypt,
                first.0,
                first.1,
            ),
            final_evaluator: TrialEvaluator::new(
                initial,
                domain,
                input,
                Direction::Decrypt,
                last.0,
                last.1,
            ),
            identical: first.0 == last.0 && same_resource,
            switch_pairs,
        }
    }

    fn with_preparation(mut self, preparation: &'a RunPreparation<'a>, outer_index: u128) -> Self {
        self.initial_evaluator = preparation.evaluator(
            self.initial,
            outer_index,
            self.initial_evaluator.objective(),
        );
        self.final_evaluator =
            preparation.evaluator(self.initial, outer_index, self.final_evaluator.objective());
        self
    }

    fn start<A: EvaluationAccounting>(
        &self,
        board: MutableBoard,
        allowance: &mut A,
    ) -> Result<ScoringState<'_, 'a>, A::Error> {
        validated_trial_board(self.initial, self.domain, &board)
            .map_err(TrialEvaluationError::Board)?;
        let final_phase = self.domain.fixed_pairs().len() + board.len() >= self.switch_pairs;
        let known_final = final_phase || self.identical;
        let evaluator = if final_phase {
            &self.final_evaluator
        } else {
            &self.initial_evaluator
        };
        let (plaintext, score) = allowance.evaluate(evaluator, &board)?;
        Ok(ScoringState {
            context: self,
            current: ScoredBoard {
                board,
                plaintext,
                score,
            },
            final_phase,
            known_final,
        })
    }
}

impl ScoringState<'_, '_> {
    /// Consuming the state makes finalization once-only; it never starts another ascent.
    fn finalize<A: EvaluationAccounting>(
        mut self,
        allowance: &mut A,
    ) -> Result<ScoredBoard, A::Error> {
        if !self.known_final {
            let (plaintext, score) =
                allowance.evaluate(&self.context.final_evaluator, &self.current.board)?;
            self.current.plaintext = plaintext;
            self.current.score = score;
        }
        Ok(self.current)
    }

    /// Precondition for 11.4b.2: trial is a complete-scan-selected strict winner,
    /// evaluated with THIS context's current objective; its call was already charged.
    /// This lifecycle does not verify selection.
    /// Consuming self prevents an unscored committed board escaping on any error.
    fn commit_trial<A: EvaluationAccounting>(
        mut self,
        trial: ScoredBoard,
        allowance: &mut A,
    ) -> Result<Self, A::Error> {
        validated_trial_board(self.context.initial, self.context.domain, &trial.board)
            .map_err(TrialEvaluationError::Board)?;
        self.current = trial;
        self.known_final = self.final_phase || self.context.identical;
        if !self.final_phase
            && self.context.domain.fixed_pairs().len() + self.current.board.len()
                >= self.context.switch_pairs
        {
            self.final_phase = true;
            if !self.known_final {
                let (plaintext, score) =
                    allowance.evaluate(&self.context.final_evaluator, &self.current.board)?;
                self.current.plaintext = plaintext;
                self.current.score = score;
            }
            self.known_final = true;
        }
        Ok(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ScanOutcome {
    Complete(Option<ScoredBoard>),
    Cancelled,
}

pub(super) struct NeighborhoodSelection<'a> {
    pub(super) initial: &'a ResolvedConfiguration,
    pub(super) domain: &'a AttackPlugboardDomain,
    pub(super) evaluator: &'a TrialEvaluator<'a>,
    pub(super) backtrack_pairs: usize,
}

impl NeighborhoodSelection<'_> {
    fn scan<A: EvaluationAccounting>(
        &self,
        current: &[(char, char)],
        ranking: FixedScore,
        allowance: &mut A,
    ) -> Result<ScanOutcome, A::Error> {
        // The walker owns its mapping, so no early return can leak an applied trial.
        let mut walker =
            NeighborhoodWalker::validated(self.initial, self.domain, current, self.backtrack_pairs)
                .map_err(TrialEvaluationError::Board)?;
        let mut best = None;
        let mut best_ranking = ranking;
        while let Some(action) = walker.next_action() {
            if allowance.cancelled() {
                return Ok(ScanOutcome::Cancelled);
            }
            walker.apply(action);
            let scored = allowance.evaluate_score_mapped(self.evaluator, walker.mapping());
            walker.restore();
            let (plaintext, score) = scored?;
            if score.ranking().units() > best_ranking.units() {
                best_ranking = score.ranking();
                best = Some((walker.selected(action), plaintext, score));
            }
            if allowance.cancelled() {
                // A completed losing scan has already established exhaustion.
                if best.is_none() && !walker.has_next() {
                    return Ok(ScanOutcome::Complete(None));
                }
                return Ok(ScanOutcome::Cancelled);
            }
        }
        // Only a completed scan's winner gets a board and plaintext; streamed
        // winners replay once, outside accounting.
        let winner = match best {
            Some((trial, plaintext, score)) => {
                let symbols = &self.initial.topology().alphabet().symbols;
                let board = walker.winner_board(&trial, symbols);
                Some(ScoredBoard {
                    plaintext: match plaintext {
                        Some(plaintext) => plaintext,
                        None => self.evaluator.replay_plaintext(&board)?,
                    },
                    board,
                    score,
                })
            }
            None => None,
        };
        Ok(ScanOutcome::Complete(winner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DefinitionSource, Direction, MeasureId, SlotConfiguration, TransformConfiguration,
    };

    #[derive(Default)]
    struct Recorder(Vec<crate::attack_control::CounterSnapshot>);

    impl CounterObserver for Recorder {
        fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
            self.0.push(snapshot);
        }
    }

    /// Test-only accounting decorator: inspect live facts only when the driver
    /// polls cancellation, never through the public observation stream.
    struct PollingAccounting<'a, 'b, O, F> {
        inner: &'a mut ObservedAccounting<'b, O>,
        stop: F,
    }

    impl<O: CounterObserver, F: FnMut(crate::attack_control::CounterSnapshot) -> bool>
        EvaluationAccounting for PollingAccounting<'_, '_, O, F>
    {
        type Error = ObservedClimbError;
        fn cancelled(&mut self) -> bool {
            let stop = (self.stop)(self.inner.control.snapshot());
            self.inner.control.poll_cancellation(stop)
        }
        fn admit(&mut self) -> Result<(), Self::Error> {
            self.inner.admit()
        }
        fn complete(&mut self) -> Result<(), Self::Error> {
            self.inner.complete()
        }
        fn transition(
            &mut self,
            record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
        ) -> Result<(), Self::Error> {
            self.inner.transition(record)
        }
    }

    fn climb_stopping_when(
        scoring: &BoundClimbScoring<'_>,
        board: MutableBoard,
        backtrack: usize,
        accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
        stop: impl FnMut(crate::attack_control::CounterSnapshot) -> bool,
    ) -> Result<ClimbOutcome, ObservedClimbError> {
        scoring.climb_accounted(
            board,
            backtrack,
            &mut PollingAccounting {
                inner: accounting,
                stop,
            },
        )
    }

    fn run_cancellation(
        context: &BoundClimbScoring<'_>,
        stop_poll: usize,
    ) -> (
        Result<ClimbOutcome, ObservedClimbError>,
        crate::attack_control::CounterSnapshot,
        u64,
        usize,
    ) {
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let mut polls = 0;
        let result = context.climb_cancellable(
            vec![],
            0,
            &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            },
            || {
                polls += 1;
                polls == stop_poll
            },
        );
        let snapshot = control.snapshot();
        assert!(
            observer.0.is_empty(),
            "private climbs have no lifecycle notifications"
        );
        assert_eq!(snapshot.outers_completed, 0);
        (result, snapshot, allowance.used - 7, polls)
    }

    /// Serial reference retains the former flat projection and run-wide cache.
    /// Selection, projection and stages deliberately use the production reducers.
    fn flat_serial_reference(
        request: &crate::AttackRequest,
    ) -> (String, Vec<crate::AttackProgress>) {
        let preparation = RunPreparation::new(request);
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut control = AttackControl::with_progress_every(request.settings().progress_every());
        let mut events = Vec::new();
        let mut observer = ProgressObserver(|p| events.push(p));
        let result = observed_run(&mut control, &mut observer, |control, observer| {
            let accounting = &mut ObservedAccounting {
                allowance: &mut allowance,
                control,
                observer,
            };
            let mut requested = || false;
            let capacity = request.settings().hold_capacity();
            let mut result = if request.settings().kind() == crate::AttackKind::PartialExhaustion {
                schedule_controlled_partial_with_climb(
                    request.gate().outer_selected(),
                    request.outer_candidates(),
                    accounting,
                    &mut requested,
                    |initial, index, accounting, requested| {
                        request.climb_partial_outer_prepared(
                            &preparation,
                            (initial, index),
                            accounting,
                            requested,
                            capacity,
                            |scoring, _, board, accounting, requested| {
                                scoring.climb_cancellable(
                                    board,
                                    request.settings().backtrack_pairs(),
                                    accounting,
                                    requested,
                                )
                            },
                        )
                    },
                )
                .unwrap()
                .project_public(
                    accounting.control.snapshot(),
                    request.domain(),
                    request.settings().final_measure(),
                )?
            } else {
                let mut acceptance = DirectAcceptance::new(capacity);
                let run = schedule_controlled_direct(
                    request.gate().outer_selected(),
                    request.outer_candidates(),
                    accounting,
                    &mut requested,
                    |initial, index, accounting, requested| {
                        let (scoring, start) = request
                            .direct_scoring(&initial)
                            .map_err(DirectRunError::Climb)?;
                        let climb = scoring
                            .with_preparation(&preparation, index)
                            .climb_cancellable(
                                start,
                                request.settings().backtrack_pairs(),
                                accounting,
                                requested,
                            )
                            .map_err(DirectRunError::from)?;
                        Ok(DirectOuterOutcome {
                            initial,
                            outer_index: index,
                            start_index: 0,
                            climb,
                        })
                    },
                    |outcome| {
                        acceptance.accept(
                            outcome,
                            request.domain(),
                            request.settings().final_measure(),
                        )
                    },
                );
                acceptance.finish(
                    run,
                    accounting.control.snapshot(),
                    request.domain(),
                    request.settings().final_measure(),
                )?
            };
            if !request.settings().stages().is_empty() && result.best.is_some() {
                result = stages_over_hold(result, |result| {
                    request.finalist_stages_prepared(
                        &preparation,
                        result,
                        accounting,
                        &mut requested,
                    )
                })?;
            }
            Ok(result)
        });
        (format!("{result:?}"), events)
    }

    #[test]
    fn block_serial_matches_flat_projection_and_run_wide_preparation() {
        for pe in [false, true] {
            for hold in [1, 5] {
                for staged in [false, true] {
                    let mut value = serde_json::json!({"protocol_version":1,
                        "machine":{"definition":{"kind":"custom","value":{
                            "alphabet":["A","B","C","D"],
                            "wheels":[{"name":"r","wiring":["B","C","D","A"],"turnovers":[]}],
                            "slots":[{"id":"x","role":"rotor","movement":"fixed","wheel":"r"},
                                     {"id":"y","role":"rotor","movement":"fixed","wheel":"r"}],
                            "stepping":{"rules":[]}}}},
                        "job":{"kind":"search","configuration":{"slots":[],"plugboard":[]},
                            "text":"ABACAD","passes":[if pe {"partial_exhaustion"} else {"hill_climb"}],
                            "measures":["ic"],"space":{"offset":3,"limit":200,
                                "slots":[{"id":"x","positions":["D","B","A","C"],"rings":["A","B","C","D"]},
                                         {"id":"y","positions":["D","B","A","C"],"rings":["A","B","C","D"]}],
                                "plugboard":{"kind":"attack","symbols":["A","B","C","D"],"max_pairs":1}},
                            "attack":{"kind":if pe {"partial_exhaustion"} else {"hill_climb"},
                                "initial_measure":"ic","final_measure":"ic","switch_pairs":1,
                                "backtrack_pairs":0,"hold":hold,"progress_every":3}}});
                    if pe {
                        value["job"]["attack"]["seeds"] =
                            serde_json::json!({"kind":"empty_single","selection":"all"});
                    } else {
                        value["job"]["attack"]["start"] = serde_json::json!([]);
                    }
                    if staged {
                        value["job"]["passes"]
                            .as_array_mut()
                            .unwrap()
                            .push(serde_json::json!("measure"));
                        value["job"]["attack"]["measure"] = serde_json::json!({"measure":"ic"});
                    }
                    let request = crate::AttackRequest::parse_json(&value.to_string()).unwrap();
                    assert_eq!(request.outer_plan().blocks().count(), 2);
                    let expected = flat_serial_reference(&request);
                    let mut events = Vec::new();
                    let result = request.run(|p| events.push(p), || false);
                    assert_eq!(
                        format!("{result:?}"),
                        expected.0,
                        "pe={pe}, hold={hold}, staged={staged}"
                    );
                    let per_outer = if pe { 67 } else { 7 };
                    let outer_end = 200 * per_outer;
                    let mut counts = vec![0, 128 * per_outer, outer_end];
                    if staged {
                        counts.extend(
                            (outer_end + 1..=outer_end + hold).filter(|count| count % 3 == 0),
                        );
                    }
                    counts.push(outer_end + if staged { hold } else { 0 });
                    assert_eq!(
                        events
                            .iter()
                            .map(|p| p.evaluations_completed())
                            .collect::<Vec<_>>(),
                        counts
                    );
                    for every in [1, 100_000] {
                        value["job"]["attack"]["progress_every"] = serde_json::json!(every);
                        let request = crate::AttackRequest::parse_json(&value.to_string()).unwrap();
                        let mut snapshots = Vec::new();
                        let completed = request.run(|p| snapshots.push(p), || false).unwrap();
                        let mut counts = vec![0];
                        if every == 1 {
                            counts.extend([128 * per_outer, outer_end]);
                            if staged {
                                counts.extend(outer_end + 1..=outer_end + hold);
                            }
                        }
                        counts.push(outer_end + if staged { hold } else { 0 });
                        assert_eq!(
                            snapshots
                                .iter()
                                .map(|p| p.evaluations_completed())
                                .collect::<Vec<_>>(),
                            counts
                        );
                        assert_eq!(format!("Ok({completed:?})"), expected.0);
                        let mut polls = 0;
                        let stopped = request
                            .run(
                                |_| {},
                                || {
                                    polls += 1;
                                    polls == 2
                                },
                            )
                            .unwrap();
                        assert_eq!(polls, 2);
                        assert_eq!(stopped.termination(), crate::AttackTermination::Cancelled);
                        assert_eq!(
                            stopped.counters().0,
                            crate::attack_control::CounterSnapshot {
                                evaluations_admitted: 128 * per_outer,
                                evaluations_completed: 128 * per_outer,
                                climbs_started: 128 * if pe { 7 } else { 1 },
                                climbs_completed: 128 * if pe { 7 } else { 1 },
                                outers_completed: 128,
                            }
                        );
                        assert!(stopped
                            .hold()
                            .all(|entry| !entry.best().incomplete() && entry.stages().is_empty()));
                        let before = request.run(|_| {}, || true).unwrap();
                        assert_eq!(before.termination(), crate::AttackTermination::Cancelled);
                        assert_eq!(before.counters().0, Default::default());
                        assert!(before.best().is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn public_completed_pe_blocks_pin_final_counts_and_seeds() {
        for distinct in [false, true] {
            for touching in [false, true] {
                for multiple in [false, true] {
                    let request = direct_request_with(
                        serde_json::json!([]),
                        distinct,
                        true,
                        |job| {
                            if touching {
                                job["attack"]["seeds"] = serde_json::json!({"kind":"empty_single","selection":"touching","symbols":["C"]});
                            }
                            if multiple {
                                job["configuration"]["slots"][0]
                                    .as_object_mut()
                                    .unwrap()
                                    .remove("position");
                                job["space"]["slots"] =
                                    serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
                            }
                        },
                    );
                    let result = request.run(|_| {}, || false).unwrap();
                    let used = match (distinct, touching, multiple) {
                        (false, false, false) => 32,
                        (false, false, true) => 96,
                        (false, true, false) => 21,
                        (false, true, true) => 73,
                        (true, false, false) => 28,
                        (true, false, true) => 84,
                        (true, true, false) => 17,
                        (true, true, true) => 61,
                    };
                    let climbs = if touching { 3 } else { 4 } * if multiple { 3 } else { 1 };
                    public_pe_facts(
                        &result,
                        crate::AttackTermination::Completed,
                        (used, climbs, climbs, if multiple { 3 } else { 1 }),
                        Some((0, u128::from(distinct), "CB", 2, false, true, true)),
                    );
                }
            }
        }
    }

    #[test]
    fn public_outer_phase_observes_only_finished_blocks() {
        for pe in [false, true] {
            let request = hold_stages_request(pe, &[], 5);
            let mut events = Vec::new();
            let mut polls = 0;
            let result = request
                .run(
                    |p| events.push(p),
                    || {
                        polls += 1;
                        polls > 1
                    },
                )
                .unwrap();
            assert_eq!(
                polls, 1,
                "exhaustion prevents a speculative final stop poll"
            );
            assert_eq!(result.termination(), crate::AttackTermination::Completed);
            assert_eq!(
                events,
                vec![crate::AttackProgress(Default::default()), result.counters()]
            );
        }
    }

    /// Three fixed slots of 16 settings each: 4,096 outer keys, 32 blocks.
    fn pool_request(
        pe: bool,
        hold: u64,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> crate::AttackRequest {
        let ids = ["x", "y", "z"];
        let machine_slots = ids
            .map(|id| serde_json::json!({"id":id,"role":"rotor","movement":"fixed","wheel":"r"}));
        let space_slots = ids.map(|id| {
            serde_json::json!({"id":id,"positions":["D","B","A","C"],"rings":["A","B","C","D"]})
        });
        let kind = if pe {
            "partial_exhaustion"
        } else {
            "hill_climb"
        };
        let mut value = serde_json::json!({"protocol_version":1,
            "machine":{"definition":{"kind":"custom","value":{
                "alphabet":["A","B","C","D"],
                "wheels":[{"name":"r","wiring":["B","C","D","A"],"turnovers":[]}],
                "slots":machine_slots,
                "stepping":{"rules":[]}}}},
            "job":{"kind":"search","configuration":{"slots":[],"plugboard":[]},
                "text":"ABACAD","passes":[kind],"measures":["ic"],
                "space":{"slots":space_slots,
                    "plugboard":{"kind":"attack","symbols":["A","B","C","D"],"max_pairs":1}},
                "attack":{"kind":kind,"initial_measure":"ic","final_measure":"ic",
                    "switch_pairs":1,"backtrack_pairs":0,"hold":hold}}});
        let attack = &mut value["job"]["attack"];
        if pe {
            attack["seeds"] = serde_json::json!({"kind":"empty_single","selection":"all"});
        } else {
            attack["start"] = serde_json::json!([]);
        }
        edit(&mut value["job"]);
        crate::AttackRequest::parse_json(&value.to_string()).unwrap()
    }

    fn pooled(
        request: &crate::AttackRequest,
        threads: usize,
        hooks: &PoolHooks,
        cancel: impl FnMut() -> bool,
    ) -> (String, Vec<crate::AttackProgress>) {
        let options = crate::ExecutionOptions::with_threads(threads).unwrap();
        let mut events = Vec::new();
        let result = request.run_pooled(options, hooks, |p| events.push(p), cancel);
        (format!("{result:?}"), events)
    }

    /// Waits on `condvar` until `ready`; a timeout fails the calling worker instead
    /// of hanging the test when the expected concurrency never happens.
    fn wait_for<'a, T>(
        condvar: &std::sync::Condvar,
        guard: std::sync::MutexGuard<'a, T>,
        what: &str,
        mut ready: impl FnMut(&T) -> bool,
    ) -> std::sync::MutexGuard<'a, T> {
        let timeout = std::time::Duration::from_secs(30);
        let (guard, wait) = condvar
            .wait_timeout_while(guard, timeout, |state| !ready(state))
            .unwrap();
        assert!(!wait.timed_out(), "timed out waiting for {what}");
        guard
    }

    #[test]
    fn pool_workers_run_blocks_concurrently() {
        use std::sync::{Arc, Condvar, Mutex};
        for threads in [2, 4, 8] {
            let limit = 2 * threads as u64 * 128;
            let request = pool_request(false, 1, |job| job["space"]["limit"] = limit.into());
            let seen = Arc::new((
                Mutex::new(std::collections::BTreeSet::new()),
                Condvar::new(),
            ));
            let state = Arc::clone(&seen);
            // Every worker holds its first block until all `threads` workers hold
            // one: this only completes when that many workers run at once.
            let hooks = PoolHooks {
                ran: Some(Box::new(move |worker, _, _| {
                    let (lock, condvar) = &*state;
                    let mut workers = lock.lock().unwrap();
                    if workers.insert(worker) {
                        condvar.notify_all();
                        let what = format!("{threads} concurrent workers");
                        drop(wait_for(condvar, workers, &what, |w| w.len() >= threads));
                    }
                })),
                sent: None,
            };
            let parallel = pooled(&request, threads, &hooks, || false);
            assert_eq!(
                *seen.0.lock().unwrap(),
                (0..threads).collect(),
                "{threads} distinct workers"
            );
            assert_eq!(
                parallel,
                pooled(&request, 1, &PoolHooks::default(), || false)
            );
        }
    }

    #[test]
    fn pool_reduction_ignores_block_completion_order() {
        use std::sync::{Arc, Condvar, Mutex};
        for pe in [false, true] {
            for hold in [1, 5] {
                for threads in [2, 4] {
                    // Seven blocks; the last group of the permutation is partial.
                    let request = pool_request(pe, hold, |job| {
                        job["space"]["limit"] = (7 * 128 - 5).into();
                        job["attack"]["progress_every"] = 3.into();
                    });
                    // Blocks reach the coordinator in reversed groups of `threads`.
                    let order: Vec<u128> = (0..7u128)
                        .collect::<Vec<_>>()
                        .chunks(threads)
                        .flat_map(|group| group.iter().rev().copied().collect::<Vec<_>>())
                        .collect();
                    let sent = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
                    let (ran_state, sent_state) = (Arc::clone(&sent), Arc::clone(&sent));
                    let expected = order.clone();
                    let hooks = PoolHooks {
                        ran: Some(Box::new(move |_, block, _| {
                            let (lock, condvar) = &*ran_state;
                            let sent = lock.lock().unwrap();
                            drop(wait_for(condvar, sent, "send turn", |sent: &Vec<u128>| {
                                expected[sent.len()] == block.index
                            }));
                        })),
                        sent: Some(Box::new(move |_, block| {
                            let (lock, condvar) = &*sent_state;
                            lock.lock().unwrap().push(block.index);
                            condvar.notify_all();
                        })),
                    };
                    let shuffled = pooled(&request, threads, &hooks, || false);
                    assert_eq!(*sent.0.lock().unwrap(), order);
                    let serial = pooled(&request, 1, &PoolHooks::default(), || false);
                    assert_eq!(shuffled, serial, "pe={pe}, hold={hold}, threads={threads}");
                    assert!(serial.0.starts_with("Ok("));
                }
            }
        }
    }

    #[test]
    fn pool_matches_serial_matrix() {
        type Edit = fn(&mut serde_json::Value);
        let cases: [(Edit, bool); 3] = [
            (|job| job["space"]["limit"] = 1000.into(), false),
            (
                |job| {
                    job["space"]["offset"] = 3.into();
                    job["space"]["limit"] = 700.into();
                    job["attack"]["progress_every"] = 1.into();
                    job["passes"].as_array_mut().unwrap().push("measure".into());
                    job["attack"]["measure"] = serde_json::json!({"measure":"ic"});
                },
                true,
            ),
            (
                |job| {
                    job["space"]["offset"] = 130.into();
                    job["space"]["limit"] = 900.into();
                    job["attack"]["progress_every"] = 3.into();
                },
                false,
            ),
        ];
        for pe in [false, true] {
            for hold in [1, 5] {
                for (case, (edit, staged)) in cases.iter().enumerate() {
                    let request = pool_request(pe, hold, edit);
                    let mut variants = vec![("plain", PoolHooks::default())];
                    if case == 0 {
                        // A later block fails at its fourth key, in every thread count.
                        variants.push((
                            "error",
                            PoolHooks {
                                ran: Some(Box::new(|_, block, outcome| {
                                    fn fail<T, E>(
                                        block: OuterBlock,
                                        outcome: &mut BlockOutcome<T, E>,
                                    ) {
                                        outcome.outers.truncate(3);
                                        outcome.error = Some((
                                            block.start + 3,
                                            BlockFailure::Resolution(vec![]),
                                        ));
                                    }
                                    if block.index == 3 {
                                        match outcome {
                                            PhaseBlock::Direct(outcome) => fail(block, outcome),
                                            PhaseBlock::Partial(outcome) => fail(block, outcome),
                                        }
                                    }
                                })),
                                sent: None,
                            },
                        ));
                        if !pe {
                            // Every outer reports the first key's slots, so equal
                            // boards from different blocks are duplicate offers.
                            let first = request.outer_candidates().next().unwrap().1.unwrap();
                            variants.push((
                                "duplicates",
                                PoolHooks {
                                    ran: Some(Box::new(move |_, _, outcome| {
                                        if let PhaseBlock::Direct(outcome) = outcome {
                                            for outer in &mut outcome.outers {
                                                outer.initial = first.clone();
                                            }
                                        }
                                    })),
                                    sent: None,
                                },
                            ));
                        }
                    }
                    for (variant, hooks) in &variants {
                        let serial = pooled(&request, 1, hooks, || false);
                        assert_eq!(serial.0.starts_with("Err("), *variant == "error");
                        if *staged {
                            assert!(serial.0.contains("AttackStageResult"));
                        }
                        for threads in [2, 4, 8] {
                            assert_eq!(
                                pooled(&request, threads, hooks, || false),
                                serial,
                                "pe={pe}, hold={hold}, case={case}, {variant}, threads={threads}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pool_cancellation_commits_a_key_order_prefix() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for pe in [false, true] {
            let request = pool_request(pe, 5, |job| job["space"]["limit"] = (12 * 128).into());
            for threads in [2, 4] {
                let ran = std::sync::Arc::new(AtomicUsize::new(0));
                let counted = std::sync::Arc::clone(&ran);
                let hooks = PoolHooks {
                    ran: Some(Box::new(move |_, _, _| {
                        counted.fetch_add(1, Ordering::Relaxed);
                    })),
                    sent: None,
                };
                let before = pooled(&request, threads, &hooks, || true);
                assert_eq!(before, pooled(&request, 1, &PoolHooks::default(), || true));
                assert_eq!(ran.load(Ordering::Relaxed), 0, "no outer work");

                let options = crate::ExecutionOptions::with_threads(threads).unwrap();
                let mut polls = 0;
                let stopped = request
                    .run_with(
                        options,
                        |_| {},
                        || {
                            polls += 1;
                            polls == 2
                        },
                    )
                    .unwrap();
                assert_eq!(stopped.termination(), crate::AttackTermination::Cancelled);
                let outers = stopped.counters().outers_completed();
                let blocks = outers / 128;
                assert_eq!(outers % 128, 0, "only whole blocks are committed");
                assert!(
                    (1..12).contains(&blocks),
                    "pe={pe}, threads={threads}: {blocks}"
                );
                // The serial run stopped before block `blocks` holds exactly those blocks.
                let mut serial_polls = 0;
                let prefix = request.run(
                    |_| {},
                    || {
                        serial_polls += 1;
                        serial_polls == blocks + 1
                    },
                );
                assert_eq!(format!("{:?}", Ok::<_, ()>(stopped)), format!("{prefix:?}"));
            }
        }
    }

    #[test]
    fn worker_block_runner_matches_serial_on_another_thread() {
        fn compare<T, E>(
            run: impl Fn() -> BlockOutcome<T, E> + Send,
            reference: &crate::AttackResult,
        ) where
            T: Send + std::fmt::Debug,
            E: Send + std::fmt::Debug,
        {
            let serial = run();
            assert_eq!(serial.accounting.control.snapshot(), reference.counters().0);
            assert_eq!(serial.accounting.used, reference.evaluations_used());
            assert_eq!(
                serial.outers.len() as u128,
                reference.counters().outers_completed()
            );
            // The actual owned outcome crosses the thread boundary, not a
            // projection made inside the worker. Its preparation stays local.
            let threaded = std::thread::scope(|scope| scope.spawn(run).join().unwrap());
            assert!(serial.error.is_none() && threaded.error.is_none());
            assert_eq!(
                format!("{:?}", serial.outers),
                format!("{:?}", threaded.outers)
            );
            assert_eq!(serial.accounting.used, threaded.accounting.used);
            assert_eq!(
                serial.accounting.control.snapshot(),
                threaded.accounting.control.snapshot()
            );
        }
        for pe in [false, true] {
            for hold in [1, 5] {
                let request = hold_stages_request(pe, &[], hold);
                let plan = request.outer_plan();
                let block = plan.blocks().next().unwrap();
                let reference = request.run(|_| {}, || false).unwrap();
                if pe {
                    compare(
                        || request.run_partial_block(&RunPreparation::new(&request), &plan, block),
                        &reference,
                    );
                } else {
                    compare(
                        || request.run_direct_block(&RunPreparation::new(&request), &plan, block),
                        &reference,
                    );
                }
            }
        }
    }

    #[test]
    fn worker_later_block_error_keeps_work_before_first_failed_evaluation() {
        let request = hold_stages_request(false, &[], 1);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let resolved = std::cell::Cell::new(0);
        let run = |start| {
            run_worker_block(
                (start..start + crate::attack_blocks::OUTER_BLOCK_KEYS).map(|index| {
                    resolved.set(resolved.get() + 1);
                    (index, Ok(initial.clone()))
                }),
                |initial, index, accounting| {
                    let evaluator = TrialEvaluator::new(
                        &initial,
                        request.domain(),
                        if index >= 130 { "?" } else { request.text() },
                        Direction::Decrypt,
                        MeasureId::Ic,
                        None,
                    );
                    accounting.evaluate(&evaluator, &[])?;
                    Ok::<_, ObservedClimbError>(index)
                },
            )
        };
        let first = run(0);
        assert_eq!(first.outers, (0..128).collect::<Vec<_>>());
        assert!(first.error.is_none());
        assert_eq!(first.accounting.used, 128);
        let later = run(128);
        assert_eq!(later.outers, [128, 129]);
        assert!(matches!(
            later.error,
            Some((
                130,
                BlockFailure::Climb(ObservedClimbError::Evaluation(TrialEvaluationError::Model(
                    crate::ModelError::UnknownSymbol('?')
                )))
            ))
        ));
        assert_eq!(
            resolved.get(),
            131,
            "no key after the first error is resolved"
        );
        assert_eq!(later.accounting.used, 3);
        assert_eq!(
            later.accounting.control.snapshot(),
            crate::attack_control::CounterSnapshot {
                evaluations_admitted: 3,
                evaluations_completed: 2,
                outers_completed: 2,
                ..Default::default()
            }
        );
    }

    #[test]
    fn worker_duplicate_across_blocks_preserves_first_offered_payload() {
        for capacity in [1, 5] {
            let request = hold_stages_request(false, &[], capacity);
            let preparation = RunPreparation::new(&request);
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let mut hold = crate::attack_hold::AttackHold::new(capacity as usize);
            for start in [0, crate::attack_blocks::OUTER_BLOCK_KEYS] {
                let block = run_worker_block(
                    (start..start + crate::attack_blocks::OUTER_BLOCK_KEYS)
                        .map(|index| (index, Ok(initial.clone()))),
                    |initial, index, accounting| {
                        let (scoring, board) = request
                            .direct_scoring(&initial)
                            .map_err(DirectRunError::Climb)?;
                        let climb = scoring
                            .with_preparation(&preparation, index)
                            .climb_accounted(board, 0, accounting)
                            .map_err(DirectRunError::from)?;
                        let mut best = DirectOuterOutcome {
                            initial,
                            outer_index: index,
                            start_index: 0,
                            climb,
                        }
                        .project(request.domain(), request.settings().final_measure())
                        .map_err(DirectRunError::Projection)?;
                        best.plaintext = format!("payload-{index}");
                        Ok::<_, DirectRunError>(best)
                    },
                );
                assert!(block.error.is_none());
                assert_eq!(block.accounting.control.snapshot().outers_completed, 128);
                for best in block.outers {
                    hold.offer(best);
                }
                assert_eq!(hold.entries().len(), 1);
                assert_eq!(hold.entries()[0].outer_index, 0);
                assert_eq!(hold.entries()[0].plaintext, "payload-0");
            }
        }
    }

    #[test]
    fn outer_execution_returns_owned_accounting_even_on_error() {
        let mut control = AttackControl::with_progress_every(1);
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut observer = Recorder::default();
        let mut accounting = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut observer,
        };
        let execution = execute_outer(
            accounting.allowance.clone(),
            accounting.control.clone(),
            accounting.observer,
            |local| {
                local.admit().unwrap();
                local.complete().unwrap();
                local.control.poll_cancellation(true);
                Err::<(), _>("injected evaluation failure")
            },
        );
        // Nothing is committed until the ordered coordinator folds the outcome.
        assert_eq!(accounting.allowance.used, 7);
        assert_eq!(accounting.control.snapshot(), Default::default());
        assert_eq!(
            execution.commit(&mut accounting),
            Err("injected evaluation failure")
        );
        assert_eq!(accounting.allowance.used, 8);
        assert_eq!(accounting.control.snapshot().evaluations_completed, 1);
        assert!(accounting.control.poll_cancellation(false));
        assert_eq!(observer.0.len(), 1);
    }

    #[test]
    fn cancelled_scan_keeps_committed_board() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&resource)),
            (MeasureId::Trie, Some(&resource)),
            2,
        );
        // Successful provisional winners, including the last trial, never commit.
        for (stop, used, committed) in [(4, 2, false), (6, 3, false), (8, 4, false), (9, 4, true)] {
            let (result, snapshot, actual, _) = run_cancellation(&context, stop);
            let outcome = result.unwrap();
            assert_eq!(
                outcome.current.unwrap().board,
                if committed { vec![('A', 'C')] } else { vec![] }
            );
            assert!(outcome.cancelled);
            assert!(outcome.incomplete && !outcome.neighborhood_exhausted);
            assert_eq!(outcome.final_objective_ascent, committed);
            assert_eq!(actual, used);
            assert_eq!(
                (
                    snapshot.evaluations_admitted,
                    snapshot.evaluations_completed
                ),
                (used, used)
            );
            assert_eq!((snapshot.climbs_started, snapshot.climbs_completed), (1, 0));
        }
    }

    #[test]
    fn cancellation_precedence_and_initial_result() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&resource)),
            (MeasureId::Trie, Some(&resource)),
            2,
        );
        for (stop, used, cancelled, exhausted) in [
            (1, 0, true, false),
            (2, 1, true, false),
            (3, 1, true, false),
            (19, 9, false, true),
        ] {
            let (result, snapshot, actual, polls) = run_cancellation(&context, stop);
            let outcome = result.unwrap();
            assert_eq!(
                (outcome.cancelled, outcome.neighborhood_exhausted),
                (cancelled, exhausted)
            );
            assert_eq!(outcome.incomplete, !exhausted);
            assert_eq!(outcome.current.is_some(), used > 0);
            assert_eq!(actual, used);
            assert_eq!(snapshot.climbs_started, u128::from(used > 0));
            assert_eq!(snapshot.climbs_completed, u128::from(exhausted));
            if stop == 2 {
                assert!(polls > stop);
            } // True then false stays sticky.
        }
        let empty = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[],
            r#"{"kind":"attack","symbols":["A","B","C"],"max_pairs":0}"#,
        )
        .unwrap();
        let context = BoundClimbScoring::new(
            &initial,
            &empty,
            "AA",
            (MeasureId::Trie, Some(&resource)),
            (MeasureId::Trie, Some(&resource)),
            2,
        );
        let (result, snapshot, used, _) = run_cancellation(&context, 2);
        let outcome = result.unwrap();
        assert!(outcome.neighborhood_exhausted && !outcome.cancelled);
        assert_eq!((used, snapshot.climbs_completed), (1, 1));
    }

    #[test]
    fn cancelled_finalization_preserves_errors_and_usage() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let last = resource(&initial);
        // Distinct objective binding requires exactly one final rescore.
        for (threshold, stop, used, paired) in [
            (2, 2, 2, false),
            (2, 8, 5, false),
            (2, 9, 5, true),
            (1, 9, 5, true),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(&last)),
                threshold,
            );
            let (result, snapshot, actual, _) = run_cancellation(&context, stop);
            let outcome = result.unwrap();
            let current = outcome.current.unwrap();
            assert!(outcome.cancelled && !outcome.neighborhood_exhausted);
            assert_eq!(
                current.board,
                if paired { vec![('A', 'C')] } else { vec![] }
            );
            assert_eq!(
                current.score.ranking().units(),
                if paired { 2i128 << 32 } else { 0 }
            );
            assert_eq!(actual, used);
            assert_eq!(
                (
                    snapshot.evaluations_admitted,
                    snapshot.evaluations_completed
                ),
                (used, used)
            );
            assert_eq!(snapshot.climbs_completed, 0);
        }
        for (missing_initial, stop, used, started) in [
            (true, 2, 1, 0),
            (false, 2, 2, 1),
            (false, 8, 5, 1),
            (false, 9, 5, 1),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (
                    MeasureId::Trie,
                    if missing_initial { None } else { Some(&first) },
                ),
                (MeasureId::Trie, None),
                if stop == 9 { 1 } else { 2 },
            );
            let (result, snapshot, actual, _) = run_cancellation(&context, stop);
            assert_eq!(
                result.unwrap_err(),
                ObservedClimbError::Evaluation(TrialEvaluationError::MissingResource(
                    MeasureId::Trie
                ))
            );
            assert_eq!(actual, used);
            assert_eq!(
                (
                    snapshot.evaluations_admitted,
                    snapshot.evaluations_completed
                ),
                (used, used - 1)
            );
            assert_eq!(
                (snapshot.climbs_started, snapshot.climbs_completed),
                (started, 0)
            );
        }
    }

    #[test]
    fn admitted_trial_error_precedes_pending_cancellation() {
        let (initial, domain) = fixture();
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            None,
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let mut polls = 0;
        let result = selection.scan(
            &[],
            FixedScore::from_units(0),
            &mut CancellableAccounting {
                observed: &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                requested: || {
                    polls += 1;
                    polls > 1
                },
            },
        );
        assert_eq!(
            result,
            Err(ObservedClimbError::Evaluation(
                TrialEvaluationError::MissingResource(MeasureId::Trie)
            ))
        );
        assert_eq!(polls, 1); // A failed evaluation never reaches the post-success poll.
        assert_eq!(allowance.used, 8);
        assert_eq!(control.snapshot().evaluations_admitted, 1);
        assert_eq!(control.snapshot().evaluations_completed, 0);
        assert_eq!(control.snapshot().climbs_completed, 0);
    }

    #[test]
    fn control_records_successful_and_failed_evaluations() {
        let (initial, domain) = fixture();
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let mut accounting = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut observer,
        };
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        );
        accounting.evaluate(&evaluator, &[]).unwrap();
        let failing = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            None,
        );
        assert_eq!(
            accounting.evaluate(&failing, &[]),
            Err(ObservedClimbError::Evaluation(
                TrialEvaluationError::MissingResource(MeasureId::Trie)
            ))
        );
        assert_eq!(allowance.used, 9);
        assert_eq!(control.snapshot().evaluations_admitted, 2);
        assert_eq!(control.snapshot().evaluations_completed, 1);
    }

    #[test]
    fn observed_climb_preserves_phases_and_notifications() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        // Distinct bindings cross at one pair, or rescore at termination at two.
        for (threshold, distinct, used, exhausted, paired, expected_ascent) in [
            (2, false, 9, true, true, true),
            (1, true, 10, true, true, true),
            (2, true, 10, true, true, false),
        ] {
            crate::engine::ROW_BUILDS.with(|count| count.set(0));
            let last = resource(&initial);
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(if distinct { &last } else { &first })),
                threshold,
            );
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let outcome = context
                .climb_accounted(
                    vec![],
                    0,
                    &mut ObservedAccounting {
                        allowance: &mut allowance,
                        control: &mut control,
                        observer: &mut observer,
                    },
                )
                .unwrap();
            let snapshot = control.snapshot();
            assert_eq!(
                (
                    snapshot.evaluations_admitted,
                    snapshot.evaluations_completed
                ),
                (used, used)
            );
            crate::engine::ROW_BUILDS.with(|count| {
                assert_eq!(count.get() == 0, used == 0);
            });
            assert_eq!(allowance.used, 7 + used);
            assert_eq!(snapshot.climbs_started, u128::from(used > 0));
            assert_eq!(snapshot.climbs_completed, u128::from(exhausted));
            assert_eq!(snapshot.outers_completed, 0);
            assert_eq!(outcome.neighborhood_exhausted, exhausted);
            assert_eq!(outcome.incomplete, !exhausted);
            assert_eq!(outcome.final_objective_ascent, expected_ascent);
            if let Some(current) = outcome.current {
                assert_eq!(
                    current.board,
                    if paired { vec![('A', 'C')] } else { vec![] }
                );
                assert_eq!(current.plaintext, if paired { "CB" } else { "CA" });
                assert_eq!(
                    current.score.ranking().units(),
                    if paired { 2i128 << 32 } else { 0 }
                );
            } else {
                assert_eq!(used, 0);
            }
            assert!(
                observer.0.is_empty(),
                "all completions are below the default cadence"
            );
            assert!(observer
                .0
                .windows(2)
                .all(|pair| pair[1].evaluations_completed <= pair[1].evaluations_admitted));
        }
    }

    #[test]
    fn observed_errors_keep_charges_and_never_complete_the_climb() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        for (threshold, used) in [(1, 5), (2, 10)] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&resource)),
                (MeasureId::Trie, None),
                threshold,
            );
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let error = context
                .climb_accounted(
                    vec![],
                    0,
                    &mut ObservedAccounting {
                        allowance: &mut allowance,
                        control: &mut control,
                        observer: &mut observer,
                    },
                )
                .unwrap_err();
            assert_eq!(
                error,
                ObservedClimbError::Evaluation(TrialEvaluationError::MissingResource(
                    MeasureId::Trie
                ))
            );
            let snapshot = control.snapshot();
            assert_eq!(
                (
                    snapshot.evaluations_admitted,
                    snapshot.evaluations_completed
                ),
                (used, used - 1)
            );
            assert_eq!(
                (
                    snapshot.climbs_started,
                    snapshot.climbs_completed,
                    snapshot.outers_completed
                ),
                (1, 0, 0)
            );
            assert_eq!(allowance.used, 7 + used);
            assert!(observer.0.is_empty(), "failed evaluations do not notify");
        }
    }

    #[test]
    fn observed_counter_overflow_is_explicit() {
        use crate::attack_control::CounterSnapshot;
        let (initial, domain) = fixture();
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        );
        for (admitted, completed, expected) in [
            (u64::MAX, 0, CounterOverflow::EvaluationsAdmitted),
            (0, u64::MAX, CounterOverflow::EvaluationsCompleted),
        ] {
            let mut control = AttackControl::with_counters(CounterSnapshot {
                evaluations_admitted: admitted,
                evaluations_completed: completed,
                ..CounterSnapshot::default()
            });
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut observer = Recorder::default();
            let error = ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            }
            .evaluate(&evaluator, &[])
            .unwrap_err();
            assert_eq!(error, ObservedClimbError::Counter(expected));
            assert_eq!(allowance.used, 8);
            assert_eq!(control.snapshot().evaluations_completed, completed);
            assert_eq!(
                control.snapshot().evaluations_admitted,
                if admitted == 0 { 1 } else { admitted }
            );
        }
    }

    fn fixture() -> (ResolvedConfiguration, AttackPlugboardDomain) {
        let source = serde_json::json!({"kind": "custom", "value": {
            "alphabet": ["A", "B", "C"],
            "wheels": [{"name": "r", "wiring": ["B", "A", "C"], "turnovers": []}],
            "slots": [{"id": "r", "role": "rotor", "movement": "movable", "wheel": "r"}],
            "stepping": {"rules": [{"when": {"always": true}, "advance": ["r"]}]}
        }});
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        let initial =
            TransformConfiguration::new(vec![SlotConfiguration::new("r", "r", 'A', 'A')], vec![])
                .resolve(&definition)
                .unwrap();
        let domain = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[],
            r#"{"kind":"attack","symbols":["A","B","C"],"max_pairs":1}"#,
        )
        .unwrap();
        (initial, domain)
    }

    fn direct_request(start: serde_json::Value, distinct: bool, pe: bool) -> crate::AttackRequest {
        direct_request_with(start, distinct, pe, |_| {})
    }

    fn direct_request_with(
        start: serde_json::Value,
        distinct: bool,
        pe: bool,
        customize: impl FnOnce(&mut serde_json::Value),
    ) -> crate::AttackRequest {
        let value = serde_json::json!({"protocol_version":1,"machine":{"definition":{
            "kind":"custom","value":{"alphabet":["A","B","C"],
            "wheels":[{"name":"r","wiring":["B","A","C"],"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"movable","wheel":"r"}],
            "stepping":{"rules":[{"when":{"always":true},"advance":["r"]}]}}}},
            "job":{"kind":"search","configuration":{"slots":[{"id":"r","position":"A","ring":"A"}],
            "plugboard":[]},"space":{"plugboard":{"kind":"attack","symbols":["A","B","C"],"max_pairs":1}},
            "text":"AA","passes":[if pe {"partial_exhaustion"} else {"hill_climb"}],
            "measures":if distinct {vec!["ic","trie"]} else {vec!["trie"]},
            "resources":{"trie":{"path":"dictionary.json"}},
            "attack":{"kind":"hill_climb","initial_measure":if distinct {"ic"} else {"trie"},
            "final_measure":"trie","switch_pairs":1,"backtrack_pairs":0,"start":start}}});
        let mut value = value;
        if pe {
            value["job"]["attack"]["kind"] = serde_json::json!("partial_exhaustion");
            value["job"]["attack"]
                .as_object_mut()
                .unwrap()
                .remove("start");
            value["job"]["attack"]["seeds"] =
                serde_json::json!({"kind":"empty_single","selection":"all"});
        }
        customize(&mut value["job"]);
        let json = value.to_string();
        let dictionary = serde_json::json!({"resource_version":1,"kind":"dictionary","alphabet":["A","B","C"],
            "entries":[{"word":["A","C"],"weight":1},{"word":["C","B"],"weight":2},{"word":["B","A"],"weight":2}]}).to_string();
        let supplied = std::collections::BTreeMap::from([("trie".to_owned(), dictionary.as_str())]);
        crate::ParsedAttackRequest::parse_json(&json)
            .unwrap()
            .bind_resources(&supplied)
            .unwrap()
    }

    #[test]
    fn early_scheduler_error_keeps_distinct_initial_and_terminal_observations() {
        // Characterization: even an error before the first admission must pass
        // through the same terminal boundary as a successfully evaluated run.
        for pe in [false, true] {
            let request = scheduler_request(false, pe, 0);
            let mut control = AttackControl::default();
            let mut snapshots = Vec::new();
            let mut observer = ProgressObserver(|p| snapshots.push(p));
            let error = observed_run(&mut control, &mut observer, |control, observer| {
                let mut allowance = EvaluationAllowance { used: 0 };
                let accounting = &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control,
                    observer,
                };
                if pe {
                    let error = schedule_controlled_partial_with_climb(
                        1,
                        request.outer_candidates().take(0),
                        accounting,
                        &mut || false,
                        |_, _, _, _| panic!("no outer may start"),
                    )
                    .unwrap_err();
                    Err(error.project(request.domain(), MeasureId::Trie))
                } else {
                    let error = schedule_controlled_direct(
                        1,
                        request.outer_candidates().take(0),
                        accounting,
                        &mut || false,
                        |_, _, _, _| panic!("no outer may start"),
                        |_| panic!("no outer may be accepted"),
                    )
                    .unwrap_err();
                    Err(error.project(request.domain(), MeasureId::Trie))
                }
            })
            .unwrap_err();
            assert_eq!(error.evaluations_used(), 0);
            assert_eq!(error.counters().0, Default::default());
            assert_eq!(
                snapshots,
                vec![crate::AttackProgress(Default::default()); 2]
            );
        }
    }

    #[test]
    fn observed_run_errors_keep_terminal_live_counters() {
        use crate::attack_result::RunPayload;
        // Valid external requests cannot deterministically manufacture these
        // invariant failures. Inject at the existing scheduler/projection/scorer
        // seams, inside the exact lifecycle boundary used by public run().
        for pe in [false, true] {
            for fault in [
                "early_scheduler",
                "later_scheduler",
                "projection",
                "chained_stage",
            ] {
                for every in [1, 3, 100_000] {
                    let request = scheduler_request(false, pe, 0);
                    let mut allowance = EvaluationAllowance { used: 0 };
                    let mut control = AttackControl::with_progress_every(every);
                    let mut snapshots = Vec::new();
                    let mut observer = ProgressObserver(|p| snapshots.push(p));
                    let error = observed_run(&mut control, &mut observer, |control, observer| {
                        let accounting = &mut ObservedAccounting {
                            allowance: &mut allowance,
                            control,
                            observer,
                        };
                        let selected = if fault == "later_scheduler" { 2 } else { 1 };
                        let take = usize::from(fault != "early_scheduler");
                        let result = if pe {
                            let run = schedule_controlled_partial_with_climb(
                                selected,
                                request.outer_candidates().take(take),
                                accounting,
                                &mut || false,
                                |initial, index, accounting, requested| {
                                    let mut outer = request.climb_partial_outer_controlled(
                                        initial, index, accounting, requested,
                                    )?;
                                    if fault == "projection" {
                                        outer
                                            .seeds
                                            .seeds
                                            .best
                                            .as_mut()
                                            .unwrap()
                                            .current
                                            .board
                                            .push(('A', 'Z'));
                                    }
                                    Ok(outer)
                                },
                            );
                            match run {
                                Ok(run) => run.project_public(
                                    accounting.control.snapshot(),
                                    request.domain(),
                                    MeasureId::Trie,
                                )?,
                                Err(error) => {
                                    return Err(error.project(request.domain(), MeasureId::Trie))
                                }
                            }
                        } else {
                            let mut acceptance = DirectAcceptance::new(1);
                            let run = schedule_controlled_direct(
                                selected,
                                request.outer_candidates().take(take),
                                accounting,
                                &mut || false,
                                |initial, index, accounting, requested| {
                                    let (scoring, start) = request
                                        .direct_scoring(&initial)
                                        .map_err(DirectRunError::Climb)?;
                                    let mut climb = scoring
                                        .climb_cancellable(start, 0, accounting, requested)
                                        .map_err(DirectRunError::from)?;
                                    if fault == "projection" {
                                        climb.current.as_mut().unwrap().board.push(('A', 'Z'));
                                    }
                                    Ok(DirectOuterOutcome {
                                        initial,
                                        outer_index: index,
                                        start_index: 0,
                                        climb,
                                    })
                                },
                                |outcome| {
                                    acceptance.accept(outcome, request.domain(), MeasureId::Trie)
                                },
                            );
                            acceptance.finish(
                                run,
                                accounting.control.snapshot(),
                                request.domain(),
                                MeasureId::Trie,
                            )?
                        };
                        assert_eq!(fault, "chained_stage", "projection must fail before stages");
                        stages_over_hold(result, |result| {
                            let result = scoring_stage(
                                result,
                                crate::space::AttackStage::Measure {
                                    measure: MeasureId::Trie,
                                },
                                accounting,
                                |best| Ok((best.plaintext.clone(), best.score)),
                            )?;
                            scoring_stage(
                                result,
                                crate::space::AttackStage::Trie { base_measure: None },
                                accounting,
                                |_| {
                                    Err(RunPayload::Evaluation(
                                        TrialEvaluationError::MissingResource(MeasureId::Trie),
                                    ))
                                },
                            )
                        })
                    })
                    .unwrap_err();
                    let live = control.snapshot();
                    assert_eq!(error.counters().0, live, "pe={pe}, fault={fault}");
                    assert_eq!(error.evaluations_used(), allowance.used);
                    assert_eq!(live.evaluations_admitted, allowance.used);
                    assert_eq!(
                        live.evaluations_admitted - live.evaluations_completed,
                        u64::from(fault == "chained_stage")
                    );
                    if fault == "early_scheduler" {
                        assert_eq!(live, Default::default());
                    } else {
                        assert!(live.evaluations_completed > 0);
                        assert_eq!(live.outers_completed, 1);
                    }
                    let mut expected = vec![0];
                    expected.extend((1..=live.evaluations_completed).filter(|n| n % every == 0));
                    expected.push(live.evaluations_completed);
                    assert_eq!(
                        snapshots
                            .iter()
                            .map(|p| p.evaluations_completed())
                            .collect::<Vec<_>>(),
                        expected
                    );
                    assert_eq!(snapshots.last(), Some(&crate::AttackProgress(live)));
                }
            }
        }
    }

    #[test]
    fn public_progress_grid_spans_outers_seeds_objectives_stages_and_finalists() {
        for pe in [false, true] {
            for every in [1, 3, 100_000, u64::MAX] {
                let request = direct_request_with(serde_json::json!([]), true, pe, |job| {
                    job["configuration"]["slots"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("position");
                    job["space"]["slots"] =
                        serde_json::json!([{"id":"r","positions":["B","A","C"]}]);
                    job["attack"]["progress_every"] = serde_json::json!(every);
                    job["attack"]["hold"] = serde_json::json!(3);
                    for pass in ["reswapping", "trie", "measure"] {
                        job["passes"]
                            .as_array_mut()
                            .unwrap()
                            .push(serde_json::json!(pass));
                        job["attack"][pass] = if pass == "trie" {
                            serde_json::json!({})
                        } else {
                            serde_json::json!({"measure":"trie"})
                        };
                    }
                });
                for cancel in [false, true] {
                    let plan = request.outer_plan();
                    let block = plan.blocks().next().unwrap();
                    let preparation = RunPreparation::new(&request);
                    let outer_completed = if pe {
                        request
                            .run_partial_block(&preparation, &plan, block)
                            .accounting
                            .used
                    } else {
                        request
                            .run_direct_block(&preparation, &plan, block)
                            .accounting
                            .used
                    };
                    let mut snapshots = Vec::new();
                    let mut polls = 0;
                    let result = request
                        .run(
                            |p| snapshots.push(p),
                            || {
                                polls += 1;
                                cancel && polls == 5
                            },
                        )
                        .unwrap();
                    let completed = result.counters().evaluations_completed();
                    let mut expected = vec![0];
                    if outer_completed >= every {
                        expected.push(outer_completed);
                    }
                    expected.extend(
                        (outer_completed + 1..=completed).filter(|count| count % every == 0),
                    );
                    expected.push(completed);
                    assert_eq!(
                        snapshots
                            .iter()
                            .map(|p| p.evaluations_completed())
                            .collect::<Vec<_>>(),
                        expected,
                        "pe={pe}, every={every}, cancel={cancel}"
                    );
                    assert_eq!(snapshots.last(), Some(&result.counters()));
                    if !cancel {
                        assert_eq!(result.counters().outers_completed(), 3);
                        assert_eq!(result.hold().count(), 3);
                        assert!(result.hold().all(|entry| entry.stages().len() == 3));
                    }
                }
            }
        }
    }

    #[test]
    fn request_bound_partial_order_lifetime_and_shared_allowance() {
        // direct_request_with drops the external JSON and dictionary buffers.
        for (selection, mask, cost, count) in
            [("all", vec![], 32, 4), ("touching", vec!["B"], 26, 3)]
        {
            let request = direct_request_with(serde_json::json!([]), false, true, |job| {
                job["attack"]["seeds"]["selection"] = serde_json::json!(selection);
                if selection == "touching" {
                    job["attack"]["seeds"]["symbols"] = serde_json::json!(mask);
                }
            });
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let retained = initial.clone();
            let index = u128::from(u64::MAX) + 7;
            let mut allowance = EvaluationAllowance { used: 7 };
            let outcome = request
                .climb_partial_outer(initial, index, &mut allowance)
                .unwrap();
            assert_eq!(outcome.initial, retained);
            assert_eq!(outcome.outer_index, index); // Retention, not provenance validation.
            let run = outcome.seeds;
            assert_eq!(run.evaluations_used, 7 + cost);
            assert_eq!(allowance.used, 7 + cost);
            assert_eq!((run.climbs_started, run.climbs_completed), (count, count));
            let best = run.best.unwrap();
            assert_eq!(best.seed_index, 0);
            assert_eq!(best.current.board, vec![('A', 'C')]);
            assert_eq!(best.current.plaintext, "CB");
            assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
            assert!(!best.incomplete);
            assert!(best.neighborhood_exhausted && best.final_objective_ascent);
        }
    }

    #[test]
    fn request_bound_partial_fixed_facts_exact_completion_and_wrong_pass() {
        for distinct in [false, true] {
            let request = direct_request_with(serde_json::json!([]), distinct, true, |job| {
                if distinct {
                    job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
                } else {
                    job["configuration"]["plugboard"] = serde_json::json!([["A", "B"]]);
                    job["space"]["plugboard"]["symbols"] = serde_json::json!(["C"]);
                }
            });
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let cost = if distinct { 2 } else { 1 };
            let mut allowance = EvaluationAllowance { used: 7 };
            let outcome = request
                .climb_partial_outer(initial.clone(), 0, &mut allowance)
                .unwrap();
            assert_eq!(outcome.initial, initial);
            let run = outcome.seeds;
            assert_eq!(run.evaluations_used, 7 + cost);
            assert_eq!((run.climbs_started, run.climbs_completed), (1, 1));
            let best = run.best.unwrap();
            assert!(best.current.board.is_empty());
            assert_eq!(best.current.plaintext, if distinct { "CA" } else { "AC" });
            assert_eq!(
                best.current.score.ranking().units(),
                if distinct { 0 } else { 1i128 << 32 }
            );
            assert!(!best.incomplete && best.neighborhood_exhausted);
            assert_eq!(best.final_objective_ascent, !distinct);
        }
        let request = direct_request(serde_json::json!([]), false, false);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let mut allowance = EvaluationAllowance { used: 7 };
        let error = request
            .climb_partial_outer(initial, 9, &mut allowance)
            .unwrap_err();
        assert_eq!(error.source, PartialClimbError::UnsupportedPass);
        assert_eq!((error.outer_index, error.evaluations_used), (9, 7));
        assert_eq!(allowance.used, 7);
    }

    #[test]
    fn request_bound_partial_later_interrupted_winner_and_dense_mask_index() {
        for (selection, symbols, used, climbs) in
            [("all", vec![], 28, 4), ("touching", vec!["C"], 17, 3)]
        {
            let request = direct_request_with(serde_json::json!([]), true, true, |job| {
                // A mid-seed stop is not observed until this block is finished.
                job["attack"]["seeds"]["selection"] = serde_json::json!(selection);
                if selection == "touching" {
                    job["attack"]["seeds"]["symbols"] = serde_json::json!(symbols);
                }
            });
            let run = public_pe_probe(&request, |p| p.evaluations_completed() >= 7);
            public_pe_facts(
                &run,
                crate::AttackTermination::Completed,
                (used, climbs, climbs, 1),
                Some((0, 1, "CB", 2, false, true, true)),
            );
        }
    }

    fn scheduler_request(distinct: bool, pe: bool, offset: u64) -> crate::AttackRequest {
        direct_request_with(serde_json::json!([]), distinct, pe, |job| {
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
            job["space"]["offset"] = serde_json::json!(offset);
        })
    }

    fn partial_scheduler_request(
        distinct: bool,
        customize: impl FnOnce(&mut serde_json::Value),
    ) -> crate::AttackRequest {
        direct_request_with(serde_json::json!([]), distinct, true, |job| {
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
            customize(job);
        })
    }

    #[test]
    fn measure_failure_retains_committed_best_and_original_source() {
        use crate::attack_result::RunPayload;
        let result = scheduler_request(false, false, 0)
            .run(|_| {}, || false)
            .unwrap();
        let used = result.evaluations_used;
        let score = result.best.as_ref().unwrap().score;
        let key = result.best.as_ref().unwrap().configuration.clone();
        let mut control = AttackControl::with_counters(result.counters.0);
        let mut allowance = EvaluationAllowance { used };
        let mut recorder = Recorder::default();
        // Valid bound requests cannot manufacture a scoring failure; inject at evaluation.
        let error = scoring_stage(
            result,
            crate::space::AttackStage::Measure {
                measure: MeasureId::Entropy,
            },
            &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut recorder,
            },
            |_| {
                Err(RunPayload::Evaluation(
                    TrialEvaluationError::MissingResource(MeasureId::Trie),
                ))
            },
        )
        .unwrap_err();
        assert_eq!(
            error.run_source().category(),
            crate::AttackRunCategory::Evaluation
        );
        assert!(matches!(
            error.run_source().0,
            RunPayload::Evaluation(TrialEvaluationError::MissingResource(MeasureId::Trie))
        ));
        assert_eq!(error.evaluations_used(), used + 1);
        assert_eq!(error.counters().evaluations_admitted(), used + 1);
        assert_eq!(error.counters().evaluations_completed(), used);
        assert!(
            recorder.0.is_empty(),
            "stage errors leave terminal delivery to run"
        );
        let best = error.best().unwrap().unwrap();
        assert_eq!(best.configuration(), &key);
        assert_eq!(best.score(), score);
        let stage = &error.stages()[0];
        assert_eq!(
            (stage.score(), stage.evaluations_used(), stage.completed()),
            (None, 1, false)
        );
    }

    #[test]
    fn hold_ownership_scoring_failure_keeps_tail_history_best_and_charge() {
        use crate::attack_result::RunPayload;
        use std::error::Error;
        let request = direct_request_with(serde_json::json!([]), true, false, |job| {
            job["passes"] = serde_json::json!(["hill_climb", "measure"]);
            job["attack"]["measure"] = serde_json::json!({"measure":"ic"});
        });
        let mut result = request.run(|_| {}, || false).unwrap();
        result.held_tail = crate::attack_hold::tests::tail_fixture();
        let tail = crate::attack_hold::tests::snapshot(&result.held_tail);
        let indices = result.best.as_ref().map(|b| (b.outer_index, b.start_index));
        let prior_counters = result.counters;
        let used = result.evaluations_used;
        let key = result.best.as_ref().unwrap().configuration.clone();
        let score = result.best.as_ref().unwrap().score;
        let prior_score = result.stages[0].score;
        let mut control = AttackControl::with_counters(result.counters.0);
        let mut allowance = EvaluationAllowance { used };
        let mut recorder = Recorder::default();
        let error = scoring_stage(
            result,
            crate::space::AttackStage::Trie { base_measure: None },
            &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut recorder,
            },
            |best| {
                // Synthetic composition seam: real bounded dictionaries cannot reach i128::MAX.
                MeasuredScore::higher_is_better(FixedScore::from_units(1))
                    .with_ranking_base(FixedScore::from_units(i128::MAX))
                    .map(|score| (best.plaintext.clone(), score))
                    .map_err(|source| RunPayload::Evaluation(TrialEvaluationError::Measure(source)))
            },
        )
        .unwrap_err();
        assert_eq!(error.best().unwrap().unwrap().configuration(), &key);
        assert_eq!(error.best().unwrap().unwrap().score(), score);
        assert_eq!(
            crate::attack_hold::tests::snapshot(crate::attack_result::tests::held_tail(&error)),
            tail
        );
        assert_eq!(error.outer_index().zip(error.start_index()), indices);
        assert_eq!(
            error.counters().climbs_started(),
            prior_counters.climbs_started()
        );
        assert_eq!(
            error.counters().climbs_completed(),
            prior_counters.climbs_completed()
        );
        assert_eq!(
            error.counters().outers_completed(),
            prior_counters.outers_completed()
        );
        assert_eq!(error.stages()[0].pass(), "measure");
        assert_eq!(error.stages()[0].score(), prior_score);
        assert_eq!(error.evaluations_used(), used + 1);
        assert_eq!(error.counters().evaluations_admitted(), used + 1);
        assert_eq!(error.counters().evaluations_completed(), used);
        assert!(
            recorder.0.is_empty(),
            "failed composition is not a completion"
        );
        let stage = &error.stages()[1];
        assert_eq!(stage.pass(), "trie");
        assert_eq!(stage.score(), None);
        assert_eq!(stage.evaluations_used(), 1);
        assert!(!stage.completed());
        assert_eq!(
            error.run_source().category(),
            crate::AttackRunCategory::Evaluation
        );
        let trial = error.run_source().source().unwrap();
        let measure = trial.source().unwrap();
        assert_eq!(
            measure.downcast_ref::<crate::MeasureError>(),
            Some(&crate::MeasureError::Arithmetic(
                crate::ScoreError::Overflow
            ))
        );
        assert_eq!(
            measure
                .source()
                .unwrap()
                .downcast_ref::<crate::ScoreError>(),
            Some(&crate::ScoreError::Overflow)
        );
    }

    #[test]
    fn controlled_partial_error_retains_prior_owned_projection() {
        let request = partial_scheduler_request(false, |_| {});
        let expected = request
            .schedule_partial_outers_controlled(
                &mut AttackControl::default(),
                &mut Recorder::default(),
                || false,
            )
            .unwrap()
            .best
            .unwrap()
            .into_direct()
            .project(request.domain(), request.settings().final_measure())
            .unwrap();
        for resolution in [false, true] {
            let failure_index = u128::from(u64::MAX) + 9;
            let mut outers: Vec<_> = request.outer_candidates().take(1).collect();
            if resolution {
                outers.push((failure_index, Err(vec![])));
            }
            let mut allowance = EvaluationAllowance { used: 0 };
            let mut control = AttackControl::default();
            let mut recorder = Recorder::default();
            let error = schedule_controlled_partial(
                &request,
                2,
                outers.into_iter(),
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut recorder,
                },
                &mut || false,
                1,
            )
            .unwrap_err();
            assert_eq!(error.counters, control.snapshot());
            assert!(recorder.0.is_empty());
            let error = error.project(request.domain(), request.settings().final_measure());
            assert_eq!(error.outer_index(), resolution.then_some(failure_index));
            assert_eq!(error.start_index(), None);
            assert_eq!(error.evaluations_used(), allowance.used);
            let best = error
                .best()
                .unwrap()
                .expect("first accepted outer survives later failure");
            assert_eq!(best.configuration(), expected.configuration());
            assert_eq!(best.mutable_plugboard(), expected.mutable_plugboard());
            assert_eq!(best.plaintext(), expected.plaintext());
            assert_eq!(best.score(), expected.score());
            assert_eq!(best.outer_index(), 0);
            assert_eq!(best.start_index(), expected.start_index());
            assert_eq!(best.incomplete(), expected.incomplete());
            assert_eq!(
                best.final_objective_ascent(),
                expected.final_objective_ascent()
            );
            assert_eq!(
                best.neighborhood_exhausted(),
                expected.neighborhood_exhausted()
            );
        }
    }

    fn partial_projection_outer(
        request: &crate::AttackRequest,
        index: u128,
    ) -> ControlledPartialOutcome {
        request
            .climb_partial_outer_controlled(
                request.outer_candidates().next().unwrap().1.unwrap(),
                index,
                &mut ObservedAccounting {
                    allowance: &mut EvaluationAllowance { used: 0 },
                    control: &mut AttackControl::default(),
                    observer: &mut Recorder::default(),
                },
                &mut || false,
            )
            .unwrap()
    }

    #[test]
    fn controlled_partial_failing_outer_seed_strict_selection() {
        let request = partial_scheduler_request(false, |_| {});
        let failure = u128::from(u64::MAX) + 11;
        for delta in [-1, 0, 1] {
            let prior = partial_projection_outer(&request, 4);
            let prior_score = prior
                .seeds
                .seeds
                .best
                .as_ref()
                .unwrap()
                .current
                .score
                .ranking()
                .units();
            let mut retained = partial_projection_outer(&request, failure);
            let mut seed = retained.seeds.seeds.best.take().unwrap();
            seed.seed_index = u128::from(u64::MAX) + 3;
            seed.current.score =
                MeasuredScore::higher_is_better(FixedScore::from_units(prior_score + delta));
            seed.incomplete = true;
            seed.neighborhood_exhausted = false;
            let mut prior = Some(prior);
            let mut retained = Some((retained.initial, seed));
            let mut control = AttackControl::default();
            let mut recorder = Recorder::default();
            let error = schedule_controlled_partial_with_climb(
                2,
                request.outer_candidates().take(2),
                &mut ObservedAccounting {
                    allowance: &mut EvaluationAllowance { used: 7 },
                    control: &mut control,
                    observer: &mut recorder,
                },
                &mut || false,
                |_, _, _, _| {
                    if let Some(prior) = prior.take() {
                        return Ok(prior);
                    }
                    Err(ControlledPartialError {
                        outer_index: failure,
                        seed_index: Some(u128::MAX),
                        source: ControlledPartialSource::Climb(ObservedClimbError::Counter(
                            CounterOverflow::ClimbsStarted,
                        )),
                        best: retained.take().map(Box::new),
                        held: None,
                    })
                },
            )
            .unwrap_err();
            assert!(recorder.0.is_empty());
            let error = error.project(request.domain(), MeasureId::Trie);
            assert_eq!(error.outer_index(), Some(failure));
            assert_eq!(error.start_index(), Some(u128::MAX));
            let best = error.best().unwrap().unwrap();
            assert_eq!(best.outer_index(), if delta > 0 { failure } else { 4 });
            assert_eq!(best.score().ranking().units(), prior_score + delta.max(0));
            assert_eq!(best.incomplete(), delta > 0);
            assert_eq!(best.neighborhood_exhausted(), delta <= 0);
            assert_ne!(Some(best.start_index()), error.start_index());
        }
    }

    #[test]
    fn controlled_partial_actual_later_counter_fault_and_outer_acceptance_order() {
        use crate::attack_control::CounterSnapshot;
        let request = partial_scheduler_request(false, |_| {});
        for outer_overflow in [false, true] {
            let prior = if outer_overflow {
                CounterSnapshot {
                    outers_completed: u128::MAX - 1,
                    ..Default::default()
                }
            } else {
                CounterSnapshot {
                    climbs_started: u128::MAX - 5,
                    ..Default::default()
                }
            };
            let mut control = AttackControl::with_counters(prior);
            let mut recorder = Recorder::default();
            let error = request
                .schedule_partial_outers_controlled(&mut control, &mut recorder, || false)
                .unwrap_err();
            assert_eq!(error.outer_index, Some(1));
            assert_eq!(
                error.seed_index,
                if outer_overflow { None } else { Some(1) }
            );
            assert_eq!(error.counters, control.snapshot());
            assert!(recorder.0.is_empty());
            let best = error.best.as_ref().unwrap();
            if outer_overflow {
                assert_eq!(
                    best.outer_index, 0,
                    "unaccounted current outer is not accepted"
                );
            }
            let error = error.project(request.domain(), MeasureId::Trie);
            assert_eq!(
                error.run_source().overflow(),
                Some(if outer_overflow {
                    crate::AttackCounterOverflow::OutersCompleted
                } else {
                    crate::AttackCounterOverflow::ClimbsStarted
                })
            );
            assert_eq!(error.counters(), crate::AttackProgress(control.snapshot()));
            assert!(error.best().unwrap().is_some());
        }
    }

    #[test]
    fn controlled_partial_success_projection_independent_flags_and_terminals() {
        use crate::{attack_control::CounterSnapshot, AttackTermination};
        let request = partial_scheduler_request(false, |_| {});
        let snapshot = CounterSnapshot {
            evaluations_admitted: u64::MAX,
            evaluations_completed: u64::MAX - 1,
            climbs_started: u128::MAX,
            climbs_completed: u128::MAX - 1,
            outers_completed: u128::MAX - 2,
        };
        for (termination, expected) in [
            (
                ControlledPartialTermination::Completed,
                AttackTermination::Completed,
            ),
            (
                ControlledPartialTermination::OuterSliceEnd,
                AttackTermination::OuterSliceEnd,
            ),
            (
                ControlledPartialTermination::Cancelled,
                AttackTermination::Cancelled,
            ),
        ] {
            for flags in 0..8 {
                let mut best = partial_projection_outer(&request, u128::MAX);
                let seed = best.seeds.seeds.best.as_mut().unwrap();
                seed.seed_index = u128::from(u64::MAX) + 2;
                seed.incomplete = flags & 1 != 0;
                seed.final_objective_ascent = flags & 2 != 0;
                seed.neighborhood_exhausted = flags & 4 != 0;
                let run = ControlledPartialRun {
                    termination: match expected {
                        AttackTermination::Completed => ControlledPartialTermination::Completed,
                        AttackTermination::OuterSliceEnd => {
                            ControlledPartialTermination::OuterSliceEnd
                        }
                        AttackTermination::Cancelled => ControlledPartialTermination::Cancelled,
                    },
                    outer_completed: 1,
                    climbs_started: 4,
                    climbs_completed: 4,
                    evaluations_used: u64::MAX,
                    best: Some(best),
                    held: None,
                }
                .project_public(snapshot, request.domain(), MeasureId::Trie)
                .unwrap();
                assert_eq!(run.termination(), expected);
                assert_eq!(run.counters(), crate::AttackProgress(snapshot));
                assert_eq!(run.evaluations_used(), u64::MAX);
                let best = run.best().unwrap();
                assert_eq!(
                    (best.outer_index(), best.start_index()),
                    (u128::MAX, u128::from(u64::MAX) + 2)
                );
                assert_eq!(
                    (
                        best.incomplete(),
                        best.final_objective_ascent(),
                        best.neighborhood_exhausted()
                    ),
                    (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0)
                );
            }
            let empty = ControlledPartialRun {
                termination,
                outer_completed: 0,
                climbs_started: 0,
                climbs_completed: 0,
                evaluations_used: 7,
                best: None,
                held: None,
            }
            .project_public(snapshot, request.domain(), MeasureId::Trie)
            .unwrap();
            assert!(empty.best().is_none());
        }
    }

    #[test]
    fn controlled_partial_projection_malformed_best_and_original_causes() {
        use crate::attack_evaluator::TrialBoardError;
        use std::error::Error;
        let request = partial_scheduler_request(false, |_| {});
        let snapshot = crate::attack_control::CounterSnapshot {
            evaluations_completed: 17,
            ..Default::default()
        };
        for source in [
            TrialEvaluationError::Board(TrialBoardError::Model(crate::ModelError::UnknownSymbol(
                'Z',
            ))),
            TrialEvaluationError::Model(crate::ModelError::EmptyAlphabet),
            TrialEvaluationError::Measure(crate::MeasureError::Arithmetic(
                crate::ScoreError::Overflow,
            )),
        ] {
            let mut best = partial_projection_outer(&request, 0).into_direct();
            best.climb.current.as_mut().unwrap().board = vec![('A', 'A')];
            let error = ControlledPartialRunError {
                outer_index: Some(u128::MAX),
                seed_index: Some(u128::MAX - 1),
                evaluations_used: 19,
                source: ControlledPartialRunSource::Climb(ControlledPartialSource::Climb(
                    ObservedClimbError::Evaluation(source),
                )),
                best: Some(best),
                counters: snapshot,
                held: None,
            }
            .project(request.domain(), MeasureId::Trie);
            assert!(matches!(
                error.best().unwrap_err().downcast_ref::<ProjectionError>(),
                Some(ProjectionError::Board(_))
            ));
            assert_eq!(error.counters(), crate::AttackProgress(snapshot));
            assert_eq!(error.evaluations_used(), 19);
            assert!(std::ptr::eq(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<crate::AttackRunSource>()
                    .unwrap(),
                error.run_source()
            ));
            let trial = error
                .run_source()
                .source()
                .unwrap()
                .downcast_ref::<TrialEvaluationError>()
                .unwrap();
            match trial {
                TrialEvaluationError::Board(board) => {
                    assert!(std::ptr::eq(
                        trial
                            .source()
                            .unwrap()
                            .downcast_ref::<TrialBoardError>()
                            .unwrap(),
                        board
                    ));
                    assert_eq!(
                        board.source().unwrap().downcast_ref::<crate::ModelError>(),
                        Some(&crate::ModelError::UnknownSymbol('Z'))
                    );
                }
                TrialEvaluationError::Model(model) => assert!(std::ptr::eq(
                    trial
                        .source()
                        .unwrap()
                        .downcast_ref::<crate::ModelError>()
                        .unwrap(),
                    model
                )),
                TrialEvaluationError::Measure(measure) => {
                    assert!(std::ptr::eq(
                        trial
                            .source()
                            .unwrap()
                            .downcast_ref::<crate::MeasureError>()
                            .unwrap(),
                        measure
                    ));
                    assert_eq!(
                        measure
                            .source()
                            .unwrap()
                            .downcast_ref::<crate::ScoreError>(),
                        Some(&crate::ScoreError::Overflow)
                    );
                }
                _ => panic!("unexpected injected source"),
            }
        }
        let mut best = partial_projection_outer(&request, 0);
        best.seeds.seeds.best.as_mut().unwrap().current.board = vec![('A', 'A')];
        let error = ControlledPartialRun {
            termination: ControlledPartialTermination::Cancelled,
            outer_completed: 1,
            climbs_started: 4,
            climbs_completed: 4,
            evaluations_used: 19,
            best: Some(best),
            held: None,
        }
        .project_public(snapshot, request.domain(), MeasureId::Trie)
        .unwrap_err();
        assert!(error.best().is_err());
        assert_eq!(error.counters(), crate::AttackProgress(snapshot));
        assert_eq!(error.evaluations_used(), 19);
        assert_eq!(error.outer_index(), Some(0));
        assert_eq!(
            error.run_source().category(),
            crate::AttackRunCategory::Invariant
        );
    }

    #[test]
    fn controlled_partial_projection_missing_seed_is_not_absence() {
        let request = partial_scheduler_request(false, |_| {});
        let mut best = partial_projection_outer(&request, 42);
        best.seeds.seeds.best = None; // Malformed accepted aggregate, not an absent aggregate.
        let snapshot = crate::attack_control::CounterSnapshot {
            outers_completed: 1,
            ..Default::default()
        };
        let error = ControlledPartialRun {
            termination: ControlledPartialTermination::Completed,
            outer_completed: 1,
            climbs_started: 4,
            climbs_completed: 4,
            evaluations_used: 32,
            best: Some(best),
            held: None,
        }
        .project_public(snapshot, request.domain(), MeasureId::Trie)
        .unwrap_err();
        assert!(matches!(
            error.best().unwrap_err().downcast_ref::<ProjectionError>(),
            Some(ProjectionError::MissingCommittedBoard)
        ));
        assert_eq!(error.counters(), crate::AttackProgress(snapshot));
        assert_eq!(error.evaluations_used(), 32);
        assert_eq!(error.outer_index(), Some(42));
        assert_eq!(error.start_index(), None);
    }

    fn public_pe_probe(
        request: &crate::AttackRequest,
        stop: impl Fn(crate::AttackProgress) -> bool,
    ) -> crate::AttackResult {
        // Derive the external pulse from independent driver polling in the
        // existing private scheduler seam, not from public progress callbacks.
        let polls = std::cell::Cell::new(0usize);
        let stop_poll = std::cell::Cell::new(usize::MAX);
        let poll = |facts| {
            polls.set(polls.get() + 1);
            if stop(crate::AttackProgress(facts)) {
                stop_poll.set(stop_poll.get().min(polls.get()));
                true
            } else {
                false
            }
        };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        schedule_controlled_partial_with_climb(
            request.gate().outer_selected(),
            request.outer_candidates(),
            &mut ObservedAccounting {
                allowance: &mut EvaluationAllowance { used: 0 },
                control: &mut control,
                observer: &mut observer,
            },
            &mut || poll(Default::default()),
            |initial, index, accounting, requested| {
                request.climb_partial_outer_controlled_with(
                    initial,
                    index,
                    accounting,
                    requested,
                    request.settings().hold_capacity(),
                    |scoring, _, board, accounting, _| {
                        climb_stopping_when(
                            scoring,
                            board,
                            request.settings().backtrack_pairs(),
                            accounting,
                            &poll,
                        )
                    },
                )
            },
        )
        .unwrap();
        assert!(observer.0.is_empty());
        let mut last = None;
        let mut actual_polls = 0;
        let result = request
            .run(
                |p| last = Some(p),
                || {
                    actual_polls += 1;
                    actual_polls == stop_poll.get()
                },
            )
            .expect("public PE executes");
        // The legacy pulse may occur inside a block; the public runner cannot
        // observe it there and established block exhaustion wins.
        assert_eq!(last, Some(result.counters()));
        assert_eq!(
            result.evaluations_used(),
            result.counters().evaluations_admitted()
        );
        assert_eq!(
            result.evaluations_used(),
            result.counters().evaluations_completed()
        );
        result
    }

    type PublicPeWinner<'a> = (u128, u128, &'a str, i128, bool, bool, bool);

    fn public_pe_facts(
        result: &crate::AttackResult,
        termination: crate::AttackTermination,
        counts: (u64, u128, u128, u128),
        winner: Option<PublicPeWinner<'_>>,
    ) {
        let p = result.counters();
        assert_eq!(result.termination(), termination, "{result:?}");
        assert_eq!(
            (
                result.evaluations_used(),
                p.climbs_started(),
                p.climbs_completed(),
                p.outers_completed()
            ),
            counts,
            "{result:?}"
        );
        assert_eq!(result.best().is_some(), winner.is_some());
        if let Some((outer, seed, text, score, incomplete, ascent, exhausted)) = winner {
            let best = result.best().unwrap();
            assert_eq!((best.outer_index(), best.start_index()), (outer, seed));
            assert_eq!(best.plaintext(), text);
            assert_eq!(best.measure(), MeasureId::Trie);
            assert_eq!(best.score().ranking().units(), score << 32);
            assert_eq!(best.configuration().plugboard(), best.mutable_plugboard());
            assert_eq!(
                best.configuration().slots(),
                &[crate::SlotConfiguration::new(
                    "r",
                    "r",
                    ['A', 'B', 'C'][outer as usize],
                    'A'
                )]
            );
            assert_eq!(best.incomplete(), incomplete);
            assert_eq!(best.final_objective_ascent(), ascent);
            assert_eq!(best.neighborhood_exhausted(), exhausted);
        }
    }

    #[test]
    fn public_pe_seed_winner_order_and_interruption() {
        use crate::AttackTermination::Completed;
        for (distinct, touching, cancel_after, termination, counts, seed, text, score, flags) in [
            (
                false,
                false,
                100,
                Completed,
                (32, 4, 4, 1),
                0,
                "CB",
                2,
                (false, true, true),
            ),
            (
                true,
                false,
                7,
                Completed,
                (28, 4, 4, 1),
                1,
                "CB",
                2,
                (false, true, true),
            ),
            (
                true,
                true,
                7,
                Completed,
                (17, 3, 3, 1),
                1,
                "CB",
                2,
                (false, true, true),
            ),
        ] {
            let request = direct_request_with(serde_json::json!([]), distinct, true, |job| {
                if touching {
                    job["attack"]["seeds"] = serde_json::json!({"kind":"empty_single","selection":"touching","symbols":["C"]});
                }
            });
            let result = public_pe_probe(&request, |p| {
                distinct && p.evaluations_completed() >= cancel_after
            });
            public_pe_facts(
                &result,
                termination,
                counts,
                Some((0, seed, text, score, flags.0, flags.1, flags.2)),
            );
            let pair = ('A', 'C');
            assert_eq!(result.best().unwrap().mutable_plugboard(), &[pair]);
        }
    }

    #[test]
    fn public_pe_outer_winner_order_and_interruption() {
        use crate::AttackTermination::Completed;
        for (
            distinct,
            text,
            cancel_after,
            offset,
            termination,
            counts,
            winner,
            plain,
            score,
            flags,
        ) in [
            (
                true,
                "CB",
                6,
                0,
                Completed,
                (6, 3, 3, 3),
                1,
                "BA",
                2,
                (false, false, true),
            ),
            (
                false,
                "A",
                2,
                1,
                Completed,
                (2, 2, 2, 2),
                1,
                "A",
                0,
                (false, true, true),
            ),
            (
                true,
                "CB",
                5,
                0,
                Completed,
                (6, 3, 3, 3),
                1,
                "BA",
                2,
                (false, false, true),
            ),
        ] {
            let request = partial_scheduler_request(distinct, |job| {
                job["text"] = serde_json::json!(text);
                job["space"]["offset"] = serde_json::json!(offset);
                job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            });
            let result = public_pe_probe(&request, |p| {
                cancel_after == 5 && p.evaluations_completed() >= cancel_after - 1
            });
            public_pe_facts(
                &result,
                termination,
                counts,
                Some((winner, 0, plain, score, flags.0, flags.1, flags.2)),
            );
            assert_eq!(
                result.best().unwrap().configuration().slots(),
                &[crate::SlotConfiguration::new("r", "r", 'B', 'A')]
            );
            assert!(result.best().unwrap().mutable_plugboard().is_empty());
        }
    }

    #[test]
    fn public_pe_later_interrupted_outer_replaces_aggregate_winner() {
        let fixture = |first_only| {
            partial_scheduler_request(true, |job| {
                job["text"] = serde_json::json!("CB");
                job["space"]["plugboard"]["symbols"] = serde_json::json!(["A", "B"]);
                job["space"]["slots"] = serde_json::json!([{
                    "id":"r", "positions": if first_only { vec!["A"] } else { vec!["A", "B"] }
                }]);
            })
        };
        let earlier = public_pe_probe(&fixture(true), |_| false);
        let later = public_pe_probe(&fixture(false), |p| {
            p.outers_completed() == 1 && p.climbs_started() == 3
        });
        public_pe_facts(
            &earlier,
            crate::AttackTermination::Completed,
            (8, 2, 2, 1),
            Some((0, 0, "AC", 1, false, true, true)),
        );
        public_pe_facts(
            &later,
            crate::AttackTermination::Completed,
            (16, 4, 4, 2),
            Some((1, 0, "BA", 2, false, true, true)),
        );
        // Both outers finish before the block-boundary stop check; B wins strictly.
        for (result, position, evaluations, flags) in [
            (&earlier, 'A', 8, (false, true, true)),
            (&later, 'B', 16, (false, true, true)),
        ] {
            let best = result.best().unwrap();
            assert_eq!(
                best.configuration(),
                &crate::TransformConfiguration::new(
                    vec![crate::SlotConfiguration::new("r", "r", position, 'A')],
                    vec![],
                )
            );
            assert!(best.mutable_plugboard().is_empty());
            let terminal = result.counters();
            assert_eq!(result.evaluations_used(), evaluations);
            assert_eq!(terminal.evaluations_admitted(), evaluations);
            assert_eq!(terminal.evaluations_completed(), evaluations);
            assert_eq!(best.incomplete(), flags.0);
            assert_eq!(best.final_objective_ascent(), flags.1);
            assert_eq!(best.neighborhood_exhausted(), flags.2);
        }
        let earlier_best = earlier.best().unwrap();
        let later_best = later.best().unwrap();
        assert!(later_best.score().ranking().units() > earlier_best.score().ranking().units());
        assert_eq!(later_best.outer_index(), 1);
        assert_eq!(later_best.start_index(), 0);
        assert_eq!(later_best.plaintext(), "BA");
        assert_eq!(later_best.score().ranking().units(), 2_i128 << 32);
        assert_eq!(later.evaluations_used() - earlier.evaluations_used(), 8);
        assert_eq!(later.counters().climbs_started(), 4);
        assert_eq!(later.counters().climbs_completed(), 4);
        assert_eq!(later.counters().outers_completed(), 2);
    }

    #[test]
    fn public_pe_observation_cancellation_boundaries() {
        let request = partial_scheduler_request(true, |_| {});
        // A stop inside a later outer cannot interrupt the single block.
        let interrupted_outer = public_pe_probe(&request, |p| {
            p.outers_completed() == 1 && p.climbs_started() == 5
        });
        public_pe_facts(
            &interrupted_outer,
            crate::AttackTermination::Completed,
            (84, 12, 12, 3),
            Some((0, 1, "CB", 2, false, true, true)),
        );
        for (boundary, counts, winner) in [
            (0, (0, 0, 0, 0), None),
            (1, (96, 12, 12, 3), Some((0, 0, "CB", 2, false, true, true))),
            (2, (96, 12, 12, 3), Some((0, 0, "CB", 2, false, true, true))),
            (3, (96, 12, 12, 3), Some((0, 0, "CB", 2, false, true, true))),
        ] {
            let request = partial_scheduler_request(false, |_| {});
            let result = public_pe_probe(&request, |p| match boundary {
                0 => true,
                1 => p.outers_completed() == 1,
                2 => p.climbs_completed() == 1,
                _ => p.evaluations_completed() >= 2,
            });
            let termination = if boundary == 0 {
                crate::AttackTermination::Cancelled
            } else {
                crate::AttackTermination::Completed
            };
            public_pe_facts(&result, termination, counts, winner);
        }
        // Distinct objectives also finish all required final rescoring in-block.
        let request = partial_scheduler_request(true, |_| {});
        let result = public_pe_probe(&request, |p| p.evaluations_completed() >= 2);
        public_pe_facts(
            &result,
            crate::AttackTermination::Completed,
            (84, 12, 12, 3),
            Some((0, 1, "CB", 2, false, true, true)),
        );
    }

    #[test]
    fn public_pe_cancellation_and_empty_precedence() {
        use crate::AttackTermination::{Cancelled, Completed, OuterSliceEnd};
        for (distinct, offset, cancel, termination, counts, winner) in [
            (false, 3, true, OuterSliceEnd, (0, 0, 0, 0), None),
            (
                false,
                0,
                false,
                Completed,
                (32, 4, 4, 1),
                Some((0, 0, "CB", 2, false, true, true)),
            ),
            (true, 0, true, Cancelled, (0, 0, 0, 0), None),
            (
                true,
                0,
                false,
                Completed,
                (28, 4, 4, 1),
                Some((0, 1, "CB", 2, false, true, true)),
            ),
        ] {
            let request = partial_scheduler_request(distinct, |job| {
                job["space"]["offset"] = serde_json::json!(offset);
                job["space"]["limit"] = serde_json::json!(1);
            });
            let result = public_pe_probe(&request, |p| {
                cancel || (distinct && p.evaluations_completed() >= 1)
            });
            public_pe_facts(&result, termination, counts, winner);
        }
    }

    #[test]
    fn public_pe_restarts_after_cancel_and_completion() {
        let request = partial_scheduler_request(false, |job| {
            job["space"]["limit"] = serde_json::json!(1);
        });
        let cancelled = public_pe_probe(&request, |_| true);
        public_pe_facts(
            &cancelled,
            crate::AttackTermination::Cancelled,
            (0, 0, 0, 0),
            None,
        );
        for _ in 0..2 {
            let complete = public_pe_probe(&request, |_| false);
            public_pe_facts(
                &complete,
                crate::AttackTermination::Completed,
                (32, 4, 4, 1),
                Some((0, 0, "CB", 2, false, true, true)),
            );
            assert_eq!(complete.best().unwrap().mutable_plugboard(), &[('A', 'C')]);
        }
    }

    #[test]
    fn controlled_partial_outer_cancel_between_outers() {
        let request = partial_scheduler_request(false, |_| {});
        // Independently validate the fixture by running the entire first seed run.
        let (index, initial) = request.outer_candidates().next().unwrap();
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut control = AttackControl::default();
        let mut recorder = Recorder::default();
        let outer = request
            .climb_partial_outer_controlled(
                initial.unwrap(),
                index,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut recorder,
                },
                &mut || false,
            )
            .unwrap();
        assert!(!outer.seeds.cancelled);
        assert_eq!(allowance.used, 32);
        assert_eq!(outer.seeds.seeds.climbs_completed, 4);
        let cancelled = std::cell::Cell::new(false);
        let mut observer = Recorder::default();
        let mut control = AttackControl::default();
        let run = schedule_controlled_partial_with_climb(
            request.gate().outer_selected(),
            request.outer_candidates(),
            &mut ObservedAccounting {
                allowance: &mut EvaluationAllowance { used: 0 },
                control: &mut control,
                observer: &mut observer,
            },
            &mut || cancelled.get(),
            |initial, index, accounting, requested| {
                let outer = request
                    .climb_partial_outer_controlled(initial, index, accounting, requested)?;
                // Inject an external request after the first outer's climbs return;
                // the scheduler accounts that outer before polling the next one.
                cancelled.set(true);
                Ok(outer)
            },
        )
        .unwrap();
        assert!(observer.0.is_empty());
        assert_eq!(run.termination, ControlledPartialTermination::Cancelled);
        assert_eq!(
            (
                run.outer_completed,
                run.climbs_started,
                run.climbs_completed,
                run.evaluations_used
            ),
            (1, 4, 4, 32)
        );
        let outer = run.best.unwrap();
        assert_eq!(outer.outer_index, 0);
        assert_eq!(outer.seeds.seeds.best.unwrap().seed_index, 0);
    }

    fn controlled_partial_outer_probe(
        request: &crate::AttackRequest,
        prior: crate::attack_control::CounterSnapshot,
        stop_at: Option<u64>,
    ) -> (ControlledPartialRun, Recorder, AttackControl) {
        let mut observer = Recorder::default();
        let mut control = AttackControl::with_counters(prior);
        let pending = std::cell::Cell::new(stop_at == Some(0));
        let run = schedule_controlled_partial_with_climb(
            request.gate().outer_selected(),
            request.outer_candidates(),
            &mut ObservedAccounting {
                allowance: &mut EvaluationAllowance { used: 0 },
                control: &mut control,
                observer: &mut observer,
            },
            &mut || pending.get(),
            |initial, index, accounting, requested| {
                let result = request.climb_partial_outer_controlled_with(
                    initial,
                    index,
                    accounting,
                    requested,
                    1,
                    |scoring, _, board, accounting, _| {
                        climb_stopping_when(
                            scoring,
                            board,
                            request.settings().backtrack_pairs(),
                            accounting,
                            |facts| stop_at.is_some_and(|stop| facts.evaluations_completed >= stop),
                        )
                    },
                );
                // If the final evaluation exhausts an outer with no further poll,
                // deliver the independent request at the next outer's entry poll.
                pending.set(stop_at.is_some_and(|stop| {
                    accounting.control.snapshot().evaluations_completed >= stop
                }));
                result
            },
        )
        .unwrap();
        assert!(observer.0.is_empty());
        (run, observer, control)
    }

    #[test]
    fn controlled_partial_outer_early_empty_exhaustion_and_cancellation() {
        for (offset, stop, termination) in [
            (0, Some(0), ControlledPartialTermination::Cancelled),
            (3, Some(0), ControlledPartialTermination::OuterSliceEnd),
        ] {
            let request = partial_scheduler_request(false, |job| {
                job["space"]["offset"] = serde_json::json!(offset);
            });
            let (run, _, control) =
                controlled_partial_outer_probe(&request, Default::default(), stop);
            assert_eq!(run.termination, termination);
            assert!(run.best.is_none());
            assert_eq!(control.snapshot(), Default::default());
        }
        for (limit, stop, termination) in [
            (1, Some(32), ControlledPartialTermination::Completed),
            (3, Some(32), ControlledPartialTermination::Cancelled),
        ] {
            let request = partial_scheduler_request(false, |job| {
                job["space"]["limit"] = serde_json::json!(limit);
            });
            let (run, _, _) = controlled_partial_outer_probe(&request, Default::default(), stop);
            assert_eq!(run.termination, termination);
            assert_eq!(
                (
                    run.outer_completed,
                    run.climbs_completed,
                    run.evaluations_used
                ),
                (1, 4, 32)
            );
            assert_eq!(run.best.unwrap().outer_index, 0);
        }
    }

    #[test]
    fn controlled_partial_outer_inside_seed_finalization_and_prior_deltas() {
        let prior = crate::attack_control::CounterSnapshot {
            evaluations_admitted: 10,
            evaluations_completed: 10,
            climbs_started: 2,
            climbs_completed: 2,
            outers_completed: 1,
        };
        let request = partial_scheduler_request(false, |_| {});
        let (run, _, control) = controlled_partial_outer_probe(&request, prior, Some(12));
        assert_eq!(run.termination, ControlledPartialTermination::Cancelled);
        assert_eq!(
            (
                run.outer_completed,
                run.climbs_started,
                run.climbs_completed
            ),
            (0, 1, 0)
        );
        let best = run.best.unwrap().seeds.seeds.best.unwrap();
        assert!(best.incomplete);
        assert!(best.current.board.is_empty());
        assert_eq!(best.current.plaintext, "CA");
        assert_eq!(best.current.score.ranking().units(), 0);
        assert_eq!(
            control.snapshot().evaluations_completed,
            10 + run.evaluations_used
        );
        // A completed winning seed does not imply completion of later seeds.
        let (run, _, _) = controlled_partial_outer_probe(&request, Default::default(), Some(9));
        assert_eq!(run.termination, ControlledPartialTermination::Cancelled);
        assert_eq!(
            (
                run.outer_completed,
                run.climbs_started,
                run.climbs_completed
            ),
            (0, 1, 1)
        );
        assert!(!run.best.unwrap().seeds.seeds.best.unwrap().incomplete);
    }

    #[test]
    fn controlled_partial_outer_fixed_owner_and_strict_winners() {
        let fixed = partial_scheduler_request(false, |job| {
            job["space"]["offset"] = serde_json::json!(1);
            job["space"]["limit"] = serde_json::json!(1);
            job["configuration"]["plugboard"] = serde_json::json!([["A", "B"]]);
            job["space"]["plugboard"]["symbols"] = serde_json::json!(["C"]);
        });
        let initial = fixed.outer_candidates().next().unwrap().1.unwrap();
        let (run, _, _) = controlled_partial_outer_probe(&fixed, Default::default(), None);
        assert_eq!(run.termination, ControlledPartialTermination::Completed);
        let outer = run.best.unwrap();
        assert_eq!(outer.initial, initial);
        assert_eq!(outer.outer_index, 1);
        assert_eq!(outer.initial.plugboard().map('A'), Some('B'));
        let seed = outer.seeds.seeds.best.unwrap();
        assert!(seed.current.board.is_empty());
        assert_eq!(seed.current.plaintext, "CB");
        assert_eq!(seed.current.score.ranking().units(), 2i128 << 32);
        for (distinct, text, offset, winner, plaintext) in
            [(true, "CB", 0, 1, "BA"), (false, "A", 1, 1, "A")]
        {
            let request = partial_scheduler_request(distinct, |job| {
                job["text"] = serde_json::json!(text);
                job["space"]["offset"] = serde_json::json!(offset);
                job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            });
            let expected = request
                .outer_candidates()
                .nth((winner - offset) as usize)
                .unwrap()
                .1
                .unwrap();
            let (run, _, _) = controlled_partial_outer_probe(&request, Default::default(), None);
            assert_eq!(run.termination, ControlledPartialTermination::Completed);
            let outer = run.best.unwrap();
            assert_eq!(outer.outer_index, winner);
            assert_eq!(outer.initial, expected);
            let seed = outer.seeds.seeds.best.unwrap();
            assert_eq!(seed.seed_index, 0);
            assert_eq!(seed.current.plaintext, plaintext);
        }
    }

    #[test]
    fn controlled_partial_outer_indexed_failures_and_terminal_snapshots() {
        use crate::attack_control::{CounterOverflow, CounterSnapshot};
        let request = partial_scheduler_request(false, |_| {});
        for (prior, expected, seed, used) in [
            (
                CounterSnapshot {
                    evaluations_admitted: u64::MAX,
                    ..Default::default()
                },
                CounterOverflow::EvaluationsAdmitted,
                Some(0),
                1,
            ),
            (
                CounterSnapshot {
                    evaluations_completed: u64::MAX,
                    ..Default::default()
                },
                CounterOverflow::EvaluationsCompleted,
                Some(0),
                1,
            ),
            (
                CounterSnapshot {
                    climbs_started: u128::MAX,
                    ..Default::default()
                },
                CounterOverflow::ClimbsStarted,
                Some(0),
                1,
            ),
            (
                CounterSnapshot {
                    climbs_completed: u128::MAX,
                    ..Default::default()
                },
                CounterOverflow::ClimbsCompleted,
                Some(0),
                9,
            ),
            (
                CounterSnapshot {
                    outers_completed: u128::MAX,
                    ..Default::default()
                },
                CounterOverflow::OutersCompleted,
                None,
                32,
            ),
        ] {
            let mut control = AttackControl::with_counters(prior);
            let mut recorder = Recorder::default();
            let error = request
                .schedule_partial_outers_controlled(&mut control, &mut recorder, || false)
                .unwrap_err();
            assert_eq!(
                (error.outer_index, error.seed_index, error.evaluations_used),
                (Some(0), seed, used)
            );
            assert!(matches!(error.source, ControlledPartialRunSource::Climb(
                ControlledPartialSource::Climb(ObservedClimbError::Counter(actual))
            ) if actual == expected));
            assert!(recorder.0.is_empty());
            assert_eq!(error.counters, control.snapshot());
            let projected = error.project(request.domain(), MeasureId::Trie);
            assert_eq!(projected.evaluations_used(), used);
            assert_eq!(
                projected.counters(),
                crate::AttackProgress(control.snapshot())
            );
            assert_eq!(projected.start_index(), seed);
            assert!(projected.best().unwrap().is_none());
            assert_eq!(
                projected.run_source().overflow(),
                Some(match expected {
                    CounterOverflow::EvaluationsAdmitted =>
                        crate::AttackCounterOverflow::EvaluationsAdmitted,
                    CounterOverflow::EvaluationsCompleted =>
                        crate::AttackCounterOverflow::EvaluationsCompleted,
                    CounterOverflow::ClimbsStarted => crate::AttackCounterOverflow::ClimbsStarted,
                    CounterOverflow::ClimbsCompleted =>
                        crate::AttackCounterOverflow::ClimbsCompleted,
                    CounterOverflow::OutersCompleted =>
                        crate::AttackCounterOverflow::OutersCompleted,
                })
            );
        }
        let mut control = AttackControl::default();
        let mut recorder = Recorder::default();
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut accounting = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut recorder,
        };
        let error = schedule_controlled_partial(
            &request,
            1,
            std::iter::empty(),
            &mut accounting,
            &mut || false,
            1,
        )
        .unwrap_err();
        assert_eq!(
            (error.outer_index, error.seed_index, error.evaluations_used),
            (None, None, 7)
        );
        assert!(matches!(
            error.source,
            ControlledPartialRunSource::MissingOuter
        ));
        let error = schedule_controlled_partial(
            &request,
            1,
            std::iter::once((42, Err(vec![]))),
            &mut accounting,
            &mut || false,
            1,
        )
        .unwrap_err();
        assert_eq!(
            (error.outer_index, error.seed_index, error.evaluations_used),
            (Some(42), None, 7)
        );
        assert!(
            matches!(error.source, ControlledPartialRunSource::Resolution(diagnostics) if diagnostics.is_empty())
        );
        let wrong = scheduler_request(false, false, 0);
        let error = wrong
            .schedule_partial_outers_controlled(&mut control, &mut recorder, || true)
            .unwrap_err();
        assert!(matches!(
            error.source,
            ControlledPartialRunSource::Climb(ControlledPartialSource::UnsupportedPass)
        ));
        assert!(recorder.0.is_empty());
    }

    #[test]
    fn controlled_partial_outer_binding_and_resolution_sources() {
        use crate::attack_control::CounterSnapshot;
        let request = partial_scheduler_request(true, |job| {
            job["configuration"]["plugboard"] = serde_json::json!([["A", "B"]]);
            job["space"]["plugboard"]["symbols"] = serde_json::json!(["C"]);
        });
        let index = u128::from(u64::MAX) + 7;
        let diagnostics = vec![crate::SearchDiagnostic::new(
            "invalid_search_space",
            "injected aggregate resolution",
            "/job/space",
        )];
        for fault in 0..2 {
            let initial = if fault == 1 {
                fixture().0
            } else {
                request.outer_candidates().next().unwrap().1.unwrap()
            };
            let item = if fault == 0 {
                Err(diagnostics.clone())
            } else {
                Ok(initial)
            };
            let prior = CounterSnapshot {
                evaluations_admitted: 3,
                evaluations_completed: 2,
                climbs_started: 2,
                climbs_completed: 1,
                outers_completed: 1,
            };
            let mut control = AttackControl::with_counters(prior);
            let mut recorder = Recorder::default();
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut polls = 0;
            let error = schedule_controlled_partial(
                &request,
                1,
                std::iter::once((index, item)),
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut recorder,
                },
                &mut || {
                    polls += 1;
                    false
                },
                1,
            )
            .unwrap_err();
            assert_eq!(error.outer_index, Some(index));
            assert_eq!(error.seed_index, None);
            assert_eq!(error.evaluations_used, 7);
            assert_eq!(allowance.used, error.evaluations_used);
            match fault {
                0 => assert!(matches!(error.source,
                    ControlledPartialRunSource::Resolution(actual) if actual == diagnostics)),
                _ => assert!(matches!(
                    error.source,
                    ControlledPartialRunSource::Climb(ControlledPartialSource::Climb(
                        ObservedClimbError::Evaluation(TrialEvaluationError::Board(
                            crate::attack_evaluator::TrialBoardError::FixedFactsBinding
                        ))
                    ))
                )),
            }
            assert_eq!(polls, 1);
            assert_eq!(control.snapshot(), prior);
            assert!(recorder.0.is_empty());
        }
    }

    #[test]
    fn controlled_partial_outer_charged_evaluator_mapping_with_pending_cancel() {
        use crate::attack_control::CounterSnapshot;
        let owner = partial_scheduler_request(true, |_| {});
        let initial = owner.outer_candidates().next().unwrap().1.unwrap();
        let index = u128::from(u64::MAX) + 7;
        let prior = CounterSnapshot {
            evaluations_admitted: 3,
            evaluations_completed: 2,
            climbs_started: 2,
            climbs_completed: 1,
            outers_completed: 1,
        };
        let mut control = AttackControl::with_counters(prior);
        let mut allowance = EvaluationAllowance { used: 7 };
        let pending = std::cell::Cell::new(false);
        let mut observer = Recorder::default();
        let mut polls = 0;
        let mut expected = None;
        // Helper-qualified synthetic Board/seed-context fault, not a valid-owner runtime failure.
        let error = schedule_controlled_partial_with_climb(
            1,
            std::iter::once((index, Ok(initial))),
            &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            },
            &mut || {
                polls += 1;
                pending.get()
            },
            |initial, index, accounting, _| {
                let evaluator = TrialEvaluator::new(
                    &initial,
                    owner.domain(),
                    owner.text(),
                    Direction::Decrypt,
                    owner.settings().initial_measure(),
                    owner.bound_resource(owner.settings().initial_measure()),
                );
                let original = evaluator.evaluate(&[('A', 'Z')]).unwrap_err();
                assert!(matches!(original, TrialEvaluationError::Board(_)));
                expected = Some(original);
                // External cancellation arrives after the scheduler poll, before
                // this nonpreemptible failing evaluation; no observer drives it.
                pending.set(true);
                let source = accounting.evaluate(&evaluator, &[('A', 'Z')]).unwrap_err();
                Err(ControlledPartialError::from_seed(
                    index,
                    initial.clone(),
                    ControlledSeedError {
                        seed_index: Some(2),
                        source,
                        best: None,
                    },
                ))
            },
        )
        .unwrap_err();
        assert_eq!(
            (error.outer_index, error.seed_index, error.evaluations_used),
            (Some(index), Some(2), 8)
        );
        assert_eq!(allowance.used, 8);
        assert_eq!(
            control.snapshot(),
            CounterSnapshot {
                evaluations_admitted: 4,
                ..prior
            }
        );
        assert!(
            matches!(error.source, ControlledPartialRunSource::Climb(actual)
            if actual == ControlledPartialSource::Climb(expected.unwrap().into()))
        );
        assert!(pending.get());
        assert_eq!(polls, 1); // No post-fault poll masks the admitted evaluator error.
        assert!(
            observer.0.is_empty(),
            "failed evaluations do not advance cadence"
        );
    }

    fn partial_counts(run: &PartialRunOutcome) -> (u128, u128, u128, u64) {
        (
            run.outer_completed,
            run.climbs_started,
            run.climbs_completed,
            run.evaluations_used,
        )
    }

    #[test]
    fn partial_outer_scheduler_empty_and_wrong_pass() {
        let run = scheduler_request(false, true, 3)
            .schedule_partial_outers()
            .unwrap();
        assert_eq!(run.termination, PartialRunTermination::OuterSliceEnd);
        assert_eq!(partial_counts(&run), (0, 0, 0, 0));
        assert!(run.best.is_none());
        for offset in [0, 3] {
            let error = scheduler_request(false, false, offset)
                .schedule_partial_outers()
                .unwrap_err();
            assert_eq!((error.outer_index, error.evaluations_used), (None, 0));
            assert!(matches!(
                error.source,
                PartialRunError::Climb(PartialClimbError::UnsupportedPass)
            ));
        }
    }

    #[test]
    fn partial_outer_scheduler_order_exact_boundary_and_seed_boundaries() {
        for (selection, cost, seeds) in [("all", 32, 4), ("touching", 26, 3)] {
            let request = partial_scheduler_request(false, |job| {
                job["space"]["limit"] = serde_json::json!(1);
                job["attack"]["seeds"]["selection"] = serde_json::json!(selection);
                if selection == "touching" {
                    job["attack"]["seeds"]["symbols"] = serde_json::json!(["B"]);
                }
            });
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let run = request.schedule_partial_outers().unwrap();
            assert_eq!(run.termination, PartialRunTermination::Completed);
            assert_eq!(partial_counts(&run), (1, seeds, seeds, cost));
            let outer = run.best.unwrap();
            assert_eq!(outer.initial, initial);
            assert_eq!(outer.outer_index, 0);
            let best = outer.seeds.best.unwrap();
            assert_eq!(best.seed_index, 0);
            assert_eq!(best.current.board, vec![('A', 'C')]);
            assert_eq!(best.current.plaintext, "CB");
            assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
            assert!(!best.incomplete);
            assert!(best.neighborhood_exhausted && best.final_objective_ascent);
        }
    }

    #[test]
    fn partial_outer_scheduler_matches_ordered_adapter_composition() {
        // Supplemental composition oracle; the boundary tests above retain the
        // literal A-outer costs, plaintext, scores and independent seed counts.
        let request = scheduler_request(false, true, 0);
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut expected: Option<PartialOuterOutcome> = None;
        for (index, initial) in request.outer_candidates() {
            let outer = request
                .climb_partial_outer(initial.unwrap(), index, &mut allowance)
                .unwrap();
            assert_eq!(
                (outer.seeds.climbs_started, outer.seeds.climbs_completed),
                (4, 4)
            );
            if expected.as_ref().is_none_or(|best| {
                outer
                    .seeds
                    .best
                    .as_ref()
                    .unwrap()
                    .current
                    .score
                    .ranking()
                    .units()
                    > best
                        .seeds
                        .best
                        .as_ref()
                        .unwrap()
                        .current
                        .score
                        .ranking()
                        .units()
            }) {
                expected = Some(outer);
            }
        }
        let run = request.schedule_partial_outers().unwrap();
        assert_eq!(run.termination, PartialRunTermination::Completed);
        assert_eq!(partial_counts(&run), (3, 12, 12, allowance.used));
        let outer = run.best.unwrap();
        let expected = expected.unwrap();
        assert_eq!(outer.outer_index, 0);
        assert_eq!(outer.outer_index, expected.outer_index);
        assert_eq!(outer.initial, expected.initial);
        let best = outer.seeds.best.unwrap();
        let expected = expected.seeds.best.unwrap();
        assert_eq!(best.seed_index, 0);
        assert_eq!(best.current, expected.current);
        assert_eq!(best.current.plaintext, "CB");
        assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
        assert!(!best.incomplete);
        assert!(best.neighborhood_exhausted && best.final_objective_ascent);
    }

    #[test]
    fn partial_outer_scheduler_distinct_objectives_and_zero_cost_completion() {
        for single in [true, false] {
            let run = partial_scheduler_request(true, |job| {
                job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
                if single {
                    job["space"]["limit"] = serde_json::json!(1);
                }
            })
            .schedule_partial_outers()
            .unwrap();
            let count = if single { 1 } else { 3 };
            assert_eq!(
                partial_counts(&run),
                (count, count, count, count as u64 * 2)
            );
            assert_eq!(run.termination, PartialRunTermination::Completed);
            let best = run.best.unwrap().seeds.best.unwrap();
            assert_eq!(best.current.plaintext, "CA");
            assert_eq!(best.current.score.ranking().units(), 0);
            assert!(!best.incomplete && best.neighborhood_exhausted);
            assert!(!best.final_objective_ascent);
        }
    }

    #[test]
    fn partial_outer_scheduler_literal_later_winner_tie_and_dense_seed() {
        let run = partial_scheduler_request(true, |job| {
            job["text"] = serde_json::json!("CB");
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
        })
        .schedule_partial_outers()
        .unwrap();
        assert_eq!(run.termination, PartialRunTermination::Completed);
        assert_eq!(partial_counts(&run), (3, 3, 3, 6));
        let outer = run.best.unwrap();
        assert_eq!(outer.outer_index, 1);
        let best = outer.seeds.best.unwrap();
        assert_eq!(best.seed_index, 0);
        assert_eq!(best.current.plaintext, "BA");
        assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
        let ties = partial_scheduler_request(false, |job| {
            job["text"] = serde_json::json!("A");
            job["space"]["offset"] = serde_json::json!(1);
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
        })
        .schedule_partial_outers()
        .unwrap();
        assert_eq!(ties.termination, PartialRunTermination::Completed);
        assert_eq!(partial_counts(&ties), (2, 2, 2, 2));
        let outer = ties.best.unwrap();
        assert_eq!(outer.outer_index, 1); // Earliest SELECTED absolute outer.
        assert_eq!(outer.seeds.best.unwrap().current.score.ranking().units(), 0);
        for (selection, used, climbs) in [("all", 84, 12), ("touching", 61, 9)] {
            let request = partial_scheduler_request(true, |job| {
                job["attack"]["seeds"]["selection"] = serde_json::json!(selection);
                if selection == "touching" {
                    job["attack"]["seeds"]["symbols"] = serde_json::json!(["C"]);
                }
            });
            let run = public_pe_probe(&request, |p| p.evaluations_completed() >= 7);
            public_pe_facts(
                &run,
                crate::AttackTermination::Completed,
                (used, climbs, climbs, 3),
                Some((0, 1, "CB", 2, false, true, true)),
            );
        }
    }

    #[test]
    fn partial_outer_scheduler_preserves_owned_fixed_facts() {
        let request = partial_scheduler_request(false, |job| {
            job["space"]["offset"] = serde_json::json!(1);
            job["space"]["limit"] = serde_json::json!(1);
            job["configuration"]["plugboard"] = serde_json::json!([["A", "B"]]);
            job["space"]["plugboard"]["symbols"] = serde_json::json!(["C"]);
        });
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        assert_eq!(initial.topology().slots()[0].position(), 'B');
        assert_eq!(initial.plugboard().map('A'), Some('B'));
        let run = request.schedule_partial_outers().unwrap();
        assert_eq!(run.termination, PartialRunTermination::Completed);
        assert_eq!(partial_counts(&run), (1, 1, 1, 1));
        let outer = run.best.unwrap();
        assert_eq!(outer.outer_index, 1);
        assert_eq!(outer.initial, initial);
        let best = outer.seeds.best.unwrap();
        assert_eq!(best.seed_index, 0);
        assert!(best.current.board.is_empty());
        assert_eq!(best.current.plaintext, "CB");
        assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
        assert!(!best.incomplete && best.neighborhood_exhausted);
        assert!(best.final_objective_ascent);
    }

    #[test]
    fn direct_outer_scheduler_empty_and_unsupported_pass() {
        let empty = scheduler_request(false, false, 3)
            .schedule_direct_outers()
            .unwrap();
        assert_eq!(empty.termination, DirectRunTermination::OuterSliceEnd);
        assert_eq!(
            (
                empty.outer_completed,
                empty.climbs_started,
                empty.climbs_completed,
                empty.evaluations_used
            ),
            (0, 0, 0, 0)
        );
        assert!(empty.best.is_none());
        for offset in [0, 3] {
            let error = scheduler_request(false, true, offset)
                .schedule_direct_outers()
                .unwrap_err();
            assert!(matches!(
                error.source,
                DirectRunError::Climb(DirectClimbError::UnsupportedPass)
            ));
            assert_eq!(error.evaluations_used, 0);
        }
    }

    #[test]
    fn controlled_outer_cancel_between_outers() {
        let pending = std::cell::Cell::new(false);
        let mut observer = Recorder::default();
        let mut control = AttackControl::default();
        let request = scheduler_request(false, false, 0);
        let run = schedule_controlled_direct(
            request.gate().outer_selected(),
            request.outer_candidates(),
            &mut ObservedAccounting {
                allowance: &mut EvaluationAllowance { used: 0 },
                control: &mut control,
                observer: &mut observer,
            },
            &mut || pending.get(),
            |initial, index, accounting, requested| {
                let (scoring, start) = request
                    .direct_scoring(&initial)
                    .map_err(DirectRunError::Climb)?;
                let climb = scoring
                    .climb_cancellable(start, 0, accounting, requested)
                    .map_err(DirectRunError::from)?;
                // External cancellation arrives after the completed climb, before
                // the next outer poll. Accounting still records the first outer.
                pending.set(true);
                Ok(DirectOuterOutcome {
                    initial,
                    outer_index: index,
                    start_index: 0,
                    climb,
                })
            },
            |outcome| Ok(Some(outcome)),
        )
        .unwrap();
        assert_eq!(run.termination, DirectRunTermination::Cancelled);
        assert_eq!(direct_counts(&run), (1, 1, 1, 9));
        let best = run.best.unwrap();
        assert_eq!(best.outer_index, 0);
        assert_eq!(best.start_index, 0);
        let current = best.climb.current.unwrap();
        assert_eq!(current.board, vec![('A', 'C')]);
        assert_eq!(current.plaintext, "CB");
        assert_eq!(current.score.ranking().units(), 2i128 << 32);
        assert!(best.climb.neighborhood_exhausted && best.climb.final_objective_ascent);
        assert!(!best.climb.cancelled && !best.climb.incomplete);
        let snapshot = control.snapshot();
        assert_eq!(
            (
                snapshot.evaluations_admitted,
                snapshot.evaluations_completed
            ),
            (9, 9)
        );
        assert_eq!(
            (
                snapshot.climbs_started,
                snapshot.climbs_completed,
                snapshot.outers_completed
            ),
            (1, 1, 1)
        );
        assert!(observer.0.is_empty());
    }

    fn direct_counts(run: &DirectRunOutcome) -> (u128, u128, u128, u64) {
        (
            run.outer_completed,
            run.climbs_started,
            run.climbs_completed,
            run.evaluations_used,
        )
    }

    fn controlled_run(
        request: &crate::AttackRequest,
        stop: usize,
    ) -> (DirectRunOutcome, crate::attack_control::CounterSnapshot) {
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let mut polls = 0;
        let run = request
            .schedule_direct_outers_controlled(&mut control, &mut observer, || {
                polls += 1;
                polls == stop // Subsequent false polls must not clear cancellation.
            })
            .unwrap();
        assert!(observer.0.is_empty());
        (run, control.snapshot())
    }

    #[test]
    fn controlled_outer_entry_exhaustion_and_pass_precedence() {
        for (offset, pe, reason) in [
            (0, false, Some(DirectRunTermination::Cancelled)),
            (3, false, Some(DirectRunTermination::OuterSliceEnd)),
            (3, true, None),
        ] {
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            control.poll_cancellation(offset == 0);
            let mut polls = 0;
            let run = scheduler_request(false, pe, offset).schedule_direct_outers_controlled(
                &mut control,
                &mut observer,
                || {
                    polls += 1;
                    offset != 0
                },
            );
            if let Some(reason) = reason {
                let run = run.unwrap();
                assert_eq!(run.termination, reason);
                assert!(run.best.is_none());
                assert_eq!(direct_counts(&run), (0, 0, 0, 0));
            } else {
                let error = run.unwrap_err();
                assert!(matches!(
                    error.source,
                    DirectRunError::Climb(DirectClimbError::UnsupportedPass)
                ));
                assert_eq!(error.outer_index, None);
            }
            assert_eq!(polls, usize::from(offset == 0));
            assert_eq!(control.snapshot(), Default::default());
            assert_eq!(observer.0.last(), observer.0.first());
        }
    }

    #[test]
    fn controlled_outer_scan_and_required_finalization() {
        // One outer-entry poll precedes the existing single-climb safe points.
        for (stop, used, paired) in [
            (3, 1, false),
            (5, 2, false),
            (7, 3, false),
            (9, 4, false),
            (10, 4, true),
        ] {
            let (run, snapshots) = controlled_run(&scheduler_request(false, false, 0), stop);
            assert_eq!(run.termination, DirectRunTermination::Cancelled);
            assert_eq!(direct_counts(&run), (0, 1, 0, used));
            let best = run.best.unwrap();
            let current = best.climb.current.unwrap();
            assert_eq!(
                current.board,
                if paired { vec![('A', 'C')] } else { vec![] }
            );
            assert_eq!(current.plaintext, if paired { "CB" } else { "CA" });
            assert_eq!(
                current.score.ranking().units(),
                if paired { 2i128 << 32 } else { 0 }
            );
            assert!(
                best.climb.cancelled && best.climb.incomplete && !best.climb.neighborhood_exhausted
            );
            assert_eq!(best.climb.final_objective_ascent, paired);
            let final_snapshot = snapshots;
            assert_eq!(
                (
                    final_snapshot.evaluations_admitted,
                    final_snapshot.evaluations_completed
                ),
                (used, used)
            );
        }
        for distinct in [false, true] {
            let (run, _) = controlled_run(&scheduler_request(distinct, false, 0), 3);
            assert_eq!(run.evaluations_used, if distinct { 2 } else { 1 });
            assert_eq!(run.best.unwrap().climb.current.unwrap().plaintext, "CA");
        }
    }

    #[test]
    fn controlled_outer_legacy_equivalence_and_prior_counters() {
        for (distinct, offset) in [(false, 0), (true, 1), (true, 0)] {
            let request = scheduler_request(distinct, false, offset);
            let expected = request.schedule_direct_outers().unwrap();
            let mut control = AttackControl::default();
            control.record_climb_started().unwrap();
            control.record_climb_completed().unwrap();
            control.record_outer_completed().unwrap();
            let before = control.snapshot();
            let mut observer = Recorder::default();
            let run = request
                .schedule_direct_outers_controlled(&mut control, &mut observer, || false)
                .unwrap();
            assert_eq!(run.termination, expected.termination);
            assert_eq!(direct_counts(&run), direct_counts(&expected));
            if let Some(best) = run.best {
                let expected = expected.best.unwrap();
                assert_eq!(
                    (best.outer_index, best.start_index),
                    (expected.outer_index, expected.start_index)
                );
                assert_eq!(best.initial, expected.initial);
                assert_eq!(best.climb.current, expected.climb.current);
                assert_eq!(
                    best.climb.neighborhood_exhausted,
                    expected.climb.neighborhood_exhausted
                );
                assert_eq!(
                    best.climb.final_objective_ascent,
                    expected.climb.final_objective_ascent
                );
                assert_eq!(best.climb.incomplete, expected.climb.incomplete);
                assert!(!best.climb.cancelled);
            } else {
                assert!(expected.best.is_none());
            }
            assert!(observer.0.is_empty());
            assert_eq!(
                control.snapshot().outers_completed,
                before.outers_completed + run.outer_completed
            );
        }
        let empty = direct_request_with(serde_json::json!([]), false, false, |job| {
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
        });
        // Initial success latches cancellation, but established empty exhaustion wins.
        let (run, _) = controlled_run(&empty, 3);
        assert_eq!(run.termination, DirectRunTermination::Completed);
        assert_eq!(direct_counts(&run), (1, 1, 1, 1));
        let fixed = direct_request_with(serde_json::json!([]), false, false, |job| {
            job["configuration"]["plugboard"] = serde_json::json!([["A", "B"]]);
            job["space"]["plugboard"]["symbols"] = serde_json::json!(["C"]);
        });
        let expected = fixed.schedule_direct_outers().unwrap().best.unwrap();
        let (run, _) = controlled_run(&fixed, 0);
        let best = run.best.unwrap();
        assert_eq!(best.initial, expected.initial);
        assert_eq!(best.initial.plugboard().map('A'), Some('B'));
        assert_eq!(best.climb.current, expected.climb.current);
    }

    fn projection_fixture() -> (crate::AttackRequest, DirectOuterOutcome) {
        projection_fixture_at("é")
    }

    fn projection_fixture_at(position: &str) -> (crate::AttackRequest, DirectOuterOutcome) {
        let alphabet = ["🦀", "é", "Ω", "中"];
        let json = serde_json::json!({
            "protocol_version": 1, "machine": {"definition": {"kind": "custom", "value": {
                "alphabet": alphabet, "wheels": [{"name": "r", "wiring": alphabet, "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
                "stepping": {"rules": []}
            }}}, "job": {
                "kind": "search", "configuration": {"slots": [{"id": "r", "position": position, "ring": "Ω"}],
                    "plugboard": [["中", "é"]]}, "text": "🦀🦀", "measures": ["ic"], "passes": ["hill_climb"],
                "space": {"plugboard": {"kind": "attack", "symbols": ["🦀", "Ω"], "max_pairs": 2}},
                "attack": {"kind": "hill_climb", "initial_measure": "ic", "final_measure": "ic",
                    "switch_pairs": 2, "backtrack_pairs": 2, "start": [["Ω", "🦀"]]}
            }
        });
        let request = crate::AttackRequest::parse_json(&json.to_string()).unwrap();
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let outcome = request
            .climb_direct_outer(initial, u128::MAX, &mut EvaluationAllowance { used: 0 })
            .unwrap();
        (request, outcome)
    }

    #[test]
    fn hc_hold_canonical_rank_ties_and_eviction() {
        let (request, _) = projection_fixture();
        let mut acceptance = DirectAcceptance::new(2);
        for (index, rank, empty, reverse) in [
            (0, -9, false, false),
            (1, -9, false, true),
            (2, 4, true, false),
            (3, 4, false, false),
        ] {
            let (_, mut outcome) = projection_fixture();
            outcome.outer_index = index;
            let current = outcome.climb.current.as_mut().unwrap();
            current.score = MeasuredScore::higher_is_better(FixedScore::from_units(rank));
            if empty {
                current.board.clear();
            } else if reverse {
                for pair in &mut current.board {
                    *pair = (pair.1, pair.0);
                }
            }
            // A distinct slot key permits capacity eviction; the equal rank keeps index 2 first.
            if index == 3 {
                outcome.initial = projection_fixture_at("Ω").1.initial;
            }
            acceptance
                .accept(outcome, request.domain(), MeasureId::Ic)
                .unwrap();
            if index == 1 {
                let entries = acceptance.0.as_ref().unwrap().entries();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].outer_index(), 0);
            }
        }
        let entries = acceptance.0.unwrap().into_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.iter().map(|e| e.outer_index).collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(entries[1].mutable_plugboard, [('🦀', 'Ω')]);
    }

    // Synthetic internal faults are unreachable through validated external requests.
    fn hc_hold_fault_run(
        capacity: usize,
        fault: u8,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        let (request, _) = projection_fixture();
        let mut acceptance = DirectAcceptance::new(capacity);
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let mut allowance = EvaluationAllowance { used: 0 };
        let outers = ["é", "Ω", "中"]
            .into_iter()
            .enumerate()
            .map(|(i, p)| (i as u128, Ok(projection_fixture_at(p).1.initial)));
        let run = schedule_controlled_direct(
            3,
            outers,
            &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            },
            &mut || false,
            |initial, index, accounting, requested| {
                if (fault == 4 && index == 1) || (fault == 8 && index == 2) {
                    return Err(DirectRunError::Climb(DirectClimbError::Evaluation(
                        TrialEvaluationError::Model(crate::ModelError::UnknownSymbol('Z')),
                    )));
                }
                let (scoring, start) = request.direct_scoring(&initial).unwrap();
                let climb = scoring
                    .climb_cancellable(start, 2, accounting, requested)
                    .map_err(DirectRunError::from)?;
                let mut outcome = DirectOuterOutcome {
                    initial,
                    outer_index: index,
                    start_index: 0,
                    climb,
                };
                let current = outcome.climb.current.as_mut().unwrap();
                current.score =
                    MeasuredScore::higher_is_better(FixedScore::from_units(index as i128));
                if (fault == 2 && index == 2) || ((fault == 3 || fault == 4) && index == 0) {
                    current.board.push(('Z', '🦀'));
                }
                if index == 2 {
                    if fault == 1 {
                        let mut counters = accounting.control.snapshot();
                        counters.outers_completed = u128::MAX;
                        *accounting.control = AttackControl::with_counters(counters);
                    } else if fault >= 5 {
                        outcome.climb.neighborhood_exhausted = false;
                        outcome.climb.cancelled = true;
                        outcome.climb.incomplete = false;
                        if fault == 7 {
                            outcome.climb.current = None;
                        }
                    }
                }
                Ok(outcome)
            },
            |outcome| acceptance.accept(outcome, request.domain(), MeasureId::Ic),
        );
        assert!(observer.0.is_empty());
        let result = acceptance.finish(run, control.snapshot(), request.domain(), MeasureId::Ic);
        let (used, counters) = match &result {
            Ok(r) => (r.evaluations_used, r.counters),
            Err(e) => (e.evaluations_used(), e.counters()),
        };
        assert_eq!(used, allowance.used);
        assert_eq!(counters, crate::AttackProgress(control.snapshot()));
        result
    }

    #[test]
    fn hc_hold_transactional_overflow_and_projection_faults() {
        use crate::AttackRunCategory::{Counter, Evaluation, Invariant};
        for (fault, category, outers) in [
            (1, Counter, u128::MAX),
            (2, Invariant, 3),
            (8, Evaluation, 2),
        ] {
            let error = hc_hold_fault_run(2, fault).unwrap_err();
            assert_eq!(error.outer_index(), Some(2));
            assert_eq!(error.start_index(), Some(0));
            assert_eq!(error.best().unwrap().unwrap().outer_index(), 1);
            assert_eq!(error.held_tail()[0].outer_index(), 0);
            assert_eq!(error.held_tail().len(), 1);
            assert_eq!(error.counters().outers_completed(), outers);
            assert_eq!(error.run_source().category(), category);
            if fault == 1 {
                assert_eq!(
                    error.run_source().overflow(),
                    Some(crate::AttackCounterOverflow::OutersCompleted)
                );
            } else if fault == 2 {
                assert!(error.to_string().contains("projection failed"));
            } else {
                assert!(matches!(
                    error.run_source().0,
                    crate::attack_result::RunPayload::Evaluation(TrialEvaluationError::Model(
                        crate::ModelError::UnknownSymbol('Z')
                    ))
                ));
            }
        }
    }

    #[test]
    fn hc_hold_capacity_one_keeps_lazy_projection_and_original_fault() {
        assert_eq!(
            hc_hold_fault_run(1, 3).unwrap().best.unwrap().outer_index(),
            2
        );
        let eager = hc_hold_fault_run(3, 3).unwrap_err();
        assert_eq!(eager.outer_index(), Some(0));
        assert_eq!(
            eager.run_source().category(),
            crate::AttackRunCategory::Invariant
        );
        assert!(eager.best().is_err());
        let lazy = hc_hold_fault_run(1, 4).unwrap_err();
        assert_eq!(lazy.outer_index(), Some(1));
        assert_eq!(
            lazy.run_source().category(),
            crate::AttackRunCategory::Evaluation
        );
        assert!(lazy
            .best()
            .unwrap_err()
            .downcast_ref::<ProjectionError>()
            .is_some());
        assert!(matches!(
            lazy.run_source().0,
            crate::attack_result::RunPayload::Evaluation(TrialEvaluationError::Model(
                crate::ModelError::UnknownSymbol('Z')
            ))
        ));
    }

    #[test]
    fn hc_hold_interrupted_scored_and_unstarted_offers() {
        let actual = scheduler_request(false, false, 0)
            .run(|_| {}, || false)
            .unwrap();
        assert_eq!(actual.held_tail.len(), 2);
        for fault in [5, 6, 7] {
            let result = hc_hold_fault_run(3, fault).unwrap();
            assert_eq!(result.termination, crate::AttackTermination::Cancelled);
            let head = result.best.unwrap();
            assert_eq!(head.outer_index(), if fault == 7 { 1 } else { 2 });
            assert_eq!(head.incomplete(), fault != 7);
            assert_eq!(result.held_tail.len(), if fault == 7 { 1 } else { 2 });
        }
    }

    #[test]
    fn hc_hold_capacity_one_matches_raw_observation_and_polling() {
        for stop in [usize::MAX, 1, 3, 10] {
            let request = direct_request_with(serde_json::json!([]), false, false, |job| {
                job["attack"]["hold"] = serde_json::json!(1);
            });
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let raw = request
                .schedule_direct_outers_controlled(&mut control, &mut observer, || stop == 1)
                .unwrap();
            let expected = raw
                .project_public(
                    control.snapshot(),
                    request.domain(),
                    request.settings().final_measure(),
                )
                .unwrap();
            let mut snapshots = Vec::new();
            let mut polls = 0;
            let actual = request
                .run(
                    |p| snapshots.push(p.0),
                    || {
                        polls += 1;
                        polls == stop
                    },
                )
                .unwrap();
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
            assert!(observer.0.is_empty());
            assert_eq!(snapshots, [Default::default(), control.snapshot()]);
            assert_eq!(polls, 1);
        }
    }

    #[derive(Default)]
    struct PeHoldTrace {
        entered: Vec<(u128, u128)>,
        post_climb: Vec<(u64, crate::attack_control::CounterSnapshot)>,
    }

    // Synthetic board-keyed scores and faults drive the production seed loop.
    fn pe_hold_fault_run(
        capacity: usize,
        fault: u8,
    ) -> Result<crate::AttackResult, crate::AttackRunError> {
        pe_hold_fault_run_at(capacity, fault, (1, 2)).0
    }

    fn pe_hold_fault_run_at(
        capacity: usize,
        fault: u8,
        coordinates: (u128, u128),
    ) -> (
        Result<crate::AttackResult, crate::AttackRunError>,
        PeHoldTrace,
    ) {
        let mut trace = PeHoldTrace::default();
        let request = partial_scheduler_request(false, |_| {});
        let mut control = AttackControl::with_counters(crate::attack_control::CounterSnapshot {
            outers_completed: if fault == 1 { u128::MAX - 1 } else { 0 },
            ..Default::default()
        });
        // Fault 4 drops the third outer; fault 5 makes it unresolvable.
        let outers = request
            .outer_candidates()
            .take(if fault == 4 { 2 } else { 3 });
        let run = schedule_controlled_partial_with_climb(
            3,
            outers.map(|(i, outer)| match (fault, i) {
                (5, 2) => (i, Err(Vec::new())),
                _ => (i, outer),
            }),
            &mut ObservedAccounting {
                allowance: &mut EvaluationAllowance { used: 0 },
                control: &mut control,
                observer: &mut Recorder::default(),
            },
            &mut || false,
            |initial, index, accounting, requested| {
                request.climb_partial_outer_controlled_with(
                    initial,
                    index,
                    accounting,
                    requested,
                    capacity,
                    |scoring, seed, board, accounting, requested| {
                        trace.entered.push((index, seed));
                        let target = (index, seed) == coordinates;
                        if fault == 3 && target {
                            return Err(TrialEvaluationError::Model(
                                crate::ModelError::UnknownSymbol('Z'),
                            )
                            .into());
                        }
                        let climb = scoring.climb_cancellable(board, 0, accounting, requested);
                        trace
                            .post_climb
                            .push((accounting.allowance.used, accounting.control.snapshot()));
                        let mut climb = climb?;
                        let current = climb.current.as_mut().unwrap();
                        let rank = match current.board.as_slice() {
                            [('A', 'C') | ('C', 'A')] => 30,
                            [('A', 'B') | ('B', 'A')] => 20,
                            _ => 10,
                        };
                        current.score =
                            MeasuredScore::higher_is_better(FixedScore::from_units(rank));
                        if fault == 2 && target {
                            current.board.push(('Z', 'A'));
                        }
                        Ok(climb)
                    },
                )
            },
        );
        let result = match run {
            Ok(run) => run.project_public(control.snapshot(), request.domain(), MeasureId::Trie),
            Err(error) => Err(error.project(request.domain(), MeasureId::Trie)),
        };
        (result, trace)
    }

    fn pe_hold_indices(
        best: Option<&crate::AttackBest>,
        tail: &[crate::AttackBest],
    ) -> Vec<(u128, u128)> {
        best.into_iter()
            .chain(tail)
            .map(|entry| (entry.outer_index, entry.start_index))
            .collect()
    }

    #[test]
    fn pe_hold_all_seeds_ranked_deduped_and_evicted() {
        let all = pe_hold_fault_run(1000, 0).unwrap();
        // Twelve final-scored seeds collapse to six complete keys; ties keep index order.
        assert_eq!(all.counters.climbs_started(), 12);
        assert_eq!(
            pe_hold_indices(all.best.as_ref(), &all.held_tail),
            [(0, 0), (1, 2), (1, 0), (2, 0), (0, 3), (2, 3)]
        );
        // Outer 1's losing seed 0 survives; outer 0's (0, 3) is evicted by outer 2.
        let four = pe_hold_fault_run(4, 0).unwrap();
        assert_eq!(
            pe_hold_indices(four.best.as_ref(), &four.held_tail),
            [(0, 0), (1, 2), (1, 0), (2, 0)]
        );
        assert_eq!(
            format!("{:?}", four.held_tail),
            format!("{:?}", &all.held_tail[..3])
        );
        let raw = pe_hold_fault_run(1, 0).unwrap();
        assert_eq!(format!("{:?}", raw.best), format!("{:?}", four.best));
        assert!(raw.held_tail.is_empty());
    }

    #[test]
    fn pe_hold_overflow_and_seed_fault_classification() {
        use crate::AttackRunCategory::{Counter, Evaluation, Invariant};
        for (fault, category, start) in [
            (1, Counter, None),
            (2, Invariant, Some(2)),
            (3, Evaluation, Some(2)),
        ] {
            let error = pe_hold_fault_run(4, fault).unwrap_err();
            assert_eq!(error.outer_index(), Some(1));
            assert_eq!(error.start_index(), start);
            assert_eq!(error.run_source().category(), category);
            assert_eq!(
                fault == 2,
                error.to_string().contains("seed projection failed")
            );
            // Overflow discards outer 1; seed faults keep its earlier seeds
            // (seed 1 duplicates seed 0) but never the failing seed.
            let kept: &[_] = match fault {
                1 => &[(0, 0), (0, 3)],
                _ => &[(0, 0), (1, 0), (0, 3)],
            };
            assert_eq!(
                pe_hold_indices(error.best().unwrap(), error.held_tail()),
                kept
            );
        }
        // Missing-outer and resolution errors keep every earlier accepted offer.
        for (fault, outer) in [(4, None), (5, Some(2))] {
            let error = pe_hold_fault_run(4, fault).unwrap_err();
            assert_eq!(error.outer_index(), outer);
            assert_eq!(
                pe_hold_indices(error.best().unwrap(), error.held_tail()),
                [(0, 0), (1, 2), (1, 0), (0, 3)]
            );
        }
        // Capacity one keeps lazy projection and the raw 12.9a/b retained best.
        let lazy = pe_hold_fault_run(1, 2).unwrap();
        assert_eq!(pe_hold_indices(lazy.best.as_ref(), &[]), [(0, 0)]);
        let raw = pe_hold_fault_run(1, 3).unwrap_err();
        assert_eq!(raw.run_source().category(), Evaluation);
        assert_eq!(
            pe_hold_indices(raw.best().unwrap(), raw.held_tail()),
            [(0, 0)]
        );
    }

    fn assert_pe_projection_fault(
        error: &crate::AttackRunError,
        trace: &PeHoldTrace,
        coordinates: (u128, u128),
    ) {
        assert_eq!(
            error.run_source().category(),
            crate::AttackRunCategory::Invariant
        );
        assert!(error.to_string().contains("seed projection failed"));
        assert_eq!(
            (error.outer_index(), error.start_index()),
            (Some(coordinates.0), Some(coordinates.1))
        );
        assert_eq!(trace.post_climb.len(), trace.entered.len());
        let &(used, counters) = trace.post_climb.last().unwrap();
        assert_eq!(error.evaluations_used(), used);
        assert_eq!(error.counters(), crate::AttackProgress(counters));
        assert_eq!(error.counters().outers_completed(), coordinates.0);
    }

    #[test]
    fn pe_hold_projection_fault_stops_later_seed_execution() {
        let (result, trace) = pe_hold_fault_run_at(4, 2, (1, 2));
        let error = result.unwrap_err();
        assert_eq!(
            trace.entered,
            [(0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (1, 1), (1, 2)]
        );
        assert_pe_projection_fault(&error, &trace, (1, 2));
        let hold: Vec<_> = error.hold().unwrap().collect();
        assert_eq!(
            hold.iter()
                .map(|entry| (entry.best().outer_index(), entry.best().start_index()))
                .collect::<Vec<_>>(),
            [(0, 0), (1, 0), (0, 3)]
        );
    }

    #[test]
    fn pe_hold_first_outer_projection_fault_retains_only_prior_seeds() {
        let reference = pe_hold_fault_run(4, 0).unwrap();
        for seed in [0, 2] {
            let (result, trace) = pe_hold_fault_run_at(4, 2, (0, seed));
            let error = result.unwrap_err();
            let expected: Vec<_> = (0..=seed).map(|start| (0, start)).collect();
            assert_eq!(trace.entered, expected);
            assert_pe_projection_fault(&error, &trace, (0, seed));
            if seed == 0 {
                // Without a retained head, independent projection errors stay errors.
                let best_error = error.best().unwrap_err();
                let hold_error = error
                    .hold()
                    .err()
                    .expect("independent hold projection error");
                assert!(best_error.downcast_ref::<ProjectionError>().is_some());
                assert!(hold_error.downcast_ref::<ProjectionError>().is_some());
                assert!(std::ptr::eq(best_error, hold_error));
                assert!(error.held_tail().is_empty());
            } else {
                let hold: Vec<_> = error.hold().unwrap().collect();
                assert_eq!(hold.len(), 1); // Seed 1 duplicates seed 0.
                assert_eq!(
                    pe_hold_indices(error.best().unwrap(), error.held_tail()),
                    [(0, 0)]
                );
                // Debug includes every owned payload field, but not allocation addresses.
                assert_eq!(
                    format!("{:?}", hold[0].best()),
                    format!("{:?}", reference.best.as_ref().unwrap())
                );
                assert!(hold[0].stages().is_empty());
            }
        }
    }

    #[test]
    fn pe_hold_capacity_one_raw_equivalence_and_interrupted_offers() {
        for stop in [usize::MAX, 1, 12, 20] {
            let observe = |hold: u64| {
                let request = partial_scheduler_request(false, |job| {
                    job["attack"]["hold"] = serde_json::json!(hold);
                });
                let (mut snapshots, mut polls) = (Vec::new(), 0);
                let result = request
                    .run(
                        |p| snapshots.push(p.0),
                        || {
                            polls += 1;
                            polls == stop
                        },
                    )
                    .unwrap();
                (request, result, snapshots, polls)
            };
            let (request, raw, snapshots, polls) = observe(1);
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let expected = request
                .schedule_partial_outers_controlled(&mut control, &mut observer, || stop == 1)
                .unwrap()
                .project_public(control.snapshot(), request.domain(), MeasureId::Trie)
                .unwrap();
            assert_eq!(format!("{raw:?}"), format!("{expected:?}"));
            assert!(observer.0.is_empty());
            assert_eq!(snapshots, [Default::default(), control.snapshot()]);
            assert_eq!(polls, 1);
            // Larger capacities add no evaluation or boundary polling.
            let (_, held, held_snapshots, held_polls) = observe(1000);
            assert_eq!((held_snapshots, held_polls), (snapshots, polls));
            assert_eq!(held.termination, raw.termination);
            assert_eq!(format!("{:?}", held.best), format!("{:?}", raw.best));
            assert!(!held.best.as_ref().is_some_and(|best| best.incomplete));
            let tail: Vec<_> = (held.held_tail.iter())
                .map(|e| (e.outer_index, e.start_index, e.incomplete))
                .collect();
            let expected_tail: &[_] = match stop {
                1 => &[],
                _ => &[
                    (0, 3, false),
                    (1, 0, false),
                    (1, 2, false),
                    (2, 0, false),
                    (2, 3, false),
                ],
            };
            assert_eq!(tail, expected_tail);
        }
    }

    #[test]
    fn public_success_projection_fault_retains_terminal_facts() {
        // Synthetic corruption of an otherwise real completed outcome, not a
        // naturally reachable failure of a validated external request.
        let (request, mut best) = projection_fixture();
        best.climb.current = None;
        let counters = crate::attack_control::CounterSnapshot {
            evaluations_admitted: 7,
            evaluations_completed: 7,
            climbs_started: 3,
            climbs_completed: 3,
            outers_completed: 2,
        };
        let error = DirectRunOutcome {
            termination: DirectRunTermination::Completed,
            outer_completed: 2,
            climbs_started: 3,
            climbs_completed: 3,
            evaluations_used: 7,
            best: Some(best),
        }
        .project_public(counters, request.domain(), MeasureId::Ic)
        .unwrap_err();
        assert_eq!(
            error.run_source().category(),
            crate::AttackRunCategory::Invariant
        );
        assert_eq!(error.evaluations_used(), 7);
        assert_eq!(error.counters(), crate::AttackProgress(counters));
        assert_eq!(
            (error.outer_index(), error.start_index()),
            (Some(u128::MAX), Some(0))
        );
        assert!(matches!(
            error.best().unwrap_err().downcast_ref::<ProjectionError>(),
            Some(ProjectionError::MissingCommittedBoard)
        ));
        assert!(error.to_string().contains("projection failed"));
    }

    #[test]
    fn public_projection_preserves_winning_key() {
        let (request, mut outcome) = projection_fixture();
        outcome.start_index = u128::MAX - 1;
        let current = outcome.climb.current.as_ref().unwrap();
        assert!(
            !current.board.is_empty(),
            "production climb must retain mutable pairs"
        );
        let plaintext = current.plaintext.clone();
        let score = current.score;
        let best = outcome.project(request.domain(), MeasureId::Ic).unwrap();
        assert_eq!(
            best.configuration().plugboard(),
            &[('🦀', 'Ω'), ('é', '中')]
        );
        assert_eq!(best.mutable_plugboard(), &[('🦀', 'Ω')]);
        assert_eq!(
            best.configuration().slots(),
            &[crate::SlotConfiguration::new("r", "r", 'é', 'Ω')]
        );
        assert_eq!(best.plaintext(), plaintext);
        assert_eq!(best.score(), score);
        assert_eq!(best.measure(), MeasureId::Ic);
        assert_eq!(
            (best.outer_index(), best.start_index()),
            (u128::MAX, u128::MAX - 1)
        );
    }

    fn projection_run(
        best: Option<DirectOuterOutcome>,
        termination: DirectRunTermination,
    ) -> DirectRunOutcome {
        DirectRunOutcome {
            termination,
            outer_completed: 0,
            climbs_started: 0,
            climbs_completed: 0,
            evaluations_used: u64::MAX,
            best,
        }
    }

    #[test]
    fn public_run_projection_preserves_full_width_values_and_independent_flags() {
        use crate::attack_control::CounterSnapshot;
        use crate::AttackTermination;
        for (termination, expected) in [
            (
                DirectRunTermination::Completed,
                AttackTermination::Completed,
            ),
            (
                DirectRunTermination::OuterSliceEnd,
                AttackTermination::OuterSliceEnd,
            ),
            (
                DirectRunTermination::Cancelled,
                AttackTermination::Cancelled,
            ),
        ] {
            let (request, _) = projection_fixture();
            let counters = CounterSnapshot {
                evaluations_admitted: u64::MAX - 1,
                evaluations_completed: u64::MAX - 2,
                climbs_started: u128::MAX,
                climbs_completed: u128::MAX - 1,
                outers_completed: u128::MAX - 2,
            };
            let null = projection_run(None, termination)
                .project(counters, request.domain(), MeasureId::Ic)
                .unwrap();
            assert_eq!(null.termination(), expected);
            assert!(null.best().is_none());
            for flags in 0..16 {
                let (request, mut best) = projection_fixture();
                best.start_index = u128::MAX - 1;
                best.climb.cancelled = flags & 1 != 0;
                best.climb.incomplete = flags & 2 != 0;
                best.climb.final_objective_ascent = flags & 4 != 0;
                best.climb.neighborhood_exhausted = flags & 8 != 0;
                let termination = match expected {
                    AttackTermination::Completed => DirectRunTermination::Completed,
                    AttackTermination::OuterSliceEnd => DirectRunTermination::OuterSliceEnd,
                    AttackTermination::Cancelled => DirectRunTermination::Cancelled,
                };
                let result = projection_run(Some(best), termination)
                    .project(counters, request.domain(), MeasureId::Ic)
                    .unwrap();
                assert_eq!(result.termination(), expected);
                assert_eq!(result.counters(), crate::AttackProgress(counters));
                assert_eq!(result.evaluations_used(), u64::MAX);
                let best = result.best().unwrap();
                assert_eq!(
                    (best.outer_index(), best.start_index()),
                    (u128::MAX, u128::MAX - 1)
                );
                assert_eq!(best.incomplete(), flags & 3 != 0);
                assert_eq!(best.final_objective_ascent(), flags & 4 != 0);
                assert_eq!(best.neighborhood_exhausted(), flags & 8 != 0);
            }
        }
    }

    #[test]
    fn public_projection_rejects_malformed_best() {
        for missing in [true, false] {
            let (request, mut best) = projection_fixture();
            if missing {
                best.climb.current = None;
            } else {
                best.climb.current.as_mut().unwrap().board = vec![('🦀', '🦀')];
            }
            let error = projection_run(Some(best), DirectRunTermination::Completed)
                .project(Default::default(), request.domain(), MeasureId::Ic)
                .unwrap_err();
            match error {
                ProjectionError::MissingCommittedBoard => assert!(missing),
                ProjectionError::Board(source) => {
                    assert!(!missing);
                    assert_eq!(
                        source,
                        crate::attack_evaluator::TrialBoardError::Model(
                            crate::ModelError::PlugboardSelfPair('🦀')
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn public_error_projection_retains_prior_best() {
        let request = scheduler_request(false, false, 0);
        let mut expected_allowance = EvaluationAllowance { used: 0 };
        let expected = request
            .climb_direct_outer(
                request.outer_candidates().next().unwrap().1.unwrap(),
                0,
                &mut expected_allowance,
            )
            .unwrap();
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let error = schedule_controlled_direct(
            2,
            request.outer_candidates().take(1),
            &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            },
            &mut || false,
            |initial, index, accounting, requested| {
                let (scoring, start) = request
                    .direct_scoring(&initial)
                    .map_err(DirectRunError::Climb)?;
                let climb = scoring
                    .climb_cancellable(start, 0, accounting, requested)
                    .map_err(DirectRunError::from)?;
                Ok(DirectOuterOutcome {
                    initial,
                    outer_index: index,
                    start_index: 0,
                    climb,
                })
            },
            |outcome| Ok(Some(outcome)),
        )
        .unwrap_err();
        assert!(matches!(error.source, DirectRunError::MissingOuter));
        assert_eq!(error.outer_index, None);
        assert_eq!(error.counters.outers_completed, 1);
        assert!(observer.0.is_empty());
        assert_eq!(error.evaluations_used, expected_allowance.used);
        let expected = expected.project(request.domain(), MeasureId::Trie).unwrap();
        let error = error.project(request.domain(), MeasureId::Trie);
        assert_eq!(error.outer_index(), None);
        assert_eq!(error.start_index(), None);
        assert_eq!(error.counters(), crate::AttackProgress(control.snapshot()));
        assert_eq!(error.evaluations_used(), allowance.used);
        let best = error
            .best()
            .unwrap()
            .expect("accepted first outer survives failure");
        assert_eq!(best.configuration(), expected.configuration());
        assert_eq!(best.mutable_plugboard(), expected.mutable_plugboard());
        assert_eq!(best.plaintext(), expected.plaintext());
        assert_eq!(best.score(), expected.score());
        assert_eq!(best.measure(), expected.measure());
        assert_eq!(best.outer_index(), expected.outer_index());
        assert_eq!(best.start_index(), expected.start_index());
        assert_eq!(best.incomplete(), expected.incomplete());
        assert_eq!(
            best.final_objective_ascent(),
            expected.final_objective_ascent()
        );
        assert_eq!(
            best.neighborhood_exhausted(),
            expected.neighborhood_exhausted()
        );
    }

    #[test]
    fn public_error_context_and_all_overflows() {
        use crate::{AttackCounterOverflow as Public, AttackRunCategory};
        let request = scheduler_request(false, false, 0);
        let diagnostics = vec![crate::SearchDiagnostic::new(
            "invalid_search_space",
            "injected resolution",
            "/job/space",
        )];
        let snapshot = crate::attack_control::CounterSnapshot {
            evaluations_admitted: u64::MAX,
            evaluations_completed: u64::MAX - 1,
            climbs_started: u128::MAX,
            climbs_completed: u128::MAX - 1,
            outers_completed: u128::MAX - 2,
        };
        let project = |source, outer_index| {
            ControlledDirectError {
                source,
                outer_index,
                evaluations_used: u64::MAX,
                counters: snapshot,
                best: None,
            }
            .project(request.domain(), MeasureId::Trie)
        };
        let index = u128::MAX;
        let resolution = project(DirectRunError::Resolution(diagnostics.clone()), Some(index));
        assert_eq!(
            resolution.run_source().category(),
            AttackRunCategory::Resolution
        );
        assert_eq!(
            resolution.run_source().diagnostics(),
            Some(diagnostics.as_slice())
        );
        assert_eq!(resolution.outer_index(), Some(index));
        assert_eq!(resolution.start_index(), None);
        assert!(resolution.best().unwrap().is_none());
        assert!(resolution.to_string().contains("injected resolution"));
        for source in [
            DirectRunError::MissingOuter,
            DirectRunError::Climb(DirectClimbError::MissingStart),
            DirectRunError::Climb(DirectClimbError::UnsupportedPass),
        ] {
            let missing_outer = matches!(source, DirectRunError::MissingOuter);
            let error = project(source, if missing_outer { None } else { Some(index) });
            assert_eq!(error.run_source().category(), AttackRunCategory::Invariant);
            assert!(error.run_source().diagnostics().is_none());
            assert!(error.run_source().overflow().is_none());
            assert_eq!(
                error.start_index(),
                if missing_outer { None } else { Some(0) }
            );
        }
        for (private, public) in [
            (
                CounterOverflow::EvaluationsAdmitted,
                Public::EvaluationsAdmitted,
            ),
            (
                CounterOverflow::EvaluationsCompleted,
                Public::EvaluationsCompleted,
            ),
            (CounterOverflow::ClimbsStarted, Public::ClimbsStarted),
            (CounterOverflow::ClimbsCompleted, Public::ClimbsCompleted),
            (CounterOverflow::OutersCompleted, Public::OutersCompleted),
        ] {
            let error = project(DirectRunError::Counter(private), Some(index));
            assert_eq!(error.run_source().category(), AttackRunCategory::Counter);
            assert_eq!(error.run_source().overflow(), Some(public));
            assert_eq!(error.outer_index(), Some(index));
            assert_eq!(error.start_index(), Some(0));
            assert_eq!(error.evaluations_used(), u64::MAX);
            assert_eq!(error.counters(), crate::AttackProgress(snapshot));
        }
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::with_counters(snapshot);
        let mut observer = Recorder::default();
        let mut accounting = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut observer,
        };
        let source = accounting.admit().unwrap_err();
        let error = ControlledDirectError {
            source: DirectRunError::from(source),
            outer_index: Some(index),
            evaluations_used: allowance.used,
            counters: control.snapshot(),
            best: None,
        }
        .project(request.domain(), MeasureId::Trie);
        assert_eq!(error.evaluations_used(), 8);
        assert_eq!(error.counters(), crate::AttackProgress(control.snapshot()));
        assert_eq!(allowance.used, 8, "overflow happens after charging");
        assert_eq!(
            control.snapshot(),
            snapshot,
            "failed admission does not mutate counters"
        );
        assert_eq!(
            error.run_source().overflow(),
            Some(Public::EvaluationsAdmitted)
        );
    }

    #[test]
    fn public_error_malformed_best_preserves_runtime_cause() {
        use std::error::Error;
        let request = scheduler_request(false, false, 0);
        let mut best = request
            .climb_direct_outer(
                request.outer_candidates().next().unwrap().1.unwrap(),
                0,
                &mut EvaluationAllowance { used: 0 },
            )
            .unwrap();
        best.climb.current = None; // Inject a malformed private retained carrier.
        let error = ControlledDirectError {
            source: DirectRunError::Climb(DirectClimbError::Evaluation(
                TrialEvaluationError::Model(crate::ModelError::UnknownSymbol('Z')),
            )),
            outer_index: Some(u128::MAX),
            evaluations_used: 9,
            counters: crate::attack_control::CounterSnapshot::default(),
            best: Some(best),
        }
        .project(request.domain(), MeasureId::Trie);
        assert!(matches!(
            error.best().unwrap_err().downcast_ref::<ProjectionError>(),
            Some(ProjectionError::MissingCommittedBoard)
        ));
        assert_eq!(error.outer_index(), Some(u128::MAX));
        assert_eq!(error.start_index(), Some(0));
        assert_eq!(error.evaluations_used(), 9);
        assert_eq!(
            error.counters(),
            crate::AttackProgress(crate::attack_control::CounterSnapshot::default())
        );
        assert_eq!(
            error.run_source().category(),
            crate::AttackRunCategory::Evaluation
        );
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<crate::AttackRunSource>()
            .unwrap();
        let trial = source
            .source()
            .unwrap()
            .downcast_ref::<TrialEvaluationError>()
            .unwrap();
        assert_eq!(
            trial.source().unwrap().downcast_ref::<crate::ModelError>(),
            Some(&crate::ModelError::UnknownSymbol('Z'))
        );
    }

    #[test]
    fn controlled_direct_later_faults_keep_only_accepted_outer() {
        let request = scheduler_request(false, false, 0);
        let mut expected_allowance = EvaluationAllowance { used: 0 };
        let expected = request
            .climb_direct_outer(
                request.outer_candidates().next().unwrap().1.unwrap(),
                0,
                &mut expected_allowance,
            )
            .unwrap();
        for fault in 0..4 {
            let diagnostics = vec![crate::SearchDiagnostic::new(
                "invalid_search_space",
                "injected later resolution",
                "/job/space",
            )];
            let outers = request.outer_candidates().take(2).map(|(index, initial)| {
                (
                    index,
                    if fault == 0 && index == 1 {
                        Err(diagnostics.clone())
                    } else {
                        initial
                    },
                )
            });
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let error = schedule_controlled_direct(
                2,
                outers,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || false,
                |initial, index, accounting, requested| {
                    if index == 1 && fault >= 2 {
                        let mut counters = accounting.control.snapshot();
                        if fault == 2 {
                            counters.evaluations_admitted = u64::MAX;
                        } else {
                            counters.outers_completed = u128::MAX;
                        }
                        *accounting.control = AttackControl::with_counters(counters);
                    }
                    let scoring = BoundClimbScoring::new(
                        &initial,
                        request.domain(),
                        request.text(),
                        (
                            MeasureId::Trie,
                            if index == 1 && fault == 1 {
                                None
                            } else {
                                request.bound_resource(MeasureId::Trie)
                            },
                        ),
                        (MeasureId::Trie, request.bound_resource(MeasureId::Trie)),
                        1,
                    );
                    let climb = scoring
                        .climb_cancellable(vec![], 0, accounting, requested)
                        .map_err(DirectRunError::from)?;
                    Ok(DirectOuterOutcome {
                        initial,
                        outer_index: index,
                        start_index: 0,
                        climb,
                    })
                },
                |outcome| Ok(Some(outcome)),
            )
            .unwrap_err();
            assert_eq!(error.outer_index, Some(1));
            assert_eq!(error.counters, control.snapshot());
            assert!(observer.0.is_empty());
            let additional = match fault {
                0 => 0,
                1 | 2 => 1,
                _ => expected_allowance.used,
            };
            assert_eq!(
                error.evaluations_used,
                7 + expected_allowance.used + additional
            );
            assert_eq!(allowance.used, error.evaluations_used);
            match fault {
                0 => assert!(
                    matches!(error.source, DirectRunError::Resolution(ref actual) if *actual == diagnostics)
                ),
                1 => assert!(matches!(
                    error.source,
                    DirectRunError::Climb(DirectClimbError::Evaluation(
                        TrialEvaluationError::MissingResource(MeasureId::Trie)
                    ))
                )),
                2 => {
                    assert!(matches!(
                        error.source,
                        DirectRunError::Counter(CounterOverflow::EvaluationsAdmitted)
                    ));
                    assert_eq!(error.counters.evaluations_admitted, u64::MAX);
                    assert_eq!(
                        error.counters.evaluations_completed,
                        expected_allowance.used
                    );
                }
                _ => assert!(matches!(
                    error.source,
                    DirectRunError::Counter(CounterOverflow::OutersCompleted)
                )),
            }
            let best = error.best.as_ref().unwrap();
            assert_eq!(best.outer_index, 0);
            assert_eq!(best.initial, expected.initial);
            assert_eq!(best.climb.current, expected.climb.current);
            assert_eq!(best.start_index, expected.start_index);
            let error = error.project(request.domain(), MeasureId::Trie);
            assert_eq!(error.outer_index(), Some(1));
            assert_eq!(error.start_index(), if fault == 0 { None } else { Some(0) });
            assert_eq!(error.evaluations_used(), allowance.used);
            assert_eq!(error.counters(), crate::AttackProgress(control.snapshot()));
            if fault == 0 {
                assert_eq!(
                    error.run_source().diagnostics(),
                    Some(diagnostics.as_slice())
                );
            }
            let best = error.best().unwrap().unwrap();
            let current = expected.climb.current.as_ref().unwrap();
            assert_eq!(best.plaintext(), current.plaintext);
            assert_eq!(best.score(), current.score);
            assert_eq!(best.outer_index(), 0);
            assert_eq!(best.start_index(), 0);
            assert_eq!(
                best.incomplete(),
                expected.climb.cancelled || expected.climb.incomplete
            );
            assert_eq!(
                best.neighborhood_exhausted(),
                expected.climb.neighborhood_exhausted
            );
            assert_eq!(
                best.final_objective_ascent(),
                expected.climb.final_objective_ascent
            );
        }
    }

    #[test]
    fn controlled_outer_indexed_errors_and_terminal_snapshots() {
        let request = scheduler_request(false, false, 0);
        let index = u128::from(u64::MAX) + 7;
        for fault in 0..4 {
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let diagnostics = vec![crate::SearchDiagnostic::new(
                "invalid_search_space",
                "injected resolution",
                "/job/space",
            )];
            let item = if fault == 0 {
                Err(diagnostics.clone())
            } else {
                Ok(initial)
            };
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let mut polls = 0;
            let error = schedule_controlled_direct(
                1,
                std::iter::once((index, item)),
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || {
                    polls += 1;
                    polls == if fault == 3 { 9 } else { 3 }
                },
                |initial, index, accounting, requested| {
                    let resource = request.bound_resource(MeasureId::Trie);
                    let scoring = BoundClimbScoring::new(
                        &initial,
                        request.domain(),
                        request.text(),
                        (MeasureId::Trie, if fault == 1 { None } else { resource }),
                        (MeasureId::Trie, if fault >= 2 { None } else { resource }),
                        1,
                    );
                    let climb = scoring
                        .climb_cancellable(vec![], 0, accounting, requested)
                        .map_err(DirectRunError::from)?;
                    Ok(DirectOuterOutcome {
                        initial,
                        outer_index: index,
                        start_index: 0,
                        climb,
                    })
                },
                |outcome| Ok(Some(outcome)),
            )
            .unwrap_err();
            assert_eq!(error.outer_index, Some(index));
            assert!(error.best.is_none());
            assert_eq!(error.counters, control.snapshot());
            let snapshot = control.snapshot();
            assert!(observer.0.is_empty());
            assert_eq!(snapshot.outers_completed, 0);
            assert_eq!(snapshot.climbs_completed, 0);
            if fault == 0 {
                match error.source {
                    DirectRunError::Resolution(source) => assert_eq!(source, diagnostics),
                    _ => panic!("resolution source lost"),
                }
                assert_eq!(error.evaluations_used, 7);
            } else {
                assert!(matches!(
                    error.source,
                    DirectRunError::Climb(DirectClimbError::Evaluation(
                        TrialEvaluationError::MissingResource(MeasureId::Trie)
                    ))
                ));
                let used = match fault {
                    1 => 1,
                    3 => 5,
                    _ => 2,
                };
                assert_eq!(error.evaluations_used, 7 + used);
                assert_eq!(
                    (
                        snapshot.evaluations_admitted,
                        snapshot.evaluations_completed
                    ),
                    (used, used - 1)
                );
                assert_eq!(snapshot.climbs_started, u128::from(fault != 1));
            }
        }
    }

    #[test]
    fn controlled_outer_checked_counter_failures() {
        use crate::attack_control::CounterSnapshot;
        for (expected, used) in [
            (CounterOverflow::EvaluationsAdmitted, 1),
            (CounterOverflow::EvaluationsCompleted, 1),
            (CounterOverflow::ClimbsStarted, 1),
            (CounterOverflow::ClimbsCompleted, 9),
            (CounterOverflow::OutersCompleted, 9),
        ] {
            let mut before = CounterSnapshot::default();
            match expected {
                CounterOverflow::EvaluationsAdmitted => before.evaluations_admitted = u64::MAX,
                CounterOverflow::EvaluationsCompleted => before.evaluations_completed = u64::MAX,
                CounterOverflow::ClimbsStarted => before.climbs_started = u128::MAX,
                CounterOverflow::ClimbsCompleted => before.climbs_completed = u128::MAX,
                CounterOverflow::OutersCompleted => before.outers_completed = u128::MAX,
            }
            let mut control = AttackControl::with_counters(before);
            let mut observer = Recorder::default();
            let error = scheduler_request(false, false, 0)
                .schedule_direct_outers_controlled(&mut control, &mut observer, || false)
                .unwrap_err();
            assert!(error.best.is_none());
            assert_eq!(error.counters, control.snapshot());
            assert!(matches!(error.source, DirectRunError::Counter(source) if source == expected));
            assert_eq!(error.outer_index, Some(0));
            assert_eq!(error.evaluations_used, used);
            assert!(observer.0.is_empty());
            // The retained input facts survive every failed checked increment.
            assert_eq!(before, AttackControl::with_counters(before).snapshot());
        }
    }

    #[test]
    fn direct_outer_scheduler_order_fresh_state_and_final_ranking() {
        let request = scheduler_request(false, false, 0);
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut expected_best = None;
        let mut costs = Vec::new();
        for (index, initial) in request.outer_candidates() {
            let outcome = request
                .climb_direct_outer(initial.unwrap(), index, &mut allowance)
                .unwrap();
            costs.push(allowance.used);
            if expected_best
                .as_ref()
                .is_none_or(|best: &DirectOuterOutcome| {
                    outcome
                        .climb
                        .current
                        .as_ref()
                        .unwrap()
                        .score
                        .ranking()
                        .units()
                        > best.climb.current.as_ref().unwrap().score.ranking().units()
                })
            {
                expected_best = Some(outcome);
            }
        }
        let result = request.schedule_direct_outers().unwrap();
        assert_eq!(result.termination, DirectRunTermination::Completed);
        assert_eq!(
            (
                result.outer_completed,
                result.climbs_started,
                result.climbs_completed
            ),
            (3, 3, 3)
        );
        assert_eq!(result.evaluations_used, *costs.last().unwrap());
        let best = result.best.unwrap();
        let expected = expected_best.unwrap();
        assert_eq!(best.outer_index, expected.outer_index);
        assert_eq!(best.start_index, 0);
        assert_eq!(best.initial, expected.initial);
        assert_eq!(best.climb.current, expected.climb.current);
        assert!(!best.climb.incomplete);
    }

    #[test]
    fn direct_outer_scheduler_literal_later_winner_and_earliest_tie() {
        let request = direct_request_with(serde_json::json!([]), true, false, |job| {
            job["text"] = serde_json::json!("CB");
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
        });
        let result = request.schedule_direct_outers().unwrap();
        let best = result.best.unwrap();
        assert_eq!(best.outer_index, 1);
        assert_eq!(best.climb.current.as_ref().unwrap().plaintext, "BA");
        assert_eq!(
            best.climb.current.unwrap().score.ranking().units(),
            2 * (1i128 << 32)
        );
        assert_eq!(result.evaluations_used, 6);
        let ties = direct_request_with(serde_json::json!([]), false, false, |job| {
            job["text"] = serde_json::json!("A");
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
        })
        .schedule_direct_outers()
        .unwrap();
        assert_eq!(ties.termination, DirectRunTermination::Completed);
        assert_eq!(ties.best.unwrap().outer_index, 0);
        assert_eq!(ties.evaluations_used, 3);
    }

    #[test]
    fn direct_outer_scheduler_completes_selected_outers() {
        let single = direct_request_with(serde_json::json!([]), false, false, |job| {
            job["attack"]["hold"] = serde_json::json!(1);
        })
        .schedule_direct_outers()
        .unwrap();
        assert_eq!(single.termination, DirectRunTermination::Completed);
        assert_eq!(
            (
                single.outer_completed,
                single.climbs_started,
                single.climbs_completed,
                single.evaluations_used
            ),
            (1, 1, 1, 9)
        );
        let distinct = direct_request_with(serde_json::json!([]), true, false, |job| {
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
        })
        .schedule_direct_outers()
        .unwrap();
        assert_eq!(distinct.termination, DirectRunTermination::Completed);
        assert_eq!(
            (
                distinct.outer_completed,
                distinct.climbs_started,
                distinct.evaluations_used
            ),
            (3, 3, 6)
        );
        assert!(!distinct.best.unwrap().climb.incomplete);
    }

    #[test]
    fn request_bound_direct_owned_start_and_shared_allowance() {
        for (start, cost) in [
            (serde_json::json!([]), 9),
            (serde_json::json!([["A", "B"]]), 11),
        ] {
            // Caller JSON and supplied dictionary buffers have already been dropped.
            let request = direct_request(start, false, false);
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let expected_initial = initial.clone();
            let index = u128::from(u64::MAX) + 7;
            let mut allowance = EvaluationAllowance { used: 0 };
            let result = request
                .climb_direct_outer(initial, index, &mut allowance)
                .unwrap();
            assert_eq!(result.outer_index, index);
            assert_eq!(result.start_index, 0);
            assert_eq!(result.initial, expected_initial);
            assert_eq!(result.initial.plugboard().map('A'), Some('A'));
            assert_eq!(allowance.used, cost);
            let current = result.climb.current.unwrap();
            assert_eq!(current.board, vec![('A', 'C')]);
            assert_eq!(current.plaintext, "CB");
            assert_eq!(current.score.ranking().units(), 2 * (1i128 << 32));
            assert!(!result.climb.incomplete);
            assert!(result.climb.neighborhood_exhausted);
            assert!(result.climb.final_objective_ascent);
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let repeated = request
                .climb_direct_outer(initial, index, &mut allowance)
                .unwrap();
            assert_eq!(repeated.climb.current.unwrap(), current);
            assert!(!repeated.climb.incomplete);
            assert!(repeated.climb.neighborhood_exhausted);
            assert_eq!(allowance.used, cost * 2);
        }
    }

    #[test]
    fn request_bound_direct_rejects_promoted_partial_exhaustion() {
        let request = direct_request(serde_json::json!([]), false, true);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let mut allowance = EvaluationAllowance { used: 7 };
        let error = request
            .climb_direct_outer(initial, 29, &mut allowance)
            .unwrap_err();
        assert_eq!(error.outer_index, 29);
        assert_eq!(error.evaluations_used, 7);
        assert_eq!(error.source, DirectClimbError::UnsupportedPass);
        assert_eq!(allowance.used, 7);
    }

    #[test]
    fn seeds_have_independent_literal_order_and_dense_indices() {
        let (initial, _) = fixture();
        for (symbols, cap, policy, expected) in [
            (
                vec!['C', 'A', 'B'],
                1,
                crate::AttackSeedPolicy::All,
                vec![vec![], vec![('A', 'B')], vec![('A', 'C')], vec![('B', 'C')]],
            ),
            (
                vec!['B', 'C', 'A'],
                1,
                crate::AttackSeedPolicy::Touching(vec!['C']),
                vec![vec![], vec![('A', 'C')], vec![('B', 'C')]],
            ),
            (
                vec!['C', 'B', 'A'],
                1,
                crate::AttackSeedPolicy::Touching(vec!['C', 'A']),
                vec![vec![], vec![('A', 'B')], vec![('A', 'C')], vec![('B', 'C')]],
            ),
            (
                vec!['B', 'A', 'C'],
                0,
                crate::AttackSeedPolicy::All,
                vec![vec![]],
            ),
            (vec!['B'], 0, crate::AttackSeedPolicy::All, vec![vec![]]),
        ] {
            let domain = AttackPlugboardDomain::parse_json(
                initial.topology().alphabet(), &[],
                &serde_json::json!({"kind":"attack","symbols":symbols.iter().map(char::to_string).collect::<Vec<_>>(),"max_pairs":cap}).to_string(),
            ).unwrap();
            let mut cursor = SeedCursor::new(&initial, &domain, &policy).unwrap();
            for (index, board) in expected.iter().enumerate() {
                assert_eq!(cursor.next(), Some((index as u128, board.clone())));
            }
            assert_eq!(cursor.next(), None);
            assert_eq!(cursor.next(), None);
        }
    }

    #[test]
    fn seeds_preserve_fixed_facts_unicode_order_and_gate_counts() {
        // Runtime order deliberately differs from Unicode scalar order.
        let alphabet = ["🦀", "é", "Ω", "中", "β", "あ"];
        let value = serde_json::json!({"protocol_version":1,"machine":{"definition":{
            "kind":"custom","value":{"alphabet":alphabet,
            "wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}}}},"job":{"kind":"search",
            "configuration":{"slots":[{"id":"r","position":"🦀","ring":"🦀"}],
                "plugboard":[["é","中"]]},
            "space":{},"text":"🦀🦀","passes":["partial_exhaustion"],"measures":["ic"]}});
        let request = crate::SearchRequest::parse_json(&value.to_string()).unwrap();
        let initial = TransformConfiguration::new(
            vec![SlotConfiguration::new("r", "r", '🦀', '🦀')],
            vec![('é', '中')],
        )
        .resolve(request.definition())
        .unwrap();
        for (cap, seeds, expected) in [
            (
                2,
                serde_json::json!({"kind":"empty_single","selection":"all"}),
                vec![
                    vec![],
                    vec![('🦀', 'Ω')],
                    vec![('🦀', 'β')],
                    vec![('🦀', 'あ')],
                    vec![('Ω', 'β')],
                    vec![('Ω', 'あ')],
                    vec![('β', 'あ')],
                ],
            ),
            (
                3,
                serde_json::json!({"kind":"empty_single","selection":"touching","symbols":["あ","Ω"]}),
                vec![
                    vec![],
                    vec![('🦀', 'Ω')],
                    vec![('🦀', 'あ')],
                    vec![('Ω', 'β')],
                    vec![('Ω', 'あ')],
                    vec![('β', 'あ')],
                ],
            ),
            (
                1,
                serde_json::json!({"kind":"empty_single","selection":"all"}),
                vec![vec![]],
            ),
            (
                1,
                serde_json::json!({"kind":"empty_single","selection":"touching","symbols":["β"]}),
                vec![vec![]],
            ),
        ] {
            let domain = AttackPlugboardDomain::parse_json(
                request.definition().alphabet(),
                request.configuration().plugboard(),
                &serde_json::json!({"kind":"attack","symbols":["あ","β","Ω","🦀"],"max_pairs":cap})
                    .to_string(),
            )
            .unwrap();
            let settings = crate::AttackSettings::parse_json(
                request.definition().alphabet(),
                &domain,
                request.passes(),
                request.measures(),
                &serde_json::json!({"kind":"partial_exhaustion","initial_measure":"ic",
                    "final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,
                    "seeds":seeds})
                .to_string(),
            )
            .unwrap();
            let policy = settings.seed_policy().unwrap();
            let actual: Vec<_> = SeedCursor::new(&initial, &domain, policy)
                .unwrap()
                .collect();
            let indexed: Vec<_> = expected
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, board)| (index as u128, board))
                .collect();
            assert_eq!(actual, indexed);
            // Gate checks count only; the spelled sequence above is the order oracle.
            assert_eq!(
                crate::AttackGate::check(&request, &domain, &settings)
                    .unwrap()
                    .starts_per_outer(),
                expected.len() as u128
            );
            for (_, board) in actual {
                let full = validated_trial_board(&initial, &domain, &board).unwrap();
                assert_eq!(full.map('é'), Some('中'));
                assert_eq!(full.map('中'), Some('é'));
                for (a, b) in board {
                    assert_eq!(full.map(a), Some(b));
                    assert_eq!(full.map(b), Some(a));
                }
            }
        }
    }

    fn resource(initial: &ResolvedConfiguration) -> crate::BoundResource {
        crate::BoundResource::Trie(
            crate::TrieModel::new(
                initial.topology().alphabet().clone(),
                vec![
                    (vec!['A', 'C'], 1),
                    (vec!['C', 'B'], 2),
                    (vec!['B', 'A'], 2),
                ],
            )
            .unwrap(),
        )
    }

    fn controlled_seed_probe(
        context: &BoundClimbScoring<'_>,
        counters: crate::attack_control::CounterSnapshot,
        mut requested: impl FnMut(usize) -> bool,
    ) -> (
        Result<ControlledSeedOutcome, ControlledSeedError>,
        u64,
        crate::attack_control::CounterSnapshot,
        usize,
    ) {
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::with_counters(counters);
        let mut observer = Recorder::default();
        let mut polls = 0;
        let result = context.climb_seeds_controlled(
            &crate::AttackSeedPolicy::All,
            0,
            &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            },
            &mut || {
                polls += 1;
                requested(polls)
            },
        );
        assert!(observer.0.is_empty());
        assert_eq!(
            control.snapshot().outers_completed,
            counters.outers_completed
        );
        (result, allowance.used, control.snapshot(), polls)
    }

    #[test]
    fn controlled_seeds_later_interrupted_winner() {
        let (initial, domain) = fixture();
        let first = crate::BoundResource::Trie(
            crate::TrieModel::new(
                initial.topology().alphabet().clone(),
                vec![
                    (vec!['C', 'A'], 4),
                    (vec!['A', 'C'], 1),
                    (vec!['C', 'B'], 2),
                ],
            )
            .unwrap(),
        );
        for weight in [0, 3] {
            let last = crate::BoundResource::Trie(
                crate::TrieModel::new(
                    initial.topology().alphabet().clone(),
                    vec![(vec!['C', 'A'], 1), (vec!['A', 'C'], weight)],
                )
                .unwrap(),
            );
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(&last)),
                2,
            );
            {
                let cancel = true;
                // First seed consumes five; second start plus final rescore consumes two.
                let (result, used, _, _) =
                    controlled_seed_probe(&context, Default::default(), |poll| {
                        cancel && poll == 10
                    });
                let result = result.unwrap();
                assert_eq!(used, 14);
                assert_eq!(result.cancelled, cancel);
                assert_eq!(
                    (result.seeds.climbs_started, result.seeds.climbs_completed),
                    (2, 1)
                );
                let best = result.seeds.best.unwrap();
                assert_eq!(best.seed_index, u128::from(weight == 3));
                assert_eq!(best.incomplete, weight == 3);
                assert!(!best.final_objective_ascent);
                assert_eq!(
                    best.current.board,
                    if weight == 3 {
                        vec![('A', 'B')]
                    } else {
                        vec![]
                    }
                );
                assert_eq!(best.neighborhood_exhausted, weight != 3);
                assert_eq!(
                    best.current.plaintext,
                    if weight == 3 { "AC" } else { "CA" }
                );
                assert_eq!(
                    best.current.score.ranking().units(),
                    if weight == 3 { 3 << 32 } else { 1 << 32 }
                );
            }
        }
    }

    #[test]
    fn controlled_seeds_retains_completed_best_after_later_fault() {
        use crate::attack_control::CounterSnapshot;
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&first)),
            (MeasureId::Trie, Some(&first)),
            1,
        );
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let expected = context
            .climb_cancellable(
                vec![],
                0,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || false,
            )
            .unwrap();
        let expected_current = expected.current.as_ref().unwrap();
        let first_used = allowance.used;
        for fault in 0..3 {
            let broken = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (
                    MeasureId::Trie,
                    if fault == 0 { None } else { Some(&first) },
                ),
                (MeasureId::Trie, None),
                2,
            );
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::with_counters(CounterSnapshot {
                climbs_completed: if fault == 2 { u128::MAX - 1 } else { 0 },
                ..Default::default()
            });
            let mut observer = Recorder::default();
            // Only later seeds use the injected missing-resource context. The
            // counter case uses the unmodified production climb for every seed.
            let error = context
                .climb_seeds_controlled_with(
                    &crate::AttackSeedPolicy::All,
                    &mut ObservedAccounting {
                        allowance: &mut allowance,
                        control: &mut control,
                        observer: &mut observer,
                    },
                    &mut || false,
                    |index, board, accounting, requested| {
                        let scoring = if index == 0 || fault == 2 {
                            &context
                        } else {
                            &broken
                        };
                        scoring.climb_cancellable(board, 0, accounting, requested)
                    },
                    |seed| ControlFlow::Continue(Some(seed)),
                )
                .unwrap_err();
            assert_eq!(error.seed_index, Some(1));
            let expected_source = if fault == 2 {
                ObservedClimbError::Counter(CounterOverflow::ClimbsCompleted)
            } else {
                TrialEvaluationError::MissingResource(MeasureId::Trie).into()
            };
            assert_eq!(error.source, expected_source);
            assert!(allowance.used > 7 + first_used);
            let snapshot = control.snapshot();
            assert_eq!(snapshot.evaluations_admitted, allowance.used - 7);
            assert_eq!(
                snapshot.evaluations_completed,
                snapshot.evaluations_admitted - u64::from(fault != 2)
            );
            if fault == 0 {
                assert_eq!(snapshot.evaluations_completed, first_used);
            } else {
                // The later climb scores successfully before its final fault.
                assert!(snapshot.evaluations_completed > first_used);
            }
            assert!(observer.0.is_empty());
            let mapped = ControlledPartialError::from_seed(99, initial.clone(), error);
            assert_eq!(mapped.outer_index, 99);
            assert_eq!(mapped.seed_index, Some(1));
            assert!(mapped.best.is_some());
            assert_eq!(
                mapped.source,
                ControlledPartialSource::Climb(expected_source)
            );
            let (key, best) = *mapped.best.expect("earlier final-scored seed retained");
            assert_eq!(key, initial);
            assert_eq!(best.seed_index, 0);
            assert_eq!(best.current.board, expected_current.board);
            assert_eq!(best.current.plaintext, expected_current.plaintext);
            assert_eq!(best.current.score, expected_current.score);
            assert_eq!(best.incomplete, expected.cancelled || expected.incomplete);
            assert_eq!(best.final_objective_ascent, expected.final_objective_ascent);
            assert_eq!(best.neighborhood_exhausted, expected.neighborhood_exhausted);
        }
    }

    #[test]
    fn controlled_partial_retains_owned_fixed_key_after_later_counter_fault() {
        use crate::attack_control::CounterSnapshot;
        let value = serde_json::json!({"protocol_version":1,"machine":{"definition":{
            "kind":"custom","value":{"alphabet":["A","B","C","D","E"],
            "wheels":[{"name":"r","wiring":["B","A","D","E","C"],"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"movable","wheel":"r"}],
            "stepping":{"rules":[{"when":{"always":true},"advance":["r"]}]}}}},
            "job":{"kind":"search","configuration":{"slots":[{"id":"r","position":"A","ring":"A"}],
            "plugboard":[["A","B"]]},"space":{"plugboard":{"kind":"attack",
            "symbols":["C","D","E"],"max_pairs":2}},"text":"CCDD","passes":["partial_exhaustion"],
            "measures":["ic"],"attack":{"kind":"partial_exhaustion","initial_measure":"ic",
            "final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,
            "seeds":{"kind":"empty_single","selection":"all"}}}});
        let request = crate::AttackRequest::parse_json(&value.to_string()).unwrap();
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let before = initial.clone();
        let mut allowance = EvaluationAllowance { used: 0 };
        let mut control = AttackControl::with_counters(CounterSnapshot {
            climbs_started: u128::MAX - 1,
            ..Default::default()
        });
        let mut observer = Recorder::default();
        let error = request
            .climb_partial_outer_controlled(
                initial,
                73,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || false,
            )
            .unwrap_err();
        assert_eq!(error.outer_index, 73);
        assert_eq!(error.seed_index, Some(1));
        assert!(allowance.used > 0);
        assert_eq!(allowance.used, control.snapshot().evaluations_completed);
        assert_eq!(
            error.source,
            ControlledPartialSource::Climb(ObservedClimbError::Counter(
                CounterOverflow::ClimbsStarted
            ))
        );
        let (key, best) = *error.best.unwrap();
        assert_eq!(key, before);
        assert_eq!(key.plugboard().map('A'), Some('B'));
        assert_eq!(key.plugboard().map('B'), Some('A'));
        assert_eq!(best.seed_index, 0);
        assert!(best
            .current
            .board
            .iter()
            .all(|&(a, b)| { !['A', 'B'].contains(&a) && !['A', 'B'].contains(&b) }));
        let evaluated = TrialEvaluator::new(
            &key,
            request.domain(),
            request.text(),
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        )
        .evaluate(&best.current.board)
        .unwrap();
        assert_eq!(best.current.plaintext, evaluated.0);
        assert_eq!(best.current.score, evaluated.1);
        assert!(!best.incomplete);
        assert!(best.neighborhood_exhausted);
        assert_eq!(control.snapshot().climbs_started, u128::MAX);
        assert_eq!(control.snapshot().climbs_completed, 1);
        assert!(observer.0.is_empty());
        let projected = best
            .into_direct(key, 73)
            .project(request.domain(), MeasureId::Ic)
            .unwrap();
        assert!(projected.configuration().plugboard().contains(&('A', 'B')));
        assert_eq!(projected.start_index(), 0);
        assert!(!projected.incomplete());
        assert!(projected.neighborhood_exhausted());
    }

    #[test]
    fn controlled_seeds_counter_sources_and_prior_facts() {
        use crate::attack_control::CounterSnapshot;
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&first)),
            (MeasureId::Trie, Some(&first)),
            1,
        );
        for (source, used) in [
            (CounterOverflow::EvaluationsAdmitted, 8),
            (CounterOverflow::EvaluationsCompleted, 8),
            (CounterOverflow::ClimbsStarted, 8),
            (CounterOverflow::ClimbsCompleted, 16),
        ] {
            let mut counters = CounterSnapshot {
                outers_completed: u128::MAX,
                ..Default::default()
            };
            match source {
                CounterOverflow::EvaluationsAdmitted => counters.evaluations_admitted = u64::MAX,
                CounterOverflow::EvaluationsCompleted => counters.evaluations_completed = u64::MAX,
                CounterOverflow::ClimbsStarted => counters.climbs_started = u128::MAX,
                CounterOverflow::ClimbsCompleted => counters.climbs_completed = u128::MAX,
                _ => unreachable!(),
            }
            let (result, actual, recorder, _) =
                controlled_seed_probe(&context, counters, |_| false);
            let mut expected = counters;
            match source {
                CounterOverflow::EvaluationsAdmitted => {}
                CounterOverflow::EvaluationsCompleted => expected.evaluations_admitted = 1,
                CounterOverflow::ClimbsStarted => {
                    expected.evaluations_admitted = 1;
                    expected.evaluations_completed = 1;
                }
                CounterOverflow::ClimbsCompleted => {
                    expected.evaluations_admitted = 9;
                    expected.evaluations_completed = 9;
                    expected.climbs_started = 1;
                }
                _ => unreachable!(),
            }
            assert_eq!(recorder, expected);
            assert_eq!(actual, used);
            let error = result.unwrap_err();
            assert_eq!(error.seed_index, Some(0));
            assert_eq!(error.source, ObservedClimbError::Counter(source));
            assert!(error.best.is_none());
        }
        let counters = CounterSnapshot {
            evaluations_admitted: 11,
            evaluations_completed: 10,
            climbs_started: 5,
            climbs_completed: 4,
            outers_completed: u128::MAX,
        };
        let (result, used, recorder, _) = controlled_seed_probe(&context, counters, |_| false);
        let result = result.unwrap().seeds;
        assert_eq!(
            (result.climbs_started, result.climbs_completed, used),
            (4, 4, 39)
        );
        let after = recorder;
        assert_eq!(
            (after.evaluations_admitted, after.evaluations_completed),
            (43, 42)
        );
        assert_eq!((after.climbs_started, after.climbs_completed), (9, 8));
        let mut control = AttackControl::with_counters(counters);
        assert!(control.poll_cancellation(true));
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut observer = Recorder::default();
        let result = context
            .climb_seeds_controlled(
                &crate::AttackSeedPolicy::All,
                0,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || false,
            )
            .unwrap();
        assert!(result.cancelled && result.seeds.best.is_none());
        assert_eq!(allowance.used, 7);
        assert!(observer.0.iter().all(|snapshot| *snapshot == counters));
    }

    #[test]
    fn controlled_seeds_fixed_sole_seed_exact_rescore_and_exhaustion() {
        let request = direct_request_with(serde_json::json!([]), true, true, |job| {
            job["configuration"]["plugboard"] = serde_json::json!([["A", "B"]]);
            job["space"]["plugboard"]["symbols"] = serde_json::json!(["C"]);
        });
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let before = initial.clone();
        let context = BoundClimbScoring::new(
            &initial,
            request.domain(),
            request.text(),
            (MeasureId::Ic, None),
            (MeasureId::Trie, request.bound_resource(MeasureId::Trie)),
            2,
        );
        {
            for stop in [2, 3] {
                let (result, used, recorder, polls) =
                    controlled_seed_probe(&context, Default::default(), |poll| poll == stop);
                let result = result.unwrap();
                assert!(!result.cancelled);
                assert_eq!((used, polls), (9, 2));
                assert_eq!(
                    (result.seeds.climbs_started, result.seeds.climbs_completed),
                    (1, 1)
                );
                let best = result.seeds.best.unwrap();
                assert_eq!(best.seed_index, 0);
                assert!(best.current.board.is_empty());
                assert_eq!(best.current.plaintext, "AC");
                assert_eq!(best.current.score.ranking().units(), 1 << 32);
                assert!(!best.incomplete && !best.final_objective_ascent);
                assert!(best.neighborhood_exhausted);
                let after = recorder;
                assert_eq!(
                    (after.evaluations_admitted, after.evaluations_completed),
                    (2, 2)
                );
                assert_eq!((after.climbs_started, after.climbs_completed), (1, 1));
                assert_eq!(initial, before);
                assert_eq!(initial.plugboard().map('A'), Some('B'));
                assert_eq!(initial.plugboard().map('B'), Some('A'));
            }
        }
    }

    #[test]
    fn controlled_seeds_natural_last_seed_no_speculative_poll() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&first)),
            (MeasureId::Trie, Some(&first)),
            1,
        );
        {
            for stop in [66, 67] {
                let (result, used, recorder, polls) =
                    controlled_seed_probe(&context, Default::default(), |poll| poll == stop);
                let result = result.unwrap();
                assert!(!result.cancelled);
                assert_eq!((used, polls), (39, 66));
                assert_eq!(
                    (result.seeds.climbs_started, result.seeds.climbs_completed),
                    (4, 4)
                );
                let best = result.seeds.best.unwrap();
                assert_eq!(best.seed_index, 0);
                assert!(!best.incomplete && best.neighborhood_exhausted);
                let after = recorder;
                assert_eq!(
                    (after.evaluations_admitted, after.evaluations_completed),
                    (32, 32)
                );
            }
        }
    }

    #[test]
    fn controlled_seeds_finalization_and_error_context() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let last = resource(&initial);
        for (threshold, stop, used, paired) in [
            (2, 2, 2, false),
            (2, 8, 5, false),
            (2, 9, 5, true),
            (1, 9, 5, true),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(&last)),
                threshold,
            );
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let mut polls = 0;
            let result = context
                .climb_seeds_controlled(
                    &crate::AttackSeedPolicy::All,
                    0,
                    &mut ObservedAccounting {
                        allowance: &mut allowance,
                        control: &mut control,
                        observer: &mut observer,
                    },
                    &mut || {
                        polls += 1;
                        polls == stop
                    },
                )
                .unwrap();
            assert!(result.cancelled);
            assert_eq!(result.seeds.evaluations_used, 7 + used);
            let best = result.seeds.best.unwrap();
            assert!(best.incomplete);
            assert_eq!(
                best.current.board,
                if paired { vec![('A', 'C')] } else { vec![] }
            );
            assert_eq!(control.snapshot().evaluations_completed, used);
            assert!(observer.0.is_empty());
        }
        for (missing_initial, stop, used) in
            [(true, 2, 1), (false, 2, 2), (false, 8, 5), (false, 9, 5)]
        {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (
                    MeasureId::Trie,
                    if missing_initial { None } else { Some(&first) },
                ),
                (MeasureId::Trie, None),
                if stop == 9 { 1 } else { 2 },
            );
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let mut polls = 0;
            let error = context
                .climb_seeds_controlled(
                    &crate::AttackSeedPolicy::All,
                    0,
                    &mut ObservedAccounting {
                        allowance: &mut allowance,
                        control: &mut control,
                        observer: &mut observer,
                    },
                    &mut || {
                        polls += 1;
                        polls == stop
                    },
                )
                .unwrap_err();
            assert_eq!(error.seed_index, Some(0));
            assert!(error.best.is_none());
            assert_eq!(
                error.source,
                ObservedClimbError::Evaluation(TrialEvaluationError::MissingResource(
                    MeasureId::Trie
                ))
            );
            assert_eq!(allowance.used, 7 + used);
            assert_eq!(control.snapshot().evaluations_completed, used - 1);
            assert!(observer.0.is_empty());
        }
    }

    #[test]
    fn controlled_seeds_legacy_equivalence_and_stops() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&first)),
            (MeasureId::Trie, Some(&first)),
            1,
        );
        for cancel in [true, false] {
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let outcome = context
                .climb_seeds_controlled(
                    &crate::AttackSeedPolicy::All,
                    0,
                    &mut ObservedAccounting {
                        allowance: &mut allowance,
                        control: &mut control,
                        observer: &mut observer,
                    },
                    &mut || cancel,
                )
                .unwrap();
            assert_eq!(outcome.cancelled, cancel);
            assert!(observer.0.is_empty());
            assert_eq!(control.snapshot().outers_completed, 0);
            if cancel {
                assert!(outcome.seeds.best.is_none());
                assert_eq!(allowance.used, 7);
            } else {
                let legacy = context
                    .climb_seeds(
                        &crate::AttackSeedPolicy::All,
                        0,
                        &mut EvaluationAllowance { used: 7 },
                    )
                    .unwrap();
                assert_eq!(outcome.seeds.evaluations_used, legacy.evaluations_used);
                assert_eq!(outcome.seeds.climbs_started, legacy.climbs_started);
                assert_eq!(outcome.seeds.climbs_completed, legacy.climbs_completed);
                assert_eq!(
                    outcome.seeds.best.as_ref().map(|b| &b.current),
                    legacy.best.as_ref().map(|b| &b.current)
                );
            }
        }
    }

    #[test]
    fn controlled_partial_adapter_exact_error_mapping() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        for (input, bound, expected) in [
            (
                "AZ",
                None,
                TrialEvaluationError::Model(crate::ModelError::UnknownSymbol('Z')),
            ),
            (
                "A",
                None,
                TrialEvaluationError::Measure(crate::MeasureError::InsufficientSamples {
                    required: 2,
                    actual: 1,
                }),
            ),
            (
                "AA",
                Some(&resource),
                TrialEvaluationError::IncompatibleResource(MeasureId::Ic),
            ),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                input,
                (MeasureId::Ic, bound),
                (MeasureId::Ic, bound),
                0,
            );
            let (result, used, recorder, _) =
                controlled_seed_probe(&context, Default::default(), |_| false);
            let mapped =
                ControlledPartialError::from_seed(99, initial.clone(), result.unwrap_err());
            assert_eq!(mapped.outer_index, 99);
            assert_eq!(mapped.seed_index, Some(0));
            assert_eq!(used, 8);
            assert_eq!(
                mapped.source,
                ControlledPartialSource::Climb(expected.into())
            );
            let snapshot = recorder;
            assert_eq!(
                (
                    snapshot.evaluations_admitted,
                    snapshot.evaluations_completed
                ),
                (1, 0)
            );
        }
        let wrong_domain = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[('A', 'B')],
            r#"{"kind":"attack","symbols":["C"],"max_pairs":1}"#,
        )
        .unwrap();
        let context = BoundClimbScoring::new(
            &initial,
            &wrong_domain,
            "AA",
            (MeasureId::Ic, None),
            (MeasureId::Ic, None),
            0,
        );
        let (error, used, recorder, polls) =
            controlled_seed_probe(&context, Default::default(), |_| true);
        let mapped = ControlledPartialError::from_seed(99, initial.clone(), error.unwrap_err());
        assert_eq!((mapped.outer_index, mapped.seed_index, used), (99, None, 7));
        assert_eq!(
            mapped.source,
            ControlledPartialSource::Climb(ObservedClimbError::Evaluation(
                TrialEvaluationError::Board(
                    crate::attack_evaluator::TrialBoardError::FixedFactsBinding
                )
            ))
        );
        assert_eq!(polls, 0);
        assert_eq!(recorder.evaluations_admitted, 0);
    }

    #[test]
    fn controlled_partial_adapter_admitted_board_and_counter_mapping() {
        let (initial, domain) = fixture();
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        );
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        // Helper-qualified fault: this invalid trial reaches the evaluator after admission.
        let source = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut observer,
        }
        .evaluate(&evaluator, &[('A', 'Z')])
        .unwrap_err();
        let expected = evaluator.evaluate(&[('A', 'Z')]).unwrap_err();
        assert!(matches!(expected, TrialEvaluationError::Board(_)));
        let mapped = ControlledPartialError::from_seed(
            99,
            initial.clone(),
            ControlledSeedError {
                seed_index: Some(2),
                source,
                best: None,
            },
        );
        assert_eq!(
            mapped.source,
            ControlledPartialSource::Climb(expected.into())
        );
        assert_eq!(
            (mapped.outer_index, mapped.seed_index, allowance.used),
            (99, Some(2), 8)
        );
        assert_eq!(
            (
                control.snapshot().evaluations_admitted,
                control.snapshot().evaluations_completed
            ),
            (1, 0)
        );
        for source in [
            CounterOverflow::EvaluationsAdmitted,
            CounterOverflow::EvaluationsCompleted,
            CounterOverflow::ClimbsStarted,
            CounterOverflow::ClimbsCompleted,
            CounterOverflow::OutersCompleted,
        ] {
            // Mapping only: the single-outer adapter never records outer completion.
            let mapped = ControlledPartialError::from_seed(
                99,
                initial.clone(),
                ControlledSeedError {
                    seed_index: Some(2),
                    source: ObservedClimbError::Counter(source),
                    best: None,
                },
            );
            assert_eq!(
                mapped.source,
                ControlledPartialSource::Climb(ObservedClimbError::Counter(source))
            );
            assert_eq!((mapped.outer_index, mapped.seed_index), (99, Some(2)));
        }
    }

    #[test]
    fn controlled_partial_adapter_fixed_owner_later_cancel() {
        let alphabet = ["A", "B", "C", "D", "E", "F"];
        let value = serde_json::json!({"protocol_version":1,"machine":{"definition":{
            "kind":"custom","value":{"alphabet":alphabet,
            "wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}}}},"job":{"kind":"search",
            "configuration":{"slots":[{"id":"r","position":"A","ring":"A"}],
                "plugboard":[["A","B"],["C","D"]]},
            "space":{"plugboard":{"kind":"attack","symbols":["E","F"],"max_pairs":3}},
            "text":"EE","passes":["partial_exhaustion"],"measures":["ic"],
            "attack":{"kind":"partial_exhaustion","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":0,"backtrack_pairs":0,
                "seeds":{"kind":"empty_single","selection":"all"}}}});
        let request = crate::ParsedAttackRequest::parse_json(&value.to_string())
            .unwrap()
            .bind_resources(&std::collections::BTreeMap::new())
            .unwrap();
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        // Pair orientation and ordering are electrical facts, not provenance requirements.
        let equivalent = TransformConfiguration::new(
            vec![SlotConfiguration::new("r", "r", 'A', 'A')],
            vec![('D', 'C'), ('B', 'A')],
        )
        .resolve(request.definition())
        .unwrap();
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let result = request
            .climb_partial_outer_controlled_with(
                equivalent.clone(),
                99,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || false,
                1,
                |scoring, _, board, accounting, _| {
                    climb_stopping_when(scoring, board, 0, accounting, |facts| {
                        facts.climbs_completed == 1
                    })
                },
            )
            .unwrap();
        assert_eq!(initial.plugboard(), equivalent.plugboard());
        assert_eq!(result.initial, equivalent);
        assert_eq!(result.outer_index, 99);
        assert_eq!(control.snapshot().climbs_completed, 1);
        assert!(result.seeds.cancelled);
        assert_eq!(result.seeds.seeds.evaluations_used, 9);
        let best = result.seeds.seeds.best.unwrap();
        assert_eq!(best.seed_index, 0);
        assert_eq!(best.current.plaintext, "EE");
        assert_eq!(best.current.score.ranking().units(), 6i128 << 32);
        assert!(best.current.board.is_empty());
        assert!(!best.incomplete);
        assert!(best.final_objective_ascent && best.neighborhood_exhausted);
        assert_eq!(control.snapshot().outers_completed, 0);
        assert!(observer.0.is_empty());
    }

    #[test]
    fn controlled_partial_adapter_binding_equivalence() {
        for distinct in [false, true] {
            for touching in [false, true] {
                let request = direct_request_with(serde_json::json!([]), distinct, true, |job| {
                    if touching {
                        job["attack"]["seeds"]["selection"] = serde_json::json!("touching");
                        job["attack"]["seeds"]["symbols"] = serde_json::json!(["B"]);
                    }
                });
                let initial = request.outer_candidates().next().unwrap().1.unwrap();
                let mut allowance = EvaluationAllowance { used: 7 };
                let mut control = AttackControl::default();
                let mut observer = Recorder::default();
                let result = request
                    .climb_partial_outer_controlled(
                        initial.clone(),
                        88,
                        &mut ObservedAccounting {
                            allowance: &mut allowance,
                            control: &mut control,
                            observer: &mut observer,
                        },
                        &mut || false,
                    )
                    .unwrap();
                let legacy = request
                    .climb_partial_outer(initial, 88, &mut EvaluationAllowance { used: 7 })
                    .unwrap();
                assert_eq!(result.initial, legacy.initial);
                assert!(!result.seeds.cancelled);
                assert_eq!(
                    result.seeds.seeds.evaluations_used,
                    legacy.seeds.evaluations_used
                );
                assert_eq!(
                    result.seeds.seeds.climbs_completed,
                    legacy.seeds.climbs_completed
                );
                let best = result.seeds.seeds.best.unwrap();
                let expected = legacy.seeds.best.unwrap();
                assert_eq!(best.seed_index, expected.seed_index);
                assert_eq!(best.current, expected.current);
                assert_eq!(best.incomplete, expected.incomplete);
                assert_eq!(best.final_objective_ascent, expected.final_objective_ascent);
                assert_eq!(best.neighborhood_exhausted, expected.neighborhood_exhausted);
                assert_eq!(control.snapshot().outers_completed, 0);
            }
        }
    }

    #[test]
    fn controlled_partial_adapter_wrong_pass_and_counter_context() {
        use crate::attack_control::CounterSnapshot;
        for pe in [false, true] {
            let request = direct_request(serde_json::json!([]), false, pe);
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let mut allowance = EvaluationAllowance { used: 7 };
            let mut control = AttackControl::with_counters(CounterSnapshot {
                evaluations_admitted: u64::MAX,
                outers_completed: 3,
                ..CounterSnapshot::default()
            });
            let mut observer = Recorder::default();
            let mut polls = 0;
            let error = request
                .climb_partial_outer_controlled(
                    initial,
                    99,
                    &mut ObservedAccounting {
                        allowance: &mut allowance,
                        control: &mut control,
                        observer: &mut observer,
                    },
                    &mut || {
                        polls += 1;
                        false
                    },
                )
                .unwrap_err();
            assert_eq!(error.outer_index, 99);
            assert_eq!(error.seed_index, if pe { Some(0) } else { None });
            assert_eq!(allowance.used, if pe { 8 } else { 7 });
            assert_eq!(control.snapshot().evaluations_admitted, u64::MAX);
            assert_eq!(
                error.source,
                if pe {
                    ControlledPartialSource::Climb(ObservedClimbError::Counter(
                        CounterOverflow::EvaluationsAdmitted,
                    ))
                } else {
                    ControlledPartialSource::UnsupportedPass
                }
            );
            assert_eq!(polls, usize::from(pe));
            assert_eq!(control.snapshot().outers_completed, 3);
            assert!(observer.0.is_empty());
        }
    }

    #[test]
    fn controlled_partial_adapter_cancel_preserves_owner_and_index() {
        let request = direct_request(serde_json::json!([]), false, true);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let retained = initial.clone();
        let index = u128::from(u64::MAX) + 7;
        let mut allowance = EvaluationAllowance { used: 7 };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let result = request
            .climb_partial_outer_controlled_with(
                initial,
                index,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || false,
                1,
                |scoring, _, board, accounting, _| {
                    climb_stopping_when(scoring, board, 0, accounting, |facts| {
                        facts.climbs_completed == 1
                    })
                },
            )
            .expect("validated PE adapter must retain the completed seed on cancellation");
        assert!(result.seeds.cancelled);
        assert_eq!(result.initial, retained);
        assert_eq!(result.outer_index, index);
        assert_eq!(control.snapshot().outers_completed, 0);
        assert_eq!(result.seeds.seeds.evaluations_used, 16);
        let best = result.seeds.seeds.best.unwrap();
        assert_eq!(best.current.plaintext, "CB");
        let expected = TrialEvaluator::new(
            &retained,
            request.domain(),
            request.text(),
            Direction::Decrypt,
            request.settings().final_measure(),
            request.bound_resource(request.settings().final_measure()),
        )
        .evaluate(&best.current.board)
        .unwrap();
        assert_eq!(
            (best.current.plaintext.clone(), best.current.score),
            expected
        );
        assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
        assert_eq!(best.seed_index, 0);
        assert!(!best.incomplete);
        assert!(best.final_objective_ascent && best.neighborhood_exhausted);
        assert!(observer.0.is_empty());
    }

    #[test]
    fn controlled_seeds_cancel_between_seeds() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&first)),
            (MeasureId::Trie, Some(&first)),
            1,
        );
        let mut observer = Recorder::default();
        let mut control = AttackControl::default();
        let mut allowance = EvaluationAllowance { used: 7 };
        let result = context
            .climb_seeds_controlled_with(
                &crate::AttackSeedPolicy::All,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || false,
                |_, board, accounting, _| {
                    climb_stopping_when(&context, board, 0, accounting, |facts| {
                        facts.climbs_completed == 1
                    })
                },
                |seed| ControlFlow::Continue(Some(seed)),
            )
            .unwrap();
        assert_eq!(result.seeds.evaluations_used, 16);
        assert!(result.cancelled);
        assert_eq!(
            (result.seeds.climbs_started, result.seeds.climbs_completed),
            (1, 1)
        );
        let best = result.seeds.best.unwrap();
        assert_eq!(best.seed_index, 0);
        assert_eq!(best.current.board, vec![('A', 'C')]);
        assert_eq!(best.current.plaintext, "CB");
        assert_eq!(best.current.score.ranking().units(), 2 << 32);
        assert!(!best.incomplete);
        let snapshot = control.snapshot();
        assert_eq!(snapshot.evaluations_admitted, 9);
        assert_eq!(snapshot.evaluations_completed, 9);
        assert_eq!(snapshot.outers_completed, 0);
        assert!(observer.0.is_empty());
    }

    #[test]
    fn ordered_climbs_share_accounting_and_reset_every_seed() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let last = crate::BoundResource::Trie(
            crate::TrieModel::new(
                initial.topology().alphabet().clone(),
                vec![(vec!['C', 'A'], 4), (vec!['C', 'B'], 3)],
            )
            .unwrap(),
        );
        // Stepping inverse maps AA to CA/AC/CB/BA for empty/AB/AC/BC.
        // Identical: empty costs 1+3+5, AB 1+5+5, AC and BC 1+5.
        // Different: empty costs 1+3+1+5+3; singles start final,
        // then reach empty in five trials and exhaust its three neighbors.
        for (different, used, board, text, weight) in [
            (false, 32, vec![('A', 'C')], "CB", 2),
            (true, 40, vec![], "CA", 4),
        ] {
            let (started, completed, best_index) = (4, 4, Some(0));
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (
                    MeasureId::Trie,
                    Some(if different { &last } else { &first }),
                ),
                1,
            );
            let mut allowance = EvaluationAllowance { used: 0 };
            let result = context
                .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                .unwrap();
            assert_eq!(result.evaluations_used, used);
            assert_eq!(allowance.used, used);
            assert_eq!(
                (result.climbs_started, result.climbs_completed),
                (started, completed)
            );
            assert_eq!(result.best.as_ref().map(|best| best.seed_index), best_index);
            if let Some(best) = result.best {
                assert_eq!(best.current.board, board);
                assert_eq!(best.current.plaintext, text);
                assert_eq!(best.current.score.ranking().units(), weight << 32);
                assert_eq!(best.incomplete, completed == 0);
                assert_eq!(best.neighborhood_exhausted, completed != 0);
                assert!(best.final_objective_ascent);
            }
        }
    }

    #[test]
    fn ordered_sole_seed_reports_cumulative_usage() {
        let (initial, _) = fixture();
        let last = resource(&initial);
        let domain = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[],
            r#"{"kind":"attack","symbols":["A","B","C"],"max_pairs":0}"#,
        )
        .unwrap();
        for identical in [false, true] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Ic, None),
                if identical {
                    (MeasureId::Ic, None)
                } else {
                    (MeasureId::Trie, Some(&last))
                },
                2,
            );
            let cost = if identical { 1 } else { 2 };
            let mut allowance = EvaluationAllowance { used: 7 };
            let result = context
                .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                .unwrap();
            assert_eq!(result.evaluations_used, 7 + cost);
            assert_eq!((result.climbs_started, result.climbs_completed), (1, 1));
            let best = result.best.unwrap();
            assert_eq!(best.seed_index, 0);
            assert!(!best.incomplete);
            assert!(best.neighborhood_exhausted);
            assert_eq!(best.final_objective_ascent, identical);
            assert_eq!(best.current.plaintext, "CA");
            assert_eq!(best.current.score.ranking().units(), 0);
        }
    }

    #[test]
    fn ordered_local_accounting_keeps_gate_widths_at_allowance_extremes() {
        // Unicode scalar count bounds the cursor and both climb counters.
        let scalar_count = 1_112_064u128;
        let maximum_seeds = 1 + scalar_count * (scalar_count - 1) / 2;
        assert!(maximum_seeds < u128::from(u64::MAX));
        let (initial, _) = fixture();
        let domain = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[],
            r#"{"kind":"attack","symbols":["A"],"max_pairs":0}"#,
        )
        .unwrap();
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Ic, None),
            (MeasureId::Ic, None),
            0,
        );
        for used in [u64::MAX - 1, u64::MAX] {
            let mut allowance = EvaluationAllowance { used };
            let result = context.climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance);
            if used == u64::MAX {
                assert_eq!(
                    result.unwrap_err(),
                    TrialEvaluationError::Invariant("evaluation admission counter overflow")
                );
                assert_eq!(allowance.used, u64::MAX);
                continue;
            }
            let result = result.unwrap();
            let count: u128 = 1;
            assert_eq!(
                (result.climbs_started, result.climbs_completed),
                (count, count)
            );
            assert_eq!(result.evaluations_used, u64::MAX);
            assert_eq!(
                result.best.map(|best| best.seed_index),
                if count == 0 { None } else { Some(0u128) }
            );
        }
    }

    #[test]
    fn ordered_runtime_errors_preserve_admissions() {
        let (initial, domain) = fixture();
        for (input, measure, expected) in [
            (
                "AZ",
                MeasureId::Ic,
                TrialEvaluationError::Model(crate::ModelError::UnknownSymbol('Z')),
            ),
            (
                "AA",
                MeasureId::Trie,
                TrialEvaluationError::MissingResource(MeasureId::Trie),
            ),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                input,
                (measure, None),
                (measure, None),
                0,
            );
            let before = format!("{initial:?}{domain:?}");
            let mut allowance = EvaluationAllowance { used: 0 };
            assert_eq!(
                context
                    .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                    .unwrap_err(),
                expected
            );
            assert_eq!(allowance.used, 1);
            assert_eq!(format!("{initial:?}{domain:?}"), before);
        }
    }

    #[test]
    fn driver_repeats_complete_scans_and_retains_only_committed_boards() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let last = crate::BoundResource::Trie(
            crate::TrieModel::new(
                initial.topology().alphabet().clone(),
                vec![(vec!['C', 'A'], 4), (vec!['C', 'B'], 3)],
            )
            .unwrap(),
        );
        // AB touches A -> AB, BC; AC removes -> empty; BC touches C -> BC, AB.
        // Thus AC neighbors cost five calls, including repeated boards.
        let neighbors: Vec<_> = NeighborhoodCursor::new(&initial, &domain, &[('A', 'C')], 0)
            .unwrap()
            .collect();
        assert_eq!(
            neighbors,
            vec![
                vec![('A', 'B')],
                vec![('B', 'C')],
                vec![],
                vec![('B', 'C')],
                vec![('A', 'B')]
            ]
        );
        // start + first scan + crossing = 5; final winning scan = 5;
        // last empty-board scan = 3. Initial optimum instead costs 1+3+5+1.
        for (threshold, stop_poll, board, text, weight, used, ascent, exhausted) in [
            (1, usize::MAX, vec![], "CA", 4, 13, true, true),
            (1, 9, vec![('A', 'C')], "CB", 3, 5, false, false),
            (1, 20, vec![], "CA", 4, 10, true, false),
            (1, 6, vec![], "CA", 4, 4, false, false),
            (2, usize::MAX, vec![('A', 'C')], "CB", 3, 10, false, true),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(&last)),
                threshold,
            );
            let (result, _, actual_used, _) = run_cancellation(&context, stop_poll);
            let result = result.unwrap();
            let current = result.current.unwrap();
            assert_eq!(current.board, board);
            assert_eq!(current.plaintext, text);
            assert_eq!(current.score.ranking().units(), weight << 32);
            assert_eq!(actual_used, used);
            assert_eq!(result.final_objective_ascent, ascent);
            assert_eq!(result.neighborhood_exhausted, exhausted);
            assert_eq!(result.incomplete, !exhausted);
        }
    }

    #[test]
    fn driver_identical_objective_requires_a_complete_scan_not_just_a_score() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&resource)),
            (MeasureId::Trie, Some(&resource)),
            2,
        );
        // No switch is reached. First tied maximum is AC, not BC.
        // 1 start + 3 empty neighbors + 5 AC plateau neighbors = 9.
        for (stop_poll, used, board, weight, ascent, exhausted) in [
            (usize::MAX, 9, vec![('A', 'C')], 2, true, true),
            (9, 4, vec![('A', 'C')], 2, true, false),
            (6, 3, vec![], 0, false, false),
        ] {
            let (result, _, actual_used, _) = run_cancellation(&context, stop_poll);
            let result = result.unwrap();
            let current = result.current.unwrap();
            assert_eq!(current.board, board);
            assert_eq!(
                current.plaintext,
                if board.is_empty() { "CA" } else { "CB" }
            );
            assert_eq!(current.score.ranking().units(), weight << 32);
            assert_eq!(actual_used, used);
            assert_eq!(result.final_objective_ascent, ascent);
            assert_eq!(result.neighborhood_exhausted, exhausted);
            assert_eq!(result.incomplete, !exhausted);
        }
    }

    #[test]
    fn driver_starting_final_is_not_itself_final_objective_ascent() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Ic, None),
            (MeasureId::Trie, Some(&resource)),
            0,
        );
        for (limit, board, ascent, exhausted) in
            [(1, vec![], false, false), (9, vec![('A', 'C')], true, true)]
        {
            let (result, _, actual_used, _) =
                run_cancellation(&context, if limit == 1 { 2 } else { usize::MAX });
            let result = result.unwrap();
            assert_eq!(result.current.unwrap().board, board);
            assert_eq!(result.final_objective_ascent, ascent);
            assert_eq!(result.neighborhood_exhausted, exhausted);
            assert_eq!(result.incomplete, !exhausted);
            assert_eq!(actual_used, limit);
        }
    }

    #[test]
    fn driver_zero_cost_neighborhood_completion() {
        let (initial, _) = fixture();
        let resource = resource(&initial);
        let empty_domain = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[],
            r#"{"kind":"attack","symbols":["A","B","C"],"max_pairs":0}"#,
        )
        .unwrap();
        for identical in [false, true] {
            let context = BoundClimbScoring::new(
                &initial,
                &empty_domain,
                "AA",
                (MeasureId::Ic, None),
                if identical {
                    (MeasureId::Ic, None)
                } else {
                    (MeasureId::Trie, Some(&resource))
                },
                2,
            );
            let limit = if identical { 1 } else { 2 };
            let mut allowance = EvaluationAllowance { used: 0 };
            let result = context.climb(vec![], 0, &mut allowance).unwrap();
            let current = result.current.unwrap();
            assert!(current.board.is_empty());
            assert_eq!(current.plaintext, "CA");
            assert_eq!(current.score.ranking().units(), 0);
            assert_eq!(allowance.used, limit);
            assert!(!result.incomplete);
            assert!(result.neighborhood_exhausted);
            assert_eq!(result.final_objective_ascent, identical);
        }
    }

    #[test]
    fn driver_errors_remain_errors_and_charge_only_admitted_calls() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Ic, None),
            (MeasureId::Ic, None),
            0,
        );
        let mut allowance = EvaluationAllowance { used: 0 };
        assert!(matches!(
            context.climb(vec![('A', 'A')], 0, &mut allowance),
            Err(TrialEvaluationError::Board(_))
        ));
        assert_eq!(allowance.used, 0);
        for (input, objective, expected) in [
            (
                "AZ",
                MeasureId::Ic,
                TrialEvaluationError::Model(crate::ModelError::UnknownSymbol('Z')),
            ),
            (
                "AA",
                MeasureId::Trie,
                TrialEvaluationError::MissingResource(MeasureId::Trie),
            ),
            (
                "A",
                MeasureId::Ic,
                TrialEvaluationError::Measure(crate::MeasureError::InsufficientSamples {
                    required: 2,
                    actual: 1,
                }),
            ),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                input,
                (objective, None),
                (objective, None),
                0,
            );
            let mut allowance = EvaluationAllowance { used: 0 };
            assert_eq!(
                context.climb(vec![], 0, &mut allowance).err(),
                Some(expected)
            );
            assert_eq!(allowance.used, 1);
        }
        // Missing final resource fails at either actual crossing or terminal rescore.
        for (threshold, used) in [(1, 5), (2, 10)] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&resource)),
                (MeasureId::Trie, None),
                threshold,
            );
            let mut allowance = EvaluationAllowance { used: 0 };
            assert_eq!(
                context.climb(vec![], 0, &mut allowance).err(),
                Some(TrialEvaluationError::MissingResource(MeasureId::Trie))
            );
            assert_eq!(allowance.used, used);
        }
    }

    #[test]
    fn lifecycle_finalizes_the_literal_current_board() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Ic, None),
            (MeasureId::Trie, Some(&resource)),
            2,
        );
        let mut allowance = EvaluationAllowance { used: 4 };
        let state = context.start(vec![], &mut allowance).unwrap();
        assert!(!state.final_phase);
        assert_eq!(state.current.plaintext, "CA");
        assert_eq!(state.current.score.ranking().units(), 0);
        let final_board = state.finalize(&mut allowance).unwrap();
        assert_eq!(final_board.board, vec![]);
        assert_eq!(final_board.plaintext, "CA");
        assert_eq!(final_board.score.ranking().units(), 0);
        assert_eq!(allowance.used, 6);

        let mut allowance = EvaluationAllowance { used: 0 };
        let state = context.start(vec![], &mut allowance).unwrap();
        allowance.admit().unwrap();
        let (plaintext, score) = context.initial_evaluator.evaluate(&[('A', 'C')]).unwrap();
        let trial = ScoredBoard {
            board: vec![('A', 'C')],
            plaintext,
            score,
        };
        // Transition mechanics only; this IC fixture does not claim strict selection.
        let state = state.commit_trial(trial, &mut allowance).unwrap();
        assert!(!state.final_phase);
        let result = state.finalize(&mut allowance).unwrap();
        assert_eq!(result.board, vec![('A', 'C')]);
        assert_eq!(result.plaintext, "CB");
        assert_eq!(result.score.ranking().units(), 2 << 32);
        assert_eq!(allowance.used, 3);
    }

    #[test]
    fn fixed_and_mutable_counts_choose_start_phase() {
        let source = serde_json::json!({"kind":"custom", "value": {
            "alphabet":["A","B","C","D","E","F"],
            "wheels":[{"name":"r","wiring":["A","B","C","D","E","F"],"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}
        }});
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        let initial = TransformConfiguration::new(
            vec![SlotConfiguration::new("r", "r", 'A', 'A')],
            vec![('A', 'B')],
        )
        .resolve(&definition)
        .unwrap();
        let domain = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[('A', 'B')],
            r#"{"kind":"attack","symbols":["C","D","E","F"],"max_pairs":3}"#,
        )
        .unwrap();
        // Identity wheel: substitutions cancel; AA has alphabet-scaled IC = 6.
        for (board, threshold, final_phase) in [
            (vec![], 2, false),
            (vec![('C', 'D')], 2, true),
            (vec![('C', 'D'), ('E', 'F')], 2, true),
            (vec![], 0, true),
            (vec![('C', 'D')], 4, false),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Ic, None),
                (MeasureId::Entropy, None),
                threshold,
            );
            let mut allowance = EvaluationAllowance { used: 0 };
            let state = context.start(board.clone(), &mut allowance).unwrap();
            assert_eq!(state.final_phase, final_phase);
            assert_eq!(state.current.board, board);
            assert_eq!(state.current.plaintext, "AA");
            assert_eq!(
                state.current.score.ranking().units(),
                if final_phase { 0 } else { 6 << 32 }
            );
            state.finalize(&mut allowance).unwrap();
            assert_eq!(allowance.used, if final_phase { 1 } else { 2 });
        }
        // Integrated fixed knowledge: identity decrypts AA under every seed.
        // Cap two permits empty + six singles. Empty costs 1+6;
        // each single costs 1+9 (remove + four one-free pairs twice).
        for (cap, cost, count) in [(1, 1, 1), (2, 67, 7)] {
            let domain = AttackPlugboardDomain::parse_json(
                initial.topology().alphabet(),
                &[('A', 'B')],
                &serde_json::json!({"kind":"attack","symbols":["C","D","E","F"],"max_pairs":cap})
                    .to_string(),
            )
            .unwrap();
            let before = format!("{initial:?}{domain:?}");
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Ic, None),
                (MeasureId::Ic, None),
                0,
            );
            let mut allowance = EvaluationAllowance { used: 0 };
            let result = context
                .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                .unwrap();
            assert_eq!(result.evaluations_used, cost);
            assert_eq!(
                (result.climbs_started, result.climbs_completed),
                (count, count)
            );
            let best = result.best.unwrap();
            assert_eq!(best.seed_index, 0);
            assert!(best.current.board.is_empty());
            assert_eq!(best.current.plaintext, "AA");
            assert_eq!(best.current.score.ranking().units(), 6 << 32);
            let board = validated_trial_board(&initial, &domain, &best.current.board).unwrap();
            assert_eq!(board.map('A'), Some('B'));
            assert_eq!(board.map('B'), Some('A'));
            assert_eq!(format!("{initial:?}{domain:?}"), before);
        }
    }

    #[test]
    fn identity_uses_the_borrowed_resource_not_only_measure_id() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let independent = resource(&initial);
        for (last, expected) in [(&first, 1), (&independent, 2)] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(last)),
                2,
            );
            let mut allowance = EvaluationAllowance { used: 0 };
            let state = context.start(vec![('A', 'C')], &mut allowance).unwrap();
            let result = state.finalize(&mut allowance).unwrap();
            assert_eq!(result.plaintext, "CB");
            assert_eq!(result.score.ranking().units(), 2 << 32);
            assert_eq!(allowance.used, expected);
        }
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Ic, None),
            (MeasureId::Ic, None),
            1,
        );
        let mut allowance = EvaluationAllowance { used: 0 };
        let state = context.start(vec![], &mut allowance).unwrap();
        allowance.admit().unwrap();
        let (plaintext, score) = context.initial_evaluator.evaluate(&[('A', 'C')]).unwrap();
        let trial = ScoredBoard {
            board: vec![('A', 'C')],
            plaintext,
            score,
        };
        // Exercise transition mechanics only: strict winner selection is the caller's duty.
        let state = state.commit_trial(trial, &mut allowance).unwrap();
        assert!(state.final_phase);
        state.finalize(&mut allowance).unwrap();
        assert_eq!(allowance.used, 2);
    }

    #[test]
    fn crossing_remeasures_current_then_removal_stays_final() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let last = crate::BoundResource::Trie(
            crate::TrieModel::new(
                initial.topology().alphabet().clone(),
                vec![(vec!['C', 'A'], 4), (vec!['C', 'B'], 3)],
            )
            .unwrap(),
        );
        let context = BoundClimbScoring::new(
            &initial,
            &domain,
            "AA",
            (MeasureId::Trie, Some(&first)),
            (MeasureId::Trie, Some(&last)),
            1,
        );
        let mut allowance = EvaluationAllowance { used: 3 };
        let state = context.start(vec![], &mut allowance).unwrap();
        // AC is the initial objective's complete-neighborhood winner (existing fixture).
        allowance.admit().unwrap();
        let (plaintext, score) = context.initial_evaluator.evaluate(&[('A', 'C')]).unwrap();
        assert_eq!(plaintext, "CB");
        assert_eq!(score.ranking().units(), 2 << 32);
        let trial = ScoredBoard {
            board: vec![('A', 'C')],
            plaintext,
            score,
        };
        let state = state.commit_trial(trial, &mut allowance).unwrap();
        assert!(state.final_phase);
        assert_eq!(state.current.board, vec![('A', 'C')]);
        assert_eq!(state.current.plaintext, "CB");
        assert_eq!(state.current.score.ranking().units(), 3 << 32);
        assert_eq!(allowance.used, 6);
        allowance.admit().unwrap();
        let (plaintext, score) = context.final_evaluator.evaluate(&[]).unwrap();
        // Empty board is the final objective's strict complete-neighborhood winner.
        let trial = ScoredBoard {
            board: vec![],
            plaintext,
            score,
        };
        let state = state.commit_trial(trial, &mut allowance).unwrap();
        assert!(state.final_phase);
        let result = state.finalize(&mut allowance).unwrap();
        assert!(result.board.is_empty());
        assert_eq!(result.plaintext, "CA");
        assert_eq!(result.score.ranking().units(), 4 << 32);
        assert_eq!(allowance.used, 7);
    }

    #[test]
    fn validation_precedes_admission_and_charged_failures_propagate() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let mismatched = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[('A', 'B')],
            r#"{"kind":"attack","symbols":["C"],"max_pairs":1}"#,
        )
        .unwrap();
        let mut allowance = EvaluationAllowance { used: 0 };
        for (binding, board) in [(&domain, vec![('A', 'A')]), (&mismatched, vec![])] {
            let context = BoundClimbScoring::new(
                &initial,
                binding,
                "AA",
                (MeasureId::Ic, None),
                (MeasureId::Ic, None),
                0,
            );
            assert!(matches!(
                context.start(board, &mut allowance),
                Err(TrialEvaluationError::Board(_))
            ));
            assert_eq!(allowance.used, 0);
        }
        for (input, objective, model, expected) in [
            (
                "AZ",
                MeasureId::Ic,
                None,
                TrialEvaluationError::Model(crate::ModelError::UnknownSymbol('Z')),
            ),
            (
                "AA",
                MeasureId::Trie,
                None,
                TrialEvaluationError::MissingResource(MeasureId::Trie),
            ),
            (
                "AA",
                MeasureId::Ic,
                Some(&resource),
                TrialEvaluationError::IncompatibleResource(MeasureId::Ic),
            ),
            (
                "A",
                MeasureId::Ic,
                None,
                TrialEvaluationError::Measure(crate::MeasureError::InsufficientSamples {
                    required: 2,
                    actual: 1,
                }),
            ),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                input,
                (objective, model),
                (objective, model),
                0,
            );
            let before = allowance.used;
            assert_eq!(context.start(vec![], &mut allowance).err(), Some(expected));
            assert_eq!(allowance.used, before + 1);
        }
    }

    #[test]
    fn final_scoring_errors_charge_without_returning_state() {
        let (initial, domain) = fixture();
        for threshold in [1, 2] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Ic, None),
                (MeasureId::Trie, None),
                threshold,
            );
            let mut allowance = EvaluationAllowance { used: 0 };
            let state = context.start(vec![], &mut allowance).unwrap();
            let error = if threshold == 1 {
                allowance.admit().unwrap();
                let (plaintext, score) = context.initial_evaluator.evaluate(&[('A', 'C')]).unwrap();
                state
                    .commit_trial(
                        ScoredBoard {
                            board: vec![('A', 'C')],
                            plaintext,
                            score,
                        },
                        &mut allowance,
                    )
                    .err()
            } else {
                state.finalize(&mut allowance).err()
            };
            assert_eq!(
                error,
                Some(TrialEvaluationError::MissingResource(MeasureId::Trie))
            );
            assert_eq!(allowance.used, if threshold == 1 { 3 } else { 2 });
        }
    }

    #[test]
    fn complete_scan_selects_a_strict_winner() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut allowance = EvaluationAllowance { used: 0 };
        let ranking = evaluator.evaluate(&[]).unwrap().1.ranking();
        let result = selection.scan(&[], ranking, &mut allowance).unwrap();
        assert_eq!(
            result,
            ScanOutcome::Complete(Some(ScoredBoard {
                board: vec![('A', 'C')],
                plaintext: String::from("CB"),
                score: MeasuredScore::higher_is_better(FixedScore::from_units(2 << 32)),
            }))
        );
        assert_eq!(allowance.used, 3);
    }

    #[test]
    fn independent_order_plaintexts_and_rankings_preserve_borrowed_inputs() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let before = format!("{initial:?}{domain:?}{resource:?}");
        let input = String::from("AA");
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            &input,
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        let expected = vec![vec![('A', 'B')], vec![('A', 'C')], vec![('B', 'C')]];
        let boards: Vec<_> = NeighborhoodCursor::new(&initial, &domain, &[], 0)
            .unwrap()
            .collect();
        assert_eq!(boards, expected);
        // For wiring BAC, the stepped inverse maps are CBA, ACB, BAC.
        // Applying each board before and after these maps gives these literals.
        for (board, plaintext, weight) in [
            (vec![], "CA", 0),
            (expected[0].clone(), "AC", 1),
            (expected[1].clone(), "CB", 2),
            (expected[2].clone(), "BA", 2),
        ] {
            let (actual, score) = evaluator.evaluate(&board).unwrap();
            assert_eq!(actual, plaintext);
            assert_eq!(score.ranking().units(), weight << 32);
            assert_eq!(evaluator.evaluate(&board).unwrap(), (actual, score));
        }
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut allowance = EvaluationAllowance { used: 0 };
        assert!(matches!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance),
            Ok(ScanOutcome::Complete(Some(_)))
        ));
        assert_eq!(input, "AA");
        assert_eq!(format!("{initial:?}{domain:?}{resource:?}"), before);
    }

    #[test]
    fn plateau_and_worsening_have_no_winner() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        for weight in [2, 3] {
            let mut allowance = EvaluationAllowance { used: 0 };
            assert_eq!(
                selection.scan(&[], FixedScore::from_units(weight << 32), &mut allowance),
                Ok(ScanOutcome::Complete(None))
            );
            assert_eq!(allowance.used, 3);
        }
    }

    #[test]
    fn repeated_boards_cost_separate_fresh_evaluations() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        let current = vec![('A', 'B')];
        let boards: Vec<_> = NeighborhoodCursor::new(&initial, &domain, &current, 0)
            .unwrap()
            .collect();
        assert_eq!(
            boards,
            vec![
                vec![],
                vec![('A', 'C')],
                vec![('B', 'C')],
                vec![('B', 'C')],
                vec![('A', 'C')]
            ]
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut allowance = EvaluationAllowance { used: 0 };
        let score = evaluator.evaluate(&current).unwrap().1;
        assert_eq!(
            selection.scan(&current, score.ranking(), &mut allowance),
            Ok(ScanOutcome::Complete(Some(ScoredBoard {
                board: boards[1].clone(),
                plaintext: String::from("CB"),
                score: MeasuredScore::higher_is_better(FixedScore::from_units(2 << 32)),
            })))
        );
        assert_eq!(allowance.used, 5);
        assert_eq!(current, vec![('A', 'B')]);
    }

    #[test]
    fn interruption_discards_provisional_best_and_preserves_snapshot() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let current = vec![];
        for cancel_after in [1, 2] {
            let mut allowance = EvaluationAllowance { used: 0 };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let mut observed = ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            };
            let mut accounting = PollingAccounting {
                inner: &mut observed,
                stop: |facts: crate::attack_control::CounterSnapshot| {
                    facts.evaluations_completed >= cancel_after
                },
            };
            assert_eq!(
                selection.scan(&current, FixedScore::from_units(0), &mut accounting),
                Ok(ScanOutcome::Cancelled)
            );
            assert_eq!(allowance.used, cancel_after);
            assert!(current.is_empty());
        }
    }

    #[test]
    fn shared_accounting_accumulates_and_rejects_overflow() {
        let (initial, domain) = fixture();
        let resource = resource(&initial);
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut allowance = EvaluationAllowance { used: 1 };
        for expected_used in [4, 7] {
            assert!(matches!(
                selection.scan(&[], FixedScore::from_units(0), &mut allowance),
                Ok(ScanOutcome::Complete(Some(_)))
            ));
            assert_eq!(allowance.used, expected_used);
        }
        let mut maximum = EvaluationAllowance { used: u64::MAX - 1 };
        assert_eq!(maximum.admit(), Ok(()));
        assert_eq!(maximum.used, u64::MAX);
        assert_eq!(maximum.admit(), Err(CounterOverflow::EvaluationsAdmitted));
        assert_eq!(maximum.used, u64::MAX);
        assert_eq!(
            EvaluationAccounting::admit(&mut maximum),
            Err(TrialEvaluationError::Invariant(
                "evaluation admission counter overflow"
            ))
        );
        assert_eq!(maximum.used, u64::MAX);
    }

    #[test]
    fn observed_admission_maximum_reports_overflow_and_keeps_separate_counters() {
        use crate::attack_control::CounterSnapshot;
        let before = CounterSnapshot {
            evaluations_admitted: u64::MAX - 1,
            evaluations_completed: u64::MAX - 2,
            ..CounterSnapshot::default()
        };
        let mut allowance = EvaluationAllowance { used: u64::MAX - 1 };
        let mut control = AttackControl::with_counters(before);
        let mut observer = Recorder::default();
        let mut accounting = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut observer,
        };
        assert_eq!(accounting.admit(), Ok(()));
        let admitted = CounterSnapshot {
            evaluations_admitted: u64::MAX,
            ..before
        };
        assert_eq!(accounting.allowance.used, u64::MAX);
        assert_eq!(accounting.control.snapshot(), admitted);
        assert_eq!(
            accounting.admit(),
            Err(ObservedClimbError::Counter(
                CounterOverflow::EvaluationsAdmitted
            ))
        );
        assert_eq!(accounting.allowance.used, u64::MAX);
        assert_eq!(accounting.control.snapshot(), admitted);
        assert_eq!(accounting.complete(), Ok(()));
        assert_eq!(
            accounting.control.snapshot(),
            CounterSnapshot {
                evaluations_completed: u64::MAX - 1,
                ..admitted
            }
        );
        assert!(observer.0.is_empty());
    }

    #[test]
    fn empty_legal_neighborhood_needs_no_evaluation() {
        let (initial, _) = fixture();
        let domain = AttackPlugboardDomain::parse_json(
            initial.topology().alphabet(),
            &[],
            r#"{"kind":"attack","symbols":["A","B","C"],"max_pairs":0}"#,
        )
        .unwrap();
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut allowance = EvaluationAllowance { used: 0 };
        assert_eq!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance),
            Ok(ScanOutcome::Complete(None))
        );
        assert_eq!(allowance.used, 0);
    }

    #[test]
    fn real_evaluator_errors_propagate_and_count_the_attempt() {
        let (initial, domain) = fixture();
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            None,
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut allowance = EvaluationAllowance { used: 0 };
        assert_eq!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance),
            Err(TrialEvaluationError::MissingResource(MeasureId::Trie))
        );
        assert_eq!(allowance.used, 1);
        assert!(matches!(
            selection.scan(&[('A', 'A')], FixedScore::from_units(0), &mut allowance),
            Err(TrialEvaluationError::Board(_))
        ));
        assert_eq!(allowance.used, 1);
    }

    /// The materializing scan before score-only trials, kept as an oracle.
    fn reference_scan<A: EvaluationAccounting>(
        selection: &NeighborhoodSelection<'_>,
        current: &[(char, char)],
        ranking: FixedScore,
        allowance: &mut A,
    ) -> Result<ScanOutcome, A::Error> {
        let mut cursor = NeighborhoodCursor::new(
            selection.initial,
            selection.domain,
            current,
            selection.backtrack_pairs,
        )
        .map_err(TrialEvaluationError::Board)?
        .peekable();
        let mut best = None;
        let mut best_ranking = ranking;
        while let Some(board) = cursor.next() {
            if allowance.cancelled() {
                return Ok(ScanOutcome::Cancelled);
            }
            let (plaintext, score) = allowance.evaluate(selection.evaluator, &board)?;
            if score.ranking().units() > best_ranking.units() {
                best_ranking = score.ranking();
                best = Some(ScoredBoard {
                    board,
                    plaintext,
                    score,
                });
            }
            if allowance.cancelled() {
                if best.is_none() && cursor.peek().is_none() {
                    return Ok(ScanOutcome::Complete(None));
                }
                return Ok(ScanOutcome::Cancelled);
            }
        }
        Ok(ScanOutcome::Complete(best))
    }

    /// Checked accounting whose cancellation poll fires from the `stop`th poll on.
    struct CancelAfter {
        allowance: EvaluationAllowance,
        polls: usize,
        stop: usize,
    }

    impl EvaluationAccounting for CancelAfter {
        type Error = TrialEvaluationError;
        fn cancelled(&mut self) -> bool {
            self.polls += 1;
            self.polls >= self.stop
        }
        fn admit(&mut self) -> Result<(), Self::Error> {
            EvaluationAccounting::admit(&mut self.allowance)
        }
    }

    fn plaintext_builds() -> usize {
        crate::attack_evaluator::PLAINTEXT_BUILDS.with(|count| count.replace(0))
    }

    #[test]
    fn score_only_scans_match_materializing_reference_and_build_one_plaintext() {
        let (initial, domain) = fixture();
        let trie = resource(&initial);
        let bigram = crate::BoundResource::Ngram(
            crate::NgramModel::new(
                initial.topology().alphabet().clone(),
                2,
                vec![(vec!['C', 'B'], 3), (vec!['A', 'C'], 1)],
            )
            .unwrap(),
        );
        for (objective, resource) in [
            (MeasureId::Ic, None),
            (MeasureId::Entropy, None),
            (MeasureId::SinkovBigram, Some(&bigram)),
            (MeasureId::Trie, Some(&trie)),
        ] {
            for deny in [false, true] {
                for input in ["A", "AA", "ABCABCAB"] {
                    let new = || {
                        let evaluator = TrialEvaluator::new(
                            &initial,
                            &domain,
                            input,
                            Direction::Decrypt,
                            objective,
                            resource,
                        );
                        if deny {
                            evaluator.with_reservation_denied()
                        } else {
                            evaluator
                        }
                    };
                    let (old, new) = (new(), new());
                    let streams = !deny && objective != MeasureId::Trie;
                    for ranking in [i128::MIN, 0, i128::MAX].map(FixedScore::from_units) {
                        for current in [vec![], vec![('A', 'B')]] {
                            let mut outcomes = Vec::new();
                            for evaluator in [&old, &new] {
                                let selection = NeighborhoodSelection {
                                    initial: &initial,
                                    domain: &domain,
                                    evaluator,
                                    backtrack_pairs: 0,
                                };
                                let mut allowance = EvaluationAllowance { used: 3 };
                                let mut control = AttackControl::default();
                                let mut observer = Recorder::default();
                                let mut accounting = ObservedAccounting {
                                    allowance: &mut allowance,
                                    control: &mut control,
                                    observer: &mut observer,
                                };
                                plaintext_builds();
                                let outcome = if std::ptr::eq(evaluator, &old) {
                                    reference_scan(&selection, &current, ranking, &mut accounting)
                                } else {
                                    selection.scan(&current, ranking, &mut accounting)
                                };
                                let builds = plaintext_builds();
                                if std::ptr::eq(evaluator, &new) {
                                    let trials = usize::try_from(allowance.used - 3).unwrap();
                                    let winner =
                                        matches!(outcome, Ok(ScanOutcome::Complete(Some(_))));
                                    let expected =
                                        if streams { usize::from(winner) } else { trials };
                                    assert_eq!(builds, expected, "{objective:?} {input} {deny}");
                                }
                                outcomes.push((
                                    outcome,
                                    allowance.used,
                                    control.snapshot(),
                                    observer.0,
                                ));
                            }
                            assert_eq!(outcomes[0], outcomes[1], "{objective:?} {input} {deny}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn cancelled_and_losing_scans_build_no_plaintext() {
        let (initial, domain) = fixture();
        let evaluator = TrialEvaluator::new(
            &initial,
            &domain,
            "ABCABCAB",
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        );
        let selection = NeighborhoodSelection {
            initial: &initial,
            domain: &domain,
            evaluator: &evaluator,
            backtrack_pairs: 0,
        };
        let mut seen = Vec::new();
        for ranking in [i128::MIN, i128::MAX].map(FixedScore::from_units) {
            for (stop, limit) in [(1, 9), (2, 9), (3, 9), (5, 9), (99, 9)] {
                let mut runs = Vec::new();
                for reference in [true, false] {
                    let mut accounting = CancelAfter {
                        allowance: EvaluationAllowance { used: 0 },
                        polls: 0,
                        stop,
                    };
                    plaintext_builds();
                    let outcome = if reference {
                        reference_scan(&selection, &[], ranking, &mut accounting)
                    } else {
                        selection.scan(&[], ranking, &mut accounting)
                    };
                    let builds = plaintext_builds();
                    if !reference {
                        let winner = matches!(outcome, Ok(ScanOutcome::Complete(Some(_))));
                        assert_eq!(builds, usize::from(winner), "{stop} {limit}");
                        seen.push(std::mem::discriminant(outcome.as_ref().unwrap()));
                    }
                    runs.push((outcome, accounting.allowance.used, accounting.polls));
                }
                assert_eq!(runs[0], runs[1], "{stop} {limit}");
            }
        }
        for outcome in [ScanOutcome::Cancelled, ScanOutcome::Complete(None)] {
            assert!(seen.contains(&std::mem::discriminant(&outcome)));
        }
    }

    #[test]
    fn mapped_scans_fill_no_trial_board_and_build_one_winner_plaintext() {
        let (initial, domain) = fixture();
        let fills = || crate::attack_evaluator::BOARD_FILLS.with(|count| count.replace(0));
        for deny in [false, true] {
            let evaluator = TrialEvaluator::new(
                &initial,
                &domain,
                "ABCABCAB",
                Direction::Decrypt,
                MeasureId::Ic,
                None,
            );
            let evaluator = if deny {
                evaluator.with_reservation_denied()
            } else {
                evaluator
            };
            let selection = NeighborhoodSelection {
                initial: &initial,
                domain: &domain,
                evaluator: &evaluator,
                backtrack_pairs: 0,
            };
            for ranking in [i128::MIN, i128::MAX].map(FixedScore::from_units) {
                for current in [vec![], vec![('A', 'B')]] {
                    let mut allowance = EvaluationAllowance { used: 0 };
                    plaintext_builds();
                    fills();
                    let outcome = selection.scan(&current, ranking, &mut allowance);
                    let Ok(ScanOutcome::Complete(winner)) = outcome else {
                        panic!("{outcome:?}");
                    };
                    let trials = usize::try_from(allowance.used).unwrap();
                    assert!(trials > 1);
                    let winner = usize::from(winner.is_some());
                    assert_eq!(winner, usize::from(ranking.units() == i128::MIN));
                    // Trials never fill a board mapping; only a streamed winner's
                    // replay does, once per scan.
                    assert_eq!(fills(), if deny { 0 } else { winner }, "{deny}");
                    // Denied rows materialize every trial; streamed scans build only
                    // the winner's plaintext.
                    let builds = if deny { trials } else { winner };
                    assert_eq!(plaintext_builds(), builds, "{deny}");
                }
            }
        }
    }

    #[test]
    fn replay_invariants_project_to_the_invariant_category() {
        use crate::attack_result::RunPayload;
        let (_, domain) = fixture();
        let invariant = || TrialEvaluationError::Invariant("winner replay failed");
        let observed = || ObservedClimbError::Evaluation(invariant());
        let direct = ControlledDirectError {
            outer_index: Some(0),
            evaluations_used: 0,
            source: DirectRunError::from(observed()),
            best: None,
            counters: Default::default(),
        }
        .project(&domain, MeasureId::Ic);
        let partial = ControlledPartialRunError {
            outer_index: Some(0),
            seed_index: Some(0),
            evaluations_used: 0,
            source: ControlledPartialRunSource::Climb(ControlledPartialSource::Climb(observed())),
            best: None,
            counters: Default::default(),
            held: None,
        }
        .project(&domain, MeasureId::Ic);
        for source in [
            crate::AttackRunSource(RunPayload::from(observed())),
            crate::AttackRunSource(RunPayload::from(invariant())),
        ] {
            assert_eq!(source.category(), crate::AttackRunCategory::Invariant);
            assert_eq!(source.to_string(), "winner replay failed");
        }
        for error in [direct, partial] {
            let source = error.run_source();
            assert_eq!(source.category(), crate::AttackRunCategory::Invariant);
            assert_eq!(source.to_string(), "winner replay failed");
        }
    }

    /// Outers B, A, C decrypt "ABA" to AAC, CCB and BBA, tied on IC; the
    /// dictionary (AC 1, CB 2, BA 2) then separates them in trie stages.
    fn hold_stages_request(pe: bool, passes: &[&str], hold: u64) -> crate::AttackRequest {
        direct_request_with(serde_json::json!([]), false, pe, |job| {
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["B","A","C"]}]);
            job["text"] = serde_json::json!("ABA");
            job["measures"] = serde_json::json!(["ic", "trie"]);
            job["attack"]["initial_measure"] = serde_json::json!("ic");
            job["attack"]["final_measure"] = serde_json::json!("ic");
            job["attack"]["hold"] = serde_json::json!(hold);
            for &pass in passes {
                job["passes"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!(pass));
                job["attack"][pass] = match pass {
                    "trie" => serde_json::json!({}),
                    _ => serde_json::json!({"measure": "trie"}),
                };
            }
        })
    }

    /// Final entries as (outer, start, whole ranking units, own history length).
    fn hold_stages_entries(result: &crate::AttackResult) -> Vec<(u128, u128, i128, usize)> {
        (result.best.iter().chain(&result.held_tail))
            .map(|e| {
                (
                    e.outer_index,
                    e.start_index,
                    e.score.ranking().units() >> 32,
                    e.stages.len(),
                )
            })
            .collect()
    }

    #[test]
    fn latest_outer_preparation_evicts_and_is_run_local() {
        let request = hold_stages_request(false, &[], 3);
        let outers: Vec<_> = request
            .outer_candidates()
            .take(2)
            .map(|(index, initial)| (index, initial.unwrap()))
            .collect();
        crate::engine::ROW_BUILDS.with(|count| count.set(0));
        for _ in 0..2 {
            let run = RunPreparation::new(&request);
            for (step, outer) in [0, 0, 1, 0, 0].into_iter().enumerate() {
                let (index, initial) = &outers[outer];
                let objective = if step % 2 == 0 {
                    MeasureId::Ic
                } else {
                    MeasureId::Entropy
                };
                let scorer = run.evaluator(initial, *index, objective);
                assert_eq!(
                    scorer.evaluate(&[]).unwrap(),
                    TrialEvaluator::new(
                        initial,
                        request.domain(),
                        request.text(),
                        Direction::Decrypt,
                        objective,
                        None,
                    )
                    .evaluate(&[])
                    .unwrap()
                );
            }
        }
        // Three shared builds per run (A/B/A), plus ten standalone oracle builds.
        crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), 16));
    }

    #[test]
    fn hc_and_pe_share_consecutive_finalist_stages_without_retaining_all_outers() {
        for pe in [false, true] {
            crate::engine::ROW_BUILDS.with(|count| count.set(0));
            let plain = hold_stages_request(pe, &[], 3)
                .run(|_| {}, || false)
                .unwrap();
            let exploration = crate::engine::ROW_BUILDS.with(|count| count.get());
            assert_eq!(exploration, 3);
            let mut latest = 2;
            let mut expected = exploration;
            for entry in plain.best.iter().chain(&plain.held_tail) {
                if latest != entry.outer_index {
                    expected += 1;
                    latest = entry.outer_index;
                }
            }
            crate::engine::ROW_BUILDS.with(|count| count.set(0));
            let staged = hold_stages_request(pe, &["reswapping", "trie"], 3)
                .run(|_| {}, || false)
                .unwrap();
            assert_eq!(staged.termination, crate::AttackTermination::Completed);
            assert!(staged.hold().all(|entry| entry.stages().len() == 2));
            crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), expected));
        }
    }

    #[test]
    fn reswapping_retains_one_lazy_evaluator_and_stops_before_preparation() {
        let builds = || crate::engine::ROW_BUILDS.with(|count| count.get());
        let reset = || crate::engine::ROW_BUILDS.with(|count| count.set(0));
        reset();
        let request = hold_stages_request(false, &["reswapping"], 1);
        let result = request.run(|_| {}, || true).unwrap();
        assert_eq!(builds(), 0);
        assert_eq!(result.evaluations_used, 0);
        let request = |staged: bool| {
            let mut value = serde_json::json!({"protocol_version":1,"machine":{"definition":{
                "kind":"custom","value":{"alphabet":["A","B","C","D"],
                "wheels":[{"name":"r","wiring":["B","C","A","D"],"turnovers":[]}],
                "slots":[{"id":"r","role":"rotor","movement":"movable","wheel":"r"}],
                "stepping":{"rules":[]}}}},
                "job":{"kind":"search","configuration":{"slots":[{"id":"r","position":"A","ring":"A"}],"plugboard":[]},
                "space":{"plugboard":{"kind":"attack","symbols":["A","B","C","D"],"max_pairs":2}},
                "text":"AABBCD","passes":if staged {vec!["hill_climb","reswapping"]} else {vec!["hill_climb"]},
                "measures":["ic"],"attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":2,"backtrack_pairs":0,
                "start":[["A","B"],["C","D"]],"reswapping":{"measure":"ic"}}}});
            if !staged {
                value["job"]["attack"]
                    .as_object_mut()
                    .unwrap()
                    .remove("reswapping");
            }
            crate::ParsedAttackRequest::parse_json(&value.to_string())
                .unwrap()
                .bind_resources(&std::collections::BTreeMap::new())
                .unwrap()
        };
        reset();
        request(false).run(|_| {}, || false).unwrap();
        let direct = builds();
        reset();
        let result = request(true).run(|_| {}, || false).unwrap();
        assert!(result.stages[0].evaluations_used > 1);
        assert_eq!(direct, 1);
        assert_eq!(builds(), direct);
        // Streamed reswapping trials build no plaintext; only the commit replays.
        let plaintexts = |staged| {
            plaintext_builds();
            let result = request(staged).run(|_| {}, || false).unwrap();
            (result, plaintext_builds())
        };
        let ((_, plain), (staged, builds)) = (plaintexts(false), plaintexts(true));
        assert_eq!((builds - plain, staged.stages.len()), (1, 1));
    }

    #[test]
    fn hold_strict_best_capacity_parity_without_stages() {
        for pe in [false, true] {
            let observe = |capacity| {
                let request = hold_stages_request(pe, &[], capacity);
                let (mut snapshots, mut polls) = (Vec::new(), 0);
                let result = request
                    .run(
                        |p| snapshots.push(p.0),
                        || {
                            polls += 1;
                            false
                        },
                    )
                    .unwrap();
                (result, snapshots, polls)
            };
            let (one, one_snapshots, one_polls) = observe(1);
            let (many, many_snapshots, many_polls) = observe(100);
            let best = one.best.as_ref().unwrap();
            let head = many.hold().next().unwrap();
            // Full Debug payload covers configuration, mutable board, plaintext,
            // measure/score, absolute indices, flags and entry history.
            assert_eq!(format!("{best:?}"), format!("{:?}", head.best()));
            assert_eq!(one.termination, crate::AttackTermination::Completed);
            assert_eq!(many.termination, one.termination);
            assert_eq!(many.evaluations_used, one.evaluations_used);
            assert_eq!(many.counters, one.counters);
            assert_eq!((many_snapshots, many_polls), (one_snapshots, one_polls));
            assert!(one.stages.is_empty());
            assert!(many.stages.is_empty());
            assert_eq!(one.hold().count(), 1);
            assert!(many.hold().all(|entry| entry.stages().is_empty()));
            let tied: Vec<_> = many
                .hold()
                .filter(|entry| entry.best().score == best.score)
                .collect();
            assert!(tied.len() > 1);
            let indices: Vec<_> = tied
                .iter()
                .map(|entry| (entry.best().outer_index(), entry.best().start_index()))
                .collect();
            assert_eq!(indices[0], (0, 0));
            assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
            for (i, entry) in tied.iter().enumerate() {
                for later in &tied[i + 1..] {
                    assert_ne!(entry.best().configuration, later.best().configuration);
                }
            }
            assert_eq!((best.outer_index(), best.start_index()), indices[0]);
        }
    }

    #[test]
    fn hold_stages_capacity_one_matches_task13_pipeline() {
        for pe in [false, true] {
            for stop in [usize::MAX, 99, 14, 70] {
                let request = hold_stages_request(pe, &["trie", "reswapping"], 1);
                let (mut control, mut observer, mut polls) =
                    (AttackControl::default(), Recorder::default(), 0);
                let mut requested = || {
                    polls += 1;
                    polls == stop
                };
                let (domain, measure) = (request.domain(), request.settings().final_measure());
                assert!(!requested()); // One pre-block poll; no interior outer polls.
                let mut expected = if pe {
                    let run = request.schedule_partial_outers_controlled(
                        &mut control,
                        &mut observer,
                        || false,
                    );
                    run.unwrap()
                        .project_public(control.snapshot(), domain, measure)
                } else {
                    let run = request.schedule_direct_outers_controlled(
                        &mut control,
                        &mut observer,
                        || false,
                    );
                    run.unwrap()
                        .project_public(control.snapshot(), domain, measure)
                }
                .unwrap();
                // Task 13: the single winner runs the stage loop without
                // introducing internal public boundary notifications.
                if expected.termination == crate::AttackTermination::Completed
                    && expected.best.is_some()
                {
                    let allowance = &mut EvaluationAllowance {
                        used: expected.evaluations_used,
                    };
                    let accounting = &mut ObservedAccounting {
                        allowance,
                        control: &mut control,
                        observer: &mut observer,
                    };
                    expected = request
                        .finalist_stages(expected, accounting, &mut requested)
                        .unwrap();
                }
                assert!(observer.0.is_empty());
                let (mut snapshots, mut actual_polls) = (Vec::new(), 0);
                let actual = request
                    .run(
                        |p| snapshots.push(p.0),
                        || {
                            actual_polls += 1;
                            actual_polls == stop
                        },
                    )
                    .unwrap();
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                assert_eq!(snapshots, [Default::default(), control.snapshot()]);
                assert_eq!(actual_polls, polls);
            }
        }
    }

    #[test]
    fn hold_stages_polish_every_finalist_then_rerank_and_dedup() {
        for (pe, passes, expected) in [
            (
                false,
                &["trie"][..],
                [(1, 0, 3, 0), (2, 0, 3, 1), (0, 0, 2, 1)],
            ),
            (
                false,
                &["trie", "reswapping"],
                [(1, 0, 2, 0), (2, 0, 2, 2), (0, 0, 1, 2)],
            ),
            // Every PE seed reswaps onto its outer's empty board; the smaller index stays.
            (
                true,
                &["reswapping"],
                [(1, 0, 2, 0), (2, 0, 2, 1), (0, 0, 1, 1)],
            ),
        ] {
            let before = hold_stages_request(pe, &[], 100)
                .run(|_| {}, || false)
                .unwrap();
            assert_eq!(hold_stages_entries(&before).len(), if pe { 12 } else { 3 });
            let mut last = None;
            let result = hold_stages_request(pe, passes, 100)
                .run(|p| last = Some(p), || false)
                .unwrap();
            assert_eq!(result.termination, crate::AttackTermination::Completed);
            assert_eq!(last, Some(result.counters));
            // Outer 0 led before stages and now trails; the new head's history is the run's.
            assert_eq!(hold_stages_entries(&result), expected);
            let histories: Vec<_> = std::iter::once(&result.stages)
                .chain(result.held_tail.iter().map(|e| &e.stages))
                .collect();
            for (entry, history) in result.best.iter().chain(&result.held_tail).zip(&histories) {
                assert_eq!(history.len(), passes.len());
                assert!(history.iter().all(|stage| stage.completed));
                assert_eq!(history.last().unwrap().score, Some(entry.score));
            }
            // One shared allowance: every finalist's stage cost, deduplicated ones included
            // (PE: three empty boards cost 1 each, nine single pairs cost 7 each).
            let spent = if pe {
                66
            } else {
                histories
                    .iter()
                    .flat_map(|h| h.iter())
                    .map(|s| s.evaluations_used)
                    .sum()
            };
            assert_eq!(result.evaluations_used, before.evaluations_used + spent);
            let admitted = before.counters.evaluations_admitted() + spent;
            assert_eq!(result.counters.evaluations_admitted(), admitted);
        }
    }

    #[test]
    fn hold_stages_stop_mid_finalist_before_start_and_between_finalists() {
        use crate::AttackTermination::Cancelled;
        let used = (hold_stages_request(false, &[], 3).run(|_| {}, || false))
            .unwrap()
            .evaluations_used;
        // A one-finalist run establishes the exact independent polling prefix.
        // The next poll in the three-finalist run is entry to finalist two.
        let mut prefix_polls = 0;
        hold_stages_request(false, &["trie", "reswapping"], 1)
            .run(
                |_| {},
                || {
                    prefix_polls += 1;
                    false
                },
            )
            .unwrap();
        for (extra_polls, partial) in [(1, false), (2, true)] {
            let mut polls = 0;
            let result = hold_stages_request(false, &["trie", "reswapping"], 3)
                .run(
                    |_| {},
                    || {
                        polls += 1;
                        polls == prefix_polls + extra_polls
                    },
                )
                .unwrap();
            assert_eq!(result.termination, Cancelled);
            assert_eq!(result.evaluations_used, used + 2 + u64::from(partial));
            // Polished first, then the partial entry despite its higher score, then the
            // unpolished entries in pre-stage order with their HC scores.
            let middle = if partial { (1, 0, 3, 1) } else { (1, 0, 1, 0) };
            assert_eq!(
                hold_stages_entries(&result),
                [(0, 0, 1, 0), middle, (2, 0, 1, 0)]
            );
            assert_eq!(result.stages.len(), 2);
            assert_eq!(
                result.held_tail[0].stages.first().map(|s| s.completed),
                partial.then_some(true)
            );
        }
    }

    #[test]
    fn hold_stage_error_reranks_polished_partial_and_unprocessed_finalists() {
        use crate::attack_result::RunPayload;
        // Pre-stage hold: outers 0, 1, 2 tied on IC; finalist k fails its measure stage.
        for (fail_at, duplicate, expected) in [
            (1, false, vec![(0, vec![false]), (1, vec![]), (2, vec![])]),
            (
                2,
                false,
                vec![(0, vec![true]), (1, vec![false]), (2, vec![])],
            ),
            (
                3,
                false,
                vec![(1, vec![true]), (0, vec![true]), (2, vec![false])],
            ),
            // The unprocessed outer 2 repeats outer 0's key and is dropped after rerank.
            (2, true, vec![(0, vec![true]), (1, vec![false])]),
        ] {
            let mut result = (hold_stages_request(false, &[], 3).run(|_| {}, || false)).unwrap();
            if duplicate {
                result.held_tail[1].configuration =
                    result.best.as_ref().unwrap().configuration.clone();
            }
            let used = result.evaluations_used;
            let mut control = AttackControl::with_counters(result.counters.0);
            let mut allowance = EvaluationAllowance { used };
            let mut recorder = Recorder::default();
            let accounting = &mut ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut recorder,
            };
            let mut calls = 0;
            let error = stages_over_hold(result, |result| {
                calls += 1;
                let stage = crate::space::AttackStage::Measure {
                    measure: MeasureId::Ic,
                };
                scoring_stage(result, stage, accounting, |best| {
                    if calls == fail_at {
                        let missing = TrialEvaluationError::MissingResource(MeasureId::Trie);
                        return Err(RunPayload::Evaluation(missing));
                    }
                    // Later finalists score higher, so polished entries reverse order.
                    let units = (best.outer_index as i128 + 1) << 32;
                    let score = MeasuredScore::higher_is_better(FixedScore::from_units(units));
                    Ok((best.plaintext.clone(), score))
                })
            })
            .unwrap_err();
            let best = error.best().unwrap().unwrap();
            let held = crate::attack_result::tests::held_tail(&error);
            let history = |stages: &[crate::AttackStageResult]| -> Vec<bool> {
                stages.iter().map(|stage| stage.completed).collect()
            };
            let entries: Vec<_> = std::iter::once((best.outer_index, history(error.stages())))
                .chain(held.iter().map(|e| (e.outer_index, history(&e.stages))))
                .collect();
            assert_eq!(entries, expected);
            assert!(best.stages.is_empty());
            if expected[0].1 == [true] {
                let units = (best.outer_index as i128 + 1) << 32;
                assert_eq!(best.score().ranking().units(), units);
            }
            // The failing finalist keeps the error indices, cause and accounting.
            let failing = (fail_at - 1) as u128;
            assert_eq!(
                error.outer_index().zip(error.start_index()),
                Some((failing, 0))
            );
            assert!(matches!(
                error.run_source().0,
                RunPayload::Evaluation(TrialEvaluationError::MissingResource(MeasureId::Trie))
            ));
            assert_eq!(error.evaluations_used(), used + fail_at);
            assert_eq!(error.counters().evaluations_admitted(), used + fail_at);
            assert_eq!(error.counters().evaluations_completed(), used + fail_at - 1);
            assert_eq!(error.counters().0, control.snapshot());
            assert!(recorder.0.is_empty());
        }
    }
}
