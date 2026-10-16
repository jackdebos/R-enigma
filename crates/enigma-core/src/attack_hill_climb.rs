//! Private complete-neighborhood strict ascent with bound scoring and shared accounting.

use crate::attack_control::{AttackControl, CounterObserver, CounterOverflow};
use crate::attack_evaluator::{validated_trial_board, TrialEvaluationError, TrialEvaluator};
use crate::attack_neighborhood::NeighborhoodCursor;
use crate::attack_result::AttackRunErrorData;
use crate::{
    AttackPlugboardDomain, BoundResource, Direction, FixedScore, MeasureId, MeasuredScore,
    ResolvedConfiguration,
};

type MutableBoard = Vec<(char, char)>;

/// Owned initial key facts remain separate from the committed mutable remainder.
#[derive(Debug)]
pub(crate) struct DirectOuterOutcome {
    pub(crate) initial: ResolvedConfiguration,
    pub(crate) outer_index: u128,
    pub(crate) start_index: u128,
    pub(crate) climb: ClimbOutcome,
}

#[derive(Debug)]
enum ProjectionError {
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
            incomplete: self.climb.cancelled || self.climb.budget_stopped,
            final_objective_ascent: self.climb.final_objective_ascent,
            neighborhood_exhausted: self.climb.neighborhood_exhausted,
        })
    }
}

struct ProgressObserver<F>(F);

impl<F: FnMut(crate::AttackProgress)> CounterObserver for ProgressObserver<F> {
    fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
        (self.0)(crate::AttackProgress(snapshot));
    }
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
        let mut control = AttackControl::default();
        let mut observer = ProgressObserver(observe);
        if self.settings().kind() == crate::AttackKind::PartialExhaustion {
            return match self.schedule_partial_outers_controlled(
                &mut control,
                &mut observer,
                cancel_requested,
            ) {
                Ok(outcome) => outcome.project_public(
                    control.snapshot(),
                    self.domain(),
                    self.settings().final_measure(),
                ),
                Err(error) => Err(error.project(self.domain(), self.settings().final_measure())),
            };
        }
        match self.schedule_direct_outers_controlled(&mut control, &mut observer, cancel_requested)
        {
            Ok(outcome) => outcome.project_public(
                control.snapshot(),
                self.domain(),
                self.settings().final_measure(),
            ),
            Err(error) => Err(error.project(self.domain(), self.settings().final_measure())),
        }
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
            DirectRunTermination::EvaluationBudget => AttackTermination::EvaluationBudget,
            DirectRunTermination::Cancelled => AttackTermination::Cancelled,
        };
        Ok(crate::AttackResult {
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
    EvaluationBudget,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct DirectRunOutcome {
    pub(crate) termination: DirectRunTermination,
    pub(crate) outer_completed: u128,
    pub(crate) climbs_started: u128,
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
    MissingOuter,
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
    EvaluationBudget,
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
}

#[derive(Debug, PartialEq, Eq)]
enum ControlledPartialSource {
    UnsupportedPass,
    Climb(ObservedClimbError),
}

#[derive(Debug)]
struct ControlledPartialError {
    outer_index: u128,
    seed_index: Option<u128>,
    source: ControlledPartialSource,
    best: Option<Box<(ResolvedConfiguration, SeedBest)>>,
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
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ControlledPartialTermination {
    OuterSliceEnd,
    Completed,
    Cancelled,
    EvaluationBudget,
}

#[derive(Debug)]
struct ControlledPartialRun {
    termination: ControlledPartialTermination,
    outer_completed: u128,
    climbs_started: u128,
    climbs_completed: u128,
    evaluations_used: u64,
    best: Option<ControlledPartialOutcome>,
}

#[derive(Debug)]
enum ControlledPartialRunSource {
    Resolution(Vec<crate::SearchDiagnostic>),
    Climb(ControlledPartialSource),
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
}

impl SeedBest {
    fn into_direct(self, initial: ResolvedConfiguration, outer_index: u128) -> DirectOuterOutcome {
        DirectOuterOutcome {
            initial,
            outer_index,
            start_index: self.seed_index,
            climb: ClimbOutcome {
                current: Some(self.current),
                budget_stopped: self.incomplete,
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
                    budget_stopped: false,
                    cancelled: false,
                    final_objective_ascent: false,
                    neighborhood_exhausted: false,
                },
            },
        }
    }
}

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
            ControlledPartialTermination::EvaluationBudget => {
                DirectRunTermination::EvaluationBudget
            }
        };
        DirectRunOutcome {
            termination,
            outer_completed: self.outer_completed,
            climbs_started: self.climbs_started,
            climbs_completed: self.climbs_completed,
            evaluations_used: self.evaluations_used,
            best: self.best.map(ControlledPartialOutcome::into_direct),
        }
        .project_public(counters, domain, measure)
    }
}

impl ControlledPartialRunError {
    fn project(self, domain: &AttackPlugboardDomain, measure: MeasureId) -> crate::AttackRunError {
        use crate::attack_result::RunPayload;
        let source = match self.source {
            ControlledPartialRunSource::Resolution(diagnostics) => {
                RunPayload::Resolution(diagnostics)
            }
            ControlledPartialRunSource::MissingOuter => {
                RunPayload::Invariant("missing selected outer")
            }
            ControlledPartialRunSource::Climb(ControlledPartialSource::UnsupportedPass) => {
                RunPayload::Invariant("unsupported partial pass")
            }
            ControlledPartialRunSource::Climb(ControlledPartialSource::Climb(source)) => {
                match source {
                    ObservedClimbError::Evaluation(source) => RunPayload::Evaluation(source),
                    ObservedClimbError::Counter(source) => RunPayload::Counter(source),
                }
            }
        };
        crate::AttackRunError::new(AttackRunErrorData {
            stages: Vec::new(),
            source: crate::AttackRunSource(source),
            outer_index: self.outer_index,
            start_index: self.seed_index,
            evaluations_used: self.evaluations_used,
            counters: crate::AttackProgress(self.counters),
            best: self
                .best
                .map(|best| best.project(domain, measure))
                .transpose()
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>),
        })
    }
}

impl crate::AttackRequest {
    fn schedule_partial_outers_controlled(
        &self,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        mut requested: impl FnMut() -> bool,
    ) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
        control.notify(observer);
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: self.settings().evaluation_budget(),
        };
        let result = if self.settings().kind() != crate::AttackKind::PartialExhaustion {
            Err(Box::new(ControlledPartialRunError {
                outer_index: None,
                seed_index: None,
                evaluations_used: 0,
                source: ControlledPartialRunSource::Climb(ControlledPartialSource::UnsupportedPass),
                best: None,
                counters: control.snapshot(),
            }))
        } else {
            schedule_controlled_partial(
                self,
                self.gate().outer_selected(),
                self.outer_candidates(),
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control,
                    observer,
                },
                &mut requested,
            )
        };
        control.notify(observer);
        result
    }

    fn climb_partial_outer_controlled<O: CounterObserver, F: FnMut() -> bool>(
        &self,
        initial: ResolvedConfiguration,
        outer_index: u128,
        accounting: &mut ObservedAccounting<'_, O>,
        requested: &mut F,
    ) -> Result<ControlledPartialOutcome, ControlledPartialError> {
        accounting.control.notify(accounting.observer);
        let result = (|| {
            let settings = self.settings();
            if settings.kind() != crate::AttackKind::PartialExhaustion {
                return Err(ControlledPartialError {
                    outer_index,
                    seed_index: None,
                    source: ControlledPartialSource::UnsupportedPass,
                    best: None,
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
                .climb_seeds_controlled(
                    settings
                        .seed_policy()
                        .expect("validated PE settings have seeds"),
                    settings.backtrack_pairs(),
                    accounting,
                    requested,
                )
                .map_err(|error| {
                    ControlledPartialError::from_seed(outer_index, initial.clone(), error)
                })?;
            Ok(ControlledPartialOutcome {
                initial,
                outer_index,
                seeds,
            })
        })();
        accounting.control.notify(accounting.observer);
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
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: self.settings().evaluation_budget(),
        };
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
            let interrupted = outcome.seeds.budget_stopped;
            if !interrupted {
                result.outer_completed = result
                    .outer_completed
                    .checked_add(1)
                    .expect("completed outers cannot exceed charged starts");
            }
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
            // Select committed interrupted winners before returning; winning seed
            // flags never stand in for completion of the entire seed run.
            if interrupted {
                result.termination = PartialRunTermination::EvaluationBudget;
                return Ok(result);
            }
            // Iterator exhaustion and zero-cost completion precede budget denial.
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
    fn schedule_direct_outers_controlled(
        &self,
        control: &mut AttackControl,
        observer: &mut impl CounterObserver,
        mut requested: impl FnMut() -> bool,
    ) -> Result<DirectRunOutcome, Box<ControlledDirectError>> {
        control.notify(observer);
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: self.settings().evaluation_budget(),
        };
        let result = if self.settings().kind() != crate::AttackKind::HillClimb {
            Err(Box::new(ControlledDirectError {
                outer_index: None,
                evaluations_used: 0,
                source: DirectRunError::Climb(DirectClimbError::UnsupportedPass),
                best: None,
                counters: control.snapshot(),
            }))
        } else {
            schedule_controlled_direct(
                self.gate().outer_selected(),
                self.outer_candidates(),
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control,
                    observer,
                },
                &mut requested,
                |initial, index, accounting, requested| {
                    let (scoring, start) = self
                        .direct_scoring(&initial)
                        .map_err(DirectRunError::Climb)?;
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
            )
        };
        control.notify(observer);
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
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: self.settings().evaluation_budget(),
        };
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
            let interrupted = outcome.climb.budget_stopped;
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
            if interrupted {
                result.termination = DirectRunTermination::EvaluationBudget;
                return Ok(result);
            }
            // Do not stop on usage == limit: exhaustion and zero-cost work take precedence.
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
) -> Result<ControlledPartialRun, Box<ControlledPartialRunError>> {
    schedule_controlled_partial_with_climb(
        selected,
        outers,
        accounting,
        requested,
        |initial, index, accounting, requested| {
            owner.climb_partial_outer_controlled(initial, index, accounting, requested)
        },
    )
}

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
    accounting.control.notify(accounting.observer);
    let run = (|| -> Result<_, Box<ControlledPartialRunError>> {
        let before = accounting.control.snapshot();
        let mut result = ControlledPartialRun {
            termination: ControlledPartialTermination::OuterSliceEnd,
            outer_completed: 0,
            climbs_started: 0,
            climbs_completed: 0,
            evaluations_used: accounting.allowance.used,
            best: None,
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
            })?;
            let outcome = climb(initial, index, accounting, requested).map_err(|error| {
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
                ControlledPartialRunError {
                    outer_index: Some(error.outer_index),
                    seed_index: error.seed_index,
                    evaluations_used: accounting.allowance.used,
                    source: ControlledPartialRunSource::Climb(error.source),
                    best,
                    counters: accounting.control.snapshot(),
                }
            })?;
            let cancelled = outcome.seeds.cancelled;
            let interrupted = outcome.seeds.seeds.budget_stopped;
            // Only whole seed-run exhaustion completes an outer, not its winner's flags.
            if !cancelled && !interrupted {
                accounting
                    .transition(AttackControl::record_outer_completed)
                    .map_err(|source| ControlledPartialRunError {
                        outer_index: Some(index),
                        seed_index: None,
                        evaluations_used: accounting.allowance.used,
                        source: ControlledPartialRunSource::Climb(ControlledPartialSource::Climb(
                            source,
                        )),
                        best: result
                            .best
                            .take()
                            .map(ControlledPartialOutcome::into_direct),
                        counters: accounting.control.snapshot(),
                    })?;
            }
            let now = accounting.control.snapshot();
            result.outer_completed = now.outers_completed - before.outers_completed;
            result.climbs_started = now.climbs_started - before.climbs_started;
            result.climbs_completed = now.climbs_completed - before.climbs_completed;
            result.evaluations_used = accounting.allowance.used;
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
            if cancelled || interrupted {
                result.termination = if cancelled {
                    ControlledPartialTermination::Cancelled
                } else {
                    ControlledPartialTermination::EvaluationBudget
                };
                break;
            }
            result.termination = ControlledPartialTermination::Completed;
        }
        Ok(result)
    })();
    accounting.control.notify(accounting.observer);
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
            DirectRunError::Resolution(_) | DirectRunError::MissingOuter => None,
            _ => self.outer_index.map(|_| 0),
        };
        let source = match self.source {
            DirectRunError::Resolution(diagnostics) => RunPayload::Resolution(diagnostics),
            DirectRunError::Climb(DirectClimbError::Evaluation(source)) => {
                RunPayload::Evaluation(source)
            }
            DirectRunError::Counter(source) => RunPayload::Counter(source),
            DirectRunError::MissingOuter => RunPayload::Invariant("missing selected outer"),
            DirectRunError::Climb(DirectClimbError::MissingStart) => {
                RunPayload::Invariant("missing direct start")
            }
            DirectRunError::Climb(DirectClimbError::UnsupportedPass) => {
                RunPayload::Invariant("unsupported direct pass")
            }
        };
        crate::AttackRunError::new(AttackRunErrorData {
            stages: Vec::new(),
            source: crate::AttackRunSource(source),
            outer_index: self.outer_index,
            start_index,
            evaluations_used: self.evaluations_used,
            counters: crate::AttackProgress(self.counters),
            best: self
                .best
                .map(|best| best.project(domain, measure))
                .transpose()
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>),
        })
    }
}

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
) -> Result<DirectRunOutcome, Box<ControlledDirectError>> {
    accounting.control.notify(accounting.observer);
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
            let outcome = (|| {
                let initial = initial.map_err(DirectRunError::Resolution)?;
                let outcome = climb(initial, index, accounting, requested)?;
                if outcome.climb.neighborhood_exhausted {
                    accounting
                        .transition(AttackControl::record_outer_completed)
                        .map_err(DirectRunError::from)?;
                }
                Ok(outcome)
            })()
            .map_err(|source| IndexedDirectRunError {
                outer_index: Some(index),
                evaluations_used: accounting.allowance.used,
                source,
            })?;
            let cancelled = outcome.climb.cancelled;
            let interrupted = outcome.climb.budget_stopped;
            let now = accounting.control.snapshot();
            // These counters only increase; subtraction retains prior caller facts without reset.
            result.climbs_started = now.climbs_started - before.climbs_started;
            result.climbs_completed = now.climbs_completed - before.climbs_completed;
            result.outer_completed = now.outers_completed - before.outers_completed;
            result.evaluations_used = accounting.allowance.used;
            if let Some(current) = &outcome.climb.current {
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
            if cancelled || interrupted {
                result.termination = if cancelled {
                    DirectRunTermination::Cancelled
                } else {
                    DirectRunTermination::EvaluationBudget
                };
                break;
            }
            result.termination = DirectRunTermination::Completed;
        }
        Ok(())
    })();
    accounting.control.notify(accounting.observer);
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

/// Shared accounting, never reset by a scan. Reserve is supplied per operation.
#[derive(Debug)]
pub(super) struct EvaluationAllowance {
    pub(super) used: u64,
    pub(super) limit: u64,
}

impl EvaluationAllowance {
    fn admit(&mut self, reserve: u64) -> bool {
        // Subtraction avoids overflow even for an unlimited-looking u64 limit.
        if self.limit.saturating_sub(self.used) <= reserve {
            return false;
        }
        self.used += 1;
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ObservedClimbError {
    Evaluation(TrialEvaluationError),
    Counter(CounterOverflow),
}

impl From<TrialEvaluationError> for ObservedClimbError {
    fn from(error: TrialEvaluationError) -> Self {
        Self::Evaluation(error)
    }
}

/// One accounting path for all scoring phases; existing callers remain budget-only.
trait EvaluationAccounting {
    type Error: From<TrialEvaluationError>;
    fn cancelled(&mut self) -> bool {
        false
    }
    fn admit(&mut self, reserve: u64) -> Result<bool, Self::Error>;
    fn transition(
        &mut self,
        _record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn evaluate(
        &mut self,
        evaluator: &TrialEvaluator<'_>,
        board: &[(char, char)],
        reserve: u64,
    ) -> Result<Option<(String, MeasuredScore)>, Self::Error> {
        if !self.admit(reserve)? {
            return Ok(None);
        }
        let result = evaluator.evaluate(board)?;
        self.transition(AttackControl::record_evaluation_completed)?;
        Ok(Some(result))
    }
}

// Budget-only accounting supports legacy tests; production uses controlled accounting.
#[cfg(test)]
impl EvaluationAccounting for EvaluationAllowance {
    type Error = TrialEvaluationError;
    fn admit(&mut self, reserve: u64) -> Result<bool, Self::Error> {
        Ok(EvaluationAllowance::admit(self, reserve))
    }
}

struct ObservedAccounting<'a, O> {
    allowance: &'a mut EvaluationAllowance,
    control: &'a mut AttackControl,
    observer: &'a mut O,
}

impl<O: CounterObserver> EvaluationAccounting for ObservedAccounting<'_, O> {
    type Error = ObservedClimbError;
    fn admit(&mut self, reserve: u64) -> Result<bool, Self::Error> {
        if !self.allowance.admit(reserve) {
            return Ok(false);
        }
        self.transition(AttackControl::record_evaluation_admitted)?;
        Ok(true)
    }
    fn transition(
        &mut self,
        record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
    ) -> Result<(), Self::Error> {
        record(self.control).map_err(ObservedClimbError::Counter)?;
        self.control.notify(self.observer);
        Ok(())
    }
}

/// Request polling is independent of counter notification and sticks in the control.
struct CancellableAccounting<'a, 'b, O, F> {
    observed: &'a mut ObservedAccounting<'b, O>,
    requested: F,
}

impl<O: CounterObserver, F: FnMut() -> bool> EvaluationAccounting
    for CancellableAccounting<'_, '_, O, F>
{
    type Error = ObservedClimbError;

    fn cancelled(&mut self) -> bool {
        self.observed.control.poll_cancellation((self.requested)())
    }

    fn admit(&mut self, reserve: u64) -> Result<bool, Self::Error> {
        self.observed.admit(reserve)
    }

    fn transition(
        &mut self,
        record: fn(&mut AttackControl) -> Result<(), CounterOverflow>,
    ) -> Result<(), Self::Error> {
        self.observed.transition(record)
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
    pub(crate) budget_stopped: bool,
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
    pub(crate) budget_stopped: bool,
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
        )
    }

    fn climb_seeds_controlled_with<O: CounterObserver, F: FnMut() -> bool>(
        &self,
        policy: &crate::AttackSeedPolicy,
        accounting: &mut ObservedAccounting<'_, O>,
        requested: &mut F,
        mut climb: impl FnMut(
            u128,
            MutableBoard,
            &mut ObservedAccounting<'_, O>,
            &mut F,
        ) -> Result<ClimbOutcome, ObservedClimbError>,
    ) -> Result<ControlledSeedOutcome, ControlledSeedError> {
        accounting.control.notify(accounting.observer);
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
                    budget_stopped: false,
                    evaluations_used: accounting.allowance.used,
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
                result.seeds.budget_stopped = outcome.budget_stopped;
                if let Some(current) = outcome.current {
                    result.seeds.climbs_started += 1;
                    if outcome.neighborhood_exhausted {
                        result.seeds.climbs_completed += 1;
                    }
                    if result.seeds.best.as_ref().is_none_or(|best| {
                        current.score.ranking().units() > best.current.score.ranking().units()
                    }) {
                        result.seeds.best = Some(SeedBest {
                            seed_index,
                            current,
                            incomplete: outcome.cancelled || outcome.budget_stopped,
                            final_objective_ascent: outcome.final_objective_ascent,
                            neighborhood_exhausted: outcome.neighborhood_exhausted,
                        });
                    }
                }
                if outcome.cancelled || outcome.budget_stopped {
                    break;
                }
            }
            result.seeds.evaluations_used = accounting.allowance.used;
            Ok(result)
        })();
        accounting.control.notify(accounting.observer);
        run
    }

    // Legacy scoring wrappers retain budget and observation regression coverage.
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
            budget_stopped: false,
            evaluations_used: allowance.used,
            climbs_started: 0,
            climbs_completed: 0,
            best: None,
        };
        for (seed_index, board) in seeds {
            let outcome = self.climb(board, backtrack_pairs, allowance)?;
            result.budget_stopped = outcome.budget_stopped;
            let Some(current) = outcome.current else {
                break;
            };
            // Each counter is bounded by SeedCursor's scalar pair count, fits
            // u128 like the gate, and never narrows to a platform-sized index.
            result.climbs_started = result
                .climbs_started
                .checked_add(1)
                .expect("scalar seed count fits u128");
            if outcome.neighborhood_exhausted && !outcome.budget_stopped {
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
                    incomplete: outcome.budget_stopped,
                    final_objective_ascent: outcome.final_objective_ascent,
                    neighborhood_exhausted: outcome.neighborhood_exhausted,
                });
            }
            if outcome.budget_stopped {
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
    fn climb_observed(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
    ) -> Result<ClimbOutcome, ObservedClimbError> {
        accounting.control.notify(accounting.observer);
        let result = self.climb_accounted(board, backtrack_pairs, accounting);
        accounting.control.notify(accounting.observer);
        result
    }

    fn climb_cancellable(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
        requested: impl FnMut() -> bool,
    ) -> Result<ClimbOutcome, ObservedClimbError> {
        accounting.control.notify(accounting.observer);
        let result = self.climb_accounted(
            board,
            backtrack_pairs,
            &mut CancellableAccounting {
                observed: accounting,
                requested,
            },
        );
        accounting.control.notify(accounting.observer);
        result
    }

    fn climb_accounted<A: EvaluationAccounting>(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        allowance: &mut A,
    ) -> Result<ClimbOutcome, A::Error> {
        let mut cancelled = allowance.cancelled();
        let started = if cancelled {
            None
        } else {
            self.start(board, allowance)?
        };
        let Some(mut state) = started else {
            return Ok(ClimbOutcome {
                current: None,
                budget_stopped: !cancelled,
                cancelled,
                final_objective_ascent: false,
                neighborhood_exhausted: false,
            });
        };
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
            // Even with no allowance, the cursor may complete without evaluations.
            let outcome = selection.scan(
                &state.current.board,
                state.current.score.ranking(),
                allowance,
                state.reserve(),
            )?;
            match outcome {
                ScanOutcome::Interrupted => break false,
                ScanOutcome::Cancelled => {
                    cancelled = true;
                    break false;
                }
                ScanOutcome::Complete(winner) => {
                    final_objective_ascent |= state.final_phase || self.identical;
                    let Some(winner) = winner else { break true };
                    // Each admitted scan call leaves reserve intact. Crossing spends at
                    // most that reserve; identical/already-final commits spend nothing.
                    state = state
                        .commit_trial(winner, allowance)?
                        .expect("complete scan preserved the objective-crossing reservation");
                    allowance.cancelled();
                }
            }
        };
        // The same invariant leaves one call for an unknown final score, even
        // after an interrupted scan. Consuming finalization cannot run twice.
        let current = state
            .finalize(allowance)?
            .expect("driver preserved the final-score reservation");
        if neighborhood_exhausted {
            allowance.transition(AttackControl::record_climb_completed)?;
        }
        Ok(ClimbOutcome {
            current: Some(current),
            budget_stopped: !neighborhood_exhausted && !cancelled,
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

    fn start<A: EvaluationAccounting>(
        &self,
        board: MutableBoard,
        allowance: &mut A,
    ) -> Result<Option<ScoringState<'_, 'a>>, A::Error> {
        validated_trial_board(self.initial, self.domain, &board)
            .map_err(TrialEvaluationError::Board)?;
        let final_phase = self.domain.fixed_pairs().len() + board.len() >= self.switch_pairs;
        let known_final = final_phase || self.identical;
        let evaluator = if final_phase {
            &self.final_evaluator
        } else {
            &self.initial_evaluator
        };
        let Some((plaintext, score)) =
            allowance.evaluate(evaluator, &board, u64::from(!known_final))?
        else {
            return Ok(None);
        };
        Ok(Some(ScoringState {
            context: self,
            current: ScoredBoard {
                board,
                plaintext,
                score,
            },
            final_phase,
            known_final,
        }))
    }
}

impl ScoringState<'_, '_> {
    fn reserve(&self) -> u64 {
        u64::from(!self.known_final)
    }

    /// Caller must preserve reserve in the shared allowance. None reports denied admission.
    /// Consuming the state makes finalization once-only; it never starts another ascent.
    fn finalize<A: EvaluationAccounting>(
        mut self,
        allowance: &mut A,
    ) -> Result<Option<ScoredBoard>, A::Error> {
        if !self.known_final {
            let Some((plaintext, score)) =
                allowance.evaluate(&self.context.final_evaluator, &self.current.board, 0)?
            else {
                return Ok(None);
            };
            self.current.plaintext = plaintext;
            self.current.score = score;
        }
        Ok(Some(self.current))
    }

    /// Precondition for 11.4b.2: trial is a complete-scan-selected strict winner,
    /// evaluated with THIS context's current objective; its call was already charged.
    /// This lifecycle does not verify selection. Caller must have preserved reserve.
    /// Consuming self prevents an unscored committed board escaping on any error.
    fn commit_trial<A: EvaluationAccounting>(
        mut self,
        trial: ScoredBoard,
        allowance: &mut A,
    ) -> Result<Option<Self>, A::Error> {
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
                let Some((plaintext, score)) =
                    allowance.evaluate(&self.context.final_evaluator, &self.current.board, 0)?
                else {
                    return Ok(None);
                };
                self.current.plaintext = plaintext;
                self.current.score = score;
            }
            self.known_final = true;
        }
        Ok(Some(self))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ScanOutcome {
    Complete(Option<ScoredBoard>),
    Interrupted,
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
        reserve: u64,
    ) -> Result<ScanOutcome, A::Error> {
        let mut cursor =
            NeighborhoodCursor::new(self.initial, self.domain, current, self.backtrack_pairs)
                .map_err(TrialEvaluationError::Board)?
                .peekable();
        let mut best = None;
        let mut best_ranking = ranking;
        while let Some(board) = cursor.next() {
            if allowance.cancelled() {
                return Ok(ScanOutcome::Cancelled);
            }
            let Some((plaintext, score)) = allowance.evaluate(self.evaluator, &board, reserve)?
            else {
                return Ok(ScanOutcome::Interrupted);
            };
            if score.ranking().units() > best_ranking.units() {
                best_ranking = score.ranking();
                best = Some(ScoredBoard {
                    board,
                    plaintext,
                    score,
                });
            }
            if allowance.cancelled() {
                // A completed losing scan has already established exhaustion.
                if best.is_none() && cursor.peek().is_none() {
                    return Ok(ScanOutcome::Complete(None));
                }
                return Ok(ScanOutcome::Cancelled);
            }
        }
        Ok(ScanOutcome::Complete(best))
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

    fn run_cancellation(
        context: &BoundClimbScoring<'_>,
        stop_poll: usize,
        limit: u64,
    ) -> (
        Result<ClimbOutcome, ObservedClimbError>,
        crate::attack_control::CounterSnapshot,
        u64,
        usize,
    ) {
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 7 + limit,
        };
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
        assert_eq!(observer.0.last(), Some(&snapshot));
        assert_eq!(snapshot.outers_completed, 0);
        (result, snapshot, allowance.used - 7, polls)
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
            let (result, snapshot, actual, _) = run_cancellation(&context, stop, 100);
            let outcome = result.unwrap();
            assert_eq!(
                outcome.current.unwrap().board,
                if committed { vec![('A', 'C')] } else { vec![] }
            );
            assert!(outcome.cancelled);
            assert!(!outcome.budget_stopped && !outcome.neighborhood_exhausted);
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
        for (stop, limit, used, cancelled, exhausted) in [
            (1, 0, 0, true, false),
            (1, 100, 0, true, false),
            (2, 1, 1, true, false),
            (3, 1, 1, true, false),
            (0, 1, 1, false, false),
            (19, 9, 9, false, true),
        ] {
            let (result, snapshot, actual, polls) = run_cancellation(&context, stop, limit);
            let outcome = result.unwrap();
            assert_eq!(
                (outcome.cancelled, outcome.neighborhood_exhausted),
                (cancelled, exhausted)
            );
            assert_eq!(outcome.budget_stopped, !cancelled && !exhausted);
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
        let (result, snapshot, used, _) = run_cancellation(&context, 2, 1);
        let outcome = result.unwrap();
        assert!(outcome.neighborhood_exhausted && !outcome.cancelled);
        assert_eq!((used, snapshot.climbs_completed), (1, 1));
    }

    #[test]
    fn cancelled_finalization_preserves_errors_and_usage() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        let last = resource(&initial);
        // Distinct objective binding reserves exactly one final rescore.
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
            let (result, snapshot, actual, _) = run_cancellation(&context, stop, used);
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
            let (result, snapshot, actual, _) = run_cancellation(&context, stop, 100);
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
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 107,
        };
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
            0,
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
        let mut allowance = EvaluationAllowance { used: 7, limit: 10 };
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
        assert!(accounting.evaluate(&evaluator, &[], 0).unwrap().is_some());
        let failing = TrialEvaluator::new(
            &initial,
            &domain,
            "AA",
            Direction::Decrypt,
            MeasureId::Trie,
            None,
        );
        assert_eq!(
            accounting.evaluate(&failing, &[], 0),
            Err(ObservedClimbError::Evaluation(
                TrialEvaluationError::MissingResource(MeasureId::Trie)
            ))
        );
        assert_eq!(allowance.used, 9);
        assert_eq!(control.snapshot().evaluations_admitted, 2);
        assert_eq!(control.snapshot().evaluations_completed, 1);
    }

    #[test]
    fn observed_climb_preserves_phases_budgets_and_notifications() {
        let (initial, domain) = fixture();
        let first = resource(&initial);
        // Distinct bindings cross at one pair, or rescore at termination at two.
        for (threshold, distinct, limit, used, exhausted, paired, expected_ascent) in [
            (2, false, 0, 0, false, false, false),
            (2, false, 3, 3, false, false, false),
            (2, false, 9, 9, true, true, true),
            (1, true, 1, 0, false, false, false),
            (1, true, 5, 5, false, true, false),
            (2, true, 100, 10, true, true, false),
        ] {
            let last = resource(&initial);
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(if distinct { &last } else { &first })),
                threshold,
            );
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 7 + limit,
            };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let outcome = context
                .climb_observed(
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
            assert_eq!(allowance.used, 7 + used);
            assert_eq!(snapshot.climbs_started, u128::from(used > 0));
            assert_eq!(snapshot.climbs_completed, u128::from(exhausted));
            assert_eq!(snapshot.outers_completed, 0);
            assert_eq!(outcome.neighborhood_exhausted, exhausted);
            assert_eq!(outcome.budget_stopped, !exhausted);
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
            assert_eq!(observer.0.first(), Some(&Default::default()));
            assert_eq!(observer.0.last(), Some(&snapshot));
            assert_eq!(
                observer.0.len() as u64,
                2 + used * 2 + u64::from(used > 0) + u64::from(exhausted)
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 107,
            };
            let mut control = AttackControl::default();
            let mut observer = Recorder::default();
            let error = context
                .climb_observed(
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
            assert_eq!(observer.0.last(), Some(&snapshot));
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
            let mut allowance = EvaluationAllowance { used: 7, limit: 8 };
            let mut observer = Recorder::default();
            let error = ObservedAccounting {
                allowance: &mut allowance,
                control: &mut control,
                observer: &mut observer,
            }
            .evaluate(&evaluator, &[], 0)
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
            "final_measure":"trie","switch_pairs":1,"backtrack_pairs":0,"evaluation_budget":100,"start":start}}});
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 100,
            };
            let outcome = request
                .climb_partial_outer(initial, index, &mut allowance)
                .unwrap();
            assert_eq!(outcome.initial, retained);
            assert_eq!(outcome.outer_index, index); // Retention, not provenance validation.
            let run = outcome.seeds;
            assert_eq!(run.evaluations_used, 7 + cost);
            assert_eq!(allowance.used, 7 + cost);
            assert_eq!((run.climbs_started, run.climbs_completed), (count, count));
            assert!(!run.budget_stopped);
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
    fn request_bound_partial_admission_and_interruption() {
        // Literal costs protect independent fresh seeds, not chained climbs.
        for (limit, started, completed, incomplete) in [
            (0, 0, 0, false),
            (8, 1, 0, true),
            (9, 1, 1, false),
            (10, 2, 1, false),
            (20, 2, 2, false),
        ] {
            let request = direct_request(serde_json::json!([]), false, true);
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let mut allowance = EvaluationAllowance {
                used: 3,
                limit: 3 + limit,
            };
            let run = request
                .climb_partial_outer(initial, 2, &mut allowance)
                .unwrap()
                .seeds;
            assert_eq!(run.evaluations_used, 3 + limit);
            assert_eq!(
                (run.climbs_started, run.climbs_completed),
                (started, completed)
            );
            assert!(run.budget_stopped);
            if let Some(best) = run.best {
                assert_eq!(best.seed_index, 0);
                assert_eq!(best.current.plaintext, "CB");
                assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
                assert_eq!(best.incomplete, incomplete);
                assert_eq!(best.neighborhood_exhausted, !incomplete);
            } else {
                assert_eq!(started, 0);
            }
        }
        let request = direct_request(serde_json::json!([]), true, true);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let mut allowance = EvaluationAllowance { used: 7, limit: 8 };
        let run = request
            .climb_partial_outer(initial, 0, &mut allowance)
            .unwrap()
            .seeds;
        assert_eq!(run.evaluations_used, 7);
        assert_eq!((run.climbs_started, run.climbs_completed), (0, 0));
        assert!(run.best.is_none() && run.budget_stopped);
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 7 + cost,
            };
            let outcome = request
                .climb_partial_outer(initial.clone(), 0, &mut allowance)
                .unwrap();
            assert_eq!(outcome.initial, initial);
            let run = outcome.seeds;
            assert_eq!(run.evaluations_used, 7 + cost);
            assert_eq!((run.climbs_started, run.climbs_completed), (1, 1));
            assert!(!run.budget_stopped);
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
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
        let error = request
            .climb_partial_outer(initial, 9, &mut allowance)
            .unwrap_err();
        assert_eq!(error.source, PartialClimbError::UnsupportedPass);
        assert_eq!((error.outer_index, error.evaluations_used), (9, 7));
        assert_eq!(allowance.used, 7);
    }

    #[test]
    fn request_bound_partial_later_interrupted_winner_and_dense_mask_index() {
        for (selection, symbols, index, plaintext, weight) in [
            ("all", vec![], 1, "AC", 1),
            ("touching", vec!["C"], 1, "CB", 2),
        ] {
            let request = direct_request_with(serde_json::json!([]), true, true, |job| {
                // IC ties all two-distinct-letter outputs. Empty completes without
                // ascent; the next seed's committed final score wins while interrupted.
                job["attack"]["seeds"]["selection"] = serde_json::json!(selection);
                if selection == "touching" {
                    job["attack"]["seeds"]["symbols"] = serde_json::json!(symbols);
                }
            });
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let mut allowance = EvaluationAllowance { used: 0, limit: 7 };
            let run = request
                .climb_partial_outer(initial, 0, &mut allowance)
                .unwrap()
                .seeds;
            assert_eq!((run.climbs_started, run.climbs_completed), (2, 1));
            assert_eq!(run.evaluations_used, 7);
            assert!(run.budget_stopped);
            let best = run.best.unwrap();
            assert_eq!(best.seed_index, index);
            assert_eq!(best.current.plaintext, plaintext);
            assert_eq!(best.current.score.ranking().units(), weight << 32);
            assert!(best.incomplete);
            assert!(!best.neighborhood_exhausted && !best.final_objective_ascent);
        }
    }

    fn scheduler_request(
        limit: u64,
        distinct: bool,
        pe: bool,
        offset: u64,
    ) -> crate::AttackRequest {
        direct_request_with(serde_json::json!([]), distinct, pe, |job| {
            job["attack"]["evaluation_budget"] = serde_json::json!(limit);
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
            job["space"]["offset"] = serde_json::json!(offset);
        })
    }

    fn partial_scheduler_request(
        budget: u64,
        distinct: bool,
        customize: impl FnOnce(&mut serde_json::Value),
    ) -> crate::AttackRequest {
        direct_request_with(serde_json::json!([]), distinct, true, |job| {
            job["attack"]["evaluation_budget"] = serde_json::json!(budget);
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
            customize(job);
        })
    }

    #[test]
    fn controlled_partial_error_retains_prior_owned_projection() {
        let request = partial_scheduler_request(100, false, |_| {});
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
            let mut allowance = EvaluationAllowance {
                used: 0,
                limit: 100,
            };
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
            )
            .unwrap_err();
            assert_eq!(error.counters, control.snapshot());
            assert_eq!(recorder.0.last(), Some(&error.counters));
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
                    allowance: &mut EvaluationAllowance {
                        used: 0,
                        limit: 100,
                    },
                    control: &mut AttackControl::default(),
                    observer: &mut Recorder::default(),
                },
                &mut || false,
            )
            .unwrap()
    }

    #[test]
    fn controlled_partial_failing_outer_seed_strict_selection() {
        let request = partial_scheduler_request(100, false, |_| {});
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
                    allowance: &mut EvaluationAllowance {
                        used: 7,
                        limit: 100,
                    },
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
                    })
                },
            )
            .unwrap_err();
            assert_eq!(recorder.0.last(), Some(&error.counters));
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
        let request = partial_scheduler_request(100, false, |_| {});
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
            assert_eq!(recorder.0.last(), Some(&error.counters));
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
        let request = partial_scheduler_request(100, false, |_| {});
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
            (
                ControlledPartialTermination::EvaluationBudget,
                AttackTermination::EvaluationBudget,
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
                        AttackTermination::EvaluationBudget => {
                            ControlledPartialTermination::EvaluationBudget
                        }
                    },
                    outer_completed: 1,
                    climbs_started: 4,
                    climbs_completed: 4,
                    evaluations_used: u64::MAX,
                    best: Some(best),
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
        let request = partial_scheduler_request(100, false, |_| {});
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
        let request = partial_scheduler_request(100, false, |_| {});
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
        let cancel = std::cell::Cell::new(false);
        let mut last = None;
        let result = request
            .run(
                |p| {
                    cancel.set(stop(p));
                    last = Some(p);
                },
                || cancel.get(),
            )
            .expect("public PE executes");
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
        use crate::AttackTermination::{Completed, EvaluationBudget};
        for (distinct, touching, budget, termination, counts, seed, text, score, flags) in [
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
                EvaluationBudget,
                (7, 2, 1, 0),
                1,
                "AC",
                1,
                (true, false, false),
            ),
            (
                true,
                true,
                7,
                EvaluationBudget,
                (7, 2, 1, 0),
                1,
                "CB",
                2,
                (true, false, false),
            ),
        ] {
            let request = direct_request_with(serde_json::json!([]), distinct, true, |job| {
                job["attack"]["evaluation_budget"] = serde_json::json!(budget);
                if touching {
                    job["attack"]["seeds"] = serde_json::json!({"kind":"empty_single","selection":"touching","symbols":["C"]});
                }
            });
            let result = public_pe_probe(&request, |_| false);
            public_pe_facts(
                &result,
                termination,
                counts,
                Some((0, seed, text, score, flags.0, flags.1, flags.2)),
            );
            let pair = if touching || !distinct {
                ('A', 'C')
            } else {
                ('A', 'B')
            };
            assert_eq!(result.best().unwrap().mutable_plugboard(), &[pair]);
        }
    }

    #[test]
    fn public_pe_outer_winner_order_and_interruption() {
        use crate::AttackTermination::{Completed, EvaluationBudget};
        for (distinct, text, budget, offset, termination, counts, winner, plain, score, flags) in [
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
                EvaluationBudget,
                (4, 2, 2, 2),
                1,
                "BA",
                2,
                (false, false, true),
            ),
        ] {
            let request = partial_scheduler_request(budget, distinct, |job| {
                job["text"] = serde_json::json!(text);
                job["space"]["offset"] = serde_json::json!(offset);
                job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            });
            let result = public_pe_probe(&request, |_| false);
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
            partial_scheduler_request(100, true, |job| {
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
            crate::AttackTermination::Cancelled,
            (10, 3, 2, 1),
            Some((1, 0, "BA", 2, true, false, false)),
        );
        // The completed A outer establishes an eligible aggregate winner. The B
        // outer is stopped after its empty seed starts, before any climb completes.
        // Its reserved final rescore still makes that unfinished seed eligible.
        for (result, position, evaluations, flags) in [
            (&earlier, 'A', 8, (false, true, true)),
            (&later, 'B', 10, (true, false, false)),
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
        // Eight evaluations belonged to the completed outer; the interrupted
        // empty seed admitted its initial score and one reserved final rescore.
        assert_eq!(later.evaluations_used() - earlier.evaluations_used(), 2);
        assert_eq!(later.counters().climbs_started(), 3);
        assert_eq!(later.counters().climbs_completed(), 2);
        assert_eq!(later.counters().outers_completed(), 1);
    }

    #[test]
    fn public_pe_observation_cancellation_boundaries() {
        let request = partial_scheduler_request(100, true, |_| {});
        // An interrupted later outer must not replace the earlier eligible winner.
        let interrupted_outer = public_pe_probe(&request, |p| {
            p.outers_completed() == 1 && p.climbs_started() == 5
        });
        public_pe_facts(
            &interrupted_outer,
            crate::AttackTermination::Cancelled,
            (30, 5, 4, 1),
            Some((0, 1, "CB", 2, false, true, true)),
        );
        for (boundary, counts, winner) in [
            (0, (0, 0, 0, 0), None),
            (1, (32, 4, 4, 1), Some((0, 0, "CB", 2, false, true, true))),
            (2, (9, 1, 1, 0), Some((0, 0, "CB", 2, false, true, true))),
            (3, (2, 1, 0, 0), Some((0, 0, "CA", 0, true, false, false))),
        ] {
            let request = partial_scheduler_request(100, false, |_| {});
            let result = public_pe_probe(&request, |p| match boundary {
                0 => true,
                1 => p.outers_completed() == 1,
                2 => p.climbs_completed() == 1,
                _ => p.evaluations_completed() >= 2,
            });
            public_pe_facts(&result, crate::AttackTermination::Cancelled, counts, winner);
        }
        // Distinct objectives must spend the reserved final rescore after cancellation.
        let request = partial_scheduler_request(100, true, |_| {});
        let result = public_pe_probe(&request, |p| p.evaluations_completed() >= 2);
        public_pe_facts(
            &result,
            crate::AttackTermination::Cancelled,
            (3, 1, 0, 0),
            Some((0, 0, "CA", 0, true, false, false)),
        );
    }

    #[test]
    fn public_pe_budget_and_empty_precedence() {
        use crate::AttackTermination::{Completed, EvaluationBudget, OuterSliceEnd};
        for (budget, distinct, offset, cancel, termination, counts, winner) in [
            (1, false, 3, true, OuterSliceEnd, (0, 0, 0, 0), None),
            (
                32,
                false,
                0,
                false,
                Completed,
                (32, 4, 4, 1),
                Some((0, 0, "CB", 2, false, true, true)),
            ),
            (1, true, 0, false, EvaluationBudget, (0, 0, 0, 0), None),
            (
                2,
                true,
                0,
                false,
                EvaluationBudget,
                (2, 1, 0, 0),
                Some((0, 0, "CA", 0, true, false, false)),
            ),
        ] {
            let request = partial_scheduler_request(budget, distinct, |job| {
                job["space"]["offset"] = serde_json::json!(offset);
                job["space"]["limit"] = serde_json::json!(1);
            });
            let result = public_pe_probe(&request, |_| cancel);
            public_pe_facts(&result, termination, counts, winner);
        }
    }

    #[test]
    fn public_pe_restarts_after_cancel_and_completion() {
        let request = partial_scheduler_request(32, false, |job| {
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
        let request = partial_scheduler_request(32, false, |_| {});
        // Independently validate the fixture by running the entire first seed run.
        let (index, initial) = request.outer_candidates().next().unwrap();
        let mut allowance = EvaluationAllowance { used: 0, limit: 32 };
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
        assert!(!outer.seeds.cancelled && !outer.seeds.seeds.budget_stopped);
        assert_eq!(allowance.used, 32);
        assert_eq!(outer.seeds.seeds.climbs_completed, 4);
        let cancelled = std::cell::Cell::new(false);
        struct Observer<'a>(&'a std::cell::Cell<bool>);
        impl CounterObserver for Observer<'_> {
            fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
                self.0.set(snapshot.outers_completed == 1);
            }
        }
        let mut observer = Observer(&cancelled);
        let mut control = AttackControl::default();
        let run = request
            .schedule_partial_outers_controlled(&mut control, &mut observer, || cancelled.get())
            .unwrap();
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
        struct Observer<'a>(&'a std::cell::Cell<u64>, Recorder);
        impl CounterObserver for Observer<'_> {
            fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
                self.0.set(snapshot.evaluations_completed);
                self.1.observe(snapshot);
            }
        }
        let completed = std::cell::Cell::new(0);
        let mut observer = Observer(&completed, Recorder::default());
        let mut control = AttackControl::with_counters(prior);
        let run = request
            .schedule_partial_outers_controlled(&mut control, &mut observer, || {
                stop_at.is_some_and(|stop| completed.get() >= stop)
            })
            .unwrap();
        assert_eq!(observer.1 .0.last(), Some(&control.snapshot()));
        (run, observer.1, control)
    }

    #[test]
    fn controlled_partial_outer_early_empty_exhaustion_and_budget() {
        for (offset, stop, termination) in [
            (0, Some(0), ControlledPartialTermination::Cancelled),
            (3, Some(0), ControlledPartialTermination::OuterSliceEnd),
        ] {
            let request = partial_scheduler_request(32, false, |job| {
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
            (3, None, ControlledPartialTermination::EvaluationBudget),
        ] {
            let request = partial_scheduler_request(32, false, |job| {
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
        let request = partial_scheduler_request(100, false, |_| {});
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
        let fixed = partial_scheduler_request(1, false, |job| {
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
        for (distinct, text, budget, offset, winner, plaintext) in
            [(true, "CB", 6, 0, 1, "BA"), (false, "A", 2, 1, 1, "A")]
        {
            let request = partial_scheduler_request(budget, distinct, |job| {
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
        let request = partial_scheduler_request(32, false, |_| {});
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
            assert_eq!(recorder.0.last(), Some(&control.snapshot()));
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
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
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
        )
        .unwrap_err();
        assert_eq!(
            (error.outer_index, error.seed_index, error.evaluations_used),
            (Some(42), None, 7)
        );
        assert!(
            matches!(error.source, ControlledPartialRunSource::Resolution(diagnostics) if diagnostics.is_empty())
        );
        let wrong = scheduler_request(32, false, false, 0);
        let error = wrong
            .schedule_partial_outers_controlled(&mut control, &mut recorder, || true)
            .unwrap_err();
        assert!(matches!(
            error.source,
            ControlledPartialRunSource::Climb(ControlledPartialSource::UnsupportedPass)
        ));
        assert_eq!(recorder.0.last(), Some(&control.snapshot()));
    }

    #[test]
    fn controlled_partial_outer_binding_and_resolution_sources() {
        use crate::attack_control::CounterSnapshot;
        let request = partial_scheduler_request(100, true, |job| {
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 100,
            };
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
            assert_eq!(recorder.0.last(), Some(&prior));
        }
    }

    #[test]
    fn controlled_partial_outer_charged_evaluator_mapping_with_pending_cancel() {
        use crate::attack_control::CounterSnapshot;
        let owner = partial_scheduler_request(100, true, |_| {});
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
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
        let pending = std::cell::Cell::new(false);
        let mut snapshots = Vec::new();
        struct Observer<'a>(&'a mut Vec<CounterSnapshot>, &'a std::cell::Cell<bool>);
        impl CounterObserver for Observer<'_> {
            fn observe(&mut self, snapshot: CounterSnapshot) {
                self.0.push(snapshot);
                if snapshot.evaluations_admitted > 3 {
                    self.1.set(true);
                }
            }
        }
        let mut observer = Observer(&mut snapshots, &pending);
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
                let source = accounting
                    .evaluate(&evaluator, &[('A', 'Z')], 0)
                    .unwrap_err();
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
        assert_eq!(snapshots.first(), Some(&prior));
        assert_eq!(snapshots.last(), Some(&control.snapshot()));
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
        let run = scheduler_request(1, false, true, 3)
            .schedule_partial_outers()
            .unwrap();
        assert_eq!(run.termination, PartialRunTermination::OuterSliceEnd);
        assert_eq!(partial_counts(&run), (0, 0, 0, 0));
        assert!(run.best.is_none());
        for offset in [0, 3] {
            let error = scheduler_request(1, false, false, offset)
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
            let request = partial_scheduler_request(cost, false, |job| {
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
            assert!(!outer.seeds.budget_stopped);
            let best = outer.seeds.best.unwrap();
            assert_eq!(best.seed_index, 0);
            assert_eq!(best.current.board, vec![('A', 'C')]);
            assert_eq!(best.current.plaintext, "CB");
            assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
            assert!(!best.incomplete);
            assert!(best.neighborhood_exhausted && best.final_objective_ascent);
        }
        // Exact exhaustion wins only if no outer remains. Fresh second-outer
        // admission costs one evaluation; it never reuses the previous board.
        for (budget, started) in [(32, 4), (33, 5)] {
            let run = scheduler_request(budget, false, true, 0)
                .schedule_partial_outers()
                .unwrap();
            assert_eq!(run.termination, PartialRunTermination::EvaluationBudget);
            assert_eq!(partial_counts(&run), (1, started, 4, budget));
            let outer = run.best.unwrap();
            assert_eq!(outer.outer_index, 0);
            let best = outer.seeds.best.unwrap();
            assert_eq!(best.current.plaintext, "CB");
            assert!(!best.incomplete && best.neighborhood_exhausted);
        }
        for (budget, started, completed, incomplete) in
            [(8, 1, 0, true), (9, 1, 1, false), (10, 2, 1, false)]
        {
            let run = scheduler_request(budget, false, true, 0)
                .schedule_partial_outers()
                .unwrap();
            assert_eq!(run.termination, PartialRunTermination::EvaluationBudget);
            assert_eq!(partial_counts(&run), (0, started, completed, budget));
            let best = run.best.unwrap().seeds.best.unwrap();
            assert_eq!(best.seed_index, 0);
            assert_eq!(best.current.plaintext, "CB");
            assert_eq!(best.current.score.ranking().units(), 2i128 << 32);
            assert_eq!(best.incomplete, incomplete);
            assert_eq!(best.neighborhood_exhausted, !incomplete);
        }
    }

    #[test]
    fn partial_outer_scheduler_matches_ordered_adapter_composition() {
        // Supplemental composition oracle; the boundary tests above retain the
        // literal A-outer costs, plaintext, scores and independent seed counts.
        let request = scheduler_request(100, false, true, 0);
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: 100,
        };
        let mut expected: Option<PartialOuterOutcome> = None;
        for (index, initial) in request.outer_candidates() {
            let outer = request
                .climb_partial_outer(initial.unwrap(), index, &mut allowance)
                .unwrap();
            assert!(!outer.seeds.budget_stopped);
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
    fn partial_outer_scheduler_distinct_admission_and_zero_cost_completion() {
        let denied = scheduler_request(1, true, true, 0)
            .schedule_partial_outers()
            .unwrap();
        assert_eq!(denied.termination, PartialRunTermination::EvaluationBudget);
        assert_eq!(partial_counts(&denied), (0, 0, 0, 0));
        assert!(denied.best.is_none());
        for (budget, single) in [(2, true), (3, false)] {
            let run = partial_scheduler_request(budget, true, |job| {
                job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
                if single {
                    job["space"]["limit"] = serde_json::json!(1);
                }
            })
            .schedule_partial_outers()
            .unwrap();
            assert_eq!(partial_counts(&run), (1, 1, 1, 2));
            assert_eq!(
                run.termination,
                if single {
                    PartialRunTermination::Completed
                } else {
                    PartialRunTermination::EvaluationBudget
                }
            );
            let best = run.best.unwrap().seeds.best.unwrap();
            assert_eq!(best.current.plaintext, "CA");
            assert_eq!(best.current.score.ranking().units(), 0);
            assert!(!best.incomplete && best.neighborhood_exhausted);
            assert!(!best.final_objective_ascent);
        }
    }

    #[test]
    fn partial_outer_scheduler_literal_later_winner_tie_and_dense_seed() {
        let run = partial_scheduler_request(6, true, |job| {
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
        let ties = partial_scheduler_request(2, false, |job| {
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
        for (selection, plaintext, rank) in [("all", "AC", 1), ("touching", "CB", 2)] {
            let run = partial_scheduler_request(7, true, |job| {
                job["attack"]["seeds"]["selection"] = serde_json::json!(selection);
                if selection == "touching" {
                    job["attack"]["seeds"]["symbols"] = serde_json::json!(["C"]);
                }
            })
            .schedule_partial_outers()
            .unwrap();
            assert_eq!(run.termination, PartialRunTermination::EvaluationBudget);
            assert_eq!(partial_counts(&run), (0, 2, 1, 7));
            let outer = run.best.unwrap();
            assert_eq!(outer.outer_index, 0);
            assert!(outer.seeds.budget_stopped);
            let best = outer.seeds.best.unwrap();
            assert_eq!(best.seed_index, 1); // Dense local, including touching mask.
            assert_eq!(best.current.plaintext, plaintext);
            assert_eq!(best.current.score.ranking().units(), rank << 32);
            assert!(best.incomplete);
            assert!(!best.neighborhood_exhausted && !best.final_objective_ascent);
        }
    }

    #[test]
    fn partial_outer_scheduler_committed_not_provisional_and_owned_fixed_facts() {
        for (budget, board, plaintext, rank) in
            [(3, vec![], "CA", 0), (4, vec![('A', 'C')], "CB", 2)]
        {
            let run = scheduler_request(budget, false, true, 0)
                .schedule_partial_outers()
                .unwrap();
            assert_eq!(run.termination, PartialRunTermination::EvaluationBudget);
            assert_eq!(partial_counts(&run), (0, 1, 0, budget));
            let outer = run.best.unwrap();
            assert_eq!(outer.outer_index, 0);
            let best = outer.seeds.best.unwrap();
            assert_eq!(best.current.board, board);
            assert_eq!(best.current.plaintext, plaintext);
            assert_eq!(best.current.score.ranking().units(), rank << 32);
            assert!(best.incomplete);
            assert!(!best.neighborhood_exhausted);
            assert_eq!(best.final_objective_ascent, budget == 4);
        }
        let request = partial_scheduler_request(1, false, |job| {
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
        let empty = scheduler_request(1, false, false, 3)
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
            let error = scheduler_request(1, false, true, offset)
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
        struct Observer<'a>(&'a std::cell::Cell<u128>, Recorder);
        impl CounterObserver for Observer<'_> {
            fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
                self.0.set(snapshot.outers_completed);
                self.1.observe(snapshot);
            }
        }
        let completed = std::cell::Cell::new(0);
        let mut observer = Observer(&completed, Recorder::default());
        let mut control = AttackControl::default();
        let run = scheduler_request(9, false, false, 0)
            .schedule_direct_outers_controlled(&mut control, &mut observer, || completed.get() == 1)
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
        assert!(!best.climb.cancelled && !best.climb.budget_stopped);
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
        assert_eq!(observer.1 .0.last(), Some(&snapshot));
        assert_eq!(observer.1 .0.first(), Some(&Default::default()));
    }

    fn direct_counts(run: &DirectRunOutcome) -> (u128, u128, u128, u64) {
        (
            run.outer_completed,
            run.climbs_started,
            run.climbs_completed,
            run.evaluations_used,
        )
    }

    fn controlled_run(request: &crate::AttackRequest, stop: usize) -> (DirectRunOutcome, Recorder) {
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        let mut polls = 0;
        let run = request
            .schedule_direct_outers_controlled(&mut control, &mut observer, || {
                polls += 1;
                polls == stop // Subsequent false polls must not clear cancellation.
            })
            .unwrap();
        assert_eq!(observer.0.last(), Some(&control.snapshot()));
        (run, observer)
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
            let run = scheduler_request(1, false, pe, offset).schedule_direct_outers_controlled(
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
    fn controlled_outer_scan_and_reserved_finalization() {
        // One outer-entry poll precedes the existing single-climb safe points.
        for (stop, used, paired) in [
            (3, 1, false),
            (5, 2, false),
            (7, 3, false),
            (9, 4, false),
            (10, 4, true),
        ] {
            let (run, snapshots) = controlled_run(&scheduler_request(100, false, false, 0), stop);
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
                best.climb.cancelled
                    && !best.climb.budget_stopped
                    && !best.climb.neighborhood_exhausted
            );
            assert_eq!(best.climb.final_objective_ascent, paired);
            let final_snapshot = snapshots.0.last().unwrap();
            assert_eq!(
                (
                    final_snapshot.evaluations_admitted,
                    final_snapshot.evaluations_completed
                ),
                (used, used)
            );
        }
        for distinct in [false, true] {
            let (run, _) = controlled_run(&scheduler_request(100, distinct, false, 0), 3);
            assert_eq!(run.evaluations_used, if distinct { 2 } else { 1 });
            assert_eq!(run.best.unwrap().climb.current.unwrap().plaintext, "CA");
        }
    }

    #[test]
    fn controlled_outer_legacy_equivalence_and_prior_counters() {
        for (budget, distinct, offset) in
            [(100, false, 0), (100, true, 1), (9, false, 0), (1, true, 0)]
        {
            let request = scheduler_request(budget, distinct, false, offset);
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
                assert_eq!(best.climb.budget_stopped, expected.climb.budget_stopped);
                assert!(!best.climb.cancelled);
            } else {
                assert!(expected.best.is_none());
            }
            assert_eq!(observer.0[0], before);
            assert_eq!(
                control.snapshot().outers_completed,
                before.outers_completed + run.outer_completed
            );
        }
        let empty = direct_request_with(serde_json::json!([]), false, false, |job| {
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            job["attack"]["evaluation_budget"] = serde_json::json!(1);
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
        let alphabet = ["🦀", "é", "Ω", "中"];
        let json = serde_json::json!({
            "protocol_version": 1, "machine": {"definition": {"kind": "custom", "value": {
                "alphabet": alphabet, "wheels": [{"name": "r", "wiring": alphabet, "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
                "stepping": {"rules": []}
            }}}, "job": {
                "kind": "search", "configuration": {"slots": [{"id": "r", "position": "é", "ring": "Ω"}],
                    "plugboard": [["中", "é"]]}, "text": "🦀🦀", "measures": ["ic"], "passes": ["hill_climb"],
                "space": {"plugboard": {"kind": "attack", "symbols": ["🦀", "Ω"], "max_pairs": 2}},
                "attack": {"kind": "hill_climb", "initial_measure": "ic", "final_measure": "ic",
                    "switch_pairs": 2, "backtrack_pairs": 2, "evaluation_budget": 100, "start": [["Ω", "🦀"]]}
            }
        });
        let request = crate::AttackRequest::parse_json(&json.to_string()).unwrap();
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let outcome = request
            .climb_direct_outer(
                initial,
                u128::MAX,
                &mut EvaluationAllowance {
                    used: 0,
                    limit: 100,
                },
            )
            .unwrap();
        (request, outcome)
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
                DirectRunTermination::EvaluationBudget,
                AttackTermination::EvaluationBudget,
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
                best.climb.budget_stopped = flags & 2 != 0;
                best.climb.final_objective_ascent = flags & 4 != 0;
                best.climb.neighborhood_exhausted = flags & 8 != 0;
                let termination = match expected {
                    AttackTermination::Completed => DirectRunTermination::Completed,
                    AttackTermination::OuterSliceEnd => DirectRunTermination::OuterSliceEnd,
                    AttackTermination::EvaluationBudget => DirectRunTermination::EvaluationBudget,
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
        let request = scheduler_request(100, false, false, 0);
        let mut expected_allowance = EvaluationAllowance {
            used: 0,
            limit: 100,
        };
        let expected = request
            .climb_direct_outer(
                request.outer_candidates().next().unwrap().1.unwrap(),
                0,
                &mut expected_allowance,
            )
            .unwrap();
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: 100,
        };
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
        )
        .unwrap_err();
        assert!(matches!(error.source, DirectRunError::MissingOuter));
        assert_eq!(error.outer_index, None);
        assert_eq!(error.counters.outers_completed, 1);
        assert_eq!(observer.0.last(), Some(&error.counters));
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
        let request = scheduler_request(100, false, false, 0);
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
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
        let mut control = AttackControl::with_counters(snapshot);
        let mut observer = Recorder::default();
        let mut accounting = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut observer,
        };
        let source = accounting.admit(0).unwrap_err();
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
        let request = scheduler_request(100, false, false, 0);
        let mut best = request
            .climb_direct_outer(
                request.outer_candidates().next().unwrap().1.unwrap(),
                0,
                &mut EvaluationAllowance {
                    used: 0,
                    limit: 100,
                },
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
        let request = scheduler_request(100, false, false, 0);
        let mut expected_allowance = EvaluationAllowance {
            used: 0,
            limit: 100,
        };
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 107,
            };
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
            )
            .unwrap_err();
            assert_eq!(error.outer_index, Some(1));
            assert_eq!(error.counters, control.snapshot());
            assert_eq!(observer.0.last(), Some(&error.counters));
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
                expected.climb.cancelled || expected.climb.budget_stopped
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
        let request = scheduler_request(100, false, false, 0);
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 107,
            };
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
            )
            .unwrap_err();
            assert_eq!(error.outer_index, Some(index));
            assert!(error.best.is_none());
            assert_eq!(error.counters, control.snapshot());
            let snapshot = control.snapshot();
            assert_eq!(observer.0.last(), Some(&snapshot));
            assert_eq!(observer.0.first(), Some(&Default::default()));
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
            let error = scheduler_request(100, false, false, 0)
                .schedule_direct_outers_controlled(&mut control, &mut observer, || false)
                .unwrap_err();
            assert!(error.best.is_none());
            assert_eq!(error.counters, control.snapshot());
            assert!(matches!(error.source, DirectRunError::Counter(source) if source == expected));
            assert_eq!(error.outer_index, Some(0));
            assert_eq!(error.evaluations_used, used);
            assert_eq!(observer.0[0], before); // Retained copies never change.
            assert_eq!(observer.0.last(), Some(&control.snapshot()));
        }
    }

    #[test]
    fn direct_outer_scheduler_order_fresh_state_and_final_ranking() {
        let request = scheduler_request(100, false, false, 0);
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: 100,
        };
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
        assert!(!best.climb.budget_stopped);
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
            job["attack"]["evaluation_budget"] = serde_json::json!(3);
        })
        .schedule_direct_outers()
        .unwrap();
        assert_eq!(ties.termination, DirectRunTermination::Completed);
        assert_eq!(ties.best.unwrap().outer_index, 0);
        assert_eq!(ties.evaluations_used, 3);
    }

    #[test]
    fn direct_outer_scheduler_exact_completion_and_denied_next_start() {
        let single = direct_request_with(serde_json::json!([]), false, false, |job| {
            job["attack"]["evaluation_budget"] = serde_json::json!(9);
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
        let next = scheduler_request(9, false, false, 0)
            .schedule_direct_outers()
            .unwrap();
        assert_eq!(next.termination, DirectRunTermination::EvaluationBudget);
        assert_eq!(
            (
                next.outer_completed,
                next.climbs_started,
                next.climbs_completed,
                next.evaluations_used
            ),
            (1, 1, 1, 9)
        );
        assert!(!next.best.unwrap().climb.budget_stopped);
        let denied = scheduler_request(1, true, false, 0)
            .schedule_direct_outers()
            .unwrap();
        assert_eq!((denied.climbs_started, denied.evaluations_used), (0, 0));
        assert!(denied.best.is_none());
        let reserved = direct_request_with(serde_json::json!([]), true, false, |job| {
            job["space"]["plugboard"]["max_pairs"] = serde_json::json!(0);
            job["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("position");
            job["space"]["slots"] = serde_json::json!([{"id":"r","positions":["A","B","C"]}]);
            job["attack"]["evaluation_budget"] = serde_json::json!(3);
        })
        .schedule_direct_outers()
        .unwrap();
        assert_eq!(reserved.termination, DirectRunTermination::EvaluationBudget);
        assert_eq!(
            (
                reserved.outer_completed,
                reserved.climbs_started,
                reserved.evaluations_used
            ),
            (1, 1, 2)
        );
        assert!(!reserved.best.unwrap().climb.budget_stopped);
    }

    #[test]
    fn direct_outer_scheduler_committed_not_provisional_interruption() {
        for (limit, board, used) in [(3, vec![], 3), (4, vec![('A', 'C')], 4)] {
            let result = scheduler_request(limit, false, false, 0)
                .schedule_direct_outers()
                .unwrap();
            assert_eq!(result.termination, DirectRunTermination::EvaluationBudget);
            assert_eq!(
                (
                    result.outer_completed,
                    result.climbs_started,
                    result.climbs_completed
                ),
                (0, 1, 0)
            );
            assert_eq!(result.evaluations_used, used);
            let best = result.best.unwrap();
            assert_eq!(best.climb.current.unwrap().board, board);
            assert!(best.climb.budget_stopped);
            assert!(!best.climb.neighborhood_exhausted);
        }
        let losing = scheduler_request(10, false, false, 0)
            .schedule_direct_outers()
            .unwrap();
        assert_eq!(
            (
                losing.outer_completed,
                losing.climbs_started,
                losing.climbs_completed
            ),
            (1, 2, 1)
        );
        assert_eq!(losing.termination, DirectRunTermination::EvaluationBudget);
        assert_eq!(losing.best.as_ref().unwrap().outer_index, 0);
        let best = losing.best.unwrap();
        assert!(!best.climb.budget_stopped);
        assert!(best.climb.neighborhood_exhausted);
        assert!(best.climb.final_objective_ascent);
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
            let mut allowance = EvaluationAllowance {
                used: 0,
                limit: cost,
            };
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
            assert!(!result.climb.budget_stopped);
            assert!(result.climb.neighborhood_exhausted);
            assert!(result.climb.final_objective_ascent);
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let denied = request
                .climb_direct_outer(initial, index, &mut allowance)
                .unwrap();
            assert!(denied.climb.current.is_none());
            assert!(denied.climb.budget_stopped);
            assert!(!denied.climb.neighborhood_exhausted);
            assert_eq!(allowance.used, cost);
        }
    }

    #[test]
    fn request_bound_direct_reservation_and_interrupted_winners() {
        for (distinct, limit, board, plaintext, units, used) in [
            (true, 1, None, "", 0, 0),
            (true, 2, Some(vec![]), "CA", 0, 2),
            (false, 3, Some(vec![]), "CA", 0, 3),
            (false, 4, Some(vec![('A', 'C')]), "CB", 2 * (1i128 << 32), 4),
        ] {
            let request = direct_request(serde_json::json!([]), distinct, false);
            let initial = request.outer_candidates().next().unwrap().1.unwrap();
            let mut allowance = EvaluationAllowance { used: 0, limit };
            let result = request
                .climb_direct_outer(initial, 17, &mut allowance)
                .unwrap();
            assert_eq!(allowance.used, used);
            assert!(result.climb.budget_stopped);
            assert!(!result.climb.neighborhood_exhausted);
            match (board, result.climb.current) {
                (Some(board), Some(current)) => {
                    assert_eq!(current.board, board);
                    assert_eq!(current.plaintext, plaintext);
                    assert_eq!(current.score.ranking().units(), units);
                }
                (None, None) => assert!(!result.climb.final_objective_ascent),
                other => panic!("unexpected committed outcome: {other:?}"),
            }
        }
    }

    #[test]
    fn request_bound_direct_rejects_promoted_partial_exhaustion() {
        let request = direct_request(serde_json::json!([]), false, true);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
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
                    "evaluation_budget":1,"seeds":seeds})
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
        limit: u64,
        mut requested: impl FnMut(usize) -> bool,
    ) -> (
        Result<ControlledSeedOutcome, ControlledSeedError>,
        u64,
        Recorder,
        usize,
    ) {
        let mut allowance = EvaluationAllowance { used: 7, limit };
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
        assert_eq!(observer.0.first(), Some(&counters));
        assert_eq!(observer.0.last(), Some(&control.snapshot()));
        assert_eq!(
            control.snapshot().outers_completed,
            counters.outers_completed
        );
        (result, allowance.used, observer, polls)
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
            for cancel in [false, true] {
                // First seed consumes five; second start plus reserved rescore consumes two.
                let (result, used, _, _) =
                    controlled_seed_probe(&context, Default::default(), 14, |poll| {
                        cancel && poll == 10
                    });
                let result = result.unwrap();
                assert_eq!(used, 14);
                assert_eq!(result.cancelled, cancel);
                assert_eq!(result.seeds.budget_stopped, !cancel);
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
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: 100,
        };
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 100,
            };
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
            assert_eq!(observer.0.last(), Some(&snapshot));
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
            assert_eq!(
                best.incomplete,
                expected.cancelled || expected.budget_stopped
            );
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
            "final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,"evaluation_budget":100,
            "seeds":{"kind":"empty_single","selection":"all"}}}});
        let request = crate::AttackRequest::parse_json(&value.to_string()).unwrap();
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let before = initial.clone();
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: 100,
        };
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
        assert_eq!(observer.0.last(), Some(&control.snapshot()));
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
                controlled_seed_probe(&context, counters, 100, |_| false);
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
            assert_eq!(recorder.0.last(), Some(&expected));
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
        let (result, used, recorder, _) = controlled_seed_probe(&context, counters, 100, |_| false);
        let result = result.unwrap().seeds;
        assert_eq!(
            (result.climbs_started, result.climbs_completed, used),
            (4, 4, 39)
        );
        let after = recorder.0.last().unwrap();
        assert_eq!(
            (after.evaluations_admitted, after.evaluations_completed),
            (43, 42)
        );
        assert_eq!((after.climbs_started, after.climbs_completed), (9, 8));
        let mut control = AttackControl::with_counters(counters);
        assert!(control.poll_cancellation(true));
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
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
        for limit in [9, 100] {
            for stop in [2, 3] {
                let (result, used, recorder, polls) =
                    controlled_seed_probe(&context, Default::default(), limit, |poll| poll == stop);
                let result = result.unwrap();
                assert!(!result.cancelled && !result.seeds.budget_stopped);
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
                let after = recorder.0.last().unwrap();
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
        for limit in [39, 100] {
            for stop in [66, 67] {
                let (result, used, recorder, polls) =
                    controlled_seed_probe(&context, Default::default(), limit, |poll| poll == stop);
                let result = result.unwrap();
                assert!(!result.cancelled && !result.seeds.budget_stopped);
                assert_eq!((used, polls), (39, 66));
                assert_eq!(
                    (result.seeds.climbs_started, result.seeds.climbs_completed),
                    (4, 4)
                );
                let best = result.seeds.best.unwrap();
                assert_eq!(best.seed_index, 0);
                assert!(!best.incomplete && best.neighborhood_exhausted);
                let after = recorder.0.last().unwrap();
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 100,
            };
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
            assert_eq!(observer.0.last(), Some(&control.snapshot()));
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 100,
            };
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
            assert_eq!(observer.0.last(), Some(&control.snapshot()));
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
        for (limit, cancel) in [(7, true), (7, false), (8, true), (16, false), (100, false)] {
            let mut allowance = EvaluationAllowance { used: 7, limit };
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
            assert_eq!(observer.0.last(), Some(&control.snapshot()));
            assert_eq!(control.snapshot().outers_completed, 0);
            if cancel {
                assert!(outcome.seeds.best.is_none());
                assert!(!outcome.seeds.budget_stopped);
                assert_eq!(allowance.used, 7);
            } else {
                let legacy = context
                    .climb_seeds(
                        &crate::AttackSeedPolicy::All,
                        0,
                        &mut EvaluationAllowance { used: 7, limit },
                    )
                    .unwrap();
                assert_eq!(outcome.seeds.evaluations_used, legacy.evaluations_used);
                assert_eq!(outcome.seeds.climbs_started, legacy.climbs_started);
                assert_eq!(outcome.seeds.climbs_completed, legacy.climbs_completed);
                assert_eq!(outcome.seeds.budget_stopped, legacy.budget_stopped);
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
                controlled_seed_probe(&context, Default::default(), 100, |_| false);
            let mapped =
                ControlledPartialError::from_seed(99, initial.clone(), result.unwrap_err());
            assert_eq!(mapped.outer_index, 99);
            assert_eq!(mapped.seed_index, Some(0));
            assert_eq!(used, 8);
            assert_eq!(
                mapped.source,
                ControlledPartialSource::Climb(expected.into())
            );
            let snapshot = recorder.0.last().unwrap();
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
            controlled_seed_probe(&context, Default::default(), 100, |_| true);
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
        assert_eq!(recorder.0.last().unwrap().evaluations_admitted, 0);
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
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        // Helper-qualified fault: this invalid trial reaches the evaluator after admission.
        let source = ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut observer,
        }
        .evaluate(&evaluator, &[('A', 'Z')], 0)
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
                "switch_pairs":0,"backtrack_pairs":0,"evaluation_budget":100,
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
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
        let mut control = AttackControl::default();
        struct Observer<'a>(&'a std::cell::Cell<u128>, Recorder);
        impl CounterObserver for Observer<'_> {
            fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
                self.0.set(snapshot.climbs_completed);
                self.1.observe(snapshot);
            }
        }
        let completed = std::cell::Cell::new(0);
        let mut observer = Observer(&completed, Recorder::default());
        let result = request
            .climb_partial_outer_controlled(
                equivalent.clone(),
                99,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                // The next seed's entry poll follows notification of the prior completion.
                &mut || completed.get() == 1,
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
        assert_eq!(observer.1 .0.last(), Some(&control.snapshot()));
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
                let mut allowance = EvaluationAllowance {
                    used: 7,
                    limit: 100,
                };
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
                    .climb_partial_outer(
                        initial,
                        88,
                        &mut EvaluationAllowance {
                            used: 7,
                            limit: 100,
                        },
                    )
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 100,
            };
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
            assert_eq!(observer.0.last(), Some(&control.snapshot()));
        }
    }

    #[test]
    fn controlled_partial_adapter_cancel_preserves_owner_and_index() {
        let request = direct_request(serde_json::json!([]), false, true);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let retained = initial.clone();
        let index = u128::from(u64::MAX) + 7;
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
        let mut control = AttackControl::default();
        struct Observer<'a>(&'a std::cell::Cell<u128>, Recorder);
        impl CounterObserver for Observer<'_> {
            fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
                self.0.set(snapshot.climbs_completed);
                self.1.observe(snapshot);
            }
        }
        let completed = std::cell::Cell::new(0);
        let mut observer = Observer(&completed, Recorder::default());
        let result = request
            .climb_partial_outer_controlled(
                initial,
                index,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || completed.get() == 1,
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
        assert_eq!(observer.1 .0.last(), Some(&control.snapshot()));
    }

    #[test]
    fn controlled_seeds_cancel_between_seeds() {
        struct Observer<'a>(&'a std::cell::Cell<u128>, Recorder);
        impl CounterObserver for Observer<'_> {
            fn observe(&mut self, snapshot: crate::attack_control::CounterSnapshot) {
                self.0.set(snapshot.climbs_completed);
                self.1.observe(snapshot);
            }
        }
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
        let completed = std::cell::Cell::new(0);
        let mut observer = Observer(&completed, Recorder::default());
        let mut control = AttackControl::default();
        let mut allowance = EvaluationAllowance {
            used: 7,
            limit: 100,
        };
        let result = context
            .climb_seeds_controlled(
                &crate::AttackSeedPolicy::All,
                0,
                &mut ObservedAccounting {
                    allowance: &mut allowance,
                    control: &mut control,
                    observer: &mut observer,
                },
                &mut || completed.get() == 1,
            )
            .unwrap();
        assert_eq!(result.seeds.evaluations_used, 16);
        assert!(result.cancelled);
        assert!(!result.seeds.budget_stopped);
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
        assert_eq!(observer.1 .0.last(), Some(&snapshot));
    }

    #[test]
    fn ordered_climbs_share_budget_and_reset_every_seed() {
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
        for (
            different,
            limit,
            used,
            started,
            completed,
            stopped,
            best_index,
            board,
            text,
            weight,
        ) in [
            (false, 0, 0, 0, 0, true, None, vec![], "", 0),
            (false, 8, 8, 1, 0, true, Some(0), vec![('A', 'C')], "CB", 2),
            (false, 9, 9, 1, 1, true, Some(0), vec![('A', 'C')], "CB", 2),
            (
                false,
                10,
                10,
                2,
                1,
                true,
                Some(0),
                vec![('A', 'C')],
                "CB",
                2,
            ),
            (
                false,
                20,
                20,
                2,
                2,
                true,
                Some(0),
                vec![('A', 'C')],
                "CB",
                2,
            ),
            (
                false,
                32,
                32,
                4,
                4,
                false,
                Some(0),
                vec![('A', 'C')],
                "CB",
                2,
            ),
            (
                false,
                100,
                32,
                4,
                4,
                false,
                Some(0),
                vec![('A', 'C')],
                "CB",
                2,
            ),
            (true, 12, 12, 1, 0, true, Some(0), vec![], "CA", 4),
            (true, 13, 13, 1, 1, true, Some(0), vec![], "CA", 4),
            (true, 14, 14, 2, 1, true, Some(0), vec![], "CA", 4),
            (true, 40, 40, 4, 4, false, Some(0), vec![], "CA", 4),
            (true, 100, 40, 4, 4, false, Some(0), vec![], "CA", 4),
        ] {
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
            let mut allowance = EvaluationAllowance { used: 0, limit };
            let result = context
                .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                .unwrap();
            assert_eq!(result.evaluations_used, used);
            assert_eq!(allowance.used, used);
            assert_eq!(
                (result.climbs_started, result.climbs_completed),
                (started, completed)
            );
            assert_eq!(result.budget_stopped, stopped);
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
    fn ordered_interrupted_committed_winner_and_reservation_denial() {
        let (initial, domain) = fixture();
        let first = crate::BoundResource::Trie(
            crate::TrieModel::new(
                initial.topology().alphabet().clone(),
                vec![
                    (vec!['C', 'A'], 4),
                    (vec!['A', 'C'], 1),
                    (vec!['C', 'B'], 2),
                    (vec!['B', 'A'], 2),
                ],
            )
            .unwrap(),
        );
        // Initial empty CA=4 exhausts in three trials: 1+3+final=5.
        // AB starts at AC=1, but its interrupted scan cannot commit a winner.
        // Its reserved final AC score is independently either 3 or 0.
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
            for limit in [5, 6, 7, 8] {
                let mut allowance = EvaluationAllowance { used: 0, limit };
                let result = context
                    .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                    .unwrap();
                let admitted = limit >= 7;
                assert_eq!(result.evaluations_used, if admitted { limit } else { 5 });
                assert_eq!(
                    (result.climbs_started, result.climbs_completed),
                    (if admitted { 2 } else { 1 }, 1)
                );
                assert!(result.budget_stopped);
                let best = result.best.unwrap();
                let later_wins = admitted && weight == 3;
                assert_eq!(best.seed_index, u128::from(later_wins));
                assert_eq!(best.incomplete, later_wins);
                assert_eq!(best.neighborhood_exhausted, !later_wins);
                assert!(!best.final_objective_ascent);
                assert_eq!(
                    best.current.board,
                    if later_wins { vec![('A', 'B')] } else { vec![] }
                );
                assert_eq!(best.current.plaintext, if later_wins { "AC" } else { "CA" });
                assert_eq!(
                    best.current.score.ranking().units(),
                    if later_wins { 3 << 32 } else { 1 << 32 }
                );
            }
        }
    }

    #[test]
    fn ordered_sole_seed_finishes_at_exact_budget_and_reports_cumulative_usage() {
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
            let mut allowance = EvaluationAllowance {
                used: 7,
                limit: 7 + cost,
            };
            let result = context
                .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                .unwrap();
            assert_eq!(result.evaluations_used, 7 + cost);
            assert_eq!((result.climbs_started, result.climbs_completed), (1, 1));
            assert!(!result.budget_stopped);
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
            let mut allowance = EvaluationAllowance {
                used,
                limit: u64::MAX,
            };
            let result = context
                .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                .unwrap();
            let count: u128 = u128::from(used != u64::MAX);
            assert_eq!(
                (result.climbs_started, result.climbs_completed),
                (count, count)
            );
            assert_eq!(result.evaluations_used, u64::MAX);
            assert_eq!(result.budget_stopped, count == 0);
            assert_eq!(
                result.best.map(|best| best.seed_index),
                if count == 0 { None } else { Some(0u128) }
            );
        }
    }

    #[test]
    fn ordered_runtime_errors_are_not_budget_outcomes() {
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
            let mut allowance = EvaluationAllowance {
                used: 0,
                limit: 100,
            };
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
        for (threshold, limit, board, text, weight, used, ascent, exhausted) in [
            (1, 100, vec![], "CA", 4, 13, true, true),
            (1, 5, vec![('A', 'C')], "CB", 3, 5, false, false),
            (1, 10, vec![], "CA", 4, 10, true, false),
            (1, 4, vec![], "CA", 4, 4, false, false),
            (2, 100, vec![('A', 'C')], "CB", 3, 10, false, true),
        ] {
            let context = BoundClimbScoring::new(
                &initial,
                &domain,
                "AA",
                (MeasureId::Trie, Some(&first)),
                (MeasureId::Trie, Some(&last)),
                threshold,
            );
            let mut allowance = EvaluationAllowance { used: 0, limit };
            let result = context.climb(vec![], 0, &mut allowance).unwrap();
            let current = result.current.unwrap();
            assert_eq!(current.board, board);
            assert_eq!(current.plaintext, text);
            assert_eq!(current.score.ranking().units(), weight << 32);
            assert_eq!(allowance.used, used);
            assert_eq!(result.final_objective_ascent, ascent);
            assert_eq!(result.neighborhood_exhausted, exhausted);
            assert_eq!(result.budget_stopped, !exhausted);
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
        for (limit, used, board, weight, ascent, exhausted) in [
            (9, 9, vec![('A', 'C')], 2, true, true),
            (4, 4, vec![('A', 'C')], 2, true, false),
            (3, 3, vec![], 0, false, false),
        ] {
            let mut allowance = EvaluationAllowance { used: 0, limit };
            let result = context.climb(vec![], 0, &mut allowance).unwrap();
            let current = result.current.unwrap();
            assert_eq!(current.board, board);
            assert_eq!(
                current.plaintext,
                if board.is_empty() { "CA" } else { "CB" }
            );
            assert_eq!(current.score.ranking().units(), weight << 32);
            assert_eq!(allowance.used, used);
            assert_eq!(result.final_objective_ascent, ascent);
            assert_eq!(result.neighborhood_exhausted, exhausted);
            assert_eq!(result.budget_stopped, !exhausted);
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
            let mut allowance = EvaluationAllowance { used: 0, limit };
            let result = context.climb(vec![], 0, &mut allowance).unwrap();
            assert_eq!(result.current.unwrap().board, board);
            assert_eq!(result.final_objective_ascent, ascent);
            assert_eq!(result.neighborhood_exhausted, exhausted);
            assert_eq!(result.budget_stopped, !exhausted);
            assert_eq!(allowance.used, limit);
        }
    }

    #[test]
    fn driver_reservation_denial_and_zero_cost_completion() {
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
        for limit in [0, 1] {
            let mut allowance = EvaluationAllowance { used: 0, limit };
            let result = context.climb(vec![], 0, &mut allowance).unwrap();
            assert!(result.current.is_none());
            assert!(result.budget_stopped);
            assert!(!result.final_objective_ascent);
            assert!(!result.neighborhood_exhausted);
            assert_eq!(allowance.used, 0);
        }
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
            let mut allowance = EvaluationAllowance { used: 0, limit };
            let result = context.climb(vec![], 0, &mut allowance).unwrap();
            let current = result.current.unwrap();
            assert!(current.board.is_empty());
            assert_eq!(current.plaintext, "CA");
            assert_eq!(current.score.ranking().units(), 0);
            assert_eq!(allowance.used, limit);
            assert!(!result.budget_stopped);
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 0 };
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
            let mut allowance = EvaluationAllowance { used: 0, limit: 1 };
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
            let mut allowance = EvaluationAllowance {
                used: 0,
                limit: 100,
            };
            assert_eq!(
                context.climb(vec![], 0, &mut allowance).err(),
                Some(TrialEvaluationError::MissingResource(MeasureId::Trie))
            );
            assert_eq!(allowance.used, used);
        }
    }

    #[test]
    fn lifecycle_reserves_then_finalizes_the_literal_current_board() {
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
        let mut allowance = EvaluationAllowance { used: 4, limit: 5 };
        assert!(context.start(vec![], &mut allowance).unwrap().is_none());
        assert_eq!(allowance.used, 4);
        allowance.limit = 6;
        let state = context.start(vec![], &mut allowance).unwrap().unwrap();
        assert!(!state.final_phase);
        assert_eq!(state.reserve(), 1);
        assert_eq!(state.current.plaintext, "CA");
        assert_eq!(state.current.score.ranking().units(), 0);
        let final_board = state.finalize(&mut allowance).unwrap().unwrap();
        assert_eq!(final_board.board, vec![]);
        assert_eq!(final_board.plaintext, "CA");
        assert_eq!(final_board.score.ranking().units(), 0);
        assert_eq!(allowance.used, 6);

        let mut allowance = EvaluationAllowance { used: 0, limit: 3 };
        let state = context.start(vec![], &mut allowance).unwrap().unwrap();
        assert!(allowance.admit(state.reserve()));
        let (plaintext, score) = context.initial_evaluator.evaluate(&[('A', 'C')]).unwrap();
        let trial = ScoredBoard {
            board: vec![('A', 'C')],
            plaintext,
            score,
        };
        // Transition mechanics only; this IC fixture does not claim strict selection.
        let state = state.commit_trial(trial, &mut allowance).unwrap().unwrap();
        assert!(!state.final_phase);
        assert_eq!(state.reserve(), 1);
        let result = state.finalize(&mut allowance).unwrap().unwrap();
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
            let mut allowance = EvaluationAllowance { used: 0, limit: 2 };
            let state = context
                .start(board.clone(), &mut allowance)
                .unwrap()
                .unwrap();
            assert_eq!(state.final_phase, final_phase);
            assert_eq!(state.reserve(), u64::from(!final_phase));
            assert_eq!(state.current.board, board);
            assert_eq!(state.current.plaintext, "AA");
            assert_eq!(
                state.current.score.ranking().units(),
                if final_phase { 0 } else { 6 << 32 }
            );
            state.finalize(&mut allowance).unwrap().unwrap();
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
            let mut allowance = EvaluationAllowance {
                used: 0,
                limit: cost,
            };
            let result = context
                .climb_seeds(&crate::AttackSeedPolicy::All, 0, &mut allowance)
                .unwrap();
            assert!(!result.budget_stopped);
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
            let mut allowance = EvaluationAllowance { used: 0, limit: 2 };
            let state = context
                .start(vec![('A', 'C')], &mut allowance)
                .unwrap()
                .unwrap();
            assert_eq!(state.reserve(), expected - 1);
            let result = state.finalize(&mut allowance).unwrap().unwrap();
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 2 };
        let state = context.start(vec![], &mut allowance).unwrap().unwrap();
        assert_eq!(state.reserve(), 0);
        assert!(allowance.admit(state.reserve()));
        let (plaintext, score) = context.initial_evaluator.evaluate(&[('A', 'C')]).unwrap();
        let trial = ScoredBoard {
            board: vec![('A', 'C')],
            plaintext,
            score,
        };
        // Exercise transition mechanics only: strict winner selection is the caller's duty.
        let state = state.commit_trial(trial, &mut allowance).unwrap().unwrap();
        assert!(state.final_phase);
        assert_eq!(state.reserve(), 0);
        state.finalize(&mut allowance).unwrap().unwrap();
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
        let mut allowance = EvaluationAllowance { used: 3, limit: 7 };
        let state = context.start(vec![], &mut allowance).unwrap().unwrap();
        assert_eq!(state.reserve(), 1);
        // AC is the initial objective's complete-neighborhood winner (existing fixture).
        assert!(allowance.admit(state.reserve()));
        let (plaintext, score) = context.initial_evaluator.evaluate(&[('A', 'C')]).unwrap();
        assert_eq!(plaintext, "CB");
        assert_eq!(score.ranking().units(), 2 << 32);
        let trial = ScoredBoard {
            board: vec![('A', 'C')],
            plaintext,
            score,
        };
        let state = state.commit_trial(trial, &mut allowance).unwrap().unwrap();
        assert!(state.final_phase);
        assert_eq!(state.current.board, vec![('A', 'C')]);
        assert_eq!(state.current.plaintext, "CB");
        assert_eq!(state.current.score.ranking().units(), 3 << 32);
        assert_eq!(state.reserve(), 0);
        assert_eq!(allowance.used, 6);
        assert!(allowance.admit(state.reserve()));
        let (plaintext, score) = context.final_evaluator.evaluate(&[]).unwrap();
        // Empty board is the final objective's strict complete-neighborhood winner.
        let trial = ScoredBoard {
            board: vec![],
            plaintext,
            score,
        };
        let state = state.commit_trial(trial, &mut allowance).unwrap().unwrap();
        assert!(state.final_phase);
        assert_eq!(state.reserve(), 0);
        let result = state.finalize(&mut allowance).unwrap().unwrap();
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 0 };
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
            allowance.limit = allowance.used + 1;
            let before = allowance.used;
            assert_eq!(context.start(vec![], &mut allowance).err(), Some(expected));
            assert_eq!(allowance.used, before + 1);
        }
    }

    #[test]
    fn final_scoring_errors_consume_reserve_without_returning_state() {
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
            let mut allowance = EvaluationAllowance { used: 0, limit: 3 };
            let state = context.start(vec![], &mut allowance).unwrap().unwrap();
            let error = if threshold == 1 {
                assert!(allowance.admit(state.reserve()));
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 3 };
        let ranking = evaluator.evaluate(&[]).unwrap().1.ranking();
        let result = selection.scan(&[], ranking, &mut allowance, 0).unwrap();
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 3 };
        assert!(matches!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance, 0),
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
            let mut allowance = EvaluationAllowance { used: 0, limit: 3 };
            assert_eq!(
                selection.scan(&[], FixedScore::from_units(weight << 32), &mut allowance, 0),
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 5 };
        let score = evaluator.evaluate(&current).unwrap().1;
        assert_eq!(
            selection.scan(&current, score.ranking(), &mut allowance, 0),
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
        for limit in [1, 2] {
            let mut allowance = EvaluationAllowance { used: 0, limit };
            assert_eq!(
                selection.scan(&current, FixedScore::from_units(0), &mut allowance, 0),
                Ok(ScanOutcome::Interrupted)
            );
            assert_eq!(allowance.used, limit);
            assert!(current.is_empty());
        }
    }

    #[test]
    fn shared_allowance_retains_reserve_and_accepts_exact_boundaries() {
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
        let mut allowance = EvaluationAllowance { used: 1, limit: 8 };
        for expected_used in [4, 7] {
            assert!(matches!(
                selection.scan(&[], FixedScore::from_units(0), &mut allowance, 1),
                Ok(ScanOutcome::Complete(Some(_)))
            ));
            assert_eq!(allowance.used, expected_used);
        }
        assert_eq!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance, 1),
            Ok(ScanOutcome::Interrupted)
        );
        assert_eq!(allowance.used, 7);
        assert_eq!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance, 0),
            Ok(ScanOutcome::Interrupted)
        );
        assert_eq!(allowance.used, 8);
        assert!(!allowance.admit(0));
        let mut maximum = EvaluationAllowance {
            used: u64::MAX - 1,
            limit: u64::MAX,
        };
        assert!(!maximum.admit(1));
        assert!(maximum.admit(0));
        assert!(!maximum.admit(0));
        assert!(!maximum.admit(u64::MAX));
    }

    #[test]
    fn exhausted_allowance_still_completes_empty_legal_neighborhood() {
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 0 };
        assert_eq!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance, 1),
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
        let mut allowance = EvaluationAllowance { used: 0, limit: 3 };
        assert_eq!(
            selection.scan(&[], FixedScore::from_units(0), &mut allowance, 0),
            Err(TrialEvaluationError::MissingResource(MeasureId::Trie))
        );
        assert_eq!(allowance.used, 1);
        assert!(matches!(
            selection.scan(&[('A', 'A')], FixedScore::from_units(0), &mut allowance, 0),
            Err(TrialEvaluationError::Board(_))
        ));
        assert_eq!(allowance.used, 1);
    }
}
