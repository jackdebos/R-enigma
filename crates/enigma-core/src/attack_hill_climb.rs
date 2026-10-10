//! Private complete-neighborhood strict ascent with bound scoring and shared accounting.

use crate::attack_control::{AttackControl, CounterObserver, CounterOverflow};
use crate::attack_evaluator::{validated_trial_board, TrialEvaluationError, TrialEvaluator};
use crate::attack_neighborhood::NeighborhoodCursor;
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
    /// Cumulative caller allowance usage, including earlier work.
    pub(crate) evaluations_used: u64,
    pub(crate) climb: ClimbOutcome,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectClimbError {
    UnsupportedPass,
    MissingStart,
    Evaluation(TrialEvaluationError),
}

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

/// Single resolved outer only; seed completion is independent of winner flags.
#[derive(Debug)]
pub(crate) struct PartialOuterOutcome {
    pub(crate) initial: ResolvedConfiguration,
    pub(crate) outer_index: u128,
    pub(crate) seeds: SeedRunOutcome,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PartialClimbError {
    UnsupportedPass,
    Evaluation(TrialEvaluationError),
}

#[derive(Debug)]
pub(crate) struct IndexedPartialClimbError {
    pub(crate) outer_index: u128,
    pub(crate) evaluations_used: u64,
    pub(crate) source: PartialClimbError,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PartialRunTermination {
    OuterSliceEnd,
    Completed,
    EvaluationBudget,
}

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

#[derive(Debug)]
pub(crate) enum PartialRunError {
    Resolution(Vec<crate::SearchDiagnostic>),
    Climb(PartialClimbError),
}

#[derive(Debug)]
pub(crate) struct IndexedPartialRunError {
    /// None only for pass rejection before enumeration or evaluation.
    pub(crate) outer_index: Option<u128>,
    pub(crate) evaluations_used: u64,
    pub(crate) source: PartialRunError,
}

impl crate::AttackRequest {
    /// Same-owner projection supplies absolute indices and fresh independent seeds.
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
    ) -> Result<DirectRunOutcome, IndexedDirectRunError> {
        control.notify(observer);
        let mut allowance = EvaluationAllowance {
            used: 0,
            limit: self.settings().evaluation_budget(),
        };
        let result = if self.settings().kind() != crate::AttackKind::HillClimb {
            Err(IndexedDirectRunError {
                outer_index: None,
                evaluations_used: 0,
                source: DirectRunError::Climb(DirectClimbError::UnsupportedPass),
            })
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
                        evaluations_used: accounting.allowance.used,
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
            evaluations_used: allowance.used,
            climb,
        })
    }
}

/// Known cardinality establishes exhaustion without resolving a speculative next outer.
/// The adapter seam also permits deterministic indexed resolution/scoring fault tests.
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
) -> Result<DirectRunOutcome, IndexedDirectRunError> {
    accounting.control.notify(accounting.observer);
    let run = (|| {
        let before = accounting.control.snapshot();
        let mut result = DirectRunOutcome {
            termination: DirectRunTermination::OuterSliceEnd,
            outer_completed: 0,
            climbs_started: 0,
            climbs_completed: 0,
            evaluations_used: accounting.allowance.used,
            best: None,
        };
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
        Ok(result)
    })();
    accounting.control.notify(accounting.observer);
    run
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

impl<'a> BoundClimbScoring<'a> {
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

    fn climb(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        allowance: &mut EvaluationAllowance,
    ) -> Result<ClimbOutcome, TrialEvaluationError> {
        self.climb_accounted(board, backtrack_pairs, allowance)
    }

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
                        evaluations_used: accounting.allowance.used,
                        climb,
                    })
                },
            )
            .unwrap_err();
            assert_eq!(error.outer_index, Some(index));
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
            costs.push(outcome.evaluations_used);
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
            assert_eq!(result.evaluations_used, cost);
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
            assert_eq!(denied.evaluations_used, cost);
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
            assert_eq!(result.evaluations_used, used);
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
