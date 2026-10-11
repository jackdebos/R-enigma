//! Owned attack projections; execution and public error envelopes remain deferred.

use crate::attack_control::CounterSnapshot;
use crate::{MeasureId, MeasuredScore, TransformConfiguration};

/// Five factual whole-run counters, independent of charged allowance usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttackProgress(pub(crate) CounterSnapshot);

impl AttackProgress {
    /// Evaluations admitted after allowance charging.
    pub fn evaluations_admitted(&self) -> u64 {
        self.0.evaluations_admitted
    }
    /// Evaluations whose decryption and scoring succeeded.
    pub fn evaluations_completed(&self) -> u64 {
        self.0.evaluations_completed
    }
    /// Climbs whose initial evaluation succeeded.
    pub fn climbs_started(&self) -> u128 {
        self.0.climbs_started
    }
    /// Climbs that exhausted their neighborhood and finalized successfully.
    pub fn climbs_completed(&self) -> u128 {
        self.0.climbs_completed
    }
    /// Outers whose climbs all completed.
    pub fn outers_completed(&self) -> u128 {
        self.0.outers_completed
    }
}

/// Whole-run stop reason, independent of winning-climb flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackTermination {
    /// The nonempty requested slice completed.
    Completed,
    /// The requested outer slice was empty.
    OuterSliceEnd,
    /// Allowance prevented remaining work.
    EvaluationBudget,
    /// Cooperative cancellation stopped remaining work.
    Cancelled,
}

/// Owned final-scored committed winner, never a provisional neighborhood trial.
#[derive(Debug)]
pub struct AttackBest {
    pub(crate) configuration: TransformConfiguration,
    pub(crate) mutable_plugboard: Vec<(char, char)>,
    pub(crate) plaintext: String,
    pub(crate) score: MeasuredScore,
    pub(crate) measure: MeasureId,
    pub(crate) outer_index: u128,
    pub(crate) start_index: u128,
    pub(crate) incomplete: bool,
    pub(crate) final_objective_ascent: bool,
    pub(crate) neighborhood_exhausted: bool,
}

impl AttackBest {
    /// Initial slot key and complete winning board, in topology/alphabet order.
    pub fn configuration(&self) -> &TransformConfiguration {
        &self.configuration
    }
    /// Canonical winning mutable pairs, excluding immutable fixed knowledge.
    pub fn mutable_plugboard(&self) -> &[(char, char)] {
        &self.mutable_plugboard
    }
    /// Plaintext from the committed board's final evaluation.
    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }
    /// Final measured value and higher-is-better ranking, without a new wrapper.
    pub fn score(&self) -> MeasuredScore {
        self.score
    }
    /// Owner-selected final objective identifier.
    pub fn measure(&self) -> MeasureId {
        self.measure
    }
    /// Absolute unsliced outer index.
    pub fn outer_index(&self) -> u128 {
        self.outer_index
    }
    /// Direct start index, or seed index when that projection is supported.
    pub fn start_index(&self) -> u128 {
        self.start_index
    }
    /// Whether this winning climb was cancelled or budget-interrupted.
    pub fn incomplete(&self) -> bool {
        self.incomplete
    }
    /// Whether final-objective ascent occurred, not merely final scoring.
    pub fn final_objective_ascent(&self) -> bool {
        self.final_objective_ascent
    }
    /// Whether this winning climb exhausted its legal neighborhood.
    pub fn neighborhood_exhausted(&self) -> bool {
        self.neighborhood_exhausted
    }
}

/// Owned run projection with optional winner and independent factual accounting.
///
/// Raw scheduler modules and methods remain inaccessible:
/// ```compile_fail
/// use enigma_core::attack_hill_climb::DirectRunOutcome;
/// ```
/// ```compile_fail
/// fn raw_run(request: &enigma_core::AttackRequest) {
///     request.schedule_direct_outers();
/// }
/// ```
#[derive(Debug)]
pub struct AttackResult {
    pub(crate) termination: AttackTermination,
    pub(crate) counters: AttackProgress,
    pub(crate) evaluations_used: u64,
    pub(crate) best: Option<AttackBest>,
}

impl AttackResult {
    /// Whole-run stop reason.
    pub fn termination(&self) -> AttackTermination {
        self.termination
    }
    /// Final factual counter snapshot.
    pub fn counters(&self) -> AttackProgress {
        self.counters
    }
    /// Charged allowance, which can exceed admitted count on counter overflow.
    pub fn evaluations_used(&self) -> u64 {
        self.evaluations_used
    }
    /// Earlier or final accepted winner; absence is not a sentinel key.
    pub fn best(&self) -> Option<&AttackBest> {
        self.best.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_preserves_null_best_and_all_terminations() {
        for termination in [
            AttackTermination::Completed,
            AttackTermination::OuterSliceEnd,
            AttackTermination::EvaluationBudget,
            AttackTermination::Cancelled,
        ] {
            let result = AttackResult {
                termination,
                counters: AttackProgress(CounterSnapshot {
                    evaluations_admitted: u64::MAX - 1,
                    evaluations_completed: u64::MAX - 2,
                    climbs_started: u128::MAX,
                    climbs_completed: u128::MAX - 1,
                    outers_completed: u128::MAX - 2,
                }),
                evaluations_used: u64::MAX,
                best: None,
            };
            assert_eq!(result.termination(), termination);
            assert!(result.best().is_none());
            assert_eq!(result.evaluations_used(), u64::MAX);
            let counters = result.counters();
            assert_eq!(counters.evaluations_admitted(), u64::MAX - 1);
            assert_eq!(counters.evaluations_completed(), u64::MAX - 2);
            assert_eq!(counters.climbs_started(), u128::MAX);
            assert_eq!(counters.climbs_completed(), u128::MAX - 1);
            assert_eq!(counters.outers_completed(), u128::MAX - 2);
        }
    }
}
