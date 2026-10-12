//! Owned attack projections for the public synchronous HC facade.

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

/// Public classification without exposing private scheduler payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackRunCategory {
    /// Candidate resolution diagnostics.
    Resolution,
    /// Decryption, board construction or scoring failure.
    Evaluation,
    /// Factual accounting overflow.
    Counter,
    /// Missing scheduler facts or violated internal assumptions.
    Invariant,
    /// The validated attack kind has no public execution implementation.
    UnsupportedExecution,
}

/// The five independent factual counters that can overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackCounterOverflow {
    /// Admission after charging.
    EvaluationsAdmitted,
    /// Successful evaluation accounting.
    EvaluationsCompleted,
    /// Initial climb success accounting.
    ClimbsStarted,
    /// Finalized climb accounting.
    ClimbsCompleted,
    /// Completed outer accounting.
    OutersCompleted,
}

#[derive(Debug)]
pub(crate) enum RunPayload {
    Resolution(Vec<crate::SearchDiagnostic>),
    Evaluation(crate::attack_evaluator::TrialEvaluationError),
    Counter(crate::attack_control::CounterOverflow),
    Invariant(&'static str),
}

/// Opaque owned original cause. Nested causes remain available through `Error`.
/// Private payload construction is unavailable to external clients:
/// ```compile_fail
/// use enigma_core::AttackRunSource;
/// let source = AttackRunSource("invented cause");
/// ```
/// ```compile_fail
/// fn payload(source: &enigma_core::AttackRunSource) { let _ = &source.0; }
/// ```
#[derive(Debug)]
pub struct AttackRunSource(pub(crate) RunPayload);

impl AttackRunSource {
    /// Classification independent of private payload representation.
    pub fn category(&self) -> AttackRunCategory {
        match self.0 {
            RunPayload::Resolution(_) => AttackRunCategory::Resolution,
            RunPayload::Evaluation(_) => AttackRunCategory::Evaluation,
            RunPayload::Counter(_) => AttackRunCategory::Counter,
            RunPayload::Invariant(_) => AttackRunCategory::Invariant,
        }
    }
    /// Original resolution diagnostics, without formatting conversion.
    pub fn diagnostics(&self) -> Option<&[crate::SearchDiagnostic]> {
        match &self.0 {
            RunPayload::Resolution(diagnostics) => Some(diagnostics),
            _ => None,
        }
    }
    /// Typed counter identity for accounting failures.
    pub fn overflow(&self) -> Option<AttackCounterOverflow> {
        use crate::attack_control::CounterOverflow as Private;
        Some(match self.0 {
            RunPayload::Counter(Private::EvaluationsAdmitted) => {
                AttackCounterOverflow::EvaluationsAdmitted
            }
            RunPayload::Counter(Private::EvaluationsCompleted) => {
                AttackCounterOverflow::EvaluationsCompleted
            }
            RunPayload::Counter(Private::ClimbsStarted) => AttackCounterOverflow::ClimbsStarted,
            RunPayload::Counter(Private::ClimbsCompleted) => AttackCounterOverflow::ClimbsCompleted,
            RunPayload::Counter(Private::OutersCompleted) => AttackCounterOverflow::OutersCompleted,
            _ => return None,
        })
    }
}

impl std::fmt::Display for AttackRunSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            RunPayload::Resolution(diagnostics) => write!(f, "attack resolution: {diagnostics:?}"),
            RunPayload::Evaluation(source) => source.fmt(f),
            RunPayload::Counter(source) => source.fmt(f),
            RunPayload::Invariant(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for AttackRunSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            RunPayload::Evaluation(source) => Some(source),
            RunPayload::Counter(source) => Some(source),
            _ => None,
        }
    }
}

/// Runtime failure and terminal accounting, with independently fallible best projection.
/// A malformed retained best never replaces the original runtime cause.
/// ```compile_fail
/// fn replace(error: &mut enigma_core::AttackRunError) { error.outer_index = None; }
/// ```
#[derive(Debug)]
pub struct AttackRunError(Box<AttackRunErrorData>);

/// Private complete envelope; boxing preserves the public result signature.
#[derive(Debug)]
pub(crate) struct AttackRunErrorData {
    pub(crate) source: AttackRunSource,
    pub(crate) outer_index: Option<u128>,
    pub(crate) start_index: Option<u128>,
    pub(crate) evaluations_used: u64,
    pub(crate) counters: AttackProgress,
    pub(crate) best: Result<Option<AttackBest>, Box<dyn std::error::Error + Send + Sync>>,
}

impl AttackRunError {
    pub(crate) fn new(data: AttackRunErrorData) -> Self {
        Self(Box::new(data))
    }

    /// Original owned runtime cause, independent of best projection failure.
    pub fn run_source(&self) -> &AttackRunSource {
        &self.0.source
    }
    /// Failure outer, absent when an outer is missing or enumeration has not begun.
    pub fn outer_index(&self) -> Option<u128> {
        self.0.outer_index
    }
    /// Failure start, absent during resolution or missing-outer failures.
    pub fn start_index(&self) -> Option<u128> {
        self.0.start_index
    }
    /// Cumulative charged allowance, not admitted count.
    pub fn evaluations_used(&self) -> u64 {
        self.0.evaluations_used
    }
    /// Final factual snapshot, including any earlier accepted work.
    pub fn counters(&self) -> AttackProgress {
        self.0.counters
    }
    /// `Ok(None)` means absent; `Err` means retained best could not be projected.
    pub fn best(
        &self,
    ) -> Result<Option<&AttackBest>, &(dyn std::error::Error + Send + Sync + 'static)> {
        self.0
            .best
            .as_ref()
            .map(Option::as_ref)
            .map_err(|error| error.as_ref())
    }
}

impl std::fmt::Display for AttackRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.source.fmt(f)
    }
}

impl std::error::Error for AttackRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_private_causes_preserve_public_downcast_chain() {
        use crate::attack_evaluator::{TrialBoardError, TrialEvaluationError};
        use crate::{MeasureError, ModelError, ScoreError};
        use std::error::Error;
        // These are injected private causes, not naturally failing validated runs.
        for payload in [
            TrialEvaluationError::Board(TrialBoardError::Model(ModelError::UnknownSymbol('Z'))),
            TrialEvaluationError::Model(ModelError::EmptyAlphabet),
            TrialEvaluationError::Measure(MeasureError::Arithmetic(ScoreError::Overflow)),
            TrialEvaluationError::MissingResource(MeasureId::Trie),
            TrialEvaluationError::IncompatibleResource(MeasureId::Trie),
        ] {
            let error = AttackRunError::new(AttackRunErrorData {
                source: AttackRunSource(RunPayload::Evaluation(payload)),
                outer_index: None,
                start_index: None,
                evaluations_used: 0,
                counters: AttackProgress(CounterSnapshot::default()),
                best: Ok(None),
            });
            assert_eq!(error.run_source().category(), AttackRunCategory::Evaluation);
            assert!(error.run_source().diagnostics().is_none());
            assert!(error.run_source().overflow().is_none());
            assert!(!error.to_string().is_empty());
            let source = error
                .source()
                .unwrap()
                .downcast_ref::<AttackRunSource>()
                .unwrap();
            assert!(std::ptr::eq(source, error.run_source()));
            assert_eq!(error.to_string(), source.to_string());
            let trial = source
                .source()
                .unwrap()
                .downcast_ref::<TrialEvaluationError>()
                .unwrap();
            match trial {
                TrialEvaluationError::Board(_) => {
                    let board = trial
                        .source()
                        .unwrap()
                        .downcast_ref::<TrialBoardError>()
                        .unwrap();
                    assert_eq!(
                        board,
                        &TrialBoardError::Model(ModelError::UnknownSymbol('Z'))
                    );
                    let model = board
                        .source()
                        .unwrap()
                        .downcast_ref::<ModelError>()
                        .unwrap();
                    assert_eq!(model, &ModelError::UnknownSymbol('Z'));
                    assert!(model.source().is_none());
                }
                TrialEvaluationError::Model(_) => {
                    let model = trial
                        .source()
                        .unwrap()
                        .downcast_ref::<ModelError>()
                        .unwrap();
                    assert_eq!(model, &ModelError::EmptyAlphabet);
                    assert!(model.source().is_none());
                }
                TrialEvaluationError::Measure(_) => {
                    let measure = trial
                        .source()
                        .unwrap()
                        .downcast_ref::<MeasureError>()
                        .unwrap();
                    assert_eq!(measure, &MeasureError::Arithmetic(ScoreError::Overflow));
                    let score = measure
                        .source()
                        .unwrap()
                        .downcast_ref::<ScoreError>()
                        .unwrap();
                    assert_eq!(score, &ScoreError::Overflow);
                    assert!(score.source().is_none());
                }
                _ => assert!(trial.source().is_none()),
            }
        }
        for payload in [
            RunPayload::Resolution(vec![]),
            RunPayload::Invariant("missing outer"),
        ] {
            assert!(AttackRunSource(payload).source().is_none());
        }
    }

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
