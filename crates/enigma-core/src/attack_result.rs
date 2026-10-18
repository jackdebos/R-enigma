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
    /// This entry's own stage history; no accessor until the hold is projected.
    #[allow(dead_code)] // Read once 14.3b runs stages over the hold.
    pub(crate) stages: Vec<AttackStageResult>,
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

/// Committed history for one stage whose first evaluation was admitted.
#[derive(Clone, Debug)]
pub struct AttackStageResult {
    pub(crate) pass: &'static str,
    pub(crate) measure: MeasureId,
    pub(crate) base_measure: Option<MeasureId>,
    pub(crate) score: Option<MeasuredScore>,
    pub(crate) evaluations_used: u64,
    pub(crate) completed: bool,
}

impl AttackStageResult {
    /// Stage identifier in pipeline order.
    pub fn pass(&self) -> &'static str {
        self.pass
    }
    /// Resolved stage objective.
    pub fn measure(&self) -> MeasureId {
        self.measure
    }
    /// Configured trie base objective, otherwise absent.
    pub fn base_measure(&self) -> Option<MeasureId> {
        self.base_measure
    }
    /// Last committed stage score, absent if its first evaluation failed.
    pub fn score(&self) -> Option<MeasuredScore> {
        self.score
    }
    /// Charged allowance used by this stage alone.
    pub fn evaluations_used(&self) -> u64 {
        self.evaluations_used
    }
    /// Whether the stage finished all requested work.
    pub fn completed(&self) -> bool {
        self.completed
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
    // Unpolished finalists; only the head runs stages until Task 14.3.
    pub(crate) held_tail: Vec<AttackBest>,
    pub(crate) stages: Vec<AttackStageResult>,
}

impl AttackResult {
    /// Started stages in pipeline order; empty for HC/PE-only runs.
    pub fn stages(&self) -> &[AttackStageResult] {
        &self.stages
    }
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

impl From<crate::attack_hill_climb::ObservedClimbError> for RunPayload {
    fn from(error: crate::attack_hill_climb::ObservedClimbError) -> Self {
        use crate::attack_hill_climb::ObservedClimbError;
        match error {
            ObservedClimbError::Counter(source) => Self::Counter(source),
            ObservedClimbError::Evaluation(source) => Self::Evaluation(source),
        }
    }
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
    // Retained privately until Task 14 result projection consumes this field.
    #[allow(dead_code)]
    pub(crate) held_tail: Vec<AttackBest>,
    pub(crate) stages: Vec<AttackStageResult>,
    pub(crate) source: AttackRunSource,
    pub(crate) outer_index: Option<u128>,
    pub(crate) start_index: Option<u128>,
    pub(crate) evaluations_used: u64,
    pub(crate) counters: AttackProgress,
    pub(crate) best: Result<Option<AttackBest>, Box<dyn std::error::Error + Send + Sync>>,
}

impl AttackRunError {
    /// Started stage history retained independently of best projection.
    pub fn stages(&self) -> &[AttackStageResult] {
        &self.0.stages
    }
    pub(crate) fn new(data: AttackRunErrorData) -> Self {
        Self(Box::new(data))
    }

    pub(crate) fn with_held(mut self, head: Option<AttackBest>, tail: Vec<AttackBest>) -> Self {
        if head.is_some() {
            self.0.best = Ok(head);
        }
        self.0.held_tail = tail;
        self
    }

    #[cfg(test)]
    pub(crate) fn held_tail(&self) -> &[AttackBest] {
        &self.0.held_tail
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
pub(crate) mod tests {
    use super::*;

    pub(crate) fn held_tail(error: &AttackRunError) -> &[AttackBest] {
        &error.0.held_tail
    }

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
                held_tail: Vec::new(),
                stages: Vec::new(),
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
                held_tail: Vec::new(),
                termination,
                stages: Vec::new(),
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
