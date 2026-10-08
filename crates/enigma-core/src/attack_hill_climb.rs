//! Private complete-neighborhood strict ascent with bound scoring and shared accounting.

use crate::attack_evaluator::{validated_trial_board, TrialEvaluationError, TrialEvaluator};
use crate::attack_neighborhood::NeighborhoodCursor;
use crate::{
    AttackPlugboardDomain, BoundResource, Direction, FixedScore, MeasureId, MeasuredScore,
    ResolvedConfiguration,
};

type MutableBoard = Vec<(char, char)>;

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
struct ScoredBoard {
    board: MutableBoard,
    plaintext: String,
    score: MeasuredScore,
}

struct ScoringState<'c, 'a> {
    context: &'c BoundClimbScoring<'a>,
    current: ScoredBoard,
    final_phase: bool,
    known_final: bool,
}

#[derive(Debug)]
struct ClimbOutcome {
    current: Option<ScoredBoard>,
    budget_stopped: bool,
    final_objective_ascent: bool,
    neighborhood_exhausted: bool,
}

impl<'a> BoundClimbScoring<'a> {
    fn climb(
        &self,
        board: MutableBoard,
        backtrack_pairs: usize,
        allowance: &mut EvaluationAllowance,
    ) -> Result<ClimbOutcome, TrialEvaluationError> {
        let Some(mut state) = self.start(board, allowance)? else {
            return Ok(ClimbOutcome {
                current: None,
                budget_stopped: true,
                final_objective_ascent: false,
                neighborhood_exhausted: false,
            });
        };
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
                ScanOutcome::Complete(winner) => {
                    final_objective_ascent |= state.final_phase || self.identical;
                    let Some(winner) = winner else { break true };
                    // Each admitted scan call leaves reserve intact. Crossing spends at
                    // most that reserve; identical/already-final commits spend nothing.
                    state = state
                        .commit_trial(winner, allowance)?
                        .expect("complete scan preserved the objective-crossing reservation");
                }
            }
        };
        // The same invariant leaves one call for an unknown final score, even
        // after an interrupted scan. Consuming finalization cannot run twice.
        let current = state
            .finalize(allowance)?
            .expect("driver preserved the final-score reservation");
        Ok(ClimbOutcome {
            current: Some(current),
            budget_stopped: !neighborhood_exhausted,
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

    fn start(
        &self,
        board: MutableBoard,
        allowance: &mut EvaluationAllowance,
    ) -> Result<Option<ScoringState<'_, 'a>>, TrialEvaluationError> {
        validated_trial_board(self.initial, self.domain, &board)
            .map_err(TrialEvaluationError::Board)?;
        let final_phase = self.domain.fixed_pairs().len() + board.len() >= self.switch_pairs;
        let known_final = final_phase || self.identical;
        if !allowance.admit(u64::from(!known_final)) {
            return Ok(None);
        }
        let evaluator = if final_phase {
            &self.final_evaluator
        } else {
            &self.initial_evaluator
        };
        let (plaintext, score) = evaluator.evaluate(&board)?;
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
    fn finalize(
        mut self,
        allowance: &mut EvaluationAllowance,
    ) -> Result<Option<ScoredBoard>, TrialEvaluationError> {
        if !self.known_final {
            if !allowance.admit(0) {
                return Ok(None);
            }
            let (plaintext, score) = self.context.final_evaluator.evaluate(&self.current.board)?;
            self.current.plaintext = plaintext;
            self.current.score = score;
        }
        Ok(Some(self.current))
    }

    /// Precondition for 11.4b.2: trial is a complete-scan-selected strict winner,
    /// evaluated with THIS context's current objective; its call was already charged.
    /// This lifecycle does not verify selection. Caller must have preserved reserve.
    /// Consuming self prevents an unscored committed board escaping on any error.
    fn commit_trial(
        mut self,
        trial: ScoredBoard,
        allowance: &mut EvaluationAllowance,
    ) -> Result<Option<Self>, TrialEvaluationError> {
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
                if !allowance.admit(0) {
                    return Ok(None);
                }
                let (plaintext, score) =
                    self.context.final_evaluator.evaluate(&self.current.board)?;
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
}

pub(super) struct NeighborhoodSelection<'a> {
    pub(super) initial: &'a ResolvedConfiguration,
    pub(super) domain: &'a AttackPlugboardDomain,
    pub(super) evaluator: &'a TrialEvaluator<'a>,
    pub(super) backtrack_pairs: usize,
}

impl NeighborhoodSelection<'_> {
    fn scan(
        &self,
        current: &[(char, char)],
        ranking: FixedScore,
        allowance: &mut EvaluationAllowance,
        reserve: u64,
    ) -> Result<ScanOutcome, TrialEvaluationError> {
        let cursor =
            NeighborhoodCursor::new(self.initial, self.domain, current, self.backtrack_pairs)
                .map_err(TrialEvaluationError::Board)?;
        let mut best = None;
        let mut best_ranking = ranking;
        for board in cursor {
            if !allowance.admit(reserve) {
                return Ok(ScanOutcome::Interrupted);
            }
            let (plaintext, score) = self.evaluator.evaluate(&board)?;
            if score.ranking().units() > best_ranking.units() {
                best_ranking = score.ranking();
                best = Some(ScoredBoard {
                    board,
                    plaintext,
                    score,
                });
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
