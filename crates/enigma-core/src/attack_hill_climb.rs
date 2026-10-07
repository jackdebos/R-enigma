//! Complete-neighborhood selection only; no ascent or objective-phase orchestration.

use crate::attack_evaluator::{TrialEvaluationError, TrialEvaluator};
use crate::attack_neighborhood::NeighborhoodCursor;
use crate::{AttackPlugboardDomain, FixedScore, MeasuredScore, ResolvedConfiguration};

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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ScanOutcome {
    Complete(Option<(MutableBoard, MeasuredScore)>),
    Interrupted,
}

pub(super) struct NeighborhoodSelection<'a> {
    pub(super) initial: &'a ResolvedConfiguration,
    pub(super) domain: &'a AttackPlugboardDomain,
    pub(super) evaluator: &'a TrialEvaluator<'a>,
    pub(super) backtrack_pairs: usize,
}

impl NeighborhoodSelection<'_> {
    pub(super) fn scan(
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
            let (_, score) = self.evaluator.evaluate(&board)?;
            if score.ranking().units() > best_ranking.units() {
                best_ranking = score.ranking();
                best = Some((board, score));
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
            ScanOutcome::Complete(Some((
                vec![('A', 'C')],
                MeasuredScore::higher_is_better(FixedScore::from_units(2 << 32)),
            )))
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
            Ok(ScanOutcome::Complete(Some((
                boards[1].clone(),
                MeasuredScore::higher_is_better(FixedScore::from_units(2 << 32))
            ))))
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
