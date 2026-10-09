//! Private complete-neighborhood strict ascent with bound scoring and shared accounting.

use crate::attack_evaluator::{validated_trial_board, TrialEvaluationError, TrialEvaluator};
use crate::attack_neighborhood::NeighborhoodCursor;
use crate::{
    AttackPlugboardDomain, BoundResource, Direction, FixedScore, MeasureId, MeasuredScore,
    ResolvedConfiguration,
};

type MutableBoard = Vec<(char, char)>;

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

#[derive(Debug)]
struct SeedBest {
    seed_index: u128,
    current: ScoredBoard,
    incomplete: bool,
    final_objective_ascent: bool,
    neighborhood_exhausted: bool,
}

#[derive(Debug)]
struct SeedRunOutcome {
    budget_stopped: bool,
    /// Cumulative usage of the borrowed allowance, including earlier work.
    evaluations_used: u64,
    climbs_started: u128,
    climbs_completed: u128,
    best: Option<SeedBest>,
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
