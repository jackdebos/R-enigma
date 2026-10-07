//! Bounded per-pair replacements and lazy alphabet-index neighborhood traversal.

use crate::attack_evaluator::{validated_trial_board, TrialBoardError};
use crate::{AttackPlugboardDomain, ResolvedConfiguration};

type MutableBoard = Vec<(char, char)>;

#[cfg(test)]
thread_local! {
    static PAIR_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Owns the current snapshot; only immutable configuration and domain are borrowed.
struct NeighborhoodCursor<'a> {
    initial: &'a ResolvedConfiguration,
    domain: &'a AttackPlugboardDomain,
    current: MutableBoard,
    backtrack_pairs: usize,
    next_pair: (usize, usize),
    pending: std::vec::IntoIter<MutableBoard>,
    exhausted: bool,
}

impl<'a> NeighborhoodCursor<'a> {
    fn new(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        current: &[(char, char)],
        backtrack_pairs: usize,
    ) -> Result<Self, TrialBoardError> {
        TrialContext::new(initial, domain, current, backtrack_pairs)?;
        Ok(Self {
            initial,
            domain,
            current: current.to_vec(),
            backtrack_pairs,
            next_pair: (0, 1),
            pending: Vec::new().into_iter(),
            exhausted: false,
        })
    }
}

impl Iterator for NeighborhoodCursor<'_> {
    type Item = MutableBoard;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(board) = self.pending.next() {
                return Some(board);
            }
            let n = self.initial.topology().alphabet().symbols.len();
            let (a, b) = self.next_pair;
            if self.exhausted || b >= n {
                self.exhausted = true;
                return None;
            }
            self.next_pair = if b + 1 < n {
                (a, b + 1)
            } else {
                (a + 1, a + 2)
            };
            let context = TrialContext {
                initial: self.initial,
                domain: self.domain,
                current: &self.current,
                backtrack_pairs: self.backtrack_pairs,
            };
            // Constructor validation and legal alphabet indices make helper errors
            // invariant failures; candidate admissibility filtering remains in trials_for.
            self.pending = context
                .trials_for(a, b)
                .expect("validated snapshot and increasing in-range alphabet indices")
                .into_iter();
        }
    }
}

struct TrialContext<'a> {
    initial: &'a ResolvedConfiguration,
    domain: &'a AttackPlugboardDomain,
    current: &'a [(char, char)],
    backtrack_pairs: usize,
}

impl<'a> TrialContext<'a> {
    fn new(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        current: &'a [(char, char)],
        backtrack_pairs: usize,
    ) -> Result<Self, TrialBoardError> {
        validated_trial_board(initial, domain, current)?;
        Ok(Self {
            initial,
            domain,
            current,
            backtrack_pairs,
        })
    }

    /// Indices must be increasing and inside the runtime alphabet.
    /// Invalid selections report AlphabetBinding without producing any trials.
    fn trials_for(&self, a: usize, b: usize) -> Result<Vec<MutableBoard>, TrialBoardError> {
        #[cfg(test)]
        PAIR_VISITS.with(|visits| visits.set(visits.get() + 1));
        let alphabet = &self.initial.topology().alphabet().symbols;
        if a >= b || b >= alphabet.len() {
            return Err(TrialBoardError::AlphabetBinding);
        }
        let (a, b) = (alphabet[a], alphabet[b]);
        let partner = |symbol| {
            self.domain
                .fixed_pairs()
                .iter()
                .chain(self.current)
                .find_map(|&(x, y)| {
                    if x == symbol {
                        Some(y)
                    } else if y == symbol {
                        Some(x)
                    } else {
                        None
                    }
                })
                .unwrap_or(symbol)
        };
        let (c, d) = (partner(a), partner(b));
        let both_free = a == c && b == d;
        if !both_free && self.domain.fixed_pairs().len() + self.current.len() < self.backtrack_pairs
        {
            return Ok(Vec::new());
        }
        // Every action starts from the same board, never from the preceding trial.
        let additions = if both_free {
            vec![vec![(a, b)]]
        } else if c == b {
            vec![vec![]]
        } else if a == c || b == d {
            let (f, x, y) = if a == c { (a, b, d) } else { (b, a, c) };
            vec![vec![(f, x)], vec![(f, y)]]
        } else {
            vec![
                vec![(a, b)],
                vec![(a, b), (c, d)],
                vec![(a, d)],
                vec![(a, d), (c, b)],
            ]
        };
        if [a, b, c, d].iter().any(|s| {
            self.domain
                .fixed_pairs()
                .iter()
                .any(|&(x, y)| *s == x || *s == y)
        }) {
            return Ok(Vec::new());
        }
        let original = validated_trial_board(self.initial, self.domain, self.current)?;
        let mut trials = Vec::with_capacity(4);
        for added in additions {
            let mut trial: MutableBoard = self
                .current
                .iter()
                .copied()
                .filter(|&(x, y)| x != a && y != a && x != b && y != b)
                .collect();
            trial.extend(added);
            if let Ok(board) = validated_trial_board(self.initial, self.domain, &trial) {
                if board != original {
                    // Canonicalize by alphabet indices, not Unicode character order.
                    let index = |s| alphabet.iter().position(|c| *c == s).unwrap();
                    for pair in &mut trial {
                        if index(pair.0) > index(pair.1) {
                            *pair = (pair.1, pair.0);
                        }
                    }
                    trial.sort_by_key(|&(x, y)| (index(x), index(y)));
                    trials.push(trial);
                }
            }
        }
        Ok(trials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Alphabet, DefinitionSource, SlotConfiguration, TransformConfiguration};

    fn initial(alphabet: &Alphabet, fixed: &[(char, char)]) -> ResolvedConfiguration {
        let symbols = &alphabet.symbols;
        let source = serde_json::json!({"kind": "custom", "value": {
            "alphabet": symbols,
            "wheels": [{"name": "r", "wiring": symbols, "turnovers": []}],
            "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
            "stepping": {"rules": []}
        }});
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        TransformConfiguration::new(
            vec![SlotConfiguration::new("r", "r", symbols[0], symbols[0])],
            fixed.to_vec(),
        )
        .resolve(&definition)
        .unwrap()
    }

    fn domain(
        alphabet: &Alphabet,
        fixed: &[(char, char)],
        mask: &[char],
        cap: usize,
    ) -> AttackPlugboardDomain {
        let source = serde_json::json!({"kind": "attack", "symbols": mask, "max_pairs": cap});
        AttackPlugboardDomain::parse_json(alphabet, fixed, &source.to_string()).unwrap()
    }

    // Enumerate every involution directly; production pair construction is not used.
    fn mappings(n: usize) -> Vec<Vec<usize>> {
        fn visit(map: &mut Vec<usize>, next: usize, output: &mut Vec<Vec<usize>>) {
            if next == map.len() {
                output.push(map.clone());
            } else if map[next] != next {
                visit(map, next + 1, output);
            } else {
                visit(map, next + 1, output);
                for other in next + 1..map.len() {
                    if map[other] == other {
                        map[next] = other;
                        map[other] = next;
                        visit(map, next + 1, output);
                        map[next] = next;
                        map[other] = other;
                    }
                }
            }
        }
        let mut output = Vec::new();
        visit(&mut (0..n).collect(), 0, &mut output);
        output
    }

    fn pairs(map: &[usize], alphabet: &[char]) -> MutableBoard {
        (0..map.len())
            .filter(|&i| i < map[i])
            .map(|i| (alphabet[i], alphabet[map[i]]))
            .collect()
    }

    // Derive actions electrically, severing selected connections before reconnecting.
    fn oracle(
        map: &[usize],
        fixed: &[bool],
        mask: &[bool],
        cap: usize,
        threshold: usize,
        a: usize,
        b: usize,
    ) -> Vec<Vec<usize>> {
        let count = (0..map.len()).filter(|&i| i < map[i]).count();
        let (c, d) = (map[a], map[b]);
        if fixed[a] || fixed[b] || (count < threshold && (c != a || d != b)) {
            return vec![];
        }
        let reconnect = match (c == a, d == b, c == b) {
            (true, true, _) => vec![vec![(a, b)]],
            (_, _, true) => vec![vec![]],
            (true, false, _) => vec![vec![(a, b)], vec![(a, d)]],
            (false, true, _) => vec![vec![(b, a)], vec![(b, c)]],
            _ => vec![
                vec![(a, b)],
                vec![(a, b), (c, d)],
                vec![(a, d)],
                vec![(a, d), (c, b)],
            ],
        };
        let mut output = Vec::new();
        for links in reconnect {
            if links.iter().any(|&(x, y)| !mask[x] || !mask[y]) {
                continue;
            }
            let mut trial = map.to_vec();
            for x in [a, b] {
                trial[map[x]] = map[x];
                trial[x] = x;
            }
            for (x, y) in links {
                trial[x] = y;
                trial[y] = x;
            }
            if trial != map && (0..map.len()).filter(|&i| i < trial[i]).count() <= cap {
                output.push(trial);
            }
        }
        output
    }

    #[test]
    fn exhaustive_per_pair_oracle_and_input_isolation() {
        let alphabet = Alphabet::new("Ωa🦀Zé中".chars().collect()).unwrap();
        let maps = mappings(6);
        assert_eq!(maps.len(), 76);
        let mut comparisons = 0;
        let mut neighborhoods = 0;
        for map in maps {
            let all = pairs(&map, &alphabet.symbols);
            for fixed_bits in 0..1usize << all.len() {
                let mut fixed = Vec::new();
                let mut current = Vec::new();
                let mut protected = vec![false; 6];
                for (i, &(x, y)) in all.iter().enumerate() {
                    if fixed_bits & (1 << i) != 0 {
                        fixed.push((y, x));
                        protected[alphabet.symbols.iter().position(|s| *s == x).unwrap()] = true;
                        protected[alphabet.symbols.iter().position(|s| *s == y).unwrap()] = true;
                    } else {
                        current.push((y, x));
                    }
                }
                current.reverse();
                for mask_bits in 1..64usize {
                    let mask: Vec<_> = (0..6).map(|i| mask_bits & (1 << i) != 0).collect();
                    if (0..6).any(|i| {
                        (protected[i] && mask[i]) || (!protected[i] && map[i] != i && !mask[i])
                    }) {
                        continue;
                    }
                    let symbols: Vec<_> = (0..6)
                        .filter(|&i| mask[i])
                        .map(|i| alphabet.symbols[i])
                        .collect();
                    for cap in all.len()..=fixed.len() + symbols.len() / 2 {
                        let initial = initial(&alphabet, &fixed);
                        let domain = domain(&alphabet, &fixed, &symbols, cap);
                        let snapshot = (initial.clone(), domain.clone(), current.clone());
                        for threshold in [0, all.len(), all.len() + 1] {
                            let context =
                                TrialContext::new(&initial, &domain, &current, threshold).unwrap();
                            let mut flattened = Vec::new();
                            for a in 0..6 {
                                for b in a + 1..6 {
                                    let expected: Vec<_> =
                                        oracle(&map, &protected, &mask, cap, threshold, a, b)
                                            .iter()
                                            .map(|m| {
                                                pairs(m, &alphabet.symbols)
                                                    .into_iter()
                                                    .filter(|&(x, _)| {
                                                        !fixed
                                                            .iter()
                                                            .any(|&(f, g)| x == f || x == g)
                                                    })
                                                    .collect::<MutableBoard>()
                                            })
                                            .collect();
                                    flattened.extend(expected.clone());
                                    let actual = context.trials_for(a, b).unwrap();
                                    let canonical = pairs(&map, &alphabet.symbols);
                                    let canonical: Vec<_> = canonical
                                        .into_iter()
                                        .filter(|&(x, _)| {
                                            !fixed.iter().any(|&(f, g)| x == f || x == g)
                                        })
                                        .collect();
                                    let alternate =
                                        TrialContext::new(&initial, &domain, &canonical, threshold)
                                            .unwrap();
                                    assert_eq!(alternate.trials_for(a, b).unwrap(), actual);
                                    assert_eq!(
                                        actual, expected,
                                        "{map:?} {fixed:?} {mask:?} {cap} {threshold} {a} {b}"
                                    );
                                    assert!(actual.len() <= 4);
                                    comparisons += 1;
                                }
                            }
                            let canonical: MutableBoard = pairs(&map, &alphabet.symbols)
                                .into_iter()
                                .filter(|&(x, _)| !fixed.iter().any(|&(f, g)| x == f || x == g))
                                .collect();
                            for board in [&current, &canonical] {
                                assert_eq!(
                                    NeighborhoodCursor::new(&initial, &domain, board, threshold)
                                        .unwrap()
                                        .collect::<Vec<_>>(),
                                    flattened,
                                );
                                neighborhoods += 1;
                            }
                        }
                        assert_eq!((initial, domain, current.clone()), snapshot);
                    }
                }
            }
        }
        assert_eq!(comparisons, 86_760);
        assert_eq!(neighborhoods, 11_568);
        println!("independent per-pair comparisons: {comparisons}; neighborhoods: {neighborhoods}");
    }

    #[test]
    fn constructor_errors_and_invalid_selections() {
        let alphabet = Alphabet::new("ABCD".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let full = domain(&alphabet, &[], &alphabet.symbols, 2);
        let assert_error =
            |d: &AttackPlugboardDomain, board: &[(char, char)], expected: TrialBoardError| {
                assert_eq!(
                    TrialContext::new(&initial, d, board, 0).err().as_ref(),
                    Some(&expected)
                );
                assert_eq!(
                    NeighborhoodCursor::new(&initial, d, board, 0).err(),
                    Some(expected)
                );
            };
        let reversed = Alphabet::new("DCBA".chars().collect()).unwrap();
        assert_error(
            &domain(&reversed, &[], &reversed.symbols, 2),
            &[],
            TrialBoardError::AlphabetBinding,
        );
        assert_error(
            &domain(&alphabet, &[('B', 'A')], &['C', 'D'], 2),
            &[],
            TrialBoardError::FixedFactsBinding,
        );
        assert_error(
            &domain(&alphabet, &[], &['A', 'B'], 1),
            &[('C', 'D')],
            TrialBoardError::OutsideMutable('C'),
        );
        assert_error(
            &domain(&alphabet, &[], &alphabet.symbols, 0),
            &[('A', 'B')],
            TrialBoardError::TotalCapacity,
        );
        use crate::ModelError::{DuplicatePlugboardSymbol, PlugboardSelfPair, UnknownSymbol};
        for (board, error) in [
            (vec![('A', 'A')], PlugboardSelfPair('A')),
            (vec![('A', '?')], UnknownSymbol('?')),
            (vec![('A', 'B'), ('C', 'A')], DuplicatePlugboardSymbol('A')),
        ] {
            assert_error(&full, &board, TrialBoardError::Model(error));
        }
        let context = TrialContext::new(&initial, &full, &[], 0).unwrap();
        for (a, b) in [(0, 0), (2, 1), (0, 4), (usize::MAX, usize::MAX)] {
            assert_eq!(
                context.trials_for(a, b),
                Err(TrialBoardError::AlphabetBinding)
            );
        }
    }

    #[test]
    fn lazy_prefix_pending_and_snapshot_isolation() {
        let alphabet = Alphabet::new("ABCD".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], &alphabet.symbols, 2);
        let snapshot = (initial.clone(), domain.clone());
        let mut caller = vec![('D', 'B'), ('C', 'A')];
        let mut expected = Vec::new();
        for a in 0..4 {
            for b in a + 1..4 {
                expected.extend(
                    oracle(&[2, 3, 0, 1], &[false; 4], &[true; 4], 2, 0, a, b)
                        .iter()
                        .map(|m| pairs(m, &alphabet.symbols)),
                );
            }
        }
        PAIR_VISITS.with(|v| v.set(0));
        let mut cursor = NeighborhoodCursor::new(&initial, &domain, &caller, 0).unwrap();
        caller.clear();
        drop(caller);
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 0);
        let mut first = cursor.next().unwrap_or_default();
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 1);
        assert_eq!(first, vec![('A', 'B')]);
        first.clear();
        assert_eq!(cursor.next(), Some(vec![('A', 'B'), ('C', 'D')]));
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 1);
        assert_eq!(cursor.next(), Some(vec![('A', 'D')]));
        assert_eq!(cursor.next(), Some(vec![('A', 'D'), ('B', 'C')]));
        drop(cursor);
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 1);
        let mut cursor =
            NeighborhoodCursor::new(&initial, &domain, &[('D', 'B'), ('C', 'A')], 0).unwrap();
        PAIR_VISITS.with(|v| v.set(0));
        let mut yielded = cursor.next().unwrap();
        yielded.clear();
        assert_eq!(cursor.by_ref().collect::<Vec<_>>(), expected[1..]);
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 6);
        assert_eq!(cursor.next(), None);
        assert_eq!(cursor.next(), None);
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 6);
        assert_eq!((initial, domain), snapshot);
    }

    #[test]
    fn complete_cross_pair_duplicates_in_action_order() {
        let alphabet = Alphabet::new("ABCD".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], &alphabet.symbols, 2);
        // AB removes; AC/AD/BC/BD reconnect independently; CD adds to AB.
        let expected = vec![
            vec![],
            vec![('A', 'C')],
            vec![('B', 'C')],
            vec![('A', 'D')],
            vec![('B', 'D')],
            vec![('B', 'C')],
            vec![('A', 'C')],
            vec![('B', 'D')],
            vec![('A', 'D')],
            vec![('A', 'B'), ('C', 'D')],
        ];
        let actual: Vec<_> = NeighborhoodCursor::new(&initial, &domain, &[('A', 'B')], 0)
            .unwrap()
            .collect();
        assert_eq!(actual, expected);
        for board in [
            vec![('A', 'C')],
            vec![('A', 'D')],
            vec![('B', 'C')],
            vec![('B', 'D')],
        ] {
            assert_eq!(actual.iter().filter(|b| **b == board).count(), 2);
        }
    }

    #[test]
    fn unicode_reverse_mask_uses_declared_alphabet_order() {
        let alphabet = Alphabet::new("Ωa🦀Zé中".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let mask: Vec<_> = alphabet.symbols.iter().rev().copied().collect();
        let domain = domain(&alphabet, &[], &mask, 1);
        let expected = vec![
            vec![('Ω', 'a')],
            vec![('Ω', '🦀')],
            vec![('Ω', 'Z')],
            vec![('Ω', 'é')],
            vec![('Ω', '中')],
            vec![('a', '🦀')],
            vec![('a', 'Z')],
            vec![('a', 'é')],
            vec![('a', '中')],
            vec![('🦀', 'Z')],
            vec![('🦀', 'é')],
            vec![('🦀', '中')],
            vec![('Z', 'é')],
            vec![('Z', '中')],
            vec![('é', '中')],
        ];
        PAIR_VISITS.with(|v| v.set(0));
        let mut cursor = NeighborhoodCursor::new(&initial, &domain, &[], 0).unwrap();
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 0);
        assert_eq!(cursor.by_ref().collect::<Vec<_>>(), expected);
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 15);
        assert_eq!(cursor.next(), None);
        assert_eq!(cursor.next(), None);
        assert_eq!(PAIR_VISITS.with(|v| v.get()), 15);
    }

    #[test]
    fn filtered_prefix_empty_capacity_and_smallest_alphabet() {
        for (symbols, mask, cap, current, threshold, expected, prefix) in [
            ("ABCD", "CD", 1, vec![], 0, vec![vec![('C', 'D')]], 6),
            ("ABCD", "ABCD", 0, vec![], 0, vec![], 6),
            ("AB", "AB", 1, vec![('A', 'B')], 2, vec![], 1),
            ("AB", "AB", 1, vec![], 0, vec![vec![('A', 'B')]], 1),
            ("A", "A", 0, vec![], 0, vec![], 0),
        ] {
            let alphabet = Alphabet::new(symbols.chars().collect()).unwrap();
            let initial = initial(&alphabet, &[]);
            let domain = domain(&alphabet, &[], &mask.chars().collect::<Vec<_>>(), cap);
            PAIR_VISITS.with(|v| v.set(0));
            let mut cursor =
                NeighborhoodCursor::new(&initial, &domain, &current, threshold).unwrap();
            assert_eq!(PAIR_VISITS.with(|v| v.get()), 0);
            assert_eq!(cursor.next(), expected.first().cloned());
            assert_eq!(PAIR_VISITS.with(|v| v.get()), prefix);
            assert_eq!(cursor.next(), None);
            assert_eq!(cursor.next(), None);
            let n = alphabet.symbols.len();
            assert_eq!(PAIR_VISITS.with(|v| v.get()), n * (n - 1) / 2);
        }
    }

    #[test]
    fn fixed_mutable_collision_rejected_by_both_constructors() {
        let alphabet = Alphabet::new("ABCD".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let domain = domain(&alphabet, &[('A', 'B')], &['C', 'D'], 2);
        let board = [('A', 'C')];
        let expected = TrialBoardError::Model(crate::ModelError::DuplicatePlugboardSymbol('A'));
        assert_eq!(
            TrialContext::new(&initial, &domain, &board, 0).err(),
            Some(expected)
        );
        assert_eq!(
            NeighborhoodCursor::new(&initial, &domain, &board, 0).err(),
            Some(TrialBoardError::Model(
                crate::ModelError::DuplicatePlugboardSymbol('A')
            )),
        );
    }

    #[test]
    fn both_free_add_is_a_full_replacement() {
        let alphabet = Alphabet::new("ABCD".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], &alphabet.symbols, 2);
        let context = TrialContext::new(&initial, &domain, &[], 1).unwrap();
        assert_eq!(context.trials_for(0, 1).unwrap(), vec![vec![('A', 'B')]]);
    }
}
