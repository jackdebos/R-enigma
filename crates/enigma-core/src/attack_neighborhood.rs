//! Bounded per-pair replacements and lazy alphabet-index neighborhood traversal.

use crate::attack_evaluator::{validated_trial_board, TrialBoardError};
use crate::{AttackPlugboardDomain, ResolvedConfiguration};

type MutableBoard = Vec<(char, char)>;

#[cfg(test)]
thread_local! {
    static PAIR_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only owned-board adapter; owns the current snapshot, and only immutable
/// configuration and domain are borrowed.
#[cfg(test)]
pub(super) struct NeighborhoodCursor<'a> {
    symbols: &'a [char],
    walker: NeighborhoodWalker,
}

#[cfg(test)]
impl<'a> NeighborhoodCursor<'a> {
    pub(super) fn new(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        current: &[(char, char)],
        backtrack_pairs: usize,
    ) -> Result<Self, TrialBoardError> {
        Ok(Self {
            symbols: &initial.topology().alphabet().symbols,
            walker: NeighborhoodWalker::validated(initial, domain, current, backtrack_pairs)?,
        })
    }
}

#[cfg(test)]
impl Iterator for NeighborhoodCursor<'_> {
    type Item = MutableBoard;

    fn next(&mut self) -> Option<Self::Item> {
        let k = self.walker.next_action()?;
        Some(self.walker.trial(k, self.symbols))
    }
}

fn mutable_symbol_mask(
    initial: &ResolvedConfiguration,
    domain: &AttackPlugboardDomain,
) -> Vec<bool> {
    initial
        .topology()
        .alphabet()
        .symbols
        .iter()
        .map(|s| domain.symbols().contains(s))
        .collect()
}

/// Admissible replacement actions for one selected pair, held on the stack.
#[derive(Clone, Copy, Default)]
struct PairActions {
    /// a, b and their baseline partners c, d (a free endpoint is its own partner).
    endpoints: [usize; 4],
    links: [[(usize, usize); 2]; 4],
    lens: [u8; 4],
    count: usize,
}

/// A loaded pair's actions and one selected action, replayable after the walk moves on.
#[derive(Clone, Copy)]
pub(super) struct WalkerTrial {
    actions: PairActions,
    action: usize,
}

/// Walks the neighborhood over one full involution (fixed and current pairs),
/// rewriting only the touched endpoints of a trial and restoring them afterwards.
#[derive(Clone)]
pub(super) struct NeighborhoodWalker {
    map: Vec<usize>,
    fixed: Vec<bool>,
    mutable_symbols: Vec<bool>,
    pairs: usize,
    backtrack_pairs: usize,
    max_pairs: usize,
    next_pair: (usize, usize),
    actions: PairActions,
    next_action: usize,
    saved: [usize; 4],
}

impl NeighborhoodWalker {
    /// Validates the snapshot like [`NeighborhoodCursor::new`] before walking it.
    pub(super) fn validated(
        initial: &ResolvedConfiguration,
        domain: &AttackPlugboardDomain,
        current: &[(char, char)],
        backtrack_pairs: usize,
    ) -> Result<Self, TrialBoardError> {
        validated_trial_board(initial, domain, current)?;
        Ok(Self::new(
            initial,
            domain,
            current,
            backtrack_pairs,
            mutable_symbol_mask(initial, domain),
        ))
    }

    /// The snapshot must already be validated against configuration and domain.
    fn new(
        initial: &ResolvedConfiguration,
        domain: &AttackPlugboardDomain,
        current: &[(char, char)],
        backtrack_pairs: usize,
        mutable_symbols: Vec<bool>,
    ) -> Self {
        let alphabet = initial.topology().alphabet();
        let index = |s| alphabet.index_of(s).expect("validated snapshot symbol");
        let mut map: Vec<usize> = (0..alphabet.symbols.len()).collect();
        let mut fixed = vec![false; map.len()];
        for &(x, y) in domain.fixed_pairs() {
            let (x, y) = (index(x), index(y));
            (map[x], map[y], fixed[x], fixed[y]) = (y, x, true, true);
        }
        for &(x, y) in current {
            let (x, y) = (index(x), index(y));
            (map[x], map[y]) = (y, x);
        }
        Self {
            map,
            fixed,
            mutable_symbols,
            pairs: domain.fixed_pairs().len() + current.len(),
            backtrack_pairs,
            max_pairs: domain.max_pairs(),
            next_pair: (0, 1),
            actions: PairActions::default(),
            next_action: 0,
            saved: [0; 4],
        }
    }

    /// Loads the next pair in lexicographic alphabet-index order; false once exhausted.
    fn advance(&mut self) -> bool {
        let n = self.map.len();
        let (a, b) = self.next_pair;
        if b >= n {
            return false;
        }
        self.next_pair = if b + 1 < n {
            (a, b + 1)
        } else {
            (a + 1, a + 2)
        };
        self.load(a, b);
        true
    }

    /// Whether another admissible trial remains, loading pairs as needed; visits
    /// exactly the pairs a peeking iterator would, and never revisits them.
    pub(super) fn has_next(&mut self) -> bool {
        while self.next_action >= self.actions.count {
            if !self.advance() {
                return false;
            }
            self.next_action = 0;
        }
        true
    }

    /// The next admissible action of the loaded pair, to [`Self::apply`].
    pub(super) fn next_action(&mut self) -> Option<usize> {
        if !self.has_next() {
            return None;
        }
        self.next_action += 1;
        Some(self.next_action - 1)
    }

    /// Indices must be increasing and inside the runtime alphabet.
    /// Only reads the baseline map; every action starts from it, never from the
    /// preceding trial.
    fn load(&mut self, a: usize, b: usize) {
        #[cfg(test)]
        PAIR_VISITS.with(|visits| visits.set(visits.get() + 1));
        let (c, d) = (self.map[a], self.map[b]);
        self.actions = PairActions {
            endpoints: [a, b, c, d],
            ..PairActions::default()
        };
        let both_free = a == c && b == d;
        if (!both_free && self.pairs < self.backtrack_pairs)
            || [a, b, c, d].iter().any(|&s| self.fixed[s])
        {
            return;
        }
        // The validated snapshot is a disjoint involution. Fixed endpoints were
        // rejected above. Severing a/b frees their partners; every action reconnects
        // distinct available endpoints (four distinct symbols in the last case).
        // Add/remove, moving a link to a free endpoint, and reconnecting two links
        // all change the mapping. Thus only mask and capacity can reject a trial;
        // neither model construction nor an electrical no-op comparison is needed.
        // Severing removes each existing link once; c == b is a single link.
        let remaining = self.pairs - usize::from(a != c) - usize::from(b != d && c != b);
        let (mask, max_pairs, actions) = (&self.mutable_symbols, self.max_pairs, &mut self.actions);
        let mut push = |links: &[(usize, usize)]| {
            if remaining + links.len() <= max_pairs
                && links.iter().all(|&(x, y)| mask[x] && mask[y])
            {
                actions.links[actions.count][..links.len()].copy_from_slice(links);
                actions.lens[actions.count] = links.len() as u8;
                actions.count += 1;
            }
        };
        if both_free {
            push(&[(a, b)]);
        } else if c == b {
            push(&[]);
        } else if a == c || b == d {
            let (f, x, y) = if a == c { (a, b, d) } else { (b, a, c) };
            push(&[(f, x)]);
            push(&[(f, y)]);
        } else {
            push(&[(a, b)]);
            push(&[(a, b), (c, d)]);
            push(&[(a, d)]);
            push(&[(a, d), (c, b)]);
        }
    }

    /// Rewrites the loaded action k in place; restore must follow before another apply.
    pub(super) fn apply(&mut self, k: usize) {
        let endpoints = self.actions.endpoints;
        for (saved, &s) in self.saved.iter_mut().zip(&endpoints) {
            *saved = self.map[s];
        }
        for s in endpoints {
            self.map[s] = s;
        }
        let links = self.actions.links[k];
        for &(x, y) in &links[..usize::from(self.actions.lens[k])] {
            (self.map[x], self.map[y]) = (y, x);
        }
    }

    /// Duplicate endpoints saved the same baseline value, so write order is irrelevant.
    pub(super) fn restore(&mut self) {
        for (&s, &value) in self.actions.endpoints.iter().zip(&self.saved) {
            self.map[s] = value;
        }
    }

    /// Canonical mutable board: pairs by ascending lower alphabet index, fixed omitted.
    fn board(&self, symbols: &[char]) -> MutableBoard {
        (0..self.map.len())
            .filter(|&i| i < self.map[i] && !self.fixed[i])
            .map(|i| (symbols[i], symbols[self.map[i]]))
            .collect()
    }

    /// The full fixed and mutable involution, including any applied trial.
    pub(super) fn mapping(&self) -> &[usize] {
        &self.map
    }

    /// Captures loaded action k so its board can be rebuilt once the walk is done.
    pub(super) fn selected(&self, k: usize) -> WalkerTrial {
        WalkerTrial {
            actions: self.actions,
            action: k,
        }
    }

    /// Re-applies a selected trial to the unchanged baseline and reads its board.
    pub(super) fn winner_board(&mut self, winner: &WalkerTrial, symbols: &[char]) -> MutableBoard {
        let loaded = std::mem::replace(&mut self.actions, winner.actions);
        let board = self.trial(winner.action, symbols);
        self.actions = loaded;
        board
    }

    fn trial(&mut self, k: usize, symbols: &[char]) -> MutableBoard {
        self.apply(k);
        let board = self.board(symbols);
        self.restore();
        board
    }
}

/// Test-only per-pair view: validates like the cursor and owns the alphabet copy.
#[cfg(test)]
struct TrialContext {
    walker: NeighborhoodWalker,
    symbols: Vec<char>,
}

#[cfg(test)]
impl TrialContext {
    fn new(
        initial: &ResolvedConfiguration,
        domain: &AttackPlugboardDomain,
        current: &[(char, char)],
        backtrack_pairs: usize,
        mutable_symbols: &[bool],
    ) -> Result<Self, TrialBoardError> {
        validated_trial_board(initial, domain, current)?;
        Ok(Self {
            walker: NeighborhoodWalker::new(
                initial,
                domain,
                current,
                backtrack_pairs,
                mutable_symbols.to_vec(),
            ),
            symbols: initial.topology().alphabet().symbols.clone(),
        })
    }

    /// Indices must be increasing and inside the runtime alphabet.
    /// Invalid selections report AlphabetBinding without producing any trials.
    fn trials_for(&self, a: usize, b: usize) -> Result<Vec<MutableBoard>, TrialBoardError> {
        if a >= b || b >= self.walker.map.len() {
            PAIR_VISITS.with(|visits| visits.set(visits.get() + 1));
            return Err(TrialBoardError::AlphabetBinding);
        }
        let mut walker = self.walker.clone();
        walker.load(a, b);
        Ok((0..walker.actions.count)
            .map(|k| walker.trial(k, &self.symbols))
            .collect())
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
                        let mutable_symbols = mutable_symbol_mask(&initial, &domain);
                        for threshold in [0, all.len(), all.len() + 1] {
                            let context = TrialContext::new(
                                &initial,
                                &domain,
                                &current,
                                threshold,
                                &mutable_symbols,
                            )
                            .unwrap();
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
                                    let alternate = TrialContext::new(
                                        &initial,
                                        &domain,
                                        &canonical,
                                        threshold,
                                        &mutable_symbols,
                                    )
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
                                let cursor =
                                    NeighborhoodCursor::new(&initial, &domain, board, threshold)
                                        .unwrap();
                                crate::PLUGBOARD_BUILDS.with(|c| c.set(0));
                                crate::attack_evaluator::BINDING_CHECKS.with(|c| c.set(0));
                                // Full sequence equality includes action order and duplicates.
                                assert_eq!(cursor.collect::<Vec<_>>(), flattened);
                                assert_eq!(crate::PLUGBOARD_BUILDS.with(|c| c.get()), 0);
                                assert_eq!(
                                    crate::attack_evaluator::BINDING_CHECKS.with(|c| c.get()),
                                    0
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
    fn walker_actions_match_oracle_per_pair() {
        let alphabet = Alphabet::new("Ωa🦀Zé中".chars().collect()).unwrap();
        let mut comparisons = 0;
        for map in mappings(6) {
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
                        for threshold in [0, all.len(), all.len() + 1] {
                            let mut walker = NeighborhoodWalker::new(
                                &initial,
                                &domain,
                                &current,
                                threshold,
                                mutable_symbol_mask(&initial, &domain),
                            );
                            assert_eq!(walker.map, map);
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
                                    walker.load(a, b);
                                    let mut actual = Vec::new();
                                    for k in 0..walker.actions.count {
                                        walker.apply(k);
                                        actual.push(walker.board(&alphabet.symbols));
                                        walker.restore();
                                        assert_eq!(walker.map, map);
                                    }
                                    assert_eq!(
                                        actual, expected,
                                        "{map:?} {fixed:?} {mask:?} {cap} {threshold} {a} {b}"
                                    );
                                    comparisons += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, 86_760);
    }

    #[test]
    fn constructor_errors_and_invalid_selections() {
        let alphabet = Alphabet::new("ABCD".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let full = domain(&alphabet, &[], &alphabet.symbols, 2);
        let assert_error =
            |d: &AttackPlugboardDomain, board: &[(char, char)], expected: TrialBoardError| {
                assert_eq!(
                    TrialContext::new(&initial, d, board, 0, &mutable_symbol_mask(&initial, d))
                        .err()
                        .as_ref(),
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
        let mutable_symbols = mutable_symbol_mask(&initial, &full);
        let context = TrialContext::new(&initial, &full, &[], 0, &mutable_symbols).unwrap();
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
        // Positive control: standalone validation still performs both constructions.
        crate::PLUGBOARD_BUILDS.with(|c| c.set(0));
        crate::attack_evaluator::BINDING_CHECKS.with(|c| c.set(0));
        validated_trial_board(&initial, &domain, &[('A', 'B')]).unwrap();
        assert_eq!(crate::PLUGBOARD_BUILDS.with(|c| c.get()), 2);
        assert_eq!(crate::attack_evaluator::BINDING_CHECKS.with(|c| c.get()), 1);
        let cursor = NeighborhoodCursor::new(&initial, &domain, &[('A', 'B')], 0).unwrap();
        crate::PLUGBOARD_BUILDS.with(|c| c.set(0));
        crate::attack_evaluator::BINDING_CHECKS.with(|c| c.set(0));
        let actual: Vec<_> = cursor.collect();
        assert_eq!(actual, expected);
        assert_eq!(crate::PLUGBOARD_BUILDS.with(|c| c.get()), 0);
        assert_eq!(crate::attack_evaluator::BINDING_CHECKS.with(|c| c.get()), 0);
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
            TrialContext::new(
                &initial,
                &domain,
                &board,
                0,
                &mutable_symbol_mask(&initial, &domain),
            )
            .err(),
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
        let mutable_symbols = mutable_symbol_mask(&initial, &domain);
        let context = TrialContext::new(&initial, &domain, &[], 1, &mutable_symbols).unwrap();
        assert_eq!(context.trials_for(0, 1).unwrap(), vec![vec![('A', 'B')]]);
    }
}
