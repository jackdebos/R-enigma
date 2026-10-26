//! Pure crib dragging and exact one-setting bombe (docs/crib-attack.md §§2–4).
//!
//! Indices are already validated/normalized by the caller; no text normalization is
//! performed here. Menus and facts are built once, scratch is reused across settings.

use std::borrow::Cow;

/// Admission keeps every position's menu only while their estimated heap stays
/// within this bound (the same 64 MiB as the accelerator's byte rows).
pub(crate) const MAX_SHARED_MENU_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    /// Test-only override of `MAX_SHARED_MENU_BYTES` for admissions on this thread.
    pub(crate) static MENU_BUDGET: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

fn menu_budget() -> usize {
    #[cfg(test)]
    if let Some(budget) = MENU_BUDGET.get() {
        return budget;
    }
    MAX_SHARED_MENU_BYTES
}

/// Upper bound on the heap held by `positions` menus, or `None` on overflow. Per
/// menu: `crib` edges, each also listed once by its component, plus at most `size`
/// components whose symbols partition at most `size` symbols:
/// `crib * (size_of::<Edge>() + size_of::<usize>())
///  + size * (size_of::<Component>() + size_of::<usize>()) + size_of::<Menu>()`.
pub(crate) fn shared_menu_bytes(positions: usize, crib: usize, size: usize) -> Option<usize> {
    use std::mem::size_of;
    let edges = crib.checked_mul(size_of::<Edge>() + size_of::<usize>())?;
    let components = size.checked_mul(size_of::<Component>() + size_of::<usize>())?;
    edges
        .checked_add(components)?
        .checked_add(size_of::<Menu>())?
        .checked_mul(positions)
}

/// Menus for the admitted positions, in position order.
#[derive(Debug)]
pub(crate) enum Menus {
    /// Built once at admission and shared by every outer.
    Shared(Vec<Menu>),
    /// Over budget: each use rebuilds its menu from the crib and text indices.
    OnDemand {
        size: usize,
        crib: Vec<usize>,
        text: Vec<usize>,
    },
}

/// Immutable admission-time menus and facts shared by outer workers.
#[derive(Debug)]
pub(crate) struct Plan {
    pub(crate) positions: Vec<usize>,
    pub(crate) menus: Menus,
    pub(crate) facts: Facts,
    pub(crate) row_length: usize,
}

impl Plan {
    /// The menu of the admitted position at `rank`; identical for both storages.
    pub(crate) fn menu(&self, rank: usize) -> Cow<'_, Menu> {
        match &self.menus {
            Menus::Shared(menus) => Cow::Borrowed(&menus[rank]),
            Menus::OnDemand { size, crib, text } => Cow::Owned(
                Menu::new(*size, crib, text, self.positions[rank]).expect("admitted position"),
            ),
        }
    }

    pub(crate) fn build(
        request: &crate::SearchRequest,
        domain: &crate::AttackPlugboardDomain,
        settings: &crate::AttackSettings,
    ) -> Result<Self, Vec<crate::SearchDiagnostic>> {
        let (crib, position) = settings.crib().expect("bombe settings");
        let alphabet = request.definition().alphabet();
        let indices = |text: &str| {
            text.chars()
                .map(|c| alphabet.index_of(c))
                .collect::<Option<Vec<_>>>()
        };
        let text = indices(request.text()).expect("validated request text");
        // Detached settings may come from another alphabet; the gate must recheck
        // the crib rather than rely on settings-fragment provenance.
        let crib = indices(crib).ok_or_else(|| {
            vec![crate::SearchDiagnostic::new(
                "invalid_search_space",
                "crib contains a symbol outside the machine alphabet",
                "/job/attack/crib/text",
            )]
        })?;
        let positions = admissible_positions(&text, &crib, position).map_err(|error| {
            let (member, message) = match error {
                CribError::Empty => ("/text", "crib must not be empty".to_owned()),
                CribError::TooLong => ("/text", "crib is longer than ciphertext".to_owned()),
                CribError::Position => ("/position", "crib position exceeds ciphertext".to_owned()),
                CribError::Crash { index } => {
                    ("/position", format!("crib crashes at text index {index}"))
                }
                _ => ("", "no admissible crib position".to_owned()),
            };
            vec![crate::SearchDiagnostic::new(
                "invalid_search_space",
                message,
                format!("/job/attack/crib{member}"),
            )]
        })?;
        let row_length = positions.last().unwrap() + crib.len();
        let fits = shared_menu_bytes(positions.len(), crib.len(), alphabet.len())
            .is_some_and(|bytes| bytes <= menu_budget());
        let menus = if fits {
            Menus::Shared(
                positions
                    .iter()
                    .map(|&p| {
                        Menu::new(alphabet.len(), &crib, &text, p).expect("admitted position")
                    })
                    .collect(),
            )
        } else {
            let mut text = text;
            text.truncate(row_length);
            Menus::OnDemand {
                size: alphabet.len(),
                crib,
                text,
            }
        };
        let mutable = alphabet
            .symbols
            .iter()
            .map(|c| domain.symbols().contains(c))
            .collect::<Vec<_>>();
        let fixed = domain
            .fixed_pairs()
            .iter()
            .map(|&(a, b)| (alphabet.index_of(a).unwrap(), alphabet.index_of(b).unwrap()))
            .collect::<Vec<_>>();
        let facts = Facts::new(&mutable, &fixed, domain.max_pairs()).expect("validated domain");
        Ok(Self {
            positions,
            menus,
            facts,
            row_length,
        })
    }
}

const UNKNOWN: usize = usize::MAX;

/// Crib placement failures, before any setting is tested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CribError {
    Empty,
    TooLong,
    Position,
    /// Absolute text index of the first crash at a fixed position.
    Crash {
        index: usize,
    },
    NoPosition,
    Symbol,
}

/// Ascending crash-free positions, or only `position` when supplied.
/// Symbols are alphabet indices; this function does not interpret their values.
pub(crate) fn admissible_positions(
    text: &[usize],
    crib: &[usize],
    position: Option<usize>,
) -> Result<Vec<usize>, CribError> {
    if crib.is_empty() {
        return Err(CribError::Empty);
    }
    let last = text
        .len()
        .checked_sub(crib.len())
        .ok_or(CribError::TooLong)?;
    let crash = |p: usize| crib.iter().zip(&text[p..]).position(|(k, c)| k == c);
    if let Some(p) = position {
        if p > last {
            return Err(CribError::Position);
        }
        if let Some(j) = crash(p) {
            return Err(CribError::Crash { index: p + j });
        }
        return Ok(vec![p]);
    }
    let positions: Vec<_> = (0..=last).filter(|&p| crash(p).is_none()).collect();
    if positions.is_empty() {
        Err(CribError::NoPosition)
    } else {
        Ok(positions)
    }
}

/// One undirected menu edge; parallel edges retain their distinct text indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Edge {
    pub(crate) left: usize,
    pub(crate) right: usize,
    pub(crate) index: usize,
}

/// An edge-connected set of symbols (isolated alphabet symbols are omitted).
#[derive(Clone, Debug)]
pub(crate) struct Component {
    pub(crate) symbols: Vec<usize>,
    pub(crate) test_symbol: usize,
    edges: Vec<usize>,
}

/// Setting-independent multigraph at one admissible crib position.
#[derive(Clone, Debug)]
pub(crate) struct Menu {
    pub(crate) edges: Vec<Edge>,
    pub(crate) components: Vec<Component>,
    size: usize,
    position: usize,
}

impl Menu {
    /// Builds a validated menu; component/symbol order is ascending alphabet order.
    pub(crate) fn new(
        size: usize,
        crib: &[usize],
        text: &[usize],
        position: usize,
    ) -> Result<Self, CribError> {
        admissible_positions(text, crib, Some(position))?;
        if size == 0 || crib.iter().chain(text).any(|&x| x >= size) {
            return Err(CribError::Symbol);
        }
        let edges: Vec<_> = crib
            .iter()
            .enumerate()
            .map(|(j, &left)| Edge {
                left,
                right: text[position + j],
                index: position + j,
            })
            .collect();
        let mut adjacency = vec![Vec::new(); size];
        for (i, edge) in edges.iter().enumerate() {
            adjacency[edge.left].push(i);
            adjacency[edge.right].push(i);
        }
        let mut visited = vec![false; size];
        let mut components = Vec::new();
        for start in 0..size {
            if visited[start] || adjacency[start].is_empty() {
                continue;
            }
            let mut symbols = vec![start];
            visited[start] = true;
            let mut cursor = 0;
            while cursor < symbols.len() {
                let x = symbols[cursor];
                cursor += 1;
                for &i in &adjacency[x] {
                    let e = edges[i];
                    let y = if e.left == x { e.right } else { e.left };
                    if !visited[y] {
                        visited[y] = true;
                        symbols.push(y);
                    }
                }
            }
            symbols.sort_unstable();
            let mut test_symbol = symbols[0];
            for &x in &symbols {
                if adjacency[x].len() > adjacency[test_symbol].len() {
                    test_symbol = x;
                }
            }
            let component_edges = edges
                .iter()
                .enumerate()
                .filter_map(|(i, e)| symbols.binary_search(&e.left).is_ok().then_some(i))
                .collect();
            components.push(Component {
                symbols,
                test_symbol,
                edges: component_edges,
            });
        }
        Ok(Self {
            edges,
            components,
            size,
            position,
        })
    }
}

/// Known board assignments and the global pair budget. Unknown entries are mutable.
#[derive(Debug)]
pub(crate) struct Facts {
    board: Vec<usize>,
    pairs: usize,
    max_pairs: usize,
}

impl Facts {
    /// Fixed endpoints override the mutable mask; all other nonmutable symbols are
    /// self-connected. Rejects invalid/reused endpoints and an overfull fixed board.
    pub(crate) fn new(
        mutable: &[bool],
        fixed: &[(usize, usize)],
        max_pairs: usize,
    ) -> Option<Self> {
        if mutable.is_empty() {
            return None;
        }
        let mut board = vec![UNKNOWN; mutable.len()];
        let mut pairs = 0;
        for &(x, y) in fixed {
            if x >= board.len()
                || y >= board.len()
                || x == y
                || board[x] != UNKNOWN
                || board[y] != UNKNOWN
                || !assign(&mut board, x, y, &mut pairs, max_pairs)
            {
                return None;
            }
        }
        for (x, &is_mutable) in mutable.iter().enumerate() {
            if !is_mutable && board[x] == UNKNOWN {
                assign(&mut board, x, x, &mut pairs, max_pairs);
            }
        }
        Some(Self {
            board,
            pairs,
            max_pairs,
        })
    }
}

/// The diagonal board invariant: all assignments are symmetric, with budget checked
/// before mutation. Reused for facts and component propagation.
fn assign(board: &mut [usize], x: usize, y: usize, pairs: &mut usize, max: usize) -> bool {
    if board[x] != UNKNOWN {
        return board[x] == y;
    }
    if board[y] != UNKNOWN || (x != y && *pairs == max) {
        return false;
    }
    board[x] = y;
    board[y] = x;
    *pairs += usize::from(x != y);
    true
}

/// Reusable setting workspace. After capacity warmup, testing allocates no heap
/// memory. Results are cleared on every call, including rejection.
#[derive(Default)]
pub(crate) struct Scratch {
    /// Canonical, sorted pairs from locally unique component closures (including
    /// any known pairs incident to those components).
    pub(crate) deduced_pairs: Vec<(usize, usize)>,
    /// Sorted self-connections from locally unique component closures.
    pub(crate) deduced_self: Vec<usize>,
    closures: Vec<usize>,
    counts: Vec<usize>,
    work: Vec<usize>,
    trail: Vec<usize>,
    deduced: Vec<usize>,
}

impl Scratch {
    /// Tests exactly the declarative stop predicate. `rows` is the flattened
    /// `Engine::scrambler_rows` slice for the crib window ONLY, not the text prefix.
    /// Each row must be a fixed-point-free involution on the menu's alphabet.
    /// Panics on dimension mismatch; malformed permutations violate this internal
    /// API's precondition (checked in debug builds).
    pub(crate) fn test(&mut self, menu: &Menu, rows: &[u32], facts: &Facts) -> bool {
        let n = menu.size;
        assert_eq!(facts.board.len(), n);
        assert_eq!(rows.len(), menu.edges.len() * n);
        debug_assert!(rows
            .chunks_exact(n)
            .all(|row| row.iter().enumerate().all(|(x, &y)| {
                (y as usize) < n && y as usize != x && row[y as usize] as usize == x
            })));
        self.deduced_pairs.clear();
        self.deduced_self.clear();
        self.closures.resize(menu.components.len() * n * n, UNKNOWN);
        self.counts.resize(menu.components.len(), 0);
        self.counts.fill(0);
        self.work.resize(n, UNKNOWN);
        self.deduced.resize(n, UNKNOWN);
        self.deduced.fill(UNKNOWN);
        self.trail.clear();
        for (c, component) in menu.components.iter().enumerate() {
            let test = component.test_symbol;
            for y in 0..n {
                if facts.board[test] != UNKNOWN && facts.board[test] != y {
                    continue;
                }
                self.work.copy_from_slice(&facts.board);
                let mut pairs = facts.pairs;
                if !assign(&mut self.work, test, y, &mut pairs, facts.max_pairs)
                    || !propagate(
                        menu,
                        component,
                        rows,
                        &mut self.work,
                        &mut pairs,
                        facts.max_pairs,
                    )
                {
                    continue;
                }
                let offset = (c * n + self.counts[c]) * n;
                self.closures[offset..offset + n].copy_from_slice(&self.work);
                self.counts[c] += 1;
            }
            if self.counts[c] == 0 {
                return false;
            }
        }
        self.work.copy_from_slice(&facts.board);
        if !choose_closures(
            0,
            n,
            &self.counts,
            &self.closures,
            &mut self.work,
            &mut self.trail,
            facts.pairs,
            facts.max_pairs,
        ) {
            return false;
        }
        // Local uniqueness, not uniqueness after global combination: this is the
        // contract's conservative deduction rule. Include symmetric endpoints but
        // not unrelated facts carried in every stored closure.
        for (c, component) in menu.components.iter().enumerate() {
            if self.counts[c] == 1 {
                let closure = &self.closures[c * n * n..(c * n + 1) * n];
                for &x in &component.symbols {
                    let y = closure[x];
                    self.deduced[x] = y;
                    self.deduced[y] = x;
                }
            }
        }
        for (x, &y) in self.deduced.iter().enumerate() {
            if y == x {
                self.deduced_self.push(x);
            } else if x < y && y != UNKNOWN {
                self.deduced_pairs.push((x, y));
            }
        }
        true
    }
}

fn propagate(
    menu: &Menu,
    component: &Component,
    rows: &[u32],
    board: &mut [usize],
    pairs: &mut usize,
    max: usize,
) -> bool {
    loop {
        let mut changed = false;
        for &i in &component.edges {
            let e = menu.edges[i];
            let row = &rows[(e.index - menu.position) * menu.size..];
            for (x, y) in [(e.left, e.right), (e.right, e.left)] {
                if board[x] != UNKNOWN {
                    let partner = row[board[x]] as usize;
                    changed |= board[y] == UNKNOWN;
                    if !assign(board, y, partner, pairs, max) {
                        return false;
                    }
                }
            }
        }
        if !changed {
            return true;
        }
    }
}

// Closures can each be locally consistent yet conflict through partners outside
// their components or exceed the shared pair budget. Exhaustive backtracking over
// these small domains is necessary for exactness. Unassigned symbols can be self.
#[allow(clippy::too_many_arguments)]
fn choose_closures(
    c: usize,
    n: usize,
    counts: &[usize],
    closures: &[usize],
    board: &mut [usize],
    trail: &mut Vec<usize>,
    pairs: usize,
    max: usize,
) -> bool {
    if c == counts.len() {
        return true;
    }
    for choice in 0..counts[c] {
        let closure = &closures[(c * n + choice) * n..(c * n + choice + 1) * n];
        let mark = trail.len();
        let mut count = pairs;
        let mut compatible = true;
        for (x, &y) in closure.iter().enumerate() {
            if y == UNKNOWN {
                continue;
            }
            if board[x] == UNKNOWN {
                board[x] = y;
                trail.push(x);
                count += usize::from(x < y);
            } else if board[x] != y {
                compatible = false;
                break;
            }
        }
        let stop = compatible
            && count <= max
            && choose_closures(c + 1, n, counts, closures, board, trail, count, max);
        for &x in &trail[mark..] {
            board[x] = UNKNOWN;
        }
        trail.truncate(mark);
        if stop {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DefinitionSource, Direction, SlotConfiguration, TransformConfiguration};

    #[test]
    fn bombe_crash_rule_and_fixed_positions() {
        let text = [1, 2, 0, 1, 2];
        let crib = [0, 1];
        assert_eq!(admissible_positions(&text, &crib, None), Ok(vec![0, 1, 3]));
        assert_eq!(admissible_positions(&text, &crib, Some(1)), Ok(vec![1]));
        assert_eq!(
            admissible_positions(&text, &crib, Some(2)),
            Err(CribError::Crash { index: 2 })
        );
        assert_eq!(
            admissible_positions(&[0, 0], &[0], None),
            Err(CribError::NoPosition)
        );
        assert_eq!(
            admissible_positions(&text, &[], None),
            Err(CribError::Empty)
        );
        assert_eq!(
            admissible_positions(&[0], &crib, None),
            Err(CribError::TooLong)
        );
        assert_eq!(
            admissible_positions(&text, &crib, Some(usize::MAX)),
            Err(CribError::Position)
        );
    }

    #[test]
    fn bombe_menu_multigraph_components_and_degree_ties() {
        let menu = Menu::new(8, &[0, 1, 0, 4, 5], &[7, 7, 1, 2, 1, 5, 6], 2).unwrap();
        assert_eq!(
            menu.edges,
            vec![
                Edge {
                    left: 0,
                    right: 1,
                    index: 2
                },
                Edge {
                    left: 1,
                    right: 2,
                    index: 3
                },
                Edge {
                    left: 0,
                    right: 1,
                    index: 4
                },
                Edge {
                    left: 4,
                    right: 5,
                    index: 5
                },
                Edge {
                    left: 5,
                    right: 6,
                    index: 6
                },
            ]
        );
        assert_eq!(menu.components.len(), 2);
        assert_eq!(menu.components[0].symbols, vec![0, 1, 2]);
        assert_eq!(menu.components[0].test_symbol, 1);
        assert_eq!(menu.components[1].symbols, vec![4, 5, 6]);
        assert_eq!(menu.components[1].test_symbol, 5);
        let tie = Menu::new(4, &[2, 0], &[3, 1], 0).unwrap();
        assert_eq!(tie.components[0].test_symbol, 0);
        assert_eq!(tie.components[1].test_symbol, 2);
    }

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((self.0 >> 32) as usize) % n
        }
        fn shuffle(&mut self, values: &mut [usize]) {
            for i in (1..values.len()).rev() {
                let j = self.below(i + 1);
                values.swap(i, j);
            }
        }
        fn involution(&mut self, n: usize) -> Vec<u32> {
            let mut order: Vec<_> = (0..n).collect();
            self.shuffle(&mut order);
            let mut row = vec![0; n];
            for pair in order.chunks_exact(2) {
                row[pair[0]] = pair[1] as u32;
                row[pair[1]] = pair[0] as u32;
            }
            row
        }
    }

    // Independent enumeration: every involution, without propagation or menu logic.
    fn boards(n: usize) -> Vec<Vec<usize>> {
        fn visit(board: &mut [usize], out: &mut Vec<Vec<usize>>) {
            let Some(x) = board.iter().position(|&y| y == usize::MAX) else {
                out.push(board.to_vec());
                return;
            };
            board[x] = x;
            visit(board, out);
            for y in x + 1..board.len() {
                if board[y] == usize::MAX {
                    board[x] = y;
                    board[y] = x;
                    visit(board, out);
                    board[y] = usize::MAX;
                }
            }
            board[x] = usize::MAX;
        }
        let mut out = Vec::new();
        visit(&mut vec![usize::MAX; n], &mut out);
        out
    }

    #[test]
    fn bombe_exactness_against_exhaustive_boards() {
        let mut rng = Rng(0xb0be_1234_aabb_ccdd);
        let mut scratch = Scratch::default();
        let mut stops = 0;
        let mut rejections = 0;
        for n in [6, 8] {
            let all_boards = boards(n);
            for case in 0..1200 {
                let m = 1 + rng.below(10);
                let position = rng.below(4);
                let crib: Vec<_> = (0..m).map(|_| rng.below(n)).collect();
                let mut ciphertext: Vec<_> = (0..position + m).map(|_| rng.below(n)).collect();
                let rows: Vec<_> = (0..m).flat_map(|_| rng.involution(n)).collect();
                let max_pairs = rng.below(n / 2 + 1);
                let mutable: Vec<_> = (0..n).map(|_| rng.below(4) != 0).collect();
                let mut order: Vec<_> = (0..n).collect();
                rng.shuffle(&mut order);
                let fixed: Vec<_> = order[..2 * rng.below(max_pairs + 1)]
                    .chunks_exact(2)
                    .map(|p| (p[0], p[1]))
                    .collect();
                let facts = Facts::new(&mutable, &fixed, max_pairs).unwrap();
                let admissible: Vec<_> = all_boards
                    .iter()
                    .filter(|b| {
                        b.iter().enumerate().filter(|&(x, &y)| x < y).count() <= max_pairs
                            && fixed.iter().all(|&(x, y)| b[x] == y)
                            && (0..n).all(|x| {
                                mutable[x]
                                    || fixed.iter().any(|&(a, z)| x == a || x == z)
                                    || b[x] == x
                            })
                    })
                    .collect();
                // Half the cases start with a guaranteed witness; the others are random.
                if case % 2 == 0 {
                    let board = admissible[rng.below(admissible.len())];
                    for j in 0..m {
                        ciphertext[position + j] = board[rows[j * n + board[crib[j]]] as usize];
                    }
                }
                let solutions: Vec<_> = admissible
                    .iter()
                    .copied()
                    .filter(|b| {
                        (0..m).all(|j| {
                            b[rows[j * n + b[crib[j]]] as usize] == ciphertext[position + j]
                        })
                    })
                    .collect();
                // A crash is a rejection before a menu is built.
                if admissible_positions(&ciphertext, &crib, Some(position)).is_err() {
                    assert!(solutions.is_empty());
                    rejections += 1;
                    continue;
                }
                let menu = Menu::new(n, &crib, &ciphertext, position).unwrap();
                let stop = scratch.test(&menu, &rows, &facts);
                assert_eq!(stop, !solutions.is_empty(), "n={n}, case={case}");
                if stop {
                    stops += 1;
                } else {
                    rejections += 1;
                }
                for board in &solutions {
                    for &(x, y) in &scratch.deduced_pairs {
                        assert_eq!(board[x], y);
                    }
                    for &x in &scratch.deduced_self {
                        assert_eq!(board[x], x);
                    }
                }
                if !stop {
                    assert!(scratch.deduced_pairs.is_empty());
                    assert!(scratch.deduced_self.is_empty());
                    continue;
                }
                // Independently derive exactly the locally unique component closures.
                let mut expected = vec![None; n];
                for component in &menu.components {
                    let local: Vec<_> = admissible
                        .iter()
                        .copied()
                        .filter(|b| {
                            menu.edges
                                .iter()
                                .filter(|e| component.symbols.contains(&e.left))
                                .all(|e| {
                                    b[rows[(e.index - position) * n + b[e.left]] as usize]
                                        == e.right
                                })
                        })
                        .collect();
                    let first = local[0];
                    if local
                        .iter()
                        .all(|b| component.symbols.iter().all(|&x| b[x] == first[x]))
                    {
                        for &x in &component.symbols {
                            expected[x] = Some(first[x]);
                            expected[first[x]] = Some(x);
                        }
                    }
                }
                let pairs: Vec<_> = (0..n)
                    .filter_map(|x| expected[x].filter(|&y| x < y).map(|y| (x, y)))
                    .collect();
                let selves: Vec<_> = (0..n).filter(|&x| expected[x] == Some(x)).collect();
                assert_eq!(scratch.deduced_pairs, pairs, "n={n}, case={case}");
                assert_eq!(scratch.deduced_self, selves, "n={n}, case={case}");
            }
        }
        assert!(stops > 500 && rejections > 500);
    }

    #[test]
    fn bombe_unique_closure_includes_diagonal_partners_and_self_connections() {
        let menu = Menu::new(4, &[0], &[1], 0).unwrap();
        let rows = [1, 0, 3, 2];
        let mut scratch = Scratch::default();
        let facts = Facts::new(&[true; 4], &[(0, 2)], 2).unwrap();
        assert!(scratch.test(&menu, &rows, &facts));
        assert_eq!(scratch.deduced_pairs, vec![(0, 2), (1, 3)]);
        assert!(scratch.deduced_self.is_empty());
        let facts = Facts::new(&[true; 4], &[], 0).unwrap();
        assert!(scratch.test(&menu, &rows, &facts));
        assert!(scratch.deduced_pairs.is_empty());
        assert_eq!(scratch.deduced_self, vec![0, 1]);
    }

    #[test]
    fn bombe_components_must_be_jointly_compatible_and_share_the_budget() {
        let mut scratch = Scratch::default();
        let menu = Menu::new(4, &[0, 2], &[1, 3], 0).unwrap();
        let rows = [1, 0, 3, 2, 2, 3, 0, 1];
        let facts = Facts::new(&[true; 4], &[], 2).unwrap();
        // Both components have local closures, but no closures coexist.
        for (crib, text, row) in [(&[0][..], &[1][..], &rows[..4]), (&[2], &[3], &rows[4..])] {
            let local = Menu::new(4, crib, text, 0).unwrap();
            assert!(scratch.test(&local, row, &facts));
        }
        assert!(!scratch.test(&menu, &rows, &facts));
        assert!(scratch.deduced_pairs.is_empty());
        assert!(scratch.deduced_self.is_empty());

        let menu = Menu::new(8, &[0, 4], &[1, 5], 0).unwrap();
        let rows = [2, 3, 0, 1, 5, 4, 7, 6, 1, 0, 3, 2, 6, 7, 4, 5];
        let mutable = [false, true, true, false, false, true, true, false];
        let facts = Facts::new(&mutable, &[], 2).unwrap();
        assert!(scratch.test(&menu, &rows, &facts));
        assert_eq!(scratch.deduced_pairs, vec![(1, 2), (5, 6)]);
        assert_eq!(scratch.deduced_self, vec![0, 4]);
        let facts = Facts::new(&mutable, &[], 1).unwrap();
        assert!(!scratch.test(&menu, &rows, &facts));
        assert!(scratch.deduced_pairs.is_empty());
        assert!(scratch.deduced_self.is_empty());
    }

    #[test]
    fn bombe_true_keys_survive_enigma_i_and_m4_with_middle_steps() {
        let mut rng = Rng(0x1234_abcd_ebba_7654);
        let plaintext =
            "ANXOBERKOMMANDOXWETTERVORHERSAGEXFUERXDENXNORDATLANTIKXWINDXWESTXDREIXBISXVIERX";
        for id in ["enigma-i", "enigma-m4"] {
            let definition =
                DefinitionSource::parse_json(&format!(r#"{{"kind":"bundled","id":"{id}"}}"#))
                    .unwrap()
                    .resolve()
                    .unwrap();
            for trial in 0..16 {
                let mut order: Vec<_> = (0..26).collect();
                rng.shuffle(&mut order);
                let pairs: Vec<_> = order[..20]
                    .chunks_exact(2)
                    .map(|p| ((b'A' + p[0] as u8) as char, (b'A' + p[1] as u8) as char))
                    .collect();
                let mut board: Vec<_> = (0..26).collect();
                for p in order[..20].chunks_exact(2) {
                    board[p[0]] = p[1];
                    board[p[1]] = p[0];
                }
                let mut slots = vec![SlotConfiguration::new(
                    "reflector",
                    if id == "enigma-i" {
                        if rng.below(2) == 0 {
                            "B"
                        } else {
                            "C"
                        }
                    } else if rng.below(2) == 0 {
                        "Thin-B"
                    } else {
                        "Thin-C"
                    },
                    'A',
                    'A',
                )];
                if id == "enigma-m4" {
                    slots.push(SlotConfiguration::new(
                        "greek",
                        if rng.below(2) == 0 { "Beta" } else { "Gamma" },
                        (b'A' + rng.below(26) as u8) as char,
                        (b'A' + rng.below(26) as u8) as char,
                    ));
                }
                let mut wheels = ["I", "II", "III", "IV", "V"];
                for i in (1..wheels.len()).rev() {
                    let j = rng.below(i + 1);
                    wheels.swap(i, j);
                }
                for (i, name) in ["left", "middle", "right"].iter().enumerate() {
                    slots.push(SlotConfiguration::new(
                        *name,
                        wheels[i],
                        (b'A' + rng.below(26) as u8) as char,
                        (b'A' + rng.below(26) as u8) as char,
                    ));
                }
                let mut engine = TransformConfiguration::new(slots, pairs)
                    .resolve(&definition)
                    .unwrap()
                    .into_engine()
                    .unwrap();
                let mut stepping_probe = engine.clone();
                let middle = if id == "enigma-i" { 2 } else { 3 };
                let mut steps = Vec::new();
                for i in 0..plaintext.len() {
                    let before = stepping_probe.positions()[middle];
                    stepping_probe.transform("A", Direction::Encrypt).unwrap();
                    if before != stepping_probe.positions()[middle] {
                        steps.push(i);
                    }
                }
                let position = steps
                    .iter()
                    .copied()
                    .find(|&i| i >= 3 && i + 20 < plaintext.len())
                    .unwrap()
                    - 3;
                let crib_len = 30;
                assert!(steps
                    .iter()
                    .any(|&i| position < i && i < position + crib_len));
                let mut row_engine = engine.clone();
                let ciphertext = engine.transform(plaintext, Direction::Encrypt).unwrap();
                let text: Vec<_> = ciphertext.bytes().map(|b| (b - b'A') as usize).collect();
                let crib: Vec<_> = plaintext.as_bytes()[position..position + crib_len]
                    .iter()
                    .map(|b| (b - b'A') as usize)
                    .collect();
                let menu = Menu::new(26, &crib, &text, position).unwrap();
                let mut rows = Vec::new();
                row_engine
                    .scrambler_rows(position + crib_len, Direction::Encrypt, &mut rows)
                    .unwrap();
                let fixed = if trial % 2 == 0 {
                    vec![(order[0], order[1])]
                } else {
                    vec![]
                };
                let facts = Facts::new(&[true; 26], &fixed, 10).unwrap();
                let mut scratch = Scratch::default();
                assert!(
                    scratch.test(&menu, &rows[position * 26..], &facts),
                    "{id}, trial {trial}"
                );
                for &(x, y) in &scratch.deduced_pairs {
                    assert_eq!(board[x], y);
                }
                for &x in &scratch.deduced_self {
                    assert_eq!(board[x], x);
                }
            }
        }
    }

    /// Historical M4 message: Stefan Krah's M4 Project first break (U-264, Kptlt.
    /// Hartwig Looks), key and plaintext as recorded in
    /// `e2e/bomm/m4-u264-sinkov-trigram-correct/case.json` (source
    /// <https://www.bytereef.org/m4-project-first-break.html>, plaintext confirmed against
    /// the U-264 war diary). Encrypting the sourced plaintext with the sourced key gives
    /// the historical ciphertext, so cribs taken from the plaintext sit at their true
    /// positions.
    #[test]
    fn bombe_true_key_stops_on_the_historical_u264_message() {
        let plaintext = "VONVONJLOOKSJHFFTTTEINSEINSDREIZWOYYQNNSNEUNINHALTXXBEIANGRIFFUNTERWASSERGEDRUECKTYWABOSXLETZTERGEGNERSTANDNULACHTDREINULUHRMARQUANTONJOTANEUNACHTSEYHSDREIYZWOZWONULGRADYACHTSMYSTOSSENACHXEKNSVIERMBFAELLTYNNNNNNOOOVIERYSICHTEINSNULL";
        let stecker = ["AT", "BL", "DF", "GJ", "HM", "NW", "OP", "QY", "RZ", "VX"];
        let definition = DefinitionSource::parse_json(r#"{"kind":"bundled","id":"enigma-m4"}"#)
            .unwrap()
            .resolve()
            .unwrap();
        let slots = vec![
            SlotConfiguration::new("reflector", "Thin-B", 'A', 'A'),
            SlotConfiguration::new("greek", "Beta", 'V', 'A'),
            SlotConfiguration::new("left", "II", 'J', 'A'),
            SlotConfiguration::new("middle", "IV", 'N', 'A'),
            SlotConfiguration::new("right", "I", 'A', 'V'),
        ];
        let pairs: Vec<_> = stecker
            .iter()
            .map(|p| (p.as_bytes()[0] as char, p.as_bytes()[1] as char))
            .collect();
        let mut board: Vec<_> = (0..26).collect();
        for p in stecker {
            let (x, y) = (
                (p.as_bytes()[0] - b'A') as usize,
                (p.as_bytes()[1] - b'A') as usize,
            );
            board[x] = y;
            board[y] = x;
        }
        let engine = TransformConfiguration::new(slots, pairs)
            .resolve(&definition)
            .unwrap()
            .into_engine()
            .unwrap();
        let ciphertext = engine
            .clone()
            .transform(plaintext, Direction::Encrypt)
            .unwrap();
        let text: Vec<_> = ciphertext.bytes().map(|b| (b - b'A') as usize).collect();
        let mut rows = Vec::new();
        engine
            .clone()
            .scrambler_rows(text.len(), Direction::Encrypt, &mut rows)
            .unwrap();
        let facts = Facts::new(&[true; 26], &[], 10).unwrap();
        let mut scratch = Scratch::default();
        for crib in ["VONVONJLOOKS", "BEIANGRIFFUNTERWASSERGEDRUECKT"] {
            let position = plaintext.find(crib).unwrap();
            let crib: Vec<_> = crib.bytes().map(|b| (b - b'A') as usize).collect();
            assert!(admissible_positions(&text, &crib, Some(position)).is_ok());
            let menu = Menu::new(26, &crib, &text, position).unwrap();
            let window = &rows[position * 26..(position + crib.len()) * 26];
            assert!(scratch.test(&menu, window, &facts), "crib at {position}");
            for &(x, y) in &scratch.deduced_pairs {
                assert_eq!(board[x], y);
            }
            for &x in &scratch.deduced_self {
                assert_eq!(board[x], x);
            }
        }
    }
}

#[cfg(test)]
mod independent_contract_probes {
    use super::*;

    #[test] // S3, contract §2
    fn bombe_probe_drag_boundaries() {
        assert_eq!(
            admissible_positions(&[3, 0, 2, 1], &[0, 1], None),
            Ok(vec![0])
        );
        assert_eq!(
            admissible_positions(&[3, 0, 2, 1], &[0, 1], Some(2)),
            Err(CribError::Crash { index: 3 })
        );
        assert_eq!(admissible_positions(&[1], &[0], Some(0)), Ok(vec![0]));
        assert_eq!(
            admissible_positions(&[1], &[0], Some(1)),
            Err(CribError::Position)
        );
        assert_eq!(
            admissible_positions(&[], &[0], None),
            Err(CribError::TooLong)
        );
        assert_eq!(admissible_positions(&[], &[], None), Err(CribError::Empty));
    }

    #[test] // S2, contract §3: parallel-edge degree and component order
    fn bombe_probe_menu_degrees() {
        let menu = Menu::new(6, &[4, 2, 2, 0, 3], &[5, 5, 5, 3, 3, 1, 4], 2).unwrap();
        assert_eq!(
            menu.components
                .iter()
                .map(|c| (&c.symbols, c.test_symbol))
                .collect::<Vec<_>>(),
            vec![(&vec![0, 1], 0), (&vec![2, 3, 4, 5], 3)]
        );
        assert_eq!(
            menu.edges
                .iter()
                .map(|e| (e.left, e.right, e.index))
                .collect::<Vec<_>>(),
            vec![(4, 5, 2), (2, 3, 3), (2, 3, 4), (0, 1, 5), (3, 4, 6)]
        );
    }

    #[test] // S2, contract §§3–4: independent total-map enumeration
    fn bombe_probe_six_symbol_boards() {
        const N: usize = 6;
        // Enumerate ALL functions, retain involutions. No assign/closure/menu logic.
        let boards: Vec<Vec<usize>> = (0..N.pow(N as u32))
            .filter_map(|mut code| {
                let b: Vec<_> = (0..N)
                    .map(|_| {
                        let x = code % N;
                        code /= N;
                        x
                    })
                    .collect();
                (0..N).all(|x| b[b[x]] == x).then_some(b)
            })
            .collect();
        assert_eq!(boards.len(), 76);
        let rows: Vec<_> = boards
            .iter()
            .filter(|b| (0..N).all(|x| b[x] != x))
            .collect();
        assert_eq!(rows.len(), 15);
        let patterns = [
            (vec![0], vec![1]),
            (vec![0, 2], vec![1, 3]), // disconnected, partners can cross components
            (vec![0, 0], vec![1, 1]), // repeated edges
            (vec![0, 1], vec![1, 0]), // same symbols in both directions
            (vec![0, 1, 2], vec![1, 2, 0]), // cycle
            (vec![0, 2, 4], vec![1, 1, 1]), // test symbol is right endpoint
            (vec![0, 0, 4], vec![1, 2, 5]),
            (vec![4, 3, 2], vec![5, 4, 3]),
        ];
        let fixed_sets = [vec![], vec![(0, 5)], vec![(0, 5), (1, 4)]];
        let mut scratch = Scratch::default();
        let mut checked = 0;
        for (crib, cipher) in patterns {
            let mut text = vec![5, 5];
            text.extend(&cipher);
            let menu = Menu::new(N, &crib, &text, 2).unwrap();
            for r in 0..rows.len() {
                let scramblers: Vec<u32> = (0..crib.len())
                    .flat_map(|j| rows[(r + j * 7) % rows.len()].iter().map(|&x| x as u32))
                    .collect();
                for mask in 0..1 << N {
                    let mutable: Vec<_> = (0..N).map(|x| mask & (1 << x) != 0).collect();
                    for fixed in &fixed_sets {
                        for max in fixed.len()..=N / 2 {
                            let solutions: Vec<_> = boards
                                .iter()
                                .filter(|b| {
                                    b.iter().enumerate().filter(|&(x, &y)| x < y).count() <= max
                                        && fixed.iter().all(|&(x, y)| b[x] == y)
                                        && (0..N).all(|x| {
                                            mutable[x]
                                                || b[x] == x
                                                || fixed.iter().any(|&(a, z)| x == a || x == z)
                                        })
                                        && (0..crib.len()).all(|j| {
                                            b[scramblers[j * N + b[crib[j]]] as usize] == cipher[j]
                                        })
                                })
                                .collect();
                            let facts = Facts::new(&mutable, fixed, max).unwrap();
                            let stop = scratch.test(&menu, &scramblers, &facts);
                            assert_eq!(stop, !solutions.is_empty(),
                                "crib={crib:?} cipher={cipher:?} r={r} mask={mask} fixed={fixed:?} max={max}");
                            for b in solutions {
                                assert!(scratch.deduced_pairs.iter().all(|&(x, y)| b[x] == y));
                                assert!(scratch.deduced_self.iter().all(|&x| b[x] == x));
                            }
                            if !stop {
                                assert!(
                                    scratch.deduced_pairs.is_empty()
                                        && scratch.deduced_self.is_empty()
                                );
                            }
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 69_120);
    }
}
