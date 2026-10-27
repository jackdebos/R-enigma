//! Immutable sparse weighted dictionaries and exact overlapping Q32 scoring.

use crate::{Alphabet, FixedScore, MeasureError, MeasuredScore, ScoreError, SCALE};

const MAX_ENTRIES: usize = 250_000;
const MAX_NODES: usize = 1_000_000;
const MAX_WORD_LENGTH: usize = 256;

/// Dictionary construction failure; entry indices are zero-based.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrieError {
    /// Resource alphabet exceeds 256 scalars.
    AlphabetTooLarge(usize),
    /// Entry count is zero or exceeds 250,000.
    EntryCount(usize),
    /// A word is malformed or repeated.
    InvalidEntry {
        /// Position in the supplied entries.
        index: usize,
        /// Concrete failure, including scalar context when applicable.
        message: String,
    },
    /// Inserting this entry would exceed the root-inclusive node budget.
    NodeLimit {
        /// Position in the supplied entries.
        index: usize,
    },
}

impl std::fmt::Display for TrieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlphabetTooLarge(size) => {
                write!(f, "resource alphabet has {size} scalars; maximum is 256")
            }
            Self::EntryCount(size) => {
                write!(f, "dictionary entry count {size} must be in 1..=250000")
            }
            Self::InvalidEntry { index, message } => {
                write!(f, "dictionary entry {index}: {message}")
            }
            Self::NodeLimit { index } => write!(
                f,
                "dictionary entry {index} exceeds the root-inclusive trie node budget"
            ),
        }
    }
}

impl std::error::Error for TrieError {}

#[derive(Debug, Default)]
struct Node {
    // Sorted sparse edges permit bounded lookup without per-node hash tables.
    children: Vec<(char, usize)>,
    weight: Option<i32>,
}

/// Validated immutable dictionary; shared prefixes occupy one node each.
#[derive(Debug)]
pub struct TrieModel {
    alphabet: Alphabet,
    nodes: Vec<Node>,
    entry_count: usize,
    max_word_length: usize,
    identity: std::sync::Arc<()>,
}

/// One flattened node; edges are ordered by alphabet index, not Unicode scalar.
#[derive(Debug)]
pub struct FlatTrieNode {
    /// First edge in `FlatTrie::edges`.
    pub edge_start: u32,
    /// Number of children.
    pub edge_count: u32,
    /// Complete word weight, including zero and negative weights.
    pub terminal: Option<i32>,
}

/// One alphabet-indexed sparse edge.
#[derive(Debug)]
pub struct FlatTrieEdge {
    /// Ordered alphabet index.
    pub symbol: u8,
    /// Target node index.
    pub child: u32,
}

/// Validated device-independent sparse trie projection, rooted at node zero.
#[derive(Debug)]
pub struct FlatTrie {
    /// Root-inclusive nodes.
    pub nodes: Vec<FlatTrieNode>,
    /// Contiguous sorted child ranges.
    pub edges: Vec<FlatTrieEdge>,
    /// Longest word length.
    pub max_depth: usize,
}

impl TrieModel {
    /// Construct from caller-owned words and signed weights, without I/O or normalization.
    pub fn new(alphabet: Alphabet, entries: Vec<(Vec<char>, i32)>) -> Result<Self, TrieError> {
        Self::with_limits(alphabet, entries, MAX_ENTRIES, MAX_NODES)
    }

    // Private budgets let tests exercise growth guards without enormous fixtures.
    fn with_limits(
        alphabet: Alphabet,
        entries: Vec<(Vec<char>, i32)>,
        entry_limit: usize,
        node_limit: usize,
    ) -> Result<Self, TrieError> {
        if alphabet.len() > 256 {
            return Err(TrieError::AlphabetTooLarge(alphabet.len()));
        }
        if entries.is_empty() || entries.len() > entry_limit {
            return Err(TrieError::EntryCount(entries.len()));
        }
        // Validate lengths and membership before allocating trie nodes.
        for (index, (word, _)) in entries.iter().enumerate() {
            let invalid = |message| TrieError::InvalidEntry { index, message };
            if word.is_empty() || word.len() > MAX_WORD_LENGTH {
                return Err(invalid(format!(
                    "word length {} must be in 1..=256",
                    word.len()
                )));
            }
            for (position, &symbol) in word.iter().enumerate() {
                if alphabet.index_of(symbol).is_none() {
                    return Err(invalid(format!(
                        "symbol {symbol:?} at scalar {position} is outside the alphabet"
                    )));
                }
            }
        }
        let entry_count = entries.len();
        let mut nodes = vec![Node::default()];
        let mut max_word_length = 0;
        for (index, (word, weight)) in entries.into_iter().enumerate() {
            max_word_length = max_word_length.max(word.len());
            let mut current = 0;
            for symbol in word {
                current = match nodes[current]
                    .children
                    .binary_search_by_key(&symbol, |&(key, _)| key)
                {
                    Ok(edge) => nodes[current].children[edge].1,
                    Err(edge) => {
                        // Root and shared prefixes already count; check before allocating the next node.
                        if nodes.len() >= node_limit {
                            return Err(TrieError::NodeLimit { index });
                        }
                        let next = nodes.len();
                        nodes.push(Node::default());
                        nodes[current].children.insert(edge, (symbol, next));
                        next
                    }
                };
            }
            if nodes[current].weight.is_some() {
                return Err(TrieError::InvalidEntry {
                    index,
                    message: "duplicate word".into(),
                });
            }
            nodes[current].weight = Some(weight);
        }
        Ok(Self {
            alphabet,
            nodes,
            entry_count,
            max_word_length,
            identity: std::sync::Arc::new(()),
        })
    }

    /// Ordered resource alphabet for subsequent binding identity checks.
    pub fn alphabet(&self) -> &Alphabet {
        &self.alphabet
    }

    /// Number of unique complete words, including zero-weight words.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Number of trie nodes, including the root and shared prefixes once.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Stable allocation identity; retaining it prevents address reuse after model drop.
    pub fn table_identity(&self) -> std::sync::Arc<()> {
        std::sync::Arc::clone(&self.identity)
    }

    /// Longest validated word, at most 256 symbols.
    pub fn max_depth(&self) -> usize {
        self.max_word_length
    }

    /// Serialized accelerator size: two i64 header words, three per node, two per edge.
    /// Every non-root node has exactly one incoming edge.
    pub fn flattened_bytes(&self) -> u64 {
        16 + self.nodes.len() as u64 * 24 + self.nodes.len().saturating_sub(1) as u64 * 16
    }

    /// Flatten without changing node identity; preserve signed/zero terminals.
    /// Constructor budgets guarantee all offsets and children fit u32, and the
    /// constructor rejects alphabets over 256 scalars, so symbol indices fit u8.
    pub fn flatten(&self) -> Result<FlatTrie, TrieError> {
        if self.nodes.len() > MAX_NODES {
            return Err(TrieError::NodeLimit {
                index: self.entry_count.saturating_sub(1),
            });
        }
        let mut flat = FlatTrie {
            nodes: Vec::with_capacity(self.nodes.len()),
            edges: Vec::with_capacity(self.nodes.len() - 1),
            max_depth: self.max_word_length,
        };
        for node in &self.nodes {
            let mut children: Vec<_> = node
                .children
                .iter()
                .map(|&(symbol, child)| FlatTrieEdge {
                    symbol: self
                        .alphabet
                        .index_of(symbol)
                        .expect("validated trie symbol") as u8,
                    child: child as u32,
                })
                .collect();
            children.sort_unstable_by_key(|edge| edge.symbol);
            flat.nodes.push(FlatTrieNode {
                edge_start: flat.edges.len() as u32,
                edge_count: children.len() as u32,
                terminal: node.weight,
            });
            flat.edges.extend(children);
        }
        Ok(flat)
    }

    /// Sum every complete match at every scalar start, including prefixes and overlaps.
    /// Validate the entire text first; traversal allocates nothing and stops at the longest word.
    pub fn score(&self, text: &str) -> Result<MeasuredScore, MeasureError> {
        for (scalar_index, symbol) in text.chars().enumerate() {
            if self.alphabet.index_of(symbol).is_none() {
                return Err(MeasureError::InvalidSymbol {
                    symbol,
                    scalar_index,
                });
            }
        }
        if text.is_empty() {
            return Err(MeasureError::InsufficientSamples {
                required: 1,
                actual: 0,
            });
        }
        let mut raw = 0_i128;
        for (start, _) in text.char_indices() {
            let mut current = 0;
            for symbol in text[start..].chars().take(self.max_word_length) {
                let Ok(edge) = self.nodes[current]
                    .children
                    .binary_search_by_key(&symbol, |&(key, _)| key)
                else {
                    break;
                };
                current = self.nodes[current].children[edge].1;
                if let Some(weight) = self.nodes[current].weight {
                    raw = add_weight(raw, weight)?;
                }
            }
        }
        Ok(MeasuredScore::higher_is_better(scaled_score(raw)?))
    }
}

fn add_weight(raw: i128, weight: i32) -> Result<i128, ScoreError> {
    raw.checked_add(i128::from(weight))
        .ok_or(ScoreError::Overflow)
}

fn scaled_score(raw: i128) -> Result<FixedScore, ScoreError> {
    raw.checked_mul(SCALE)
        .map(FixedScore::from_units)
        .ok_or(ScoreError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Alphabet, MeasureError, ScoreError, SCALE};

    fn alphabet() -> Alphabet {
        Alphabet::new(vec!['A', 'B']).unwrap()
    }

    fn entries(words: &[(&str, i32)]) -> Vec<(Vec<char>, i32)> {
        words
            .iter()
            .map(|(word, weight)| (word.chars().collect(), *weight))
            .collect()
    }

    fn model(words: &[(&str, i32)]) -> TrieModel {
        TrieModel::new(alphabet(), entries(words)).unwrap()
    }

    #[test]
    fn flattened_edges_follow_alphabet_order_and_keep_terminals_and_limits() {
        let trie = TrieModel::new(
            Alphabet::new(vec!['B', 'A']).unwrap(),
            entries(&[("A", 0), ("AB", -7), ("B", i32::MIN)]),
        )
        .unwrap();
        let flat = trie.flatten().unwrap();
        assert_eq!(flat.max_depth, 2);
        assert_eq!(flat.nodes.len(), trie.node_count());
        assert_eq!(flat.edges.len() + 1, flat.nodes.len());
        let root = &flat.nodes[0];
        assert_eq!(root.terminal, None);
        let edges =
            &flat.edges[root.edge_start as usize..(root.edge_start + root.edge_count) as usize];
        assert_eq!(edges.iter().map(|e| e.symbol).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(flat.nodes[edges[0].child as usize].terminal, Some(i32::MIN));
        assert_eq!(flat.nodes[edges[1].child as usize].terminal, Some(0));
        assert_eq!(trie.flattened_bytes(), 16 + 24 * 4 + 16 * 3);
        let longest = model(&[(&"A".repeat(256), i32::MAX)]).flatten().unwrap();
        assert_eq!(longest.max_depth, 256);
        assert_eq!(longest.nodes.len(), 257);
        assert!(TrieModel::with_limits(alphabet(), entries(&[("AB", 1)]), 1, 2).is_err());
    }

    #[test]
    fn frozen_overlap_prefix_and_order_invariance() {
        let words = [("A", 1), ("AB", 3), ("BA", -2)];
        let trie = model(&words);
        let score = trie.score("ABA").unwrap();
        assert_eq!(score.measured().units(), 3 * SCALE);
        assert_eq!(score.ranking(), score.measured());
        assert_eq!(trie.entry_count(), 3);
        assert_eq!(trie.node_count(), 5);
        assert_eq!(trie.alphabet(), &alphabet());
        assert_eq!(
            model(&[("BA", -2), ("AB", 3), ("A", 1)]).score("ABA"),
            Ok(score)
        );
    }

    #[test]
    fn repeated_overlaps_zero_terminals_and_penalties() {
        assert_eq!(
            model(&[("A", 1), ("AA", 2), ("AAA", 3)])
                .score("AAAA")
                .unwrap()
                .measured()
                .units(),
            16 * SCALE
        );
        let trie = model(&[("A", 0), ("AB", -3)]);
        assert_eq!(trie.entry_count(), 2);
        assert_eq!(trie.score("ABAB").unwrap().measured().units(), -6 * SCALE);
        assert_eq!(trie.score("BBB").unwrap().measured().units(), 0);
        assert!(matches!(
            TrieModel::new(alphabet(), entries(&[("A", 0), ("A", 2)])),
            Err(TrieError::InvalidEntry { index: 1, .. })
        ));
    }

    #[test]
    fn exact_unicode_and_complete_validation() {
        let alphabet = Alphabet::new(vec!['é', 'e', '\u{301}', '🙂']).unwrap();
        let trie =
            TrieModel::new(alphabet.clone(), entries(&[("é", 4), ("e\u{301}", -1)])).unwrap();
        assert_eq!(
            trie.score("ée\u{301}🙂").unwrap().measured().units(),
            3 * SCALE
        );
        assert_eq!(trie.score("e").unwrap().measured().units(), 0);
        assert_eq!(
            trie.score("🙂éX"),
            Err(MeasureError::InvalidSymbol {
                symbol: 'X',
                scalar_index: 2
            })
        );
        assert_eq!(
            trie.score(""),
            Err(MeasureError::InsufficientSamples {
                required: 1,
                actual: 0
            })
        );
        for text in ["É", " é", "é\n"] {
            assert!(matches!(
                trie.score(text),
                Err(MeasureError::InvalidSymbol { .. })
            ));
        }
        assert_eq!(trie.alphabet(), &alphabet);
    }

    #[test]
    fn invalid_entries_and_word_length_boundary() {
        assert!(matches!(
            TrieModel::new(alphabet(), vec![]),
            Err(TrieError::EntryCount(0))
        ));
        for words in [
            entries(&[("", 1)]),
            entries(&[("C", 1)]),
            entries(&[("A", 1), ("A", -1)]),
        ] {
            assert!(matches!(
                TrieModel::new(alphabet(), words),
                Err(TrieError::InvalidEntry { .. })
            ));
        }
        let longest = vec!['A'; 256];
        let trie = TrieModel::new(alphabet(), vec![(longest, 1)]).unwrap();
        assert_eq!(trie.node_count(), 257);
        assert_eq!(
            trie.score(&"A".repeat(256)).unwrap().measured().units(),
            SCALE
        );
        assert!(matches!(
            TrieModel::new(alphabet(), vec![(vec!['A'; 257], 1)]),
            Err(TrieError::InvalidEntry { index: 0, .. })
        ));
    }

    #[test]
    fn alphabet_boundary_and_existing_alphabet_invariants() {
        let symbols: Vec<char> = (0..256).map(|n| char::from_u32(n).unwrap()).collect();
        assert!(TrieModel::new(
            Alphabet::new(symbols.clone()).unwrap(),
            vec![(vec!['A'], 0)]
        )
        .is_ok());
        let mut excess = symbols;
        excess.push('\u{100}');
        assert!(matches!(
            TrieModel::new(Alphabet::new(excess).unwrap(), vec![(vec!['A'], 0)]),
            Err(TrieError::AlphabetTooLarge(257))
        ));
        assert!(Alphabet::new(vec![]).is_err());
        assert!(Alphabet::new(vec!['A', 'A']).is_err());
    }

    #[test]
    fn private_limits_exercise_entry_and_root_inclusive_growth() {
        // Small private budgets exercise the same production guards, not a million-node run.
        assert_eq!(MAX_ENTRIES, 250_000);
        assert_eq!(MAX_NODES, 1_000_000);
        assert!(TrieModel::with_limits(alphabet(), entries(&[("A", 1), ("AB", 2)]), 2, 3).is_ok());
        assert!(matches!(
            TrieModel::with_limits(alphabet(), entries(&[("A", 1), ("AB", 2), ("B", 3)]), 2, 10),
            Err(TrieError::EntryCount(3))
        ));
        assert!(matches!(
            TrieModel::with_limits(alphabet(), entries(&[("A", 1)]), 2, 1),
            Err(TrieError::NodeLimit { index: 0 })
        ));
        let shared =
            TrieModel::with_limits(alphabet(), entries(&[("AB", 2), ("A", 1)]), 2, 3).unwrap();
        assert_eq!(shared.node_count(), 3);
        assert!(matches!(
            TrieModel::with_limits(alphabet(), entries(&[("AB", 2), ("BA", 1)]), 2, 4),
            Err(TrieError::NodeLimit { index: 1 })
        ));
    }

    #[test]
    fn signed_extrema_and_checked_arithmetic_guards() {
        for weight in [i32::MIN, i32::MAX, 0] {
            assert_eq!(
                model(&[("A", weight)])
                    .score("AA")
                    .unwrap()
                    .measured()
                    .units(),
                i128::from(weight) * 2 * SCALE
            );
        }
        assert_eq!(add_weight(i128::MAX, 1), Err(ScoreError::Overflow));
        assert_eq!(add_weight(i128::MIN, -1), Err(ScoreError::Overflow));
        assert_eq!(scaled_score(i128::MAX), Err(ScoreError::Overflow));
        assert_eq!(scaled_score(i128::MIN), Err(ScoreError::Overflow));
    }
}
