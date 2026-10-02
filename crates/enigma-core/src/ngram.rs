//! Typed sparse n-gram models and overlapping Sinkov mean-ln scoring.

use crate::{
    floor_div, ln_ratio_q32, Alphabet, FixedScore, MeasureError, MeasuredScore, ScoreError,
};
use std::collections::HashMap;

/// Typed construction failure; entry indices are zero-based.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NgramError {
    /// Order outside the supported range 1–6.
    InvalidOrder(usize),
    /// Alphabet exceeds 256 scalars.
    AlphabetTooLarge(usize),
    /// Entry count is zero or exceeds 250,000.
    EntryCount(usize),
    /// A malformed or repeated gram, or nonpositive count.
    InvalidEntry {
        /// Position in the supplied entries.
        index: usize,
        /// Concrete validation failure, including symbol context when applicable.
        message: String,
    },
    /// Checked model arithmetic failed.
    Arithmetic(ScoreError),
}

impl From<ScoreError> for NgramError {
    fn from(error: ScoreError) -> Self {
        Self::Arithmetic(error)
    }
}

impl std::fmt::Display for NgramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOrder(order) => write!(f, "ngram order {order} must be in 1..=6"),
            Self::AlphabetTooLarge(size) => {
                write!(f, "resource alphabet has {size} scalars; maximum is 256")
            }
            Self::EntryCount(size) => write!(f, "ngram entry count {size} must be in 1..=250000"),
            Self::InvalidEntry { index, message } => write!(f, "ngram entry {index}: {message}"),
            Self::Arithmetic(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for NgramError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Arithmetic(error) => Some(error),
            _ => None,
        }
    }
}

/// Immutable validated sparse model; log weights are computed once at construction.
#[derive(Debug)]
pub struct NgramModel {
    alphabet: Alphabet,
    order: usize,
    weights: HashMap<Vec<char>, FixedScore>,
    unseen: FixedScore,
    total: u128,
    minimum: u64,
}

impl NgramModel {
    /// Construct from typed entries, not embedded request resources or JSON.
    /// Validate bounds and entries before allocating the sparse weight map.
    pub fn new(
        alphabet: Alphabet,
        order: usize,
        entries: Vec<(Vec<char>, u64)>,
    ) -> Result<Self, NgramError> {
        if !(1..=6).contains(&order) {
            return Err(NgramError::InvalidOrder(order));
        }
        if alphabet.len() > 256 {
            return Err(NgramError::AlphabetTooLarge(alphabet.len()));
        }
        if entries.is_empty() || entries.len() > 250_000 {
            return Err(NgramError::EntryCount(entries.len()));
        }
        let mut total = 0_u128;
        let mut minimum = u64::MAX;
        for (index, (gram, count)) in entries.iter().enumerate() {
            let invalid = |message| NgramError::InvalidEntry { index, message };
            if gram.len() != order {
                return Err(invalid(format!(
                    "expected {order} scalars, got {}",
                    gram.len()
                )));
            }
            if *count == 0 {
                return Err(invalid("count must be positive".into()));
            }
            for (position, symbol) in gram.iter().enumerate() {
                if alphabet.index_of(*symbol).is_none() {
                    return Err(invalid(format!(
                        "symbol {symbol:?} at scalar {position} is outside the alphabet"
                    )));
                }
            }
            total = total
                .checked_add(u128::from(*count))
                .ok_or(ScoreError::Overflow)?;
            minimum = minimum.min(*count);
        }
        let floor_total = total.checked_mul(2).ok_or(ScoreError::Overflow)?;
        let unseen = ln_ratio_q32(u128::from(minimum), floor_total)?;
        let mut weights = HashMap::with_capacity(entries.len());
        for (index, (gram, count)) in entries.into_iter().enumerate() {
            match weights.entry(gram) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(NgramError::InvalidEntry {
                        index,
                        message: "duplicate gram".into(),
                    })
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(ln_ratio_q32(u128::from(count), total)?);
                }
            }
        }
        Ok(Self {
            alphabet,
            order,
            weights,
            unseen,
            total,
            minimum,
        })
    }

    /// Ordered resource alphabet, for subsequent binding identity checks.
    pub fn alphabet(&self) -> &Alphabet {
        &self.alphabet
    }
    /// Validated gram order.
    pub fn order(&self) -> usize {
        self.order
    }
    /// Number of explicitly listed grams (not the alphabet power).
    pub fn entry_count(&self) -> usize {
        self.weights.len()
    }
    /// Checked sum of all listed positive counts.
    pub fn total_count(&self) -> u128 {
        self.total
    }
    /// Minimum listed positive count used for the unseen floor.
    pub fn minimum_count(&self) -> u64 {
        self.minimum
    }

    /// Score every overlapping scalar window using prequantized natural logs.
    /// Validate all membership before sample sufficiency; no normalization or padding.
    pub fn score(&self, text: &str) -> Result<MeasuredScore, MeasureError> {
        let mut length = 0_u128;
        for (scalar_index, symbol) in text.chars().enumerate() {
            if self.alphabet.index_of(symbol).is_none() {
                return Err(MeasureError::InvalidSymbol {
                    symbol,
                    scalar_index,
                });
            }
            length = length.checked_add(1).ok_or(ScoreError::Overflow)?;
        }
        let required = u128::try_from(self.order).map_err(|_| ScoreError::Overflow)?;
        if length < required {
            return Err(MeasureError::InsufficientSamples {
                required,
                actual: length,
            });
        }
        let windows = length
            .checked_sub(required)
            .and_then(|n| n.checked_add(1))
            .ok_or(ScoreError::Overflow)?;
        let mut storage = ['\0'; 6];
        let window = &mut storage[..self.order];
        let mut symbols = text.chars();
        for (slot, symbol) in window.iter_mut().zip(symbols.by_ref()) {
            *slot = symbol;
        }
        let weight = |gram: &[char]| self.weights.get(gram).copied().unwrap_or(self.unseen);
        let mut sum = weight(window);
        for symbol in symbols {
            window.rotate_left(1);
            window[self.order - 1] = symbol;
            sum = sum.checked_add(weight(window))?;
        }
        let divisor = i128::try_from(windows).map_err(|_| ScoreError::Overflow)?;
        let measured = FixedScore::from_units(floor_div(sum.units(), divisor)?);
        Ok(MeasuredScore::higher_is_better(measured))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alphabet() -> Alphabet {
        Alphabet::new(vec!['A', 'B']).unwrap()
    }

    fn example() -> NgramModel {
        NgramModel::new(
            alphabet(),
            2,
            vec![
                (vec!['A', 'A'], 2),
                (vec!['A', 'B'], 1),
                (vec!['B', 'A'], 1),
            ],
        )
        .unwrap()
    }

    #[test]
    fn construction_preserves_order_and_positive_count_metadata() {
        let alphabet = Alphabet::new(vec!['B', 'A']).unwrap();
        let model =
            NgramModel::new(alphabet.clone(), 1, vec![(vec!['A'], 3), (vec!['B'], 2)]).unwrap();
        assert_eq!(model.alphabet(), &alphabet);
        assert_eq!(model.order(), 1);
        assert_eq!(model.entry_count(), 2);
        assert_eq!(model.total_count(), 5);
        assert_eq!(model.minimum_count(), 2);
    }

    #[test]
    fn rejects_invalid_order_alphabet_and_entry_count_before_construction() {
        for order in [0, 7] {
            assert!(matches!(
                NgramModel::new(alphabet(), order, vec![]),
                Err(NgramError::InvalidOrder(_))
            ));
        }
        assert!(matches!(
            NgramModel::new(alphabet(), 1, vec![]),
            Err(NgramError::EntryCount(0))
        ));
        let entries = vec![(vec!['A'], 1); 250_001];
        assert!(matches!(
            NgramModel::new(alphabet(), 1, entries),
            Err(NgramError::EntryCount(250_001))
        ));
        let oversized =
            Alphabet::new((0..257).map(|i| char::from_u32(i).unwrap()).collect()).unwrap();
        assert!(matches!(
            NgramModel::new(oversized, 1, vec![(vec!['A'], 1)]),
            Err(NgramError::AlphabetTooLarge(257))
        ));
    }

    #[test]
    fn rejects_bad_grams_counts_and_duplicates_with_entry_context() {
        for entries in [
            vec![(vec!['A'], 1)],
            vec![(vec!['A', 'λ'], 1)],
            vec![(vec!['A', 'B'], 0)],
            vec![(vec!['A', 'B'], 1), (vec!['A', 'B'], 2)],
        ] {
            let expected_index = entries.len() - 1;
            match NgramModel::new(alphabet(), 2, entries) {
                Err(NgramError::InvalidEntry { index, message }) => {
                    assert_eq!(index, expected_index);
                    assert!(!message.is_empty());
                }
                other => panic!("expected an invalid entry, got {other:?}"),
            }
        }
    }

    #[test]
    fn known_unseen_and_overlapping_scores_match_contract_goldens() {
        let model = example();
        for (text, expected) in [
            ("ABA", -5_954_088_944),
            ("BB", -8_931_133_416),
            ("AAB", -4_465_566_708),
            ("AAA", -2_977_044_472),
        ] {
            let result = model.score(text).unwrap();
            assert_eq!(result.measured().units(), expected);
            assert_eq!(result.ranking(), result.measured());
            assert_eq!(model.score(text), Ok(result));
        }
    }

    #[test]
    fn membership_is_checked_before_insufficient_samples_at_scalar_indices() {
        let model = NgramModel::new(
            Alphabet::new(vec!['λ', 'β']).unwrap(),
            2,
            vec![(vec!['λ', 'β'], 1)],
        )
        .unwrap();
        for text in ["", "λ"] {
            assert_eq!(
                model.score(text),
                Err(MeasureError::InsufficientSamples {
                    required: 2,
                    actual: text.chars().count() as u128
                })
            );
        }
        assert_eq!(
            model.score("λβX"),
            Err(MeasureError::InvalidSymbol {
                symbol: 'X',
                scalar_index: 2
            })
        );
        assert_eq!(
            model.score("X"),
            Err(MeasureError::InvalidSymbol {
                symbol: 'X',
                scalar_index: 0
            })
        );
        assert_eq!(
            model.score("λβλβ").unwrap().measured().units(),
            -992_348_158
        );
    }

    #[test]
    fn maximum_counts_use_u128_totals_and_unseen_floor_without_renormalization() {
        let model = NgramModel::new(
            alphabet(),
            1,
            vec![(vec!['A'], u64::MAX), (vec!['B'], u64::MAX)],
        )
        .unwrap();
        assert_eq!(model.total_count(), 2 * u128::from(u64::MAX));
        assert_eq!(model.minimum_count(), u64::MAX);
        assert_eq!(
            model.score("AB").unwrap().measured().units(),
            -2_977_044_472
        );
        let sparse = NgramModel::new(alphabet(), 1, vec![(vec!['A'], 1)]).unwrap();
        assert_eq!(sparse.score("A").unwrap().measured().units(), 0);
        assert_eq!(
            sparse.score("B").unwrap().measured().units(),
            -2_977_044_472
        );
    }

    #[test]
    fn sixth_order_is_sparse_and_combining_scalars_are_exact() {
        let alphabet = Alphabet::new(vec!['e', '\u{301}']).unwrap();
        let gram = vec!['e', '\u{301}', 'e', '\u{301}', 'e', '\u{301}'];
        let model = NgramModel::new(alphabet, 6, vec![(gram, 1)]).unwrap();
        assert_eq!(model.entry_count(), 1);
        assert_eq!(
            model
                .score("e\u{301}e\u{301}e\u{301}")
                .unwrap()
                .measured()
                .units(),
            0
        );
        assert!(matches!(
            model.score("ééé"),
            Err(MeasureError::InvalidSymbol {
                scalar_index: 0,
                ..
            })
        ));
    }
}
