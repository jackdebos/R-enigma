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
    dense: Option<DenseWeights>,
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
        let dense = DenseWeights::new(&alphabet, order, &weights, unseen, false);
        Ok(Self {
            alphabet,
            order,
            weights,
            dense,
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
        self.score_windows(text, length)
    }

    /// [`Self::score`] for text already known to lie in this model's alphabet.
    pub(crate) fn score_valid(&self, text: &str) -> Result<MeasuredScore, MeasureError> {
        let length = u128::try_from(text.chars().count()).map_err(|_| ScoreError::Overflow)?;
        self.score_windows(text, length)
    }

    /// Score matching plaintext indices in this model's ordered alphabet. The caller
    /// must establish alphabet identity and supply one valid index per text scalar.
    pub(crate) fn score_indices(
        &self,
        text: &str,
        indices: &[u32],
    ) -> Result<MeasuredScore, MeasureError> {
        self.score_index_iter(indices.iter().copied())
            .unwrap_or_else(|| self.score_valid(text))
    }

    /// Dense-table [`Self::score_indices`] over streamed indices; `None` means this
    /// model has no dense table and the caller must score text sparsely instead.
    pub(crate) fn score_index_iter<I: ExactSizeIterator<Item = u32>>(
        &self,
        indices: I,
    ) -> Option<Result<MeasuredScore, MeasureError>> {
        let dense = self.dense.as_ref()?;
        Some(self.score_dense(dense, indices))
    }

    fn score_dense<I: ExactSizeIterator<Item = u32>>(
        &self,
        dense: &DenseWeights,
        indices: I,
    ) -> Result<MeasuredScore, MeasureError> {
        let length = u128::try_from(indices.len()).map_err(|_| ScoreError::Overflow)?;
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
        // Narrow sums are exact only while every partial sum provably fits i64.
        let sum = if fits_i64(windows, dense.max_abs) {
            self.sum_dense::<i64, _>(dense, indices)?
        } else {
            self.sum_dense::<i128, _>(dense, indices)?
        };
        let divisor = i128::try_from(windows).map_err(|_| ScoreError::Overflow)?;
        let measured = FixedScore::from_units(floor_div(sum, divisor)?);
        Ok(MeasuredScore::higher_is_better(measured))
    }

    /// Sum every window weight of at least `order` streamed indices, in Q32 units.
    fn sum_dense<A: WindowSum, I: Iterator<Item = u32>>(
        &self,
        dense: &DenseWeights,
        mut indices: I,
    ) -> Result<i128, ScoreError> {
        let width = self.alphabet.len();
        // Dense dimensions bound every radix key; indices are already validated.
        // A power-of-two ring longer than every order (1..=6): masked positions
        // need no bounds checks or wrap branches.
        const RING: usize = 8;
        let mut ring = [0_usize; RING];
        let mut key = 0;
        for (slot, index) in ring.iter_mut().zip(indices.by_ref().take(self.order)) {
            *slot = index as usize;
            key = key * width + *slot;
        }
        let mut sum = A::start(dense.weights[key]);
        for (written, incoming) in (self.order..).zip(indices) {
            let outgoing = ring[(written - self.order) & (RING - 1)];
            let incoming = incoming as usize;
            // Remove the highest radix digit before shifting; the key stays bounded.
            key = (key - outgoing * dense.high) * width + incoming;
            ring[written & (RING - 1)] = incoming;
            sum = sum.add(dense.weights[key])?;
        }
        Ok(sum.units())
    }

    fn score_windows(&self, text: &str, length: u128) -> Result<MeasuredScore, MeasureError> {
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
        let weight = |gram: &[char]| {
            #[cfg(test)]
            SPARSE_LOOKUPS.with(|count| count.set(count.get() + 1));
            self.weights.get(gram).copied().unwrap_or(self.unseen)
        };
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

/// Whether `windows` weights of magnitude at most `max_abs` sum within i64.
fn fits_i64(windows: u128, max_abs: u64) -> bool {
    u128::from(max_abs)
        .checked_mul(windows)
        .is_some_and(|bound| bound <= i64::MAX as u128)
}

/// Window-weight accumulator; the narrow kernel relies on [`fits_i64`].
trait WindowSum: Sized {
    fn start(weight: i64) -> Self;
    fn add(self, weight: i64) -> Result<Self, ScoreError>;
    fn units(self) -> i128;
}

impl WindowSum for i64 {
    fn start(weight: i64) -> Self {
        weight
    }
    fn add(self, weight: i64) -> Result<Self, ScoreError> {
        // Unchecked by design: the caller proved windows * max_abs <= i64::MAX.
        Ok(self + weight)
    }
    fn units(self) -> i128 {
        i128::from(self)
    }
}

impl WindowSum for i128 {
    fn start(weight: i64) -> Self {
        i128::from(weight)
    }
    fn add(self, weight: i64) -> Result<Self, ScoreError> {
        self.checked_add(i128::from(weight))
            .ok_or(ScoreError::Overflow)
    }
    fn units(self) -> i128 {
        self
    }
}

const DENSE_DATA_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Debug)]
struct DenseWeights {
    weights: Vec<i64>,
    /// Largest weight magnitude, the per-call bound input for [`fits_i64`].
    max_abs: u64,
    high: usize,
}

/// Admission is sized by `FixedScore` entries, so narrowing the stored weights
/// to i64 does not change which models get a dense table.
fn dense_dimensions(width: usize, order: usize) -> Option<(usize, usize)> {
    let exponent = u32::try_from(order.checked_sub(1)?).ok()?;
    let high = width.checked_pow(exponent)?;
    let entries = high.checked_mul(width)?;
    (entries.checked_mul(std::mem::size_of::<FixedScore>())? <= DENSE_DATA_LIMIT)
        .then_some((entries, high))
}

impl DenseWeights {
    fn new(
        alphabet: &Alphabet,
        order: usize,
        sparse: &HashMap<Vec<char>, FixedScore>,
        unseen: FixedScore,
        deny_reservation: bool,
    ) -> Option<Self> {
        let (entries, high) = dense_dimensions(alphabet.len(), order)?;
        // Any weight outside i64 keeps the model on exact sparse scoring.
        let narrow = |weight: FixedScore| i64::try_from(weight.units()).ok();
        let unseen = narrow(unseen)?;
        let mut max_abs = unseen.unsigned_abs();
        let mut weights = Vec::new();
        if deny_reservation || weights.try_reserve_exact(entries).is_err() {
            return None;
        }
        weights.resize(entries, unseen);
        for (gram, &weight) in sparse {
            let key = gram.iter().fold(0, |key, &symbol| {
                key * alphabet.len() + alphabet.index_of(symbol).expect("validated model gram")
            });
            let weight = narrow(weight)?;
            max_abs = max_abs.max(weight.unsigned_abs());
            weights[key] = weight;
        }
        Some(Self {
            weights,
            max_abs,
            high,
        })
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static SPARSE_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
    fn prevalidated_scores_match_validated_scores_and_sample_errors() {
        let model = NgramModel::new(
            Alphabet::new(vec!['λ', 'β', 'A']).unwrap(),
            3,
            vec![(vec!['λ', 'β', 'A'], 4), (vec!['A', 'A', 'A'], 1)],
        )
        .unwrap();
        for text in ["", "λ", "λβ", "λβA", "AAAλβAλβ", "βββ"] {
            assert_eq!(model.score_valid(text), model.score(text), "{text}");
        }
    }

    #[test]
    fn dense_scores_match_both_sparse_paths_for_all_orders_and_lengths() {
        for symbols in ["A", "BA", "λ界\u{301}", "\u{301}界λ"] {
            let alphabet = Alphabet::new(symbols.chars().collect()).unwrap();
            let s = &alphabet.symbols;
            for order in 1..=6 {
                for count in [3, u64::MAX] {
                    let mut entries = vec![(vec![s[0]; order], count)];
                    if s.len() > 1 {
                        entries.push((vec![s[1]; order], 1));
                        if order > 1 {
                            let mixed = s.iter().cycle().take(order).copied().collect();
                            entries.push((mixed, u64::MAX));
                        }
                    }
                    let model = NgramModel::new(alphabet.clone(), order, entries).unwrap();
                    assert!(model.dense.is_some());
                    for pattern in [
                        vec![s[0]],
                        vec![s[s.len() - 1]],
                        s.clone(),
                        vec![s[0], s[0], s[s.len() - 1], s[0], s[s.len() - 1]],
                    ] {
                        for length in 0..=3 * order + 1 {
                            let text: String = pattern.iter().cycle().take(length).collect();
                            let indices: Vec<_> = text
                                .chars()
                                .map(|c| alphabet.index_of(c).unwrap() as u32)
                                .collect();
                            let expected = model.score(&text);
                            assert_eq!(model.score_valid(&text), expected);
                            SPARSE_LOOKUPS.with(|count| count.set(0));
                            assert_eq!(
                                model.score_indices(&text, &indices),
                                expected,
                                "{symbols:?}, order {order}, text {text:?}"
                            );
                            SPARSE_LOOKUPS.with(|count| assert_eq!(count.get(), 0));
                        }
                    }
                    // Public validation must still precede insufficient samples.
                    for text in ["X".to_owned(), format!("{symbols}X")] {
                        assert_eq!(
                            model.score(&text),
                            Err(MeasureError::InvalidSymbol {
                                symbol: 'X',
                                scalar_index: text.chars().count() - 1,
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rolling_scores_match_sparse_at_width_and_ring_boundaries() {
        for width in [1, 5, 256] {
            let symbols: Vec<_> = (0..width)
                .map(|i| char::from_u32(0x400 + i as u32).unwrap())
                .collect();
            for order in 1..=6 {
                let mut entries = vec![(vec![symbols[0]; order], u64::MAX)];
                if width > 1 {
                    entries.push((vec![symbols[width - 1]; order], 3));
                    if order > 1 {
                        entries.push(((0..order).map(|i| symbols[i % width]).collect(), 7));
                    }
                }
                let model =
                    NgramModel::new(Alphabet::new(symbols.clone()).unwrap(), order, entries)
                        .unwrap();
                let admitted = dense_dimensions(width, order).is_some();
                assert_eq!(model.dense.is_some(), admitted);
                for length in [0, order - 1, order, order + 1, 7 * order + 3, 521] {
                    for pattern in [
                        vec![0],
                        vec![(width - 1) as u32],
                        (0..width as u32).collect(),
                        vec![0, (width - 1) as u32, 0, 0, (width - 1) as u32],
                        pseudo_random_indices(width, 31, 17),
                    ] {
                        let indices: Vec<_> = pattern.into_iter().cycle().take(length).collect();
                        let text: String = indices.iter().map(|&i| symbols[i as usize]).collect();
                        let expected = model.score(&text);
                        SPARSE_LOOKUPS.with(|count| count.set(0));
                        let streamed = model.score_index_iter(indices.iter().copied());
                        assert_eq!(streamed, admitted.then(|| expected.clone()));
                        SPARSE_LOOKUPS.with(|count| assert_eq!(count.get(), 0));
                        assert_eq!(
                            model.score_indices(&text, &indices),
                            expected,
                            "width {width}, order {order}, length {length}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn oversized_models_and_denied_reservations_keep_sparse_scoring() {
        let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect()).unwrap();
        let trigram = NgramModel::new(alphabet.clone(), 3, vec![(vec!['A'; 3], 1)]).unwrap();
        assert_eq!(
            trigram.dense.as_ref().unwrap().weights.len() * std::mem::size_of::<FixedScore>(),
            281_216
        );
        for order in 3..=6 {
            let mut model =
                NgramModel::new(alphabet.clone(), order, vec![(vec!['A'; order], 1)]).unwrap();
            assert_eq!(model.dense.is_some(), order == 3);
            if order == 3 {
                model.dense =
                    DenseWeights::new(&model.alphabet, order, &model.weights, model.unseen, true);
                assert!(model.dense.is_none());
            }
            let text = format!("{}BAAAA", "A".repeat(order));
            let indices: Vec<_> = text
                .chars()
                .map(|c| alphabet.index_of(c).unwrap() as u32)
                .collect();
            let expected = model.score(&text);
            assert_eq!(model.score_valid(&text), expected);
            SPARSE_LOOKUPS.with(|count| count.set(0));
            assert_eq!(model.score_indices(&text, &indices), expected);
            SPARSE_LOOKUPS.with(|count| assert_eq!(count.get(), text.len() - order + 1));
            for length in 0..order {
                let short = "A".repeat(length);
                assert_eq!(
                    model.score_indices(&short, &vec![0; length]),
                    model.score(&short)
                );
            }
        }
    }

    /// Deterministic LCG index sequence in `0..width`.
    fn pseudo_random_indices(width: usize, length: usize, seed: u64) -> Vec<u32> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ((state >> 33) % width as u64) as u32
            })
            .collect()
    }

    #[test]
    fn index_iterator_matches_slice_and_text_scores_or_reports_sparse() {
        for (width, order) in [(1, 1), (1, 4), (2, 2), (2, 6), (5, 3), (26, 1), (26, 3)] {
            let symbols: Vec<char> = (0..width)
                .map(|i| char::from_u32(0x3b1 + i as u32).unwrap())
                .collect();
            let alphabet = Alphabet::new(symbols.clone()).unwrap();
            let entries: Vec<(Vec<char>, u64)> = (0..width.min(40) as u64)
                .map(|seed| {
                    let gram = pseudo_random_indices(width, order, seed + 11);
                    (
                        gram.iter().map(|&i| symbols[i as usize]).collect(),
                        seed + 1,
                    )
                })
                .collect::<HashMap<_, _>>()
                .into_iter()
                .collect();
            let model = NgramModel::new(alphabet, order, entries).unwrap();
            assert!(model.dense.is_some());
            for length in [0, order - 1, order, order + 1, 64, 301] {
                for seed in [3, 0x9e37_79b9] {
                    let indices = pseudo_random_indices(width, length, seed);
                    let text: String = indices.iter().map(|&i| symbols[i as usize]).collect();
                    let streamed = (0..indices.len()).map(|i| indices[i]);
                    let result = model.score_index_iter(streamed).unwrap();
                    assert_eq!(result, model.score_indices(&text, &indices));
                    assert_eq!(result, model.score(&text), "{width}, {order}, {length}");
                    if length < order {
                        assert_eq!(
                            result,
                            Err(MeasureError::InsufficientSamples {
                                required: order as u128,
                                actual: length as u128
                            })
                        );
                    } else {
                        assert!(result.is_ok());
                    }
                }
            }
        }
        let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect()).unwrap();
        let sparse = NgramModel::new(alphabet, 4, vec![(vec!['A'; 4], 1)]).unwrap();
        assert!(sparse.dense.is_none());
        assert!(sparse.score_index_iter([0_u32; 8].into_iter()).is_none());
    }

    #[test]
    fn narrow_sum_bound_admits_exactly_up_to_i64_max() {
        let max = i64::MAX as u64;
        assert!(fits_i64(1, max));
        assert!(!fits_i64(2, max));
        assert!(!fits_i64(1, max + 1));
        assert!(fits_i64(7, max / 7));
        assert!(!fits_i64(7, max / 7 + 1));
        assert!(fits_i64(u128::MAX, 0));
        assert!(!fits_i64(u128::MAX, 1));
        assert!(fits_i64(0, u64::MAX));
    }

    #[test]
    fn dense_table_requires_i64_weights_and_records_their_largest_magnitude() {
        let alphabet = alphabet();
        let unseen = FixedScore::from_units(-3);
        let mut sparse = HashMap::new();
        sparse.insert(vec!['A'], FixedScore::from_units(i128::from(i64::MIN)));
        let dense = DenseWeights::new(&alphabet, 1, &sparse, unseen, false).unwrap();
        assert_eq!(dense.weights, [i64::MIN, -3]);
        assert_eq!(dense.max_abs, 1 << 63);
        sparse.insert(vec!['B'], FixedScore::from_units(i128::from(i64::MIN) - 1));
        assert!(DenseWeights::new(&alphabet, 1, &sparse, unseen, false).is_none());
        let too_high = FixedScore::from_units(i128::from(i64::MAX) + 1);
        assert!(DenseWeights::new(&alphabet, 1, &HashMap::new(), too_high, false).is_none());
        let unseen = FixedScore::from_units(i128::from(i64::MAX));
        let dense = DenseWeights::new(&alphabet, 1, &HashMap::new(), unseen, false).unwrap();
        assert_eq!(dense.max_abs, i64::MAX as u64);
    }

    #[test]
    fn narrow_and_wide_window_sums_match_an_independent_sparse_sum() {
        for (width, order) in [(1, 1), (1, 5), (2, 6), (5, 3), (26, 1), (26, 3)] {
            let symbols: Vec<char> = (0..width)
                .map(|i| char::from_u32(0x5d0 + i as u32).unwrap())
                .collect();
            let entries: Vec<(Vec<char>, u64)> = (0..width.min(40) as u64)
                .map(|seed| {
                    let gram = pseudo_random_indices(width, order, seed + 5);
                    let gram = gram.iter().map(|&i| symbols[i as usize]).collect();
                    (
                        gram,
                        if seed % 2 == 0 {
                            u64::MAX - seed
                        } else {
                            seed + 1
                        },
                    )
                })
                .collect::<HashMap<_, _>>()
                .into_iter()
                .collect();
            let model =
                NgramModel::new(Alphabet::new(symbols.clone()).unwrap(), order, entries).unwrap();
            let dense = model.dense.as_ref().unwrap();
            for length in [order, order + 1, 64, 301] {
                let indices = pseudo_random_indices(width, length, 0x51ed);
                let grams: Vec<char> = indices.iter().map(|&i| symbols[i as usize]).collect();
                let expected = grams.windows(order).try_fold(0_i128, |sum, gram| {
                    let weight = model.weights.get(gram).copied().unwrap_or(model.unseen);
                    sum.checked_add(weight.units())
                });
                let expected = expected.unwrap();
                let narrow = model.sum_dense::<i64, _>(dense, indices.iter().copied());
                let wide = model.sum_dense::<i128, _>(dense, indices.iter().copied());
                assert_eq!(narrow, Ok(expected), "{width}, {order}, {length}");
                assert_eq!(wide, Ok(expected), "{width}, {order}, {length}");
            }
        }
    }

    #[test]
    fn dense_dimensions_check_payload_ceiling_and_arithmetic_overflow() {
        let entries = DENSE_DATA_LIMIT / std::mem::size_of::<FixedScore>();
        assert_eq!(dense_dimensions(2, 18), Some((entries, entries / 2)));
        assert_eq!(dense_dimensions(2, 19), None);
        assert_eq!(dense_dimensions(usize::MAX, 6), None);
        assert_eq!(dense_dimensions(usize::MAX, 1), None);
        if usize::BITS > u32::BITS {
            assert_eq!(dense_dimensions(1, usize::MAX), None);
        }
        assert_eq!(dense_dimensions(1, 0), None);
        for order in 1..=6 {
            assert_eq!(dense_dimensions(1, order), Some((1, 1)));
        }
    }

    #[test]
    fn later_entry_validation_still_precedes_duplicate_detection() {
        let entries = vec![(vec!['A'], 1), (vec!['A'], 2), (vec!['B'], 0)];
        assert_eq!(
            NgramModel::new(alphabet(), 1, entries).unwrap_err(),
            NgramError::InvalidEntry {
                index: 2,
                message: "count must be positive".into(),
            }
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
