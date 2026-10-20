//! Resource-free monogram measures with explicit measured and ranking values.

use crate::{floor_div, integer_log2_q48, Alphabet, FixedScore, ScoreError, SCALE};

/// Input validation or checked arithmetic failure while measuring text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeasureError {
    /// A scalar is outside the alphabet; the index is zero-based, not a byte offset.
    InvalidSymbol {
        /// Rejected Unicode scalar.
        symbol: char,
        /// Position among input Unicode scalars.
        scalar_index: usize,
    },
    /// A measure does not have enough scalar samples.
    InsufficientSamples {
        /// Minimum required scalar count.
        required: u128,
        /// Validated input scalar count.
        actual: u128,
    },
    /// Arithmetic domain or overflow failure from the fixed-point foundation.
    Arithmetic(ScoreError),
}

impl From<ScoreError> for MeasureError {
    fn from(error: ScoreError) -> Self {
        Self::Arithmetic(error)
    }
}

impl std::fmt::Display for MeasureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSymbol {
                symbol,
                scalar_index,
            } => {
                write!(
                    formatter,
                    "symbol {symbol:?} at scalar index {scalar_index} is outside the alphabet"
                )
            }
            Self::InsufficientSamples { required, actual } => {
                write!(
                    formatter,
                    "measure requires at least {required} scalars; got {actual}"
                )
            }
            Self::Arithmetic(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MeasureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Arithmetic(error) => Some(error),
            _ => None,
        }
    }
}

/// A measured Q32 value and its per-measure higher-is-better ranking orientation.
/// Only trie stages compose rankings with a base (search-passes §9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasuredScore {
    measured: FixedScore,
    ranking: FixedScore,
}

impl MeasuredScore {
    pub(crate) const fn higher_is_better(measured: FixedScore) -> Self {
        Self {
            measured,
            ranking: measured,
        }
    }

    /// Trie stages retain the trie measurement while adding a base ranking (§9.4).
    pub(crate) fn with_ranking_base(self, base: FixedScore) -> Result<Self, MeasureError> {
        Ok(Self {
            measured: self.measured,
            ranking: base.checked_add(self.ranking)?,
        })
    }

    /// Read the measured value (entropy is nonnegative bits, not negative bits).
    pub const fn measured(self) -> FixedScore {
        self.measured
    }

    /// Read the higher-is-better ranking, including a trie stage's base if any.
    pub const fn ranking(self) -> FixedScore {
        self.ranking
    }
}

fn monograms(
    alphabet: &Alphabet,
    text: &str,
    required: u128,
) -> Result<(Vec<u128>, u128), MeasureError> {
    let mut counts = vec![0_u128; alphabet.len()];
    let mut length = 0_u128;
    for (scalar_index, symbol) in text.chars().enumerate() {
        let index = alphabet
            .index_of(symbol)
            .ok_or(MeasureError::InvalidSymbol {
                symbol,
                scalar_index,
            })?;
        counts[index] = counts[index].checked_add(1).ok_or(ScoreError::Overflow)?;
        length = length.checked_add(1).ok_or(ScoreError::Overflow)?;
    }
    sufficient(counts, length, required)
}

/// Counts prevalidated alphabet indices, skipping the per-symbol membership lookup.
fn index_monograms<I: ExactSizeIterator<Item = u32>>(
    width: usize,
    indices: I,
    required: u128,
) -> Result<(Vec<u128>, u128), MeasureError> {
    // The exact length bounds every count by `usize::MAX`, so no u128 count overflows.
    let length = u128::try_from(indices.len()).map_err(|_| ScoreError::Overflow)?;
    let mut counts = vec![0_u128; width];
    for index in indices {
        counts[index as usize] += 1;
    }
    sufficient(counts, length, required)
}

fn sufficient(
    counts: Vec<u128>,
    length: u128,
    required: u128,
) -> Result<(Vec<u128>, u128), MeasureError> {
    if length < required {
        return Err(MeasureError::InsufficientSamples {
            required,
            actual: length,
        });
    }
    Ok((counts, length))
}

/// Alphabet-scaled monogram IC, quantized once after the exact rational product.
/// Membership is validated before sample sufficiency; requires at least two scalars.
/// Measured and ranking values are identical and higher is better.
pub fn index_of_coincidence(
    alphabet: &Alphabet,
    text: &str,
) -> Result<MeasuredScore, MeasureError> {
    let (counts, length) = monograms(alphabet, text, 2)?;
    coincidence(alphabet.len(), counts, length)
}

/// [`index_of_coincidence`] over prevalidated indices of an alphabet of `width` symbols.
pub(crate) fn index_coincidence(
    width: usize,
    indices: &[u32],
) -> Result<MeasuredScore, MeasureError> {
    index_coincidence_iter(width, indices.iter().copied())
}

/// [`index_coincidence`] over streamed prevalidated indices.
pub(crate) fn index_coincidence_iter<I: ExactSizeIterator<Item = u32>>(
    width: usize,
    indices: I,
) -> Result<MeasuredScore, MeasureError> {
    let (counts, length) = index_monograms(width, indices, 2)?;
    coincidence(width, counts, length)
}

fn coincidence(
    width: usize,
    counts: Vec<u128>,
    length: u128,
) -> Result<MeasuredScore, MeasureError> {
    let mut pairs = 0_u128;
    for count in counts.into_iter().filter(|&count| count > 0) {
        let previous = count.checked_sub(1).ok_or(ScoreError::Overflow)?;
        let contribution = count.checked_mul(previous).ok_or(ScoreError::Overflow)?;
        pairs = pairs
            .checked_add(contribution)
            .ok_or(ScoreError::Overflow)?;
    }
    let alphabet_size = u128::try_from(width).map_err(|_| ScoreError::Overflow)?;
    let scale = u128::try_from(SCALE).map_err(|_| ScoreError::Overflow)?;
    let numerator = pairs
        .checked_mul(alphabet_size)
        .and_then(|value| value.checked_mul(scale))
        .ok_or(ScoreError::Overflow)?;
    let denominator = length
        .checked_sub(1)
        .and_then(|previous| length.checked_mul(previous))
        .ok_or(ScoreError::Overflow)?;
    let units = numerator
        .checked_div(denominator)
        .ok_or(ScoreError::Overflow)?;
    let measured = FixedScore::from_units(i128::try_from(units).map_err(|_| ScoreError::Overflow)?);
    Ok(MeasuredScore {
        measured,
        ranking: measured,
    })
}

/// Positive Shannon entropy in bits using the deterministic Q48 log helper.
/// Membership is validated before sample sufficiency; requires a nonempty input.
/// Ranking negates the positive measured value only after Q32 quantization.
pub fn shannon_entropy(alphabet: &Alphabet, text: &str) -> Result<MeasuredScore, MeasureError> {
    let (counts, length) = monograms(alphabet, text, 1)?;
    entropy(counts, length)
}

/// [`shannon_entropy`] over prevalidated indices of an alphabet of `width` symbols.
pub(crate) fn index_entropy(width: usize, indices: &[u32]) -> Result<MeasuredScore, MeasureError> {
    index_entropy_iter(width, indices.iter().copied())
}

/// [`index_entropy`] over streamed prevalidated indices.
pub(crate) fn index_entropy_iter<I: ExactSizeIterator<Item = u32>>(
    width: usize,
    indices: I,
) -> Result<MeasuredScore, MeasureError> {
    let (counts, length) = index_monograms(width, indices, 1)?;
    entropy(counts, length)
}

fn entropy(counts: Vec<u128>, length: u128) -> Result<MeasuredScore, MeasureError> {
    let log_length = integer_log2_q48(length)?;
    let mut numerator = 0_i128;
    for count in counts.into_iter().filter(|&count| count > 0) {
        let difference = log_length
            .checked_sub(integer_log2_q48(count)?)
            .ok_or(ScoreError::Overflow)?;
        let count = i128::try_from(count).map_err(|_| ScoreError::Overflow)?;
        let contribution = count.checked_mul(difference).ok_or(ScoreError::Overflow)?;
        numerator = numerator
            .checked_add(contribution)
            .ok_or(ScoreError::Overflow)?;
    }
    let denominator = i128::try_from(length)
        .map_err(|_| ScoreError::Overflow)?
        .checked_mul(1_i128 << 16)
        .ok_or(ScoreError::Overflow)?;
    let measured = FixedScore::from_units(floor_div(numerator, denominator)?);
    Ok(MeasuredScore {
        measured,
        ranking: measured.checked_neg()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SCALE;

    fn alphabet() -> Alphabet {
        Alphabet::new(vec!['A', 'B']).unwrap()
    }

    #[test]
    fn exact_ic_and_entropy_examples_keep_ranking_separate() {
        for (text, ic, entropy) in [
            ("AA", 2 * SCALE, 0),
            ("AB", 0, SCALE),
            ("AAAA", 2 * SCALE, 0),
            ("AABB", 2_863_311_530, SCALE),
        ] {
            let coincidence = index_of_coincidence(&alphabet(), text).unwrap();
            assert_eq!(coincidence.measured().units(), ic);
            assert_eq!(coincidence.ranking(), coincidence.measured());
            let result = shannon_entropy(&alphabet(), text).unwrap();
            assert_eq!(result.measured().units(), entropy);
            assert_eq!(result.ranking().units(), -entropy);
        }
    }

    #[test]
    fn nonuniform_entropy_matches_independent_decimal_and_integer_oracles() {
        // Python Decimal precision 100 and an independent contract integer oracle
        // both floor AAB entropy to these Q32 units; no runtime float is used.
        let result = shannon_entropy(&alphabet(), "AAB").unwrap();
        assert_eq!(result.measured().units(), 3_944_050_575);
        assert_eq!(result.ranking().units(), -3_944_050_575);
    }

    #[test]
    fn one_symbol_alphabet_and_minimum_entropy_sample() {
        let single = Alphabet::new(vec!['λ']).unwrap();
        assert_eq!(
            index_of_coincidence(&single, "λλ")
                .unwrap()
                .measured()
                .units(),
            SCALE
        );
        for text in ["λ", "λλλλ"] {
            let result = shannon_entropy(&single, text).unwrap();
            assert_eq!(result.measured().units(), 0);
            assert_eq!(result.ranking().units(), 0);
        }
    }

    #[test]
    fn insufficient_samples_are_errors_not_scores() {
        for text in ["", "A"] {
            assert_eq!(
                index_of_coincidence(&alphabet(), text),
                Err(MeasureError::InsufficientSamples {
                    required: 2,
                    actual: text.len() as u128
                })
            );
        }
        assert_eq!(
            shannon_entropy(&alphabet(), ""),
            Err(MeasureError::InsufficientSamples {
                required: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn membership_precedes_sample_checks_and_reports_scalar_positions() {
        let unicode = Alphabet::new(vec!['λ', 'β']).unwrap();
        for scorer in [index_of_coincidence, shannon_entropy] {
            assert_eq!(
                scorer(&unicode, "λβX"),
                Err(MeasureError::InvalidSymbol {
                    symbol: 'X',
                    scalar_index: 2
                })
            );
            assert_eq!(
                scorer(&unicode, "X"),
                Err(MeasureError::InvalidSymbol {
                    symbol: 'X',
                    scalar_index: 0
                })
            );
        }
    }

    #[test]
    fn unicode_scalars_are_not_normalized_or_trimmed() {
        let unicode = Alphabet::new(vec!['é', 'e', '\u{301}']).unwrap();
        let result = shannon_entropy(&unicode, "e\u{301}").unwrap();
        assert_eq!(result.measured().units(), SCALE);
        assert_eq!(
            shannon_entropy(&unicode, "é").unwrap().measured().units(),
            0
        );
        assert_eq!(
            index_of_coincidence(&unicode, "éé")
                .unwrap()
                .measured()
                .units(),
            3 * SCALE
        );
        for text in ["E", " é", "é\n"] {
            assert!(matches!(
                shannon_entropy(&unicode, text),
                Err(MeasureError::InvalidSymbol { .. })
            ));
        }
    }

    #[test]
    fn error_context_preserves_scalar_counts_and_arithmetic_sources() {
        let unicode = Alphabet::new(vec!['λ']).unwrap();
        assert_eq!(
            index_of_coincidence(&unicode, "λ"),
            Err(MeasureError::InsufficientSamples {
                required: 2,
                actual: 1
            })
        );
        let error = MeasureError::from(ScoreError::Overflow);
        assert_eq!(error.to_string(), "fixed-point score arithmetic overflow");
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn index_counts_match_character_scores_and_sample_errors() {
        let unicode = Alphabet::new(vec!['λ', 'A', 'é']).unwrap();
        for text in ["", "λ", "λλ", "Aé", "éλAAéλλ", "AAAAAAAAé"] {
            let indices: Vec<u32> = text
                .chars()
                .map(|symbol| unicode.index_of(symbol).unwrap() as u32)
                .collect();
            assert_eq!(
                index_coincidence(unicode.len(), &indices),
                index_of_coincidence(&unicode, text)
            );
            assert_eq!(
                index_entropy(unicode.len(), &indices),
                shannon_entropy(&unicode, text)
            );
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
    fn iterator_kernels_match_slice_and_text_scores_and_sample_errors() {
        for width in [1, 2, 7, 26] {
            let symbols: Vec<char> = (0..width)
                .map(|i| char::from_u32(0x3b1 + i as u32).unwrap())
                .collect();
            let unicode = Alphabet::new(symbols.clone()).unwrap();
            for length in [0, 1, 2, 3, 26, 27, 257] {
                for seed in [1, 0x9e37_79b9] {
                    let indices = pseudo_random_indices(width, length, seed);
                    let text: String = indices.iter().map(|&i| symbols[i as usize]).collect();
                    let streamed = || (0..indices.len()).map(|i| indices[i]);
                    let coincidence = index_coincidence_iter(width, streamed());
                    assert_eq!(coincidence, index_coincidence(width, &indices));
                    assert_eq!(coincidence, index_of_coincidence(&unicode, &text));
                    let entropy = index_entropy_iter(width, streamed());
                    assert_eq!(entropy, index_entropy(width, &indices));
                    assert_eq!(entropy, shannon_entropy(&unicode, &text));
                    match length {
                        0 => assert_eq!(
                            entropy,
                            Err(MeasureError::InsufficientSamples {
                                required: 1,
                                actual: 0
                            })
                        ),
                        _ => assert!(entropy.is_ok()),
                    }
                    if length < 2 {
                        assert_eq!(
                            coincidence,
                            Err(MeasureError::InsufficientSamples {
                                required: 2,
                                actual: length as u128
                            })
                        );
                    } else {
                        assert!(coincidence.is_ok());
                    }
                }
            }
        }
    }

    #[test]
    fn monogram_scores_are_repeatable_and_permutation_invariant() {
        for scorer in [index_of_coincidence, shannon_entropy] {
            let expected = scorer(&alphabet(), "AAABB").unwrap();
            for text in ["AAABB", "ABABA", "BBAAA", "AAABB"] {
                assert_eq!(scorer(&alphabet(), text), Ok(expected));
            }
        }
    }
}
