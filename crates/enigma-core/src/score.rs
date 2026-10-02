//! Checked deterministic fixed-point primitives, as specified by scoring contract §4.
//! No measure composition or ranking policy is defined here.

/// Number of integer units representing one Q32 score unit.
pub const SCALE: i128 = 1_i128 << 32;

/// Frozen floor of ln(2) multiplied by 2^48.
pub const LN_2_Q48: i128 = 195_103_586_505_167;

/// Invalid arithmetic domains or checked score overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScoreError {
    /// Integer logarithms require a positive input.
    ZeroLogInput,
    /// Logarithmic ratios require a positive numerator.
    ZeroNumerator,
    /// Logarithmic ratios require a positive denominator.
    ZeroDenominator,
    /// Signed floor division requires a strictly positive divisor.
    NonPositiveDivisor,
    /// A checked intermediate or score operation exceeded its integer range.
    Overflow,
}

impl std::fmt::Display for ScoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroLogInput => "integer logarithm input must be positive",
            Self::ZeroNumerator => "logarithmic ratio numerator must be positive",
            Self::ZeroDenominator => "logarithmic ratio denominator must be positive",
            Self::NonPositiveDivisor => "floor division divisor must be positive",
            Self::Overflow => "fixed-point score arithmetic overflow",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ScoreError {}

/// Signed Q32 measured value; interpretation and ranking belong to each measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedScore(i128);

impl FixedScore {
    /// Wrap already-quantized signed Q32 units without changing their scale.
    pub const fn from_units(units: i128) -> Self {
        Self(units)
    }

    /// Read the signed Q32 units without floating-point conversion.
    pub const fn units(self) -> i128 {
        self.0
    }

    /// Add like-scaled units with overflow detection, not a composition policy.
    pub fn checked_add(self, other: Self) -> Result<Self, ScoreError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(ScoreError::Overflow)
    }

    /// Multiply units by an integer (not another Q32 value).
    pub fn checked_mul(self, factor: i128) -> Result<Self, ScoreError> {
        self.0
            .checked_mul(factor)
            .map(Self)
            .ok_or(ScoreError::Overflow)
    }

    /// Negate units with overflow detection.
    pub fn checked_neg(self) -> Result<Self, ScoreError> {
        self.0.checked_neg().map(Self).ok_or(ScoreError::Overflow)
    }
}

/// Divide signed integers toward negative infinity, requiring a positive divisor.
/// Rejecting nonpositive divisors also prevents the MIN / -1 overflow case.
pub fn floor_div(numerator: i128, denominator: i128) -> Result<i128, ScoreError> {
    if denominator <= 0 {
        return Err(ScoreError::NonPositiveDivisor);
    }
    let quotient = numerator
        .checked_div(denominator)
        .ok_or(ScoreError::Overflow)?;
    let remainder = numerator
        .checked_rem(denominator)
        .ok_or(ScoreError::Overflow)?;
    if remainder < 0 {
        quotient.checked_sub(1).ok_or(ScoreError::Overflow)
    } else {
        Ok(quotient)
    }
}

/// Deterministic Q48 approximation B(v) of log2(v) for positive u128 inputs.
/// Q63 normalization and each of the 48 squaring steps discard bits downward.
pub fn integer_log2_q48(value: u128) -> Result<i128, ScoreError> {
    if value == 0 {
        return Err(ScoreError::ZeroLogInput);
    }
    let exponent = 127 - value.leading_zeros();
    let mut mantissa = if exponent <= 63 {
        value.checked_shl(63 - exponent)
    } else {
        value.checked_shr(exponent - 63)
    }
    .ok_or(ScoreError::Overflow)?;
    let mut fraction = 0_i128;
    for bit in (0..48).rev() {
        // A pre-square mantissa is below 2^64. Keep the post-square
        // value in u128 until halving: it can temporarily exceed u64.
        mantissa = mantissa.checked_mul(mantissa).ok_or(ScoreError::Overflow)? >> 63;
        if mantissa >= (1_u128 << 64) {
            mantissa >>= 1;
            fraction |= 1_i128 << bit;
        }
    }
    i128::from(exponent)
        .checked_mul(1_i128 << 48)
        .and_then(|integer| integer.checked_add(fraction))
        .ok_or(ScoreError::Overflow)
}

/// Quantize ln(numerator / denominator) to Q32 using the frozen integer helper.
/// Ratios above one are valid. Negative results floor rather than truncate.
pub fn ln_ratio_q32(numerator: u128, denominator: u128) -> Result<FixedScore, ScoreError> {
    if numerator == 0 {
        return Err(ScoreError::ZeroNumerator);
    }
    if denominator == 0 {
        return Err(ScoreError::ZeroDenominator);
    }
    let difference = integer_log2_q48(numerator)?
        .checked_sub(integer_log2_q48(denominator)?)
        .ok_or(ScoreError::Overflow)?;
    let product = difference
        .checked_mul(LN_2_Q48)
        .ok_or(ScoreError::Overflow)?;
    floor_div(product, 1_i128 << 64).map(FixedScore::from_units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_u128_power_of_two_has_exact_integer_log() {
        for exponent in 0..128 {
            assert_eq!(
                integer_log2_q48(1_u128 << exponent),
                Ok(i128::from(exponent) * (1_i128 << 48))
            );
        }
    }

    #[test]
    fn logarithm_rejects_zero() {
        assert_eq!(integer_log2_q48(0), Err(ScoreError::ZeroLogInput));
    }

    #[test]
    fn mantissa_boundaries_and_maximum_stay_in_u128() {
        let unit = 1_i128 << 48;
        assert_eq!(integer_log2_q48((1_u128 << 63) - 1), Ok(63 * unit - 1));
        assert_eq!(integer_log2_q48((1_u128 << 64) - 1), Ok(64 * unit - 1));
        assert_eq!(integer_log2_q48(1_u128 << 64), Ok(64 * unit));
        assert_eq!(integer_log2_q48((1_u128 << 64) + 1), Ok(64 * unit));
        assert_eq!(integer_log2_q48(u128::MAX), Ok(128 * unit - 1));
        // The right-shift normalization deliberately discards low input bits.
        assert_eq!(
            integer_log2_q48(u128::MAX),
            integer_log2_q48(u128::MAX - ((1_u128 << 64) - 1))
        );
    }

    #[test]
    fn natural_log_ratios_match_independent_contract_goldens() {
        assert_eq!(ln_ratio_q32(1, 1).unwrap().units(), 0);
        assert_eq!(ln_ratio_q32(1, 4).unwrap().units(), -5_954_088_944);
        assert_eq!(ln_ratio_q32(1, 8).unwrap().units(), -8_931_133_416);
        assert_eq!(ln_ratio_q32(4, 1).unwrap().units(), 5_954_088_943);
        assert_eq!(ln_ratio_q32(8, 1).unwrap().units(), 8_931_133_415);
        // Flooring makes reciprocal quantized logs differ by one unit.
        assert_eq!(
            ln_ratio_q32(1, 4)
                .unwrap()
                .checked_add(ln_ratio_q32(4, 1).unwrap())
                .unwrap()
                .units(),
            -1
        );
    }

    #[test]
    fn ratio_domain_errors_are_distinct() {
        assert_eq!(ln_ratio_q32(0, 1), Err(ScoreError::ZeroNumerator));
        assert_eq!(ln_ratio_q32(1, 0), Err(ScoreError::ZeroDenominator));
    }

    #[test]
    fn signed_division_floors_instead_of_truncating() {
        assert_eq!(floor_div(-7, 3), Ok(-3));
        assert_eq!(floor_div(-6, 3), Ok(-2));
        assert_eq!(floor_div(-1, 2), Ok(-1));
        assert_eq!(floor_div(7, 3), Ok(2));
        assert_eq!(floor_div(0, 3), Ok(0));
        assert_eq!(floor_div(i128::MIN, 1), Ok(i128::MIN));
        assert_eq!(floor_div(i128::MIN, i128::MAX), Ok(-2));
        for divisor in [0, -1, i128::MIN] {
            assert_eq!(
                floor_div(i128::MIN, divisor),
                Err(ScoreError::NonPositiveDivisor)
            );
        }
    }

    #[test]
    fn score_operations_are_checked_and_units_are_explicit() {
        assert_eq!(SCALE, 4_294_967_296);
        assert_eq!(LN_2_Q48, 195_103_586_505_167);
        let score = FixedScore::from_units(3 * SCALE);
        assert_eq!(score.checked_mul(2).unwrap().units(), 6 * SCALE);
        assert_eq!(score.checked_neg().unwrap().units(), -3 * SCALE);
        assert_eq!(
            FixedScore::from_units(i128::MAX).checked_add(FixedScore::from_units(1)),
            Err(ScoreError::Overflow)
        );
        assert_eq!(
            FixedScore::from_units(i128::MAX).checked_mul(2),
            Err(ScoreError::Overflow)
        );
        assert_eq!(
            FixedScore::from_units(i128::MIN).checked_neg(),
            Err(ScoreError::Overflow)
        );
    }

    #[test]
    fn integer_api_is_repeatable_across_extreme_inputs() {
        for (numerator, denominator) in [(3, 7), (7, 3), (u128::MAX, 1), (1, u128::MAX)] {
            let first: FixedScore = ln_ratio_q32(numerator, denominator).unwrap();
            for _ in 0..8 {
                assert_eq!(ln_ratio_q32(numerator, denominator), Ok(first));
            }
        }
    }
}
