// SPDX-License-Identifier: MIT OR Apache-2.0
//! Standard rejection sampling as D.2.2 uses it (lines 2819 and 3187), with the widths and the
//! theorem D.2.3 cites at line 3253: a response `z = y + v` with `y` drawn from the discrete Gaussian
//! of standard deviation `σ = 12·T`, `‖v‖ ≤ T`, is released only when
//!
//! `u ≤ (1/M)·exp((−2⟨z, v⟩ + ‖v‖²)/(2σ²))`, `u ← [0, 1)`, `M = exp(12/α + 1/(2α²))`, `α = 12`,
//!
//! after which `z` is within statistical distance `2^{−100}` of the Gaussian, independent of `v`.
//! This module is the only place the crate uses floating point: proofs are randomised and need
//! not be reproducible, so the acceptance test may round. Inner products and norms are exact
//! integers until the final conversion.

use crate::{
    error::{Error, Result, check_dimension},
    proof::params::REJECTION_SLACK,
};
use crypto_bigint::U512;

/// `ln M = 12/α + 1/(2α²)` for `α = 12`.
// α = 12 converts exactly.
const LOG_M: f64 =
    12.0 / REJECTION_SLACK as f64 + 1.0 / (2.0 * REJECTION_SLACK as f64 * REJECTION_SLACK as f64);

/// Whether to release `z = y + v`, given the integer coefficient vectors `z` and `v`, the
/// realised variance `σ²` and 64 uniform bits.
pub(crate) fn accept(z: &[i64], v: &[i64], variance: &U512, uniform: u64) -> Result<bool> {
    check_dimension(z.len(), v.len())?;
    let overflow = || Error::ProverAborted;
    let (zv, vv) = z
        .iter()
        .zip(v)
        .try_fold((0i128, 0i128), |(zv, vv), (&a, &b)| {
            let (a, b) = (i128::from(a), i128::from(b));
            Some((zv.checked_add(a * b)?, vv.checked_add(b * b)?))
        })
        .ok_or_else(overflow)?;
    let numerator = vv
        .checked_sub(zv.checked_mul(2).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;
    // Rounded to the nearest f64, which the acceptance test tolerates.
    let exponent = numerator as f64 / (2.0 * to_f64(variance)) - LOG_M;
    // 53 uniform bits give u ∈ [0, 1) with the full precision of an f64.
    // Both are at most 2^53, so both conversions are exact.
    let u = (uniform >> 11) as f64 / (1u64 << 53) as f64;
    Ok(u <= exponent.exp())
}

/// The nearest `f64` to a wide unsigned integer.
fn to_f64(value: &U512) -> f64 {
    value
        .as_words()
        .iter()
        .rev()
        // Each word rounds to the nearest f64, as the result does.
        .fold(0.0, |acc, &w| acc * 18_446_744_073_709_551_616.0 + w as f64)
}

#[cfg(test)]
mod tests {
    use super::{LOG_M, accept, to_f64};
    use crypto_bigint::U512;

    #[test]
    fn log_m_is_one_plus_one_over_288() {
        assert!((LOG_M - (1.0 + 1.0 / 288.0)).abs() < 1e-15);
        assert_eq!(to_f64(&U512::from_u128(1 << 100)), 2f64.powi(100));
    }

    /// With `v = 0` the acceptance probability is `1/M` exactly; with `z = v` (a response
    /// pointing straight along the secret) it is `exp(−‖v‖²/(2σ²))/M`, smaller.
    #[test]
    fn acceptance_threshold() {
        let variance = U512::from_u64(100);
        let threshold = (-LOG_M).exp();
        let below = ((threshold * 0.999 * (1u64 << 53) as f64) as u64) << 11;
        let above = ((threshold * 1.001 * (1u64 << 53) as f64) as u64) << 11;
        assert!(accept(&[3, 4], &[0, 0], &variance, below).unwrap());
        assert!(!accept(&[3, 4], &[0, 0], &variance, above).unwrap());
        // ⟨z, v⟩ = ‖v‖² = 25: exponent −25/200 − ln M.
        let shrunk = threshold * (-0.125f64).exp();
        let between = ((shrunk * 1.01 * (1u64 << 53) as f64) as u64) << 11;
        assert!(!accept(&[3, 4], &[3, 4], &variance, between).unwrap());
        assert!(accept(&[3, 4], &[3, 4], &variance, 0).unwrap());
        assert!(accept(&[1], &[1, 2], &variance, 0).is_err());
    }
}
