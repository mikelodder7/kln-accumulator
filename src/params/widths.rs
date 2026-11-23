// SPDX-License-Identifier: MIT OR Apache-2.0
//! The widths of the trapdoor and of the preimage sampler, derived in integer arithmetic.
//!
//! Every quantity is an upper bound (or, where it is checked from below, a lower bound) on the
//! real number it stands for, so that the inequalities of Theorem 2.1 hold for the realised
//! values. Logarithms and powers of two are evaluated in 64-bit binary fixed point by repeated
//! squaring and repeated square roots, rounding in the safe direction at every step.

use super::{PI_LOWER, PI_UPPER, Wide, ceil_div, ceil_sqrt, product, sum, width_sq_upper};
use crate::{
    error::{Error, Result},
    preimage::{Stage, TAIL},
    zq::Coeff,
};

/// Fractional bits of the fixed-point logarithms and exponents.
const FRACTION: u32 = 64;

/// `log₂(1/ε)` for the `ε` of every smoothing condition the sampler meets: `ε = 2^-128`.
const SMOOTHING_EPSILON_BITS: u64 = 128;

/// `ln 2 < 61/88`, a convergent of the continued fraction `ln 2 = [0; 1, 2, 3, 1, 6, …]`.
const LN2_UPPER: (u64, u64) = (61, 88);

/// The largest integer part [`exp2_upper`] accepts.
const MAX_EXPONENT: u32 = 384;

/// Significant bits a variance may carry so that it is exact as an `f64`.
const MANTISSA_BITS: u32 = 53;

/// The largest least variance accepted, so that every coordinate the sampler produces, and
/// every centre it computes, fits an `i64` with room to spare.
const MAX_LEAST_VARIANCE_BITS: u32 = 100;

/// An upper bound on `log₂ q` in fixed point with [`FRACTION`] bits.
///
/// With `q ∈ [2^{B−1}, 2^B)`, the mantissa `x = q / 2^{B−1} ∈ [1, 2)` is rounded up, and each
/// fractional bit is read off by squaring: a square at or above 2 sets the bit and is halved.
/// Every rounding is upward, so the bits read are those of a number at least `x`; the final
/// unit covers the bits beyond the last one read.
fn log2_upper(q: &Coeff) -> Wide {
    let bits = q.bit_width_vartime();
    let one = Wide::ONE.shl_vartime(FRACTION);
    let two = one.shl_vartime(1);
    let mut x = shr_ceil(
        &q.resize::<{ Wide::LIMBS }>().shl_vartime(FRACTION),
        bits - 1,
    );
    let mut fraction = Wide::ZERO;
    for position in (0..FRACTION).rev() {
        x = shr_ceil(&x.wrapping_mul(&x), FRACTION);
        if x >= two {
            fraction = fraction.wrapping_add(&Wide::ONE.shl_vartime(position));
            x = shr_ceil(&x, 1);
        }
    }
    Wide::from_u32(bits - 1)
        .shl_vartime(FRACTION)
        .wrapping_add(&fraction)
        .wrapping_add(&Wide::ONE)
}

/// `⌈a / 2^shift⌉`.
fn shr_ceil(a: &Wide, shift: u32) -> Wide {
    let quotient = a.shr_vartime(shift);
    if quotient.shl_vartime(shift) == *a {
        quotient
    } else {
        quotient.wrapping_add(&Wide::ONE)
    }
}

/// An upper bound on `2^x` for `x` in fixed point with [`FRACTION`] bits, itself in fixed
/// point with [`FRACTION`] bits.
///
/// `2^x = 2^{⌊x⌋}·Π_j 2^{b_j/2^j}` over the fractional bits `b_j`; the factors `2^{2^{−j}}` are
/// upper bounds obtained by rounding up each square root of the previous one, and every
/// product is rounded up.
fn exp2_upper(x: &Wide) -> Result<Wide> {
    let one = Wide::ONE.shl_vartime(FRACTION);
    let integer = x.shr_vartime(FRACTION);
    // The result is below 2^{integer + 1}; it must fit with room for the products above.
    if integer >= Wide::from_u32(MAX_EXPONENT) {
        return Err(Error::WitnessBoundTooLarge);
    }
    let integer = u32::try_from(integer.as_words()[0]).map_err(|_| Error::WitnessBoundTooLarge)?;
    let mut factor = ceil_sqrt(&one.shl_vartime(FRACTION + 1));
    let mut result = one;
    for position in (0..FRACTION).rev() {
        if x.bit_vartime(position) {
            result = shr_ceil(&result.wrapping_mul(&factor), FRACTION);
        }
        factor = ceil_sqrt(&factor.shl_vartime(FRACTION));
    }
    Ok(result.shl_vartime(integer))
}

/// The least variance `σ_ς²` of the trapdoor's coefficients: Theorem 2.1 asks for a width
/// `ς > 2d·q^{n/(m−m') + 2/(d(m−m'))}`, and `2π·σ² ≥ 2·(333/106)·σ² ≥ ς²` once
/// `σ² ≥ 106·ς²/666`.
///
/// The exponent is `(nd + 2)/(d(m − m'))`, applied to an upper bound on `log₂ q` and rounded
/// up, so `ς² ≤ 4d²·2^{2·exponent·log₂ q}` is an upper bound on the threshold.
pub(super) fn trapdoor_min_variance(
    degree: usize,
    modulus: &Coeff,
    n: usize,
    left: usize,
) -> Result<Wide> {
    let w = |v: usize| Wide::from_u64(v as u64);
    let numerator = product(&[
        w(2),
        log2_upper(modulus),
        sum(product(&[w(n), w(degree)])?, w(2))?,
    ])?;
    let exponent = ceil_div(&numerator, &product(&[w(degree), w(left)])?)?;
    // ς² ≤ 4d²·2^{2·exponent}, in fixed point.
    let threshold_sq = product(&[w(4), w(degree), w(degree), exp2_upper(&exponent)?])?;
    ceil_div(
        &product(&[Wide::from_u64(PI_LOWER.1), threshold_sq])?,
        &Wide::from_u64(2 * PI_LOWER.0).shl_vartime(FRACTION),
    )
}

/// `ς²` for a Gaussian trapdoor of variance `variance`, in fixed point with [`FRACTION`] bits:
/// [`width_sq_upper`], so `ς² = 2π·variance` is bounded from above.
pub(super) fn gaussian_width_sq(variance: &Wide) -> Result<Wide> {
    Ok(width_sq_upper(variance)?.shl_vartime(FRACTION))
}

/// The square of the subgaussian width of a coefficient uniform on `{−1, 0, 1}`, `4π/3`,
/// bounded from above by `4·355/(3·113)` in fixed point with [`FRACTION`] bits.
///
/// Such a coefficient `X` has `E[e^{2πtX}] = (1 + 2·cosh 2πt)/3 ≤ e^{(2/3)(2πt)²/2}
/// = e^{π·(4π/3)·t²}`: with `u = 2πt` both sides are series in `u²` that agree up to `u²`, and
/// the left's later terms `(2/3)·u^{2k}/(2k)!` are at most the right's `(u²/3)^k/k!` because
/// `(2k)! ≥ 2·3^{k−1}·k!`. So `X` is subgaussian with parameter `√(4π/3)` in the convention
/// of ePrint 2011/501, Section 2.4, `E[e^{2πtX}] ≤ e^{πs²t²}`, which a Gaussian of width `s`
/// meets (that section's rule for bounded symmetric variables gives only `√(2π)` here). The
/// bound of Lemma 2.3 of ePrint 2025/1099, which its Lemma A.2 applies to ternary matrices,
/// then gives `s₁(T_A) ≤ √(4π/3)·√d·(√m + √m' + log √d)` with overwhelming probability.
/// Lemma A.2 states the constant `√(2/3)`, the coefficients' standard deviation; Lemma 2.3's
/// `s` is a width, `√(2π)` times a standard deviation, so the larger `√(4π/3)` is used here.
/// ePrint 2011/501, Lemma 2.9 has the same shape, `s₁ ≤ C·s·(√m + √n + t)`, for independent
/// entries and an unspecified constant `C`; Lemma 2.3 of ePrint 2025/1099 is the explicit one.
pub(super) fn ternary_width_sq() -> Result<Wide> {
    ceil_div(
        &Wide::from_u64(4 * PI_UPPER.0).shl_vartime(FRACTION),
        &Wide::from_u64(3 * PI_UPPER.1),
    )
}

/// An upper bound on `S²`, the square of the bound `s₁(T_A) ≤ ς·√d·(√m + √m' + log √d)` of
/// Theorem 2.1 and Lemma 2.3 for a trapdoor of (subgaussian) width `ς`, with
/// `ς² ≤ width_sq` in fixed point with [`FRACTION`] bits.
///
/// The logarithm is taken to base 2, which bounds the natural one from above. The bracket is
/// evaluated in fixed point with 32 fractional bits, each square root rounded up.
pub(super) fn spectral_sq(
    degree: usize,
    m: usize,
    m_prime: usize,
    width_sq: &Wide,
) -> Result<Wide> {
    let root = |v: usize| ceil_sqrt(&Wide::from_u64(v as u64).shl_vartime(64));
    // log₂ √d = log₂(d)/2 for d a power of two, in 32-bit fixed point.
    let log_half = Wide::from_u32(degree.trailing_zeros()).shl_vartime(31);
    let bracket = sum(sum(root(m), root(m_prime))?, log_half)?;
    let scaled = product(&[*width_sq, Wide::from_u64(degree as u64), bracket, bracket])?;
    Ok(shr_ceil(&scaled, 64 + FRACTION))
}

/// `⌈√(⌈ς²⌉)⌉` for `ς²` in fixed point with [`FRACTION`] bits: the trapdoor width reported in
/// [`crate::Bounds::trapdoor_width`].
pub(super) fn width_ceiling(width_sq: &Wide) -> Wide {
    ceil_sqrt(&shr_ceil(width_sq, FRACTION))
}

/// An upper bound, in fixed point with [`FRACTION`] bits, on `C_{ε,N}²/(2π)` for
/// `C_{ε,N} = √(ln(2N(1 + 1/ε))/π)`, the constant ePrint 2017/308 states before Corollary 3.1,
/// at `ε = 2^-128`.
///
/// Lemma 2.2 of ePrint 2017/308 (ePrint 2007/432, Lemma 3.1; ePrint 2011/501, Lemma 2.3)
/// bounds `η_ε(Λ) ≤ ‖B̃‖·C_{ε,N}` for an `N`-dimensional lattice with basis `B`, so a covariance `Σ ⪰ V·I` with `V` at least this bound has `√Σ ≥ η_ε(Λ)`
/// whenever `‖B̃‖ ≤ 1`, as for `Z^N`. With `ln x = ln 2·log₂ x`, `ln 2 < 61/88` and
/// `π > 333/106`, the bound is `(61/88)·log₂(2N(1 + 2^128))·106²/(2·333²)`; the logarithm is
/// [`log2_upper`] of `2N`, plus 128, plus one unit for `log₂(1 + 2^-128) < 2^-127`.
///
/// Fails with [`Error::WitnessBoundTooLarge`] for `N = 0`, which no lattice of a set has and
/// whose logarithm is undefined, and when `2N` overflows.
fn smoothing_variance(dimension: usize) -> Result<Wide> {
    let w = Wide::from_u64;
    let doubled = (dimension as u64)
        .checked_mul(2)
        .filter(|doubled| *doubled != 0)
        .ok_or(Error::WitnessBoundTooLarge)?;
    let log = sum(
        sum(
            log2_upper(&Coeff::from_u64(doubled)),
            w(SMOOTHING_EPSILON_BITS).shl_vartime(FRACTION),
        )?,
        Wide::ONE,
    )?;
    ceil_div(
        &product(&[log, w(LN2_UPPER.0), w(PI_LOWER.1), w(PI_LOWER.1)])?,
        &product(&[w(LN2_UPPER.1), w(2), w(PI_LOWER.0), w(PI_LOWER.0)])?,
    )
}

/// The dimensions of a set that the trapdoor stage's smoothing conditions are stated in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StageShape {
    /// The gadget base `b`.
    pub(super) base: u32,
    /// The digits `k` of one gadget coset.
    pub(super) digits: usize,
    /// `m'd`, the integer dimension of `Λ⊥(G)`.
    pub(super) gadget_columns: usize,
    /// `md`, the integer dimension of `Λ⊥(A)`.
    pub(super) columns: usize,
}

/// The G-lattice sampler's variances `σ²` and `α² = σ²·r²`, `r² = (b + 1)² + 1` (see
/// [`crate::preimage::gadget`]): `σ²` is the least integer meeting both of
///
/// * `σ²·min((b + 1)², (b − 1)²·(4b + 1))/r² ≥` [`smoothing_variance`] of `k`: that bound on
///   the least eigenvalue of the covariance `Σ₃` of ePrint 2017/308, Theorem 2.3, for one
///   coset gives `√Σ₃ ≥ η_ε(Z^k)`, and with it `√(2π)·σ ≥ C_{ε,k} ≥ η_ε(L(D))` and every
///   one-dimensional draw at least `σ²`;
/// * `σ²·r²/(b² + 1) ≥` [`smoothing_variance`] of `m'd`: the input condition
///   `r√Σ_G ≥ η_ε(Λ⊥(G))` of ePrint 2011/501, Algorithm 3, for all of `Λ⊥(G)` at once, by
///   its Lemma 2.3 (ePrint 2007/432, Lemma 3.1) with the basis of its Theorem 4.1, whose
///   Gram–Schmidt vectors are at most `√(b² + 1)` long for base `b` and any modulus.
///
/// Algorithm 3 also asks `Σ_G ≥ 2` in units of `r²`; that is `α² ≥ 2·M` for the margin `M` of
/// [`stage`], which the second condition implies because `b² + 1 ≥ 5`.
fn gadget_variances(shape: &StageShape) -> Result<(u64, u64)> {
    let w = Wide::from_u64;
    let b = u64::from(shape.base);
    let b1_sq = product(&[w(b + 1), w(b + 1)])?;
    let r_sq = sum(b1_sq, Wide::ONE)?;
    let least = b1_sq.min(product(&[w(b - 1), w(b - 1), w(4 * b + 1)])?);
    let coset = ceil_div(
        &product(&[smoothing_variance(shape.digits)?, r_sq])?,
        &least.shl_vartime(FRACTION),
    )?;
    let lattice = ceil_div(
        &product(&[
            smoothing_variance(shape.gadget_columns)?,
            sum(product(&[w(b), w(b)])?, Wide::ONE)?,
        ])?,
        &r_sq.shl_vartime(FRACTION),
    )?;
    let sigma_sq = coset.max(lattice);
    let alpha_sq = product(&[sigma_sq, r_sq])?;
    let to_u64 = |v: &Wide| -> Result<u64> {
        if v.bit_width_vartime() > u64::BITS {
            return Err(Error::WitnessBoundTooLarge);
        }
        Ok(u64::from(v.resize::<{ crypto_bigint::U64::LIMBS }>()))
    };
    Ok((to_u64(&sigma_sq)?, to_u64(&alpha_sq)?))
}

/// The trapdoor stage at a set of shape `shape` and spectral bound `S² ≤ spectral_sq`.
///
/// The G-lattice sampler draws variance `α² = σ²·((b+1)² + 1)` per coordinate
/// ([`gadget_variances`]). With `M'` and `M` the [`smoothing_variance`] of `m'd` and of `md`
/// rounded up, the least variance `V₀` is the larger of
///
/// * `(α² + 2M')·(S² + 1) + M`. ePrint 2011/501, Algorithm 3, asks
///   `Σ ≥ [R; I](2 + Σ_G)[Rᵗ I]`, `Σ_p = Σ − [R; I]Σ_G[Rᵗ I] ≥ 2·[R; I][Rᵗ I]` in units of
///   `r² ≥ η_ε(Z^{m'd})²`, which its proof of Theorem 5.5 uses for `r√Σ₃ ≥ η_ε(L([R; I]))`;
///   with `R = T`, `Σ = V₀`, `Σ_G = α²` and `s₁([T; I])² = s₁(T)² + 1 ≤ S² + 1`, the first
///   term is that. The added `M` makes `Σ_p ⪰ M·I ⪰ η_ε(Z^{md})²/(2π)`, the hypothesis of
///   ePrint 2017/308, Theorem 4.1, which `[R; I][Rᵗ I]`, of rank `m'd` only, does not give.
/// * `(⌈S⌉ + 1)²·(b² + 1)·C_{ε,md}²/(2π)`, so that `√(2π·V₀) ≥ η_ε(Λ⊥(A))` for the outer
///   convolution: `Λ⊥(A)` has a basis with Gram–Schmidt vectors at most
///   `(s₁(T) + 1)·√(b² + 1)` long (ePrint 2011/501, Lemma 5.3 with Theorem 4.1), and its
///   Lemma 2.3 bounds the smoothing parameter.
///
/// `V₀` is rounded up to [`MANTISSA_BITS`] significant bits so that it is exact as an `f64`.
/// Every coordinate the stage returns is at most `⌈13·√V₀⌉ + 1` in magnitude.
pub(super) fn stage(shape: &StageShape, spectral_sq: &Wide) -> Result<Stage> {
    let w = Wide::from_u64;
    let (base_variance, gadget) = gadget_variances(shape)?;
    let rounding = shr_ceil(&smoothing_variance(shape.gadget_columns)?, FRACTION);
    let columns = smoothing_variance(shape.columns)?;
    let perturbation = sum(
        product(&[
            sum(w(gadget), product(&[w(2), rounding])?)?,
            sum(*spectral_sq, Wide::ONE)?,
        ])?,
        shr_ceil(&columns, FRACTION),
    )?;
    let b = u64::from(shape.base);
    let gram_schmidt = sum(ceil_sqrt(spectral_sq), Wide::ONE)?;
    let smoothing = shr_ceil(
        &product(&[
            gram_schmidt,
            gram_schmidt,
            sum(product(&[w(b), w(b)])?, Wide::ONE)?,
            columns,
        ])?,
        FRACTION,
    );
    let exact = perturbation.max(smoothing);
    let excess = exact.bit_width_vartime().saturating_sub(MANTISSA_BITS);
    let least = shr_ceil(&exact, excess).shl_vartime(excess);
    if least.bit_width_vartime() > MAX_LEAST_VARIANCE_BITS {
        return Err(Error::WitnessBoundTooLarge);
    }
    let tail = sum(
        ceil_sqrt(&product(&[Wide::from_u64(TAIL * TAIL), least])?),
        Wide::ONE,
    )?;
    let to_u128 = |v: &Wide| u128::from(v.resize::<{ crypto_bigint::U128::LIMBS }>());
    Ok(Stage {
        least_variance: to_u128(&least),
        gadget_base_variance: base_variance,
        gadget_variance: gadget,
        tail: to_u128(&tail),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        StageShape, Wide, exp2_upper, gadget_variances, log2_upper, shr_ceil, smoothing_variance,
        spectral_sq, stage, trapdoor_min_variance,
    };
    use crate::{error::Error, test_util::to_f64, zq::Coeff};

    fn fixed(value: &Wide) -> f64 {
        to_f64(value) / 2f64.powi(64)
    }

    /// The fixed-point logarithm bounds `log₂ q` from above and is within `2^-50` of it.
    #[test]
    fn log2_is_a_tight_upper_bound() {
        for q in [
            Coeff::from_u64(2),
            Coeff::from_u64(3),
            Coeff::from_u64(0x0fff_ffdc_9803_a1ad),
            Coeff::from_be_hex("00000003ffffffffffffffffff2bd00c6625d7590754436d"),
            Coeff::from_u64(u64::MAX),
        ] {
            let got = fixed(&log2_upper(&q));
            let want = to_f64(&q.resize()).log2();
            assert!(got >= want - 1e-12 && got - want < 1e-12, "{got} vs {want}");
        }
        // Exact powers of two: the bound exceeds the integer by one unit only.
        let bound = log2_upper(&Coeff::from_u64(1 << 40));
        assert_eq!(
            bound,
            Wide::from_u64(40).shl_vartime(64).wrapping_add(&Wide::ONE)
        );
    }

    /// The fixed-point exponential bounds `2^x` from above and is within one part in `10^12`.
    #[test]
    fn exp2_is_a_tight_upper_bound() {
        for x in [0.0, 0.5, 1.0, 6.1875, 13.004_882_8, 40.25] {
            let fixed_x = Wide::from_u128((x * 2f64.powi(64)) as u128);
            let got = fixed(&exp2_upper(&fixed_x).unwrap());
            let want = fixed(&fixed_x).exp2();
            assert!(
                got >= want * (1.0 - 1e-15) && got <= want * (1.0 + 1e-12),
                "{x}"
            );
        }
        assert_eq!(
            exp2_upper(&Wide::from_u64(10).shl_vartime(64)).unwrap(),
            Wide::from_u64(1024).shl_vartime(64)
        );
    }

    /// Theorem 2.1's `ς` at the toy shape, `2·64·q^{(64+2)/(64·10)}`, and the spectral bound
    /// and stage that follow from a variance.
    #[test]
    fn toy_shape_widths() {
        let q = Coeff::from_u64(0x0fff_ffdc_9803_a1ad);
        let variance = trapdoor_min_variance(64, &q, 1, 10).unwrap();
        let sigma = 128.0 * to_f64(&q.resize()).powf(66.0 / 640.0);
        // σ² ≥ ς²/(2·(333/106)) ≥ ς²/(2π).
        let want = sigma * sigma * 106.0 / 666.0;
        let got = to_f64(&variance);
        assert!(got >= want && got < want + 2.0, "{got} vs {want}");
        let spectral = spectral_sq(64, 20, 10, &Wide::from_u64(1_000_000).shl_vartime(64)).unwrap();
        let bracket = 20f64.sqrt() + 10f64.sqrt() + 3.0;
        let want = 1e6 * 64.0 * bracket * bracket;
        assert!(to_f64(&spectral) >= want && to_f64(&spectral) < want * (1.0 + 1e-8));
        let shape = StageShape {
            base: 64,
            digits: 10,
            gadget_columns: 10 * 64,
            columns: 20 * 64,
        };
        let stage = stage(&shape, &spectral).unwrap();
        assert_eq!(stage.gadget_base_variance, 5);
        assert_eq!(stage.gadget_variance, 5 * (65 * 65 + 1));
        let least = stage.least_variance as f64;
        // ⌈C_{ε,640}²/(2π)⌉ = ⌈4.86⌉ and ⌈C_{ε,1280}²/(2π)⌉ = ⌈4.89⌉: (α² + 2·5)(S² + 1) + 5,
        // which is above (S + 1)²·(b² + 1)·4.89.
        let want = (21_130.0 + 10.0) * (to_f64(&spectral) + 1.0) + 5.0;
        assert!(least >= want && least < want * (1.0 + 1e-15));
        // At most 53 significant bits, so the value converts to f64 exactly.
        let excess = (128 - stage.least_variance.leading_zeros()).saturating_sub(53);
        assert_eq!(stage.least_variance & ((1u128 << excess) - 1), 0);
        assert_eq!(least as u128, stage.least_variance);
        assert!(stage.tail as f64 >= 13.0 * least.sqrt());
    }

    /// `C_{ε,N}²/(2π) = ln(2N(1 + 2^128))/(2π²)` in floating point.
    fn smoothing_f64(dimension: usize) -> f64 {
        ((2 * dimension) as f64).ln() + 128.0 * 2f64.ln()
    }

    /// The smoothing bound is above `C_{ε,N}²/(2π)` and within two parts in `10^4` of it (the
    /// slack of `61/88` and `333/106`), and
    /// its ceiling, the margin of `V₀`, is 5 at the toy shapes (`md = 1280, 1920`) and 6 at the
    /// 128-bit ones (`md = 81920, 368640`), where 5 would be below `C_{ε,md}²/(2π)`.
    #[test]
    fn smoothing_variance_bounds_the_constant_of_corollary_3_1() {
        let two_pi_sq = 2.0 * std::f64::consts::PI * std::f64::consts::PI;
        for (dimension, ceiling) in [
            (1, 5),
            (10, 5),
            (63, 5),
            (1280, 5),
            (1920, 5),
            (81_920, 6),
            (368_640, 6),
        ] {
            let bound = smoothing_variance(dimension).unwrap();
            let got = fixed(&bound);
            let want = smoothing_f64(dimension) / two_pi_sq;
            assert!(
                got >= want && got < want * (1.0 + 2e-4),
                "{dimension}: {got}"
            );
            assert_eq!(shr_ceil(&bound, 64), Wide::from_u64(ceiling), "{dimension}");
        }
    }

    /// A zero dimension, which a wrapped gadget width `n·k` used to reach, is refused rather
    /// than taken as `log₂ 0`.
    #[test]
    fn smoothing_variance_refuses_a_zero_dimension() {
        assert_eq!(smoothing_variance(0), Err(Error::WitnessBoundTooLarge));
    }

    /// `σ²` is the least integer with both `σ²·min((b+1)², (b−1)²(4b+1))/r² ≥ C_{ε,k}²/(2π)` and
    /// `σ²·r²/(b² + 1) ≥ C_{ε,m'd}²/(2π)`, `r² = (b+1)² + 1`, and `α² = σ²·r²`. It is 5 at the
    /// toy and succinct sets; 6 at the 128-bit set, where `Λ⊥(G)` has dimension `m'd = 40960`
    /// and `r²/(b² + 1)` is only `1.002`; and 6 at `b = 2`, `k = 60`, where the least
    /// eigenvalue of `Σ₃` is only `0.9·σ²`.
    #[test]
    fn gadget_variances_meet_both_smoothing_conditions() {
        let two_pi_sq = 2.0 * std::f64::consts::PI * std::f64::consts::PI;
        for (base, digits, degree, sigma_sq) in [
            (64u32, 10, 64, 5),
            (1024, 10, 4096, 6),
            (64, 15, 64, 5),
            (6, 63, 4096, 5),
            (2, 60, 64, 6),
        ] {
            let shape = StageShape {
                base,
                digits,
                gadget_columns: digits * degree,
                columns: 2 * digits * degree,
            };
            let (got, alpha_sq) = gadget_variances(&shape).unwrap();
            assert_eq!(got, sigma_sq, "b = {base}, k = {digits}");
            let b = f64::from(base);
            let r_sq = (b + 1.0) * (b + 1.0) + 1.0;
            assert_eq!(alpha_sq as f64, got as f64 * r_sq);
            let coset = ((b + 1.0) * (b + 1.0)).min((b - 1.0) * (b - 1.0) * (4.0 * b + 1.0)) / r_sq;
            let lattice = r_sq / (b * b + 1.0);
            let meets = |sigma_sq: f64| {
                sigma_sq * coset >= smoothing_f64(digits) / two_pi_sq
                    && sigma_sq * lattice >= smoothing_f64(digits * degree) / two_pi_sq
            };
            assert!(meets(got as f64), "b = {base}, k = {digits}");
            assert!(!meets((got - 1) as f64), "b = {base}, k = {digits}");
        }
    }
}
