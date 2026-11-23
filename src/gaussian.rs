// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integer-only discrete Gaussian sampling over `Z`, driven by a SHAKE256 stream.
//!
//! The paper's Gaussian of width `s` has density proportional to `ρ_s(x) = exp(−π x²/s²)`
//! (Section 2), a centred normal of standard deviation `σ = s/√(2π)`. Sampling works in `σ`:
//!
//! * The base sampler draws `x ← D_{Z,σ₀}`, `ρ(x) = exp(−x²/(2V₀))` with `V₀ = σ₀²` an integer,
//!   by inversion of a cumulative table with 128-bit entries over `|x| ≤ X = ⌈13σ₀⌉`. The table
//!   is derived at construction in 256-bit fixed point from `exp(−1/(2V₀))` (a Taylor series)
//!   and the recurrence `ρ(x) = ρ(x − 1)·exp(−(2x − 1)/(2V₀))`, so it holds no pasted constants.
//! * The wide sampler combines `L` independent base draws as `x = Σ_{i<L} K^i·x_i`, evaluated
//!   by Horner's rule `y ← K·y + x_i`. Each step adds a `D_{Z,σ₀}` draw to `K` times a draw of
//!   width at least `σ₀`; by the convolution theorem for integer Gaussians the sum is
//!   statistically close to `D_{Z,√(σ₀² + K²σ'²)}` once `σ₀ ≥ √2·K·η_ε(Z)`. For `ε = 2^-128`,
//!   `η_ε(Z) ≈ 5.33` in the `s` convention, so the condition reads `σ₀ ≥ 24.1`, and the base
//!   variance is never below `32²`. The result has `σ² = V₀·Σ_{i<L} K^{2i}`.
//!
//! Draws are returned as residues modulo `q`: every parameter set keeps `|x| < q/2`, so the
//! centred lift recovers the integer exactly.

use crate::{
    poly::Poly,
    ring::Ring,
    vector::PolyVec,
    zq::{Coeff, Zq},
};
use core::{fmt, num::NonZeroU32};
use crypto_bigint::{Limb, NonZero, U128, U384, U512, U768};
use sha3::{Shake256Reader, digest::XofReader};
use zeroize::Zeroizing;

/// The radix `K` of the wide sampler.
pub(crate) const RADIX: u64 = 8;

/// The least base variance `V₀ = σ₀²`, so that `σ₀ = 32` clears the smoothing condition.
pub(crate) const MIN_BASE_VARIANCE: u32 = 32 * 32;

/// The tail cut `τ`: base draws satisfy `|x| ≤ ⌈τ·σ₀⌉`, which drops mass `exp(−τ²/2) < 2^-121`.
const TAIL: u64 = 13;

/// Fractional bits of the fixed-point arithmetic that derives the table.
const FRACTION_BITS: u32 = 256;

/// Bits of every cumulative table entry and of every uniform draw compared against it.
const TABLE_BITS: u32 = 128;

/// The top bits of a uniform draw that select its bucket in the guide table.
const GUIDE_BITS: u32 = 12;

/// How a uniform value is looked up in the cumulative table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// Every entry is read and compared without a branch: neither the memory touched nor the
    /// time taken depends on the value, as the assembly of one x86-64 release build shows (no
    /// dynamic test). For the draws that are the trapdoor's coefficients.
    Scan,
    /// A search within the range a guide table gives for the value's top bits: about a hundred
    /// times faster and not constant time. For every other draw.
    Guided,
}

/// Fixed-point numbers in `[0, 1]` with [`FRACTION_BITS`] fractional bits.
type Fixed = U384;

/// The sampler `D_{Z,σ}`, `σ² = V₀·Σ_{i<L} K^{2i}`, for one parameter set.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DiscreteGaussian {
    base_variance: NonZeroU32,
    levels: u32,
    tail: u64,
    /// `⌊2^128·Pr[x ≤ i − X]⌋` for `i ∈ [0, 2X)`; `Pr[x ≤ X] = 1` is implicit.
    cdt: Vec<u128>,
    /// For each of the `2^12` buckets of uniform values sharing their top 12 bits, the range of
    /// table indices a value in it can map to, so that a search runs over that range only.
    guide: Vec<(u32, u32)>,
    /// `X mod q`.
    tail_residue: Coeff,
    /// `K` in Montgomery form.
    radix: Coeff,
    /// `X·Σ_{i<L} K^i`, when twice that is below both `q` and `2^128`: a draw is then combined
    /// in a `u128` from its table indices and this is subtracted once.
    offset: Option<Coeff>,
}

impl DiscreteGaussian {
    /// Builds the sampler with base variance `V₀ = base_variance` and `L = levels` base draws per
    /// sample, with residues modulo the `q` of `zq`.
    pub(crate) fn new(base_variance: NonZeroU32, levels: u32, zq: &Zq) -> Self {
        let tail = ceil_sqrt_u64(TAIL * TAIL * u64::from(base_variance.get()));
        let rho = weights(base_variance, tail);
        // S = ρ(0) + 2·Σ_{x ≥ 1} ρ(x).
        let total = rho
            .iter()
            .skip(1)
            .fold(U512::ZERO, |acc, r| acc.wrapping_add(&r.resize()))
            .shl_vartime(1)
            .wrapping_add(&rho[0].resize());
        // S ≥ ρ(0) = 2^256 and S < 2^270, so S is never zero and the fallback is unreachable.
        let total = NonZero::new(total).unwrap_or(NonZero::<U512>::ONE);
        let mut cumulative = U512::ZERO;
        let cdt = (0..2 * tail)
            .map(|i| {
                let weight: U512 = rho[i.abs_diff(tail) as usize].resize();
                cumulative = cumulative.wrapping_add(&weight);
                // ρ(X) ≥ 2^-122 keeps every partial sum below S, so each entry is below 2^128.
                let entry = cumulative
                    .shl_vartime(TABLE_BITS)
                    .div_rem_vartime(&total)
                    .0
                    .resize::<{ U128::LIMBS }>();
                u128::from(entry)
            })
            .collect::<Vec<u128>>();
        let shift = TABLE_BITS - GUIDE_BITS;
        let bound =
            |u: u128| u32::try_from(cdt.partition_point(|&entry| entry <= u)).unwrap_or(u32::MAX);
        let guide = (0..1u128 << GUIDE_BITS)
            .map(|b| {
                (
                    bound(b << shift),
                    bound((b << shift) | ((1u128 << shift) - 1)),
                )
            })
            .collect();
        let mut sampler = Self {
            base_variance,
            levels,
            tail,
            cdt,
            guide,
            tail_residue: zq.reduce_u64(tail),
            radix: zq.montgomery(&Coeff::from_u64(RADIX)),
            offset: None,
        };
        let largest = sampler.max_magnitude();
        let twice = largest.shl_vartime(1);
        if twice.bit_width_vartime() <= u128::BITS && twice < zq.modulus().resize() {
            sampler.offset = Some(largest.resize());
        }
        sampler
    }

    /// The exact variance `σ² = V₀·Σ_{i<L} K^{2i}`.
    pub(crate) fn variance(&self) -> U512 {
        U512::from_u32(self.base_variance.get())
            .wrapping_mul(&radix_sum(RADIX * RADIX, self.levels))
    }

    /// The largest magnitude a sample can take, `X·Σ_{i<L} K^i`.
    pub(crate) fn max_magnitude(&self) -> U512 {
        U512::from_u64(self.tail).wrapping_mul(&radix_sum(RADIX, self.levels))
    }

    /// The next `len` polynomials whose coefficients are independent draws, in order.
    pub(crate) fn vector(&self, reader: &mut Shake256Reader, len: usize, ring: &Ring) -> PolyVec {
        let per_draw = (TABLE_BITS / 8) as usize * self.levels as usize;
        // One polynomial's bytes at a time, in the order single reads would take them.
        let mut buffer = Zeroizing::new(vec![0u8; per_draw * ring.degree()]);
        (0..len)
            .map(|_| {
                reader.read(&mut buffer);
                Poly::from_reduced(
                    buffer
                        .chunks_exact(per_draw)
                        .map(|draw| self.combine(draw, ring.zq()))
                        .collect(),
                )
            })
            .collect()
    }

    /// The next `count` draws as integers, in the order and with the values that
    /// [`DiscreteGaussian::vector`] returns as residues. The stream is read in batches and the
    /// radix combination is done in `i64`; `None` when the largest possible draw does not fit
    /// an `i64`. `lookup` chooses how each uniform value is looked up; the draws are the same
    /// either way.
    pub(crate) fn integers(
        &self,
        reader: &mut Shake256Reader,
        count: usize,
        lookup: Lookup,
    ) -> Option<Vec<i64>> {
        const BATCH: usize = 4096;
        if self.max_magnitude().bit_width_vartime() >= i64::BITS {
            return None;
        }
        let tail = i64::try_from(self.tail).ok()?;
        let radix = i64::try_from(RADIX).ok()?;
        let per_draw = (TABLE_BITS / 8) as usize * self.levels as usize;
        let mut buffer = Zeroizing::new(vec![0u8; per_draw * BATCH]);
        let mut out = Vec::with_capacity(count);
        while out.len() < count {
            let bytes = &mut buffer[..(count - out.len()).min(BATCH) * per_draw];
            reader.read(bytes);
            out.extend(bytes.chunks_exact(per_draw).map(|draw| {
                draw.as_chunks::<{ (TABLE_BITS / 8) as usize }>()
                    .0
                    .iter()
                    .fold(0i64, |acc, chunk| {
                        let index = self.index(u128::from_le_bytes(*chunk), lookup);
                        // index < 2X < 2^63; a checked conversion would branch on the draw.
                        acc * radix + (index as i64 - tail)
                    })
            }));
        }
        Some(out)
    }

    /// One wide draw as a residue, from the bytes of its `L` base draws: `y ← K·y + x_i` with
    /// `x_i = i − X` for the table index `i` of each 16-byte uniform value. With an offset the
    /// indices are combined as integers and `X·Σ K^i` subtracted once; otherwise every step is
    /// taken modulo `q`. Both give the same residue.
    fn combine(&self, draw: &[u8], zq: &Zq) -> Coeff {
        let indices = draw
            .as_chunks::<{ (TABLE_BITS / 8) as usize }>()
            .0
            .iter()
            .map(|chunk| self.index(u128::from_le_bytes(*chunk), Lookup::Guided));
        match &self.offset {
            Some(offset) => zq.sub(
                &Coeff::from_u128(
                    // Widening from index < 2X; there is no `From<usize> for u128`.
                    indices.fold(0u128, |acc, index| acc * u128::from(RADIX) + index as u128),
                ),
                offset,
            ),
            None => indices.fold(Coeff::ZERO, |acc, index| {
                zq.add(
                    &zq.mont_mul(&self.radix, &acc),
                    // index < 2X < 2^64; a checked conversion would branch on the draw.
                    &zq.sub(&zq.reduce_u64(index as u64), &self.tail_residue),
                )
            }),
        }
    }

    /// The first `i` whose cumulative entry exceeds `uniform`: the number of entries that do
    /// not. A scan counts them all, taking each comparison from a subtraction's borrow; a
    /// guided lookup searches the range the guide table gives for the top bits of `uniform`.
    fn index(&self, uniform: u128, lookup: Lookup) -> usize {
        match lookup {
            Lookup::Scan => self.cdt.iter().fold(0usize, |count, &entry| {
                count + usize::from(!uniform.overflowing_sub(entry).1)
            }),
            Lookup::Guided => {
                // The top GUIDE_BITS bits, below 2^12.
                let (start, end) = self.guide[(uniform >> (TABLE_BITS - GUIDE_BITS)) as usize];
                let (start, end) = (start as usize, end as usize);
                start + self.cdt[start..end].partition_point(|&entry| entry <= uniform)
            }
        }
    }
}

impl fmt::Debug for DiscreteGaussian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscreteGaussian")
            .field("base_variance", &self.base_variance)
            .field("levels", &self.levels)
            .field("tail", &self.tail)
            .finish_non_exhaustive()
    }
}

/// `Σ_{i<levels} radix^i`, wrapping (callers keep it far below `2^512`).
pub(crate) fn radix_sum(radix: u64, levels: u32) -> U512 {
    let radix = U512::from_u64(radix);
    (0..levels).fold(U512::ZERO, |acc, _| {
        acc.wrapping_mul(&radix).wrapping_add(&U512::ONE)
    })
}

/// `⌈√x⌉` for a `u64`.
fn ceil_sqrt_u64(x: u64) -> u64 {
    let root = x.isqrt();
    if root * root < x { root + 1 } else { root }
}

/// `ρ(x) = exp(−x²/(2V₀))` for `x ∈ [0, X]` in fixed point, by `ρ(x) = ρ(x − 1)·r^{2x−1}`
/// with `r = exp(−1/(2V₀))`.
fn weights(base_variance: NonZeroU32, tail: u64) -> Vec<Fixed> {
    let one = Fixed::ONE.shl_vartime(FRACTION_BITS);
    // t = 1/(2V₀) = 2^255 / V₀ in fixed point.
    let t = one
        .shr_vartime(1)
        .div_rem_limb(NonZero::<Limb>::from_u32(base_variance))
        .0;
    let r = exp_neg_small(&t);
    let r_squared = fixed_mul(&r, &r);
    let mut factor = r;
    let mut rho = Vec::with_capacity(tail as usize + 1);
    rho.push(one);
    for x in 1..=tail as usize {
        rho.push(fixed_mul(&rho[x - 1], &factor));
        factor = fixed_mul(&factor, &r_squared);
    }
    rho
}

/// `exp(−t)` for a fixed-point `0 ≤ t ≤ 1/2048`, by its Taylor series. The terms fall by a
/// factor of at least 2048 each, so about 25 of them exhaust the precision; even and odd terms
/// are summed apart so that every intermediate is non-negative.
fn exp_neg_small(t: &Fixed) -> Fixed {
    let one = Fixed::ONE.shl_vartime(FRACTION_BITS);
    let (mut even, mut odd) = (one, Fixed::ZERO);
    let mut term = one;
    let mut n = NonZeroU32::MIN;
    loop {
        term = fixed_mul(&term, t)
            .div_rem_limb(NonZero::<Limb>::from_u32(n))
            .0;
        if term == Fixed::ZERO {
            return even.wrapping_sub(&odd);
        }
        if n.get() % 2 == 0 {
            even = even.wrapping_add(&term);
        } else {
            odd = odd.wrapping_add(&term);
        }
        n = n.saturating_add(1);
    }
}

/// The truncated fixed-point product `⌊a·b / 2^256⌋`.
fn fixed_mul(a: &Fixed, b: &Fixed) -> Fixed {
    let wide: U768 = a.concatenating_mul(b);
    wide.shr_vartime(FRACTION_BITS).resize()
}

#[cfg(test)]
mod tests {
    use super::{
        DiscreteGaussian, Lookup, MIN_BASE_VARIANCE, RADIX, exp_neg_small, fixed_mul, weights,
    };
    use crate::{
        sample::{DomainLabel, Seed, xof},
        test_util::{TOY, centred_f64, to_f64},
    };
    use crypto_bigint::{U384, U512};
    use std::num::NonZeroU32;

    /// The integer combination of a draw and the modular one give the same polynomials from the
    /// same stream.
    #[test]
    fn both_combinations_of_a_draw_agree() {
        let ring = TOY.ring();
        let direct = TOY.gaussian().clone();
        assert!(direct.offset.is_some());
        let modular = DiscreteGaussian {
            offset: None,
            ..direct.clone()
        };
        let stream = || {
            xof(
                &Seed::from([7u8; 32]),
                DomainLabel::from(&b"kln/test/combine"[..]),
            )
        };
        assert_eq!(
            direct.vector(&mut stream(), 3, ring),
            modular.vector(&mut stream(), 3, ring)
        );
    }

    /// The full scan and the guided lookup return what a search of the sorted table returns, at every table entry,
    /// on both sides of it, at the ends of the range and for values from a stream.
    #[test]
    fn the_scan_is_the_search() {
        let gaussian = base(MIN_BASE_VARIANCE);
        let search = |u: u128| gaussian.cdt.partition_point(|&entry| entry <= u);
        let mut reader = xof(
            &Seed::from([9u8; 32]),
            DomainLabel::from(&b"kln/test/scan"[..]),
        );
        let stream = (0..4096).map(|_| {
            let mut bytes = [0u8; 16];
            sha3::digest::XofReader::read(&mut reader, &mut bytes);
            u128::from_le_bytes(bytes)
        });
        let edges = gaussian
            .cdt
            .iter()
            .flat_map(|&entry| [entry.wrapping_sub(1), entry, entry.wrapping_add(1)]);
        for u in edges.chain([0, u128::MAX]).chain(stream) {
            assert_eq!(gaussian.index(u, Lookup::Scan), search(u), "{u}");
            assert_eq!(gaussian.index(u, Lookup::Guided), search(u), "{u}");
        }
    }

    fn base(variance: u32) -> DiscreteGaussian {
        DiscreteGaussian::new(NonZeroU32::new(variance).unwrap(), 1, TOY.ring().zq())
    }

    #[test]
    fn fixed_point_weights_match_f64() {
        let one = U384::ONE.shl_vartime(256);
        assert_eq!(fixed_mul(&one, &one), one);
        assert_eq!(exp_neg_small(&U384::ZERO), one);
        for variance in [MIN_BASE_VARIANCE, 16_477, 66_495] {
            let tail = 13 * u64::from(variance).isqrt() + 13;
            let rho = weights(NonZeroU32::new(variance).unwrap(), tail);
            assert_eq!(rho.len() as u64, tail + 1);
            for (x, r) in rho.iter().enumerate() {
                let expected = (-((x * x) as f64) / (2.0 * f64::from(variance))).exp();
                let got = to_f64(&r.resize()) / 2f64.powi(256);
                assert!((got - expected).abs() < 1e-15, "{variance}, {x}");
            }
        }
    }

    /// The table probabilities, recovered as differences of consecutive entries, agree with an
    /// independent floating-point evaluation of `exp(−x²/(2V₀)) / S`.
    #[test]
    fn table_matches_floating_point_density() {
        for variance in [MIN_BASE_VARIANCE, 16_477, 66_495] {
            let gaussian = base(variance);
            let sigma = f64::from(variance).sqrt();
            assert_eq!(gaussian.tail, (13.0 * sigma).ceil() as u64);
            let tail = gaussian.tail as i64;
            let density = |x: i64| (-((x * x) as f64) / (2.0 * f64::from(variance))).exp();
            let total: f64 = (-tail..=tail).map(density).sum();
            let scale = 2f64.powi(128);
            let mut previous = 0.0;
            for (i, &entry) in gaussian.cdt.iter().enumerate() {
                let x = i as i64 - tail;
                let probability = (entry as f64 - previous) / scale;
                previous = entry as f64;
                assert!(
                    (probability - density(x) / total).abs() < 1e-15,
                    "V₀ = {variance}, x = {x}"
                );
            }
            // The last cumulative entry is 1 − Pr[x = X].
            assert!((1.0 - previous / scale - density(tail) / total).abs() < 1e-15);
            assert_eq!(gaussian.cdt.len() as u64, 2 * gaussian.tail);
        }
    }

    #[test]
    fn variance_and_max_magnitude() {
        let gaussian = DiscreteGaussian::new(NonZeroU32::new(2000).unwrap(), 3, TOY.ring().zq());
        // V₀·(1 + 64 + 4096) and X·(1 + 8 + 64) with X = ⌈13·√2000⌉ = 582.
        assert_eq!(gaussian.variance(), U512::from_u64(2000 * 4161));
        assert_eq!(gaussian.max_magnitude(), U512::from_u64(582 * 73));
        assert_eq!(RADIX, 8);
        assert!(format!("{gaussian:?}").starts_with("DiscreteGaussian { base_variance: 2000"));
    }

    /// The wide sampler at the toy set: over 2^18 draws the empirical standard deviation is
    /// within 1% of `σ`, the mean within 1% of `σ` of zero, and no draw exceeds the hard bound.
    #[test]
    fn wide_sampler_moments_at_toy_set() {
        let ring = TOY.ring();
        let gaussian = TOY.gaussian();
        let sigma = to_f64(&gaussian.variance()).sqrt();
        let max = to_f64(&gaussian.max_magnitude());
        let mut reader = xof(
            &Seed::from([3; 32]),
            DomainLabel::from(&b"kln/test/gaussian"[..]),
        );
        let values = centred_f64(&gaussian.vector(&mut reader, 4096, ring), ring);
        let count = values.len() as f64;
        let mean = values.iter().sum::<f64>() / count;
        let std = (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / count).sqrt();
        assert!((std / sigma - 1.0).abs() < 0.01, "{std} vs {sigma}");
        assert!(mean.abs() < 0.01 * sigma, "{mean}");
        assert!(values.iter().all(|v| v.abs() <= max));
    }

    #[test]
    fn same_stream_same_draws() {
        let ring = TOY.ring();
        let draw = |seed: u8| {
            let mut reader = xof(&Seed::from([seed; 32]), DomainLabel::from(&b"kln/test"[..]));
            TOY.gaussian().vector(&mut reader, 2, ring)
        };
        assert_eq!(draw(1), draw(1));
        assert_ne!(draw(1), draw(2));
    }
}
