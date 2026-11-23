// SPDX-License-Identifier: MIT OR Apache-2.0
//! The floating-point half of the preimage sampler: `SampleD` of ePrint 2011/501, Section 5.4,
//! Algorithm 3 (reference [51] of ePrint 2017/308, recalled in its Sections 1 and 4), with the
//! G-lattice sampler of ePrint 2017/308, Section 3, for arbitrary modulus and its perturbation
//! sampler for ring trapdoors, Section 4.
//!
//! This module and its children are the only floating-point code on any sampling path. They
//! use `f64` addition, subtraction, multiplication, division and square root, and `as`
//! conversions between `f64` and integers, nothing else: every one of these is correctly
//! rounded by IEEE 754, so the same seed gives the same preimage on every platform. No
//! transcendental function is called, neither for the roots of unity of the FFT (which are
//! repeated complex square roots of `i`) nor for sampling over `Z` with a real centre (which
//! compares uniform deviates, as in ePrint 2017/308's reference [41], Algorithm D).
//!
//! References by number are to the bibliography of ePrint 2017/308:
//! [41] is the work titled "Sampling exactly from the normal distribution" (ACM Transactions on
//! Mathematical Software 42(1), 2016), and [55] the work titled "An efficient and parallel
//! gaussian sampler for lattices" (CRYPTO 2010). Neither was read for this crate, so the
//! algorithm and theorem numbers quoted from them here are not checked against their text.
//!
//! # Construction
//!
//! Widths here are variances `V = s²/(2π)` of the widths `s` of ePrint 2017/308, whose
//! `D_{Λ,√Σ}` has covariance `Σ/(2π)` (Section 2.2; ePrint 2011/501, Section 2.3, likewise).
//! Section, figure, lemma and theorem numbers in this module and its children are those of
//! ePrint 2017/308 unless another work is named. `T` is a G-trapdoor for `A` with tag `I`,
//! `A·[T; I] = G` (ePrint 2011/501, Definition 5.2), and `R = [T; I]`. The trapdoor stage
//! samples a preimage of `v` under `A` with spherical variance `V₀` by Algorithm 3 with
//! `Σ = V₀` and `Σ_G = α²`: the off-line perturbation and the on-line G-lattice sample that
//! ePrint 2017/308, Section 1 also describes.
//!
//! 1. A perturbation `p ← D_{Z^{md}, √Σ_p}` with `Σ_p = V₀·I − α²·R·Rᵀ` (Algorithm 3, step 1;
//!    the covariance of Section 4's opening paragraph and of `SamplePz`, Figure 4), by
//!    [`perturbation`]: its last `m'` entries are spherical with variance `V₀ − α²`, and its
//!    first `m − m'` are drawn given them, with the Schur complement `V₀·I − κ·T·T*`,
//!    `κ = (α^{-2} − V₀^{-1})^{-1}`, as covariance. Algorithm 3 suggests rounding a continuous
//!    Gaussian instead (its Runtime analysis, by ePrint 2017/308's reference [55], Theorem 3.1); the discrete
//!    sampler of Section 4 is used here.
//! 2. `z ← D_{Λ⊥_{v − A·p}(G), α}` (step 3), one G-lattice sample per coefficient, by
//!    [`gadget`]: `Λ⊥(G)` is the orthogonal sum of copies of `Λ⊥(gᵀ)` (Section 1).
//! 3. The result `p + R·z` (step 4), so `A·(p + R·z) = A·p + G·z = v`.
//!
//! The G-lattice sampler draws variance `α² = σ²·((b+1)² + 1)` per coordinate, and the least
//! variance `V₀` is at least `(α² + 2M')·(S² + 1) + M` for the bound `S ≥ s₁(T)` of Theorem
//! 2.1 of ePrint 2025/1099 (or of its Lemma A.2 for a ternary trapdoor), so that `√V₀` bounds
//! the spectral norm of `α·R` as Section 4 asks and Algorithm 3's covariance condition holds.
//! `σ²`, `M'` and `M` are the least integers meeting the smoothing conditions below
//! (`crate::params`); key generation also refuses a trapdoor unless every pivot of step 1's
//! decomposition is at least `V₀/4` ([`Perturbation::new`]).
//!
//! The width `s` of the scheme is far above what `f64` can carry (about `2^77` at the 128-bit
//! set). The caller writes it as a convolution: an integer-only spherical draw `y` with
//! variance `V_y = s²/(2π) − V₀` (the crate's table sampler, no floating point), then this
//! stage at `V₀` on the residual target `u − A·y`, and the sum. For `SampleLeft` the
//! extension coordinates are `y` plus a spherical draw of variance `V₀`. Neither
//! ePrint 2017/308 nor ePrint 2011/501 has this step; it is how this crate reaches a width
//! beyond `f64`.
//!
//! # Statistical conditions relied on
//!
//! Every smoothing condition is met at `ε = 2^-128` through `C_{ε,N} = √(ln(2N(1 + 1/ε))/π)`,
//! the constant ePrint 2017/308 states before Corollary 3.1: `η_ε` of an `N`-dimensional
//! lattice with a basis `B` is at most `‖B̃‖·C_{ε,N}` (Lemma 2.2; ePrint 2007/432, Lemma 3.1;
//! ePrint 2011/501, Lemma 2.3).
//!
//! * Sampling over `Z` with a real centre is exact up to the 53-bit uniform deviates that
//!   decide each comparison, and is cut at 13 standard deviations: by Lemma 2.1 of
//!   ePrint 2017/308 (ePrint 2007/432, Lemma 4.2) the mass cut is at most
//!   `2·e^{−169/2}·(1 + ε)/(1 − ε) < 2^-120`.
//! * Each convolution is ePrint 2017/308, Theorem 2.3 (ePrint 2017/308's reference [55], Theorem 3.1), or its
//!   Lemma 4.3 on `Z^N`, applied along a triangular decomposition: the randomized
//!   nearest-plane argument of Theorem 2.4, which is ePrint 2007/432, Theorem 4.1, and whose
//!   proof (with that paper's Lemmas 2.7 and 4.5) needs only every one-dimensional width to be
//!   at least `η_ε(Z)`; `Perturb` and `SampleD` instantiate it (Section 3.2).
//! * Step 2, and Algorithm 3's input condition `r√Σ_G ≥ η_ε(Λ⊥(G))`: [`gadget`] meets its
//!   conditions for one coset of `Λ⊥(gᵀ)` with `C_{ε,k}`, and `σ²` is also large enough that
//!   `√(2π)·α ≥ √(b² + 1)·C_{ε,m'd} ≥ η_ε(Λ⊥(G))` for all of `Λ⊥(G)` at once, by the basis of
//!   ePrint 2011/501, Theorem 4.1, whose Gram–Schmidt vectors are at most `√(b² + 1)` long.
//!   Algorithm 3 also asks `Σ_G ≥ 2` in units of `r² ≥ η_ε(Z^{m'd})²`, which this implies.
//! * Step 1: `Σ_p ⪰ 2M'·R·Rᵀ`, Algorithm 3's condition `Σ_p ≥ 2[R; I][Rᵗ I]`, which the proof
//!   of its Theorem 5.5 uses for the smoothing of `L([R; I])` (with `r ≥ η_ε(Z^{m'd})` by its
//!   Lemma 2.3); and `Σ_p ⪰ M·I ⪰ η_ε(Z^{md})²/(2π)`, the hypothesis of ePrint 2017/308,
//!   Theorem 4.1. Both hold when `s₁(T) ≤ S`. The pivot floor makes every conditional
//!   variance of the recursion at least `V₀/4` (Theorems 2.1 and 2.2 of ePrint 2017/308,
//!   interlacing), which is what Lemma 4.3 asks of each step, deterministically and with a wide
//!   margin. Under these conditions Algorithm 3's output is within `O(ε)` of
//!   `D_{Λ⊥_u(A), √(2πV₀)}` (its Theorem 5.5).
//! * The outer convolution, ePrint 2017/308, Theorem 2.3 again: `√(2π·V₀) ≥ η_ε(Λ⊥(A))`
//!   because `V₀ ≥ (⌈S⌉ + 1)²·(b² + 1)·C_{ε,md}²/(2π)` and `Λ⊥(A)` has a basis with
//!   Gram–Schmidt vectors at most `(s₁(T) + 1)·√(b² + 1)` long (ePrint 2011/501, Lemma 5.3
//!   with Theorem 4.1); and `(1/V_y + 1/V₀)^{-1} ≥ V₀/2` is far above `C_{ε,N}²/(2π)` for
//!   every dimension `N` a preimage has.
//!
//! # Precision
//!
//! Every centre and variance the perturbation computes scales with `√V₀`, so the precision
//! margin is the same at every set: centres are computed with an error of a few hundred ulps of
//! their magnitude, which is a few standard deviations, against conditional standard
//! deviations of at least `√V₀/2`. The relative error is below `2^-40` at every defined set;
//! the tests measure it. The G-lattice sampler's centres are rationals `x/bⁱ` (ePrint
//! 2017/308, Section 3.2, Storage) at most `(b + 13α)/(b − 1)` in magnitude, against
//! deviations of at least `σ`.
//!
//! These are measurements, not a bound on the statistical loss. ePrint 2017/308 bounds that
//! loss for the G-lattice sampler in ML distance (Proposition 3.1), and the security it then
//! states assumes a mantissa of `κ/2` bits, 64 for `κ = 128`, where `f64` has 53; for the
//! perturbation it gives no floating-point analysis (Section 4.1, before Theorem 4.1).

pub(crate) mod fft;
pub(crate) mod gadget;
pub(crate) mod perturbation;

pub(crate) use gadget::GadgetSampler;
pub(crate) use perturbation::Perturbation;

use core::fmt;
use shake::{Shake256Reader, digest::XofReader};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The tail cut: every draw over `Z` lies within this many standard deviations of its centre.
pub(crate) const TAIL: u64 = 13;

/// Bytes read from the stream at a time.
const BUFFER: usize = 512;

/// `2^-53`, the spacing of uniform deviates.
const DEVIATE_UNIT: f64 = 1.0 / 9_007_199_254_740_992.0;

/// The trapdoor stage at one parameter set, in integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stage {
    /// The least variance `V₀`, with at most 53 significant bits so that it is exact as `f64`.
    pub(crate) least_variance: u128,
    /// The variance `σ²` of the G-lattice sampler's draws on `L(D)` ([`gadget`]).
    pub(crate) gadget_base_variance: u64,
    /// The G-lattice sampler's output variance `α² = σ²·((b+1)² + 1)`.
    pub(crate) gadget_variance: u64,
    /// `⌈13·√V₀⌉ + 1`, the largest magnitude of a coordinate the stage returns.
    pub(crate) tail: u128,
}

impl Stage {
    /// `V₀` as `f64`, exactly.
    pub(crate) fn variance(&self) -> f64 {
        // V₀ is rounded to 53 significant bits when the stage is derived, so this is exact.
        self.least_variance as f64
    }
}

/// Uniform values from a SHAKE256 stream: 64-bit words little-endian, and deviates in `[0, 1)`
/// as their top 53 bits times `2^-53`. The buffered stream bytes are the sampler's secret
/// randomness and are overwritten when the value is dropped.
pub(crate) struct Uniform<'a> {
    reader: &'a mut Shake256Reader,
    buffer: [u8; BUFFER],
    position: usize,
}

impl<'a> Uniform<'a> {
    /// Reads from `reader` from its current position on.
    pub(crate) fn new(reader: &'a mut Shake256Reader) -> Self {
        Self {
            reader,
            buffer: [0; BUFFER],
            position: BUFFER,
        }
    }

    /// The next 64-bit word.
    fn word(&mut self) -> u64 {
        if self.position == BUFFER {
            self.reader.read(&mut self.buffer);
            self.position = 0;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[self.position..self.position + 8]);
        self.position += 8;
        u64::from_le_bytes(bytes)
    }

    /// A deviate uniform on the multiples of `2^-53` in `[0, 1)`.
    fn deviate(&mut self) -> f64 {
        // Below 2^53 after the shift, so the conversion is exact.
        (self.word() >> 11) as f64 * DEVIATE_UNIT
    }

    /// An integer uniform in `[0, n)` for `n ≥ 1`, by rejection of the top partial block.
    fn below(&mut self, n: u64) -> u64 {
        let limit = u64::MAX - u64::MAX % n;
        loop {
            let word = self.word();
            if word < limit {
                return word % n;
            }
        }
    }
}

impl Drop for Uniform<'_> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl ZeroizeOnDrop for Uniform<'_> {}

impl fmt::Debug for Uniform<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uniform").finish_non_exhaustive()
    }
}

/// `D_{Z, σ, c}`: an integer `z` with probability proportional to `exp(−(z − c)²/(2σ²))`,
/// cut to `|z − c| < 13σ`, by ePrint 2017/308's reference [41], Algorithm D.
///
/// This is the `SampleZt` of ePrint 2017/308, Figure 2, which admits any one-dimensional
/// sampler; Section 3.3 uses the same one (its reference [41]). Figure 2 also fixes a common
/// support `[c − t·σ_max, c + t·σ_max]` for every draw, for its ML-distance analysis
/// (Proposition 3.1); here each draw is cut at 13 of its own standard deviations instead, and
/// the analysis is by statistical distance (see the module documentation).
///
/// `σ` must be at least 1 and `|c| + 13σ` below `2^52`.
pub(crate) fn sample_z(uniform: &mut Uniform<'_>, centre: f64, std: f64) -> i64 {
    let span = ceil_u64(std);
    loop {
        // D1, D2: k with probability proportional to exp(−k²/2); k < 13 is the tail cut.
        let k = geometric(uniform);
        if k >= TAIL || !half_power(uniform, k * k.saturating_sub(1)) {
            continue;
        }
        // D3, D4: a side, and the candidate s·(i₀ + j) at x standard deviations past kσ.
        let negative = uniform.word() & 1 == 1;
        let side = if negative { -centre } else { centre };
        // k < 13, and start and j are below 2^52 by the bound on |c| + 13σ: exact.
        let shifted = std * k as f64 + side;
        let start = ceil_i64(shifted);
        let x0 = (start as f64 - shifted) / std;
        let j = uniform.below(span);
        let x = x0 + j as f64 / std;
        // D5, D6: x in [0, 1), and zero counted once.
        if x >= 1.0 || (x == 0.0 && k == 0 && negative) {
            continue;
        }
        // D7: accept with probability exp(−x(2k + x)/2), as k + 1 draws of B(k, x).
        if !(0..=k).all(|_| exp_bernoulli(uniform, k, x)) {
            continue;
        }
        let magnitude = start + j as i64;
        return if negative { -magnitude } else { magnitude };
    }
}

/// `n` draws of [`sample_z`] with standard deviation `std` around zero, overwritten when
/// dropped.
pub(crate) fn spherical(uniform: &mut Uniform<'_>, std: f64, n: usize) -> Zeroizing<Vec<i64>> {
    Zeroizing::new((0..n).map(|_| sample_z(uniform, 0.0, std)).collect())
}

/// Algorithm H of ePrint 2017/308's reference [41]: true with probability `exp(−1/2)`, by the parity of a
/// descending run of deviates starting below `1/2`.
fn exp_minus_half(uniform: &mut Uniform<'_>) -> bool {
    let mut a = uniform.deviate();
    if a >= 0.5 {
        return true;
    }
    loop {
        let b = uniform.deviate();
        if b >= a {
            return false;
        }
        a = uniform.deviate();
        if a >= b {
            return true;
        }
    }
}

/// Step N1 (= D1) of ePrint 2017/308's reference [41] as rewritten in terms of Algorithm H in its Section 3:
/// the number of consecutive successes of [`exp_minus_half`], stopped once it reaches the tail
/// cut (such a value is rejected by the caller).
fn geometric(uniform: &mut Uniform<'_>) -> u64 {
    let mut n = 0;
    while n < TAIL && exp_minus_half(uniform) {
        n += 1;
    }
    n
}

/// Step N2 (= D2) of ePrint 2017/308's reference [41] in terms of Algorithm H: true with probability
/// `exp(−n/2)`, as `n` successes of [`exp_minus_half`].
fn half_power(uniform: &mut Uniform<'_>, n: u64) -> bool {
    (0..n).all(|_| exp_minus_half(uniform))
}

/// Algorithm B of ePrint 2017/308's reference [41]: true with probability `exp(−x(2k + x)/(2k + 2))` for `x ∈ [0, 1)`.
fn exp_bernoulli(uniform: &mut Uniform<'_>, k: u64, x: f64) -> bool {
    // k < 13: exact.
    let bound = (2.0 * k as f64 + x) / (2.0 * k as f64 + 2.0);
    let mut y = x;
    let mut n = 0u64;
    loop {
        let z = uniform.deviate();
        if z >= y {
            break;
        }
        let r = uniform.deviate();
        if r >= bound {
            break;
        }
        y = z;
        n += 1;
    }
    n.is_multiple_of(2)
}

/// `⌈x⌉` for `1 ≤ x < 2^63`, by truncation.
fn ceil_u64(x: f64) -> u64 {
    // In range for the documented 1 ≤ x < 2^63; the cast saturates outside it.
    let truncated = x as u64;
    if (truncated as f64) < x {
        truncated + 1
    } else {
        truncated
    }
}

/// `⌈x⌉` for `|x| < 2^62`, by truncation toward zero.
fn ceil_i64(x: f64) -> i64 {
    // In range for the documented |x| < 2^62; the cast saturates outside it.
    let truncated = x as i64;
    if (truncated as f64) < x {
        truncated + 1
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::{Uniform, ceil_i64, ceil_u64, sample_z, spherical};
    use crate::sample::{DomainLabel, Seed, xof};
    use std::path::Path;

    fn stream(seed: u8) -> shake::Shake256Reader {
        xof(
            &Seed::from([seed; 32]),
            DomainLabel::from(&b"kln/test/preimage"[..]),
        )
    }

    #[test]
    fn ceilings() {
        assert_eq!(ceil_u64(1.0), 1);
        assert_eq!(ceil_u64(1.5), 2);
        assert_eq!(ceil_u64(2f64.powi(44) + 0.25), (1 << 44) + 1);
        assert_eq!(ceil_i64(-2.5), -2);
        assert_eq!(ceil_i64(-3.0), -3);
        assert_eq!(ceil_i64(0.1), 1);
        assert_eq!(ceil_i64(-0.1), 0);
    }

    /// The empirical mean and variance of `D_{Z,σ,c}` match the exact moments of the discrete
    /// distribution, computed by summing its weights, for small and large widths and centres
    /// with and without a fractional part; no draw passes the tail cut.
    #[test]
    fn real_centre_moments() {
        const DRAWS: usize = 200_000;
        for (i, (centre, std)) in [
            (0.0, 1.0),
            (0.5, 1.2),
            (-3.25, 2.236),
            (1e6 + 0.3, 7.5),
            (-12_345.678, 1000.0),
            (2f64.powi(40) + 0.75, 2f64.powi(30)),
        ]
        .into_iter()
        .enumerate()
        {
            let mut reader = stream(i as u8);
            let mut uniform = Uniform::new(&mut reader);
            let draws: Vec<f64> = (0..DRAWS)
                .map(|_| sample_z(&mut uniform, centre, std) as f64 - centre)
                .collect();
            assert!(draws.iter().all(|x| x.abs() < 13.0 * std));
            let mean = draws.iter().sum::<f64>() / DRAWS as f64;
            let variance = draws.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / DRAWS as f64;
            // Exact moments of the discrete distribution around its centre.
            let start = (centre - 14.0 * std).floor() as i64;
            let end = (centre + 14.0 * std).ceil() as i64;
            let step = ((end - start) / 2_000_000).max(1);
            let (mut weight, mut first, mut second) = (0.0, 0.0, 0.0);
            let mut z = start;
            while z <= end {
                let x = z as f64 - centre;
                let w = (-x * x / (2.0 * std * std)).exp();
                weight += w;
                first += w * x;
                second += w * x * x;
                z += step;
            }
            let exact_mean = first / weight;
            let exact_variance = second / weight - exact_mean * exact_mean;
            let tolerance = 5.0 * (exact_variance / DRAWS as f64).sqrt();
            assert!(
                (mean - exact_mean).abs() < tolerance,
                "c = {centre}, σ = {std}: mean {mean} vs {exact_mean}"
            );
            assert!(
                (variance / exact_variance - 1.0).abs() < 5.0 * (2.0 / DRAWS as f64).sqrt(),
                "c = {centre}, σ = {std}: variance {variance} vs {exact_variance}"
            );
        }
    }

    /// The frequencies of the values of a narrow `D_{Z,σ,c}` agree with its exact probabilities
    /// (a χ² test over the values within four standard deviations).
    #[test]
    fn narrow_distribution_matches_exactly() {
        const DRAWS: usize = 400_000;
        let (centre, std) = (0.37, 1.5);
        let mut reader = stream(40);
        let mut uniform = Uniform::new(&mut reader);
        let mut counts = std::collections::BTreeMap::new();
        for _ in 0..DRAWS {
            *counts
                .entry(sample_z(&mut uniform, centre, std))
                .or_insert(0usize) += 1;
        }
        let density = |z: i64| (-(z as f64 - centre).powi(2) / (2.0 * std * std)).exp();
        let total: f64 = (-30..=30).map(density).sum();
        let mut chi_squared = 0.0;
        let mut cells = 0;
        for z in -6..=6 {
            let expected = DRAWS as f64 * density(z) / total;
            let observed = *counts.get(&z).unwrap_or(&0) as f64;
            chi_squared += (observed - expected).powi(2) / expected;
            cells += 1;
        }
        // 13 cells: the 99.9% quantile of χ² with 12 degrees of freedom is 32.9.
        assert!(chi_squared < 32.9, "χ² = {chi_squared} over {cells} cells");
    }

    #[test]
    fn same_stream_same_draws() {
        let draw = |seed| {
            let mut reader = stream(seed);
            let mut uniform = Uniform::new(&mut reader);
            spherical(&mut uniform, 1234.5, 64)
        };
        assert_eq!(draw(1), draw(1));
        assert_ne!(draw(1), draw(2));
    }

    /// The source of the sampling modules (`src/preimage.rs` and `src/preimage/`, outside their
    /// tests and comments) calls no floating-point function other than `sqrt`, and every other
    /// file outside its tests and comments uses no floating point at all, except the proof's
    /// rejection sampling, whose output need not be reproducible, and the test-only files.
    #[test]
    fn floating_point_is_confined_and_basic() {
        const FORBIDDEN: [&str; 24] = [
            ".exp(",
            ".exp2(",
            ".exp_m1(",
            ".ln(",
            ".ln_1p(",
            ".log(",
            ".log2(",
            ".log10(",
            ".powf(",
            ".powi(",
            ".sin(",
            ".cos(",
            ".tan(",
            ".sin_cos(",
            ".atan2(",
            ".hypot(",
            ".cbrt(",
            ".mul_add(",
            ".floor(",
            ".ceil(",
            ".round(",
            ".trunc(",
            ".fract(",
            ".abs(",
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        let mut pending = vec![root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
        let mut sampling = 0;
        for path in files {
            let text = std::fs::read_to_string(&path).unwrap();
            // The code before the first test item, without comments.
            let body: String = text
                .split("#[cfg(test)]")
                .next()
                .unwrap()
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let relative = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if relative == "preimage.rs" || relative.starts_with("preimage/") {
                sampling += 1;
                for name in FORBIDDEN {
                    assert!(!body.contains(name), "{relative} calls {name}");
                }
            } else if relative != "proof/rejection.rs"
                && relative != "test_util.rs"
                && !relative.ends_with("tests.rs")
            {
                for name in ["f64", "f32"] {
                    assert!(!body.contains(name), "{relative} uses {name}");
                }
            }
        }
        assert_eq!(sampling, 4);
    }
}
