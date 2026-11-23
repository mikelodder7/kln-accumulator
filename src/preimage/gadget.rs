// SPDX-License-Identifier: MIT OR Apache-2.0
//! Discrete Gaussian sampling over cosets of `Λ⊥(gᵀ) = {z ∈ Z^k : ⟨g, z⟩ ≡ 0 (mod q)}` for
//! `g = (1, b, …, b^{k−1})` and a modulus `q < b^k` that need not be a power of `b`: `SampleG`
//! of ePrint 2017/308, Section 3.2, Figure 2, with the perturbation drawn on `Z^k` instead of
//! the lattice `Perturb` uses (see below). Variances here are `V = s²/(2π)` for the paper's
//! widths `s`. Section, figure, equation, lemma and theorem numbers in this module are those of
//! ePrint 2017/308.
//!
//! # Construction
//!
//! With `q = Σ qᵢ·bⁱ`, the lattice has the basis `B_q` whose column `j < k − 1` is
//! `b·e_j − e_{j+1}` and whose last column is `(q₀, …, q_{k−1})` (Section 3; ePrint 2011/501,
//! Section 4.2, for base 2, and its Theorem 4.1 for base `b`, with Gram–Schmidt vectors at
//! most `√(b² + 1)` long). Section 3.1
//! factors it as `B_q = B·D`, with `B = B_{b^k}` the basis for modulus `b^k` (lower bidiagonal,
//! `b` on the diagonal and `−1` below) used as a linear map, and `D` the identity except for
//! its last column `d`, `dᵢ = (d_{i−1} + qᵢ)/b` from `d₋₁ = 0`, so `d_{k−1} = q/b^k ∈ (0, 1)`.
//! Following the outline of Section 3 (its steps 1 to 6), a sample of the coset of `u` with
//! variance `α²` is `x = p + B·y`:
//!
//! * `p ← D_{Z^k, √Σ₂}` for the complementary covariance `Σ₂ = α²·I − σ²·B·Bᵀ` (steps 1–3);
//! * `c = B⁻¹(u⃗ − p)` by forward substitution, the first loop of `SampleG` (step 4);
//! * `y = c + D·z ← D_{L(D) + c, σ}` by `SampleD`, the nearest-plane sampler on `D`, whose
//!   Gram–Schmidt vectors are `e₀, …, e_{k−2}` and `d_{k−1}·e_{k−1}`: `z_{k−1}` at standard
//!   deviation `σ/d_{k−1}`, then the others independently at `σ` (step 5);
//! * `x = u⃗ + B_q·z`, the last loop of `SampleG`, in integers (step 6);
//!
//! where `u⃗` holds the base-`b` digits of `u`. Every step is sparse, so a sample costs `O(k)`.
//! This is the hybrid ePrint 2011/501, Section 4.2 suggests for a modulus that is not a power
//! of the base: one randomized nearest-plane step for the last basis vector and the
//! convolution of ePrint 2017/308's reference [55] for the others.
//! The one-dimensional draws are [`sample_z`], the sampler of ePrint 2017/308's reference [41],
//! which Section 3.3 also uses; Figure 2 admits any such sampler.
//!
//! # The perturbation: a deliberate difference
//!
//! Figure 2's `Perturb(σ)` takes `σ = s/(b + 1)` and `Σ₂ = (b + 1)²·I − B·Bᵀ` and draws `p` on
//! the lattice `L(Σ₂)`, as `p = Σ₂·z` for a nearest-plane sample `z` along the closed-form
//! upper-triangular Cholesky factor of equation (1). Here `p` lies on `Z^k` and
//! `Σ₂ = σ²·(r²·I − B·Bᵀ)` with `r² = (b + 1)² + 1`, so `α² = σ²·r²`. `Σ₂` is tridiagonal; its
//! `LDLᵀ` decomposition has a unit lower bidiagonal `L`, so `pᵢ` is drawn given `p_{i−1}` and
//! its centre alone, with the pivot `Dᵢ` as variance. Two reasons:
//!
//! * Width. The middle condition stated before Corollary 3.1, `√Σ₃ ≥ η_ε(Σ₂)` (the smoothing
//!   parameter of `Perturb`'s lattice `L(Σ₂)`), is what forces `s ≥ √(2b)·(2b + 1)·C_{ε,k}`
//!   there. On `Z^k` the same condition is about `η_ε(Z^k)` and holds at a width
//!   `√(2π)·α ≈ (b + 1)·C_{ε,k}` (below), about `2√(2b)` times narrower; the trapdoor stage's
//!   least variance is proportional to `α²`.
//! * Conditioning. With `r = b + 1`, `Σ₂` tends to singularity as `k` grows (its least
//!   eigenvalue is `(b + 1)² − λ_max(B·Bᵀ)`), and Section 3.1 notes that its lower-triangular
//!   factor needs far more precision than its upper-triangular one. All eigenvalues of `B·Bᵀ`
//!   lie in `[(b − 1)², (b + 1)²]` (Section 3.1, by the Gershgorin circle theorem), so with
//!   `r² = (b + 1)² + 1`, `Σ₂ ⪰ σ²·I` and every pivot `Dᵢ` is at least `σ²`.
//!
//! # Width conditions
//!
//! `x` is the convolution of ePrint 2017/308, Theorem 2.3 (ePrint 2017/308's reference [55], Theorem 3.1) with
//! `Λ₁ = Λ⊥(gᵀ)`, covariance `Σ₁ = σ²·B·Bᵀ`, `Λ₂ = Z^k` and `Σ₂` as above, so its output is
//! within `8ε` of `D_{Λ⊥_u(gᵀ), α}` (up to the nearest-plane steps) once the following hold.
//! The theorem's matrices are `2π` times these covariances, so a smoothing parameter is
//! compared with `√(2π)` times a standard deviation.
//!
//! * `√Σ₁ ≥ η_ε(Λ⊥(gᵀ))`, which is `√(2π)·σ ≥ η_ε(L(D))` since `Λ⊥(gᵀ) = B·L(D)`: the first
//!   condition before Corollary 3.1, `s ≥ (b + 1)·η_ε(D)`, in Figure 2's scaling. Lemma 2.2
//!   bounds `η_ε(L(D)) ≤ C_{ε,k} = √(ln(2k(1 + 1/ε))/π)` because `‖D̃‖ = 1`.
//! * `√Σ₃ ≥ η_ε(Z^k)` for `Σ₃⁻¹ = Σ₁⁻¹ + Σ₂⁻¹`. As in Lemma 3.1, the eigenvalues of `Σ₃` are
//!   `σ²·λ(r² − λ)/r²` over the eigenvalues `λ` of `B·Bᵀ`; this is concave in `λ`, so it is
//!   least at an end of `[(b − 1)², (b + 1)²]`, and
//!   `Σ₃ ⪰ σ²·min((b + 1)², (b − 1)²·(4b + 1))/r²·I`.
//! * Every one-dimensional draw, of the perturbation (pivots `≥ σ²`) and of `SampleD` (`σ`
//!   and `σ/d_{k−1} > σ`), has `√(2π)` times its deviation at least `η_ε(Z)`: the analogue
//!   of the third condition, `s ≥ (b + 1)·η_ε(L)`, for the randomized nearest-plane steps
//!   (Theorem 2.4; ePrint 2007/432, Theorem 4.1, whose proof asks each one-dimensional width
//!   to be at least `η_ε(Z)`).
//!
//! `crate::params` sets `σ²` to the least integer with
//! `σ²·min((b + 1)², (b − 1)²·(4b + 1))/r² ≥ C_{ε,k}²/(2π)` at `ε = 2^-128`, which implies the
//! other two conditions since the factor is below one, and with `σ²·r²/(b² + 1) ≥
//! C_{ε,m'd}²/(2π)`, the condition `r√Σ_G ≥ η_ε(Λ⊥(G))` of ePrint 2011/501, Algorithm 3, for
//! the `nd` cosets together. That is 5 at the toy and succinct sets and 6 at the 128-bit set.

use super::{Stage, Uniform, sample_z};
use zeroize::Zeroizing;

/// The G-lattice sampler for one base and modulus.
#[derive(Clone, Debug)]
pub(crate) struct GadgetSampler {
    base: i64,
    /// The digits `qᵢ` of the modulus.
    modulus: Vec<i64>,
    /// The last column `d` of `D`.
    last: Vec<f64>,
    /// `L_{i,i−1}` of the perturbation's decomposition (`0` for `i = 0`).
    lower: Vec<f64>,
    /// `√D_i`, the conditional standard deviations of the perturbation.
    std: Vec<f64>,
    /// `σ`, the standard deviation of `SampleD`'s draws.
    sigma: f64,
}

impl GadgetSampler {
    /// The sampler for base `b ≥ 2`, the base-`b` digits of `q` (least significant first, with
    /// `q < b^k` for `k` digits), and the variances `σ²` and `α² = σ²·((b + 1)² + 1)` of
    /// `stage`.
    pub(crate) fn new(base: u32, modulus: Vec<i64>, stage: &Stage) -> Self {
        let b = f64::from(base);
        // Exact below 2^53, rounded to 53 significant bits above.
        let sigma_sq = stage.gadget_base_variance as f64;
        let alpha_sq = stage.gadget_variance as f64;
        // Σ₂ = α²·I − σ²·B·Bᵀ: diagonal α² − σ²b² then α² − σ²(b² + 1), off-diagonal σ²b
        // (B·Bᵀ as in Section 3.1).
        let off = sigma_sq * b;
        let mut last = Vec::with_capacity(modulus.len());
        let mut lower = Vec::with_capacity(modulus.len());
        let mut std = Vec::with_capacity(modulus.len());
        let mut previous_d = 0.0;
        let mut previous_pivot = 0.0;
        for (i, &digit) in modulus.iter().enumerate() {
            // dᵢ = (d_{i−1} + qᵢ)/b, Section 3.1.
            // A digit of q is below the base, at most 2^32: exact.
            previous_d = (previous_d + digit as f64) / b;
            last.push(previous_d);
            // LDLᵀ of the tridiagonal Σ₂: L_{i,i−1} = σ²b/D_{i−1}, Dᵢ = Σ_{ii} − L_{i,i−1}·σ²b.
            let (l, pivot) = if i == 0 {
                (0.0, alpha_sq - sigma_sq * b * b)
            } else {
                let l = off / previous_pivot;
                (l, alpha_sq - sigma_sq * (b * b + 1.0) - l * off)
            };
            lower.push(l);
            std.push(pivot.sqrt());
            previous_pivot = pivot;
        }
        Self {
            base: i64::from(base),
            modulus,
            last,
            lower,
            std,
            sigma: sigma_sq.sqrt(),
        }
    }

    /// A sample `x ∈ Z^k` with `Σ bⁱ·xᵢ ≡ u (mod q)` for the coset given by the base-`b`
    /// digits `digits` of `u`. The sample, the perturbation's centres and the nearest-plane
    /// draws are overwritten when dropped: with the perturbation they would reveal the trapdoor.
    pub(crate) fn sample(&self, digits: &[i64], uniform: &mut Uniform<'_>) -> Zeroizing<Vec<i64>> {
        let k = self.modulus.len();
        // The base is at most 2^32: exact.
        let b = self.base as f64;
        // p ← D_{Z^k, √Σ₂}, pᵢ given p_{i−1} through L; with it, SampleG's first loop
        // cᵢ = (c_{i−1} + uᵢ − pᵢ)/b, that is c = B⁻¹(u⃗ − p).
        let mut previous = 0.0;
        let mut centre = 0.0;
        let mut c = Zeroizing::new(Vec::with_capacity(k));
        for (i, &digit) in digits.iter().enumerate() {
            let mean = self.lower[i] * previous;
            let p = sample_z(uniform, mean, self.std[i]);
            // Draws and digits are below 2^52 by the bound on |c| + 13σ: exact.
            previous = p as f64 - mean;
            centre = (centre + (digit - p) as f64) / b;
            c.push(centre);
        }
        // SampleD(σ, c): z_{k−1} centred at −c_{k−1}/d_{k−1} with deviation σ/d_{k−1}, then
        // c := c + z_{k−1}·d and zᵢ centred at −cᵢ with deviation σ.
        let d_last = self.last[k - 1];
        let z_last = sample_z(uniform, -c[k - 1] / d_last, self.sigma / d_last);
        let mut z: Zeroizing<Vec<i64>> = Zeroizing::new(Vec::with_capacity(k));
        z.extend(
            c[..k - 1]
                .iter()
                .zip(&self.last)
                // A draw is below 2^52 by the bound on |c| + 13σ: exact.
                .map(|(ci, di)| sample_z(uniform, -(ci + z_last as f64 * di), self.sigma)),
        );
        z.push(z_last);
        // SampleG's last loop: tᵢ = b·zᵢ − z_{i−1} + qᵢ·z_{k−1} + uᵢ, with no b·z_{k−1} term in
        // t_{k−1}; that is x = u⃗ + B_q·z.
        Zeroizing::new(
            (0..k)
                .map(|i| {
                    let own = if i + 1 < k { self.base * z[i] } else { 0 };
                    let carry = if i > 0 { z[i - 1] } else { 0 };
                    digits[i] + self.modulus[i] * z_last + own - carry
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::GadgetSampler;
    use crate::{
        preimage::{Stage, Uniform},
        sample::{DomainLabel, Seed, xof},
    };

    /// The base-`b` digits of `value`, `count` of them.
    fn digits(mut value: u128, base: u32, count: usize) -> Vec<i64> {
        (0..count)
            .map(|_| {
                let digit = (value % u128::from(base)) as i64;
                value /= u128::from(base);
                digit
            })
            .collect()
    }

    /// A stage with G-lattice variances `σ²` and `α² = σ²·((b+1)² + 1)`; the other fields are
    /// unused here.
    fn stage(base: u32, sigma_sq: u64) -> Stage {
        Stage {
            least_variance: 0,
            gadget_base_variance: sigma_sq,
            gadget_variance: sigma_sq * ((u64::from(base) + 1).pow(2) + 1),
            tail: 0,
        }
    }

    /// For small moduli that are not powers of the base, at the `σ²` `crate::params` derives
    /// for their `(b, k)`: every sample is in the coset, every coordinate has mean zero and
    /// standard deviation within 5% of `α`, and every pair of coordinates has covariance within
    /// five standard errors of zero. Without the perturbation, or with its off-diagonal sign
    /// flipped, the neighbouring covariances at `b = 2` and `b = 6` would be between `−0.12·α²`
    /// and `−0.40·α²`, far outside that.
    #[test]
    fn small_moduli_cosets_and_widths() {
        const SAMPLES: usize = 20_000;
        for (base, q, k, sigma_sq) in [
            (2u32, 1000u128, 10usize, 6),
            (6, 46_655, 6, 5),
            (64, 1 << 59 | 12_345, 10, 5),
        ] {
            let stage = stage(base, sigma_sq);
            let sampler = GadgetSampler::new(base, digits(q, base, k), &stage);
            let mut reader = xof(&Seed::from([base as u8; 32]), DomainLabel::from(&b"g"[..]));
            let mut uniform = Uniform::new(&mut reader);
            let mut sums = vec![0.0; k];
            let mut products = vec![vec![0.0; k]; k];
            for i in 0..SAMPLES {
                let target = (i as u128 * 2_654_435_761) % q;
                let x = sampler.sample(&digits(target, base, k), &mut uniform);
                let value = x
                    .iter()
                    .rev()
                    .fold(0i128, |acc, &xi| acc * i128::from(base) + i128::from(xi));
                assert_eq!(value.rem_euclid(q as i128), target as i128);
                for (a, &xa) in x.iter().enumerate() {
                    sums[a] += xa as f64;
                    for (b, &xb) in x.iter().enumerate().take(a + 1) {
                        products[a][b] += (xa * xb) as f64;
                    }
                }
            }
            let count = SAMPLES as f64;
            let alpha_sq = stage.gadget_variance as f64;
            let covariance =
                |a: usize, b: usize| products[a][b] / count - (sums[a] / count) * (sums[b] / count);
            for (a, sum) in sums.iter().enumerate() {
                let mean = sum / count;
                assert!(
                    mean.abs() < 0.05 * alpha_sq.sqrt(),
                    "b = {base}, i = {a}: mean {mean}"
                );
                let std = covariance(a, a).sqrt();
                assert!(
                    (std / alpha_sq.sqrt() - 1.0).abs() < 0.05,
                    "b = {base}, i = {a}: {std} vs {}",
                    alpha_sq.sqrt()
                );
                for b in 0..a {
                    let ratio = covariance(a, b) / alpha_sq;
                    assert!(
                        ratio.abs() < 5.0 / count.sqrt(),
                        "b = {base}, ({a}, {b}): covariance {ratio}·α²"
                    );
                }
            }
        }
    }

    /// `Σ₂ ⪰ σ²·I`: every pivot of the perturbation's `LDLᵀ` decomposition is at least `σ²`, at
    /// the bases and digit counts of the defined sets and at `b = 2`, `k = 60`.
    #[test]
    fn perturbation_pivots_are_at_least_sigma_squared() {
        for (base, k, sigma_sq) in [
            (2u32, 60usize, 6u64),
            (6, 63, 5),
            (64, 15, 5),
            (1024, 10, 5),
        ] {
            // q = b^{k−1} + 1.
            let mut modulus = vec![0; k];
            modulus[0] = 1;
            modulus[k - 1] = 1;
            let sampler = GadgetSampler::new(base, modulus, &stage(base, sigma_sq));
            let floor = sigma_sq as f64;
            assert!(
                sampler.std.iter().all(|s| s * s >= floor * (1.0 - 1e-12)),
                "b = {base}"
            );
            assert!(sampler.last.iter().all(|d| *d > 0.0 && *d < 1.0));
        }
    }
}
