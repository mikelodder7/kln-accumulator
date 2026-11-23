// SPDX-License-Identifier: MIT OR Apache-2.0
//! The parameters of the LNP layer, each computed from the formulas of Appendix D.2.3
//! (paper lines 3247–3303) in exact integer arithmetic.
//!
//! * `m̄₁ = ℓ + l + (m + ℓm')·D` (line 2788), with `D` digits per coefficient of `s_x`
//!   (see [`LnpParameters::digits`]).
//! * `τ = ⌈λ / log₂ q⌉` with `λ = 128` (line 2641).
//! * Widths (line 3253): `σᵢ = 12·Tᵢ` with `T₁ = ν·√(m̄₁d)`, `T₂ = ν·√(m̄₂d)` and
//!   `T₃ = √(337·m̄₁d)`. Each is realised by the crate's integer Gaussian at the least variance
//!   at or above `σᵢ²`, and every bound below uses the realised variance.
//! * Bounds: `β₁ = σ₁·√(2m̄₁d)`, `β₂ = σ₂·√(2m̄₂d)` (the paper prints `√(m̄₂d)`; the factor `√2`
//!   it gives the other two is restored) and `β₃ = σ₃·√(2·256)`.
//! * `m̄₂ = (n̄ + 256/d + τ + 1)·⌈log₂ q⌉ + ⌈2λ/d⌉` (line 3275, the leftover hash lemma over
//!   rings for the binary `s₂`); the `ω(log d)` term is instantiated as `⌈2λ/d⌉`, the entropy
//!   slack for statistical distance `2^{−λ}`.
//! * `n̄`, which D.2.3 leaves to a hardness estimate, is the least rank for which Module-SIS on
//!   `[Ā₁ | Ā₂]` with bound `B` has root Hermite factor `2^{(log₂ B)²/(4·n̄·d·log₂ q)} < 1.0044`,
//!   a common rule of thumb for 128-bit Module-SIS hardness that is not the paper's Core-SVP
//!   estimate, and `B < q`. Relaxed binding (line 3279) asks
//!   for `B = 4ν·√(β₁² + β₂²)` with `β₁`, `β₂` the norms of the responses the extractor obtains.
//!   For the uncompressed proof those are the verifier's own bounds. Through the LaBRADOR
//!   compression they are not: the verifier checks `‖zₓ‖ ≤ β₁` in the clear, but of the
//!   witness `(z_r, σ(z_r), z_{s̄}, σ(z_{s̄}), z₂)` only that a LaBRADOR proof exists for the
//!   relaxed bound `2β₁² + β₂²`, and the extractor of ePrint 2022/1341, Theorem 5.1 returns a
//!   witness that is longer by that layer's slack, `S² = 337/30` here (the paper's `128/30`; see
//!   `labrador/params.rs`). The `σ` copies are extracted exactly, because the
//!   constant-coefficient constraints tying them to the originals are part of the extracted
//!   relation, so `2(‖z_r‖² + ‖z_{s̄}‖²) + ‖z₂‖² ≤ S²·(2β₁² + β₂²)` and
//!   `‖z₁‖² + ‖z₂‖² ≤ β₁² + S²·(2β₁² + β₂²)`. The rank is therefore sized for
//!   `B² = 16ν²·(β₁² + ⌈337·(2β₁² + β₂²)/30⌉)`, for compressed and uncompressed proofs alike: an
//!   uncompressed proof can be compressed by anyone under the same parameters, so the
//!   commitment must be binding for the larger norm in either case. Only relaxed binding is
//!   re-sized; whether another step of the LNP soundness argument uses `β₁`, `β₂` in a way the
//!   slack affects was not checked against its source.
//!
//! The conditions on `q` are then checked: `q ≥ 16·β₃·m̄₁·d` for Lemma D.2 (line 3282; the
//! printed intermediate `β₃·√(13/2)` is `β₃·√(2/13)`, which is what yields the printed `16`),
//! `q > 2β₃²/13 + β₃·√(2m̄₁d/13)` for `⟨s₁, s₁ − 1⟩ = 0` over the integers (line 3294), and
//! `q > max(8, κ/2)` (line 3303).

use crate::{
    error::{Error, Result},
    gaussian::DiscreteGaussian,
    params::{Params, ceil_div, ceil_sqrt, choose_gaussian, product, sum},
    proof::{
        challenge::{DEGREE, KAPPA, NU},
        labrador::projection_slack_squared,
    },
    zq::Coeff,
};
use crypto_bigint::U512;

/// The integer type of every parameter computation.
type Wide = U512;

/// The security parameter `λ`.
const SECURITY: u64 = 128;
/// The number of rows of the range-proof challenge `R` (line 2812).
pub(crate) const RANGE_ROWS: usize = 256;
/// The factor `12` in `σᵢ = 12·Tᵢ` (line 3253, from the rejection-sampling theorem cited there).
pub(crate) const REJECTION_SLACK: u64 = 12;
/// The factor `337` in `‖R·s₁‖ ≤ √337·‖s₁‖` (line 2749).
const RANGE_OPERATOR_SQUARED: u64 = 337;
/// `log₂ 1.0044 > 6333/10⁶`, the target root Hermite factor's logarithm, bounded below.
const LOG2_DELTA: (u64, u64) = (6333, 1_000_000);
/// The largest Module-SIS rank tried.
const MAX_RANK: usize = 1024;

/// The dimensions, Gaussian widths and norm bounds of the LNP proof for one statement shape,
/// with the quantities each condition on `q` compares against.
///
/// Every width and bound is rounded up to an integer; the checks themselves use the exact
/// squares. **Public.** At the toy set with a two-entry `r`: `m̄₁ = 4310`, `m̄₂ = 1564`,
/// `n̄ = 18`, `τ = 3`, `D = 43`.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{LnpParameters, Params};
///
/// let lnp = LnpParameters::new(&Params::toy()?, 2)?;
/// assert_eq!((lnp.degree, lnp.element_bits, lnp.r_len), (64, 8, 2));
/// assert_eq!(lnp.witness_len, 100); // m + ℓm'
/// assert_eq!(lnp.digits, 43);
/// assert_eq!(lnp.m1, lnp.element_bits + lnp.r_len + lnp.witness_len * lnp.digits);
/// assert_eq!((lnp.m2, lnp.n, lnp.tau), (1564, 18, 3));
/// assert!(LnpParameters::new(&Params::paper_128()?, 2).is_err());
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LnpParameters {
    /// The proof ring degree `d`.
    pub degree: usize,
    /// `ℓ`, the number of bits of the element, each committed as a constant polynomial.
    pub element_bits: usize,
    /// `l`, the number of entries of the linking vector `r`.
    pub r_len: usize,
    /// `m + ℓm'`, the number of entries of the witness `s_x`.
    pub witness_len: usize,
    /// `D`, the digits per coefficient of `s_x`: the bit width of `β` in binary digits of weight
    /// `2^j`, then one top digit of weight `−2^{D−1}`, so every coefficient in `[−β, β]` has a
    /// binary decomposition.
    pub digits: usize,
    /// `m̄₁`, the length of the Ajtai message `s₁ = (x, r, s̄_x)`.
    pub m1: usize,
    /// `m̄₂`, the length of the commitment randomness `s₂`.
    pub m2: usize,
    /// `n̄`, the rank of the commitment `t_A`.
    pub n: usize,
    /// `τ`, the number of masked openings `hᵢ` (soundness amplification).
    pub tau: usize,
    /// `⌈σ₁⌉`, the realised width of the mask `y₁`.
    pub sigma1: Coeff,
    /// `⌈σ₂⌉`, the realised width of the mask `y₂`.
    pub sigma2: Coeff,
    /// `⌈σ₃⌉`, the realised width of the mask `y₃`.
    pub sigma3: Coeff,
    /// `⌈β₁⌉`, the bound on `‖z₁‖`.
    pub beta1: Coeff,
    /// `⌈β₂⌉`, the bound on `‖z₂‖`.
    pub beta2: Coeff,
    /// `⌈β₃⌉`, the bound on `‖z₃‖`.
    pub beta3: Coeff,
    /// `⌈B⌉` with `B = 4ν·√(β₁² + ⌈337·(2β₁² + β₂²)/30⌉)`, the Module-SIS bound of relaxed
    /// binding for responses extracted through the LaBRADOR compression; below `q`.
    pub msis_bound: Coeff,
    /// `⌈16·β₃·m̄₁·d⌉`, which `q` must be at least.
    pub range_bound: Coeff,
    /// An integer upper bound on `2β₃²/13 + β₃·√(2m̄₁d/13)`, which `q` must exceed.
    pub binary_bound: Coeff,
    /// The exact realised variances `σ₁², σ₂², σ₃²`.
    variances: [Wide; 3],
    /// The exact squares `β₁², β₂², β₃²`.
    beta_squares: [Wide; 3],
    /// The samplers of `y₁`, `y₂`, `y₃`.
    gaussians: [DiscreteGaussian; 3],
}

impl LnpParameters {
    /// Derives every parameter for a statement over `params` whose linking vector `r` has
    /// `r_len` entries. Fails with [`Error::UnsupportedProofDegree`] unless `d = 64`, and with
    /// [`Error::ProofModulusTooSmall`] when a condition of D.2.3 on `q` fails or
    /// `m̄₁ = ℓ + r_len + (m + ℓm')·D` overflows. See the type's example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn new(params: &Params, r_len: usize) -> Result<Self> {
        let ring = params.ring();
        let degree = ring.degree();
        if degree != DEGREE {
            return Err(Error::UnsupportedProofDegree(degree));
        }
        let spec = params.spec();
        let element_bits = spec.element_bits as usize;
        let witness_len = params.witness_len();
        let digits = params.bounds().witness.bit_width_vartime() as usize + 1;
        let m1 = witness_len
            .checked_mul(digits)
            .and_then(|w| w.checked_add(element_bits))
            .and_then(|w| w.checked_add(r_len))
            .ok_or(Error::ProofModulusTooSmall)?;
        let w = |x: usize| Wide::from_u64(x as u64);
        let d = w(degree);
        let q: Wide = ring.modulus().resize();
        let log_q_floor = u64::from(ring.modulus().bit_width_vartime() - 1);
        let log_q_ceil = log_q_floor + 1;
        let tau = usize::try_from(SECURITY.div_ceil(log_q_floor))
            .map_err(|_| Error::ProofModulusTooSmall)?;
        let n1 = product(&[w(m1), d])?;
        let nu = Wide::from_u64(NU);
        let slack = Wide::from_u64(REJECTION_SLACK);

        // σ₁² ≥ 144·ν²·m̄₁d and σ₃² ≥ 144·337·m̄₁d.
        let gaussian1 = choose_gaussian(&product(&[slack, slack, nu, nu, n1])?, ring)?;
        let gaussian3 = choose_gaussian(
            &product(&[slack, slack, Wide::from_u64(RANGE_OPERATOR_SQUARED), n1])?,
            ring,
        )?;
        let (var1, var3) = (gaussian1.variance(), gaussian3.variance());
        let beta1_sq = product(&[Wide::from_u64(2), n1, var1])?;
        let beta3_sq = product(&[Wide::from_u64(2 * RANGE_ROWS as u64), var3])?;

        let y3_len = RANGE_ROWS / degree;
        let slack_m2 = (2 * SECURITY).div_ceil(degree as u64);
        let mut rank = 1;
        let (m2, gaussian2, beta2_sq, msis_sq) = loop {
            let rows = (rank + y3_len + tau + 1) as u64;
            let m2 = rows * log_q_ceil + slack_m2;
            let n2 = product(&[Wide::from_u64(m2), d])?;
            let gaussian2 = choose_gaussian(&product(&[slack, slack, nu, nu, n2])?, ring)?;
            let beta2_sq = product(&[Wide::from_u64(2), n2, gaussian2.variance()])?;
            let extracted =
                projection_slack_squared(&relaxed_bound_squared(&beta1_sq, &beta2_sq)?)?;
            let msis_sq = product(&[Wide::from_u64(16), nu, nu, sum(beta1_sq, extracted)?])?;
            if msis_is_hard(&msis_sq, rank, degree, log_q_floor)? && msis_sq < product(&[q, q])? {
                break (
                    usize::try_from(m2).map_err(|_| Error::ProofModulusTooSmall)?,
                    gaussian2,
                    beta2_sq,
                    msis_sq,
                );
            }
            rank += 1;
            if rank > MAX_RANK {
                return Err(Error::ProofModulusTooSmall);
            }
        };

        // q ≥ 16·β₃·m̄₁·d, compared as squares.
        let range_sq = product(&[Wide::from_u64(256), beta3_sq, n1, n1])?;
        if product(&[q, q])? < range_sq {
            return Err(Error::ProofModulusTooSmall);
        }
        // q > 2β₃²/13 + β₃·√(2m̄₁d/13), with both terms rounded up.
        let thirteen = Wide::from_u64(13);
        let binary = sum(
            ceil_div(&product(&[Wide::from_u64(2), beta3_sq])?, &thirteen)?,
            ceil_sqrt(&ceil_div(
                &product(&[Wide::from_u64(2), beta3_sq, n1])?,
                &thirteen,
            )?),
        )?;
        if q <= binary || q <= Wide::from_u64(8.max(KAPPA.unsigned_abs() / 2)) {
            return Err(Error::ProofModulusTooSmall);
        }
        let narrow = |x: Wide| -> Result<Coeff> {
            if x.bit_width_vartime() > Coeff::BITS {
                Err(Error::ProofModulusTooSmall)
            } else {
                Ok(x.resize())
            }
        };
        let var2 = gaussian2.variance();
        Ok(Self {
            degree,
            element_bits,
            r_len,
            witness_len,
            digits,
            m1,
            m2,
            n: rank,
            tau,
            sigma1: narrow(ceil_sqrt(&var1))?,
            sigma2: narrow(ceil_sqrt(&var2))?,
            sigma3: narrow(ceil_sqrt(&var3))?,
            beta1: narrow(ceil_sqrt(&beta1_sq))?,
            beta2: narrow(ceil_sqrt(&beta2_sq))?,
            beta3: narrow(ceil_sqrt(&beta3_sq))?,
            msis_bound: narrow(ceil_sqrt(&msis_sq))?,
            range_bound: narrow(ceil_sqrt(&range_sq))?,
            binary_bound: narrow(binary)?,
            variances: [var1, var2, var3],
            beta_squares: [beta1_sq, beta2_sq, beta3_sq],
            gaussians: [gaussian1, gaussian2, gaussian3],
        })
    }

    /// The number of polynomials of `y₃` and `t_y`, `256/d`.
    pub(crate) fn y3_len(&self) -> usize {
        RANGE_ROWS / self.degree
    }

    /// The offset of `r` in `s₁`.
    pub(crate) fn r_offset(&self) -> usize {
        self.element_bits
    }

    /// The offset of `s̄_x` in `s₁`.
    pub(crate) fn witness_offset(&self) -> usize {
        self.element_bits + self.r_len
    }

    /// The realised variance `σᵢ²` of mask `i ∈ {0, 1, 2}` (for `y₁, y₂, y₃`).
    pub(crate) fn variance(&self, i: usize) -> &Wide {
        &self.variances[i]
    }

    /// The exact square `βᵢ²` of bound `i ∈ {0, 1, 2}` (for `z₁, z₂, z₃`).
    pub(crate) fn beta_squared(&self, i: usize) -> &Wide {
        &self.beta_squares[i]
    }

    /// The sampler of mask `i ∈ {0, 1, 2}`.
    pub(crate) fn gaussian(&self, i: usize) -> &DiscreteGaussian {
        &self.gaussians[i]
    }

    /// `2β₁² + β₂²`, the squared norm bound on `(z_r, σ(z_r), z_{s̄}, σ(z_{s̄}), z₂)` the LaBRADOR
    /// compression proves.
    pub(crate) fn relaxed_bound_squared(&self) -> Result<Wide> {
        relaxed_bound_squared(&self.beta_squares[0], &self.beta_squares[1])
    }
}

/// `2β₁² + β₂²`.
fn relaxed_bound_squared(beta1_sq: &Wide, beta2_sq: &Wide) -> Result<Wide> {
    sum(product(&[Wide::from_u64(2), *beta1_sq])?, *beta2_sq)
}

/// Whether the root Hermite factor `2^{(log₂ B)²/(4·n̄·d·log₂ q)}` is below `1.0044`, with
/// `log₂ B` bounded above by half the bit width of `B²` and `log₂ q` below by `log_q_floor`:
/// `bw(B²)²·10⁶ < 16·n̄·d·log_q_floor·6333`.
pub(crate) fn msis_is_hard(
    msis_sq: &Wide,
    rank: usize,
    degree: usize,
    log_q_floor: u64,
) -> Result<bool> {
    let width = Wide::from_u32(msis_sq.bit_width_vartime());
    let lhs = product(&[width, width, Wide::from_u64(LOG2_DELTA.1)])?;
    let rhs = product(&[
        Wide::from_u64(16),
        Wide::from_u64(rank as u64),
        Wide::from_u64(degree as u64),
        Wide::from_u64(log_q_floor),
        Wide::from_u64(LOG2_DELTA.0),
    ])?;
    Ok(lhs < rhs)
}

#[cfg(test)]
mod tests {
    use super::LnpParameters;
    use crate::{
        error::Error,
        params::{Params, ParamsSpec},
        test_util::{PAPER, TOY},
        zq::Coeff,
    };
    use crypto_bigint::{NonZero, U512};

    /// The toy set satisfies every condition, and the derived numbers follow the formulas.
    #[test]
    fn toy_parameters_follow_d_2_3() {
        let lnp = LnpParameters::new(&TOY, 2).unwrap();
        let beta = TOY.bounds().witness;
        assert_eq!(lnp.digits, beta.bit_width_vartime() as usize + 1);
        assert_eq!(lnp.witness_len, 20 + 8 * 10);
        assert_eq!(lnp.m1, 8 + 2 + 100 * lnp.digits);
        assert_eq!(lnp.tau, 3);
        assert_eq!(lnp.m2, (lnp.n + 4 + 3 + 1) * 60 + 4);
        let q = *TOY.ring().modulus();
        assert!(lnp.msis_bound < q && lnp.range_bound <= q && lnp.binary_bound < q);
        // The rank is sized for the norm extracted through the compression layer:
        // B² ≥ 16ν²·(β₁² + 337·(2β₁² + β₂²)/30), which needs rank 18 at the toy set.
        let (b1, b2) = (*lnp.beta_squared(0), *lnp.beta_squared(1));
        let extracted = b1
            .wrapping_add(&b1)
            .wrapping_add(&b2)
            .wrapping_mul(&U512::from_u64(337))
            .wrapping_div(&NonZero::new(U512::from_u64(30)).unwrap());
        let msis: U512 = lnp.msis_bound.resize();
        assert!(
            msis.wrapping_mul(&msis)
                >= b1
                    .wrapping_add(&extracted)
                    .wrapping_mul(&U512::from_u64(16 * 140 * 140))
        );
        assert_eq!((lnp.n, lnp.m2), (18, 1564));
        // σ₁ ≥ 12·ν·√(m̄₁d).
        let t1 = 12.0 * 140.0 * ((lnp.m1 * 64) as f64).sqrt();
        assert!(lnp.sigma1 >= Coeff::from_u64(t1 as u64));
        println!("{lnp:#?}");
    }

    #[test]
    fn rejects_other_degrees_and_small_moduli() {
        assert_eq!(
            LnpParameters::new(&PAPER, 0),
            Err(Error::UnsupportedProofDegree(4096))
        );
        // A 42-bit prime ≡ 5 (mod 8) carries the toy accumulator (2β < q) but not the proof:
        // q ≥ 16·β₃·m̄₁·d needs about 2^43.
        let small = Params::try_from(ParamsSpec {
            modulus: Coeff::from_u64(0x3ff_ffff_fff5),
            ..ParamsSpec::TOY
        })
        .unwrap();
        assert_eq!(
            LnpParameters::new(&small, 0),
            Err(Error::ProofModulusTooSmall)
        );
    }

    /// A linking vector of `usize::MAX` entries, the column count of a `0 × usize::MAX` matrix
    /// `A₂` that holds no entries, makes `m̄₁` overflow. It is refused in every build profile,
    /// where it used to panic with overflow checks on and wrap to a small `m̄₁` with them off.
    #[test]
    fn an_overflowing_message_length_is_refused() {
        assert_eq!(
            LnpParameters::new(&TOY, usize::MAX),
            Err(Error::ProofModulusTooSmall)
        );
    }
}
