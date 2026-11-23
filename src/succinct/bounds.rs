// SPDX-License-Identifier: MIT OR Apache-2.0
//! The norm bounds of the `ℓ`-succinct variant, and the width of the trapdoor `T`.

use crate::{
    error::{Error, Result},
    params::{Params, Wide, ceil_sqrt, product, sum, width_sq_upper},
    zq::Coeff,
};

/// The Gaussian width of `T` and the bounds of the `ℓ`-succinct variant at one parameter set,
/// each an upper bound rounded up to an integer.
///
/// A witness is `s_x = [s̃₁ − (xᵀ⊗I_m)T₀·s̃₂ ; −T₁·s̃₂]` for the base preimage `s̃ = [s̃₁; s̃₂]`
/// with its updates, so `‖s̃‖ ≤ β₀` (the base [`crate::Bounds::witness`]). For ring matrices
/// `‖M·v‖ ≤ √d·‖M‖_F·‖v‖`, since every coefficient of a product `a·b` in `R` is at most
/// `‖a‖·‖b‖`. Each column of `[(xᵀ⊗I_m)T₀; T₁]` sums at most `ℓ` blocks of a column of `T`,
/// so its norm is at most `√ℓ·τ` and `‖[(xᵀ⊗I_m)T₀; T₁]‖_F ≤ ℓ·√m'·τ`. Hence
///
/// `‖s_x‖ ≤ ‖s̃₁‖ + √d·ℓ·√m'·τ·‖s̃₂‖ ≤ β₀·(1 + √d·ℓ·√m'·τ) = β_succ`,
///
/// the paper's factor `O(ℓ²·ς·d·(m + m'))` made concrete. Like `β₀` it rests on the Gaussian
/// tail bound `‖p‖ ≤ ς·√(d·len)`, so honest values satisfy it with overwhelming probability.
///
/// **Public.** Realised `β_succ`: `2^79.70` at [`crate::ParamsSpec::SUCCINCT_TOY`] (`2^67.53`
/// with a ternary trapdoor) and `2^138.25` at [`crate::ParamsSpec::SUCCINCT_128`], against a
/// 90-bit and a 162-bit modulus. Built with `TryFrom<&Params>`, which fails with
/// [`Error::WitnessBoundTooLarge`] unless `2·β_succ < q` and every coefficient of `T` is below
/// `q/2`.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Params, succinct::Bounds};
///
/// let bounds = Bounds::try_from(&Params::succinct_toy()?)?;
/// assert_eq!(bounds.witness.bit_width_vartime(), 80); // 2^79.70
/// assert!(bounds.trapdoor_width < bounds.column);
/// // The base toy set's 60-bit modulus is too small for it.
/// assert!(Bounds::try_from(&Params::toy()?).is_err());
/// // At the 128-bit shape the bound is derived even though key generation is impractical.
/// assert_eq!(Bounds::try_from(&Params::succinct_128()?)?.witness.bit_width_vartime(), 139);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// `⌈ς⌉` for the width `ς` of the columns of `T`: the preimage sampler's least width
    /// ([`crate::Bounds::least_width`]), at which they are sampled.
    pub trapdoor_width: Coeff,
    /// `τ = ⌈ς·√(d(ℓm + m'))⌉`, the bound on the norm of a column of `T`: each of its `ℓ`
    /// blocks in `T₀` is a width-`ς` preimage in `R^m` and its block in `T₁` a width-`ς`
    /// Gaussian in `R^{m'}`.
    pub column: Coeff,
    /// `β_succ = β₀·(1 + ⌈√(d·ℓ²·m'·τ²)⌉)`, the witness norm bound.
    pub witness: Coeff,
    /// The largest centred magnitude a coefficient of `T` can take: the tail cut of the
    /// preimage sampler at its least width. The packed encoding of `T₀` and `T₁` in the public
    /// key is sized by it.
    pub trapdoor_entry: Coeff,
}

/// Fails with [`Error::WitnessBoundTooLarge`] unless `2·β_succ < q`, and unless every
/// coefficient `T` can take is below `q/2`.
impl TryFrom<&Params> for Bounds {
    type Error = Error;

    fn try_from(params: &Params) -> Result<Self> {
        let w = Wide::from_u64;
        let spec = params.spec();
        let d = w(spec.degree as u64);
        let m = w(spec.m as u64);
        let mp = w(params.m_prime() as u64);
        let ell = w(u64::from(spec.element_bits));
        let stage = params.stage();
        let width_sq = width_sq_upper(&Wide::from_u128(stage.least_variance))?;
        let entries = sum(product(&[ell, m])?, mp)?;
        let column = ceil_sqrt(&product(&[width_sq, d, entries])?);
        let factor = sum(
            Wide::ONE,
            ceil_sqrt(&product(&[d, ell, ell, mp, column, column])?),
        )?;
        let witness = product(&[params.bounds().witness.resize(), factor])?;
        let entry = Wide::from_u128(stage.tail);
        let modulus: Wide = spec.modulus.resize();
        if product(&[w(2), witness.max(entry)])? >= modulus {
            return Err(Error::WitnessBoundTooLarge);
        }
        Ok(Self {
            trapdoor_width: ceil_sqrt(&width_sq).resize(),
            column: column.resize(),
            witness: witness.resize(),
            trapdoor_entry: entry.resize(),
        })
    }
}
