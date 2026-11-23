// SPDX-License-Identifier: MIT OR Apache-2.0
//! The verification equations D.12 of the LNP proof as a principal relation (ePrint 2025/1099,
//! D.3, lines 3403–3470).
//!
//! `zₓ` is sent in the clear and the witness is `(z_r, σ(z_r), z_{s̄}, σ(z_{s̄}), z₂)`, in five
//! blocks. The full constraints are
//!
//! * the `n̄` rows of `Ā₁z₁ + Ā₂z₂ = w + c·t_A` with `z₁ = (zₓ, z_r, z_{s̄})` (the paper's
//!   `A′·(…) = t′`);
//! * the quadratic check `Z = c²·(γ₁ᵀt + γ₂ᵀc + Σγ₄,ᵢhᵢ) + (c·t_quad − B̄_quad·z₂) + v`, in which
//!   `z₁ᵀσ(z₁)` becomes `zₓᵀσ(zₓ) + ⟨z_r, σ(z_r)⟩ + ⟨z_{s̄}, σ(z_{s̄})⟩` with the copies as
//!   witness blocks, the openings of `y₃` and `p` are `c·t_y − B̄_y·z₂` and `c·t_p − B̄_p·z₂`,
//!   and every term with `zₓ` is public (the paper's `u′ᵀ(…) + ⟨z_r, z_r′⟩ + ⟨z_{sx}, z_{sx}′⟩ =
//!   t″`);
//!
//! These are the family `F` of the principal relation (ePrint 2022/1341, Section 5.1). The
//! constant-coefficient constraints, the family `F′`, are D.13: every coefficient of each copy
//! equals the corresponding coefficient of `σ` of the original. They are never materialised: combined with
//! weights `ψ` they are `const(⟨σ(Ψ), z′⟩ − ⟨Ψ, z⟩) = 0` for `Ψ` the weights laid out as
//! polynomials, because `const(σ(a)·b) = ⟨a, b⟩` and `σ` is an involution fixing constant terms.
//!
//! The norm bound is the relaxed `‖(z_r, σ(z_r), z_{s̄}, σ(z_{s̄}), z₂)‖² ≤ 2β₁² + β₂²`
//! ([`LnpParameters::relaxed_bound_squared`]). Difference: ePrint 2025/1099 prints
//! `√2·β₁ + β₂` (line 3433); the bound here is tighter and still holds for honest responses,
//! since `σ` preserves norms. LaBRADOR proves this bound only up to its slack (Theorem 5.1 of
//! ePrint 2022/1341; `S² = 337/30` here), which is why the LNP commitment rank is sized for
//! `β₁² + S²·(2β₁² + β₂²)` (see `proof/params.rs`). The remaining checks of D.12,
//! `‖z₃‖ ≤ β₃` and `h̃ᵢ = Σ_j α_{i,j}z₃,ⱼ`, involve only public messages and stay with the
//! verifier, as does `‖zₓ‖ ≤ β₁`.

use super::relation::{Combination, PrincipalRelation, Quadratic, Wide, offsets, split};
use crate::{
    error::{Error, Result, check_dimension},
    poly::Poly,
    proof::{
        abdlop::CommitmentKey,
        coeffs::{inner, mul_each, transform},
        params::LnpParameters,
        protocol::Messages,
        relation::{Linearised, Opening, Relation},
    },
    ring::Ring,
    sample::UniformSampler,
    vector::PolyVec,
};

/// The block of `z_r`.
const R: usize = 0;
/// The block of `σ(z_r)`.
const R_SIGMA: usize = 1;
/// The block of `z_{s̄}`.
const WITNESS: usize = 2;
/// The block of `σ(z_{s̄})`.
const WITNESS_SIGMA: usize = 3;
/// The block of `z₂`.
const RANDOMNESS: usize = 4;

/// What the relation is built from.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LnpInputs<'a> {
    /// The ABDLOP key.
    pub(crate) key: &'a CommitmentKey,
    /// The round-7 relation for the proof's challenges.
    pub(crate) relation: &'a Relation<'a>,
    /// The LNP parameters.
    pub(crate) lnp: &'a LnpParameters,
    /// The messages of rounds 1 to 7.
    pub(crate) messages: Messages<'a>,
    /// `zₓ`.
    pub(crate) z_x: &'a PolyVec,
    /// The final challenge `c`.
    pub(crate) c: &'a Poly,
}

/// The relation of the module documentation.
#[derive(Debug)]
pub(crate) struct LnpRelation<'a> {
    inputs: LnpInputs<'a>,
    form: Linearised,
    blocks: [usize; 5],
    beta_squared: Wide,
}

impl<'a> LnpRelation<'a> {
    /// Builds the relation, linearising the quadratic check in the public `zₓ`.
    pub(crate) fn new(inputs: LnpInputs<'a>) -> Result<Self> {
        let lnp = inputs.lnp;
        let form = inputs.relation.linearise(inputs.c, inputs.z_x.as_slice())?;
        let witness = lnp.witness_len * lnp.digits;
        let beta_squared = lnp.relaxed_bound_squared()?;
        Ok(Self {
            inputs,
            form,
            blocks: [lnp.r_len, lnp.r_len, witness, witness, lnp.m2],
            beta_squared,
        })
    }

    /// `z₁ = (zₓ, z_r, z_{s̄})` and `z₂` from a witness.
    fn responses(&self, witness: &PolyVec) -> Result<(PolyVec, PolyVec)> {
        let parts = split(witness, &self.blocks)?;
        let z1 = self
            .inputs
            .z_x
            .as_slice()
            .iter()
            .chain(parts[R])
            .chain(parts[WITNESS])
            .cloned()
            .collect();
        Ok((z1, parts[RANDOMNESS].iter().cloned().collect()))
    }
}

/// Splits the LNP responses into the public `zₓ` and the witness
/// `(z_r, σ(z_r), z_{s̄}, σ(z_{s̄}), z₂)`.
pub(crate) fn witness(
    z1: &PolyVec,
    z2: &PolyVec,
    lnp: &LnpParameters,
    ring: &Ring,
) -> Result<(PolyVec, PolyVec)> {
    let z1 = z1.as_slice();
    let (x_end, r_end) = (lnp.r_offset(), lnp.witness_offset());
    check_dimension(lnp.m1, z1.len())?;
    let z_x: PolyVec = z1[..x_end].iter().cloned().collect();
    let z_r: PolyVec = z1[x_end..r_end].iter().cloned().collect();
    let z_w: PolyVec = z1[r_end..].iter().cloned().collect();
    let witness = z_r
        .concat(&z_r.sigma_minus_one(ring)?)
        .concat(&z_w)
        .concat(&z_w.sigma_minus_one(ring)?)
        .concat(z2);
    Ok((z_x, witness))
}

impl PrincipalRelation for LnpRelation<'_> {
    fn blocks(&self) -> &[usize] {
        &self.blocks
    }

    fn norm_bound_squared(&self) -> &Wide {
        &self.beta_squared
    }

    fn full_constraints(&self) -> usize {
        self.inputs.lnp.n + 1
    }

    /// The rows of `Ā₁z₁ + Ā₂z₂ − (w + c·t_A)` and `Fh(c, ẑ) − (c·t_quad − B̄_quad·z₂ + v)`,
    /// evaluated with the LNP verifier's own code, so that a test can hold the combination of
    /// [`PrincipalRelation::combine`] against them.
    fn residuals(&self, witness: &PolyVec, ring: &Ring) -> Result<Vec<Poly>> {
        let LnpInputs {
            key, messages, c, ..
        } = self.inputs;
        let (z1, z2) = self.responses(witness)?;
        let target = messages.w.add(&mul_each(c, messages.t_a, ring)?, ring)?;
        let mut out: Vec<Poly> = key.ajtai(&z1, &z2, ring)?.sub(&target, ring)?.into();
        let rows = key.bdlop(&z2, ring)?;
        let opening_y = mul_each(c, messages.t_y, ring)?.sub(&rows.y, ring)?;
        let opening_p = mul_each(c, messages.t_p, ring)?.sub(&rows.p, ring)?;
        let lhs = self.inputs.relation.evaluate(
            c,
            &Opening {
                z1: &z1,
                y: &opening_y,
                p: &opening_p,
            },
        )?;
        let rhs = c
            .mul(messages.t_quad, ring)?
            .sub(&rows.quad, ring)?
            .add(messages.v, ring)?;
        out.push(lhs.sub(&rhs, ring)?);
        Ok(out)
    }

    fn combine(&self, weights: &[Poly], ring: &Ring) -> Result<Combination> {
        let LnpInputs {
            key,
            lnp,
            messages,
            z_x,
            c,
            ..
        } = self.inputs;
        let (rows, quad) = match weights.split_at_checked(lnp.n) {
            Some((rows, [quad])) => (rows, quad),
            _ => {
                return Err(Error::DimensionMismatch {
                    expected: lnp.n + 1,
                    found: weights.len(),
                });
            }
        };
        let form = &self.form;
        let starts = offsets(&self.blocks);
        let (x_end, r_end) = (lnp.r_offset(), lnp.witness_offset());
        let times_quad = |p: &Poly| quad.mul(p, ring);

        // z₂: wᵀĀ₂ from the rows, and B̄ᵀ(−λ_y, −λ_p, 1)·w_quad from the quadratic check.
        let mut bdlop = form
            .y
            .iter()
            .chain(&form.p)
            .map(|l| times_quad(&l.neg(ring)?))
            .collect::<Result<Vec<_>>>()?;
        bdlop.push(quad.clone());
        let (on_z1, on_z2) = key.transposed(rows, &bdlop, ring)?;

        let mut f = Combination::zero(starts[RANDOMNESS] + lnp.m2, ring);
        f.add_linear(starts[RANDOMNESS], &on_z2, ring)?;
        let scaled_form = form.z1.iter().map(times_quad).collect::<Result<Vec<_>>>()?;
        for (block, range) in [(R, x_end..r_end), (WITNESS, r_end..lnp.m1)] {
            f.add_linear(starts[block], &on_z1[range.clone()], ring)?;
            f.add_linear(starts[block], &scaled_form[range], ring)?;
        }
        let binary = times_quad(&form.binary)?;
        f.quadratic = [(R, R_SIGMA), (WITNESS, WITNESS_SIGMA)]
            .into_iter()
            .map(|(left, right)| Quadratic {
                left,
                right,
                weight: binary.clone(),
            })
            .collect();

        // b: the rows' targets less their zₓ part, less w_quad times every public term of the
        // quadratic check.
        let x = transform(z_x.as_slice(), ring)?;
        let target = messages.w.add(&mul_each(c, messages.t_a, ring)?, ring)?;
        let rows_constant = inner(
            &transform(rows, ring)?,
            &transform(target.as_slice(), ring)?,
            ring,
        )?
        .sub(&inner(&transform(&on_z1[..x_end], ring)?, &x, ring)?, ring)?;
        let public = form
            .binary
            .mul(
                &inner(
                    &x,
                    &transform(z_x.sigma_minus_one(ring)?.as_slice(), ring)?,
                    ring,
                )?,
                ring,
            )?
            .add(
                &inner(&transform(&form.z1[..x_end], ring)?, &x, ring)?,
                ring,
            )?
            .add(
                &c.mul(
                    &inner(
                        &transform(&form.y, ring)?,
                        &transform(messages.t_y.as_slice(), ring)?,
                        ring,
                    )?
                    .add(
                        &inner(
                            &transform(&form.p, ring)?,
                            &transform(messages.t_p.as_slice(), ring)?,
                            ring,
                        )?,
                        ring,
                    )?
                    .sub(messages.t_quad, ring)?,
                    ring,
                )?,
                ring,
            )?
            .add(&form.constant, ring)?
            .sub(messages.v, ring)?;
        f.constant = rows_constant.sub(&times_quad(&public)?, ring)?;
        Ok(f)
    }

    fn constants_vanish(&self, witness: &PolyVec, ring: &Ring) -> Result<bool> {
        let parts = split(witness, &self.blocks)?;
        for (original, copy) in [(R, R_SIGMA), (WITNESS, WITNESS_SIGMA)] {
            for (z, z_sigma) in parts[original].iter().zip(parts[copy]) {
                if z.sigma_minus_one(ring)? != *z_sigma {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn combine_constants(
        &self,
        sampler: &mut UniformSampler,
        ring: &Ring,
    ) -> Result<Option<Combination>> {
        let starts = offsets(&self.blocks);
        let total = starts[RANDOMNESS] + self.blocks[RANDOMNESS];
        let mut f = Combination::zero(total, ring);
        for (original, copy) in [(R, R_SIGMA), (WITNESS, WITNESS_SIGMA)] {
            let weights = sampler.vector(self.blocks[original], ring);
            f.add_linear(
                starts[copy],
                weights.sigma_minus_one(ring)?.as_slice(),
                ring,
            )?;
            f.add_linear(starts[original], weights.neg(ring)?.as_slice(), ring)?;
        }
        Ok(Some(f))
    }
}
