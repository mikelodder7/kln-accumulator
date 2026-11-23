// SPDX-License-Identifier: MIT OR Apache-2.0
//! The single quadratic relation of D.2.2's seventh round (equation D.6, lines 2921–2965) and
//! its homogenisation in the final challenge `c`, the verifier's `Z` (lines 3216–3246).
//!
//! With `ŝ = (s₁, y₃, p)` the committed messages, the prover must show `F(ŝ) = 0` where
//!
//! `F = γ₁ᵀ(A₁x + A₂r − t) + γ₂ᵀ([A | B − xᵀ⊗G]·G_β·s̄_x − c_acc) + Σᵢ γ₃,ᵢ·xᵢ(xᵢ − 1)`
//! `  + Σᵢ γ₄,ᵢ·(pᵢ + Σ_j α_{i,j}·(σ(r_j)ᵀs₁ + σ(e_j)ᵀy₃) + α_{i,257}·s₁ᵀσ(s₁ − P_W) − hᵢ)`.
//!
//! `F` is a quadratic form `Q`, a linear form `L` and a constant `K`, which this module
//! gathers once per proof into `Fh(c, ẑ) = Q(ẑ) + c·L(ẑ) − c²·K`, the verifier's `Z` with the
//! constant moved to the left. For openings `ẑ = ŷ + c·ŝ` it is a polynomial of degree two in
//! `c` (`σ(c) = c` keeps the `σ` terms in it), `Fh = c²·F(ŝ) + c·g₁ + g₀`. The prover obtains
//! `g₁` and `g₀` from this same evaluation at `c ∈ {0, 1, −1}` rather than from the printed
//! formulas of lines 3133–3169, which drop terms of D.8 and D.11.
//!
//! Two notational points are fixed here. `γ₂ ∈ R_q^n`, one challenge per row of the membership
//! equation (the paper prints `R_q^{m'·n}`). And the range-proof terms use `σ(e_j)ᵀy₃`, whose
//! constant coefficient is coefficient `j` of `y₃`; the printed `e_jᵀy₃` has constant coefficient
//! `±y₃` at index `−j mod d` instead, which would not match `z₃,j`.

use crate::{
    accumulator::Accumulator,
    error::{Error, Result, check_dimension},
    key::PublicKey,
    matrix::PolyMatrix,
    params::Params,
    poly::Poly,
    proof::{
        LinkingRelation,
        coeffs::{inner, transform},
        params::{LnpParameters, RANGE_ROWS},
    },
    ring::{NttPoly, Ring},
    vector::PolyVec,
    zq::Coeff,
};
use zeroize::Zeroizing;

/// The verifier's challenges `γ₁ ∈ R_q^h`, `γ₂ ∈ R_q^n`, `γ₃ ∈ R_q^ℓ`, `γ₄ ∈ R_q^τ` (line 2910).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Gammas {
    /// `γ₁`, one per row of the linking relation.
    pub(crate) link: PolyVec,
    /// `γ₂`, one per row of the membership equation.
    pub(crate) membership: PolyVec,
    /// `γ₃`, one per bit of `x`.
    pub(crate) bits: PolyVec,
    /// `γ₄`, one per masked opening `hᵢ`.
    pub(crate) openings: PolyVec,
}

/// Everything `F` is built from.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RelationInputs<'a> {
    /// The proof parameters.
    pub(crate) lnp: &'a LnpParameters,
    /// The accumulator's public key `(A, B, u)`.
    pub(crate) pubkey: &'a PublicKey,
    /// The accumulator value `c_acc`.
    pub(crate) accumulator: &'a Accumulator,
    /// `A₁`, `A₂`, `t`.
    pub(crate) link: &'a LinkingRelation,
    /// `γ₁, …, γ₄`.
    pub(crate) gammas: &'a Gammas,
    /// `α ∈ Z_q^{τ×257}`, row by row.
    pub(crate) alpha: &'a [Vec<Coeff>],
    /// `σ(a_i)`, transformed, for `a_i = Σ_j α_{i,j}·r_j` and every `i < τ` (see
    /// [`sigma_transforms`]).
    pub(crate) range: &'a [Vec<NttPoly>],
    /// The masked openings `h₁, …, h_τ`.
    pub(crate) h: &'a PolyVec,
}

/// `Fh(c, ·)` with `c` and `zₓ` fixed (see [`Relation::linearise`]).
#[derive(Clone, Debug)]
pub(crate) struct Linearised {
    /// `γ★`, the weight of `z₁ᵀσ(z₁)`.
    pub(crate) binary: Poly,
    /// `λ₁ ∈ R_q^{m̄₁}`, the coefficients of `z₁`, including those of `zₓ`.
    pub(crate) z1: Vec<Poly>,
    /// `λ_y = c·Σᵢ γ₄,ᵢ·σ(Eᵢ)`, the coefficients of the opening of `y₃`.
    pub(crate) y: Vec<Poly>,
    /// `λ_p = c·γ₄`, the coefficients of the opening of `p`.
    pub(crate) p: Vec<Poly>,
    /// `κ₀ = Σᵢ γ₃,ᵢ·zₓ,ᵢ² − c²·K`.
    pub(crate) constant: Poly,
}

/// Openings of the committed messages at one challenge: `z₁` for `s₁`, and `c·t_y − B̄_y·z₂`,
/// `c·t_p − B̄_p·z₂` for `y₃` and `p`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Opening<'a> {
    /// The opening of `s₁`.
    pub(crate) z1: &'a PolyVec,
    /// The opening of `y₃`.
    pub(crate) y: &'a PolyVec,
    /// The opening of `p`.
    pub(crate) p: &'a PolyVec,
}

/// `Fh(c, ẑ) = Q(ẑ) + c·L(ẑ) − c²·K` with every public part precomputed.
///
/// `L(ẑ) = Σᵢ γ₄,ᵢ·σ(aᵢ)ᵀz₁ + (A₁ᵀγ₁ − γ₃)ᵀzₓ + (A₂ᵀγ₁)ᵀz_r + ([A | B]ᵀγ₂)ᵀ(G_β·z_{s̄})
/// − γ★·σ(P_W)·Σ_k z₁,k + (Σᵢ γ₄,ᵢ·σ(Eᵢ))ᵀo_y + γ₄ᵀo_p`, where `γ★ = Σᵢ γ₄,ᵢ·α_{i,257}` and `Eᵢ`
/// is the vector whose coefficients are `α_{i,1..256}`;
/// `Q(ẑ) = γ★·z₁ᵀσ(z₁) + Σᵢ zₓ,ᵢ·(γ₃,ᵢ·zₓ,ᵢ − γ₂ᵀG·(G_β·z_{s̄})_{B,i})`;
/// `K = γ₁ᵀt + γ₂ᵀc_acc + γ₄ᵀh`.
#[derive(Debug)]
pub(crate) struct Relation<'a> {
    params: &'a Params,
    lnp: &'a LnpParameters,
    range: &'a [Vec<NttPoly>],
    /// `γ₄`, as polynomials and transformed.
    openings: Vec<Poly>,
    openings_ntt: Vec<NttPoly>,
    /// `A₁ᵀγ₁ − γ₃`.
    linear_x: Vec<NttPoly>,
    /// `A₂ᵀγ₁`.
    linear_r: Vec<NttPoly>,
    /// `[A | B]ᵀγ₂`.
    linear_witness: Vec<NttPoly>,
    /// `γ★·σ(P_W)`, the weight of `Σ_k z₁,k`.
    linear_ones: Poly,
    /// `Σᵢ γ₄,ᵢ·σ(Eᵢ)`.
    linear_y: Vec<NttPoly>,
    /// `γ★`.
    binary: Poly,
    /// `γ₃`.
    bits: Vec<Poly>,
    /// `γ₂`, transformed.
    membership: Vec<NttPoly>,
    /// `K`.
    constant: Poly,
    /// The digit weights of `G_β` in Montgomery form.
    weights: Vec<Coeff>,
}

impl<'a> Relation<'a> {
    /// Gathers `Q`, `L` and `K` from `inputs`.
    pub(crate) fn new(inputs: RelationInputs<'a>) -> Result<Self> {
        let params = &**inputs.pubkey.params();
        let lnp = inputs.lnp;
        let ring = params.ring();
        let gammas = inputs.gammas;
        let tau = lnp.tau;
        if inputs.alpha.len() != tau || inputs.range.len() != tau || inputs.h.len() != tau {
            return Err(Error::DimensionMismatch {
                expected: tau,
                found: inputs
                    .alpha
                    .len()
                    .min(inputs.range.len())
                    .min(inputs.h.len()),
            });
        }
        let openings_ntt = transform(gammas.openings.as_slice(), ring)?;
        let binary = gammas
            .openings
            .as_slice()
            .iter()
            .zip(inputs.alpha)
            .try_fold(Poly::zero(ring), |acc, (g, row)| {
                acc.add(&Poly::scale(g, binary_weight(row)?, ring), ring)
            })?;
        let linear_ones = binary.mul(&ones(ring).sigma_minus_one(ring)?, ring)?;

        let gamma1 = transform(gammas.link.as_slice(), ring)?;
        let linear_x = transposed_combination(&gamma1, inputs.link.a1(), ring)?
            .iter()
            .zip(gammas.bits.as_slice())
            .map(|(l, g3)| ring.ntt(&l.sub(g3, ring)?))
            .collect::<Result<Vec<_>>>()?;
        let linear_r = transform(
            &transposed_combination(&gamma1, inputs.link.a2(), ring)?,
            ring,
        )?;
        let membership = transform(gammas.membership.as_slice(), ring)?;
        let mut mu = transposed_combination(&membership, inputs.pubkey.a(), ring)?;
        mu.extend(transposed_combination(
            &membership,
            inputs.pubkey.b(),
            ring,
        )?);
        let linear_witness = transform(&mu, ring)?;

        let linear_y = (0..lnp.y3_len())
            .map(|t| {
                let sigmas = inputs
                    .alpha
                    .iter()
                    .map(|row| {
                        ring.ntt(&range_polys(row, ring)?.as_slice()[t].sigma_minus_one(ring)?)
                    })
                    .collect::<Result<Vec<_>>>()?;
                ring.ntt(&inner(&openings_ntt, &sigmas, ring)?)
            })
            .collect::<Result<Vec<_>>>()?;

        let constant = inner(&gamma1, &transform(inputs.link.t().as_slice(), ring)?, ring)?
            .add(
                &inner(
                    &membership,
                    &transform(inputs.accumulator.value().as_slice(), ring)?,
                    ring,
                )?,
                ring,
            )?
            .add(
                &inner(&openings_ntt, &transform(inputs.h.as_slice(), ring)?, ring)?,
                ring,
            )?;
        let weights = digit_weights(lnp, ring)?
            .iter()
            .map(|w| ring.zq().montgomery(w))
            .collect();
        Ok(Self {
            params,
            lnp,
            range: inputs.range,
            openings: gammas.openings.as_slice().to_vec(),
            openings_ntt,
            linear_x,
            linear_r,
            linear_witness,
            linear_ones,
            linear_y,
            binary,
            bits: gammas.bits.as_slice().to_vec(),
            membership,
            constant,
            weights,
        })
    }

    /// `Fh(c, ẑ)`.
    pub(crate) fn evaluate(&self, c: &Poly, opening: &Opening<'_>) -> Result<Poly> {
        let ring = self.params.ring();
        let lnp = self.lnp;
        let z1 = opening.z1.as_slice();
        check_dimension(lnp.m1, z1.len())?;
        let z1_ntt = Zeroizing::new(transform(z1, ring)?);
        let recomposed: Zeroizing<Vec<Poly>> = Zeroizing::new(
            (0..lnp.witness_len)
                .map(|k| self.recompose(z1, k, ring))
                .collect(),
        );
        let total = z1
            .iter()
            .try_fold(Poly::zero(ring), |acc, p| acc.add(p, ring))?;
        let (x_end, r_end) = (lnp.r_offset(), lnp.witness_offset());
        let mut linear = inner(&self.linear_x, &z1_ntt[..x_end], ring)?
            .add(&inner(&self.linear_r, &z1_ntt[x_end..r_end], ring)?, ring)?
            .add(
                &inner(&self.linear_witness, &transform(&recomposed, ring)?, ring)?,
                ring,
            )?
            .sub(&self.linear_ones.mul(&total, ring)?, ring)?
            .add(
                &inner(
                    &self.linear_y,
                    &transform(opening.y.as_slice(), ring)?,
                    ring,
                )?,
                ring,
            )?
            .add(
                &inner(
                    &self.openings_ntt,
                    &transform(opening.p.as_slice(), ring)?,
                    ring,
                )?,
                ring,
            )?;
        for (g4, range) in self.openings.iter().zip(self.range) {
            linear = linear.add(&g4.mul(&inner(range, &z1_ntt, ring)?, ring)?, ring)?;
        }

        let sigma = Zeroizing::new(transform(
            opening.z1.sigma_minus_one(ring)?.as_slice(),
            ring,
        )?);
        let mut quadratic = self.binary.mul(&inner(&z1_ntt, &sigma, ring)?, ring)?;
        let gadget = self.params.gadget();
        let (m, m_prime) = (self.params.spec().m, self.params.m_prime());
        for (i, (zx, g3)) in z1.iter().zip(&self.bits).enumerate() {
            let block: PolyVec = recomposed[m + i * m_prime..m + (i + 1) * m_prime]
                .iter()
                .cloned()
                .collect();
            let gadget_rows = transform(gadget.mul_vec(&block)?.as_slice(), ring)?;
            let membership = inner(&self.membership, &gadget_rows, ring)?;
            let term = g3.mul(zx, ring)?.sub(&membership, ring)?.mul(zx, ring)?;
            quadratic = quadratic.add(&term, ring)?;
        }
        let c_squared = c.mul(c, ring)?;
        quadratic
            .add(&c.mul(&linear, ring)?, ring)?
            .sub(&c_squared.mul(&self.constant, ring)?, ring)
    }

    /// `Fh(c, ·)` for a fixed challenge `c` and a fixed `zₓ`, as the quadratic form the
    /// LaBRADOR layer of D.3 needs (lines 3403–3470): for every opening whose first `ℓ` entries
    /// are `zₓ`,
    ///
    /// `Fh(c, ẑ) = γ★·z₁ᵀσ(z₁) + ⟨λ₁, z₁⟩ + ⟨λ_y, o_y⟩ + ⟨λ_p, o_p⟩ + κ₀`.
    ///
    /// With `zₓ` known, the term `Σᵢ zₓ,ᵢ·γ₂ᵀG·(G_β·z_{s̄})_{B,i}` of `Q` is linear in `z_{s̄}` and
    /// moves into `λ₁`, and `Σᵢ γ₃,ᵢ·zₓ,ᵢ²` moves into `κ₀`; that is the reason D.3 sends `zₓ`
    /// in the clear (line 3471).
    pub(crate) fn linearise(&self, c: &Poly, z_x: &[Poly]) -> Result<Linearised> {
        let ring = self.params.ring();
        let lnp = self.lnp;
        check_dimension(lnp.element_bits, z_x.len())?;
        let c_ntt = ring.ntt(c)?;
        let times_c = |p: &NttPoly| ring.sum_of_products([(&c_ntt, p)]);
        let c_openings = transform(
            &self.openings_ntt.iter().map(times_c).collect::<Vec<_>>(),
            ring,
        )?;
        let c_ones = c.mul(&self.linear_ones, ring)?;
        let mut z1 = (0..lnp.m1)
            .map(|k| {
                ring.sum_of_products(c_openings.iter().zip(self.range).map(|(g, a)| (g, &a[k])))
                    .sub(&c_ones, ring)
            })
            .collect::<Result<Vec<_>>>()?;
        let r_end = lnp.witness_offset();
        let public = self.linear_x.iter().chain(&self.linear_r);
        for (entry, l) in z1[..r_end].iter_mut().zip(public) {
            *entry = entry.add(&times_c(l), ring)?;
        }
        let gadget_t = self.gadget_transposed(ring)?;
        let (m, m_prime) = (self.params.spec().m, self.params.m_prime());
        let zq = ring.zq();
        for (e, mu) in self.linear_witness.iter().enumerate() {
            let mut nu = times_c(mu);
            if e >= m {
                let (i, t) = ((e - m) / m_prime, (e - m) % m_prime);
                nu = nu.sub(&z_x[i].mul(&gadget_t[t], ring)?, ring)?;
            }
            let start = r_end + e * lnp.digits;
            for (entry, w) in z1[start..start + lnp.digits].iter_mut().zip(&self.weights) {
                let scaled = Poly::from_reduced(
                    nu.coefficients()
                        .iter()
                        .map(|x| zq.mont_mul(w, x))
                        .collect(),
                );
                *entry = entry.add(&scaled, ring)?;
            }
        }
        let squares = z_x
            .iter()
            .zip(&self.bits)
            .try_fold(Poly::zero(ring), |acc, (zx, g3)| {
                acc.add(&g3.mul(&zx.mul(zx, ring)?, ring)?, ring)
            })?;
        let constant = squares.sub(&c.mul(c, ring)?.mul(&self.constant, ring)?, ring)?;
        Ok(Linearised {
            binary: self.binary.clone(),
            z1,
            y: self.linear_y.iter().map(times_c).collect(),
            p: self.openings_ntt.iter().map(times_c).collect(),
            constant,
        })
    }

    /// `Gᵀγ₂ ∈ R_q^{m'}`: entry `t` is `Σ_row G_{row,t}·γ₂,row`.
    fn gadget_transposed(&self, ring: &Ring) -> Result<Vec<Poly>> {
        let gadget = PolyMatrix::from(self.params.gadget());
        let shape = gadget.shape();
        (0..shape.cols)
            .map(|t| {
                let column = (0..shape.rows)
                    .map(|row| {
                        gadget
                            .get(row, t)
                            .ok_or(Error::DimensionMismatch {
                                expected: shape.rows,
                                found: row,
                            })
                            .and_then(|entry| ring.ntt(entry))
                    })
                    .collect::<Result<Vec<_>>>()?;
                inner(&self.membership, &column, ring)
            })
            .collect()
    }

    /// Entry `k` of `G_β·z_{s̄}`: `Σ_j w_j·z₁[off + k·D + j]`.
    fn recompose(&self, z1: &[Poly], k: usize, ring: &Ring) -> Poly {
        let zq = ring.zq();
        let start = self.lnp.witness_offset() + k * self.lnp.digits;
        let mut acc = vec![Coeff::ZERO; ring.degree()];
        for (digit, w) in z1[start..start + self.lnp.digits].iter().zip(&self.weights) {
            for (out, x) in acc.iter_mut().zip(digit.coefficients()) {
                *out = zq.add(out, &zq.mont_mul(w, x));
            }
        }
        Poly::from_reduced(acc)
    }
}

/// `σ(a_i)` transformed, entry by entry, for every combined vector `a_i`.
pub(crate) fn sigma_transforms(combined: &[PolyVec], ring: &Ring) -> Result<Vec<Vec<NttPoly>>> {
    combined
        .iter()
        .map(|a| transform(a.sigma_minus_one(ring)?.as_slice(), ring))
        .collect()
}

/// `Eᵢ`: the `256/d` polynomials whose coefficients are `α_{i,1}, …, α_{i,256}`.
pub(crate) fn range_polys(row: &[Coeff], ring: &Ring) -> Result<PolyVec> {
    let rows = row.get(..RANGE_ROWS).ok_or(Error::DimensionMismatch {
        expected: RANGE_ROWS + 1,
        found: row.len(),
    })?;
    Ok(rows
        .chunks_exact(ring.degree())
        .map(|chunk| Poly::from_reduced(chunk.to_vec()))
        .collect())
}

/// `α_{i,257}`, the weight of the binary relation in row `i` of `α`.
pub(crate) fn binary_weight(row: &[Coeff]) -> Result<&Coeff> {
    row.get(RANGE_ROWS).ok_or(Error::DimensionMismatch {
        expected: RANGE_ROWS + 1,
        found: row.len(),
    })
}

/// `P_W`'s entry `Σ_{j<d} X^j`.
pub(crate) fn ones(ring: &Ring) -> Poly {
    Poly::from_reduced(vec![Coeff::ONE; ring.degree()])
}

/// The digit weights of `G_β`: `2^j` for `j < D − 1` and `−2^{D−1}` for the top digit, reduced.
/// Every weight is below `q` because `2^{D−1} ≤ 2β < q`.
pub(crate) fn digit_weights(lnp: &LnpParameters, ring: &Ring) -> Result<Vec<Coeff>> {
    let zq = ring.zq();
    (0..lnp.digits)
        .map(|j| {
            let shift = u32::try_from(j).map_err(|_| Error::ProofModulusTooSmall)?;
            let power = Coeff::ONE.shl_vartime(shift);
            if !zq.is_reduced(&power) {
                return Err(Error::ProofModulusTooSmall);
            }
            Ok(if j + 1 == lnp.digits {
                zq.neg(&power)
            } else {
                power
            })
        })
        .collect()
}

/// `γᵀM` for `M ∈ R_q^{rows×cols}` and transformed `γ ∈ R_q^{rows}`: one entry per column.
fn transposed_combination(gamma: &[NttPoly], m: &PolyMatrix, ring: &Ring) -> Result<Vec<Poly>> {
    let shape = m.shape();
    check_dimension(gamma.len(), shape.rows)?;
    (0..shape.cols)
        .map(|col| {
            let column = (0..shape.rows)
                .map(|row| {
                    let entry = m.get(row, col).ok_or(Error::DimensionMismatch {
                        expected: shape.rows,
                        found: row,
                    })?;
                    ring.ntt(entry)
                })
                .collect::<Result<Vec<_>>>()?;
            inner(gamma, &column, ring)
        })
        .collect()
}
