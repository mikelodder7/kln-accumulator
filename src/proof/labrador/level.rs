// SPDX-License-Identifier: MIT OR Apache-2.0
//! One LaBRADOR level: the prover, the verifier, and the relation the level's opening must
//! satisfy, which is the input of the next level or, after the last, checked in the clear.
//!
//! A committed level is the main protocol of ePrint 2022/1341, Section 5.2 (Figure 2), with the
//! recursion of Section 5.3; the last level ("tail") is Section 5.6's variant without outer
//! commitments. The rounds are made non-interactive by Fiat–Shamir over a merlin
//! transcript (Section 5.7 sizes "the non-interactive variant (via Fiat-Shamir)"):
//!
//! | round | prover sends | challenge | paper |
//! |---|---|---|---|
//! | 1 | committed: `u₁ = B·(t̂ ‖ ĝ)`; tail: `t ‖ g` | `Π ∈ {−1, 0, 1}^{256×nd}` | §5.2 "Committing", "Projecting"; `g` in `u₁` per p. 14 |
//! | 2 | `p = Π·s` | `ω⁽ᵏ⁾ ∈ Z_q^{256}`, `ψ⁽ᵏ⁾ ∈ Z_q^L`, `k < ⌈128/log q⌉` | §5.2 "Aggregating", first step |
//! | 3 | the lifts `ℓ⁽ᵏ⁾` (the paper's `b″⁽ᵏ⁾`) | `α ∈ R_q^K`, `β ∈ R_q^{⌈128/log q⌉}` | §5.2 "Aggregating", second step |
//! | 4 | committed: `u₂ = D·ĥ`; tail: `h` | `c₁, …, c_r ∈ C` | §5.2 "Amortizing" |
//!
//! with `tᵢ = A·sᵢ`, `g_ij = ⟨sᵢ, s_j⟩`, `h_ii = ⟨φᵢ, sᵢ⟩`, hats denoting digit decompositions,
//! and `z = Σ cᵢ·sᵢ`. Here `f″⁽ᵏ⁾ = Σ_j ω_j⁽ᵏ⁾·(⟨σ₋₁(π_j), s⟩ − p_j) + Σ_l ψ_l⁽ᵏ⁾·f′_l` aggregates
//! the projection rows `π_j` and the constant-coefficient constraints `F′`, and
//! `F = Σ_k α_k·f_k + Σ_k β_k·(f″⁽ᵏ⁾ − ℓ⁽ᵏ⁾) = Σ a_ij⟨sᵢ, s_j⟩ + Σ⟨φᵢ, sᵢ⟩ − b` (Figure 3, lines
//! 03–07). The paper's `b″⁽ᵏ⁾` is `ℓ⁽ᵏ⁾` with `⟨ω⁽ᵏ⁾, p⟩ + Σψb′₀` moved into the constant of
//! `f″⁽ᵏ⁾`, so that the paper's check "the constant coefficient of `b″⁽ᵏ⁾` is correct" becomes
//! `const(ℓ⁽ᵏ⁾) = 0`.
//!
//! The verifier checks, in the order of the rounds:
//!
//! * `‖p‖² ≤ 337·β²`.
//!   The paper checks `‖p‖ ≤ √128·β` (Section 5.2, "Projecting"; Section 5.3, last paragraph);
//!   the bound here is Lemma 4.1's upper tail, for the reason given in `params.rs`. An honest
//!   prover whose projection exceeds it aborts with [`Error::ProverAborted`] (probability
//!   about `2^{−128}`) instead of requesting a new `Π` as the paper's prover does.
//! * `const(ℓ⁽ᵏ⁾) = 0` for every lift (Section 5.2, "the verifier checks that their constant
//!   coefficients are correct").
//!
//! and then holds the opening `(z, t, g, h)` to the relation of [`LevelRelation`], the
//! remaining lines of Figure 3:
//!
//! * `u₁ = B·(t̂ ‖ ĝ)` and `u₂ = D·ĥ` (lines 19–20; committed levels). As in Figure 3, `g` is committed in `u₁`, which page 14
//!   prefers to equation (4)'s `u₂ = C·g + D·h` "for a slightly better security proof"; one
//!   matrix `B` stands for the paper's `B_ik` and `C_ijk` (see `key.rs`).
//! * `A·z = Σ cᵢ·tᵢ` (line 15, equation (2)).
//! * `⟨z, z⟩ = Σ_{i,j} cᵢc_j·g_ij` (line 16), with
//!   `z = z⁽⁰⁾ + b·z⁽¹⁾` expanded as in Section 5.3.
//! * `Σᵢ cᵢ·⟨φᵢ, z⟩ = Σ_{i,j} cᵢc_j·h_ij` (line 17).
//! * `Σ a_ij·g_ij + Σᵢ h_ii − b = 0` (line 18).
//! * The norm of the opening: `‖(z⁽⁰⁾, z⁽¹⁾, t̂, ĝ, ĥ)‖² ≤ β′²` (line 14, equation (5)), proved
//!   by the next level; on the tail `‖z‖² ≤ γ²` exactly (equation (2)), `t`, `g`, `h` being
//!   sent in full.
//!
//! Deliberate differences from Figures 2 and 3:
//!
//! * Only the pairs `i ≤ j` of `g` and `h` exist, so lines 08–09 (`g_ij = g_ji`,
//!   `h_ij = h_ji`) hold by construction. For `i < j`, `h_ij = ⟨φᵢ, s_j⟩ + ⟨φ_j, sᵢ⟩` is not
//!   halved as on page 13, and the checks
//!   weight off-diagonal `g_ij`, `h_ij` once each with `cᵢc_j` (and `g` with the explicit factor
//!   2): the same polynomial identities as the paper's sums over all `(i, j)`.
//! * Lines 10–13, the `ℓ∞` ranges of the digits (`‖z⁽⁰⁾‖∞ ≤ b/2` and the like), are not
//!   checked: they cannot be expressed in the principal relation, and Appendix B uses only the `ℓ₂` bound of line 14 (`‖z‖ ≤ (1 + b)β′`, page 15).
//!   This reading of the proof is the implementation's, not a statement of the paper.
//! * The tail sends all `r(r+1)/2` terms of `g` and `h` (Section 5.6 reduces them to `2ν + 1`
//!   and `2r − 1` with interleaved challenges). Size only: soundness is Theorem 5.1's argument
//!   with `t`, `g` fixed by the first message and `h` fixed before the challenges.

use super::{
    challenge as amortisation,
    decompose::{decompose, digit_weights},
    key::LevelKeys,
    params::{Digits, Kind, LevelParams, PROJECTION_BOUND, PROJECTION_ROWS, pair_index},
    relation::{Combination, PrincipalRelation, Quadratic, Wide, offsets, split},
};
use crate::{
    error::{Error, Result, check_dimension},
    poly::Poly,
    proof::{
        append_vec, challenge_seed,
        coeffs::{centred, inner, transform, transposed_product},
        protocol::check_field,
        range::BinomialMatrix,
    },
    ring::{NttPoly, Ring},
    sample::{DomainLabel, Seed, UniformSampler, xof},
    vector::PolyVec,
    zq::Coeff,
};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// Label of the projection matrix's stream.
const LABEL_PROJECTION: &[u8] = b"kln/labrador/projection";
/// Label of the stream of `ω` and `ψ`.
const LABEL_PSI: &[u8] = b"kln/labrador/psi";
/// Label of the stream of `α` and `β`.
const LABEL_ALPHA: &[u8] = b"kln/labrador/alpha";
/// Label of the stream of the amortisation challenges.
const LABEL_AMORTISE: &[u8] = b"kln/labrador/amortise";

/// The messages of one level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LevelMessages {
    /// `u₁`, or on the tail `t ‖ g` in the clear.
    pub(crate) commitment: PolyVec,
    /// `p = Π·s`.
    pub(crate) projection: Vec<i64>,
    /// `ℓ⁽¹⁾, …, ℓ⁽ˡⁱᶠᵗˢ⁾`.
    pub(crate) lifts: PolyVec,
    /// `u₂`, or on the tail `h` in the clear.
    pub(crate) garbage: PolyVec,
}

/// Where a level sits in the chain.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Context<'a> {
    /// Committed or tail.
    pub(crate) kind: Kind,
    /// The level's index, which separates its keys.
    pub(crate) index: usize,
    /// The seed every level's keys derive from.
    pub(crate) seed: &'a Seed,
    /// The ring.
    pub(crate) ring: &'a Ring,
}

/// A proved level: its messages, the relation of its opening, and the opening, which on the
/// tail is `z` alone.
#[derive(Debug)]
pub(crate) struct ProvedLevel {
    /// The messages.
    pub(crate) messages: LevelMessages,
    /// The relation the opening satisfies.
    pub(crate) relation: LevelRelation,
    /// `(z₀, z₁, t̂, ĝ, ĥ)` for a committed level, `z` for the tail.
    pub(crate) opening: PolyVec,
}

/// Proves that `witness` satisfies `relation`, without checking that it does.
pub(crate) fn prove(
    relation: &dyn PrincipalRelation,
    witness: &PolyVec,
    context: &Context<'_>,
    transcript: &mut Transcript,
) -> Result<ProvedLevel> {
    let ring = context.ring;
    let params = LevelParams::derive(
        relation.blocks(),
        relation.norm_bound_squared(),
        context.kind,
        ring,
    )?;
    check_dimension(params.total, witness.len())?;
    let keys = LevelKeys::expand(context.seed, context.index, &params, ring)?;
    let s = witness.as_slice();
    let s_ntt = transform(s, ring)?;
    let vectors = views(&params, &s_ntt);

    // Round 1: inner commitments and quadratic garbage.
    let t = params
        .chunks
        .iter()
        .map(|chunk| {
            let padded: PolyVec = s[chunk.start..chunk.start + chunk.len]
                .iter()
                .cloned()
                .chain(core::iter::repeat_n(
                    Poly::zero(ring),
                    params.width - chunk.len,
                ))
                .collect();
            keys.inner.mul_vec(&padded, ring).map(Vec::from)
        })
        .collect::<Result<Vec<_>>>()?
        .concat();
    let g = pairs(params.r())
        .map(|(i, j)| inner_shortest(vectors[i], vectors[j], ring))
        .collect::<Result<Vec<_>>>()?;
    let (commitment, t_hat, g_hat) = match &keys.outer {
        None => (concat(&[&t, &g]), t, g),
        Some(outer) => {
            let t_hat = decompose_grouped(&t, params.kappa, params.digits, ring)?;
            let g_hat = decompose_grouped(&g, 1, params.digits, ring)?;
            let u1 = outer.garbage.mul_vec(&concat(&[&t_hat, &g_hat]), ring)?;
            (u1, t_hat, g_hat)
        }
    };
    append_vec(transcript, b"labrador commitment", &commitment);

    // Round 2: the projection.
    let matrix = projection_matrix(transcript, &params, ring)?;
    let projection = matrix
        .apply(&centred(witness, ring)?)
        .map_err(|_| Error::CompressionParameters)?;
    if !projection_within(&projection, &params.beta_squared)? {
        return Err(Error::ProverAborted);
    }
    absorb_projection(transcript, &projection);

    // Round 3: the lifts.
    let mut lifted = lifted_constraints(relation, &params, &matrix, &projection, transcript, ring)?;
    let lifts: PolyVec = lifted
        .iter()
        .map(|f| f.evaluate(relation.blocks(), &s_ntt, ring))
        .collect::<Result<_>>()?;
    settle(&mut lifted, &lifts, ring)?;
    append_vec(transcript, b"labrador lifts", &lifts);

    // Round 4: linear garbage.
    let combined = final_constraint(relation, &params, &lifted, transcript, ring)?;
    let phi_ntt = transform(&combined.linear, ring)?;
    let phis = views(&params, &phi_ntt);
    let h = pairs(params.r())
        .map(|(i, j)| {
            if i == j {
                inner(phis[i], vectors[i], ring)
            } else {
                inner_shortest(phis[i], vectors[j], ring)?
                    .add(&inner_shortest(phis[j], vectors[i], ring)?, ring)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let (garbage, h_hat) = match &keys.outer {
        None => (PolyVec::from(h.clone()), h),
        Some(outer) => {
            let h_hat = decompose_grouped(&h, 1, params.digits, ring)?;
            (outer.linear.mul_entries(&h_hat, ring)?, h_hat)
        }
    };
    append_vec(transcript, b"labrador garbage", &garbage);

    // Amortisation.
    let challenges = amortisation_challenges(transcript, params.r(), ring)?;
    let c_ntt = transform(&challenges, ring)?;
    let z: Vec<Poly> = (0..params.width)
        .map(|k| {
            ring.sum_of_products(
                params
                    .chunks
                    .iter()
                    .zip(&c_ntt)
                    .filter(|(chunk, _)| k < chunk.len)
                    .map(|(chunk, c)| (c, &s_ntt[chunk.start + k])),
            )
        })
        .collect();
    // Section 5.3: a committed level's opening is (z⁽⁰⁾, z⁽¹⁾, t̂, ĝ, ĥ); the tail's is z.
    let opening = match context.kind {
        Kind::Tail => PolyVec::from(z),
        Kind::Committed => {
            let z_parts = decompose_grouped(&z, params.width, params.z_digits, ring)?;
            concat(&[&z_parts, &t_hat, &g_hat, &h_hat])
        }
    };
    let messages = LevelMessages {
        commitment,
        projection,
        lifts,
        garbage,
    };
    let relation = LevelRelation::new(
        Conclusion {
            params,
            keys,
            combined: &combined,
            challenges,
            messages: &messages,
        },
        ring,
    )?;
    Ok(ProvedLevel {
        messages,
        relation,
        opening,
    })
}

/// Replays a level against `relation`, runs the checks of rounds 2 and 3, and returns the
/// relation the level's opening must satisfy. Fails with [`Error::ProofRejected`] when a
/// message has the wrong shape or a check fails.
pub(crate) fn verify(
    relation: &dyn PrincipalRelation,
    messages: &LevelMessages,
    context: &Context<'_>,
    transcript: &mut Transcript,
) -> Result<LevelRelation> {
    let ring = context.ring;
    let params = LevelParams::derive(
        relation.blocks(),
        relation.norm_bound_squared(),
        context.kind,
        ring,
    )?;
    let (commitment_len, garbage_len) = match context.kind {
        Kind::Tail => (params.r() * params.kappa + params.pairs(), params.pairs()),
        Kind::Committed => (params.outer_rank, params.outer_rank),
    };
    check_field(&messages.commitment, commitment_len, ring)?;
    check_field(&messages.lifts, params.lifts, ring)?;
    check_field(&messages.garbage, garbage_len, ring)?;
    if messages.projection.len() != PROJECTION_ROWS {
        return Err(Error::ProofRejected);
    }
    let keys = LevelKeys::expand(context.seed, context.index, &params, ring)?;

    append_vec(transcript, b"labrador commitment", &messages.commitment);
    let matrix = projection_matrix(transcript, &params, ring)?;
    // ‖p‖² ≤ 337·β² (Section 5.2, "Projecting", with Lemma 4.1's 337 for the paper's 128).
    if !projection_within(&messages.projection, &params.beta_squared)? {
        return Err(Error::ProofRejected);
    }
    absorb_projection(transcript, &messages.projection);
    let mut lifted = lifted_constraints(
        relation,
        &params,
        &matrix,
        &messages.projection,
        transcript,
        ring,
    )?;
    // const(ℓ⁽ᵏ⁾) = 0: the constant coefficients of the b″⁽ᵏ⁾ are correct (Section 5.2,
    // "Aggregating"; Appendix B's q^{−⌈128/log q⌉} term).
    if messages
        .lifts
        .as_slice()
        .iter()
        .any(|lift| lift.coefficients().first() != Some(&Coeff::ZERO))
    {
        return Err(Error::ProofRejected);
    }
    settle(&mut lifted, &messages.lifts, ring)?;
    append_vec(transcript, b"labrador lifts", &messages.lifts);
    let combined = final_constraint(relation, &params, &lifted, transcript, ring)?;
    append_vec(transcript, b"labrador garbage", &messages.garbage);
    let challenges = amortisation_challenges(transcript, params.r(), ring)?;
    LevelRelation::new(
        Conclusion {
            params,
            keys,
            combined: &combined,
            challenges,
            messages,
        },
        ring,
    )
}

/// What a level ends with, for both prover and verifier.
struct Conclusion<'a> {
    params: LevelParams,
    keys: LevelKeys,
    combined: &'a Combination,
    challenges: Vec<Poly>,
    messages: &'a LevelMessages,
}

/// The relation the opening `(z parts, t̂, ĝ, ĥ)` of a level must satisfy: the verifier's
/// checks of the module documentation, as a principal relation over the opening (the
/// recursion of LaBRADOR).
#[derive(Debug)]
pub(crate) struct LevelRelation {
    params: LevelParams,
    keys: LevelKeys,
    /// `c₁, …, c_r`.
    challenges: Vec<Poly>,
    /// `cᵢc_j` for every pair `i ≤ j`, in [`pair_index`] order.
    products: Vec<Poly>,
    /// `Σᵢ cᵢ·φᵢ`, of length `n`.
    phi: Vec<Poly>,
    /// `(i, j, a_ij)` with `i ≤ j`.
    quadratic: Vec<(usize, usize, Poly)>,
    /// `b`.
    constant: Poly,
    /// `u₁` and `u₂` of a committed level.
    outer: Option<(PolyVec, PolyVec)>,
    /// The blocks of the opening.
    blocks: Vec<usize>,
}

impl LevelRelation {
    fn new(conclusion: Conclusion<'_>, ring: &Ring) -> Result<Self> {
        let Conclusion {
            params,
            keys,
            combined,
            challenges,
            messages,
        } = conclusion;
        let c_ntt = transform(&challenges, ring)?;
        let products = pairs(params.r())
            .map(|(i, j)| ring.sum_of_products([(&c_ntt[i], &c_ntt[j])]))
            .collect();
        let phi_ntt = transform(&combined.linear, ring)?;
        let phi = (0..params.width)
            .map(|k| {
                ring.sum_of_products(
                    params
                        .chunks
                        .iter()
                        .zip(&c_ntt)
                        .filter(|(chunk, _)| k < chunk.len)
                        .map(|(chunk, c)| (c, &phi_ntt[chunk.start + k])),
                )
            })
            .collect();
        let mut quadratic = Vec::new();
        for term in &combined.quadratic {
            let lookup = |b: usize| {
                params
                    .block_chunks
                    .get(b)
                    .copied()
                    .ok_or(Error::DimensionMismatch {
                        expected: params.block_chunks.len(),
                        found: b,
                    })
            };
            let ((left, count), (right, other)) = (lookup(term.left)?, lookup(term.right)?);
            let same_shape = count == other
                && (0..count).all(|t| params.chunks[left + t].len == params.chunks[right + t].len);
            if !same_shape {
                return Err(Error::DimensionMismatch {
                    expected: count,
                    found: other,
                });
            }
            quadratic.extend((0..count).map(|t| {
                let (i, j) = (left + t, right + t);
                (i.min(j), i.max(j), term.weight.clone())
            }));
        }
        let outer = match params.kind {
            Kind::Tail => None,
            Kind::Committed => Some((messages.commitment.clone(), messages.garbage.clone())),
        };
        let blocks = params.opening_blocks();
        Ok(Self {
            params,
            keys,
            challenges,
            products,
            phi,
            quadratic,
            constant: combined.constant.clone(),
            outer,
            blocks,
        })
    }

    /// The final check of a chain: the tail's opening `(z, t, g, h)`, with `t ‖ g` and `h` the
    /// tail's messages, satisfies every equation (Figure 3, lines 15–18), and `‖z‖² ≤ γ²`
    /// (equation (2); Section 5.6 sends the openings in the clear).
    pub(crate) fn check_tail(
        &self,
        z: &PolyVec,
        messages: &LevelMessages,
        ring: &Ring,
    ) -> Result<()> {
        check_field(z, self.params.width, ring)?;
        if self.params.kind != Kind::Tail || z.norm_l2_squared(ring) > self.params.gamma_squared {
            return Err(Error::ProofRejected);
        }
        let opening = concat(&[
            z.as_slice(),
            messages.commitment.as_slice(),
            messages.garbage.as_slice(),
        ]);
        let zero = Poly::zero(ring);
        if self
            .residuals(&opening, ring)?
            .iter()
            .all(|residual| *residual == zero)
        {
            Ok(())
        } else {
            Err(Error::ProofRejected)
        }
    }

    /// The weights of `t̂`, `ĝ`, `ĥ`'s digits and of `z`'s parts.
    fn weights(&self, ring: &Ring) -> (Vec<Coeff>, Vec<Coeff>) {
        (
            digit_weights(self.params.digits, ring),
            digit_weights(self.params.z_digits, ring),
        )
    }
}

impl PrincipalRelation for LevelRelation {
    fn blocks(&self) -> &[usize] {
        &self.blocks
    }

    fn norm_bound_squared(&self) -> &Wide {
        &self.params.next_beta_squared
    }

    fn full_constraints(&self) -> usize {
        let outer = if self.outer.is_some() {
            2 * self.params.outer_rank
        } else {
            0
        };
        outer + self.params.kappa + 3
    }

    fn residuals(&self, witness: &PolyVec, ring: &Ring) -> Result<Vec<Poly>> {
        let params = &self.params;
        let parts = split(witness, &self.blocks)?;
        let z_parts = params.z_digits.parts;
        let (digit, z_weight) = self.weights(ring);
        let z: Vec<Poly> = (0..params.width)
            .map(|k| weighted_sum(parts[..z_parts].iter().map(|p| &p[k]), &z_weight, ring))
            .collect::<Result<_>>()?;
        let (t_hat, g_hat, h_hat) = (parts[z_parts], parts[z_parts + 1], parts[z_parts + 2]);
        let t = recompose_grouped(t_hat, params.kappa, &digit, ring)?;
        let g = recompose_grouped(g_hat, 1, &digit, ring)?;
        let h = recompose_grouped(h_hat, 1, &digit, ring)?;
        let mut out = Vec::with_capacity(self.full_constraints());
        if let (Some((u1, u2)), Some(outer)) = (&self.outer, &self.keys.outer) {
            // u₁ = B·(t̂ ‖ ĝ), u₂ = D·ĥ (Figure 3, lines 19–20).
            let tg = concat(&[t_hat, g_hat]);
            out.extend(Vec::from(outer.garbage.mul_vec(&tg, ring)?.sub(u1, ring)?));
            out.extend(Vec::from(
                outer.linear.mul_entries(h_hat, ring)?.sub(u2, ring)?,
            ));
        }
        // A·z = Σ cᵢ·tᵢ (Figure 3, line 15).
        let az: Vec<Poly> = self.keys.inner.mul_entries(&z, ring)?.into();
        let c_ntt = transform(&self.challenges, ring)?;
        let t_ntt = transform(&t, ring)?;
        for (row, a) in az.iter().enumerate() {
            let ct = ring.sum_of_products(
                c_ntt
                    .iter()
                    .enumerate()
                    .map(|(i, c)| (c, &t_ntt[i * params.kappa + row])),
            );
            out.push(a.sub(&ct, ring)?);
        }
        // ⟨z, z⟩ = Σ cᵢc_j·g_ij (Figure 3, line 16), off-diagonal pairs doubled.
        let z_ntt = transform(&z, ring)?;
        let p_ntt = transform(&self.products, ring)?;
        let doubled: Vec<NttPoly> = pairs(params.r())
            .zip(&self.products)
            .map(|((i, j), p)| ring.ntt(&p.mul_small(if i == j { 1 } else { 2 }, ring)?))
            .collect::<Result<_>>()?;
        out.push(
            inner(&z_ntt, &z_ntt, ring)?
                .sub(&inner(&doubled, &transform(&g, ring)?, ring)?, ring)?,
        );
        // Σ cᵢ⟨φᵢ, z⟩ = Σ cᵢc_j·h_ij (Figure 3, line 17), h unhalved.
        out.push(
            inner(&transform(&self.phi, ring)?, &z_ntt, ring)?
                .sub(&inner(&p_ntt, &transform(&h, ring)?, ring)?, ring)?,
        );
        // Σ a_ij·g_ij + Σ h_ii − b = 0 (Figure 3, line 18).
        let r = params.r();
        let mut system = Poly::zero(ring);
        for (i, j, a) in &self.quadratic {
            system = system.add(&a.mul(&g[pair_index(*i, *j, r)], ring)?, ring)?;
        }
        for i in 0..r {
            system = system.add(&h[pair_index(i, i, r)], ring)?;
        }
        out.push(system.sub(&self.constant, ring)?);
        Ok(out)
    }

    fn combine(&self, weights: &[Poly], ring: &Ring) -> Result<Combination> {
        let params = &self.params;
        check_dimension(self.full_constraints(), weights.len())?;
        let total: usize = self.blocks.iter().sum();
        let starts = offsets(&self.blocks);
        let z_parts = params.z_digits.parts;
        let (t_start, g_start, h_start) =
            (starts[z_parts], starts[z_parts + 1], starts[z_parts + 2]);
        let (digit, z_weight) = self.weights(ring);
        let parts = params.digits.parts;
        let r = params.r();
        let mut f = Combination::zero(total, ring);

        let mut rest = weights;
        if let (Some((u1, u2)), Some(outer)) = (&self.outer, &self.keys.outer) {
            let (w1, tail) = rest.split_at(params.outer_rank);
            let (w2, tail) = tail.split_at(params.outer_rank);
            rest = tail;
            f.add_linear(
                t_start,
                &transposed_product(&outer.garbage, w1, ring)?,
                ring,
            )?;
            f.add_linear(h_start, &transposed_product(&outer.linear, w2, ring)?, ring)?;
            f.constant = f
                .constant
                .add(&dot(w1, u1.as_slice(), ring)?, ring)?
                .add(&dot(w2, u2.as_slice(), ring)?, ring)?;
        }
        let (w3, tail) = rest.split_at(params.kappa);
        let (w4, w5, w6) = match tail {
            [w4, w5, w6] => (w4, w5, w6),
            _ => {
                return Err(Error::DimensionMismatch {
                    expected: 3,
                    found: tail.len(),
                });
            }
        };

        // A·z − Σ cᵢ·tᵢ.
        let az = transposed_product(&self.keys.inner, w3, ring)?;
        let w3_ntt = transform(w3, ring)?;
        let mut t_coefficients = Vec::with_capacity(params.t_len());
        for c in &self.challenges {
            let c_ntt = ring.ntt(c)?;
            let cw: Vec<Poly> = w3_ntt
                .iter()
                .map(|w| ring.sum_of_products([(&c_ntt, w)]).neg(ring))
                .collect::<Result<_>>()?;
            for weight in &digit {
                t_coefficients.extend(cw.iter().map(|p| Poly::scale(p, weight, ring)));
            }
        }
        f.add_linear(t_start, &t_coefficients, ring)?;

        // ⟨z, z⟩ − Σ cᵢc_j·g_ij and Σ cᵢ⟨φᵢ, z⟩ − Σ cᵢc_j·h_ij, with z = Σ_p b^p·z_p: the
        // quadratic form of Section 5.3, ⟨z⁽⁰⁾, z⁽⁰⁾⟩ + 2b⟨z⁽¹⁾, z⁽⁰⁾⟩ + b²⟨z⁽¹⁾, z⁽¹⁾⟩.
        let w4_ntt = ring.ntt(w4)?;
        let on_z = az
            .iter()
            .zip(&self.phi)
            .map(|(a, phi)| a.add(&w5.mul(phi, ring)?, ring))
            .collect::<Result<Vec<_>>>()?;
        for p in 0..z_parts {
            let scaled: Vec<Poly> = on_z
                .iter()
                .map(|x| Poly::scale(x, &z_weight[p], ring))
                .collect();
            f.add_linear(starts[p], &scaled, ring)?;
            for q in p..z_parts {
                let zq = ring.zq();
                let mut weight = zq.mont_mul(&zq.montgomery(&z_weight[p]), &z_weight[q]);
                if p != q {
                    weight = zq.add(&weight, &weight);
                }
                f.quadratic.push(Quadratic {
                    left: p,
                    right: q,
                    weight: Poly::scale(w4, &weight, ring),
                });
            }
        }
        let mut g_coefficients = Vec::with_capacity(params.g_len());
        let mut h_coefficients = Vec::with_capacity(params.g_len());
        for ((i, j), product) in pairs(r).zip(&self.products) {
            let product_ntt = ring.ntt(product)?;
            let doubled = if i == j { 1 } else { 2 };
            let g_base = ring
                .sum_of_products([(&w4_ntt, &product_ntt)])
                .mul_small(-doubled, ring)?;
            let h_base = w5.mul(product, ring)?.neg(ring)?;
            for weight in &digit {
                g_coefficients.push(Poly::scale(&g_base, weight, ring));
                h_coefficients.push(Poly::scale(&h_base, weight, ring));
            }
        }

        // Σ a_ij·g_ij + Σ h_ii − b.
        for (i, j, a) in &self.quadratic {
            let base = w6.mul(a, ring)?;
            let at = pair_index(*i, *j, r) * parts;
            for (slot, weight) in g_coefficients[at..at + parts].iter_mut().zip(&digit) {
                *slot = slot.add(&Poly::scale(&base, weight, ring), ring)?;
            }
        }
        for i in 0..r {
            let at = pair_index(i, i, r) * parts;
            for (slot, weight) in h_coefficients[at..at + parts].iter_mut().zip(&digit) {
                *slot = slot.add(&Poly::scale(w6, weight, ring), ring)?;
            }
        }
        f.add_linear(g_start, &g_coefficients, ring)?;
        f.add_linear(h_start, &h_coefficients, ring)?;
        f.constant = f.constant.add(&w6.mul(&self.constant, ring)?, ring)?;
        Ok(f)
    }

    fn constants_vanish(&self, _witness: &PolyVec, _ring: &Ring) -> Result<bool> {
        Ok(true)
    }

    fn combine_constants(
        &self,
        _sampler: &mut UniformSampler,
        _ring: &Ring,
    ) -> Result<Option<Combination>> {
        Ok(None)
    }
}

/// The pairs `(i, j)` with `i ≤ j < r`, in [`pair_index`] order.
fn pairs(r: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..r).flat_map(move |i| (i..r).map(move |j| (i, j)))
}

/// The witness vectors (or a vector laid out like the witness) as slices, one per chunk.
fn views<'a>(params: &LevelParams, flat: &'a [NttPoly]) -> Vec<&'a [NttPoly]> {
    params
        .chunks
        .iter()
        .map(|chunk| &flat[chunk.start..chunk.start + chunk.len])
        .collect()
}

/// `⟨a, b⟩` over the shorter length: vectors are zero beyond their own length.
fn inner_shortest(a: &[NttPoly], b: &[NttPoly], ring: &Ring) -> Result<Poly> {
    let len = a.len().min(b.len());
    inner(&a[..len], &b[..len], ring)
}

/// `Σ wᵢ·vᵢ` for ring elements `w` and `v`.
fn dot(w: &[Poly], v: &[Poly], ring: &Ring) -> Result<Poly> {
    inner(&transform(w, ring)?, &transform(v, ring)?, ring)
}

/// `Σ_k weights_k·parts_k` for scalars `weights`.
fn weighted_sum<'a>(
    parts: impl Iterator<Item = &'a Poly>,
    weights: &[Coeff],
    ring: &Ring,
) -> Result<Poly> {
    parts
        .zip(weights)
        .try_fold(Poly::zero(ring), |acc, (p, w)| {
            acc.add(&Poly::scale(p, w, ring), ring)
        })
}

/// The digits of `values`, in groups of `group`: for each group, digit 0 of every member, then
/// digit 1, and so on.
fn decompose_grouped(
    values: &[Poly],
    group: usize,
    digits: Digits,
    ring: &Ring,
) -> Result<Vec<Poly>> {
    let mut out = Vec::with_capacity(values.len() * digits.parts);
    for members in values.chunks(group) {
        let split = members
            .iter()
            .map(|p| decompose(p, digits, ring))
            .collect::<Result<Vec<_>>>()?;
        for k in 0..digits.parts {
            out.extend(split.iter().map(|d| d[k].clone()));
        }
    }
    Ok(out)
}

/// The inverse of [`decompose_grouped`] for digit weights `weights`.
fn recompose_grouped(
    digits: &[Poly],
    group: usize,
    weights: &[Coeff],
    ring: &Ring,
) -> Result<Vec<Poly>> {
    let parts = weights.len();
    digits
        .chunks(group * parts)
        .flat_map(|block| {
            (0..group).map(move |m| {
                weighted_sum((0..parts).map(|k| &block[k * group + m]), weights, ring)
            })
        })
        .collect()
}

/// The concatenation of polynomial sequences.
fn concat<P: AsRef<[Poly]>>(parts: &[P]) -> PolyVec {
    parts
        .iter()
        .flat_map(|p| p.as_ref().iter().cloned())
        .collect()
}

/// Appends `p` as little-endian `i64`.
fn absorb_projection(transcript: &mut Transcript, projection: &[i64]) {
    let bytes: Vec<u8> = projection.iter().flat_map(|x| x.to_le_bytes()).collect();
    transcript.append_message(b"labrador projection", &bytes);
}

/// `Π`, drawn after the first message, with independent entries `−1, 0, 1` of probabilities
/// `1/4, 1/2, 1/4` (Lemma 4.1; Section 5.2, "Projecting", with one matrix over the whole
/// witness for the paper's `Π₁, …, Π_r`).
fn projection_matrix(
    transcript: &mut Transcript,
    params: &LevelParams,
    ring: &Ring,
) -> Result<BinomialMatrix> {
    BinomialMatrix::sample_labelled(
        &challenge_seed(transcript, b"labrador projection matrix"),
        LABEL_PROJECTION,
        params.total * ring.degree(),
    )
}

/// `‖p‖² ≤ 337·β²`, exactly (Lemma 4.1's upper tail; the paper checks `128·β²`, Section 5.2).
fn projection_within(projection: &[i64], beta_squared: &Wide) -> Result<bool> {
    let norm = projection.iter().fold(Wide::ZERO, |acc, &x| {
        let m = u128::from(x.unsigned_abs());
        acc.wrapping_add(&Wide::from_u128(m * m))
    });
    let bound = crate::params::product(&[Wide::from_u64(PROJECTION_BOUND), *beta_squared])
        .map_err(|_| Error::CompressionParameters)?;
    Ok(norm <= bound)
}

/// `f''⁽ᵏ⁾` for every lift, before its lift is subtracted: `⟨σ(Πᵀω⁽ᵏ⁾), s⟩ − ⟨ω⁽ᵏ⁾, p⟩` plus the
/// relation's constant-coefficient constraints combined with `ψ⁽ᵏ⁾`: the
/// first aggregation of Section 5.2, `⌈128/log q⌉` times, with `ω⁽ᵏ⁾ ∈ Z_q^{256}` and
/// `ψ⁽ᵏ⁾ ∈ Z_q^L` uniform (Figure 3, lines 03–04).
fn lifted_constraints(
    relation: &dyn PrincipalRelation,
    params: &LevelParams,
    matrix: &BinomialMatrix,
    projection: &[i64],
    transcript: &mut Transcript,
    ring: &Ring,
) -> Result<Vec<Combination>> {
    let mut sampler = UniformSampler::new(
        &challenge_seed(transcript, b"labrador psi"),
        DomainLabel::from(LABEL_PSI),
    );
    let zq = ring.zq();
    let omegas: Vec<Vec<Coeff>> = (0..params.lifts)
        .map(|_| {
            sampler
                .vector(PROJECTION_ROWS / ring.degree(), ring)
                .as_slice()
                .iter()
                .flat_map(|p| p.coefficients().iter().copied())
                .collect()
        })
        .collect();
    let rows = matrix.combine(&omegas, ring)?;
    rows.iter()
        .zip(&omegas)
        .map(|(row, omega)| {
            let projected = omega
                .iter()
                .zip(projection)
                .fold(Coeff::ZERO, |acc, (w, &p)| {
                    zq.add(&acc, &zq.mont_mul(&zq.montgomery(w), &zq.reduce_i64(p)))
                });
            let mut constant = vec![Coeff::ZERO; ring.degree()];
            constant[0] = projected;
            let mut f = Combination {
                quadratic: Vec::new(),
                linear: row.sigma_minus_one(ring)?.into(),
                constant: Poly::from_reduced(constant),
            };
            if let Some(part) = relation.combine_constants(&mut sampler, ring)? {
                f.add_assign(&part, ring)?;
            }
            Ok(f)
        })
        .collect()
}

/// Adds each lift to its constraint's constant, making `f''⁽ᵏ⁾ − ℓ⁽ᵏ⁾ = 0` a full constraint.
fn settle(lifted: &mut [Combination], lifts: &PolyVec, ring: &Ring) -> Result<()> {
    for (f, lift) in lifted.iter_mut().zip(lifts.as_slice()) {
        f.constant = f.constant.add(lift, ring)?;
    }
    Ok(())
}

/// `F = Σ_k α_k·f_k + Σ_k β_k·(f''⁽ᵏ⁾ − ℓ⁽ᵏ⁾)`: the second aggregation of
/// Section 5.2 with `α ∈ R_q^K`, `β ∈ R_q^{⌈128/log q⌉}` uniform (Figure 3, lines 05–07;
/// Appendix B's `q^{−d/2}` term).
fn final_constraint(
    relation: &dyn PrincipalRelation,
    params: &LevelParams,
    lifted: &[Combination],
    transcript: &mut Transcript,
    ring: &Ring,
) -> Result<Combination> {
    let mut sampler = UniformSampler::new(
        &challenge_seed(transcript, b"labrador alpha"),
        DomainLabel::from(LABEL_ALPHA),
    );
    let alpha = sampler.vector(relation.full_constraints(), ring);
    let beta = sampler.vector(lifted.len(), ring);
    let mut combined = relation.combine(alpha.as_slice(), ring)?;
    check_dimension(params.total, combined.linear.len())?;
    for (f, b) in lifted.iter().zip(beta.as_slice()) {
        combined.add_scaled(f, b, ring)?;
    }
    Ok(combined)
}

/// `c₁, …, c_r`, drawn after the last message from the set of `challenge.rs` (Section 5.2,
/// "Amortizing").
fn amortisation_challenges(
    transcript: &mut Transcript,
    r: usize,
    ring: &Ring,
) -> Result<Vec<Poly>> {
    let mut reader = xof(
        &challenge_seed(transcript, b"labrador amortisation"),
        DomainLabel::from(LABEL_AMORTISE),
    );
    (0..r)
        .map(|_| amortisation::sample(&mut reader, ring))
        .collect()
}
