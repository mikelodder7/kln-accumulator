// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ABDLOP commitment of the LNP framework (Appendix D.2.1, lines 2658–2708):
//!
//! `[t_A; t_B] = [Ā₁; 0]·s₁ + [Ā₂; B̄]·s₂ + [0; m]`
//!
//! with `Ā₁ ∈ R_q^{n̄×m̄₁}`, `Ā₂ ∈ R_q^{n̄×m̄₂}` and `B̄ ∈ R_q^{ℓ̄×m̄₂}` uniform. The rows of `B̄` are
//! `B̄_y` (`256/d` rows, for `y₃`), `B̄_p` (`τ` rows, for the garbage `p`) and `B̄_quad` (one row,
//! for `g₁`), the three BDLOP messages of the protocol (lines 2787–2809).
//!
//! The key is expanded deterministically from the [`Seed`] of a `ProofParams` (itself a hash of
//! the accumulator's public key and an entropy input) and the statement's dimensions, and kept
//! in multi-prime NTT form.

use crate::{
    error::{Error, Result},
    matrix::{NttMatrix, Shape},
    poly::Poly,
    proof::{coeffs::transposed_product, params::LnpParameters},
    ring::Ring,
    sample::{DomainLabel, Seed, UniformSampler},
    vector::PolyVec,
};

/// Label of `Ā₁`.
const LABEL_A1: &[u8] = b"kln/lnp/abdlop/a1";
/// Label of `Ā₂`.
const LABEL_A2: &[u8] = b"kln/lnp/abdlop/a2";
/// Label of `B̄ = [B̄_y; B̄_p; B̄_quad]`.
const LABEL_B: &[u8] = b"kln/lnp/abdlop/b";

/// The commitment key `(Ā₁, Ā₂, B̄)`.
#[derive(Debug)]
pub(crate) struct CommitmentKey {
    a1: NttMatrix,
    a2: NttMatrix,
    b: NttMatrix,
    y_rows: usize,
    p_rows: usize,
}

/// `B̄·v` split into the rows of each BDLOP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BdlopRows {
    /// `B̄_y·v`.
    pub(crate) y: PolyVec,
    /// `B̄_p·v`.
    pub(crate) p: PolyVec,
    /// `B̄_quad·v`.
    pub(crate) quad: Poly,
}

impl zeroize::Zeroize for BdlopRows {
    fn zeroize(&mut self) {
        self.y.zeroize();
        self.p.zeroize();
        self.quad.zeroize();
    }
}

impl CommitmentKey {
    /// Expands the key for the dimensions of `lnp` from `seed`.
    pub(crate) fn expand(seed: &Seed, lnp: &LnpParameters, ring: &Ring) -> Result<Self> {
        let y_rows = lnp.y3_len();
        let p_rows = lnp.tau;
        Ok(Self {
            a1: uniform_ntt(
                seed,
                LABEL_A1,
                Shape {
                    rows: lnp.n,
                    cols: lnp.m1,
                },
                ring,
            )?,
            a2: uniform_ntt(
                seed,
                LABEL_A2,
                Shape {
                    rows: lnp.n,
                    cols: lnp.m2,
                },
                ring,
            )?,
            b: uniform_ntt(
                seed,
                LABEL_B,
                Shape {
                    rows: y_rows + p_rows + 1,
                    cols: lnp.m2,
                },
                ring,
            )?,
            y_rows,
            p_rows,
        })
    }

    /// The Ajtai part `Ā₁·s₁ + Ā₂·s₂`: the commitment `t_A` for the witness, the first message
    /// `w` for the masks, and the verifier's `Ā₁z₁ + Ā₂z₂`.
    pub(crate) fn ajtai(&self, s1: &PolyVec, s2: &PolyVec, ring: &Ring) -> Result<PolyVec> {
        self.a1
            .mul_vec(s1, ring)?
            .add(&self.a2.mul_vec(s2, ring)?, ring)
    }

    /// `B̄·s₂`, split by message.
    pub(crate) fn bdlop(&self, s2: &PolyVec, ring: &Ring) -> Result<BdlopRows> {
        let rows: Vec<Poly> = self.b.mul_vec(s2, ring)?.into();
        let mut rows = rows.into_iter();
        let y = rows.by_ref().take(self.y_rows).collect();
        let p = rows.by_ref().take(self.p_rows).collect();
        let quad = rows.next().ok_or(Error::DimensionMismatch {
            expected: self.y_rows + self.p_rows + 1,
            found: self.y_rows + self.p_rows,
        })?;
        Ok(BdlopRows { y, p, quad })
    }

    /// The coefficients of the linear form `s ↦ ⟨w, Ā₁s₁ + Ā₂s₂⟩ + ⟨v, B̄s₂⟩`: `wᵀĀ₁` on `s₁` and
    /// `wᵀĀ₂ + vᵀB̄` on `s₂`, for `w ∈ R_q^{n̄}` and `v` with one entry per row of `B̄`.
    pub(crate) fn transposed(
        &self,
        w: &[Poly],
        v: &[Poly],
        ring: &Ring,
    ) -> Result<(Vec<Poly>, Vec<Poly>)> {
        let on_s1 = transposed_product(&self.a1, w, ring)?;
        let on_s2 = transposed_product(&self.a2, w, ring)?
            .iter()
            .zip(transposed_product(&self.b, v, ring)?)
            .map(|(a, b)| a.add(&b, ring))
            .collect::<Result<_>>()?;
        Ok((on_s1, on_s2))
    }
}

/// A uniform matrix drawn entry by entry, row-major, from `seed` under `label`, each entry
/// transformed as soon as it is drawn so that the coefficient form is never held whole.
pub(crate) fn uniform_ntt(
    seed: &Seed,
    label: &[u8],
    shape: Shape,
    ring: &Ring,
) -> Result<NttMatrix> {
    let mut sampler = UniformSampler::new(seed, DomainLabel::from(label));
    let entries = (0..shape.rows * shape.cols)
        .map(|_| ring.ntt(&sampler.poly(ring)))
        .collect::<Result<Vec<_>>>()?;
    Ok(NttMatrix::from_parts(shape, entries))
}

#[cfg(test)]
mod tests {
    use super::{BdlopRows, CommitmentKey, LABEL_A1};
    use crate::{
        matrix::Shape,
        proof::params::LnpParameters,
        ring::Ring,
        sample::{DomainLabel, Seed, UniformSampler},
        test_util::TOY,
        vector::PolyVec,
    };

    /// A commitment `(t_A, t_B)` to `(s₁, m)` under randomness `s₂`.
    fn commit(
        key: &CommitmentKey,
        s1: &PolyVec,
        s2: &PolyVec,
        m: &BdlopRows,
        ring: &Ring,
    ) -> (PolyVec, BdlopRows) {
        let t_a = key.ajtai(s1, s2, ring).unwrap();
        let rows = key.bdlop(s2, ring).unwrap();
        let t_b = BdlopRows {
            y: rows.y.add(&m.y, ring).unwrap(),
            p: rows.p.add(&m.p, ring).unwrap(),
            quad: rows.quad.add(&m.quad, ring).unwrap(),
        };
        (t_a, t_b)
    }

    fn binary(len: usize, seed: u8, ring: &Ring) -> PolyVec {
        let values: Vec<i64> =
            UniformSampler::new(&Seed::from([seed; 32]), DomainLabel::from(&b"t"[..]))
                .vector(len, ring)
                .as_slice()
                .iter()
                .flat_map(|p| {
                    p.coefficients()
                        .iter()
                        .map(|c| i64::from(c.as_words()[0] & 1 == 1))
                })
                .collect();
        crate::proof::coeffs::from_integers(&values, ring).unwrap()
    }

    /// Commit, then open: the commitment recomputed from the opening matches, and changing
    /// any one of `s₁`, `s₂` or a message changes it (C34).
    #[test]
    fn commitment_opens() {
        let ring = TOY.ring();
        let lnp = LnpParameters::new(&TOY, 1).unwrap();
        let key = CommitmentKey::expand(&Seed::from([7; 32]), &lnp, ring).unwrap();
        let (s1, s2) = (binary(lnp.m1, 1, ring), binary(lnp.m2, 2, ring));
        let mut sampler = UniformSampler::new(&Seed::from([3; 32]), DomainLabel::from(&b"m"[..]));
        let m = BdlopRows {
            y: sampler.vector(lnp.y3_len(), ring),
            p: sampler.vector(lnp.tau, ring),
            quad: sampler.poly(ring),
        };
        let commitment = commit(&key, &s1, &s2, &m, ring);
        assert_eq!(commit(&key, &s1, &s2, &m, ring), commitment);
        assert_eq!(commitment.0.len(), lnp.n);
        let other_s1 = binary(lnp.m1, 4, ring);
        assert_ne!(commit(&key, &other_s1, &s2, &m, ring).0, commitment.0);
        let other_s2 = binary(lnp.m2, 5, ring);
        let reopened = commit(&key, &s1, &other_s2, &m, ring);
        assert_ne!(reopened.0, commitment.0);
        assert_ne!(reopened.1, commitment.1);
        let mut other_m = m.clone();
        other_m.quad = other_m
            .quad
            .add(&crate::poly::Poly::constant(1, ring), ring)
            .unwrap();
        let changed = commit(&key, &s1, &s2, &other_m, ring);
        assert_eq!(changed.0, commitment.0);
        assert_ne!(changed.1.quad, commitment.1.quad);
    }

    /// The key is a function of its seed: the same seed gives the same matrices, the entries
    /// are the uniform stream of each label, and another seed gives another key.
    #[test]
    fn key_is_deterministic_in_its_seed() {
        let ring = TOY.ring();
        let lnp = LnpParameters::new(&TOY, 0).unwrap();
        let seed = Seed::from([9; 32]);
        let key = CommitmentKey::expand(&seed, &lnp, ring).unwrap();
        let again = CommitmentKey::expand(&seed, &lnp, ring).unwrap();
        assert_eq!(key.a1, again.a1);
        assert_eq!(key.b, again.b);
        let other = CommitmentKey::expand(&Seed::from([10; 32]), &lnp, ring).unwrap();
        assert_ne!(key.a1, other.a1);
        assert_ne!(key.a2, other.a2);
        // The first row of Ā₁ is the start of its label's uniform stream.
        let first = UniformSampler::new(&seed, DomainLabel::from(LABEL_A1))
            .matrix(Shape { rows: 1, cols: 1 }, ring);
        let unit = PolyVec::from(
            core::iter::once(crate::poly::Poly::constant(1, ring))
                .chain(core::iter::repeat_n(
                    crate::poly::Poly::zero(ring),
                    lnp.m1 - 1,
                ))
                .collect::<Vec<_>>(),
        );
        let column = key.a1.mul_vec(&unit, ring).unwrap();
        assert_eq!(column.as_slice()[0], *first.get(0, 0).unwrap());
    }
}
