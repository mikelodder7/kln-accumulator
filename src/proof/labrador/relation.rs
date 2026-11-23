// SPDX-License-Identifier: MIT OR Apache-2.0
//! The principal relation of LaBRADOR (ePrint 2022/1341, Section 5.1; recalled in ePrint
//! 2025/1099, D.3, lines 3373–3398) and the single combined constraint every aggregation step
//! produces.
//!
//! A witness is a list of blocks of polynomials, flattened into one vector. A constraint is
//!
//! `f(s) = Σ a·⟨B_a, B_b⟩ + ⟨φ, s⟩ − b`
//!
//! with the quadratic part over pairs of equally long blocks and the linear part `φ` over the
//! flattened witness. Each LaBRADOR level splits every block into vectors of at most its rank, so
//! a quadratic block term becomes the sum of the products of corresponding vectors, and the
//! principal relation's `a_ij⟨s_i, s_j⟩` follows.
//!
//! A relation consists of full constraints `f(s) = 0` over `R_q` (the paper's family `F`),
//! constant-coefficient constraints `const(f'(s)) = 0` (the family `F′`), and one bound
//! `‖s‖² ≤ β²`. The paper's `a_ij` is symmetric; here each unordered pair is one term. Relations expose their constraints
//! only through random combinations, because the families at hand (the rows of a commitment
//! matrix, one constraint per coefficient of `σ(z)`) are far too large to hold one by one.

use crate::{
    error::{Error, Result, check_dimension},
    poly::Poly,
    proof::coeffs::{inner, transform},
    ring::{NttPoly, Ring},
    sample::UniformSampler,
    vector::PolyVec,
};
use crypto_bigint::U512;

/// The integer type of norm bounds.
pub(crate) type Wide = U512;

/// A principal relation as the LaBRADOR prover and verifier use it.
pub(crate) trait PrincipalRelation {
    /// The length of every witness block, in polynomials.
    fn blocks(&self) -> &[usize];

    /// `β²`, the bound on the squared norm of the whole witness.
    fn norm_bound_squared(&self) -> &Wide;

    /// The number of full constraints.
    fn full_constraints(&self) -> usize;

    /// `f_k(s)` for every full constraint, in order; all vanish exactly when `s` satisfies them.
    fn residuals(&self, witness: &PolyVec, ring: &Ring) -> Result<Vec<Poly>>;

    /// `Σ_k w_k·f_k` for one weight per full constraint.
    fn combine(&self, weights: &[Poly], ring: &Ring) -> Result<Combination>;

    /// Whether the constant coefficient of every constant-coefficient constraint vanishes.
    fn constants_vanish(&self, witness: &PolyVec, ring: &Ring) -> Result<bool>;

    /// `Σ_l ψ_l·f'_l` with every `ψ_l ∈ Z_q` drawn from `sampler`, or `None` when the relation
    /// has no constant-coefficient constraints.
    fn combine_constants(
        &self,
        sampler: &mut UniformSampler,
        ring: &Ring,
    ) -> Result<Option<Combination>>;
}

/// The quadratic term `weight·⟨B_left, B_right⟩` of a constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Quadratic {
    /// The first block.
    pub(crate) left: usize,
    /// The second block, of the same length.
    pub(crate) right: usize,
    /// The coefficient.
    pub(crate) weight: Poly,
}

/// One constraint `Σ a·⟨B_a, B_b⟩ + ⟨φ, s⟩ − b`, typically a random combination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Combination {
    /// The quadratic terms.
    pub(crate) quadratic: Vec<Quadratic>,
    /// `φ`, one entry per polynomial of the flattened witness.
    pub(crate) linear: Vec<Poly>,
    /// `b`.
    pub(crate) constant: Poly,
}

impl Combination {
    /// The zero constraint over a witness of `len` polynomials.
    pub(crate) fn zero(len: usize, ring: &Ring) -> Self {
        Self {
            quadratic: Vec::new(),
            linear: vec![Poly::zero(ring); len],
            constant: Poly::zero(ring),
        }
    }

    /// Adds `coefficients` to `φ` from position `start` on.
    pub(crate) fn add_linear(
        &mut self,
        start: usize,
        coefficients: &[Poly],
        ring: &Ring,
    ) -> Result<()> {
        let end = start + coefficients.len();
        let len = self.linear.len();
        let slots = self
            .linear
            .get_mut(start..end)
            .ok_or(Error::DimensionMismatch {
                expected: end,
                found: len,
            })?;
        for (slot, c) in slots.iter_mut().zip(coefficients) {
            *slot = slot.add(c, ring)?;
        }
        Ok(())
    }

    /// `self += other`.
    pub(crate) fn add_assign(&mut self, other: &Self, ring: &Ring) -> Result<()> {
        self.add_linear(0, &other.linear, ring)?;
        self.quadratic.extend(other.quadratic.iter().cloned());
        self.constant = self.constant.add(&other.constant, ring)?;
        Ok(())
    }

    /// `self += weight·other`.
    pub(crate) fn add_scaled(&mut self, other: &Self, weight: &Poly, ring: &Ring) -> Result<()> {
        let weight_ntt = ring.ntt(weight)?;
        let times =
            |p: &Poly| -> Result<Poly> { Ok(ring.sum_of_products([(&weight_ntt, &ring.ntt(p)?)])) };
        let scaled = other.linear.iter().map(times).collect::<Result<Vec<_>>>()?;
        self.add_linear(0, &scaled, ring)?;
        for term in &other.quadratic {
            self.quadratic.push(Quadratic {
                left: term.left,
                right: term.right,
                weight: times(&term.weight)?,
            });
        }
        self.constant = self.constant.add(&times(&other.constant)?, ring)?;
        Ok(())
    }

    /// `f(s)` for the witness `s` given transformed, laid out in `blocks`.
    pub(crate) fn evaluate(
        &self,
        blocks: &[usize],
        witness: &[NttPoly],
        ring: &Ring,
    ) -> Result<Poly> {
        let linear = inner(&transform(&self.linear, ring)?, witness, ring)?;
        let starts = offsets(blocks);
        let block = |b: usize| -> Result<&[NttPoly]> {
            let (start, len) = (
                *starts.get(b).ok_or(Error::DimensionMismatch {
                    expected: blocks.len(),
                    found: b,
                })?,
                blocks[b],
            );
            witness
                .get(start..start + len)
                .ok_or(Error::DimensionMismatch {
                    expected: start + len,
                    found: witness.len(),
                })
        };
        let mut value = linear.sub(&self.constant, ring)?;
        for term in &self.quadratic {
            let product = inner(block(term.left)?, block(term.right)?, ring)?;
            value = value.add(&term.weight.mul(&product, ring)?, ring)?;
        }
        Ok(value)
    }
}

/// The offset of every block in the flattened witness.
pub(crate) fn offsets(blocks: &[usize]) -> Vec<usize> {
    blocks
        .iter()
        .scan(0, |offset, len| {
            let start = *offset;
            *offset += len;
            Some(start)
        })
        .collect()
}

/// The blocks of `witness` as slices, failing unless their lengths add up to the witness.
pub(crate) fn split<'a>(witness: &'a PolyVec, blocks: &[usize]) -> Result<Vec<&'a [Poly]>> {
    let total: usize = blocks.iter().sum();
    check_dimension(total, witness.len())?;
    let mut rest = witness.as_slice();
    blocks
        .iter()
        .map(|&len| {
            let (head, tail) = rest.split_at_checked(len).ok_or(Error::DimensionMismatch {
                expected: len,
                found: rest.len(),
            })?;
            rest = tail;
            Ok(head)
        })
        .collect()
}

/// Whether `witness` satisfies `relation`: every full constraint, every constant-coefficient
/// constraint, and the norm bound (the three conditions of the relation `R`, Section 5.1).
pub(crate) fn is_satisfied(
    relation: &dyn PrincipalRelation,
    witness: &PolyVec,
    ring: &Ring,
) -> Result<bool> {
    let zero = Poly::zero(ring);
    Ok(relation
        .residuals(witness, ring)?
        .iter()
        .all(|residual| *residual == zero)
        && relation.constants_vanish(witness, ring)?
        && witness.norm_l2_squared(ring) <= *relation.norm_bound_squared())
}
