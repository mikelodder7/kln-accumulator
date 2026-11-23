// SPDX-License-Identifier: MIT OR Apache-2.0
//! The gadget matrix `G = I_n ⊗ (1, b, …, b^{k−1})` and its decomposition `G⁻¹` (ePrint
//! 2025/1099, Section 2.1).
//!
//! `G` is what makes the trapdoor work (`A·[T_A; I] = G`, Theorem 2.1) and what the indicator
//! evaluation of Corollary 2.2.1 decomposes through; `B_{1y}·G⁻¹(u)` is what a deletion adds to
//! the accumulator. A set's gadget is [`crate::Params::gadget`].
//!
//! ```
//! use kln_accumulator::Params;
//! use kln_accumulator::lattice::{DomainLabel, Seed, UniformSampler};
//!
//! let params = Params::toy()?;
//! let gadget = params.gadget();
//! let u = UniformSampler::new(&Seed::from([6; 32]), DomainLabel::from(&b"g"[..]))
//!     .vector(params.spec().n, params.ring());
//! let digits = gadget.inverse_vec(&u)?;
//! assert_eq!(digits.len(), params.m_prime());
//! // Every digit is below b, and recomposing gives u back.
//! let b = kln_accumulator::lattice::Coeff::from_u32(gadget.base());
//! assert!(digits.as_slice().iter().flat_map(|p| p.coefficients()).all(|c| *c < b));
//! assert_eq!(gadget.mul_vec(&digits)?, u);
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

use crate::{
    error::{Error, Result, check_dimension},
    matrix::{PolyMatrix, Shape},
    poly::Poly,
    ring::Ring,
    vector::PolyVec,
    zq::{Coeff, Zq},
};
use core::num::NonZeroU32;
use crypto_bigint::{Limb, NonZero};

/// The gadget matrix `G = I_n ⊗ g` with `g = (1, b, …, b^{k−1})` and `k = ⌈log_b q⌉`, so
/// `G ∈ R_q^{n × nk}`, and its base-`b` decomposition `G⁻¹`, which maps `u ∈ R_q^n` to the
/// unique `G⁻¹(u) ∈ R_q^{nk}` with coefficients in `[0, b)` and `G · G⁻¹(u) = u`.
///
/// Products with `G` are computed directly from the digit weights; `From<&Gadget> for PolyMatrix`
/// materialises `G` only for callers that need it as a matrix. **Public.**
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{PolyMatrix, Shape};
///
/// let params = Params::toy()?;
/// let gadget = params.gadget();
/// assert_eq!(gadget.base(), 64);
/// assert_eq!(gadget.digits(), 10); // ⌈log₆₄ q⌉ for the 60-bit toy modulus
/// assert_eq!(gadget.shape(), Shape { rows: 1, cols: 10 });
/// // G·M equals the explicit matrix times M.
/// let g = PolyMatrix::from(gadget);
/// let digits = gadget.inverse_matrix(&g)?;
/// assert_eq!(gadget.mul_matrix(&digits)?, g);
/// assert_eq!(g.mul(&digits, params.ring())?, g);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gadget {
    zq: Zq,
    degree: usize,
    rank: usize,
    base: u32,
    base_limb: NonZero<Limb>,
    /// `b^j mod q` in Montgomery form, for `j ∈ [0, k)`.
    weights: Vec<Coeff>,
    /// The width `m' = n·k`, computed once with checked arithmetic.
    cols: usize,
}

/// The powers `1, b, b², …` below `modulus`: `k = ⌈log_b q⌉` of them, since `k` is the least `k`
/// with `b^k ≥ q`; an overflow of `b^k` past 2^192 also means `b^k > q`. Needs no ring, so a
/// set's gadget width can be checked before any table is built.
///
/// Fails with [`Error::BaseTooSmall`] for `b < 2`, whose powers never reach `q`.
pub(crate) fn powers(modulus: &Coeff, base: u32) -> Result<impl Iterator<Item = Coeff> + '_> {
    if base < 2 {
        return Err(Error::BaseTooSmall(base));
    }
    let wide_base = Coeff::from_u32(base);
    Ok(core::iter::successors(Some(Coeff::ONE), move |p| {
        p.checked_mul(&wide_base).into_option()
    })
    .take_while(move |p| p < modulus))
}

impl Gadget {
    /// Builds `G` for rank `n` and base `b` over `ring`. Fails with
    /// [`Error::WitnessBoundTooLarge`] when `n·k` overflows.
    pub(crate) fn new(ring: &Ring, rank: usize, base: u32) -> Result<Self> {
        let powers = powers(ring.modulus(), base)?;
        if rank == 0 {
            return Err(Error::ZeroRank);
        }
        let base_limb = NonZeroU32::new(base)
            .map(NonZero::<Limb>::from_u32)
            .ok_or(Error::BaseTooSmall(base))?;
        let zq = *ring.zq();
        let weights: Vec<Coeff> = powers.map(|p| zq.montgomery(&p)).collect();
        let cols = rank
            .checked_mul(weights.len())
            .ok_or(Error::WitnessBoundTooLarge)?;
        Ok(Self {
            zq,
            degree: ring.degree(),
            rank,
            base,
            base_limb,
            weights,
            cols,
        })
    }

    /// The base `b`; see the type's example.
    #[must_use]
    pub fn base(&self) -> u32 {
        self.base
    }

    /// The number of digits `k = ⌈log_b q⌉`; see the type's example.
    #[must_use]
    pub fn digits(&self) -> usize {
        self.weights.len()
    }

    /// The shape of `G`, `n × nk`; see the type's example.
    #[must_use]
    pub fn shape(&self) -> Shape {
        Shape {
            rows: self.rank,
            cols: self.cols,
        }
    }

    /// `G⁻¹(u)` for `u ∈ R_q^n`: entry `i·k + j` holds digit `j` of every coefficient of `u_i`.
    /// See the example in the book's chapter "The lattice building blocks".
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `u` has `n` entries of degree `d`.
    pub fn inverse_vec(&self, u: &PolyVec) -> Result<PolyVec> {
        check_dimension(self.rank, u.len())?;
        Ok(u.as_slice()
            .iter()
            .map(|p| self.decompose(p))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect())
    }

    /// `G⁻¹(M)` for `M ∈ R_q^{n × c}`, decomposing column by column into `R_q^{nk × c}`. See
    /// the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `M` has `n` rows of entries of degree `d`.
    pub fn inverse_matrix(&self, m: &PolyMatrix) -> Result<PolyMatrix> {
        let shape = m.shape();
        check_dimension(self.rank, shape.rows)?;
        let digits = self.digits();
        let mut entries = Vec::with_capacity(shape.rows * digits * shape.cols);
        for i in 0..shape.rows {
            // One digit stream per column of row i; output row i·k + j takes digit j of each.
            let mut columns = (0..shape.cols)
                .map(|c| Ok(self.decompose(self.entry(m, i, c)?)?.into_iter()))
                .collect::<Result<Vec<_>>>()?;
            for _ in 0..digits {
                entries.extend(columns.iter_mut().filter_map(Iterator::next));
            }
        }
        Ok(PolyMatrix::from_parts(
            Shape {
                rows: shape.rows * digits,
                cols: shape.cols,
            },
            entries,
        ))
    }

    /// `G · v` for `v ∈ R_q^{nk}`, without materialising `G`; see the example in the book's
    /// chapter "The lattice building blocks".
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `v` has `nk` entries of degree `d`.
    pub fn mul_vec(&self, v: &PolyVec) -> Result<PolyVec> {
        check_dimension(self.cols, v.len())?;
        v.as_slice()
            .chunks_exact(self.digits())
            .map(|block| self.recompose(block.iter()))
            .collect()
    }

    /// `G · M` for `M ∈ R_q^{nk × c}`, without materialising `G`; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `M` has `nk` rows of entries of degree `d`.
    pub fn mul_matrix(&self, m: &PolyMatrix) -> Result<PolyMatrix> {
        let shape = m.shape();
        check_dimension(self.cols, shape.rows)?;
        let digits = self.digits();
        let entries = (0..self.rank)
            .flat_map(|i| (0..shape.cols).map(move |c| (i, c)))
            .map(|(i, c)| {
                let column = (0..digits)
                    .map(|j| self.entry(m, i * digits + j, c))
                    .collect::<Result<Vec<_>>>()?;
                self.recompose(column.into_iter())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PolyMatrix::from_parts(
            Shape {
                rows: self.rank,
                cols: shape.cols,
            },
            entries,
        ))
    }

    /// The `k` base-`b` digit polynomials of `p`, least significant first.
    fn decompose(&self, p: &Poly) -> Result<Vec<Poly>> {
        check_dimension(self.degree, p.coefficients().len())?;
        let mut digits = vec![vec![Coeff::ZERO; self.degree]; self.digits()];
        // A power-of-two base takes each digit with a mask and a shift by a public amount; any
        // other base divides. The branch is on the base alone, never on the coefficient.
        let shift = self
            .base
            .is_power_of_two()
            .then(|| self.base.trailing_zeros());
        let mask = u64::from(self.base).wrapping_sub(1);
        for (t, coefficient) in p.coefficients().iter().enumerate() {
            let mut rest = *coefficient;
            for digit in &mut digits {
                if let Some(bits) = shift {
                    digit[t] = Coeff::from_u64(rest.as_words()[0] & mask);
                    rest = rest.wrapping_shr_vartime(bits);
                } else {
                    let (quotient, remainder) = rest.div_rem_limb(self.base_limb);
                    digit[t] = Coeff::from(remainder);
                    rest = quotient;
                }
            }
        }
        Ok(digits.into_iter().map(Poly::from_reduced).collect())
    }

    /// `Σ_j b^j · p_j` over the `k` polynomials of one gadget block.
    fn recompose<'a>(&self, block: impl Iterator<Item = &'a Poly>) -> Result<Poly> {
        let mut acc = vec![Coeff::ZERO; self.degree];
        for (p, weight) in block.zip(&self.weights) {
            check_dimension(self.degree, p.coefficients().len())?;
            for (out, c) in acc.iter_mut().zip(p.coefficients()) {
                *out = self.zq.add(out, &self.zq.mont_mul(weight, c));
            }
        }
        Ok(Poly::from_reduced(acc))
    }

    fn entry<'a>(&self, m: &'a PolyMatrix, row: usize, col: usize) -> Result<&'a Poly> {
        m.get(row, col).ok_or(Error::DimensionMismatch {
            expected: m.shape().rows,
            found: row,
        })
    }
}

/// `G` as an explicit `n × nk` matrix of constant polynomials; see [`Gadget`]'s example.
impl From<&Gadget> for PolyMatrix {
    fn from(value: &Gadget) -> Self {
        let shape = value.shape();
        let entries = (0..shape.rows)
            .flat_map(|i| (0..shape.cols).map(move |c| (i, c)))
            .map(|(i, c)| {
                let mut coefficients = vec![Coeff::ZERO; value.degree];
                if c / value.digits() == i {
                    coefficients[0] = value
                        .zq
                        .mont_mul(&value.weights[c % value.digits()], &Coeff::ONE);
                }
                Poly::from_reduced(coefficients)
            })
            .collect();
        PolyMatrix::from_parts(shape, entries)
    }
}

#[cfg(test)]
mod tests {
    use super::Gadget;
    use crate::{
        error::Error,
        matrix::{PolyMatrix, Shape},
        params::{Params, ParamsSpec},
        poly::Poly,
        ring::Ring,
        test_util::{PAPER, TOY, arb_matrix, arb_vec},
        vector::PolyVec,
        zq::Coeff,
    };
    use proptest::prelude::*;
    use std::sync::LazyLock;

    /// The toy set at rank 2, so that the `I_n ⊗ g` block structure is exercised. `m = 40`
    /// keeps `m − m' = 20`, so that Theorem 2.1's trapdoor width stays small.
    static RANK_TWO: LazyLock<Params> = LazyLock::new(|| {
        Params::try_from(ParamsSpec {
            n: 2,
            m: 40,
            ..ParamsSpec::TOY
        })
        .unwrap()
    });

    fn digits_below_base(v: &[Poly], base: u32) -> bool {
        v.iter()
            .flat_map(Poly::coefficients)
            .all(|c| *c < Coeff::from_u32(base))
    }

    #[test]
    fn shape_base_and_digits() {
        let toy = TOY.gadget();
        assert_eq!(toy.base(), 64);
        assert_eq!(toy.digits(), 10);
        assert_eq!(toy.shape(), Shape { rows: 1, cols: 10 });
        assert_eq!(PAPER.gadget().base(), 1024);
        assert_eq!(PAPER.gadget().digits(), 10);
        assert_eq!(RANK_TWO.gadget().shape(), Shape { rows: 2, cols: 20 });
    }

    #[test]
    fn digit_count_is_ceil_log_base_q() {
        // q = 269, a prime ≡ 5 (mod 8), needs nine bits, so k = ⌈log₂ 269⌉ = 9 and
        // ⌈log₁₆ 269⌉ = 3. The ring is built directly: q is far too small for any witness bound.
        let ring = Ring::new(128, Coeff::from_u64(269)).unwrap();
        let digits = |base| Gadget::new(&ring, 1, base).unwrap().digits();
        assert_eq!(digits(2), 9);
        assert_eq!(digits(16), 3);
        // b ≥ q leaves a single digit.
        assert_eq!(digits(1 << 20), 1);
    }

    #[test]
    fn to_matrix_is_identity_kron_powers() {
        let ring = RANK_TWO.ring();
        let g = PolyMatrix::from(RANK_TWO.gadget());
        assert_eq!(g.shape(), Shape { rows: 2, cols: 20 });
        for (i, c) in (0..2).flat_map(|i| (0..20).map(move |c| (i, c))) {
            let entry = g.get(i, c).unwrap();
            let expected = if c / 10 == i {
                1u64 << (6 * (c % 10))
            } else {
                0
            };
            assert_eq!(entry.coefficients()[0], Coeff::from_u64(expected));
            assert!(entry.coefficients()[1..].iter().all(|x| *x == Coeff::ZERO));
            assert!(entry.validate(ring).is_ok());
        }
    }

    #[test]
    fn dimension_errors() {
        let gadget = TOY.gadget();
        let ring = TOY.ring();
        let wrong = Error::DimensionMismatch {
            expected: 1,
            found: 2,
        };
        assert_eq!(gadget.inverse_vec(&PolyVec::zero(2, ring)), Err(wrong));
        assert_eq!(
            gadget.inverse_matrix(&PolyMatrix::zero(Shape { rows: 2, cols: 1 }, ring)),
            Err(wrong)
        );
        assert!(gadget.mul_vec(&PolyVec::zero(9, ring)).is_err());
        assert!(
            gadget
                .mul_matrix(&PolyMatrix::zero(Shape { rows: 9, cols: 1 }, ring))
                .is_err()
        );
        assert!(gadget.inverse_vec(&PolyVec::zero(1, PAPER.ring())).is_err());
    }

    proptest! {
        #[test]
        fn inverse_vec_roundtrip_rank_two(u in arb_vec(&RANK_TWO, 2)) {
            let gadget = RANK_TWO.gadget();
            let digits = gadget.inverse_vec(&u).unwrap();
            prop_assert_eq!(digits.len(), 20);
            prop_assert!(digits_below_base(digits.as_slice(), gadget.base()));
            prop_assert_eq!(gadget.mul_vec(&digits).unwrap(), u);
        }

        #[test]
        fn inverse_matrix_roundtrip_rank_two(m in arb_matrix(&RANK_TWO, Shape { rows: 2, cols: 3 })) {
            let ring = RANK_TWO.ring();
            let gadget = RANK_TWO.gadget();
            let digits = gadget.inverse_matrix(&m).unwrap();
            prop_assert_eq!(digits.shape(), Shape { rows: 20, cols: 3 });
            let all: Vec<Poly> = (0..20)
                .flat_map(|r| (0..3).map(move |c| (r, c)))
                .map(|(r, c)| digits.get(r, c).unwrap().clone())
                .collect();
            prop_assert!(digits_below_base(&all, gadget.base()));
            prop_assert_eq!(gadget.mul_matrix(&digits).unwrap(), m.clone());
            // The implicit product agrees with the explicit G.
            prop_assert_eq!(PolyMatrix::from(gadget).mul(&digits, ring).unwrap(), m);
        }

        #[test]
        fn mul_vec_matches_explicit_g(v in arb_vec(&RANK_TWO, 20)) {
            let ring = RANK_TWO.ring();
            let gadget = RANK_TWO.gadget();
            prop_assert_eq!(gadget.mul_vec(&v).unwrap(), PolyMatrix::from(gadget).mul_vec(&v, ring).unwrap());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4))]

        #[test]
        fn inverse_roundtrip_paper(m in arb_matrix(&PAPER, Shape { rows: 1, cols: 2 })) {
            let gadget = PAPER.gadget();
            let digits = gadget.inverse_matrix(&m).unwrap();
            let column = PolyVec::from(vec![m.get(0, 0).unwrap().clone()]);
            let vector_digits = gadget.inverse_vec(&column).unwrap();
            prop_assert!(digits_below_base(vector_digits.as_slice(), 1024));
            prop_assert_eq!(gadget.mul_vec(&vector_digits).unwrap(), column);
            prop_assert_eq!(gadget.mul_matrix(&digits).unwrap(), m);
        }
    }
}
