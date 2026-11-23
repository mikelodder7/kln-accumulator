// SPDX-License-Identifier: MIT OR Apache-2.0
//! Homomorphic evaluation of indicator functions on matrices: `EvalF` and `EvalFx` of
//! Theorem 2.2 for `1_y`, in the closed form of Corollary 2.2.1.
//!
//! For `B = [B_0 | … | B_{ℓ−1}] ∈ R_q^{n×ℓm'}` and the function's own string `y`, let
//! `D_i = B_i` when `y_i = 1` and `D_i = G − B_i` when `y_i = 0`, and run the chain
//! `W_{ℓ−1} = D_{ℓ−1}`, `W_i = D_i·G⁻¹(W_{i+1})`. Then `EvalF(1_y, B) = B_{1y} = W_0`, and
//! `EvalFx(1_y, B, x) = H` stacks the blocks
//!
//! `H_i = (−1)^{1−y_i}·δ_0⋯δ_{i−1}·G⁻¹(W_{i+1})` for `i < ℓ−1` and
//! `H_{ℓ−1} = (−1)^{1−y_{ℓ−1}}·δ_0⋯δ_{ℓ−2}·I_{m'}`, with `δ_j = [x_j = y_j]`.
//!
//! Because `B_i − x_i·G = (−1)^{1−y_i}·(D_i − δ_i·G)`, block `i` contributes
//! `δ_0⋯δ_{i−1}·W_i − δ_0⋯δ_i·W_{i+1}`, and the sum telescopes to
//! `(B − xᵀ⊗G)·H = B_{1y} − 1_y(x)·G` (equation 2.1). Every block after the first bit where `x`
//! and `y` differ is zero, and `‖H‖_∞ ≤ b − 1` (equation 2.2).
//!
//! This is what makes deletion and witness update work in Construction 4.1 (ePrint 2025/1099):
//! deleting `y` adds `B_{1y}·G⁻¹(u)` to the accumulator value, and the holder of `x ≠ y` adds
//! `H·G⁻¹(u)` to the last `ℓm'` coordinates of its witness, which by equation 2.1 keeps
//! `[A | B − xᵀ⊗G]·s_x = c`. The crate uses only the vector forms
//! [`Indicator::eval_f_vec`] and [`Indicator::eval_fx_vec`]; the matrix forms are exposed to
//! check the equations against.
//!
//! The [`Indicator`] documentation checks equation 2.1 in an example.

use crate::{
    error::{Error, Result, check_dimension},
    matrix::{NttMatrix, PolyMatrix, Shape},
    params::Params,
    vector::PolyVec,
};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A bit string `x ∈ {0, 1}^ℓ`; entry `i` is the bit `x_i` of Corollary 2.2.1.
///
/// **Public**, as the element it is made from ([`crate::Element::to_bits`]); like that element
/// it is overwritten when dropped, since in a membership proof the element is the prover's
/// hidden input.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Element, Params};
/// use kln_accumulator::lattice::BitString;
///
/// let params = Params::toy()?;
/// let element = Element::try_from(&[0b0000_0101u8][..])?;
/// let bits: BitString = element.to_bits(&params)?;
/// assert_eq!(bits.as_slice(), &[true, false, true, false, false, false, false, false]);
/// assert_eq!(BitString::from(vec![true, false]).as_slice(), &[true, false]);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, derive_more::From)]
pub struct BitString(Vec<bool>);

/// Prints the number of bits, not the bits.
impl fmt::Debug for BitString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitString")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Overwrites the bits.
impl Zeroize for BitString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for BitString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for BitString {}

impl BitString {
    /// The bits, `x_0` first; see the type's example.
    #[must_use]
    pub fn as_slice(&self) -> &[bool] {
        &self.0
    }
}

/// The indicator function `1_y` evaluated homomorphically on `B ∈ R_q^{n×ℓm'}` (Theorem 2.2,
/// Corollary 2.2.1). **Public**: it borrows a public `B` and a bit string.
///
/// For `B = [B_0 | … | B_{ℓ−1}]` let `D_i = B_i` when `y_i = 1` and `D_i = G − B_i` when
/// `y_i = 0`, and run the chain `W_{ℓ−1} = D_{ℓ−1}`, `W_i = D_i·G⁻¹(W_{i+1})`. Then
/// `EvalF(1_y, B) = B_{1y} = W_0`, and `EvalFx(1_y, B, x) = H` stacks the blocks
/// `H_i = (−1)^{1−y_i}·δ_0⋯δ_{i−1}·G⁻¹(W_{i+1})` for `i < ℓ−1` and
/// `H_{ℓ−1} = (−1)^{1−y_{ℓ−1}}·δ_0⋯δ_{ℓ−2}·I_{m'}`, with `δ_j = [x_j = y_j]`. Every block after
/// the first bit where `x` and `y` differ is zero, and `‖H‖_∞ ≤ b − 1` (equation 2.2).
///
/// # Equation 2.1
///
/// `(B − xᵀ⊗G)·H = B_{1y} − 1_y(x)·G`, checked for one `x ≠ y` and for `x = y`:
///
/// ```
/// use kln_accumulator::{Error, Params};
/// use kln_accumulator::lattice::{
///     BitString, DomainLabel, Indicator, PolyMatrix, Seed, Shape, UniformSampler,
/// };
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let (n, m_prime) = (params.spec().n, params.m_prime());
/// let ell = params.spec().element_bits as usize;
/// let b = UniformSampler::new(&Seed::from([8; 32]), DomainLabel::from(&b"B"[..]))
///     .matrix(Shape { rows: n, cols: ell * m_prime }, ring);
/// let bits = |s: &str| BitString::from(s.chars().map(|c| c == '1').collect::<Vec<_>>());
/// let (y, x) = (bits("10110010"), bits("10110011")); // they differ in the last bit
///
/// // [B₀ − x₀·G | … | B_{ℓ−1} − x_{ℓ−1}·G]
/// let g = PolyMatrix::from(params.gadget());
/// let shifted = |x: &BitString| -> Result<PolyMatrix, Error> {
///     let mut entries = Vec::new();
///     for row in 0..n {
///         for (i, &bit) in x.as_slice().iter().enumerate() {
///             for col in 0..m_prime {
///                 let entry = b.get(row, i * m_prime + col).ok_or(Error::InvalidElement)?;
///                 let g_entry = g.get(row, col).ok_or(Error::InvalidElement)?;
///                 entries.push(if bit { entry.sub(g_entry, ring)? } else { entry.clone() });
///             }
///         }
///     }
///     PolyMatrix::new(Shape { rows: n, cols: ell * m_prime }, entries)
/// };
///
/// let indicator = Indicator::new(&params, &y, &b)?;
/// let b_1y = indicator.eval_f()?;
/// // Equation 2.1 for x ≠ y: (B − xᵀ⊗G)·H = B_{1y}.
/// assert_eq!(shifted(&x)?.mul(&indicator.eval_fx(&x)?, ring)?, b_1y);
/// // And for x = y: (B − yᵀ⊗G)·H = B_{1y} − G.
/// assert_eq!(shifted(&y)?.mul(&indicator.eval_fx(&y)?, ring)?, b_1y.sub(&g, ring)?);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
///
/// # Cost
///
/// Every method walks the chain `W_i = D_i·G⁻¹(W_{i+1})` once: `ℓ − 1` gadget decompositions
/// of an `n × m'` matrix and `ℓ − 2` products of `n × m'` by `m' × m'` matrices.
/// [`Indicator::eval_fx_vec`] adds `ℓ − 1` products of an `m' × m'` matrix with a vector, all of
/// them whatever `x`.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{BitString, DomainLabel, Indicator, Seed, Shape, UniformSampler};
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let ell = params.spec().element_bits as usize;
/// let mut sampler = UniformSampler::new(&Seed::from([9; 32]), DomainLabel::from(&b"i"[..]));
/// let b = sampler.matrix(Shape { rows: params.spec().n, cols: ell * params.m_prime() }, ring);
/// let u = sampler.vector(params.spec().n, ring);
/// let y = BitString::from(vec![false; ell]);
/// let x = BitString::from(vec![true; ell]);
/// let indicator = Indicator::new(&params, &y, &b)?;
/// // The vector forms equal the matrix forms applied to G⁻¹(u).
/// let digits = params.gadget().inverse_vec(&u)?;
/// assert_eq!(indicator.eval_f_vec(&u)?, indicator.eval_f()?.mul_vec(&digits, ring)?);
/// assert_eq!(indicator.eval_fx_vec(&x, &u)?, indicator.eval_fx(&x)?.mul_vec(&digits, ring)?);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub struct Indicator<'a> {
    params: &'a Params,
    y: &'a BitString,
    b: &'a PolyMatrix,
}

/// Prints the parameter set, not `y` or `B`.
impl fmt::Debug for Indicator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Indicator")
            .field("params", self.params.spec())
            .finish_non_exhaustive()
    }
}

impl<'a> Indicator<'a> {
    /// The evaluator of `1_y` on `B`; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `y` has `ℓ` bits and `B` is `n × ℓm'`.
    pub fn new(params: &'a Params, y: &'a BitString, b: &'a PolyMatrix) -> Result<Self> {
        let expected = Shape {
            rows: params.spec().n,
            cols: params.extension_len(),
        };
        if b.shape() != expected {
            return Err(Error::DimensionMismatch {
                expected: expected.saturating_len(),
                found: b.shape().saturating_len(),
            });
        }
        let indicator = Self { params, y, b };
        indicator.check_bits(y)?;
        Ok(indicator)
    }

    /// `EvalF(1_y, B) = B_{1y} ∈ R_q^{n×m'}`; see the type's documentation.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when an entry of `B` does not have degree `d`.
    pub fn eval_f(&self) -> Result<PolyMatrix> {
        let ring = self.params.ring();
        let mut first = None;
        self.walk(|i, _, transformed| {
            if i == 0 {
                first = Some(transformed.left_mul(&self.d(0)?, ring)?);
            }
            Ok(())
        })?;
        first.map_or_else(|| self.d(0), Ok)
    }

    /// `EvalFx(1_y, B, x) = H ∈ R^{ℓm'×m'}`, as residues of integers in `[−(b−1), b−1]`; see
    /// the type's documentation and its equation 2.1 example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `x` has `ℓ` bits and every entry of `B` has
    /// degree `d`.
    pub fn eval_fx(&self, x: &BitString) -> Result<PolyMatrix> {
        self.check_bits(x)?;
        let ring = self.params.ring();
        let size = self.params.m_prime();
        let last = self.y.0.len() - 1;
        let zero = PolyMatrix::zero(
            Shape {
                rows: size,
                cols: size,
            },
            ring,
        );
        let mut blocks = vec![zero; last + 1];
        blocks[last] = PolyMatrix::identity(size, ring)
            .mul_small(self.sign(last), ring)?
            .mul_small(self.agree(x, last), ring)?;
        self.walk(|i, digits, _| {
            blocks[i] = digits
                .mul_small(self.sign(i), ring)?
                .mul_small(self.agree(x, i), ring)?;
            Ok(())
        })?;
        PolyMatrix::vstack(blocks)
    }

    /// `B_{1y}·G⁻¹(u) ∈ R_q^n` for `u ∈ R_q^n` (Construction 4.1, Delete step 3), without
    /// forming `B_{1y}`; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `u` has `n` entries and every entry has degree `d`.
    pub fn eval_f_vec(&self, u: &PolyVec) -> Result<PolyVec> {
        let ring = self.params.ring();
        let digits_u = self.params.gadget().inverse_vec(u)?;
        let mut first = None;
        self.walk(|i, _, transformed| {
            if i == 0 {
                first = Some(transformed.mul_vec(&digits_u, ring)?);
            }
            Ok(())
        })?;
        self.d(0)?
            .mul_vec(first.as_ref().unwrap_or(&digits_u), ring)
    }

    /// `H·G⁻¹(u) ∈ R^{ℓm'}` for `H = EvalFx(1_y, B, x)` and `u ∈ R_q^n` (Construction 4.1,
    /// MemWitUp), without forming `H`. Blocks after the first differing bit are zero, and their
    /// products are computed all the same and then multiplied by zero: `x` is the holder's
    /// element, `y` is public, and skipping them would let the time taken show how long a
    /// prefix the two share. The result is the residue of an integer vector with coefficients
    /// at most `(b−1)²·d·m'` in magnitude. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `x` has `ℓ` bits, `u` has `n` entries, and every
    /// entry has degree `d`.
    pub fn eval_fx_vec(&self, x: &BitString, u: &PolyVec) -> Result<PolyVec> {
        self.check_bits(x)?;
        let ring = self.params.ring();
        let digits_u = self.params.gadget().inverse_vec(u)?;
        let last = self.y.0.len() - 1;
        let mut blocks = vec![PolyVec::zero(self.params.m_prime(), ring); last + 1];
        blocks[last] = digits_u
            .mul_small(self.sign(last), ring)?
            .mul_small(self.agree(x, last), ring)?;
        self.walk(|i, _, transformed| {
            blocks[i] = transformed
                .mul_vec(&digits_u, ring)?
                .mul_small(self.sign(i), ring)?
                .mul_small(self.agree(x, i), ring)?;
            Ok(())
        })?;
        Ok(blocks.into_iter().flat_map(Vec::from).collect())
    }

    /// Runs the chain from the last block down, calling `visit(i, D, D̂)` for
    /// `i = ℓ−2, …, 0`, where `D = G⁻¹(W_{i+1})` and `D̂` is its transform. `W_0` itself is never
    /// formed.
    fn walk(
        &self,
        mut visit: impl FnMut(usize, &PolyMatrix, &NttMatrix) -> Result<()>,
    ) -> Result<()> {
        let ring = self.params.ring();
        let gadget = self.params.gadget();
        let last = self.y.0.len() - 1;
        let mut w = self.d(last)?;
        for i in (0..last).rev() {
            let digits = gadget.inverse_matrix(&w)?;
            // One transform of the digit matrix serves the visit and the next step.
            let transformed = NttMatrix::new(&digits, ring)?;
            visit(i, &digits, &transformed)?;
            if i > 0 {
                w = transformed.left_mul(&self.d(i)?, ring)?;
            }
        }
        Ok(())
    }

    /// `D_i = B_i` when `y_i = 1`, else `G − B_i`.
    fn d(&self, i: usize) -> Result<PolyMatrix> {
        let width = self.params.m_prime();
        let block = self.b.column_block(i * width, width)?;
        if self.y.0[i] {
            Ok(block)
        } else {
            PolyMatrix::from(self.params.gadget()).sub(&block, self.params.ring())
        }
    }

    /// `(−1)^{1−y_i}`, the sign of block `i`; a function of the public `y` alone.
    fn sign(&self, i: usize) -> i64 {
        if self.y.0[i] { 1 } else { -1 }
    }

    /// 1 when `x` and `y` agree on every bit before `i`, else 0 (the block is zero). Every bit
    /// before `i` is read whatever the outcome, and the result is used as a multiplier, never as
    /// a condition.
    fn agree(&self, x: &BitString, i: usize) -> i64 {
        x.0[..i]
            .iter()
            .zip(&self.y.0[..i])
            .fold(1, |all, (a, b)| all & i64::from(a == b))
    }

    fn check_bits(&self, bits: &BitString) -> Result<()> {
        check_dimension(self.params.spec().element_bits as usize, bits.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::{BitString, Indicator};
    use crate::{
        error::Error,
        matrix::{PolyMatrix, Shape},
        params::Params,
        test_util::{TOY, arb_matrix, arb_vec},
        vector::PolyVec,
        zq::Coeff,
    };
    use proptest::prelude::*;

    const ELL: usize = 8;
    const B_SHAPE: Shape = Shape {
        rows: 1,
        cols: ELL * 10,
    };

    /// `B − xᵀ⊗G`: `G` subtracted from every block `i` with `x_i = 1`.
    fn shifted(b: &PolyMatrix, x: &BitString, params: &Params) -> PolyMatrix {
        let ring = params.ring();
        let width = params.m_prime();
        let g = PolyMatrix::from(params.gadget());
        x.as_slice()
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                let block = b.column_block(i * width, width).unwrap();
                if bit {
                    block.sub(&g, ring).unwrap()
                } else {
                    block
                }
            })
            .reduce(|left, right| left.hconcat(&right).unwrap())
            .unwrap()
    }

    fn entries(m: &PolyMatrix) -> Vec<&crate::poly::Poly> {
        let shape = m.shape();
        (0..shape.rows)
            .flat_map(|r| (0..shape.cols).map(move |c| (r, c)))
            .map(|(r, c)| m.get(r, c).unwrap())
            .collect()
    }

    /// Checks equation 2.1, the bound 2.2, the zero blocks after the first mismatch, and that
    /// the vector forms equal the matrix forms applied to `G⁻¹(u)`.
    fn check(b: &PolyMatrix, x: &BitString, y: &BitString, u: &PolyVec) {
        let params = &*TOY;
        let ring = params.ring();
        let indicator = Indicator::new(params, y, b).unwrap();
        let b_1y = indicator.eval_f().unwrap();
        let h = indicator.eval_fx(x).unwrap();
        assert_eq!(b_1y.shape(), Shape { rows: 1, cols: 10 });
        assert_eq!(h.shape(), Shape { rows: 80, cols: 10 });
        let left = shifted(b, x, params).mul(&h, ring).unwrap();
        let right = if x == y {
            b_1y.sub(&PolyMatrix::from(params.gadget()), ring).unwrap()
        } else {
            b_1y.clone()
        };
        assert_eq!(left, right);
        let bound = Coeff::from_u32(params.gadget().base() - 1);
        assert!(entries(&h).iter().all(|p| p.norm_inf(ring) <= bound));
        let first_mismatch = (0..ELL).find(|&i| x.as_slice()[i] != y.as_slice()[i]);
        if let Some(k) = first_mismatch {
            let zero = crate::poly::Poly::zero(ring);
            assert!(entries(&h)[(k + 1) * 100..].iter().all(|p| **p == zero));
        }
        let digits = params.gadget().inverse_vec(u).unwrap();
        assert_eq!(
            indicator.eval_f_vec(u).unwrap(),
            b_1y.mul_vec(&digits, ring).unwrap()
        );
        let h_u = indicator.eval_fx_vec(x, u).unwrap();
        assert_eq!(h_u, h.mul_vec(&digits, ring).unwrap());
        // H·G⁻¹(u) is short: at most (b−1)²·d·m' per coefficient.
        let short = Coeff::from_u64(63 * 63 * 64 * 10);
        assert!(h_u.norm_inf(ring) <= short);
    }

    fn arb_bits() -> impl Strategy<Value = BitString> {
        prop::collection::vec(any::<bool>(), ELL).prop_map(BitString::from)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// C15 with independent random `x` and `y` (almost always different).
        #[test]
        fn indicator_identity_random(
            b in arb_matrix(&TOY, B_SHAPE),
            x in arb_bits(),
            y in arb_bits(),
            u in arb_vec(&TOY, 1),
        ) {
            check(&b, &x, &y, &u);
        }

        /// C15 with `x = y`, where `1_y(x) = 1`.
        #[test]
        fn indicator_identity_equal(
            b in arb_matrix(&TOY, B_SHAPE),
            y in arb_bits(),
            u in arb_vec(&TOY, 1),
        ) {
            check(&b, &y, &y, &u);
        }

        /// C15 with `x` and `y` differing in exactly one chosen bit, so every mismatch position
        /// (including the last) is exercised.
        #[test]
        fn indicator_identity_one_flip(
            b in arb_matrix(&TOY, B_SHAPE),
            y in arb_bits(),
            flip in 0..ELL,
            u in arb_vec(&TOY, 1),
        ) {
            let mut bits = y.as_slice().to_vec();
            bits[flip] = !bits[flip];
            check(&b, &BitString::from(bits), &y, &u);
        }
    }

    #[test]
    fn dimension_errors() {
        let params = &*TOY;
        let ring = params.ring();
        let b = PolyMatrix::zero(B_SHAPE, ring);
        let y = BitString::from(vec![true; ELL]);
        let short = BitString::from(vec![true; ELL - 1]);
        let mismatch = |expected, found| Error::DimensionMismatch { expected, found };
        assert_eq!(
            Indicator::new(params, &short, &b).err(),
            Some(mismatch(8, 7))
        );
        let narrow = PolyMatrix::zero(Shape { rows: 1, cols: 70 }, ring);
        assert_eq!(
            Indicator::new(params, &y, &narrow).err(),
            Some(mismatch(80, 70))
        );
        let indicator = Indicator::new(params, &y, &b).unwrap();
        assert_eq!(indicator.eval_fx(&short).err(), Some(mismatch(8, 7)));
        let u = PolyVec::zero(1, ring);
        assert_eq!(
            indicator.eval_fx_vec(&short, &u).err(),
            Some(mismatch(8, 7))
        );
        assert!(indicator.eval_f_vec(&PolyVec::zero(2, ring)).is_err());
    }
}
