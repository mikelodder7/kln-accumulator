// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rank-`k` module map between the accumulator ring `R = Z_q[X]/(X^d + 1)` and the proof
//! ring `S = Z_q[Y]/(Y^{d_S} + 1)` with `Y = X^k`, `k = d/d_S`: the translation of statements
//! over `Z_q[X]/(X^4096 + 1)` into equivalent ones over `Z_q[X]/(X^64 + 1)` that Section 5.3
//! ("Commit-and-prove sizes") of ePrint 2025/1099 takes from the work it cites titled "Shorter
//! lattice-based group signatures via 'almost free' encryption and other optimizations"
//! (ASIACRYPT 2021).
//!
//! The map is built and tested, but the proof does not use it yet: membership proofs run only
//! where the accumulator ring is the proof ring, degree 64, so [`crate::ProofParams::new`]
//! refuses other degrees with [`Error::UnsupportedProofDegree`].
//!
//! ```
//! use kln_accumulator::{Params, SubringMap};
//! use kln_accumulator::lattice::{DomainLabel, Seed, UniformSampler};
//!
//! let params = Params::paper_128()?;
//! let map = SubringMap::new(params.ring(), 64)?;
//! assert_eq!(map.rank(), 64);
//! assert_eq!(map.small().degree(), 64);
//! let mut sampler = UniformSampler::new(&Seed::from([1; 32]), DomainLabel::from(&b"s"[..]));
//! let a = sampler.poly(params.ring());
//! let parts = map.split(&a)?;
//! assert_eq!(parts.len(), 64);
//! assert_eq!(map.combine(parts.as_slice())?, a);
//! // The map only permutes coefficients, so norms are preserved.
//! assert_eq!(parts.norm_l2_squared(map.small()), a.norm_l2_squared(params.ring()));
//! # Ok::<(), kln_accumulator::Error>(())
//! ```
//!
//! Every `a ∈ R` is uniquely `Σ_{i<k} a_i(Y)·X^i` with `a_i ∈ S`, where coefficient `j` of
//! `a_i` is coefficient `jk + i` of `a`. So `R ≅ S^k` as an `S`-module; the map only permutes
//! coefficients, so it preserves every norm, and the identity `const(a·σ(b)) = ⟨a, b⟩` of the
//! proof layer carries over as `Σ_i const(a_i·σ_S(b_i)) = ⟨a, b⟩`. Multiplication by a fixed
//! `a` is `S`-linear, and since `X^k = Y` its matrix has entry `a_{l−j}` at `(l, j)` for
//! `j ≤ l` and `Y·a_{l−j+k}` above the diagonal. At `d = d_S` the map is the identity.

use crate::{
    error::{Error, Result, check_dimension},
    matrix::{PolyMatrix, Shape},
    poly::Poly,
    ring::Ring,
    vector::PolyVec,
};

/// The map `R → S^k` for `R` of degree `d` and `S` of degree `d_S` with the same modulus, and
/// its inverse, on polynomials, vectors and matrices. **Public**; it moves values without
/// copying them anywhere but the returned value, which wipes itself on drop like every
/// polynomial.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Params, SubringMap};
/// use kln_accumulator::lattice::{DomainLabel, Seed, Shape, UniformSampler};
///
/// let ring = Params::paper_128()?.ring().clone();
/// let map = SubringMap::new(&ring, 1024)?;
/// assert_eq!(map.rank(), 4);
/// let mut sampler = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"m"[..]));
/// let m = sampler.matrix(Shape { rows: 2, cols: 3 }, &ring);
/// let v = sampler.vector(3, &ring);
/// // split(M·v) = split_matrix(M)·split_vector(v), and combine_vector inverts split_vector.
/// let lhs = map.split_vector(&m.mul_vec(&v, &ring)?)?;
/// let rhs = map.split_matrix(&m)?.mul_vec(&map.split_vector(&v)?, map.small())?;
/// assert_eq!(lhs, rhs);
/// assert_eq!(map.combine_vector(&map.split_vector(&v)?)?, v);
/// let block = map.multiplication_block(m.get(0, 0).ok_or(kln_accumulator::Error::InvalidElement)?)?;
/// assert_eq!(block.shape(), Shape { rows: 4, cols: 4 });
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubringMap {
    rank: usize,
    small: Ring,
}

impl SubringMap {
    /// The map from `big` to the ring of degree `small_degree` with the same modulus. Fails with
    /// [`Error::DegreeNotPowerOfTwo`] unless `small_degree` is a power of two, and with
    /// [`Error::DimensionMismatch`] when it exceeds the degree of `big`. See the type's example.
    ///
    /// # Errors
    ///
    /// As above, and as the ring of degree `small_degree` is validated.
    pub fn new(big: &Ring, small_degree: usize) -> Result<Self> {
        let small = Ring::new(small_degree, *big.modulus())?;
        if small_degree > big.degree() {
            return Err(Error::DimensionMismatch {
                expected: big.degree(),
                found: small_degree,
            });
        }
        Ok(Self {
            rank: big.degree() / small_degree,
            small,
        })
    }

    /// The rank `k = d/d_S`; see the type's example.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.rank
    }

    /// The ring `S`; see the type's example.
    #[must_use]
    pub fn small(&self) -> &Ring {
        &self.small
    }

    /// `(a_0, …, a_{k−1}) ∈ S^k` with `a = Σ_i a_i(X^k)·X^i`. Fails with
    /// [`Error::DimensionMismatch`] unless `a` has `k·d_S` coefficients. See the module
    /// example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn split(&self, a: &Poly) -> Result<PolyVec> {
        let (k, d_s) = (self.rank, self.small.degree());
        check_dimension(k * d_s, a.coefficients().len())?;
        let c = a.coefficients();
        Ok((0..k)
            .map(|i| Poly::from_reduced((0..d_s).map(|j| c[j * k + i]).collect()))
            .collect())
    }

    /// The inverse of [`SubringMap::split`]: `Σ_i a_i(X^k)·X^i` from `k` polynomials of degree
    /// `d_S`. Fails with [`Error::DimensionMismatch`] on any other shape. See the module
    /// example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn combine(&self, parts: &[Poly]) -> Result<Poly> {
        let (k, d_s) = (self.rank, self.small.degree());
        check_dimension(k, parts.len())?;
        parts
            .iter()
            .try_for_each(|p| check_dimension(d_s, p.coefficients().len()))?;
        Ok(Poly::from_reduced(
            (0..k * d_s)
                .map(|t| parts[t % k].coefficients()[t / k])
                .collect(),
        ))
    }

    /// [`SubringMap::split`] of every entry, concatenated: entry `e` becomes entries
    /// `ek, …, ek + k − 1`. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless every entry has `k·d_S` coefficients.
    pub fn split_vector(&self, v: &PolyVec) -> Result<PolyVec> {
        let parts = v
            .as_slice()
            .iter()
            .map(|p| self.split(p).map(Vec::from))
            .collect::<Result<Vec<_>>>()?;
        Ok(parts.into_iter().flatten().collect())
    }

    /// The inverse of [`SubringMap::split_vector`]. Fails with [`Error::DimensionMismatch`]
    /// unless the length is a multiple of `k` and every entry has degree `d_S`. See the type's
    /// example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn combine_vector(&self, v: &PolyVec) -> Result<PolyVec> {
        let entries = v.as_slice();
        if !entries.len().is_multiple_of(self.rank) {
            return Err(Error::DimensionMismatch {
                expected: entries.len().next_multiple_of(self.rank),
                found: entries.len(),
            });
        }
        entries
            .chunks_exact(self.rank)
            .map(|parts| self.combine(parts))
            .collect()
    }

    /// The `k × k` matrix over `S` of `b ↦ a·b` in the split coordinates: entry `(l, j)` is
    /// `a_{l−j}` for `j ≤ l` and `Y·a_{l−j+k}` for `j > l`, since `X^i·X^j = Y·X^{i+j−k}` once
    /// `i + j ≥ k`. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `a` has `k·d_S` coefficients.
    pub fn multiplication_block(&self, a: &Poly) -> Result<PolyMatrix> {
        let k = self.rank;
        let parts = Vec::from(self.split(a)?);
        let shifted: Vec<Poly> = parts.iter().map(|p| self.times_y(p)).collect();
        let entries = (0..k)
            .flat_map(|l| (0..k).map(move |j| (l, j)))
            .map(|(l, j)| {
                if j <= l {
                    parts[l - j].clone()
                } else {
                    shifted[l + k - j].clone()
                }
            })
            .collect();
        PolyMatrix::new(Shape { rows: k, cols: k }, entries)
    }

    /// The matrix over `S` of `v ↦ M·v` in the split coordinates of [`SubringMap::split_vector`]:
    /// block `(r, c)` is [`SubringMap::multiplication_block`] of entry `(r, c)` of `M`. See the
    /// type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless every entry has `k·d_S` coefficients.
    pub fn split_matrix(&self, matrix: &PolyMatrix) -> Result<PolyMatrix> {
        let k = self.rank;
        let Shape { rows, cols } = matrix.shape();
        let blocks = matrix
            .entries()
            .iter()
            .map(|a| self.multiplication_block(a))
            .collect::<Result<Vec<_>>>()?;
        // Row `r·k + l` of the result is row `l` of the blocks `(r, 0), …, (r, cols − 1)`.
        let entries = (0..rows)
            .flat_map(|r| (0..k).map(move |l| (r, l)))
            .flat_map(|(r, l)| {
                blocks[r * cols..(r + 1) * cols]
                    .iter()
                    .flat_map(move |block| block.entries()[l * k..(l + 1) * k].iter().cloned())
            })
            .collect();
        PolyMatrix::new(
            Shape {
                rows: rows * k,
                cols: cols * k,
            },
            entries,
        )
    }

    /// `Y·p` in `S`: the coefficients move up by one and the top one wraps around negated.
    fn times_y(&self, p: &Poly) -> Poly {
        Poly::from_reduced(match p.coefficients().split_last() {
            Some((top, rest)) => core::iter::once(self.small.zq().neg(top))
                .chain(rest.iter().copied())
                .collect(),
            None => Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SubringMap;
    use crate::{
        error::Error,
        matrix::{PolyMatrix, Shape},
        poly::Poly,
        ring::Ring,
        test_util::{PAPER, TOY, arb_ring_poly},
        vector::PolyVec,
        zq::Coeff,
    };
    use proptest::prelude::*;
    use std::sync::LazyLock;

    /// `R` at degrees 64 (the proof ring itself), 128 and 4096, with the toy and the 128-bit
    /// moduli.
    static R64: LazyLock<Ring> = LazyLock::new(|| TOY.ring().clone());
    static R128: LazyLock<Ring> = LazyLock::new(|| Ring::new(128, *TOY.ring().modulus()).unwrap());
    static R4096: LazyLock<Ring> = LazyLock::new(|| PAPER.ring().clone());

    fn map(big: &Ring) -> SubringMap {
        SubringMap::new(big, 64).unwrap()
    }

    /// `Σ_j a_j·b_j mod q` over the coefficients, with crypto-bigint's non-Montgomery `mul_mod`.
    fn inner_product(a: &Poly, b: &Poly, ring: &Ring) -> Coeff {
        let q = crypto_bigint::NonZero::new(*ring.modulus()).unwrap();
        a.coefficients()
            .iter()
            .zip(b.coefficients())
            .fold(Coeff::ZERO, |acc, (x, y)| {
                acc.add_mod(&x.mul_mod(y, &q), &q)
            })
    }

    /// The map is a bijection that only permutes coefficients, so norms are preserved, and the
    /// split inner-product identity `Σ_i const(a_i·σ_S(b_i)) = ⟨a, b⟩` holds.
    fn check_bijection_norms_and_inner_product(a: &Poly, b: &Poly, big: &Ring) {
        let map = map(big);
        let small = map.small();
        let parts = map.split(a).unwrap();
        assert_eq!(parts.len(), big.degree() / 64);
        assert_eq!(map.combine(parts.as_slice()).unwrap(), *a);
        assert_eq!(parts.norm_l2_squared(small), a.norm_l2_squared(big));
        assert_eq!(parts.norm_inf(small), a.norm_inf(big));
        let b_parts = map.split(b).unwrap();
        let sum = parts
            .as_slice()
            .iter()
            .zip(b_parts.as_slice())
            .map(|(x, y)| x.mul(&y.sigma_minus_one(small).unwrap(), small).unwrap())
            .fold(Poly::zero(small), |acc, p| acc.add(&p, small).unwrap());
        assert_eq!(sum.coefficients()[0], inner_product(a, b, big));
    }

    /// Big-ring products equal the split block products.
    fn check_products(a: &Poly, b: &Poly, big: &Ring) {
        let map = map(big);
        let block = map.multiplication_block(a).unwrap();
        let expected = map.split(&a.mul(b, big).unwrap()).unwrap();
        let split_b = map.split(b).unwrap();
        assert_eq!(block.mul_vec(&split_b, map.small()).unwrap(), expected);
    }

    #[test]
    fn identity_at_the_proof_degree() {
        let map = map(&R64);
        assert_eq!(map.rank(), 1);
        let a = Poly::constant(7, &R64).mul_small(3, &R64).unwrap();
        assert_eq!(map.split(&a).unwrap(), PolyVec::from(vec![a.clone()]));
        assert_eq!(
            map.multiplication_block(&a).unwrap(),
            PolyMatrix::new(Shape { rows: 1, cols: 1 }, vec![a]).unwrap()
        );
    }

    /// Coefficient `jk + i` of `a` is coefficient `j` of `a_i`; `X^{k−1}·X = Y` brings the factor
    /// `Y` into the block above the diagonal.
    #[test]
    fn layout_and_the_wrap_into_y() {
        let map = map(&R128);
        assert_eq!(map.rank(), 2);
        let small = map.small();
        let monomial = |ring: &Ring, i: usize| {
            let mut c = vec![Coeff::ZERO; ring.degree()];
            c[i] = Coeff::ONE;
            Poly::new(c, ring).unwrap()
        };
        assert_eq!(
            map.split(&monomial(&R128, 5)).unwrap(),
            PolyVec::from(vec![Poly::zero(small), monomial(small, 2)])
        );
        let x = monomial(&R128, 1);
        let block = map.multiplication_block(&x).unwrap();
        assert_eq!(block.get(0, 1), Some(&monomial(small, 1)));
        assert_eq!(block.get(1, 0), Some(&Poly::constant(1, small)));
        assert_eq!(block.get(0, 0), Some(&Poly::zero(small)));
    }

    #[test]
    fn shapes_are_checked() {
        let map = map(&R128);
        let small = map.small();
        let mismatch = |expected, found| Err(Error::DimensionMismatch { expected, found });
        assert_eq!(map.split(&Poly::zero(&R64)), mismatch(128, 64));
        assert_eq!(
            map.combine(&[Poly::zero(small)]),
            Err(Error::DimensionMismatch {
                expected: 2,
                found: 1
            })
        );
        assert_eq!(map.combine_vector(&PolyVec::zero(3, small)), mismatch(4, 3));
        assert_eq!(
            SubringMap::new(&R64, 128).err(),
            Some(Error::DimensionMismatch {
                expected: 64,
                found: 128
            })
        );
        assert_eq!(
            SubringMap::new(&R128, 48).err(),
            Some(Error::DegreeNotPowerOfTwo(48))
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn bijection_norms_and_inner_product_at_64(a in arb_ring_poly(&R64), b in arb_ring_poly(&R64)) {
            check_bijection_norms_and_inner_product(&a, &b, &R64);
        }

        #[test]
        fn bijection_norms_and_inner_product_at_128(a in arb_ring_poly(&R128), b in arb_ring_poly(&R128)) {
            check_bijection_norms_and_inner_product(&a, &b, &R128);
        }

        /// Short vectors too, whose norms are not dominated by the modulus.
        #[test]
        fn norms_of_short_vectors_at_128(values in prop::collection::vec(-1000i64..=1000, 128)) {
            let a = crate::test_util::signed_to_coeff(&values, &R128);
            check_bijection_norms_and_inner_product(&a, &a, &R128);
        }

        #[test]
        fn products_at_64_and_128(a in arb_ring_poly(&R128), b in arb_ring_poly(&R128), c in arb_ring_poly(&R64), e in arb_ring_poly(&R64)) {
            check_products(&a, &b, &R128);
            check_products(&c, &e, &R64);
        }

        /// `split(M·v) = split_matrix(M)·split_vector(v)`, and `combine_vector` inverts
        /// `split_vector`.
        #[test]
        fn matrix_vector_products_at_128(
            entries in prop::collection::vec(arb_ring_poly(&R128), 6),
            v in prop::collection::vec(arb_ring_poly(&R128), 3),
        ) {
            let map = map(&R128);
            let matrix = PolyMatrix::new(Shape { rows: 2, cols: 3 }, entries).unwrap();
            let v = PolyVec::from(v);
            let split_v = map.split_vector(&v).unwrap();
            prop_assert_eq!(map.combine_vector(&split_v).unwrap(), v.clone());
            let big = matrix.mul_vec(&v, &R128).unwrap();
            let blocks = map.split_matrix(&matrix).unwrap();
            prop_assert_eq!(blocks.shape(), Shape { rows: 4, cols: 6 });
            prop_assert_eq!(blocks.mul_vec(&split_v, map.small()).unwrap(), map.split_vector(&big).unwrap());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2))]

        #[test]
        fn bijection_norms_inner_product_and_products_at_4096(a in arb_ring_poly(&R4096), b in arb_ring_poly(&R4096)) {
            check_bijection_norms_and_inner_product(&a, &b, &R4096);
            check_products(&a, &b, &R4096);
        }

        #[test]
        fn matrix_vector_products_at_4096(
            entries in prop::collection::vec(arb_ring_poly(&R4096), 2),
            v in prop::collection::vec(arb_ring_poly(&R4096), 2),
        ) {
            let map = map(&R4096);
            let matrix = PolyMatrix::new(Shape { rows: 1, cols: 2 }, entries).unwrap();
            let v = PolyVec::from(v);
            let blocks = map.split_matrix(&matrix).unwrap();
            let expected = map.split_vector(&matrix.mul_vec(&v, &R4096).unwrap()).unwrap();
            prop_assert_eq!(blocks.mul_vec(&map.split_vector(&v).unwrap(), map.small()).unwrap(), expected);
        }
    }
}
