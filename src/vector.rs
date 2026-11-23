// SPDX-License-Identifier: MIT OR Apache-2.0
//! Column vectors over `R_q`: the accumulator value `c ∈ R_q^n`, the vector `u`, preimages and
//! witnesses, and every vector of the proofs.
//!
//! A [`PolyVec`] is a list of [`Poly`] entries with no parameters; operations take the
//! [`Ring`]. Since each entry overwrites itself when dropped, so does every vector.
//!
//! ```
//! use kln_accumulator::Params;
//! use kln_accumulator::lattice::{PolyVec, UniformSampler, Seed, DomainLabel};
//!
//! let params = Params::toy()?;
//! let ring = params.ring();
//! let mut sampler = UniformSampler::new(&Seed::from([1; 32]), DomainLabel::from(&b"v"[..]));
//! let (a, b) = (sampler.vector(3, ring), sampler.vector(3, ring));
//! let sum = a.add(&b, ring)?;
//! assert_eq!(sum.sub(&b, ring)?, a);
//! assert_eq!(a.concat(&b).len(), 6);
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

use crate::{
    error::{Error, Result, check_dimension},
    poly::Poly,
    ring::Ring,
    zq::Coeff,
};
use crypto_bigint::U512;
use serde::{Deserialize, Serialize};

/// A column vector over `R_q`.
///
/// **Public type, wiped on drop**: its entries are [`Poly`]s, which overwrite their coefficients
/// when dropped ([`zeroize::ZeroizeOnDrop`]). Serialized as the sequence of its polynomials
/// (see [`Poly`]'s serde form); `From<&PolyVec> for Vec<u8>` gives a self-describing byte form
/// with 24 bytes per coefficient, which the proofs use. Built from polynomials with
/// `From<Vec<Poly>>` or [`FromIterator`], and taken apart with `From<PolyVec> for Vec<Poly>`.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{Coeff, Poly, PolyVec};
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let mut c = vec![Coeff::ZERO; ring.degree()];
/// c[0] = Coeff::from_u64(2);
/// let two = Poly::new(c, ring)?;
/// let v = PolyVec::from(vec![two.clone(), Poly::zero(ring)]);
/// assert_eq!(v.len(), 2);
/// assert!(!v.is_empty());
/// assert_eq!(v.as_slice()[0], two);
/// assert_eq!(v.mul_small(3, ring)?.norm_inf(ring), Coeff::from_u64(6));
/// assert_eq!(v.neg(ring)?.add(&v, ring)?, PolyVec::zero(2, ring));
/// assert_eq!(v.sub(&v, ring)?, PolyVec::zero(2, ring));
/// assert_eq!(v.concat(&v).len(), 4);
/// // The self-describing byte form round-trips.
/// let bytes = Vec::<u8>::from(&v);
/// assert_eq!(PolyVec::try_from(bytes.as_slice())?, v);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, derive_more::From, derive_more::Into,
)]
#[serde(transparent)]
pub struct PolyVec(Vec<Poly>);

impl PolyVec {
    /// The zero vector of length `len`; see the type's example.
    #[must_use]
    pub fn zero(len: usize, ring: &Ring) -> Self {
        Self(vec![Poly::zero(ring); len])
    }

    /// The number of entries; see the type's example.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the vector has no entries; see the type's example.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The entries in order; see the type's example.
    #[must_use]
    pub fn as_slice(&self) -> &[Poly] {
        &self.0
    }

    /// Checks every entry with [`Poly::validate`]. Vectors decoded with `TryFrom<&[u8]>` or
    /// serde are not checked against any ring, so call this before using them.
    ///
    /// # Errors
    ///
    /// As [`Poly::validate`], for the first entry that fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::PolyVec;
    ///
    /// let (toy, paper) = (Params::toy()?, Params::paper_128()?);
    /// let v = PolyVec::zero(2, toy.ring());
    /// assert!(v.validate(toy.ring()).is_ok());
    /// assert!(v.validate(paper.ring()).is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn validate(&self, ring: &Ring) -> Result<()> {
        self.0.iter().try_for_each(|p| p.validate(ring))
    }

    /// `self + rhs`, entry by entry. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when the lengths differ or an entry does not have
    /// degree `d`.
    pub fn add(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        self.zip_with(rhs, |a, b| a.add(b, ring))
    }

    /// `self − rhs`, entry by entry. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when the lengths differ or an entry does not have
    /// degree `d`.
    pub fn sub(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        self.zip_with(rhs, |a, b| a.sub(b, ring))
    }

    /// `−self`. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when an entry does not have degree `d`.
    pub fn neg(&self, ring: &Ring) -> Result<Self> {
        self.0.iter().map(|p| p.neg(ring)).collect()
    }

    /// `scalar · self` for a signed integer `scalar`. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when an entry does not have degree `d`.
    pub fn mul_small(&self, scalar: i64, ring: &Ring) -> Result<Self> {
        self.0.iter().map(|p| p.mul_small(scalar, ring)).collect()
    }

    /// `σ₋₁` (see [`Poly::sigma_minus_one`]) applied to every entry. The constant coefficient
    /// of `Σ_i a_i·σ₋₁(b_i)` is the inner product of all coefficients of `a` and `b`.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when an entry does not have degree `d`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::{DomainLabel, Seed, UniformSampler};
    ///
    /// let params = Params::toy()?;
    /// let ring = params.ring();
    /// let v = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"s"[..]))
    ///     .vector(2, ring);
    /// assert_eq!(v.sigma_minus_one(ring)?.sigma_minus_one(ring)?, v);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn sigma_minus_one(&self, ring: &Ring) -> Result<Self> {
        self.0.iter().map(|p| p.sigma_minus_one(ring)).collect()
    }

    /// The vertical concatenation `[self; rhs]`; see the type's example.
    #[must_use]
    pub fn concat(&self, rhs: &Self) -> Self {
        Self(self.0.iter().chain(&rhs.0).cloned().collect())
    }

    /// `‖self‖₂²` over the centered lift of all coefficients, exact in 512 bits. A witness
    /// verifies only if this is at most `β²` ([`crate::Bounds::witness`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::{Coeff, Poly, PolyVec};
    ///
    /// let params = Params::toy()?;
    /// let ring = params.ring();
    /// let mut c = vec![Coeff::ZERO; ring.degree()];
    /// c[0] = Coeff::from_u64(2);
    /// let v = PolyVec::from(vec![Poly::new(c.clone(), ring)?, Poly::new(c, ring)?]);
    /// assert_eq!(v.norm_l2_squared(ring), crypto_bigint::U512::from_u64(8));
    /// assert_eq!(v.norm_inf(ring), Coeff::from_u64(2));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn norm_l2_squared(&self, ring: &Ring) -> U512 {
        self.0.iter().fold(U512::ZERO, |acc, p| {
            acc.wrapping_add(&p.norm_l2_squared(ring))
        })
    }

    /// `‖self‖_∞` over the centered lift of all coefficients; see
    /// [`PolyVec::norm_l2_squared`] for an example.
    #[must_use]
    pub fn norm_inf(&self, ring: &Ring) -> Coeff {
        self.0
            .iter()
            .map(|p| p.norm_inf(ring))
            .max()
            .unwrap_or(Coeff::ZERO)
    }

    /// Appends every coefficient, entries in order, as in [`Poly::write_coefficients`].
    pub(crate) fn write_coefficients(&self, out: &mut Vec<u8>) {
        self.0.iter().for_each(|p| p.write_coefficients(out));
    }

    /// Reads `len` polynomials of `degree` coefficients written by
    /// [`Poly::write_coefficients`] from the front of `bytes`, and returns them with the
    /// bytes that follow. The coefficients are not checked against a modulus.
    pub(crate) fn read_coefficients(
        bytes: &[u8],
        len: usize,
        degree: usize,
    ) -> Result<(Self, &[u8])> {
        let invalid = Error::InvalidEncodingLength(bytes.len());
        let poly_bytes = degree.checked_mul(Coeff::BYTES).ok_or(invalid)?;
        let total = len.checked_mul(poly_bytes).ok_or(invalid)?;
        if poly_bytes == 0 && len > 0 {
            return Err(invalid);
        }
        let (head, rest) = bytes.split_at_checked(total).ok_or(invalid)?;
        let vector = head
            .chunks_exact(poly_bytes.max(1))
            .map(Poly::try_from)
            .collect::<Result<Self>>()?;
        Ok((vector, rest))
    }

    fn zip_with(&self, rhs: &Self, f: impl Fn(&Poly, &Poly) -> Result<Poly>) -> Result<Self> {
        check_dimension(self.len(), rhs.len())?;
        self.0.iter().zip(&rhs.0).map(|(a, b)| f(a, b)).collect()
    }
}

impl FromIterator<Poly> for PolyVec {
    fn from_iter<I: IntoIterator<Item = Poly>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Overwrites every entry.
impl zeroize::Zeroize for PolyVec {
    fn zeroize(&mut self) {
        self.0.iter_mut().for_each(zeroize::Zeroize::zeroize);
    }
}

/// Every entry is a [`Poly`], which overwrites its coefficients when dropped.
impl zeroize::ZeroizeOnDrop for PolyVec {}

/// The self-describing encoding: the number of entries and their degree `d`, each as a
/// little-endian `u64`, then every coefficient as [`Coeff::BYTES`] little-endian bytes.
impl From<&PolyVec> for Vec<u8> {
    fn from(vector: &PolyVec) -> Self {
        encode_entries(&vector.0)
    }
}

/// The encoding of `From<&PolyVec> for Vec<u8>` for the vector with entries `entries`, without
/// building the vector.
pub(crate) fn encode_entries(entries: &[Poly]) -> Vec<u8> {
    let degree = entries.first().map_or(0, |p| p.coefficients().len());
    let mut out = Vec::with_capacity(16 + entries.len() * degree * Coeff::BYTES);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    out.extend_from_slice(&(degree as u64).to_le_bytes());
    entries.iter().for_each(|p| p.write_coefficients(&mut out));
    out
}

/// Decodes the encoding of `From<&PolyVec> for Vec<u8>`, which must be consumed exactly. An
/// empty vector must carry degree 0, as the encoder writes it. The coefficients are not
/// checked against a modulus; call [`PolyVec::validate`] before use.
impl TryFrom<&[u8]> for PolyVec {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let invalid = Error::InvalidEncodingLength(bytes.len());
        let read = |raw: &[u8; 8]| usize::try_from(u64::from_le_bytes(*raw)).map_err(|_| invalid);
        let (len, rest) = bytes.split_first_chunk::<8>().ok_or(invalid)?;
        let (degree, body) = rest.split_first_chunk::<8>().ok_or(invalid)?;
        let (len, degree) = (read(len)?, read(degree)?);
        if len == 0 && degree != 0 {
            return Err(invalid);
        }
        let (vector, trailing) = Self::read_coefficients(body, len, degree).map_err(|_| invalid)?;
        if trailing.is_empty() {
            Ok(vector)
        } else {
            Err(invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PolyVec;
    use crate::{
        error::Error,
        poly::Poly,
        test_util::{PAPER, TOY, arb_poly, arb_small_poly, arb_vec, signed_to_coeff, six_formats},
        zq::Coeff,
    };
    use crypto_bigint::U512;
    use proptest::prelude::*;

    /// A vector round-trips in the six formats as its polynomials, each in hex in the
    /// human-readable forms.
    #[test]
    fn serde_six_formats() {
        let ring = TOY.ring();
        let v = PolyVec::from(vec![Poly::constant(7, ring); 2]);
        let mut bytes = Vec::new();
        v.as_slice()[0].write_coefficients(&mut bytes);
        let _ = six_formats(v, &hex::encode(&bytes));
    }

    proptest! {
        /// `const(Σ_i a_i·σ₋₁(b_i)) = Σ_{i,j} a_{i,j}·b_{i,j} mod q`, and `σ₋₁` on vectors is an
        /// involution acting entry by entry.
        #[test]
        fn sigma_minus_one_gives_inner_products(a in arb_vec(&TOY, 3), b in arb_vec(&TOY, 3)) {
            let ring = TOY.ring();
            let sigma_b = b.sigma_minus_one(ring).unwrap();
            prop_assert_eq!(sigma_b.sigma_minus_one(ring).unwrap(), b.clone());
            let product = a
                .as_slice()
                .iter()
                .zip(sigma_b.as_slice())
                .fold(Poly::zero(ring), |acc, (x, y)| acc.add(&x.mul(y, ring).unwrap(), ring).unwrap());
            let q = crypto_bigint::NonZero::new(*ring.modulus()).unwrap();
            let expected = a
                .as_slice()
                .iter()
                .flat_map(Poly::coefficients)
                .zip(b.as_slice().iter().flat_map(Poly::coefficients))
                .fold(Coeff::ZERO, |acc, (x, y)| acc.add_mod(&x.mul_mod(y, &q), &q));
            prop_assert_eq!(product.coefficients()[0], expected);
            prop_assert_eq!(
                PolyVec::zero(1, PAPER.ring()).sigma_minus_one(ring),
                Err(Error::DimensionMismatch { expected: 64, found: 4096 })
            );
        }
    }

    #[test]
    fn zero_len_and_slice() {
        let ring = TOY.ring();
        let zero = PolyVec::zero(3, ring);
        assert_eq!(zero.len(), 3);
        assert!(!zero.is_empty());
        assert!(PolyVec::zero(0, ring).is_empty());
        assert_eq!(zero.as_slice(), vec![Poly::zero(ring); 3].as_slice());
        assert_eq!(Vec::<Poly>::from(zero.clone()), vec![Poly::zero(ring); 3]);
        assert_eq!(PolyVec::from(vec![Poly::zero(ring); 3]), zero);
        assert_eq!(zero.norm_inf(ring), Coeff::ZERO);
        assert_eq!(PolyVec::zero(0, ring).norm_inf(ring), Coeff::ZERO);
    }

    #[test]
    fn bytes_round_trip_and_reject_malformed() {
        let ring = TOY.ring();
        let empty = Vec::<u8>::from(&PolyVec::zero(0, ring));
        assert_eq!(empty, [0u8; 16]);
        assert_eq!(
            PolyVec::try_from(empty.as_slice()),
            Ok(PolyVec::zero(0, ring))
        );
        let mut bytes = Vec::<u8>::from(&PolyVec::zero(2, ring));
        assert_eq!(bytes.len(), 16 + 2 * 64 * Coeff::BYTES);
        assert_eq!(
            PolyVec::try_from(bytes.as_slice()),
            Ok(PolyVec::zero(2, ring))
        );
        let len = bytes.len();
        assert_eq!(
            PolyVec::try_from(&bytes[..len - 1]),
            Err(Error::InvalidEncodingLength(len - 1))
        );
        bytes.push(0);
        assert_eq!(
            PolyVec::try_from(bytes.as_slice()),
            Err(Error::InvalidEncodingLength(len + 1))
        );
        // A huge count of degree-0 entries is refused without allocating.
        let mut zero_degree = [0u8; 16];
        zero_degree[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(PolyVec::try_from(zero_degree.as_slice()).is_err());
        assert!(PolyVec::try_from([0u8; 15].as_slice()).is_err());
        // An empty vector with a non-zero degree word would re-encode differently.
        let mut empty_degree_five = [0u8; 16];
        empty_degree_five[8..].copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(
            PolyVec::try_from(empty_degree_five.as_slice()),
            Err(Error::InvalidEncodingLength(16))
        );
    }

    #[test]
    fn length_mismatch_is_an_error() {
        let ring = TOY.ring();
        let mismatch = Err(Error::DimensionMismatch {
            expected: 2,
            found: 3,
        });
        assert_eq!(
            PolyVec::zero(2, ring).add(&PolyVec::zero(3, ring), ring),
            mismatch
        );
        assert_eq!(
            PolyVec::zero(2, ring).sub(&PolyVec::zero(3, ring), ring),
            mismatch
        );
    }

    #[test]
    fn validate_reports_bad_entries() {
        assert!(PolyVec::zero(2, TOY.ring()).validate(TOY.ring()).is_ok());
        assert!(PolyVec::zero(2, PAPER.ring()).validate(TOY.ring()).is_err());
    }

    proptest! {
        #[test]
        fn elementwise_operations(a in arb_vec(&TOY, 3), b in arb_vec(&TOY, 3), k in -5i64..5) {
            let ring = TOY.ring();
            let sum = a.add(&b, ring).unwrap();
            let difference = a.sub(&b, ring).unwrap();
            let negated = a.neg(ring).unwrap();
            let scaled = a.mul_small(k, ring).unwrap();
            for i in 0..3 {
                let (x, y) = (&a.as_slice()[i], &b.as_slice()[i]);
                prop_assert_eq!(&sum.as_slice()[i], &x.add(y, ring).unwrap());
                prop_assert_eq!(&difference.as_slice()[i], &x.sub(y, ring).unwrap());
                prop_assert_eq!(&negated.as_slice()[i], &x.neg(ring).unwrap());
                prop_assert_eq!(&scaled.as_slice()[i], &x.mul_small(k, ring).unwrap());
            }
        }

        #[test]
        fn bytes_round_trip(a in arb_vec(&TOY, 3)) {
            let bytes = Vec::<u8>::from(&a);
            prop_assert_eq!(PolyVec::try_from(bytes.as_slice()), Ok(a));
        }

        #[test]
        fn concat_stacks(a in arb_vec(&TOY, 2), b in arb_vec(&TOY, 3)) {
            let stacked = a.concat(&b);
            prop_assert_eq!(stacked.len(), 5);
            prop_assert_eq!(&stacked.as_slice()[..2], a.as_slice());
            prop_assert_eq!(&stacked.as_slice()[2..], b.as_slice());
        }

        #[test]
        fn collects_from_polys(a in arb_poly(&TOY), b in arb_poly(&TOY)) {
            let collected: PolyVec = [a.clone(), b.clone()].into_iter().collect();
            let expected = [a, b];
            prop_assert_eq!(collected.as_slice(), expected.as_slice());
        }

        #[test]
        fn norms_match_direct_integer_computation(
            x in arb_small_poly(64, 1 << 58),
            y in arb_small_poly(64, 1 << 58),
        ) {
            let ring = TOY.ring();
            let vector = PolyVec::from(vec![signed_to_coeff(&x, ring), signed_to_coeff(&y, ring)]);
            let all = x.iter().chain(&y);
            let l2: i128 = all.clone().map(|&v| i128::from(v) * i128::from(v)).sum();
            let inf = all.map(|v| v.unsigned_abs()).max().unwrap_or(0);
            prop_assert_eq!(vector.norm_l2_squared(ring), U512::from_u128(l2.unsigned_abs()));
            prop_assert_eq!(vector.norm_inf(ring), Coeff::from_u64(inf));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn norms_at_paper_modulus(x in arb_small_poly(4096, 1 << 40)) {
            let ring = PAPER.ring();
            let vector = PolyVec::from(vec![signed_to_coeff(&x, ring)]);
            let l2: i128 = x.iter().map(|&v| i128::from(v) * i128::from(v)).sum();
            let inf = x.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
            prop_assert_eq!(vector.norm_l2_squared(ring), U512::from_u128(l2.unsigned_abs()));
            prop_assert_eq!(vector.norm_inf(ring), Coeff::from_u64(inf));
        }
    }
}
