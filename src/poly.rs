// SPDX-License-Identifier: MIT OR Apache-2.0
//! Elements of `R_q = Z_q[X]/(X^d + 1)` in coefficient form, the building block of every
//! vector and matrix of ePrint 2025/1099.
//!
//! A [`Poly`] holds `d` coefficients in `[0, q)` and no parameters; every operation takes the
//! [`Ring`] it works in, so values stay small and serialize as bare coefficients. Short vectors
//! (preimages, witnesses, trapdoors) are held as their residues too: every parameter set keeps
//! their coefficients below `q/2`, so [`Ring::center`] recovers the integers and the norms
//! [`Poly::norm_l2_squared`] and [`Poly::norm_inf`] are exact.
//!
//! ```
//! use kln_accumulator::Params;
//! use kln_accumulator::lattice::{Coeff, Poly};
//!
//! let params = Params::toy()?;
//! let ring = params.ring();
//! let d = ring.degree();
//! // X and X^{d−1}: their product is X^d = −1 in R_q.
//! let mut x = vec![Coeff::ZERO; d];
//! x[1] = Coeff::ONE;
//! let mut top = vec![Coeff::ZERO; d];
//! top[d - 1] = Coeff::ONE;
//! let product = Poly::new(x, ring)?.mul(&Poly::new(top, ring)?, ring)?;
//! let mut minus_one = vec![Coeff::ZERO; d];
//! minus_one[0] = ring.modulus().wrapping_sub(&Coeff::ONE);
//! assert_eq!(product, Poly::new(minus_one, ring)?);
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

use crate::{
    error::{Error, Result},
    ring::Ring,
    secret_hex,
    zq::{Coeff, Zq},
};
use crypto_bigint::U512;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An element of `R_q = Z_q[X]/(X^d + 1)`: `d` coefficients in `[0, q)`, constant term first.
///
/// Arithmetic takes the [`Ring`] explicitly so that values carry no parameters and serialize
/// as bare coefficients; it fails with [`Error::DimensionMismatch`] when an operand's length is
/// not the ring degree. Values from outside the crate should pass [`Poly::validate`] first.
///
/// **Public type, wiped on drop.** A polynomial is a general value, but it also makes up every
/// secret the crate holds (trapdoor products, preimages, witnesses, the prover's vectors), so
/// its coefficients are overwritten whenever it is dropped ([`ZeroizeOnDrop`]). Every vector
/// and matrix built of polynomials inherits this. [`fmt::Debug`](core::fmt::Debug) prints the
/// coefficients: wrapper types that hold secrets print none.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{Coeff, Poly};
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let mut coefficients = vec![Coeff::ZERO; ring.degree()];
/// coefficients[0] = Coeff::from_u64(3);
/// let three = Poly::new(coefficients, ring)?;
/// let six = three.add(&three, ring)?;
/// assert_eq!(six, three.mul_small(2, ring)?);
/// assert_eq!(six.sub(&three, ring)?, three);
/// assert_eq!(three.neg(ring)?.add(&three, ring)?, Poly::zero(ring));
/// assert_eq!(six.norm_inf(ring), Coeff::from_u64(6));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    coefficients: Vec<Coeff>,
}

impl Poly {
    /// Builds a polynomial from `d` coefficients in `[0, q)`, constant term first.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless there are exactly `d` coefficients, and
    /// [`Error::CoefficientOutOfRange`] when one is not below `q`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params};
    /// use kln_accumulator::lattice::{Coeff, Poly};
    ///
    /// let params = Params::toy()?;
    /// let ring = params.ring();
    /// assert!(Poly::new(vec![Coeff::ONE; ring.degree()], ring).is_ok());
    /// assert!(matches!(
    ///     Poly::new(vec![Coeff::ONE; 3], ring),
    ///     Err(Error::DimensionMismatch { .. })
    /// ));
    /// assert_eq!(
    ///     Poly::new(vec![*ring.modulus(); ring.degree()], ring),
    ///     Err(Error::CoefficientOutOfRange)
    /// );
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new(coefficients: Vec<Coeff>, ring: &Ring) -> Result<Self> {
        let poly = Self { coefficients };
        poly.validate(ring)?;
        Ok(poly)
    }

    /// Wraps coefficients that the caller has already reduced into a degree-`d` vector.
    pub(crate) fn from_reduced(coefficients: Vec<Coeff>) -> Self {
        Self { coefficients }
    }

    /// The residue of a polynomial with small signed coefficients, constant term first. The
    /// caller guarantees there are `d` of them.
    pub(crate) fn from_signed(coefficients: &[i64], ring: &Ring) -> Self {
        Self::from_reduced(
            coefficients
                .iter()
                .map(|&t| ring.zq().reduce_i64(t))
                .collect(),
        )
    }

    /// The zero polynomial of `ring`'s degree; see the type's example.
    #[must_use]
    pub fn zero(ring: &Ring) -> Self {
        Self::from_reduced(vec![Coeff::ZERO; ring.degree()])
    }

    /// The constant polynomial `value`.
    pub(crate) fn constant(value: i64, ring: &Ring) -> Self {
        let mut coefficients = vec![Coeff::ZERO; ring.degree()];
        if let Some(first) = coefficients.first_mut() {
            *first = ring.zq().reduce_i64(value);
        }
        Self::from_reduced(coefficients)
    }

    /// The coefficients, constant term first; see the type's example.
    #[must_use]
    pub fn coefficients(&self) -> &[Coeff] {
        &self.coefficients
    }

    /// Checks that the polynomial has `d` coefficients, each in `[0, q)`. Polynomials decoded
    /// with `TryFrom<&[u8]>` or serde are not checked against any ring, so call this before
    /// using them.
    ///
    /// # Errors
    ///
    /// As [`Poly::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::Poly;
    ///
    /// let (toy, paper) = (Params::toy()?, Params::paper_128()?);
    /// let p = Poly::zero(toy.ring());
    /// assert!(p.validate(toy.ring()).is_ok());
    /// assert!(p.validate(paper.ring()).is_err()); // degree 64 is not 4096
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn validate(&self, ring: &Ring) -> Result<()> {
        ring.check_degree(self.coefficients.len())?;
        if self.coefficients.iter().all(|c| ring.zq().is_reduced(c)) {
            Ok(())
        } else {
            Err(Error::CoefficientOutOfRange)
        }
    }

    /// `self + rhs`. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when either operand does not have degree `d`.
    pub fn add(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        self.zip_with(rhs, ring, Zq::add)
    }

    /// `self − rhs`. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when either operand does not have degree `d`.
    pub fn sub(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        self.zip_with(rhs, ring, Zq::sub)
    }

    /// `−self`. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when `self` does not have degree `d`.
    pub fn neg(&self, ring: &Ring) -> Result<Self> {
        self.map(ring, |zq, c| zq.neg(c))
    }

    /// `self · rhs` in `R_q`, through the multi-prime NTT: both operands are transformed modulo
    /// the ring's auxiliary word primes, multiplied pointwise, and the exact integer product is
    /// recovered by Chinese remaindering and reduced modulo `q` (see [`Ring`]). The cost is
    /// three transforms per auxiliary prime, `O(d log d)` word operations each; to multiply by
    /// one matrix many times, use [`crate::lattice::NttMatrix`].
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when either operand does not have degree `d`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::{Coeff, Poly};
    ///
    /// let params = Params::toy()?;
    /// let ring = params.ring();
    /// let mut c = vec![Coeff::ZERO; ring.degree()];
    /// c[0] = Coeff::from_u64(2);
    /// c[1] = Coeff::ONE;
    /// let a = Poly::new(c, ring)?; // 2 + X
    /// let square = a.mul(&a, ring)?; // 4 + 4X + X²
    /// assert_eq!(&square.coefficients()[..3], &[4, 4, 1].map(Coeff::from_u64));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn mul(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        let (a, b) = (ring.ntt(self)?, ring.ntt(rhs)?);
        Ok(ring.sum_of_products([(&a, &b)]))
    }

    /// `σ₋₁(self)` for the automorphism `σ₋₁: X ↦ X⁻¹ = −X^{d−1}` of `R_q`: the constant term
    /// is fixed and `X^i ↦ −X^{d−i}` for `0 < i < d`.
    ///
    /// `σ₋₁` is an involutive ring automorphism, and the constant coefficient of `a·σ₋₁(b)` is
    /// the inner product of the coefficient vectors of `a` and `b`. The membership proof
    /// (Appendix D.2) uses this to express inner products and norms as ring equations.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when `self` does not have degree `d`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::{Coeff, Poly};
    ///
    /// let params = Params::toy()?;
    /// let ring = params.ring();
    /// let a = Poly::new((1..=64).map(Coeff::from_u64).collect(), ring)?;
    /// // An involution.
    /// assert_eq!(a.sigma_minus_one(ring)?.sigma_minus_one(ring)?, a);
    /// // The constant term of a·σ₋₁(a) is ‖a‖₂² = 1² + … + 64².
    /// let product = a.mul(&a.sigma_minus_one(ring)?, ring)?;
    /// assert_eq!(product.coefficients()[0], Coeff::from_u64(64 * 65 * 129 / 6));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn sigma_minus_one(&self, ring: &Ring) -> Result<Self> {
        ring.check_degree(self.coefficients.len())?;
        let (zq, c, d) = (ring.zq(), &self.coefficients, self.coefficients.len());
        Ok(Self::from_reduced(
            (0..d)
                .map(|i| if i == 0 { c[0] } else { zq.neg(&c[d - i]) })
                .collect(),
        ))
    }

    /// `scalar · self` for a signed integer `scalar`, reduced modulo `q` first. See the type's
    /// example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when `self` does not have degree `d`.
    pub fn mul_small(&self, scalar: i64, ring: &Ring) -> Result<Self> {
        ring.check_degree(self.coefficients.len())?;
        Ok(self.scale(&ring.zq().reduce_i64(scalar), ring))
    }

    /// `scalar · self` for a reduced `scalar ∈ Z_q`, coefficient by coefficient; the degree is
    /// not checked.
    pub(crate) fn scale(&self, scalar: &Coeff, ring: &Ring) -> Self {
        let zq = ring.zq();
        let scalar = zq.montgomery(scalar);
        Self::from_reduced(
            self.coefficients
                .iter()
                .map(|c| zq.mont_mul(&scalar, c))
                .collect(),
        )
    }

    /// `‖self‖₂²` over the centered lift of the coefficients, exact: each square is below
    /// `2^382` and the sum is held in 512 bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::{Coeff, Poly};
    ///
    /// let params = Params::toy()?;
    /// let ring = params.ring();
    /// let mut c = vec![Coeff::ZERO; ring.degree()];
    /// c[0] = Coeff::from_u64(3);
    /// c[1] = ring.modulus().wrapping_sub(&Coeff::from_u64(4)); // −4
    /// let p = Poly::new(c, ring)?;
    /// assert_eq!(p.norm_l2_squared(ring), crypto_bigint::U512::from_u64(25));
    /// assert_eq!(p.norm_inf(ring), Coeff::from_u64(4));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn norm_l2_squared(&self, ring: &Ring) -> U512 {
        self.coefficients.iter().fold(U512::ZERO, |acc, c| {
            acc.wrapping_add(&ring.center(c).magnitude_squared())
        })
    }

    /// `‖self‖_∞` over the centered lift of the coefficients; see
    /// [`Poly::norm_l2_squared`] for an example.
    #[must_use]
    pub fn norm_inf(&self, ring: &Ring) -> Coeff {
        self.coefficients
            .iter()
            .map(|c| *ring.center(c).magnitude())
            .max()
            .unwrap_or(Coeff::ZERO)
    }

    /// Appends every coefficient as [`Coeff::BYTES`] little-endian bytes, constant term first.
    pub(crate) fn write_coefficients(&self, out: &mut Vec<u8>) {
        for coefficient in &self.coefficients {
            out.extend_from_slice(coefficient.to_le_bytes().as_slice());
        }
    }

    fn map(&self, ring: &Ring, f: impl Fn(&Zq, &Coeff) -> Coeff) -> Result<Self> {
        ring.check_degree(self.coefficients.len())?;
        let zq = ring.zq();
        Ok(Self::from_reduced(
            self.coefficients.iter().map(|c| f(zq, c)).collect(),
        ))
    }

    fn zip_with(
        &self,
        rhs: &Self,
        ring: &Ring,
        f: impl Fn(&Zq, &Coeff, &Coeff) -> Coeff,
    ) -> Result<Self> {
        ring.check_degree(self.coefficients.len())?;
        ring.check_degree(rhs.coefficients.len())?;
        let zq = ring.zq();
        Ok(Self::from_reduced(
            self.coefficients
                .iter()
                .zip(&rhs.coefficients)
                .map(|(a, b)| f(zq, a, b))
                .collect(),
        ))
    }
}

/// Overwrites every coefficient.
impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
    }
}

impl Drop for Poly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Poly {}

/// Serialized as the concatenated little-endian [`Coeff`] encodings: raw bytes in binary
/// formats, one lowercase hex string in human-readable formats.
/// The encoding is built and decoded in buffers that are overwritten when dropped, since a
/// polynomial may be secret.
impl Serialize for Poly {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.coefficients.len() * Coeff::BYTES));
        self.write_coefficients(&mut bytes);
        secret_hex::serialize(&*bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for Poly {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let bytes = secret_hex::deserialize(deserializer)?;
        Self::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// Decodes concatenated little-endian [`Coeff`] encodings. The result is not reduced against
/// any ring; call [`Poly::validate`] before using it. Fails with
/// [`Error::InvalidEncodingLength`] unless the length is a multiple of [`Coeff::BYTES`].
impl TryFrom<&[u8]> for Poly {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if !bytes.len().is_multiple_of(Coeff::BYTES) {
            return Err(Error::InvalidEncodingLength(bytes.len()));
        }
        Ok(Self::from_reduced(
            bytes
                .as_chunks::<{ Coeff::BYTES }>()
                .0
                .iter()
                .map(|chunk| Coeff::from_le_slice(chunk))
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::Poly;
    use crate::{
        error::Error,
        test_util::{PAPER, TOY, arb_poly, arb_small_poly, signed_to_coeff, six_formats},
        zq::Coeff,
    };
    use crypto_bigint::U512;
    use proptest::prelude::*;

    /// A polynomial round-trips in the six formats, as its coefficient bytes: raw in binary
    /// formats and lowercase hex in human-readable ones.
    #[test]
    fn serde_six_formats() {
        let ring = TOY.ring();
        let p = Poly::constant(0x1234, ring);
        let mut bytes = Vec::new();
        p.write_coefficients(&mut bytes);
        let binary = six_formats(p, &hex::encode(&bytes));
        assert!(binary.iter().all(|b| b.len() < bytes.len() + 16));
    }

    #[test]
    fn new_validates_length_and_range() {
        let ring = TOY.ring();
        let q = *ring.modulus();
        assert!(Poly::new(vec![Coeff::ONE; 64], ring).is_ok());
        assert_eq!(
            Poly::new(vec![Coeff::ONE; 63], ring),
            Err(Error::DimensionMismatch {
                expected: 64,
                found: 63
            })
        );
        let mut coefficients = vec![Coeff::ZERO; 64];
        coefficients[5] = q;
        assert_eq!(
            Poly::new(coefficients, ring),
            Err(Error::CoefficientOutOfRange)
        );
    }

    #[test]
    fn zero_and_coefficients() {
        let zero = Poly::zero(TOY.ring());
        assert_eq!(zero.coefficients(), vec![Coeff::ZERO; 64].as_slice());
        assert!(zero.validate(TOY.ring()).is_ok());
        assert_eq!(zero.norm_inf(TOY.ring()), Coeff::ZERO);
        assert_eq!(zero.norm_l2_squared(TOY.ring()), U512::ZERO);
    }

    #[test]
    fn operations_reject_wrong_degree() {
        let toy = Poly::zero(TOY.ring());
        let paper = Poly::zero(PAPER.ring());
        let ring = TOY.ring();
        let mismatch = Err(Error::DimensionMismatch {
            expected: 64,
            found: 4096,
        });
        assert_eq!(toy.add(&paper, ring), mismatch);
        assert_eq!(toy.sub(&paper, ring), mismatch);
        assert_eq!(paper.neg(ring), mismatch);
        assert_eq!(toy.mul(&paper, ring), mismatch);
        assert_eq!(paper.mul_small(3, ring), mismatch);
        assert_eq!(paper.sigma_minus_one(ring), mismatch);
    }

    #[test]
    fn byte_decoding_rejects_partial_coefficients() {
        assert_eq!(
            Poly::try_from([0u8; 25].as_slice()),
            Err(Error::InvalidEncodingLength(25))
        );
        let decoded = Poly::try_from([1u8; 48].as_slice()).unwrap();
        assert_eq!(decoded.coefficients().len(), 2);
    }

    #[test]
    fn deserializes_from_hex_in_human_readable_formats() {
        use serde::{
            Deserialize,
            de::value::{Error as ValueError, StrDeserializer},
        };
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut bytes = vec![0u8; 2 * Coeff::BYTES];
        bytes[0] = 7;
        bytes[Coeff::BYTES] = 9;
        let text = hex(&bytes);
        let poly = Poly::deserialize(StrDeserializer::<ValueError>::new(&text)).unwrap();
        assert_eq!(
            poly.coefficients(),
            [Coeff::from_u8(7), Coeff::from_u8(9)].as_slice()
        );
        let short = hex(&bytes[..Coeff::BYTES + 1]);
        assert!(Poly::deserialize(StrDeserializer::<ValueError>::new(&short)).is_err());
    }

    #[test]
    fn norms_at_the_centering_boundary_of_the_paper_modulus() {
        // The largest magnitudes, ±⌊q/2⌋ with q ≈ 2^100, square to about 2^198; the expected
        // values come from a 512-bit multiplication rather than the widening square.
        let ring = PAPER.ring();
        let half = ring.modulus().shr_vartime(1);
        let mut coefficients = vec![Coeff::ZERO; ring.degree()];
        coefficients[0] = half;
        coefficients[1] = half.wrapping_add(&Coeff::ONE);
        coefficients[2] = Coeff::ONE;
        let poly = Poly::new(coefficients, ring).unwrap();
        let wide: U512 = half.resize();
        let square = wide.wrapping_mul(&wide);
        let expected = square.wrapping_add(&square).wrapping_add(&U512::ONE);
        assert_eq!(poly.norm_l2_squared(ring), expected);
        assert_eq!(poly.norm_inf(ring), half);
    }

    /// `Σ_i a_i·b_i mod q` over the coefficients, with crypto-bigint's non-Montgomery `mul_mod`.
    fn inner_product(a: &Poly, b: &Poly, ring: &crate::ring::Ring) -> Coeff {
        let q = crypto_bigint::NonZero::new(*ring.modulus()).unwrap();
        a.coefficients()
            .iter()
            .zip(b.coefficients())
            .fold(Coeff::ZERO, |acc, (x, y)| {
                acc.add_mod(&x.mul_mod(y, &q), &q)
            })
    }

    /// `σ₋₁(X) = −X^{d−1}` and `σ₋₁(1) = 1`.
    #[test]
    fn sigma_minus_one_on_monomials() {
        let ring = TOY.ring();
        let monomial = |i: usize, value: Coeff| {
            let mut c = vec![Coeff::ZERO; 64];
            c[i] = value;
            Poly::new(c, ring).unwrap()
        };
        let minus_one = ring.zq().reduce_i64(-1);
        assert_eq!(
            monomial(1, Coeff::ONE).sigma_minus_one(ring).unwrap(),
            monomial(63, minus_one)
        );
        assert_eq!(
            monomial(63, Coeff::ONE).sigma_minus_one(ring).unwrap(),
            monomial(1, minus_one)
        );
        assert_eq!(
            monomial(0, Coeff::ONE).sigma_minus_one(ring).unwrap(),
            monomial(0, Coeff::ONE)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2))]

        #[test]
        fn sigma_minus_one_identities_paper(a in arb_poly(&PAPER), b in arb_poly(&PAPER)) {
            let ring = PAPER.ring();
            let sigma = |p: &Poly| p.sigma_minus_one(ring).unwrap();
            prop_assert_eq!(sigma(&sigma(&a)), a.clone());
            prop_assert_eq!(sigma(&a.mul(&b, ring).unwrap()), sigma(&a).mul(&sigma(&b), ring).unwrap());
            prop_assert_eq!(a.mul(&sigma(&b), ring).unwrap().coefficients()[0], inner_product(&a, &b, ring));
        }
    }

    proptest! {
        #[test]
        fn ring_axioms(a in arb_poly(&TOY), b in arb_poly(&TOY), c in arb_poly(&TOY)) {
            let ring = TOY.ring();
            let zero = Poly::zero(ring);
            prop_assert_eq!(a.add(&b, ring).unwrap().sub(&b, ring).unwrap(), a.clone());
            prop_assert_eq!(a.add(&a.neg(ring).unwrap(), ring).unwrap(), zero.clone());
            prop_assert_eq!(a.mul(&b, ring).unwrap(), b.mul(&a, ring).unwrap());
            let left = a.mul(&b.add(&c, ring).unwrap(), ring).unwrap();
            let right = a.mul(&b, ring).unwrap().add(&a.mul(&c, ring).unwrap(), ring).unwrap();
            prop_assert_eq!(left, right);
            prop_assert_eq!(a.mul(&zero, ring).unwrap(), zero);
        }

        /// `σ₋₁` is an involution and a ring homomorphism, and `const(a·σ₋₁(b)) = ⟨a, b⟩ mod q`.
        #[test]
        fn sigma_minus_one_identities(a in arb_poly(&TOY), b in arb_poly(&TOY)) {
            let ring = TOY.ring();
            let sigma = |p: &Poly| p.sigma_minus_one(ring).unwrap();
            prop_assert_eq!(sigma(&sigma(&a)), a.clone());
            prop_assert_eq!(sigma(&a.mul(&b, ring).unwrap()), sigma(&a).mul(&sigma(&b), ring).unwrap());
            prop_assert_eq!(sigma(&a.add(&b, ring).unwrap()), sigma(&a).add(&sigma(&b), ring).unwrap());
            prop_assert_eq!(a.mul(&sigma(&b), ring).unwrap().coefficients()[0], inner_product(&a, &b, ring));
        }

        #[test]
        fn mul_small_is_repeated_addition(a in arb_poly(&TOY), k in -20i64..20) {
            let ring = TOY.ring();
            let repeated = (0..k.unsigned_abs()).try_fold(Poly::zero(ring), |acc, _| acc.add(&a, ring)).unwrap();
            let expected = if k < 0 { repeated.neg(ring).unwrap() } else { repeated };
            prop_assert_eq!(a.mul_small(k, ring).unwrap(), expected);
        }

        #[test]
        fn norms_match_direct_integer_computation(values in arb_small_poly(64, 1 << 58)) {
            let ring = TOY.ring();
            let poly = signed_to_coeff(&values, ring);
            let l2: i128 = values.iter().map(|&v| i128::from(v) * i128::from(v)).sum();
            let inf = values.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
            prop_assert_eq!(poly.norm_l2_squared(ring), U512::from_u128(l2.unsigned_abs()));
            prop_assert_eq!(poly.norm_inf(ring), Coeff::from_u64(inf));
        }

        #[test]
        fn validate_accepts_sampled(a in arb_poly(&PAPER)) {
            prop_assert!(a.validate(PAPER.ring()).is_ok());
        }

        #[test]
        fn byte_roundtrip(a in arb_poly(&TOY)) {
            let bytes: Vec<u8> = a.coefficients().iter().flat_map(|c| c.to_le_bytes().as_slice().to_vec()).collect();
            prop_assert_eq!(Poly::try_from(bytes.as_slice()).unwrap(), a);
        }
    }
}
