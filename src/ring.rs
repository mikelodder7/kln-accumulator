// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ring `R_q = Z_q[X]/(X^d + 1)` and its multiplication by a multi-prime NTT.
//!
//! The moduli the crate uses are primes `q ≡ 5 (mod 8)`, for which `X^d + 1` splits into only
//! two irreducible factors and no negacyclic NTT modulo `q` exists. A product is therefore
//! computed exactly over the integers: each operand's coefficients, taken in `[0, q)`, are
//! transformed modulo `k` word-size NTT-friendly primes, multiplied pointwise, and the integer
//! result is recovered by Chinese remaindering and reduced modulo `q`. Each coefficient of a
//! negacyclic product of reduced polynomials has magnitude at most `d·(q−1)²`, so `k` is the
//! least count whose product `P` satisfies `P − 1 ≥ 2·d·(q−1)²`, and
//! `⌊(P − 1)/(2·d·(q−1)²)⌋` products may be summed in transformed form before a reduction.
//!
//! Two factors is what the membership proof of Appendix D.2 needs (ePrint 2025/1099): there
//! the differences of challenges must be invertible. The ring is part of a parameter set and is
//! reached through [`crate::Params::ring`]; it is built and validated with the set.
//!
//! ```
//! use kln_accumulator::Params;
//! use kln_accumulator::lattice::Coeff;
//!
//! let params = Params::toy()?;
//! let ring = params.ring();
//! assert_eq!(ring.degree(), 64);
//! assert_eq!(*ring.modulus() & Coeff::from_u8(7), Coeff::from_u8(5));
//! // q − 1 is the centred value −1.
//! let minus_one = ring.center(&ring.modulus().wrapping_sub(&Coeff::ONE));
//! assert!(minus_one.is_negative() && *minus_one.magnitude() == Coeff::ONE);
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

mod crt;
mod prime;

use crate::{
    error::{Error, Result, check_dimension},
    poly::Poly,
    zq::{CenteredCoeff, Coeff, Zq},
};
use core::fmt;
use crt::Crt;
use crypto_bigint::{NonZero, U64, U512};
use prime::{AUX_PRIMES, MAX_DEGREE, PrimeNtt};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The polynomial ring `R_q = Z_q[X]/(X^d + 1)` for `d` a power of two and `q` a prime with
/// `q ≡ 5 (mod 8)`, together with its precomputed multi-prime NTT tables. **Public.**
///
/// The tables cost `O(k·d)` words for `k` auxiliary primes: 3 at the 60-bit toy modulus, 4 at
/// the 100-bit 128-bit-set modulus, 6 at the 162-bit succinct modulus. [`fmt::Debug`] prints
/// the degree, the modulus and that count.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
///
/// let params = Params::paper_128()?;
/// let ring = params.ring();
/// assert_eq!(ring.degree(), 4096);
/// assert_eq!(ring.modulus().bit_width_vartime(), 100);
/// assert!(format!("{ring:?}").contains("auxiliary_primes: 4"));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ring {
    degree: usize,
    zq: Zq,
    modulus_bits: u32,
    /// The transforms modulo the auxiliary primes the product bound needs.
    primes: Vec<PrimeNtt>,
    crt: Crt,
    /// How many products of reduced polynomials one transformed sum may hold.
    max_terms: usize,
}

/// A polynomial in NTT form: for each auxiliary prime in turn, the `d` evaluations of its
/// coefficients modulo that prime, in Montgomery form and bit-reversed order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NttPoly(Vec<u64>);

impl Zeroize for NttPoly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for NttPoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for NttPoly {}

impl Ring {
    /// Validates `(d, q)` and precomputes the NTT tables.
    pub(crate) fn new(degree: usize, modulus: Coeff) -> Result<Self> {
        if !degree.is_power_of_two() {
            return Err(Error::DegreeNotPowerOfTwo(degree));
        }
        let zq = Zq::new(modulus).ok_or(Error::ModulusNotPrime)?;
        if !zq.is_probable_prime() {
            return Err(Error::ModulusNotPrime);
        }
        if modulus & Coeff::from_u8(7) != Coeff::from_u8(5) {
            return Err(Error::ModulusNotFiveModEight);
        }
        if degree > MAX_DEGREE {
            return Err(Error::DegreeTooLarge(degree));
        }
        let (count, max_terms) = prime_count(degree, &modulus)?;
        let primes = AUX_PRIMES[..count]
            .iter()
            .map(|&p| PrimeNtt::new(p, degree))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::DegreeTooLarge(degree))?;
        let crt = Crt::new(primes.iter().map(|p| *p.prime()).collect(), &zq);
        Ok(Self {
            degree,
            zq,
            modulus_bits: modulus.bit_width_vartime(),
            primes,
            crt,
            max_terms,
        })
    }

    /// The degree `d`; see the type's example.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// The modulus `q`; see the type's example.
    #[must_use]
    pub fn modulus(&self) -> &Coeff {
        self.zq.modulus()
    }

    /// The centered lift of a reduced coefficient to `(−q/2, q/2]`, as a sign and a magnitude;
    /// see [`CenteredCoeff`]'s example. A value not below `q` gives a meaningless result: call
    /// [`Poly::validate`] on values from outside the crate first.
    #[must_use]
    pub fn center(&self, value: &Coeff) -> CenteredCoeff {
        self.zq.center(value)
    }

    pub(crate) fn zq(&self) -> &Zq {
        &self.zq
    }

    pub(crate) fn modulus_bits(&self) -> u32 {
        self.modulus_bits
    }

    /// Fails unless `len` equals the degree.
    pub(crate) fn check_degree(&self, len: usize) -> Result<()> {
        check_dimension(self.degree, len)
    }

    /// Forward transform modulo every auxiliary prime.
    pub(crate) fn ntt(&self, poly: &Poly) -> Result<NttPoly> {
        self.check_degree(poly.coefficients().len())?;
        let mut values = Vec::with_capacity(self.primes.len() * self.degree);
        for prime in &self.primes {
            let start = values.len();
            values.extend(
                poly.coefficients()
                    .iter()
                    .map(|c| prime.montgomery_residue(c)),
            );
            prime.forward(&mut values[start..]);
        }
        Ok(NttPoly(values))
    }

    /// Inverse transform modulo every auxiliary prime, then Chinese remaindering of each
    /// coefficient, read as an integer of magnitude at most `(P − 1)/2`, and reduction mod `q`.
    ///
    /// The transformed values are inverted in place and overwritten, with the scratch residues,
    /// when the transform returns.
    pub(crate) fn intt(&self, mut poly: NttPoly) -> Poly {
        let values = &mut poly.0;
        for (prime, block) in self.primes.iter().zip(values.chunks_exact_mut(self.degree)) {
            prime.inverse(block);
        }
        let mut scratch = Zeroizing::new([0u64; AUX_PRIMES.len()]);
        let residues = &mut scratch[..self.crt.len()];
        Poly::from_reduced(
            (0..self.degree)
                .map(|i| {
                    for (r, block) in residues.iter_mut().zip(values.chunks_exact(self.degree)) {
                        *r = block[i];
                    }
                    self.crt.reconstruct(residues, &self.zq)
                })
                .collect(),
        )
    }

    /// `Σ_t a_t·b_t` in `R_q` over pairs of transformed polynomials. Products are summed in
    /// transformed form, at most `max_terms` at a time, so that every integer sum stays within
    /// the range the Chinese remaindering recovers.
    pub(crate) fn sum_of_products<'a>(
        &self,
        pairs: impl IntoIterator<Item = (&'a NttPoly, &'a NttPoly)>,
    ) -> Poly {
        let mut acc = self.ntt_zero();
        let (mut terms, mut total) = (0, None);
        for (a, b) in pairs {
            if terms == self.max_terms {
                let part = self.intt(core::mem::replace(&mut acc, self.ntt_zero()));
                total = Some(self.accumulate(total, part));
                terms = 0;
            }
            self.ntt_mul_acc(&mut acc, a, b);
            terms += 1;
        }
        let last = self.intt(acc);
        self.accumulate(total, last)
    }

    /// `total + part`, or `part` alone when there is no total yet.
    fn accumulate(&self, total: Option<Poly>, part: Poly) -> Poly {
        match total {
            None => part,
            Some(total) => Poly::from_reduced(
                total
                    .coefficients()
                    .iter()
                    .zip(part.coefficients())
                    .map(|(x, y)| self.zq.add(x, y))
                    .collect(),
            ),
        }
    }

    /// The zero polynomial in NTT form.
    fn ntt_zero(&self) -> NttPoly {
        NttPoly(vec![0; self.primes.len() * self.degree])
    }

    /// `acc += a ∘ b` in NTT form, prime by prime.
    fn ntt_mul_acc(&self, acc: &mut NttPoly, a: &NttPoly, b: &NttPoly) {
        let d = self.degree;
        for (((prime, out), x), y) in self
            .primes
            .iter()
            .zip(acc.0.chunks_exact_mut(d))
            .zip(a.0.chunks_exact(d))
            .zip(b.0.chunks_exact(d))
        {
            prime.mul_acc(out, x, y);
        }
    }
}

impl fmt::Debug for Ring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ring")
            .field("degree", &self.degree)
            .field("modulus", self.zq.modulus())
            .field("auxiliary_primes", &self.primes.len())
            .finish_non_exhaustive()
    }
}

/// The least number `k` of auxiliary primes whose product `P` satisfies
/// `P − 1 ≥ 2·d·(q−1)²`, and `⌊(P − 1)/(2·d·(q−1)²)⌋`, the number of products of reduced
/// polynomials one sum may hold (saturated at `usize::MAX`).
///
/// With `d ≤ 2^31` and `q < 2^192` the bound is below `2^416`, and all the primes multiply to
/// more than `2^433`, so some `k` always exists.
fn prime_count(degree: usize, modulus: &Coeff) -> Result<(usize, usize)> {
    let q_minus_one: U512 = modulus.wrapping_sub(&Coeff::ONE).resize();
    let bound = q_minus_one
        .wrapping_mul(&q_minus_one)
        .wrapping_mul(&U512::from_u64(
            2 * u64::try_from(degree).map_err(|_| Error::DegreeTooLarge(degree))?,
        ));
    // q ≥ 5 once it is a prime ≡ 5 (mod 8), so the bound is positive.
    let bound = NonZero::new(bound)
        .into_option()
        .ok_or(Error::ModulusNotPrime)?;
    let mut product = U512::ONE;
    for (count, &p) in AUX_PRIMES.iter().enumerate() {
        product = product.wrapping_mul(&U512::from_u64(p));
        let (terms, _) = product.wrapping_sub(&U512::ONE).div_rem_vartime(&bound);
        if terms != U512::ZERO {
            let terms = if terms.bit_width_vartime() > u64::BITS {
                u64::MAX
            } else {
                u64::from(terms.resize::<{ U64::LIMBS }>())
            };
            return Ok((count + 1, usize::try_from(terms).unwrap_or(usize::MAX)));
        }
    }
    Err(Error::DegreeTooLarge(degree))
}

#[cfg(test)]
mod tests {
    use super::Ring;
    use crate::{
        error::Error,
        poly::Poly,
        test_util::{PAPER, TOY, arb_poly, arb_ring_poly, schoolbook_mul},
        zq::Coeff,
    };
    use proptest::prelude::*;
    use std::sync::LazyLock;

    /// A 165-bit prime `≡ 5 (mod 8)` at `d = 64`, the size of a later parameter set.
    static WIDE: LazyLock<Ring> = LazyLock::new(|| {
        Ring::new(
            64,
            Coeff::from_be_hex("0000001ffffffffffffffffffffffb6f7ad7459013513d55"),
        )
        .unwrap()
    });

    /// A 90-bit prime `≡ 5 (mod 8)` at `d = 64` for which three auxiliary primes leave room for
    /// exactly one product per sum, so that every sum of two or more products is reduced in
    /// chunks.
    static CHUNKED: LazyLock<Ring> = LazyLock::new(|| {
        Ring::new(
            64,
            Coeff::from_be_hex("00000000000000000000000002d413c89d1a16065a73cb65"),
        )
        .unwrap()
    });

    #[test]
    fn accessors() {
        let ring = TOY.ring();
        assert_eq!(ring.degree(), 64);
        assert_eq!(*ring.modulus(), Coeff::from_u64(0x0fff_ffdc_9803_a1ad));
        assert_eq!(PAPER.ring().degree(), 4096);
        assert!(format!("{ring:?}").contains("degree: 64"));
    }

    #[test]
    fn center_uses_the_ring_modulus() {
        let ring = TOY.ring();
        let minus_two = ring.zq().reduce_i64(-2);
        let centered = ring.center(&minus_two);
        assert!(centered.is_negative());
        assert_eq!(*centered.magnitude(), Coeff::from_u64(2));
    }

    #[test]
    fn rejects_bad_ring_shapes() {
        let q = Coeff::from_u64(0x0fff_ffdc_9803_a1ad);
        assert_eq!(Ring::new(48, q), Err(Error::DegreeNotPowerOfTwo(48)));
        assert_eq!(Ring::new(0, q), Err(Error::DegreeNotPowerOfTwo(0)));
        // 2^61 − 1 is prime and ≡ 7 (mod 8).
        let mersenne = Coeff::from_u64((1 << 61) - 1);
        assert_eq!(Ring::new(64, mersenne), Err(Error::ModulusNotFiveModEight));
        assert_eq!(
            Ring::new(64, Coeff::from_u64(1 << 40)),
            Err(Error::ModulusNotPrime)
        );
        // 13 is prime and ≡ 5 (mod 8), at any degree the auxiliary primes support.
        assert!(Ring::new(128, Coeff::from_u64(13)).is_ok());
        assert!(Ring::new(1 << 16, Coeff::from_u64(13)).is_ok());
        // 257 = 2^8 + 1 is prime and ≡ 1 (mod 8), the fully splitting case the crate used to
        // require.
        assert_eq!(
            Ring::new(256, Coeff::from_u64(257)),
            Err(Error::ModulusNotFiveModEight)
        );
        assert_eq!(
            Ring::new(1 << 32, Coeff::from_u64(13)),
            Err(Error::DegreeTooLarge(1 << 32))
        );
    }

    /// The number of auxiliary primes follows `2·d·(q−1)²`: about `2^127` at the toy set
    /// (three 62-bit primes), `2^213` at the 128-bit set (four), `2^337` and `2^343` for a
    /// 165-bit modulus at `d = 64` and `d = 4096` (six).
    #[test]
    fn auxiliary_prime_count_follows_the_bound() {
        assert_eq!(TOY.ring().primes.len(), 3);
        assert_eq!(PAPER.ring().primes.len(), 4);
        assert_eq!(WIDE.primes.len(), 6);
        let wide_4096 = Ring::new(4096, *WIDE.modulus()).unwrap();
        assert_eq!(wide_4096.primes.len(), 6);
        assert_eq!(WIDE.modulus().bit_width_vartime(), 165);
        assert_eq!(CHUNKED.primes.len(), 3);
        assert_eq!(CHUNKED.max_terms, 1);
        assert!(TOY.ring().max_terms > 1 << 40 && PAPER.ring().max_terms > 1 << 30);
    }

    #[test]
    fn x_times_x_to_the_d_minus_one_is_minus_one() {
        let ring = TOY.ring();
        let monomial = |i: usize| {
            let mut c = vec![Coeff::ZERO; ring.degree()];
            c[i] = Coeff::ONE;
            Poly::new(c, ring).unwrap()
        };
        let product = monomial(1).mul(&monomial(ring.degree() - 1), ring).unwrap();
        let mut expected = vec![Coeff::ZERO; ring.degree()];
        expected[0] = ring.zq().reduce_i64(-1);
        assert_eq!(product.coefficients(), expected.as_slice());
    }

    #[test]
    fn ntt_rejects_wrong_degree() {
        let short = Poly::zero(TOY.ring());
        assert_eq!(
            PAPER.ring().ntt(&short),
            Err(Error::DimensionMismatch {
                expected: 4096,
                found: 64
            })
        );
    }

    /// The extreme integer products: with every coefficient `q − 1`, coefficient `d − 1` of the
    /// product is `d·(q−1)²` and coefficient 0 is `−(d−2)·(q−1)²`, the edges of the range the
    /// Chinese remaindering must recover; three such products overflow one sum at `CHUNKED`.
    #[test]
    fn extreme_products_match_schoolbook() {
        for ring in [TOY.ring(), PAPER.ring(), &*WIDE, &*CHUNKED] {
            let top = Poly::new(
                vec![ring.modulus().wrapping_sub(&Coeff::ONE); ring.degree()],
                ring,
            )
            .unwrap();
            assert_eq!(
                top.mul(&top, ring).unwrap(),
                schoolbook_mul(&top, &top, ring)
            );
            let transformed = ring.ntt(&top).unwrap();
            let square = top.mul(&top, ring).unwrap();
            let tripled = square
                .add(&square, ring)
                .unwrap()
                .add(&square, ring)
                .unwrap();
            assert_eq!(
                ring.sum_of_products([(&transformed, &transformed); 3]),
                tripled
            );
        }
    }

    proptest! {
        #[test]
        fn ntt_roundtrip_toy(a in arb_poly(&TOY)) {
            let ring = TOY.ring();
            prop_assert_eq!(ring.intt(ring.ntt(&a).unwrap()), a);
        }

        #[test]
        fn ntt_mul_matches_schoolbook_toy(a in arb_poly(&TOY), b in arb_poly(&TOY)) {
            let ring = TOY.ring();
            prop_assert_eq!(a.mul(&b, ring).unwrap(), schoolbook_mul(&a, &b, ring));
        }

        #[test]
        fn ntt_mul_matches_schoolbook_wide(a in arb_ring_poly(&WIDE), b in arb_ring_poly(&WIDE)) {
            prop_assert_eq!(a.mul(&b, &WIDE).unwrap(), schoolbook_mul(&a, &b, &WIDE));
        }

        /// Sums of up to five products at `CHUNKED`, one reduction per product, equal the sum of
        /// schoolbook products.
        #[test]
        fn chunked_sums_match_schoolbook(
            pairs in prop::collection::vec((arb_ring_poly(&CHUNKED), arb_ring_poly(&CHUNKED)), 0..5),
        ) {
            let ring = &*CHUNKED;
            let transformed: Vec<_> = pairs
                .iter()
                .map(|(a, b)| (ring.ntt(a).unwrap(), ring.ntt(b).unwrap()))
                .collect();
            let expected = pairs.iter().fold(Poly::zero(ring), |acc, (a, b)| {
                acc.add(&schoolbook_mul(a, b, ring), ring).unwrap()
            });
            prop_assert_eq!(ring.sum_of_products(transformed.iter().map(|(a, b)| (a, b))), expected);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2))]

        #[test]
        fn ntt_mul_matches_schoolbook_paper(a in arb_poly(&PAPER), b in arb_poly(&PAPER)) {
            let ring = PAPER.ring();
            prop_assert_eq!(a.mul(&b, ring).unwrap(), schoolbook_mul(&a, &b, ring));
        }
    }
}
