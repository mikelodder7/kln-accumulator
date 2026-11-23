// SPDX-License-Identifier: MIT OR Apache-2.0
//! The coefficient type and arithmetic in `Z_q` through crypto-bigint's Montgomery form.
//!
//! Every coefficient in the crate is a [`Coeff`], a 192-bit unsigned integer, so the public
//! types are not generic over the modulus size. Arithmetic modulo `q` is crate-internal; the
//! public face is [`crate::lattice::Ring::center`] and its result, [`CenteredCoeff`].

use crypto_bigint::{
    NonZero, Odd, U192, U384, U512,
    modular::{FixedMontyForm, FixedMontyParams},
};
use ctutils::{Choice, CtGt, CtSelect};

/// The integer type of every coefficient in the crate.
///
/// It is fixed-width so that the public types stay non-generic. 192 bits covers the largest
/// modulus the paper uses (about `2^162`, for the ℓ-succinct set of Section 4). Its methods are
/// those of `crypto_bigint::U192`.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::Coeff;
///
/// let params = Params::toy()?;
/// let q = params.ring().modulus();
/// assert_eq!(Coeff::BYTES, 24);
/// assert!(Coeff::from_u64(5) < *q);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub type Coeff = U192;

/// Montgomery parameters for a [`Coeff`] modulus.
type MontyParams = FixedMontyParams<{ Coeff::LIMBS }>;

/// Montgomery-form element for a [`Coeff`] modulus.
type Monty = FixedMontyForm<{ Coeff::LIMBS }>;

/// The representative of a residue in `(−q/2, q/2]`, as a sign and a magnitude, from
/// [`crate::lattice::Ring::center`]. **Public.**
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::Coeff;
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let three = ring.center(&Coeff::from_u64(3));
/// assert!(!three.is_negative());
/// assert_eq!(*three.magnitude(), Coeff::from_u64(3));
/// let minus_three = ring.center(&ring.modulus().wrapping_sub(&Coeff::from_u64(3)));
/// assert!(minus_three.is_negative());
/// assert_eq!(*minus_three.magnitude(), Coeff::from_u64(3));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CenteredCoeff {
    negative: bool,
    magnitude: Coeff,
}

impl CenteredCoeff {
    /// Whether the representative is negative; see the type's example.
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// The absolute value of the representative, at most `⌊q/2⌋`; see the type's example.
    #[must_use]
    pub fn magnitude(&self) -> &Coeff {
        &self.magnitude
    }

    /// The square of the magnitude, widened so that sums over any realistic vector length cannot
    /// overflow (`2^382` per term against a `2^512` capacity).
    pub(crate) fn magnitude_squared(&self) -> U512 {
        let square: U384 = self.magnitude.concatenating_square();
        square.resize()
    }
}

/// Arithmetic modulo an odd `q`. Reduced values are kept in `[0, q)`; values tagged as
/// Montgomery form represent `x·R mod q` with `R = 2^192`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Zq {
    monty: MontyParams,
    half: Coeff,
}

impl Zq {
    /// Builds the context for an odd modulus, or `None` when `q` is even.
    pub(crate) fn new(modulus: Coeff) -> Option<Self> {
        Odd::new(modulus).into_option().map(|odd| Self {
            monty: MontyParams::new_vartime(odd),
            half: modulus.shr_vartime(1),
        })
    }

    /// The modulus `q`.
    pub(crate) fn modulus(&self) -> &Coeff {
        self.monty.modulus().as_ref()
    }

    fn non_zero(&self) -> &NonZero<Coeff> {
        self.monty.modulus().as_nz_ref()
    }

    /// Whether `value` lies in `[0, q)`.
    pub(crate) fn is_reduced(&self, value: &Coeff) -> bool {
        value < self.modulus()
    }

    /// `a + b mod q` for reduced inputs; also valid on Montgomery forms.
    pub(crate) fn add(&self, a: &Coeff, b: &Coeff) -> Coeff {
        a.add_mod(b, self.non_zero())
    }

    /// `a − b mod q` for reduced inputs; also valid on Montgomery forms.
    pub(crate) fn sub(&self, a: &Coeff, b: &Coeff) -> Coeff {
        a.sub_mod(b, self.non_zero())
    }

    /// `−a mod q` for a reduced input; also valid on Montgomery forms.
    pub(crate) fn neg(&self, a: &Coeff) -> Coeff {
        a.neg_mod(self.non_zero())
    }

    /// Montgomery product `a·b·R⁻¹ mod q`. With one operand in Montgomery form and the other
    /// reduced, the result is the reduced product.
    pub(crate) fn mont_mul(&self, a: &Coeff, b: &Coeff) -> Coeff {
        Monty::from_montgomery(*a, &self.monty)
            .mul(&Monty::from_montgomery(*b, &self.monty))
            .to_montgomery()
    }

    /// Converts a reduced value to Montgomery form.
    pub(crate) fn montgomery(&self, a: &Coeff) -> Coeff {
        Monty::new(a, &self.monty).to_montgomery()
    }

    /// `base^exponent mod q` for a reduced base, returned reduced. Variable time in the
    /// exponent, which is only ever public.
    #[cfg(test)]
    pub(crate) fn pow(&self, base: &Coeff, exponent: &Coeff) -> Coeff {
        Monty::new(base, &self.monty)
            .pow_vartime(exponent)
            .retrieve()
    }

    /// Reduces a word modulo `q`, dividing only when `q` is below the word.
    pub(crate) fn reduce_u64(&self, value: u64) -> Coeff {
        self.reduce_u128(u128::from(value))
    }

    /// `value mod q`. A value below `q` is returned as it is; the division is reached only when
    /// `q` is small enough for `value` to exceed it.
    pub(crate) fn reduce_u128(&self, value: u128) -> Coeff {
        let value = Coeff::from_u128(value);
        if self.is_reduced(&value) {
            value
        } else {
            value.rem(self.non_zero())
        }
    }

    /// Reduces a signed integer modulo `q`, selecting the negation by mask rather than by a
    /// branch on the sign.
    pub(crate) fn reduce_i64(&self, value: i64) -> Coeff {
        let magnitude = self.reduce_u64(value.unsigned_abs());
        let negative = Choice::from_u64_lsb(value.cast_unsigned() >> 63);
        magnitude.ct_select(&self.neg(&magnitude), negative)
    }

    /// The centered lift of a reduced value to `(−q/2, q/2]`, selecting the magnitude by mask
    /// rather than by a branch on the comparison with `q/2`.
    pub(crate) fn center(&self, value: &Coeff) -> CenteredCoeff {
        let negative = value.ct_gt(&self.half);
        CenteredCoeff {
            negative: negative.to_bool(),
            magnitude: value.ct_select(&self.modulus().wrapping_sub(value), negative),
        }
    }

    /// Miller–Rabin with the first twenty primes as bases.
    ///
    /// Deterministic for `q < 3.3·10^24` (the first thirteen prime bases suffice there); above
    /// that a composite passes with probability at most `4^-20` per non-adversarial input.
    pub(crate) fn is_probable_prime(&self) -> bool {
        const BASES: [u64; 20] = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        ];
        let modulus = self.modulus();
        if *modulus <= Coeff::from_u64(BASES[BASES.len() - 1]) {
            return BASES.iter().any(|&p| Coeff::from_u64(p) == *modulus);
        }
        let q_minus_one = modulus.wrapping_sub(&Coeff::ONE);
        let two_adicity = q_minus_one.trailing_zeros_vartime();
        let odd_part = q_minus_one.shr_vartime(two_adicity);
        let one = Monty::one(&self.monty);
        let minus_one = one.neg();
        BASES.iter().all(|&base| {
            let mut x = Monty::new(&Coeff::from_u64(base), &self.monty).pow_vartime(&odd_part);
            if x == one || x == minus_one {
                return true;
            }
            (1..two_adicity).any(|_| {
                x = x.square();
                x == minus_one
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Coeff, Zq};
    use proptest::prelude::*;

    const TOY_Q: u64 = 0x0fff_ffdc_9803_a1ad;

    fn toy() -> Zq {
        Zq::new(Coeff::from_u64(TOY_Q)).unwrap()
    }

    #[test]
    fn even_modulus_is_rejected() {
        assert!(Zq::new(Coeff::from_u64(1 << 20)).is_none());
    }

    #[test]
    fn modulus_and_range_check() {
        let zq = toy();
        assert_eq!(*zq.modulus(), Coeff::from_u64(TOY_Q));
        assert!(zq.is_reduced(&Coeff::from_u64(TOY_Q - 1)));
        assert!(!zq.is_reduced(&Coeff::from_u64(TOY_Q)));
    }

    #[test]
    fn center_boundaries() {
        let zq = toy();
        let half = (TOY_Q - 1) / 2;
        let at_half = zq.center(&Coeff::from_u64(half));
        assert!(!at_half.is_negative());
        assert_eq!(*at_half.magnitude(), Coeff::from_u64(half));
        let past_half = zq.center(&Coeff::from_u64(half + 1));
        assert!(past_half.is_negative());
        assert_eq!(*past_half.magnitude(), Coeff::from_u64(half));
        let minus_one = zq.center(&Coeff::from_u64(TOY_Q - 1));
        assert!(minus_one.is_negative());
        assert_eq!(*minus_one.magnitude(), Coeff::ONE);
        assert_eq!(*zq.center(&Coeff::ZERO).magnitude(), Coeff::ZERO);
    }

    #[test]
    fn primality_known_values() {
        let primes: [u128; 6] = [
            73,
            0x1fff_ffff_ffff_ffff,
            (1 << 89) - 1,
            (1 << 127) - 1,
            TOY_Q as u128,
            97,
        ];
        for p in primes {
            assert!(
                Zq::new(Coeff::from_u128(p)).unwrap().is_probable_prime(),
                "{p}"
            );
        }
        // 561 is a Carmichael number, 3215031751 a strong pseudoprime to bases 2, 3, 5, 7,
        // 3825123056546413051 a strong pseudoprime to the first nine prime bases, and the last a
        // product of two 61-bit primes.
        let composites: [u128; 6] = [
            1,
            9,
            561,
            3_215_031_751,
            3_825_123_056_546_413_051,
            0x1fff_ffff_ffff_ffff_u128 * 0x1fff_ffff_ffff_ffe7,
        ];
        for c in composites {
            assert!(
                !Zq::new(Coeff::from_u128(c)).unwrap().is_probable_prime(),
                "{c}"
            );
        }
        assert!(Zq::new(Coeff::from_u64(3)).unwrap().is_probable_prime());
    }

    proptest! {
        #[test]
        fn arithmetic_matches_u128(a in 0..TOY_Q, b in 0..TOY_Q, s in any::<i64>()) {
            let zq = toy();
            let q = u128::from(TOY_Q);
            let (ca, cb) = (Coeff::from_u64(a), Coeff::from_u64(b));
            let reduce = |x: u128| Coeff::from_u128(x % q);
            prop_assert_eq!(zq.add(&ca, &cb), reduce(u128::from(a) + u128::from(b)));
            prop_assert_eq!(zq.sub(&ca, &cb), reduce(u128::from(a) + q - u128::from(b)));
            prop_assert_eq!(zq.neg(&ca), reduce(q - u128::from(a)));
            prop_assert_eq!(
                zq.mont_mul(&zq.montgomery(&ca), &cb),
                reduce(u128::from(a) * u128::from(b))
            );
            let expected = i128::from(s).rem_euclid(i128::try_from(q).unwrap());
            prop_assert_eq!(zq.reduce_i64(s), Coeff::from_u128(u128::try_from(expected).unwrap()));
            let word = s.cast_unsigned();
            prop_assert_eq!(zq.reduce_u64(word), Coeff::from_u128(u128::from(word) % q));
        }

        #[test]
        fn pow_matches_repeated_multiplication(a in 0..TOY_Q, e in 0u64..64) {
            let zq = toy();
            let q = u128::from(TOY_Q);
            let expected = (0..e).fold(1u128, |acc, _| acc * u128::from(a) % q);
            prop_assert_eq!(
                zq.pow(&Coeff::from_u64(a), &Coeff::from_u64(e)),
                Coeff::from_u128(expected)
            );
        }

        #[test]
        fn magnitude_squared_is_exact(a in 0..TOY_Q) {
            let zq = toy();
            let centered = zq.center(&Coeff::from_u64(a));
            let m = centered.magnitude().as_words()[0];
            prop_assert_eq!(
                centered.magnitude_squared(),
                crypto_bigint::U512::from_u128(u128::from(m) * u128::from(m))
            );
        }
    }
}
