// SPDX-License-Identifier: MIT OR Apache-2.0
//! The amortisation challenges `c₁, …, c_r` of a LaBRADOR level at ring degree 64 (ePrint
//! 2022/1341, Section 2, "Challenge Space", and Section 5.2, "Amortizing").
//!
//! # The set
//!
//! A candidate has [`ONES`] coefficients `±1`, [`TWOS`] coefficients `±2` and the rest zero, and
//! is kept only when the operator norm of multiplication by it is at most [`OPERATOR_NORM`]. Its
//! squared `ℓ₂` norm is `ONES + 4·TWOS = 80` ([`NORM_SQUARED`], the variance `τ` of Section
//! 5.4; Section 2 calls the corresponding 71 of its own set the `ℓ₂` norm). Theorem 5.1 needs
//! `‖c‖_op ≤ T` for every challenge and invertible differences of distinct challenges, and its
//! proof (Appendix B) needs a set large enough that a non-zero quadratic in one uniform
//! challenge vanishes with probability at most `2/|C| ≤ 2·2^{−128}`.
//!
//! Deliberate difference from the paper. Section 2 uses 31 coefficients `±1`, 10 coefficients
//! `±2` and 23 zeros with `T = 15`, and says the set has "more than 2^128 elements". That counts
//! the candidates (`2^{128.09}`) before the operator-norm rejection; about 18% of them pass it,
//! so the set the protocol samples from has about `2^{125.6}` elements. The constants here, 32 × `±1`, 12 × `±2`, 20 zeros and `T = 16`, give `2^{132.42}` candidates of
//! which about 18% pass this module's test, about `2^{129.9}` challenges. The price is a larger
//! `T`: every `T²` in the level parameters grows by `(16/15)² ≈ 1.14` against the paper's.
//!
//! How the sizes were obtained: the candidate count is the exact multinomial
//! `64!/(z!·o!·t!)·2^{o+t}` for `z` zeros, `o` ones and `t` twos. The acceptance rates are
//! Monte-Carlo estimates over 40,000 uniform candidates each, by the true operator norm (the
//! largest `|c(ζ)|` over the 64 primitive 128th roots of unity, in floating point) and by this
//! module's exact test: 0.180 / 0.170 for the paper's set, 0.191 / 0.180 for this one. The test `challenge_space_has_2_128_elements` re-derives the
//! claim that matters, `|C| ≥ 2^{128}` under the exact test, from the exact candidate count and a
//! sample of this module's own sampler, with a Chernoff bound on the acceptance rate.
//!
//! # Sampling
//!
//! Candidates are drawn as a sign word first, then an inside-out shuffle placing the non-zero coefficients at positions read from the
//! stream as bytes masked to `d − 1`, rejecting positions beyond the current index. Every
//! arrangement and every sign pattern is equally likely, so the accepted challenge is uniform on
//! `C`.
//!
//! The operator-norm test is exact (no counterpart in the paper, which only says "operator
//! norm at most 15"): a candidate passes when
//! `‖c^{64}‖₁ ≤ T^{64}` in exact integer arithmetic. That implies `|c(ζ)| ≤ T` at every root,
//! because `|c(ζ)|^{64} = |c^{64}(ζ)| ≤ ‖c^{64}‖₁`, and is stricter than `|c(ζ)| ≤ T` by at most
//! the factor `64^{1/128} ≈ 1.033` (`‖f‖₁ ≤ √64·max|f(ζ)|` for `f = c^{64}`).
//!
//! # Invertible differences
//!
//! Section 2 cites a corollary of an earlier work for the invertibility of `c − c'`. This module
//! relies on a direct argument instead. For a prime `q ≡ 5 (mod 8)` (which `Ring::new` enforces)
//! there is an `r` with `r² = −1`, and `X^{64} + 1 = (X^{32} − r)(X^{32} + r)` with both factors
//! irreducible, because `r` has order 4 in `Z_q^×` and `(q − 1)/4` is odd. Write
//! `y = y₀ + X^{32}·y₁` with `y₀, y₁` of degree below 32. Then `y` is a zero divisor only if
//! `y₀ + r·y₁ = 0` or `y₀ − r·y₁ = 0` modulo `q`, coefficient by coefficient, which forces
//! `y₀,ᵢ² + y₁,ᵢ² ≡ 0 (mod q)` for every `i`. For `y ≠ 0` some `i` has `0 < y₀,ᵢ² + y₁,ᵢ² ≤
//! 2‖y‖∞²`, so `2‖y‖∞² < q` rules this out. Differences of two challenges have
//! `‖y‖∞ ≤ 2·MAX_MAGNITUDE = 4`, so the condition is `32 < q`, which
//! [`differences_are_invertible`] states and level parameter derivation enforces.

use super::relation::Wide;
use crate::{
    error::Result,
    poly::Poly,
    proof::challenge::{Coefficients, DEGREE, power_norm_at_most},
    ring::Ring,
};
use sha3::{Shake256Reader, digest::XofReader};

/// The number of coefficients `±1` (Section 2 uses 31).
pub(crate) const ONES: usize = 32;
/// The number of coefficients `±2` (Section 2 uses 10); chosen so that
/// `|C| ≥ 2^{128}`, see the module documentation.
pub(crate) const TWOS: usize = 12;
/// The magnitude of the [`TWOS`] coefficients, the largest of a challenge.
pub(crate) const MAX_MAGNITUDE: u64 = 2;
/// `T`, the bound on the operator norm (Section 2 uses 15).
pub(crate) const OPERATOR_NORM: u64 = 16;
/// `‖c‖² = ONES + MAX_MAGNITUDE²·TWOS`, the paper's `τ` (Section 5.4).
pub(crate) const NORM_SQUARED: u64 = ONES as u64 + MAX_MAGNITUDE * MAX_MAGNITUDE * TWOS as u64;

/// Whether every difference of two distinct challenges is invertible in `R_q` for a prime
/// `q ≡ 5 (mod 8)`: the differences have `‖y‖∞ ≤ 2·MAX_MAGNITUDE`, and `2‖y‖∞² < q` suffices by
/// the argument of the module documentation.
pub(crate) fn differences_are_invertible(q: &Wide) -> bool {
    let bound = 2 * MAX_MAGNITUDE;
    Wide::from_u64(2 * bound * bound) < *q
}

/// Draws candidates from `reader` until one passes the operator-norm condition. Fails only if
/// `ring` does not have degree 64.
pub(crate) fn sample(reader: &mut Shake256Reader, ring: &Ring) -> Result<Poly> {
    ring.check_degree(DEGREE)?;
    loop {
        let c = candidate(reader);
        if power_norm_at_most(&c, OPERATOR_NORM) {
            return Ok(Poly::from_signed(&c, ring));
        }
    }
}

/// One candidate: `ONES + TWOS` sign bits, then the inside-out shuffle of the module
/// documentation.
pub(crate) fn candidate(reader: &mut Shake256Reader) -> Coefficients {
    let mut sign_bytes = [0u8; 8];
    reader.read(&mut sign_bytes[..(ONES + TWOS).div_ceil(8)]);
    let mut signs = u64::from_le_bytes(sign_bytes);
    let mut c = [0i64; DEGREE];
    let mut k = DEGREE - ONES - TWOS;
    let mut byte = [0u8; 1];
    while k < DEGREE {
        reader.read(&mut byte);
        let b = usize::from(byte[0]) & (DEGREE - 1);
        if b <= k {
            c[k] = c[b];
            let magnitude = if k < DEGREE - TWOS {
                1
            } else {
                MAX_MAGNITUDE.cast_signed()
            };
            c[b] = if signs & 1 == 1 {
                -magnitude
            } else {
                magnitude
            };
            signs >>= 1;
            k += 1;
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MAGNITUDE, ONES, OPERATOR_NORM, TWOS, candidate, differences_are_invertible, sample,
    };
    use crate::{
        proof::{
            challenge::{DEGREE, power_norm_at_most},
            labrador::relation::Wide,
        },
        sample::{DomainLabel, Seed, xof},
        test_util::TOY,
    };
    use crypto_bigint::{NonZero, U512};

    const ZEROS: usize = DEGREE - ONES - TWOS;

    fn reader(seed: u8) -> sha3::Shake256Reader {
        xof(
            &Seed::from([seed; 32]),
            DomainLabel::from(&b"test/labrador/challenge"[..]),
        )
    }

    /// Every sample has [`ONES`] coefficients `±1`, [`TWOS`] coefficients `±2` and the rest zero,
    /// passes the operator-norm test, and is reproduced by the same stream.
    #[test]
    fn samples_have_the_set_shape() {
        let ring = TOY.ring();
        let (mut stream, mut again) = (reader(1), reader(1));
        for _ in 0..32 {
            let c = sample(&mut stream, ring).unwrap();
            assert_eq!(c, sample(&mut again, ring).unwrap());
            let integers: Vec<i64> = c
                .coefficients()
                .iter()
                .map(|x| {
                    let centred = ring.center(x);
                    let m = i64::try_from(centred.magnitude().as_words()[0]).unwrap();
                    if centred.is_negative() { -m } else { m }
                })
                .collect();
            let count = |m: i64| integers.iter().filter(|x| x.abs() == m).count();
            let large = MAX_MAGNITUDE.cast_signed();
            assert_eq!((count(1), count(large), count(0)), (ONES, TWOS, ZEROS));
            assert!(power_norm_at_most(
                &integers.try_into().unwrap(),
                OPERATOR_NORM
            ));
        }
    }

    /// `|C| ≥ 2^{128}` under the exact operator-norm test. The candidates number exactly
    /// `N = 64!/(20!·32!·12!)·2^{44}`, and the sampler's candidates are uniform among them, so
    /// `|C| = N·p` for the acceptance rate `p`. `|C| < 2^{128}` means `p < p₀ = 2^{128}/N`; with
    /// `2^{e} ≤ N` this is at most `2^{128−e}`, used as `p₀`. Then `k` acceptances among `n`
    /// candidates with `k/n > p₀` occur with probability at most `exp(−n·D(k/n ‖ p₀))` (the
    /// Chernoff bound, `D` the binary relative entropy), and the test asks that to be below
    /// `2^{−64}`.
    #[test]
    fn challenge_space_has_2_128_elements() {
        let factorial =
            |n: usize| (1..=n as u64).fold(U512::ONE, |acc, k| acc.wrapping_mul(&U512::from(k)));
        let denominator = factorial(ZEROS)
            .wrapping_mul(&factorial(ONES))
            .wrapping_mul(&factorial(TWOS));
        let candidates = factorial(DEGREE)
            .wrapping_div(&NonZero::new(denominator).unwrap())
            .shl_vartime((ONES + TWOS) as u32);
        let width = candidates.bit_width_vartime();
        let floor_log = width - 1;
        assert_eq!(floor_log, 132);
        let log_candidates = (candidates.shr_vartime(width - 53).as_words()[0] as f64).log2()
            + f64::from(width - 53);

        let n = 1000;
        let mut stream = reader(2);
        let k = (0..n)
            .filter(|_| power_norm_at_most(&candidate(&mut stream), OPERATOR_NORM))
            .count();
        let rate = k as f64 / n as f64;
        let p0 = 2f64.powi(128 - floor_log as i32);
        assert!(rate > p0, "acceptance {k}/{n} ≤ {p0}");
        let divergence = rate * (rate / p0).ln() + (1.0 - rate) * ((1.0 - rate) / (1.0 - p0)).ln();
        let confidence_bits = n as f64 * divergence / 2f64.ln();
        println!(
            "amortisation challenges: 2^{log_candidates:.2} candidates, {k}/{n} accepted, \
             |C| ≈ 2^{:.1}; |C| < 2^128 would show this with probability below 2^-{confidence_bits:.0}",
            log_candidates + rate.log2()
        );
        assert!(confidence_bits >= 64.0);
    }

    /// The invertibility condition `2·(2·MAX_MAGNITUDE)² < q` holds exactly from `q = 33` on, and
    /// at the toy modulus.
    #[test]
    fn invertibility_needs_q_above_32() {
        assert!(!differences_are_invertible(&Wide::from_u64(29)));
        assert!(!differences_are_invertible(&Wide::from_u64(32)));
        assert!(differences_are_invertible(&Wide::from_u64(37)));
        assert!(differences_are_invertible(&TOY.ring().modulus().resize()));
    }
}
