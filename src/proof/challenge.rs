// SPDX-License-Identifier: MIT OR Apache-2.0
//! The challenge space `C` of Appendix D.2.1, equation D.3 (paper lines 2709–2725):
//!
//! `C = {c ∈ R_q : ‖c‖_∞ ≤ κ, σ(c) = c, ‖c^{2k}‖₁^{1/(2k)} ≤ ν}`,
//!
//! with the `d = 64` row of Figure 2 (lines 2625–2640): `κ = 8`, `ν = 140`, `k = 32`, and
//! `|C| ≥ 2^129`.
//!
//! Candidates have coefficients `c_0, …, c_{d/2−1}` uniform in `[−κ, κ]`, `c_{d/2} = 0` and
//! `c_{d−i} = −c_i`, which is exactly the condition `σ(c) = c` for `σ: X ↦ X⁻¹ = −X^{d−1}`.
//! The set also requires the operator-norm condition, so a candidate is kept only when `‖c^{2k}‖₁ ≤ ν^{2k}` holds in exact integer arithmetic in `Z[X]/(X^d + 1)`,
//! and the next candidate is drawn from the same stream otherwise. The condition is what lets
//! the lemma cited at line 2720 bound `‖c·r‖ ≤ ν·‖r‖` (line 2720), on which every rejection-sampling
//! bound of D.2.3 rests.

use crate::{error::Result, poly::Poly, ring::Ring};
use crypto_bigint::U640;
use sha3::{Shake256Reader, digest::XofReader};

/// The ring degree the challenge space is defined for (Figure 2, first row).
pub(crate) const DEGREE: usize = 64;
/// `κ`, the bound on every coefficient.
pub(crate) const KAPPA: i64 = 8;
/// `ν`, the bound on the operator norm.
pub(crate) const NU: u64 = 140;
/// `k`: the norm condition is on `c^{2k}`.
pub(crate) const NORM_POWER: u32 = 32;

/// Two's-complement integers modulo `2^640`. Every coefficient of `c^{2^j}` for `j ≤ 6` is at
/// most `‖c‖₁^{64} ≤ (63·κ)^{64} < 2^575` in magnitude, and so is every partial sum while it is
/// computed, so wrapping arithmetic modulo `2^640` is exact on them.
type Wide = U640;

/// A challenge `c ∈ C` as integer coefficients, constant term first.
pub(crate) type Coefficients = [i64; DEGREE];

/// Draws candidates from `reader` until one passes the norm condition, and returns it as an
/// element of `R_q`. Fails only if `ring` does not have degree 64.
pub(crate) fn sample(reader: &mut Shake256Reader, ring: &Ring) -> Result<Poly> {
    ring.check_degree(DEGREE)?;
    loop {
        let candidate = candidate(reader);
        if passes_norm_condition(&candidate) {
            return Ok(Poly::from_signed(&candidate, ring));
        }
    }
}

/// One `σ`-fixed candidate with coefficients in `[−κ, κ]`: each of `c_0, …, c_{d/2−1}` is the
/// first byte of the stream whose low five bits are below `2κ + 1 = 17`, minus `κ`.
pub(crate) fn candidate(reader: &mut Shake256Reader) -> Coefficients {
    // 2κ + 1 = 17, so its low byte is the whole value.
    const RANGE: u8 = (2 * KAPPA + 1).to_le_bytes()[0];
    let mut c = [0i64; DEGREE];
    let half = DEGREE / 2;
    let mut filled = 0;
    let mut byte = [0u8; 1];
    while filled < half {
        reader.read(&mut byte);
        let value = byte[0] & 0x1f;
        if value < RANGE {
            c[filled] = i64::from(value) - KAPPA;
            filled += 1;
        }
    }
    for i in 1..half {
        c[DEGREE - i] = -c[i];
    }
    c
}

/// Whether `‖c^{2k}‖₁ ≤ ν^{2k}`, computed exactly: `c^{2k}` by `log₂(2k)` negacyclic squarings
/// over the integers.
pub(crate) fn passes_norm_condition(c: &Coefficients) -> bool {
    power_norm_at_most(c, NU)
}

/// Whether `‖c^{2k}‖₁ ≤ bound^{2k}` for `k = 32`, computed exactly. It implies that the operator
/// norm of multiplication by `c`, the largest `|c(ζ)|` over the primitive `2d`-th roots of unity
/// `ζ`, is at most `bound`, because `|c(ζ)|^{2k} = |c^{2k}(ζ)| ≤ ‖c^{2k}‖₁`. The squarings stay
/// exact for every `c` with `‖c‖₁ ≤ 63·κ`.
pub(crate) fn power_norm_at_most(c: &Coefficients, bound: u64) -> bool {
    let mut power: Vec<Wide> = c.iter().map(|&x| signed(x)).collect();
    let mut exponent = 1;
    while exponent < 2 * NORM_POWER {
        power = square(&power);
        exponent *= 2;
    }
    let l1 = power
        .iter()
        .fold(Wide::ZERO, |acc, x| acc.wrapping_add(&magnitude(x)));
    l1 <= bound_power(bound)
}

/// `bound^{2k}`; `ν^{2k}` is about `2^456`.
fn bound_power(bound: u64) -> Wide {
    (0..2 * NORM_POWER).fold(Wide::ONE, |acc, _| acc.wrapping_mul(&Wide::from_u64(bound)))
}

/// `x` in two's complement modulo `2^640`.
fn signed(x: i64) -> Wide {
    let magnitude = Wide::from_u64(x.unsigned_abs());
    if x < 0 {
        magnitude.wrapping_neg()
    } else {
        magnitude
    }
}

/// `|x|` for a two's-complement value.
fn magnitude(x: &Wide) -> Wide {
    if x.bit_vartime(Wide::BITS - 1) {
        x.wrapping_neg()
    } else {
        *x
    }
}

/// `a²` in `Z[X]/(X^d + 1)`.
fn square(a: &[Wide]) -> Vec<Wide> {
    let d = a.len();
    let mut out = vec![Wide::ZERO; d];
    for (i, x) in a.iter().enumerate() {
        if *x == Wide::ZERO {
            continue;
        }
        for (j, y) in a.iter().enumerate() {
            let product = x.wrapping_mul(y);
            if i + j < d {
                out[i + j] = out[i + j].wrapping_add(&product);
            } else {
                out[i + j - d] = out[i + j - d].wrapping_sub(&product);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{DEGREE, KAPPA, candidate, passes_norm_condition, sample, signed, square};
    use crate::{
        sample::{DomainLabel, Seed, xof},
        test_util::TOY,
        zq::Coeff,
    };

    fn reader(seed: u8) -> sha3::Shake256Reader {
        xof(
            &Seed::from([seed; 32]),
            DomainLabel::from(&b"test/challenge"[..]),
        )
    }

    /// Every sampled challenge is `σ`-fixed, has `‖c‖_∞ ≤ κ`, passes the exact norm test, and
    /// is reproduced by the same stream (C43).
    #[test]
    fn sampled_challenges_lie_in_the_challenge_space() {
        let ring = TOY.ring();
        let mut stream = reader(1);
        let mut again = reader(1);
        let mut other = reader(2);
        for _ in 0..64 {
            let c = sample(&mut stream, ring).unwrap();
            assert_eq!(c.sigma_minus_one(ring).unwrap(), c);
            assert!(c.norm_inf(ring) <= Coeff::from_u64(KAPPA as u64));
            let integers: Vec<i64> = c
                .coefficients()
                .iter()
                .map(|x| {
                    let centred = ring.center(x);
                    let m = i64::try_from(centred.magnitude().as_words()[0]).unwrap();
                    if centred.is_negative() { -m } else { m }
                })
                .collect();
            assert!(passes_norm_condition(&integers.try_into().unwrap()));
            assert_eq!(sample(&mut again, ring).unwrap(), c);
            assert_ne!(sample(&mut other, ring).unwrap(), c);
        }
    }

    /// The paper chooses `ν` so that at least 99% of candidates pass (line 2722); the measured
    /// rate over 2000 candidates is reported.
    #[test]
    fn norm_condition_passes_almost_all_candidates() {
        let mut stream = reader(3);
        let total = 2000;
        let passed = (0..total)
            .filter(|_| passes_norm_condition(&candidate(&mut stream)))
            .count();
        println!("challenge norm-condition pass rate: {passed}/{total}");
        assert!(passed * 100 >= total * 98, "{passed}/{total}");
        assert!(passed < total, "the condition never rejected a candidate");
    }

    /// The `σ`-fixed element with every free coefficient at `κ` fails the condition, and the
    /// zero and unit challenges pass it.
    #[test]
    fn norm_condition_rejects_a_large_element() {
        let mut c = [0i64; DEGREE];
        c[..DEGREE / 2].fill(KAPPA);
        for i in 1..DEGREE / 2 {
            c[DEGREE - i] = -KAPPA;
        }
        assert!(!passes_norm_condition(&c));
        assert!(passes_norm_condition(&[0; DEGREE]));
        let mut one = [0i64; DEGREE];
        one[0] = 1;
        assert!(passes_norm_condition(&one));
    }

    /// The integer squaring is negacyclic: `X^{32} · X^{32} = −1`, and signs survive.
    #[test]
    fn squaring_is_negacyclic_over_the_integers() {
        let mut a = vec![signed(0); DEGREE];
        a[DEGREE / 2] = signed(-3);
        let squared = square(&a);
        assert_eq!(squared[0], signed(-9));
        assert!(squared[1..].iter().all(|x| *x == signed(0)));
    }

    #[test]
    fn rejects_other_degrees() {
        assert!(sample(&mut reader(0), crate::test_util::PAPER.ring()).is_err());
    }
}
