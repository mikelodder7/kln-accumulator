// SPDX-License-Identifier: MIT OR Apache-2.0
//! Centred base-`2^k` decompositions of ring elements: every digit but the last lies in `[−2^{k−1}, 2^{k−1})` and the last takes
//! what remains of the centred coefficient. These are the decompositions of ePrint 2022/1341,
//! Section 5.2 (`tᵢ = tᵢ⁽⁰⁾ + … + tᵢ⁽ᵗ¹⁻¹⁾·b₁^{t₁−1}` "where centered representatives modulo
//! `b₁` are used") and Section 5.3 (`z = z⁽⁰⁾ + b·z⁽¹⁾`), with power-of-two bases; Figure 3,
//! lines 10–13, likewise bounds every digit but the last. The digit ranges are not checked by
//! the verifier (see `level.rs`).

use super::params::Digits;
use crate::{
    error::{Error, Result},
    poly::Poly,
    ring::Ring,
    zq::Coeff,
};

/// The digits of `p`, digit `k` of every coefficient forming polynomial `k`.
pub(crate) fn decompose(p: &Poly, digits: Digits, ring: &Ring) -> Result<Vec<Poly>> {
    let base = 1i128 << digits.bits;
    let half = base >> 1;
    let mut values = p
        .coefficients()
        .iter()
        .map(|c| centred_i128(c, ring))
        .collect::<Result<Vec<_>>>()?;
    let mut parts = Vec::with_capacity(digits.parts);
    for _ in 1..digits.parts {
        let digit: Vec<i128> = values
            .iter_mut()
            .map(|v| {
                let low = (v.rem_euclid(base) + half).rem_euclid(base) - half;
                *v = (*v - low) >> digits.bits;
                low
            })
            .collect();
        parts.push(from_i128(&digit, ring));
    }
    parts.push(from_i128(&values, ring));
    Ok(parts)
}

/// `2^e mod q`.
pub(crate) fn power_of_two(e: u32, ring: &Ring) -> Coeff {
    let zq = ring.zq();
    (0..e).fold(Coeff::ONE, |acc, _| zq.add(&acc, &acc))
}

/// The weights `2^{k·bits} mod q` of the digits, `k < parts`.
pub(crate) fn digit_weights(digits: Digits, ring: &Ring) -> Vec<Coeff> {
    // parts is at most the modulus bit width, below 2^8.
    (0..digits.parts as u32)
        .map(|k| power_of_two(k * digits.bits, ring))
        .collect()
}

/// The centred lift of a reduced coefficient as an `i128`; the level parameters keep `q` below
/// `2^{126}`.
fn centred_i128(c: &Coeff, ring: &Ring) -> Result<i128> {
    let centred = ring.center(c);
    let magnitude = centred.magnitude();
    if magnitude.bit_width_vartime() >= i128::BITS - 1 {
        return Err(Error::CompressionParameters);
    }
    let words = magnitude.as_words();
    let value = (i128::from(words[1]) << 64) | i128::from(words[0]);
    Ok(if centred.is_negative() { -value } else { value })
}

/// The polynomial with coefficients `values` reduced modulo `q`.
fn from_i128(values: &[i128], ring: &Ring) -> Poly {
    let zq = ring.zq();
    let word = zq.montgomery(&power_of_two(64, ring));
    Poly::from_reduced(
        values
            .iter()
            .map(|&v| {
                let magnitude = v.unsigned_abs();
                // The high and the low word of the magnitude, the second truncated on purpose.
                let high = zq.reduce_u64((magnitude >> 64) as u64);
                let value = zq.add(&zq.mont_mul(&word, &high), &zq.reduce_u64(magnitude as u64));
                if v < 0 { zq.neg(&value) } else { value }
            })
            .collect(),
    )
}
