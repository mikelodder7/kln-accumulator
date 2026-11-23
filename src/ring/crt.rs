// SPDX-License-Identifier: MIT OR Apache-2.0
//! Chinese remaindering from the auxiliary primes back to `Z_q`.

use super::prime::WordPrime;
use crate::zq::{Coeff, Zq};
use crypto_bigint::Limb;
use ctutils::{Choice, CtEq, CtGt, CtSelect};

/// Reconstructs an integer `x` with `|x| ≤ (P − 1)/2`, `P = Π p_i`, from its residues modulo
/// the auxiliary primes `p_0, …, p_{k−1}` and reduces it modulo `q`.
///
/// Garner's algorithm gives the mixed-radix digits `0 ≤ v_i < p_i` of the representative in
/// `[0, P)`, `Σ_i v_i·Π_{j<i} p_j`. That representative stands for `x` itself when it is at
/// most `(P − 1)/2`, which a lexicographic comparison of digits decides, and for `x + P`
/// otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Crt {
    primes: Vec<WordPrime>,
    /// `inverses[i][j] = p_j⁻¹·R mod p_i` for `j < i`, in Montgomery form modulo `p_i`.
    inverses: Vec<Vec<u64>>,
    /// `Π_{j<i} p_j mod q`, in Montgomery form modulo `q`.
    weights: Vec<Coeff>,
    /// The mixed-radix digits of `(P − 1)/2`.
    half: Vec<u64>,
    /// `P mod q`.
    product: Coeff,
}

impl Crt {
    /// Precomputes the reconstruction for `primes`, which must be distinct.
    pub(super) fn new(primes: Vec<WordPrime>, zq: &Zq) -> Self {
        let inverses = primes
            .iter()
            .enumerate()
            .map(|(i, p)| {
                primes[..i]
                    .iter()
                    .map(|earlier| p.inverse_montgomery(earlier.modulus()))
                    .collect()
            })
            .collect();
        let mut weights = Vec::with_capacity(primes.len());
        let product = primes.iter().fold(Coeff::ONE, |acc, p| {
            let acc = zq.montgomery(&acc);
            weights.push(acc);
            zq.mont_mul(&acc, &zq.reduce_u64(p.modulus()))
        });
        // (P − 1)/2 ≡ −2⁻¹ ≡ (p_i − 1)/2 (mod p_i), since P ≡ 0.
        let mut half: Vec<u64> = primes.iter().map(|p| p.modulus() / 2).collect();
        let mut crt = Self {
            primes,
            inverses,
            weights,
            half: Vec::new(),
            product,
        };
        crt.digits(&mut half);
        crt.half = half;
        crt
    }

    /// The number of auxiliary primes.
    pub(super) fn len(&self) -> usize {
        self.primes.len()
    }

    /// Replaces the residues `r_i = x mod p_i` of some `x ∈ [0, P)` by its mixed-radix digits.
    fn digits(&self, residues: &mut [u64]) {
        for i in 1..residues.len() {
            let (done, rest) = residues.split_at_mut(i);
            let (prime, inverses) = (&self.primes[i], &self.inverses[i]);
            if let Some(digit) = rest.first_mut() {
                // v_i = (…((r_i − v_0)·p_0⁻¹ − v_1)·p_1⁻¹ − …)·p_{i−1}⁻¹ mod p_i.
                *digit = done.iter().zip(inverses).fold(*digit, |t, (v, inverse)| {
                    prime.mul(prime.sub(t, prime.reduce(*v)), *inverse)
                });
            }
        }
    }

    /// `x mod q` for the `x` with `|x| ≤ (P − 1)/2` and residues `residues[i] = x mod p_i`
    /// (reduced); `residues` is overwritten.
    pub(super) fn reconstruct(&self, residues: &mut [u64], zq: &Zq) -> Coeff {
        self.digits(residues);
        // S = Σ v_i·W_i as one integer, `low + high·2^192`. Each weight is in Montgomery form,
        // W_i = w_i·2^192 mod q, and each digit is below 2^62, so with at most seven primes
        // `high` stays below 2^65. Then Σ v_i·w_i ≡ S·2^-192 = low·2^-192 + high (mod q): one
        // Montgomery reduction of `low` and one addition, in place of a modular multiplication
        // and addition per prime. No step branches on a digit.
        let mut low = [Limb::ZERO; Coeff::LIMBS];
        let mut high = 0u128;
        for (digit, weight) in residues.iter().zip(&self.weights) {
            let digit = Limb::from_u64(*digit);
            let mut carry = Limb::ZERO;
            for (word, w) in low.iter_mut().zip(weight.as_limbs()) {
                (*word, carry) = digit.carrying_mul_add(*w, *word, carry);
            }
            high += u128::from(carry.0);
        }
        let sum = zq.add(
            &zq.mont_mul(&Coeff::new(low), &Coeff::ONE),
            &zq.reduce_u128(high),
        );
        // The digits compared from the least significant up, every digit read and the higher
        // one deciding, so that neither the comparison nor the correction branches on `x`.
        let greater = residues
            .iter()
            .zip(&self.half)
            .fold(Choice::FALSE, |greater, (digit, half)| {
                digit.ct_gt(half).or(digit.ct_eq(half).and(greater))
            });
        sum.ct_select(&zq.sub(&sum, &self.product), greater)
    }
}

#[cfg(test)]
mod tests {
    use super::{Crt, WordPrime};
    use crate::{ring::prime::AUX_PRIMES, zq::Zq};
    use crypto_bigint::{NonZero, U512};
    use proptest::prelude::*;

    /// Residues of the signed integer `sign·magnitude` modulo `p`, through 512-bit division.
    fn residue(magnitude: &U512, negative: bool, p: u64) -> u64 {
        let r = magnitude
            .rem(&NonZero::new(U512::from_u64(p)).unwrap())
            .as_words()[0];
        if negative && r != 0 { p - r } else { r }
    }

    proptest! {
        /// Every integer in `[−(P−1)/2, (P−1)/2]` is recovered modulo `q`, for `P` the product of
        /// the first three primes and `q` the 100-bit modulus of the 128-bit set.
        #[test]
        fn reconstructs_signed_integers(words in any::<[u64; 3]>(), negative in any::<bool>(), edge in 0u8..3) {
            let primes: Vec<WordPrime> = AUX_PRIMES[..3].iter().map(|&p| WordPrime::new(p)).collect();
            let product = AUX_PRIMES[..3].iter().fold(U512::ONE, |acc, &p| acc.wrapping_mul(&U512::from_u64(p)));
            let half = product.wrapping_sub(&U512::ONE).shr_vartime(1);
            let magnitude = match edge {
                0 => U512::from_words([words[0], words[1], words[2], 0, 0, 0, 0, 0]).rem(&NonZero::new(half.wrapping_add(&U512::ONE)).unwrap()),
                1 => half,
                _ => U512::ZERO,
            };
            let q = *crate::test_util::PAPER.ring().modulus();
            let zq = Zq::new(q).unwrap();
            let crt = Crt::new(primes, &zq);
            prop_assert_eq!(crt.len(), 3);
            let mut residues: Vec<u64> = AUX_PRIMES[..3].iter().map(|&p| residue(&magnitude, negative, p)).collect();
            let q_wide: U512 = q.resize();
            let reduced = magnitude.rem(&NonZero::new(q_wide).unwrap());
            let expected = if negative && reduced != U512::ZERO { q_wide.wrapping_sub(&reduced) } else { reduced };
            prop_assert_eq!(crt.reconstruct(&mut residues, &zq), expected.resize());
        }
    }
}
