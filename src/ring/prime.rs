// SPDX-License-Identifier: MIT OR Apache-2.0
//! Word-size NTT-friendly primes: Montgomery arithmetic and the negacyclic transform modulo each.

use crate::zq::Coeff;

/// The auxiliary primes, largest first: the seven largest primes below `2^62` that are
/// `≡ 1 (mod 2^32)`, written `c·2^32 + 1`. Each has a primitive `2d`-th root of unity for every
/// `d ≤ 2^31`, and all seven multiply to more than `2^433`, above `2·d·q²` for every 192-bit `q`
/// at every such `d`.
pub(super) const AUX_PRIMES: [u64; 7] = [
    0x3fff_ffee_0000_0001,
    0x3fff_ffb4_0000_0001,
    0x3fff_ffa0_0000_0001,
    0x3fff_ff5d_0000_0001,
    0x3fff_ff49_0000_0001,
    0x3fff_ff46_0000_0001,
    0x3fff_ff30_0000_0001,
];

/// The largest degree the auxiliary primes support: `2d` must divide `p − 1 = c·2^32`.
pub(super) const MAX_DEGREE: usize = 1 << 31;

/// The number of 64-bit words in a [`Coeff`].
const WORDS: usize = Coeff::BYTES / 8;

/// Arithmetic modulo an odd prime `p < 2^62`, with Montgomery radix `R = 2^64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WordPrime {
    modulus: u64,
    /// `−p⁻¹ mod 2^64`.
    neg_inv: u64,
    /// `R mod p`.
    r: u64,
    /// `R² mod p`.
    r2: u64,
}

impl WordPrime {
    /// The arithmetic context of `modulus`, which must be odd and below `2^62`.
    pub(super) fn new(modulus: u64) -> Self {
        // Newton's iteration doubles the number of correct low bits from 1: p·p ≡ 1 (mod 2).
        let inv = (0..6).fold(1u64, |inv, _| {
            inv.wrapping_mul(2u64.wrapping_sub(modulus.wrapping_mul(inv)))
        });
        let p = u128::from(modulus);
        let r = (1u128 << 64) % p;
        Self {
            modulus,
            neg_inv: inv.wrapping_neg(),
            // Both are reduced modulo p < 2^64.
            r: r as u64,
            r2: (r * r % p) as u64,
        }
    }

    /// The prime `p`.
    pub(super) fn modulus(&self) -> u64 {
        self.modulus
    }

    /// `a·b·R⁻¹ mod p`, reduced, for any `a < 2^64` and `b < p`: the sum `a·b + m·p` is below
    /// `2^65·p < 2^127`, and the reduction is below `2p`.
    pub(super) fn mul(&self, a: u64, b: u64) -> u64 {
        let t = u128::from(a) * u128::from(b);
        // The low word of t, truncated on purpose; the high word of the sum below 2^127 fits.
        let m = (t as u64).wrapping_mul(self.neg_inv);
        self.reduce_once(((t + u128::from(m) * u128::from(self.modulus)) >> 64) as u64)
    }

    /// `a + b mod p` for reduced inputs.
    pub(super) fn add(&self, a: u64, b: u64) -> u64 {
        self.reduce_once(a + b)
    }

    /// `a − b mod p` for reduced inputs.
    pub(super) fn sub(&self, a: u64, b: u64) -> u64 {
        self.add_back(a.wrapping_sub(b))
    }

    /// `x mod p` for `x < 2p`.
    fn reduce_once(&self, x: u64) -> u64 {
        self.add_back(x.wrapping_sub(self.modulus))
    }

    /// `t + p` when `t`, read as a signed difference of values below `2^63`, is negative, and
    /// `t` otherwise. Branch-free, because the sign of a butterfly's difference is a coin toss
    /// that a branch predictor cannot learn.
    fn add_back(&self, t: u64) -> u64 {
        t.wrapping_add(self.modulus & (t >> 63).wrapping_neg())
    }

    /// `a mod p` for any word `a`.
    pub(super) fn reduce(&self, a: u64) -> u64 {
        self.mul(a, self.r)
    }

    /// The Montgomery form `a·R mod p` of any word `a`.
    pub(super) fn montgomery(&self, a: u64) -> u64 {
        self.mul(a, self.r2)
    }

    /// `base^exponent` for `base` and result in Montgomery form.
    fn pow(&self, base: u64, mut exponent: u64) -> u64 {
        let (mut result, mut square) = (self.r, base);
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = self.mul(result, square);
            }
            square = self.mul(square, square);
            exponent >>= 1;
        }
        result
    }

    /// `a⁻¹·R mod p` for `a` coprime to `p`, by Fermat's little theorem.
    pub(super) fn inverse_montgomery(&self, a: u64) -> u64 {
        self.pow(self.montgomery(a), self.modulus - 2)
    }
}

/// The negacyclic NTT of degree `d` modulo one auxiliary prime. Transformed values are in
/// Montgomery form, so pointwise Montgomery products stay in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PrimeNtt {
    prime: WordPrime,
    /// `ψ^{brv(i)}·R mod p`, for `ψ` a primitive `2d`-th root of unity.
    zetas: Vec<u64>,
    /// `ψ^{−brv(i)}·R mod p`.
    zetas_inv: Vec<u64>,
    /// `d⁻¹ mod p`, not in Montgomery form, so that the final scaling of the inverse transform
    /// also leaves Montgomery form.
    degree_inv: u64,
    /// `R^{w+2} mod p` for word `w` of a [`Coeff`], so that `Σ_w mul(c_w, ·)` is `c·R mod p`.
    word_weights: [u64; WORDS],
}

impl PrimeNtt {
    /// The tables for `prime` at `degree`, or `None` when `2·degree` does not divide `prime − 1`
    /// (no primitive `2d`-th root of unity exists then).
    pub(super) fn new(prime: u64, degree: usize) -> Option<Self> {
        let prime = WordPrime::new(prime);
        let two_d = u64::try_from(degree).ok()?.checked_mul(2)?;
        let p_minus_one = prime.modulus() - 1;
        if !p_minus_one.is_multiple_of(two_d) {
            return None;
        }
        // ψ = g^{(p−1)/2d} has order exactly 2d once ψ^d = −1, which holds for any quadratic
        // non-residue g; half of all residues are non-residues.
        let minus_one = prime.montgomery(p_minus_one);
        let psi = (2..=u64::from(u16::MAX))
            .map(|g| prime.pow(prime.montgomery(g), p_minus_one / two_d))
            .find(|&psi| prime.pow(psi, two_d / 2) == minus_one)?;
        // ψ has order 2d, so ψ⁻¹ = ψ^{2d−1}.
        let psi_inv = prime.pow(psi, two_d - 1);
        let mut word_weights = [0u64; WORDS];
        // R² mod p, then each further word weight is one more factor of R.
        let mut weight = prime.r2;
        for slot in &mut word_weights {
            *slot = weight;
            weight = prime.montgomery(weight);
        }
        Some(Self {
            prime,
            zetas: bit_reversed_powers(&prime, psi, degree),
            zetas_inv: bit_reversed_powers(&prime, psi_inv, degree),
            // d·((p−1)/d) = p − 1 ≡ −1, so d⁻¹ = p − (p−1)/d.
            degree_inv: prime.modulus() - p_minus_one / (two_d / 2),
            word_weights,
        })
    }

    /// The prime's arithmetic.
    pub(super) fn prime(&self) -> &WordPrime {
        &self.prime
    }

    /// The Montgomery form of `value mod p`.
    pub(super) fn montgomery_residue(&self, value: &Coeff) -> u64 {
        let bytes = value.to_le_bytes();
        bytes
            .as_ref()
            .as_chunks::<8>()
            .0
            .iter()
            .zip(&self.word_weights)
            .fold(0, |acc, (word, weight)| {
                self.prime
                    .add(acc, self.prime.mul(u64::from_le_bytes(*word), *weight))
            })
    }

    /// Forward negacyclic NTT in place (Cooley–Tukey, natural order in, bit-reversed order out).
    pub(super) fn forward(&self, values: &mut [u64]) {
        let p = &self.prime;
        let (mut len, mut blocks) = (values.len() / 2, 1);
        while len > 0 {
            for (block, zeta) in values
                .chunks_exact_mut(2 * len)
                .zip(&self.zetas[blocks..2 * blocks])
            {
                let (low, high) = block.split_at_mut(len);
                for (x, y) in low.iter_mut().zip(high.iter_mut()) {
                    let t = p.mul(*y, *zeta);
                    *y = p.sub(*x, t);
                    *x = p.add(*x, t);
                }
            }
            len /= 2;
            blocks *= 2;
        }
    }

    /// Inverse negacyclic NTT in place (Gentleman–Sande, bit-reversed order in, natural order
    /// out), leaving Montgomery form.
    pub(super) fn inverse(&self, values: &mut [u64]) {
        let p = &self.prime;
        let degree = values.len();
        let (mut len, mut blocks) = (1, degree / 2);
        while len < degree {
            for (block, zeta_inv) in values
                .chunks_exact_mut(2 * len)
                .zip(&self.zetas_inv[blocks..2 * blocks])
            {
                let (low, high) = block.split_at_mut(len);
                for (x, y) in low.iter_mut().zip(high.iter_mut()) {
                    let difference = p.sub(*x, *y);
                    *x = p.add(*x, *y);
                    *y = p.mul(difference, *zeta_inv);
                }
            }
            len *= 2;
            blocks /= 2;
        }
        values
            .iter_mut()
            .for_each(|v| *v = p.mul(*v, self.degree_inv));
    }

    /// `acc += a ∘ b` pointwise, all in Montgomery form.
    pub(super) fn mul_acc(&self, acc: &mut [u64], a: &[u64], b: &[u64]) {
        let p = &self.prime;
        for ((out, x), y) in acc.iter_mut().zip(a).zip(b) {
            *out = p.add(*out, p.mul(*x, *y));
        }
    }
}

/// `[root^{brv(i)}]` for `i ∈ [0, d)`, `root` and output in Montgomery form, with `brv` the
/// `log₂ d`-bit reversal.
fn bit_reversed_powers(prime: &WordPrime, root: u64, degree: usize) -> Vec<u64> {
    let powers: Vec<u64> =
        core::iter::successors(Some(prime.r), |&power| Some(prime.mul(power, root)))
            .take(degree)
            .collect();
    let shift = usize::BITS - degree.trailing_zeros();
    (0..degree)
        .map(|i| powers[i.reverse_bits().checked_shr(shift).unwrap_or(0)])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{AUX_PRIMES, PrimeNtt, WordPrime};
    use crate::zq::Coeff;
    use proptest::prelude::*;

    /// Deterministic Miller–Rabin for 64-bit integers in `u128` arithmetic, independent of the
    /// Montgomery code: the first twelve prime bases suffice below `3.3·10^24`.
    fn is_prime_u64(n: u64) -> bool {
        const BASES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
        let pow = |mut b: u128, mut e: u64, m: u128| {
            let mut r = 1u128;
            b %= m;
            while e > 0 {
                if e & 1 == 1 {
                    r = r * b % m;
                }
                b = b * b % m;
                e >>= 1;
            }
            r
        };
        if n < 2 || BASES.iter().any(|&p| n.is_multiple_of(p) && n != p) {
            return false;
        }
        let (n128, s) = (u128::from(n), (n - 1).trailing_zeros());
        let d = (n - 1) >> s;
        BASES.iter().filter(|&&a| a != n).all(|&a| {
            let mut x = pow(u128::from(a), d, n128);
            if x == 1 || x == n128 - 1 {
                return true;
            }
            (1..s).any(|_| {
                x = x * x % n128;
                x == n128 - 1
            })
        })
    }

    #[test]
    fn auxiliary_primes_are_distinct_ntt_friendly_primes() {
        for (i, &p) in AUX_PRIMES.iter().enumerate() {
            assert!(is_prime_u64(p), "{p:#x}");
            assert_eq!((p - 1) % (1 << 32), 0, "{p:#x}");
            assert!(p > 1 << 61 && p < 1 << 62, "{p:#x}");
            assert!(AUX_PRIMES[..i].iter().all(|&q| q > p), "{p:#x}");
        }
        let bits: f64 = AUX_PRIMES.iter().map(|&p| (p as f64).log2()).sum();
        assert!(bits > 433.0, "{bits}");
        assert!(is_prime_u64(97) && !is_prime_u64(561) && !is_prime_u64(3_215_031_751));
    }

    #[test]
    fn degree_must_divide_the_two_adic_part() {
        assert!(PrimeNtt::new(AUX_PRIMES[0], 1 << 12).is_some());
        // p − 1 = c·2^32 with c odd for this prime, so d = 2^31 is its largest degree. (The
        // primes with c even support larger degrees than the ring ever asks of them.)
        assert_eq!(((AUX_PRIMES[3] - 1) >> 32) % 2, 1);
        assert!(PrimeNtt::new(AUX_PRIMES[3], 1 << 32).is_none());
        assert!(PrimeNtt::new(AUX_PRIMES[0], 1).is_some());
    }

    proptest! {
        #[test]
        fn word_arithmetic_matches_u128(a in any::<u64>(), b in any::<u64>(), i in 0..AUX_PRIMES.len()) {
            let p = AUX_PRIMES[i];
            let prime = WordPrime::new(p);
            let (p128, a128) = (u128::from(p), u128::from(a));
            let r_inv = u128::from(prime.mul(1, 1)); // R⁻¹ mod p
            let (ar, br) = (a % p, b % p);
            prop_assert_eq!(u128::from(prime.reduce(a)), a128 % p128);
            prop_assert_eq!(u128::from(prime.montgomery(a)), (a128 % p128) * ((1u128 << 64) % p128) % p128);
            prop_assert_eq!(u128::from(prime.mul(a, br)), a128 % p128 * u128::from(br) % p128 * r_inv % p128);
            prop_assert_eq!(prime.add(ar, br), ((u128::from(ar) + u128::from(br)) % p128) as u64);
            prop_assert_eq!(prime.sub(ar, br), ((u128::from(ar) + p128 - u128::from(br)) % p128) as u64);
            if ar != 0 {
                let inv = prime.inverse_montgomery(ar);
                prop_assert_eq!(prime.mul(inv, ar), 1);
            }
        }

        #[test]
        fn residue_matches_bigint_remainder(words in any::<[u64; 3]>(), i in 0..AUX_PRIMES.len()) {
            let ntt = PrimeNtt::new(AUX_PRIMES[i], 64).unwrap();
            let value = Coeff::from_words(words);
            let p = AUX_PRIMES[i];
            let expected = value.rem(&crypto_bigint::NonZero::new(Coeff::from_u64(p)).unwrap()).as_words()[0];
            prop_assert_eq!(ntt.prime().mul(ntt.montgomery_residue(&value), 1), expected);
        }
    }
}
