// SPDX-License-Identifier: MIT OR Apache-2.0
//! The approximate range proof's challenge `R ← Bin₁^{256×m̄₁d}` (Appendix D.2.1, lines
//! 2734–2781, and D.2.2, line 2812) and the two products the protocol takes with it.
//!
//! An entry of `Bin₁` is `a − b` for two uniform bits; entries are drawn row-major from a SHAKE256
//! stream, four to a byte, the entry in bits `2t, 2t+1` being `bit_{2t} − bit_{2t+1}`.
//! Row `j` of `R` is the coefficient vector of the polynomial vector `r_j ∈ R_q^{m̄₁}` of line
//! 2822, so that `const(σ(r_j)ᵀs₁) = ⟨r_j, s₁⟩` is entry `j` of `R·s₁`.

use crate::{
    error::{Error, Result, check_dimension},
    poly::Poly,
    proof::params::RANGE_ROWS,
    ring::Ring,
    sample::{DomainLabel, Seed, xof},
    vector::PolyVec,
    zq::Coeff,
};
use crypto_bigint::NonZero;
use shake::digest::XofReader;

/// Label of the stream `R` is drawn from.
const LABEL_R: &[u8] = b"kln/lnp/range/r";

/// `R ∈ {−1, 0, 1}^{256 × cols}`, packed four entries to a byte, row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BinomialMatrix {
    cols: usize,
    packed: Vec<u8>,
}

impl BinomialMatrix {
    /// Draws `R` with `cols` columns, a multiple of four, from `seed`.
    pub(crate) fn sample(seed: &Seed, cols: usize) -> Result<Self> {
        Self::sample_labelled(seed, LABEL_R, cols)
    }

    /// Draws a matrix with the distribution of `R` and `cols` columns, a multiple of four, from
    /// `seed` under `label`. LaBRADOR's Johnson–Lindenstrauss projection has this distribution.
    pub(crate) fn sample_labelled(seed: &Seed, label: &[u8], cols: usize) -> Result<Self> {
        if !cols.is_multiple_of(4) {
            return Err(Error::DimensionMismatch {
                expected: cols.next_multiple_of(4),
                found: cols,
            });
        }
        let mut packed = vec![0u8; RANGE_ROWS * cols / 4];
        xof(seed, DomainLabel::from(label)).read(&mut packed);
        Ok(Self { cols, packed })
    }

    /// The bytes of row `j`.
    fn row(&self, j: usize) -> &[u8] {
        let stride = self.cols / 4;
        &self.packed[j * stride..(j + 1) * stride]
    }

    /// `R·s` over the integers, for an integer vector `s` of length `cols` whose entries are
    /// small enough that no row sum can overflow an `i64` (`cols·max|sᵢ| < 2^62`).
    pub(crate) fn apply(&self, s: &[i64]) -> Result<Vec<i64>> {
        self.check_cols(s.len())?;
        let largest = s.iter().map(|x| x.unsigned_abs()).max().unwrap_or(0);
        if largest
            .checked_mul(self.cols as u64)
            .is_none_or(|bound| bound >= 1 << 62)
        {
            return Err(Error::ProofRejected);
        }
        Ok((0..RANGE_ROWS)
            .map(|j| {
                self.row(j)
                    .iter()
                    .zip(s.as_chunks::<4>().0)
                    .map(|(&byte, chunk)| {
                        let e = &ENTRIES[usize::from(byte)];
                        i64::from(e[0]) * chunk[0]
                            + i64::from(e[1]) * chunk[1]
                            + i64::from(e[2]) * chunk[2]
                            + i64::from(e[3]) * chunk[3]
                    })
                    .sum()
            })
            .collect())
    }

    /// `a_i = Σ_j α_{i,j}·r_j ∈ R_q^{cols/d}` for every row `α_i ∈ Z_q^{256}` of `alpha`: the
    /// combination that turns `Σ_j α_{i,j}·σ(r_j)ᵀs₁` into `σ(a_i)ᵀs₁`.
    ///
    /// Rows are taken four at a time: for each block the 256 possible sums
    /// `Σ_{t<4} e_t·α_{i,4b+t}` over the four rows' 2-bit codes are tabulated, and each column
    /// adds the entry its four codes select. Each `α_{i,j}` is split into 64-bit limbs and every
    /// limb is accumulated in an `i128`, which 256 terms below `2^64` cannot overflow; the limbs
    /// are recombined modulo `q` at the end.
    pub(crate) fn combine(&self, alpha: &[Vec<Coeff>], ring: &Ring) -> Result<Vec<PolyVec>> {
        let limbs = (ring.modulus().bit_width_vartime() as usize).div_ceil(64);
        let cols = self.cols;
        let width = alpha.len() * limbs;
        let words = alpha
            .iter()
            .map(|row| {
                let row = row.get(..RANGE_ROWS).ok_or(Error::DimensionMismatch {
                    expected: RANGE_ROWS,
                    found: row.len(),
                })?;
                Ok(row
                    .iter()
                    .map(|value| {
                        let bytes = value.to_le_bytes();
                        bytes
                            .as_ref()
                            .as_chunks::<8>()
                            .0
                            .iter()
                            .take(limbs)
                            .map(|w| i128::from(u64::from_le_bytes(*w)))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>())
            })
            .collect::<Result<Vec<_>>>()?;
        // acc[col·width + i·limbs + l]: limb l of entry col of a_i.
        let mut acc = vec![0i128; cols * width];
        let mut table = vec![0i128; 256 * width];
        for block in 0..RANGE_ROWS / 4 {
            for (code, sums) in table.chunks_exact_mut(width).enumerate() {
                for (i, row) in words.iter().enumerate() {
                    for l in 0..limbs {
                        sums[i * limbs + l] = (0..4)
                            // code < 256, so its low byte is the whole value.
                            .map(|t| {
                                i128::from(entry(code.to_le_bytes()[0], t)) * row[4 * block + t][l]
                            })
                            .sum();
                    }
                }
            }
            let rows = [0, 1, 2, 3].map(|t| self.row(4 * block + t));
            for (b, out) in acc.chunks_exact_mut(4 * width).enumerate() {
                let bytes = rows.map(|row| row[b]);
                for (t, slot) in out.chunks_exact_mut(width).enumerate() {
                    let code = bytes.iter().enumerate().fold(0usize, |code, (k, byte)| {
                        code | usize::from((byte >> (2 * t)) & 3) << (2 * k)
                    });
                    for (x, y) in slot
                        .iter_mut()
                        .zip(&table[code * width..(code + 1) * width])
                    {
                        *x += y;
                    }
                }
            }
        }
        let zq = ring.zq();
        let modulus = NonZero::new(*ring.modulus())
            .into_option()
            .ok_or(Error::ModulusNotPrime)?;
        // 2^{64l} mod q in Montgomery form, for l < limbs.
        let shifts: Vec<Coeff> = (0..limbs)
            // l < limbs ≤ 3 for a modulus of at most 192 bits.
            .map(|l| zq.montgomery(&Coeff::ONE.shl_vartime(64 * l as u32).rem(&modulus)))
            .collect();
        // |x| < 2^127: when q ≥ 2^127 the magnitude is already reduced, and otherwise q fits a
        // u128 and native division reduces it.
        let small_modulus = (ring.modulus().bit_width_vartime() < u128::BITS)
            .then(|| u128::from(ring.modulus().resize::<{ crypto_bigint::U128::LIMBS }>()));
        let reduce = |x: i128| {
            let magnitude = x.unsigned_abs();
            let magnitude = Coeff::from_u128(small_modulus.map_or(magnitude, |q| magnitude % q));
            if x < 0 { zq.neg(&magnitude) } else { magnitude }
        };
        let d = ring.degree();
        Ok((0..alpha.len())
            .map(|i| {
                let coefficients: Vec<Coeff> = acc
                    .chunks_exact(width)
                    .map(|limb_sums| {
                        shifts
                            .iter()
                            .enumerate()
                            .fold(Coeff::ZERO, |sum, (l, shift)| {
                                let part = reduce(limb_sums[i * limbs + l]);
                                zq.add(&sum, &zq.mont_mul(shift, &part))
                            })
                    })
                    .collect();
                coefficients
                    .chunks_exact(d)
                    .map(|chunk| Poly::from_reduced(chunk.to_vec()))
                    .collect()
            })
            .collect())
    }

    fn check_cols(&self, len: usize) -> Result<()> {
        check_dimension(self.cols, len)
    }
}

/// The four entries of every byte value.
const ENTRIES: [[i8; 4]; 256] = {
    let mut table = [[0i8; 4]; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut t = 0;
        while t < 4 {
            // byte < 256, so its low byte is the whole value.
            table[byte][t] = entry(byte.to_le_bytes()[0], t);
            t += 1;
        }
        byte += 1;
    }
    table
};

/// Entry `t ∈ [0, 4)` of a packed byte: `bit_{2t} − bit_{2t+1}`.
const fn entry(byte: u8, t: usize) -> i8 {
    let bits = (byte >> (2 * t)) & 3;
    (bits & 1).cast_signed() - (bits >> 1).cast_signed()
}

#[cfg(test)]
mod tests {
    use super::{BinomialMatrix, RANGE_ROWS, entry};
    use crate::{
        proof::coeffs::centred,
        sample::{DomainLabel, Seed, UniformSampler},
        test_util::TOY,
        zq::Coeff,
    };

    fn dense(r: &BinomialMatrix) -> Vec<Vec<i64>> {
        (0..RANGE_ROWS)
            .map(|j| {
                r.row(j)
                    .iter()
                    .flat_map(|&b| (0..4).map(move |t| i64::from(entry(b, t))))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn entries_are_centred_binomial() {
        let r = BinomialMatrix::sample(&Seed::from([1; 32]), 256).unwrap();
        let all: Vec<i64> = dense(&r).into_iter().flatten().collect();
        let zeros = all.iter().filter(|&&e| e == 0).count();
        let ones = all.iter().filter(|&&e| e == 1).count();
        assert_eq!(all.len(), RANGE_ROWS * 256);
        // Bin₁ is 0 with probability 1/2 and ±1 with 1/4 each.
        assert!((zeros as f64 / all.len() as f64 - 0.5).abs() < 0.01);
        assert!((ones as f64 / all.len() as f64 - 0.25).abs() < 0.01);
        assert_eq!(
            BinomialMatrix::sample(&Seed::from([1; 32]), 256).unwrap(),
            r
        );
        assert!(BinomialMatrix::sample(&Seed::from([1; 32]), 6).is_err());
    }

    /// `R·s` and the `α`-combination of the rows agree with a dense computation.
    #[test]
    fn products_match_dense_computation() {
        let ring = TOY.ring();
        let cols = 2 * ring.degree();
        let r = BinomialMatrix::sample(&Seed::from([2; 32]), cols).unwrap();
        let rows = dense(&r);
        let s: Vec<i64> = (0..cols as i64).map(|i| i % 5 - 2).collect();
        let expected: Vec<i64> = rows
            .iter()
            .map(|row| row.iter().zip(&s).map(|(a, b)| a * b).sum())
            .collect();
        assert_eq!(r.apply(&s).unwrap(), expected);
        assert!(r.apply(&s[1..]).is_err());

        let mut sampler = UniformSampler::new(&Seed::from([3; 32]), DomainLabel::from(&b"a"[..]));
        let alpha: Vec<Vec<Coeff>> = (0..2)
            .map(|_| {
                sampler
                    .vector(RANGE_ROWS / ring.degree(), ring)
                    .as_slice()
                    .iter()
                    .flat_map(|p| p.coefficients().to_vec())
                    .collect()
            })
            .collect();
        let combined = r.combine(&alpha, ring).unwrap();
        let zq = ring.zq();
        for (row_alpha, a) in alpha.iter().zip(&combined) {
            let flat: Vec<Coeff> = a
                .as_slice()
                .iter()
                .flat_map(|p| p.coefficients().to_vec())
                .collect();
            for (col, value) in flat.iter().enumerate() {
                let direct =
                    rows.iter()
                        .zip(row_alpha)
                        .fold(Coeff::ZERO, |sum, (row, w)| match row[col] {
                            1 => zq.add(&sum, w),
                            -1 => zq.sub(&sum, w),
                            _ => sum,
                        });
                assert_eq!(*value, direct);
            }
        }
        // The combination is linear: with s as a vector over R_q, const(σ(a_i)ᵀs) = Σ_j α_ij (R s)_j.
        let s_vec = crate::proof::coeffs::from_integers(&s, ring).unwrap();
        let rs = r.apply(&s).unwrap();
        for (row_alpha, a) in alpha.iter().zip(&combined) {
            let lhs = a.as_slice().iter().zip(s_vec.as_slice()).fold(
                crate::poly::Poly::zero(ring),
                |acc, (ai, si)| {
                    acc.add(
                        &ai.sigma_minus_one(ring).unwrap().mul(si, ring).unwrap(),
                        ring,
                    )
                    .unwrap()
                },
            );
            let rhs = rs.iter().zip(row_alpha).fold(Coeff::ZERO, |sum, (&x, w)| {
                zq.add(&sum, &zq.mont_mul(&zq.montgomery(w), &zq.reduce_i64(x)))
            });
            assert_eq!(lhs.coefficients()[0], rhs);
        }
        assert_eq!(*centred(&s_vec, ring).unwrap(), s);
    }
}
