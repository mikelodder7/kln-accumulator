// SPDX-License-Identifier: MIT OR Apache-2.0
//! The perturbation `p ← D_{Z^{md}, √Σ_p}` with `Σ_p = V₀·I − α²·[T; I]·[T; I]ᵀ` for a ring
//! trapdoor `T ∈ R^{(m−m')×m'}`: `SamplePz` of ePrint 2017/308, Section 4.1, Figure 4,
//! generalised from its `2×m'` trapdoor to `m − m'` rows. Section, figure, lemma and theorem
//! numbers in this module are those of ePrint 2017/308.
//!
//! Write `p = [p₁; p₂]` with `p₂ ∈ R^{m'}`. As in `SamplePz`, `p₂` is spherical with variance
//! `V₀ − α²`, and given `p₂`, `p₁` has centre `−(α²/(V₀ − α²))·T·p₂` and covariance the Schur
//! complement `Σ' = V₀·I − κ·T·T*`, `κ = (α^{-2} − V₀^{-1})^{-1}` (Figure 4's `z`): Lemma 4.1
//! factors the Gaussian this way, and Lemma 4.3 makes the two-step draw close to the joint one.
//!
//! `SamplePz` hands the `2×2` matrix `Σ'` over the ring to `Sample2z`, which draws the second
//! entry with covariance `d`, then the first given it with the Schur complement `a − b·d⁻¹·b*`.
//! With `m − m'` rows (10 at the toy and 128-bit sets) this is the block `LDL*` decomposition
//! of `Σ'` over the ring, computed in the FFT domain, where `Σ'` is an `(m−m')×(m−m')`
//! Hermitian matrix at each of the `d/2` roots: entry `i` of `p₁` is drawn with the
//! self-adjoint pivot `Dᵢ` as covariance and the centre the earlier entries give (Lemma 4.3
//! once per row, first row first rather than last, which the lemma allows). A ring element is
//! then drawn by `SampleFz`: split into even and odd parts, whose covariance over the ring of
//! half the degree is the `2×2` matrix of the stride permutation of Section 2.3, recursively
//! down to integers. Section 4.1's Efficiency paragraph suggests keeping everything in the
//! Fourier domain, as here, so that products and inverses are pointwise.
//!
//! Section 4 does not analyse floating point. Every conditional variance of the recursion is
//! at least the least value of some `Dᵢ` at a root (Theorems 2.1 and 2.2, interlacing);
//! [`Perturbation::new`] refuses a trapdoor for which any of those is below `V₀/4`, which
//! bounds the precision loss (see [`crate::preimage`]) and makes every conditional variance
//! far above `η_ε(Z)`.

use super::{
    Stage, Uniform,
    fft::{Complex, Fft},
    sample_z, spherical,
};
use crate::error::{Error, Result};
use core::fmt;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// The fraction of `V₀` below which a pivot refuses the trapdoor.
const PIVOT_FLOOR: f64 = 0.25;

/// The precomputed perturbation sampler of one trapdoor. Everything it holds but the shape is a
/// function of the trapdoor and is overwritten when the sampler is dropped.
pub(crate) struct Perturbation {
    degree: usize,
    rows: usize,
    cols: usize,
    fft: Fft,
    /// The values of `T`'s entries, row-major.
    trapdoor: Vec<Zeroizing<Vec<Complex>>>,
    /// `L_{r,i}` for `i < r`, at index `r(r−1)/2 + i`.
    lower: Zeroizing<Vec<Vec<Complex>>>,
    /// The pivots `Dᵢ` at every root.
    pivots: Zeroizing<Vec<Vec<f64>>>,
    /// `√(V₀ − α²)`.
    bottom_std: f64,
    /// `−α²/(V₀ − α²)`.
    centre_scale: f64,
}

/// The shape of a trapdoor: `rows × cols` entries in a ring of degree `degree`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrapdoorShape {
    /// `m − m'`.
    pub(crate) rows: usize,
    /// `m'`.
    pub(crate) cols: usize,
    /// `d`.
    pub(crate) degree: usize,
}

impl Perturbation {
    /// The sampler for the trapdoor with `coefficients` (entries row-major, each constant term
    /// first) at `stage`. Fails with [`Error::InvalidTrapdoor`] when a pivot is below `V₀/4`.
    pub(crate) fn new(coefficients: &[i64], shape: TrapdoorShape, stage: &Stage) -> Result<Self> {
        let TrapdoorShape { rows, cols, degree } = shape;
        let fft = Fft::new(degree);
        let trapdoor: Vec<Zeroizing<Vec<Complex>>> = coefficients
            .chunks_exact(degree)
            .map(|entry| {
                // Bounded by the trapdoor sampler's largest magnitude, checked first; exact below 2^53.
                let real = Zeroizing::new(entry.iter().map(|&t| t as f64).collect::<Vec<_>>());
                fft.forward(&real)
            })
            .collect();
        let variance = stage.variance();
        // Exact below 2^53, rounded to 53 significant bits above.
        let alpha_sq = stage.gadget_variance as f64;
        let kappa = alpha_sq * variance / (variance - alpha_sq);
        let floor = PIVOT_FLOOR * variance;
        let half = degree / 2;
        let mut lower = Zeroizing::new(vec![
            vec![Complex::default(); half];
            rows * rows.saturating_sub(1) / 2
        ]);
        let mut pivots = Zeroizing::new(vec![vec![0.0; half]; rows]);
        let mut sigma = Zeroizing::new(vec![Complex::default(); rows * rows]);
        for j in 0..half {
            for a in 0..rows {
                for b in 0..=a {
                    let gram = (0..cols).fold(Complex::default(), |acc, c| {
                        acc + trapdoor[a * cols + c][j] * trapdoor[b * cols + c][j].conj()
                    });
                    let diagonal = if a == b { variance } else { 0.0 };
                    sigma[a * rows + b] = Complex::real(diagonal) - gram.scale(kappa);
                }
            }
            for i in 0..rows {
                let pivot = (0..i).fold(sigma[i * rows + i].re, |acc, l| {
                    acc - lower[index(i, l)][j].norm_sq() * pivots[l][j]
                });
                if pivot < floor {
                    return Err(Error::InvalidTrapdoor);
                }
                pivots[i][j] = pivot;
                for r in i + 1..rows {
                    let entry = (0..i).fold(sigma[r * rows + i], |acc, l| {
                        acc - (lower[index(r, l)][j] * lower[index(i, l)][j].conj())
                            .scale(pivots[l][j])
                    });
                    lower[index(r, i)][j] = entry.scale(1.0 / pivot);
                }
            }
        }
        Ok(Self {
            degree,
            rows,
            cols,
            fft,
            trapdoor,
            lower,
            pivots,
            bottom_std: (variance - alpha_sq).sqrt(),
            centre_scale: -alpha_sq / (variance - alpha_sq),
        })
    }

    /// A perturbation `p = [p₁; p₂] ∈ Z^{md}`, entries in order, each constant term first.
    /// The perturbation hides the trapdoor in the preimage, so it and every intermediate are
    /// overwritten when dropped.
    pub(crate) fn sample(&self, uniform: &mut Uniform<'_>) -> Zeroizing<Vec<i64>> {
        let degree = self.degree;
        let bottom = spherical(uniform, self.bottom_std, self.cols * degree);
        let bottom_fft: Vec<Zeroizing<Vec<Complex>>> = bottom
            .chunks_exact(degree)
            .map(|entry| {
                // Bounded by the trapdoor sampler's largest magnitude, checked first; exact below 2^53.
                let real = Zeroizing::new(entry.iter().map(|&t| t as f64).collect::<Vec<_>>());
                self.fft.forward(&real)
            })
            .collect();
        let mut residuals: Zeroizing<Vec<Vec<Complex>>> =
            Zeroizing::new(Vec::with_capacity(self.rows));
        let mut top = Zeroizing::new(Vec::with_capacity(self.rows * degree + bottom.len()));
        for i in 0..self.rows {
            let centre: Zeroizing<Vec<Complex>> = Zeroizing::new(
                (0..degree / 2)
                    .map(|j| {
                        let product = (0..self.cols).fold(Complex::default(), |acc, c| {
                            acc + self.trapdoor[i * self.cols + c][j] * bottom_fft[c][j]
                        });
                        (0..i).fold(product.scale(self.centre_scale), |acc, l| {
                            acc + self.lower[index(i, l)][j] * residuals[l][j]
                        })
                    })
                    .collect(),
            );
            let (values, values_fft) = self.sample_ring(&self.pivots[i], &centre, degree, uniform);
            residuals.push(
                values_fft
                    .iter()
                    .zip(centre.iter())
                    .map(|(x, c)| *x - *c)
                    .collect(),
            );
            top.extend_from_slice(&values);
        }
        top.extend_from_slice(&bottom);
        top
    }

    /// `D_{Z^degree, √f, c}` for the self-adjoint `f` with real values `f` and the centre with
    /// values `centre`: the sample's coefficients and its values. This is `SampleFz` of
    /// ePrint 2017/308, Figure 4.
    ///
    /// Under `f(X) = f₀(X²) + X·f₁(X²)` the covariance of (even part, odd part) is
    /// `[[f₀, ξ·f₁], [f₁, f₀]]` over the half-degree ring with variable `ξ = X²`, the stride
    /// permutation of Section 2.3. As in `Sample2z`, the odd part is drawn first with
    /// covariance `f₀`; the even part then has centre `c₀ + ξf₁/f₀·(x₁ − c₁)` and covariance
    /// `f₀ − |f₁|²/f₀`. Figure 4 writes `Sample2z(f₀, f₁, f₀, c)`; the off-diagonal entry that
    /// Section 2.3 gives, and that the centre needs, is `ξ·f₁`. At degree 2 a self-adjoint
    /// element is a real scalar (`f₁ = 0`), so the two halves are independent.
    fn sample_ring(
        &self,
        f: &[f64],
        centre: &[Complex],
        degree: usize,
        uniform: &mut Uniform<'_>,
    ) -> (Zeroizing<Vec<i64>>, Zeroizing<Vec<Complex>>) {
        if degree == 1 {
            let z = sample_z(uniform, centre[0].re, f[0].sqrt());
            return (
                Zeroizing::new(vec![z]),
                // A draw is below 2^52 by the bound on |c| + 13σ: exact.
                Zeroizing::new(vec![Complex::real(z as f64)]),
            );
        }
        let half = degree / 2;
        let (centre_even, centre_odd) = self.fft.split(centre, degree);
        if degree == 2 {
            // A self-adjoint element of degree 2 is a real scalar: two independent draws.
            let (odd, odd_fft) = self.sample_ring(f, &centre_odd, half, uniform);
            let (even, even_fft) = self.sample_ring(f, &centre_even, half, uniform);
            return (
                Zeroizing::new(vec![even[0], odd[0]]),
                self.fft.merge(&even_fft, &odd_fft, degree),
            );
        }
        let (f_even, f_odd): (Vec<f64>, Vec<Complex>) = self
            .fft
            .roots(degree)
            .iter()
            .step_by(2)
            .zip(f.as_chunks::<2>().0)
            .map(|(zeta, pair)| {
                (
                    (pair[0] + pair[1]) / 2.0,
                    zeta.conj().scale((pair[0] - pair[1]) / 2.0),
                )
            })
            .unzip();
        let (f_even, f_odd) = (Zeroizing::new(f_even), Zeroizing::new(f_odd));
        let (odd, odd_fft) = self.sample_ring(&f_even, &centre_odd, half, uniform);
        let (conditional_centre, conditional): (Vec<Complex>, Vec<f64>) = self
            .fft
            .roots(half)
            .iter()
            .zip(f_even.iter().zip(f_odd.iter()))
            .zip(
                centre_even
                    .iter()
                    .zip(odd_fft.iter().zip(centre_odd.iter())),
            )
            .map(|((xi, (f0, f1)), (c0, (x1, c1)))| {
                let coupling = (*xi * *f1).scale(1.0 / f0);
                (*c0 + coupling * (*x1 - *c1), f0 - f1.norm_sq() / f0)
            })
            .unzip();
        let (conditional_centre, conditional) = (
            Zeroizing::new(conditional_centre),
            Zeroizing::new(conditional),
        );
        let (even, even_fft) = self.sample_ring(&conditional, &conditional_centre, half, uniform);
        (
            Zeroizing::new(
                even.iter()
                    .zip(odd.iter())
                    .flat_map(|(&e, &o)| [e, o])
                    .collect(),
            ),
            self.fft.merge(&even_fft, &odd_fft, degree),
        )
    }
}

/// The trapdoor's values, the factors and the pivots overwrite themselves when dropped.
impl ZeroizeOnDrop for Perturbation {}

/// The index of `L_{r,i}`, `i < r`.
fn index(r: usize, i: usize) -> usize {
    r * (r - 1) / 2 + i
}

impl fmt::Debug for Perturbation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Perturbation")
            .field("degree", &self.degree)
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl Perturbation {
    /// The centre `−(α²/(V₀ − α²))·T·p₂` of `p₁` for `p₂ = bottom`, as coefficients, computed
    /// in the FFT domain as [`Perturbation::sample`] does.
    pub(crate) fn top_centre(&self, bottom: &[i64]) -> Vec<f64> {
        let bottom_fft: Vec<Zeroizing<Vec<Complex>>> = bottom
            .chunks_exact(self.degree)
            .map(|entry| {
                self.fft
                    .forward(&entry.iter().map(|&t| t as f64).collect::<Vec<_>>())
            })
            .collect();
        (0..self.rows)
            .flat_map(|i| {
                let values: Vec<Complex> = (0..self.degree / 2)
                    .map(|j| {
                        (0..self.cols)
                            .fold(Complex::default(), |acc, c| {
                                acc + self.trapdoor[i * self.cols + c][j] * bottom_fft[c][j]
                            })
                            .scale(self.centre_scale)
                    })
                    .collect();
                self.fft.inverse(&values, self.degree)
            })
            .collect()
    }

    /// The least pivot over all rows and roots, divided by `V₀`.
    pub(crate) fn least_pivot_ratio(&self, stage: &Stage) -> f64 {
        self.pivots
            .iter()
            .flatten()
            .fold(f64::INFINITY, |acc, &p| acc.min(p))
            / stage.variance()
    }

    /// The largest error of an FFT round trip over the polynomials of `values`.
    pub(crate) fn round_trip_error(&self, values: &[i64]) -> f64 {
        values
            .chunks_exact(self.degree)
            .flat_map(|entry| {
                let real: Vec<f64> = entry.iter().map(|&t| t as f64).collect();
                let back = self.fft.inverse(&self.fft.forward(&real), self.degree);
                real.into_iter()
                    .zip(back)
                    .map(|(x, y)| (x - y).abs())
                    .collect::<Vec<_>>()
            })
            .fold(0.0, f64::max)
    }

    /// `√(V₀ − α²)` and `−α²/(V₀ − α²)`.
    pub(crate) fn bottom(&self) -> (f64, f64) {
        (self.bottom_std, self.centre_scale)
    }
}

#[cfg(test)]
mod tests {
    use super::{Perturbation, TrapdoorShape};
    use crate::{
        error::Error,
        preimage::{Stage, Uniform, fft::Fft},
        sample::{DomainLabel, Seed, xof},
    };

    /// The integer matrix of multiplication by `a` in `Z[X]/(X^d + 1)`: column `j` is `X^j·a`.
    fn rotation(a: &[i64]) -> Vec<Vec<f64>> {
        let d = a.len();
        let mut m = vec![vec![0.0; d]; d];
        for (k, row) in m.iter_mut().enumerate() {
            for (j, entry) in row.iter_mut().enumerate() {
                // Entry (k, j) is the coefficient of X^k in X^j·a.
                *entry = if k >= j {
                    a[k - j] as f64
                } else {
                    -(a[k + d - j] as f64)
                };
            }
        }
        m
    }

    /// A small trapdoor with its shape, and a stage whose `V₀` makes the pivot condition hold.
    struct Fixture {
        coefficients: Vec<i64>,
        shape: TrapdoorShape,
        stage: Stage,
    }

    /// The test trapdoor and stage.
    fn fixture() -> Fixture {
        let shape = TrapdoorShape {
            rows: 2,
            cols: 2,
            degree: 4,
        };
        let coefficients = vec![3, -1, 0, 2, 1, 1, -2, 0, 0, 2, 1, -1, -1, 0, 3, 1];
        let stage = Stage {
            least_variance: 4000,
            gadget_base_variance: 5,
            gadget_variance: 30,
            tail: 900,
        };
        Fixture {
            coefficients,
            shape,
            stage,
        }
    }

    /// The empirical covariance of `p` agrees with `Σ_p = V₀·I − α²·[T; I][T; I]ᵀ`, computed
    /// over the integers, entry by entry, within five standard errors.
    #[test]
    fn covariance_matches_the_target() {
        const SAMPLES: usize = 100_000;
        let Fixture {
            coefficients,
            shape,
            stage,
        } = fixture();
        let perturbation = Perturbation::new(&coefficients, shape, &stage).unwrap();
        let d = shape.degree;
        let (top, left) = (shape.rows * d, shape.cols * d);
        let n = top + left;
        // R = [T; I] over the integers, (top + left) × left.
        let mut r = vec![vec![0.0; left]; n];
        for a in 0..shape.rows {
            for c in 0..shape.cols {
                let entry = &coefficients[(a * shape.cols + c) * d..][..d];
                for (i, row) in rotation(entry).into_iter().enumerate() {
                    r[a * d + i][c * d..(c + 1) * d].copy_from_slice(&row);
                }
            }
        }
        for i in 0..left {
            r[top + i][i] = 1.0;
        }
        let v0 = stage.least_variance as f64;
        let alpha_sq = stage.gadget_variance as f64;
        let target = |i: usize, j: usize| {
            let rr: f64 = (0..left).map(|c| r[i][c] * r[j][c]).sum();
            if i == j {
                v0 - alpha_sq * rr
            } else {
                -alpha_sq * rr
            }
        };
        let mut reader = xof(&Seed::from([7; 32]), DomainLabel::from(&b"p"[..]));
        let mut uniform = Uniform::new(&mut reader);
        let mut sums = vec![0.0; n];
        let mut products = vec![vec![0.0; n]; n];
        for _ in 0..SAMPLES {
            let p = perturbation.sample(&mut uniform);
            assert_eq!(p.len(), n);
            for i in 0..n {
                sums[i] += p[i] as f64;
                for j in 0..=i {
                    products[i][j] += (p[i] * p[j]) as f64;
                }
            }
        }
        let count = SAMPLES as f64;
        for i in 0..n {
            assert!(
                (sums[i] / count).abs() < 5.0 * (v0 / count).sqrt(),
                "mean {i}"
            );
            for (j, product) in products[i].iter().enumerate().take(i + 1) {
                let empirical = product / count;
                let want = target(i, j);
                let error = 5.0 * ((target(i, i) * target(j, j) + want * want) / count).sqrt();
                assert!(
                    (empirical - want).abs() < error,
                    "({i}, {j}): {empirical} vs {want}"
                );
            }
        }
    }

    /// A stage whose `V₀` leaves a pivot below `V₀/4` refuses the trapdoor.
    #[test]
    fn small_pivots_refuse_the_trapdoor() {
        let Fixture {
            coefficients,
            shape,
            mut stage,
        } = fixture();
        stage.least_variance = 1200;
        assert_eq!(
            Perturbation::new(&coefficients, shape, &stage).err(),
            Some(Error::InvalidTrapdoor)
        );
        assert!(format!("{:?}", Fft::new(4)).starts_with("Fft"));
    }
}
