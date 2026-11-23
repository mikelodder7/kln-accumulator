// SPDX-License-Identifier: MIT OR Apache-2.0
//! The complex FFT of `R[X]/(X^d + 1)`, `d` a power of two, written with only basic `f64`
//! operations and square roots.
//!
//! A real polynomial `f` of degree below `d ≥ 2` is represented by its values at `d/2` roots
//! of `X^d + 1`, one from each conjugate pair: for `d = 2` the single root `i`, and for `2d`
//! the two square roots `±√ξ` of each root `ξ` used at `d`, in that order, so that entries
//! `2t` and `2t + 1` are `f(ζ_t)` and `f(−ζ_t)` with `ζ_t² = ξ_t`. A polynomial of degree 0
//! (the ring `R[X]/(X + 1)`) is its constant, stored as one value with zero imaginary part.
//!
//! With `f(X) = f₀(X²) + X·f₁(X²)`, [`Fft::split`] and [`Fft::merge`] move between the values
//! of `f` and those of `f₀` and `f₁`, which is both the FFT's recursion and the even/odd
//! split that the ring Gaussian sampler recurses on: the butterfly ePrint 2017/308,
//! Section 4.1 (Efficiency) uses to run `SampleFz` in the Fourier domain. Products in this
//! representation are pointwise, and the adjoint `f*(X) = f(X⁻¹)`, which is the transpose of
//! the anti-cyclic multiplication matrix (ePrint 2017/308, Section 2.3), is the complex
//! conjugate.

use core::ops::{Add, Mul, Neg, Sub};
use zeroize::{Zeroize, Zeroizing};

/// A complex number.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Complex {
    /// The real part.
    pub(crate) re: f64,
    /// The imaginary part.
    pub(crate) im: f64,
}

impl Complex {
    /// `re + 0i`.
    pub(crate) fn real(re: f64) -> Self {
        Self { re, im: 0.0 }
    }

    /// The conjugate.
    pub(crate) fn conj(self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    /// `|z|²`.
    pub(crate) fn norm_sq(self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    /// The product with a real number.
    pub(crate) fn scale(self, factor: f64) -> Self {
        Self {
            re: self.re * factor,
            im: self.im * factor,
        }
    }

    /// The principal square root, `√((|z| + re)/2) ± i·√((|z| − re)/2)` with the sign of `im`.
    fn sqrt(self) -> Self {
        let modulus = self.norm_sq().sqrt();
        let re = ((modulus + self.re) / 2.0).sqrt();
        let im = ((modulus - self.re) / 2.0).sqrt();
        Self {
            re,
            im: if self.im < 0.0 { -im } else { im },
        }
    }
}

impl Add for Complex {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }
}

impl Sub for Complex {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }
}

impl Mul for Complex {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }
}

impl Neg for Complex {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            re: -self.re,
            im: -self.im,
        }
    }
}

impl Zeroize for Complex {
    fn zeroize(&mut self) {
        self.re.zeroize();
        self.im.zeroize();
    }
}

/// The roots of unity for every degree up to `d`.
#[derive(Clone, Debug)]
pub(crate) struct Fft {
    /// `roots[j]` holds the `2^{j−1}` roots used at degree `2^j`, for `1 ≤ j ≤ log₂ d`;
    /// `roots[0]` is empty.
    roots: Vec<Vec<Complex>>,
}

impl Fft {
    /// The roots for degree `d`, a power of two.
    pub(crate) fn new(degree: usize) -> Self {
        let levels = degree.trailing_zeros() as usize;
        let mut roots = vec![Vec::new(), vec![Complex { re: 0.0, im: 1.0 }]];
        for level in 2..=levels {
            let next = roots[level - 1]
                .iter()
                .flat_map(|xi| {
                    let zeta = xi.sqrt();
                    [zeta, -zeta]
                })
                .collect();
            roots.push(next);
        }
        roots.truncate(levels + 1);
        Self { roots }
    }

    /// The roots used at `degree`; empty for degree 1, whose root `−1` is real.
    pub(crate) fn roots(&self, degree: usize) -> &[Complex] {
        &self.roots[degree.trailing_zeros() as usize]
    }

    /// The values of the real polynomial with coefficients `f` (degree `f.len()`).
    ///
    /// Every value this FFT handles comes from the trapdoor or from a perturbation that hides
    /// it, so its results and intermediates are overwritten when dropped.
    pub(crate) fn forward(&self, f: &[f64]) -> Zeroizing<Vec<Complex>> {
        if f.len() == 1 {
            return Zeroizing::new(vec![Complex::real(f[0])]);
        }
        let even: Zeroizing<Vec<f64>> = Zeroizing::new(f.iter().step_by(2).copied().collect());
        let odd: Zeroizing<Vec<f64>> =
            Zeroizing::new(f.iter().skip(1).step_by(2).copied().collect());
        self.merge(&self.forward(&even), &self.forward(&odd), f.len())
    }

    /// The values of `f₀` and `f₁` at degree `degree/2` from those of `f` at `degree`.
    pub(crate) fn split(
        &self,
        values: &[Complex],
        degree: usize,
    ) -> (Zeroizing<Vec<Complex>>, Zeroizing<Vec<Complex>>) {
        if degree == 2 {
            return (
                Zeroizing::new(vec![Complex::real(values[0].re)]),
                Zeroizing::new(vec![Complex::real(values[0].im)]),
            );
        }
        let (even, odd) = self
            .roots(degree)
            .iter()
            .step_by(2)
            .zip(values.as_chunks::<2>().0)
            .map(|(zeta, pair)| {
                (
                    (pair[0] + pair[1]).scale(0.5),
                    ((pair[0] - pair[1]) * zeta.conj()).scale(0.5),
                )
            })
            .unzip();
        (Zeroizing::new(even), Zeroizing::new(odd))
    }

    /// The values of `f(X) = f₀(X²) + X·f₁(X²)` at `degree` from those of `f₀` and `f₁`.
    pub(crate) fn merge(
        &self,
        even: &[Complex],
        odd: &[Complex],
        degree: usize,
    ) -> Zeroizing<Vec<Complex>> {
        if degree == 2 {
            return Zeroizing::new(vec![Complex {
                re: even[0].re,
                im: odd[0].re,
            }]);
        }
        Zeroizing::new(
            self.roots(degree)
                .iter()
                .step_by(2)
                .zip(even.iter().zip(odd))
                .flat_map(|(&zeta, (&e, &o))| {
                    let rotated = zeta * o;
                    [e + rotated, e - rotated]
                })
                .collect(),
        )
    }
}

#[cfg(test)]
impl Fft {
    /// The coefficients of the real polynomial of `degree` with values `values`.
    pub(crate) fn inverse(&self, values: &[Complex], degree: usize) -> Vec<f64> {
        if degree == 1 {
            return vec![values[0].re];
        }
        let (even, odd) = self.split(values, degree);
        let (even, odd) = (
            self.inverse(&even, degree / 2),
            self.inverse(&odd, degree / 2),
        );
        even.into_iter()
            .zip(odd)
            .flat_map(|(e, o)| [e, o])
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Complex, Fft};

    fn negacyclic(a: &[f64], b: &[f64]) -> Vec<f64> {
        let d = a.len();
        let mut c = vec![0.0; d];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                if i + j < d {
                    c[i + j] += x * y;
                } else {
                    c[i + j - d] -= x * y;
                }
            }
        }
        c
    }

    fn pseudo_random(len: usize, salt: u64) -> Vec<f64> {
        (0..len as u64)
            .map(|i| ((i * 2_654_435_761 + salt * 40_503) % 2001) as f64 - 1000.0)
            .collect()
    }

    /// Every root used at degree `d` is a root of `X^d + 1`, and the roots and their conjugates
    /// are all distinct.
    #[test]
    fn roots_are_roots_of_the_cyclotomic() {
        let fft = Fft::new(64);
        for degree in [2usize, 4, 8, 64] {
            let roots = fft.roots(degree);
            assert_eq!(roots.len(), degree / 2);
            for zeta in roots {
                let power = (0..degree).fold(Complex::real(1.0), |acc, _| acc * *zeta);
                assert!((power.re + 1.0).abs() < 1e-12 && power.im.abs() < 1e-12);
            }
            let mut all: Vec<Complex> = roots.iter().flat_map(|z| [*z, z.conj()]).collect();
            all.sort_by(|a, b| (a.re, a.im).partial_cmp(&(b.re, b.im)).unwrap());
            assert!(all.windows(2).all(|w| (w[0] - w[1]).norm_sq() > 1e-6));
        }
    }

    /// Forward then inverse is the identity, products are pointwise, and the conjugate is the
    /// adjoint `f(X⁻¹) = f₀ − f_{d−1}X − … − f₁X^{d−1}`.
    #[test]
    fn fft_is_a_ring_isomorphism() {
        for degree in [1usize, 2, 4, 16, 64, 4096] {
            let fft = Fft::new(degree.max(2));
            let (a, b) = (pseudo_random(degree, 1), pseudo_random(degree, 2));
            let (fa, fb) = (fft.forward(&a), fft.forward(&b));
            assert_eq!(fa.len(), (degree / 2).max(1));
            let back = fft.inverse(&fa, degree);
            assert!(
                a.iter()
                    .zip(&back)
                    .all(|(x, y)| (x - y).abs() < 1e-9 * degree as f64)
            );
            if degree <= 64 {
                let product: Vec<Complex> =
                    fa.iter().zip(fb.iter()).map(|(x, y)| *x * *y).collect();
                let want = negacyclic(&a, &b);
                let got = fft.inverse(&product, degree);
                assert!(want.iter().zip(&got).all(|(x, y)| (x - y).abs() < 1e-6));
                let adjoint: Vec<f64> = (0..degree)
                    .map(|i| if i == 0 { a[0] } else { -a[degree - i] })
                    .collect();
                let conj: Vec<Complex> = fa.iter().map(|z| z.conj()).collect();
                let got = fft.inverse(&conj, degree);
                assert!(adjoint.iter().zip(&got).all(|(x, y)| (x - y).abs() < 1e-9));
            }
        }
    }

    /// `split` inverts `merge` and gives the values of the even and odd parts.
    #[test]
    fn split_merge() {
        let fft = Fft::new(32);
        let f = pseudo_random(32, 3);
        let values = fft.forward(&f);
        let (even, odd) = fft.split(&values, 32);
        let want_even = fft.forward(&f.iter().step_by(2).copied().collect::<Vec<_>>());
        let want_odd = fft.forward(&f.iter().skip(1).step_by(2).copied().collect::<Vec<_>>());
        assert!(
            even.iter()
                .zip(want_even.iter())
                .all(|(x, y)| (*x - *y).norm_sq() < 1e-18 * 1e6)
        );
        assert!(
            odd.iter()
                .zip(want_odd.iter())
                .all(|(x, y)| (*x - *y).norm_sq() < 1e-18 * 1e6)
        );
        let merged = fft.merge(&even, &odd, 32);
        assert!(
            merged
                .iter()
                .zip(values.iter())
                .all(|(x, y)| (*x - *y).norm_sq() < 1e-18 * 1e6)
        );
    }
}
