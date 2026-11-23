// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic uniform sampling over `R_q` from a seed, through SHAKE256.
//!
//! Everything random in the crate that must be reproducible comes from a SHAKE256 stream of a
//! 32-byte [`Seed`] under a [`DomainLabel`]: the public matrices `A`, `B`, `u` of `Gen`
//! (Construction 4.1, ePrint 2025/1099), the trapdoor `T_A`, the PRF outputs that seed
//! `SampleLeft`, and the prover's masks. Distinct labels give independent streams from one
//! seed, so a key needs to keep only its root seed. [`UniformSampler`] is the public face of
//! this: uniform polynomials, vectors and matrices over `R_q` by rejection sampling.
//!
//! # Secret handling
//!
//! A [`Seed`] may be secret (root seeds, PRF keys, the state-tag key) or public (the seed of
//! the proof commitment key), so every seed is treated as secret: it is overwritten when
//! dropped, compared in constant time, and printed without its bytes. The SHAKE256 hasher
//! and reader behind every stream are built with `sha3`'s `zeroize` feature, so their Keccak
//! state, from which the absorbed seed could be recovered by inverting the permutation, is
//! overwritten when they are dropped.
//!
//! ```
//! use kln_accumulator::Params;
//! use kln_accumulator::lattice::{DomainLabel, Seed, Shape, UniformSampler};
//!
//! let params = Params::toy()?;
//! let ring = params.ring();
//! let seed = Seed::from([7; 32]);
//! let mut a = UniformSampler::new(&seed, DomainLabel::from(&b"stream a"[..]));
//! let mut b = UniformSampler::new(&seed, DomainLabel::from(&b"stream b"[..]));
//! let first = a.vector(2, ring);
//! // The same seed and label give the same stream; another label another one.
//! let mut again = UniformSampler::new(&seed, DomainLabel::from(&b"stream a"[..]));
//! assert_eq!(again.vector(2, ring), first);
//! assert_ne!(b.vector(2, ring), first);
//! let m = a.matrix(Shape { rows: 2, cols: 3 }, ring);
//! assert!(m.validate(ring).is_ok());
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

use crate::{
    matrix::{PolyMatrix, Shape},
    poly::Poly,
    ring::Ring,
    vector::PolyVec,
    zq::Coeff,
};
use core::fmt;
use ctutils::CtEq;
use sha3::{
    Shake256, Shake256Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte sampling seed: the input of a SHAKE256 stream.
///
/// **Secret.** A seed is treated as secret wherever it is used: it is overwritten when dropped
/// ([`ZeroizeOnDrop`]), it is neither `Copy` nor `Clone`, equality is constant time, and
/// [`fmt::Debug`] prints no bytes. The crate never hands out the bytes of a seed it derives;
/// a caller builds one from 32 bytes with `From<[u8; 32]>` and keeps the source array, which
/// it must wipe itself.
///
/// # Examples
///
/// ```
/// use kln_accumulator::lattice::Seed;
///
/// let seed = Seed::from([1; 32]);
/// assert_eq!(seed, Seed::from([1; 32]));
/// assert_ne!(seed, Seed::from([2; 32]));
/// assert_eq!(format!("{seed:?}"), "Seed { .. }");
/// ```
#[derive(derive_more::From)]
pub struct Seed([u8; 32]);

impl Seed {
    /// The seed bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The next 32 bytes of `reader`, read straight into the seed so that no other copy is
    /// made.
    pub(crate) fn read_from(reader: &mut impl XofReader) -> Self {
        let mut seed = Self([0; 32]);
        reader.read(&mut seed.0);
        seed
    }
}

/// Overwrites the seed.
impl Zeroize for Seed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Seed {}

/// Compares in constant time.
impl PartialEq for Seed {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Seed {}

/// Prints no seed bytes.
impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Seed").finish_non_exhaustive()
    }
}

/// A label that separates independent streams drawn from the same [`Seed`]. **Public.**
///
/// The stream absorbs the label's length before the label, so no two labels collide. The
/// crate's own labels are byte strings of the form `kln/<component>/<purpose>`.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{DomainLabel, Seed, UniformSampler};
///
/// let params = Params::toy()?;
/// let seed = Seed::from([0; 32]);
/// let draw = |label: &[u8]| UniformSampler::new(&seed, DomainLabel::from(label)).poly(params.ring());
/// assert_ne!(draw(b"one"), draw(b"two"));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, derive_more::From)]
pub struct DomainLabel<'a>(&'a [u8]);

/// A SHAKE256 stream of uniform elements of `Z_q`, by rejection sampling: each candidate is the
/// next `⌈log₂ q⌉` bits (little-endian, in whole bytes with the excess high bits cleared) and is
/// kept only when below `q`.
///
/// The XOF absorbs `len(label) as u64 (little-endian) ‖ label ‖ seed`, so the same seed and
/// label always yield the same stream. Entries of vectors and matrices are drawn in order,
/// row-major for matrices. A candidate is refused with probability `1 − q/2^{⌈log₂ q⌉}`, below
/// one half, so a coefficient costs fewer than two candidates on average.
///
/// **Public output, secret state.** The values drawn are as public as the seed allows, but the
/// SHAKE256 state gives back the seed, so it is overwritten when the sampler is dropped
/// ([`ZeroizeOnDrop`]) and [`fmt::Debug`] does not print it.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{DomainLabel, Seed, Shape, UniformSampler};
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let mut sampler = UniformSampler::new(&Seed::from([3; 32]), DomainLabel::from(&b"doc"[..]));
/// let p = sampler.poly(ring);
/// let v = sampler.vector(4, ring);
/// let m = sampler.matrix(Shape { rows: 1, cols: 20 }, ring);
/// assert_eq!(p.coefficients().len(), ring.degree());
/// assert_eq!(v.len(), 4);
/// assert_eq!(m.shape(), Shape { rows: 1, cols: 20 });
/// // Every coefficient is reduced modulo q.
/// assert!(p.validate(ring).is_ok() && v.validate(ring).is_ok() && m.validate(ring).is_ok());
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub struct UniformSampler {
    reader: Shake256Reader,
}

impl UniformSampler {
    /// Starts the stream for `seed` under `label`. The seed is absorbed at once; the sampler
    /// does not keep a reference to it. See the type's example.
    #[must_use]
    pub fn new(seed: &Seed, label: DomainLabel<'_>) -> Self {
        Self {
            reader: xof(seed, label),
        }
    }

    /// The next uniform polynomial: `d` coefficients in `[0, q)`, constant term first. See the
    /// type's example.
    pub fn poly(&mut self, ring: &Ring) -> Poly {
        Poly::from_reduced((0..ring.degree()).map(|_| self.coefficient(ring)).collect())
    }

    /// The next `len` uniform polynomials as a vector; see the type's example.
    pub fn vector(&mut self, len: usize, ring: &Ring) -> PolyVec {
        (0..len).map(|_| self.poly(ring)).collect()
    }

    /// The next `rows · cols` uniform polynomials as a matrix, row-major; see the type's
    /// example.
    pub fn matrix(&mut self, shape: Shape, ring: &Ring) -> PolyMatrix {
        PolyMatrix::from_parts(
            shape,
            (0..shape.rows * shape.cols)
                .map(|_| self.poly(ring))
                .collect(),
        )
    }

    fn coefficient(&mut self, ring: &Ring) -> Coeff {
        let bits = ring.modulus_bits();
        let bytes = bits.div_ceil(8);
        let len = bytes as usize;
        let excess = bytes * 8 - bits;
        let mut buffer = [0u8; Coeff::BYTES];
        loop {
            self.reader.read(&mut buffer[..len]);
            buffer[len - 1] &= 0xff >> excess;
            let candidate = Coeff::from_le_slice(&buffer);
            if ring.zq().is_reduced(&candidate) {
                return candidate;
            }
        }
    }
}

/// The SHAKE256 stream for `seed` under `label`: the XOF absorbs
/// `len(label) as u64 (little-endian) ‖ label ‖ seed`. Every seeded sampler in the crate reads
/// from one of these, so distinct labels give independent streams from one seed.
pub(crate) fn xof(seed: &Seed, label: DomainLabel<'_>) -> Shake256Reader {
    let mut hasher = Shake256::default();
    hasher.update(&(label.0.len() as u64).to_le_bytes());
    hasher.update(label.0);
    hasher.update(&seed.0);
    hasher.finalize_xof()
}

/// The SHAKE256 stream of `parts` under `label`: the XOF absorbs `len(label) as u64 ‖ label`
/// and then `len(part) as u64 ‖ part` for every part (lengths little-endian). The length
/// prefixes make the encoding injective.
pub(crate) fn hash_parts(label: DomainLabel<'_>, parts: &[&[u8]]) -> Shake256Reader {
    let mut hasher = Shake256::default();
    for part in core::iter::once(&label.0).chain(parts) {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize_xof()
}

/// The [`Seed`] made of the first 32 bytes of [`hash_parts`].
pub(crate) fn hash_to_seed(label: DomainLabel<'_>, parts: &[&[u8]]) -> Seed {
    Seed::read_from(&mut hash_parts(label, parts))
}

/// With `sha3`'s `zeroize` feature the SHAKE256 reader overwrites its state when dropped. The
/// state matters even though the sampled values are public: Keccak-f is a permutation, so the
/// state of a stream gives back the seed it absorbed.
impl ZeroizeOnDrop for UniformSampler {}

impl fmt::Debug for UniformSampler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UniformSampler").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainLabel, Seed, UniformSampler};
    use crate::{
        matrix::Shape,
        test_util::{PAPER, TOY},
        zq::Coeff,
    };
    use proptest::prelude::*;

    const LABEL: &[u8] = b"kln/test";

    #[test]
    fn debug_hides_state() {
        let sampler = UniformSampler::new(&Seed::from([0; 32]), DomainLabel::from(LABEL));
        assert_eq!(format!("{sampler:?}"), "UniformSampler { .. }");
    }

    #[test]
    fn coefficients_cover_the_range() {
        // Over 64·64 = 4096 uniform draws, the top bit of the 60-bit q is set in roughly half
        // and every sample is reduced.
        let ring = TOY.ring();
        let mut sampler = UniformSampler::new(&Seed::from([7; 32]), DomainLabel::from(LABEL));
        let v = sampler.vector(64, ring);
        let all: Vec<&Coeff> = v.as_slice().iter().flat_map(|p| p.coefficients()).collect();
        assert!(v.validate(ring).is_ok());
        let high = all.iter().filter(|c| c.bit_width_vartime() == 60).count();
        assert!((1800..2300).contains(&high), "{high}");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn same_seed_and_label_reproduce(seed in any::<[u8; 32]>()) {
            let ring = TOY.ring();
            let draw = |label: &[u8]| {
                let mut s = UniformSampler::new(&Seed::from(seed), DomainLabel::from(label));
                (s.poly(ring), s.vector(2, ring), s.matrix(Shape { rows: 2, cols: 3 }, ring))
            };
            let first = draw(LABEL);
            prop_assert_eq!(&first, &draw(LABEL));
            prop_assert_ne!(&first.0, &draw(b"kln/other").0);
            prop_assert!(first.0.validate(ring).is_ok());
            prop_assert_eq!(first.1.len(), 2);
            prop_assert_eq!(first.2.shape(), Shape { rows: 2, cols: 3 });
            prop_assert!(first.2.validate(ring).is_ok());
        }

        #[test]
        fn seeds_separate_streams(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
            prop_assume!(a != b);
            let ring = PAPER.ring();
            let mut first = UniformSampler::new(&Seed::from(a), DomainLabel::from(LABEL));
            let mut second = UniformSampler::new(&Seed::from(b), DomainLabel::from(LABEL));
            let p = first.poly(ring);
            prop_assert!(p.validate(ring).is_ok());
            prop_assert_ne!(p, second.poly(ring));
        }
    }
}
