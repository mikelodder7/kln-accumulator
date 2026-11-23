// SPDX-License-Identifier: MIT OR Apache-2.0
//! The gadget trapdoor of Theorem 2.1 and the preimage samplers `SamplePre` (Theorem 2.1) and
//! `SampleLeft` (Lemma 2.6).
//!
//! `TrapGen` is `GenTrap` of ePrint 2011/501, Section 5.2, Algorithm 1, over the ring with tag
//! `H = I`: it draws `T_A` from the set's [`crate::TrapdoorDistribution`] and returns
//! `A = [Ā | G − Ā·T_A]`, so `A·[T_A; I] = G` and `T_A` is a G-trapdoor for `A` (its
//! Definition 5.2). For the Gaussian distribution the coefficients have the width `ς`
//! Theorem 2.1 asks for, so that `A` is statistically close to uniform (Algorithm 1's
//! statistical instantiation, with the regularity that Theorem 2.1 provides); for the ternary
//! one they are uniform in `{−1, 0, 1}`, a bounded symmetric distribution and so subgaussian
//! (ePrint 2011/501, Section 2.4), and `A` is pseudorandom under Module-LWE with ternary
//! secrets, as in Algorithm 1's computational instantiation. A preimage of width `s` is built
//! from two independent parts whose variances add up (ePrint 2017/308's reference [55], Theorem 3.1):
//!
//! * a wide spherical draw `y` of variance `V_y` over all coordinates, by the crate's
//!   integer-only table sampler;
//! * the trapdoor stage at the least variance `V₀` on the residual target `c − H·y`: for
//!   `H = [A | B']` the extension coordinates are a spherical draw `e` of variance `V₀`, and the
//!   first `m` a preimage of `c − H·y − B'·e` under `A` by `SampleD` of ePrint 2011/501,
//!   Section 5.4, Algorithm 3, with the samplers of ePrint 2017/308 ([`crate::preimage`]).
//!
//! The result is `A`'s or `H`'s coset of `c` with spherical width `s = √(2π·(V_y + V₀))`, and
//! `H·v = c` holds exactly. All randomness comes from one SHAKE256 stream of the seed, and the
//! only floating point is the basic IEEE-754 arithmetic of [`crate::preimage`], so a seed
//! gives the same preimage on every platform (Remark 4.1).

use crate::{
    error::{Error, Result, check_dimension},
    gaussian::{DiscreteGaussian, Lookup},
    matrix::{NttMatrix, PolyMatrix, Shape},
    params::Params,
    poly::Poly,
    preimage::{GadgetSampler, Perturbation, Uniform, perturbation::TrapdoorShape, spherical},
    ring::Ring,
    sample::{DomainLabel, Seed, UniformSampler, hash_to_seed, xof},
    secret_hex,
    vector::PolyVec,
    zq::Coeff,
};
use core::{fmt, num::NonZeroU32};
use crypto_bigint::{Limb, NonZero, U512};
use ctutils::CtEq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Shake256Reader, digest::XofReader};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// XOF label of the uniform block `Ā` in `TrapGen`.
const LABEL_UNIFORM: &[u8] = b"kln/trapgen/uniform";

/// XOF label of the trapdoor `T_A` in `TrapGen`, for either distribution.
const LABEL_TRAPDOOR: &[u8] = b"kln/trapgen/gaussian";

/// XOF label of the randomness of `SampleLeft` and `SamplePre`.
const LABEL_GAUSSIAN: &[u8] = b"kln/sample-left/gaussian";

/// Label that binds the caller's seed to the matrix, the target and the sampling mode.
const LABEL_BIND: &[u8] = b"kln/sample-left/bind";

/// Trapdoors `TrapGen` draws before giving up; one is refused with negligible probability.
const TRAPGEN_ATTEMPTS: usize = 8;

/// Trapdoor-stage draws a preimage makes before giving up; one passes the tail cut except with
/// probability below `2^-100`.
const SAMPLE_ATTEMPTS: usize = 8;

/// Bytes per coefficient in the trapdoor's encoding.
const COEFFICIENT_BYTES: usize = 8;

/// The trapdoor `T_A ∈ R^{(m−m')×m'}` of `A = [Ā | G − Ā·T_A]`, with coefficients from the
/// set's [`crate::TrapdoorDistribution`]: discrete Gaussian of width `ς`
/// ([`crate::Bounds::trapdoor_width`]) or uniform in `{−1, 0, 1}`.
///
/// Stored as `(m−m')·m'·d` signed integers, entries row-major and each entry's coefficients
/// constant term first. Serialized as 8 little-endian two's-complement bytes per coefficient:
/// raw in binary formats, hex in human-readable ones; `From<&Trapdoor> for Zeroizing<Vec<u8>>`
/// and `TryFrom<&[u8]>` are the same bytes without serde. The count and range are checked
/// against a set when the trapdoor is used, failing with [`Error::DimensionMismatch`] or
/// [`Error::InvalidTrapdoor`].
///
/// # What is established
///
/// The sampler's widths are derived per set from the smoothing conditions of ePrint 2011/501
/// and ePrint 2017/308 at `ε = 2^-128` (`src/params/widths.rs`), and `H·v = c` is exact. Its
/// floating-point error is not bounded by proof: ePrint 2017/308's Proposition 3.1 assumes a
/// 64-bit mantissa where `f64` has 53, and its Section 4 gives no analysis of the perturbation
/// sampler. The trapdoor is refused unless every perturbation pivot is at least `V₀/4`, and the
/// crate's tests measure the error of the computed centres against the least conditional
/// standard deviation (below `2^-40` at every defined set; see `src/preimage.rs`); that is
/// evidence, not a bound. Determinism assumes IEEE-754 binary64 without x87 extended
/// precision.
///
/// # Secret handling
///
/// [`Trapdoor`] is secret: its coefficients, its NTT and FFT forms, the perturbation
/// sampler's factors, and every intermediate of a draw (the wide Gaussian draw, the
/// perturbation, the G-lattice samples, the stream buffers) are overwritten when dropped, on
/// every return path. Two different short preimages of one target under one matrix give away a
/// short vector of its kernel, and enough of them the trapdoor (Remark 4.1 of ePrint
/// 2025/1099); the accumulator therefore derives every seed from a PRF so that it never samples
/// twice for one target. A caller of [`Trapdoor::sample_pre`] and [`Trapdoor::sample_left`]
/// directly must keep that rule itself: one seed per target, never two different preimages.
/// The reverse does not repeat a draw: the samplers hash the seed together with the matrix, the
/// target and the sampling mode before drawing, so one seed used for two targets or two
/// matrices gives draws that share no randomness.
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{DomainLabel, Seed, Trapdoor, UniformSampler};
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let (a, trapdoor) = Trapdoor::generate(&params, &Seed::from([1; 32]))?;
/// let u = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"u"[..]))
///     .vector(params.spec().n, ring);
/// let v = trapdoor.sample_pre(&params, &a, &u, &Seed::from([3; 32]))?;
/// assert_eq!(a.mul_vec(&v, ring)?, u);
/// // The same seed gives the same preimage.
/// assert_eq!(trapdoor.sample_pre(&params, &a, &u, &Seed::from([3; 32]))?, v);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
///
/// # Protection
///
/// **Secret.** The coefficients are overwritten when the value is dropped
/// ([`ZeroizeOnDrop`]); it is neither `Copy` nor `Clone`; equality is constant time in the
/// coefficients; [`fmt::Debug`] does not print them; its encodings are built and parsed in
/// buffers wiped on drop. The accumulator's [`crate::SecretKey`] holds one and never exposes
/// it. See "Secret handling" above for the rule a direct caller must keep.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{Seed, Trapdoor};
/// use zeroize::Zeroizing;
///
/// let params = Params::toy()?;
/// let (a, trapdoor) = Trapdoor::generate(&params, &Seed::from([1; 32]))?;
/// assert_eq!(a.shape().cols, params.spec().m);
/// // (m − m')·m'·d coefficients of 8 bytes.
/// let bytes = Zeroizing::<Vec<u8>>::from(&trapdoor);
/// assert_eq!(bytes.len(), 10 * 10 * 64 * 8);
/// assert_eq!(Trapdoor::try_from(bytes.as_slice())?, trapdoor);
/// assert_eq!(format!("{trapdoor:?}"), "Trapdoor { .. }");
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub struct Trapdoor {
    coefficients: Vec<i64>,
}

impl Trapdoor {
    /// `TrapGen` (Theorem 2.1, Construction 4.1 Gen step 1; ePrint 2011/501, Algorithm 1 with
    /// `H = I`): from `seed`, draws `Ā` uniform in `R_q^{n×(m−m')}` and `T_A` from the set's
    /// [`crate::TrapdoorDistribution`], and returns `A = [Ā | G − Ā·T_A]` with `T_A`, so that
    /// `A·[T_A; I_{m'}] = G`.
    ///
    /// A drawn `T_A` is kept only if its perturbation covariance has every pivot at least
    /// `V₀/4` (see `src/preimage.rs`); otherwise the next one in the stream is drawn. Fails
    /// with [`Error::InvalidTrapdoor`] if none of the first eight is kept, which happens with
    /// negligible probability at a valid set. `A` is public; the trapdoor is secret, and so is
    /// `seed`. See the type's example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn generate(params: &Params, seed: &Seed) -> Result<(PolyMatrix, Self)> {
        let ring = params.ring();
        let shape = Self::shape(params);
        let a_bar = UniformSampler::new(seed, DomainLabel::from(LABEL_UNIFORM)).matrix(
            Shape {
                rows: params.spec().n,
                cols: shape.rows,
            },
            ring,
        );
        let count = shape.rows * shape.cols * ring.degree();
        let mut reader = xof(seed, DomainLabel::from(LABEL_TRAPDOOR));
        let trapdoor = (0..TRAPGEN_ATTEMPTS)
            .find_map(|_| {
                let candidate = Self {
                    coefficients: params.trapdoor_sampler().integers(&mut reader, count)?,
                };
                candidate.perturbation(params).ok().map(|_| candidate)
            })
            .ok_or(Error::InvalidTrapdoor)?;
        let a_bar_t = trapdoor.ntt_form(params)?.left_mul(&a_bar, ring)?;
        let right = PolyMatrix::from(params.gadget()).sub(&a_bar_t, ring)?;
        Ok((a_bar.hconcat(&right)?, trapdoor))
    }

    /// `SamplePre(A, T_A, u, s)` (Theorem 2.1): a vector `v ∈ R^m` with `A·v = u`, statistically
    /// close to `D_{Λ⊥_u(A), s}` for the set's width `s`, determined by `seed`, `A` and `u`.
    ///
    /// The result is returned modulo `q`; its centred lift is the integer preimage, exact
    /// because every coefficient is below `q/2` at any valid [`Params`]. Its norm is at most
    /// `s·√(d·m)` except with negligible probability. See the
    /// [`Trapdoor`] documentation for an example, and for why one target must never get two
    /// preimages.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `a` is `n × m` and `u` has `n` entries;
    /// [`Error::DimensionMismatch`] or [`Error::InvalidTrapdoor`] when the trapdoor does not
    /// fit `params`; [`Error::InvalidTrapdoor`] when eight trapdoor-stage draws in a row fall
    /// beyond the tail cut, which happens with probability below `2^-100`, and when `a` is not
    /// the matrix this trapdoor was generated with, since the draw is checked against `A·v = u`
    /// before it is returned.
    pub fn sample_pre(
        &self,
        params: &Params,
        a: &PolyMatrix,
        u: &PolyVec,
        seed: &Seed,
    ) -> Result<PolyVec> {
        let m = params.spec().m;
        check_dimension(m, a.shape().cols)?;
        self.sample_left(params, a, u, seed)
    }

    /// `SampleLeft(H, T_A, c, s; r)` (Lemma 2.6, Construction 4.1 Add step 3) for
    /// `H = [A | B'] ∈ R_q^{n×(m+t)}` whose first `m` columns are the `A` this trapdoor was
    /// generated with: a vector `v ∈ R^{m+t}` with `H·v = c`, statistically close to
    /// `D_{Λ⊥_c(H), s}`, determined by `seed`, `H` and `c`.
    ///
    /// The last `t` coordinates are a spherical Gaussian of width `s` and the first `m` a
    /// width-`s` preimage under `A` of what remains of `c`. As with [`Trapdoor::sample_pre`],
    /// the result is the residue of a vector with coefficients below `q/2`.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless `h` has `n` rows and at least `m` columns and `c`
    /// has `n` entries; otherwise as [`Trapdoor::sample_pre`].
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::{DomainLabel, Seed, Shape, Trapdoor, UniformSampler};
    ///
    /// let params = Params::toy()?;
    /// let ring = params.ring();
    /// let (a, trapdoor) = Trapdoor::generate(&params, &Seed::from([1; 32]))?;
    /// let mut sampler = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"h"[..]));
    /// let extension = sampler.matrix(Shape { rows: params.spec().n, cols: 5 }, ring);
    /// let h = a.hconcat(&extension)?;
    /// let c = sampler.vector(params.spec().n, ring);
    /// let v = trapdoor.sample_left(&params, &h, &c, &Seed::from([3; 32]))?;
    /// assert_eq!(v.len(), params.spec().m + 5);
    /// assert_eq!(h.mul_vec(&v, ring)?, c);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn sample_left(
        &self,
        params: &Params,
        h: &PolyMatrix,
        c: &PolyVec,
        seed: &Seed,
    ) -> Result<PolyVec> {
        self.sample(params, h, c, seed, Some(params.gaussian()))
    }

    /// [`Trapdoor::sample_left`] at the preimage sampler's least width
    /// ([`crate::Bounds::least_width`]) instead of `s`: the trapdoor stage alone.
    pub(crate) fn sample_left_least(
        &self,
        params: &Params,
        h: &PolyMatrix,
        c: &PolyVec,
        seed: &Seed,
    ) -> Result<PolyVec> {
        self.sample(params, h, c, seed, None)
    }

    /// A preimage of `c` under `h`, with the wide draw from `wide` when there is one.
    fn sample(
        &self,
        params: &Params,
        h: &PolyMatrix,
        c: &PolyVec,
        seed: &Seed,
        wide: Option<&DiscreteGaussian>,
    ) -> Result<PolyVec> {
        let ring = params.ring();
        let spec = params.spec();
        let shape = h.shape();
        check_dimension(spec.n, shape.rows)?;
        let extra = shape
            .cols
            .checked_sub(spec.m)
            .ok_or(Error::DimensionMismatch {
                expected: spec.m,
                found: shape.cols,
            })?;
        let prepared = Prepared::new(self, params)?;
        let a = h.column_block(0, spec.m)?;
        // Every draw below comes from a seed bound to what is sampled for. With the caller's
        // seed alone, one seed used for two targets or two matrices would share the wide draw
        // and the perturbation, and the difference of the two preimages would be
        // `[T_A·Δz; Δz]`, which gives `T_A` after about `m'` such pairs.
        let mut statement = Vec::new();
        h.write_coefficients(&mut statement);
        c.write_coefficients(&mut statement);
        let seed = &hash_to_seed(
            DomainLabel::from(LABEL_BIND),
            &[
                seed.as_bytes(),
                &[u8::from(wide.is_some())],
                &(shape.cols as u64).to_le_bytes(),
                &statement,
            ],
        );
        let mut reader = xof(seed, DomainLabel::from(LABEL_GAUSSIAN));
        let wide = wide.map(|gaussian| gaussian.vector(&mut reader, shape.cols, ring));
        let mut uniform = Uniform::new(&mut reader);
        let extension = spherical(
            &mut uniform,
            params.stage().variance().sqrt(),
            extra * ring.degree(),
        );
        let offset = PolyVec::zero(spec.m, ring).concat(&residues(&extension, ring));
        let offset = match wide {
            Some(y) => y.add(&offset, ring)?,
            None => offset,
        };
        // `h` is transformed once, for this product and for the check of the result.
        let transformed = NttMatrix::new(h, ring)?;
        let target = c.sub(&transformed.mul_vec(&offset, ring)?, ring)?;
        let x = prepared.coset(&a, &target, &mut uniform)?;
        let v = offset.add(&x.concat(&PolyVec::zero(extra, ring)), ring)?;
        // `h·v = c` holds only when the first `m` columns of `h` are the matrix this trapdoor
        // was generated with; for any other matrix the draw is withheld.
        if transformed.mul_vec(&v, ring)? != *c {
            return Err(Error::InvalidTrapdoor);
        }
        Ok(v)
    }

    /// The shape `(m−m') × m'` of `T_A` at `params`.
    fn shape(params: &Params) -> Shape {
        Shape {
            rows: params.spec().m - params.m_prime(),
            cols: params.m_prime(),
        }
    }

    /// Checks the length and the range of the coefficients against `params`.
    fn check(&self, params: &Params) -> Result<()> {
        let shape = Self::shape(params);
        let expected = shape.rows * shape.cols * params.ring().degree();
        check_dimension(expected, self.coefficients.len())?;
        let limit = params.trapdoor_sampler().max_magnitude();
        if self
            .coefficients
            .iter()
            .any(|t| U512::from_u64(t.unsigned_abs()) > limit)
        {
            return Err(Error::InvalidTrapdoor);
        }
        Ok(())
    }

    /// `T_A` over `R_q` in NTT form, for products; overwritten when dropped.
    fn ntt_form(&self, params: &Params) -> Result<Zeroizing<NttMatrix>> {
        self.check(params)?;
        let ring = params.ring();
        let entries = self
            .coefficients
            .chunks_exact(ring.degree())
            .map(|chunk| ring.ntt(&Zeroizing::new(Poly::from_signed(chunk, ring))))
            .collect::<Result<Vec<_>>>()?;
        Ok(Zeroizing::new(NttMatrix::from_parts(
            Self::shape(params),
            entries,
        )))
    }

    /// The perturbation sampler of this trapdoor at `params`.
    fn perturbation(&self, params: &Params) -> Result<Perturbation> {
        self.check(params)?;
        let shape = Self::shape(params);
        Perturbation::new(
            &self.coefficients,
            TrapdoorShape {
                rows: shape.rows,
                cols: shape.cols,
                degree: params.ring().degree(),
            },
            params.stage(),
        )
    }
}

/// The sampler of a set's trapdoor coefficients, by its [`crate::TrapdoorDistribution`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TrapdoorSampler {
    /// Discrete Gaussian of the width `ς` of Theorem 2.1, by the crate's table sampler.
    Gaussian(DiscreteGaussian),
    /// Uniform on `{−1, 0, 1}`.
    Ternary,
}

impl TrapdoorSampler {
    /// The next `count` coefficients from `reader`; `None` when a Gaussian draw would not fit
    /// an `i64`.
    ///
    /// A ternary coefficient is one byte `x` of the stream, kept when `x < 255` and mapped to
    /// `(x mod 3) − 1`: each of the 255 kept values maps to each of `−1, 0, 1` exactly 85 times,
    /// and whether a byte is kept does not depend on the coefficient it gives.
    pub(crate) fn integers(&self, reader: &mut Shake256Reader, count: usize) -> Option<Vec<i64>> {
        const BATCH: usize = 4096;
        match self {
            Self::Gaussian(gaussian) => gaussian.integers(reader, count, Lookup::Scan),
            Self::Ternary => {
                let mut buffer = Zeroizing::new([0u8; BATCH]);
                let mut out = Vec::with_capacity(count);
                while out.len() < count {
                    let bytes = &mut buffer[..(count - out.len()).min(BATCH)];
                    reader.read(bytes);
                    out.extend(
                        bytes
                            .iter()
                            .filter(|&&byte| byte < u8::MAX)
                            .map(|&byte| i64::from(byte % 3) - 1),
                    );
                }
                Some(out)
            }
        }
    }

    /// The largest magnitude a coefficient can take.
    pub(crate) fn max_magnitude(&self) -> U512 {
        match self {
            Self::Gaussian(gaussian) => gaussian.max_magnitude(),
            Self::Ternary => U512::ONE,
        }
    }
}

/// A spherical draw of `len` polynomials at the preimage sampler's least width, from `reader`:
/// the extension coordinates `SampleLeft` adds at that width.
pub(crate) fn least_width_vector(
    params: &Params,
    reader: &mut Shake256Reader,
    len: usize,
) -> PolyVec {
    let mut uniform = Uniform::new(reader);
    let draws = spherical(
        &mut uniform,
        params.stage().variance().sqrt(),
        len * params.ring().degree(),
    );
    residues(&draws, params.ring())
}

/// A trapdoor made ready for sampling at one set: `T_A` in NTT form, its perturbation sampler,
/// and the G-lattice sampler.
struct Prepared<'a> {
    params: &'a Params,
    trapdoor: Zeroizing<NttMatrix>,
    perturbation: Perturbation,
    gadget: GadgetSampler,
}

/// `T_A` in NTT form and the perturbation sampler overwrite themselves when dropped; the
/// G-lattice sampler holds only public values.
impl ZeroizeOnDrop for Prepared<'_> {}

impl<'a> Prepared<'a> {
    fn new(trapdoor: &Trapdoor, params: &'a Params) -> Result<Self> {
        Ok(Self {
            params,
            trapdoor: trapdoor.ntt_form(params)?,
            perturbation: trapdoor.perturbation(params)?,
            gadget: GadgetSampler::new(params.spec().base, modulus_digits(params)?, params.stage()),
        })
    }

    /// A preimage of `target` under `a` at the least variance `V₀`: a perturbation `p`, then
    /// [`Prepared::complete`]. A result with a coefficient beyond the tail cut is drawn again.
    fn coset(
        &self,
        a: &PolyMatrix,
        target: &PolyVec,
        uniform: &mut Uniform<'_>,
    ) -> Result<PolyVec> {
        let ring = self.params.ring();
        let tail = Coeff::from_u128(self.params.stage().tail);
        for _ in 0..SAMPLE_ATTEMPTS {
            let p = residues(&self.perturbation.sample(uniform), ring);
            let x = self.complete(a, target, p, uniform)?;
            if x.as_slice()
                .iter()
                .flat_map(Poly::coefficients)
                .all(|c| *ring.center(c).magnitude() <= tail)
            {
                return Ok(x);
            }
        }
        Err(Error::InvalidTrapdoor)
    }

    /// `p + [T_A; I]·z` for `z ← D_{Λ⊥_{target − a·p}(G), α}`, so that `a·(p + [T_A; I]·z)`
    /// is `target`.
    fn complete(
        &self,
        a: &PolyMatrix,
        target: &PolyVec,
        p: PolyVec,
        uniform: &mut Uniform<'_>,
    ) -> Result<PolyVec> {
        let ring = self.params.ring();
        let degree = ring.degree();
        let k = self.params.digits();
        let syndrome = target.sub(&a.mul_vec(&p, ring)?, ring)?;
        let digits = self.params.gadget().inverse_vec(&syndrome)?;
        let mut z = Zeroizing::new(vec![0i64; digits.len() * degree]);
        for (row, block) in digits.as_slice().chunks_exact(k).enumerate() {
            for t in 0..degree {
                let coset: Zeroizing<Vec<i64>> = Zeroizing::new(
                    block
                        .iter()
                        // A digit is below the base, at most 2^32, so it keeps its value.
                        .map(|digit| digit.coefficients()[t].as_words()[0].cast_signed())
                        .collect(),
                );
                for (i, x) in self.gadget.sample(&coset, uniform).iter().enumerate() {
                    z[(row * k + i) * degree + t] = *x;
                }
            }
        }
        let z = residues(&z, ring);
        let tz = self.trapdoor.mul_vec(&z, ring)?;
        p.add(&tz.concat(&z), ring)
    }
}

/// The base-`b` digits of `q`, least significant first, `k` of them.
fn modulus_digits(params: &Params) -> Result<Vec<i64>> {
    let base = params.spec().base;
    let divisor = NonZeroU32::new(base)
        .map(NonZero::<Limb>::from_u32)
        .ok_or(Error::BaseTooSmall(base))?;
    let mut rest = *params.ring().modulus();
    Ok((0..params.digits())
        .map(|_| {
            let (quotient, digit) = rest.div_rem_limb(divisor);
            rest = quotient;
            // A digit is below the base, at most 2^32, so it keeps its value.
            digit.0.cast_signed()
        })
        .collect())
}

/// The residues of `values`, `d` per polynomial.
fn residues(values: &[i64], ring: &Ring) -> PolyVec {
    values
        .chunks_exact(ring.degree())
        .map(|chunk| Poly::from_signed(chunk, ring))
        .collect()
}

impl Drop for Trapdoor {
    fn drop(&mut self) {
        self.coefficients.zeroize();
    }
}

impl ZeroizeOnDrop for Trapdoor {}

/// Compares the coefficients in constant time; only the lengths, which the parameter set
/// fixes, are compared directly.
impl PartialEq for Trapdoor {
    fn eq(&self, other: &Self) -> bool {
        bool::from(
            self.coefficients
                .as_slice()
                .ct_eq(other.coefficients.as_slice()),
        )
    }
}

impl Eq for Trapdoor {}

impl fmt::Debug for Trapdoor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trapdoor").finish_non_exhaustive()
    }
}

/// The coefficients as 8-byte little-endian two's complement.
impl From<&Trapdoor> for Zeroizing<Vec<u8>> {
    fn from(trapdoor: &Trapdoor) -> Self {
        Zeroizing::new(
            trapdoor
                .coefficients
                .iter()
                .flat_map(|t| t.to_le_bytes())
                .collect(),
        )
    }
}

/// Decodes 8-byte little-endian two's-complement coefficients; the length must be a multiple
/// of 8. The count and the range are checked against a parameter set when the trapdoor is used.
impl TryFrom<&[u8]> for Trapdoor {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let (chunks, rest) = bytes.as_chunks::<COEFFICIENT_BYTES>();
        if !rest.is_empty() {
            return Err(Error::InvalidEncodingLength(bytes.len()));
        }
        Ok(Self {
            coefficients: chunks.iter().map(|c| i64::from_le_bytes(*c)).collect(),
        })
    }
}

impl Serialize for Trapdoor {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let bytes = Zeroizing::<Vec<u8>>::from(self);
        secret_hex::serialize(&*bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for Trapdoor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let bytes = secret_hex::deserialize(deserializer)?;
        Self::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{Prepared, Trapdoor, TrapdoorSampler, modulus_digits, residues};
    use crate::{
        error::Error,
        matrix::{NttMatrix, PolyMatrix, Shape},
        params::Params,
        poly::Poly,
        preimage::{GadgetSampler, Uniform, spherical},
        sample::{DomainLabel, Seed, UniformSampler, hash_to_seed, xof},
        test_util::{PAPER, PAPER_TERNARY, TOY, TOY_TERNARY, centred_f64, six_formats, to_f64},
        vector::PolyVec,
    };
    use crypto_bigint::U512;
    use sha3::digest::XofReader;
    use zeroize::{ZeroizeOnDrop, Zeroizing};

    fn seed(i: u32) -> Seed {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&i.to_le_bytes());
        Seed::from(bytes)
    }

    fn uniform(i: u32, len: usize, params: &Params) -> PolyVec {
        UniformSampler::new(&seed(i), DomainLabel::from(&b"kln/test/target"[..]))
            .vector(len, params.ring())
    }

    /// `T_A` as a matrix over `R_q`.
    fn t_matrix(trapdoor: &Trapdoor, params: &Params) -> PolyMatrix {
        PolyMatrix::new(
            Trapdoor::shape(params),
            Vec::from(residues(&trapdoor.coefficients, params.ring())),
        )
        .unwrap()
    }

    /// The toy set with each trapdoor distribution.
    fn toy_sets() -> [(&'static str, &'static Params); 2] {
        [("toy", &*TOY), ("toy ternary", &*TOY_TERNARY)]
    }

    /// `V_y + V₀`, the variance of a width-`s` preimage's coefficients.
    fn full_variance(params: &Params) -> f64 {
        to_f64(&params.gaussian().variance()) + params.stage().variance()
    }

    /// `⌈s·√(d·cols)⌉²`: the C13 norm bound for a preimage with `cols` entries.
    fn norm_limit_squared(params: &Params, cols: usize) -> U512 {
        let width: U512 = params.bounds().width.resize();
        let limit = width
            .wrapping_mul(&width)
            .wrapping_mul(&U512::from_u64((params.ring().degree() * cols) as u64))
            .floor_sqrt_vartime()
            .wrapping_add(&U512::ONE);
        limit.wrapping_mul(&limit)
    }

    /// C11, with each trapdoor distribution: `A·[T_A; I] = G` exactly; the pair is a function
    /// of the seed; and the coefficients of `T_A` follow the set's distribution. Gaussian ones
    /// have mean zero and the standard deviation `ς/√(2π)` and stay within the tail cut;
    /// ternary ones lie in `{−1, 0, 1}` with frequencies that pass a χ² test against `1/3` each.
    #[test]
    fn trapgen_satisfies_the_gadget_equation() {
        for (name, params) in toy_sets() {
            trapgen_at(name, params);
        }
    }

    fn trapgen_at(name: &str, params: &Params) {
        let ring = params.ring();
        let (a, trapdoor) = Trapdoor::generate(params, &seed(1)).unwrap();
        let mp = params.m_prime();
        assert_eq!(a.shape(), Shape { rows: 1, cols: 20 });
        assert!(a.validate(ring).is_ok());
        let stacked = PolyMatrix::vstack(vec![
            t_matrix(&trapdoor, params),
            PolyMatrix::identity(mp, ring),
        ])
        .unwrap();
        assert_eq!(
            a.mul(&stacked, ring).unwrap(),
            PolyMatrix::from(params.gadget())
        );
        let values: Vec<f64> = trapdoor.coefficients.iter().map(|&t| t as f64).collect();
        let count = values.len() as f64;
        let mean = values.iter().sum::<f64>() / count;
        let std = (values.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / count).sqrt();
        let width = to_f64(&params.bounds().trapdoor_width.resize());
        let limit = to_f64(&params.trapdoor_sampler().max_magnitude());
        assert!(values.iter().all(|t| t.abs() <= limit), "{name}");
        let sigma = match params.trapdoor_sampler() {
            TrapdoorSampler::Gaussian(gaussian) => {
                let sigma = to_f64(&gaussian.variance()).sqrt();
                let two_pi = 2.0 * std::f64::consts::PI;
                assert!((width / (sigma * two_pi.sqrt()) - 1.0).abs() < 1e-3);
                sigma
            }
            TrapdoorSampler::Ternary => {
                assert_eq!(limit, 1.0);
                // χ² over the three values: the 99.9% quantile with 2 degrees of freedom is 13.8.
                let chi_squared: f64 = [-1.0, 0.0, 1.0]
                    .iter()
                    .map(|v| {
                        let observed = values.iter().filter(|t| *t == v).count() as f64;
                        (observed - count / 3.0).powi(2) / (count / 3.0)
                    })
                    .sum();
                assert!(chi_squared < 13.8, "{name}: χ² = {chi_squared}");
                (2.0f64 / 3.0).sqrt()
            }
        };
        eprintln!(
            "C11 {name}: {count} coefficients, std {std:.3} against {sigma:.3} (ς ≤ 2^{:.3}), \
             mean {mean:.3}, max |t| = {}",
            width.log2(),
            values.iter().fold(0f64, |acc, t| acc.max(t.abs()))
        );
        assert!((std / sigma - 1.0).abs() < 0.03, "{name}");
        assert!(mean.abs() < 0.05 * sigma, "{name}");
        let (again_a, again_t) = Trapdoor::generate(params, &seed(1)).unwrap();
        assert_eq!((&again_a, &again_t), (&a, &trapdoor));
        let (other_a, other_t) = Trapdoor::generate(params, &seed(2)).unwrap();
        assert_ne!(other_a, a);
        assert_ne!(other_t, trapdoor);
    }

    /// C12, with each trapdoor distribution: `A·v = u` for random `u`.
    #[test]
    fn sample_pre_hits_the_target() {
        for (_, params) in toy_sets() {
            sample_pre_at(params);
        }
    }

    fn sample_pre_at(params: &Params) {
        let (a, trapdoor) = Trapdoor::generate(params, &seed(3)).unwrap();
        for i in 0..20 {
            let u = uniform(i, 1, params);
            let v = trapdoor.sample_pre(params, &a, &u, &seed(i)).unwrap();
            assert_eq!(v.len(), 20);
            assert_eq!(a.mul_vec(&v, params.ring()).unwrap(), u);
            let w = trapdoor
                .sample_left_least(params, &a, &u, &seed(i))
                .unwrap();
            assert_eq!(a.mul_vec(&w, params.ring()).unwrap(), u);
        }
    }

    /// With each trapdoor distribution, a matrix generated with another trapdoor gets no
    /// preimage: the draw would not satisfy `A·v = u`, so it is refused rather than returned.
    #[test]
    fn foreign_matrices_are_refused() {
        for (_, params) in toy_sets() {
            let (_, trapdoor) = Trapdoor::generate(params, &seed(3)).unwrap();
            let (foreign, _) = Trapdoor::generate(params, &seed(4)).unwrap();
            let u = uniform(0, 1, params);
            assert_eq!(
                trapdoor.sample_pre(params, &foreign, &u, &seed(0)),
                Err(Error::InvalidTrapdoor)
            );
            assert_eq!(
                trapdoor.sample_left_least(params, &foreign, &u, &seed(0)),
                Err(Error::InvalidTrapdoor)
            );
        }
    }

    /// C13, with each trapdoor distribution: over 1000 toy-set preimages every
    /// `‖v‖₂ ≤ s·√(d·m)`, and the per-coefficient standard deviation is within 5% of
    /// `s/√(2π)`.
    #[test]
    fn preimages_are_short_and_gaussian() {
        for (name, params) in toy_sets() {
            short_and_gaussian_at(name, params);
        }
    }

    fn short_and_gaussian_at(name: &str, params: &Params) {
        const SAMPLES: u32 = 1000;
        let ring = params.ring();
        let (a, trapdoor) = Trapdoor::generate(params, &seed(4)).unwrap();
        let a_ntt = NttMatrix::new(&a, ring).unwrap();
        let limit = norm_limit_squared(params, params.spec().m);
        let (mut count, mut total, mut squares, mut max_norm) = (0.0, 0.0, 0.0, 0f64);
        for i in 0..SAMPLES {
            let u = uniform(i, 1, params);
            let v = trapdoor.sample_pre(params, &a, &u, &seed(i)).unwrap();
            assert_eq!(a_ntt.mul_vec(&v, ring).unwrap(), u);
            let norm = v.norm_l2_squared(ring);
            assert!(norm <= limit, "sample {i}");
            max_norm = max_norm.max(to_f64(&norm).sqrt());
            for value in centred_f64(&v, ring) {
                count += 1.0;
                total += value;
                squares += value * value;
            }
        }
        let sigma = full_variance(params).sqrt();
        let width = to_f64(&params.bounds().width.resize());
        let mean = total / count;
        let std = (squares / count - mean * mean).sqrt();
        eprintln!(
            "C13 {name}: {SAMPLES} preimages, {count} coefficients; std = {std:.6e}, \
             s/√(2π) = {:.6e} (σ = {sigma:.6e}), ratio {:.5}; mean = {mean:.3e}; \
             max ‖v‖ = {max_norm:.6e} against s·√(dm) = {:.6e}",
            width / (2.0 * std::f64::consts::PI).sqrt(),
            std / sigma,
            to_f64(&limit).sqrt(),
        );
        assert!((std / sigma - 1.0).abs() < 0.05, "{name}");
        assert!(mean.abs() < 0.01 * sigma, "{name}");
    }

    /// C13.1, with each trapdoor distribution: the same seed gives the same preimage, a
    /// different seed a different one, and a fixed seed gives a fixed preimage: its digest is
    /// pinned, so the test fails on any platform whose arithmetic would produce a different
    /// preimage.
    #[test]
    fn sampling_is_a_function_of_the_seed() {
        for ((name, params), known) in toy_sets().into_iter().zip(KNOWN_ANSWERS) {
            assert_eq!(seeded_digest(params), known, "{name}: preimage digest");
        }
    }

    /// One seed used for two targets shares no randomness between the two preimages. If it did,
    /// the perturbation would cancel in their difference and leave `[T_A·Δz; Δz]`: the top
    /// `m − m'` entries would be `T_A` times the bottom `m'`, which gives `T_A` away.
    #[test]
    fn one_seed_for_two_targets_does_not_expose_the_trapdoor() {
        let params = &*TOY;
        let ring = params.ring();
        let (a, trapdoor) = Trapdoor::generate(params, &seed(5)).unwrap();
        let sample = |target: u32| {
            trapdoor
                .sample_pre(params, &a, &uniform(target, 1, params), &seed(7))
                .unwrap()
        };
        let difference = Vec::from(sample(0).sub(&sample(1), ring).unwrap());
        let (top, bottom) = difference.split_at(params.spec().m - params.m_prime());
        let (top, bottom): (PolyVec, PolyVec) = (
            top.iter().cloned().collect(),
            bottom.iter().cloned().collect(),
        );
        assert_ne!(
            t_matrix(&trapdoor, params).mul_vec(&bottom, ring).unwrap(),
            top
        );
    }

    /// The digest of two preimages from fixed seeds, after checking that a seed determines its
    /// preimage.
    fn seeded_digest(params: &Params) -> String {
        let (a, trapdoor) = Trapdoor::generate(params, &seed(5)).unwrap();
        let u = uniform(0, 1, params);
        let v = trapdoor.sample_pre(params, &a, &u, &seed(7)).unwrap();
        assert_eq!(v, trapdoor.sample_pre(params, &a, &u, &seed(7)).unwrap());
        assert_ne!(v, trapdoor.sample_pre(params, &a, &u, &seed(8)).unwrap());
        let least = trapdoor
            .sample_left_least(params, &a, &u, &seed(7))
            .unwrap();
        let mut bytes = Vec::new();
        v.write_coefficients(&mut bytes);
        least.write_coefficients(&mut bytes);
        let digest = hash_to_seed(DomainLabel::from(&b"kln/test/kat"[..]), &[&bytes]);
        digest
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The digests of [`sampling_is_a_function_of_the_seed`]'s preimages at the toy set with
    /// the Gaussian and the ternary trapdoor.
    const KNOWN_ANSWERS: [&str; 2] = [
        "828abbc9a7e2eeec113fa5826825fd398149f22c37de91d00d4226ddd7693d2b",
        "81ec78b245c6af8bb1c47471e7ba22329ebf3bdcb98c6d6b66a3b6999d82296d",
    ];

    /// C14: `[A | B']·v = c` for a uniform `B'` as wide as the accumulator's, with the norm
    /// bound over all `m + t` entries; the same seed gives the same `v`, and with `t = 0` it is
    /// `SamplePre`. The extension coordinates have the width-`s` standard deviation. With each
    /// trapdoor distribution.
    #[test]
    fn sample_left_hits_the_target() {
        for (name, params) in toy_sets() {
            sample_left_at(name, params);
        }
    }

    fn sample_left_at(name: &str, params: &Params) {
        let ring = params.ring();
        let (a, trapdoor) = Trapdoor::generate(params, &seed(6)).unwrap();
        let t = params.spec().element_bits as usize * params.m_prime();
        let b = UniformSampler::new(&seed(9), DomainLabel::from(&b"kln/test/b"[..]))
            .matrix(Shape { rows: 1, cols: t }, ring);
        let h = a.hconcat(&b).unwrap();
        let limit = norm_limit_squared(params, params.spec().m + t);
        let mut extension = Vec::new();
        for i in 0..10 {
            let c = uniform(i, 1, params);
            let v = trapdoor.sample_left(params, &h, &c, &seed(i)).unwrap();
            assert_eq!(v.len(), 100);
            assert_eq!(h.mul_vec(&v, ring).unwrap(), c);
            assert!(v.norm_l2_squared(ring) <= limit);
            assert_eq!(v, trapdoor.sample_left(params, &h, &c, &seed(i)).unwrap());
            assert_eq!(
                trapdoor.sample_left(params, &a, &c, &seed(i)).unwrap(),
                trapdoor.sample_pre(params, &a, &c, &seed(i)).unwrap()
            );
            extension.extend(centred_f64(
                &PolyVec::from(Vec::from(v)[20..].to_vec()),
                ring,
            ));
        }
        let std = (extension.iter().map(|x| x * x).sum::<f64>() / extension.len() as f64).sqrt();
        assert!(
            (std / full_variance(params).sqrt() - 1.0).abs() < 0.05,
            "{name}"
        );
    }

    /// C47: at the toy, 128-bit and succinct 128-bit sets (`q` not a power of `b` at any, and
    /// `b = 64`, `1024`, `6`), every G-lattice sample `z` satisfies `G·z = u` for its target,
    /// and every coordinate has mean zero and standard deviation within 5% of `α/√(2π)`, the
    /// requested width `α = √(2π·σ²·((b+1)² + 1))` with the set's `σ²`.
    #[test]
    fn gadget_samples_at_every_set() {
        for (name, params, polys) in [
            ("toy", Params::toy().unwrap(), 200),
            ("paper", Params::paper_128().unwrap(), 2),
            ("succinct 128", Params::succinct_128().unwrap(), 2),
        ] {
            let ring = params.ring();
            let k = params.digits();
            let degree = ring.degree();
            let variance = params.stage().gadget_variance;
            let sampler = GadgetSampler::new(
                params.spec().base,
                modulus_digits(&params).unwrap(),
                params.stage(),
            );
            let mut reader = xof(&seed(47), DomainLabel::from(&b"kln/test/g"[..]));
            let mut stream = Uniform::new(&mut reader);
            let mut moments = vec![(0.0, 0.0); k];
            for i in 0..polys {
                let u = uniform(i, 1, &params);
                let digits = params.gadget().inverse_vec(&u).unwrap();
                let mut z = vec![0i64; k * degree];
                for t in 0..degree {
                    let coset: Vec<i64> = digits
                        .as_slice()
                        .iter()
                        .map(|digit| digit.coefficients()[t].as_words()[0] as i64)
                        .collect();
                    for (j, &x) in sampler.sample(&coset, &mut stream).iter().enumerate() {
                        z[j * degree + t] = x;
                        moments[j].0 += x as f64;
                        moments[j].1 += (x as f64).powi(2);
                    }
                }
                assert_eq!(
                    params.gadget().mul_vec(&residues(&z, ring)).unwrap(),
                    u,
                    "{name}"
                );
            }
            let count = (polys * degree as u32) as f64;
            let alpha = (variance as f64).sqrt();
            let worst = moments
                .iter()
                .map(|(sum, squares)| {
                    let mean = sum / count;
                    assert!(mean.abs() < 0.05 * alpha, "{name}: mean {mean}");
                    ((squares / count - mean * mean).sqrt() / alpha - 1.0).abs()
                })
                .fold(0f64, f64::max);
            eprintln!(
                "C47 {name}: b = {}, k = {k}, α/√(2π) = {alpha:.2}, worst coordinate std off by \
                 {:.2}%",
                params.spec().base,
                100.0 * worst
            );
            assert!(worst < 0.05, "{name}");
        }
    }

    /// `R*·v = T_A*·v₁ + v₂` over the integers, for `v = [v₁; v₂]`, as `f64`.
    fn trapdoor_projection(trapdoor: &Trapdoor, params: &Params, v: &PolyVec) -> Vec<f64> {
        let ring = params.ring();
        let shape = Trapdoor::shape(params);
        let degree = ring.degree();
        let adjoint: Vec<Poly> = (0..shape.cols)
            .flat_map(|c| (0..shape.rows).map(move |r| (r, c)))
            .map(|(r, c)| {
                let entry = &trapdoor.coefficients[(r * shape.cols + c) * degree..][..degree];
                let flipped: Vec<i64> = (0..degree)
                    .map(|i| if i == 0 { entry[0] } else { -entry[degree - i] })
                    .collect();
                Vec::from(residues(&flipped, ring)).remove(0)
            })
            .collect();
        let adjoint = PolyMatrix::new(
            Shape {
                rows: shape.cols,
                cols: shape.rows,
            },
            adjoint,
        )
        .unwrap();
        let parts = Vec::from(v.clone());
        let (top, bottom) = parts.split_at(shape.rows);
        let projected = adjoint
            .mul_vec(&PolyVec::from(top.to_vec()), ring)
            .unwrap()
            .add(&PolyVec::from(bottom.to_vec()), ring)
            .unwrap();
        centred_f64(&projected, ring)
    }

    /// The mean of `‖R*·v‖² / (V₀·tr(R·R*))` over `samples` and its standard error.
    fn leak_statistic(samples: &[f64]) -> (f64, f64) {
        let n = samples.len() as f64;
        let mean = samples.iter().sum::<f64>() / n;
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (mean, (variance / n).sqrt())
    }

    /// C48: over 1000 toy preimages at the least width, the energy along the trapdoor
    /// directions, `‖R*·v‖²` with `R = [T_A; I]`, matches what a spherical Gaussian of variance
    /// `V₀` gives, `V₀·tr(R·R*)`, within four standard errors. With the perturbation switched
    /// off (`v = R·z`, test-only) the same statistic is far outside that range. With each
    /// trapdoor distribution.
    #[test]
    fn preimages_do_not_leak_the_trapdoor() {
        for (name, params) in toy_sets() {
            no_leak_at(name, params);
        }
    }

    fn no_leak_at(name: &str, params: &Params) {
        const SAMPLES: u32 = 1000;
        let ring = params.ring();
        let degree = ring.degree() as f64;
        let (a, trapdoor) = Trapdoor::generate(params, &seed(48)).unwrap();
        let prepared = Prepared::new(&trapdoor, params).unwrap();
        let frobenius: f64 = trapdoor
            .coefficients
            .iter()
            .map(|&t| (t as f64).powi(2))
            .sum();
        let trace = degree * frobenius + degree * params.m_prime() as f64;
        let scale = params.stage().variance() * trace;
        let (mut on, mut off) = (Vec::new(), Vec::new());
        for i in 0..SAMPLES {
            let u = uniform(1000 + i, 1, params);
            let v = trapdoor
                .sample_left_least(params, &a, &u, &seed(i))
                .unwrap();
            assert_eq!(a.mul_vec(&v, ring).unwrap(), u);
            let energy: f64 = trapdoor_projection(&trapdoor, params, &v)
                .iter()
                .map(|x| x * x)
                .sum();
            on.push(energy / scale);
            let mut reader = xof(&seed(i), DomainLabel::from(&b"kln/test/off"[..]));
            let mut stream = Uniform::new(&mut reader);
            let zero = PolyVec::zero(params.spec().m, ring);
            let w = prepared.complete(&a, &u, zero, &mut stream).unwrap();
            assert_eq!(a.mul_vec(&w, ring).unwrap(), u);
            let energy: f64 = trapdoor_projection(&trapdoor, params, &w)
                .iter()
                .map(|x| x * x)
                .sum();
            off.push(energy / scale);
        }
        let (mean_on, error_on) = leak_statistic(&on);
        let (mean_off, error_off) = leak_statistic(&off);
        eprintln!(
            "C48 {name}: ‖R*v‖²/(V₀·tr RR*) over {SAMPLES} preimages: perturbation on \
             {mean_on:.5} ± {error_on:.5} ({:.2} standard errors from 1), off {mean_off:.5} ± \
             {error_off:.5} ({:.0} standard errors from 1)",
            (mean_on - 1.0).abs() / error_on,
            (mean_off - 1.0).abs() / error_off,
        );
        assert!((mean_on - 1.0).abs() <= 4.0 * error_on, "{name}");
        assert!((mean_off - 1.0).abs() > 4.0 * error_off, "{name}");
    }

    /// The precision margin: the centre of `p₁` given `p₂`, computed in the FFT domain, against
    /// the same centre from the exact integer product `T_A·p₂`, relative to the least
    /// conditional standard deviation `√(V₀/4)`; and the least pivot of the decomposition.
    fn precision_margin(params: &Params, label: &str) {
        let ring = params.ring();
        let (_, trapdoor) = Trapdoor::generate(params, &seed(50)).unwrap();
        let prepared = Prepared::new(&trapdoor, params).unwrap();
        let (bottom_std, centre_scale) = prepared.perturbation.bottom();
        let mut reader = xof(&seed(51), DomainLabel::from(&b"kln/test/precision"[..]));
        let mut stream = Uniform::new(&mut reader);
        let bottom = spherical(&mut stream, bottom_std, params.m_prime() * ring.degree());
        let approximate = prepared.perturbation.top_centre(&bottom);
        let exact = centred_f64(
            &prepared
                .trapdoor
                .mul_vec(&residues(&bottom, ring), ring)
                .unwrap(),
            ring,
        );
        let error = approximate
            .iter()
            .zip(&exact)
            .map(|(x, y)| (x - y * centre_scale).abs())
            .fold(0f64, f64::max);
        let largest = exact
            .iter()
            .fold(0f64, |acc, y| acc.max((y * centre_scale).abs()));
        let floor = (params.stage().variance() / 4.0).sqrt();
        let pivot = prepared.perturbation.least_pivot_ratio(params.stage());
        // The ring sampler's centres are sums of FFT-domain products of vectors as large as a
        // perturbation; the round-trip error of one measures the error such a sum carries.
        let p = prepared.perturbation.sample(&mut stream);
        let largest_p = p
            .iter()
            .fold(0f64, |acc, &x| acc.max(x.unsigned_abs() as f64));
        let round_trip = prepared.perturbation.round_trip_error(&p);
        eprintln!(
            "precision {label}: √V₀ = 2^{:.2}, least pivot {pivot:.3}·V₀; input centre: largest \
             2^{:.2}, worst error 2^{:.2} = 2^{:.2}·√(V₀/4); FFT round trip of a perturbation \
             (largest 2^{:.2}): worst error 2^{:.2} = 2^{:.2}·√(V₀/4)",
            params.stage().variance().sqrt().log2(),
            largest.log2(),
            error.log2(),
            (error / floor).log2(),
            largest_p.log2(),
            round_trip.log2(),
            (round_trip / floor).log2(),
        );
        assert!(error / floor < 2f64.powi(-30));
        assert!(round_trip / floor < 2f64.powi(-30));
        assert!(pivot >= 0.25);
    }

    #[test]
    fn precision_margin_at_the_toy_set() {
        for (name, params) in toy_sets() {
            precision_margin(params, name);
        }
    }

    #[test]
    #[ignore = "128-bit set at d = 4096: a few seconds in release"]
    fn precision_margin_at_the_paper_set() {
        precision_margin(&PAPER, "paper");
        precision_margin(&PAPER_TERNARY, "paper ternary");
    }

    #[test]
    fn dimension_errors() {
        let params = &*TOY;
        let ring = params.ring();
        let (a, trapdoor) = Trapdoor::generate(params, &seed(10)).unwrap();
        let u = uniform(0, 1, params);
        let narrow = a.column_block(0, 19).unwrap();
        let wide = a.hconcat(&a).unwrap();
        let mismatch = |expected, found| Err(Error::DimensionMismatch { expected, found });
        assert_eq!(
            trapdoor.sample_pre(params, &wide, &u, &seed(0)),
            mismatch(20, 40)
        );
        assert_eq!(
            trapdoor.sample_left(params, &narrow, &u, &seed(0)),
            mismatch(20, 19)
        );
        let two_rows = PolyMatrix::zero(Shape { rows: 2, cols: 20 }, ring);
        assert_eq!(
            trapdoor.sample_left(params, &two_rows, &u, &seed(0)),
            mismatch(1, 2)
        );
        let short = Trapdoor::try_from([0u8; 24].as_slice()).unwrap();
        assert_eq!(
            short.sample_pre(params, &a, &u, &seed(0)),
            mismatch(6400, 3)
        );
    }

    /// With each trapdoor distribution, a coefficient beyond the largest the distribution can
    /// give (the Gaussian tail cut, or 1), and a scaled trapdoor, which is too wide for the
    /// stage's pivot floor or out of the ternary range, are refused when the trapdoor is used;
    /// so is a Gaussian trapdoor under the ternary set.
    #[test]
    fn out_of_range_trapdoors_are_refused() {
        for (_, params) in toy_sets() {
            out_of_range_at(params);
        }
        let (a, gaussian) = Trapdoor::generate(&TOY, &seed(13)).unwrap();
        assert_eq!(
            gaussian.sample_pre(&TOY_TERNARY, &a, &uniform(0, 1, &TOY), &seed(0)),
            Err(Error::InvalidTrapdoor)
        );
    }

    fn out_of_range_at(params: &Params) {
        let (a, trapdoor) = Trapdoor::generate(params, &seed(13)).unwrap();
        let u = uniform(0, 1, params);
        let limit = i64::try_from(u64::from(
            params.trapdoor_sampler().max_magnitude().resize::<1>(),
        ))
        .unwrap();
        let mut coefficients = trapdoor.coefficients.clone();
        coefficients[0] = limit + 1;
        let beyond = Trapdoor { coefficients };
        assert_eq!(
            beyond.sample_pre(params, &a, &u, &seed(0)),
            Err(Error::InvalidTrapdoor)
        );
        let scaled = Trapdoor {
            coefficients: trapdoor.coefficients.iter().map(|t| 4 * t).collect(),
        };
        assert_eq!(
            scaled.sample_pre(params, &a, &u, &seed(0)),
            Err(Error::InvalidTrapdoor)
        );
    }

    /// The ternary sampler reads one byte per candidate, skips 255 and maps `x` to
    /// `(x mod 3) − 1`, in stream order and across batch boundaries.
    #[test]
    fn ternary_coefficients_follow_the_stream() {
        const COUNT: usize = 10_000;
        let label = || DomainLabel::from(&b"kln/test/ternary"[..]);
        let got = TrapdoorSampler::Ternary
            .integers(&mut xof(&seed(60), label()), COUNT)
            .unwrap();
        let mut reader = xof(&seed(60), label());
        let mut want = Vec::new();
        while want.len() < COUNT {
            let mut byte = [0u8];
            reader.read(&mut byte);
            if byte[0] < u8::MAX {
                want.push(i64::from(byte[0] % 3) - 1);
            }
        }
        assert_eq!(got, want);
    }

    /// TOML needs a table at the top level.
    /// The bytes round-trip, the length must be a multiple of 8, and the trapdoor round-trips
    /// byte-exactly in postcard, CBOR, BARE, JSON, TOML and YAML, as hex in the last three.
    #[test]
    fn bytes_and_serde_round_trip() {
        let (_, trapdoor) = Trapdoor::generate(&TOY, &seed(11)).unwrap();
        let bytes = Zeroizing::<Vec<u8>>::from(&trapdoor);
        assert_eq!(bytes.len(), 6400 * 8);
        assert_eq!(Trapdoor::try_from(bytes.as_slice()).unwrap(), trapdoor);
        assert_eq!(
            Trapdoor::try_from([0u8; 7].as_slice()),
            Err(Error::InvalidEncodingLength(7))
        );
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let binary = six_formats(trapdoor, &hex);
        for (format, encoded) in ["postcard", "cbor", "bare"].iter().zip(&binary) {
            assert!(encoded.len() < bytes.len() + 16, "{format}");
        }
    }

    #[test]
    fn secret_is_hidden_and_wiped() {
        fn wiped_on_drop<T: ZeroizeOnDrop>(_: &T) {}
        let (_, trapdoor) = Trapdoor::generate(&TOY, &seed(12)).unwrap();
        wiped_on_drop(&trapdoor);
        crate::test_util::wiped_on_drop::<Prepared<'_>>();
        assert_eq!(format!("{trapdoor:?}"), "Trapdoor { .. }");
    }

    /// C12 and the C13 norm bound at the 128-bit set, for one preimage.
    #[test]
    #[ignore = "128-bit set at d = 4096: a few seconds in release, far slower unoptimised"]
    fn sample_pre_at_paper_set() {
        let params = &*PAPER;
        let (a, trapdoor) = Trapdoor::generate(params, &seed(13)).unwrap();
        let u = uniform(0, 1, params);
        let v = trapdoor.sample_pre(params, &a, &u, &seed(14)).unwrap();
        assert_eq!(a.mul_vec(&v, params.ring()).unwrap(), u);
        let norm = v.norm_l2_squared(params.ring());
        assert!(norm <= norm_limit_squared(params, params.spec().m));
        eprintln!("paper: ‖v‖ = 2^{:.3}", to_f64(&norm).sqrt().log2());
    }
}
