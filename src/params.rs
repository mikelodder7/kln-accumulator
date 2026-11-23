// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lattice parameter sets: one typed definition per security target.
//!
//! A [`ParamsSpec`] holds the free choices of Section 4 of ePrint 2025/1099 (ring degree `d`,
//! modulus `q`, rank `n`, width `m`, gadget base `b`, element length `ℓ`, deletion bound `γ`)
//! and the [`TrapdoorDistribution`]. [`Params::try_from`] validates a spec and derives
//! everything else: the ring and its NTT tables, the gadget, the Gaussian widths and norm
//! [`Bounds`] of Theorems 2.1 and 4.3, and the samplers. Parameters are runtime data, so every
//! key and value carries its set (usually as `Arc<Params>`) and refuses values of another.
//!
//! See the book's chapter "Parameter sets and trapdoor distributions" for the defined sets
//! and what the trapdoor distribution costs and buys.

mod widths;

use crate::{
    error::{Error, Result},
    gadget::{self, Gadget},
    gaussian::{DiscreteGaussian, MIN_BASE_VARIANCE, RADIX, radix_sum},
    preimage::Stage,
    ring::Ring,
    trapdoor::TrapdoorSampler,
    zq::Coeff,
};
use core::num::NonZeroU32;
use crypto_bigint::{CheckedAdd, NonZero, U64, U512};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, EnumIter};

/// The integer type of the bound computations. Every quantity a valid set produces is below
/// `q² < 2^384`; a larger intermediate overflows into [`Error::WitnessBoundTooLarge`].
pub(crate) type Wide = U512;

/// `333/106 < π`, a convergent of the continued fraction `π = [3; 7, 15, 1, 292, …]`.
pub(crate) const PI_LOWER: (u64, u64) = (333, 106);

/// `π < 355/113`, the next convergent.
pub(crate) const PI_UPPER: (u64, u64) = (355, 113);

/// The distribution of the coefficients of the trapdoor `T_A` that `TrapGen` draws.
///
/// Every width of the preimage sampler follows from a bound `S ≥ s₁(T_A)`, so the choice moves
/// the least width, `s`, `β` and the succinct bounds ([`Bounds`], [`crate::succinct::Bounds`]).
///
/// * [`TrapdoorDistribution::Gaussian`], the default, is Theorem 2.1's: discrete Gaussian
///   coefficients of width `ς > 2d·q^{n/(m−m') + 2/(d(m−m'))}`, which makes `A` statistically
///   close to uniform. `S` is proportional to `ς`.
/// * [`TrapdoorDistribution::Ternary`] draws every coefficient uniformly from `{−1, 0, 1}`.
///   `S` is that of a width `√(4π/3) ≈ 2` in place of `ς` (Lemma A.2), so the least width
///   drops by about `log₂ ς − 1` bits. `A` is then pseudorandom under Module-LWE with uniform
///   ternary secrets, `M-LWE_{m−n,m,q,U(S₁)}`, an assumption Theorem 4.3 already makes, instead
///   of statistically close to uniform.
///
/// It is one byte of the 64-byte [`ParamsSpec`] encoding: 0 for Gaussian, 1 for Ternary
/// (`From<TrapdoorDistribution> for u8` and `TryFrom<u8>`, derived with `num_enum`; an unknown
/// byte is [`Error::InvalidTrapdoorDistribution`]). The variants can be listed with
/// `strum::IntoEnumIterator::iter`, and `strum::EnumCount::COUNT` is their number. See
/// [`Bounds`] and the book's chapter "Parameter sets and trapdoor distributions" for the
/// realised widths. **Public.**
///
/// # Examples
///
/// ```
/// use kln_accumulator::{ParamsSpec, TrapdoorDistribution};
///
/// assert_eq!(TrapdoorDistribution::default(), TrapdoorDistribution::Gaussian);
/// assert_eq!(ParamsSpec::TOY.trapdoor, TrapdoorDistribution::Gaussian);
/// let ternary = ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary);
/// assert_eq!(u8::from(ternary.trapdoor), 1);
/// assert_eq!(TrapdoorDistribution::try_from(0u8)?, TrapdoorDistribution::Gaussian);
/// assert!(TrapdoorDistribution::try_from(2u8).is_err());
/// use strum::{EnumCount, IntoEnumIterator};
/// assert_eq!(TrapdoorDistribution::iter().count(), TrapdoorDistribution::COUNT);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    IntoPrimitive,
    TryFromPrimitive,
    EnumCount,
    EnumIter,
)]
#[num_enum(error_type(name = Error, constructor = Error::InvalidTrapdoorDistribution))]
#[repr(u8)]
pub enum TrapdoorDistribution {
    /// Discrete Gaussian coefficients of the width Theorem 2.1 asks for; byte 0.
    #[default]
    Gaussian = 0,
    /// Coefficients uniform in `{−1, 0, 1}`; byte 1.
    Ternary = 1,
}

/// The free choices of a parameter set; [`Params`] validates them and derives the rest.
///
/// Symbols follow Section 4 of the paper: `R_q = Z_q[X]/(X^d + 1)`, `A ∈ R_q^{n×m}`, gadget
/// `G ∈ R_q^{n×m'}` in base `b` with `m' = n·⌈log_b q⌉`, elements of `ℓ` bits, and at most `γ`
/// deletions. The named sets use the Gaussian trapdoor; [`ParamsSpec::with_trapdoor`] gives any
/// of them with the other distribution.
///
/// Serialized field by field, with the modulus as its 24 little-endian bytes (hex in
/// human-readable formats); keys carry their set this way. The byte form
/// (`From<ParamsSpec> for [u8; 64]` and `TryFrom<&[u8]>`) is the 64-byte prefix of every encoded key and
/// value. **Public.**
///
/// A custom set is built by filling in the fields and passing the spec to
/// [`Params::try_from`], which refuses any set its bounds cannot serve, and any set beyond the
/// caps [`ParamsSpec::MAX_DEGREE`] and [`ParamsSpec::MAX_MATRIX_ENTRIES`]. Those caps are checked
/// first, with integer arithmetic only, so a spec read from untrusted bytes is refused before
/// any table is built or any large allocation is made.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Params, ParamsSpec};
///
/// let spec = ParamsSpec::TOY;
/// let bytes = <[u8; ParamsSpec::BYTES]>::from(spec);
/// assert_eq!(bytes.len(), ParamsSpec::BYTES);
/// assert_eq!(ParamsSpec::try_from(&bytes[..])?, spec);
/// // A set with too few columns for the gadget is refused.
/// assert!(Params::try_from(ParamsSpec { m: 10, ..ParamsSpec::TOY }).is_err());
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "SpecWire", try_from = "SpecWire")]
pub struct ParamsSpec {
    /// The ring degree `d`, a power of two.
    pub degree: usize,
    /// The modulus `q`, a prime with `q ≡ 5 (mod 8)`.
    pub modulus: Coeff,
    /// The module rank `n` (rows of `A`).
    pub n: usize,
    /// The width `m` of `A`; must exceed `m'`.
    pub m: usize,
    /// The gadget base `b ≥ 2`.
    pub base: u32,
    /// The bit length `ℓ` of accumulated elements.
    pub element_bits: u32,
    /// The deletion bound `γ`.
    pub max_deletions: u64,
    /// The distribution of the trapdoor's coefficients.
    pub trapdoor: TrapdoorDistribution,
}

impl ParamsSpec {
    /// A small set for tests: `d = 64`, the 60-bit prime `q = 4·3^19·247990961 + 1 ≡ 5 (mod 8)`,
    /// `n = 1`, `b = 2^6` (so `k = 10` and `m' = 10`), `m = 20`, `ℓ = 8`, `γ = 2^8`.
    pub const TOY: Self = Self {
        degree: 64,
        modulus: Coeff::from_u64(0x0fff_ffdc_9803_a1ad),
        n: 1,
        m: 20,
        base: 1 << 6,
        element_bits: 8,
        max_deletions: 1 << 8,
        trapdoor: TrapdoorDistribution::Gaussian,
    };

    /// The 128-bit shape of Table 2: `d = 4096`, the 100-bit prime
    /// `q = 4·3^32·171024931063165 + 1 ≡ 5 (mod 8)`, `n = 1`, `m = 20`, `b = 2^10` (so
    /// `k = 10`), `ℓ = 32`, `γ = 2^32`.
    pub const PAPER_128: Self = Self {
        degree: 4096,
        modulus: Coeff::from_be_hex("00000000000000000000000ffffffffffefc98b54c0227f5"),
        n: 1,
        m: 20,
        base: 1 << 10,
        element_bits: 32,
        max_deletions: 1 << 32,
        trapdoor: TrapdoorDistribution::Gaussian,
    };

    /// A small set for the `ℓ`-succinct variant ([`crate::succinct`]), whose witnesses need a
    /// larger modulus than [`ParamsSpec::TOY`]: `d = 64`, the 90-bit prime
    /// `q = 4·3^28·13528339273457 + 1 ≡ 5 (mod 8)`, `n = 1`, `b = 2^6` (so `k = m' = 15`),
    /// `m = 30`, `ℓ = 4`, `γ = 16`. The small `ℓ` and `γ` keep the public matrix `T₀`
    /// (`ℓm × ℓm'` entries) and the tests small; the base scheme runs at this set too.
    pub const SUCCINCT_TOY: Self = Self {
        degree: 64,
        modulus: Coeff::from_be_hex("00000000000000000000000003ffffffffe12483334ccc85"),
        n: 1,
        m: 30,
        base: 1 << 6,
        element_bits: 4,
        max_deletions: 16,
        trapdoor: TrapdoorDistribution::Gaussian,
    };

    /// The 128-bit shape of Table 2 for the `ℓ`-succinct variant: `d = 4096`, the 162-bit
    /// prime `q = 4·3^51·678602281655571156740225 + 1 ≡ 5 (mod 8)`, `n = 1`, `m = 90`, `b = 6`
    /// (so `k = 63`), `ℓ = 32`, `γ = 2^32`.
    pub const SUCCINCT_128: Self = Self {
        degree: 4096,
        modulus: Coeff::from_be_hex("00000003ffffffffffffffffff2bd00c6625d7590754436d"),
        n: 1,
        m: 90,
        base: 6,
        element_bits: 32,
        max_deletions: 1 << 32,
        trapdoor: TrapdoorDistribution::Gaussian,
    };

    /// The length of the byte encoding, `From<ParamsSpec> for [u8; 64]`; see the type's
    /// example.
    pub const BYTES: usize = 64;

    /// The largest ring degree `d` a set may have, `2^13`. [`Params::try_from`] refuses a larger
    /// one with [`Error::DegreeTooLarge`] before it builds any NTT table. The defined sets use
    /// at most 4096.
    ///
    /// ```
    /// use kln_accumulator::{Error, Params, ParamsSpec};
    ///
    /// let wide = ParamsSpec { degree: ParamsSpec::MAX_DEGREE * 2, ..ParamsSpec::TOY };
    /// assert_eq!(Params::try_from(wide).map(drop), Err(Error::DegreeTooLarge(1 << 14)));
    /// ```
    pub const MAX_DEGREE: usize = 1 << 13;

    /// The most polynomials the public matrix `[A | B] ∈ R_q^{n×(m + ℓm')}` of a set may hold,
    /// `n·(m + ℓ·m') ≤ 2^16`. [`Params::try_from`] refuses a larger set, and one whose dimensions
    /// overflow, with [`Error::WitnessBoundTooLarge`] before it builds any NTT table. The defined
    /// sets hold at most 2106 ([`ParamsSpec::SUCCINCT_128`]).
    ///
    /// ```
    /// use kln_accumulator::{Error, Params, ParamsSpec};
    ///
    /// // n·(m + ℓ·m') = 20 + 8·10 = 100 at the toy set.
    /// assert!(100 <= ParamsSpec::MAX_MATRIX_ENTRIES);
    /// let long = ParamsSpec { element_bits: 1 << 13, ..ParamsSpec::TOY };
    /// assert_eq!(Params::try_from(long).map(drop), Err(Error::WitnessBoundTooLarge));
    /// ```
    pub const MAX_MATRIX_ENTRIES: usize = 1 << 16;

    /// This set with the trapdoor drawn from `trapdoor`, for example
    /// `ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary)`. See the book's chapter
    /// "Parameter sets and trapdoor distributions" for what the choice costs and buys.
    #[must_use]
    pub const fn with_trapdoor(self, trapdoor: TrapdoorDistribution) -> Self {
        Self { trapdoor, ..self }
    }
}

/// The fixed-width encoding, all little-endian: `d` as `u32`, the trapdoor distribution as
/// one byte and three zero bytes, then `q` in [`Coeff::BYTES`] bytes, `n` and `m` as `u64`,
/// `b` and `ℓ` as `u32`, and `γ` as `u64`.
///
/// Every valid `d` is at most `2^31`, so the first eight bytes of a Gaussian set are those
/// of `d` as a `u64`. A `d` beyond `u32::MAX`, which no set accepts, is written as
/// `u32::MAX`. See [`ParamsSpec`]'s example.
impl From<ParamsSpec> for [u8; ParamsSpec::BYTES] {
    fn from(spec: ParamsSpec) -> Self {
        let mut out = [0u8; ParamsSpec::BYTES];
        let degree = u32::try_from(spec.degree).unwrap_or(u32::MAX);
        let modulus = spec.modulus.to_le_bytes();
        let fields: [&[u8]; 8] = [
            &degree.to_le_bytes(),
            &[u8::from(spec.trapdoor), 0, 0, 0],
            modulus.as_slice(),
            &(spec.n as u64).to_le_bytes(),
            &(spec.m as u64).to_le_bytes(),
            &spec.base.to_le_bytes(),
            &spec.element_bits.to_le_bytes(),
            &spec.max_deletions.to_le_bytes(),
        ];
        let mut offset = 0;
        for field in fields {
            out[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        out
    }
}

/// Decodes the 64-byte [`ParamsSpec`] encoding; the set itself is checked by [`Params::try_from`]. Fails
/// with [`Error::NonCanonicalEncoding`] when the three bytes after the distribution are not
/// zero, and with [`Error::InvalidTrapdoorDistribution`] for an unknown distribution.
impl TryFrom<&[u8]> for ParamsSpec {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let invalid = Error::InvalidEncodingLength(bytes.len());
        let bytes: &[u8; Self::BYTES] = bytes.try_into().map_err(|_| invalid)?;
        let (degree, rest) = bytes.split_first_chunk::<4>().ok_or(invalid)?;
        let (trapdoor, rest) = rest.split_first_chunk::<4>().ok_or(invalid)?;
        let (modulus, rest) = rest
            .split_first_chunk::<{ Coeff::BYTES }>()
            .ok_or(invalid)?;
        let (n, rest) = rest.split_first_chunk::<8>().ok_or(invalid)?;
        let (m, rest) = rest.split_first_chunk::<8>().ok_or(invalid)?;
        let (base, rest) = rest.split_first_chunk::<4>().ok_or(invalid)?;
        let (element_bits, rest) = rest.split_first_chunk::<4>().ok_or(invalid)?;
        let max_deletions = rest.first_chunk::<8>().ok_or(invalid)?;
        if trapdoor[1..] != [0, 0, 0] {
            return Err(Error::NonCanonicalEncoding);
        }
        let size = |raw: &[u8; 8]| usize::try_from(u64::from_le_bytes(*raw)).map_err(|_| invalid);
        Ok(Self {
            degree: usize::try_from(u32::from_le_bytes(*degree)).map_err(|_| invalid)?,
            modulus: Coeff::from_le_slice(modulus),
            n: size(n)?,
            m: size(m)?,
            base: u32::from_le_bytes(*base),
            element_bits: u32::from_le_bytes(*element_bits),
            max_deletions: u64::from_le_bytes(*max_deletions),
            trapdoor: TrapdoorDistribution::try_from(trapdoor[0])?,
        })
    }
}

/// The serialized form of [`ParamsSpec`]; a field it does not name is refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecWire {
    degree: u64,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    modulus: Vec<u8>,
    n: u64,
    m: u64,
    base: u32,
    element_bits: u32,
    max_deletions: u64,
    trapdoor: TrapdoorDistribution,
}

impl From<ParamsSpec> for SpecWire {
    fn from(spec: ParamsSpec) -> Self {
        Self {
            degree: spec.degree as u64,
            modulus: spec.modulus.to_le_bytes().as_slice().to_vec(),
            n: spec.n as u64,
            m: spec.m as u64,
            base: spec.base,
            element_bits: spec.element_bits,
            max_deletions: spec.max_deletions,
            trapdoor: spec.trapdoor,
        }
    }
}

impl TryFrom<SpecWire> for ParamsSpec {
    type Error = Error;

    fn try_from(wire: SpecWire) -> Result<Self> {
        if wire.modulus.len() != Coeff::BYTES {
            return Err(Error::InvalidEncodingLength(wire.modulus.len()));
        }
        let size = |value: u64| {
            usize::try_from(value).map_err(|_| Error::InvalidEncodingLength(Self::BYTES))
        };
        Ok(Self {
            degree: size(wire.degree)?,
            modulus: Coeff::from_le_slice(&wire.modulus),
            n: size(wire.n)?,
            m: size(wire.m)?,
            base: wire.base,
            element_bits: wire.element_bits,
            max_deletions: wire.max_deletions,
            trapdoor: wire.trapdoor,
        })
    }
}

/// The Gaussian widths and the norm bounds of a parameter set (Theorems 2.1 and 4.3), each
/// rounded up to an integer.
///
/// A preimage of width `s` is the sum of an integer-only spherical draw of variance `V_y` and
/// the trapdoor sampler's output at its least variance `V₀` ([`crate::lattice::Trapdoor`]), so
/// `s = √(2π·(V_y + V₀))`. The integer sampler reaches only a discrete set of variances; `V_y`
/// is the least such that `√(2π·V_y) ≥ T` is certain. The other two terms in Theorem 4.3's
/// maximum for `s` are, up to constants, the least width, and construction refuses a set
/// whose `√(2π·V_y)` is below it. Irrational factors are bounded with `333/106 < π < 355/113`,
/// so every field is an upper bound and every check against a floor uses a lower bound.
///
/// **Public.** Realised values (`log₂`, Gaussian trapdoor):
///
/// | set | `T` | `s` | `β` | `ς` | `S` | least width |
/// |---|---|---|---|---|---|---|
/// | toy | 35.341 | 35.341 | 41.681 | 13.188 | 19.598 | 28.108 |
/// | 128-bit | 77.457 | 77.457 | 87.663 | 23.005 | 32.774 | 45.394 |
/// | succinct toy | 31.607 | 31.615 | 37.880 | 13.188 | 19.814 | 28.324 |
/// | succinct 128-bit | 66.087 | 66.087 | 77.608 | 19.003 | 29.553 | 34.896 |
///
/// With the ternary trapdoor `ς = 2^1.585`, and `S` and the least width drop (toy least width
/// `2^15.954`, 128-bit `2^23.422`, succinct toy `2^16.169`, succinct 128-bit `2^16.926`). `T`,
/// `s` and `β` stay, except at the succinct toy set, where the least variance is a visible part
/// of `s = √(2π·(V_y + V₀))`: there `s = 2^31.607` and `β = 2^37.872`.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::Coeff;
///
/// let params = Params::toy()?;
/// let bounds = params.bounds();
/// // s ≥ T, and β < q/2 so that short vectors are exact as residues.
/// assert!(bounds.width >= bounds.update);
/// assert!(bounds.witness.wrapping_add(&bounds.witness) < *params.ring().modulus());
/// assert_eq!(bounds.witness.bit_width_vartime(), 42); // β = 2^41.68
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// `⌈T⌉` with `T = γ(b−1)√(m'd)·√(1 + ((b−1)·d·m'·√(ℓ−1))²)`, Theorem 4.3's bound on the ℓ2
    /// norm of everything `γ` deletions add to a witness.
    pub update: Coeff,
    /// `⌈s⌉` for the realised Gaussian width `s ≥ T`.
    pub width: Coeff,
    /// `β = ⌈s·√(d(m + ℓm'))⌉ + ⌈T⌉`, the witness norm bound `β₀` of Theorem 4.3.
    pub witness: Coeff,
    /// `⌈ς⌉` for the width `ς` of the coefficients of the trapdoor `T_A`: for a Gaussian
    /// trapdoor the realised `ς > 2d·q^{n/(m−m') + 2/(d(m−m'))}` (Theorem 2.1), for a ternary
    /// one the subgaussian width `√(4π/3)` of a uniform ternary coefficient (so 3).
    pub trapdoor_width: Coeff,
    /// `⌈S⌉` for the bound `s₁(T_A) ≤ S = ς·√d·(√m + √m' + log₂ √d)` (Theorem 2.1; Lemmas 2.3
    /// and A.2 for a ternary trapdoor).
    pub spectral: Coeff,
    /// `⌈√(2π·V₀)⌉`: the least width of the preimage sampler, at which `SamplePre` and
    /// `SampleLeft` run when no wider draw is added. `V₀` is the larger of
    /// `(α² + 2M')·(S² + 1) + M` and `(⌈S⌉ + 1)²·(b² + 1)·C_{ε,md}²/(2π)`, with
    /// `α² = σ²·((b+1)² + 1)` the variance of its G-lattice samples and `σ²`, `M'` and `M` the
    /// least integers that meet the smoothing conditions of ePrint 2011/501, Algorithm 3 and
    /// Lemma 5.3, and of ePrint 2017/308, Theorems 2.3 and 4.1, at `ε = 2^-128`.
    pub least_width: Coeff,
}

/// A validated parameter set with its ring, gadget, bounds and Gaussian samplers precomputed.
/// Later types share one by reference or `Arc` rather than carrying type parameters.
/// **Public.**
///
/// Building one is cheap next to any operation at it (the NTT tables and a few big-integer
/// bounds); keys take an `Arc<Params>` and share it with every value they make.
///
/// # Errors
///
/// [`Params::try_from`] (`TryFrom<ParamsSpec>`) fails with [`Error::DegreeNotPowerOfTwo`],
/// [`Error::DegreeTooLarge`], [`Error::ModulusNotPrime`], [`Error::ModulusNotFiveModEight`],
/// [`Error::BaseTooSmall`], [`Error::ZeroRank`], [`Error::TooFewColumns`],
/// [`Error::ZeroElementBits`], [`Error::WidthTooSmall`] or [`Error::WitnessBoundTooLarge`],
/// as the set requires.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Params, ParamsSpec};
///
/// let params = Params::toy()?;
/// assert_eq!(params.spec(), &ParamsSpec::TOY);
/// assert_eq!(params.digits(), 10);
/// assert_eq!(params.m_prime(), params.spec().n * params.digits());
/// assert_eq!(params.ring().degree(), 64);
/// assert_eq!(params.gadget().base(), 64);
/// assert!(params.bounds().witness < *params.ring().modulus());
/// assert_eq!(Params::try_from(ParamsSpec::PAPER_128)?, Params::paper_128()?);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    spec: ParamsSpec,
    dims: Dims,
    ring: Ring,
    gadget: Gadget,
    bounds: Bounds,
    gaussian: DiscreteGaussian,
    trapdoor_sampler: TrapdoorSampler,
    stage: Stage,
}

impl TryFrom<ParamsSpec> for Params {
    type Error = Error;

    /// Rejects `d` above [`ParamsSpec::MAX_DEGREE`] or not a power of two, `b < 2`, `n = 0`,
    /// `q` not prime, `q ≢ 5 (mod 8)`, `m ≤ m'`, `ℓ = 0`, more than
    /// [`ParamsSpec::MAX_MATRIX_ENTRIES`] polynomials in `[A | B]` (or dimensions that
    /// overflow), a width `√(2π·V_y)` below the preimage sampler's least width, and `2β ≥ q`.
    /// The checks that need no ring run first, so a set beyond the caps is refused before any
    /// NTT table is built.
    fn try_from(spec: ParamsSpec) -> Result<Self> {
        let dims = Dims::new(&spec)?;
        let ring = Ring::new(spec.degree, spec.modulus)?;
        let gadget = Gadget::new(&ring, spec.n, spec.base)?;
        let derived = derive_bounds(&spec, &gadget, &ring)?;
        Ok(Self {
            spec,
            dims,
            ring,
            gadget,
            bounds: derived.bounds,
            gaussian: derived.gaussian,
            trapdoor_sampler: derived.trapdoor_sampler,
            stage: derived.stage,
        })
    }
}

/// The dimensions a set derives from its spec, each computed once with checked arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Dims {
    /// `ℓ·m'`, the width of `B`.
    extension: usize,
    /// `m + ℓ·m'`, the length of a witness.
    witness: usize,
    /// `n·(m + ℓ·m')`, the entries of `[A | B]`.
    matrix: usize,
    /// `n·(m + ℓ·m') + n`, the polynomials of a public key `(A, B, u)`.
    key: usize,
}

impl Dims {
    /// The checks of a spec that need no ring, in integer arithmetic only: `d` at most
    /// [`ParamsSpec::MAX_DEGREE`], `b ≥ 2`, `m > m'`, `ℓ ≥ 1`, and at most
    /// [`ParamsSpec::MAX_MATRIX_ENTRIES`] entries in `[A | B]`. `n = 0` passes here and is
    /// refused by [`Gadget::new`].
    fn new(spec: &ParamsSpec) -> Result<Self> {
        if spec.degree > ParamsSpec::MAX_DEGREE {
            return Err(Error::DegreeTooLarge(spec.degree));
        }
        let over = Error::WitnessBoundTooLarge;
        let digits = gadget::powers(&spec.modulus, spec.base)?.count();
        let m_prime = spec.n.checked_mul(digits).ok_or(over)?;
        if spec.m <= m_prime {
            return Err(Error::TooFewColumns { m: spec.m, m_prime });
        }
        if spec.element_bits == 0 {
            return Err(Error::ZeroElementBits);
        }
        let extension = usize::try_from(spec.element_bits)
            .ok()
            .and_then(|ell| ell.checked_mul(m_prime))
            .ok_or(over)?;
        let witness = spec.m.checked_add(extension).ok_or(over)?;
        let matrix = spec
            .n
            .checked_mul(witness)
            .filter(|entries| *entries <= ParamsSpec::MAX_MATRIX_ENTRIES)
            .ok_or(over)?;
        let key = matrix.checked_add(spec.n).ok_or(over)?;
        Ok(Self {
            extension,
            witness,
            matrix,
            key,
        })
    }
}

/// What [`derive_bounds`] derives from a set.
struct Derived {
    bounds: Bounds,
    gaussian: DiscreteGaussian,
    trapdoor_sampler: TrapdoorSampler,
    stage: Stage,
}

/// The widths, bounds and samplers of a set whose ring and gadget are valid.
fn derive_bounds(spec: &ParamsSpec, gadget: &Gadget, ring: &Ring) -> Result<Derived> {
    let w = Wide::from_u64;
    let m_prime = gadget.shape().cols;
    let d = w(spec.degree as u64);
    let mp = w(m_prime as u64);
    let ell = w(u64::from(spec.element_bits));
    let gamma = w(spec.max_deletions);
    let b1 = w(u64::from(spec.base) - 1);
    // T² = γ²·(b−1)²·m'·d·(1 + ((b−1)·d·m')²·(ℓ−1)), Theorem 4.3.
    let inner = product(&[b1, b1, d, d, mp, mp, ell.wrapping_sub(&Wide::ONE)])?;
    let update_sq = product(&[gamma, gamma, b1, b1, mp, d, sum(Wide::ONE, inner)?])?;
    // Theorem 2.1: the trapdoor's width ς, the bound S on s₁(T_A), and the least variance V₀.
    let (trapdoor_sampler, trapdoor_width_sq) = match spec.trapdoor {
        TrapdoorDistribution::Gaussian => {
            let gaussian = choose_gaussian(
                &widths::trapdoor_min_variance(
                    spec.degree,
                    &spec.modulus,
                    spec.n,
                    spec.m - m_prime,
                )?,
                ring,
            )?;
            let width_sq = widths::gaussian_width_sq(&gaussian.variance())?;
            (TrapdoorSampler::Gaussian(gaussian), width_sq)
        }
        TrapdoorDistribution::Ternary => (TrapdoorSampler::Ternary, widths::ternary_width_sq()?),
    };
    let spectral_sq = widths::spectral_sq(spec.degree, spec.m, m_prime, &trapdoor_width_sq)?;
    let columns = |count: usize| {
        count
            .checked_mul(spec.degree)
            .ok_or(Error::WitnessBoundTooLarge)
    };
    let shape = widths::StageShape {
        base: spec.base,
        digits: gadget.digits(),
        gadget_columns: columns(m_prime)?,
        columns: columns(spec.m)?,
    };
    let stage = widths::stage(&shape, &spectral_sq)?;
    let least = Wide::from_u128(stage.least_variance);
    // 2π·V_y ≥ 2·(333/106)·V_y ≥ T² once V_y ≥ 106·T² / 666.
    let min_variance = ceil_div(&product(&[w(PI_LOWER.1), update_sq])?, &w(2 * PI_LOWER.0))?;
    let gaussian = choose_gaussian(&min_variance, ring)?;
    // √(2π·V_y) ≥ √(2π·V₀) is certain once (333/106)·V_y ≥ (355/113)·V₀.
    if product(&[w(PI_LOWER.0 * PI_UPPER.1), gaussian.variance()])?
        < product(&[w(PI_UPPER.0 * PI_LOWER.1), least])?
    {
        return Err(Error::WidthTooSmall);
    }
    let width_sq = width_sq_upper(&sum(gaussian.variance(), least)?)?;
    let update = ceil_sqrt(&update_sq);
    let columns = sum(w(spec.m as u64), product(&[ell, mp])?)?;
    let witness = sum(ceil_sqrt(&product(&[width_sq, d, columns])?), update)?;
    // Every coefficient of a preimage is at most the integer sampler's hard bound plus the
    // trapdoor stage's tail cut; below q/2 the centred lift is exact.
    let hard = sum(gaussian.max_magnitude(), Wide::from_u128(stage.tail))?;
    let modulus: Wide = spec.modulus.resize();
    if product(&[w(2), witness.max(hard)])? >= modulus {
        return Err(Error::WitnessBoundTooLarge);
    }
    let bounds = Bounds {
        update: update.resize(),
        width: ceil_sqrt(&width_sq).resize(),
        witness: witness.resize(),
        trapdoor_width: widths::width_ceiling(&trapdoor_width_sq).resize(),
        spectral: ceil_sqrt(&spectral_sq).resize(),
        least_width: ceil_sqrt(&width_sq_upper(&least)?).resize(),
    };
    Ok(Derived {
        bounds,
        gaussian,
        trapdoor_sampler,
        stage,
    })
}

/// `⌈2·(355/113)·V⌉ ≥ 2π·V`, the square of the width of variance `V`, rounded up.
pub(crate) fn width_sq_upper(variance: &Wide) -> Result<Wide> {
    ceil_div(
        &product(&[Wide::from_u64(2 * PI_UPPER.0), *variance])?,
        &Wide::from_u64(PI_UPPER.1),
    )
}

/// The sampler of least variance `σ² = V₀·Σ_{i<L} K^{2i} ≥ min_variance` with `V₀` at least
/// the smoothing floor: `L` is the largest level count that leaves `V₀ ≥` the floor, so
/// `V₀ < 65·floor` and the base table stays small.
pub(crate) fn choose_gaussian(min_variance: &Wide, ring: &Ring) -> Result<DiscreteGaussian> {
    let floor = Wide::from_u32(MIN_BASE_VARIANCE);
    let mut levels = 1;
    while product(&[floor, radix_sum(RADIX * RADIX, levels + 1)])
        .is_ok_and(|needed| needed <= *min_variance)
    {
        levels += 1;
    }
    let base = ceil_div(min_variance, &radix_sum(RADIX * RADIX, levels))?.max(floor);
    if base.bit_width_vartime() > u32::BITS {
        return Err(Error::WitnessBoundTooLarge);
    }
    let base = u32::try_from(u64::from(base.resize::<{ U64::LIMBS }>()))
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(Error::WitnessBoundTooLarge)?;
    Ok(DiscreteGaussian::new(base, levels, ring.zq()))
}

/// The product of `factors`, or [`Error::WitnessBoundTooLarge`] on overflow.
pub(crate) fn product(factors: &[Wide]) -> Result<Wide> {
    factors.iter().try_fold(Wide::ONE, |acc, factor| {
        acc.checked_mul(factor)
            .into_option()
            .ok_or(Error::WitnessBoundTooLarge)
    })
}

/// `a + b`, or [`Error::WitnessBoundTooLarge`] on overflow.
pub(crate) fn sum(a: Wide, b: Wide) -> Result<Wide> {
    a.checked_add(&b)
        .into_option()
        .ok_or(Error::WitnessBoundTooLarge)
}

/// `⌈a / b⌉`; every divisor here is a positive constant or a sum of powers, so a zero divisor
/// only arises from overflow and reports [`Error::WitnessBoundTooLarge`].
pub(crate) fn ceil_div(a: &Wide, b: &Wide) -> Result<Wide> {
    let divisor = NonZero::new(*b)
        .into_option()
        .ok_or(Error::WitnessBoundTooLarge)?;
    let (quotient, remainder) = a.div_rem_vartime(&divisor);
    Ok(if remainder == Wide::ZERO {
        quotient
    } else {
        quotient.wrapping_add(&Wide::ONE)
    })
}

/// `⌈√a⌉`.
pub(crate) fn ceil_sqrt(a: &Wide) -> Wide {
    let root = a.floor_sqrt_vartime();
    if root.wrapping_mul(&root) < *a {
        root.wrapping_add(&Wide::ONE)
    } else {
        root
    }
}

impl Params {
    /// The toy set [`ParamsSpec::TOY`], for tests and examples: it gives no security.
    ///
    /// # Errors
    ///
    /// None for this set; the `Result` is that of [`Params::try_from`].
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Params, ParamsSpec, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// // Build the set once and share it: every key, value and witness holds an `Arc` of it.
    /// let params = Arc::new(Params::toy()?);
    /// assert_eq!(params.spec(), &ParamsSpec::TOY);
    /// let key = SecretKey::new(None, Arc::clone(&params), &mut StdRng::seed_from_u64(0))?;
    /// assert!(Arc::ptr_eq(key.params(), &params));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn toy() -> Result<Self> {
        Self::try_from(ParamsSpec::TOY)
    }

    /// The 128-bit set [`ParamsSpec::PAPER_128`]. See the type's example.
    ///
    /// # Errors
    ///
    /// None for this set; the `Result` is that of [`Params::try_from`].
    pub fn paper_128() -> Result<Self> {
        Self::try_from(ParamsSpec::PAPER_128)
    }

    /// The succinct toy set [`ParamsSpec::SUCCINCT_TOY`], for tests of [`crate::succinct`]: it
    /// gives no security.
    ///
    /// # Errors
    ///
    /// None for this set; the `Result` is that of [`Params::try_from`].
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Params, succinct};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let mut rng = StdRng::seed_from_u64(0);
    /// let params = Arc::new(Params::succinct_toy()?);
    /// assert!(succinct::SecretKey::new(None, Arc::clone(&params), &mut rng).is_ok());
    /// // Misuse: the base toy set's modulus is too small for a succinct key.
    /// assert!(succinct::SecretKey::new(None, Arc::new(Params::toy()?), &mut rng).is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn succinct_toy() -> Result<Self> {
        Self::try_from(ParamsSpec::SUCCINCT_TOY)
    }

    /// The succinct 128-bit set [`ParamsSpec::SUCCINCT_128`]. See the type's example.
    ///
    /// # Errors
    ///
    /// None for this set; the `Result` is that of [`Params::try_from`].
    pub fn succinct_128() -> Result<Self> {
        Self::try_from(ParamsSpec::SUCCINCT_128)
    }

    /// The free choices this set was built from. See the type's example.
    #[must_use]
    pub fn spec(&self) -> &ParamsSpec {
        &self.spec
    }

    /// Fails with [`Error::ParameterMismatch`] unless `other` has the same free choices.
    pub(crate) fn check_same(&self, other: &Self) -> Result<()> {
        if self.spec == other.spec {
            Ok(())
        } else {
            Err(Error::ParameterMismatch)
        }
    }

    /// The number of gadget digits `k = ⌈log_b q⌉`. See the type's example.
    #[must_use]
    pub fn digits(&self) -> usize {
        self.gadget.digits()
    }

    /// The gadget width `m' = n·k`. See the type's example.
    #[must_use]
    pub fn m_prime(&self) -> usize {
        self.gadget.shape().cols
    }

    /// `ℓ·m'`, the width of `B` and of the extension part of a witness.
    pub(crate) fn extension_len(&self) -> usize {
        self.dims.extension
    }

    /// `m + ℓ·m'`, the length of a witness.
    pub(crate) fn witness_len(&self) -> usize {
        self.dims.witness
    }

    /// `n·(m + ℓ·m')`, the number of entries of `[A | B]`.
    pub(crate) fn matrix_entries(&self) -> usize {
        self.dims.matrix
    }

    /// `n·(m + ℓ·m') + n`, the number of polynomials of a public key `(A, B, u)`.
    pub(crate) fn key_entries(&self) -> usize {
        self.dims.key
    }

    /// The ring `R_q`. See the type's example.
    #[must_use]
    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    /// The gadget matrix `G`. See the type's example.
    #[must_use]
    pub fn gadget(&self) -> &Gadget {
        &self.gadget
    }

    /// The realised Gaussian width and the norm bounds. See the type's example.
    #[must_use]
    pub fn bounds(&self) -> &Bounds {
        &self.bounds
    }

    /// The integer sampler of variance `V_y`, the wide part of a width-`s` preimage.
    pub(crate) fn gaussian(&self) -> &DiscreteGaussian {
        &self.gaussian
    }

    /// The sampler of the trapdoor's coefficients.
    pub(crate) fn trapdoor_sampler(&self) -> &TrapdoorSampler {
        &self.trapdoor_sampler
    }

    /// The preimage sampler's trapdoor stage.
    pub(crate) fn stage(&self) -> &Stage {
        &self.stage
    }
}

#[cfg(test)]
mod tests {
    use super::{Dims, PI_LOWER, PI_UPPER, Params, ParamsSpec, TrapdoorDistribution};
    use crate::{
        error::Error,
        test_util::{six_formats, to_f64},
        trapdoor::TrapdoorSampler,
        zq::Coeff,
    };
    use crypto_bigint::{NonZero, U512};

    /// Theorems 2.1 and 4.3 in floating point: `T`, `β` for the realised `s`, the threshold
    /// for `ς`, `S` for the realised `ς`, and the least width for that `S`.
    struct Expected {
        update: f64,
        witness: f64,
        trapdoor_threshold: f64,
        spectral: f64,
        least_width: f64,
    }

    fn expected(params: &Params) -> Expected {
        let spec = params.spec();
        let (d, m, mp) = (spec.degree as f64, spec.m as f64, params.m_prime() as f64);
        let (b1, ell) = (f64::from(spec.base - 1), f64::from(spec.element_bits));
        let gamma = spec.max_deletions as f64;
        let two_pi = 2.0 * std::f64::consts::PI;
        let update = gamma
            * b1
            * (mp * d).sqrt()
            * (1.0 + (b1 * d * mp * (ell - 1.0).sqrt()).powi(2)).sqrt();
        let variance = to_f64(&params.gaussian().variance()) + params.stage().variance();
        let width = (two_pi * variance).sqrt();
        let left = m - mp;
        let q = to_f64(&params.ring().modulus().resize());
        let trapdoor_width = match params.trapdoor_sampler() {
            TrapdoorSampler::Gaussian(gaussian) => (two_pi * to_f64(&gaussian.variance())).sqrt(),
            TrapdoorSampler::Ternary => (4.0 * std::f64::consts::PI / 3.0).sqrt(),
        };
        let spectral = trapdoor_width * d.sqrt() * (m.sqrt() + mp.sqrt() + d.sqrt().log2());
        let sigma_sq = params.stage().gadget_base_variance as f64;
        let b = b1 + 1.0;
        let alpha_sq = sigma_sq * ((b + 1.0).powi(2) + 1.0);
        // C_{ε,N}²/(2π) = ln(2N(1 + 2^128))/(2π²).
        let smoothing =
            |n: f64| ((2.0 * n).ln() + 128.0 * 2f64.ln()) / (two_pi * std::f64::consts::PI);
        // ePrint 2011/501, Algorithm 3 with ePrint 2017/308, Theorem 4.1; and Lemma 5.3 for
        // the smoothing parameter of Λ⊥(A).
        let least_variance = ((alpha_sq + 2.0 * smoothing(mp * d).ceil())
            * (spectral * spectral + 1.0)
            + smoothing(m * d).ceil())
        .max((spectral.ceil() + 1.0).powi(2) * (b * b + 1.0) * smoothing(m * d));
        Expected {
            update,
            witness: width * (d * (m + ell * mp)).sqrt() + update,
            trapdoor_threshold: 2.0 * d * q.powf(spec.n as f64 / left + 2.0 / (d * left)),
            spectral,
            least_width: (two_pi * least_variance).sqrt(),
        }
    }

    fn coeff(value: &Coeff) -> f64 {
        to_f64(&value.resize())
    }

    #[test]
    fn pi_lies_between_the_convergents() {
        let ratio = |(p, q): (u64, u64)| p as f64 / q as f64;
        assert!(ratio(PI_LOWER) < std::f64::consts::PI);
        assert!(std::f64::consts::PI < ratio(PI_UPPER));
    }

    /// The integer bounds agree with Theorems 2.1 and 4.3 in floating point, at every set
    /// with either trapdoor: `T`, `β` and `s` keep the values Theorem 4.3 gives at both sets,
    /// a Gaussian `ς` exceeds Theorem 2.1's threshold within the integer sampler's granularity
    /// and a ternary one is `⌈√(4π/3)⌉ = 3`, `S` and the least width follow from it, and `s` is
    /// at least the least width. The values printed are those reported for the sets.
    #[test]
    fn bounds_follow_theorems_2_1_and_4_3() {
        for ((name, spec, log_update, log_witness, sigma_sq), distribution) in [
            ("toy", ParamsSpec::TOY, 35.34, 41.68, 5),
            ("paper", ParamsSpec::PAPER_128, 77.46, 87.66, 6),
            ("succinct toy", ParamsSpec::SUCCINCT_TOY, 0.0, 0.0, 5),
            ("succinct 128", ParamsSpec::SUCCINCT_128, 0.0, 0.0, 5),
        ]
        .into_iter()
        .flat_map(|set| {
            [
                TrapdoorDistribution::Gaussian,
                TrapdoorDistribution::Ternary,
            ]
            .map(|d| (set, d))
        }) {
            let params = &Params::try_from(spec.with_trapdoor(distribution)).unwrap();
            let bounds = params.bounds();
            assert_eq!(params.stage().gadget_base_variance, sigma_sq, "{name}");
            let want = expected(params);
            // Each bound is an upper bound; ceilings add at most 2 and the π bounds 5·10^-8.
            let close = |got: f64, want: f64| {
                got >= want * (1.0 - 1e-12) && got <= want * (1.0 + 1e-7) + 2.0
            };
            let (update, width) = (coeff(&bounds.update), coeff(&bounds.width));
            let witness = coeff(&bounds.witness);
            let (trapdoor_width, spectral) =
                (coeff(&bounds.trapdoor_width), coeff(&bounds.spectral));
            let least_width = coeff(&bounds.least_width);
            assert!(
                close(update, want.update),
                "{name}: {update} vs {}",
                want.update
            );
            assert!(
                close(witness, want.witness),
                "{name}: {witness} vs {}",
                want.witness
            );
            assert!(
                close(spectral, want.spectral),
                "{name}: {spectral} vs {}",
                want.spectral
            );
            assert!(
                close(least_width, want.least_width)
                    || least_width / want.least_width < 1.0 + 1e-15,
                "{name}: {least_width} vs {}",
                want.least_width
            );
            match distribution {
                TrapdoorDistribution::Gaussian => assert!(
                    trapdoor_width > want.trapdoor_threshold
                        && trapdoor_width / want.trapdoor_threshold < 1.001,
                    "{name}: ς = {trapdoor_width} vs {}",
                    want.trapdoor_threshold
                ),
                TrapdoorDistribution::Ternary => assert_eq!(trapdoor_width, 3.0, "{name}"),
            }
            assert!(width >= update && width >= least_width, "{name}: {width}");
            assert!(2.0 * witness < coeff(params.ring().modulus()), "{name}");
            if log_update > 0.0 {
                assert!(width / update < 1.001, "{name}: {width}");
                assert!((update.log2() - log_update).abs() < 0.01, "{name}");
                assert!((witness.log2() - log_witness).abs() < 0.01, "{name}");
            }
            eprintln!(
                "{name} ({distribution:?}): T = 2^{:.3}, s = 2^{:.3}, β = 2^{:.3}, ς = 2^{:.3} \
                 (threshold 2^{:.3}), S = 2^{:.3}, α = 2^{:.3}, least width 2^{:.3}, \
                 s/least = 2^{:.2}",
                update.log2(),
                width.log2(),
                witness.log2(),
                trapdoor_width.log2(),
                want.trapdoor_threshold.log2(),
                spectral.log2(),
                (2.0 * std::f64::consts::PI * params.stage().gadget_variance as f64)
                    .sqrt()
                    .log2(),
                least_width.log2(),
                (width / least_width).log2(),
            );
        }
    }

    #[test]
    fn rejects_sets_the_sampler_cannot_serve() {
        let toy = ParamsSpec::TOY;
        let reject = |spec: ParamsSpec| Params::try_from(spec).err();
        assert_eq!(
            reject(ParamsSpec {
                element_bits: 0,
                ..toy
            }),
            Some(Error::ZeroElementBits)
        );
        // ℓ = 1 and γ = 1 give T ≈ 1594, far below the least width 2^28.1.
        assert_eq!(
            reject(ParamsSpec {
                element_bits: 1,
                max_deletions: 1,
                ..toy
            }),
            Some(Error::WidthTooSmall)
        );
        // m − m' = 1 makes Theorem 2.1's ς about 2^69, and the least variance V₀ about 2^172,
        // beyond the 2^100 the sampler accepts.
        assert_eq!(
            reject(ParamsSpec { m: 11, ..toy }),
            Some(Error::WitnessBoundTooLarge)
        );
        // m − m' = 4: ς ≈ 2^22.5 and a least width about 2^37.3 above s ≈ 2^35.3.
        assert_eq!(
            reject(ParamsSpec { m: 14, ..toy }),
            Some(Error::WidthTooSmall)
        );
        // γ = 2^30 gives T ≈ 2^57.3 and β ≈ 2^63.6 against q ≈ 2^60.
        assert_eq!(
            reject(ParamsSpec {
                max_deletions: 1 << 30,
                ..toy
            }),
            Some(Error::WitnessBoundTooLarge)
        );
        assert!(
            Params::try_from(ParamsSpec {
                max_deletions: 1 << 20,
                ..toy
            })
            .is_ok()
        );
    }

    /// Pocklington's criterion: if `N − 1 = F·R` with the factorisation of `F` known and
    /// `F > √N`, and for every prime `f | F` some `a_f` has `a_f^{N−1} ≡ 1 (mod N)` and
    /// `gcd(a_f^{(N−1)/f} − 1, N) = 1`, then `N` is prime. Here `F = 4·3^e`, whose only prime
    /// factors are 2 and 3, and `R = h`; the witnesses `a_2, a_3` with `F` and `h` form a
    /// primality certificate independent of the Miller–Rabin check used at construction.
    fn pocklington_certifies(params: &Params, e: u32, h: u128, witnesses: [u64; 2]) -> bool {
        let ring = params.ring();
        let q = *ring.modulus();
        let q_minus_one = q.wrapping_sub(&Coeff::ONE);
        let factored = Coeff::from_u128(4 * 3u128.pow(e));
        let factored_wide: U512 = factored.resize();
        let pow = |a: u64, exponent: &Coeff| ring.zq().pow(&Coeff::from_u64(a), exponent);
        q_minus_one == factored.wrapping_mul(&Coeff::from_u128(h))
            && factored_wide.wrapping_mul(&factored_wide) > q.resize()
            && [2u64, 3].into_iter().zip(witnesses).all(|(f, a)| {
                let (cofactor, remainder) =
                    q_minus_one.div_rem_vartime(&NonZero::new(Coeff::from_u64(f)).unwrap());
                remainder == Coeff::ZERO
                    && pow(a, &q_minus_one) == Coeff::ONE
                    && pow(a, &cofactor).wrapping_sub(&Coeff::ONE).gcd(&q) == Coeff::ONE
            })
    }

    /// The certificate check fails on a wrong factorisation, on a factored part below `√q`,
    /// and on a non-witness.
    #[test]
    fn pocklington_rejects_wrong_certificates() {
        let toy = Params::toy().unwrap();
        assert!(!pocklington_certifies(&toy, 19, 247_990_959, [2, 2]));
        // A true factorisation whose factored part F = 4 is far below √q.
        assert!(!pocklington_certifies(
            &toy,
            0,
            3u128.pow(19) * 247_990_961,
            [2, 2]
        ));
        // a = 1 satisfies a^{N−1} ≡ 1 but a^{(N−1)/f} − 1 = 0 shares every factor with N.
        assert!(!pocklington_certifies(&toy, 19, 247_990_961, [1, 2]));
    }

    #[test]
    fn toy_set() {
        let toy = Params::toy().unwrap();
        assert_eq!(*toy.spec(), ParamsSpec::TOY);
        assert_eq!(toy.digits(), 10);
        assert_eq!(toy.m_prime(), 10);
        assert_eq!(toy.ring().degree(), 64);
        assert_eq!(toy.gadget().base(), 64);
        assert_eq!(toy.ring().modulus().bit_width_vartime(), 60);
        assert!(pocklington_certifies(&toy, 19, 247_990_961, [2, 2]));
        assert_eq!(toy.ring().modulus().as_words()[0] % 8, 5);
    }

    #[test]
    fn paper_128_set() {
        let paper = Params::paper_128().unwrap();
        assert_eq!(*paper.spec(), ParamsSpec::PAPER_128);
        assert_eq!(paper.digits(), 10);
        assert_eq!(paper.m_prime(), 10);
        assert_eq!(paper.ring().degree(), 4096);
        assert_eq!(paper.ring().modulus().bit_width_vartime(), 100);
        assert!(pocklington_certifies(
            &paper,
            32,
            171_024_931_063_165,
            [2, 3]
        ));
        assert_eq!(paper.ring().modulus().as_words()[0] % 8, 5);
    }

    /// The two succinct sets: their gadget widths and certified primes `q ≡ 5 (mod 8)`. The
    /// 128-bit shape has `k = ⌈log_6 q⌉ = 63` as in Table 2.
    #[test]
    fn succinct_sets() {
        for (params, spec, bits, k, e, h) in [
            (
                Params::succinct_toy().unwrap(),
                ParamsSpec::SUCCINCT_TOY,
                90,
                15,
                28,
                13_528_339_273_457,
            ),
            (
                Params::succinct_128().unwrap(),
                ParamsSpec::SUCCINCT_128,
                162,
                63,
                51,
                678_602_281_655_571_156_740_225,
            ),
        ] {
            assert_eq!(*params.spec(), spec);
            assert_eq!(params.digits(), k);
            assert_eq!(params.m_prime(), k);
            assert_eq!(params.ring().modulus().bit_width_vartime(), bits);
            assert!(pocklington_certifies(&params, e, h, [2, 3]));
            assert_eq!(params.ring().modulus().as_words()[0] % 8, 5);
        }
    }

    /// Both distributions round-trip through the 64-byte encoding. A Gaussian set encodes as
    /// before the distribution existed (`d` as a `u64` first), the distribution is byte 4, and
    /// a nonzero reserved byte or an unknown distribution is refused.
    #[test]
    fn spec_bytes_round_trip() {
        for spec in [
            ParamsSpec::TOY,
            ParamsSpec::PAPER_128,
            ParamsSpec::SUCCINCT_TOY,
            ParamsSpec::SUCCINCT_128,
        ] {
            let ternary = spec.with_trapdoor(TrapdoorDistribution::Ternary);
            for spec in [spec, ternary] {
                let bytes = <[u8; ParamsSpec::BYTES]>::from(spec);
                assert_eq!(ParamsSpec::try_from(bytes.as_slice()), Ok(spec));
            }
            let modulus = spec.modulus.to_le_bytes();
            let fields: [&[u8]; 7] = [
                &(spec.degree as u64).to_le_bytes(),
                modulus.as_slice(),
                &(spec.n as u64).to_le_bytes(),
                &(spec.m as u64).to_le_bytes(),
                &spec.base.to_le_bytes(),
                &spec.element_bits.to_le_bytes(),
                &spec.max_deletions.to_le_bytes(),
            ];
            assert_eq!(
                <[u8; ParamsSpec::BYTES]>::from(spec).as_slice(),
                fields.concat().as_slice()
            );
            let mut flipped = <[u8; ParamsSpec::BYTES]>::from(spec);
            flipped[4] = 1;
            assert_eq!(flipped, <[u8; ParamsSpec::BYTES]>::from(ternary));
            flipped[4] = 2;
            assert_eq!(
                ParamsSpec::try_from(flipped.as_slice()),
                Err(Error::InvalidTrapdoorDistribution(2))
            );
            let mut reserved = <[u8; ParamsSpec::BYTES]>::from(spec);
            reserved[5] = 1;
            assert_eq!(
                ParamsSpec::try_from(reserved.as_slice()),
                Err(Error::NonCanonicalEncoding)
            );
        }
        assert_eq!(
            ParamsSpec::try_from([0u8; 63].as_slice()),
            Err(Error::InvalidEncodingLength(63))
        );
        assert_eq!(
            ParamsSpec::try_from([0u8; 65].as_slice()),
            Err(Error::InvalidEncodingLength(65))
        );
    }

    /// The distribution defaults to Gaussian, which every named set uses, and
    /// [`ParamsSpec::with_trapdoor`] changes nothing else.
    #[test]
    fn named_sets_are_gaussian() {
        assert_eq!(
            TrapdoorDistribution::default(),
            TrapdoorDistribution::Gaussian
        );
        for spec in [
            ParamsSpec::TOY,
            ParamsSpec::PAPER_128,
            ParamsSpec::SUCCINCT_TOY,
            ParamsSpec::SUCCINCT_128,
        ] {
            assert_eq!(spec.trapdoor, TrapdoorDistribution::Gaussian);
            let ternary = spec.with_trapdoor(TrapdoorDistribution::Ternary);
            assert_eq!(ternary.trapdoor, TrapdoorDistribution::Ternary);
            assert_eq!(ternary.with_trapdoor(TrapdoorDistribution::Gaussian), spec);
        }
        for (distribution, byte) in [
            (TrapdoorDistribution::Gaussian, 0),
            (TrapdoorDistribution::Ternary, 1),
        ] {
            assert_eq!(u8::from(distribution), byte);
            assert_eq!(TrapdoorDistribution::try_from(byte), Ok(distribution));
        }
        // Every variant round-trips, and every other byte is refused with the crate's error.
        use strum::{EnumCount, IntoEnumIterator};
        assert_eq!(
            TrapdoorDistribution::iter().count(),
            TrapdoorDistribution::COUNT
        );
        for distribution in TrapdoorDistribution::iter() {
            assert_eq!(
                TrapdoorDistribution::try_from(u8::from(distribution)),
                Ok(distribution)
            );
        }
        for byte in TrapdoorDistribution::COUNT as u8..=u8::MAX {
            assert_eq!(
                TrapdoorDistribution::try_from(byte),
                Err(Error::InvalidTrapdoorDistribution(byte))
            );
        }
    }

    /// The distribution and the spec carrying it round-trip in the six formats; the
    /// human-readable forms name the distribution and give the modulus in hex.
    #[test]
    fn distribution_and_spec_serde() {
        for distribution in [
            TrapdoorDistribution::Gaussian,
            TrapdoorDistribution::Ternary,
        ] {
            let name = format!("{distribution:?}");
            let _ = six_formats(distribution, &name);
            let spec = ParamsSpec::TOY.with_trapdoor(distribution);
            let _ = six_formats(spec, &name);
            let _ = six_formats(spec, &hex::encode(spec.modulus.to_le_bytes().as_slice()));
        }
    }

    #[test]
    fn rejections() {
        let toy = ParamsSpec::TOY;
        let reject = |spec: ParamsSpec| Params::try_from(spec).err();
        assert_eq!(
            reject(ParamsSpec { degree: 96, ..toy }),
            Some(Error::DegreeNotPowerOfTwo(96))
        );
        // 129·257 = 259·128 + 1 is composite and ≡ 1 (mod 2d = 128).
        assert_eq!(
            reject(ParamsSpec {
                modulus: Coeff::from_u64(129 * 257),
                ..toy
            }),
            Some(Error::ModulusNotPrime)
        );
        // 2^61 − 1 is prime and ≡ 7 (mod 8).
        assert_eq!(
            reject(ParamsSpec {
                modulus: Coeff::from_u64((1 << 61) - 1),
                ..toy
            }),
            Some(Error::ModulusNotFiveModEight)
        );
        // The previous toy modulus, the Proth prime 268435323·2^32 + 1 ≡ 1 (mod 8).
        assert_eq!(
            reject(ParamsSpec {
                modulus: Coeff::from_u64(0x0fff_ff7b_0000_0001),
                ..toy
            }),
            Some(Error::ModulusNotFiveModEight)
        );
        assert_eq!(
            reject(ParamsSpec { base: 1, ..toy }),
            Some(Error::BaseTooSmall(1))
        );
        assert_eq!(
            reject(ParamsSpec { base: 0, ..toy }),
            Some(Error::BaseTooSmall(0))
        );
        assert_eq!(reject(ParamsSpec { n: 0, ..toy }), Some(Error::ZeroRank));
        assert_eq!(
            reject(ParamsSpec { m: 10, ..toy }),
            Some(Error::TooFewColumns { m: 10, m_prime: 10 })
        );
        assert_eq!(
            reject(ParamsSpec { n: 2, ..toy }),
            Some(Error::TooFewColumns { m: 20, m_prime: 20 })
        );
        assert!(Params::try_from(ParamsSpec { m: 16, ..toy }).is_ok());
    }

    /// The checks that need no ring: the degree cap, the entry cap exactly at its boundary
    /// (`20 + 10ℓ` entries at the toy shape), and overflow of `n·k`, `ℓ·m'`, `m + ℓm'` and
    /// `n·(m + ℓm')`, each an error rather than a wrapped value.
    #[test]
    fn dimensions_are_capped_and_checked() {
        let toy = ParamsSpec::TOY;
        let dims = |spec: ParamsSpec| Dims::new(&spec);
        assert_eq!(
            dims(toy),
            Ok(Dims {
                extension: 80,
                witness: 100,
                matrix: 100,
                key: 101,
            })
        );
        let at_cap = ParamsSpec {
            degree: ParamsSpec::MAX_DEGREE,
            ..toy
        };
        assert!(dims(at_cap).is_ok());
        assert_eq!(
            dims(ParamsSpec {
                degree: ParamsSpec::MAX_DEGREE + 1,
                ..toy
            }),
            Err(Error::DegreeTooLarge(ParamsSpec::MAX_DEGREE + 1))
        );
        let entries = |element_bits| {
            dims(ParamsSpec {
                element_bits,
                ..toy
            })
            .map(|d| d.matrix)
        };
        assert_eq!(entries(6551), Ok(65_530));
        assert_eq!(entries(6552), Err(Error::WitnessBoundTooLarge));
        let over = Err(Error::WitnessBoundTooLarge);
        assert_eq!(dims(ParamsSpec { n: 1 << 63, ..toy }), over);
        assert_eq!(
            dims(ParamsSpec {
                m: usize::MAX,
                ..toy
            }),
            over
        );
        assert_eq!(
            dims(ParamsSpec {
                m: 1 << 62,
                n: 4,
                ..toy
            }),
            over
        );
        assert_eq!(
            dims(ParamsSpec {
                element_bits: u32::MAX,
                m: usize::MAX - 1,
                ..toy
            }),
            over
        );
        // The parameter set exposes the same values.
        let params = Params::toy().unwrap();
        assert_eq!(
            (
                params.extension_len(),
                params.witness_len(),
                params.matrix_entries(),
                params.key_entries()
            ),
            (80, 100, 100, 101)
        );
    }
}
