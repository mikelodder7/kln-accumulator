// SPDX-License-Identifier: MIT OR Apache-2.0
//! The keys of Construction 4.1, `Gen` steps 1, 2 and 4: the manager's [`SecretKey`] and the
//! public parameters `pp = (A, B, u)` as a [`PublicKey`].
//!
//! # Key generation
//!
//! See the book's chapter "Keys".

use crate::{
    accumulator::{Accumulator, Element},
    error::{Error, Result, check_dimension},
    eval::{BitString, Indicator},
    matrix::{PolyMatrix, Shape},
    packing::{self, Packed, Uniform, packed_impls},
    params::{Params, ParamsSpec},
    poly::Poly,
    sample::{DomainLabel, Seed, UniformSampler, hash_to_seed},
    secret_hex,
    trapdoor::Trapdoor,
    vector::PolyVec,
};
use core::fmt;
use ctutils::CtEq;
use rand_core::CryptoRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Label that hashes the caller's seed into the root seed of a key.
const LABEL_ROOT: &[u8] = b"kln/keygen/root";

/// Label of the seed `TrapGen` runs from.
const LABEL_TRAPGEN: &[u8] = b"kln/keygen/trapgen";

/// Label of the uniform matrix `B`.
const LABEL_B: &[u8] = b"kln/keygen/b";

/// Label of the uniform vector `u`.
const LABEL_U: &[u8] = b"kln/keygen/u";

/// Label of the PRF key `k`.
const LABEL_PRF: &[u8] = b"kln/keygen/prf";

/// Label of the key that tags the manager state.
const LABEL_STATE_MAC: &[u8] = b"kln/keygen/state-mac";

/// Label of the genesis value `c₀` of the key's accumulator.
const LABEL_GENESIS: &[u8] = b"kln/keygen/genesis";

/// Label that binds a root seed to its parameter set before anything is derived from it.
const LABEL_SET: &[u8] = b"kln/keygen/set";

/// Label that separates the base key inside a succinct key from a Construction 4.1 key with
/// the same root seed.
const LABEL_COMPRESSED: &[u8] = b"kln/keygen/compressed";

/// The length of the root seed in [`SecretKey::to_bytes`].
const SEED_BYTES: usize = 32;

/// The shortest seed [`SecretKey::new`] accepts from its caller, in bytes, in every variant:
/// the length of the root seed it is hashed into. A shorter seed is refused with
/// [`Error::SeedTooShort`].
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Error, MIN_SEED_BYTES, Params, SecretKey};
/// use rand::{SeedableRng, rngs::StdRng};
/// use std::sync::Arc;
///
/// let params = Arc::new(Params::toy()?);
/// let mut rng = StdRng::seed_from_u64(0);
/// let short = [7u8; MIN_SEED_BYTES - 1];
/// let refused = SecretKey::new(Some(&short), Arc::clone(&params), &mut rng);
/// assert_eq!(refused.map(drop), Err(Error::SeedTooShort(MIN_SEED_BYTES - 1)));
/// assert!(SecretKey::new(Some(&[7u8; MIN_SEED_BYTES]), params, &mut rng).is_ok());
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub const MIN_SEED_BYTES: usize = SEED_BYTES;

/// The manager's secret key: the trapdoor `T_A` and the PRF key `k` of `Gen`, with the public
/// key they belong to, the key that tags the [`crate::ManagerState`], and the genesis value
/// `c₀` of the one accumulator the key keeps ([`Accumulator::new`]).
///
/// Everything is derived from a 32-byte root seed and the parameter set, so the serialized form
/// is the parameter set and that seed. The trapdoor and the PRF key are never exposed: the only
/// operation that uses the trapdoor is [`crate::MembershipWitness::new`], which samples one
/// preimage per element, for `c₀`, and so always reproduces the same one whatever the state
/// (Remark 4.1). Equality compares the set and the root seed in constant time.
///
/// **Secret (owner only).** The root seed, the PRF key, the state-tag key and the trapdoor are
/// overwritten when the key is dropped ([`ZeroizeOnDrop`]); the genesis value is public, the
/// first value the manager publishes. The key is neither `Copy` nor
/// `Clone`; [`fmt::Debug`] prints none of it. [`SecretKey::to_bytes`] returns the encoding in a
/// buffer wiped on drop, and the serde forms build and parse their hex in such buffers too;
/// the bytes a serializer writes to its own output are the caller's to wipe.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Params, SecretKey};
/// use rand::{SeedableRng, rngs::StdRng};
/// use std::sync::Arc;
///
/// let mut rng = StdRng::seed_from_u64(0);
/// let params = Arc::new(Params::toy()?);
/// // From a caller's seed the key is reproducible; the RNG is not used.
/// let a = SecretKey::new(Some(b"a seed of at least thirty-two bytes"), Arc::clone(&params), &mut rng)?;
/// let b = SecretKey::new(Some(b"a seed of at least thirty-two bytes"), Arc::clone(&params), &mut rng)?;
/// assert_eq!(a, b);
/// assert_eq!(**a.params(), *params);
/// assert_eq!(format!("{a:?}"), "SecretKey { .. }");
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub struct SecretKey {
    seed: Seed,
    prf_key: Seed,
    state_mac_key: Seed,
    trapdoor: Trapdoor,
    genesis: Accumulator,
    public: PublicKey,
    witness_form: WitnessForm,
}

/// Which witnesses a base key issues to callers of the public API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessForm {
    /// The key is a Construction 4.1 key and issues Construction 4.1 witnesses.
    Full,
    /// The key runs the accumulator of an `ℓ`-succinct key, whose holders receive only the
    /// compressed image of a Construction 4.1 witness.
    Compressed,
}

/// A secret key that is a function of its parameter set and a 32-byte root seed, so that its
/// encodings are the set and the seed. The secret key of every accumulator variant implements
/// it and takes its constructor, byte encoding, comparison and serde forms from here.
pub(crate) trait RootSeeded: Sized {
    /// The label that hashes the caller's seed into the root seed.
    const LABEL_ROOT: &'static [u8];

    /// The key whose root seed is `seed`.
    fn from_root(seed: Seed, params: Arc<Params>) -> Result<Self>;

    /// The root seed.
    fn root(&self) -> &Seed;

    /// The parameter set.
    fn root_params(&self) -> &Arc<Params>;

    /// With `Some(seed)` the key is a function of `seed` and the set alone, and a seed shorter
    /// than [`MIN_SEED_BYTES`] is refused with [`Error::SeedTooShort`]; with `None` the seed is
    /// 32 bytes from `rng`. Either way the root seed is SHAKE256 of the seed under
    /// [`RootSeeded::LABEL_ROOT`].
    fn from_input<R: CryptoRng + ?Sized>(
        seed: Option<&[u8]>,
        params: Arc<Params>,
        rng: &mut R,
    ) -> Result<Self> {
        let mut fresh = Zeroizing::new([0u8; SEED_BYTES]);
        let input = match seed {
            Some(bytes) if bytes.len() < MIN_SEED_BYTES => {
                return Err(Error::SeedTooShort(bytes.len()));
            }
            Some(bytes) => bytes,
            None => {
                rng.fill_bytes(fresh.as_mut_slice());
                fresh.as_slice()
            }
        };
        Self::from_root(
            hash_to_seed(DomainLabel::from(Self::LABEL_ROOT), &[input]),
            params,
        )
    }

    /// the 64-byte [`ParamsSpec`] encoding followed by the 32-byte root seed.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(ParamsSpec::BYTES + SEED_BYTES));
        out.extend_from_slice(&<[u8; ParamsSpec::BYTES]>::from(*self.root_params().spec()));
        out.extend_from_slice(self.root().as_bytes());
        out
    }

    /// Decodes [`RootSeeded::encode`] and rebuilds the key from the seed.
    fn decode(bytes: &[u8]) -> Result<Self> {
        let (spec, seed) = bytes
            .split_at_checked(ParamsSpec::BYTES)
            .ok_or(Error::InvalidEncodingLength(bytes.len()))?;
        Self::from_parts(ParamsSpec::try_from(spec)?, seed)
    }

    /// Rebuilds the key from a parameter set and a root seed of exactly 32 bytes.
    fn from_parts(spec: ParamsSpec, seed: &[u8]) -> Result<Self> {
        let root = Zeroizing::new(
            <[u8; SEED_BYTES]>::try_from(seed)
                .map_err(|_| Error::InvalidEncodingLength(seed.len()))?,
        );
        Self::from_root(Seed::from(*root), Arc::new(Params::try_from(spec)?))
    }

    /// Whether both keys have the same parameters and root seed; the seeds are compared in
    /// constant time.
    fn same_root(&self, other: &Self) -> bool {
        self.root_params() == other.root_params()
            && bool::from(self.root().as_bytes().ct_eq(other.root().as_bytes()))
    }

    /// Serializes the parameter set and the root seed (raw in binary formats, hex in
    /// human-readable ones).
    fn serialize_root<S: Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        SecretKeyRef {
            params: self.root_params().spec(),
            seed: self.root().as_bytes(),
        }
        .serialize(serializer)
    }

    /// Deserializes [`RootSeeded::serialize_root`] and rebuilds the key.
    fn deserialize_root<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let wire = SecretKeyWire::deserialize(deserializer)?;
        Self::from_parts(wire.params, &wire.seed).map_err(serde::de::Error::custom)
    }
}

/// The trait impls a [`RootSeeded`] secret key takes from the trait: decoding from bytes,
/// comparison, the `ZeroizeOnDrop` marker, a `Debug` that prints no field, the serde forms and
/// the byte encoding in a buffer wiped on drop. The documentation of the decoder and of the
/// marker, which differ between keys, comes with the invocation. The invoking module imports
/// `core::fmt` and `zeroize::ZeroizeOnDrop`, which its key's documentation links to.
macro_rules! root_seeded_impls {
    ($key:ident, $(#[$decode:meta])* decode, $(#[$wipe:meta])* wipe) => {
        $(#[$decode])*
        impl TryFrom<&[u8]> for $key {
            type Error = $crate::Error;

            fn try_from(bytes: &[u8]) -> $crate::Result<Self> {
                <Self as $crate::key::RootSeeded>::decode(bytes)
            }
        }

        /// Two keys are equal when they have the same parameters and root seed; the seeds are compared
        /// in constant time.
        impl PartialEq for $key {
            fn eq(&self, other: &Self) -> bool {
                <Self as $crate::key::RootSeeded>::same_root(self, other)
            }
        }

        impl Eq for $key {}

        $(#[$wipe])*
        impl ZeroizeOnDrop for $key {}

        impl fmt::Debug for $key {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("SecretKey").finish_non_exhaustive()
            }
        }

        /// Serialized as the parameter set and the root seed (raw in binary formats, hex in
        /// human-readable ones).
        impl ::serde::Serialize for $key {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                <Self as $crate::key::RootSeeded>::serialize_root(self, serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $key {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                <Self as $crate::key::RootSeeded>::deserialize_root(deserializer)
            }
        }

        /// The encoding of [`SecretKey::to_bytes`], which calls this, in a buffer wiped on drop.
        impl From<&$key> for ::zeroize::Zeroizing<Vec<u8>> {
            fn from(value: &$key) -> Self {
                <$key as $crate::key::RootSeeded>::encode(value)
            }
        }
    };
}
pub(crate) use root_seeded_impls;

impl SecretKey {
    /// `Gen` (Construction 4.1): a key for `params`. With `Some(seed)` the key is a function of
    /// `seed` and the set alone; with `None` the seed is 32 bytes from `rng`. Either way the root
    /// seed is SHAKE256 of the seed under a fixed label, and everything else is derived from
    /// SHAKE256 of the 64-byte [`ParamsSpec`] encoding and the root seed: `TrapGen` runs from a
    /// seed derived from it, and `B ∈ R_q^{n×ℓm'}`, `u ∈ R_q^n`, `k` and the state-tag key are
    /// drawn from it under their own labels. One seed under two parameter sets so gives two
    /// unrelated keys.
    ///
    /// The cost is dominated by `TrapGen`: drawing `T_A` (`(m − m')·m'·d` coefficients),
    /// checking its perturbation covariance, and one product `Ā·T_A`. A Gaussian `T_A` is drawn
    /// with a scan of the whole sampling table per base draw, which does not branch on the draw
    /// and is slower than a table search. Milliseconds at the toy set; the `paper_128`
    /// benchmark measures the 128-bit set (see the book's benchmarks chapter).
    ///
    /// # Errors
    ///
    /// [`Error::SeedTooShort`] for a caller's seed shorter than [`crate::MIN_SEED_BYTES`], and
    /// [`Error::InvalidTrapdoor`] when none of the first eight trapdoors drawn passes the
    /// sampler's check, which happens with negligible probability at a valid set.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params, ParamsSpec, PublicKey, SecretKey, TrapdoorDistribution};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let mut rng = StdRng::seed_from_u64(0);
    /// let params = Arc::new(Params::toy()?);
    /// let fresh = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    /// let stored = b"stored seed of at least 32 bytes";
    /// let seeded = SecretKey::new(Some(stored), Arc::clone(&params), &mut rng)?;
    /// assert_ne!(fresh, seeded);
    /// // A short seed is refused.
    /// let short = SecretKey::new(Some(b"stored seed"), Arc::clone(&params), &mut rng);
    /// assert_eq!(short.map(drop), Err(Error::SeedTooShort(11)));
    /// // The same seed under another set gives an unrelated key.
    /// let ternary = Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))?;
    /// let other = SecretKey::new(Some(stored), Arc::new(ternary), &mut rng)?;
    /// assert_ne!(PublicKey::from(&other).a(), PublicKey::from(&seeded).a());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new<R: CryptoRng + ?Sized>(
        seed: Option<&[u8]>,
        params: Arc<Params>,
        rng: &mut R,
    ) -> Result<Self> {
        Self::from_input(seed, params, rng)
    }

    /// The parameter set; see the type's example.
    #[must_use]
    pub fn params(&self) -> &Arc<Params> {
        &self.public.params
    }

    /// The encoding: the 64-byte [`ParamsSpec`] encoding followed by the 32-byte root seed, 96 bytes. It
    /// is the whole secret, and is overwritten when dropped. `TryFrom<&[u8]>` decodes it,
    /// failing with [`Error::InvalidEncodingLength`] for any other length and as
    /// [`Params::try_from`] and [`SecretKey::new`] do otherwise. See the book's chapter "Keys".
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let stored = key.to_bytes(); // wiped when `stored` is dropped
    /// assert_eq!(stored.len(), 96);
    /// let reloaded = SecretKey::try_from(stored.as_slice())?;
    /// assert_eq!(reloaded, key);
    /// // Keep the bytes in that buffer: a copy such as `stored.to_vec()` is never wiped.
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::<Vec<u8>>::from(self)
    }

    /// The public key this key belongs to.
    pub(crate) fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The trapdoor `T_A`.
    pub(crate) fn trapdoor(&self) -> &Trapdoor {
        &self.trapdoor
    }

    /// The PRF key `k`.
    pub(crate) fn prf_key(&self) -> &Seed {
        &self.prf_key
    }

    /// The key that tags the [`crate::ManagerState`].
    pub(crate) fn state_mac_key(&self) -> &Seed {
        &self.state_mac_key
    }

    /// The genesis value `c₀` of the key's accumulator.
    pub(crate) fn genesis(&self) -> &Accumulator {
        &self.genesis
    }

    /// Which witnesses the key issues through the public API.
    pub(crate) fn witness_form(&self) -> WitnessForm {
        self.witness_form
    }

    /// `Gen` from the root seed `seed` with `B ∈ R_q^{n×ℓm'}` supplied by `make_b` from the
    /// set, the [`derivation_seed`], `A` and `T_A` instead of drawn uniformly; `make_b` also
    /// returns whatever else it derived. The trapdoor, `u` and `k` derive from the derivation
    /// seed as in [`SecretKey::new`]. The `ℓ`-succinct variant uses this for `B = −B₁·T₁`,
    /// with [`WitnessForm::Compressed`].
    pub(crate) fn with_b<T>(
        seed: Seed,
        params: Arc<Params>,
        witness_form: WitnessForm,
        make_b: impl FnOnce(&Params, &Seed, &PolyMatrix, &Trapdoor) -> Result<(PolyMatrix, T)>,
    ) -> Result<(Self, T)> {
        // The form enters the derivation: the root seed of the base key inside a succinct key,
        // decoded as a Construction 4.1 key, gives a key that shares nothing with it. Were the
        // trapdoor and the PRF key shared, the two keys would sample for two matrices from one
        // randomness, and their witnesses for one element would give the trapdoor away.
        let derived = match witness_form {
            WitnessForm::Full => derivation_seed(&seed, &params),
            WitnessForm::Compressed => hash_to_seed(
                DomainLabel::from(LABEL_COMPRESSED),
                &[derivation_seed(&seed, &params).as_bytes()],
            ),
        };
        let base = derived.as_bytes().as_slice();
        let trapgen_seed = hash_to_seed(DomainLabel::from(LABEL_TRAPGEN), &[base]);
        let (a, trapdoor) = Trapdoor::generate(&params, &trapgen_seed)?;
        let (b, extra) = make_b(&params, &derived, &a, &trapdoor)?;
        let u = UniformSampler::new(&derived, DomainLabel::from(LABEL_U))
            .vector(params.spec().n, params.ring());
        let genesis = Accumulator::from_vector(
            UniformSampler::new(&derived, DomainLabel::from(LABEL_GENESIS))
                .vector(params.spec().n, params.ring()),
            &params,
        )?;
        let key = Self {
            genesis,
            prf_key: hash_to_seed(DomainLabel::from(LABEL_PRF), &[base]),
            state_mac_key: hash_to_seed(DomainLabel::from(LABEL_STATE_MAC), &[base]),
            seed,
            trapdoor,
            public: PublicKey::from_parts(params, a, b, u)?,
            witness_form,
        };
        Ok((key, extra))
    }
}

impl RootSeeded for SecretKey {
    const LABEL_ROOT: &'static [u8] = LABEL_ROOT;

    fn from_root(seed: Seed, params: Arc<Params>) -> Result<Self> {
        Self::with_b(seed, params, WitnessForm::Full, |params, derived, _, _| {
            let shape = Shape {
                rows: params.spec().n,
                cols: params.extension_len(),
            };
            let b = UniformSampler::new(derived, DomainLabel::from(LABEL_B))
                .matrix(shape, params.ring());
            Ok((b, ()))
        })
        .map(|(key, ())| key)
    }

    fn root(&self) -> &Seed {
        &self.seed
    }

    fn root_params(&self) -> &Arc<Params> {
        self.params()
    }
}

impl From<&SecretKey> for PublicKey {
    /// The public key of `secret_key`, the `pp = (A, B, u)` the manager publishes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Params, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let pk = PublicKey::from(&key);
    /// assert!(Arc::ptr_eq(pk.params(), key.params()));
    /// let published = pk.to_bytes(); // safe to publish; the secret key is not
    /// assert_eq!(PublicKey::from_bytes(key.params(), &published)?, pk);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    fn from(secret_key: &SecretKey) -> Self {
        secret_key.public.clone()
    }
}

root_seeded_impls! {
    SecretKey,
    /// Decodes [`SecretKey::to_bytes`] and rebuilds the trapdoor, `B`, `u` and `k` from the seed.
    decode,
    /// The seeds and the trapdoor overwrite themselves when dropped, so the key needs no `Drop` of
    /// its own.
    wipe
}

/// The seed every value of a key is derived from: SHAKE256 of the 64-byte [`ParamsSpec`]
/// encoding of `params` and the root seed, under its own label. Deriving from it rather than
/// from the root seed makes one root seed under two parameter sets give two unrelated keys,
/// sharing no trapdoor, matrix, PRF key or state-tag key. Overwritten when dropped, as every
/// [`Seed`] is.
pub(crate) fn derivation_seed(root: &Seed, params: &Params) -> Seed {
    let spec = <[u8; ParamsSpec::BYTES]>::from(*params.spec());
    hash_to_seed(DomainLabel::from(LABEL_SET), &[&spec, root.as_bytes()])
}

/// The serialized form of a [`RootSeeded`] key. The seed's hex text is built in a buffer that
/// is overwritten when dropped.
#[derive(Serialize)]
struct SecretKeyRef<'a> {
    params: &'a ParamsSpec,
    #[serde(serialize_with = "secret_hex::serialize")]
    seed: &'a [u8; SEED_BYTES],
}

/// The serialized form of a [`RootSeeded`] key, before the key is rebuilt. The decoded seed is
/// overwritten when dropped, on success and on every error. A field it does not name is
/// refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretKeyWire {
    params: ParamsSpec,
    #[serde(deserialize_with = "secret_hex::deserialize")]
    seed: Zeroizing<Vec<u8>>,
}

/// The public parameters `pp = (A, B, u)` of Construction 4.1 with their parameter set:
/// `A ∈ R_q^{n×m}` with a trapdoor, `B ∈ R_q^{n×ℓm'}` and `u ∈ R_q^n` uniform.
///
/// A deserialized or decoded key has its set rebuilt and validated, and `A`, `B`, `u` checked
/// for shape and range against it. **Public.**
///
/// Size: `n·(m + ℓm') + n` polynomials of `⌈log₂ q⌉`-bit coefficients plus the 64-byte set.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Params, PublicKey, SecretKey};
/// use kln_accumulator::lattice::Shape;
/// use rand::{SeedableRng, rngs::StdRng};
/// use std::sync::Arc;
///
/// let mut rng = StdRng::seed_from_u64(0);
/// let key = SecretKey::new(Some(b"a seed of at least thirty-two bytes"), Arc::new(Params::toy()?), &mut rng)?;
/// let pk = PublicKey::from(&key);
/// let spec = pk.params().spec();
/// assert_eq!(pk.a().shape(), Shape { rows: spec.n, cols: spec.m });
/// assert_eq!(pk.b().shape(), Shape { rows: spec.n, cols: 8 * 10 }); // ℓ·m'
/// assert_eq!(pk.u().len(), spec.n);
/// // 64 bytes of set, then 101 polynomials of 64 coefficients at 60 bits.
/// assert_eq!(pk.to_bytes().len(), 64 + 101 * 64 * 60 / 8);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    params: Arc<Params>,
    a: PolyMatrix,
    b: PolyMatrix,
    u: PolyVec,
}

impl PublicKey {
    /// The parameter set. See the type's example.
    #[must_use]
    pub fn params(&self) -> &Arc<Params> {
        &self.params
    }

    /// `A ∈ R_q^{n×m}`. See the type's example.
    #[must_use]
    pub fn a(&self) -> &PolyMatrix {
        &self.a
    }

    /// `B ∈ R_q^{n×ℓm'}`. See the type's example.
    #[must_use]
    pub fn b(&self) -> &PolyMatrix {
        &self.b
    }

    /// `u ∈ R_q^n`. See the type's example.
    #[must_use]
    pub fn u(&self) -> &PolyVec {
        &self.u
    }

    /// The encoding: the 64-byte [`ParamsSpec`] encoding, then the coefficients of `A` and `B` (entries
    /// row-major) and of `u` in `⌈log₂ q⌉` bits each (Table 2), least significant bit first,
    /// the last byte padded with zero bits. `TryFrom<&[u8]>` decodes it, rebuilding the set and
    /// failing with [`Error::InvalidEncodingLength`], [`Error::NonCanonicalEncoding`] or
    /// [`Error::CoefficientOutOfRange`] on a malformed input.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Params, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let pk = PublicKey::from(&key);
    /// let published = pk.to_bytes();
    /// assert_eq!(published.len(), 64 + 101 * 64 * 60 / 8); // set, then n·(m + ℓm') + n polynomials
    /// // Holders decode against the set they expect, so the bytes cannot choose it.
    /// assert_eq!(PublicKey::from_bytes(key.params(), &published)?, pk);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// Appends the packed coefficients of `A`, `B` and `u`.
    fn write_coefficients(&self, out: &mut Vec<u8>) {
        Uniform::new(self.params.ring()).write(
            self.a
                .entries()
                .iter()
                .chain(self.b.entries())
                .chain(self.u.as_slice()),
            out,
        );
    }

    /// `[A | B − xᵀ⊗G]`, the matrix a witness for `x` is a short preimage under.
    pub(crate) fn membership_matrix(&self, x: &BitString) -> Result<PolyMatrix> {
        let params = &*self.params;
        let ell = params.spec().element_bits as usize;
        check_dimension(ell, x.as_slice().len())?;
        let ring = params.ring();
        let g = PolyMatrix::from(params.gadget());
        let width = g.shape().cols;
        let (rows, a_cols) = (self.a.shape().rows, self.a.shape().cols);
        let cols = params.witness_len();
        /// Entry `(row, col)` of `m`, which the shapes checked at construction guarantee.
        fn entry(m: &PolyMatrix, row: usize, col: usize) -> Result<&Poly> {
            m.get(row, col).ok_or(Error::DimensionMismatch {
                expected: m.shape().cols,
                found: col,
            })
        }
        // Row by row: the row of A, then block i of B − xᵀ⊗G, which is B_i − x_i·G. Built in
        // one pass, so no partial concatenation is copied.
        let mut entries = Vec::with_capacity(params.matrix_entries());
        for row in 0..rows {
            for col in 0..a_cols {
                entries.push(entry(&self.a, row, col)?.clone());
            }
            for (i, &bit) in x.as_slice().iter().enumerate() {
                for col in 0..width {
                    let b = entry(&self.b, row, i * width + col)?;
                    entries.push(if bit {
                        b.sub(entry(&g, row, col)?, ring)?
                    } else {
                        b.clone()
                    });
                }
            }
        }
        PolyMatrix::new(Shape { rows, cols }, entries)
    }

    /// `B_{1y}·G⁻¹(u)`, what deleting `y` adds to the accumulator value (Construction 4.1,
    /// Delete step 3).
    pub(crate) fn deletion_offset(&self, y: &Element) -> Result<PolyVec> {
        let bits = y.to_bits(&self.params)?;
        Indicator::new(&self.params, &bits, &self.b)?.eval_f_vec(&self.u)
    }

    /// `Σ_y H_{1y,x}·G⁻¹(u) ∈ R^{ℓm'}` over `deletions` (Construction 4.1, MemWitUp), what those
    /// deletions add to the last `ℓm'` coordinates of the witness for `x`. Fails with
    /// [`Error::ElementDeleted`] when `x` is among them: its correction would satisfy the
    /// update equation only up to `−u`.
    pub(crate) fn correction<'a>(
        &self,
        x: &Element,
        deletions: impl IntoIterator<Item = &'a Element>,
    ) -> Result<PolyVec> {
        let params = &*self.params;
        let ring = params.ring();
        let x_bits = x.to_bits(params)?;
        let width = params.extension_len();
        deletions
            .into_iter()
            .try_fold(PolyVec::zero(width, ring), |sum, y| {
                if y == x {
                    return Err(Error::ElementDeleted);
                }
                let y_bits = y.to_bits(params)?;
                let h_u =
                    Indicator::new(params, &y_bits, &self.b)?.eval_fx_vec(&x_bits, &self.u)?;
                sum.add(&h_u, ring)
            })
    }

    /// Checks the shapes of `A`, `B`, `u` against `params` and every coefficient against `q`.
    pub(crate) fn from_parts(
        params: Arc<Params>,
        a: PolyMatrix,
        b: PolyMatrix,
        u: PolyVec,
    ) -> Result<Self> {
        let spec = params.spec();
        let ring = params.ring();
        let check_shape = |found: Shape, cols: usize| {
            let expected = Shape { rows: spec.n, cols };
            if found == expected {
                Ok(())
            } else {
                Err(Error::DimensionMismatch {
                    expected: expected.saturating_len(),
                    found: found.saturating_len(),
                })
            }
        };
        check_shape(a.shape(), spec.m)?;
        check_shape(b.shape(), params.extension_len())?;
        check_dimension(spec.n, u.len())?;
        a.validate(ring)?;
        b.validate(ring)?;
        u.validate(ring)?;
        Ok(Self { params, a, b, u })
    }
}

impl Packed for PublicKey {
    fn params(&self) -> &Arc<Params> {
        &self.params
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.write_coefficients(out);
        Ok(())
    }

    fn read_body(params: Arc<Params>, body: &[u8]) -> Result<Self> {
        let spec = params.spec();
        let a_shape = Shape {
            rows: spec.n,
            cols: spec.m,
        };
        let b_shape = Shape {
            rows: spec.n,
            cols: params.extension_len(),
        };
        let (entries, rest) =
            Uniform::new(params.ring()).read(body, params.key_entries(), params.ring().degree())?;
        let mut entries = Vec::from(entries);
        let u = entries.split_off(params.matrix_entries());
        let b = entries.split_off(a_shape.len().ok_or(Error::WitnessBoundTooLarge)?);
        let key = Self::from_parts(
            params,
            PolyMatrix::new(a_shape, entries)?,
            PolyMatrix::new(b_shape, b)?,
            u.into_iter().collect(),
        )?;
        packing::finish(key, rest)
    }
}

packed_impls! {
    PublicKey,
    /// Decodes [`PublicKey::to_bytes`], rebuilding and validating the parameter set; the input must
    /// be consumed exactly.
    decode,
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params, PublicKey, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let params = Arc::new(Params::toy()?);
    /// let key = SecretKey::new(None, Arc::clone(&params), &mut StdRng::seed_from_u64(0))?;
    /// let bytes = PublicKey::from(&key).to_bytes();
    /// let pk = PublicKey::from_bytes(&params, &bytes)?;
    /// assert!(Arc::ptr_eq(pk.params(), &params));
    /// // The bytes of a key at another set are refused.
    /// let other = Arc::new(Params::succinct_toy()?);
    /// assert_eq!(PublicKey::from_bytes(&other, &bytes).map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    from_bytes,
    /// Serialized as the parameter set and the packed coefficients of [`PublicKey::to_bytes`] (raw
    /// in binary formats, hex in human-readable ones).
    serialize
}

/// The encoding of [`PublicKey::to_bytes`], which calls this.
impl From<&PublicKey> for Vec<u8> {
    fn from(value: &PublicKey) -> Self {
        packing::to_bytes_with(value, PublicKey::write_coefficients)
    }
}

#[cfg(test)]
mod tests {
    use super::{MIN_SEED_BYTES, PublicKey, SecretKey};
    use crate::{
        error::Error,
        test_util::{TOY, TOY_TERNARY},
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::Arc;

    /// The seed both toy sets are keyed from in these tests.
    const SEED: &[u8] = b"kln/test/key, one seed for two sets";

    /// C69: a caller's seed shorter than 32 bytes is refused with its length; 32 bytes, a
    /// longer seed and the RNG's seed are accepted.
    #[test]
    fn short_seeds_are_refused() {
        let params = Arc::new(TOY.clone());
        let mut rng = StdRng::seed_from_u64(0);
        for len in [0, 1, MIN_SEED_BYTES - 1] {
            let seed = vec![7u8; len];
            let refused = SecretKey::new(Some(&seed), Arc::clone(&params), &mut rng);
            assert_eq!(refused.map(drop), Err(Error::SeedTooShort(len)));
        }
        for len in [MIN_SEED_BYTES, MIN_SEED_BYTES + 1] {
            assert!(SecretKey::new(Some(&vec![7u8; len]), Arc::clone(&params), &mut rng).is_ok());
        }
        assert!(SecretKey::new(None, params, &mut rng).is_ok());
    }

    /// C70: one seed under the Gaussian and the ternary toy sets gives keys that share no
    /// derived value: the PRF keys, the state-tag keys and the public keys all differ. The
    /// encoding keeps its form, the set and then the same root seed, and round-trips.
    #[test]
    fn one_seed_under_two_sets_shares_nothing() {
        let mut rng = StdRng::seed_from_u64(0);
        let gaussian = SecretKey::new(Some(SEED), Arc::new(TOY.clone()), &mut rng).unwrap();
        let ternary = SecretKey::new(Some(SEED), Arc::new(TOY_TERNARY.clone()), &mut rng).unwrap();
        assert_ne!(gaussian.prf_key(), ternary.prf_key());
        assert_ne!(gaussian.state_mac_key(), ternary.state_mac_key());
        let (pk, pk_ternary) = (PublicKey::from(&gaussian), PublicKey::from(&ternary));
        assert_ne!(pk.a(), pk_ternary.a());
        assert_ne!(pk.b(), pk_ternary.b());
        assert_ne!(pk.u(), pk_ternary.u());
        let (bytes, bytes_ternary) = (gaussian.to_bytes(), ternary.to_bytes());
        assert_eq!(bytes.len(), 96);
        assert_eq!(bytes[64..], bytes_ternary[64..]);
        assert_ne!(bytes[..64], bytes_ternary[..64]);
        assert_eq!(SecretKey::try_from(bytes.as_slice()).unwrap(), gaussian);
        assert_eq!(
            SecretKey::try_from(bytes_ternary.as_slice()).unwrap(),
            ternary
        );
    }
}
