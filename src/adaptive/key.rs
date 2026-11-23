// SPDX-License-Identifier: MIT OR Apache-2.0
//! The keys of Construction 4.2, `Gen` steps 1–3 and 5: `sk = (sk_Σ, s̃k)` with the PRF key `k`
//! as a [`SecretKey`], and `pp = (pk_Σ, p̃p)` as a [`PublicKey`].

use super::accumulator::Element;
use crate::{
    accumulator::Element as Handle,
    error::{Error, Result},
    key::{
        PublicKey as InnerPublicKey, RootSeeded, SecretKey as InnerSecretKey, derivation_seed,
        root_seeded_impls,
    },
    params::Params,
    sample::{DomainLabel, Seed, hash_to_seed},
};
use core::fmt;
use ml_dsa::{
    B32, EncodedVerifyingKey, Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use rand_core::CryptoRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Label that hashes the caller's seed into the root seed of an adaptive key.
const LABEL_ROOT: &[u8] = b"kln/adaptive/keygen/root";

/// Label of the root seed of the inner Construction 4.1 key.
const LABEL_INNER: &[u8] = b"kln/adaptive/keygen/inner";

/// Label of the ML-DSA key-generation seed `ξ`.
const LABEL_SIGNING: &[u8] = b"kln/adaptive/keygen/ml-dsa";

/// Label of the PRF key `k`.
const LABEL_PRF: &[u8] = b"kln/adaptive/keygen/prf";

/// Label of the key that tags the manager state.
const LABEL_STATE_MAC: &[u8] = b"kln/adaptive/keygen/state-mac";

/// Label of the handle PRF `F_k(x, i)`.
const LABEL_HANDLE: &[u8] = b"kln/adaptive/handle";

/// Prefix of every signed message `kln/adaptive/sign ‖ x ‖ r_x`.
const LABEL_MESSAGE: &[u8] = b"kln/adaptive/sign";

/// The length of an ML-DSA-65 signature (FIPS 204, Table 2).
pub(super) const SIGNATURE_BYTES: usize = 3309;

/// The length of an ML-DSA-65 verifying key (FIPS 204, Table 2).
const VERIFYING_KEY_BYTES: usize = 1952;

/// The manager's secret key of Construction 4.2: the ML-DSA-65 signing key, the inner
/// Construction 4.1 key and the PRF key `k` of the handles, with the public key, and the key
/// that tags the [`super::ManagerState`].
///
/// Everything is derived from a 32-byte root seed and the parameter set (see the
/// [module documentation](super)), so
/// the serialized form is the parameter set and that seed, 96 bytes. Equality compares the set
/// and the root seed in constant time.
///
/// **Secret (owner only).** The seeds, the ML-DSA signing key (wiped by `ml-dsa`'s `zeroize`
/// feature) and the inner key with its trapdoor are overwritten when the key is dropped
/// ([`ZeroizeOnDrop`]); the key is neither `Copy` nor `Clone`; [`fmt::Debug`] prints none of
/// it; [`SecretKey::to_bytes`] and the serde forms use buffers wiped on drop.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::Params;
/// # use kln_accumulator::adaptive::{
/// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
/// # };
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
/// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// # // Deleting publishes handles; the holder updates with the handles in the messages.
/// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
/// #     c.iter().map(|m| m.element().clone()).collect()
/// # };
/// assert_eq!(SecretKey::try_from(key.to_bytes().as_slice())?, key);
/// assert_eq!(key.params().spec().element_bits, 8);
/// assert_eq!(format!("{key:?}"), "SecretKey { .. }");
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub struct SecretKey {
    seed: Seed,
    prf_key: Seed,
    state_mac_key: Seed,
    signing: SigningKey<MlDsa65>,
    inner: InnerSecretKey,
    public: PublicKey,
}

impl SecretKey {
    /// `Gen` (Construction 4.2): a key for `params`. With `Some(seed)` the key is a function of
    /// `seed` and the set alone, and a seed shorter than [`crate::MIN_SEED_BYTES`] is refused;
    /// with `None` the seed is 32 bytes from `rng`. One seed under two sets gives unrelated
    /// keys.
    ///
    /// The cost is that of the inner [`crate::SecretKey::new`] plus ML-DSA-65 key generation.
    ///
    /// # Errors
    ///
    /// As [`crate::SecretKey::new`]: [`Error::SeedTooShort`] for a short seed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::SecretKey;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// let params = Arc::new(Params::toy()?);
    /// let a = SecretKey::new(Some(b"a seed of at least thirty-two bytes"), Arc::clone(&params), &mut rng)?;
    /// assert_eq!(a, SecretKey::new(Some(b"a seed of at least thirty-two bytes"), params, &mut rng)?);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new<R: CryptoRng + ?Sized>(
        seed: Option<&[u8]>,
        params: Arc<Params>,
        rng: &mut R,
    ) -> Result<Self> {
        Self::from_input(seed, params, rng)
    }

    /// The parameter set of the inner accumulator; see the type's example.
    #[must_use]
    pub fn params(&self) -> &Arc<Params> {
        self.inner.params()
    }

    /// The encoding: the 64-byte [`crate::ParamsSpec`] encoding followed by the 32-byte root
    /// seed, 96 bytes. It is the whole secret, and is overwritten when dropped.
    /// `TryFrom<&[u8]>` decodes it and rebuilds every key from the seed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::SecretKey;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let stored = key.to_bytes(); // wiped when `stored` is dropped
    /// assert_eq!(stored.len(), 96); // the ML-DSA-65 signing key is rebuilt, not stored
    /// assert_eq!(SecretKey::try_from(stored.as_slice())?, key);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::<Vec<u8>>::from(self)
    }

    /// The inner Construction 4.1 key `s̃k`.
    pub(super) fn inner(&self) -> &InnerSecretKey {
        &self.inner
    }

    /// The key that tags the [`super::ManagerState`].
    pub(super) fn state_mac_key(&self) -> &Seed {
        &self.state_mac_key
    }

    /// The handle `F_k(x, i) ∈ {0, 1}^ℓ`: SHAKE256 of `k ‖ x ‖ i` under its own label,
    /// truncated to `ℓ` bits.
    pub(super) fn handle(&self, x: &Element, index: u64) -> Handle {
        Handle::derive(
            DomainLabel::from(LABEL_HANDLE),
            &[self.prf_key.as_bytes(), &x.to_bytes(), &index.to_le_bytes()],
            self.params(),
        )
    }

    /// `Σ.Sign(sk_Σ, (x, r))`, deterministic, as the encoded signature, which is part of the
    /// holder's witness and so overwritten when dropped.
    pub(super) fn sign(&self, x: &Element, handle: &Handle) -> Result<Zeroizing<Vec<u8>>> {
        self.signing
            .try_sign(&message(x, handle))
            .map(|signature| Zeroizing::new(signature.encode().to_vec()))
            .map_err(|_| Error::SigningFailed)
    }
}

impl RootSeeded for SecretKey {
    const LABEL_ROOT: &'static [u8] = LABEL_ROOT;

    fn from_root(seed: Seed, params: Arc<Params>) -> Result<Self> {
        let derived = derivation_seed(&seed, &params);
        let base = derived.as_bytes().as_slice();
        let inner_seed = hash_to_seed(DomainLabel::from(LABEL_INNER), &[base]);
        let inner = InnerSecretKey::from_root(inner_seed, params)?;
        let signing_seed = hash_to_seed(DomainLabel::from(LABEL_SIGNING), &[base]);
        let mut xi = B32::from(*signing_seed.as_bytes());
        let signing = SigningKey::<MlDsa65>::from_seed(&xi);
        xi.zeroize();
        let public = PublicKey {
            verifying: signing.verifying_key(),
            inner: InnerPublicKey::from(&inner),
        };
        Ok(Self {
            prf_key: hash_to_seed(DomainLabel::from(LABEL_PRF), &[base]),
            state_mac_key: hash_to_seed(DomainLabel::from(LABEL_STATE_MAC), &[base]),
            seed,
            signing,
            inner,
            public,
        })
    }

    fn root(&self) -> &Seed {
        &self.seed
    }

    fn root_params(&self) -> &Arc<Params> {
        self.params()
    }
}

/// The signed message `kln/adaptive/sign ‖ x ‖ r`, overwritten when dropped since it holds the
/// holder's handle.
fn message(x: &Element, handle: &Handle) -> Zeroizing<Vec<u8>> {
    Zeroizing::new([LABEL_MESSAGE, &x.to_bytes(), handle.as_bytes()].concat())
}

impl From<&SecretKey> for PublicKey {
    /// The public key of `secret_key`: the ML-DSA-65 verifying key and the inner public key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{PublicKey, SecretKey};
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
    /// Decodes [`SecretKey::to_bytes`] and rebuilds every key from the seed.
    decode,
    /// The seeds, the ML-DSA signing key (through `ml-dsa`'s `zeroize` feature) and the inner key
    /// overwrite themselves when dropped, so the key needs no `Drop` of its own.
    wipe
}

/// The public parameters `pp = (pk_Σ, p̃p)` of Construction 4.2: the ML-DSA-65 verifying key and
/// the inner public key `(A, B, u)` with its parameter set. **Public.** Its encoding is the
/// 1952-byte verifying key followed by the inner public key's.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::Params;
/// # use kln_accumulator::adaptive::{
/// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
/// # };
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
/// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// # // Deleting publishes handles; the holder updates with the handles in the messages.
/// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
/// #     c.iter().map(|m| m.element().clone()).collect()
/// # };
/// assert_eq!(pk.params(), key.params());
/// assert_eq!(pk.inner().params(), key.params());
/// let bytes = pk.to_bytes();
/// assert_eq!(bytes.len(), 1952 + pk.inner().to_bytes().len());
/// assert_eq!(PublicKey::try_from(bytes.as_slice())?, pk);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    verifying: VerifyingKey<MlDsa65>,
    inner: InnerPublicKey,
}

impl PublicKey {
    /// The parameter set of the inner accumulator; see the type's example.
    #[must_use]
    pub fn params(&self) -> &Arc<Params> {
        self.inner.params()
    }

    /// The inner public key `p̃p = (A, B, u)`, under which the handles are accumulated. See the
    /// type's example.
    #[must_use]
    pub fn inner(&self) -> &InnerPublicKey {
        &self.inner
    }

    /// The encoding: the 1952-byte ML-DSA-65 verifying key, then [`InnerPublicKey::to_bytes`].
    /// `TryFrom<&[u8]>` decodes it and fails with [`Error::InvalidEncodingLength`] or as the
    /// inner key's decoding does.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let pk = PublicKey::from(&key);
    /// let published = pk.to_bytes();
    /// assert_eq!(published.len(), 1952 + pk.inner().to_bytes().len()); // verifying key, inner key
    /// // Holders decode against the set they expect, so the bytes cannot choose it.
    /// assert_eq!(PublicKey::from_bytes(key.params(), &published)?, pk);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// Decodes [`PublicKey::to_bytes`] against `params`, the set the caller expects: the inner
    /// key is decoded with [`InnerPublicKey::from_bytes`], so no set is built from the input,
    /// and the result shares `params`. Use this for bytes from an untrusted source.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEncodingLength`] when the bytes are shorter than the verifying key, and
    /// otherwise as [`InnerPublicKey::from_bytes`]: [`Error::ParameterMismatch`] when the bytes
    /// name another set.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params, adaptive::{PublicKey, SecretKey}};
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
    pub fn from_bytes(params: &Arc<Params>, bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, |inner| InnerPublicKey::from_bytes(params, inner))
    }

    /// Decodes [`PublicKey::to_bytes`], reading the inner key with `inner`.
    fn decode<'b>(
        bytes: &'b [u8],
        inner: impl FnOnce(&'b [u8]) -> Result<InnerPublicKey>,
    ) -> Result<Self> {
        let (verifying, rest) = bytes
            .split_at_checked(VERIFYING_KEY_BYTES)
            .ok_or(Error::InvalidEncodingLength(bytes.len()))?;
        Self::from_parts(verifying, inner(rest)?)
    }

    /// `Σ.Verify(pk_Σ, σ, (x, r))` for the encoded signature `signature`.
    pub(super) fn signs(&self, x: &Element, handle: &Handle, signature: &[u8]) -> bool {
        Signature::<MlDsa65>::try_from(signature).is_ok_and(|signature| {
            self.verifying
                .verify(&message(x, handle), &signature)
                .is_ok()
        })
    }

    /// The key from an encoded verifying key and an inner public key.
    fn from_parts(verifying: &[u8], inner: InnerPublicKey) -> Result<Self> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(verifying)
            .map_err(|_| Error::InvalidEncodingLength(verifying.len()))?;
        Ok(Self {
            verifying: VerifyingKey::decode(&encoded),
            inner,
        })
    }
}

/// The verifying key is compared structurally, which is an equivalence.
impl Eq for PublicKey {}

/// Decodes [`PublicKey::to_bytes`], which must be consumed exactly. It builds the set the bytes
/// name, so for bytes from an untrusted source use [`PublicKey::from_bytes`] with the set you
/// expect.
impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, InnerPublicKey::try_from)
    }
}

/// Serialized as the verifying key (raw in binary formats, hex in human-readable ones) and the
/// inner public key.
impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        PublicKeyRef {
            verifying_key: &self.verifying.encode(),
            inner: &self.inner,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let wire = PublicKeyWire::deserialize(deserializer)?;
        Self::from_parts(&wire.verifying_key, wire.inner).map_err(serde::de::Error::custom)
    }
}

/// The serialized form of [`PublicKey`].
#[derive(Serialize)]
struct PublicKeyRef<'a> {
    #[serde(serialize_with = "serdect::slice::serialize_hex_lower_or_bin")]
    verifying_key: &'a [u8],
    inner: &'a InnerPublicKey,
}

/// The serialized form of [`PublicKey`], before the verifying key is decoded; a field it does
/// not name is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyWire {
    #[serde(deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec")]
    verifying_key: Vec<u8>,
    inner: InnerPublicKey,
}

/// The encoding of [`PublicKey::to_bytes`], which calls this.
impl From<&PublicKey> for Vec<u8> {
    fn from(value: &PublicKey) -> Self {
        let mut out = value.verifying.encode().to_vec();
        out.extend_from_slice(&value.inner.to_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{SIGNATURE_BYTES, SecretKey, VERIFYING_KEY_BYTES};
    use crate::{
        adaptive::Element,
        error::Error,
        key::PublicKey as InnerPublicKey,
        test_util::{TOY, TOY_TERNARY},
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::Arc;

    /// C69: a caller's seed shorter than 32 bytes is refused with its length; 32 bytes are
    /// accepted.
    #[test]
    fn short_seeds_are_refused() {
        let params = Arc::new((*TOY).clone());
        let mut rng = StdRng::seed_from_u64(0);
        for len in [0, 31] {
            let refused = SecretKey::new(Some(&vec![7u8; len]), Arc::clone(&params), &mut rng);
            assert_eq!(refused.map(drop), Err(Error::SeedTooShort(len)));
        }
        assert!(SecretKey::new(Some(&[7u8; 32]), params, &mut rng).is_ok());
    }

    /// C70: one seed under the Gaussian and the ternary toy sets gives keys that share no
    /// derived value: the ML-DSA keys, the handle PRF keys, the state-tag keys and the inner
    /// keys all differ, so the same element gets unrelated handles. The encoding keeps the same
    /// root seed after the set.
    #[test]
    fn one_seed_under_two_sets_shares_nothing() {
        let seed = b"kln/test/adaptive-key, one seed for two sets";
        let mut rng = StdRng::seed_from_u64(0);
        let gaussian = SecretKey::new(Some(seed), Arc::new((*TOY).clone()), &mut rng).unwrap();
        let ternary =
            SecretKey::new(Some(seed), Arc::new((*TOY_TERNARY).clone()), &mut rng).unwrap();
        assert_ne!(
            gaussian.public.verifying.encode(),
            ternary.public.verifying.encode()
        );
        assert_ne!(gaussian.prf_key, ternary.prf_key);
        assert_ne!(gaussian.state_mac_key, ternary.state_mac_key);
        assert_ne!(gaussian.inner.prf_key(), ternary.inner.prf_key());
        assert_ne!(
            InnerPublicKey::from(&gaussian.inner).a(),
            InnerPublicKey::from(&ternary.inner).a()
        );
        let x = Element::hash(b"x");
        let handles = |key: &SecretKey| (0..8).map(|i| key.handle(&x, i)).collect::<Vec<_>>();
        assert_ne!(handles(&gaussian), handles(&ternary));
        assert_eq!(gaussian.to_bytes()[64..], ternary.to_bytes()[64..]);
    }

    /// The FIPS 204 lengths agree with the encodings the `ml-dsa` crate produces, and signing
    /// is deterministic.
    #[test]
    fn ml_dsa_65_lengths_and_determinism() {
        let key = SecretKey::new(
            Some(b"kln/test/adaptive-lengths, 32 bytes"),
            Arc::new((*TOY).clone()),
            &mut StdRng::seed_from_u64(0),
        )
        .unwrap();
        let x = Element::hash(b"x");
        let handle = key.handle(&x, 0);
        let signature = key.sign(&x, &handle).unwrap();
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        assert_eq!(signature, key.sign(&x, &handle).unwrap());
        assert_eq!(key.public.verifying.encode().len(), VERIFYING_KEY_BYTES);
        assert!(key.public.signs(&x, &handle, &signature));
        assert!(!key.public.signs(&x, &key.handle(&x, 1), &signature));
        assert_ne!(key.handle(&x, 0), key.handle(&Element::hash(b"y"), 0));
    }
}
