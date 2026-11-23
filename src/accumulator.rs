// SPDX-License-Identifier: MIT OR Apache-2.0
//! Accumulator elements, values and update messages of Construction 4.1: `Gen` step 2 (the
//! initial value `c₀`), `Add` (free: the value never changes) and `Delete`.
//!
//! The manager holds the [`SecretKey`] and the [`ManagerState`] and runs every method here.
//! Adding is free: the value `c` does not change, the element is only recorded in the state,
//! and its witness is issued by [`crate::MembershipWitness::new`]. Deleting `y` sets
//! `c' = c + B_{1y}·G⁻¹(u)` and publishes a [`Coefficient`] naming `y`, from which every other
//! holder updates its witness. An element is added at most once over the life of an
//! accumulator (Remark 4.2): re-adding it, present or deleted, is
//! [`Error::ElementAlreadyAdded`]; the [`crate::adaptive`] variant lifts that restriction.
//!
//! Every adding and removing method goes through [`Accumulator::update_assign`], which checks
//! the state's tag, checks that the value is the state's current one, checks every operation
//! before applying any, and so is atomic.
//!
//! ```
//! use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
//! use kln_accumulator::{PublicKey, SecretKey};
//! use rand::{SeedableRng, rngs::StdRng};
//! use std::sync::Arc;
//!
//! let mut rng = StdRng::seed_from_u64(0);
//! let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
//! let pk = PublicKey::from(&key);
//! let element = |name: &[u8]| Element::hash(name, key.params());
//! let (x, y) = (element(b"x"), element(b"y"));
//!
//! let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
//! let wx = MembershipWitness::new(&x, &acc, &key, &state)?;
//!
//! // Delete y: the value moves and one update message is published.
//! let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
//! assert_eq!(coefficients.len(), 1);
//! assert_eq!(coefficients[0].element(), &y);
//!
//! // x's holder updates from the published deletion; y cannot be added again.
//! let wx = wx.batch_update(&x, &[], &[y.clone()], &coefficients, &pk)?;
//! assert!(wx.verify(&x, &pk, &acc));
//! assert!(acc.add(&key, &y, &mut state).is_err());
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

use crate::{
    error::{Error, Result, check_dimension},
    eval::BitString,
    key::SecretKey,
    packing::{self, Packed, Uniform, packed_impls},
    params::Params,
    sample::{DomainLabel, Seed, UniformSampler, hash_parts},
    state::ManagerState,
    vector::PolyVec,
};
use rand_core::CryptoRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shake::digest::XofReader;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Label of [`Element::hash`].
const LABEL_HASH: &[u8] = b"kln/element/hash";

/// Label of the uniform draw in [`Accumulator::random`].
const LABEL_INITIAL: &[u8] = b"kln/accumulator/initial";

/// An element of the domain `M = {0, 1}^ℓ`, stored as `⌈ℓ/8⌉` bytes: bit `i` is bit `i mod 8`
/// of byte `⌊i/8⌋`, and the bits from `ℓ` up are zero.
///
/// It carries no parameters; [`Element::validate`] checks it against a set, and every
/// operation does so before using it. Serialized as its bytes: raw in binary formats, hex in
/// human-readable ones. `TryFrom<&[u8]>` takes bytes as they are (only the empty string is
/// refused there) and leaves the length and high bits to [`Element::validate`].
///
/// **Public** to the manager, who records it, and to everyone once it is deleted, since the
/// update message names it. In a membership proof it is the prover's hidden input, so the
/// crate's copies are overwritten when dropped ([`ZeroizeOnDrop`]) and its hex form is built and
/// parsed in buffers wiped on drop; [`Element::to_bytes`] returns a plain copy, and
/// [`fmt::Debug`](core::fmt::Debug) prints the bytes.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Element, Params};
/// use rand::{SeedableRng, rngs::StdRng};
///
/// let params = Params::toy()?; // ℓ = 8: one byte
/// let x = Element::hash(b"revocation handle 17", &params);
/// assert_eq!(x.to_bytes().len(), 1);
/// x.validate(&params)?;
/// assert_eq!(x.to_bits(&params)?.as_slice().len(), 8);
/// let random = Element::random(&mut StdRng::seed_from_u64(0), &params);
/// random.validate(&params)?;
/// assert_eq!(Element::try_from(x.to_bytes().as_slice())?, x);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Element(Vec<u8>);

impl Element {
    /// The element whose bits are SHAKE256 of `d` under a fixed label, truncated to `ℓ` bits.
    /// With `ℓ` bits there are only `2^ℓ` elements (256 at the toy set), so distinct inputs
    /// collide after about `2^{ℓ/2}` of them.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Element, Params};
    /// use std::collections::BTreeSet;
    ///
    /// let params = Params::toy()?;
    /// let x = Element::hash(b"member 17", &params);
    /// assert_eq!(x, Element::hash(b"member 17", &params));
    /// x.validate(&params)?;
    /// // Misuse: hashing identifiers at a small set. 64 identifiers do not give 64 elements.
    /// let hashed: BTreeSet<Element> =
    ///     (0u32..64).map(|i| Element::hash(&i.to_le_bytes(), &params)).collect();
    /// assert!(hashed.len() < 64);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn hash(d: &[u8], params: &Params) -> Self {
        Self::derive(DomainLabel::from(LABEL_HASH), &[d], params)
    }

    /// The element whose bits are [`hash_parts`] of `parts` under `label`, truncated to `ℓ`
    /// bits; with a secret key among the parts it is a PRF.
    pub(crate) fn derive(label: DomainLabel<'_>, parts: &[&[u8]], params: &Params) -> Self {
        let mut bytes = vec![0u8; Self::len(params)];
        hash_parts(label, parts).read(&mut bytes);
        Self::truncated(bytes, params)
    }

    /// A uniformly random element of `{0, 1}^ℓ`, from `⌈ℓ/8⌉` bytes of `rng`; see the type's
    /// example.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, params: &Params) -> Self {
        let mut bytes = vec![0u8; Self::len(params)];
        rng.fill_bytes(&mut bytes);
        Self::truncated(bytes, params)
    }

    /// The `⌈ℓ/8⌉` bytes, as a plain copy that is not wiped; see the type's example.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// The `⌈ℓ/8⌉` bytes, borrowed.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Checks that the element has `⌈ℓ/8⌉` bytes and no bit set at or above position `ℓ`; see
    /// the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidElement`] otherwise.
    pub fn validate(&self, params: &Params) -> Result<()> {
        let used = params.spec().element_bits % 8;
        let high_bits = match self.0.last() {
            Some(last) if used != 0 => last >> used,
            _ => 0,
        };
        if self.0.len() == Self::len(params) && high_bits == 0 {
            Ok(())
        } else {
            Err(Error::InvalidElement)
        }
    }

    /// The bits `x_0, …, x_{ℓ−1}` the element denotes, after [`Element::validate`]: bit `i` is
    /// bit `i mod 8` of byte `⌊i/8⌋`. See [`BitString`]'s example.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidElement`] as [`Element::validate`].
    pub fn to_bits(&self, params: &Params) -> Result<BitString> {
        self.validate(params)?;
        Ok(BitString::from(
            (0..params.spec().element_bits as usize)
                .map(|i| self.0[i / 8] >> (i % 8) & 1 == 1)
                .collect::<Vec<_>>(),
        ))
    }

    /// `⌈ℓ/8⌉`.
    fn len(params: &Params) -> usize {
        (params.spec().element_bits as usize).div_ceil(8)
    }

    /// Clears the bits of `bytes` from `ℓ` up.
    fn truncated(mut bytes: Vec<u8>, params: &Params) -> Self {
        let used = params.spec().element_bits % 8;
        if let (Some(last), true) = (bytes.last_mut(), used != 0) {
            *last &= (1u8 << used) - 1;
        }
        Self(bytes)
    }
}

/// Overwrites the bytes.
impl Zeroize for Element {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Element {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Element {}

/// Takes the bytes as they are; only the empty string is refused here, since `ℓ ≥ 1`. The
/// length and the high bits are checked by [`Element::validate`].
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Element, Error, Params};
///
/// let params = Params::toy()?; // ℓ = 8: one byte
/// let x = Element::try_from(&[17u8][..])?;
/// x.validate(&params)?;
/// assert_eq!(Element::try_from(&[][..]), Err(Error::InvalidElement));
/// // Misuse: the 128-bit set's four-byte form at the toy set decodes, but is not an element of it.
/// let wide = Element::try_from(&17u32.to_le_bytes()[..])?;
/// assert_eq!(wide.validate(&params), Err(Error::InvalidElement));
/// # Ok::<(), Error>(())
/// ```
impl TryFrom<&[u8]> for Element {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            Err(Error::InvalidElement)
        } else {
            Ok(Self(bytes.to_vec()))
        }
    }
}

impl Serialize for Element {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        crate::secret_hex::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Element {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let bytes = crate::secret_hex::deserialize(deserializer)?;
        Self::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// The update message of one deletion, the paper's `upmsg = (Del, y)`: it names the deleted
/// element `y`. Additions publish nothing, since they leave the accumulator value unchanged.
/// **Public**: the manager publishes it to every holder. It keeps the vb20 name of the pairing
/// accumulator's update coefficient; `From<Element>` and `From<Coefficient> for Element`
/// convert, and `TryFrom<&[u8]>` decodes as the element does.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Coefficient, Element, Params};
///
/// let params = Params::toy()?;
/// let y = Element::hash(b"y", &params);
/// let message = Coefficient::from(y.clone());
/// assert_eq!(message.element(), &y);
/// assert_eq!(message.to_bytes(), y.to_bytes());
/// message.validate(&params)?;
/// assert_eq!(Element::from(message), y);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, derive_more::From, derive_more::Into,
)]
#[serde(transparent)]
pub struct Coefficient(Element);

impl Coefficient {
    /// The deleted element; see the type's example.
    #[must_use]
    pub fn element(&self) -> &Element {
        &self.0
    }

    /// The bytes of the deleted element; see the type's example.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// Checks the deleted element with [`Element::validate`]; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidElement`] as [`Element::validate`].
    pub fn validate(&self, params: &Params) -> Result<()> {
        self.0.validate(params)
    }
}

/// Decodes the deleted element as `TryFrom<&[u8]> for Element` does.
impl TryFrom<&[u8]> for Coefficient {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Element::try_from(bytes).map(Self)
    }
}

/// The accumulator value `c ∈ R_q^n` of Construction 4.1.
///
/// Additions never change it: [`Accumulator::add`] only registers the element in the
/// [`ManagerState`]. Deleting `y` sets `c' = c + B_{1y}·G⁻¹(u)`. It is bound to its parameter
/// set, which fixes its shape and its encoding; [`Accumulator::validate`] checks that the set is
/// the one an operation uses. Encoded as the set and the `n·d` coefficients in `⌈log₂ q⌉` bits
/// each (Table 2): 544 bytes at the toy set, 51,264 bytes (50.06 KiB, Table 2: 50 KB) at the
/// 128-bit set.
///
/// **Public**: the value is published after every deletion. The method names and argument
/// order are those of the vb20 pairing accumulator, with the [`ManagerState`] appended (see
/// the book's chapter "Correspondence with the vb20 pairing accumulator").
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Accumulator, Params};
/// use kln_accumulator::lattice::PolyVec;
/// use rand::{SeedableRng, rngs::StdRng};
/// use std::sync::Arc;
///
/// let params = Arc::new(Params::toy()?);
/// let acc = Accumulator::random(&mut StdRng::seed_from_u64(0), &params);
/// acc.validate(&params)?;
/// let bytes = acc.to_bytes();
/// assert_eq!(bytes.len(), 64 + 64 * 60 / 8);
/// assert_eq!(Accumulator::try_from(bytes.as_slice())?, acc);
/// let value = PolyVec::from(acc.clone());
/// assert_eq!(Accumulator::from_vector(value, &params)?, acc);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, derive_more::Into)]
pub struct Accumulator {
    #[into(skip)]
    params: Arc<Params>,
    value: PolyVec,
}

impl Accumulator {
    /// `Gen` step 2: the genesis value `c₀` of the one accumulator `key` keeps, uniform in
    /// `R_q^n` and derived from the key's seed and parameter set. Every keyed operation starts
    /// from it, through [`ManagerState::new`] or [`Accumulator::with_elements`]; the same key
    /// always gives the same value.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Accumulator, ManagerState, Params, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
    /// let acc = Accumulator::new(&key);
    /// assert_eq!(acc, Accumulator::new(&key));
    /// assert_eq!(ManagerState::new(&key).current(), &acc);
    /// acc.validate(key.params())?;
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn new(key: &SecretKey) -> Self {
        key.genesis().clone()
    }

    /// A uniform value in `R_q^n` from 32 bytes of `rng`: a public value for tests and for
    /// statements that need some value of a set. No keyed operation accepts it, since every
    /// state starts from the key's genesis value ([`Accumulator::new`]). See the type's
    /// example.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, params: &Arc<Params>) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self {
            params: Arc::clone(params),
            value: UniformSampler::new(&Seed::from(seed), DomainLabel::from(LABEL_INITIAL))
                .vector(params.spec().n, params.ring()),
        }
    }

    /// The value `value ∈ R_q^n` at `params`. Fails with [`Error::DimensionMismatch`] unless it
    /// has `n` entries of degree `d`, and with [`Error::CoefficientOutOfRange`] unless every
    /// coefficient is below `q`. See the type's example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn from_vector(value: PolyVec, params: &Arc<Params>) -> Result<Self> {
        let n = params.spec().n;
        check_dimension(n, value.len())?;
        value.validate(params.ring())?;
        Ok(Self {
            params: Arc::clone(params),
            value,
        })
    }

    /// The key's accumulator holding `m`: the genesis value ([`Accumulator::new`]) and a
    /// [`ManagerState`] in which every element of `m` is added. The value is the genesis value.
    /// The book's chapter "Witnesses and updates" uses it in a full lifecycle.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]: [`Error::InvalidElement`] or
    /// [`Error::ElementAlreadyAdded`] (for a repeat within `m`).
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y) = (element(b"x"), element(b"y"));
    /// let (acc, state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
    /// assert_eq!(acc, Accumulator::new(&key)); // additions leave the value unchanged
    /// assert_eq!(state.current(), &acc);
    /// assert!(state.record(&x).is_some() && state.record(&y).is_some());
    /// // A repeat within the list refuses the whole call.
    /// assert!(Accumulator::with_elements(&key, &[x.clone(), x]).is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn with_elements(key: &SecretKey, m: &[Element]) -> Result<(Self, ManagerState)> {
        let mut accumulator = Self::new(key);
        let mut state = ManagerState::new(key);
        accumulator.add_elements_assign(key, m, &mut state)?;
        Ok((accumulator, state))
    }

    /// `Add` for every element of `m`, in order; the value is returned unchanged.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error nothing is added.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// let unchanged = acc.add_elements(&key, &[x.clone(), y.clone()], &mut state)?;
    /// assert_eq!(unchanged, acc);
    /// assert!(state.record(&x).is_some() && state.record(&y).is_some());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn add_elements(
        &self,
        key: &SecretKey,
        m: &[Element],
        state: &mut ManagerState,
    ) -> Result<Self> {
        self.update(key, m, &[], state).map(|(value, _)| value)
    }

    /// `Add` for every element of `m`, in order.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error nothing is added.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// acc.add_elements_assign(&key, &[x.clone(), y.clone()], &mut state)?;
    /// // A repeat anywhere in the batch refuses the whole batch.
    /// assert!(acc.add_elements_assign(&key, &[z.clone(), x.clone()], &mut state).is_err());
    /// assert!(state.record(&z).is_none());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn add_elements_assign(
        &mut self,
        key: &SecretKey,
        m: &[Element],
        state: &mut ManagerState,
    ) -> Result<()> {
        self.update_assign(key, m, &[], state).map(drop)
    }

    /// `Add` (Construction 4.1): registers `value` in `state` at the current deletion epoch and
    /// returns the value unchanged. Fails with [`Error::ElementAlreadyAdded`] when `value` was
    /// ever added, present or deleted (Remark 4.2); the witness is issued separately by
    /// [`crate::MembershipWitness::new`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidStateTag`], [`Error::ParameterMismatch`], [`Error::AccumulatorMismatch`],
    /// [`Error::InvalidElement`] and [`Error::ElementAlreadyAdded`], as
    /// [`Accumulator::update_assign`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// let same = acc.add(&key, &x, &mut state)?;
    /// assert_eq!(same, acc);
    /// assert_eq!(acc.add(&key, &x, &mut state), Err(kln_accumulator::Error::ElementAlreadyAdded));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn add(&self, key: &SecretKey, value: &Element, state: &mut ManagerState) -> Result<Self> {
        self.add_elements(key, core::slice::from_ref(value), state)
    }

    /// `Add`, in place; see [`Accumulator::add`].
    ///
    /// # Errors
    ///
    /// As [`Accumulator::add`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// acc.add_assign(&key, &x, &mut state)?;
    /// assert!(state.record(&x).is_some());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn add_assign(
        &mut self,
        key: &SecretKey,
        value: &Element,
        state: &mut ManagerState,
    ) -> Result<()> {
        self.add_elements_assign(key, core::slice::from_ref(value), state)
    }

    /// `Delete` (Construction 4.1): `c' = c + B_{1y}·G⁻¹(u)` for `y = value`. Fails with
    /// [`Error::DeletionBoundReached`] once `γ` deletions were made and with
    /// [`Error::ElementNotPresent`] when `value` is not in the accumulator.
    ///
    /// Erratum (Construction 4.1, p. 17): the paper's `Delete` also takes the witness `w_x` and
    /// never uses it, so this does not take one.
    ///
    /// The cost is one evaluation of `B_{1y}·G⁻¹(u)`: `ℓ − 1` gadget decompositions and
    /// `ℓ − 1` matrix products of size `n × m'` by `m' × m'`. About 0.75 s at the 128-bit set.
    /// Use [`Accumulator::update`] to get the update message.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error nothing changes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// acc.add_elements_assign(&key, &[x.clone(), y.clone()], &mut state)?;
    /// let removed = acc.remove(&key, &y, &mut state)?;
    /// assert_ne!(removed, acc);
    /// assert_eq!(state.counter(), 1);
    /// // The state now belongs to the returned value; the old one is refused.
    /// assert_eq!(acc.remove(&key, &z, &mut state), Err(kln_accumulator::Error::AccumulatorMismatch));
    /// assert_eq!(removed.remove(&key, &z, &mut state), Err(kln_accumulator::Error::ElementNotPresent));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn remove(
        &self,
        key: &SecretKey,
        value: &Element,
        state: &mut ManagerState,
    ) -> Result<Self> {
        self.remove_elements(key, core::slice::from_ref(value), state)
    }

    /// `Delete`, in place; see [`Accumulator::remove`].
    ///
    /// # Errors
    ///
    /// As [`Accumulator::remove`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// acc.add_assign(&key, &y, &mut state)?;
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// assert_eq!(state.counter(), 1);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn remove_assign(
        &mut self,
        key: &SecretKey,
        value: &Element,
        state: &mut ManagerState,
    ) -> Result<()> {
        self.remove_elements_assign(key, core::slice::from_ref(value), state)
    }

    /// `Delete` for every element of `deletions`, in order; the `j`-th deletion records epoch
    /// `ctr + j`.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error nothing is deleted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// acc.add_elements_assign(&key, &[x.clone(), y.clone()], &mut state)?;
    /// let removed = acc.remove_elements(&key, &[x.clone(), y.clone()], &mut state)?;
    /// assert_ne!(removed, acc);
    /// assert_eq!(state.counter(), 2);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn remove_elements(
        &self,
        key: &SecretKey,
        deletions: &[Element],
        state: &mut ManagerState,
    ) -> Result<Self> {
        self.update(key, &[], deletions, state)
            .map(|(value, _)| value)
    }

    /// `Delete` for every element of `deletions`, in order, in place.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error nothing is deleted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// acc.add_elements_assign(&key, &[x.clone(), y.clone()], &mut state)?;
    /// // Deleting an element twice in one batch refuses the batch.
    /// assert!(acc.remove_elements_assign(&key, &[y.clone(), y.clone()], &mut state).is_err());
    /// acc.remove_elements_assign(&key, &[y.clone()], &mut state)?;
    /// assert_eq!(state.counter(), 1);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn remove_elements_assign(
        &mut self,
        key: &SecretKey,
        deletions: &[Element],
        state: &mut ManagerState,
    ) -> Result<()> {
        self.update_assign(key, &[], deletions, state).map(drop)
    }

    /// `Add` for every element of `additions`, then `Delete` for every element of
    /// `deletions`, in order. Returns the new value and the update messages, one per deletion,
    /// in order; holders pass them to [`crate::MembershipWitness::batch_update`] with the same
    /// additions and deletions.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error neither the value nor `state` changes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// acc.add_assign(&key, &y, &mut state)?;
    /// let (new_acc, coefficients) = acc.update(&key, &[x.clone(), z.clone()], &[y.clone()], &mut state)?;
    /// assert_ne!(new_acc, acc);
    /// assert_eq!(coefficients.len(), 1);
    /// assert_eq!(coefficients[0].element(), &y);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn update(
        &self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
        state: &mut ManagerState,
    ) -> Result<(Self, Vec<Coefficient>)> {
        let mut accumulator = self.clone();
        let coefficients = accumulator.update_assign(key, additions, deletions, state)?;
        Ok((accumulator, coefficients))
    }

    /// [`Accumulator::update`] in place. Every operation is checked before any takes effect: on
    /// an error neither the value nor `state` changes. Before anything else, `state` must carry
    /// a tag that verifies under `key`, else [`Error::InvalidStateTag`], and the value must be
    /// the state's current one ([`ManagerState::current`]), else
    /// [`Error::AccumulatorMismatch`]; on success the state records the new value and is tagged
    /// again. Every other adding and removing method of [`Accumulator`] goes through this one.
    ///
    /// Each deletion costs one `B_{1y}·G⁻¹(u)` (see [`Accumulator::remove`]); re-tagging hashes
    /// the whole state, so its cost grows with the number of elements ever added.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidStateTag`] when `state` was altered or tagged under another key;
    /// - [`Error::ParameterMismatch`] when the value belongs to another set than `key`;
    /// - [`Error::AccumulatorMismatch`] when the value is not the state's current one: an
    ///   unrelated value, or an earlier value of the same accumulator;
    /// - [`Error::InvalidElement`] for an element that is not an `ℓ`-bit string of the set;
    /// - [`Error::ElementAlreadyAdded`] for an addition that was ever added, or repeats;
    /// - [`Error::DeletionBoundReached`] once the deletions would exceed `γ`;
    /// - [`Error::ElementNotPresent`] for a deletion of an element that is not present after
    ///   the additions, or that repeats.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// let messages = acc.update_assign(&key, &[x.clone(), y.clone()], &[x.clone()], &mut state)?;
    /// assert_eq!(messages.len(), 1);
    /// assert_eq!(state.counter(), 1);
    /// // Atomic: z is not added when the deletion of the absent z fails.
    /// let before = acc.clone();
    /// assert!(acc.update_assign(&key, &[], &[z.clone()], &mut state).is_err());
    /// assert_eq!(acc, before);
    /// // Only the current value is accepted: an unrelated one is refused, and nothing changes.
    /// let mut unrelated = Accumulator::random(&mut rng, key.params());
    /// let kept = state.clone();
    /// assert_eq!(
    ///     unrelated.update_assign(&key, &[z.clone()], &[y.clone()], &mut state),
    ///     Err(kln_accumulator::Error::AccumulatorMismatch)
    /// );
    /// assert_eq!(state, kept);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn update_assign(
        &mut self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
        state: &mut ManagerState,
    ) -> Result<Vec<Coefficient>> {
        state.authenticate(key)?;
        let public = key.public();
        let params = public.params();
        let ring = params.ring();
        self.validate(params)?;
        state.check_current(self)?;
        state.check_update(additions, deletions, params)?;
        let offset = deletions
            .iter()
            .try_fold(PolyVec::zero(params.spec().n, ring), |sum, y| {
                sum.add(&public.deletion_offset(y)?, ring)
            })?;
        self.value = self.value.add(&offset, ring)?;
        state.apply_update(additions, deletions, self, key);
        Ok(deletions.iter().cloned().map(Coefficient).collect())
    }

    /// The encoding: the 64-byte [`crate::ParamsSpec`] encoding, then the `n·d` coefficients in
    /// `⌈log₂ q⌉` bits each, least significant bit first, the last byte padded with zero bits.
    /// `TryFrom<&[u8]>` decodes it, rebuilding the set, and fails with
    /// [`Error::InvalidEncodingLength`], [`Error::NonCanonicalEncoding`] or
    /// [`Error::CoefficientOutOfRange`] on a malformed input.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let acc = Accumulator::new(&key);
    /// let published = acc.to_bytes();
    /// assert_eq!(published.len(), 544); // 64 bytes of set, then 64·60 bits
    /// // A holder decodes against the set it expects, not the set the bytes name.
    /// assert_eq!(Accumulator::from_bytes(key.params(), &published)?, acc);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// Fails with [`Error::ParameterMismatch`] unless the value belongs to `params`. Its shape
    /// and range were checked against its set when it was made or decoded. See the type's
    /// example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn validate(&self, params: &Params) -> Result<()> {
        self.params.check_same(params)
    }

    /// The parameter set the value belongs to; see the type's example.
    #[must_use]
    pub fn params(&self) -> &Arc<Params> {
        &self.params
    }

    /// The value `c`.
    pub(crate) fn value(&self) -> &PolyVec {
        &self.value
    }

    /// Appends the packed coefficients of `c`.
    fn write_coefficients(&self, out: &mut Vec<u8>) {
        Uniform::new(self.params.ring()).write(self.value.as_slice(), out);
    }
}

/// Values are equal when they belong to the same set and have the same coefficients.
impl PartialEq for Accumulator {
    fn eq(&self, other: &Self) -> bool {
        self.params.spec() == other.params.spec() && self.value == other.value
    }
}

impl Eq for Accumulator {}

impl Packed for Accumulator {
    fn params(&self) -> &Arc<Params> {
        &self.params
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.write_coefficients(out);
        Ok(())
    }

    fn read_body(params: Arc<Params>, body: &[u8]) -> Result<Self> {
        let (value, rest) =
            Uniform::new(params.ring()).read(body, params.spec().n, params.ring().degree())?;
        packing::finish(Self::from_vector(value, &params)?, rest)
    }
}

packed_impls! {
    Accumulator,
    /// Decodes [`Accumulator::to_bytes`], rebuilding and validating the parameter set; the input
    /// must be consumed exactly.
    decode,
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Accumulator, Error, Params};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let params = Arc::new(Params::toy()?);
    /// let bytes = Accumulator::random(&mut StdRng::seed_from_u64(0), &params).to_bytes();
    /// let acc = Accumulator::from_bytes(&params, &bytes)?;
    /// assert!(Arc::ptr_eq(acc.params(), &params));
    /// // The bytes of a value at another set are refused.
    /// let other = Arc::new(Params::succinct_toy()?);
    /// assert_eq!(Accumulator::from_bytes(&other, &bytes).map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    from_bytes,
    /// Serialized as the parameter set and the packed coefficients of [`Accumulator::to_bytes`]
    /// (raw in binary formats, hex in human-readable ones).
    serialize
}

/// The `⌈ℓ/8⌉` bytes of the element, as a plain copy that is not wiped; [`Element::to_bytes`]
/// calls this.
impl From<&Element> for Vec<u8> {
    fn from(value: &Element) -> Self {
        value.0.clone()
    }
}

/// The encoding of [`Coefficient::to_bytes`], which calls this.
impl From<&Coefficient> for Vec<u8> {
    fn from(value: &Coefficient) -> Self {
        value.0.to_bytes()
    }
}

/// The encoding of [`Accumulator::to_bytes`], which calls this.
impl From<&Accumulator> for Vec<u8> {
    fn from(value: &Accumulator) -> Self {
        packing::to_bytes_with(value, Accumulator::write_coefficients)
    }
}

#[cfg(test)]
mod tests {
    use super::Element;
    use crate::{
        error::Error,
        params::{Params, ParamsSpec},
        test_util::TOY,
    };
    use rand::{SeedableRng, rngs::StdRng};

    fn with_bits(element_bits: u32) -> Params {
        Params::try_from(ParamsSpec {
            element_bits,
            ..ParamsSpec::TOY
        })
        .unwrap()
    }

    /// Hashing is deterministic, separates inputs, and yields exactly `ℓ` bits; the bits are read
    /// least significant first.
    #[test]
    fn elements_are_l_bit_strings() {
        assert_eq!(Element::hash(b"a", &TOY), Element::hash(b"a", &TOY));
        assert_ne!(Element::hash(b"a", &TOY), Element::hash(b"b", &TOY));
        for bits in [7, 8, 12] {
            let params = with_bits(bits);
            let mut rng = StdRng::seed_from_u64(u64::from(bits));
            for x in [
                Element::hash(b"x", &params),
                Element::random(&mut rng, &params),
            ] {
                assert!(x.validate(&params).is_ok());
                assert_eq!(x.to_bytes().len(), (bits as usize).div_ceil(8));
                assert_eq!(x.to_bits(&params).unwrap().as_slice().len(), bits as usize);
            }
        }
        let params = with_bits(12);
        let x = Element::try_from([0b0000_0101, 0b0000_1000].as_slice()).unwrap();
        let bits = x.to_bits(&params).unwrap();
        let set: Vec<usize> = (0..12).filter(|&i| bits.as_slice()[i]).collect();
        assert_eq!(set, [0, 2, 11]);
    }

    #[test]
    fn malformed_elements_are_refused() {
        let params = with_bits(12);
        let invalid = Err(Error::InvalidElement);
        assert_eq!(
            Element::try_from([].as_slice()).err(),
            Some(Error::InvalidElement)
        );
        let high = Element::try_from([0, 0b0001_0000].as_slice()).unwrap();
        assert_eq!(high.validate(&params), invalid);
        assert_eq!(high.to_bits(&params).err(), Some(Error::InvalidElement));
        let short = Element::try_from([0].as_slice()).unwrap();
        assert_eq!(short.validate(&params), invalid);
        assert!(short.validate(&TOY).is_ok());
    }
}
