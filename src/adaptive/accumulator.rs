// SPDX-License-Identifier: MIT OR Apache-2.0
//! Elements of the domain `V` and the accumulator value of Construction 4.2, `Add` and
//! `Delete`.

use super::{key::SecretKey, state::ManagerState};
use crate::{
    accumulator::{Accumulator as InnerAccumulator, Coefficient},
    error::{Error, Result},
    params::Params,
    sample::{DomainLabel, hash_parts},
};
use rand_core::CryptoRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shake::digest::XofReader;
use std::sync::Arc;

/// Label of [`Element::hash`].
const LABEL_HASH: &[u8] = b"kln/adaptive/element/hash";

/// An element of the domain `V = {0, 1}^256` of Construction 4.2, as 32 bytes.
///
/// Unlike the base [`crate::Element`] it does not depend on the parameter set: the inner
/// accumulator only ever sees handles. Serialized as its bytes: raw in binary formats, hex in
/// human-readable ones.
///
/// **Public.** The manager adds and deletes elements by value, and the update messages never
/// name them (they name handles), but the element itself is not hidden by this crate: it is
/// `Copy` and is not wiped. The handle that stands for it in the inner accumulator is
/// holder-private and lives in the [`super::MembershipWitness`].
///
/// # Examples
///
/// ```
/// use kln_accumulator::adaptive::Element;
/// use rand::{SeedableRng, rngs::StdRng};
///
/// let x = Element::hash(b"credential 42");
/// assert_eq!(x.to_bytes().len(), Element::BYTES);
/// assert_eq!(Element::try_from(&x.to_bytes()[..])?, x);
/// assert_eq!(Element::from(x.to_bytes()), x);
/// assert!(Element::try_from(&[0u8; 31][..]).is_err());
/// let _random = Element::random(&mut StdRng::seed_from_u64(0));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::From, derive_more::Into,
)]
pub struct Element([u8; Element::BYTES]);

impl Element {
    /// The length of an element, 32 bytes; see the type's example.
    pub const BYTES: usize = 32;

    /// The element whose bytes are SHAKE256 of `d` under a fixed label. Unlike the base
    /// [`crate::Element::hash`] it needs no parameter set, and with 256 bits distinct inputs
    /// do not collide in practice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let x = Element::hash(b"credential 42");
    /// assert_eq!(x, Element::hash(b"credential 42"));
    /// assert_ne!(x, Element::hash(b"credential 43"));
    /// // The adaptive accumulator takes this type; the base `kln_accumulator::Element` does not fit.
    /// let (_acc, state) = Accumulator::with_elements(&key, &[x])?;
    /// assert!(state.record(&x).is_some());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn hash(d: &[u8]) -> Self {
        let mut bytes = [0u8; Self::BYTES];
        hash_parts(DomainLabel::from(LABEL_HASH), &[d]).read(&mut bytes);
        Self(bytes)
    }

    /// A uniformly random element, 32 bytes of `rng`; see the type's example.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; Self::BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The 32 bytes; see the type's example.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        (*self).into()
    }

    /// The 32 bytes, borrowed.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Refuses any length other than 32 bytes with [`Error::InvalidElement`].
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Error, adaptive::Element};
///
/// let id = [7u8; Element::BYTES];
/// assert_eq!(Element::try_from(&id[..])?, Element::from(id));
/// // Misuse: the base variant's one-byte toy element is not an adaptive element.
/// assert_eq!(Element::try_from(&[7u8][..]), Err(Error::InvalidElement));
/// # Ok::<(), Error>(())
/// ```
impl TryFrom<&[u8]> for Element {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        <[u8; Self::BYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidElement)
    }
}

impl Serialize for Element {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Element {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let mut bytes = [0u8; Self::BYTES];
        let _ = serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        Ok(Self(bytes))
    }
}

/// The accumulator value of Construction 4.2, which is the value `c ∈ R_q^n` of the inner
/// accumulator of handles (`Gen` step 5, `A₀ := Ã₀`).
///
/// Additions never change it; deleting `x` deletes its handle from the inner accumulator. Like
/// the inner value it is bound to its parameter set, which [`Accumulator::validate`] compares.
/// Encoded and serialized as the inner value. **Public.**
///
/// # Examples
///
/// ```
/// # use kln_accumulator::Params;
/// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let mut acc = Accumulator::new(&key);
/// # let mut state = ManagerState::new(&key);
/// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
/// acc.validate(key.params())?;
/// let bytes = acc.to_bytes();
/// assert_eq!(Accumulator::try_from(bytes.as_slice())?, acc);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, derive_more::From, derive_more::Into,
)]
#[serde(transparent)]
pub struct Accumulator(InnerAccumulator);

impl Accumulator {
    /// `Gen` step 5: the genesis value of the one accumulator `key` keeps, which is the genesis
    /// value of the inner key ([`InnerAccumulator::new`]). Every keyed operation starts from
    /// it, through [`ManagerState::new`] or [`Accumulator::with_elements`].
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::adaptive::{Accumulator, ManagerState, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
    /// let acc = Accumulator::new(&key);
    /// assert_eq!(acc, Accumulator::new(&key));
    /// assert_eq!(ManagerState::new(&key).inner().current(), &acc.clone().into());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn new(key: &SecretKey) -> Self {
        Self(InnerAccumulator::new(key.inner()))
    }

    /// A uniform value in `R_q^n`: a public value for tests. No keyed operation accepts it,
    /// since every state starts from the key's genesis value ([`Accumulator::new`]). See the
    /// type's example.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, params: &Arc<Params>) -> Self {
        Self(InnerAccumulator::random(rng, params))
    }

    /// The key's accumulator holding `m`: the genesis value ([`Accumulator::new`]) and a
    /// [`ManagerState`] in which every element of `m` is added.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// let (acc, state) = Accumulator::with_elements(&key, &[x, y])?;
    /// assert!(state.record(&x).is_some());
    /// acc.validate(key.params())?;
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
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// let unchanged = acc.add_elements(&key, &[x, y], &mut state)?;
    /// assert_eq!(unchanged, acc);
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
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// acc.add_elements_assign(&key, &[x, y], &mut state)?;
    /// assert!(state.record(&y).is_some());
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

    /// `Add` (Construction 4.2): derives a fresh handle for `value`, adds it to the inner
    /// accumulator and records `(Add, i)`; the value is returned unchanged. Fails with
    /// [`Error::ElementAlreadyAdded`] when `value` is present and with
    /// [`Error::HandleSpaceExhausted`] once all `2^ℓ` handles were used. The witness is issued
    /// separately by [`super::MembershipWitness::new`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidStateTag`], [`Error::ParameterMismatch`], [`Error::AccumulatorMismatch`],
    /// [`Error::ElementAlreadyAdded`] and [`Error::HandleSpaceExhausted`], as
    /// [`Accumulator::update_assign`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
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
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
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

    /// `Delete` (Construction 4.2): deletes the handle of `value` from the inner accumulator and
    /// records `(Del, i + 1)`. Fails with [`Error::ElementNotPresent`] when `value` is not
    /// present and with [`Error::DeletionBoundReached`] once `γ` deletions were made.
    ///
    /// The paper's `Delete` takes the witness and aborts when its handle is not `F_k(x, i)`;
    /// the handle is recomputed from `k` here, so no witness is taken, as in the base.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error nothing changes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// acc.add_assign(&key, &y, &mut state)?;
    /// let mut removed = acc.remove(&key, &y, &mut state)?;
    /// assert_ne!(removed, acc);
    /// // Unlike the base scheme, y may be added again, to the current value; it gets a new
    /// // handle.
    /// removed.add_assign(&key, &y, &mut state)?;
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
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// acc.add_assign(&key, &y, &mut state)?;
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// assert_eq!(acc.remove_assign(&key, &y, &mut state), Err(kln_accumulator::Error::ElementNotPresent));
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

    /// `Delete` for every element of `deletions`, in order.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error nothing is deleted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// acc.add_elements_assign(&key, &[x, y], &mut state)?;
    /// let removed = acc.remove_elements(&key, &[x, y], &mut state)?;
    /// assert_ne!(removed, acc);
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
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// acc.add_elements_assign(&key, &[x, y], &mut state)?;
    /// acc.remove_elements_assign(&key, &[x, y], &mut state)?;
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
    /// `deletions`, in order. Returns the new value and the update messages, one per deletion;
    /// each names the deleted handle.
    ///
    /// # Errors
    ///
    /// As [`Accumulator::update_assign`]; on an error neither the value nor `state` changes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// acc.add_assign(&key, &y, &mut state)?;
    /// let (new_acc, coefficients) = acc.update(&key, &[x, z], &[y], &mut state)?;
    /// assert_ne!(new_acc, acc);
    /// // The message names y's handle, not y.
    /// assert_eq!(coefficients.len(), 1);
    /// assert_eq!(coefficients[0].element().to_bytes().len(), 1); // ℓ = 8 bits at the toy set
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
    /// the current value of the inner state ([`crate::ManagerState::current`]), else
    /// [`Error::AccumulatorMismatch`]; on success the state records the new value and is tagged
    /// again. Every other adding and removing method of [`Accumulator`] goes through this one.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidStateTag`] when `state` was altered or tagged under another key;
    /// - [`Error::ParameterMismatch`] when the value belongs to another set than `key`;
    /// - [`Error::AccumulatorMismatch`] when the value is not the state's current one: an
    ///   unrelated value, or an earlier value of the same accumulator;
    /// - [`Error::ElementAlreadyAdded`] for an addition that is present or repeats;
    /// - [`Error::HandleSpaceExhausted`] once all `2^ℓ` handles were used;
    /// - [`Error::DeletionBoundReached`] once the deletions would exceed `γ`;
    /// - [`Error::ElementNotPresent`] for a deletion of an element that is not present after the
    ///   additions, or that repeats.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let mut acc = Accumulator::new(&key);
    /// # let mut state = ManagerState::new(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// let messages = acc.update_assign(&key, &[x, y], &[x], &mut state)?;
    /// assert_eq!(messages.len(), 1);
    /// let before = acc.clone();
    /// assert!(acc.update_assign(&key, &[z], &[z, z], &mut state).is_err());
    /// assert_eq!(acc, before);
    /// assert!(state.record(&z).is_none());
    /// // An earlier value of the same accumulator is refused, and nothing changes.
    /// let mut stale = Accumulator::new(&key);
    /// let kept = state.clone();
    /// assert_eq!(
    ///     stale.update_assign(&key, &[z], &[y], &mut state),
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
        state.update(key, &mut self.0, additions, deletions)
    }

    /// The encoding of the inner value, [`InnerAccumulator::to_bytes`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// let acc = Accumulator::new(&key);
    /// let published = acc.to_bytes();
    /// assert_eq!(published.len(), 544); // the inner value's encoding at the toy set
    /// assert_eq!(Accumulator::from_bytes(key.params(), &published)?, acc);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// Decodes [`Accumulator::to_bytes`] against `params`, the set the caller expects, as
    /// [`InnerAccumulator::from_bytes`] does: no set is built from the input, and the result
    /// shares `params`. Use this for bytes from an untrusted source.
    ///
    /// # Errors
    ///
    /// As [`InnerAccumulator::from_bytes`]: [`Error::ParameterMismatch`] when the bytes name
    /// another set.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params, adaptive::Accumulator};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let params = Arc::new(Params::toy()?);
    /// let bytes = Accumulator::random(&mut StdRng::seed_from_u64(0), &params).to_bytes();
    /// let acc = Accumulator::from_bytes(&params, &bytes)?;
    /// assert_eq!(acc.to_bytes(), bytes);
    /// // The bytes of a value at another set are refused.
    /// let other = Arc::new(Params::succinct_toy()?);
    /// assert_eq!(Accumulator::from_bytes(&other, &bytes).map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_bytes(params: &Arc<Params>, bytes: &[u8]) -> Result<Self> {
        InnerAccumulator::from_bytes(params, bytes).map(Self)
    }

    /// Checks the inner value with [`InnerAccumulator::validate`]: fails with
    /// [`Error::ParameterMismatch`] unless it belongs to `params`. See the type's example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn validate(&self, params: &Params) -> Result<()> {
        self.0.validate(params)
    }

    /// The inner value.
    pub(super) fn inner(&self) -> &InnerAccumulator {
        &self.0
    }
}

/// Decodes [`Accumulator::to_bytes`] as `TryFrom<&[u8]> for InnerAccumulator` does. It builds
/// the set the bytes name, so for bytes from an untrusted source use [`Accumulator::from_bytes`]
/// with the set you expect.
impl TryFrom<&[u8]> for Accumulator {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        InnerAccumulator::try_from(bytes).map(Self)
    }
}

/// The encoding of [`Accumulator::to_bytes`], which calls this.
impl From<&Accumulator> for Vec<u8> {
    fn from(value: &Accumulator) -> Self {
        value.0.to_bytes()
    }
}
