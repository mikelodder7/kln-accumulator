// SPDX-License-Identifier: MIT OR Apache-2.0
//! The manager state `st = (k, ctr, c₀, D_X)` of Construction 4.1, without the PRF key `k`,
//! which lives in the [`crate::SecretKey`], and with a tag that binds it to that key.
//!
//! The paper's algorithms keep state between calls; the vb20 pairing accumulator this crate
//! mirrors does not. So every keyed operation takes a [`ManagerState`] as its last argument,
//! checks the state's tag under the key first, and tags it again after changing it.
//!
//! # The tag
//!
//! See the book's chapter "Manager state and its tag" for what it protects against and what not.

use crate::{
    accumulator::{Accumulator, Coefficient, Element},
    error::{Error, Result},
    key::SecretKey,
    params::Params,
    sample::{DomainLabel, Seed, hash_parts},
};
use core::fmt;
use ctutils::CtEq;
use num_enum::IntoPrimitive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::digest::XofReader;
use std::collections::{BTreeMap, BTreeSet};
use strum::{EnumCount, EnumIter};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Label of the tag of a [`ManagerState`].
const LABEL_TAG: &[u8] = b"kln/state/tag";

/// The operation recorded for an element, the paper's `Op ∈ {Add, Del}`. **Public.** See
/// [`Record`]'s example.
///
/// `From<Operation> for u8` (derived with `num_enum`) is the byte that encodes the operation in
/// a tagged dictionary: 0 for [`Operation::Add`], 1 for [`Operation::Del`]. Serde uses the
/// variant names.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, IntoPrimitive, EnumCount, EnumIter,
)]
#[repr(u8)]
pub enum Operation {
    /// The element was added and is in the accumulator; byte 0.
    Add = 0,
    /// The element was deleted; byte 1.
    Del = 1,
}

/// The entry `D_X[x] = (Op, i)` of the dictionary. **Public**, as part of the manager state.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Accumulator, Element, Operation, Params, Record, SecretKey};
/// use rand::{SeedableRng, rngs::StdRng};
/// use std::sync::Arc;
///
/// let mut rng = StdRng::seed_from_u64(0);
/// let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// let (x, y) = (Element::hash(b"x", key.params()), Element::hash(b"y", key.params()));
/// let (acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
/// let _ = acc.remove(&key, &y, &mut state)?;
/// // x was added before any deletion; y was the first deletion, so its epoch is 1.
/// assert_eq!(state.record(&x), Some(Record { operation: Operation::Add, epoch: 0 }));
/// assert_eq!(state.record(&y), Some(Record { operation: Operation::Del, epoch: 1 }));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// What last happened to the element.
    pub operation: Operation,
    /// For [`Operation::Add`], the deletion counter when the element was added; for
    /// [`Operation::Del`], the counter after its own deletion, so the `j`-th deletion records
    /// `j`. A record of the history only: witnesses do not depend on it, since
    /// [`crate::MembershipWitness::new`] samples every element for the genesis value.
    pub epoch: u64,
}

/// A 32-byte tag that binds a manager state to the secret key that keeps it. Equality is
/// constant time. Serialized raw in binary formats and as hex in human-readable ones.
///
/// A state's own tag is public, but the tag recomputed to check a state that was altered is a
/// forgery for it, so every tag is overwritten when dropped.
#[derive(Clone)]
pub(crate) struct StateTag([u8; StateTag::BYTES]);

/// Prints none of the tag.
impl fmt::Debug for StateTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateTag").finish_non_exhaustive()
    }
}

impl StateTag {
    /// The length of a tag.
    const BYTES: usize = 32;

    /// SHAKE256 keyed by prefix: the first 32 bytes of [`hash_parts`] of `mac_key` and then
    /// `parts`, under `label`.
    pub(crate) fn compute(label: DomainLabel<'_>, mac_key: &Seed, parts: &[&[u8]]) -> Self {
        let keyed: Vec<&[u8]> = core::iter::once(mac_key.as_bytes().as_slice())
            .chain(parts.iter().copied())
            .collect();
        let mut tag = [0u8; Self::BYTES];
        hash_parts(label, &keyed).read(&mut tag);
        Self(tag)
    }

    /// The tag bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }

    /// Fails with [`Error::InvalidStateTag`] unless the tag equals `expected`, compared in
    /// constant time.
    pub(crate) fn verify(&self, expected: &Self) -> Result<()> {
        if *self == *expected {
            Ok(())
        } else {
            Err(Error::InvalidStateTag)
        }
    }
}

impl Drop for StateTag {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for StateTag {}

impl PartialEq for StateTag {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for StateTag {}

impl Serialize for StateTag {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for StateTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let mut bytes = [0u8; Self::BYTES];
        let _ = serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        Ok(Self(bytes))
    }
}

/// The encoding of a dictionary that a tag covers: the number of entries as a `u64`, then for
/// every entry in order the length of the element's bytes as a `u64`, those bytes, the
/// operation byte (0 for [`Operation::Add`], 1 for [`Operation::Del`]) and the epoch as a
/// `u64`; every integer little-endian. The length prefixes make it injective.
pub(crate) fn encode_dictionary<'a>(
    entries: impl ExactSizeIterator<Item = (&'a [u8], &'a Record)>,
) -> Vec<u8> {
    let mut out = (entries.len() as u64).to_le_bytes().to_vec();
    for (x, record) in entries {
        out.extend_from_slice(&(x.len() as u64).to_le_bytes());
        out.extend_from_slice(x);
        out.push(u8::from(record.operation));
        out.extend_from_slice(&record.epoch.to_le_bytes());
    }
    out
}

/// What the manager keeps between operations: the deletion counter `ctr`, the current value
/// `c`, the dictionary `D_X` from elements to their [`Record`], and a tag that binds them to
/// the [`SecretKey`] that keeps the accumulator.
///
/// A key keeps one accumulator, which starts at the key's genesis value `c₀`
/// ([`Accumulator::new`]); the state does not store `c₀`, the key does. The current value is
/// the one the last keyed update left; it is stored rather than recomputed from `c₀` and the
/// deletions, which would cost one `B_{1y}·G⁻¹(u)` per past deletion.
///
/// # The tag
///
/// The tag is SHAKE256 keyed by prefix with a 32-byte key derived from the secret key's root
/// seed and parameter set under its own label. It absorbs, each part preceded by its length as
/// a little-endian `u64`: the label `kln/state/tag`, the MAC key, [`Accumulator::to_bytes`] of
/// `c` (the parameter set followed by the packed coefficients), `ctr` as a little-endian
/// `u64`, and the dictionary in element order (its entry count, then for each entry the
/// element's length and bytes, a byte 0 for [`Operation::Add`] or 1 for [`Operation::Del`],
/// and the epoch, integers little-endian). The first 32 bytes of the output are the tag.
///
/// [`ManagerState::new`] tags a fresh state, and every keyed operation that reads a state
/// first checks its tag under its key and refuses the state with [`Error::InvalidStateTag`]
/// otherwise, leaving the value and the state as they were: the add, remove and update methods
/// of [`Accumulator`], which all run through [`Accumulator::update_assign`], and
/// [`crate::MembershipWitness::new`]. Each of them then refuses a value other than the
/// state's current one with [`Error::AccumulatorMismatch`], again changing nothing. Every
/// operation that changes the state records the new value and tags the state again.
/// [`ManagerState::authenticate`] runs the tag check alone. Checking and re-tagging hash the
/// whole state, so their cost grows with the number of elements ever added.
///
/// # Fresh, forked and older states
///
/// The tag does not detect rollback: an older state that the key once tagged still verifies,
/// since nothing monotonic lives outside the state, and two copies of a state can be moved on
/// separately. None of this can make the key leak: a witness is sampled for `c₀` and corrected
/// for the set of deletions, so a fresh, forked, older or rebuilt state can only reproduce the
/// one preimage the key has for each element. What an old state still does is issue witnesses
/// for the old value, and a manager moving two states on publishes two histories; keeping only
/// the latest state is the manager's job. A lost state is remade with
/// [`ManagerState::rebuild`].
///
/// Deserialization has no key, so it checks only that the history is one Construction 4.1 can
/// produce (the deletion epochs are exactly `1, …, ctr` and no addition epoch exceeds `ctr`);
/// the tag is checked at the first keyed use, or by [`ManagerState::authenticate`].
/// [`ManagerState::validate`] checks the state against a parameter set.
///
/// **Manager-private, not key material.** It holds no key, so it is not wiped as a secret
/// (its elements overwrite themselves on drop as [`Element`] does); see the book's chapter
/// "Manager state and its tag" for what its disclosure reveals. Serialized field
/// by field, with the tag raw in binary formats and hex in human-readable ones.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
/// use rand::{SeedableRng, rngs::StdRng};
/// use std::sync::Arc;
///
/// let mut rng = StdRng::seed_from_u64(0);
/// let params = Arc::new(Params::toy()?);
/// let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::clone(&params), &mut rng)?;
/// let mut acc = Accumulator::new(&key);
/// let mut state = ManagerState::new(&key);
/// assert_eq!(state.counter(), 0);
/// assert_eq!(state.current(), &acc);
/// let y = Element::hash(b"y", &params);
/// acc.add_assign(&key, &y, &mut state)?;
/// acc.remove_assign(&key, &y, &mut state)?;
/// assert_eq!(state.counter(), 1);
/// // The state follows the value: the deletion moved it away from genesis.
/// assert_eq!(state.current(), &acc);
/// assert_ne!(&Accumulator::new(&key), &acc);
/// state.validate(&params)?;
/// state.authenticate(&key)?;
/// // The state survives a round trip through serde; the tag is checked at its next use.
/// let json = serde_json::to_string(&state)?;
/// let back: ManagerState = serde_json::from_str(&json)?;
/// assert_eq!(back, state);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "StateWire")]
pub struct ManagerState {
    counter: u64,
    current: Accumulator,
    entries: BTreeMap<Element, Record>,
    tag: StateTag,
}

/// Prints the deletion counter and the number of elements, not the elements or the tag.
impl fmt::Debug for ManagerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagerState")
            .field("counter", &self.counter)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl ManagerState {
    /// `Gen` step 3: an empty dictionary and `ctr = 0` for the accumulator of `key`, whose
    /// current value is the key's genesis value ([`Accumulator::new`]), tagged under `key`.
    /// [`Accumulator::with_elements`] makes the value and the state together, and
    /// [`ManagerState::rebuild`] remakes a lost state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, Error, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let (x, y) = (Element::hash(b"x", key.params()), Element::hash(b"y", key.params()));
    /// let mut acc = Accumulator::new(&key);
    /// let mut state = ManagerState::new(&key);
    /// assert_eq!((state.counter(), state.current()), (0, &acc));
    /// acc.add_elements_assign(&key, &[x.clone(), y.clone()], &mut state)?;
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// // Misuse: a second `new` is a fresh state at genesis, not the manager's; keep the state
    /// // and reload it, or remake a lost one with `ManagerState::rebuild`.
    /// let mut fresh = ManagerState::new(&key);
    /// assert_eq!(acc.add_assign(&key, &x, &mut fresh), Err(Error::AccumulatorMismatch));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn new(key: &SecretKey) -> Self {
        let mut state = Self {
            counter: 0,
            current: Accumulator::new(key),
            entries: BTreeMap::new(),
            tag: StateTag([0; StateTag::BYTES]),
        };
        state.tag = state.tag_under(key);
        state
    }

    /// Rebuilds a lost state, and the current value, from the key, the published update
    /// messages and the manager's own list of current members: every element `log` names is
    /// recorded as deleted, so it can never be added again, every element of `members` as
    /// present, and the value is the genesis value plus the offsets of the deletions. The log
    /// may come in any order; the rebuilt state is the same for every order (its deletions are
    /// numbered in element order).
    ///
    /// Witnesses issued from the rebuilt state equal the ones the lost state issued, because a
    /// witness depends only on the key, the element and the set of deletions. The member list
    /// is policy, not safety: a wrong list cannot make the key sample a second preimage, it can
    /// only make the manager issue a witness it should not (for an element listed by mistake)
    /// or refuse one it should issue (for a member left out).
    ///
    /// The cost is one `B_{1y}·G⁻¹(u)` per deletion, as the deletions themselves were.
    ///
    /// # Errors
    ///
    /// - [`Error::ElementNotPresent`] when `log` names an element twice;
    /// - [`Error::ElementAlreadyAdded`] when a member is also in `log`, or is listed twice;
    /// - [`Error::DeletionBoundReached`] when `log` holds more than `γ` deletions;
    /// - [`Error::InvalidElement`] for an element that is not an `ℓ`-bit string of the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Accumulator, Element, Error, ManagerState, MembershipWitness, Params};
    /// use kln_accumulator::SecretKey;
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
    /// let element = |name: &[u8]| Element::hash(name, key.params());
    /// let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
    /// let mut log = acc.update_assign(&key, &[z.clone()], &[y.clone()], &mut state)?;
    /// let issued = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// drop(state); // lost
    ///
    /// let (value, rebuilt) = ManagerState::rebuild(&key, &log, &[x.clone(), z.clone()])?;
    /// assert_eq!(value, acc);
    /// assert_eq!(MembershipWitness::new(&x, &value, &key, &rebuilt)?, issued);
    /// // The deleted element stays deleted.
    /// let mut value = value;
    /// let mut rebuilt = rebuilt;
    /// assert_eq!(value.add_assign(&key, &y, &mut rebuilt), Err(Error::ElementAlreadyAdded));
    /// // A log that names an element twice is refused.
    /// log.push(log[0].clone());
    /// assert_eq!(ManagerState::rebuild(&key, &log, &[x]).map(drop), Err(Error::ElementNotPresent));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn rebuild(
        key: &SecretKey,
        log: &[Coefficient],
        members: &[Element],
    ) -> Result<(Accumulator, Self)> {
        let mut deleted: Vec<Element> = log.iter().map(|c| c.element().clone()).collect();
        deleted.sort_unstable();
        if deleted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::ElementNotPresent);
        }
        let additions: Vec<Element> = deleted.iter().chain(members).cloned().collect();
        let mut value = Accumulator::new(key);
        let mut state = Self::new(key);
        let _ = value.update_assign(key, &additions, &deleted, &mut state)?;
        Ok((value, state))
    }

    /// The deletion counter `ctr`, the number of deletions made; see the type's example.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The current value `c`, the one the last keyed update left (the key's genesis value `c₀`
    /// before any); every keyed operation refuses any other value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, Error, ManagerState, Params, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let (x, y) = (Element::hash(b"x", key.params()), Element::hash(b"y", key.params()));
    /// let (acc, mut state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// let mut older = acc.clone();
    /// let _ = acc.remove(&key, &x, &mut state)?;
    /// // A manager that kept only the state takes the value to publish and update from it.
    /// let mut acc = state.current().clone();
    /// acc.add_assign(&key, &y, &mut state)?;
    /// // An earlier value is refused.
    /// assert_eq!(older.add_assign(&key, &y, &mut state), Err(Error::AccumulatorMismatch));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn current(&self) -> &Accumulator {
        &self.current
    }

    /// `D_X[x]`, or `None` (the paper's `⊥`) when `x` was never added; see [`Record`]'s
    /// example.
    #[must_use]
    pub fn record(&self, x: &Element) -> Option<Record> {
        self.entries.get(x).copied()
    }

    /// Checks the state against `params`: `ctr ≤ γ`, `c` with
    /// [`Accumulator::validate`] and every element with [`Element::validate`]. It does not check
    /// the tag, which needs the key; [`ManagerState::authenticate`] and every keyed operation do
    /// that. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::InconsistentState`] when `ctr > γ`, [`Error::ParameterMismatch`] when `c`
    /// belongs to another set, and [`Error::InvalidElement`] for an element that is not an
    /// `ℓ`-bit string of `params`.
    pub fn validate(&self, params: &Params) -> Result<()> {
        if self.counter > params.spec().max_deletions {
            return Err(Error::InconsistentState);
        }
        self.current.validate(params)?;
        self.entries.keys().try_for_each(|x| x.validate(params))
    }

    /// Checks the tag under `key` and changes nothing: the check every keyed operation makes
    /// first, on its own, for example on a state just loaded from storage. The tag is
    /// recomputed and compared in constant time; the cost grows with the number of elements
    /// ever added.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidStateTag`] when a field of the state was altered after `key` tagged it,
    /// or another key tagged it.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Accumulator, Element, Error, ManagerState, Params, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let mut rng = StdRng::seed_from_u64(0);
    /// let params = Arc::new(Params::toy()?);
    /// let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::clone(&params), &mut rng)?;
    /// let other = SecretKey::new(Some(b"another manager's seed, 32 bytes"), Arc::clone(&params), &mut rng)?;
    /// let x = Element::hash(b"x", &params);
    /// let (_, state) = Accumulator::with_elements(&key, &[x])?;
    /// let stored = serde_json::to_string(&state)?;
    ///
    /// let loaded: ManagerState = serde_json::from_str(&stored)?;
    /// loaded.authenticate(&key)?;
    /// assert_eq!(loaded, state);
    /// assert_eq!(loaded.authenticate(&other), Err(Error::InvalidStateTag));
    ///
    /// // A stored state whose current value was replaced loads, and fails the check.
    /// let mut json: serde_json::Value = serde_json::from_str(&stored)?;
    /// json["current"] = serde_json::to_value(Accumulator::random(&mut rng, &params))?;
    /// let altered: ManagerState = serde_json::from_value(json)?;
    /// assert_eq!(altered.authenticate(&key), Err(Error::InvalidStateTag));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn authenticate(&self, key: &SecretKey) -> Result<()> {
        self.tag.verify(&self.tag_under(key))
    }

    /// Fails with [`Error::ParameterMismatch`] unless `value` belongs to the set of the current
    /// value, and with [`Error::AccumulatorMismatch`] unless it is the current value.
    pub(crate) fn check_current(&self, value: &Accumulator) -> Result<()> {
        value.validate(self.current.params())?;
        if *value == self.current {
            Ok(())
        } else {
            Err(Error::AccumulatorMismatch)
        }
    }

    /// The tag of the state under `key`.
    fn tag_under(&self, key: &SecretKey) -> StateTag {
        self.mac(DomainLabel::from(LABEL_TAG), key.state_mac_key(), &[])
    }

    /// [`StateTag::compute`] of `c`, `ctr`, the dictionary (encoded as the type
    /// documentation describes) and then `extra`, under `label` and `mac_key`. The state's own
    /// tag is not among them; a state that wraps this one passes it in `extra`.
    pub(crate) fn mac(&self, label: DomainLabel<'_>, mac_key: &Seed, extra: &[&[u8]]) -> StateTag {
        let current = self.current.to_bytes();
        let counter = self.counter.to_le_bytes();
        let entries = encode_dictionary(self.entries.iter().map(|(x, r)| (x.as_bytes(), r)));
        let parts: Vec<&[u8]> = [current.as_slice(), &counter, &entries]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        StateTag::compute(label, mac_key, &parts)
    }

    /// The tag.
    pub(crate) fn tag(&self) -> &StateTag {
        &self.tag
    }

    /// Checks that adding `additions` and then deleting `deletions`, one at a time, would
    /// succeed (Construction 4.1, Add step 1 and Delete steps 1 and 2).
    pub(crate) fn check_update(
        &self,
        additions: &[Element],
        deletions: &[Element],
        params: &Params,
    ) -> Result<()> {
        let mut added = BTreeSet::new();
        for x in additions {
            x.validate(params)?;
            if self.entries.contains_key(x) || !added.insert(x) {
                return Err(Error::ElementAlreadyAdded);
            }
        }
        let mut deleted = BTreeSet::new();
        for (j, y) in (0u64..).zip(deletions) {
            // Erratum (Construction 4.1, p. 17): Delete step 1 aborts only when ctr > γ, which admits γ + 1 deletions;
            // the bound needs ctr ≥ γ.
            if self.counter.saturating_add(j) >= params.spec().max_deletions {
                return Err(Error::DeletionBoundReached);
            }
            y.validate(params)?;
            let present = added.contains(y)
                || self
                    .entries
                    .get(y)
                    .is_some_and(|r| r.operation == Operation::Add);
            if !present || !deleted.insert(y) {
                return Err(Error::ElementNotPresent);
            }
        }
        Ok(())
    }

    /// Records `additions` and then `deletions`, which [`ManagerState::check_update`] accepted,
    /// and `current`, the value they lead to, and tags the result under `key`.
    pub(crate) fn apply_update(
        &mut self,
        additions: &[Element],
        deletions: &[Element],
        current: &Accumulator,
        key: &SecretKey,
    ) {
        for x in additions {
            let record = Record {
                operation: Operation::Add,
                epoch: self.counter,
            };
            let _ = self.entries.insert(x.clone(), record);
        }
        for y in deletions {
            // Erratum (Construction 4.1, p. 17): Delete step 5 records the counter before step
            // 4's increment, so the first deletion would record 0. Recording the incremented
            // counter puts the j-th deletion at epoch j, which deserialization checks; no
            // witness depends on it, since MemWitCreate here samples for c₀.
            self.counter += 1;
            let record = Record {
                operation: Operation::Del,
                epoch: self.counter,
            };
            let _ = self.entries.insert(y.clone(), record);
        }
        self.current = current.clone();
        self.tag = self.tag_under(key);
    }

    /// Fails with [`Error::ElementNotPresent`] unless `x` is present (MemWitCreate step 1).
    pub(crate) fn check_present(&self, x: &Element) -> Result<()> {
        match self.entries.get(x) {
            Some(Record {
                operation: Operation::Add,
                ..
            }) => Ok(()),
            _ => Err(Error::ElementNotPresent),
        }
    }

    /// The number of elements ever added, present or deleted.
    pub(crate) fn recorded(&self) -> usize {
        self.entries.len()
    }

    /// The deleted elements, in element order: a witness depends on their set only.
    pub(crate) fn deleted(&self) -> impl Iterator<Item = &Element> {
        self.entries
            .iter()
            .filter(|(_, r)| r.operation == Operation::Del)
            .map(|(x, _)| x)
    }
}

/// The serialized form of [`ManagerState`], before its history is checked; a field it does not
/// name is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateWire {
    counter: u64,
    current: Accumulator,
    entries: BTreeMap<Element, Record>,
    tag: StateTag,
}

impl TryFrom<StateWire> for ManagerState {
    type Error = Error;

    fn try_from(wire: StateWire) -> Result<Self> {
        let mut epochs: Vec<u64> = wire
            .entries
            .values()
            .filter(|r| r.operation == Operation::Del)
            .map(|r| r.epoch)
            .collect();
        epochs.sort_unstable();
        let deletions_are_numbered = epochs.iter().copied().eq(1..=wire.counter);
        let additions_are_past = wire
            .entries
            .values()
            .all(|r| r.operation == Operation::Del || r.epoch <= wire.counter);
        if deletions_are_numbered && additions_are_past {
            Ok(Self {
                counter: wire.counter,
                current: wire.current,
                entries: wire.entries,
                tag: wire.tag,
            })
        } else {
            Err(Error::InconsistentState)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{ManagerState, Operation, Record, StateTag};
    use crate::{
        accumulator::{Accumulator, Element},
        error::Error,
        key::SecretKey,
        test_util::{TOY, TOY_TERNARY},
        witness::MembershipWitness,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::{Arc, LazyLock};

    /// The operation bytes the tag absorbs are pinned: 0 for `Add`, 1 for `Del`.
    #[test]
    fn operation_bytes_are_fixed() {
        use strum::{EnumCount, IntoEnumIterator};
        assert_eq!(u8::from(Operation::Add), 0);
        assert_eq!(u8::from(Operation::Del), 1);
        assert_eq!(Operation::COUNT, 2);
        let bytes: Vec<u8> = Operation::iter().map(u8::from).collect();
        assert_eq!(bytes, [0, 1]);
    }

    /// The operation and a record round-trip in the six formats; the operation by its name.
    #[test]
    fn operation_and_record_serde() {
        use strum::IntoEnumIterator;
        for operation in Operation::iter() {
            let name = format!("{operation:?}");
            let _ = crate::test_util::six_formats(operation, &name);
            let _ = crate::test_util::six_formats(
                Record {
                    operation,
                    epoch: 3,
                },
                &name,
            );
        }
    }

    static KEY: LazyLock<SecretKey> = LazyLock::new(|| key(b"kln/test/state-tag, a 32-byte seed"));
    static OTHER: LazyLock<SecretKey> =
        LazyLock::new(|| key(b"kln/test/state-tag/other, 32 bytes"));

    fn key(seed: &[u8]) -> SecretKey {
        SecretKey::new(
            Some(seed),
            Arc::new(TOY.clone()),
            &mut StdRng::seed_from_u64(0),
        )
        .unwrap()
    }

    fn element(i: u8) -> Element {
        Element::try_from([i].as_slice()).unwrap()
    }

    /// A state under `key` after adding 1, 2 and 3, deleting 2 and adding 4: `ctr = 1`, with
    /// additions before and after the deletion.
    fn honest(key: &SecretKey) -> (Accumulator, ManagerState) {
        let (mut value, mut state) =
            Accumulator::with_elements(key, &[element(1), element(2), element(3)]).unwrap();
        value.remove_assign(key, &element(2), &mut state).unwrap();
        value.add_assign(key, &element(4), &mut state).unwrap();
        (value, state)
    }

    /// `state` with one field altered, for every field: the counter, the current value, an
    /// entry's operation, an entry's epoch, an extra entry, a missing entry,
    /// and the tag. Shared with the adaptive state's tests, which alter their inner state with
    /// it.
    pub(crate) fn tamperings(state: &ManagerState) -> Vec<(&'static str, ManagerState)> {
        let alter = |change: &dyn Fn(&mut ManagerState)| {
            let mut altered = state.clone();
            change(&mut altered);
            assert_ne!(altered, *state);
            altered
        };
        let first = state.entries.keys().next().cloned().unwrap();
        let params = state.current.params();
        vec![
            ("counter", alter(&|s| s.counter += 1)),
            (
                "current value",
                alter(&|s| s.current = Accumulator::random(&mut StdRng::seed_from_u64(98), params)),
            ),
            (
                "operation",
                alter(&|s| {
                    let record = s.entries.get_mut(&first).unwrap();
                    record.operation = match record.operation {
                        Operation::Add => Operation::Del,
                        Operation::Del => Operation::Add,
                    };
                }),
            ),
            (
                "epoch",
                alter(&|s| s.entries.get_mut(&first).unwrap().epoch += 1),
            ),
            (
                "added entry",
                alter(&|s| {
                    let fresh = (0..=u8::MAX)
                        .map(element)
                        .find(|x| !s.entries.contains_key(x))
                        .unwrap();
                    let record = Record {
                        operation: Operation::Add,
                        epoch: 0,
                    };
                    let _ = s.entries.insert(fresh, record);
                }),
            ),
            (
                "removed entry",
                alter(&|s| {
                    let _ = s.entries.remove(&first);
                }),
            ),
            ("tag", alter(&|s| s.tag.0[0] ^= 1)),
        ]
    }

    /// Every keyed operation refuses `state` under `key` with [`Error::InvalidStateTag`], and
    /// neither the value nor the state changes.
    fn assert_refused(value: &Accumulator, state: &ManagerState, key: &SecretKey, what: &str) {
        let refused = Err(Error::InvalidStateTag);
        let (fresh, present) = (element(9), element(1));
        let (mut v, mut s) = (value.clone(), state.clone());
        let fresh_slice = std::slice::from_ref(&fresh);
        let present_slice = std::slice::from_ref(&present);
        let results = [
            MembershipWitness::new(&present, &v, key, &s).map(drop),
            v.add(key, &fresh, &mut s).map(drop),
            v.add_assign(key, &fresh, &mut s),
            v.add_elements(key, fresh_slice, &mut s).map(drop),
            v.add_elements_assign(key, fresh_slice, &mut s),
            v.remove(key, &present, &mut s).map(drop),
            v.remove_assign(key, &present, &mut s),
            v.remove_elements(key, present_slice, &mut s).map(drop),
            v.remove_elements_assign(key, present_slice, &mut s),
            v.update(key, fresh_slice, present_slice, &mut s).map(drop),
            v.update_assign(key, fresh_slice, present_slice, &mut s)
                .map(drop),
        ];
        for (i, result) in results.into_iter().enumerate() {
            assert_eq!(result, refused, "{what}: operation {i}");
        }
        assert_eq!(v, *value, "{what}: value changed");
        assert_eq!(s, *state, "{what}: state changed");
    }

    /// C51: a state altered in any single field is refused by every keyed operation.
    #[test]
    fn every_altered_field_is_refused() {
        let (value, state) = honest(&KEY);
        assert!(state.authenticate(&KEY).is_ok());
        for (what, altered) in tamperings(&state) {
            assert_refused(&value, &altered, &KEY, what);
        }
    }

    /// C71: the public tag check accepts the honest state under its key, refuses it under
    /// another key and refuses every single-field alteration, and changes nothing.
    #[test]
    fn authenticate_checks_the_tag_and_changes_nothing() {
        let (_, state) = honest(&KEY);
        let before = state.clone();
        assert_eq!(state.authenticate(&KEY), Ok(()));
        assert_eq!(state.authenticate(&OTHER), Err(Error::InvalidStateTag));
        for (what, altered) in tamperings(&state) {
            let kept = altered.clone();
            assert_eq!(
                altered.authenticate(&KEY),
                Err(Error::InvalidStateTag),
                "{what}"
            );
            assert_eq!(altered, kept, "{what}");
        }
        assert_eq!(state, before);
    }

    /// C68: the state records the value every keyed update leaves, starting from the key's
    /// genesis value `c₀`, and an addition, which leaves the value as it was, leaves the
    /// recorded value as it was.
    #[test]
    fn the_current_value_follows_every_update() {
        let genesis = Accumulator::new(&KEY);
        let mut value = genesis.clone();
        let mut state = ManagerState::new(&KEY);
        assert_eq!(state.current(), &genesis);
        value.add_assign(&KEY, &element(1), &mut state).unwrap();
        assert_eq!(state.current(), &value);
        assert_eq!(state.current(), &genesis);
        value.remove_assign(&KEY, &element(1), &mut state).unwrap();
        assert_eq!(state.current(), &value);
        assert_ne!(state.current(), &genesis);
        let (moved, _) = value
            .update(&KEY, &[element(2), element(3)], &[element(2)], &mut state)
            .unwrap();
        assert_eq!(state.current(), &moved);
        assert_ne!(moved, value);
    }

    /// C68: the current value round-trips in the six formats with the rest of the state, and
    /// `validate` refuses a state whose current value belongs to another parameter set.
    #[test]
    fn the_current_value_is_serialized_and_validated() {
        let (value, state) = honest(&KEY);
        assert_ne!(state.current(), &Accumulator::new(&KEY));
        assert_eq!(state.current(), &value);
        let _ = crate::test_util::six_formats(
            state.clone(),
            &hex::encode(&value.to_bytes()[crate::params::ParamsSpec::BYTES..]),
        );
        let mut foreign = state.clone();
        foreign.current = Accumulator::random(
            &mut StdRng::seed_from_u64(3),
            &Arc::new(TOY_TERNARY.clone()),
        );
        assert_eq!(foreign.validate(&TOY), Err(Error::ParameterMismatch));
        assert_eq!(foreign.authenticate(&KEY), Err(Error::InvalidStateTag));
    }

    /// C51: a state tagged under another key is refused, and the honest state under its own key
    /// is not.
    #[test]
    fn a_state_of_another_key_is_refused() {
        let (value, state) = honest(&OTHER);
        assert_refused(&value, &state, &KEY, "other key");
        assert!(MembershipWitness::new(&element(1), &value, &OTHER, &state).is_ok());
    }

    /// The tag covers exactly the fields: equal states under one key have equal tags, every
    /// update changes the tag, and re-tagging an unchanged state reproduces it.
    #[test]
    fn updates_re_tag_the_state() {
        let (mut value, mut state) = honest(&KEY);
        let before = state.tag.clone();
        assert_eq!(state.tag_under(&KEY), before);
        value.add_assign(&KEY, &element(5), &mut state).unwrap();
        assert_ne!(state.tag, before);
        assert!(state.authenticate(&KEY).is_ok());
        let after_add = state.tag.clone();
        value.remove_assign(&KEY, &element(5), &mut state).unwrap();
        assert_ne!(state.tag, after_add);
        assert!(state.authenticate(&KEY).is_ok());
        assert_ne!(StateTag([0; StateTag::BYTES]), state.tag);
    }
}
