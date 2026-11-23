// SPDX-License-Identifier: MIT OR Apache-2.0
//! The manager state `st = (k, s̃t, D_X)` of Construction 4.2, without the PRF key `k`, which
//! lives in the [`SecretKey`].

use super::{accumulator::Element, key::SecretKey};
use crate::{
    accumulator::{Accumulator as InnerAccumulator, Coefficient, Element as Handle},
    error::{Error, Result},
    params::Params,
    sample::DomainLabel,
    state::{ManagerState as InnerState, Operation, Record, StateTag, encode_dictionary},
};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Label of the tag of a [`ManagerState`].
const LABEL_TAG: &[u8] = b"kln/adaptive/state/tag";

/// What the manager keeps between operations: the state `s̃t` of the inner accumulator of
/// handles, the dictionary `D_X` from elements of `V` to their [`Record`], and a tag that binds
/// them to the [`SecretKey`] that keeps the accumulator.
///
/// Here a record's `epoch` is the PRF index `i` of Construction 4.2: for [`Operation::Add`] the
/// index the current handle `F_k(x, i)` was drawn at, for [`Operation::Del`] one more than the
/// index of the deleted handle, where the next addition of the element starts.
///
/// # The tag
///
/// The inner state carries its own tag under the inner key, as [`InnerState`] describes. This
/// state adds a second one over everything: SHAKE256 keyed by prefix with a 32-byte key derived
/// from the adaptive key's root seed and parameter set under its own label, absorbing, each part
/// preceded by its length as a little-endian `u64`, the label `kln/adaptive/state/tag`, the MAC
/// key, the inner state's current value `c`, `ctr` and dictionary encoded as for the inner
/// tag, the inner tag, and this state's dictionary encoded the same way. The first 32 bytes of
/// the output are the tag.
///
/// [`ManagerState::new`] tags a fresh state. The add, remove and update methods of
/// [`super::Accumulator`] (all through [`super::Accumulator::update_assign`]) and
/// [`super::MembershipWitness::new`] first check this tag under their key and refuse the state
/// with [`Error::InvalidStateTag`] otherwise, leaving the value and the state as they were, and
/// then refuse a value other than the inner state's current one with
/// [`Error::AccumulatorMismatch`]; the inner operations then check the inner tag.
/// [`ManagerState::authenticate`] runs the tag check alone. Every operation that changes the
/// state records the new value and tags both again. The cost of checking and re-tagging grows with the number of elements and handles
/// ever added.
///
/// As for the inner state, the tag does not stop rollback: an older state that the key once
/// tagged still verifies, since nothing monotonic lives outside the state. It cannot leak the
/// key: an inner witness is sampled for the inner genesis value with randomness derived from
/// its handle, so it is a function of the handle and the deleted handles, whatever state
/// assigned the handle. A fork may assign an element a different handle than the original
/// did (see the [module documentation](super#handles)); that changes which witness the element
/// gets, not how often the key samples for a handle. [`ManagerState::rebuild`] remakes a lost
/// state from the log and the member records. Deserialization has
/// no key, so it checks the inner state only, and the tags are checked at the first keyed use
/// or by [`ManagerState::authenticate`].
///
/// **Manager-private, not key material**, as the base [`InnerState`]: it maps every element
/// ever added to its PRF index, so it links elements to handles, but it holds no key.
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
/// let record = state.record(&x).ok_or(kln_accumulator::Error::ElementNotPresent)?;
/// assert_eq!(record.operation, kln_accumulator::adaptive::Operation::Add);
/// assert_eq!(state.inner().counter(), 0);
/// state.validate(key.params())?;
/// acc.remove_assign(&key, &x, &mut state)?;
/// assert_eq!(state.inner().counter(), 1);
/// // A fresh state for the same value under the same key starts empty.
/// let fresh = ManagerState::new(&key);
/// assert!(fresh.record(&x).is_none());
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerState {
    inner: InnerState,
    entries: BTreeMap<Element, Record>,
    tag: StateTag,
}

/// Prints the inner state's counts and the number of elements, not the elements, their
/// handles' indices or the tags.
impl fmt::Debug for ManagerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagerState")
            .field("inner", &self.inner)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// An element with the PRF index and handle an update assigns it.
struct Assigned {
    element: Element,
    index: u64,
    handle: Handle,
}

impl ManagerState {
    /// `Gen` steps 2 and 4: the inner state for the key's accumulator, which starts at the
    /// inner key's genesis value ([`super::Accumulator::new`]), and an empty dictionary, tagged
    /// under `key`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Error, Params};
    /// # use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
    /// let mut acc = Accumulator::new(&key);
    /// let mut state = ManagerState::new(&key);
    /// acc.add_elements_assign(&key, &[x, y], &mut state)?;
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// // Misuse: a second `new` is a fresh state at genesis, not the manager's; keep the state
    /// // and reload it, or remake a lost one with `ManagerState::rebuild`.
    /// let mut fresh = ManagerState::new(&key);
    /// assert_eq!(acc.add_assign(&key, &x, &mut fresh), Err(Error::AccumulatorMismatch));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn new(key: &SecretKey) -> Self {
        let inner = InnerState::new(key.inner());
        let entries = BTreeMap::new();
        let tag = tag(key, &inner, &entries);
        Self {
            inner,
            entries,
            tag,
        }
    }

    /// Rebuilds a lost state, and the current value, from the key, the published update
    /// messages, which name the deleted handles, and the manager's records of its current
    /// members, each an element with its handle. Every handle `log` names is recorded as
    /// deleted in the inner state, so it is never handed out again; every member is recorded as
    /// present with its handle; the value is the inner genesis value plus the offsets of the
    /// deleted handles. The log may come in any order.
    ///
    /// Each record is checked: its handle must be `F_k(x, i)` for an index `i` the addition
    /// rule can reach, which means every handle `F_k(x, j)` with `j < i` is deleted or held by
    /// another member (the search is the one an addition makes, with the same bound), and it
    /// must not be deleted. A handle is not secret from the manager, and every holder carries
    /// its own in its witness ([`super::MembershipWitness::handle`]), so the records can be
    /// collected again from the holders if the manager lost them.
    ///
    /// Elements that were deleted are not known from the log, which names handles only, so the
    /// rebuilt dictionary records the members alone; a deleted element may be added again, as
    /// in any adaptive state, and gets the handle the lost state would have given it. Witnesses
    /// issued from the rebuilt state equal the ones the lost state issued, handle, signature
    /// and inner witness included. A wrong record cannot make the key sample a second preimage
    /// for a handle, since the inner preimage is a function of the handle alone; it can only
    /// make the manager issue a witness it should not, or refuse one it should issue. The two
    /// halves of the check differ in what they protect. That a handle is `F_k(x, i)` for some
    /// `i` is needed for security: Theorem 4.4 relies on handles being PRF outputs, and a handle
    /// the caller could choose would not be one. That every earlier index is already taken is
    /// for reproducibility only, and is necessary but not sufficient: where two members' handles
    /// collide crosswise, records that no order of additions produces can pass it.
    ///
    /// # Errors
    ///
    /// - [`Error::ElementNotPresent`] when `log` names a handle twice;
    /// - [`Error::ElementAlreadyAdded`] when an element or a handle is listed twice, or a
    ///   member's handle is in `log`;
    /// - [`Error::InconsistentState`] when a member's handle is not one the addition rule
    ///   gives the element;
    /// - [`Error::DeletionBoundReached`] when `log` holds more than `γ` deletions;
    /// - [`Error::InvalidElement`] for a handle that is not an `ℓ`-bit string of the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, MembershipWitness};
    /// use kln_accumulator::adaptive::SecretKey;
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
    /// let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
    /// let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y])?;
    /// let log = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let issued = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let records = [(x, issued.handle().clone())];
    /// drop(state); // lost
    ///
    /// let (value, rebuilt) = ManagerState::rebuild(&key, &log, &records)?;
    /// assert_eq!(value, acc);
    /// assert_eq!(MembershipWitness::new(&x, &value, &key, &rebuilt)?, issued);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn rebuild(
        key: &SecretKey,
        log: &[Coefficient],
        members: &[(Element, Handle)],
    ) -> Result<(super::Accumulator, Self)> {
        let deleted: BTreeSet<&Handle> = log.iter().map(Coefficient::element).collect();
        let held: BTreeSet<&Handle> = members.iter().map(|(_, h)| h).collect();
        if held.len() != members.len() {
            return Err(Error::ElementAlreadyAdded);
        }
        let mut entries = BTreeMap::new();
        for (x, handle) in members {
            // A malformed handle never equals a derived one, so with every handle in `log` the
            // index search below would not end; it is refused before the search.
            handle.validate(key.params())?;
            if deleted.contains(handle) {
                return Err(Error::ElementAlreadyAdded);
            }
            let index = handle_index(key, x, handle, |h| {
                deleted.contains(h) || (held.contains(h) && h != handle)
            })?;
            let record = Record {
                operation: Operation::Add,
                epoch: index,
            };
            if entries.insert(*x, record).is_some() {
                return Err(Error::ElementAlreadyAdded);
            }
        }
        let handles: Vec<Handle> = members.iter().map(|(_, h)| h.clone()).collect();
        let (value, inner) = InnerState::rebuild(key.inner(), log, &handles)?;
        let tag = tag(key, &inner, &entries);
        Ok((
            super::Accumulator::from(value),
            Self {
                inner,
                entries,
                tag,
            },
        ))
    }

    /// The state `s̃t` of the inner accumulator of handles; see the type's example.
    #[must_use]
    pub fn inner(&self) -> &InnerState {
        &self.inner
    }

    /// `D_X[x]`, or `None` (the paper's `⊥`) when `x` was never added; see the type's
    /// example.
    #[must_use]
    pub fn record(&self, x: &Element) -> Option<Record> {
        self.entries.get(x).copied()
    }

    /// Checks the inner state against `params` with [`InnerState::validate`]; see the type's
    /// example.
    ///
    /// # Errors
    ///
    /// As [`InnerState::validate`].
    pub fn validate(&self, params: &Params) -> Result<()> {
        self.inner.validate(params)
    }

    /// Checks the tag under `key` and changes nothing: the check every keyed operation makes
    /// first, on its own, for example on a state just loaded from storage. The tag covers the
    /// inner state together with the inner tag, so an altered inner state fails it as well.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidStateTag`] when a field of the state or of its inner state was altered
    /// after `key` tagged it, or another key tagged it.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params};
    /// use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let mut rng = StdRng::seed_from_u64(0);
    /// let params = Arc::new(Params::toy()?);
    /// let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::clone(&params), &mut rng)?;
    /// let other = SecretKey::new(Some(b"another manager's seed, 32 bytes"), params, &mut rng)?;
    /// let (_, state) = Accumulator::with_elements(&key, &[Element::hash(b"x")])?;
    /// let loaded: ManagerState = serde_json::from_str(&serde_json::to_string(&state)?)?;
    /// loaded.authenticate(&key)?;
    /// assert_eq!(loaded.authenticate(&other), Err(Error::InvalidStateTag));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn authenticate(&self, key: &SecretKey) -> Result<()> {
        self.tag.verify(&tag(key, &self.inner, &self.entries))
    }

    /// The handle `F_k(x, i)` of a present element (MemWitCreate steps 1 and 2), or
    /// [`Error::ElementNotPresent`].
    pub(super) fn handle(&self, key: &SecretKey, x: &Element) -> Result<Handle> {
        match self.entries.get(x) {
            Some(Record {
                operation: Operation::Add,
                epoch,
            }) => Ok(key.handle(x, *epoch)),
            _ => Err(Error::ElementNotPresent),
        }
    }

    /// `Add` for every element of `additions`, then `Delete` for every element of `deletions`,
    /// applied to the inner value and state at once, so that on an error nothing changes.
    /// Checks the tags under `key` first, then that `value` is the inner state's current value,
    /// and tags the result. Returns the inner update messages.
    pub(super) fn update(
        &mut self,
        key: &SecretKey,
        value: &mut InnerAccumulator,
        additions: &[Element],
        deletions: &[Element],
    ) -> Result<Vec<Coefficient>> {
        self.authenticate(key)?;
        self.inner.check_current(value)?;
        let mut added: Vec<Assigned> = Vec::with_capacity(additions.len());
        let mut taken = BTreeSet::new();
        for &element in additions {
            // Add step 1, for the elements before this one in the batch as well. Erratum
            // (Construction 4.2, p. 22): step 1 parses (Op, i) := D_X[x] even when D_X[x] = ⊥,
            // which leaves i undefined; an element never added starts at i = 0.
            let start = match self.entries.get(&element) {
                Some(Record {
                    operation: Operation::Add,
                    ..
                }) => return Err(Error::ElementAlreadyAdded),
                Some(Record { epoch, .. }) => *epoch,
                None => 0,
            };
            if added.iter().any(|a| a.element == element) {
                return Err(Error::ElementAlreadyAdded);
            }
            let (index, handle) = self.fresh_handle(key, &element, start, &taken)?;
            let _ = taken.insert(handle.clone());
            added.push(Assigned {
                element,
                index,
                handle,
            });
        }
        let deleted = deletions
            .iter()
            .map(|&element| {
                let (index, handle) = match added.iter().find(|a| a.element == element) {
                    Some(a) => (a.index, a.handle.clone()),
                    None => match self.entries.get(&element) {
                        Some(Record {
                            operation: Operation::Add,
                            epoch,
                        }) => (*epoch, key.handle(&element, *epoch)),
                        _ => return Err(Error::ElementNotPresent),
                    },
                };
                Ok(Assigned {
                    element,
                    index,
                    handle,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let handles = |assigned: &[Assigned]| -> Vec<Handle> {
            assigned.iter().map(|a| a.handle.clone()).collect()
        };
        let coefficients = value.update_assign(
            key.inner(),
            &handles(&added),
            &handles(&deleted),
            &mut self.inner,
        )?;
        for a in added {
            let record = Record {
                operation: Operation::Add,
                epoch: a.index,
            };
            let _ = self.entries.insert(a.element, record);
        }
        for a in deleted {
            // Delete step 4: D_X[x] := (Del, i + 1).
            let record = Record {
                operation: Operation::Del,
                epoch: a.index.saturating_add(1),
            };
            let _ = self.entries.insert(a.element, record);
        }
        self.tag = tag(key, &self.inner, &self.entries);
        Ok(coefficients)
    }

    /// Add steps 2 and 3: the first index `i ≥ start` whose handle `F_k(x, i)` the inner
    /// accumulator has never seen and that is not `taken` earlier in the batch. Fails with
    /// [`Error::HandleSpaceExhausted`] when all `2^ℓ` handles are used, since the loop would
    /// then never end.
    fn fresh_handle(
        &self,
        key: &SecretKey,
        x: &Element,
        start: u64,
        taken: &BTreeSet<Handle>,
    ) -> Result<(u64, Handle)> {
        let used = self.inner.recorded() + taken.len();
        // `None` when `2^ℓ` exceeds `usize`, and no state can hold that many handles.
        let capacity = 1usize.checked_shl(key.params().spec().element_bits);
        if capacity.is_some_and(|capacity| used >= capacity) {
            return Err(Error::HandleSpaceExhausted);
        }
        let mut index = start;
        loop {
            let handle = key.handle(x, index);
            if self.inner.record(&handle).is_none() && !taken.contains(&handle) {
                return Ok((index, handle));
            }
            index = index.checked_add(1).ok_or(Error::HandleSpaceExhausted)?;
        }
    }
}

/// The index `i` with `handle = F_k(x, i)` that the addition rule can give `x`: every earlier
/// index's handle must be `seen`, deleted or held by another member, since the rule skips
/// exactly those. The search stops, as an addition's does, when the index would overflow, and
/// at the first earlier handle that is not `seen`, which is [`Error::InconsistentState`].
fn handle_index(
    key: &SecretKey,
    x: &Element,
    handle: &Handle,
    seen: impl Fn(&Handle) -> bool,
) -> Result<u64> {
    let mut index = 0u64;
    loop {
        let candidate = key.handle(x, index);
        if candidate == *handle {
            return Ok(index);
        }
        if !seen(&candidate) {
            return Err(Error::InconsistentState);
        }
        index = index.checked_add(1).ok_or(Error::InconsistentState)?;
    }
}

/// The tag of an adaptive state made of `inner` and `entries` under `key`, as the
/// [`ManagerState`] documentation describes.
fn tag(key: &SecretKey, inner: &InnerState, entries: &BTreeMap<Element, Record>) -> StateTag {
    let dictionary = encode_dictionary(entries.iter().map(|(x, r)| (x.as_bytes(), r)));
    inner.mac(
        DomainLabel::from(LABEL_TAG),
        key.state_mac_key(),
        &[inner.tag().as_bytes(), &dictionary],
    )
}

#[cfg(test)]
mod tests {
    use super::{ManagerState, Operation, Record};
    use crate::{
        accumulator::{Coefficient, Element as Handle},
        adaptive::{Accumulator, Element, MembershipWitness, SecretKey},
        error::Error,
        state::tests::tamperings,
        test_util::TOY,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::{Arc, LazyLock};

    static KEY: LazyLock<SecretKey> =
        LazyLock::new(|| key(b"kln/test/adaptive-state-tag, 32 bytes"));
    static OTHER: LazyLock<SecretKey> = LazyLock::new(|| key(b"kln/test/adaptive-state-tag/other"));

    fn key(seed: &[u8]) -> SecretKey {
        SecretKey::new(
            Some(seed),
            Arc::new(TOY.clone()),
            &mut StdRng::seed_from_u64(0),
        )
        .unwrap()
    }

    fn element(i: u8) -> Element {
        Element::hash(&[i])
    }

    /// A state under `key` after adding 1, 2 and 3, deleting 2 and adding 2 again: records of
    /// both operations, and an inner state with a deletion.
    fn honest(key: &SecretKey) -> (Accumulator, ManagerState) {
        let (mut value, mut state) =
            Accumulator::with_elements(key, &[element(1), element(2), element(3)]).unwrap();
        value.remove_assign(key, &element(2), &mut state).unwrap();
        value.add_assign(key, &element(2), &mut state).unwrap();
        value.remove_assign(key, &element(3), &mut state).unwrap();
        (value, state)
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

    /// C51: altering any single field of the inner state, which keeps its own tag, is refused.
    #[test]
    fn every_altered_inner_field_is_refused() {
        let (value, state) = honest(&KEY);
        assert!(state.authenticate(&KEY).is_ok());
        for (what, inner) in tamperings(&state.inner) {
            let altered = ManagerState {
                inner,
                ..state.clone()
            };
            assert_refused(&value, &altered, &KEY, what);
        }
    }

    /// C51: altering any single field of the adaptive state's own dictionary or its tag is
    /// refused.
    #[test]
    fn every_altered_field_is_refused() {
        let (value, state) = honest(&KEY);
        let alter = |change: &dyn Fn(&mut ManagerState)| {
            let mut altered = state.clone();
            change(&mut altered);
            assert_ne!(altered, state);
            altered
        };
        let first = *state.entries.keys().next().unwrap();
        let tampered = [
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
                    let record = Record {
                        operation: Operation::Add,
                        epoch: 0,
                    };
                    let _ = s.entries.insert(element(200), record);
                }),
            ),
            (
                "removed entry",
                alter(&|s| {
                    let _ = s.entries.remove(&first);
                }),
            ),
            (
                "tag",
                alter(&|s| {
                    let inner = s.inner.clone();
                    s.tag = super::tag(&OTHER, &inner, &s.entries);
                }),
            ),
        ];
        for (what, altered) in &tampered {
            assert_refused(&value, altered, &KEY, what);
        }
    }

    /// C71: the public tag check accepts the honest state under its key, and refuses it under
    /// another key and after any single-field alteration of the inner state, changing nothing.
    #[test]
    fn authenticate_checks_the_tag_and_changes_nothing() {
        let (_, state) = honest(&KEY);
        let before = state.clone();
        assert_eq!(state.authenticate(&KEY), Ok(()));
        assert_eq!(state.authenticate(&OTHER), Err(Error::InvalidStateTag));
        for (what, inner) in tamperings(&state.inner) {
            let altered = ManagerState {
                inner,
                ..state.clone()
            };
            assert_eq!(
                altered.authenticate(&KEY),
                Err(Error::InvalidStateTag),
                "{what}"
            );
        }
        assert_eq!(state, before);
    }

    /// C68: the inner state records the value every keyed update leaves.
    #[test]
    fn the_current_value_follows_every_update() {
        let (value, state) = honest(&KEY);
        assert_eq!(state.inner.current(), value.inner());
        assert_ne!(
            state.inner.current(),
            &crate::accumulator::Accumulator::new(KEY.inner())
        );
    }

    /// C51: a state tagged under another key is refused, and the honest state under its own key
    /// is not.
    #[test]
    fn a_state_of_another_key_is_refused() {
        let (value, state) = honest(&OTHER);
        assert_refused(&value, &state, &KEY, "other key");
        assert!(MembershipWitness::new(&element(1), &value, &OTHER, &state).is_ok());
    }

    /// An inner state taken from another adaptive state of the same key, with a valid inner
    /// tag, is still refused: the outer tag covers the inner state.
    #[test]
    fn a_swapped_inner_state_is_refused() {
        let (value, state) = honest(&KEY);
        let fresh = ManagerState::new(&KEY);
        let altered = ManagerState {
            inner: fresh.inner.clone(),
            ..state.clone()
        };
        assert!(altered.inner.authenticate(KEY.inner()).is_ok());
        assert_refused(&value, &altered, &KEY, "swapped inner state");
    }

    /// With a log naming all `2^ℓ` handles of the toy set, a member record whose handle is two
    /// bytes long is refused as malformed instead of starting an index search that every
    /// candidate handle would prolong.
    #[test]
    fn rebuild_refuses_a_malformed_handle_under_a_saturated_log() {
        let log: Vec<Coefficient> = (0..=u8::MAX)
            .map(|i| Coefficient::from(Handle::try_from([i].as_slice()).unwrap()))
            .collect();
        let malformed = Handle::try_from([0u8, 0].as_slice()).unwrap();
        assert_eq!(
            ManagerState::rebuild(&KEY, &log, &[(element(1), malformed)]),
            Err(Error::InvalidElement)
        );
    }
}
