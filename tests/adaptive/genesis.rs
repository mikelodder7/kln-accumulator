// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adaptive inner witnesses do not depend on the state's history: the inner witness for a handle
//! is sampled for the inner genesis value and corrected for the deleted handles, and the
//! signature is deterministic. Over elements whose first handles are distinct, handle
//! assignment does not depend on the order of additions either, so the order of deletions, the
//! epoch of an addition, forks, older copies and rebuilt states all give the same witness; with
//! re-additions and collisions a fork may assign another handle, and then the inner witness for
//! every handle is still the same everywhere.

use crate::fixture::{KEY, TOY};
use kln_accumulator::{
    Coefficient, Element as Handle, Error, MembershipWitness as InnerWitness, Operation,
    adaptive::{Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey},
};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

/// Twelve elements whose first handles under [`KEY`] are distinct, so that in a history over them
/// in which nothing is added twice every element gets its first handle, whatever the order:
/// each is added to one state in turn and kept if it got PRF index 0.
static UNIVERSE: LazyLock<Vec<Element>> = LazyLock::new(|| {
    let (mut value, mut state) = (Accumulator::new(&KEY), ManagerState::new(&KEY));
    (0u8..=255)
        .map(|i| Element::hash(&[i]))
        .filter(|x| {
            value.add_assign(&KEY, x, &mut state).is_ok()
                && state.record(x).is_some_and(|r| r.epoch == 0)
        })
        .take(12)
        .collect()
});

/// Element `i` of [`UNIVERSE`].
fn element(i: u8) -> Element {
    UNIVERSE[usize::from(i)]
}

/// A value, its state, the update messages its deletions published, and its members.
#[derive(Clone)]
struct Run {
    value: Accumulator,
    state: ManagerState,
    log: Vec<Coefficient>,
    members: BTreeSet<u8>,
}

impl Run {
    /// The key's accumulator at its genesis value.
    fn fresh(key: &SecretKey) -> Self {
        Self {
            value: Accumulator::new(key),
            state: ManagerState::new(key),
            log: Vec::new(),
            members: BTreeSet::new(),
        }
    }

    /// Adds `i` if it was never added and deletes it if it is present.
    fn step(&mut self, key: &SecretKey, i: u8) {
        let x = element(i);
        if self
            .state
            .record(&x)
            .is_none_or(|r| r.operation == Operation::Del)
        {
            self.value
                .add_assign(key, &x, &mut self.state)
                .expect("test fixture");
            let _ = self.members.insert(i);
        } else {
            let mut log = self
                .value
                .update_assign(key, &[], &[x], &mut self.state)
                .expect("test fixture");
            self.log.append(&mut log);
            let _ = self.members.remove(&i);
        }
    }

    /// The records `(element, handle)` of the members, read from their witnesses.
    fn records(&self, key: &SecretKey) -> Vec<(Element, Handle)> {
        self.members
            .iter()
            .map(|&i| (element(i), self.witness(key, i).handle().clone()))
            .collect()
    }

    /// The witness of `i`, which must verify against the value.
    fn witness(&self, key: &SecretKey, i: u8) -> MembershipWitness {
        let x = element(i);
        let witness =
            MembershipWitness::new(&x, &self.value, key, &self.state).expect("test fixture");
        assert!(witness.verify(&x, &PublicKey::from(key), &self.value));
        witness
    }
}

/// Members and deleted elements, drawn from `0..12`, with two schedules of the same operations
/// (each member added once, each deleted element added and later deleted), a point at which
/// to copy the state, and the member whose witness is compared.
#[derive(Clone, Debug)]
struct Histories {
    members: Vec<u8>,
    first: Vec<u8>,
    second: Vec<u8>,
    copy_at: usize,
    target: u8,
}

/// A schedule lists a member once and a deleted element twice: its first appearance adds it,
/// its second deletes it.
fn histories() -> impl Strategy<Value = Histories> {
    (
        prop::sample::subsequence((0u8..12).collect::<Vec<_>>(), 1..8),
        any::<prop::sample::Index>(),
    )
        .prop_flat_map(|(chosen, split)| {
            let cut = 1 + split.index(chosen.len());
            let (members, deleted) = chosen.split_at(cut);
            let schedule: Vec<u8> = members
                .iter()
                .chain(deleted)
                .chain(deleted)
                .copied()
                .collect();
            let len = schedule.len();
            (
                Just(members.to_vec()),
                Just(schedule.clone()).prop_shuffle(),
                Just(schedule).prop_shuffle(),
                0..=len,
                prop::sample::select(members.to_vec()),
            )
        })
        .prop_map(|(members, first, second, copy_at, target)| Histories {
            members,
            first,
            second,
            copy_at,
            target,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// For random histories the witness of a member is byte-identical whatever the order of
    /// the same deletions and wherever the member's addition falls among them; from a fork that
    /// reaches the same deletions in another order; from an older serialized copy of the state
    /// brought forward through the same operations in one batch; and from a state rebuilt from
    /// the log. Every one of them verifies against the value.
    #[test]
    fn witnesses_depend_on_the_set_of_deletions_only(h in histories()) {
        let key = &*KEY;
        let mut first = Run::fresh(key);
        let mut copy = None;
        for (at, &i) in h.first.iter().enumerate() {
            if at == h.copy_at {
                copy = Some(serde_json::to_string(&(&first.value, &first.state)).unwrap());
            }
            first.step(key, i);
        }
        let copy = copy.unwrap_or_else(|| serde_json::to_string(&(&first.value, &first.state)).unwrap());
        let mut second = Run::fresh(key);
        for &i in &h.second {
            second.step(key, i);
        }
        let issued = first.witness(key, h.target);
        prop_assert_eq!(&second.value, &first.value);
        prop_assert_eq!(&second.witness(key, h.target), &issued);

        // The older copy, brought forward: every addition it has not seen, then every deletion.
        let (mut value, mut state): (Accumulator, ManagerState) = serde_json::from_str(&copy).unwrap();
        let everyone: BTreeSet<u8> = h.first.iter().copied().collect();
        let additions: Vec<_> = everyone.iter().map(|&i| element(i)).filter(|x| state.record(x).is_none()).collect();
        let deletions: Vec<_> = everyone
            .iter()
            .filter(|i| !h.members.contains(i))
            .map(|&i| element(i))
            .filter(|x| state.record(x).is_none_or(|r| r.operation == Operation::Add))
            .collect();
        let _ = value.update_assign(key, &additions, &deletions, &mut state).unwrap();
        prop_assert_eq!(&value, &first.value);
        prop_assert_eq!(&MembershipWitness::new(&element(h.target), &value, key, &state).unwrap(), &issued);

        // A state rebuilt from the log, in reverse order, and the member records.
        let mut log = first.log.clone();
        log.reverse();
        let (value, rebuilt) = ManagerState::rebuild(key, &log, &first.records(key)).unwrap();
        prop_assert_eq!(&value, &first.value);
        prop_assert_eq!(&MembershipWitness::new(&element(h.target), &value, key, &rebuilt).unwrap(), &issued);
    }
}

/// One public call in [`no_two_inner_witnesses_for_one_handle_and_value`]'s programs. Slots index a
/// pool of runs, taken modulo its length.
#[derive(Clone, Debug)]
enum Call {
    /// Adds an element in a slot.
    Add(u8, usize),
    /// Deletes an element in a slot.
    Remove(u8, usize),
    /// Issues a witness in a slot.
    Issue(u8, usize),
    /// Copies a slot into a new one: a fork.
    Fork(usize),
    /// A fresh state for the key, in a new slot.
    Fresh,
    /// Serializes a slot.
    Save(usize),
    /// Deserializes a saved copy into a new slot: an older state, rolled back to.
    Restore(usize),
    /// Rebuilds a slot from its log and members into a new slot.
    Rebuild(usize),
}

fn call() -> impl Strategy<Value = Call> {
    let element = 0u8..8;
    let slot = 0usize..4;
    prop_oneof![
        4 => (element.clone(), slot.clone()).prop_map(|(e, s)| Call::Add(e, s)),
        3 => (element.clone(), slot.clone()).prop_map(|(e, s)| Call::Remove(e, s)),
        4 => (element, slot.clone()).prop_map(|(e, s)| Call::Issue(e, s)),
        1 => slot.clone().prop_map(Call::Fork),
        1 => Just(Call::Fresh),
        1 => slot.clone().prop_map(Call::Save),
        1 => (0usize..4).prop_map(Call::Restore),
        1 => slot.prop_map(Call::Rebuild),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Under one key, no sequence of public calls makes the key sample twice for one target:
    /// every inner witness issued for one handle against one value is the same, and every
    /// signature over one element and one handle is the same. A fork may give an element
    /// another handle than the original did; that is a different handle, not a second sample. A program runs adds, deletes and witness issuance on
    /// a pool of states that it forks, starts fresh, saves and rolls back to, and rebuilds;
    /// refused calls are skipped. Every witness issued must verify, must equal every other
    /// witness issued for the same element against the same value, and must equal the witness
    /// that a state rebuilt from nothing but that run's deletions issues: a witness is a
    /// function of the key, the element and the set of deletions.
    #[test]
    fn no_two_inner_witnesses_for_one_handle_and_value(program in prop::collection::vec(call(), 1..30)) {
        let key = &*KEY;
        let public = PublicKey::from(key);
        let mut pool = vec![Run::fresh(key)];
        let mut saved: Vec<String> = Vec::new();
        let mut inner: BTreeMap<(Handle, Vec<u8>), InnerWitness> = BTreeMap::new();
        let mut signed: BTreeMap<(u8, Handle), Vec<u8>> = BTreeMap::new();
        for call in program {
            let len = pool.len();
            match call {
                Call::Add(i, s) => {
                    let run = &mut pool[s % len];
                    if run.value.add_assign(key, &element(i), &mut run.state).is_ok() {
                        let _ = run.members.insert(i);
                    }
                }
                Call::Remove(i, s) => {
                    let run = &mut pool[s % len];
                    if let Ok(mut log) = run.value.update_assign(key, &[], &[element(i)], &mut run.state) {
                        run.log.append(&mut log);
                        let _ = run.members.remove(&i);
                    }
                }
                Call::Issue(i, s) => {
                    let run = &pool[s % len];
                    let x = element(i);
                    if let Ok(witness) = MembershipWitness::new(&x, &run.value, key, &run.state) {
                        prop_assert!(witness.verify(&x, &public, &run.value));
                        let deleted: Vec<_> = run.log.iter().map(|c| c.element().clone()).collect();
                        prop_assert!(!deleted.contains(witness.handle()));
                        let (value, again) = ManagerState::rebuild(key, &run.log, &run.records(key)).unwrap();
                        prop_assert_eq!(&value, &run.value);
                        prop_assert_eq!(&MembershipWitness::new(&x, &value, key, &again).unwrap(), &witness);
                        let handle = witness.handle().clone();
                        let earlier = inner
                            .entry((handle.clone(), run.value.to_bytes()))
                            .or_insert_with(|| witness.inner().clone());
                        prop_assert_eq!(&*earlier, witness.inner());
                        let signature = signed.entry((i, handle)).or_insert_with(|| witness.signature().to_vec());
                        prop_assert_eq!(&signature[..], witness.signature());
                    }
                }
                Call::Fork(s) => {
                    let run = pool[s % len].clone();
                    pool.push(run);
                }
                Call::Fresh => pool.push(Run::fresh(key)),
                Call::Save(s) => {
                    let run = &pool[s % len];
                    saved.push(serde_json::to_string(&(&run.value, &run.state, &run.log, &run.members)).unwrap());
                }
                Call::Restore(k) => {
                    if let Some(copy) = saved.get(k % saved.len().max(1)) {
                        let (value, state, log, members) = serde_json::from_str(copy).unwrap();
                        pool.push(Run { value, state, log, members });
                    }
                }
                Call::Rebuild(s) => {
                    let run = &pool[s % len];
                    let (value, state) = ManagerState::rebuild(key, &run.log, &run.records(key)).unwrap();
                    prop_assert_eq!(&value, &run.value);
                    let log = run.log.clone();
                    let members = run.members.clone();
                    pool.push(Run { value, state, log, members });
                }
            }
        }
    }
}

/// A lost state is rebuilt from the key, the published log of deleted handles in any order
/// and the member records, including an element that was deleted and added again: the value
/// equals the lost one, and every witness the rebuilt state issues equals the one the lost
/// state issued, handle and signature included.
#[test]
fn a_lost_state_is_rebuilt_from_the_log() {
    let key = &*KEY;
    let mut lost = Run::fresh(key);
    for i in [1, 2, 3, 4, 5, 2, 6, 4, 7, 2] {
        lost.step(key, i);
    }
    assert!(lost.members.contains(&2));
    let mut log = lost.log.clone();
    log.rotate_left(1);
    let (value, rebuilt) = ManagerState::rebuild(key, &log, &lost.records(key)).unwrap();
    assert_eq!(value, lost.value);
    assert_eq!(rebuilt.inner().counter(), lost.state.inner().counter());
    for &i in &lost.members {
        assert_eq!(
            MembershipWitness::new(&element(i), &value, key, &rebuilt).unwrap(),
            lost.witness(key, i)
        );
    }
}

/// A rebuild is refused for a log that names a handle twice, a member listed twice, a member
/// whose handle was deleted, and a handle that is not one the addition rule gives the element.
#[test]
fn malformed_rebuilds_are_refused() {
    let key = &*KEY;
    let mut run = Run::fresh(key);
    for i in [1, 2, 3, 2, 3] {
        run.step(key, i);
    }
    let records = run.records(key);
    let twice: Vec<_> = [&run.log[..], &run.log[..1]].concat();
    let rebuild = |log: &[Coefficient], records: &[(Element, Handle)]| {
        ManagerState::rebuild(key, log, records).map(drop)
    };
    assert_eq!(rebuild(&twice, &records), Err(Error::ElementNotPresent));
    assert_eq!(rebuild(&run.log, &records), Ok(()));
    let doubled = [records[0].clone(), records[0].clone()];
    assert_eq!(rebuild(&run.log, &doubled), Err(Error::ElementAlreadyAdded));
    let deleted = [(element(1), run.log[0].element().clone())];
    assert_eq!(rebuild(&run.log, &deleted), Err(Error::ElementAlreadyAdded));
    // A handle that is neither deleted nor element 1's own.
    let used: BTreeSet<Handle> = run.log.iter().map(|c| c.element().clone()).collect();
    let other = (0u8..=255)
        .map(|b| Handle::try_from(&[b][..]).unwrap())
        .find(|h| !used.contains(h) && *h != records[0].1)
        .unwrap();
    assert_eq!(
        rebuild(&run.log, &[(element(1), other)]),
        Err(Error::InconsistentState)
    );
}

/// Every state starts from the key's genesis value, which is the inner key's, and a keyed
/// operation refuses any other starting value.
#[test]
fn every_state_starts_at_the_genesis_value() {
    let key = &*KEY;
    let genesis = Accumulator::new(key);
    assert_eq!(
        ManagerState::new(key).inner().current(),
        &kln_accumulator::Accumulator::from(genesis.clone())
    );
    assert_eq!(Accumulator::with_elements(key, &[]).unwrap().0, genesis);
    let other = SecretKey::new(
        Some(b"kln/test/genesis, another adaptive manager"),
        Arc::clone(&TOY),
        &mut crate::fixture::rng(0),
    )
    .unwrap();
    assert_ne!(Accumulator::new(&other), genesis);
    let mut random = Accumulator::random(&mut crate::fixture::rng(1), &TOY);
    let mut state = ManagerState::new(key);
    let before = state.clone();
    assert_eq!(
        random.add_assign(key, &element(1), &mut state),
        Err(Error::AccumulatorMismatch)
    );
    assert_eq!(state, before);
}

/// The adaptive witness bytes (handle, signature and inner witness) for a fixed key, element
/// and deletion are pinned, with those of the public key and of the value after the deletion;
/// see the base suite's test of the same name for why.
#[test]
fn the_witness_bytes_are_pinned() {
    use sha3::{Digest, Sha3_256};
    let key = &*KEY;
    let (x, y) = (element(0), element(1));
    let (mut value, mut state) = Accumulator::with_elements(key, &[x, y]).unwrap();
    let _ = value.update_assign(key, &[], &[y], &mut state).unwrap();
    let witness = MembershipWitness::new(&x, &value, key, &state).unwrap();
    let digest = Sha3_256::digest(witness.to_bytes().unwrap().as_slice());
    assert_eq!(
        hex::encode(digest),
        "74752430d79dc7ad79e7b2d57153a4689589152761628e6b150788704e30c9a4"
    );
    let public = Sha3_256::digest(PublicKey::from(key).to_bytes().as_slice());
    assert_eq!(
        hex::encode(public),
        "fa14b2545944e337722d3b9e0dadce83835aa6aa5f177edec459f65e64affafb"
    );
    let value = Sha3_256::digest(value.to_bytes().as_slice());
    assert_eq!(
        hex::encode(value),
        "cb88389bdfbd92c81d1109968225d5553adc9a65b73dc46501c75ef619cfc60a"
    );
}
