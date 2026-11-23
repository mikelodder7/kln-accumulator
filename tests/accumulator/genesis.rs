// SPDX-License-Identifier: MIT OR Apache-2.0
//! Witnesses are sampled for the key's genesis value and corrected for the set of deletions,
//! so they do not depend on the state's history: the order of deletions, the epoch of an
//! addition, forks, older copies and rebuilt states all give the same witness.

use crate::fixture::{KEY, TOY, element, with_bound};
use kln_accumulator::{
    Accumulator, Coefficient, Error, ManagerState, MembershipWitness, PublicKey, SecretKey,
};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

#[path = "../support/genesis.rs"]
mod harness;
use harness::{Call, Run, call, histories};
use std::sync::Arc;

impl Run {
    /// The witness of `i`, which must verify against the value.
    fn witness(&self, key: &SecretKey, i: u8) -> MembershipWitness {
        let x = element(i);
        let witness =
            MembershipWitness::new(&x, &self.value, key, &self.state).expect("test fixture");
        assert!(witness.verify(&x, &PublicKey::from(key), &self.value));
        witness
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// For random histories the witness of a member is byte-identical whatever the order of
    /// the same deletions and wherever the member's addition falls among them; from a fork that
    /// reaches the same deletions in another order; from an older serialized copy of the state
    /// brought forward through the same operations in one batch; and from a state rebuilt from
    /// the log. Every one of them verifies against the value.
    #[test]
    fn witnesses_depend_on_the_set_of_deletions_only(h in histories(1..8)) {
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
            .filter(|x| state.record(x).is_none_or(|r| r.operation == kln_accumulator::Operation::Add))
            .collect();
        let _ = value.update_assign(key, &additions, &deletions, &mut state).unwrap();
        prop_assert_eq!(&value, &first.value);
        prop_assert_eq!(&MembershipWitness::new(&element(h.target), &value, key, &state).unwrap(), &issued);

        // A state rebuilt from the log, in reverse order, and the members.
        let mut log = first.log.clone();
        log.reverse();
        let members: Vec<_> = h.members.iter().map(|&i| element(i)).collect();
        let (value, rebuilt) = ManagerState::rebuild(key, &log, &members).unwrap();
        prop_assert_eq!(&value, &first.value);
        prop_assert_eq!(&MembershipWitness::new(&element(h.target), &value, key, &rebuilt).unwrap(), &issued);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Under one key, no sequence of public calls yields two different verifying witnesses
    /// for one element against one value. A program runs adds, deletes and witness issuance on
    /// a pool of states that it forks, starts fresh, saves and rolls back to, and rebuilds;
    /// refused calls are skipped. Every witness issued must verify, must equal every other
    /// witness issued for the same element against the same value, and must equal the witness
    /// that a state rebuilt from nothing but that run's deletions issues: a witness is a
    /// function of the key, the element and the set of deletions.
    #[test]
    fn no_two_witnesses_for_one_element_and_value(program in prop::collection::vec(call(), 1..30)) {
        let key = &*KEY;
        let public = PublicKey::from(key);
        let mut pool = vec![Run::fresh(key)];
        let mut saved: Vec<String> = Vec::new();
        let mut issued: BTreeMap<(u8, Vec<u8>), MembershipWitness> = BTreeMap::new();
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
                        let deletions: Vec<_> = run.log.iter().map(|c| c.element().clone()).collect();
                        let (value, alone) = ManagerState::rebuild(key, &run.log, std::slice::from_ref(&x)).unwrap();
                        prop_assert_eq!(&value, &run.value);
                        prop_assert_eq!(&MembershipWitness::new(&x, &value, key, &alone).unwrap(), &witness);
                        prop_assert!(!deletions.contains(&x));
                        let earlier = issued.entry((i, run.value.to_bytes())).or_insert_with(|| witness.clone());
                        prop_assert_eq!(&*earlier, &witness);
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
                    let members: Vec<_> = run.members.iter().map(|&i| element(i)).collect();
                    let (value, state) = ManagerState::rebuild(key, &run.log, &members).unwrap();
                    prop_assert_eq!(&value, &run.value);
                    let log = run.log.clone();
                    let members = run.members.clone();
                    pool.push(Run { value, state, log, members });
                }
            }
        }
    }
}

/// A lost state is rebuilt from the key, the published log in any order and the member
/// list: the value equals the lost one, every witness the rebuilt state issues equals the one
/// the lost state issued, and the deleted elements stay deleted, so re-adding one is refused.
#[test]
fn a_lost_state_is_rebuilt_from_the_log() {
    let key = &*KEY;
    let mut lost = Run::fresh(key);
    for i in [1, 2, 3, 4, 5, 2, 6, 4, 7] {
        lost.step(key, i);
    }
    let members: Vec<_> = lost.members.iter().map(|&i| element(i)).collect();
    let mut log = lost.log.clone();
    log.rotate_left(1);
    let (mut value, mut rebuilt) = ManagerState::rebuild(key, &log, &members).unwrap();
    assert_eq!(value, lost.value);
    assert_eq!(rebuilt.counter(), lost.state.counter());
    for &i in &lost.members {
        assert_eq!(
            MembershipWitness::new(&element(i), &value, key, &rebuilt).unwrap(),
            lost.witness(key, i)
        );
    }
    let before = (value.clone(), rebuilt.clone());
    for i in [2, 4] {
        assert_eq!(
            value.add_assign(key, &element(i), &mut rebuilt),
            Err(Error::ElementAlreadyAdded)
        );
        assert_eq!(
            MembershipWitness::new(&element(i), &value, key, &rebuilt).map(drop),
            Err(Error::ElementNotPresent)
        );
    }
    assert_eq!((value, rebuilt), before);
}

/// A rebuild is refused for a log that names an element twice, a member that is also in
/// the log or is listed twice, and a log with more than `γ` deletions (four, at `γ = 3`).
#[test]
fn malformed_rebuilds_are_refused() {
    let key = &*KEY;
    let mut run = Run::fresh(key);
    for i in [1, 2, 3, 4, 5, 2, 3, 4, 5] {
        run.step(key, i);
    }
    let twice: Vec<_> = [&run.log[..], &run.log[..1]].concat();
    let rebuild = |log: &[Coefficient], members: &[u8]| {
        let members: Vec<_> = members.iter().map(|&i| element(i)).collect();
        ManagerState::rebuild(key, log, &members).map(drop)
    };
    assert_eq!(rebuild(&twice, &[1]), Err(Error::ElementNotPresent));
    assert_eq!(rebuild(&run.log, &[1, 2]), Err(Error::ElementAlreadyAdded));
    assert_eq!(rebuild(&run.log, &[1, 1]), Err(Error::ElementAlreadyAdded));
    assert_eq!(rebuild(&run.log, &[1]), Ok(()));
    let bounded = SecretKey::new(
        Some(b"kln/test/genesis, a bound of three deletions"),
        with_bound(3),
        &mut crate::fixture::rng(0),
    )
    .unwrap();
    assert_eq!(
        ManagerState::rebuild(&bounded, &run.log, &[]).map(drop),
        Err(Error::DeletionBoundReached)
    );
}

/// Every state starts from the key's genesis value. The fresh state and the value agree on
/// it, the same key always gives it, a key of another seed gives another one, and a keyed
/// operation refuses any other starting value, a uniform one from `Accumulator::random`
/// included.
#[test]
fn every_state_starts_at_the_genesis_value() {
    let key = &*KEY;
    let genesis = Accumulator::new(key);
    assert_eq!(ManagerState::new(key).current(), &genesis);
    assert_eq!(Accumulator::with_elements(key, &[]).unwrap().0, genesis);
    let other = SecretKey::new(
        Some(b"kln/test/genesis, another manager"),
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

/// A late element carries every correction. With 255 of the toy set's 256 elements added and
/// deleted (`γ = 256`), the one element left is added last; its witness is the genesis preimage
/// plus 255 corrections, and it still verifies, norm bound included, under both trapdoor
/// distributions.
#[test]
fn a_late_element_after_every_deletion_still_verifies() {
    for key in [&*KEY, &*crate::fixture::ternary::KEY] {
        let early: Vec<_> = (0u8..255).map(element).collect();
        let (mut value, mut state) = Accumulator::with_elements(key, &early).unwrap();
        value
            .remove_elements_assign(key, &early, &mut state)
            .unwrap();
        assert_eq!(state.counter(), 255);
        let late = element(255);
        value.add_assign(key, &late, &mut state).unwrap();
        let witness = MembershipWitness::new(&late, &value, key, &state).unwrap();
        assert!(witness.verify(&late, &PublicKey::from(key), &value));
    }
}

/// Before the first deletion the live value is the genesis value, so a fresh state is accepted
/// with it; it has forgotten the members, which is a policy failure and not a leak: the witness
/// it issues for a member added again is the one the lost state issued.
#[test]
fn a_fresh_state_before_any_deletion_reissues_the_same_witness() {
    let key = &*KEY;
    let x = element(7);
    let (value, lost) = Accumulator::with_elements(key, std::slice::from_ref(&x)).unwrap();
    let issued = MembershipWitness::new(&x, &value, key, &lost).unwrap();
    let mut fresh = ManagerState::new(key);
    let again = value.add(key, &x, &mut fresh).unwrap();
    assert_eq!(again, value);
    assert_eq!(
        MembershipWitness::new(&x, &again, key, &fresh).unwrap(),
        issued
    );
}

/// The witness bytes for a fixed key, element and deletion are pinned. A key has one preimage
/// per element only while the sampler draws the same bits; a change to the sampler, the PRF
/// label or the derivations that moves this digest would hand existing keys a second preimage
/// for elements they already issued, and must not ship for them. The bytes of the key's public
/// key and of the value after the deletion are pinned too, so that another platform can check
/// it derives the same key and value.
#[test]
fn the_witness_bytes_are_pinned() {
    use sha3::{Digest, Sha3_256};
    let key = &*KEY;
    let (x, y) = (element(1), element(2));
    let (mut value, mut state) = Accumulator::with_elements(key, &[x.clone(), y.clone()]).unwrap();
    value.remove_elements_assign(key, &[y], &mut state).unwrap();
    let witness = MembershipWitness::new(&x, &value, key, &state).unwrap();
    let digest = Sha3_256::digest(witness.to_bytes().unwrap().as_slice());
    assert_eq!(
        hex::encode(digest),
        "196177e65e7bda30a4b9ef9034406a3dd6f1f71b16f449a00bbf8ec040926330"
    );
    let public = Sha3_256::digest(PublicKey::from(key).to_bytes().as_slice());
    assert_eq!(
        hex::encode(public),
        "291d5b1f9d1a70ea23b7cde796dd1c5436858895850b82a21b845c3b71c7c272"
    );
    let value = Sha3_256::digest(value.to_bytes().as_slice());
    assert_eq!(
        hex::encode(value),
        "3564408a87efada23dfa8c580688790ffe4e50adc64e11f2b26529e7d290f29e"
    );
}
