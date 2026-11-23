// SPDX-License-Identifier: MIT OR Apache-2.0
//! Handle derivation: the counter loop of Construction 4.2, Add step 3, the bound of `2^ℓ`
//! additions over the life of an accumulator, and what forks and rebuilds do to handles.

use crate::fixture::{KEY, Manager, element};
use kln_accumulator::{
    Coefficient, Element as Handle, Error, Operation,
    adaptive::{Element, ManagerState, MembershipWitness},
};
use std::collections::{BTreeMap, BTreeSet};

/// At `ℓ = 8` there are 256 handles, so 64 additions collide with an earlier handle with
/// probability above 99.9%. The key is fixed, so the outcome is too: some element needs a PRF
/// index above 0, every handle is distinct, and every witness verifies. Adding the same
/// elements in one batch picks the same handles as adding them one at a time.
#[test]
fn colliding_handles_advance_the_counter() {
    let mut manager = Manager::new(&KEY);
    let members: Vec<Element> = (0..64).map(element).collect();
    let witnesses: Vec<MembershipWitness> = members.iter().map(|x| manager.add(x)).collect();
    let indices: Vec<u64> = members
        .iter()
        .map(|x| {
            let record = manager.state.record(x).unwrap();
            assert_eq!(record.operation, Operation::Add);
            record.epoch
        })
        .collect();
    let advanced = indices.iter().filter(|&&i| i > 0).count();
    eprintln!(
        "handles: {advanced} of 64 additions needed a PRF index above 0 (largest {})",
        indices.iter().max().unwrap()
    );
    assert!(advanced > 0);
    let handles: BTreeSet<_> = witnesses.iter().map(|w| w.handle().clone()).collect();
    assert_eq!(handles.len(), members.len());
    for (x, witness) in members.iter().zip(&witnesses) {
        assert!(witness.verify(x, &manager.public, &manager.value));
    }
    let mut batched = Manager::new(&KEY);
    batched
        .value
        .add_elements_assign(&KEY, &members, &mut batched.state)
        .unwrap();
    assert_eq!(batched.state, manager.state);
}

/// Handles are never reused, so after `2^ℓ = 256` additions the next one fails with
/// [`Error::HandleSpaceExhausted`] and changes nothing, including the re-addition of an element
/// whose handle was deleted: a deleted handle stays used.
#[test]
fn exhausting_the_handle_space_is_an_error() {
    let mut manager = Manager::new(&KEY);
    let members: Vec<Element> = (0..=255).map(element).collect();
    manager
        .value
        .add_elements_assign(&KEY, &members, &mut manager.state)
        .unwrap();
    assert_eq!(manager.state.inner().counter(), 0);
    let _ = manager.remove(&members[0]);
    let (value, state) = (manager.value.clone(), manager.state.clone());
    for x in [Element::hash(b"one more"), members[0]] {
        assert_eq!(
            manager.value.add_assign(&KEY, &x, &mut manager.state),
            Err(Error::HandleSpaceExhausted)
        );
        assert_eq!(manager.value, value);
        assert_eq!(manager.state, state);
    }
    let x = &members[200];
    assert!(
        manager
            .witness(x)
            .verify(x, &manager.public, &manager.value)
    );
}

/// Two elements among the first 64 whose first handles collide: added one at a time, the second
/// moves past the handle the first holds.
fn colliding_pair() -> Option<(Element, Element)> {
    let mut manager = Manager::new(&KEY);
    let mut holders = BTreeMap::new();
    for x in (0..64).map(element) {
        let handle = manager.add(&x).handle().clone();
        if manager.state.record(&x).is_some_and(|r| r.epoch > 0) {
            let alone = Manager::new(&KEY).add(&x).handle().clone();
            if let Some(&y) = holders.get(&alone) {
                return Some((y, x));
            }
        }
        let _ = holders.insert(handle, x);
    }
    None
}

/// The records `(element, handle)` of `manager`'s `members`, read from their witnesses.
fn records(manager: &Manager<'_>, members: &[Element]) -> Vec<(Element, Handle)> {
    members
        .iter()
        .map(|x| (*x, manager.witness(x).handle().clone()))
        .collect()
}

/// With a forced collision, the original adds `a` before `b` and a fork adds them in the other
/// order, both after the same deletion of `c`. They reach the same value but give `a` and `b`
/// different live handles: a reproducibility matter, not a leak. The handle `a` holds on the
/// original is the one `b` holds on the fork, and its inner witness is byte-identical on both,
/// since it is a function of the handle and the deleted handles alone. A state rebuilt from the
/// log and either copy's member records reproduces that copy's handles, signatures and inner
/// witnesses exactly.
#[test]
fn inner_witnesses_depend_on_the_handle_alone() {
    let (a, b) = colliding_pair().expect("a colliding pair among 64 elements at ℓ = 8");
    let c = Element::hash(b"deleted first");
    let mut original = Manager::new(&KEY);
    let mut fork = Manager::new(&KEY);
    let _ = original.add(&c);
    let _ = fork.add(&c);
    let log: Vec<Coefficient> = vec![original.remove(&c)];
    let _ = fork.remove(&c);
    for e in [&a, &b] {
        let _ = original.add(e);
    }
    for e in [&b, &a] {
        let _ = fork.add(e);
    }
    assert_eq!(fork.value, original.value);
    let (wa, wb) = (original.witness(&a), original.witness(&b));
    let (fa, fb) = (fork.witness(&a), fork.witness(&b));
    assert_ne!(wa.handle(), fa.handle());
    assert_eq!(wa.handle(), fb.handle());
    assert_eq!(wa.inner(), fb.inner());
    for (x, w) in [(&a, &fa), (&b, &fb), (&a, &wa), (&b, &wb)] {
        assert!(w.verify(x, &original.public, &original.value));
    }
    let members = [a, b];
    for (copy, issued) in [(&original, [&wa, &wb]), (&fork, [&fa, &fb])] {
        let (value, rebuilt) = ManagerState::rebuild(&KEY, &log, &records(copy, &members)).unwrap();
        assert_eq!(value, original.value);
        for (x, w) in members.iter().zip(issued) {
            assert_eq!(
                &MembershipWitness::new(x, &value, &KEY, &rebuilt).unwrap(),
                w
            );
        }
    }
}

/// An element deleted and added again on a rebuilt state gets the handle the lost state would
/// have given it: the rebuild recovers each member's PRF index from its handle. Records with a
/// deleted handle, a handle the element cannot have, or an element twice are refused.
#[test]
fn rebuilt_states_carry_on_as_the_lost_one() {
    let (x, y, z) = (element(1), element(2), element(3));
    let mut lost = Manager::new(&KEY);
    for e in [&x, &y, &z] {
        let _ = lost.add(e);
    }
    let mut log = vec![lost.remove(&x)];
    let _ = lost.add(&x);
    let members = [x, y, z];
    let mut kept = records(&lost, &members);
    let (mut value, mut rebuilt) = ManagerState::rebuild(&KEY, &log, &kept).unwrap();
    assert_eq!(rebuilt.record(&x), lost.state.record(&x));
    // The same deletion and re-addition on both.
    log.push(lost.remove(&x));
    let _ = lost.add(&x);
    let _ = value.update_assign(&KEY, &[], &[x], &mut rebuilt).unwrap();
    value.add_assign(&KEY, &x, &mut rebuilt).unwrap();
    assert_eq!(value, lost.value);
    assert_eq!(
        MembershipWitness::new(&x, &value, &KEY, &rebuilt).unwrap(),
        lost.witness(&x)
    );

    let rebuild = |log: &[Coefficient], records: &[(Element, Handle)]| {
        ManagerState::rebuild(&KEY, log, records).map(drop)
    };
    let mut swapped = kept.clone();
    let (hx, hy) = (swapped[0].1.clone(), swapped[1].1.clone());
    swapped[0].1 = hy;
    swapped[1].1 = hx;
    assert_eq!(rebuild(&log[..1], &swapped), Err(Error::InconsistentState));
    kept[0].1 = log[0].element().clone();
    assert_eq!(rebuild(&log[..1], &kept), Err(Error::ElementAlreadyAdded));
    let twice = records(&lost, &[y, y]);
    assert_eq!(rebuild(&log, &twice), Err(Error::ElementAlreadyAdded));
}
