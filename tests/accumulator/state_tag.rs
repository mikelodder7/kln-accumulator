// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tag that binds a manager state to its secret key (C51), through the public API: states
//! altered in their serialized form, states of another key, and an honest state carried through
//! serialization; the public tag check (C71); and the current value the state records, which
//! every keyed operation requires (C68).

use crate::fixture::{KEY, Manager, TOY, element, rng};
use kln_accumulator::{
    Accumulator, Error, ManagerState, MembershipWitness, Operation, Record, SecretKey,
};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};

/// A second toy-set key.
static OTHER: LazyLock<SecretKey> = LazyLock::new(|| {
    SecretKey::new(
        Some(b"kln/test/key/other, a 32-byte seed"),
        Arc::clone(&TOY),
        &mut rng(0),
    )
    .expect("test fixture")
});

/// A manager under `key` after adding 1, 2, 3 and 4, deleting 2 and 4, and adding 5: `ctr = 2`,
/// with element 5 added at epoch 2.
fn sample(key: &'static SecretKey) -> Manager<'static> {
    let mut manager = Manager::new(key);
    for i in 1..=4 {
        let _ = manager.add(&element(i));
    }
    let _ = manager.remove(&element(2));
    let _ = manager.remove(&element(4));
    let _ = manager.add(&element(5));
    manager
}

/// Every keyed operation refuses `value` and `state` under `key` with `error`, and neither the
/// value nor the state changes.
fn assert_refused_with(
    value: &Accumulator,
    state: &ManagerState,
    key: &SecretKey,
    error: Error,
    what: &str,
) {
    let refused = Err(error);
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

/// [`assert_refused_with`] for [`Error::InvalidStateTag`].
fn assert_refused(value: &Accumulator, state: &ManagerState, key: &SecretKey, what: &str) {
    assert_refused_with(value, state, key, Error::InvalidStateTag, what);
}

/// `state` decoded from its JSON form after `change`.
fn decode_altered(
    state: &ManagerState,
    change: impl FnOnce(&mut Value),
) -> serde_json::Result<ManagerState> {
    let mut json = serde_json::to_value(state).expect("serde");
    change(&mut json);
    serde_json::from_value(json)
}

/// A change to the JSON form of a state.
type Alteration = Box<dyn FnOnce(&mut Value)>;

/// The hex key of `element(i)` in the JSON dictionary.
fn key_of(i: u8) -> String {
    hex::encode([i])
}

/// C51: every alteration of the serialized state that deserialization lets through is refused
/// by every keyed operation; the alterations of the counter and of an operation alone break
/// the history and are refused when decoding.
#[test]
fn altered_serialized_states_are_refused() {
    let manager = sample(&KEY);
    let state = &manager.state;
    let other_current = serde_json::to_value(Accumulator::random(&mut rng(98), &TOY)).unwrap();
    let genesis_as_current = serde_json::to_value(Accumulator::new(&KEY)).unwrap();
    let alterations: [(&str, Alteration); 8] = [
        (
            "current value",
            Box::new(move |j| j["current"] = other_current),
        ),
        (
            "current value set back to the genesis value",
            Box::new(move |j| j["current"] = genesis_as_current),
        ),
        (
            "epoch of a late addition",
            Box::new(|j| j["entries"][key_of(5)]["epoch"] = json!(1)),
        ),
        (
            "deletion epochs swapped",
            Box::new(|j| {
                j["entries"][key_of(2)]["epoch"] = json!(2);
                j["entries"][key_of(4)]["epoch"] = json!(1);
            }),
        ),
        (
            "added entry",
            Box::new(|j| j["entries"][key_of(10)] = json!({"operation": "Add", "epoch": 0})),
        ),
        (
            "removed entry",
            Box::new(|j| {
                let _ = j["entries"]
                    .as_object_mut()
                    .expect("object")
                    .remove(&key_of(3));
            }),
        ),
        (
            "tag",
            Box::new(|j| {
                let tag = j["tag"].as_str().expect("hex").to_owned();
                let flipped = if tag.starts_with('0') { "1" } else { "0" };
                j["tag"] = json!(format!("{flipped}{}", &tag[1..]));
            }),
        ),
        (
            "tag of the empty state",
            Box::new(|j| {
                let empty = ManagerState::new(&KEY);
                j["tag"] = serde_json::to_value(&empty).unwrap()["tag"].clone();
            }),
        ),
    ];
    for (what, change) in alterations {
        let altered = decode_altered(state, change).expect(what);
        assert_ne!(altered, *state, "{what}");
        assert_refused(&manager.value, &altered, &KEY, what);
    }
    let counter = decode_altered(state, |j| j["counter"] = json!(3));
    assert!(counter.is_err());
    let operation = decode_altered(state, |j| {
        j["entries"][key_of(1)]["operation"] = json!("Del");
    });
    assert!(operation.is_err());
}

/// C51: a state tagged under another key is refused by every keyed operation of this key, and
/// still works under its own.
#[test]
fn a_state_of_another_key_is_refused() {
    let manager = sample(&OTHER);
    assert_refused(&manager.value, &manager.state, &KEY, "other key");
    assert!(MembershipWitness::new(&element(1), &manager.value, &OTHER, &manager.state).is_ok());
}

/// C51: an honest state passes through serialization in a binary and a human-readable format
/// with its tag, and then issues the same witnesses and accepts further additions and
/// deletions.
#[test]
fn an_honest_state_survives_serialization() {
    let manager = sample(&KEY);
    let decoded = [
        serde_json::from_str::<ManagerState>(&serde_json::to_string(&manager.state).unwrap())
            .unwrap(),
        postcard::from_bytes::<ManagerState>(&postcard::to_stdvec(&manager.state).unwrap())
            .unwrap(),
    ];
    for state in decoded {
        assert_eq!(state, manager.state);
        for i in [1, 3, 5] {
            let witness =
                MembershipWitness::new(&element(i), &manager.value, &KEY, &state).unwrap();
            assert_eq!(
                witness.to_bytes().unwrap(),
                manager.witness(&element(i)).to_bytes().unwrap()
            );
        }
        let (mut value, mut state) = (manager.value.clone(), state);
        value.add_assign(&KEY, &element(6), &mut state).unwrap();
        value.remove_assign(&KEY, &element(1), &mut state).unwrap();
        assert_eq!(
            state.record(&element(1)),
            Some(Record {
                operation: Operation::Del,
                epoch: 3
            })
        );
        let witness = MembershipWitness::new(&element(6), &value, &KEY, &state).unwrap();
        assert!(witness.verify(&element(6), &manager.public, &value));
    }
}

/// C71: the public tag check accepts the honest state under its key, and refuses a state of
/// another key and every serialized alteration the tag covers, changing nothing.
#[test]
fn authenticate_checks_the_tag_alone() {
    let manager = sample(&KEY);
    let state = manager.state.clone();
    assert_eq!(state.authenticate(&KEY), Ok(()));
    assert_eq!(state.authenticate(&OTHER), Err(Error::InvalidStateTag));
    let other_current = serde_json::to_value(Accumulator::random(&mut rng(98), &TOY)).unwrap();
    let altered = decode_altered(&state, |j| j["current"] = other_current).unwrap();
    assert_eq!(altered.authenticate(&KEY), Err(Error::InvalidStateTag));
    assert_eq!(state, manager.state);
}

/// C68: every keyed operation refuses a value that is not the state's current one, with
/// `AccumulatorMismatch` and nothing changed: an unrelated value of the same set, the initial
/// value, and the value from before the last deletion. The current value still works.
#[test]
fn values_that_are_not_current_are_refused() {
    let mut manager = sample(&KEY);
    let stale = manager.value.clone();
    let _ = manager.remove(&element(3));
    let unrelated = Accumulator::random(&mut rng(97), &TOY);
    let initial = Accumulator::new(&KEY);
    assert_eq!(manager.state.current(), &manager.value);
    for (what, value) in [
        ("unrelated value", &unrelated),
        ("initial value", &initial),
        ("value before the last deletion", &stale),
    ] {
        assert_ne!(*value, manager.value, "{what}");
        assert_refused_with(
            value,
            &manager.state,
            &KEY,
            Error::AccumulatorMismatch,
            what,
        );
    }
    let (mut value, mut state) = (manager.value.clone(), manager.state.clone());
    value.add_assign(&KEY, &element(9), &mut state).unwrap();
    value.remove_assign(&KEY, &element(1), &mut state).unwrap();
    assert_eq!(state.current(), &value);
    assert!(MembershipWitness::new(&element(9), &value, &KEY, &state).is_ok());
}
