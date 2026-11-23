// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tags that bind an adaptive manager state and its inner state to the secret key (C51),
//! through the public API; the public tag check (C71); and the current value the inner state
//! records, which every keyed operation requires (C68).

use crate::fixture::{KEY, Manager, TOY, element, rng};
use kln_accumulator::{
    Error,
    adaptive::{Accumulator, Element, ManagerState, MembershipWitness, SecretKey},
};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};

/// A second toy-set adaptive key.
static OTHER: LazyLock<SecretKey> = LazyLock::new(|| {
    SecretKey::new(
        Some(b"kln/test/adaptive-key/other, 32 bytes"),
        Arc::clone(&TOY),
        &mut rng(0),
    )
    .expect("test fixture")
});

/// A manager under `key` after adding 1, 2 and 3, deleting 2, adding 2 again and deleting 3.
fn sample(key: &'static SecretKey) -> Manager<'static> {
    let mut manager = Manager::new(key);
    for i in 1..=3 {
        let _ = manager.add(&element(i));
    }
    let _ = manager.remove(&element(2));
    let _ = manager.add(&element(2));
    let _ = manager.remove(&element(3));
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

/// A change to the JSON form of a state.
type Alteration = Box<dyn FnOnce(&mut Value)>;

/// The hex key of `x` in the JSON dictionary.
fn key_of(x: &Element) -> String {
    hex::encode(x.to_bytes())
}

/// The hex string `tag` with its first digit changed.
fn flipped(tag: &Value) -> Value {
    let tag = tag.as_str().expect("hex");
    let first = if tag.starts_with('0') { "1" } else { "0" };
    json!(format!("{first}{}", &tag[1..]))
}

/// C51: every alteration of the serialized adaptive state, in its own dictionary or tag or in
/// the inner state, that deserialization lets through is refused by every keyed operation.
#[test]
fn altered_serialized_states_are_refused() {
    let manager = sample(&KEY);
    let state = &manager.state;
    let other_current = serde_json::to_value(Accumulator::random(&mut rng(98), &TOY)).unwrap();
    let (two, three) = (key_of(&element(2)), key_of(&element(3)));
    let alterations: [(&str, Alteration); 9] = [
        (
            "operation",
            Box::new(|j| j["entries"][three]["operation"] = json!("Add")),
        ),
        (
            "epoch of a re-added element",
            Box::new(|j| j["entries"][two]["epoch"] = json!(0)),
        ),
        (
            "added entry",
            Box::new(|j| {
                j["entries"][key_of(&element(10))] = json!({"operation": "Add", "epoch": 0});
            }),
        ),
        (
            "removed entry",
            Box::new(|j| {
                let _ = j["entries"]
                    .as_object_mut()
                    .expect("object")
                    .remove(&key_of(&element(1)));
            }),
        ),
        ("tag", Box::new(|j| j["tag"] = flipped(&j["tag"]))),
        (
            "inner tag",
            Box::new(|j| j["inner"]["tag"] = flipped(&j["inner"]["tag"])),
        ),
        (
            "inner current value",
            Box::new(move |j| j["inner"]["current"] = other_current),
        ),
        (
            "inner epoch",
            Box::new(|j| {
                let record = j["inner"]["entries"]
                    .as_object_mut()
                    .expect("object")
                    .values_mut()
                    .find(|r| r["operation"] == "Add")
                    .expect("an added handle");
                let epoch = if record["epoch"] == 0 { 1 } else { 0 };
                record["epoch"] = json!(epoch);
            }),
        ),
        (
            "inner removed entry",
            Box::new(|j| {
                let entries = j["inner"]["entries"].as_object_mut().expect("object");
                let added = entries
                    .iter()
                    .find(|(_, r)| r["operation"] == "Add")
                    .map(|(handle, _)| handle.clone())
                    .expect("an added handle");
                let _ = entries.remove(&added);
            }),
        ),
    ];
    for (what, change) in alterations {
        let mut json = serde_json::to_value(state).unwrap();
        change(&mut json);
        let altered: ManagerState = serde_json::from_value(json).expect(what);
        assert_ne!(altered, *state, "{what}");
        assert_refused(&manager.value, &altered, &KEY, what);
    }
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
/// with both tags, and then issues the same witnesses and accepts further additions and
/// deletions, including the re-addition of a deleted element.
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
        for i in [1, 2] {
            let witness =
                MembershipWitness::new(&element(i), &manager.value, &KEY, &state).unwrap();
            assert_eq!(witness, manager.witness(&element(i)));
        }
        let (mut value, mut state) = (manager.value.clone(), state);
        value.add_assign(&KEY, &element(3), &mut state).unwrap();
        value.remove_assign(&KEY, &element(1), &mut state).unwrap();
        let witness = MembershipWitness::new(&element(3), &value, &KEY, &state).unwrap();
        assert!(witness.verify(&element(3), &manager.public, &value));
    }
}

/// C71: the public tag check accepts the honest state under its key, and refuses a state of
/// another key and a stored state whose inner current value was replaced, changing nothing.
#[test]
fn authenticate_checks_the_tag_alone() {
    let manager = sample(&KEY);
    let state = manager.state.clone();
    assert_eq!(state.authenticate(&KEY), Ok(()));
    assert_eq!(state.authenticate(&OTHER), Err(Error::InvalidStateTag));
    let mut json = serde_json::to_value(&state).unwrap();
    json["inner"]["current"] =
        serde_json::to_value(Accumulator::random(&mut rng(98), &TOY)).unwrap();
    let altered: ManagerState = serde_json::from_value(json).unwrap();
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
    let _ = manager.remove(&element(2));
    let unrelated = Accumulator::random(&mut rng(97), &TOY);
    let initial = Accumulator::new(&KEY);
    assert_eq!(
        manager.state.inner().current(),
        &kln_accumulator::Accumulator::from(manager.value.clone())
    );
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
    assert!(MembershipWitness::new(&element(9), &value, &KEY, &state).is_ok());
}
