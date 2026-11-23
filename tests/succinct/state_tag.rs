// SPDX-License-Identifier: MIT OR Apache-2.0
//! The succinct variant keeps the base manager state, tagged under the base key its succinct
//! key dereferences to (C51), with the current value every keyed operation requires (C68).

use crate::fixture::{KEY, Manager, SET, element, rng};
use kln_accumulator::{
    Accumulator, Error, ManagerState, SecretKey as BaseKey, succinct::MembershipWitness,
};
use serde_json::json;
use std::sync::Arc;

/// C51: the succinct `MemWitCreate` and the base updates under a succinct key refuse a state
/// whose tag was altered, or which a base key with the same parameters tagged, and change
/// nothing; the honest state still issues witnesses.
#[test]
fn succinct_keys_refuse_altered_and_foreign_states() {
    let mut manager = Manager::new(&KEY);
    let _ = manager.add(&element(1));
    let _ = manager.add(&element(2));
    let mut altered_json = serde_json::to_value(&manager.state).unwrap();
    let tag = altered_json["tag"].as_str().unwrap().to_owned();
    let first = if tag.starts_with('0') { "1" } else { "0" };
    altered_json["tag"] = json!(format!("{first}{}", &tag[1..]));
    let altered: ManagerState = serde_json::from_value(altered_json).unwrap();
    let base = BaseKey::new(
        Some(b"kln/test/succinct-base, 32 bytes"),
        Arc::clone(&SET),
        &mut rng(0),
    )
    .expect("test fixture");
    let foreign = ManagerState::new(&base);
    for (what, state) in [("altered tag", altered), ("base key's state", foreign)] {
        let (mut value, mut s) = (manager.value.clone(), state.clone());
        assert_eq!(
            MembershipWitness::new(&element(1), &value, &KEY, &s).map(drop),
            Err(Error::InvalidStateTag),
            "{what}"
        );
        assert_eq!(
            value.add_assign(&KEY, &element(3), &mut s),
            Err(Error::InvalidStateTag),
            "{what}"
        );
        assert_eq!(
            value.remove_assign(&KEY, &element(1), &mut s),
            Err(Error::InvalidStateTag),
            "{what}"
        );
        assert_eq!((&value, &s), (&manager.value, &state), "{what}");
    }
    let witness = manager.witness(&element(1));
    assert!(witness.verify(&element(1), &manager.public, &manager.value));
}

/// C68: under a succinct key, the base add, remove and update and the succinct `MemWitCreate`
/// refuse a value that is not the state's current one, an unrelated value or the value from
/// before the last deletion, with `AccumulatorMismatch` and nothing changed; the public tag
/// check (C71) passes the honest state throughout.
#[test]
fn values_that_are_not_current_are_refused() {
    let mut manager = Manager::new(&KEY);
    let _ = manager.add(&element(1));
    let _ = manager.add(&element(2));
    let stale = manager.value.clone();
    manager
        .value
        .remove_assign(&KEY, &element(2), &mut manager.state)
        .unwrap();
    assert_eq!(manager.state.current(), &manager.value);
    assert_eq!(manager.state.authenticate(&KEY), Ok(()));
    let unrelated = Accumulator::random(&mut rng(97), &SET);
    let refused = Err(Error::AccumulatorMismatch);
    for (what, value) in [("unrelated value", &unrelated), ("stale value", &stale)] {
        let (mut v, mut s) = (value.clone(), manager.state.clone());
        assert_eq!(
            MembershipWitness::new(&element(1), &v, &KEY, &s).map(drop),
            refused,
            "{what}"
        );
        assert_eq!(v.add_assign(&KEY, &element(3), &mut s), refused, "{what}");
        assert_eq!(
            v.remove_assign(&KEY, &element(1), &mut s),
            refused,
            "{what}"
        );
        assert_eq!(
            v.update_assign(&KEY, &[element(3)], &[element(1)], &mut s)
                .map(drop),
            refused,
            "{what}"
        );
        assert_eq!((&v, &s), (value, &manager.state), "{what}");
    }
    let witness = manager.witness(&element(1));
    assert!(witness.verify(&element(1), &manager.public, &manager.value));
}
