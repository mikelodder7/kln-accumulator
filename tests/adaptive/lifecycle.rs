// SPDX-License-Identifier: MIT OR Apache-2.0
// Included into `gaussian` and `ternary` in `main.rs`, each with its own `fixture`:
// Keys, additions, deletions, re-additions and witness updates of the adaptive accumulator (C27,
// C28, C30).

use self::fixture::{KEY, Manager, TOY, element, rng};
use kln_accumulator::{
    Accumulator as InnerAccumulator, Error, Operation, Record,
    adaptive::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey},
    evaluate_delta,
};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};
use std::sync::Arc;

/// The length of an encoded ML-DSA-65 verifying key (FIPS 204, Table 2).
const VERIFYING_KEY_BYTES: usize = 1952;

/// The message an adaptive witness signs, as documented on `MembershipWitness`.
fn signed_message(x: &Element, handle: &kln_accumulator::Element) -> Vec<u8> {
    [&b"kln/adaptive/sign"[..], &x.to_bytes(), &handle.to_bytes()].concat()
}

/// C30, keys: the same seed gives the same secret key, the same ML-DSA verifying key and the
/// same inner public key; another seed gives different ones; without a seed the RNG decides.
#[test]
fn keys_are_a_function_of_the_seed() {
    let make = |seed: Option<&[u8]>, rng_seed| {
        SecretKey::new(seed, Arc::clone(&TOY), &mut rng(rng_seed)).unwrap()
    };
    let first = make(Some(b"seed a, padded to thirty-two bytes"), 1);
    let again = make(Some(b"seed a, padded to thirty-two bytes"), 2);
    let other = make(Some(b"seed b, padded to thirty-two bytes"), 1);
    assert_eq!(first, again);
    assert_eq!(*first.to_bytes(), *again.to_bytes());
    let (pk, again_pk, other_pk) = (
        PublicKey::from(&first),
        PublicKey::from(&again),
        PublicKey::from(&other),
    );
    assert_eq!(pk.to_bytes(), again_pk.to_bytes());
    assert_ne!(first, other);
    assert_ne!(
        pk.to_bytes()[..VERIFYING_KEY_BYTES],
        other_pk.to_bytes()[..VERIFYING_KEY_BYTES]
    );
    assert_ne!(pk.inner(), other_pk.inner());
    assert_eq!(make(None, 7), make(None, 7));
    assert_ne!(make(None, 7), make(None, 8));
    assert_eq!(format!("{first:?}"), "SecretKey { .. }");
    assert_eq!(first.params(), pk.params());
}

/// C27: adding `x` yields `(r_x, σ_x, w̃)` where `σ_x` is an ML-DSA-65 signature over
/// `(x, r_x)`, checked here with the `ml-dsa` crate directly, and `w̃` verifies for `r_x` in
/// the inner accumulator. The value is unchanged by the addition and `MemWitCreate` reproduces
/// the witness.
#[test]
fn added_element_carries_a_signed_handle() {
    let mut manager = Manager::new(&KEY);
    let initial = manager.value.clone();
    let x = element(1);
    let witness = manager.add(&x);
    assert_eq!(manager.value, initial);
    assert!(witness.verify(&x, &manager.public, &manager.value));
    assert!(witness.handle().validate(&TOY).is_ok());

    let encoded =
        EncodedVerifyingKey::<MlDsa65>::try_from(&manager.public.to_bytes()[..VERIFYING_KEY_BYTES])
            .unwrap();
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded);
    let signature = Signature::<MlDsa65>::try_from(witness.signature()).unwrap();
    assert!(
        verifying_key
            .verify(&signed_message(&x, witness.handle()), &signature)
            .is_ok()
    );
    let inner_value = InnerAccumulator::from(manager.value.clone());
    assert!(
        witness
            .inner()
            .verify(witness.handle(), manager.public.inner(), &inner_value)
    );
    assert_eq!(manager.witness(&x), witness);
    assert!(!witness.verify(&element(2), &manager.public, &manager.value));
}

/// C28: `x` is added, deleted and added again. The two handles differ, the state records the
/// PRF index as Construction 4.2 does (`(Del, i + 1)` after the deletion), and only the second
/// witness verifies afterwards; the first cannot be updated past its own deletion.
#[test]
fn element_can_be_re_added_with_a_new_handle() {
    let mut manager = Manager::new(&KEY);
    let (x, z) = (element(3), element(4));
    let first = manager.add(&x);
    let other = manager.add(&z);
    let record = manager.state.record(&x).unwrap();
    assert_eq!(record.operation, Operation::Add);
    let index = record.epoch;
    let old = manager.value.clone();
    let coefficient = manager.remove(&x);
    assert_eq!(coefficient.element(), first.handle());
    assert_eq!(
        manager.state.record(&x),
        Some(Record {
            operation: Operation::Del,
            epoch: index + 1
        })
    );
    assert!(!first.verify(&x, &manager.public, &manager.value));
    let other = other
        .update(
            &z,
            &old,
            &manager.value,
            &[],
            std::slice::from_ref(coefficient.element()),
            &manager.public,
        )
        .unwrap();
    assert!(other.verify(&z, &manager.public, &manager.value));

    let second = manager.add(&x);
    assert_ne!(second.handle(), first.handle());
    assert!(
        manager
            .state
            .record(&x)
            .is_some_and(|r| r.operation == Operation::Add && r.epoch > index)
    );
    assert!(second.verify(&x, &manager.public, &manager.value));
    assert!(!first.verify(&x, &manager.public, &manager.value));
    assert_eq!(
        first.batch_update(
            &x,
            &[],
            std::slice::from_ref(coefficient.element()),
            std::slice::from_ref(&coefficient),
            &manager.public,
        ),
        Err(Error::ElementDeleted)
    );
    assert!(other.verify(&z, &manager.public, &manager.value));
}

/// C30, updates: after two batches of deletions, every remaining witness updated through
/// `update`, `batch_update`, `multi_batch_update` and `apply_delta` is the same witness, it
/// verifies, and it equals the one `MemWitCreate` issues afresh, byte for byte.
#[test]
fn witnesses_follow_deletions_through_every_entry_point() {
    let mut manager = Manager::new(&KEY);
    let members: Vec<Element> = (10..16).map(element).collect();
    let witnesses: Vec<MembershipWitness> = members.iter().map(|x| manager.add(x)).collect();
    let v0 = manager.value.clone();
    let (v1, c1) = v0
        .update(&KEY, &[], &members[..2], &mut manager.state)
        .unwrap();
    let (v2, c2) = v1
        .update(&KEY, &[], &members[2..3], &mut manager.state)
        .unwrap();
    manager.value = v2.clone();
    let handles = |cs: &[kln_accumulator::adaptive::Coefficient]| -> Vec<kln_accumulator::Element> {
        cs.iter().map(|c| c.element().clone()).collect()
    };
    let (h1, h2) = (handles(&c1), handles(&c2));
    let public = &manager.public;
    for (x, witness) in members.iter().zip(&witnesses).skip(3) {
        let stepwise = witness
            .update(x, &v0, &v1, &[], &h1, public)
            .unwrap()
            .update(x, &v1, &v2, &[], &h2, public)
            .unwrap();
        let batched = witness
            .batch_update(x, &[], &h1, &c1, public)
            .unwrap()
            .batch_update(x, &[], &h2, &c2, public)
            .unwrap();
        let multi = witness
            .multi_batch_update(
                x,
                &[
                    (Vec::new(), h1.clone(), c1.clone()),
                    (Vec::new(), h2.clone(), c2.clone()),
                ],
                public,
            )
            .unwrap();
        let delta = evaluate_delta(witness.handle(), &[], &h1, &c1, public.inner()).unwrap();
        let mut applied = witness.clone();
        applied.apply_delta_assign(&delta).unwrap();
        let applied = applied
            .apply_delta(&evaluate_delta(witness.handle(), &[], &h2, &c2, public.inner()).unwrap())
            .unwrap();
        for updated in [&batched, &multi, &applied] {
            assert_eq!(updated, &stepwise);
        }
        assert!(stepwise.verify(x, public, &v2));
        assert_eq!(stepwise.to_bytes(), manager.witness(x).to_bytes());
    }
    for (x, witness) in members.iter().zip(&witnesses).take(3) {
        assert!(!witness.verify(x, public, &v2));
        assert_eq!(
            MembershipWitness::new(x, &v2, &KEY, &manager.state),
            Err(Error::ElementNotPresent)
        );
    }
}

/// C30, the remaining mirrored names: `with_elements`, the single, batch and in-place forms of
/// addition and deletion, and the in-place forms of the witness updates, which agree.
#[test]
fn every_mirrored_operation_has_its_base_name() {
    let batch: Vec<Element> = (20..24).map(element).collect();
    let (mut value, mut state) = Accumulator::with_elements(&KEY, &batch).unwrap();
    assert_eq!(value, Accumulator::new(&KEY));
    let public = PublicKey::from(&*KEY);
    let (x, y) = (element(25), element(26));
    assert_eq!(value.add(&KEY, &x, &mut state).unwrap(), value);
    value.add_assign(&KEY, &y, &mut state).unwrap();
    assert_eq!(
        value
            .add_elements(&KEY, &[element(27)], &mut state)
            .unwrap(),
        value
    );
    value
        .add_elements_assign(&KEY, &[element(28)], &mut state)
        .unwrap();
    let witness = MembershipWitness::new(&x, &value, &KEY, &state).unwrap();
    assert!(witness.validate(&TOY).is_ok());

    value = value.remove(&KEY, &batch[0], &mut state).unwrap();
    value.remove_assign(&KEY, &batch[1], &mut state).unwrap();
    value = value
        .remove_elements(&KEY, &batch[2..3], &mut state)
        .unwrap();
    value
        .remove_elements_assign(&KEY, &batch[3..], &mut state)
        .unwrap();
    assert!(!witness.verify(&x, &public, &value));
    let fresh = MembershipWitness::new(&x, &value, &KEY, &state).unwrap();
    assert!(fresh.verify(&x, &public, &value));

    let old = value.clone();
    let coefficients = value
        .update_assign(&KEY, &[element(29)], std::slice::from_ref(&y), &mut state)
        .unwrap();
    let handles: Vec<kln_accumulator::Element> =
        coefficients.iter().map(|c| c.element().clone()).collect();
    let mut stepwise = fresh.clone();
    stepwise
        .update_assign(&x, &old, &value, &[], &handles, &public)
        .unwrap();
    let mut batched = fresh.clone();
    batched
        .batch_update_assign(&x, &[], &handles, &coefficients, &public)
        .unwrap();
    let mut multi = fresh;
    multi
        .multi_batch_update_assign(
            &x,
            &[(Vec::new(), handles.clone(), coefficients.clone())],
            &public,
        )
        .unwrap();
    assert_eq!(batched, stepwise);
    assert_eq!(multi, stepwise);
    assert!(stepwise.verify(&x, &public, &value));
    assert!(value.validate(&TOY).is_ok());
    assert!(state.validate(&TOY).is_ok());
    assert_eq!(state.record(&y).map(|r| r.operation), Some(Operation::Del));
}

/// Invalid operations are refused and leave the value and the state unchanged: adding a present
/// element (alone or twice in one batch), deleting an absent one (or one element twice), and
/// issuing a witness for an element that is not present.
#[test]
fn invalid_operations_are_refused_atomically() {
    let mut manager = Manager::new(&KEY);
    let (x, y, absent) = (element(30), element(31), element(32));
    let _ = manager.add(&x);
    let (value, state) = (manager.value.clone(), manager.state.clone());
    let attempts: [(&[Element], &[Element], Error); 4] = [
        (&[x], &[], Error::ElementAlreadyAdded),
        (&[y, y], &[], Error::ElementAlreadyAdded),
        (&[y], &[absent], Error::ElementNotPresent),
        (&[], &[x, x], Error::ElementNotPresent),
    ];
    for (additions, deletions, error) in attempts {
        assert_eq!(
            manager
                .value
                .update_assign(&KEY, additions, deletions, &mut manager.state),
            Err(error)
        );
        assert_eq!(manager.value, value);
        assert_eq!(manager.state, state);
    }
    assert_eq!(
        MembershipWitness::new(&absent, &manager.value, &KEY, &manager.state),
        Err(Error::ElementNotPresent)
    );
    // An element added and deleted in the same batch is recorded as deleted.
    let coefficients = manager
        .value
        .update_assign(&KEY, &[y], &[y], &mut manager.state)
        .unwrap();
    assert_eq!(coefficients.len(), 1);
    assert_eq!(
        manager.state.record(&y).map(|r| r.operation),
        Some(Operation::Del)
    );
}
