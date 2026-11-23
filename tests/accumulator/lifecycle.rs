// SPDX-License-Identifier: MIT OR Apache-2.0
// Included into `gaussian` and `ternary` in `main.rs`, each with its own `fixture`:
// Keys, additions, deletions and witness updates (C16–C22, C24).

use self::fixture::{KEY, Manager, TOY, element, rng, with_bound};
use kln_accumulator::{
    Accumulator, Coefficient, Element, Error, ManagerState, MembershipWitness, Operation, PublicKey,
    Record, SecretKey, evaluate_delta,
};
use kln_accumulator::lattice::{Indicator, PolyVec};
use proptest::prelude::*;
use std::sync::Arc;

/// C16: the same seed gives the same secret and public key, different seeds different ones;
/// without a seed the key comes from the RNG.
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
    assert_eq!(PublicKey::from(&first), PublicKey::from(&again));
    assert_eq!(
        PublicKey::from(&first).to_bytes(),
        PublicKey::from(&again).to_bytes()
    );
    assert_ne!(first, other);
    let (pk, other_pk) = (PublicKey::from(&first), PublicKey::from(&other));
    assert_ne!(pk.a(), other_pk.a());
    assert_ne!(pk.b(), other_pk.b());
    assert_ne!(pk.u(), other_pk.u());
    assert_eq!(make(None, 7), make(None, 7));
    assert_ne!(make(None, 7), make(None, 8));
    assert_eq!(format!("{first:?}"), "SecretKey { .. }");
}

/// C17: a witness for a newly added element verifies; additions leave the value unchanged.
#[test]
fn added_element_verifies_and_value_is_unchanged() {
    let mut manager = Manager::new(&KEY);
    let initial = manager.value.clone();
    let x = element(10);
    let after = manager.value.add(&KEY, &x, &mut manager.state).unwrap();
    assert_eq!(after, initial);
    let batch: Vec<Element> = (11..16).map(element).collect();
    manager
        .value
        .add_elements_assign(&KEY, &batch, &mut manager.state)
        .unwrap();
    assert_eq!(manager.value, initial);
    for y in batch.iter().chain([&x]) {
        let witness = manager.witness(y);
        assert!(witness.verify(y, &manager.public, &manager.value));
        assert!(!witness.verify(&element(99), &manager.public, &manager.value));
    }
    let (value, state) = Accumulator::with_elements(&KEY, &batch).unwrap();
    assert_eq!(value, Accumulator::new(&KEY));
    assert_eq!(state.current(), &value);
    let witness = MembershipWitness::new(&batch[2], &value, &KEY, &state).unwrap();
    assert!(witness.verify(&batch[2], &manager.public, &value));
}

/// C18: after a deletion of `y`, the witness of every other `x`, updated with the published
/// deletion through each update entry point, verifies against the new value.
#[test]
fn other_witnesses_survive_a_deletion() {
    let mut manager = Manager::new(&KEY);
    let members: Vec<Element> = (20..26).map(element).collect();
    let witnesses: Vec<MembershipWitness> = members.iter().map(|x| manager.add(x)).collect();
    let old = manager.value.clone();
    let y = &members[2];
    let (new, coefficients) = old
        .update(&KEY, &[], std::slice::from_ref(y), &mut manager.state)
        .unwrap();
    assert_ne!(new, old);
    assert_eq!(coefficients, vec![Coefficient::from(y.clone())]);
    let public = &manager.public;
    for (x, witness) in members.iter().zip(&witnesses) {
        if x == y {
            continue;
        }
        assert!(!witness.verify(x, public, &new));
        let updated = witness
            .update(x, &old, &new, &[], std::slice::from_ref(y), public)
            .unwrap();
        assert!(updated.verify(x, public, &new));
        let batched = witness
            .batch_update(x, &[], std::slice::from_ref(y), &coefficients, public)
            .unwrap();
        assert_eq!(batched, updated);
        let mut in_place = witness.clone();
        in_place
            .apply_delta_assign(
                &evaluate_delta(x, [], std::slice::from_ref(y), &coefficients, public).unwrap(),
            )
            .unwrap();
        assert_eq!(in_place, updated);
    }
}

/// C19: after the deletion of `y`, its own witness fails verification whether it is left as it
/// was, updated through the paper's MemWitUp arithmetic by hand, or offered to the update entry
/// points (which refuse it).
#[test]
fn deleted_witness_fails() {
    let mut manager = Manager::new(&KEY);
    let y = element(30);
    let witness = manager.add(&y);
    let _ = manager.add(&element(31));
    let old = manager.value.clone();
    let coefficient = manager.remove(&y);
    let new = &manager.value;
    let public = &manager.public;
    let params = &**TOY;
    assert!(!witness.verify(&y, public, new));
    // MemWitUp applied regardless: s + [0; H_{1y,y}·G⁻¹(u)], which satisfies the equation only
    // up to −u.
    let bits = y.to_bits(params).unwrap();
    let h_u = Indicator::new(params, &bits, public.b())
        .unwrap()
        .eval_fx_vec(&bits, public.u())
        .unwrap();
    let ring = params.ring();
    let padded = PolyVec::zero(params.spec().m, ring).concat(&h_u);
    let by_hand = MembershipWitness::from_vector(
        PolyVec::from(witness.clone()).add(&padded, ring).unwrap(),
        witness.params(),
    )
    .unwrap();
    assert!(!by_hand.verify(&y, public, new));
    let deletions = std::slice::from_ref(&y);
    let coefficients = std::slice::from_ref(&coefficient);
    assert_eq!(
        witness.update(&y, &old, new, &[], deletions, public),
        Err(Error::ElementDeleted)
    );
    assert_eq!(
        witness.batch_update(&y, &[], deletions, coefficients, public),
        Err(Error::ElementDeleted)
    );
    assert_eq!(
        witness.multi_batch_update(&y, &[(&[][..], deletions, coefficients)], public),
        Err(Error::ElementDeleted)
    );
    assert_eq!(
        MembershipWitness::new(&y, new, &KEY, &manager.state),
        Err(Error::ElementNotPresent)
    );
}

/// Runs `operation` and checks that it fails with `expected` and changes neither the value nor
/// the state.
fn refused(
    manager: &mut Manager<'_>,
    expected: Error,
    operation: impl FnOnce(&mut Accumulator, &mut ManagerState) -> kln_accumulator::Result<()>,
) {
    let (value, state) = (manager.value.clone(), manager.state.clone());
    assert_eq!(
        operation(&mut manager.value, &mut manager.state),
        Err(expected)
    );
    assert_eq!(manager.value, value);
    assert_eq!(manager.state, state);
}

/// C20: re-adding, removing what is not present, and exceeding `γ` each fail and leave the value
/// and the state unchanged, including when the offending operation is the last of a batch.
#[test]
fn invalid_operations_change_nothing() {
    let key = SecretKey::new(Some(b"kln/test/bound, a 32-byte test seed"), with_bound(3), &mut rng(0)).unwrap();
    let mut manager = Manager::new(&key);
    let (x, y, z, w) = (element(40), element(41), element(42), element(43));
    let v = element(44);
    for e in [&x, &y, &z, &v] {
        let _ = manager.add(e);
    }
    let _ = manager.remove(&y);
    let record = |operation, epoch| Some(Record { operation, epoch });
    assert_eq!(manager.state.record(&x), record(Operation::Add, 0));
    // Deletion epochs count from 1 (the post-increment erratum).
    assert_eq!(manager.state.record(&y), record(Operation::Del, 1));
    assert_eq!(manager.state.record(&w), None);
    let already = Error::ElementAlreadyAdded;
    let absent = Error::ElementNotPresent;
    refused(&mut manager, already, |v, s| v.add_assign(&key, &x, s));
    refused(&mut manager, already, |v, s| v.add_assign(&key, &y, s));
    refused(&mut manager, already, |v, s| {
        v.add_elements_assign(&key, &[w.clone(), w.clone()], s)
    });
    refused(&mut manager, already, |v, s| {
        v.add_elements_assign(&key, &[w.clone(), x.clone()], s)
    });
    refused(&mut manager, absent, |v, s| v.remove_assign(&key, &w, s));
    refused(&mut manager, absent, |v, s| v.remove_assign(&key, &y, s));
    refused(&mut manager, absent, |v, s| {
        v.remove_elements_assign(&key, &[x.clone(), x.clone()], s)
    });
    refused(&mut manager, absent, |v, s| {
        v.update_assign(&key, std::slice::from_ref(&w), &[w.clone(), y.clone()], s)
            .map(drop)
    });
    refused(&mut manager, Error::InvalidElement, |v, s| {
        v.add_assign(&key, &Element::try_from([1u8, 2].as_slice()).unwrap(), s)
    });
    // γ = 3 and one deletion made: three more in one batch exceed the bound.
    refused(&mut manager, Error::DeletionBoundReached, |a, s| {
        a.remove_elements_assign(&key, &[x.clone(), z.clone(), v.clone()], s)
    });
    let _ = manager.remove(&x);
    let _ = manager.remove(&z);
    assert_eq!(manager.state.counter(), 3);
    refused(&mut manager, Error::DeletionBoundReached, |a, s| {
        a.remove_assign(&key, &v, s)
    });
    // Additions stay free once the bound is reached.
    let witness = manager.add(&w);
    assert!(witness.verify(&w, &manager.public, &manager.value));
}

/// C21: the witness recreated after `k` deletions equals, byte for byte, the witness issued at
/// add time and updated through those deletions, for elements added before and after earlier
/// deletions.
#[test]
fn recreated_witness_equals_updated_witness() {
    let mut manager = Manager::new(&KEY);
    let early = element(50);
    let mut early_witness = manager.add(&early);
    let doomed: Vec<Element> = (51..56).map(element).collect();
    for d in &doomed {
        let _ = manager.add(d);
    }
    delete(
        &mut manager,
        &doomed[0],
        &mut [(&early, &mut early_witness)],
    );
    let late = element(60);
    let mut late_witness = manager.add(&late);
    for y in &doomed[1..] {
        delete(
            &mut manager,
            y,
            &mut [(&early, &mut early_witness), (&late, &mut late_witness)],
        );
    }
    assert_eq!(manager.state.counter(), 5);
    for (x, witness) in [(&early, &early_witness), (&late, &late_witness)] {
        let recreated = manager.witness(x);
        assert_eq!(recreated.to_bytes(), witness.to_bytes());
        assert!(recreated.verify(x, &manager.public, &manager.value));
    }
}

/// Deletes `y` and updates every held witness with `update_assign`.
fn delete(
    manager: &mut Manager<'_>,
    y: &Element,
    witnesses: &mut [(&Element, &mut MembershipWitness)],
) {
    let old = manager.value.clone();
    let _ = manager.remove(y);
    for (x, witness) in witnesses {
        witness
            .update_assign(
                x,
                &old,
                &manager.value,
                &[],
                std::slice::from_ref(y),
                &manager.public,
            )
            .expect("valid test history");
    }
}

/// C24: a deleted element cannot be added again through any entry point, and recreating a
/// witness returns the same witness rather than a fresh preimage.
#[test]
fn deleted_element_is_never_re_added() {
    let mut manager = Manager::new(&KEY);
    let x = element(70);
    let first = manager.add(&x);
    assert_eq!(manager.witness(&x), first);
    let _ = manager.remove(&x);
    let again = std::slice::from_ref(&x);
    refused(&mut manager, Error::ElementAlreadyAdded, |v, s| {
        v.add_assign(&KEY, &x, s)
    });
    refused(&mut manager, Error::ElementAlreadyAdded, |v, s| {
        v.add_elements_assign(&KEY, again, s)
    });
    refused(&mut manager, Error::ElementAlreadyAdded, |v, s| {
        v.update_assign(&KEY, again, &[], s).map(drop)
    });
    assert_eq!(
        MembershipWitness::new(&x, &manager.value, &KEY, &manager.state),
        Err(Error::ElementNotPresent)
    );
}

/// `MemWitCreate` refuses an accumulator value that is not the state's current value.
#[test]
fn witness_creation_checks_the_value() {
    let mut manager = Manager::new(&KEY);
    let x = element(80);
    let _ = manager.add(&x);
    let _ = manager.add(&element(81));
    let stale = manager.value.clone();
    let _ = manager.remove(&element(81));
    assert_eq!(
        MembershipWitness::new(&x, &stale, &KEY, &manager.state),
        Err(Error::AccumulatorMismatch)
    );
}

/// The deletions `0..k` of a fresh accumulator holding `x = 200`, as one-element batches.
struct History {
    public: PublicKey,
    x: Element,
    witness: MembershipWitness,
    deletions: Vec<Element>,
    coefficients: Vec<Coefficient>,
    value: Accumulator,
}

fn history(k: u8) -> History {
    let mut manager = Manager::new(&KEY);
    let x = element(200);
    let witness = manager.add(&x);
    let deletions: Vec<Element> = (0..k).map(element).collect();
    for d in &deletions {
        let _ = manager.add(d);
    }
    let coefficients = deletions.iter().map(|d| manager.remove(d)).collect();
    History {
        public: manager.public,
        x,
        witness,
        deletions,
        coefficients,
        value: manager.value,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// C22: updating through `k` deletions in order-preserving batches, with `batch_update` per
    /// batch or one `multi_batch_update`, gives the witness of one-at-a-time updates.
    #[test]
    fn batched_updates_match_single_updates(
        k in 1u8..=6,
        cuts in prop::collection::vec(any::<bool>(), 5),
    ) {
        let h = history(k);
        let one_at_a_time = h.deletions.iter().zip(&h.coefficients).try_fold(
            h.witness.clone(),
            |w, (d, c)| {
                w.batch_update(&h.x, &[], std::slice::from_ref(d), std::slice::from_ref(c), &h.public)
            },
        ).unwrap();
        prop_assert!(one_at_a_time.verify(&h.x, &h.public, &h.value));
        // A batch boundary after deletion i whenever cuts[i] is set.
        let mut bounds = vec![0];
        bounds.extend((1..usize::from(k)).filter(|&i| cuts[i - 1]));
        bounds.push(usize::from(k));
        let batches: Vec<(Vec<Element>, &[Element], &[Coefficient])> = bounds
            .windows(2)
            .map(|w| (Vec::new(), &h.deletions[w[0]..w[1]], &h.coefficients[w[0]..w[1]]))
            .collect();
        let mut batched = h.witness.clone();
        for (additions, deletions, coefficients) in &batches {
            batched.batch_update_assign(&h.x, additions, deletions, coefficients, &h.public).unwrap();
        }
        prop_assert_eq!(&batched, &one_at_a_time);
        let multi = h.witness.multi_batch_update(&h.x, &batches, &h.public).unwrap();
        prop_assert_eq!(&multi, &one_at_a_time);
        let mut multi_in_place = h.witness.clone();
        multi_in_place.multi_batch_update_assign(&h.x, &batches, &h.public).unwrap();
        prop_assert_eq!(&multi_in_place, &one_at_a_time);
    }
}

/// Update messages that do not name the deletions in order are refused.
#[test]
fn mismatched_coefficients_are_refused() {
    let h = history(2);
    let swapped = [h.coefficients[1].clone(), h.coefficients[0].clone()];
    assert_eq!(
        h.witness
            .batch_update(&h.x, &[], &h.deletions, &swapped, &h.public)
            .err(),
        Some(Error::CoefficientMismatch)
    );
    assert_eq!(
        h.witness
            .batch_update(&h.x, &[], &h.deletions, &h.coefficients[..1], &h.public)
            .err(),
        Some(Error::CoefficientMismatch)
    );
    assert_eq!(
        h.witness
            .batch_update(
                &h.x,
                std::slice::from_ref(&h.x),
                &h.deletions,
                &h.coefficients,
                &h.public
            )
            .err(),
        Some(Error::ElementAlreadyAdded)
    );
}
