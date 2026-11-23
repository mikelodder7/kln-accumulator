// SPDX-License-Identifier: MIT OR Apache-2.0
//! The encoded witness, accumulator value and public parameters at the toy set and the succinct
//! toy set, printed for comparison with the 128-bit run; correctness sets only, so nothing is
//! asserted about their sizes.

use crate::sizes::report;
use kln_accumulator::{
    Accumulator, Element, ManagerState, MembershipWitness, Params, PublicKey, SecretKey, succinct,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

#[test]
fn sizes_at_the_toy_sets() {
    let x = Element::try_from([3u8].as_slice()).unwrap();
    let mut rng = StdRng::seed_from_u64(1);

    let toy = Arc::new(Params::toy().unwrap());
    let key = SecretKey::new(Some(b"kln/test/paper-toy, a 32-byte seed"), toy, &mut rng).unwrap();
    let mut value = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    value.add_assign(&key, &x, &mut state).unwrap();
    let witness = MembershipWitness::new(&x, &value, &key, &state).unwrap();
    eprintln!("toy set:");
    report(
        "membership witness",
        witness.to_bytes().unwrap().len(),
        None,
    );
    report("accumulator value", value.to_bytes().len(), None);
    report(
        "public parameters",
        PublicKey::from(&key).to_bytes().len(),
        None,
    );

    let set = Arc::new(Params::succinct_toy().unwrap());
    let key = succinct::SecretKey::new(Some(b"kln/test/paper-succinct, 32 bytes"), set, &mut rng)
        .unwrap();
    let mut value = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    value.add_assign(&key, &x, &mut state).unwrap();
    let witness = succinct::MembershipWitness::new(&x, &value, &key, &state).unwrap();
    eprintln!("succinct toy set:");
    report(
        "membership witness",
        witness.to_bytes().unwrap().len(),
        None,
    );
    report("accumulator value", value.to_bytes().len(), None);
    report(
        "public parameters",
        succinct::PublicKey::from(&key).to_bytes().len(),
        None,
    );
}
