// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adaptive key generation refuses short seeds (C69) and binds the root seed to the parameter
//! set (C70).

use crate::fixture::{TOY, element, rng};
use kln_accumulator::{
    Error, MIN_SEED_BYTES, Params, ParamsSpec, TrapdoorDistribution,
    adaptive::{Accumulator, ManagerState, MembershipWitness, PublicKey, SecretKey},
};
use std::sync::Arc;

/// C69: an empty and a 31-byte seed are refused with their length, and a 32-byte seed is
/// accepted.
#[test]
fn short_seeds_are_refused() {
    for len in [0, MIN_SEED_BYTES - 1] {
        let seed = vec![1u8; len];
        let refused = SecretKey::new(Some(&seed), Arc::clone(&TOY), &mut rng(0));
        assert_eq!(refused.map(drop), Err(Error::SeedTooShort(len)));
    }
    let seed = [1u8; MIN_SEED_BYTES];
    assert!(SecretKey::new(Some(&seed), Arc::clone(&TOY), &mut rng(0)).is_ok());
}

/// C70: one seed under the Gaussian and the ternary toy sets gives two adaptive keys whose
/// public keys differ, in the ML-DSA key and the inner key, and a state tagged by either key
/// fails the other's tag check, in both directions, and is refused by its operations.
#[test]
fn one_seed_under_two_sets_gives_unrelated_keys() {
    let seed = b"kln/test/adaptive-key, one seed for two sets";
    let ternary = Arc::new(
        Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary)).unwrap(),
    );
    let keys = [
        SecretKey::new(Some(seed), Arc::clone(&TOY), &mut rng(0)).unwrap(),
        SecretKey::new(Some(seed), Arc::clone(&ternary), &mut rng(0)).unwrap(),
    ];
    assert_eq!(keys[0].to_bytes()[64..], keys[1].to_bytes()[64..]);
    let (pk, pk_ternary) = (PublicKey::from(&keys[0]), PublicKey::from(&keys[1]));
    // The encoding starts with the 1952-byte ML-DSA-65 verifying key.
    assert_ne!(pk.to_bytes()[..1952], pk_ternary.to_bytes()[..1952]);
    assert_ne!(pk.inner().a(), pk_ternary.inner().a());
    for (mine, theirs) in [(&keys[0], &keys[1]), (&keys[1], &keys[0])] {
        let (mut value, mut state) = Accumulator::with_elements(mine, &[element(1)]).unwrap();
        assert_eq!(state.authenticate(mine), Ok(()));
        assert_eq!(state.authenticate(theirs), Err(Error::InvalidStateTag));
        let before = (value.clone(), state.clone());
        assert_eq!(
            MembershipWitness::new(&element(1), &value, theirs, &state).map(drop),
            Err(Error::InvalidStateTag)
        );
        assert_eq!(
            value.add_assign(theirs, &element(2), &mut state),
            Err(Error::InvalidStateTag)
        );
        assert_eq!((value, state), before);
        let fresh = ManagerState::new(theirs);
        assert_eq!(fresh.authenticate(mine), Err(Error::InvalidStateTag));
    }
}
