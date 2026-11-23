// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key generation refuses short seeds (C69) and binds the root seed to the parameter set
//! (C70).

use crate::fixture::{TOY, element, rng};
use kln_accumulator::{
    Accumulator, Error, MIN_SEED_BYTES, ManagerState, Params, ParamsSpec, PublicKey, SecretKey,
    TrapdoorDistribution,
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

/// C70: one seed under the Gaussian and the ternary toy sets gives two keys whose public keys
/// differ, and a state tagged by either key fails the other's tag check, in both directions,
/// and is refused by its operations before they look at the parameter set.
#[test]
fn one_seed_under_two_sets_gives_unrelated_keys() {
    let seed = b"kln/test/key, one seed for two sets";
    let ternary = Arc::new(
        Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary)).unwrap(),
    );
    let keys = [
        SecretKey::new(Some(seed), Arc::clone(&TOY), &mut rng(0)).unwrap(),
        SecretKey::new(Some(seed), Arc::clone(&ternary), &mut rng(0)).unwrap(),
    ];
    assert_eq!(keys[0].to_bytes()[64..], keys[1].to_bytes()[64..]);
    let (pk, pk_ternary) = (PublicKey::from(&keys[0]), PublicKey::from(&keys[1]));
    assert_ne!(pk.a(), pk_ternary.a());
    assert_ne!(pk.b(), pk_ternary.b());
    assert_ne!(pk.u(), pk_ternary.u());
    for (mine, theirs) in [(&keys[0], &keys[1]), (&keys[1], &keys[0])] {
        let mut value = Accumulator::new(mine);
        let mut state = ManagerState::new(mine);
        assert_eq!(state.authenticate(mine), Ok(()));
        assert_eq!(state.authenticate(theirs), Err(Error::InvalidStateTag));
        let before = (value.clone(), state.clone());
        let x = element(1);
        assert_eq!(
            value.add_assign(theirs, &x, &mut state),
            Err(Error::InvalidStateTag)
        );
        assert_eq!((value, state), before);
    }
}
