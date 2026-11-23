// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key generation of the succinct variant (C31), its parameter checks, its refusal of short
//! seeds (C69) and its binding of the root seed to the parameter set (C70).

use crate::fixture::{KEY, SET, block_diagonal, column, log2, rng, stack, ternary};
use crypto_bigint::U512;
use kln_accumulator::lattice::Shape;
use kln_accumulator::{
    Error, MIN_SEED_BYTES, ManagerState, Params,
    succinct::{Bounds, PublicKey, SecretKey},
};
use std::sync::Arc;

/// C31: `pp = (A, B₁, W, T₀, T₁, u)` with the paper's shapes, `[I_ℓ⊗A | W]·[T₀; T₁] = I_ℓ⊗G`
/// exactly, every column of `T` within the bound `τ`, and the `B` the inner scheme runs on
/// equal to `−B₁·T₁`.
#[test]
fn trapdoor_relation_holds() {
    let params = &**SET;
    let ring = params.ring();
    let pk = PublicKey::from(&*KEY);
    let (n, m, mp) = (params.spec().n, params.spec().m, params.m_prime());
    let ell = params.spec().element_bits as usize;
    let shape = |rows, cols| Shape { rows, cols };
    assert_eq!(pk.a().shape(), shape(n, m));
    assert_eq!(pk.b1().shape(), shape(n, mp));
    assert_eq!(pk.w().shape(), shape(n * ell, mp));
    assert_eq!(pk.t0().shape(), shape(ell * m, ell * mp));
    assert_eq!(pk.t1().shape(), shape(mp, ell * mp));
    assert_eq!(pk.u().len(), n);

    let left = block_diagonal(pk.a(), ell, params).hconcat(pk.w()).unwrap();
    let t = stack(pk.t0(), pk.t1());
    let right = block_diagonal(
        &kln_accumulator::lattice::PolyMatrix::from(params.gadget()),
        ell,
        params,
    );
    assert_eq!(left.mul(&t, ring).unwrap(), right);

    let tau: U512 = pk.bounds().column.resize();
    let limit = tau.wrapping_mul(&tau);
    let largest = (0..ell * mp)
        .map(|j| column(&t, j).norm_l2_squared(ring))
        .max()
        .unwrap();
    assert!(largest <= limit);
    eprintln!(
        "C31: largest column of T has norm 2^{:.2}, bound τ = 2^{:.2}",
        log2(&largest.floor_sqrt_vartime().resize()),
        log2(&pk.bounds().column)
    );
    let b = pk.b1().mul(pk.t1(), ring).unwrap().neg(ring).unwrap();
    assert_eq!(pk.b(), &b);
}

/// The same seed gives the same keys; another seed gives other ones.
#[test]
fn keys_are_a_function_of_the_seed() {
    let make = |seed: &[u8]| SecretKey::new(Some(seed), Arc::clone(&SET), &mut rng(1)).unwrap();
    let again = make(b"kln/test/succinct-key, a 32-byte seed");
    assert_eq!(again, *KEY);
    assert_eq!(*again.to_bytes(), *KEY.to_bytes());
    assert_eq!(PublicKey::from(&again), PublicKey::from(&*KEY));
    let other = make(b"another seed, at least 32 bytes long");
    assert_ne!(other, *KEY);
    assert_ne!(PublicKey::from(&other).t0(), PublicKey::from(&*KEY).t0());
    assert_eq!(format!("{other:?}"), "SecretKey { .. }");
}

/// The succinct bound is enforced at key generation: the base toy set (`q ≈ 2^60`) and the
/// base 128-bit set (`q ≈ 2^100`) are refused, the two succinct sets are accepted.
#[test]
fn sets_too_small_for_the_succinct_bound_are_refused() {
    for params in [Params::toy().unwrap(), Params::paper_128().unwrap()] {
        assert_eq!(Bounds::try_from(&params), Err(Error::WitnessBoundTooLarge));
    }
    assert_eq!(
        SecretKey::new(
            Some(b"a seed of at least thirty-two bytes"),
            Arc::new(Params::toy().unwrap()),
            &mut rng(2)
        )
        .err(),
        Some(Error::WitnessBoundTooLarge)
    );
    for params in [
        Params::succinct_toy().unwrap(),
        Params::succinct_128().unwrap(),
    ] {
        assert!(Bounds::try_from(&params).is_ok());
    }
}

/// C69: an empty and a 31-byte seed are refused with their length before any key generation
/// work, and a 32-byte seed is accepted.
#[test]
fn short_seeds_are_refused() {
    for len in [0, MIN_SEED_BYTES - 1] {
        let seed = vec![1u8; len];
        let refused = SecretKey::new(Some(&seed), Arc::clone(&SET), &mut rng(0));
        assert_eq!(refused.map(drop), Err(Error::SeedTooShort(len)));
    }
    let seed = [1u8; MIN_SEED_BYTES];
    assert!(SecretKey::new(Some(&seed), Arc::clone(&SET), &mut rng(0)).is_ok());
}

/// C70: the fixture keys at the Gaussian and the ternary succinct toy sets come from one seed,
/// and share nothing derived from it: `B₁`, `W`, `T₀`, `T₁` and the base key differ, and a
/// state tagged by either key fails the other's tag check.
#[test]
fn one_seed_under_two_sets_gives_unrelated_keys() {
    let (gaussian, other) = (&*KEY, &*ternary::KEY);
    assert_eq!(gaussian.to_bytes()[64..], other.to_bytes()[64..]);
    let (pk, pk_ternary) = (PublicKey::from(gaussian), PublicKey::from(other));
    assert_ne!(pk.b1(), pk_ternary.b1());
    assert_ne!(pk.w(), pk_ternary.w());
    assert_ne!(pk.t0(), pk_ternary.t0());
    assert_ne!(pk.t1(), pk_ternary.t1());
    assert_ne!(pk.a(), pk_ternary.a());
    for (mine, theirs) in [(gaussian, other), (other, gaussian)] {
        let state = ManagerState::new(mine);
        assert_eq!(state.authenticate(mine), Ok(()));
        assert_eq!(state.authenticate(theirs), Err(Error::InvalidStateTag));
    }
}
