// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compile-time checks that every type holding secret or holder-private material overwrites it
//! when dropped, and behaviour checks of the `Zeroize` implementations those drops call.
//! `Committed` (the prover's state) and the trapdoor's `Prepared` form are checked in their own
//! modules, which are private.

use crate::{
    accumulator::{Accumulator, Element},
    adaptive,
    eval::{BitString, Indicator},
    key::SecretKey,
    matrix::{NttMatrix, PolyMatrix, Shape},
    poly::Poly,
    preimage::{Perturbation, Uniform},
    proof::MembershipProofCommitting,
    ring::NttPoly,
    sample::{DomainLabel, Seed, UniformSampler},
    state::StateTag,
    succinct,
    test_util::{TOY, wiped_on_drop},
    trapdoor::Trapdoor,
    vector::PolyVec,
    witness::{Delta, MembershipWitness},
};
use ml_dsa::{MlDsa65, SigningKey};
use rand::{SeedableRng, rngs::StdRng};
use sha3::{
    block_api::{Sha3HasherCore, Sha3ReaderCore},
    digest::{
        block_api::Buffer,
        block_buffer::ReadBuffer,
        consts::{U0, U136},
    },
};
use std::sync::Arc;
use zeroize::Zeroize;

/// The SHAKE padding byte, the `PAD` parameter of SHAKE256's hasher core.
const SHAKE_PAD: u8 = 0x1f;

/// The keys of all three variants, the ML-DSA signing key inside the adaptive one, and the
/// trapdoor with every form of it the sampler builds.
#[test]
fn keys_and_trapdoors_are_wiped() {
    wiped_on_drop::<SecretKey>();
    wiped_on_drop::<adaptive::SecretKey>();
    wiped_on_drop::<succinct::SecretKey>();
    wiped_on_drop::<SigningKey<MlDsa65>>();
    wiped_on_drop::<Trapdoor>();
    wiped_on_drop::<Perturbation>();
    wiped_on_drop::<NttMatrix>();
}

/// Seeds, the uniform stream drawn from one, and the SHAKE256 hasher and reader parts that
/// absorb root seeds, PRF keys and the state-tag key: `Shake256` is a `Sha3HasherCore` with a
/// block buffer and `Shake256Reader` a `Sha3ReaderCore` with a read buffer, and with `sha3`'s
/// `zeroize` feature each part overwrites itself when dropped.
#[test]
fn seeds_and_streams_are_wiped() {
    wiped_on_drop::<Seed>();
    wiped_on_drop::<UniformSampler>();
    wiped_on_drop::<Uniform<'_>>();
    wiped_on_drop::<Sha3HasherCore<U136, U0, SHAKE_PAD>>();
    wiped_on_drop::<Buffer<Sha3HasherCore<U136, U0, SHAKE_PAD>>>();
    wiped_on_drop::<Sha3ReaderCore<U136>>();
    wiped_on_drop::<ReadBuffer<U136>>();
    wiped_on_drop::<StateTag>();
}

/// The value types every secret vector is made of, and the holder-private witnesses and
/// deltas of all three variants.
#[test]
fn values_and_witnesses_are_wiped() {
    wiped_on_drop::<Poly>();
    wiped_on_drop::<NttPoly>();
    wiped_on_drop::<PolyVec>();
    wiped_on_drop::<PolyMatrix>();
    wiped_on_drop::<Element>();
    wiped_on_drop::<BitString>();
    wiped_on_drop::<MembershipWitness>();
    wiped_on_drop::<Delta>();
    wiped_on_drop::<adaptive::MembershipWitness>();
    wiped_on_drop::<succinct::MembershipWitness>();
    wiped_on_drop::<succinct::Delta>();
    wiped_on_drop::<MembershipProofCommitting>();
}

/// The `Zeroize` implementations that the drops call: a seed becomes all zeros, and a value
/// held in a `Vec` has every entry overwritten and is then emptied (the `zeroize` crate also
/// overwrites the spare capacity), so nothing of it can be read back.
#[test]
fn zeroize_clears_values() {
    let ring = TOY.ring();
    let mut seed = Seed::from([7; 32]);
    seed.zeroize();
    assert_eq!(seed, Seed::from([0; 32]));

    let mut element = Element::hash(b"x", &TOY);
    element.zeroize();
    assert!(element.as_bytes().is_empty());

    let mut bits = BitString::from(vec![true; 8]);
    bits.zeroize();
    assert!(bits.as_slice().is_empty());

    let mut poly = Poly::constant(5, ring);
    poly.zeroize();
    assert!(poly.coefficients().is_empty());

    let shape = Shape { rows: 1, cols: 2 };
    let mut matrix = PolyMatrix::new(shape, vec![Poly::constant(3, ring); 2]).unwrap();
    matrix.zeroize();
    assert!(matrix.entries().iter().all(|p| p.coefficients().is_empty()));
}

/// The secret types print none of their bytes; bit strings, indicators, state tags and the
/// manager states of both variants print counts and the parameter set only.
#[test]
fn debug_hides_secrets() {
    assert_eq!(format!("{:?}", Seed::from([7; 32])), "Seed { .. }");

    let bits = BitString::from(vec![true; 8]);
    assert_eq!(format!("{bits:?}"), "BitString { len: 8, .. }");
    let spec = TOY.spec();
    let b = PolyMatrix::zero(
        Shape {
            rows: spec.n,
            cols: spec.element_bits as usize * TOY.m_prime(),
        },
        TOY.ring(),
    );
    let indicator = Indicator::new(&TOY, &bits, &b).unwrap();
    assert_eq!(
        format!("{indicator:?}"),
        format!("Indicator {{ params: {spec:?}, .. }}")
    );
    let label = DomainLabel::from(&b"kln/test/debug"[..]);
    let tag = StateTag::compute(label, &Seed::from([7; 32]), &[]);
    assert_eq!(format!("{tag:?}"), "StateTag { .. }");

    let seed = b"kln/test/debug-hides-secrets, 32 bytes";
    let params = Arc::new(TOY.clone());
    let mut rng = StdRng::seed_from_u64(0);
    let key = SecretKey::new(Some(seed), Arc::clone(&params), &mut rng).unwrap();
    let elements = [Element::hash(b"x", &TOY), Element::hash(b"y", &TOY)];
    let (_, state) = Accumulator::with_elements(&key, &elements).unwrap();
    assert_eq!(
        format!("{state:?}"),
        "ManagerState { counter: 0, entries: 2, .. }"
    );
    let key = adaptive::SecretKey::new(Some(seed), params, &mut rng).unwrap();
    let elements = [adaptive::Element::hash(b"x"), adaptive::Element::hash(b"y")];
    let (_, state) = adaptive::Accumulator::with_elements(&key, &elements).unwrap();
    assert_eq!(
        format!("{state:?}"),
        "ManagerState { inner: ManagerState { counter: 0, entries: 2, .. }, entries: 2, .. }"
    );
}
