// SPDX-License-Identifier: MIT OR Apache-2.0
//! `MemVer` rejects vectors that satisfy the equation but are too long, and altered witnesses
//! (C23).

use crate::fixture::{KEY, Manager, TOY, element};
use kln_accumulator::lattice::{Coeff, Poly, PolyVec};
use kln_accumulator::{Error, MembershipWitness};
use proptest::prelude::*;
use std::sync::LazyLock;

/// A toy accumulator holding `x = 90` after one deletion, with the witness of `x`.
static HELD: LazyLock<(Manager<'static>, MembershipWitness)> = LazyLock::new(|| {
    let mut manager = Manager::new(&KEY);
    let _ = manager.add(&element(90));
    let _ = manager.add(&element(91));
    let _ = manager.remove(&element(91));
    let witness = manager.witness(&element(90));
    (manager, witness)
});

/// The witness of `x = 90` with `value·X^t` added to entry `i`.
fn altered(i: usize, t: usize, value: u64) -> MembershipWitness {
    let ring = TOY.ring();
    let mut coefficients = vec![Coeff::ZERO; ring.degree()];
    coefficients[t] = Coeff::from_u64(value);
    let shift = Poly::new(coefficients, ring).expect("toy-set coefficient");
    let mut entries: Vec<Poly> = PolyVec::from(HELD.1.clone()).into();
    entries[i] = entries[i].add(&shift, ring).expect("toy-set coefficient");
    MembershipWitness::from_vector(PolyVec::from(entries), &TOY).expect("toy-set witness")
}

/// C23: `s + v` for the kernel vector `v = (a₁, −a₀, 0, …)` of `A = (a₀, a₁, …)` (with `n = 1`,
/// `a₀·a₁ − a₁·a₀ = 0` in the commutative ring) satisfies the equation exactly, yet its norm
/// is far above `β`, and `verify` refuses it.
#[test]
fn over_norm_preimage_is_rejected() {
    let (manager, witness) = &*HELD;
    let x = element(90);
    let public = &manager.public;
    let params = &**TOY;
    let ring = params.ring();
    assert_eq!(params.spec().n, 1);
    assert!(witness.verify(&x, public, &manager.value));
    let a = public.a();
    let (a0, a1) = (a.get(0, 0).unwrap(), a.get(0, 1).unwrap());
    let m = params.spec().m;
    let kernel =
        PolyVec::from(vec![a1.clone(), a0.neg(ring).unwrap()]).concat(&PolyVec::zero(m - 2, ring));
    assert_eq!(a.mul_vec(&kernel, ring).unwrap(), PolyVec::zero(1, ring));
    let kernel = kernel.concat(&PolyVec::zero(witness_len() - m, ring));
    let long = PolyVec::from(witness.clone()).add(&kernel, ring).unwrap();
    let beta = params.bounds().witness.resize();
    assert!(long.norm_l2_squared(ring) > beta.wrapping_mul(&beta));
    let long = MembershipWitness::from_vector(long, &TOY).unwrap();
    assert!(long.validate(params).is_ok());
    assert!(!long.verify(&x, public, &manager.value));
    // Its coefficients do not fit the packed width ⌈log₂(2β + 1)⌉ either.
    assert_eq!(long.to_bytes(), Err(Error::CoefficientOverBound));
    assert!(serde_json::to_string(&long).is_err());
}

fn witness_len() -> usize {
    let spec = TOY.spec();
    spec.m + spec.element_bits as usize * TOY.m_prime()
}

/// C23: adding one to one coefficient of any entry of a valid witness makes `verify` fail.
#[test]
fn every_altered_entry_is_rejected() {
    let (manager, _) = &*HELD;
    let x = element(90);
    for i in 0..witness_len() {
        let witness = altered(i, (7 * i) % TOY.ring().degree(), 1);
        assert!(
            !witness.verify(&x, &manager.public, &manager.value),
            "entry {i}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// C23: any nonzero change to one coefficient makes `verify` fail.
    #[test]
    fn random_alteration_is_rejected(
        i in 0..witness_len(),
        t in 0usize..64,
        value in 1u64..(1 << 59),
    ) {
        let (manager, _) = &*HELD;
        prop_assert!(!altered(i, t, value).verify(&element(90), &manager.public, &manager.value));
    }
}
