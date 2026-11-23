// SPDX-License-Identifier: MIT OR Apache-2.0
// Included into `gaussian` and `ternary` in `main.rs`, each with its own `fixture`:
// Add, delete, update and verify for the succinct variant (C32).

use self::fixture::{KEY, Manager, SET, build, element, log2};
use crypto_bigint::{NonZero, U512};
use kln_accumulator::{
    Accumulator, Element, Error, succinct::{MembershipWitness, PublicKey, evaluate_delta},
};
use kln_accumulator::lattice::PolyVec;

/// `[A | B₁ + (xᵀ⊗I_n)·W]`, from the public key alone.
fn verification_matrix(pk: &PublicKey, x: &Element) -> kln_accumulator::lattice::PolyMatrix {
    let params = &**SET;
    let ring = params.ring();
    let n = params.spec().n;
    let bits = x.to_bits(params).expect("test fixture");
    let mut right = pk.b1().clone();
    for (i, _) in bits.as_slice().iter().enumerate().filter(|(_, b)| **b) {
        let block = build(pk.b1().shape(), |r, c| {
            pk.w().get(i * n + r, c).expect("test fixture").clone()
        });
        right = right.add(&block, ring).expect("test fixture");
    }
    pk.a().hconcat(&right).expect("test fixture")
}

/// C32, add and verify: a new witness has `m + m'` entries, satisfies
/// `[A | B₁ + (xᵀ⊗I_n)W]·s_x = c` checked from the public key alone, and is within
/// `β_succ`. That it is the paper's map of the base preimage `s̃` is a unit test of the witness
/// module, since the base preimage is not issued through the public API.
#[test]
fn added_element_verifies_with_the_succinct_equation() {
    let params = &**SET;
    let ring = params.ring();
    let mut manager = Manager::new(&KEY);
    let x = element(5);
    let witness = manager.add(&x);
    let s = PolyVec::from(witness.clone());
    assert_eq!(s.len(), params.spec().m + params.m_prime());
    assert!(witness.verify(&x, &manager.public, &manager.value));
    assert!(!witness.verify(&element(6), &manager.public, &manager.value));
    let c = PolyVec::from(manager.value.clone());
    assert_eq!(
        verification_matrix(&manager.public, &x)
            .mul_vec(&s, ring)
            .unwrap(),
        c
    );
    let beta: U512 = manager.public.bounds().witness.resize();
    let norm = s.norm_l2_squared(ring);
    assert!(norm <= beta.wrapping_mul(&beta));
    eprintln!(
        "C32: ‖s_x‖ = 2^{:.2}, β_succ = 2^{:.2}, q = 2^{:.2}",
        log2(&norm.floor_sqrt_vartime().resize()),
        log2(&manager.public.bounds().witness),
        log2(params.ring().modulus())
    );
}

/// C32, delete and update: after two batches of deletions every other witness, updated through
/// `update`, `batch_update`, `multi_batch_update` and `apply_delta`, is the same witness, equals
/// a fresh `MemWitCreate`, verifies, and stays within `β_succ`; the deleted ones fail and cannot
/// be updated.
#[test]
fn deletions_update_the_other_witnesses() {
    let params = &**SET;
    let ring = params.ring();
    let mut manager = Manager::new(&KEY);
    let members: Vec<Element> = (0..8).map(element).collect();
    let witnesses: Vec<MembershipWitness> = members.iter().map(|x| manager.add(x)).collect();
    let v0 = manager.value.clone();
    let (v1, c1) = v0
        .update(&KEY, &[], &members[..2], &mut manager.state)
        .unwrap();
    let (v2, c2) = v1
        .update(&KEY, &[], &members[2..3], &mut manager.state)
        .unwrap();
    manager.value = v2.clone();
    let public = &manager.public;
    let beta: U512 = public.bounds().witness.resize();
    for (x, witness) in members.iter().zip(&witnesses).skip(3) {
        let stepwise = witness
            .update(x, &v0, &v1, &[], &members[..2], public)
            .unwrap()
            .update(x, &v1, &v2, &[], &members[2..3], public)
            .unwrap();
        let batched = witness
            .batch_update(x, &[], &members[..2], &c1, public)
            .unwrap()
            .batch_update(x, &[], &members[2..3], &c2, public)
            .unwrap();
        let multi = witness
            .multi_batch_update(
                x,
                &[
                    (Vec::new(), members[..2].to_vec(), c1.clone()),
                    (Vec::new(), members[2..3].to_vec(), c2.clone()),
                ],
                public,
            )
            .unwrap();
        let mut applied = witness.clone();
        applied
            .apply_delta_assign(&evaluate_delta(x, &[], &members[..2], &c1, public).unwrap())
            .unwrap();
        let applied = applied
            .apply_delta(&evaluate_delta(x, &[], &members[2..3], &c2, public).unwrap())
            .unwrap();
        for updated in [&batched, &multi, &applied] {
            assert_eq!(updated, &stepwise);
        }
        assert!(stepwise.verify(x, public, &v2));
        assert_eq!(stepwise, manager.witness(x));
        assert!(PolyVec::from(stepwise).norm_l2_squared(ring) <= beta.wrapping_mul(&beta));
    }
    for (i, (x, witness)) in members.iter().zip(&witnesses).take(3).enumerate() {
        assert!(!witness.verify(x, public, &v2));
        let (deleted, coefficients) = if i < 2 {
            (&members[..2], &c1)
        } else {
            (&members[2..3], &c2)
        };
        assert_eq!(
            witness.batch_update(x, &[], deleted, coefficients, public),
            Err(Error::ElementDeleted)
        );
    }
    assert_eq!(
        witnesses[2].update(&members[2], &v1, &v2, &[], &members[2..3], public),
        Err(Error::AccumulatorMismatch)
    );
}

/// C32, the norm check: `s + t·e₀` satisfies the equation for the value it maps to, and
/// `verify` accepts it at `t = 1` and refuses it at `t = 2·β_succ`, which leaves `‖s + t·e₀‖ >
/// β_succ` whatever the
/// sign of the first coefficient.
#[test]
fn norm_bound_is_enforced() {
    let params = &**SET;
    let ring = params.ring();
    let mut manager = Manager::new(&KEY);
    let x = element(9);
    let s = PolyVec::from(manager.add(&x));
    let matrix = verification_matrix(&manager.public, &x);
    let shifted = |t: &kln_accumulator::lattice::Coeff| {
        let mut polys: Vec<kln_accumulator::lattice::Poly> = s.clone().into();
        let mut coefficients = polys[0].coefficients().to_vec();
        coefficients[0] = coefficients[0].add_mod(t, &NonZero::new(*ring.modulus()).unwrap());
        polys[0] = kln_accumulator::lattice::Poly::new(coefficients, ring).unwrap();
        let candidate: PolyVec = polys.into_iter().collect();
        let value =
            Accumulator::from_vector(matrix.mul_vec(&candidate, ring).unwrap(), &SET).unwrap();
        (
            MembershipWitness::from_vector(candidate, &SET).unwrap(),
            value,
        )
    };
    let (small, value) = shifted(&kln_accumulator::lattice::Coeff::ONE);
    assert!(small.verify(&x, &manager.public, &value));
    let beta = manager.public.bounds().witness;
    let (large, value) = shifted(&beta.wrapping_add(&beta));
    assert!(!large.verify(&x, &manager.public, &value));
}
