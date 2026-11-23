// SPDX-License-Identifier: MIT OR Apache-2.0
//! C41: Construction 4.1 at the 128-bit set of Table 2, `d = 4096`, `q ≈ 2^100`, `ℓ = 32`,
//! `γ = 2^32`: key generation, additions, a deletion, a witness update and verification, with
//! the encoded witness, accumulator value and public parameters against Table 2.

use crate::sizes::{KIB, MIB, assert_within_ten_percent, report, timed};
use kln_accumulator::{
    Accumulator, Element, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Table 2: membership witness 14.72 MB.
const WITNESS_MIB: f64 = 14.72;
/// Table 2: accumulator value 50 KB.
const ACCUMULATOR_KIB: f64 = 50.0;
/// Table 2: public parameters 16.7 MB.
const PUBLIC_MIB: f64 = 16.7;

fn element(i: u32) -> Element {
    Element::try_from(i.to_le_bytes().as_slice()).expect("an ℓ = 32 element")
}

#[test]
#[ignore = "the 128-bit set takes about 20 s and 0.5 GB in release; run with --release -- --ignored"]
fn add_delete_update_verify_and_sizes_at_the_128_bit_set() {
    eprintln!("C41 at the 128-bit set (Table 2):");
    let params = timed("parameter set", || Arc::new(Params::paper_128().unwrap()));
    let spec = params.spec();
    eprintln!(
        "  d = {}, q < 2^{}, n = {}, m = {}, m' = {}, b = {}, ℓ = {}, γ = {}, β < 2^{}",
        spec.degree,
        params.ring().modulus().bit_width_vartime(),
        spec.n,
        spec.m,
        params.m_prime(),
        spec.base,
        spec.element_bits,
        spec.max_deletions,
        params.bounds().witness.bit_width_vartime()
    );
    let mut rng = StdRng::seed_from_u64(41);
    let key = timed("key generation", || {
        SecretKey::new(
            Some(b"kln/test/c41, a 32-byte test seed"),
            Arc::clone(&params),
            &mut rng,
        )
        .unwrap()
    });
    let public = timed("public key", || PublicKey::from(&key));
    let mut value = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    let (x, y, z) = (element(0x0102_0304), element(0xdead_beef), element(7));
    timed("add x, y, z", || {
        value
            .add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)
            .unwrap()
    });
    let witness_x = timed("witness for x (MemWitCreate)", || {
        MembershipWitness::new(&x, &value, &key, &state).unwrap()
    });
    let witness_y = timed("witness for y (MemWitCreate)", || {
        MembershipWitness::new(&y, &value, &key, &state).unwrap()
    });
    assert!(timed("verify x", || witness_x.verify(&x, &public, &value)));
    let deletions = [y.clone()];
    let (new_value, coefficients) = timed("delete y", || {
        value.update(&key, &[], &deletions, &mut state).unwrap()
    });
    let updated_x = timed("update x's witness (batch_update)", || {
        witness_x
            .batch_update(&x, &[], &deletions, &coefficients, &public)
            .unwrap()
    });
    assert!(timed("verify updated x", || updated_x
        .verify(&x, &public, &new_value)));
    assert!(timed("verify deleted y (must fail)", || !witness_y
        .verify(&y, &public, &new_value)));
    assert!(
        witness_y
            .batch_update(&y, &[], &deletions, &coefficients, &public)
            .is_err()
    );

    let witness_bytes = timed("encode witness", || updated_x.to_bytes().unwrap());
    let value_bytes = timed("encode accumulator", || new_value.to_bytes());
    let public_bytes = timed("encode public key", || public.to_bytes());
    assert_eq!(
        timed("decode witness", || MembershipWitness::try_from(
            witness_bytes.as_slice()
        ))
        .unwrap(),
        updated_x
    );
    report(
        "membership witness",
        witness_bytes.len(),
        Some((WITNESS_MIB, MIB, "MiB")),
    );
    report(
        "accumulator value",
        value_bytes.len(),
        Some((ACCUMULATOR_KIB, KIB, "KiB")),
    );
    report(
        "public parameters",
        public_bytes.len(),
        Some((PUBLIC_MIB, MIB, "MiB")),
    );
    assert_within_ten_percent("membership witness", witness_bytes.len(), WITNESS_MIB, MIB);
    assert_within_ten_percent("accumulator value", value_bytes.len(), ACCUMULATOR_KIB, KIB);
    assert_within_ten_percent("public parameters", public_bytes.len(), PUBLIC_MIB, MIB);
}
