// SPDX-License-Identifier: MIT OR Apache-2.0
//! A complete run of the `ℓ`-succinct variant of ePrint 2025/1099 (Section 4), in
//! `kln_accumulator::succinct`.
//!
//! The manager side is the base scheme: the accumulator value, the manager state, the elements
//! and the update messages are the crate-root types, and the base methods take a succinct key.
//! Only the keys and the witness are the variant's own. The succinct toy set gives no security;
//! key generation there takes about a second.
//!
//! Run it with `cargo run --release --example succinct`.

use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
use kln_accumulator::{Accumulator, Element, Error, ManagerState, Params};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Prints one step of the run, or ends the run with an error when what the step shows is false.
fn step(holds: bool, line: &str) -> Result<(), String> {
    if holds {
        println!("{line}");
        Ok(())
    } else {
        Err(format!("this step does not hold: {line}"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
    let mut rng = StdRng::seed_from_u64(0);
    let params = Arc::new(Params::succinct_toy()?);
    let bits = params.spec().element_bits;
    println!("parameters: the succinct toy set, elements of {bits} bits");

    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);
    println!("manager: generated a key and derived its public key, which holds T₀ and T₁");

    let mut acc = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    // ℓ = 4 at this set: sixteen elements exist, so they are named directly.
    let [x, y, z] = [1u8, 2, 3].map(|byte| Element::try_from(&[byte][..]));
    let (x, y, z) = (x?, y?, z?);
    acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
    println!("manager: added x, y and z with the base methods and the succinct key");

    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
    step(
        witness.verify(&x, &pk, &acc),
        "holder of x: received a succinct witness and it verifies",
    )?;

    let deleted = std::slice::from_ref(&y);
    let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
    println!("manager: deleted y and published one update message, y itself");

    let stale = !witness.verify(&x, &pk, &acc);
    let witness = witness.batch_update(&x, &[], deleted, &coefficients, &pk)?;
    step(
        stale && witness.verify(&x, &pk, &acc),
        "holder of x: the old witness fails; the updated one verifies against the new value",
    )?;

    let refused = witness_y.batch_update(&y, &[], deleted, &coefficients, &pk);
    step(
        !witness_y.verify(&y, &pk, &acc) && matches!(refused, Err(Error::ElementDeleted)),
        "holder of y: its witness no longer verifies and cannot be updated",
    )?;

    let witness_bytes = witness.to_bytes()?;
    let pk_bytes = pk.to_bytes();
    let (w, p) = (witness_bytes.len(), pk_bytes.len());
    println!("wire: witness {w} bytes, public key {p} bytes");

    let decoded_pk = PublicKey::from_bytes(&params, &pk_bytes)?;
    let decoded_witness = MembershipWitness::from_bytes(&params, &witness_bytes)?;
    step(
        decoded_witness.verify(&x, &decoded_pk, &acc),
        "verifier: decoded both against the succinct toy set; the witness still verifies",
    )?;
    Ok(())
}
