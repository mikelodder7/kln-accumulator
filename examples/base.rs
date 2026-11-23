// SPDX-License-Identifier: MIT OR Apache-2.0
//! A complete run of Construction 4.1 of ePrint 2025/1099, the accumulator at the crate root.
//!
//! The manager generates a key, adds elements, issues a witness and deletes an element; the
//! holder verifies its witness and updates it from the published update message alone. The
//! witness, the public key and the accumulator value then travel as bytes and are decoded
//! against the expected set.
//! The toy parameter set gives no security; it keeps the run to a few seconds.
//!
//! Run it with `cargo run --release --example base`.

use kln_accumulator::{
    Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
};
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
    let params = Arc::new(Params::toy()?);
    let degree = params.ring().degree();
    println!("parameters: the toy set, ring degree {degree}");

    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);
    println!("manager: generated a key and derived its public key");

    let mut acc = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    let size = acc.to_bytes().len();
    println!("manager: started the accumulator at the key's genesis value, {size} bytes");

    let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
    let before = acc.clone();
    acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
    step(
        acc == before,
        "manager: added x, y and z; the value did not change and nothing was published",
    )?;

    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
    step(
        witness.verify(&x, &pk, &acc),
        "holder of x: received a witness and it verifies",
    )?;

    let deleted = std::slice::from_ref(&y);
    let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
    let message: usize = coefficients.iter().map(|c| c.to_bytes().len()).sum();
    step(
        acc != before,
        &format!(
            "manager: deleted y; the value moved, and the update message is y, {message} byte"
        ),
    )?;

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
    let acc_bytes = acc.to_bytes();
    let (w, p, a) = (witness_bytes.len(), pk_bytes.len(), acc_bytes.len());
    println!("wire: witness {w} bytes, public key {p} bytes, accumulator value {a} bytes");

    let decoded_pk = PublicKey::from_bytes(&params, &pk_bytes)?;
    let decoded_acc = Accumulator::from_bytes(&params, &acc_bytes)?;
    let decoded_witness = MembershipWitness::from_bytes(&params, &witness_bytes)?;
    step(
        decoded_witness.verify(&x, &decoded_pk, &decoded_acc),
        "verifier: decoded all three against the toy set; the witness still verifies",
    )?;
    Ok(())
}
