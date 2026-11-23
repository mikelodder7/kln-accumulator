// SPDX-License-Identifier: MIT OR Apache-2.0
//! A complete run of the adaptive accumulator, Construction 4.2 of ePrint 2025/1099, in
//! `kln_accumulator::adaptive`.
//!
//! The lifecycle is that of the base example, with the one thing this variant is for: an
//! element is deleted and then added again. The accumulator holds a handle for each element,
//! not the element, and a re-added element gets a new handle. The toy parameter set gives no
//! security; it keeps the run to a few seconds.
//!
//! Run it with `cargo run --release --example adaptive`.

use kln_accumulator::adaptive::{
    Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
};
use kln_accumulator::{Coefficient, Error, Params};
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

/// The handles an update message names; a holder updates its witness with these.
fn handles(messages: &[Coefficient]) -> Vec<kln_accumulator::Element> {
    messages.iter().map(|m| m.element().clone()).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
    let mut rng = StdRng::seed_from_u64(0);
    let params = Arc::new(Params::toy()?);

    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);
    println!("manager: generated a key, with its ML-DSA-65 key, and derived the public key");

    let mut acc = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name));
    acc.add_elements_assign(&key, &[x, y, z], &mut state)?;
    println!("manager: added x, y and z, each under a fresh handle");

    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
    step(
        witness.verify(&x, &pk, &acc),
        "holder of x: received a witness (handle, signature, inner witness); it verifies",
    )?;

    let coefficients = acc.update_assign(&key, &[], &[y], &mut state)?;
    let deleted = handles(&coefficients);
    step(
        deleted.as_slice() == [witness_y.handle().clone()],
        "manager: deleted y; the one update message names y's handle, not y",
    )?;

    let witness = witness.batch_update(&x, &[], &deleted, &coefficients, &pk)?;
    step(
        witness.verify(&x, &pk, &acc),
        "holder of x: updated from the published handle; the witness verifies",
    )?;

    let refused = witness_y.batch_update(&y, &[], &deleted, &coefficients, &pk);
    step(
        !witness_y.verify(&y, &pk, &acc) && matches!(refused, Err(Error::ElementDeleted)),
        "holder of y: its witness no longer verifies and cannot be updated",
    )?;

    acc.add_assign(&key, &y, &mut state)?;
    let again = MembershipWitness::new(&y, &acc, &key, &state)?;
    step(
        again.verify(&y, &pk, &acc)
            && again.handle() != witness_y.handle()
            && !witness_y.verify(&y, &pk, &acc),
        "manager: added y again under a new handle; the new witness verifies, the old one does not",
    )?;

    let coefficients = acc.update_assign(&key, &[], &[z], &mut state)?;
    let witness = witness.batch_update(&x, &[], &handles(&coefficients), &coefficients, &pk)?;
    step(
        witness.verify(&x, &pk, &acc),
        "manager: deleted z; holder of x: updated again, and the witness verifies",
    )?;

    let witness_bytes = witness.to_bytes()?;
    let pk_bytes = pk.to_bytes();
    let (w, s, p) = (
        witness_bytes.len(),
        witness.signature().len(),
        pk_bytes.len(),
    );
    println!("wire: witness {w} bytes ({s} of them the signature), public key {p} bytes");

    let decoded_pk = PublicKey::from_bytes(&params, &pk_bytes)?;
    let decoded_witness = MembershipWitness::from_bytes(&params, &witness_bytes)?;
    step(
        decoded_witness.verify(&x, &decoded_pk, &acc),
        "verifier: decoded both against the toy set; the witness still verifies",
    )?;
    Ok(())
}
