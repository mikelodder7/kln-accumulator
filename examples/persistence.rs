// SPDX-License-Identifier: MIT OR Apache-2.0
//! Saving, reloading and rebuilding the manager's state, for Construction 4.1 of ePrint
//! 2025/1099.
//!
//! The manager saves its `ManagerState` as JSON, reloads it after a restart and keeps working.
//! A saved state that someone altered still loads, but the key refuses it. Finally the state is
//! lost altogether and rebuilt from what survives: the key, the update messages the manager
//! published, and its own list of current members. The rebuilt state issues working witnesses.
//! The toy parameter set gives no security; it keeps the run to a few seconds.
//!
//! Run it with `cargo run --release --example persistence`.

use kln_accumulator::{
    Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
};
use rand::{SeedableRng, rngs::StdRng};
use std::slice::from_ref;
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
    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);
    println!("manager: generated a key; it is stored apart from the state and outlives it");

    let [x, y, z, w] = [b"x", b"y", b"z", b"w"].map(|name| Element::hash(name, &params));
    let (mut acc, mut state) =
        Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    // Every update message the manager publishes goes into a public log. Anyone may keep it;
    // it is what a lost state is rebuilt from at the end.
    let mut log = acc.update_assign(&key, &[], from_ref(&y), &mut state)?;
    println!("manager: added x, y and z and deleted y");

    // The state holds the current value, the record of every element and a tag the key made.
    // Save it before publishing anything, so that a crash never leaves the manager behind what
    // everyone has seen.
    let stored = serde_json::to_string(&state)?;
    println!(
        "manager: saved its state as JSON, {} bytes, and only then published the update message",
        stored.len()
    );

    // The process restarts: the in-memory state is gone, only the saved copy remains.
    drop(state);
    let published = acc;
    let mut loaded: ManagerState = serde_json::from_str(&stored)?;
    // Deserializing cannot check the tag, because it has no key. Check it before reading
    // anything from the loaded state.
    loaded.authenticate(&key)?;
    step(
        loaded.current() == &published,
        "manager: reloaded the state; the key accepts its tag and it holds the published value",
    )?;

    let mut acc = loaded.current().clone();
    acc.add_assign(&key, &w, &mut loaded)?;
    let witness_w = MembershipWitness::new(&w, &acc, &key, &loaded)?;
    step(
        witness_w.verify(&w, &pk, &acc),
        "manager: kept working from the reloaded state; it added w and w's witness verifies",
    )?;

    log.extend(acc.update_assign(&key, &[], from_ref(&z), &mut loaded)?);
    let witness_x = MembershipWitness::new(&x, &acc, &key, &loaded)?;
    let stored = serde_json::to_string(&loaded)?;
    println!("manager: deleted z, saved the state again and then published the message");

    // Someone with write access to the storage swaps the saved value for another one. The
    // altered state is still a possible history, so it loads; the tag no longer matches it.
    let mut altered: serde_json::Value = serde_json::from_str(&stored)?;
    altered["current"] = serde_json::to_value(Accumulator::random(&mut rng, &params))?;
    let altered: ManagerState = serde_json::from_value(altered)?;
    let refused = altered.authenticate(&key).err();
    step(
        refused == Some(Error::InvalidStateTag),
        &format!(
            "manager: a saved state with its value swapped loads, but the key refuses it: \"{}\"",
            Error::InvalidStateTag
        ),
    )?;
    // Every operation that uses the key makes the same check first, so the altered state
    // cannot issue a witness even when nobody calls `authenticate`.
    let issued = MembershipWitness::new(&x, altered.current(), &key, &altered);
    step(
        matches!(issued, Err(Error::InvalidStateTag)),
        "manager: asked to issue a witness from the altered state, the key refuses as well",
    )?;

    // Now the state is lost for good. What survives: the key, the public log of update
    // messages, and the manager's own list of current members. The log names deletions only,
    // so the member list has to come from the manager's records.
    drop(loaded);
    let members = [x.clone(), w.clone()];
    let (value, mut rebuilt) = ManagerState::rebuild(&key, &log, &members)?;
    step(
        value == acc,
        &format!(
            "manager: rebuilt the state from the key, the {} published messages and its \
             members x and w; the value equals the last published one",
            log.len()
        ),
    )?;

    // A witness depends only on the key, the element and the set of deletions, so the rebuilt
    // state issues exactly the witness the lost one did.
    let reissued = MembershipWitness::new(&x, &value, &key, &rebuilt)?;
    step(
        reissued.verify(&x, &pk, &value) && reissued == witness_x,
        "manager: the rebuilt state issued x a witness; it verifies and equals the one issued before",
    )?;

    // The rebuilt state remembers y and z as deleted, so neither can come back.
    let mut value = value;
    let refused = value.add_assign(&key, &y, &mut rebuilt);
    step(
        matches!(refused, Err(Error::ElementAlreadyAdded)),
        "manager: the rebuilt state refuses to add y again, since y was deleted",
    )?;
    Ok(())
}
