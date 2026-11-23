// SPDX-License-Identifier: MIT OR Apache-2.0
//! A holder that was offline catches up on every deletion it missed, for Construction 4.1 of
//! ePrint 2025/1099.
//!
//! The holder of x receives a witness and goes offline. Meanwhile the manager publishes three
//! batches of deletions. When the holder comes back it collects the published batches and
//! brings its witness up to date in one call, using only public data, and the witness verifies
//! against the latest value. The holder of y, which was deleted in one of the missed batches,
//! is refused. The run also shows why every batch must be applied: a witness that skips one
//! raises no error but does not verify.
//! The toy parameter set gives no security; it keeps the run to a few seconds.
//!
//! Run it with `cargo run --release --example offline_holder`.

use kln_accumulator::{
    Accumulator, Coefficient, Element, Error, MembershipWitness, Params, PublicKey, SecretKey,
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

/// One published batch as a holder sees it: the additions (left empty, because additions never
/// change a witness and the manager does not publish them), the deletions and the update
/// messages that name them.
type Batch = (Vec<Element>, Vec<Element>, Vec<Coefficient>);

/// The batch a holder rebuilds from the update messages alone: the messages name the deleted
/// elements, in order.
fn batch(messages: Vec<Coefficient>) -> Batch {
    let deletions = messages.iter().map(|m| m.element().clone()).collect();
    (Vec::new(), deletions, messages)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
    let mut rng = StdRng::seed_from_u64(0);
    let params = Arc::new(Params::toy()?);
    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);
    println!("manager: generated a key and published its public key");

    let [x, y, a, b, c, d] =
        [b"x", b"y", b"a", b"b", b"c", b"d"].map(|name| Element::hash(name, &params));
    let (mut acc, mut state) = Accumulator::with_elements(
        &key,
        &[x.clone(), y.clone(), a.clone(), b.clone(), c.clone()],
    )?;
    let witness_x = MembershipWitness::new(&x, &acc, &key, &state)?;
    let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
    step(
        witness_x.verify(&x, &pk, &acc),
        "manager: added x, y, a, b and c; holder of x: received a witness that verifies",
    )?;
    println!("holder of x: goes offline");

    // Three batches while x is away. The second also adds d, which nobody else needs to hear
    // about, and deletes y.
    let first = acc.update_assign(&key, &[], &[a], &mut state)?;
    let second = acc.update_assign(&key, &[d], &[y.clone(), b], &mut state)?;
    let third = acc.update_assign(&key, &[], &[c], &mut state)?;
    let missed = [batch(first), batch(second), batch(third)];
    println!(
        "manager: published 3 batches deleting a, then y and b, then c ({} messages in all)",
        missed.iter().map(|(_, _, m)| m.len()).sum::<usize>()
    );

    step(
        !witness_x.verify(&x, &pk, &acc),
        "holder of x: back online, its old witness no longer verifies against the latest value",
    )?;

    // One call over every missed batch, in the order the manager published them. No secret is
    // involved: the batches and the public key are enough.
    let caught_up = witness_x.multi_batch_update(&x, &missed, &pk)?;
    step(
        caught_up.verify(&x, &pk, &acc),
        "holder of x: applied all 3 batches in one call; the witness verifies against the latest value",
    )?;

    // The same result, one batch at a time, for a holder that applies each batch as it arrives.
    let stepwise = missed
        .iter()
        .try_fold(witness_x.clone(), |w, (adds, dels, msgs)| {
            w.batch_update(&x, adds, dels, msgs, &pk)
        })?;
    step(
        stepwise == caught_up,
        "holder of x: applying the batches one by one gives the same witness",
    )?;

    // A skipped batch raises no error, it only gives a witness that does not verify. Holders
    // must keep track of the last batch they applied.
    let without_second = [missed[0].clone(), missed[2].clone()];
    let skipped = witness_x.multi_batch_update(&x, &without_second, &pk)?;
    step(
        !skipped.verify(&x, &pk, &acc),
        "holder of x: had it skipped the second batch, the update would succeed but not verify",
    )?;

    // y was deleted in the second batch, so its holder cannot bring its witness up to date:
    // this error is how a holder learns it was removed.
    let refused = witness_y.multi_batch_update(&y, &missed, &pk);
    step(
        matches!(refused, Err(Error::ElementDeleted)),
        &format!(
            "holder of y: catching up is refused, since y was deleted: \"{}\"",
            Error::ElementDeleted
        ),
    )?;
    Ok(())
}
