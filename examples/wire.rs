// SPDX-License-Identifier: MIT OR Apache-2.0
//! Everything the manager publishes or hands out, sent as bytes and decoded safely, for
//! Construction 4.1 of ePrint 2025/1099.
//!
//! The public key, the accumulator value, an update message and a witness are encoded with
//! `to_bytes` and decoded by a receiver that already holds the parameter set, with
//! `from_bytes(&params, …)`; the witness still verifies. Bytes made under another parameter set
//! are refused before they are read, and truncated or corrupted bytes are refused too.
//! Membership proofs travel as bytes as well; `examples/proofs.rs` sends one, since making a
//! proof takes seconds.
//! The toy parameter set gives no security; it keeps the run to a few seconds.
//!
//! Run it with `cargo run --release --example wire`.

use kln_accumulator::{
    Accumulator, Coefficient, Element, Error, MembershipWitness, Params, ParamsSpec, PublicKey,
    SecretKey, TrapdoorDistribution,
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
    let [x, y] = [b"x", b"y"].map(|name| Element::hash(name, &params));
    let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    let messages = acc.update_assign(&key, &[], from_ref(&y), &mut state)?;
    println!("manager: generated a key, added x and y, issued x a witness, then deleted y");

    // Sender. The witness is private to its holder, so its bytes come back in a buffer that is
    // wiped when dropped.
    let pk_bytes = pk.to_bytes();
    let acc_bytes = acc.to_bytes();
    let message_bytes: Vec<Vec<u8>> = messages.iter().map(Coefficient::to_bytes).collect();
    let witness_bytes = witness.to_bytes()?;
    println!(
        "wire: public key {} bytes, accumulator value {} bytes, update message {} byte, witness {} bytes",
        pk_bytes.len(),
        acc_bytes.len(),
        message_bytes.iter().map(Vec::len).sum::<usize>(),
        witness_bytes.len()
    );

    // Receiver. It decodes against the parameter set it already holds, so nothing in the
    // bytes gets to choose the set, and every decoded value shares the receiver's own copy.
    let decoded_pk = PublicKey::from_bytes(&params, &pk_bytes)?;
    let decoded_acc = Accumulator::from_bytes(&params, &acc_bytes)?;
    let decoded_witness = MembershipWitness::from_bytes(&params, &witness_bytes)?;
    // An update message is just the deleted element's bytes and carries no parameter set, so
    // it has no `from_bytes`: decode it, then check it against the set.
    let decoded_messages = message_bytes
        .iter()
        .map(|bytes| {
            let message = Coefficient::try_from(bytes.as_slice())?;
            message.validate(&params).map(|()| message)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let deletions: Vec<Element> = decoded_messages
        .iter()
        .map(|m| m.element().clone())
        .collect();
    let updated =
        decoded_witness.batch_update(&x, &[], &deletions, &decoded_messages, &decoded_pk)?;
    step(
        updated.verify(&x, &decoded_pk, &decoded_acc) && Arc::ptr_eq(decoded_acc.params(), &params),
        "holder of x: decoded the four and checked each against its toy set; the updated witness verifies",
    )?;

    // The holder shows its updated witness to a verifier, again as bytes.
    let witness_bytes = updated.to_bytes()?;
    let shown = MembershipWitness::from_bytes(&params, &witness_bytes)?;
    step(
        shown.verify(&x, &decoded_pk, &decoded_acc),
        "verifier: decoded the updated witness against its toy set; it verifies",
    )?;

    // The same kinds of value, made under another parameter set: the toy set with a ternary
    // trapdoor. Each one is well formed, and each is refused on its 64-byte set prefix alone.
    let ternary = Arc::new(Params::try_from(
        ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary),
    )?);
    let other_key = SecretKey::new(None, Arc::clone(&ternary), &mut rng)?;
    let other_x = Element::hash(b"x", &ternary);
    let (other_acc, other_state) = Accumulator::with_elements(&other_key, from_ref(&other_x))?;
    let other_witness = MembershipWitness::new(&other_x, &other_acc, &other_key, &other_state)?;
    let refusals = [
        PublicKey::from_bytes(&params, &PublicKey::from(&other_key).to_bytes()).err(),
        Accumulator::from_bytes(&params, &other_acc.to_bytes()).err(),
        MembershipWitness::from_bytes(&params, &other_witness.to_bytes()?).err(),
    ];
    step(
        refusals
            .iter()
            .all(|e| *e == Some(Error::ParameterMismatch)),
        &format!(
            "verifier: a key, value and witness made under the ternary toy set are refused: \"{}\"",
            Error::ParameterMismatch
        ),
    )?;

    // Truncated bytes, and bytes with one extra at the end, are refused by their length.
    let truncated = PublicKey::from_bytes(&params, &pk_bytes[..pk_bytes.len() - 1]);
    let mut longer = acc_bytes.clone();
    longer.push(0);
    let lengthened = Accumulator::from_bytes(&params, &longer);
    step(
        matches!(truncated, Err(Error::InvalidEncodingLength(_)))
            && matches!(lengthened, Err(Error::InvalidEncodingLength(_))),
        "verifier: a public key missing its last byte and a value with one byte too many are refused",
    )?;

    // A corrupted value: its first coefficient overwritten with all ones, which is not a
    // number below the modulus q.
    let mut corrupted = acc_bytes.clone();
    corrupted[ParamsSpec::BYTES..ParamsSpec::BYTES + 8].fill(0xff);
    let refused = Accumulator::from_bytes(&params, &corrupted);
    step(
        matches!(refused, Err(Error::CoefficientOutOfRange)),
        &format!(
            "verifier: a value with a corrupted coefficient is refused: \"{}\"",
            Error::CoefficientOutOfRange
        ),
    )?;

    // A witness with one flipped bit may still decode to some short vector; it is then not a
    // witness for x. Either way the receiver does not end up accepting it.
    let mut flipped = witness_bytes.clone();
    flipped[ParamsSpec::BYTES] ^= 1;
    let outcome = match MembershipWitness::from_bytes(&params, &flipped) {
        Err(error) => Some(format!("refused at decoding: \"{error}\"")),
        Ok(w) if !w.verify(&x, &decoded_pk, &decoded_acc) => {
            Some("decoded, but does not verify".to_owned())
        }
        Ok(_) => None,
    };
    step(
        outcome.is_some(),
        &format!(
            "verifier: a witness with one flipped bit is {}",
            outcome.as_deref().unwrap_or("accepted")
        ),
    )?;

    // Update messages: empty bytes are refused at decoding, and an element too long for the
    // set (two bytes where the toy set's elements have eight bits) is refused by the check.
    let empty = Coefficient::try_from(&[0u8; 0][..]);
    let too_long = Coefficient::try_from(&[0u8, 1][..])?.validate(&params);
    step(
        empty.is_err() && too_long == Err(Error::InvalidElement),
        "holder: an empty update message and one naming a two-byte element are refused",
    )?;
    Ok(())
}
