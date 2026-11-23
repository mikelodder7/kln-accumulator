// SPDX-License-Identifier: MIT OR Apache-2.0
//! Membership proofs in zero knowledge, for Appendix D.2 of ePrint 2025/1099.
//!
//! Two holders each prove that their element is in the accumulator without revealing which
//! element it is, and a verifier checks both proofs against one prepared `ProofSetup`, built
//! once and reused. A proof is refused when it is checked against another holder's statement,
//! in another session, or against a value that has since moved. The holder then updates its
//! witness, proves again in the three-step form and compresses the proof; the sizes are
//! printed.
//!
//! **This run is slower than the others.** It makes three proofs, each a few seconds on
//! average: the prover restarts until its randomness passes a check, and how many restarts it
//! needs varies from proof to proof. The setup holds a commitment key of about 160 MB. Expect
//! about a quarter of a minute with `--release` on an idle machine. Proofs run only at the toy parameter sets, which
//! give no security.
//!
//! Run it with `cargo run --release --example proofs`.

use kln_accumulator::lattice::{Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler};
use kln_accumulator::{
    Accumulator, Challenge, CompressedMembershipProof, CompressionLevels, Element, Error,
    LinkingRelation, MembershipProof, MembershipProofCommitting, MembershipSecret,
    MembershipStatement, MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey,
    prove_with, verify_with,
};
use merlin::Transcript;
use rand::{SeedableRng, rngs::StdRng};
use std::slice::from_ref;
use std::sync::Arc;
use std::time::Instant;

/// Prints one step of the run, or ends the run with an error when what the step shows is false.
fn step(holds: bool, line: &str) -> Result<(), String> {
    if holds {
        println!("{line}");
        Ok(())
    } else {
        Err(format!("this step does not hold: {line}"))
    }
}

/// A stand-in linking relation `A₁·x + A₂·r = t` for the element `x`, and the holder's binary
/// vector `r`. A proof always speaks about such a relation: in a real protocol `t` is a
/// commitment to `x` inside the holder's credential, with `r` secret and random. Here `A₁` and
/// `A₂` come from a fixed public seed and `r` is fixed too, so this `t` hides nothing and ties
/// `x` to nothing a verifier cares about. It only shows the API.
fn linking(x: &Element, params: &Params) -> Result<(LinkingRelation, PolyVec), Error> {
    let ring = params.ring();
    // A bit as a constant polynomial.
    let constant = |bit: bool| {
        let mut coefficients = vec![Coeff::ZERO; ring.degree()];
        coefficients[0] = Coeff::from_u64(u64::from(bit));
        Poly::new(coefficients, ring)
    };
    let bits = x
        .to_bits(params)?
        .as_slice()
        .iter()
        .map(|&bit| constant(bit))
        .collect::<Result<PolyVec, _>>()?;
    let r = PolyVec::from(vec![constant(true)?]);
    let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    let a1 = sampler.matrix(
        Shape {
            rows: 1,
            cols: bits.len(),
        },
        ring,
    );
    let a2 = sampler.matrix(
        Shape {
            rows: 1,
            cols: r.len(),
        },
        ring,
    );
    let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    Ok((LinkingRelation::new(a1, a2, t)?, r))
}

/// The transcript both sides start from: a protocol label, then the verifier's fresh nonce for
/// this session. Binding both stops a proof from being replayed to another verifier.
fn session(nonce: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(b"my-protocol presentation v1");
    transcript.append_message(b"verifier nonce", nonce);
    transcript
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
    let mut rng = StdRng::seed_from_u64(0);
    let params = Arc::new(Params::toy()?);
    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);
    let [x, y, w] = [b"x", b"y", b"w"].map(|name| Element::hash(name, &params));
    let (mut acc, mut state) =
        Accumulator::with_elements(&key, &[x.clone(), y.clone(), w.clone()])?;
    let witness_x = MembershipWitness::new(&x, &acc, &key, &state)?;
    let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
    println!("manager: added x, y and w and issued x and y their witnesses");

    // Both sides derive the same public proof parameters from the public key.
    let proof_params = ProofParams::new(&pk, None)?;
    let (relation_x, r_x) = linking(&x, &params)?;
    let (relation_y, r_y) = linking(&y, &params)?;

    // The setup depends only on public values: the public key, the proof parameters and the
    // shape of the relation. One setup therefore serves every holder whose relation has that
    // shape, and keeps working after the accumulator value changes. Prover and verifier would
    // each build their own; here one program plays both and shares it.
    let started = Instant::now();
    let setup = ProofSetup::new(&pk, &proof_params, &relation_x)?;
    println!(
        "verifier: prepared one proof setup in {:.1} s; every proof below reuses it",
        started.elapsed().as_secs_f64()
    );

    let statement_x = MembershipStatement {
        pubkey: &pk,
        accumulator: &acc,
        relation: &relation_x,
    };
    let statement_y = MembershipStatement {
        pubkey: &pk,
        accumulator: &acc,
        relation: &relation_y,
    };
    let secret_x = MembershipSecret {
        element: &x,
        witness: &witness_x,
        r: &r_x,
    };
    let secret_y = MembershipSecret {
        element: &y,
        witness: &witness_y,
        r: &r_y,
    };

    // Each holder proves in its own session. The proof carries neither the element nor the
    // witness.
    let started = Instant::now();
    let proof_x = prove_with(
        &statement_x,
        &secret_x,
        &proof_params,
        &setup,
        &mut session(b"session 1"),
        &mut rng,
    )?;
    println!(
        "holder of x: proved membership in session 1 in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    let started = Instant::now();
    let proof_y = prove_with(
        &statement_y,
        &secret_y,
        &proof_params,
        &setup,
        &mut session(b"session 2"),
        &mut rng,
    )?;
    println!(
        "holder of y: proved membership in session 2 in {:.1} s",
        started.elapsed().as_secs_f64()
    );

    // Only `Ok` means accept.
    let started = Instant::now();
    verify_with(
        &statement_x,
        &proof_x,
        &proof_params,
        &setup,
        &mut session(b"session 1"),
    )?;
    verify_with(
        &statement_y,
        &proof_y,
        &proof_params,
        &setup,
        &mut session(b"session 2"),
    )?;
    println!(
        "verifier: both proofs verify against the one setup, in {:.1} s for the two",
        started.elapsed().as_secs_f64()
    );

    let wrong_statement = verify_with(
        &statement_y,
        &proof_x,
        &proof_params,
        &setup,
        &mut session(b"session 1"),
    );
    step(
        matches!(wrong_statement, Err(Error::ProofRejected)),
        &format!(
            "verifier: x's proof checked against y's statement is refused: \"{}\"",
            Error::ProofRejected
        ),
    )?;
    let replayed = verify_with(
        &statement_x,
        &proof_x,
        &proof_params,
        &setup,
        &mut session(b"session 3"),
    );
    step(
        matches!(replayed, Err(Error::ProofRejected)),
        "verifier: x's proof replayed into another session is refused",
    )?;

    // The manager deletes w and publishes the update. Verifiers now check against the new
    // value, and a proof made against the old one no longer counts.
    let messages = acc.update_assign(&key, &[], from_ref(&w), &mut state)?;
    let fresh_x = MembershipStatement {
        pubkey: &pk,
        accumulator: &acc,
        relation: &relation_x,
    };
    let stale = verify_with(
        &fresh_x,
        &proof_x,
        &proof_params,
        &setup,
        &mut session(b"session 1"),
    );
    step(
        matches!(stale, Err(Error::ProofRejected)),
        "manager: deleted w; verifier: x's earlier proof is refused against the new value",
    )?;

    // The holder of x updates its witness from the published message and proves again, this
    // time in the three-step form, which exposes the challenge. Compression needs it.
    let witness_x = witness_x.batch_update(&x, &[], from_ref(&w), &messages, &pk)?;
    let secret_x = MembershipSecret {
        element: &x,
        witness: &witness_x,
        r: &r_x,
    };
    let started = Instant::now();
    let committing =
        MembershipProofCommitting::new_with(&secret_x, &proof_params, &setup, &fresh_x, &mut rng)?;
    let mut transcript = session(b"session 4");
    committing.get_bytes_for_challenge(&mut transcript);
    let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    let proof = committing.gen_proof(&challenge)?;
    // Dropping the prover's state wipes the secrets it held.
    drop(committing);
    println!(
        "holder of x: updated its witness and proved again in session 4 in {:.1} s",
        started.elapsed().as_secs_f64()
    );

    // The proof travels as bytes. The verifier runs every check for the challenge the proof
    // claims, then rederives the challenge from its own transcript; only a match binds the
    // proof to this session.
    let wire = proof.to_bytes();
    let received = MembershipProof::try_from(wire.as_slice())?;
    let finalized =
        received.finalize_with(&acc, &proof_params, &setup, &pk, &challenge, &relation_x)?;
    let mut verifier = session(b"session 4");
    finalized.get_bytes_for_challenge(&mut verifier);
    step(
        Challenge::from_transcript(b"challenge", &mut verifier) == challenge,
        &format!(
            "verifier: received the {} byte proof; it verifies against the new value",
            wire.len()
        ),
    )?;

    // Anyone holding the proof can compress it: the parts it replaces are public.
    let started = Instant::now();
    let levels = CompressionLevels::try_from(1)?;
    let compressed = received.compress_with(&fresh_x, &proof_params, &setup, &challenge, levels)?;
    let compressed_wire = Vec::from(&compressed);
    println!(
        "holder of x: compressed the proof from {} to {} bytes with {} LaBRADOR level in {:.1} s",
        wire.len(),
        compressed_wire.len(),
        levels.get(),
        started.elapsed().as_secs_f64()
    );
    let received = CompressedMembershipProof::try_from(compressed_wire.as_slice())?;
    let finalized_compressed =
        received.finalize_with(&acc, &proof_params, &setup, &pk, &challenge, &relation_x)?;
    step(
        finalized_compressed == finalized,
        "verifier: the compressed proof verifies and binds to the same session",
    )?;
    Ok(())
}
