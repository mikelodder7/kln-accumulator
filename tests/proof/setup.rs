// SPDX-License-Identifier: MIT OR Apache-2.0
//! The prepared setup: every operation that takes one refuses, with `ParameterMismatch`, a setup
//! built for a relation of another shape, for other proof parameters or for another parameter
//! set, before it touches the transcript or the randomness it was given.

use crate::{
    compressed,
    fixture::{LABEL, PROOF, SETUP, binary_vector, linking, rng, statement},
};
use kln_accumulator::{
    Challenge, CompressionLevels, Error, MembershipProofCommitting, MembershipSecret, Params,
    ParamsSpec, ProofParams, ProofSetup, PublicKey, SecretKey, TrapdoorDistribution, prove_with,
    verify_with,
};
use merlin::Transcript;
use rand::Rng;
use std::sync::Arc;

/// The challenge a transcript labelled [`LABEL`] gives after `absorb`, which tells whether
/// `absorb` appended anything.
fn challenge_after(absorb: impl FnOnce(&mut Transcript)) -> Challenge {
    let mut transcript = Transcript::new(LABEL);
    absorb(&mut transcript);
    Challenge::from_transcript(b"challenge", &mut transcript)
}

/// Runs every operation that takes a setup with `setup` on the fixture's statement and asserts
/// that each refuses it, the provers without drawing from their randomness and the one-shot
/// operations without touching their transcript.
fn assert_refused(setup: &ProofSetup, name: &str) {
    let fixture = &*SETUP;
    let refused = Err(Error::ParameterMismatch);
    let secret = MembershipSecret {
        element: &fixture.x,
        witness: &fixture.witness,
        r: &fixture.r,
    };
    let fresh = challenge_after(|_| ());
    let unused = rng(9).next_u64();

    let mut prover = rng(9);
    let mut result = Ok(());
    let after = challenge_after(|transcript| {
        result = prove_with(
            &statement(),
            &secret,
            &fixture.params,
            setup,
            transcript,
            &mut prover,
        )
        .map(drop);
    });
    assert_eq!(result, refused, "{name}: prove_with");
    assert_eq!(after, fresh, "{name}: prove_with transcript");
    assert_eq!(prover.next_u64(), unused, "{name}: prove_with rng");

    let after = challenge_after(|transcript| {
        result = verify_with(&statement(), &PROOF, &fixture.params, setup, transcript);
    });
    assert_eq!(result, refused, "{name}: verify_with");
    assert_eq!(after, fresh, "{name}: verify_with transcript");

    let mut prover = rng(9);
    assert_eq!(
        MembershipProofCommitting::new_with(
            &secret,
            &fixture.params,
            setup,
            &statement(),
            &mut prover
        )
        .map(drop),
        refused,
        "{name}: new_with"
    );
    assert_eq!(prover.next_u64(), unused, "{name}: new_with rng");

    let challenge = Challenge::from([0; 64]);
    assert_eq!(
        PROOF
            .finalize_with(
                &fixture.accumulator,
                &fixture.params,
                setup,
                &fixture.pk,
                &challenge,
                &fixture.relation,
            )
            .map(drop),
        refused,
        "{name}: finalize_with"
    );
    let levels = CompressionLevels::try_from(1).expect("test fixture");
    assert_eq!(
        PROOF
            .compress_with(&statement(), &fixture.params, setup, &challenge, levels)
            .map(drop),
        refused,
        "{name}: compress_with"
    );
    assert_eq!(
        compressed::proof(1)
            .finalize_with(
                &fixture.accumulator,
                &fixture.params,
                setup,
                &fixture.pk,
                &challenge,
                &fixture.relation,
            )
            .map(drop),
        refused,
        "{name}: CompressedMembershipProof::finalize_with"
    );
}

/// A setup for a relation with a three-entry `r`, for other proof parameters, and for the toy
/// set with a ternary trapdoor is each refused by every operation that takes a setup. The setups
/// are built one at a time, since each holds a commitment key of about 160 MB.
#[test]
fn mismatched_setups_are_refused() {
    let fixture = &*SETUP;
    let params = fixture.pk.params();
    let wider = linking(&fixture.x, &binary_vector(3, params.ring()), params);
    let shape = ProofSetup::new(&fixture.pk, &fixture.params, &wider).unwrap();
    assert_refused(&shape, "another relation shape");
    drop(shape);

    let other_params = ProofParams::new(&fixture.pk, Some(b"kln/test/other entropy")).unwrap();
    let proof_params = ProofSetup::new(&fixture.pk, &other_params, &fixture.relation).unwrap();
    assert_refused(&proof_params, "other proof parameters");
    drop(proof_params);

    let ternary = Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))
        .map(Arc::new)
        .unwrap();
    let key = SecretKey::new(
        Some(b"kln/test/proof/ternary, a 32-byte seed"),
        ternary,
        &mut rng(0),
    )
    .unwrap();
    let set = ProofSetup::new(&PublicKey::from(&key), &fixture.params, &fixture.relation).unwrap();
    assert_refused(&set, "another parameter set");
}
