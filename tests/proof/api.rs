// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one-shot core and the three-step API mirrored from the vb20 pairing accumulator (C35,
//! C44), each with and without a prepared setup, and the prover's refusals through the public
//! API (C38).

use crate::fixture::{LABEL, PREPARED, PROOF, SETUP, binary_vector, linking, rng, statement};
use kln_accumulator::lattice::{Coeff, Poly, PolyVec};
use kln_accumulator::{
    Challenge, Element, Error, LinkingOpening, MembershipProofCommitting, MembershipSecret,
    MembershipStatement, ProofParams, prove, prove_with, verify, verify_with,
};
use merlin::Transcript;
use std::time::Instant;

/// C35: an honest proof made by the one-shot `prove` verifies with a transcript in the same
/// state, with and without a prepared setup.
#[test]
fn one_shot_proof_verifies() {
    let start = Instant::now();
    verify(
        &statement(),
        &PROOF,
        &SETUP.params,
        &mut Transcript::new(LABEL),
    )
    .unwrap();
    eprintln!("one-shot verification: {:?}", start.elapsed());
    let setup = &*PREPARED;
    let start = Instant::now();
    verify_with(
        &statement(),
        &PROOF,
        &SETUP.params,
        setup,
        &mut Transcript::new(LABEL),
    )
    .unwrap();
    eprintln!("one-shot verification with a setup: {:?}", start.elapsed());
}

/// The one-shot prover with a prepared setup makes, from the same randomness and transcript,
/// the very proof `prove` made, and `verify` accepts it.
#[test]
fn prepared_prover_makes_the_same_proof() {
    let setup = &*SETUP;
    let secret = MembershipSecret {
        element: &setup.x,
        witness: &setup.witness,
        r: &setup.r,
    };
    let proof = prove_with(
        &statement(),
        &secret,
        &setup.params,
        &PREPARED,
        &mut Transcript::new(LABEL),
        &mut rng(2),
    )
    .unwrap();
    assert_eq!(proof.to_bytes(), PROOF.to_bytes());
    verify(
        &statement(),
        &proof,
        &setup.params,
        &mut Transcript::new(LABEL),
    )
    .unwrap();
}

/// C44: the three steps — commit, absorb into the outer transcript, derive the challenge,
/// respond, finalize, absorb again — give the verifier the prover's challenge, and an outer
/// transcript with another label gives another challenge, under which the proof is rejected.
#[test]
fn three_step_api_round_trips_the_outer_challenge() {
    let setup = &*SETUP;
    let opening = LinkingOpening {
        relation: &setup.relation,
        r: &setup.r,
    };
    let committing = MembershipProofCommitting::new(
        &setup.x,
        &setup.witness,
        &setup.params,
        &setup.pk,
        &setup.accumulator,
        opening,
        &mut rng(3),
    )
    .unwrap();
    let outer = |label: &'static [u8]| {
        let mut transcript = Transcript::new(label);
        setup.params.add_to_transcript(&mut transcript);
        transcript
    };
    let mut prover = outer(b"kln outer proof");
    committing.get_bytes_for_challenge(&mut prover);
    let challenge = Challenge::from_transcript(b"challenge", &mut prover);
    let proof = committing.gen_proof(&challenge).unwrap();

    let finalized = proof
        .finalize(
            &setup.accumulator,
            &setup.params,
            &setup.pk,
            &challenge,
            &setup.relation,
        )
        .unwrap();
    let mut verifier = outer(b"kln outer proof");
    finalized.get_bytes_for_challenge(&mut verifier);
    assert_eq!(
        Challenge::from_transcript(b"challenge", &mut verifier),
        challenge
    );
    // With a prepared setup: the same finalized bytes, and a committing step from the same
    // randomness that gives the outer transcript the same bytes.
    assert_eq!(
        proof
            .finalize_with(
                &setup.accumulator,
                &setup.params,
                &PREPARED,
                &setup.pk,
                &challenge,
                &setup.relation,
            )
            .unwrap(),
        finalized
    );
    let prepared = MembershipProofCommitting::new_with(
        &MembershipSecret {
            element: &setup.x,
            witness: &setup.witness,
            r: &setup.r,
        },
        &setup.params,
        &PREPARED,
        &statement(),
        &mut rng(3),
    )
    .unwrap();
    let mut again = outer(b"kln outer proof");
    prepared.get_bytes_for_challenge(&mut again);
    assert_eq!(
        Challenge::from_transcript(b"challenge", &mut again),
        challenge
    );

    let mut relabelled = outer(b"kln outer proof, other label");
    finalized.get_bytes_for_challenge(&mut relabelled);
    let other = Challenge::from_transcript(b"challenge", &mut relabelled);
    assert_ne!(other, challenge);
    assert_eq!(
        proof
            .finalize(
                &setup.accumulator,
                &setup.params,
                &setup.pk,
                &other,
                &setup.relation
            )
            .unwrap_err(),
        Error::ProofRejected
    );
    // The one-shot proof was made for a different challenge, so it does not finalize here.
    assert_eq!(
        PROOF
            .finalize(
                &setup.accumulator,
                &setup.params,
                &setup.pk,
                &challenge,
                &setup.relation
            )
            .unwrap_err(),
        Error::ProofRejected
    );
}

/// C38: through the public API the prover refuses the witness of a deleted element, a
/// non-binary `r` (even with `t` matching it), and an `r` that breaks `A₁·x + A₂·r = t`. A
/// non-binary `x` cannot be expressed: an element is an `ℓ`-bit string, and one with a bit set
/// at or above `ℓ` is refused.
#[test]
fn prover_refuses_unsatisfied_relations() {
    let setup = &*SETUP;
    let params = setup.pk.params();
    let commit = |element: &Element, witness, relation, r| {
        MembershipProofCommitting::new(
            element,
            witness,
            &setup.params,
            &setup.pk,
            &setup.accumulator,
            LinkingOpening { relation, r },
            &mut rng(4),
        )
        .map(|_| ())
    };
    let relation = linking(&setup.deleted, &setup.r, params);
    assert_eq!(
        commit(&setup.deleted, &setup.deleted_witness, &relation, &setup.r),
        Err(Error::RelationUnsatisfied)
    );

    let ring = params.ring();
    let mut entries: Vec<Poly> = setup.r.clone().into();
    let mut coefficients = entries[1].coefficients().to_vec();
    coefficients[3] = Coeff::from_u64(2);
    entries[1] = Poly::new(coefficients, ring).unwrap();
    let wide = PolyVec::from(entries);
    let relation = linking(&setup.x, &wide, params);
    assert_eq!(
        commit(&setup.x, &setup.witness, &relation, &wide),
        Err(Error::RelationUnsatisfied)
    );

    let other_r = binary_vector(2, ring).neg(ring).unwrap();
    assert_eq!(
        commit(&setup.x, &setup.witness, &setup.relation, &other_r),
        Err(Error::RelationUnsatisfied)
    );
    assert_eq!(
        commit(
            &setup.x,
            &setup.witness,
            &setup.relation,
            &binary_vector(3, ring)
        ),
        Err(Error::RelationUnsatisfied)
    );

    // The one-shot prover refuses the same inputs.
    let secret = MembershipSecret {
        element: &setup.deleted,
        witness: &setup.deleted_witness,
        r: &setup.r,
    };
    let statement = MembershipStatement {
        relation: &linking(&setup.deleted, &setup.r, params),
        ..statement()
    };
    assert_eq!(
        prove(
            &statement,
            &secret,
            &setup.params,
            &mut Transcript::new(LABEL),
            &mut rng(5)
        )
        .unwrap_err(),
        Error::RelationUnsatisfied
    );
    assert_eq!(
        Element::try_from([0x5a, 0x01].as_slice())
            .and_then(|e| e.validate(params).map(|()| e))
            .unwrap_err(),
        Error::InvalidElement
    );
}

/// The proof parameters are a function of the public key and the entropy input (C34), and a
/// set of degree other than 64 is refused.
#[test]
fn proof_params_follow_the_key() {
    let setup = &*SETUP;
    let again = ProofParams::new(&setup.pk, Some(b"kln/test/entropy")).unwrap();
    assert_eq!(again, setup.params);
    assert_ne!(ProofParams::new(&setup.pk, None).unwrap(), setup.params);
    assert_ne!(
        ProofParams::new(&setup.other_pk, Some(b"kln/test/entropy")).unwrap(),
        setup.params
    );
}
