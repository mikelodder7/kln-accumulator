// SPDX-License-Identifier: MIT OR Apache-2.0
//! C36: verification rejects the fixture's proof when any one part of the statement, or the
//! transcript label, differs from what the prover used.

use crate::fixture::{LABEL, PROOF, SETUP, statement};
use kln_accumulator::lattice::{Poly, PolyMatrix, PolyVec};
use kln_accumulator::{Error, LinkingRelation, MembershipStatement, ProofParams, verify};
use merlin::Transcript;

/// `v` with one added to the constant coefficient of its first entry.
fn bump_vec(v: &PolyVec) -> PolyVec {
    let mut entries: Vec<Poly> = v.clone().into();
    entries[0] = bump(&entries[0]);
    entries.into()
}

/// `p + 1`.
fn bump(p: &Poly) -> Poly {
    let ring = SETUP.pk.params().ring();
    let mut coefficients = vec![kln_accumulator::lattice::Coeff::ZERO; ring.degree()];
    coefficients[0] = kln_accumulator::lattice::Coeff::ONE;
    Poly::new(coefficients, ring)
        .and_then(|one| p.add(&one, ring))
        .expect("test fixture")
}

/// `m` with one added to the constant coefficient of entry `(0, 0)`.
fn bump_matrix(m: &PolyMatrix) -> PolyMatrix {
    let shape = m.shape();
    let mut entries: Vec<Poly> = (0..shape.rows)
        .flat_map(|i| (0..shape.cols).map(move |j| (i, j)))
        .filter_map(|(i, j)| m.get(i, j).cloned())
        .collect();
    entries[0] = bump(&entries[0]);
    PolyMatrix::new(shape, entries).expect("test fixture")
}

fn rejected(statement: &MembershipStatement<'_>, params: &ProofParams, label: &'static [u8]) {
    assert_eq!(
        verify(statement, &PROOF, params, &mut Transcript::new(label)),
        Err(Error::ProofRejected)
    );
}

#[test]
fn another_accumulator_value_is_rejected() {
    rejected(
        &MembershipStatement {
            accumulator: &SETUP.old_accumulator,
            ..statement()
        },
        &SETUP.params,
        LABEL,
    );
}

#[test]
fn another_linking_relation_is_rejected() {
    let relation = &SETUP.relation;
    let variants = [
        LinkingRelation::new(
            relation.a1().clone(),
            relation.a2().clone(),
            bump_vec(relation.t()),
        ),
        LinkingRelation::new(
            bump_matrix(relation.a1()),
            relation.a2().clone(),
            relation.t().clone(),
        ),
        LinkingRelation::new(
            relation.a1().clone(),
            bump_matrix(relation.a2()),
            relation.t().clone(),
        ),
    ];
    for variant in variants {
        let variant = variant.unwrap();
        rejected(
            &MembershipStatement {
                relation: &variant,
                ..statement()
            },
            &SETUP.params,
            LABEL,
        );
    }
}

/// Another public key is rejected both with the prover's proof parameters and with parameters
/// derived from that key.
#[test]
fn another_public_key_is_rejected() {
    let other = MembershipStatement {
        pubkey: &SETUP.other_pk,
        ..statement()
    };
    rejected(&other, &SETUP.params, LABEL);
    let params = ProofParams::new(&SETUP.other_pk, Some(b"kln/test/entropy")).unwrap();
    rejected(&other, &params, LABEL);
}

#[test]
fn another_transcript_label_is_rejected() {
    rejected(
        &statement(),
        &SETUP.params,
        b"kln proof test, another label",
    );
}

/// Proof parameters from another entropy input expand another commitment key.
#[test]
fn other_proof_params_are_rejected() {
    let params = ProofParams::new(&SETUP.pk, Some(b"kln/test/other entropy")).unwrap();
    rejected(&statement(), &params, LABEL);
}
