// SPDX-License-Identifier: MIT OR Apache-2.0
//! A toy accumulator with a member, a deleted element, a linking relation, a prepared setup for
//! its statement, and one proof made through the one-shot API.

pub use crate::rng::rng;
use kln_accumulator::lattice::{Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler};
use kln_accumulator::{
    Accumulator, Element, LinkingRelation, ManagerState, MembershipProof, MembershipSecret,
    MembershipStatement, MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey,
    prove,
};
use merlin::Transcript;
use std::{
    sync::{Arc, LazyLock},
    time::Instant,
};

/// The transcript label of the fixture's proof.
pub const LABEL: &[u8] = b"kln proof test";

/// The accumulator, its member `x` with a current witness, an element deleted after its witness
/// was issued, and the linking relation `A₁·x + A₂·r = t` for a binary `r`.
pub struct Setup {
    pub pk: PublicKey,
    pub other_pk: PublicKey,
    pub accumulator: Accumulator,
    pub old_accumulator: Accumulator,
    pub x: Element,
    pub witness: MembershipWitness,
    pub deleted: Element,
    pub deleted_witness: MembershipWitness,
    pub r: PolyVec,
    pub relation: LinkingRelation,
    pub params: ProofParams,
}

pub static SETUP: LazyLock<Setup> = LazyLock::new(|| {
    let toy = Arc::new(Params::toy().expect("test fixture"));
    let key = SecretKey::new(
        Some(b"kln/test/proof, a 32-byte test seed"),
        Arc::clone(&toy),
        &mut rng(0),
    )
    .expect("test fixture");
    let other = SecretKey::new(
        Some(b"kln/test/proof/other, a 32-byte seed"),
        Arc::clone(&toy),
        &mut rng(0),
    )
    .expect("test fixture");
    let pk = PublicKey::from(&key);
    let mut accumulator = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    let element = |i: u8| Element::try_from([i].as_slice()).expect("test fixture");
    let (x, deleted) = (element(0x5a), element(0xc3));
    accumulator
        .add_elements_assign(&key, &[x.clone(), deleted.clone(), element(1)], &mut state)
        .expect("test fixture");
    let deleted_witness =
        MembershipWitness::new(&deleted, &accumulator, &key, &state).expect("test fixture");
    let old_accumulator = accumulator.clone();
    let coefficients = accumulator
        .update_assign(&key, &[], std::slice::from_ref(&deleted), &mut state)
        .expect("test fixture");
    assert_eq!(coefficients.len(), 1);
    let witness = MembershipWitness::new(&x, &accumulator, &key, &state).expect("test fixture");
    let r = binary_vector(2, toy.ring());
    let relation = linking(&x, &r, &toy);
    let params = ProofParams::new(&pk, Some(b"kln/test/entropy")).expect("test fixture");
    Setup {
        pk,
        other_pk: PublicKey::from(&other),
        accumulator,
        old_accumulator,
        x,
        witness,
        deleted,
        deleted_witness,
        r,
        relation,
        params,
    }
});

/// A binary vector of `len` polynomials with a fixed pattern.
pub fn binary_vector(len: usize, ring: &kln_accumulator::lattice::Ring) -> PolyVec {
    (0..len)
        .map(|i| {
            let coefficients = (0..ring.degree())
                .map(|j| Coeff::from_u64(((i * 31 + j * 7) % 3 % 2) as u64))
                .collect();
            Poly::new(coefficients, ring).expect("test fixture")
        })
        .collect()
}

/// `A₁ ∈ R_q^{2×ℓ}` and `A₂ ∈ R_q^{2×len(r)}` uniform, and `t = A₁·x + A₂·r` with the bits of `x`
/// as constant polynomials.
pub fn linking(x: &Element, r: &PolyVec, params: &Params) -> LinkingRelation {
    let ring = params.ring();
    let mut sampler = UniformSampler::new(
        &Seed::from([5; 32]),
        DomainLabel::from(&b"kln/test/link"[..]),
    );
    let ell = params.spec().element_bits as usize;
    let a1 = sampler.matrix(Shape { rows: 2, cols: ell }, ring);
    let a2 = sampler.matrix(
        Shape {
            rows: 2,
            cols: r.len(),
        },
        ring,
    );
    let bits: PolyVec = x
        .to_bits(params)
        .expect("test fixture")
        .as_slice()
        .iter()
        .map(|&b| {
            let mut coefficients = vec![Coeff::ZERO; ring.degree()];
            coefficients[0] = Coeff::from_u64(u64::from(b));
            Poly::new(coefficients, ring).expect("test fixture")
        })
        .collect();
    let t = a1
        .mul_vec(&bits, ring)
        .and_then(|left| left.add(&a2.mul_vec(r, ring)?, ring))
        .expect("test fixture");
    LinkingRelation::new(a1, a2, t).expect("test fixture")
}

/// The setup for the fixture's public key, proof parameters and relation.
pub static PREPARED: LazyLock<ProofSetup> = LazyLock::new(|| {
    ProofSetup::new(&SETUP.pk, &SETUP.params, &SETUP.relation).expect("test fixture")
});

/// The statement the fixture's proof is for.
pub fn statement() -> MembershipStatement<'static> {
    MembershipStatement {
        pubkey: &SETUP.pk,
        accumulator: &SETUP.accumulator,
        relation: &SETUP.relation,
    }
}

/// A proof for `x` made by [`prove`] with a transcript labelled [`LABEL`].
pub static PROOF: LazyLock<MembershipProof> = LazyLock::new(|| {
    let setup = &*SETUP;
    let secret = MembershipSecret {
        element: &setup.x,
        witness: &setup.witness,
        r: &setup.r,
    };
    let start = Instant::now();
    let proof = prove(
        &statement(),
        &secret,
        &setup.params,
        &mut Transcript::new(LABEL),
        &mut rng(2),
    )
    .expect("test fixture");
    eprintln!(
        "one-shot proof: {:?}, {} bytes",
        start.elapsed(),
        proof.to_bytes().len()
    );
    proof
});
