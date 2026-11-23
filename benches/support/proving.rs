// SPDX-License-Identifier: MIT OR Apache-2.0
//! A Construction 4.1 member with a linking relation, its membership proofs, and their
//! LaBRADOR compressions. Proofs run only where the ring has degree 64, the toy set.

use crate::{base::Base, common::Outcome, variant::Fixture};
use kln_accumulator::lattice::{
    Coeff, DomainLabel, Poly, PolyVec, Ring, Seed, Shape, UniformSampler,
};
use kln_accumulator::{
    Challenge, CompressedMembershipProof, CompressionLevels, LinkingOpening, LinkingRelation,
    MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement, Params,
    ProofParams, ProofSetup, prove, verify, verify_with,
};
use merlin::Transcript;
use std::sync::Arc;

/// The transcript label of every proof the benchmarks make and verify.
pub const LABEL: &[u8] = b"kln/bench/proof";

/// The LaBRADOR compression levels the benchmarks and the size report measure.
pub const LEVELS: [u8; 3] = [1, 2, 3];

/// The statement and secret of a proof: a [`Fixture`] member, a binary `r`, and the linking
/// relation `A₁·x + A₂·r = t` with the bits of `x` as constant polynomials.
#[derive(Debug)]
pub struct Linked {
    /// The accumulator, its member and the member's witness.
    pub fixture: Fixture<Base>,
    /// `(A₁, A₂, t)`.
    pub relation: LinkingRelation,
    /// The binary vector `r`.
    pub r: PolyVec,
    /// The public proof parameters.
    pub proof_params: ProofParams,
}

impl Linked {
    /// The proof statement: public key, accumulator value and relation.
    pub fn statement(&self) -> MembershipStatement<'_> {
        MembershipStatement {
            pubkey: &self.fixture.public,
            accumulator: &self.fixture.value,
            relation: &self.relation,
        }
    }

    /// The prover's secret: element, witness and `r`.
    pub fn secret(&self) -> MembershipSecret<'_> {
        MembershipSecret {
            element: &self.fixture.member,
            witness: &self.fixture.witness,
            r: &self.r,
        }
    }

    /// Builds the fixture at `params` and a relation for its member.
    fn new(params: Arc<Params>) -> Outcome<Self> {
        let fixture = Fixture::<Base>::new(params, 1)?;
        let params = &*fixture.params;
        let ring = params.ring();
        let bits = fixture
            .member
            .to_bits(params)?
            .as_slice()
            .iter()
            .map(|&bit| constant(bit, ring))
            .collect::<Result<PolyVec, _>>()?;
        let r = PolyVec::from(vec![constant(true, ring)?]);
        let mut uniform = UniformSampler::new(
            &Seed::from([5; 32]),
            DomainLabel::from(&b"kln/bench/link"[..]),
        );
        let a1 = uniform.matrix(
            Shape {
                rows: 1,
                cols: bits.len(),
            },
            ring,
        );
        let a2 = uniform.matrix(
            Shape {
                rows: 1,
                cols: r.len(),
            },
            ring,
        );
        let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
        let relation = LinkingRelation::new(a1, a2, t)?;
        let proof_params = ProofParams::new(&fixture.public, Some(b"kln/bench/entropy"))?;
        Ok(Self {
            fixture,
            relation,
            r,
            proof_params,
        })
    }
}

/// The constant polynomial `bit`.
fn constant(bit: bool, ring: &Ring) -> kln_accumulator::Result<Poly> {
    let mut coefficients = vec![Coeff::ZERO; ring.degree()];
    if let Some(first) = coefficients.first_mut() {
        *first = Coeff::from_u64(u64::from(bit));
    }
    Poly::new(coefficients, ring)
}

/// A [`Linked`] statement with every proof the benchmarks verify or compress, each checked.
#[derive(Debug)]
pub struct Proving {
    /// The statement and secret.
    pub linked: Linked,
    /// The setup for the statement's public key, proof parameters and relation shape.
    pub setup: ProofSetup,
    /// A proof by [`prove`] under a transcript labelled [`LABEL`].
    pub proof: MembershipProof,
    /// The outer challenge of the three-step form.
    pub challenge: Challenge,
    /// A proof by [`MembershipProofCommitting::gen_proof`] at `challenge`, the form
    /// [`MembershipProof::compress`] takes.
    pub framed: MembershipProof,
    /// `framed` compressed at each of [`LEVELS`], in order.
    pub compressed: Vec<CompressedMembershipProof>,
}

impl Proving {
    /// Builds the statement at `params` and its setup, proves it in both forms, compresses the
    /// three-step proof at each of [`LEVELS`], and verifies every proof once, the one-shot proof
    /// with and without the setup.
    ///
    /// # Errors
    ///
    /// Any error of those operations.
    pub fn new(params: Arc<Params>) -> Outcome<Self> {
        let linked = Linked::new(params)?;
        let statement = linked.statement();
        let mut rng = crate::common::rng(2);
        let proof = prove(
            &statement,
            &linked.secret(),
            &linked.proof_params,
            &mut Transcript::new(LABEL),
            &mut rng,
        )?;
        verify(
            &statement,
            &proof,
            &linked.proof_params,
            &mut Transcript::new(LABEL),
        )?;
        let setup = ProofSetup::new(
            &linked.fixture.public,
            &linked.proof_params,
            &linked.relation,
        )?;
        verify_with(
            &statement,
            &proof,
            &linked.proof_params,
            &setup,
            &mut Transcript::new(LABEL),
        )?;
        let fixture = &linked.fixture;
        let committing = MembershipProofCommitting::new(
            &fixture.member,
            &fixture.witness,
            &linked.proof_params,
            &fixture.public,
            &fixture.value,
            LinkingOpening {
                relation: &linked.relation,
                r: &linked.r,
            },
            &mut rng,
        )?;
        let mut transcript = Transcript::new(LABEL);
        committing.get_bytes_for_challenge(&mut transcript);
        let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
        let framed = committing.gen_proof(&challenge)?;
        let compressed = LEVELS
            .iter()
            .map(|&levels| {
                let compressed = framed.compress(
                    &statement,
                    &linked.proof_params,
                    &challenge,
                    CompressionLevels::try_from(levels)?,
                )?;
                let _ = compressed.finalize(
                    &fixture.value,
                    &linked.proof_params,
                    &fixture.public,
                    &challenge,
                    &linked.relation,
                )?;
                Ok(compressed)
            })
            .collect::<Outcome<Vec<_>>>()?;
        Ok(Self {
            linked,
            setup,
            proof,
            challenge,
            framed,
            compressed,
        })
    }
}
