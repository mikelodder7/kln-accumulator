// SPDX-License-Identifier: MIT OR Apache-2.0
//! The non-interactive LNP protocol of D.2.2 (lines 2782–3246): the prover's rounds with their
//! rejection-sampling restarts, the verifier's equations D.12, and the proof types of the
//! three-step API.
//!
//! Fiat–Shamir replaces each verifier message by a challenge of the inner merlin transcript,
//! which starts from the outer challenge, the statement digest and `t_A`:
//!
//! | round | prover sends | challenge |
//! |---|---|---|
//! | 1 | `w = Ā₁y₁ + Ā₂y₂`, `t_y = B̄_y·s₂ + y₃` | `R ← Bin₁^{256×m̄₁d}` |
//! | 3 | `z₃ = R·s₁ + y₃` (after rejection), `t_p = B̄_p·s₂ + p` | `α ∈ Z_q^{τ×257}` |
//! | 5 | `h₁, …, h_τ` | `γ₁, γ₂, γ₃, γ₄` |
//! | 7 | `t_quad = B̄_quad·s₂ + g₁`, `v = B̄_quad·y₂ + g₀` | `c ∈ C` |
//! | 9 | `z₁ = y₁ + c·s₁`, `z₂ = y₂ + c·s₂` (after rejection) | |
//!
//! An abort in round 3 or 9 restarts the prover at round 1 with fresh masks; `s₂`, and so
//! `t_A`, stay fixed.

use super::{
    Challenge, LinkingOpening, LinkingRelation, MembershipSecret, MembershipStatement, ProofParams,
    ProofSetup,
    abdlop::BdlopRows,
    append_commitment, append_vec, challenge, challenge_seed,
    coeffs::{centred, from_integers, inner, mul_each, mul_each_transformed, transform},
    labrador::{self, CompressedMembershipProof, CompressionLevels},
    params::LnpParameters,
    range::BinomialMatrix,
    rejection::accept,
    relation::{
        Gammas, Opening, Relation, RelationInputs, binary_weight, ones, range_polys,
        sigma_transforms,
    },
};
use crate::{
    accumulator::{Accumulator, Element},
    error::{Error, Result, check_dimension},
    gaussian::Lookup,
    key::PublicKey,
    poly::Poly,
    ring::{NttPoly, Ring},
    sample::{DomainLabel, Seed, UniformSampler, hash_parts, xof},
    vector::{PolyVec, encode_entries},
    witness::MembershipWitness,
    zq::Coeff,
};
use crypto_bigint::U512;
use merlin::Transcript;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use shake::{Shake256Reader, digest::XofReader};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Label of the prover's mask stream for one attempt.
const LABEL_MASKS: &[u8] = b"kln/lnp/masks";
/// Label of the uniform stream of `α`.
const LABEL_ALPHA: &[u8] = b"kln/lnp/alpha";
/// Label of the uniform stream of `γ₁, …, γ₄`.
const LABEL_GAMMA: &[u8] = b"kln/lnp/gamma";
/// Label of the stream the final challenge `c` is drawn from.
const LABEL_CHALLENGE: &[u8] = b"kln/lnp/c";
/// Label of the garbage polynomials `p`.
const LABEL_GARBAGE: &[u8] = b"kln/lnp/p";
/// The most restarts the prover makes before giving up; about `e³ ≈ 20` are expected.
const MAX_ATTEMPTS: u32 = 1000;

/// A membership proof: the messages of rounds 1 to 9, with `t_A`. The challenges are rederived
/// by the verifier. Serialized field by field; polynomials are hex strings in human-readable
/// formats and raw bytes in binary ones. **Public.** 9,100,960 bytes (8.68 MiB)
/// from [`MembershipProof::to_bytes`] at the toy set.
///
/// # Examples
///
/// ```no_run
/// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
/// # use kln_accumulator::{
/// #     Accumulator, Challenge, CompressionLevels, Element, LinkingOpening, LinkingRelation,
/// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
/// #     MembershipWitness, Params, ProofParams, PublicKey, SecretKey, prove, verify,
/// # };
/// # use kln_accumulator::lattice::{
/// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
/// # };
/// # use merlin::Transcript;
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let params = Arc::clone(key.params());
/// # let ring = params.ring();
/// # let x = Element::hash(b"x", &params);
/// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
/// # let constant = |b: bool| {
/// #     let mut c = vec![Coeff::ZERO; ring.degree()];
/// #     c[0] = Coeff::from_u64(u64::from(b));
/// #     Poly::new(c, ring)
/// # };
/// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
/// # let r = PolyVec::from(vec![Poly::new(
/// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
/// #     ring,
/// # )?]);
/// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
/// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
/// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
/// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
/// # let relation = LinkingRelation::new(a1, a2, t)?;
/// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
/// let committing = MembershipProofCommitting::new(
///     &x, &witness, &proof_params, &pk, &acc,
///     LinkingOpening { relation: &relation, r: &r },
///     &mut rng,
/// )?;
/// let mut transcript = Transcript::new(b"presentation");
/// committing.get_bytes_for_challenge(&mut transcript);
/// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
/// let proof = committing.gen_proof(&challenge)?;
/// let bytes = proof.to_bytes();
/// assert_eq!(MembershipProof::try_from(bytes.as_slice())?, proof);
/// proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipProof {
    pub(crate) t_a: PolyVec,
    pub(crate) w: PolyVec,
    pub(crate) t_y: PolyVec,
    pub(crate) z3: PolyVec,
    pub(crate) t_p: PolyVec,
    pub(crate) h: PolyVec,
    pub(crate) t_quad: Poly,
    pub(crate) v: Poly,
    pub(crate) z1: PolyVec,
    pub(crate) z2: PolyVec,
}

impl MembershipProof {
    /// Runs every check of D.12 against the statement `(accumulator, pubkey, relation)` for the
    /// outer `challenge`, and returns what the verifier's outer transcript must absorb to
    /// rederive that challenge. Fails with [`Error::ProofRejected`] when a check fails. See the
    /// book's chapter "Membership proofs" for the whole flow.
    ///
    /// # Errors
    ///
    /// As above; [`Error::UnsupportedProofDegree`] and [`Error::ParameterMismatch`] as for
    /// [`crate::prove`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, Error, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey, prove,
    /// #     prove_with, verify, verify_with,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// # let committing = MembershipProofCommitting::new(
    /// #     &x, &witness, &proof_params, &pk, &acc,
    /// #     LinkingOpening { relation: &relation, r: &r },
    /// #     &mut rng,
    /// # )?;
    /// # let mut prover = Transcript::new(b"presentation");
    /// # committing.get_bytes_for_challenge(&mut prover);
    /// # let challenge = Challenge::from_transcript(b"challenge", &mut prover);
    /// # let proof = committing.gen_proof(&challenge)?;
    /// // Verifier: every check for the challenge the prover claims...
    /// let finalized = proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
    /// // ...then rederive the challenge from its own transcript and compare. Misuse: skipping
    /// // this comparison leaves the proof unbound to the session.
    /// let mut verifier = Transcript::new(b"presentation");
    /// finalized.get_bytes_for_challenge(&mut verifier);
    /// assert_eq!(Challenge::from_transcript(b"challenge", &mut verifier), challenge);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn finalize(
        &self,
        accumulator: &Accumulator,
        proof_params: &ProofParams,
        pubkey: &PublicKey,
        challenge: &Challenge,
        relation: &LinkingRelation,
    ) -> Result<MembershipProofFinal> {
        let setup = ProofSetup::new(pubkey, proof_params, relation)?;
        self.finalize_with(
            accumulator,
            proof_params,
            &setup,
            pubkey,
            challenge,
            relation,
        )
    }

    /// [`MembershipProof::finalize`] with the values `setup` holds in place of deriving them.
    /// Fails with [`Error::ParameterMismatch`], before any check, unless `setup` was built for
    /// `pubkey`'s parameter set, for `proof_params` and for a relation of `relation`'s shape.
    ///
    /// # Errors
    ///
    /// As above, and as [`MembershipProof::finalize`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, Error, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey, prove,
    /// #     prove_with, verify, verify_with,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// let setup = ProofSetup::new(&pk, &proof_params, &relation)?;
    /// let committing = MembershipProofCommitting::new(
    ///     &x, &witness, &proof_params, &pk, &acc,
    ///     LinkingOpening { relation: &relation, r: &r },
    ///     &mut rng,
    /// )?;
    /// let mut transcript = Transcript::new(b"presentation");
    /// committing.get_bytes_for_challenge(&mut transcript);
    /// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    /// let proof = committing.gen_proof(&challenge)?;
    /// assert_eq!(
    ///     proof.finalize_with(&acc, &proof_params, &setup, &pk, &challenge, &relation)?,
    ///     proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?
    /// );
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn finalize_with(
        &self,
        accumulator: &Accumulator,
        proof_params: &ProofParams,
        setup: &ProofSetup,
        pubkey: &PublicKey,
        challenge: &Challenge,
        relation: &LinkingRelation,
    ) -> Result<MembershipProofFinal> {
        let statement = MembershipStatement {
            pubkey,
            accumulator,
            relation,
        };
        check(self, &statement, proof_params, setup, challenge)?;
        Ok(MembershipProofFinal {
            digest: statement.digest(proof_params),
            t_a: self.t_a.clone(),
        })
    }

    /// The encoding: every field in declaration order, each as a self-describing vector (see
    /// `From<&PolyVec> for Vec<u8>`), `t_quad` and `v` as vectors of one polynomial.
    /// `TryFrom<&[u8]>` decodes it, failing with [`Error::InvalidEncodingLength`]; shapes and
    /// ranges are checked by [`MembershipProof::finalize`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, Error, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey, prove,
    /// #     prove_with, verify, verify_with,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// # let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
    /// # let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
    /// let proof = prove(&statement, &secret, &proof_params, &mut Transcript::new(b"t"), &mut rng)?;
    /// let wire = proof.to_bytes();
    /// assert_eq!(wire.len(), 9_100_960); // 8.68 MiB at the toy set
    /// // Decoding checks the framing only; the verifier's checks come after.
    /// let received = MembershipProof::try_from(wire.as_slice())?;
    /// verify(&statement, &received, &proof_params, &mut Transcript::new(b"t"))?;
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// The commitment `t_A`.
    pub(crate) fn commitment(&self) -> &PolyVec {
        &self.t_a
    }

    /// The entries of every field, in declaration order, borrowed.
    fn fields(&self) -> impl Iterator<Item = &[Poly]> {
        self.messages()
            .fields()
            .into_iter()
            .chain([self.z1.as_slice(), self.z2.as_slice()])
    }

    /// Replaces the responses `z₁, z₂` by a LaBRADOR proof of `levels` levels (Appendix D.3).
    /// The responses are public, so anyone holding the proof can compress it. Fails with
    /// [`Error::RelationUnsatisfied`] when the responses do not satisfy D.12 for `statement`
    /// and `challenge`.
    ///
    /// # Errors
    ///
    /// As above; [`Error::CompressionParameters`] when no LaBRADOR parameters fit the relation
    /// at this modulus; [`Error::ProverAborted`] if the LaBRADOR prover aborts on every try.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, PublicKey, SecretKey, prove, verify,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// let committing = MembershipProofCommitting::new(
    ///     &x, &witness, &proof_params, &pk, &acc,
    ///     LinkingOpening { relation: &relation, r: &r },
    ///     &mut rng,
    /// )?;
    /// let mut transcript = Transcript::new(b"presentation");
    /// committing.get_bytes_for_challenge(&mut transcript);
    /// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    /// let proof = committing.gen_proof(&challenge)?;
    /// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
    /// let compressed = proof.compress(&statement, &proof_params, &challenge, CompressionLevels::try_from(2)?)?;
    /// assert_eq!(compressed.levels(), 2);
    /// assert!(Vec::from(&compressed).len() < proof.to_bytes().len());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn compress(
        &self,
        statement: &MembershipStatement<'_>,
        proof_params: &ProofParams,
        challenge: &Challenge,
        levels: CompressionLevels,
    ) -> Result<CompressedMembershipProof> {
        let setup = ProofSetup::new(statement.pubkey, proof_params, statement.relation)?;
        self.compress_with(statement, proof_params, &setup, challenge, levels)
    }

    /// [`MembershipProof::compress`] with the values `setup` holds in place of deriving them;
    /// the LaBRADOR layer's own keys are still expanded per call. Fails with
    /// [`Error::ParameterMismatch`], before any other work, unless `setup` was built for
    /// `statement`'s parameter set, for `proof_params` and for a relation of
    /// `statement.relation`'s shape.
    ///
    /// # Errors
    ///
    /// As above, and as [`MembershipProof::compress`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, Error, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey, prove,
    /// #     prove_with, verify, verify_with,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// let setup = ProofSetup::new(&pk, &proof_params, &relation)?;
    /// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
    /// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
    /// let committing = MembershipProofCommitting::new_with(&secret, &proof_params, &setup, &statement, &mut rng)?;
    /// let mut transcript = Transcript::new(b"presentation");
    /// committing.get_bytes_for_challenge(&mut transcript);
    /// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    /// let proof = committing.gen_proof(&challenge)?;
    /// let levels = CompressionLevels::try_from(2)?;
    /// let compressed = proof.compress_with(&statement, &proof_params, &setup, &challenge, levels)?;
    /// assert_eq!(compressed, proof.compress(&statement, &proof_params, &challenge, levels)?);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn compress_with(
        &self,
        statement: &MembershipStatement<'_>,
        proof_params: &ProofParams,
        setup: &ProofSetup,
        challenge: &Challenge,
        levels: CompressionLevels,
    ) -> Result<CompressedMembershipProof> {
        setup.check(statement, proof_params)?;
        let params = &**statement.pubkey.params();
        statement.relation.validate(params)?;
        statement.accumulator.validate(params)?;
        self.validate(setup.lnp(), params.ring())
            .map_err(|_| Error::RelationUnsatisfied)?;
        labrador::compress(&labrador::Compression {
            proof: self,
            statement,
            digest: &statement.digest(proof_params),
            setup,
            challenge,
            levels,
        })
    }

    /// The messages of rounds 1 to 7 and `t_A`.
    pub(crate) fn messages(&self) -> Messages<'_> {
        Messages {
            t_a: &self.t_a,
            w: &self.w,
            t_y: &self.t_y,
            z3: &self.z3,
            t_p: &self.t_p,
            h: &self.h,
            t_quad: &self.t_quad,
            v: &self.v,
        }
    }

    /// The response `z₁`.
    pub(crate) fn z1(&self) -> &PolyVec {
        &self.z1
    }

    /// The response `z₂`.
    pub(crate) fn z2(&self) -> &PolyVec {
        &self.z2
    }

    /// Checks every field's length and coefficient range against `lnp`.
    fn validate(&self, lnp: &LnpParameters, ring: &Ring) -> Result<()> {
        self.messages().validate(lnp, ring)?;
        for (field, len) in [(&self.z1, lnp.m1), (&self.z2, lnp.m2)] {
            check_field(field, len, ring)?;
        }
        Ok(())
    }
}

/// Decodes [`MembershipProof::to_bytes`], which must be consumed exactly. Shapes and
/// coefficient ranges are checked when the proof is verified.
impl TryFrom<&[u8]> for MembershipProof {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let proof = Self {
            t_a: decoder.vector()?,
            w: decoder.vector()?,
            t_y: decoder.vector()?,
            z3: decoder.vector()?,
            t_p: decoder.vector()?,
            h: decoder.vector()?,
            t_quad: decoder.poly()?,
            v: decoder.poly()?,
            z1: decoder.vector()?,
            z2: decoder.vector()?,
        };
        decoder.finish().map(|()| proof)
    }
}

/// Fails with [`Error::ProofRejected`] unless `field` has `len` entries reduced modulo `q`.
pub(crate) fn check_field(field: &PolyVec, len: usize, ring: &Ring) -> Result<()> {
    if field.len() != len {
        return Err(Error::ProofRejected);
    }
    field.validate(ring).map_err(|_| Error::ProofRejected)
}

/// Reads the self-describing vectors of a proof encoding from its front; any shortfall or
/// excess reports [`Error::InvalidEncodingLength`] with the length of the whole encoding.
#[derive(Debug)]
pub(crate) struct Decoder<'a> {
    rest: &'a [u8],
    invalid: Error,
}

impl<'a> Decoder<'a> {
    /// Starts at the front of `bytes`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            rest: bytes,
            invalid: Error::InvalidEncodingLength(bytes.len()),
        }
    }

    /// The next little-endian `u64`.
    pub(crate) fn word(&mut self) -> Result<u64> {
        let (word, rest) = self.rest.split_first_chunk::<8>().ok_or(self.invalid)?;
        self.rest = rest;
        Ok(u64::from_le_bytes(*word))
    }

    /// The next `u64` as a length.
    pub(crate) fn length(&mut self) -> Result<usize> {
        usize::try_from(self.word()?).map_err(|_| self.invalid)
    }

    /// The next vector in the encoding of `From<&PolyVec> for Vec<u8>`.
    pub(crate) fn vector(&mut self) -> Result<PolyVec> {
        let len = self.length()?;
        let degree = self.length()?;
        let (vector, rest) = PolyVec::read_coefficients(self.rest, len, degree)?;
        self.rest = rest;
        Ok(vector)
    }

    /// The next vector, which must hold exactly one polynomial.
    pub(crate) fn poly(&mut self) -> Result<Poly> {
        let mut entries: Vec<Poly> = self.vector()?.into();
        match (entries.pop(), entries.is_empty()) {
            (Some(poly), true) => Ok(poly),
            _ => Err(self.invalid),
        }
    }

    /// Succeeds only when every byte was consumed.
    pub(crate) fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(self.invalid)
        }
    }
}

/// The LNP messages every form of the proof carries: `t_A` and the messages of rounds 1 to 7.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Messages<'a> {
    /// `t_A`.
    pub(crate) t_a: &'a PolyVec,
    /// `w`.
    pub(crate) w: &'a PolyVec,
    /// `t_y`.
    pub(crate) t_y: &'a PolyVec,
    /// `z₃`.
    pub(crate) z3: &'a PolyVec,
    /// `t_p`.
    pub(crate) t_p: &'a PolyVec,
    /// `h₁, …, h_τ`.
    pub(crate) h: &'a PolyVec,
    /// `t_quad`.
    pub(crate) t_quad: &'a Poly,
    /// `v`.
    pub(crate) v: &'a Poly,
}

impl<'a> Messages<'a> {
    /// Checks every message's length and coefficient range against `lnp`.
    pub(crate) fn validate(&self, lnp: &LnpParameters, ring: &Ring) -> Result<()> {
        let lengths = [
            (self.t_a, lnp.n),
            (self.w, lnp.n),
            (self.t_y, lnp.y3_len()),
            (self.z3, lnp.y3_len()),
            (self.t_p, lnp.tau),
            (self.h, lnp.tau),
        ];
        for (field, len) in lengths {
            check_field(field, len, ring)?;
        }
        self.t_quad
            .validate(ring)
            .map_err(|_| Error::ProofRejected)?;
        self.v.validate(ring).map_err(|_| Error::ProofRejected)
    }

    /// The entries of every message in declaration order, borrowed; `t_quad` and `v` as
    /// vectors of one polynomial.
    pub(crate) fn fields(&self) -> [&'a [Poly]; 8] {
        [
            self.t_a.as_slice(),
            self.w.as_slice(),
            self.t_y.as_slice(),
            self.z3.as_slice(),
            self.t_p.as_slice(),
            self.h.as_slice(),
            core::slice::from_ref(self.t_quad),
            core::slice::from_ref(self.v),
        ]
    }
}

/// The verifier's challenges of rounds 2 to 8, rederived from the messages: `α`, `γ₁, …, γ₄`,
/// the final `c`, and `σ(aᵢ)` transformed for `aᵢ = Σ_j α_{i,j}·r_j` and the rows `r_j` of `R`.
#[derive(Debug)]
pub(crate) struct Challenges {
    /// `α ∈ Z_q^{τ×257}`.
    pub(crate) alpha: Vec<Vec<Coeff>>,
    /// `γ₁, …, γ₄`.
    pub(crate) gammas: Gammas,
    /// `σ(aᵢ)` for every `i < τ`.
    pub(crate) range: Vec<Vec<NttPoly>>,
    /// `c ∈ C`.
    pub(crate) c: Poly,
}

impl Challenges {
    /// The quadratic relation of round 7 for these challenges.
    pub(crate) fn relation<'a>(
        &'a self,
        statement: &MembershipStatement<'a>,
        lnp: &'a LnpParameters,
        h: &'a PolyVec,
    ) -> Result<Relation<'a>> {
        Relation::new(RelationInputs {
            lnp,
            pubkey: statement.pubkey,
            accumulator: statement.accumulator,
            link: statement.relation,
            gammas: &self.gammas,
            alpha: &self.alpha,
            range: &self.range,
            h,
        })
    }
}

/// Replays the inner transcript over `messages` for the statement with digest `digest` and the
/// outer `challenge`, in the order of the prover's rounds.
pub(crate) fn replay(
    messages: &Messages<'_>,
    statement: &MembershipStatement<'_>,
    digest: &[u8; 64],
    lnp: &LnpParameters,
    challenge: &Challenge,
) -> Result<Challenges> {
    let ring = statement.pubkey.params().ring();
    let mut transcript = inner_transcript(challenge, digest, messages.t_a);
    append_vec(&mut transcript, b"w", messages.w);
    append_vec(&mut transcript, b"t_y", messages.t_y);
    let r_seed = challenge_seed(&mut transcript, b"R");
    append_vec(&mut transcript, b"z3", messages.z3);
    append_vec(&mut transcript, b"t_p", messages.t_p);
    let alpha = sample_alpha(&challenge_seed(&mut transcript, b"alpha"), lnp.tau, ring);
    append_vec(&mut transcript, b"h", messages.h);
    let gammas = sample_gammas(&challenge_seed(&mut transcript, b"gamma"), statement, lnp);
    append_poly(&mut transcript, b"t_quad", messages.t_quad);
    append_poly(&mut transcript, b"v", messages.v);
    let c = challenge::sample(
        &mut xof(
            &challenge_seed(&mut transcript, b"c"),
            DomainLabel::from(LABEL_CHALLENGE),
        ),
        ring,
    )?;
    let r = BinomialMatrix::sample(&r_seed, lnp.m1 * ring.degree())?;
    let range = sigma_transforms(&r.combine(&alpha, ring)?, ring)?;
    Ok(Challenges {
        alpha,
        gammas,
        range,
        c,
    })
}

/// `h̃ᵢ = Σ_j α_{i,j}·z₃,ⱼ` for every `i` (D.12, last equation), where `h̃ᵢ` is the constant
/// coefficient of `hᵢ`.
pub(crate) fn check_openings(
    messages: &Messages<'_>,
    alpha: &[Vec<Coeff>],
    ring: &Ring,
) -> Result<()> {
    let zq = ring.zq();
    let z3: Vec<&Coeff> = messages
        .z3
        .as_slice()
        .iter()
        .flat_map(Poly::coefficients)
        .collect();
    for (h, row) in messages.h.as_slice().iter().zip(alpha) {
        let sum = row.iter().zip(&z3).fold(Coeff::ZERO, |acc, (a, z)| {
            zq.add(&acc, &zq.mont_mul(&zq.montgomery(a), z))
        });
        if h.coefficients().first() != Some(&sum) {
            return Err(Error::ProofRejected);
        }
    }
    Ok(())
}

/// What a verified proof contributes to the verifier's outer transcript: the statement digest
/// and `t_A`. **Public.** See the book's chapter "Membership proofs" for the flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProofFinal {
    pub(crate) digest: [u8; 64],
    pub(crate) t_a: PolyVec,
}

impl MembershipProofFinal {
    /// Appends the statement digest and `t_A`, the same bytes as
    /// [`MembershipProofCommitting::get_bytes_for_challenge`], so that the verifier rederives the
    /// prover's outer challenge. See the book's chapter "Membership proofs".
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, Error, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey, prove,
    /// #     prove_with, verify, verify_with,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// # let committing = MembershipProofCommitting::new(
    /// #     &x, &witness, &proof_params, &pk, &acc,
    /// #     LinkingOpening { relation: &relation, r: &r },
    /// #     &mut rng,
    /// # )?;
    /// # let mut prover = Transcript::new(b"presentation");
    /// # prover.append_message(b"verifier nonce", b"session 1");
    /// # committing.get_bytes_for_challenge(&mut prover);
    /// # let challenge = Challenge::from_transcript(b"challenge", &mut prover);
    /// # let proof = committing.gen_proof(&challenge)?;
    /// let finalized = proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
    /// let mut verifier = Transcript::new(b"presentation");
    /// verifier.append_message(b"verifier nonce", b"session 1");
    /// finalized.get_bytes_for_challenge(&mut verifier);
    /// assert_eq!(Challenge::from_transcript(b"challenge", &mut verifier), challenge);
    /// // A replay into another session derives another challenge, so the comparison fails.
    /// let mut replayed = Transcript::new(b"presentation");
    /// replayed.append_message(b"verifier nonce", b"session 2");
    /// finalized.get_bytes_for_challenge(&mut replayed);
    /// assert_ne!(Challenge::from_transcript(b"challenge", &mut replayed), challenge);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn get_bytes_for_challenge(&self, transcript: &mut Transcript) {
        append_commitment(transcript, &self.digest, &self.t_a);
    }
}

/// The prover's committing step: the commitment `t_A` to `(x, r, s̄_x)`, with the secrets the
/// later rounds use, all overwritten when dropped.
///
/// **Secret (prover only).** It holds `s₁`, `s₂`, their transforms and the mask seed in buffers
/// overwritten when it is dropped ([`ZeroizeOnDrop`]); it is neither `Copy` nor `Clone`;
/// [`fmt::Debug`](core::fmt::Debug) prints the public parameters and `t_A` only. It may answer
/// more than one challenge; each answer uses masks derived from the seed and that challenge.
///
/// # Examples
///
/// ```no_run
/// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
/// # use kln_accumulator::{
/// #     Accumulator, Challenge, CompressionLevels, Element, LinkingOpening, LinkingRelation,
/// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
/// #     MembershipWitness, Params, ProofParams, PublicKey, SecretKey, prove, verify,
/// # };
/// # use kln_accumulator::lattice::{
/// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
/// # };
/// # use merlin::Transcript;
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let params = Arc::clone(key.params());
/// # let ring = params.ring();
/// # let x = Element::hash(b"x", &params);
/// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
/// # let constant = |b: bool| {
/// #     let mut c = vec![Coeff::ZERO; ring.degree()];
/// #     c[0] = Coeff::from_u64(u64::from(b));
/// #     Poly::new(c, ring)
/// # };
/// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
/// # let r = PolyVec::from(vec![Poly::new(
/// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
/// #     ring,
/// # )?]);
/// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
/// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
/// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
/// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
/// # let relation = LinkingRelation::new(a1, a2, t)?;
/// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
/// let committing = MembershipProofCommitting::new(
///     &x, &witness, &proof_params, &pk, &acc,
///     LinkingOpening { relation: &relation, r: &r },
///     &mut rng,
/// )?;
/// let mut transcript = Transcript::new(b"presentation");
/// committing.get_bytes_for_challenge(&mut transcript);
/// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
/// let proof = committing.gen_proof(&challenge)?;
/// proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Debug)]
pub struct MembershipProofCommitting {
    committed: Committed,
}

/// The prover's state is overwritten when dropped, as its inner state's is.
impl ZeroizeOnDrop for MembershipProofCommitting {}

impl MembershipProofCommitting {
    /// Commits to the element, its witness and the linking vector. Fails with
    /// [`Error::RelationUnsatisfied`] unless the witness verifies for the element against
    /// `accumulator`, `r` is binary, and `A₁·x + A₂·r = t`. Cheap next to
    /// [`MembershipProofCommitting::gen_proof`]: one commitment.
    ///
    /// # Errors
    ///
    /// As above; [`Error::UnsupportedProofDegree`] and [`Error::ParameterMismatch`] as for
    /// [`crate::prove`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, PublicKey, SecretKey, prove, verify,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// let wrong = PolyVec::zero(1, ring); // not the r of the relation
    /// assert!(MembershipProofCommitting::new(
    ///     &x, &witness, &proof_params, &pk, &acc,
    ///     LinkingOpening { relation: &relation, r: &wrong },
    ///     &mut rng,
    /// )
    /// .is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new<R: CryptoRng + ?Sized>(
        element: &Element,
        witness: &MembershipWitness,
        proof_params: &ProofParams,
        pubkey: &PublicKey,
        accumulator: &Accumulator,
        linking: LinkingOpening<'_>,
        rng: &mut R,
    ) -> Result<Self> {
        let statement = MembershipStatement {
            pubkey,
            accumulator,
            relation: linking.relation,
        };
        let secret = MembershipSecret {
            element,
            witness,
            r: linking.r,
        };
        let setup = ProofSetup::new(pubkey, proof_params, linking.relation)?;
        Self::new_with(&secret, proof_params, &setup, &statement, rng)
    }

    /// [`MembershipProofCommitting::new`] with the values `setup` holds in place of deriving
    /// them: the same commitment from the same `rng`. The element, its witness and `r` come in
    /// `secret`, and the public key, the accumulator and the relation in `statement`. Fails with
    /// [`Error::ParameterMismatch`], before any other work and without drawing from `rng`,
    /// unless `setup` was built for `statement`'s parameter set, for `proof_params` and for a
    /// relation of `statement.relation`'s shape. The prover's state keeps a handle on the
    /// setup's values, not a copy.
    ///
    /// # Errors
    ///
    /// As above, and as [`MembershipProofCommitting::new`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, Error, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey, prove,
    /// #     prove_with, verify, verify_with,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// let setup = ProofSetup::new(&pk, &proof_params, &relation)?;
    /// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
    /// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
    /// let committing = MembershipProofCommitting::new_with(&secret, &proof_params, &setup, &statement, &mut rng)?;
    /// let mut transcript = Transcript::new(b"presentation");
    /// committing.get_bytes_for_challenge(&mut transcript);
    /// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    /// let proof = committing.gen_proof(&challenge)?;
    /// proof.finalize_with(&acc, &proof_params, &setup, &pk, &challenge, &relation)?;
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new_with<R: CryptoRng + ?Sized>(
        secret: &MembershipSecret<'_>,
        proof_params: &ProofParams,
        setup: &ProofSetup,
        statement: &MembershipStatement<'_>,
        rng: &mut R,
    ) -> Result<Self> {
        Committed::new(statement, secret, proof_params, setup, rng)
            .map(|committed| Self { committed })
    }

    /// Appends the statement digest and `t_A` to the outer transcript; see the book's chapter
    /// "Membership proofs".
    pub fn get_bytes_for_challenge(&self, transcript: &mut Transcript) {
        self.committed.append_to(transcript);
    }

    /// Runs the protocol with the inner transcript seeded by `challenge`, restarting on every
    /// rejection-sampling abort. Fails with [`Error::ProverAborted`] if every attempt aborts.
    /// About 20 attempts and 2 to 12 s at the toy set. See the book's chapter "Membership
    /// proofs".
    ///
    /// # Errors
    ///
    /// As above; the limit is 1000 attempts.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, Error, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, ProofSetup, PublicKey, SecretKey, prove,
    /// #     prove_with, verify, verify_with,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// let committing = MembershipProofCommitting::new(
    ///     &x, &witness, &proof_params, &pk, &acc,
    ///     LinkingOpening { relation: &relation, r: &r },
    ///     &mut rng,
    /// )?;
    /// // Absorb your own context first (protocol label, verifier nonce), then the proof's part.
    /// let mut transcript = Transcript::new(b"presentation");
    /// transcript.append_message(b"verifier nonce", b"session 1");
    /// committing.get_bytes_for_challenge(&mut transcript);
    /// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    /// let proof = committing.gen_proof(&challenge)?;
    /// // The proof answers this challenge only.
    /// assert!(proof.finalize(&acc, &proof_params, &pk, &challenge, &relation).is_ok());
    /// let other = Challenge::from([7u8; 64]);
    /// assert_eq!(
    ///     proof.finalize(&acc, &proof_params, &pk, &other, &relation).map(drop),
    ///     Err(Error::ProofRejected)
    /// );
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn gen_proof(&self, challenge: &Challenge) -> Result<MembershipProof> {
        self.committed.respond(challenge)
    }

    /// Runs the protocol as [`MembershipProofCommitting::gen_proof`] does, then replaces the
    /// responses `z₁, z₂` by a LaBRADOR proof of `levels` levels (Appendix D.3).
    ///
    /// # Errors
    ///
    /// As [`MembershipProofCommitting::gen_proof`] and [`MembershipProof::compress`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
    /// # use kln_accumulator::{
    /// #     Accumulator, Challenge, CompressionLevels, Element, LinkingOpening, LinkingRelation,
    /// #     MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement,
    /// #     MembershipWitness, Params, ProofParams, PublicKey, SecretKey, prove, verify,
    /// # };
    /// # use kln_accumulator::lattice::{
    /// #     Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler,
    /// # };
    /// # use merlin::Transcript;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let params = Arc::clone(key.params());
    /// # let ring = params.ring();
    /// # let x = Element::hash(b"x", &params);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // The linking relation A₁·x + A₂·r = t: x's bits as constant polynomials, r binary.
    /// # let constant = |b: bool| {
    /// #     let mut c = vec![Coeff::ZERO; ring.degree()];
    /// #     c[0] = Coeff::from_u64(u64::from(b));
    /// #     Poly::new(c, ring)
    /// # };
    /// # let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
    /// # let r = PolyVec::from(vec![Poly::new(
    /// #     (0..ring.degree()).map(|i| Coeff::from_u64((i % 2) as u64)).collect(),
    /// #     ring,
    /// # )?]);
    /// # let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
    /// # let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
    /// # let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
    /// # let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
    /// # let relation = LinkingRelation::new(a1, a2, t)?;
    /// # let proof_params = ProofParams::new(&pk, Some(b"entropy"))?;
    /// let committing = MembershipProofCommitting::new(
    ///     &x, &witness, &proof_params, &pk, &acc,
    ///     LinkingOpening { relation: &relation, r: &r },
    ///     &mut rng,
    /// )?;
    /// let mut transcript = Transcript::new(b"presentation");
    /// committing.get_bytes_for_challenge(&mut transcript);
    /// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    /// let proof = committing.gen_compressed_proof(&challenge, CompressionLevels::try_from(1)?)?;
    /// proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn gen_compressed_proof(
        &self,
        challenge: &Challenge,
        levels: CompressionLevels,
    ) -> Result<CompressedMembershipProof> {
        self.committed.respond_compressed(challenge, levels)
    }
}

/// An owned copy of the statement.
#[derive(Clone, Debug)]
struct OwnedStatement {
    pubkey: PublicKey,
    accumulator: Accumulator,
    relation: LinkingRelation,
}

/// The prover after round 0: `t_A` and every secret of the later rounds.
pub(crate) struct Committed {
    statement: OwnedStatement,
    digest: [u8; 64],
    /// The LNP parameters, the commitment key and the LaBRADOR key seed, all public.
    setup: ProofSetup,
    t_a: PolyVec,
    s1: Zeroizing<PolyVec>,
    s1_int: Zeroizing<Vec<i64>>,
    /// `s₁` and `s₂` transformed, for the products with `c`.
    s1_ntt: Zeroizing<Vec<NttPoly>>,
    s2_ntt: Zeroizing<Vec<NttPoly>>,
    /// `s₁ᵀσ(s₁ − P_W)`, the binary relation's polynomial.
    s1_binary: Zeroizing<Poly>,
    s2_rows: Zeroizing<BdlopRows>,
    seed: Zeroizing<[u8; 32]>,
}

/// Every secret field is in a buffer that is overwritten when dropped; the rest is public.
impl ZeroizeOnDrop for Committed {}

impl core::fmt::Debug for Committed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Committed")
            .field("lnp", self.setup.lnp())
            .field("t_a", &self.t_a)
            .finish_non_exhaustive()
    }
}

impl Committed {
    /// Checks that `setup` fits `statement` and `proof_params` and that `secret` satisfies
    /// relation D.2 for `statement`, then commits.
    pub(crate) fn new<R: CryptoRng + ?Sized>(
        statement: &MembershipStatement<'_>,
        secret: &MembershipSecret<'_>,
        proof_params: &ProofParams,
        setup: &ProofSetup,
        rng: &mut R,
    ) -> Result<Self> {
        setup.check(statement, proof_params)?;
        let params = &**statement.pubkey.params();
        let ring = params.ring();
        let lnp = setup.lnp();
        statement.relation.validate(params)?;
        statement.accumulator.validate(params)?;
        if !secret
            .witness
            .verify(secret.element, statement.pubkey, statement.accumulator)
        {
            return Err(Error::RelationUnsatisfied);
        }
        let bits: Zeroizing<Vec<i64>> = Zeroizing::new(
            secret
                .element
                .to_bits(params)?
                .as_slice()
                .iter()
                .map(|&b| i64::from(b))
                .collect(),
        );
        if secret.r.len() != lnp.r_len {
            return Err(Error::RelationUnsatisfied);
        }
        secret.r.validate(ring)?;
        let r = centred(secret.r, ring)?;
        if r.iter().any(|&c| c != 0 && c != 1) {
            return Err(Error::RelationUnsatisfied);
        }
        let x_int: Zeroizing<Vec<i64>> = Zeroizing::new(
            bits.iter()
                .flat_map(|&b| {
                    core::iter::once(b).chain(core::iter::repeat_n(0, ring.degree() - 1))
                })
                .collect(),
        );
        let x = Zeroizing::new(from_integers(&x_int, ring)?);
        let relation = statement.relation;
        let linked = relation
            .a1()
            .mul_vec(&x, ring)?
            .add(&relation.a2().mul_vec(secret.r, ring)?, ring)?;
        if linked != *relation.t() {
            return Err(Error::RelationUnsatisfied);
        }
        let mut s1 = Zeroizing::new(Vec::with_capacity(lnp.m1 * ring.degree()));
        s1.extend(x.as_slice().iter().flat_map(|p| {
            p.coefficients()
                .iter()
                .map(|c| i64::from(*c != Coeff::ZERO))
        }));
        s1.extend_from_slice(&r);
        decompose_witness(secret.witness.vector(), lnp, ring, &mut s1)?;
        Self::commit(statement, s1, proof_params, setup, rng)
    }

    /// Commits to the integer Ajtai message `s₁` without checking it against the statement,
    /// under a `setup` the caller has checked against `statement` and `proof_params`.
    pub(crate) fn commit<R: CryptoRng + ?Sized>(
        statement: &MembershipStatement<'_>,
        s1_int: Zeroizing<Vec<i64>>,
        proof_params: &ProofParams,
        setup: &ProofSetup,
        rng: &mut R,
    ) -> Result<Self> {
        let params = &**statement.pubkey.params();
        let ring = params.ring();
        let lnp = setup.lnp();
        check_dimension(lnp.m1 * ring.degree(), s1_int.len())?;
        let key = setup.key();
        let s1 = Zeroizing::new(from_integers(&s1_int, ring)?);
        let mut bytes = Zeroizing::new(vec![0u8; (lnp.m2 * ring.degree()).div_ceil(8)]);
        rng.fill_bytes(&mut bytes);
        let s2_int: Zeroizing<Vec<i64>> = Zeroizing::new(
            (0..lnp.m2 * ring.degree())
                .map(|i| i64::from(bytes[i / 8] >> (i % 8) & 1))
                .collect(),
        );
        let s2 = Zeroizing::new(from_integers(&s2_int, ring)?);
        let t_a = key.ajtai(&s1, &s2, ring)?;
        let s2_rows = Zeroizing::new(key.bdlop(&s2, ring)?);
        let s1_ntt = Zeroizing::new(transform(s1.as_slice(), ring)?);
        let s2_ntt = Zeroizing::new(transform(s2.as_slice(), ring)?);
        let s1_binary = Zeroizing::new(binary_polynomial(&s1, &s1_ntt, ring)?);
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut_slice());
        Ok(Self {
            statement: OwnedStatement {
                pubkey: statement.pubkey.clone(),
                accumulator: statement.accumulator.clone(),
                relation: statement.relation.clone(),
            },
            digest: statement.digest(proof_params),
            setup: setup.clone(),
            t_a,
            s1,
            s1_int,
            s1_ntt,
            s2_ntt,
            s1_binary,
            s2_rows,
            seed,
        })
    }

    /// Appends the statement digest and `t_A` to the outer transcript.
    pub(crate) fn append_to(&self, transcript: &mut Transcript) {
        append_commitment(transcript, &self.digest, &self.t_a);
    }

    /// Rounds 1 to 9 with restarts.
    pub(crate) fn respond(&self, challenge: &Challenge) -> Result<MembershipProof> {
        self.respond_counted(challenge).map(|(proof, _)| proof)
    }

    /// Rounds 1 to 9, then the LaBRADOR proof of `levels` levels in place of `z₁, z₂`.
    pub(crate) fn respond_compressed(
        &self,
        challenge: &Challenge,
        levels: CompressionLevels,
    ) -> Result<CompressedMembershipProof> {
        let proof = self.respond(challenge)?;
        labrador::compress(&labrador::Compression {
            proof: &proof,
            statement: &MembershipStatement {
                pubkey: &self.statement.pubkey,
                accumulator: &self.statement.accumulator,
                relation: &self.statement.relation,
            },
            digest: &self.digest,
            setup: &self.setup,
            challenge,
            levels,
        })
    }

    /// [`Committed::respond`], with the number of attempts it took.
    pub(crate) fn respond_counted(&self, challenge: &Challenge) -> Result<(MembershipProof, u32)> {
        let base = inner_transcript(challenge, &self.digest, &self.t_a);
        for attempt in 0..MAX_ATTEMPTS {
            let mut reader = hash_parts(
                DomainLabel::from(LABEL_MASKS),
                &[
                    self.seed.as_slice(),
                    &<[u8; 64]>::from(*challenge),
                    &attempt.to_le_bytes(),
                ],
            );
            if let Some(proof) = self.attempt(base.clone(), &mut reader)? {
                return Ok((proof, attempt + 1));
            }
        }
        Err(Error::ProverAborted)
    }

    /// One run of rounds 1 to 9, or `None` on an abort.
    fn attempt(
        &self,
        mut transcript: Transcript,
        reader: &mut Shake256Reader,
    ) -> Result<Option<MembershipProof>> {
        let statement = MembershipStatement {
            pubkey: &self.statement.pubkey,
            accumulator: &self.statement.accumulator,
            relation: &self.statement.relation,
        };
        let params = &**statement.pubkey.params();
        let ring = params.ring();
        let lnp = self.setup.lnp();
        let key = self.setup.key();

        // Round 1: masks and the first message.
        let d = ring.degree();
        let y1_int = Zeroizing::new(masks(lnp, 0, lnp.m1 * d, reader)?);
        let y2_int = Zeroizing::new(masks(lnp, 1, lnp.m2 * d, reader)?);
        let y3_int = Zeroizing::new(masks(lnp, 2, lnp.y3_len() * d, reader)?);
        let y1 = Zeroizing::new(from_integers(&y1_int, ring)?);
        let y2 = Zeroizing::new(from_integers(&y2_int, ring)?);
        let y3 = Zeroizing::new(from_integers(&y3_int, ring)?);
        let w = key.ajtai(&y1, &y2, ring)?;
        let t_y = self.s2_rows.y.add(&y3, ring)?;
        append_vec(&mut transcript, b"w", &w);
        append_vec(&mut transcript, b"t_y", &t_y);
        let r = BinomialMatrix::sample(
            &challenge_seed(&mut transcript, b"R"),
            lnp.m1 * ring.degree(),
        )?;

        // Round 3: the range-proof response with rejection, and the garbage commitment.
        let rs1 = Zeroizing::new(r.apply(&self.s1_int)?);
        // Not released on an abort, when it would leak `R·s₁`.
        let z3_int: Zeroizing<Vec<i64>> =
            Zeroizing::new(rs1.iter().zip(y3_int.iter()).map(|(a, b)| a + b).collect());
        let z3 = from_integers(&z3_int, ring)?;
        if !accept(&z3_int, &rs1, lnp.variance(2), next_u64(reader))?
            || z3.norm_l2_squared(ring) > *lnp.beta_squared(2)
        {
            return Ok(None);
        }
        let p = Zeroizing::new(garbage(reader, lnp.tau, ring));
        let t_p = self.s2_rows.p.add(&p, ring)?;
        append_vec(&mut transcript, b"z3", &z3);
        append_vec(&mut transcript, b"t_p", &t_p);
        let alpha = sample_alpha(&challenge_seed(&mut transcript, b"alpha"), lnp.tau, ring);

        // Round 5: the masked openings.
        let range = sigma_transforms(&r.combine(&alpha, ring)?, ring)?;
        let h = masked_openings(&MaskedOpeningInputs {
            range: &range,
            alpha: &alpha,
            s1_ntt: &self.s1_ntt,
            s1_binary: &self.s1_binary,
            y3: &y3,
            p: &p,
            ring,
        })?;
        append_vec(&mut transcript, b"h", &h);
        let gammas = sample_gammas(&challenge_seed(&mut transcript, b"gamma"), &statement, lnp);

        // Round 7: g₁ and g₀ from the verifier's Fh at c ∈ {0, 1, −1}.
        let relation = Relation::new(RelationInputs {
            lnp,
            pubkey: statement.pubkey,
            accumulator: statement.accumulator,
            link: statement.relation,
            gammas: &gammas,
            alpha: &alpha,
            range: &range,
            h: &h,
        })?;
        let y2_rows = Zeroizing::new(key.bdlop(&y2, ring)?);
        let at = |scalar: i64| -> Result<Poly> {
            let z1 = Zeroizing::new(y1.add(&self.s1.mul_small(scalar, ring)?, ring)?);
            let y = Zeroizing::new(y3.mul_small(scalar, ring)?.sub(&y2_rows.y, ring)?);
            let p = Zeroizing::new(p.mul_small(scalar, ring)?.sub(&y2_rows.p, ring)?);
            relation.evaluate(
                &Poly::constant(scalar, ring),
                &Opening {
                    z1: &z1,
                    y: &y,
                    p: &p,
                },
            )
        };
        let g0 = Zeroizing::new(at(0)?);
        let half = ring.modulus().wrapping_add(&Coeff::ONE).shr_vartime(1);
        let g1 = Zeroizing::new(Poly::scale(&at(1)?.sub(&at(-1)?, ring)?, &half, ring));
        let t_quad = self.s2_rows.quad.add(&g1, ring)?;
        let v = y2_rows.quad.add(&g0, ring)?;
        append_poly(&mut transcript, b"t_quad", &t_quad);
        append_poly(&mut transcript, b"v", &v);
        let c = challenge::sample(
            &mut xof(
                &challenge_seed(&mut transcript, b"c"),
                DomainLabel::from(LABEL_CHALLENGE),
            ),
            ring,
        )?;

        // Round 9: the responses with rejection.
        let Some(z1) = respond(
            &Response {
                mask: &y1_int,
                secret: &self.s1_ntt,
                c: &c,
                variance: lnp.variance(0),
                beta_squared: lnp.beta_squared(0),
                ring,
            },
            reader,
        )?
        else {
            return Ok(None);
        };
        let Some(z2) = respond(
            &Response {
                mask: &y2_int,
                secret: &self.s2_ntt,
                c: &c,
                variance: lnp.variance(1),
                beta_squared: lnp.beta_squared(1),
                ring,
            },
            reader,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(MembershipProof {
            t_a: self.t_a.clone(),
            w,
            t_y,
            z3,
            t_p,
            h,
            t_quad,
            v,
            z1,
            z2,
        }))
    }
}

/// One response `z = y + c·s` and what its rejection test needs.
struct Response<'a> {
    /// `y` as integers.
    mask: &'a [i64],
    /// `s`, transformed.
    secret: &'a [NttPoly],
    c: &'a Poly,
    variance: &'a U512,
    beta_squared: &'a U512,
    ring: &'a Ring,
}

/// `z = y + c·s` if rejection sampling releases it and `‖z‖² ≤ β²`, else `None`.
fn respond(response: &Response<'_>, reader: &mut Shake256Reader) -> Result<Option<PolyVec>> {
    let ring = response.ring;
    let shift = Zeroizing::new(mul_each_transformed(response.c, response.secret, ring)?);
    let shift_int = centred(&shift, ring)?;
    check_dimension(response.mask.len(), shift_int.len())?;
    // Not released on an abort, when it would leak the secret.
    let z_int: Zeroizing<Vec<i64>> = Zeroizing::new(
        response
            .mask
            .iter()
            .zip(shift_int.iter())
            .map(|(y, v)| y + v)
            .collect(),
    );
    let z = from_integers(&z_int, ring)?;
    if accept(&z_int, &shift_int, response.variance, next_u64(reader))?
        && z.norm_l2_squared(ring) <= *response.beta_squared
    {
        Ok(Some(z))
    } else {
        Ok(None)
    }
}

/// `count` draws of mask `i` as integers.
fn masks(
    lnp: &LnpParameters,
    i: usize,
    count: usize,
    reader: &mut Shake256Reader,
) -> Result<Vec<i64>> {
    lnp.gaussian(i)
        .integers(reader, count, Lookup::Guided)
        .ok_or(Error::ProofModulusTooSmall)
}

/// `s₁ᵀσ(s₁ − P_W) = s₁ᵀσ(s₁) − (Σ_k s₁,k)·σ(Σ_j X^j)`, whose constant coefficient is
/// `⟨s₁, s₁ − 1⟩` (line 2839).
fn binary_polynomial(s1: &PolyVec, s1_ntt: &[NttPoly], ring: &Ring) -> Result<Poly> {
    let total = s1
        .as_slice()
        .iter()
        .try_fold(Poly::zero(ring), |acc, p| acc.add(p, ring))?;
    inner(
        s1_ntt,
        &transform(s1.sigma_minus_one(ring)?.as_slice(), ring)?,
        ring,
    )?
    .sub(&total.mul(&ones(ring).sigma_minus_one(ring)?, ring)?, ring)
}

/// What the masked openings `hᵢ` are computed from.
struct MaskedOpeningInputs<'a> {
    /// `σ(aᵢ)` transformed, for every `i < τ`.
    range: &'a [Vec<NttPoly>],
    alpha: &'a [Vec<Coeff>],
    s1_ntt: &'a [NttPoly],
    s1_binary: &'a Poly,
    y3: &'a PolyVec,
    p: &'a PolyVec,
    ring: &'a Ring,
}

/// `hᵢ = pᵢ + σ(aᵢ)ᵀs₁ + σ(Eᵢ)ᵀy₃ + α_{i,257}·s₁ᵀσ(s₁ − P_W)` (line 2862), where
/// `aᵢ = Σ_j α_{i,j}·r_j` and `Eᵢ` is the vector whose coefficients are `α_{i,1..256}`.
fn masked_openings(inputs: &MaskedOpeningInputs<'_>) -> Result<PolyVec> {
    let ring = inputs.ring;
    let y3_ntt = transform(inputs.y3.as_slice(), ring)?;
    inputs
        .range
        .iter()
        .zip(inputs.alpha)
        .zip(inputs.p.as_slice())
        .map(|((range, row), p)| {
            let e = range_polys(row, ring)?;
            let y_part = inner(
                &transform(e.sigma_minus_one(ring)?.as_slice(), ring)?,
                &y3_ntt,
                ring,
            )?;
            p.add(&inner(range, inputs.s1_ntt, ring)?, ring)?
                .add(&y_part, ring)?
                .add(
                    &Poly::scale(inputs.s1_binary, binary_weight(row)?, ring),
                    ring,
                )
        })
        .collect()
}

/// The verifier: every check of D.12 for the outer `challenge`, under the values `setup` holds
/// once it is checked against `statement` and `proof_params`.
pub(crate) fn check(
    proof: &MembershipProof,
    statement: &MembershipStatement<'_>,
    proof_params: &ProofParams,
    setup: &ProofSetup,
    challenge: &Challenge,
) -> Result<()> {
    setup.check(statement, proof_params)?;
    let params = &**statement.pubkey.params();
    let ring = params.ring();
    let lnp = setup.lnp();
    statement.relation.validate(params)?;
    statement.accumulator.validate(params)?;
    proof.validate(lnp, ring)?;
    check_norms(proof, lnp, ring)?;

    let messages = proof.messages();
    let challenges = replay(
        &messages,
        statement,
        &statement.digest(proof_params),
        lnp,
        challenge,
    )?;
    let c = &challenges.c;

    // Ā₁z₁ + Ā₂z₂ = w + c·t_A.
    let key = setup.key();
    let expected = proof.w.add(&mul_each(c, &proof.t_a, ring)?, ring)?;
    if key.ajtai(&proof.z1, &proof.z2, ring)? != expected {
        return Err(Error::ProofRejected);
    }

    check_openings(&messages, &challenges.alpha, ring)?;

    // Z = c²·(γ₁ᵀt + γ₂ᵀc + Σγ₄,ᵢhᵢ) + (c·t_quad − B̄_quad·z₂) + v, as Fh = (c·t_quad − B̄_quad·z₂) + v.
    let relation = challenges.relation(statement, lnp, &proof.h)?;
    let z2_rows = key.bdlop(&proof.z2, ring)?;
    let opening_y = mul_each(c, &proof.t_y, ring)?.sub(&z2_rows.y, ring)?;
    let opening_p = mul_each(c, &proof.t_p, ring)?.sub(&z2_rows.p, ring)?;
    let lhs = relation.evaluate(
        c,
        &Opening {
            z1: &proof.z1,
            y: &opening_y,
            p: &opening_p,
        },
    )?;
    let rhs = c
        .mul(&proof.t_quad, ring)?
        .sub(&z2_rows.quad, ring)?
        .add(&proof.v, ring)?;
    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::ProofRejected)
    }
}

/// `‖z₁‖ ≤ β₁`, `‖z₂‖ ≤ β₂` and `‖z₃‖ ≤ β₃`, compared as exact squares.
pub(crate) fn check_norms(proof: &MembershipProof, lnp: &LnpParameters, ring: &Ring) -> Result<()> {
    for (i, z) in [&proof.z1, &proof.z2, &proof.z3].into_iter().enumerate() {
        if z.norm_l2_squared(ring) > *lnp.beta_squared(i) {
            return Err(Error::ProofRejected);
        }
    }
    Ok(())
}

/// The inner transcript's starting state: the outer challenge, the statement digest and `t_A`.
fn inner_transcript(challenge: &Challenge, digest: &[u8; 64], t_a: &PolyVec) -> Transcript {
    let mut transcript = Transcript::new(b"kln-accumulator/lnp-membership");
    transcript.append_message(b"outer challenge", &<[u8; 64]>::from(*challenge));
    transcript.append_message(b"statement", digest);
    append_vec(&mut transcript, b"t_A", t_a);
    transcript
}

/// Appends a polynomial's coefficient bytes under `label`.
fn append_poly(transcript: &mut Transcript, label: &'static [u8], p: &Poly) {
    let mut bytes = Vec::new();
    p.write_coefficients(&mut bytes);
    transcript.append_message(label, &bytes);
}

/// The next 64 bits of the prover's stream.
fn next_u64(reader: &mut Shake256Reader) -> u64 {
    let mut bytes = [0u8; 8];
    reader.read(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// `τ` uniform polynomials with zero constant coefficient (line 2855), from the prover's stream.
fn garbage(reader: &mut Shake256Reader, tau: usize, ring: &Ring) -> PolyVec {
    let seed = Seed::read_from(reader);
    UniformSampler::new(&seed, DomainLabel::from(LABEL_GARBAGE))
        .vector(tau, ring)
        .as_slice()
        .iter()
        .map(|poly| {
            let mut coefficients = poly.coefficients().to_vec();
            if let Some(constant) = coefficients.first_mut() {
                *constant = Coeff::ZERO;
            }
            Poly::from_reduced(coefficients)
        })
        .collect()
}

/// `α ∈ Z_q^{τ×257}`, row by row, from the coefficients of uniform polynomials.
fn sample_alpha(seed: &Seed, tau: usize, ring: &Ring) -> Vec<Vec<Coeff>> {
    let width = super::params::RANGE_ROWS + 1;
    let polys = (tau * width).div_ceil(ring.degree());
    let flat: Vec<Coeff> = UniformSampler::new(seed, DomainLabel::from(LABEL_ALPHA))
        .vector(polys, ring)
        .as_slice()
        .iter()
        .flat_map(|p| p.coefficients().iter().copied())
        .collect();
    flat.chunks_exact(width)
        .take(tau)
        .map(<[Coeff]>::to_vec)
        .collect()
}

/// `γ₁ ∈ R_q^h`, `γ₂ ∈ R_q^n`, `γ₃ ∈ R_q^ℓ`, `γ₄ ∈ R_q^τ`, in that order from one stream.
fn sample_gammas(seed: &Seed, statement: &MembershipStatement<'_>, lnp: &LnpParameters) -> Gammas {
    let params = statement.pubkey.params();
    let ring = params.ring();
    let mut sampler = UniformSampler::new(seed, DomainLabel::from(LABEL_GAMMA));
    Gammas {
        link: sampler.vector(statement.relation.t().len(), ring),
        membership: sampler.vector(params.spec().n, ring),
        bits: sampler.vector(lnp.element_bits, ring),
        openings: sampler.vector(lnp.tau, ring),
    }
}

/// Appends the digits of every coefficient of `s_x` to `out`, entry `k`'s digit `j` forming
/// polynomial `k·D + j` of `s̄_x`: the `D`-bit two's complement of the coefficient, whose top
/// digit has weight `−2^{D−1}`. Fails with [`Error::RelationUnsatisfied`] when a coefficient
/// lies outside `[−2^{D−1}, 2^{D−1})`.
fn decompose_witness(
    witness: &PolyVec,
    lnp: &LnpParameters,
    ring: &Ring,
    out: &mut Vec<i64>,
) -> Result<()> {
    let digits = u32::try_from(lnp.digits).map_err(|_| Error::ProofModulusTooSmall)?;
    let top = Coeff::ONE.shl_vartime(digits - 1);
    let modulus = Coeff::ONE.shl_vartime(digits);
    if witness.len() != lnp.witness_len {
        return Err(Error::RelationUnsatisfied);
    }
    for entry in witness.as_slice() {
        // Allocated at full length, so that pushing never moves the digits and leaves a copy.
        let mut twos: Zeroizing<Vec<Coeff>> =
            Zeroizing::new(Vec::with_capacity(entry.coefficients().len()));
        for c in entry.coefficients() {
            let centred = ring.center(c);
            let magnitude = *centred.magnitude();
            twos.push(
                match (centred.is_negative(), magnitude < top, magnitude <= top) {
                    (false, true, _) => magnitude,
                    (true, _, true) => modulus.wrapping_sub(&magnitude),
                    _ => return Err(Error::RelationUnsatisfied),
                },
            );
        }
        for j in 0..digits {
            out.extend(twos.iter().map(|u| i64::from(u.bit_vartime(j))));
        }
    }
    Ok(())
}

/// The encoding of [`MembershipProof::to_bytes`], which calls this.
impl From<&MembershipProof> for Vec<u8> {
    fn from(value: &MembershipProof) -> Self {
        let mut out = Vec::new();
        for field in value.fields() {
            out.extend_from_slice(&encode_entries(field));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    //! Tests of the protocol internals: an honest proof and the relation it rests on, single-field
    //! tampering (C37), and proofs built by bypassing the prover's relation check (C38).

    use super::{
        Committed, CompressionLevels, MembershipProof, check, check_norms, decompose_witness,
    };
    use crate::{
        accumulator::{Accumulator, Element},
        error::Error,
        key::{PublicKey, SecretKey},
        matrix::Shape,
        poly::Poly,
        proof::{
            Challenge, LinkingRelation, MembershipSecret, MembershipStatement, ProofParams,
            ProofSetup,
            coeffs::{centred, from_integers},
            params::LnpParameters,
        },
        sample::{DomainLabel, Seed, UniformSampler},
        state::ManagerState,
        test_util::TOY,
        vector::PolyVec,
        witness::MembershipWitness,
        zq::Coeff,
    };
    use merlin::Transcript;
    use rand::{SeedableRng, rngs::StdRng};
    use std::{
        sync::{Arc, LazyLock},
        time::Instant,
    };
    use zeroize::Zeroizing;

    /// A toy accumulator with three elements, one of them deleted after the witnesses were issued.
    struct Fixture {
        pk: PublicKey,
        accumulator: Accumulator,
        old_accumulator: Accumulator,
        x: Element,
        witness: MembershipWitness,
        deleted: Element,
        deleted_witness: MembershipWitness,
        params: ProofParams,
    }

    static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
        let mut rng = StdRng::seed_from_u64(7);
        let key = SecretKey::new(
            Some(b"proof/unit test seed, 32 bytes long"),
            Arc::new(TOY.clone()),
            &mut rng,
        )
        .unwrap();
        let pk = PublicKey::from(&key);
        let mut accumulator = Accumulator::new(&key);
        let mut state = ManagerState::new(&key);
        let element = |i: u8| Element::try_from([i].as_slice()).unwrap();
        let (x, y, deleted) = (element(0xa5), element(0x3c), element(0x0f));
        accumulator
            .add_elements_assign(&key, &[x.clone(), y, deleted.clone()], &mut state)
            .unwrap();
        let deleted_witness = MembershipWitness::new(&deleted, &accumulator, &key, &state).unwrap();
        let old_accumulator = accumulator.clone();
        let coefficients = accumulator
            .update_assign(&key, &[], std::slice::from_ref(&deleted), &mut state)
            .unwrap();
        assert_eq!(coefficients.len(), 1);
        let witness = MembershipWitness::new(&x, &accumulator, &key, &state).unwrap();
        let params = ProofParams::new(&pk, Some(b"unit")).unwrap();
        Fixture {
            pk,
            accumulator,
            old_accumulator,
            x,
            witness,
            deleted,
            deleted_witness,
            params,
        }
    });

    /// `A₁ ∈ R_q^{2×ℓ}`, `A₂ ∈ R_q^{2×l}` uniform and `t = A₁·x + A₂·r` for the given ring vectors.
    fn linking(x: &PolyVec, r: &PolyVec) -> LinkingRelation {
        let ring = TOY.ring();
        let mut sampler =
            UniformSampler::new(&Seed::from([4; 32]), DomainLabel::from(&b"link"[..]));
        let a1 = sampler.matrix(
            Shape {
                rows: 2,
                cols: x.len(),
            },
            ring,
        );
        let a2 = sampler.matrix(
            Shape {
                rows: 2,
                cols: r.len(),
            },
            ring,
        );
        let t = a1
            .mul_vec(x, ring)
            .unwrap()
            .add(&a2.mul_vec(r, ring).unwrap(), ring)
            .unwrap();
        LinkingRelation::new(a1, a2, t).unwrap()
    }

    /// The bits of `x` as constant polynomials.
    fn bits(x: &Element) -> PolyVec {
        let ring = TOY.ring();
        x.to_bits(&TOY)
            .unwrap()
            .as_slice()
            .iter()
            .map(|&b| Poly::constant(i64::from(b), ring))
            .collect()
    }

    /// A binary `r` with two entries.
    fn binary_r() -> PolyVec {
        let values: Vec<i64> = (0..128).map(|i| (i * 7 + 3) % 5 % 2).collect();
        from_integers(&values, TOY.ring()).unwrap()
    }

    /// `r` with coefficient 5 set to 2.
    fn wide_r() -> PolyVec {
        let mut values = centred(&binary_r(), TOY.ring()).unwrap();
        values[5] = 2;
        from_integers(&values, TOY.ring()).unwrap()
    }

    /// `s₁ = (x, r, s̄_x)` as integers, for any ring vectors `x`, `r` and witness, without checks.
    fn s1_of(x: &PolyVec, r: &PolyVec, witness: &MembershipWitness) -> Zeroizing<Vec<i64>> {
        let ring = TOY.ring();
        let lnp = LnpParameters::new(&TOY, r.len()).unwrap();
        let mut s1 = centred(x, ring).unwrap();
        s1.extend_from_slice(&centred(r, ring).unwrap());
        decompose_witness(&PolyVec::from(witness.clone()), &lnp, ring, &mut s1).unwrap();
        s1
    }

    /// Commits to `s1` without the relation check, responds to a fixed challenge, and verifies
    /// against `statement`.
    fn bypass(statement: &MembershipStatement<'_>, s1: Zeroizing<Vec<i64>>) -> Result<(), Error> {
        let mut rng = StdRng::seed_from_u64(11);
        let committed =
            Committed::commit(statement, s1, &FIXTURE.params, &PREPARED, &mut rng).unwrap();
        let challenge = Challenge::from([9; 64]);
        let proof = committed.respond(&challenge).unwrap();
        check(&proof, statement, &FIXTURE.params, &PREPARED, &challenge)
    }

    /// An honest proof for `x`, with the statement it was made for.
    struct Honest {
        relation: LinkingRelation,
        proof: MembershipProof,
        challenge: Challenge,
    }

    static HONEST: LazyLock<Honest> = LazyLock::new(|| {
        let f = &*FIXTURE;
        let r = binary_r();
        let relation = linking(&bits(&f.x), &r);
        let statement = MembershipStatement {
            pubkey: &f.pk,
            accumulator: &f.accumulator,
            relation: &relation,
        };
        let secret = MembershipSecret {
            element: &f.x,
            witness: &f.witness,
            r: &r,
        };
        let mut rng = StdRng::seed_from_u64(5);
        let start = Instant::now();
        let committed =
            Committed::new(&statement, &secret, &f.params, &PREPARED, &mut rng).unwrap();
        let committed_at = start.elapsed();
        let challenge = Challenge::from([1; 64]);
        let proof = committed.respond(&challenge).unwrap();
        println!(
            "honest proof: commit {committed_at:?}, total {:?}, {} bytes",
            start.elapsed(),
            proof.to_bytes().len()
        );
        Honest {
            relation,
            proof,
            challenge,
        }
    });

    fn honest_statement() -> MembershipStatement<'static> {
        MembershipStatement {
            pubkey: &FIXTURE.pk,
            accumulator: &FIXTURE.accumulator,
            relation: &HONEST.relation,
        }
    }

    /// A setup for the fixture's key and proof parameters and for relations of the shape
    /// [`linking`] gives with an `ℓ`-entry `x` and [`binary_r`]; every proof here is made and
    /// checked under it.
    static PREPARED: LazyLock<ProofSetup> = LazyLock::new(|| {
        let relation = linking(&bits(&FIXTURE.x), &binary_r());
        ProofSetup::new(&FIXTURE.pk, &FIXTURE.params, &relation).unwrap()
    });

    /// A setup's commitment key is the one its operations use, so verifying with a setup
    /// expands no key of its own: two verifications with one setup pass, and the same proof is
    /// rejected under a setup that names the right proof parameters but holds the key of other
    /// ones. A prover state made with a setup holds the setup's values, not a copy.
    #[test]
    fn a_setup_supplies_the_key_it_holds() {
        let f = &*FIXTURE;
        let honest = &*HONEST;
        let verify = || {
            honest.proof.finalize_with(
                &f.accumulator,
                &f.params,
                &PREPARED,
                &f.pk,
                &honest.challenge,
                &honest.relation,
            )
        };
        assert_eq!(verify().unwrap(), verify().unwrap());
        let other_params = ProofParams::new(&f.pk, Some(b"unit, other")).unwrap();
        let other = ProofSetup::new(&f.pk, &other_params, &honest.relation).unwrap();
        let relabelled = ProofSetup {
            prepared: Arc::clone(&other.prepared),
            ..PREPARED.clone()
        };
        assert_eq!(
            check(
                &honest.proof,
                &honest_statement(),
                &f.params,
                &relabelled,
                &honest.challenge
            ),
            Err(Error::ProofRejected)
        );
        let r = binary_r();
        let secret = MembershipSecret {
            element: &f.x,
            witness: &f.witness,
            r: &r,
        };
        let committed = Committed::new(
            &honest_statement(),
            &secret,
            &f.params,
            &PREPARED,
            &mut StdRng::seed_from_u64(6),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&committed.setup.prepared, &PREPARED.prepared));
    }

    /// An honest proof verifies (C35), and only for its own challenge.
    #[test]
    fn honest_proof_verifies() {
        let honest = &*HONEST;
        let start = Instant::now();
        check(
            &honest.proof,
            &honest_statement(),
            &FIXTURE.params,
            &PREPARED,
            &honest.challenge,
        )
        .unwrap();
        println!("verification: {:?}", start.elapsed());
        assert_eq!(
            check(
                &honest.proof,
                &honest_statement(),
                &FIXTURE.params,
                &PREPARED,
                &Challenge::from([2; 64])
            ),
            Err(Error::ProofRejected)
        );
    }

    /// A linking relation with `A₂ = 0 × usize::MAX`, which `PolyMatrix::zero` builds with no
    /// entries, is refused with an error by the verifier, by `finalize`, by `compress` and when a
    /// setup is built for it, and a setup for another shape is refused. With overflow checks on,
    /// `m̄₁` used to panic; with them off it wrapped, and the verifier went on to build one
    /// polynomial per column of `A₂` until the allocator aborted.
    #[test]
    fn unbounded_linking_columns_are_refused() {
        let ring = TOY.ring();
        let ell = TOY.spec().element_bits as usize;
        let relation = LinkingRelation::new(
            crate::matrix::PolyMatrix::zero(Shape { rows: 0, cols: ell }, ring),
            crate::matrix::PolyMatrix::zero(
                Shape {
                    rows: 0,
                    cols: usize::MAX,
                },
                ring,
            ),
            PolyVec::zero(0, ring),
        )
        .unwrap();
        let statement = MembershipStatement {
            pubkey: &FIXTURE.pk,
            accumulator: &FIXTURE.accumulator,
            relation: &relation,
        };
        let honest = &*HONEST;
        let refused = Err(Error::ProofModulusTooSmall);
        assert_eq!(
            crate::proof::verify(
                &statement,
                &honest.proof,
                &FIXTURE.params,
                &mut Transcript::new(b"t")
            ),
            refused
        );
        assert_eq!(
            ProofSetup::new(&FIXTURE.pk, &FIXTURE.params, &relation).map(drop),
            refused
        );
        assert_eq!(
            check(
                &honest.proof,
                &statement,
                &FIXTURE.params,
                &PREPARED,
                &honest.challenge
            ),
            Err(Error::ParameterMismatch)
        );
        let finalized = honest.proof.finalize(
            &FIXTURE.accumulator,
            &FIXTURE.params,
            &FIXTURE.pk,
            &honest.challenge,
            &relation,
        );
        assert_eq!(finalized.map(drop), refused);
        let levels = CompressionLevels::try_from(1).unwrap();
        let compressed =
            honest
                .proof
                .compress(&statement, &FIXTURE.params, &honest.challenge, levels);
        assert_eq!(compressed.map(drop), refused);
    }

    /// `vector` with one added to entry `index mod len`.
    fn bump(vector: &PolyVec, index: usize) -> PolyVec {
        let ring = TOY.ring();
        let mut entries: Vec<Poly> = vector.clone().into();
        let i = index % entries.len();
        entries[i] = entries[i].add(&Poly::constant(1, ring), ring).unwrap();
        entries.into()
    }

    /// Each single field altered by adding one to one entry is rejected (C37). Every field is
    /// covered; which entry of a vector field is altered is sampled.
    #[test]
    fn every_altered_field_is_rejected() {
        let honest = &*HONEST;
        let ring = TOY.ring();
        let mut rng = StdRng::seed_from_u64(3);
        for field in 0..10 {
            let index = rand::RngExt::random_range(&mut rng, 0..1usize << 20);
            let mut proof = honest.proof.clone();
            match field {
                0 => proof.t_a = bump(&proof.t_a, index),
                1 => proof.w = bump(&proof.w, index),
                2 => proof.t_y = bump(&proof.t_y, index),
                3 => proof.z3 = bump(&proof.z3, index),
                4 => proof.t_p = bump(&proof.t_p, index),
                5 => proof.h = bump(&proof.h, index),
                6 => proof.t_quad = proof.t_quad.add(&Poly::constant(1, ring), ring).unwrap(),
                7 => proof.v = proof.v.add(&Poly::constant(1, ring), ring).unwrap(),
                8 => proof.z1 = bump(&proof.z1, index),
                _ => proof.z2 = bump(&proof.z2, index),
            }
            assert_ne!(proof, honest.proof, "field {field}");
            assert_eq!(
                check(
                    &proof,
                    &honest_statement(),
                    &FIXTURE.params,
                    &PREPARED,
                    &honest.challenge
                ),
                Err(Error::ProofRejected),
                "field {field}"
            );
        }
    }

    /// A response whose norm exceeds its bound is rejected by the norm check, which runs before
    /// any equation (C37).
    #[test]
    fn responses_over_their_bounds_are_rejected() {
        let honest = &*HONEST;
        let ring = TOY.ring();
        let lnp = LnpParameters::new(&TOY, honest.relation.a2().shape().cols).unwrap();
        check_norms(&honest.proof, &lnp, ring).unwrap();
        for (i, bound) in [lnp.beta1, lnp.beta2, lnp.beta3].iter().enumerate() {
            let mut proof = honest.proof.clone();
            let field = match i {
                0 => &mut proof.z1,
                1 => &mut proof.z2,
                _ => &mut proof.z3,
            };
            let mut entries: Vec<Poly> = field.clone().into();
            let mut coefficients = entries[0].coefficients().to_vec();
            coefficients[0] = bound.wrapping_add(&Coeff::ONE);
            entries[0] = Poly::new(coefficients, ring).unwrap();
            *field = entries.into();
            assert_eq!(check_norms(&proof, &lnp, ring), Err(Error::ProofRejected));
            assert_eq!(
                check(
                    &proof,
                    &honest_statement(),
                    &FIXTURE.params,
                    &PREPARED,
                    &honest.challenge
                ),
                Err(Error::ProofRejected)
            );
        }
    }

    /// The prover refuses inputs that do not satisfy relation D.2 (C38): the witness of a deleted
    /// element, a non-binary `r`, and an `r` that breaks `A₁x + A₂r = t`.
    #[test]
    fn prover_refuses_unsatisfied_relations() {
        let f = &*FIXTURE;
        let commit = |statement: &MembershipStatement<'_>, secret: &MembershipSecret<'_>| {
            Committed::new(
                statement,
                secret,
                &f.params,
                &PREPARED,
                &mut StdRng::seed_from_u64(0),
            )
            .map(|_| ())
        };
        let r = binary_r();
        let relation = linking(&bits(&f.deleted), &r);
        let statement = MembershipStatement {
            pubkey: &f.pk,
            accumulator: &f.accumulator,
            relation: &relation,
        };
        let secret = MembershipSecret {
            element: &f.deleted,
            witness: &f.deleted_witness,
            r: &r,
        };
        assert_eq!(commit(&statement, &secret), Err(Error::RelationUnsatisfied));

        let wide = wide_r();
        let relation = linking(&bits(&f.x), &wide);
        let statement = MembershipStatement {
            relation: &relation,
            ..honest_statement()
        };
        let secret = MembershipSecret {
            element: &f.x,
            witness: &f.witness,
            r: &wide,
        };
        assert_eq!(commit(&statement, &secret), Err(Error::RelationUnsatisfied));

        let negated = r.neg(TOY.ring()).unwrap();
        let secret = MembershipSecret {
            element: &f.x,
            witness: &f.witness,
            r: &negated,
        };
        assert_eq!(
            commit(&honest_statement(), &secret),
            Err(Error::RelationUnsatisfied)
        );
    }

    /// A proof built for a non-binary `r` by bypassing the prover's check is rejected (C38).
    #[test]
    fn bypassed_non_binary_r_is_rejected() {
        let f = &*FIXTURE;
        let x = bits(&f.x);
        let r = wide_r();
        let relation = linking(&x, &r);
        let statement = MembershipStatement {
            relation: &relation,
            ..honest_statement()
        };
        assert_eq!(
            bypass(&statement, s1_of(&x, &r, &f.witness)),
            Err(Error::ProofRejected)
        );
    }

    /// Proofs built for an `x` outside `{0, 1}^ℓ` by bypassing the prover's check are rejected
    /// (C38): one with a bit equal to `2`, caught by the binary proof, and one with a bit equal to
    /// the polynomial `X`, whose coefficients are binary, so that only `xᵢ(xᵢ − 1) = 0` catches
    /// it. The accumulator value is what `[A | B − xᵀ⊗G]·s_x` takes for that `x`, so membership
    /// holds.
    #[test]
    fn bypassed_non_binary_x_is_rejected() {
        let f = &*FIXTURE;
        let ring = TOY.ring();
        let r = binary_r();
        let mut monomial = vec![Coeff::ZERO; ring.degree()];
        monomial[1] = Coeff::ONE;
        let mut x_monomial: Vec<Poly> = bits(&f.x).into();
        x_monomial[0] = Poly::new(monomial, ring).unwrap();
        let mut x_two: Vec<Poly> = bits(&f.x).into();
        x_two[1] = Poly::constant(2, ring);
        for x in [PolyVec::from(x_monomial), PolyVec::from(x_two)] {
            let accumulator =
                Accumulator::from_vector(membership_value(&x, &f.witness), f.pk.params()).unwrap();
            let relation = linking(&x, &r);
            let statement = MembershipStatement {
                pubkey: &f.pk,
                accumulator: &accumulator,
                relation: &relation,
            };
            assert_eq!(
                bypass(&statement, s1_of(&x, &r, &f.witness)),
                Err(Error::ProofRejected)
            );
        }
    }

    /// A proof built from the witness of a deleted element by bypassing the prover's check is
    /// rejected against the current accumulator value (C38), while the same construction proves
    /// membership in the value before the deletion.
    #[test]
    fn bypassed_deleted_witness_is_rejected() {
        let f = &*FIXTURE;
        let x = bits(&f.deleted);
        let r = binary_r();
        let relation = linking(&x, &r);
        let cases = [
            (&f.accumulator, Err(Error::ProofRejected)),
            (&f.old_accumulator, Ok(())),
        ];
        for (accumulator, expected) in cases {
            let statement = MembershipStatement {
                pubkey: &f.pk,
                accumulator,
                relation: &relation,
            };
            assert_eq!(
                bypass(&statement, s1_of(&x, &r, &f.deleted_witness)),
                expected
            );
        }
    }

    /// `[A | B − xᵀ⊗G]·s_x` for a vector `x` of ring elements.
    fn membership_value(x: &PolyVec, witness: &MembershipWitness) -> PolyVec {
        let ring = TOY.ring();
        let pk = &FIXTURE.pk;
        let s: Vec<Poly> = PolyVec::from(witness.clone()).into();
        let (m, m_prime) = (TOY.spec().m, TOY.m_prime());
        let g = crate::matrix::PolyMatrix::from(TOY.gadget());
        let head: PolyVec = s[..m].iter().cloned().collect();
        let mut value = pk.a().mul_vec(&head, ring).unwrap();
        for (i, xi) in x.as_slice().iter().enumerate() {
            let block: PolyVec = s[m + i * m_prime..m + (i + 1) * m_prime]
                .iter()
                .cloned()
                .collect();
            let b_part = pk
                .b()
                .column_block(i * m_prime, m_prime)
                .unwrap()
                .mul_vec(&block, ring)
                .unwrap();
            let g_part = g.mul_vec(&block, ring).unwrap();
            let term: PolyVec = b_part
                .as_slice()
                .iter()
                .zip(g_part.as_slice())
                .map(|(b, gp)| b.sub(&xi.mul(gp, ring).unwrap(), ring).unwrap())
                .collect();
            value = value.add(&term, ring).unwrap();
        }
        value
    }

    /// Measurement, run on demand: prover and verifier times, attempts per proof against the
    /// expected `M³ = e^{3(1 + 1/288)} ≈ 20.3`, and the proof size, over eight proofs.
    #[test]
    #[ignore = "measurement: eight full proofs"]
    fn measure_proving_cost() {
        let f = &*FIXTURE;
        let honest = &*HONEST;
        let r = binary_r();
        let statement = honest_statement();
        let secret = MembershipSecret {
            element: &f.x,
            witness: &f.witness,
            r: &r,
        };
        let runs = 8u32;
        let (mut attempts, mut proving, mut verifying) =
            (0, std::time::Duration::ZERO, std::time::Duration::ZERO);
        for run in 0..runs {
            let start = Instant::now();
            let committed = Committed::new(
                &statement,
                &secret,
                &f.params,
                &PREPARED,
                &mut StdRng::seed_from_u64(100 + u64::from(run)),
            )
            .unwrap();
            let challenge = Challenge::from([u8::try_from(run).unwrap(); 64]);
            let (proof, count) = committed.respond_counted(&challenge).unwrap();
            proving += start.elapsed();
            attempts += count;
            let start = Instant::now();
            check(&proof, &statement, &f.params, &PREPARED, &challenge).unwrap();
            verifying += start.elapsed();
            println!("run {run}: {count} attempts");
        }
        println!(
            "mean over {runs}: prove {:?}, verify {:?}, attempts {:.2}, proof {} bytes",
            proving / runs,
            verifying / runs,
            f64::from(attempts) / f64::from(runs),
            honest.proof.to_bytes().len()
        );
    }

    /// The prover's state, which holds `s₁`, `s₂` and the mask seed, is overwritten when dropped.
    #[test]
    fn prover_state_is_wiped() {
        crate::test_util::wiped_on_drop::<Committed>();
    }
}
