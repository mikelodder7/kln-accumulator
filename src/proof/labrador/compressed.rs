// SPDX-License-Identifier: MIT OR Apache-2.0
//! The compressed membership proof: the LNP messages of rounds 1 to 7, `zₓ`, and a LaBRADOR
//! proof of knowledge of `(z_r, σ(z_r), z_{s̄}, σ(z_{s̄}), z₂)` in place of `z₁, z₂` (D.3).
//!
//! The LaBRADOR transcript starts from everything the relation is built from (the outer
//! challenge, the statement, the LNP messages and `zₓ`), so every input of the first level's
//! relation is fixed before its first challenge, as Fiat–Shamir over Figure 2 requires.

use super::{
    LabradorProof, Setup,
    lnp::{LnpInputs, LnpRelation, witness},
};
use crate::{
    accumulator::Accumulator,
    error::{Error, Result},
    key::PublicKey,
    poly::Poly,
    proof::{
        Challenge, LinkingRelation, MembershipStatement, ProofParams, ProofSetup,
        protocol::{
            Decoder, MembershipProof, MembershipProofFinal, Messages, check_field, check_openings,
            replay,
        },
    },
    sample::{DomainLabel, Seed, hash_to_seed},
    vector::{PolyVec, encode_entries},
};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// Label of the seed of the LaBRADOR commitment keys.
const LABEL_KEYS: &[u8] = b"kln/labrador/keys";

/// The number of LaBRADOR levels of a compressed proof. One level sends its opening in the
/// clear; each further level proves the previous level's verification equations instead.
/// **Public.**
///
/// # Examples
///
/// ```
/// use kln_accumulator::{CompressionLevels, Error};
///
/// let levels = CompressionLevels::try_from(3)?;
/// assert_eq!(levels.get(), 3);
/// assert_eq!(CompressionLevels::try_from(0), Err(Error::InvalidCompressionLevels(0)));
/// assert!(CompressionLevels::try_from(CompressionLevels::MAX + 1).is_err());
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionLevels(u8);

impl CompressionLevels {
    /// The most levels supported. The knowledge error of the layer grows linearly in the number
    /// of levels (ePrint 2022/1341, Lemma 3.7); see the crate's documentation of the layer for
    /// its value, and the type's example.
    pub const MAX: u8 = 8;

    /// The number of levels; see the type's example.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

/// Accepts `1..=CompressionLevels::MAX`; anything else is
/// [`Error::InvalidCompressionLevels`].
impl TryFrom<u8> for CompressionLevels {
    type Error = Error;

    fn try_from(levels: u8) -> Result<Self> {
        if (1..=Self::MAX).contains(&levels) {
            Ok(Self(levels))
        } else {
            Err(Error::InvalidCompressionLevels(levels))
        }
    }
}

/// A membership proof whose LNP responses `z₁, z₂` are replaced by a LaBRADOR proof that the
/// verifier's equations D.12 hold for some responses (Appendix D.3). Only `zₓ`, the part of
/// `z₁` for the element bits, is sent in the clear. Serialized field by field; polynomials are
/// hex strings in human-readable formats and raw bytes in binary ones. **Public.** At the toy
/// set it is 2,172,640, 1,117,976 and 852,816 bytes at one, two and three levels, against
/// 9,100,960 uncompressed.
///
/// The knowledge error of the LaBRADOR layer is computed per level in the source
/// (`src/proof/labrador.rs`); its security after Fiat–Shamir is cited, not derived.
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
/// let committing = MembershipProofCommitting::new(
///     &x, &witness, &proof_params, &pk, &acc,
///     LinkingOpening { relation: &relation, r: &r },
///     &mut rng,
/// )?;
/// let mut transcript = Transcript::new(b"presentation");
/// committing.get_bytes_for_challenge(&mut transcript);
/// let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
/// let proof = committing.gen_compressed_proof(&challenge, CompressionLevels::try_from(1)?)?;
/// assert_eq!(proof.levels(), 1);
/// let finalized = proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
/// let mut verifier = Transcript::new(b"presentation");
/// finalized.get_bytes_for_challenge(&mut verifier);
/// assert_eq!(Challenge::from_transcript(b"challenge", &mut verifier), challenge);
/// assert_eq!(kln_accumulator::CompressedMembershipProof::try_from(Vec::from(&proof).as_slice())?, proof);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedMembershipProof {
    pub(crate) t_a: PolyVec,
    pub(crate) w: PolyVec,
    pub(crate) t_y: PolyVec,
    pub(crate) z3: PolyVec,
    pub(crate) t_p: PolyVec,
    pub(crate) h: PolyVec,
    pub(crate) t_quad: Poly,
    pub(crate) v: Poly,
    pub(crate) z_x: PolyVec,
    pub(crate) labrador: LabradorProof,
}

impl CompressedMembershipProof {
    /// Runs every check against the statement `(accumulator, pubkey, relation)` for the outer
    /// `challenge`: `‖z₃‖ ≤ β₃`, `‖zₓ‖ ≤ β₁` and `h̃ᵢ = Σ_j α_{i,j}z₃,ⱼ` of D.12 directly, and the
    /// rest of D.12 through the LaBRADOR proof. Returns what the outer transcript must absorb,
    /// as [`MembershipProof::finalize`] does. Fails with [`Error::ProofRejected`] when a check
    /// fails.
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
    /// # let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
    /// # let committing = MembershipProofCommitting::new(
    /// #     &x, &witness, &proof_params, &pk, &acc,
    /// #     LinkingOpening { relation: &relation, r: &r },
    /// #     &mut rng,
    /// # )?;
    /// # let mut prover = Transcript::new(b"presentation");
    /// # committing.get_bytes_for_challenge(&mut prover);
    /// # let challenge = Challenge::from_transcript(b"challenge", &mut prover);
    /// # let proof = committing.gen_proof(&challenge)?;
    /// // Anyone holding a proof and its challenge can compress it; it is checked the same way.
    /// let compressed = proof.compress(&statement, &proof_params, &challenge, CompressionLevels::try_from(1)?)?;
    /// let finalized = compressed.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
    /// assert_eq!(finalized, proof.finalize(&acc, &proof_params, &pk, &challenge, &relation)?);
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

    /// [`CompressedMembershipProof::finalize`] with the values `setup` holds in place of
    /// deriving them; the LaBRADOR layer's own keys are still expanded per call. Fails with
    /// [`Error::ParameterMismatch`], before any check, unless `setup` was built for `pubkey`'s
    /// parameter set, for `proof_params` and for a relation of `relation`'s shape.
    ///
    /// # Errors
    ///
    /// As above, and as [`CompressedMembershipProof::finalize`].
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
    /// let proof = committing.gen_compressed_proof(&challenge, CompressionLevels::try_from(1)?)?;
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

    /// The number of LaBRADOR levels; see the type's example.
    #[must_use]
    pub fn levels(&self) -> usize {
        self.labrador.levels.len()
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
}

/// Decodes the encoding of `From<&CompressedMembershipProof> for Vec<u8>`, which must be consumed exactly. Shapes and
/// coefficient ranges are checked when the proof is verified.
impl TryFrom<&[u8]> for CompressedMembershipProof {
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
            z_x: decoder.vector()?,
            labrador: LabradorProof::read(&mut decoder)?,
        };
        decoder.finish().map(|()| proof)
    }
}

/// The seed of the LaBRADOR commitment keys, a function of the proof parameters alone.
pub(crate) fn key_seed(proof_params: &ProofParams) -> Seed {
    hash_to_seed(DomainLabel::from(LABEL_KEYS), &[proof_params.seed_bytes()])
}

/// What a prover compresses: an uncompressed proof for `statement` and the prover's state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Compression<'a> {
    /// The proof to compress.
    pub(crate) proof: &'a MembershipProof,
    /// Its statement.
    pub(crate) statement: &'a MembershipStatement<'a>,
    /// The statement digest.
    pub(crate) digest: &'a [u8; 64],
    /// The LNP parameters, the ABDLOP key and [`key_seed`] of the proof parameters.
    pub(crate) setup: &'a ProofSetup,
    /// The outer challenge.
    pub(crate) challenge: &'a Challenge,
    /// The number of levels.
    pub(crate) levels: CompressionLevels,
}

/// Replaces the responses of `inputs.proof` by a LaBRADOR proof.
pub(crate) fn compress(inputs: &Compression<'_>) -> Result<CompressedMembershipProof> {
    let proof = inputs.proof;
    let statement = inputs.statement;
    let ring = statement.pubkey.params().ring();
    let lnp = inputs.setup.lnp();
    let messages = proof.messages();
    let challenges = replay(&messages, statement, inputs.digest, lnp, inputs.challenge)?;
    let relation = challenges.relation(statement, lnp, messages.h)?;
    let (z_x, labrador_witness) = witness(proof.z1(), proof.z2(), lnp, ring)?;
    let lnp_relation = LnpRelation::new(LnpInputs {
        key: inputs.setup.key(),
        relation: &relation,
        lnp,
        messages,
        z_x: &z_x,
        c: &challenges.c,
    })?;
    let mut transcript = transcript(inputs.challenge, inputs.digest, &messages, &z_x);
    let labrador = super::prove(
        &lnp_relation,
        labrador_witness,
        &Setup {
            seed: inputs.setup.compression_seed(),
            ring,
        },
        inputs.levels,
        &mut transcript,
    )?;
    Ok(CompressedMembershipProof {
        t_a: messages.t_a.clone(),
        w: messages.w.clone(),
        t_y: messages.t_y.clone(),
        z3: messages.z3.clone(),
        t_p: messages.t_p.clone(),
        h: messages.h.clone(),
        t_quad: messages.t_quad.clone(),
        v: messages.v.clone(),
        z_x,
        labrador,
    })
}

/// The verifier of a compressed proof for the outer `challenge`, under the values `setup` holds
/// once it is checked against `statement` and `proof_params`.
pub(crate) fn check(
    proof: &CompressedMembershipProof,
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
    let messages = proof.messages();
    messages.validate(lnp, ring)?;
    check_field(&proof.z_x, lnp.element_bits, ring)?;
    // ‖z₃‖ ≤ β₃ and ‖zₓ‖ ≤ β₁.
    if proof.z3.norm_l2_squared(ring) > *lnp.beta_squared(2)
        || proof.z_x.norm_l2_squared(ring) > *lnp.beta_squared(0)
    {
        return Err(Error::ProofRejected);
    }
    let digest = statement.digest(proof_params);
    let challenges = replay(&messages, statement, &digest, lnp, challenge)?;
    // h̃ᵢ = Σ_j α_{i,j}·z₃,ⱼ.
    check_openings(&messages, &challenges.alpha, ring)?;
    let relation = challenges.relation(statement, lnp, messages.h)?;
    let lnp_relation = LnpRelation::new(LnpInputs {
        key: setup.key(),
        relation: &relation,
        lnp,
        messages,
        z_x: &proof.z_x,
        c: &challenges.c,
    })?;
    let mut transcript = transcript(challenge, &digest, &messages, &proof.z_x);
    super::verify(
        &lnp_relation,
        &proof.labrador,
        &Setup {
            seed: setup.compression_seed(),
            ring,
        },
        &mut transcript,
    )
}

/// The LaBRADOR transcript: the outer challenge, the statement digest, the LNP messages (from
/// which every LNP challenge is derived) and `zₓ`.
fn transcript(
    challenge: &Challenge,
    digest: &[u8; 64],
    messages: &Messages<'_>,
    z_x: &PolyVec,
) -> Transcript {
    let mut transcript = Transcript::new(b"kln-accumulator/labrador");
    transcript.append_message(b"outer challenge", &<[u8; 64]>::from(*challenge));
    transcript.append_message(b"statement", digest);
    for field in messages.fields() {
        transcript.append_message(b"lnp message", &encode_entries(field));
    }
    transcript.append_message(b"z_x", &Vec::from(z_x));
    transcript
}

/// The encoding: the LNP messages as in [`MembershipProof::to_bytes`], then `zₓ`, then the
/// LaBRADOR levels (see the crate's documentation of the layer). `TryFrom<&[u8]>` decodes it,
/// failing with [`Error::InvalidEncodingLength`]; everything else is checked by
/// [`CompressedMembershipProof::finalize`]. See [`CompressedMembershipProof`]'s example.
impl From<&CompressedMembershipProof> for Vec<u8> {
    fn from(value: &CompressedMembershipProof) -> Self {
        let mut out = Vec::new();
        for field in value.messages().fields() {
            out.extend_from_slice(&encode_entries(field));
        }
        out.extend_from_slice(&Vec::from(&value.z_x));
        value.labrador.write(&mut out);
        out
    }
}
