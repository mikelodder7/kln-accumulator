// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zero-knowledge proofs of accumulator membership: the LNP commit-and-prove argument of
//! Appendix D.2, made non-interactive by Fiat–Shamir over merlin transcripts.
//!
//! The prover shows knowledge of an element `x ∈ {0, 1}^ℓ`, a binary vector `r` and a short
//! witness `s_x` such that
//!
//! * `A₁·x + A₂·r = t`, the linking relation to an outer credential ([`LinkingRelation`]);
//! * `[A | B − xᵀ⊗G]·s_x = c`, membership in the accumulator `c` under the public key
//!   `(A, B, u)`,
//!
//! which is relation D.1 (paper line 2541) in the form D.2 (line 2587): `s_x` is committed as a
//! digit vector `s̄_x` with `s_x = G_β·s̄_x`, each bit of `x` as a constant polynomial, and the
//! whole Ajtai message `s₁ = (x, r, s̄_x)` is proved binary by the approximate range proof and
//! `⟨s₁, s₁ − 1⟩ = 0`, together with `xᵢ(xᵢ − 1) = 0`.
//!
//! Two corrections to the printed appendix are made, as the crate's design records: the digit
//! decomposition of `s_x` ends in one top digit of weight `−2^{D−1}`, so that negative
//! coefficients are representable while every digit stays binary; and the prover's `g₁` and `g₀`
//! are derived from the verifier's `Z` itself (see `relation`), since the printed formulas
//! (lines 3133–3169) omit terms of D.8 and D.11. The parameters of D.2.3, with the notes on how
//! each is instantiated, are in [`LnpParameters`].
//!
//! The protocol runs over the degree-64 ring with the accumulator's own modulus. At the toy
//! parameter set the accumulator ring is that ring, so the public matrices enter as they are;
//! sets of larger degree are refused with [`Error::UnsupportedProofDegree`] until the
//! rank-`d/64` subring map is supplied.
//!
//! The API mirrors the vb20 pairing accumulator's three steps, over a one-shot [`prove`] and
//! [`verify`]:
//!
//! ```text
//! MembershipProofCommitting::new(…)          prover: commit t_A to (x, r, s̄_x)
//!   .get_bytes_for_challenge(&mut transcript) both: statement digest and t_A
//! Challenge::from_transcript(label, &mut transcript)
//!   .gen_proof(&challenge)                    prover: inner Fiat–Shamir with aborts
//! MembershipProof::finalize(…, &challenge, …) verifier: every check of D.12
//!   .get_bytes_for_challenge(&mut transcript) verifier: rederive and compare the challenge
//! ```
//!
//! Rejection sampling makes the prover restart with fresh masks, which invalidates its first
//! message, so the outer transcript sees only the retry-stable commitment `t_A` and the
//! statement; `gen_proof` seeds the inner Fiat–Shamir transcript with the outer challenge and
//! runs the restarts inside.
//!
//! [`MembershipProofCommitting::gen_compressed_proof`] makes the compressed form of
//! Appendix D.3, [`CompressedMembershipProof`], in which a LaBRADOR proof replaces the
//! responses `z₁, z₂`; both forms remain available.
//!
//! A [`ProofSetup`] holds the values these operations derive from the parameter set, the proof
//! parameters and the relation's shape, among them the commitment key; each operation has a
//! sibling with a `_with` suffix that takes one in place of deriving them.
//!
//!
//!
//!
//! # Examples, costs and secret handling
//!
//! See the book's chapter "Membership proofs".

mod abdlop;
mod challenge;
mod coeffs;
mod labrador;
mod params;
mod protocol;
mod range;
mod rejection;
mod relation;
mod subring;

pub use labrador::{CompressedMembershipProof, CompressionLevels};
pub use params::LnpParameters;
pub use protocol::{MembershipProof, MembershipProofCommitting, MembershipProofFinal};
pub use subring::SubringMap;

use crate::{
    accumulator::{Accumulator, Element},
    error::{Error, Result, check_dimension},
    key::PublicKey,
    matrix::{PolyMatrix, Shape},
    params::Params,
    sample::{DomainLabel, Seed, hash_parts, hash_to_seed},
    vector::PolyVec,
    witness::MembershipWitness,
};
use abdlop::CommitmentKey;
use merlin::Transcript;
use rand_core::CryptoRng;
use shake::digest::XofReader;
use std::sync::Arc;

/// Label of the hash that derives [`ProofParams`].
const LABEL_PARAMS: &[u8] = b"kln/lnp/params";
/// Label of the statement digest.
const LABEL_STATEMENT: &[u8] = b"kln/lnp/statement";
/// The transcript label of the challenge the one-shot [`prove`] and [`verify`] draw.
const CHALLENGE_LABEL: &[u8] = b"kln-lnp challenge";

/// The public parameters of membership proofs: the seed the ABDLOP commitment key is expanded
/// from, derived from the accumulator's public key and an optional entropy input, as the vb20
/// pairing accumulator derives its proof generators. **Public**; the prover and the verifier
/// must use the same.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Error, Params, ProofParams, PublicKey, SecretKey};
/// use merlin::Transcript;
/// use rand::{SeedableRng, rngs::StdRng};
/// use std::sync::Arc;
///
/// let mut rng = StdRng::seed_from_u64(0);
/// let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// let pk = PublicKey::from(&key);
/// let params = ProofParams::new(&pk, Some(b"deployment 1"))?;
/// assert_eq!(params, ProofParams::new(&pk, Some(b"deployment 1"))?);
/// assert_ne!(params, ProofParams::new(&pk, None)?);
/// params.add_to_transcript(&mut Transcript::new(b"presentation"));
/// // Proofs are implemented at ring degree 64 only.
/// let big = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::paper_128()?), &mut rng)?;
/// assert_eq!(
///     ProofParams::new(&PublicKey::from(&big), None),
///     Err(Error::UnsupportedProofDegree(4096))
/// );
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofParams {
    seed: [u8; 32],
}

impl ProofParams {
    /// The parameters for `pk`: SHAKE256 of the public key's encoding and of `entropy` (with a
    /// flag distinguishing `None` from `Some(&[])`). Fails with [`Error::UnsupportedProofDegree`]
    /// unless the accumulator ring has degree 64.
    ///
    /// # Errors
    ///
    /// As above.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Params, ProofParams, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// // Prover and verifier derive the same parameters from the public key and the entropy.
    /// let proof_params = ProofParams::new(&pk, Some(b"deployment 1"))?;
    /// assert_eq!(proof_params, ProofParams::new(&pk, Some(b"deployment 1"))?);
    /// // Misuse: no entropy and empty entropy are different inputs, so both sides must agree.
    /// assert_ne!(ProofParams::new(&pk, None)?, ProofParams::new(&pk, Some(&[]))?);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new(pk: &PublicKey, entropy: Option<&[u8]>) -> Result<Self> {
        let degree = pk.params().ring().degree();
        if degree != challenge::DEGREE {
            return Err(Error::UnsupportedProofDegree(degree));
        }
        let flag = [u8::from(entropy.is_some())];
        let seed = hash_to_seed(
            DomainLabel::from(LABEL_PARAMS),
            &[&pk.to_bytes(), &flag, entropy.unwrap_or_default()],
        );
        Ok(Self {
            seed: *seed.as_bytes(),
        })
    }

    /// Appends the parameters to `transcript`, for protocols that bind them into an outer
    /// transcript; see the type's example.
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_message(b"kln-lnp proof params", &self.seed);
    }

    /// The seed of the commitment key.
    pub(crate) fn seed(&self) -> Seed {
        Seed::from(self.seed)
    }

    /// The bytes of [`ProofParams::seed`].
    pub(crate) fn seed_bytes(&self) -> &[u8; 32] {
        &self.seed
    }
}

/// The linking relation `A₁·x + A₂·r = t` of equation 5.5 (line 2544) between the element `x`
/// and an outer credential's binary vector `r`: `A₁ ∈ R_q^{h×ℓ}`, `A₂ ∈ R_q^{h×l}`,
/// `t ∈ R_q^h`. The bits of `x` enter as constant polynomials. `h = 0` or `l = 0` give a
/// statement without that part. **Public**: it is part of the statement; `r` is the prover's.
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
/// assert_eq!(relation.a1().shape(), Shape { rows: 1, cols: 8 });
/// assert_eq!(relation.a2().shape(), Shape { rows: 1, cols: 1 });
/// assert_eq!(relation.t().len(), 1);
/// // 4 shape words, then 8 + 1 + 1 polynomials of 64 coefficients of 24 bytes.
/// assert_eq!(Vec::from(&relation).len(), 32 + 10 * 64 * 24);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkingRelation {
    a1: PolyMatrix,
    a2: PolyMatrix,
    t: PolyVec,
}

impl LinkingRelation {
    /// Checks that `A₁`, `A₂` and `t` have the same number of rows; shapes against a parameter
    /// set and coefficient ranges are checked when a proof is made or verified. See the type's
    /// example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when the row counts differ.
    pub fn new(a1: PolyMatrix, a2: PolyMatrix, t: PolyVec) -> Result<Self> {
        for rows in [a1.shape().rows, a2.shape().rows] {
            check_dimension(t.len(), rows)?;
        }
        Ok(Self { a1, a2, t })
    }

    /// `A₁`. See the type's example.
    #[must_use]
    pub fn a1(&self) -> &PolyMatrix {
        &self.a1
    }

    /// `A₂`. See the type's example.
    #[must_use]
    pub fn a2(&self) -> &PolyMatrix {
        &self.a2
    }

    /// `t`. See the type's example.
    #[must_use]
    pub fn t(&self) -> &PolyVec {
        &self.t
    }

    /// `l`, the length of `r`.
    pub(crate) fn r_len(&self) -> usize {
        self.a2.shape().cols
    }

    /// The shapes of `A₁` and `A₂`, which fix that of `t`.
    fn shapes(&self) -> [Shape; 2] {
        [self.a1.shape(), self.a2.shape()]
    }

    /// Checks `A₁` has `ℓ` columns and every coefficient is reduced modulo `q`.
    pub(crate) fn validate(&self, params: &Params) -> Result<()> {
        let ell = params.spec().element_bits as usize;
        check_dimension(ell, self.a1.shape().cols)?;
        let ring = params.ring();
        self.a1.validate(ring)?;
        self.a2.validate(ring)?;
        self.t.validate(ring)
    }
}

/// The values every membership-proof operation derives from the parameter set, the
/// [`ProofParams`] and the shape of the [`LinkingRelation`], derived once: the
/// [`LnpParameters`], with the Gaussian samplers of the prover's masks, and the ABDLOP
/// commitment key expanded from the proof parameters' seed, about 160 MB at the toy set.
///
/// [`prove_with`], [`verify_with`], [`MembershipProofCommitting::new_with`],
/// [`MembershipProof::finalize_with`], [`MembershipProof::compress_with`] and
/// [`CompressedMembershipProof::finalize_with`] take a setup in place of deriving these values
/// per call, so a verifier that checks many proofs under one public key, one `ProofParams` and
/// one relation shape expands the key once. Each refuses, with [`Error::ParameterMismatch`] and
/// before any other work, a setup built for another parameter set, for other proof parameters,
/// or for a relation whose `A₁` or `A₂` has another shape. The operations without a setup build
/// one per call, so both forms make and accept the same proofs.
///
/// The keys of the LaBRADOR compression layer are not held: each level's keys depend on the
/// number of levels a proof has, so compressing and checking a compressed proof still expand
/// them per call.
///
/// **Public.** It holds no secret, so nothing in it needs wiping. Clones share the derived
/// values. [`Debug`](core::fmt::Debug) prints what the setup was built for and the
/// `LnpParameters`, not the key. It has no serde form: it is derived, never stored or sent.
///
/// # Examples
///
/// ```
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
/// assert!(format!("{setup:?}").starts_with("ProofSetup {"));
/// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
/// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
/// // Proof parameters other than the setup's own are refused before any work.
/// let other = ProofParams::new(&pk, None)?;
/// assert_eq!(
///     MembershipProofCommitting::new_with(&secret, &other, &setup, &statement, &mut rng).map(drop),
///     Err(Error::ParameterMismatch)
/// );
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone)]
pub struct ProofSetup {
    /// The parameter set.
    params: Arc<Params>,
    /// The proof parameters.
    proof_params: ProofParams,
    /// The shapes of `A₁` and `A₂`.
    shapes: [Shape; 2],
    /// The derived values, shared by clones.
    prepared: Arc<Prepared>,
}

/// The derived values of a [`ProofSetup`].
struct Prepared {
    /// The LNP parameters for the relation's `l`.
    lnp: LnpParameters,
    /// The ABDLOP commitment key.
    key: CommitmentKey,
    /// The seed of the LaBRADOR commitment keys.
    compression_seed: Seed,
}

impl ProofSetup {
    /// Derives the setup for proofs under `pubkey`'s parameter set and `proof_params` with a
    /// linking relation of `relation`'s shape: the [`LnpParameters`] for its `l`, then the
    /// commitment key. Only the shapes of `relation` are read; each operation checks its
    /// entries. It costs about what one operation without a setup spends on these values.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedProofDegree`] and [`Error::ProofModulusTooSmall`], as
    /// [`LnpParameters::new`].
    ///
    /// # Examples
    ///
    /// ```
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
    /// // Build one setup per public key, proof parameters and relation shape, then reuse it.
    /// let setup = ProofSetup::new(&pk, &proof_params, &relation)?;
    /// let for_worker = setup.clone(); // clones share the expanded commitment key
    /// // Misuse: passing other proof parameters with it is refused before any work.
    /// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
    /// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
    /// let other = ProofParams::new(&pk, None)?;
    /// let refused = prove_with(&statement, &secret, &other, &for_worker, &mut Transcript::new(b"t"), &mut rng);
    /// assert_eq!(refused.map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new(
        pubkey: &PublicKey,
        proof_params: &ProofParams,
        relation: &LinkingRelation,
    ) -> Result<Self> {
        let params = pubkey.params();
        let lnp = LnpParameters::new(params, relation.r_len())?;
        let key = CommitmentKey::expand(&proof_params.seed(), &lnp, params.ring())?;
        Ok(Self {
            params: Arc::clone(params),
            proof_params: *proof_params,
            shapes: relation.shapes(),
            prepared: Arc::new(Prepared {
                lnp,
                key,
                compression_seed: labrador::key_seed(proof_params),
            }),
        })
    }

    /// Fails with [`Error::ParameterMismatch`] unless the setup was built for the parameter set
    /// of `statement`, for `proof_params` and for a relation of the shape of `statement`'s.
    pub(crate) fn check(
        &self,
        statement: &MembershipStatement<'_>,
        proof_params: &ProofParams,
    ) -> Result<()> {
        self.params.check_same(statement.pubkey.params())?;
        if self.proof_params == *proof_params && self.shapes == statement.relation.shapes() {
            Ok(())
        } else {
            Err(Error::ParameterMismatch)
        }
    }

    /// The LNP parameters.
    pub(crate) fn lnp(&self) -> &LnpParameters {
        &self.prepared.lnp
    }

    /// The ABDLOP commitment key.
    pub(crate) fn key(&self) -> &CommitmentKey {
        &self.prepared.key
    }

    /// The seed of the LaBRADOR commitment keys.
    pub(crate) fn compression_seed(&self) -> &Seed {
        &self.prepared.compression_seed
    }
}

impl core::fmt::Debug for ProofSetup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProofSetup")
            .field("spec", self.params.spec())
            .field("proof_params", &self.proof_params)
            .field("a1", &self.shapes[0])
            .field("a2", &self.shapes[1])
            .field("lnp", self.lnp())
            .finish_non_exhaustive()
    }
}

/// The public statement of a membership proof. **Public**; it borrows its parts, so it is
/// `Copy`.
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
/// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
/// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
/// let proof = prove(&statement, &secret, &proof_params, &mut Transcript::new(b"t"), &mut rng)?;
/// verify(&statement, &proof, &proof_params, &mut Transcript::new(b"t"))?;
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct MembershipStatement<'a> {
    /// The accumulator's public key `(A, B, u)`.
    pub pubkey: &'a PublicKey,
    /// The accumulator value `c`.
    pub accumulator: &'a Accumulator,
    /// The linking relation `(A₁, A₂, t)`.
    pub relation: &'a LinkingRelation,
}

impl MembershipStatement<'_> {
    /// SHAKE256 of the proof parameters, the public key, the accumulator value and the linking
    /// relation: what binds a proof to its statement in both transcripts.
    pub(crate) fn digest(&self, proof_params: &ProofParams) -> [u8; 64] {
        let mut out = [0u8; 64];
        hash_parts(
            DomainLabel::from(LABEL_STATEMENT),
            &[
                proof_params.seed_bytes(),
                &self.pubkey.to_bytes(),
                &self.accumulator.to_bytes(),
                &Vec::from(self.relation),
            ],
        )
        .read(&mut out);
        out
    }
}

/// The prover's secret inputs: the element, its membership witness and the linking vector `r`.
///
/// **Holder-private, by reference.** It only borrows the secrets, so it owns nothing to wipe
/// and copying it copies three references; the values it points to are wiped when their owners
/// drop them (a [`MembershipWitness`] and a [`PolyVec`] wipe themselves). [`Debug`](core::fmt::Debug)
/// prints none of it.
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
/// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
/// assert_eq!(format!("{secret:?}"), "MembershipSecret { .. }");
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy)]
pub struct MembershipSecret<'a> {
    /// The element `x`.
    pub element: &'a Element,
    /// The membership witness `s_x` for `x`.
    pub witness: &'a MembershipWitness,
    /// The binary vector `r` with `A₁·x + A₂·r = t`.
    pub r: &'a PolyVec,
}

impl core::fmt::Debug for MembershipSecret<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MembershipSecret").finish_non_exhaustive()
    }
}

/// The prover's side of the linking relation: the relation and the secret `r`.
///
/// **Holder-private, by reference**, as [`MembershipSecret`]: [`Debug`](core::fmt::Debug) prints the public
/// relation and not `r`.
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
/// let opening = LinkingOpening { relation: &relation, r: &r };
/// assert!(!format!("{opening:?}").contains(" r:"));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy)]
pub struct LinkingOpening<'a> {
    /// The public relation `(A₁, A₂, t)`.
    pub relation: &'a LinkingRelation,
    /// The binary vector `r`.
    pub r: &'a PolyVec,
}

impl core::fmt::Debug for LinkingOpening<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinkingOpening")
            .field("relation", self.relation)
            .finish_non_exhaustive()
    }
}

/// The outer Fiat–Shamir challenge: 64 bytes from a merlin transcript. It seeds the inner
/// transcript of the LNP proof, so a proof is valid for exactly one challenge. It plays the
/// role of the vb20 pairing accumulator's `Element::from_transcript`, which this crate cannot
/// reuse because its elements have only `ℓ` bits. **Public.**
///
/// # Examples
///
/// ```
/// use kln_accumulator::Challenge;
/// use merlin::Transcript;
///
/// let draw = || {
///     let mut transcript = Transcript::new(b"presentation");
///     transcript.append_message(b"nonce", b"42");
///     Challenge::from_transcript(b"challenge", &mut transcript)
/// };
/// assert_eq!(draw(), draw());
/// let bytes: [u8; 64] = draw().into();
/// assert_eq!(Challenge::from(bytes), draw());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, derive_more::From, derive_more::Into)]
pub struct Challenge([u8; 64]);

impl Challenge {
    /// Draws the challenge from `transcript` under `label`; see the type's example.
    pub fn from_transcript(label: &'static [u8], transcript: &mut Transcript) -> Self {
        let mut bytes = [0u8; 64];
        transcript.challenge_bytes(label, &mut bytes);
        Self(bytes)
    }
}

/// Appends what the outer transcript sees of a proof: the statement digest and `t_A`.
fn append_commitment(transcript: &mut Transcript, digest: &[u8; 64], t_a: &PolyVec) {
    transcript.append_message(b"kln-lnp statement", digest);
    append_vec(transcript, b"kln-lnp t_A", t_a);
}

/// Appends a vector's self-describing encoding under `label`.
fn append_vec(transcript: &mut Transcript, label: &'static [u8], v: &PolyVec) {
    transcript.append_message(label, &Vec::from(v));
}

/// A 32-byte seed drawn from the transcript.
fn challenge_seed(transcript: &mut Transcript, label: &'static [u8]) -> Seed {
    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(label, &mut bytes);
    Seed::from(bytes)
}

/// Proves membership for `statement` with `secret` in one shot: commits, absorbs the statement
/// and `t_A` into `transcript`, draws the challenge from it and responds. Fails with
/// [`Error::RelationUnsatisfied`] when the secret does not satisfy relation D.2 for the
/// statement.
///
/// The commitment randomness `s₂` and the mask seed come from `rng`; everything secret the
/// prover derives is overwritten when the call returns. 2 to 12 s at the toy set. It derives
/// the values a [`ProofSetup`] holds on every call; [`prove_with`] reuses them.
///
/// # Errors
///
/// As above; [`Error::UnsupportedProofDegree`] at a set of degree other than 64;
/// [`Error::ParameterMismatch`] for inputs of another set; [`Error::ProverAborted`] if every
/// one of 1000 attempts aborts, which does not happen in practice (about 20 are expected).
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
/// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
/// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
/// let proof = prove(&statement, &secret, &proof_params, &mut Transcript::new(b"t"), &mut rng)?;
/// verify(&statement, &proof, &proof_params, &mut Transcript::new(b"t"))?;
/// // The verifier's transcript must match the prover's.
/// assert!(verify(&statement, &proof, &proof_params, &mut Transcript::new(b"u")).is_err());
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub fn prove<R: CryptoRng + ?Sized>(
    statement: &MembershipStatement<'_>,
    secret: &MembershipSecret<'_>,
    proof_params: &ProofParams,
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<MembershipProof> {
    let setup = ProofSetup::new(statement.pubkey, proof_params, statement.relation)?;
    prove_with(statement, secret, proof_params, &setup, transcript, rng)
}

/// [`prove`] with the values `setup` holds in place of deriving them: the same proof from the
/// same transcript state and `rng`. Fails with [`Error::ParameterMismatch`], before touching
/// `transcript` or `rng`, unless `setup` was built for `statement`'s parameter set, for
/// `proof_params` and for a relation of `statement.relation`'s shape.
///
/// # Errors
///
/// As above, and as [`prove`].
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
/// let proof = prove_with(&statement, &secret, &proof_params, &setup, &mut Transcript::new(b"t"), &mut rng)?;
/// // Either verifier accepts it.
/// verify_with(&statement, &proof, &proof_params, &setup, &mut Transcript::new(b"t"))?;
/// verify(&statement, &proof, &proof_params, &mut Transcript::new(b"t"))?;
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub fn prove_with<R: CryptoRng + ?Sized>(
    statement: &MembershipStatement<'_>,
    secret: &MembershipSecret<'_>,
    proof_params: &ProofParams,
    setup: &ProofSetup,
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<MembershipProof> {
    let committed = protocol::Committed::new(statement, secret, proof_params, setup, rng)?;
    committed.append_to(transcript);
    committed.respond(&Challenge::from_transcript(CHALLENGE_LABEL, transcript))
}

/// Verifies a proof made by [`prove`] with a transcript in the same state as the prover's.
/// Fails with [`Error::ProofRejected`] when any check of D.12 fails. About 2 s at the toy set.
/// It derives the values a [`ProofSetup`] holds on every call; [`verify_with`] reuses them.
///
/// # Errors
///
/// As above; [`Error::UnsupportedProofDegree`] and [`Error::ParameterMismatch`] as for
/// [`prove`].
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
/// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
/// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
/// let proof = prove(&statement, &secret, &proof_params, &mut Transcript::new(b"presentation"), &mut rng)?;
/// verify(&statement, &proof, &proof_params, &mut Transcript::new(b"presentation"))?;
/// // Misuse: a verifier with other proof parameters (here, no entropy) rejects every proof.
/// let other = ProofParams::new(&pk, None)?;
/// let rejected = verify(&statement, &proof, &other, &mut Transcript::new(b"presentation"));
/// assert_eq!(rejected, Err(Error::ProofRejected));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub fn verify(
    statement: &MembershipStatement<'_>,
    proof: &MembershipProof,
    proof_params: &ProofParams,
    transcript: &mut Transcript,
) -> Result<()> {
    let setup = ProofSetup::new(statement.pubkey, proof_params, statement.relation)?;
    verify_with(statement, proof, proof_params, &setup, transcript)
}

/// [`verify`] with the values `setup` holds in place of deriving them, for a verifier that
/// checks many proofs of one shape under one public key and `ProofParams`. Fails with
/// [`Error::ParameterMismatch`], before touching `transcript`, unless `setup` was built for
/// `statement`'s parameter set, for `proof_params` and for a relation of `statement.relation`'s
/// shape.
///
/// # Errors
///
/// As above, and as [`verify`].
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
/// let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
/// let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
/// let proofs = [
///     prove(&statement, &secret, &proof_params, &mut Transcript::new(b"t"), &mut rng)?,
///     prove(&statement, &secret, &proof_params, &mut Transcript::new(b"t"), &mut rng)?,
/// ];
/// // One setup, one key expansion, for every verification.
/// let setup = ProofSetup::new(&pk, &proof_params, &relation)?;
/// for proof in &proofs {
///     verify_with(&statement, proof, &proof_params, &setup, &mut Transcript::new(b"t"))?;
/// }
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub fn verify_with(
    statement: &MembershipStatement<'_>,
    proof: &MembershipProof,
    proof_params: &ProofParams,
    setup: &ProofSetup,
    transcript: &mut Transcript,
) -> Result<()> {
    // Checked here as well as in `protocol::check`, so that a refused setup leaves the
    // transcript as it was.
    setup.check(statement, proof_params)?;
    let digest = statement.digest(proof_params);
    append_commitment(transcript, &digest, proof.commitment());
    let challenge = Challenge::from_transcript(CHALLENGE_LABEL, transcript);
    protocol::check(proof, statement, proof_params, setup, &challenge)
}

/// The encoding the statement digest absorbs: the shapes of `A₁` and `A₂` as four
/// little-endian `u64`, then the coefficients of `A₁`, `A₂` (row-major) and `t`, 24 bytes
/// each. See [`LinkingRelation`]'s example.
impl From<&LinkingRelation> for Vec<u8> {
    fn from(value: &LinkingRelation) -> Self {
        let mut out = Vec::new();
        for shape in [value.a1.shape(), value.a2.shape()] {
            out.extend_from_slice(&(shape.rows as u64).to_le_bytes());
            out.extend_from_slice(&(shape.cols as u64).to_le_bytes());
        }
        value.a1.write_coefficients(&mut out);
        value.a2.write_coefficients(&mut out);
        value.t.write_coefficients(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkingRelation, ProofParams};
    use crate::{
        error::Error,
        key::{PublicKey, SecretKey},
        matrix::{PolyMatrix, Shape},
        params::Params,
        test_util::TOY,
        vector::PolyVec,
    };
    use std::sync::Arc;

    /// The commitment key's seed is a function of the public key and the entropy input
    /// (C34).
    #[test]
    fn proof_params_derive_from_key_and_entropy() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        use rand::SeedableRng;
        let key = SecretKey::new(
            Some(b"kln/test/proof-params, first key"),
            Arc::new(TOY.clone()),
            &mut rng,
        )
        .unwrap();
        let other = SecretKey::new(
            Some(b"kln/test/proof-params, second key"),
            Arc::new(TOY.clone()),
            &mut rng,
        )
        .unwrap();
        let (pk, pk2) = (PublicKey::from(&key), PublicKey::from(&other));
        let params = ProofParams::new(&pk, Some(b"e")).unwrap();
        assert_eq!(params, ProofParams::new(&pk, Some(b"e")).unwrap());
        assert_ne!(params, ProofParams::new(&pk, Some(b"f")).unwrap());
        assert_ne!(params, ProofParams::new(&pk2, Some(b"e")).unwrap());
        assert_ne!(
            ProofParams::new(&pk, None).unwrap(),
            ProofParams::new(&pk, Some(b"")).unwrap()
        );
        let paper = SecretKey::new(
            Some(b"kln/test/proof-params, first key"),
            Arc::new(Params::paper_128().unwrap()),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            ProofParams::new(&PublicKey::from(&paper), None),
            Err(Error::UnsupportedProofDegree(4096))
        );
    }

    #[test]
    fn linking_relation_checks_rows() {
        let ring = TOY.ring();
        let a1 = PolyMatrix::zero(Shape { rows: 2, cols: 8 }, ring);
        let a2 = PolyMatrix::zero(Shape { rows: 2, cols: 1 }, ring);
        let relation =
            LinkingRelation::new(a1.clone(), a2.clone(), PolyVec::zero(2, ring)).unwrap();
        assert!(relation.validate(&TOY).is_ok());
        assert_eq!(relation.r_len(), 1);
        assert!(LinkingRelation::new(a1.clone(), a2, PolyVec::zero(3, ring)).is_err());
        let narrow = LinkingRelation::new(
            PolyMatrix::zero(Shape { rows: 2, cols: 7 }, ring),
            PolyMatrix::zero(Shape { rows: 2, cols: 0 }, ring),
            PolyVec::zero(2, ring),
        )
        .unwrap();
        assert!(narrow.validate(&TOY).is_err());
        assert_eq!(Vec::from(&relation).len(), 32 + (16 + 2 + 2) * 64 * 24);
    }
}
