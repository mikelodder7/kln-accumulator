// SPDX-License-Identifier: MIT OR Apache-2.0
//! LaBRADOR compression of the membership proof (ePrint 2025/1099, Appendix D.3): the LNP
//! responses `z₁, z₂` are not sent; a LaBRADOR proof of knowledge of them, for the principal
//! relation the verification equations D.12 become, is sent instead.
//!
//! LaBRADOR is ePrint 2022/1341, "the paper" in this module and its
//! children. Every verifier check, norm bound, slack factor, challenge distribution and
//! parameter rule cites the section, equation, figure line or theorem it implements, and each
//! deliberate difference is stated where it lives, with its reason. Every parameter is derived
//! for the crate's modulus in [`params`].
//!
//! A proof of `L` levels has `L − 1` committed levels, each the main protocol of Section 5.2
//! (Figure 2) proving the previous level's verification equations (Figure 3) about its opening
//! `(z⁽⁰⁾, z⁽¹⁾, t̂, ĝ, ĥ)`, recursed as in Section 5.3, and a last level that sends its `t`,
//! `g`, `h` and `z` in the clear and is checked directly (Section 5.6, see `level.rs`).
//!
//! No zero knowledge is needed at this layer: `z₁` and `z₂` are what the LNP prover would send
//! in the clear anyway (the paper's protocol is not zero-knowledge either, Section 1).
//!
//! # Soundness
//!
//! One level is a knowledge-sound proof for the principal relation (Theorem 5.1) whose
//! extractor returns a witness of norm at most `S·β`, `S = √(337/30)` here (`params.rs`
//! explains why not the paper's `√(128/30)`). Its knowledge error, read off the proof in
//! Appendix B with the challenge-set size `|C|` in place of the `2^{128}` the paper assumes, is
//!
//! `ε₀ = 2^{−128} + q^{−⌈128/⌊log₂ q⌋⌉} + q^{−d/2} + 2/|C|`:
//!
//! Lemma 4.2's failure probability for the projection; a wrong projection surviving the
//! `⌈128/log q⌉` constant-coefficient checks; a false aggregated constraint surviving the
//! random `α`, `β` modulo one of the two degree-`d/2` prime ideals; and a non-zero quadratic in
//! one challenge `cᵢ` vanishing, which also bounds the heavy-row extraction's `ε/2 > 1/|C|`.
//! At the toy modulus (`⌊log₂ q⌋ = 59`) the middle terms are about `2^{−177}` and
//! `2^{−1900}`. With `|C| ≈ 2^{129.9}` (`challenge.rs`; the test there certifies
//! `|C| ≥ 2^{128}`), `ε₀ ≈ 2^{−127.4}`, and at most `2^{−126.4}` on the certified bound alone.
//! The paper states `ε₀ = 2^{−125}` for its own set, whose size after rejection is only about
//! `2^{125.6}`.
//!
//! Composing levels adds their errors (Lemma 3.7), so a proof of `L` levels has knowledge
//! error `L·ε₀`: about `2^{−127.4}`, `2^{−126.4}`, `2^{−125.8}` for one, two and three levels
//! and `2^{−124.4}` for the most the crate allows, [`CompressionLevels::MAX`] = 8 (at most
//! `2^{−126.4}`, `2^{−125.4}`, `2^{−124.8}`, `2^{−123.4}` on the certified bound). This is the
//! LaBRADOR layer's error only; the LNP proof it compresses has its own.
//!
//! Two inputs to concrete security are cited, not derived here:
//!
//! * Fiat–Shamir. Theorem 5.1 is a statement about the interactive protocol. The proof here is
//!   non-interactive over a merlin transcript with four challenge rounds per level (`level.rs`),
//!   and its security in the random-oracle model is not derived: ePrint 2025/1099 (Appendix
//!   D.3) defers it to the work titled "Aggregating falcon signatures with labrador" (CRYPTO
//!   2024), which it cites, and so does this crate. A generic bound for a multi-round
//!   Fiat–Shamir transform with up to eight levels would lose well below 128 bits even with
//!   `|C| ≥ 2^{128}`.
//! * Module-SIS. Every rank is chosen by a root-Hermite-factor rule (`1.0044`, `params.rs`),
//!   not by the Core-SVP estimate with the BDGL sieve that the paper uses for its 128-bit
//!   target (Section 6.1). The two have not been shown to agree at these ranks and moduli.

mod challenge;
mod compressed;
mod decompose;
mod key;
mod level;
mod lnp;
mod params;
mod relation;

pub use compressed::{CompressedMembershipProof, CompressionLevels};
pub(crate) use compressed::{Compression, compress, key_seed};
pub(crate) use params::projection_slack_squared;

use crate::{
    error::{Error, Result},
    proof::protocol::Decoder,
    ring::Ring,
    sample::Seed,
    vector::PolyVec,
};
use level::{Context, LevelMessages, LevelRelation};
use merlin::Transcript;
use params::Kind;
use relation::{PrincipalRelation, is_satisfied};
use serde::{Deserialize, Serialize};

/// The messages of every level, the last being the tail, and the tail's `z`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LabradorProof {
    /// The levels in order.
    pub(crate) levels: Vec<LevelMessages>,
    /// The tail's amortised opening `z`.
    pub(crate) z: PolyVec,
}

impl LabradorProof {
    /// Appends the encoding: the number of levels as a `u64`, then for each level its
    /// commitment, the length of `p` as a `u64` and `p` as little-endian `i64`, its lifts and
    /// its garbage, each vector self-describing; then `z`.
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.levels.len() as u64).to_le_bytes());
        for level in &self.levels {
            out.extend_from_slice(&Vec::from(&level.commitment));
            out.extend_from_slice(&(level.projection.len() as u64).to_le_bytes());
            for p in &level.projection {
                out.extend_from_slice(&p.to_le_bytes());
            }
            out.extend_from_slice(&Vec::from(&level.lifts));
            out.extend_from_slice(&Vec::from(&level.garbage));
        }
        out.extend_from_slice(&Vec::from(&self.z));
    }

    /// Reads the encoding of [`LabradorProof::write`].
    pub(crate) fn read(decoder: &mut Decoder<'_>) -> Result<Self> {
        let count = decoder.length()?;
        let levels = (0..count)
            .map(|_| {
                let commitment = decoder.vector()?;
                let len = decoder.length()?;
                let projection = (0..len)
                    .map(|_| decoder.word().map(u64::cast_signed))
                    .collect::<Result<_>>()?;
                Ok(LevelMessages {
                    commitment,
                    projection,
                    lifts: decoder.vector()?,
                    garbage: decoder.vector()?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            levels,
            z: decoder.vector()?,
        })
    }
}

/// The public inputs every level shares.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Setup<'a> {
    /// The seed the levels' commitment keys derive from.
    pub(crate) seed: &'a Seed,
    /// The ring.
    pub(crate) ring: &'a Ring,
}

/// Proves that `witness` satisfies `relation` with `levels` levels. Fails with
/// [`Error::RelationUnsatisfied`] when it does not.
pub(crate) fn prove(
    relation: &dyn PrincipalRelation,
    witness: PolyVec,
    setup: &Setup<'_>,
    levels: CompressionLevels,
    transcript: &mut Transcript,
) -> Result<LabradorProof> {
    if !is_satisfied(relation, &witness, setup.ring)? {
        return Err(Error::RelationUnsatisfied);
    }
    prove_unchecked(relation, witness, setup, levels, transcript)
}

/// [`prove`] without the check that the witness satisfies the relation, so that tests can show
/// the verifier rejecting a false statement.
pub(crate) fn prove_unchecked(
    relation: &dyn PrincipalRelation,
    witness: PolyVec,
    setup: &Setup<'_>,
    levels: CompressionLevels,
    transcript: &mut Transcript,
) -> Result<LabradorProof> {
    let count = usize::from(levels.get());
    absorb_count(transcript, count);
    let mut messages = Vec::with_capacity(count);
    let mut next: Option<LevelRelation> = None;
    let mut witness = witness;
    for index in 0..count {
        let current: &dyn PrincipalRelation = match &next {
            Some(level) => level,
            None => relation,
        };
        let proved = level::prove(current, &witness, &context(index, count, setup), transcript)?;
        messages.push(proved.messages);
        witness = proved.opening;
        next = Some(proved.relation);
    }
    Ok(LabradorProof {
        levels: messages,
        z: witness,
    })
}

/// Verifies a proof made by [`prove`] for `relation` with a transcript in the same state as the
/// prover's. Fails with [`Error::ProofRejected`] when any level's check fails.
pub(crate) fn verify(
    relation: &dyn PrincipalRelation,
    proof: &LabradorProof,
    setup: &Setup<'_>,
    transcript: &mut Transcript,
) -> Result<()> {
    let count = proof.levels.len();
    if count == 0 || count > usize::from(CompressionLevels::MAX) {
        return Err(Error::ProofRejected);
    }
    absorb_count(transcript, count);
    let mut next: Option<LevelRelation> = None;
    for (index, messages) in proof.levels.iter().enumerate() {
        let current: &dyn PrincipalRelation = match &next {
            Some(level) => level,
            None => relation,
        };
        next = Some(level::verify(
            current,
            messages,
            &context(index, count, setup),
            transcript,
        )?);
    }
    match (next, proof.levels.last()) {
        (Some(tail), Some(messages)) => tail.check_tail(&proof.z, messages, setup.ring),
        _ => Err(Error::ProofRejected),
    }
}

/// Binds the transcript to the number of levels, which fixes which level is the tail.
///
/// Difference: the paper fixes the recursion schedule per instance (Section 6.1, Table 3);
/// here the prover chooses `1..=CompressionLevels::MAX` levels and the count is absorbed
/// before the first level, so every challenge depends on it.
fn absorb_count(transcript: &mut Transcript, count: usize) {
    transcript.append_message(b"labrador levels", &(count as u64).to_le_bytes());
}

/// Level `index` of `count`: committed, except the last.
fn context<'a>(index: usize, count: usize, setup: &Setup<'a>) -> Context<'a> {
    Context {
        kind: if index + 1 == count {
            Kind::Tail
        } else {
            Kind::Committed
        },
        index,
        seed: setup.seed,
        ring: setup.ring,
    }
}

#[cfg(test)]
mod tests {
    //! Tests of the LaBRADOR layer on its own, on small random satisfiable instances of the
    //! principal relation, and of the translation of D.12 into a principal relation.

    use super::{
        CompressionLevels, LabradorProof, Setup,
        decompose::{decompose, digit_weights},
        level::{self, Context},
        lnp::{LnpInputs, LnpRelation, witness},
        params::{Digits, Kind, LevelParams},
        prove, prove_unchecked,
        relation::{Combination, PrincipalRelation, Quadratic, Wide, is_satisfied},
        verify,
    };
    use crate::{
        accumulator::{Accumulator, Element},
        error::{Error, Result},
        key::{PublicKey, SecretKey},
        matrix::Shape,
        poly::Poly,
        proof::{
            Challenge, LinkingRelation, MembershipSecret, MembershipStatement, ProofParams,
            ProofSetup,
            abdlop::CommitmentKey,
            coeffs::{from_integers, transform},
            params::LnpParameters,
            protocol::{Committed, MembershipProof, replay},
        },
        ring::Ring,
        sample::{DomainLabel, Seed, UniformSampler},
        state::ManagerState,
        test_util::TOY,
        vector::PolyVec,
        witness::MembershipWitness,
        zq::Coeff,
    };
    use merlin::Transcript;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::{
        sync::{Arc, LazyLock},
        time::Instant,
    };

    /// A relation given constraint by constraint.
    #[derive(Clone, Debug)]
    struct Explicit {
        blocks: Vec<usize>,
        beta_squared: Wide,
        full: Vec<Combination>,
        constant: Vec<Combination>,
    }

    impl PrincipalRelation for Explicit {
        fn blocks(&self) -> &[usize] {
            &self.blocks
        }

        fn norm_bound_squared(&self) -> &Wide {
            &self.beta_squared
        }

        fn full_constraints(&self) -> usize {
            self.full.len()
        }

        fn residuals(&self, witness: &PolyVec, ring: &Ring) -> Result<Vec<Poly>> {
            let s = transform(witness.as_slice(), ring)?;
            self.full
                .iter()
                .map(|f| f.evaluate(&self.blocks, &s, ring))
                .collect()
        }

        fn combine(&self, weights: &[Poly], ring: &Ring) -> Result<Combination> {
            let mut out = Combination::zero(self.blocks.iter().sum(), ring);
            for (f, w) in self.full.iter().zip(weights) {
                out.add_scaled(f, w, ring)?;
            }
            Ok(out)
        }

        fn constants_vanish(&self, witness: &PolyVec, ring: &Ring) -> Result<bool> {
            let s = transform(witness.as_slice(), ring)?;
            for f in &self.constant {
                if f.evaluate(&self.blocks, &s, ring)?.coefficients()[0] != Coeff::ZERO {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        fn combine_constants(
            &self,
            sampler: &mut UniformSampler,
            ring: &Ring,
        ) -> Result<Option<Combination>> {
            if self.constant.is_empty() {
                return Ok(None);
            }
            let psi = sampler.poly(ring);
            let mut out = Combination::zero(self.blocks.iter().sum(), ring);
            for (f, psi) in self.constant.iter().zip(psi.coefficients()) {
                out.add_scaled(f, &Poly::scale(&Poly::constant(1, ring), psi, ring), ring)?;
            }
            Ok(Some(out))
        }
    }

    /// A constraint with uniform coefficients whose value at `s` is `target` plus its own value
    /// moved into `b`, so that `f(s) = target`.
    fn constraint(
        sampler: &mut UniformSampler,
        s: &PolyVec,
        blocks: &[usize],
        target: &Poly,
    ) -> Combination {
        let ring = TOY.ring();
        let mut f = Combination {
            quadratic: vec![
                Quadratic {
                    left: 0,
                    right: 1,
                    weight: sampler.poly(ring),
                },
                Quadratic {
                    left: 2,
                    right: 2,
                    weight: sampler.poly(ring),
                },
            ],
            linear: sampler.vector(s.len(), ring).into(),
            constant: Poly::zero(ring),
        };
        let value = f
            .evaluate(blocks, &transform(s.as_slice(), ring).unwrap(), ring)
            .unwrap();
        f.constant = value.sub(target, ring).unwrap();
        f
    }

    /// A satisfiable instance: three blocks, three full constraints, two constant-coefficient
    /// constraints whose values at the witness have non-zero higher coefficients, and the bound
    /// `β² = ‖s‖²`.
    fn instance(seed: u64) -> (Explicit, PolyVec) {
        let ring = TOY.ring();
        let blocks = vec![6, 6, 9];
        let mut rng = StdRng::seed_from_u64(seed);
        let total: usize = blocks.iter().sum();
        let values: Vec<i64> = (0..total * ring.degree())
            .map(|_| rng.random_range(-50..=50))
            .collect();
        let s = from_integers(&values, ring).unwrap();
        let mut sampler = UniformSampler::new(
            &Seed::from([seed as u8; 32]),
            DomainLabel::from(&b"labrador/test"[..]),
        );
        let zero = Poly::zero(ring);
        let full = (0..3)
            .map(|_| constraint(&mut sampler, &s, &blocks, &zero))
            .collect();
        let constant = (0..2)
            .map(|_| {
                let mut target = sampler.poly(ring).coefficients().to_vec();
                target[0] = Coeff::ZERO;
                constraint(&mut sampler, &s, &blocks, &Poly::from_reduced(target))
            })
            .collect();
        let beta_squared = s.norm_l2_squared(ring);
        (
            Explicit {
                blocks,
                beta_squared,
                full,
                constant,
            },
            s,
        )
    }

    const LABEL: &[u8] = b"labrador unit test";
    static SEED: LazyLock<Seed> = LazyLock::new(|| Seed::from([3; 32]));

    fn setup() -> Setup<'static> {
        Setup {
            seed: &SEED,
            ring: TOY.ring(),
        }
    }

    fn levels(n: u8) -> CompressionLevels {
        CompressionLevels::try_from(n).unwrap()
    }

    fn verify_fresh(relation: &dyn PrincipalRelation, proof: &LabradorProof) -> Result<()> {
        verify(relation, proof, &setup(), &mut Transcript::new(LABEL))
    }

    fn prove_fresh(relation: &dyn PrincipalRelation, s: &PolyVec, n: u8) -> Result<LabradorProof> {
        prove(
            relation,
            s.clone(),
            &setup(),
            levels(n),
            &mut Transcript::new(LABEL),
        )
    }

    /// Honest proofs of one, two and three levels verify, and only with the prover's transcript.
    #[test]
    fn honest_proofs_verify() {
        let (relation, s) = instance(1);
        let ring = TOY.ring();
        assert!(is_satisfied(&relation, &s, ring).unwrap());
        for n in 1..=3 {
            let start = Instant::now();
            let proof = prove_fresh(&relation, &s, n).unwrap();
            let proved = start.elapsed();
            verify_fresh(&relation, &proof).unwrap();
            println!(
                "{n} level(s): prove {proved:?}, prove+verify {:?}, levels {}",
                start.elapsed(),
                proof.levels.len()
            );
            assert_eq!(
                verify(&relation, &proof, &setup(), &mut Transcript::new(b"other")),
                Err(Error::ProofRejected)
            );
        }
    }

    /// `p` with one added to entry `index mod len`, for any vector.
    fn bump(v: &PolyVec, index: usize, coefficient: usize) -> PolyVec {
        let ring = TOY.ring();
        let mut entries: Vec<Poly> = v.clone().into();
        let i = index % entries.len();
        let mut c = entries[i].coefficients().to_vec();
        c[coefficient] = ring.zq().add(&c[coefficient], &Coeff::ONE);
        entries[i] = Poly::from_reduced(c);
        entries.into()
    }

    /// Every single message of a two-level proof, altered, is rejected: each level's commitment,
    /// projection, lifts (in a higher coefficient and in the constant one) and garbage, and `z`.
    #[test]
    fn every_altered_message_is_rejected() {
        let (relation, s) = instance(2);
        let proof = prove_fresh(&relation, &s, 2).unwrap();
        verify_fresh(&relation, &proof).unwrap();
        let mut cases: Vec<(String, LabradorProof)> = Vec::new();
        for level in 0..proof.levels.len() {
            let mut alter = |name: &str, f: &dyn Fn(&mut LabradorProof)| {
                let mut altered = proof.clone();
                f(&mut altered);
                cases.push((format!("level {level} {name}"), altered));
            };
            alter("commitment", &|p| {
                p.levels[level].commitment = bump(&p.levels[level].commitment, 1, 3);
            });
            alter("projection", &|p| p.levels[level].projection[7] += 1);
            alter("lift", &|p| {
                p.levels[level].lifts = bump(&p.levels[level].lifts, 0, 5)
            });
            alter("lift constant", &|p| {
                p.levels[level].lifts = bump(&p.levels[level].lifts, 1, 0);
            });
            alter("garbage", &|p| {
                p.levels[level].garbage = bump(&p.levels[level].garbage, 2, 1)
            });
        }
        let mut altered = proof.clone();
        altered.z = bump(&altered.z, 3, 2);
        cases.push(("z".into(), altered));
        for (name, altered) in cases {
            assert_ne!(altered, proof, "{name}");
            assert_eq!(
                verify_fresh(&relation, &altered),
                Err(Error::ProofRejected),
                "{name}"
            );
        }
    }

    /// A witness violating one full constraint, or one constant-coefficient constraint, is refused
    /// by the prover; forced through the unchecked prover, its proof is rejected by the verifier,
    /// with one level and with two.
    #[test]
    fn violated_constraints_are_rejected() {
        let ring = TOY.ring();
        let (honest, s) = instance(3);
        let mut full = honest.clone();
        full.full[1].constant = full.full[1]
            .constant
            .add(&Poly::constant(1, ring), ring)
            .unwrap();
        let mut constant = honest.clone();
        constant.constant[0].constant = constant.constant[0]
            .constant
            .add(&Poly::constant(1, ring), ring)
            .unwrap();
        for (name, relation) in [("full", &full), ("constant", &constant)] {
            assert!(!is_satisfied(relation, &s, ring).unwrap(), "{name}");
            assert_eq!(
                prove_fresh(relation, &s, 1).map(|_| ()),
                Err(Error::RelationUnsatisfied)
            );
            for n in 1..=2 {
                let forced = prove_unchecked(
                    relation,
                    s.clone(),
                    &setup(),
                    levels(n),
                    &mut Transcript::new(LABEL),
                )
                .unwrap();
                assert_eq!(
                    verify_fresh(relation, &forced),
                    Err(Error::ProofRejected),
                    "{name}, {n}"
                );
            }
        }
    }

    /// A witness above the norm bound is refused by the prover, and a proof made for the honest
    /// bound is rejected against a bound four times smaller: the projection `p` of the honest
    /// witness exceeds `337·β²` for that bound.
    #[test]
    fn norm_above_the_bound_is_rejected() {
        let ring = TOY.ring();
        let (honest, s) = instance(4);
        let mut tight = honest.clone();
        tight.beta_squared = honest.beta_squared.shr_vartime(4);
        assert!(!is_satisfied(&tight, &s, ring).unwrap());
        assert_eq!(
            prove_fresh(&tight, &s, 1).map(|_| ()),
            Err(Error::RelationUnsatisfied)
        );
        let proof = prove_fresh(&honest, &s, 1).unwrap();
        let norm: u128 = proof.levels[0]
            .projection
            .iter()
            .map(|&p| u128::from(p.unsigned_abs()).pow(2))
            .sum();
        let bound = u128::from(tight.beta_squared.as_words()[0]) * 337;
        assert!(norm > bound, "{norm} ≤ {bound}");
        assert_eq!(verify_fresh(&tight, &proof), Err(Error::ProofRejected));
    }

    /// The relation of a committed level's opening holds for the honest opening, within its bound
    /// `β'²`, and its combination with any weights equals the weighted sum of its residuals at any
    /// witness, so that the next level proves exactly the checks [`level::verify`] describes.
    #[test]
    fn level_relation_combines_its_residuals() {
        let ring = TOY.ring();
        let (relation, s) = instance(5);
        let context = Context {
            kind: Kind::Committed,
            index: 0,
            seed: &SEED,
            ring,
        };
        let proved = level::prove(&relation, &s, &context, &mut Transcript::new(LABEL)).unwrap();
        let next = &proved.relation;
        assert!(is_satisfied(next, &proved.opening, ring).unwrap());
        println!(
            "opening: {} polynomials, ‖·‖² = 2^{}, β'² = 2^{}",
            proved.opening.len(),
            proved.opening.norm_l2_squared(ring).bit_width_vartime(),
            next.norm_bound_squared().bit_width_vartime()
        );
        combination_matches_residuals(next, &proved.opening, 6);
    }

    /// `combine(w)` at a uniform witness with the opening's shape equals `Σ w_k·f_k` there.
    fn combination_matches_residuals(relation: &dyn PrincipalRelation, shape: &PolyVec, seed: u8) {
        let ring = TOY.ring();
        let mut sampler = UniformSampler::new(
            &Seed::from([seed; 32]),
            DomainLabel::from(&b"labrador/test/combine"[..]),
        );
        let w = sampler.vector(shape.len(), ring);
        let weights = sampler.vector(relation.full_constraints(), ring);
        let combined = relation.combine(weights.as_slice(), ring).unwrap();
        let value = combined
            .evaluate(
                relation.blocks(),
                &transform(w.as_slice(), ring).unwrap(),
                ring,
            )
            .unwrap();
        let expected = relation
            .residuals(&w, ring)
            .unwrap()
            .iter()
            .zip(weights.as_slice())
            .fold(Poly::zero(ring), |acc, (f, w)| {
                acc.add(&w.mul(f, ring).unwrap(), ring).unwrap()
            });
        assert_eq!(value, expected);
    }

    /// Centred digits recompose to the polynomial, every lower digit lies in `[−b/2, b/2)`, and
    /// one digit returns the polynomial itself.
    #[test]
    fn decomposition_round_trips() {
        let ring = TOY.ring();
        let mut sampler = UniformSampler::new(
            &Seed::from([8; 32]),
            DomainLabel::from(&b"labrador/test/digits"[..]),
        );
        for digits in [
            Digits { parts: 5, bits: 12 },
            Digits { parts: 2, bits: 13 },
            Digits { parts: 1, bits: 60 },
        ] {
            let weights = digit_weights(digits, ring);
            for _ in 0..8 {
                let p = sampler.poly(ring);
                let parts = decompose(&p, digits, ring).unwrap();
                assert_eq!(parts.len(), digits.parts);
                let back = parts
                    .iter()
                    .zip(&weights)
                    .fold(Poly::zero(ring), |acc, (d, w)| {
                        acc.add(&Poly::scale(d, w, ring), ring).unwrap()
                    });
                assert_eq!(back, p);
                let half = Coeff::ONE.shl_vartime(digits.bits.saturating_sub(1));
                for part in &parts[..digits.parts - 1] {
                    assert!(part.norm_inf(ring) <= half);
                }
            }
        }
    }

    /// The parameters of every level of the membership proof's chains of one, two and three levels
    /// at the toy set, with the conditions on the modulus they rest on. Each chain's last level is
    /// smaller than the previous chain's.
    #[test]
    fn parameters_at_the_toy_set() {
        let ring = TOY.ring();
        // Invertibility of challenge differences (`2·4² < q`) is checked by `LevelParams::derive`.
        let lnp = LnpParameters::new(&TOY, 2).unwrap();
        let witness = lnp.witness_len * lnp.digits;
        let first_blocks = vec![2, 2, witness, witness, lnp.m2];
        let first_bound = lnp
            .beta_squared(0)
            .wrapping_add(lnp.beta_squared(0))
            .wrapping_add(lnp.beta_squared(1));
        let mut previous = lnp.m1 + lnp.m2;
        for count in 1..=3 {
            let (mut blocks, mut bound) = (first_blocks.clone(), first_bound);
            let mut sent = 0;
            for index in 0..count {
                let kind = if index + 1 == count {
                    Kind::Tail
                } else {
                    Kind::Committed
                };
                let params = LevelParams::derive(&blocks, &bound, kind, ring).unwrap();
                println!(
                    "chain of {count}, level {}: {kind:?}, r = {}, n = {}, κ = {}, κ₁ = {}, \
                     z digits {:?}, digits {:?}, lifts {}, β² = 2^{}, γ² = 2^{}, β'² = 2^{}, \
                     opening {:?}",
                    index + 1,
                    params.r(),
                    params.width,
                    params.kappa,
                    params.outer_rank,
                    params.z_digits,
                    params.digits,
                    params.lifts,
                    params.beta_squared.bit_width_vartime(),
                    params.gamma_squared.bit_width_vartime(),
                    params.next_beta_squared.bit_width_vartime(),
                    params.opening_blocks()
                );
                assert_eq!(params.lifts, 3);
                sent += 2 * params.outer_rank + params.lifts;
                blocks = params.opening_blocks();
                bound = params.next_beta_squared;
            }
            let total = sent + blocks.iter().sum::<usize>();
            println!("chain of {count}: {total} polynomials sent besides the LNP messages");
            assert!(total < previous, "{count}: {total} ≥ {previous}");
            previous = total;
        }
    }

    /// A toy accumulator with a member, the linking relation, and one honest LNP proof.
    struct LnpFixture {
        pk: PublicKey,
        accumulator: Accumulator,
        relation: LinkingRelation,
        params: ProofParams,
        proof: MembershipProof,
        challenge: Challenge,
    }

    static LNP: LazyLock<LnpFixture> = LazyLock::new(|| {
        let ring = TOY.ring();
        let mut rng = StdRng::seed_from_u64(17);
        let key = SecretKey::new(
            Some(b"labrador/unit, a 32-byte test seed"),
            Arc::new(TOY.clone()),
            &mut rng,
        )
        .unwrap();
        let pk = PublicKey::from(&key);
        let mut accumulator = Accumulator::new(&key);
        let mut state = ManagerState::new(&key);
        let x = Element::try_from([0x69u8].as_slice()).unwrap();
        accumulator
            .add_elements_assign(&key, std::slice::from_ref(&x), &mut state)
            .unwrap();
        let witness = MembershipWitness::new(&x, &accumulator, &key, &state).unwrap();
        let bits: PolyVec = x
            .to_bits(&TOY)
            .unwrap()
            .as_slice()
            .iter()
            .map(|&b| Poly::constant(i64::from(b), ring))
            .collect();
        let r = from_integers(
            &(0..2 * ring.degree())
                .map(|i| (i % 3 % 2) as i64)
                .collect::<Vec<_>>(),
            ring,
        )
        .unwrap();
        let mut sampler = UniformSampler::new(
            &Seed::from([4; 32]),
            DomainLabel::from(&b"labrador/link"[..]),
        );
        let a1 = sampler.matrix(
            Shape {
                rows: 2,
                cols: bits.len(),
            },
            ring,
        );
        let a2 = sampler.matrix(Shape { rows: 2, cols: 2 }, ring);
        let t = a1
            .mul_vec(&bits, ring)
            .unwrap()
            .add(&a2.mul_vec(&r, ring).unwrap(), ring)
            .unwrap();
        let relation = LinkingRelation::new(a1, a2, t).unwrap();
        let params = ProofParams::new(&pk, Some(b"labrador")).unwrap();
        let statement = MembershipStatement {
            pubkey: &pk,
            accumulator: &accumulator,
            relation: &relation,
        };
        let secret = MembershipSecret {
            element: &x,
            witness: &witness,
            r: &r,
        };
        let challenge = Challenge::from([6; 64]);
        let setup = ProofSetup::new(&pk, &params, &relation).unwrap();
        let proof = Committed::new(&statement, &secret, &params, &setup, &mut rng)
            .unwrap()
            .respond(&challenge)
            .unwrap();
        LnpFixture {
            pk,
            accumulator,
            relation,
            params,
            proof,
            challenge,
        }
    });

    /// The LNP responses satisfy the principal relation of D.3, the relation's combination with
    /// any weights equals the weighted residuals of the verifier's own equations at any witness
    /// whose copies are `σ` of their originals, and the copies are what the constant-coefficient
    /// family checks.
    #[test]
    fn lnp_relation_is_the_verifier_equations() {
        let f = &*LNP;
        let ring = TOY.ring();
        let statement = MembershipStatement {
            pubkey: &f.pk,
            accumulator: &f.accumulator,
            relation: &f.relation,
        };
        let lnp = LnpParameters::new(&TOY, 2).unwrap();
        let digest = statement.digest(&f.params);
        let messages = f.proof.messages();
        let challenges = replay(&messages, &statement, &digest, &lnp, &f.challenge).unwrap();
        let relation = challenges.relation(&statement, &lnp, messages.h).unwrap();
        let key = CommitmentKey::expand(&f.params.seed(), &lnp, ring).unwrap();
        let (z_x, honest) = witness(f.proof.z1(), f.proof.z2(), &lnp, ring).unwrap();
        let lnp_relation = LnpRelation::new(LnpInputs {
            key: &key,
            relation: &relation,
            lnp: &lnp,
            messages,
            z_x: &z_x,
            c: &challenges.c,
        })
        .unwrap();
        assert!(is_satisfied(&lnp_relation, &honest, ring).unwrap());

        // A uniform witness with consistent copies.
        let mut sampler = UniformSampler::new(
            &Seed::from([9; 32]),
            DomainLabel::from(&b"labrador/test/lnp"[..]),
        );
        let z1: PolyVec = z_x
            .as_slice()
            .iter()
            .cloned()
            .chain(
                sampler
                    .vector(lnp.m1 - lnp.element_bits, ring)
                    .as_slice()
                    .iter()
                    .cloned(),
            )
            .collect();
        let z2 = sampler.vector(lnp.m2, ring);
        let (_, uniform) = witness(&z1, &z2, &lnp, ring).unwrap();
        assert!(lnp_relation.constants_vanish(&uniform, ring).unwrap());
        let weights = sampler.vector(lnp_relation.full_constraints(), ring);
        let combined = lnp_relation.combine(weights.as_slice(), ring).unwrap();
        let w_ntt = transform(uniform.as_slice(), ring).unwrap();
        let value = combined
            .evaluate(lnp_relation.blocks(), &w_ntt, ring)
            .unwrap();
        let expected = lnp_relation
            .residuals(&uniform, ring)
            .unwrap()
            .iter()
            .zip(weights.as_slice())
            .fold(Poly::zero(ring), |acc, (r, w)| {
                acc.add(&w.mul(r, ring).unwrap(), ring).unwrap()
            });
        assert_eq!(value, expected);

        // The constant-coefficient combination vanishes in the constant term exactly when the
        // copies are consistent.
        let constant = |w: &PolyVec, seed: u8| {
            let mut sampler =
                UniformSampler::new(&Seed::from([seed; 32]), DomainLabel::from(&b"psi"[..]));
            let f = lnp_relation
                .combine_constants(&mut sampler, ring)
                .unwrap()
                .unwrap();
            f.evaluate(
                lnp_relation.blocks(),
                &transform(w.as_slice(), ring).unwrap(),
                ring,
            )
            .unwrap()
            .coefficients()[0]
        };
        assert_eq!(constant(&uniform, 1), Coeff::ZERO);
        let broken = bump(&uniform, 2 + 7, 11);
        assert!(!lnp_relation.constants_vanish(&broken, ring).unwrap());
        assert_ne!(constant(&broken, 1), Coeff::ZERO);
    }
}
