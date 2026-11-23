// SPDX-License-Identifier: MIT OR Apache-2.0
//! The LaBRADOR-compressed membership proof of Appendix D.3: an honest compressed proof
//! verifies (C39), the statement-tampering cases of C36 still reject, any altered message of
//! the compressed proof rejects at every level (C39, C46), and compressed proofs are smaller
//! than the uncompressed one (C40). One LNP response is made, by a committing step with a
//! prepared setup, and compressed with one, two and three levels, the two-level proof with the
//! setup and the others without; every proof is checked both ways, and the prover's own
//! compressing step is checked against the one-level proof once.

use crate::{
    fixture::{LABEL, PREPARED, SETUP, rng, statement},
    serde_formats::round_trips,
};
use kln_accumulator::lattice::{Coeff, Poly, PolyMatrix, PolyVec};
use kln_accumulator::{
    Challenge, CompressedMembershipProof, CompressionLevels, Error, LinkingRelation,
    MembershipProof, MembershipProofCommitting, MembershipSecret, MembershipStatement, ProofParams,
};
use merlin::Transcript;
use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

/// An uncompressed proof for the fixture's statement and its compressions.
struct Compressed {
    committing: MembershipProofCommitting,
    challenge: Challenge,
    uncompressed: MembershipProof,
    /// The proofs with one, two and three levels, and how long each compression took.
    proofs: Vec<(CompressedMembershipProof, Duration)>,
}

/// The outer transcript of the three-step API.
fn outer() -> Transcript {
    let mut transcript = Transcript::new(LABEL);
    SETUP.params.add_to_transcript(&mut transcript);
    transcript
}

static COMPRESSED: LazyLock<Compressed> = LazyLock::new(|| {
    let setup = &*SETUP;
    let committing = MembershipProofCommitting::new_with(
        &MembershipSecret {
            element: &setup.x,
            witness: &setup.witness,
            r: &setup.r,
        },
        &setup.params,
        &PREPARED,
        &statement(),
        &mut rng(4),
    )
    .expect("test fixture");
    let mut transcript = outer();
    committing.get_bytes_for_challenge(&mut transcript);
    let challenge = Challenge::from_transcript(b"challenge", &mut transcript);
    let start = Instant::now();
    let uncompressed = committing.gen_proof(&challenge).expect("test fixture");
    eprintln!("uncompressed proof: {:?}", start.elapsed());
    let proofs = (1..=3)
        .map(|n| {
            let start = Instant::now();
            let proof = if n == 2 {
                uncompressed.compress_with(
                    &statement(),
                    &setup.params,
                    &PREPARED,
                    &challenge,
                    levels(n),
                )
            } else {
                uncompressed.compress(&statement(), &setup.params, &challenge, levels(n))
            }
            .expect("test fixture");
            (proof, start.elapsed())
        })
        .collect();
    Compressed {
        committing,
        challenge,
        uncompressed,
        proofs,
    }
});

fn levels(n: u8) -> CompressionLevels {
    CompressionLevels::try_from(n).expect("test fixture")
}

/// The proof with `n` levels.
pub fn proof(n: usize) -> &'static CompressedMembershipProof {
    &COMPRESSED.proofs[n - 1].0
}

/// Verifies `proof` against `statement` under `params` for the fixture's challenge.
fn check(
    proof: &CompressedMembershipProof,
    statement: &MembershipStatement<'_>,
    params: &ProofParams,
    challenge: &Challenge,
) -> Result<(), Error> {
    proof
        .finalize(
            statement.accumulator,
            params,
            statement.pubkey,
            challenge,
            statement.relation,
        )
        .map(|_| ())
}

/// The most verifications run at once; each expands the commitment keys, about 200 MB.
const THREADS: usize = 4;

/// Runs `checks` on up to [`THREADS`] threads at a time and returns their results in order.
fn in_parallel<T: Send>(checks: Vec<Box<dyn Fn() -> T + Send + Sync + '_>>) -> Vec<T> {
    checks
        .chunks(THREADS)
        .flat_map(|batch| {
            std::thread::scope(|scope| {
                let handles: Vec<_> = batch.iter().map(|check| scope.spawn(check)).collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("test thread"))
                    .collect::<Vec<_>>()
            })
        })
        .collect()
}

/// C39: compressed proofs of one, two and three levels verify with and without the prepared
/// setup, give the outer transcript the same bytes as the uncompressed proof, and the prover's
/// compressing step makes the same one-level proof as compressing its uncompressed proof.
#[test]
fn compressed_proofs_verify() {
    let c = &*COMPRESSED;
    let setup = &*SETUP;
    let finalized = c
        .uncompressed
        .finalize(
            &setup.accumulator,
            &setup.params,
            &setup.pk,
            &c.challenge,
            &setup.relation,
        )
        .unwrap();
    assert_eq!(
        c.uncompressed
            .finalize_with(
                &setup.accumulator,
                &setup.params,
                &PREPARED,
                &setup.pk,
                &c.challenge,
                &setup.relation,
            )
            .unwrap(),
        finalized
    );
    for (n, (proof, compressing)) in c.proofs.iter().enumerate() {
        assert_eq!(proof.levels(), n + 1);
        let start = Instant::now();
        let compressed_final = proof
            .finalize(
                &setup.accumulator,
                &setup.params,
                &setup.pk,
                &c.challenge,
                &setup.relation,
            )
            .unwrap();
        eprintln!(
            "{} level(s): compress {compressing:?}, verify {:?}",
            n + 1,
            start.elapsed()
        );
        assert_eq!(compressed_final, finalized);
        let prepared = proof
            .finalize_with(
                &setup.accumulator,
                &setup.params,
                &PREPARED,
                &setup.pk,
                &c.challenge,
                &setup.relation,
            )
            .unwrap();
        assert_eq!(prepared, finalized);
    }
    let start = Instant::now();
    let direct = c
        .committing
        .gen_compressed_proof(&c.challenge, levels(1))
        .unwrap();
    eprintln!("gen_compressed_proof, one level: {:?}", start.elapsed());
    assert_eq!(direct, *proof(1));
}

/// C40: the serialized sizes of the uncompressed and compressed proofs, printed; every
/// compressed proof is smaller than the uncompressed one and each level makes it smaller.
#[test]
fn compressed_proofs_are_smaller() {
    let c = &*COMPRESSED;
    let uncompressed = c.uncompressed.to_bytes().len();
    eprintln!("uncompressed: {uncompressed} bytes");
    let mut previous = uncompressed;
    for (n, (proof, _)) in c.proofs.iter().enumerate() {
        let size = Vec::from(proof).len();
        eprintln!(
            "{} level(s): {size} bytes ({:.2}× smaller)",
            n + 1,
            uncompressed as f64 / size as f64
        );
        assert!(size < previous, "{} levels: {size} ≥ {previous}", n + 1);
        previous = size;
    }
}

/// `v` with one added to coefficient `coefficient` of entry `index mod len`.
fn bump_vec(v: &PolyVec, index: usize, coefficient: usize) -> PolyVec {
    let mut entries: Vec<Poly> = v.clone().into();
    let i = index % entries.len();
    entries[i] = bump(&entries[i], coefficient);
    entries.into()
}

/// `p` with one added to coefficient `coefficient`.
fn bump(p: &Poly, coefficient: usize) -> Poly {
    let ring = SETUP.pk.params().ring();
    let mut coefficients = vec![Coeff::ZERO; ring.degree()];
    coefficients[coefficient] = Coeff::ONE;
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
    entries[0] = bump(&entries[0], 0);
    PolyMatrix::new(shape, entries).expect("test fixture")
}

/// C36 for the compressed proof: another accumulator value, linking relation, public key
/// (with the prover's and with its own proof parameters), outer challenge, or proof parameters
/// is rejected.
#[test]
fn statement_tampering_is_rejected() {
    let setup = &*SETUP;
    let c = &*COMPRESSED;
    let relation = &setup.relation;
    let relations: Vec<LinkingRelation> = [
        LinkingRelation::new(
            relation.a1().clone(),
            relation.a2().clone(),
            bump_vec(relation.t(), 0, 0),
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
    ]
    .into_iter()
    .map(|r| r.expect("test fixture"))
    .collect();
    let other_key_params = ProofParams::new(&setup.other_pk, Some(b"kln/test/entropy")).unwrap();
    let other_params = ProofParams::new(&setup.pk, Some(b"kln/test/other entropy")).unwrap();
    let mut relabelled = Transcript::new(b"kln proof test, another label");
    setup.params.add_to_transcript(&mut relabelled);
    c.committing.get_bytes_for_challenge(&mut relabelled);
    let other_challenge = Challenge::from_transcript(b"challenge", &mut relabelled);
    let proof = proof(1);
    let mut checks: Vec<Box<dyn Fn() -> Result<(), Error> + Send + Sync + '_>> = vec![
        Box::new(|| {
            check(
                proof,
                &MembershipStatement {
                    accumulator: &setup.old_accumulator,
                    ..statement()
                },
                &setup.params,
                &c.challenge,
            )
        }),
        Box::new(|| {
            let other = MembershipStatement {
                pubkey: &setup.other_pk,
                ..statement()
            };
            check(proof, &other, &setup.params, &c.challenge)
        }),
        Box::new(|| {
            let other = MembershipStatement {
                pubkey: &setup.other_pk,
                ..statement()
            };
            check(proof, &other, &other_key_params, &c.challenge)
        }),
        Box::new(|| check(proof, &statement(), &setup.params, &other_challenge)),
        Box::new(|| check(proof, &statement(), &other_params, &c.challenge)),
    ];
    for variant in &relations {
        checks.push(Box::new(move || {
            check(
                proof,
                &MembershipStatement {
                    relation: variant,
                    ..statement()
                },
                &setup.params,
                &c.challenge,
            )
        }));
    }
    for (i, result) in in_parallel(checks).into_iter().enumerate() {
        assert_eq!(result, Err(Error::ProofRejected), "case {i}");
    }
}

/// The two-level proof with the JSON value at each pointer changed: a polynomial's hex string
/// has the low bit of its first byte flipped, a number is incremented. The pointers cover every
/// LNP message, `zₓ`, each level's commitment, projection, lifts and garbage, and the final
/// `z`.
fn alterations() -> Vec<(String, CompressedMembershipProof)> {
    let base = proof(2);
    let json = serde_json::to_value(base).expect("test fixture");
    let mut pointers: Vec<String> = [
        "/t_a/3", "/w/1", "/t_y/2", "/z3/0", "/t_p/1", "/h/0", "/t_quad", "/v", "/z_x/5",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    for level in 0..base.levels() {
        for field in ["commitment/1", "projection/7", "lifts/0", "garbage/2"] {
            pointers.push(format!("/labrador/levels/{level}/{field}"));
        }
    }
    pointers.push("/labrador/z/3".into());
    pointers
        .into_iter()
        .map(|pointer| {
            let mut altered = json.clone();
            let node = altered.pointer_mut(&pointer).expect("test fixture");
            *node = match node.take() {
                serde_json::Value::String(hex) => {
                    let mut bytes = hex::decode(hex).expect("test fixture");
                    bytes[0] ^= 1;
                    serde_json::Value::String(hex::encode(bytes))
                }
                serde_json::Value::Number(n) => {
                    serde_json::Value::from(n.as_i64().expect("test fixture") + 1)
                }
                // Anything else is left as it is, and the inequality below fails.
                other => other,
            };
            let altered: CompressedMembershipProof =
                serde_json::from_value(altered).expect("test fixture");
            assert_ne!(altered, *base, "{pointer}");
            (pointer, altered)
        })
        .collect()
}

/// C39, C46: altering any one message of a two-level compressed proof is rejected.
#[test]
fn altered_messages_are_rejected() {
    let c = &*COMPRESSED;
    let cases = alterations();
    let checks: Vec<Box<dyn Fn() -> Result<(), Error> + Send + Sync + '_>> = cases
        .iter()
        .map(|(_, altered)| {
            Box::new(move || check(altered, &statement(), &SETUP.params, &c.challenge))
                as Box<dyn Fn() -> Result<(), Error> + Send + Sync + '_>
        })
        .collect();
    for ((name, _), result) in cases.iter().zip(in_parallel(checks)) {
        assert_eq!(result, Err(Error::ProofRejected), "{name}");
    }
}

/// The byte encoding round-trips and the decoded proof verifies; truncated and extended
/// encodings are refused; and the proof round-trips in the six serde formats.
#[test]
fn compressed_proof_serializes() {
    let c = &*COMPRESSED;
    let proof = proof(2);
    let bytes = Vec::from(proof);
    let decoded = CompressedMembershipProof::try_from(bytes.as_slice()).unwrap();
    assert_eq!(decoded, *proof);
    check(&decoded, &statement(), &SETUP.params, &c.challenge).unwrap();
    assert!(matches!(
        CompressedMembershipProof::try_from(&bytes[..bytes.len() - 1]),
        Err(Error::InvalidEncodingLength(_))
    ));
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(matches!(
        CompressedMembershipProof::try_from(extended.as_slice()),
        Err(Error::InvalidEncodingLength(_))
    ));
    round_trips("CompressedMembershipProof", proof.clone());
}

/// The number of levels is between one and the maximum.
#[test]
fn levels_are_bounded() {
    assert_eq!(
        CompressionLevels::try_from(0),
        Err(Error::InvalidCompressionLevels(0))
    );
    assert_eq!(
        CompressionLevels::try_from(CompressionLevels::MAX + 1),
        Err(Error::InvalidCompressionLevels(CompressionLevels::MAX + 1))
    );
    assert_eq!(levels(CompressionLevels::MAX).get(), CompressionLevels::MAX);
}
