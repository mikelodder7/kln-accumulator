// SPDX-License-Identifier: MIT OR Apache-2.0
//! Property tests of the decoders that take untrusted input: arbitrary parameter-set encodings,
//! arbitrary byte strings for every `TryFrom<&[u8]>` decoder of a public type, and arbitrary
//! shapes and entries for matrix deserialization. Each call must return, `Ok` or `Err`,
//! without panicking; an accepted matrix must hold exactly `rows · cols` entries.

use kln_accumulator::lattice::{Poly, PolyMatrix, PolyVec, Shape, Trapdoor};
use kln_accumulator::{
    Accumulator, Coefficient, CompressedMembershipProof, Element, MembershipProof,
    MembershipWitness, Params, ParamsSpec, PublicKey, SecretKey, adaptive, succinct,
};
use proptest::{collection::vec, prelude::*};
use serde::Serialize;

/// Bytes per arbitrary input: enough to cover every fixed-size header, far below what any
/// decoder could be made to allocate from them.
const MAX_INPUT: usize = 512;

/// The toy set's encoding, which most decoders read first.
fn toy_spec() -> [u8; ParamsSpec::BYTES] {
    ParamsSpec::TOY.into()
}

/// Runs every public `TryFrom<&[u8]>` decoder on `bytes`; only a panic can fail.
fn decode_all(bytes: &[u8]) {
    let _ = ParamsSpec::try_from(bytes);
    let _ = Poly::try_from(bytes);
    let _ = PolyVec::try_from(bytes);
    let _ = Trapdoor::try_from(bytes);
    let _ = Element::try_from(bytes);
    let _ = Coefficient::try_from(bytes);
    let _ = Accumulator::try_from(bytes);
    let _ = SecretKey::try_from(bytes);
    let _ = PublicKey::try_from(bytes);
    let _ = MembershipWitness::try_from(bytes);
    let _ = adaptive::Element::try_from(bytes);
    let _ = adaptive::Accumulator::try_from(bytes);
    let _ = adaptive::SecretKey::try_from(bytes);
    let _ = adaptive::PublicKey::try_from(bytes);
    let _ = adaptive::MembershipWitness::try_from(bytes);
    let _ = succinct::SecretKey::try_from(bytes);
    let _ = succinct::PublicKey::try_from(bytes);
    let _ = succinct::MembershipWitness::try_from(bytes);
    let _ = MembershipProof::try_from(bytes);
    let _ = CompressedMembershipProof::try_from(bytes);
}

/// The serialized form of a [`PolyMatrix`], with a shape and entries chosen independently.
#[derive(Serialize)]
struct MatrixInput {
    shape: Shape,
    entries: Vec<Poly>,
}

/// A dimension: mostly small, sometimes anything, so that both a matching count and an
/// overflowing product are reached.
fn dimension() -> impl Strategy<Value = usize> {
    prop_oneof![3 => 0usize..4, 1 => any::<usize>()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any 64 bytes, and the toy set's encoding with up to four bytes replaced, decode to a
    /// spec or an error, and a decoded spec builds a set or an error.
    #[test]
    fn parameter_specs_never_panic(
        random in vec(any::<u8>(), ParamsSpec::BYTES),
        edits in vec((0..ParamsSpec::BYTES, any::<u8>()), 0..=4),
    ) {
        let mut edited = toy_spec();
        for (index, byte) in edits {
            edited[index] = byte;
        }
        for bytes in [random.as_slice(), edited.as_slice()] {
            if let Ok(spec) = ParamsSpec::try_from(bytes) {
                let _ = Params::try_from(spec);
            }
        }
    }

    /// Every byte decoder returns on arbitrary bytes, alone and after the toy set's encoding,
    /// so that the body parsers past the parameter set are reached too.
    #[test]
    fn byte_decoders_never_panic(body in vec(any::<u8>(), 0..MAX_INPUT)) {
        decode_all(&body);
        let mut prefixed = toy_spec().to_vec();
        prefixed.extend_from_slice(&body);
        decode_all(&prefixed);
    }

    /// Matrix deserialization returns on any shape and entry count, in a human-readable and a
    /// binary format, and accepts only `rows · cols` entries.
    #[test]
    fn matrix_deserialization_checks_the_shape(
        rows in dimension(),
        cols in dimension(),
        count in 0usize..10,
    ) {
        let fail = |e: &dyn std::fmt::Display| TestCaseError::fail(e.to_string());
        let params = Params::toy().map_err(|e| fail(&e))?;
        let input = MatrixInput {
            shape: Shape { rows, cols },
            entries: vec![Poly::zero(params.ring()); count],
        };
        let json = serde_json::to_string(&input).map_err(|e| fail(&e))?;
        let binary = postcard::to_stdvec(&input).map_err(|e| fail(&e))?;
        let accepted = [
            serde_json::from_str::<PolyMatrix>(&json).ok(),
            postcard::from_bytes::<PolyMatrix>(&binary).ok(),
        ];
        for matrix in accepted.into_iter().flatten() {
            prop_assert_eq!(matrix.shape(), Shape { rows, cols });
            let entries = serde_json::to_value(&matrix).map_err(|e| fail(&e))?["entries"]
                .as_array()
                .map(Vec::len);
            prop_assert_eq!(entries, rows.checked_mul(cols));
        }
    }
}
