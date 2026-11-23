// SPDX-License-Identifier: MIT OR Apache-2.0
//! The serialized forms of a membership proof: six-format serde round trips with hex strings in
//! the human-readable formats, and the byte encoding.

use crate::{
    fixture::{LABEL, PROOF, SETUP, statement},
    serde_formats::{Wrap, round_trips},
};
use kln_accumulator::{Error, MembershipProof, verify};
use merlin::Transcript;

#[test]
fn proof_round_trips_in_six_formats() {
    round_trips("MembershipProof", PROOF.clone());
}

/// Polynomials are hex strings in JSON and raw bytes in postcard: the JSON form of `t_quad` is
/// the hex of its coefficient bytes, which appear verbatim in the postcard encoding.
#[test]
fn polynomials_are_hex_or_raw() {
    let json: serde_json::Value = serde_json::to_value(Wrap { value: &*PROOF }).unwrap();
    let t_quad = json["value"]["t_quad"].as_str().unwrap();
    let raw = hex::decode(t_quad).unwrap();
    let ring = SETUP.pk.params().ring();
    assert_eq!(
        raw.len(),
        ring.degree() * kln_accumulator::lattice::Coeff::BYTES
    );
    let postcard = postcard::to_stdvec(&*PROOF).unwrap();
    assert!(postcard.windows(raw.len()).any(|w| w == raw.as_slice()));
}

/// `to_bytes` round-trips, the decoded proof verifies, and truncated or extended encodings are
/// refused.
#[test]
fn byte_encoding_round_trips() {
    let bytes = PROOF.to_bytes();
    eprintln!("serialized proof: {} bytes", bytes.len());
    let decoded = MembershipProof::try_from(bytes.as_slice()).unwrap();
    assert_eq!(decoded, *PROOF);
    verify(
        &statement(),
        &decoded,
        &SETUP.params,
        &mut Transcript::new(LABEL),
    )
    .unwrap();
    assert!(matches!(
        MembershipProof::try_from(&bytes[..bytes.len() - 1]),
        Err(Error::InvalidEncodingLength(_))
    ));
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(matches!(
        MembershipProof::try_from(extended.as_slice()),
        Err(Error::InvalidEncodingLength(_))
    ));
    assert!(MembershipProof::try_from(&bytes[..10]).is_err());
}
