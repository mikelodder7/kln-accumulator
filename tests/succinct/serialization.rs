// SPDX-License-Identifier: MIT OR Apache-2.0
//! Six-format serde round trips and the byte encodings of the succinct types.

use crate::{
    fixture::{KEY, Manager, SET, element, ternary},
    serde_formats::round_trips,
};
use kln_accumulator::{
    Error, Params, ParamsSpec,
    succinct::{MembershipWitness, PublicKey, SecretKey},
};
use std::sync::Arc;

/// The key, the public key (about 12.6 MB at the succinct toy set) and a witness round-trip in
/// postcard, CBOR, BARE, JSON, TOML and YAML, and the decoded witness still verifies.
#[test]
fn every_type_round_trips_in_six_formats() {
    let mut manager = Manager::new(&KEY);
    let x = element(7);
    let witness = manager.add(&x);
    round_trips(
        "succinct SecretKey",
        SecretKey::try_from(KEY.to_bytes().as_slice()).unwrap(),
    );
    round_trips("succinct PublicKey", manager.public.clone());
    round_trips("succinct MembershipWitness", witness.clone());
    let back: MembershipWitness =
        serde_json::from_str(&serde_json::to_string(&witness).unwrap()).unwrap();
    assert!(back.verify(&x, &manager.public, &manager.value));
}

/// The byte encodings round-trip and refuse truncation; a decoded public key keeps `−B₁T₁`.
#[test]
fn byte_encodings_round_trip() {
    let mut manager = Manager::new(&KEY);
    let witness = manager.add(&element(8));
    let key = KEY.to_bytes();
    assert_eq!(SecretKey::try_from(key.as_slice()).unwrap(), *KEY);
    assert!(SecretKey::try_from(&key[..key.len() - 1]).is_err());
    let public = manager.public.to_bytes();
    let decoded = PublicKey::try_from(public.as_slice()).unwrap();
    assert_eq!(decoded, manager.public);
    assert_eq!(decoded.b(), manager.public.b());
    assert!(PublicKey::try_from(&public[..public.len() - 1]).is_err());
    let bytes = witness.to_bytes().unwrap();
    let back = MembershipWitness::try_from(bytes.as_slice()).unwrap();
    assert_eq!(back, witness);
    assert!(back.validate(&SET).is_ok());
    assert!(MembershipWitness::try_from(&bytes[..bytes.len() - 1]).is_err());
}

/// `from_bytes` decodes the public key and a witness against the caller's set, which they then
/// share; it refuses bytes of another set with `ParameterMismatch` and truncated bytes with a
/// length error.
#[test]
fn from_bytes_decodes_against_the_given_set() {
    let mut manager = Manager::new(&KEY);
    let witness = manager.add(&element(9));
    let public = manager.public.to_bytes();
    let witness_bytes = witness.to_bytes().unwrap();

    let pk = PublicKey::from_bytes(&SET, &public).unwrap();
    assert_eq!(pk, manager.public);
    assert!(Arc::ptr_eq(pk.params(), &SET));
    let decoded = MembershipWitness::from_bytes(&SET, &witness_bytes).unwrap();
    assert_eq!(decoded, witness);
    assert!(Arc::ptr_eq(decoded.params(), &SET));

    let mismatch = Some(Error::ParameterMismatch);
    for other in [&*ternary::SET, &Arc::new(Params::toy().unwrap())] {
        assert_eq!(PublicKey::from_bytes(other, &public).err(), mismatch);
        assert_eq!(
            MembershipWitness::from_bytes(other, &witness_bytes).err(),
            mismatch
        );
    }

    let short = |bytes: &[u8]| bytes[..bytes.len() - 1].to_vec();
    let length = |e: Option<Error>| matches!(e, Some(Error::InvalidEncodingLength(_)));
    assert!(length(PublicKey::from_bytes(&SET, &short(&public)).err()));
    assert!(length(
        MembershipWitness::from_bytes(&SET, &short(&witness_bytes)).err()
    ));
    assert_eq!(
        PublicKey::from_bytes(&SET, &public[..ParamsSpec::BYTES - 1]).err(),
        Some(Error::InvalidEncodingLength(ParamsSpec::BYTES - 1))
    );
}
