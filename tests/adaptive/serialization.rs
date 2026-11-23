// SPDX-License-Identifier: MIT OR Apache-2.0
//! Six-format serde round trips and the byte encodings of the adaptive types.

use crate::{
    fixture::{KEY, Manager, TOY, element, ternary},
    serde_formats::{Wrap, round_trips},
};
use kln_accumulator::{
    Error,
    adaptive::{Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey},
};
use std::sync::Arc;

/// An adaptive accumulator after three additions and one deletion, with a witness.
fn sample() -> (Manager<'static>, MembershipWitness) {
    let mut manager = Manager::new(&KEY);
    for i in 1..=3 {
        let _ = manager.add(&element(i));
    }
    let _ = manager.remove(&element(2));
    let witness = manager.witness(&element(1));
    (manager, witness)
}

/// Every adaptive type round-trips in postcard, CBOR, BARE, JSON, TOML and YAML.
#[test]
fn every_type_round_trips_in_six_formats() {
    let (manager, witness) = sample();
    round_trips(
        "adaptive SecretKey",
        SecretKey::try_from(KEY.to_bytes().as_slice()).unwrap(),
    );
    round_trips("adaptive PublicKey", manager.public.clone());
    round_trips("adaptive Element", element(1));
    round_trips("adaptive Accumulator", manager.value.clone());
    round_trips("adaptive MembershipWitness", witness);
    // The inner current value is the moved one, so the round trip covers it.
    assert_eq!(
        manager.state.inner().current(),
        &kln_accumulator::Accumulator::from(manager.value.clone())
    );
    assert_ne!(manager.value, Accumulator::new(&KEY));
    round_trips("adaptive ManagerState", manager.state.clone());
}

/// Binary data is hex in human-readable formats and raw in binary ones; a deserialized witness
/// still verifies, and one with a short signature is refused.
#[test]
fn binary_data_is_hex_or_raw() {
    let (manager, witness) = sample();
    let x = element(1);
    assert_eq!(
        serde_json::to_string(&Wrap { value: &x }).unwrap(),
        format!(r#"{{"value":"{}"}}"#, hex::encode(x.to_bytes()))
    );
    assert!(postcard::to_stdvec(&x).unwrap().ends_with(&x.to_bytes()));
    let json = serde_json::to_string(&witness).unwrap();
    assert!(json.contains(&format!(
        r#""signature":"{}""#,
        hex::encode(witness.signature())
    )));
    assert!(
        postcard::to_stdvec(&witness)
            .unwrap()
            .windows(witness.signature().len())
            .any(|w| w == witness.signature())
    );
    let back: MembershipWitness = serde_json::from_str(&json).unwrap();
    assert!(back.verify(&x, &manager.public, &manager.value));
    let short = json.replacen(&hex::encode(witness.signature()), "abcd", 1);
    assert!(serde_json::from_str::<MembershipWitness>(&short).is_err());
    let key = serde_json::to_string(&*KEY).unwrap();
    assert!(key.contains(&format!(
        r#""seed":"{}""#,
        hex::encode(&KEY.to_bytes()[64..])
    )));
    let state: ManagerState =
        serde_json::from_str(&serde_json::to_string(&manager.state).unwrap()).unwrap();
    assert!(state.validate(&TOY).is_ok());
}

/// The byte encodings round-trip through `TryFrom<&[u8]>` and refuse truncation; their sizes at
/// the toy set are printed.
#[test]
fn byte_encodings_round_trip() {
    let (manager, witness) = sample();
    let key = KEY.to_bytes();
    assert_eq!(SecretKey::try_from(key.as_slice()).unwrap(), *KEY);
    let public = manager.public.to_bytes();
    assert_eq!(
        PublicKey::try_from(public.as_slice()).unwrap(),
        manager.public
    );
    let x = element(1);
    assert_eq!(Element::try_from(x.to_bytes().as_slice()).unwrap(), x);
    assert_eq!(
        Element::try_from(&[0u8; 31][..]),
        Err(Error::InvalidElement)
    );
    let value = manager.value.to_bytes();
    assert_eq!(
        Accumulator::try_from(value.as_slice()).unwrap(),
        manager.value
    );
    let witness_bytes = witness.to_bytes().unwrap();
    let decoded = MembershipWitness::try_from(witness_bytes.as_slice()).unwrap();
    assert_eq!(decoded, witness);
    assert!(decoded.validate(&TOY).is_ok());
    assert!(SecretKey::try_from(&key[..key.len() - 1]).is_err());
    assert!(PublicKey::try_from(&public[..public.len() - 1]).is_err());
    assert!(MembershipWitness::try_from(&witness_bytes[..witness_bytes.len() - 1]).is_err());
    assert!(MembershipWitness::try_from(&witness_bytes[..20]).is_err());
    eprintln!(
        "adaptive to_bytes at the toy set: SecretKey {} PublicKey {} Element {} Accumulator {} \
         MembershipWitness {} (signature {}) bytes",
        key.len(),
        public.len(),
        x.to_bytes().len(),
        value.len(),
        witness_bytes.len(),
        witness.signature().len()
    );
}

/// `from_bytes` decodes the public key, the value and a witness against the caller's set,
/// which they then share; it refuses bytes of another set with `ParameterMismatch` and
/// truncated bytes with a length error.
#[test]
fn from_bytes_decodes_against_the_given_set() {
    let (manager, witness) = sample();
    let public = manager.public.to_bytes();
    let value = manager.value.to_bytes();
    let witness_bytes = witness.to_bytes().unwrap();

    let pk = PublicKey::from_bytes(&TOY, &public).unwrap();
    assert_eq!(pk, manager.public);
    assert!(Arc::ptr_eq(pk.params(), &TOY));
    let acc = Accumulator::from_bytes(&TOY, &value).unwrap();
    assert_eq!(acc, manager.value);
    assert!(Arc::ptr_eq(
        kln_accumulator::Accumulator::from(acc).params(),
        &TOY
    ));
    let decoded = MembershipWitness::from_bytes(&TOY, &witness_bytes).unwrap();
    assert_eq!(decoded, witness);
    assert!(Arc::ptr_eq(decoded.inner().params(), &TOY));

    let other = &*ternary::TOY;
    let mismatch = Some(Error::ParameterMismatch);
    assert_eq!(PublicKey::from_bytes(other, &public).err(), mismatch);
    assert_eq!(Accumulator::from_bytes(other, &value).err(), mismatch);
    assert_eq!(
        MembershipWitness::from_bytes(other, &witness_bytes).err(),
        mismatch
    );

    let short = |bytes: &[u8]| bytes[..bytes.len() - 1].to_vec();
    let length = |e: Option<Error>| matches!(e, Some(Error::InvalidEncodingLength(_)));
    assert!(length(PublicKey::from_bytes(&TOY, &short(&public)).err()));
    assert!(length(Accumulator::from_bytes(&TOY, &short(&value)).err()));
    assert!(length(
        MembershipWitness::from_bytes(&TOY, &short(&witness_bytes)).err()
    ));
    assert!(length(
        MembershipWitness::from_bytes(&TOY, &witness_bytes[..20]).err()
    ));
}
