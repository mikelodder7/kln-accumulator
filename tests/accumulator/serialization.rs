// SPDX-License-Identifier: MIT OR Apache-2.0
//! Six-format serde round trips and the byte encodings of every accumulator type (C26).

use crate::{
    fixture::{KEY, Manager, TOY, element, with_bound},
    serde_formats::{Wrap, round_trips},
};
use kln_accumulator::{
    Accumulator, Coefficient, Element, Error, ManagerState, MembershipWitness, ParamsSpec,
    PublicKey, SecretKey,
};
use std::sync::Arc;

/// An accumulator after two additions and one deletion, with a witness and an update message.
struct Sample {
    manager: Manager<'static>,
    witness: MembershipWitness,
    coefficient: Coefficient,
}

fn sample() -> Sample {
    let mut manager = Manager::new(&KEY);
    let witness = manager.add(&element(110));
    let _ = manager.add(&element(111));
    let coefficient = manager.remove(&element(111));
    Sample {
        manager,
        witness,
        coefficient,
    }
}

/// C26: every type round-trips in all six formats.
#[test]
fn every_type_round_trips_in_six_formats() {
    let Sample {
        manager,
        witness,
        coefficient,
    } = sample();
    round_trips(
        "SecretKey",
        SecretKey::try_from(KEY.to_bytes().as_slice()).unwrap(),
    );
    round_trips("PublicKey", manager.public.clone());
    round_trips("Element", element(110));
    round_trips("Accumulator", manager.value.clone());
    round_trips("MembershipWitness", witness);
    round_trips("Coefficient", coefficient);
    // The state's current value is the moved one, not the genesis value, so the round trip
    // covers it.
    assert_eq!(manager.state.current(), &manager.value);
    assert_ne!(manager.value, Accumulator::new(&KEY));
    round_trips("ManagerState", manager.state.clone());
}

/// C26: binary data is hex in human-readable formats and raw bytes in binary ones.
#[test]
fn binary_data_is_hex_or_raw() {
    let Sample { manager, .. } = sample();
    let x = element(0xab);
    assert_eq!(
        serde_json::to_string(&Wrap { value: &x }).unwrap(),
        r#"{"value":"ab"}"#
    );
    assert_eq!(
        yaml_serde::to_string(&Wrap { value: &x }).unwrap(),
        "value: ab\n"
    );
    assert_eq!(postcard::to_stdvec(&x).unwrap(), [1, 0xab]);
    let value = manager.value.to_bytes();
    // After the parameter set, the packed coefficients of the single entry of c: 64 of
    // ⌈log₂ q⌉ = 60 bits.
    let body = &value[ParamsSpec::BYTES..];
    assert_eq!(body.len(), 64 * 60 / 8);
    let json = serde_json::to_string(&manager.value).unwrap();
    assert!(json.starts_with(r#"{"params":{"degree":64,"#));
    assert!(json.ends_with(&format!(r#""coefficients":"{}"}}"#, hex::encode(body))));
    assert!(postcard::to_stdvec(&manager.value).unwrap().ends_with(body));
    assert!(
        serde_cbor_2::to_vec(&manager.value)
            .unwrap()
            .ends_with(body)
    );
    assert!(serde_bare::to_vec(&manager.value).unwrap().ends_with(body));
    let key = KEY.to_bytes();
    let seed = hex::encode(&key[64..]);
    assert!(
        serde_json::to_string(&*KEY)
            .unwrap()
            .contains(&format!(r#""seed":"{seed}""#))
    );
    assert!(postcard::to_stdvec(&*KEY).unwrap().ends_with(&key[64..]));
}

/// C51: the state's 32-byte tag is serialized last, as 64 lowercase hex digits in JSON, TOML and
/// YAML and as the raw bytes in postcard, CBOR and BARE.
#[test]
fn state_tag_is_hex_or_raw() {
    let Sample { manager, .. } = sample();
    let wrapped = Wrap {
        value: &manager.state,
    };
    let json = serde_json::to_value(&manager.state).unwrap();
    let hex_tag = json["tag"].as_str().unwrap().to_owned();
    assert_eq!(hex_tag.len(), 64);
    assert!(
        hex_tag
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    assert!(
        toml::to_string(&wrapped)
            .unwrap()
            .contains(&format!(r#"tag = "{hex_tag}""#))
    );
    assert!(
        yaml_serde::to_string(&wrapped)
            .unwrap()
            .contains(&format!("tag: {hex_tag}\n"))
    );
    let raw = hex::decode(&hex_tag).unwrap();
    assert!(postcard::to_stdvec(&manager.state).unwrap().ends_with(&raw));
    assert!(
        serde_cbor_2::to_vec(&manager.state)
            .unwrap()
            .ends_with(&raw)
    );
    assert!(serde_bare::to_vec(&manager.state).unwrap().ends_with(&raw));
}

/// C26: deserialized values pass `validate` against the set; keys rebuild their set and
/// refuse values outside it; the state refuses an impossible history.
#[test]
fn deserialized_values_are_checked() {
    let Sample {
        manager,
        witness,
        coefficient,
    } = sample();
    let params = &**TOY;
    let decode = |json: &str| serde_json::from_str::<ManagerState>(json);
    let state: ManagerState = decode(&serde_json::to_string(&manager.state).unwrap()).unwrap();
    assert!(state.validate(params).is_ok());
    let json = serde_json::to_string(&manager.state).unwrap();
    assert!(decode(&json.replacen(r#""counter":1"#, r#""counter":2"#, 1)).is_err());
    assert!(decode(&json.replacen(r#""counter":1"#, r#""counter":0"#, 1)).is_err());
    // A current value of another set decodes, carries its set, and is refused by `validate`
    // and by the tag.
    let mut foreign = serde_json::to_value(&manager.state).unwrap();
    foreign["current"] = serde_json::to_value(Accumulator::random(
        &mut crate::fixture::rng(5),
        &with_bound(5),
    ))
    .unwrap();
    let foreign = serde_json::from_value::<ManagerState>(foreign).unwrap();
    assert_eq!(foreign.validate(params), Err(Error::ParameterMismatch));
    assert_eq!(foreign.authenticate(&KEY), Err(Error::InvalidStateTag));
    let witness: MembershipWitness =
        serde_json::from_str(&serde_json::to_string(&witness).unwrap()).unwrap();
    assert!(witness.validate(params).is_ok());
    // Decoded values carry their own set and refuse any other one.
    assert_eq!(
        witness.validate(&with_bound(5)),
        Err(Error::ParameterMismatch)
    );
    assert_eq!(
        manager.value.validate(&with_bound(5)),
        Err(Error::ParameterMismatch)
    );
    // The first witness coefficient set to 2^43 − 1, above 2β ≈ 2^42.7: no centred value.
    let mut bytes = witness.to_bytes().unwrap();
    bytes[ParamsSpec::BYTES..ParamsSpec::BYTES + 6].fill(0xff);
    assert_eq!(
        MembershipWitness::try_from(bytes.as_slice()),
        Err(Error::CoefficientOverBound)
    );
    // The first coefficient of c set to 2^60 − 1 ≥ q, and a value with a trailing byte.
    let mut bytes = manager.value.to_bytes();
    bytes[ParamsSpec::BYTES..ParamsSpec::BYTES + 8].fill(0xff);
    assert_eq!(
        Accumulator::try_from(bytes.as_slice()),
        Err(Error::CoefficientOutOfRange)
    );
    let mut bytes = manager.value.to_bytes();
    bytes.push(0);
    assert_eq!(
        Accumulator::try_from(bytes.as_slice()),
        Err(Error::InvalidEncodingLength(1))
    );
    let coefficient: Coefficient =
        serde_json::from_str(&serde_json::to_string(&coefficient).unwrap()).unwrap();
    assert!(coefficient.validate(params).is_ok());
    let wide: Element = serde_json::from_str(r#""abcd""#).unwrap();
    assert_eq!(wide.validate(params), Err(Error::InvalidElement));
    assert!(serde_json::from_str::<Element>(r#""""#).is_err());
    // The first coefficient of A set to 2^60 − 1 ≥ q.
    let mut bytes = manager.public.to_bytes();
    bytes[ParamsSpec::BYTES..ParamsSpec::BYTES + 8].fill(0xff);
    assert_eq!(
        PublicKey::try_from(bytes.as_slice()),
        Err(Error::CoefficientOutOfRange)
    );
    let json = serde_json::to_string(&manager.public).unwrap();
    let a_start = json.find(r#""coefficients":""#).unwrap() + r#""coefficients":""#.len();
    let mut tampered = json.clone();
    tampered.replace_range(a_start..a_start + 16, &"f".repeat(16));
    assert!(serde_json::from_str::<PublicKey>(&tampered).is_err());
}

/// A field the serialized form does not name is refused, at the top of a value, inside its
/// parameter set, and in the manager state, so that one value has one JSON text.
#[test]
fn unknown_fields_are_refused() {
    let Sample { manager, .. } = sample();
    let json = serde_json::to_string(&manager.value).unwrap();
    assert!(serde_json::from_str::<Accumulator>(&json).is_ok());
    let top = json.replacen('{', r#"{"junk":1,"#, 1);
    assert!(serde_json::from_str::<Accumulator>(&top).is_err());
    let in_params = json.replacen(r#""params":{"#, r#""params":{"junk":1,"#, 1);
    assert_ne!(in_params, json);
    assert!(serde_json::from_str::<Accumulator>(&in_params).is_err());
    let state = serde_json::to_string(&manager.state).unwrap();
    let state = state.replacen('{', r#"{"junk":1,"#, 1);
    assert!(serde_json::from_str::<ManagerState>(&state).is_err());
}

/// The byte encodings round-trip through `TryFrom<&[u8]>`; their sizes at the toy set are
/// printed.
#[test]
fn byte_encodings_round_trip() {
    let Sample {
        manager,
        witness,
        coefficient,
    } = sample();
    let key = KEY.to_bytes();
    assert_eq!(SecretKey::try_from(key.as_slice()).unwrap(), *KEY);
    let public = manager.public.to_bytes();
    assert_eq!(
        PublicKey::try_from(public.as_slice()).unwrap(),
        manager.public
    );
    let x = element(110);
    assert_eq!(Element::try_from(x.to_bytes().as_slice()).unwrap(), x);
    let value = manager.value.to_bytes();
    assert_eq!(
        Accumulator::try_from(value.as_slice()).unwrap(),
        manager.value
    );
    let witness_bytes = witness.to_bytes().unwrap();
    assert_eq!(
        MembershipWitness::try_from(witness_bytes.as_slice()).unwrap(),
        witness
    );
    let coefficient_bytes = coefficient.to_bytes();
    assert_eq!(
        Coefficient::try_from(coefficient_bytes.as_slice()).unwrap(),
        coefficient
    );
    assert!(SecretKey::try_from(&key[..key.len() - 1]).is_err());
    assert!(PublicKey::try_from(&public[..public.len() - 1]).is_err());
    assert!(MembershipWitness::try_from(&witness_bytes[..witness_bytes.len() - 1]).is_err());
    eprintln!(
        "to_bytes at the toy set: SecretKey {} PublicKey {} Element {} Accumulator {} \
         MembershipWitness {} Coefficient {} bytes",
        key.len(),
        public.len(),
        x.to_bytes().len(),
        value.len(),
        witness_bytes.len(),
        coefficient_bytes.len()
    );
}

/// A value made under the ternary toy set carries the distribution in its parameter-set
/// prefix and is refused under the Gaussian toy set, and the other way round; the prefixes of
/// the two sets differ only in the distribution byte.
#[test]
fn values_carry_the_trapdoor_distribution() {
    use crate::fixture::ternary;
    let mut gaussian = Manager::new(&KEY);
    let mut other = Manager::new(&ternary::KEY);
    let (x, y) = (element(1), element(2));
    let gaussian_witness = gaussian.add(&x);
    let ternary_witness = other.add(&y);
    assert!(ternary_witness.verify(&y, &other.public, &other.value));
    for (value, witness, foreign) in [
        (&gaussian.value, &gaussian_witness, &**ternary::TOY),
        (&other.value, &ternary_witness, &**TOY),
    ] {
        assert_eq!(witness.validate(foreign), Err(Error::ParameterMismatch));
        assert_eq!(value.validate(foreign), Err(Error::ParameterMismatch));
    }
    let (g, t) = (gaussian.value.to_bytes(), other.value.to_bytes());
    let differing: Vec<usize> = (0..ParamsSpec::BYTES).filter(|&i| g[i] != t[i]).collect();
    assert_eq!(differing, [4]);
    assert_eq!((g[4], t[4]), (0, 1));
    let key = SecretKey::try_from(ternary::KEY.to_bytes().as_slice()).unwrap();
    assert_eq!(key.params().spec(), ternary::TOY.spec());
}

/// `from_bytes` decodes every packed type against the caller's set, which the value then
/// shares; it refuses bytes of another set with `ParameterMismatch` and truncated bytes with a
/// length error.
#[test]
fn from_bytes_decodes_against_the_given_set() {
    use crate::fixture::ternary;
    let Sample {
        manager, witness, ..
    } = sample();
    let public = manager.public.to_bytes();
    let value = manager.value.to_bytes();
    let witness_bytes = witness.to_bytes().unwrap();

    let pk = PublicKey::from_bytes(&TOY, &public).unwrap();
    assert_eq!(pk, manager.public);
    assert!(Arc::ptr_eq(pk.params(), &TOY));
    let acc = Accumulator::from_bytes(&TOY, &value).unwrap();
    assert_eq!(acc, manager.value);
    assert!(Arc::ptr_eq(acc.params(), &TOY));
    let decoded = MembershipWitness::from_bytes(&TOY, &witness_bytes).unwrap();
    assert_eq!(decoded, witness);
    assert!(Arc::ptr_eq(decoded.params(), &TOY));

    // The ternary toy set differs from the Gaussian one only in the distribution byte.
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
    let spec_only = &value[..ParamsSpec::BYTES - 1];
    assert_eq!(
        Accumulator::from_bytes(&TOY, spec_only).err(),
        Some(Error::InvalidEncodingLength(ParamsSpec::BYTES - 1))
    );
}

/// `from_bytes` builds no set from its input: a prefix naming a degree above
/// `ParamsSpec::MAX_DEGREE` is a mismatch, where `TryFrom<&[u8]>` reaches the set's own check.
#[test]
fn from_bytes_builds_no_set_from_the_input() {
    let Sample {
        manager, witness, ..
    } = sample();
    let wide = <[u8; ParamsSpec::BYTES]>::from(ParamsSpec {
        degree: ParamsSpec::MAX_DEGREE * 2,
        ..ParamsSpec::TOY
    });
    let relabel = |bytes: &[u8]| [wide.as_slice(), &bytes[ParamsSpec::BYTES..]].concat();
    let too_large = Some(Error::DegreeTooLarge(ParamsSpec::MAX_DEGREE * 2));
    let mismatch = Some(Error::ParameterMismatch);

    let public = relabel(&manager.public.to_bytes());
    assert_eq!(PublicKey::try_from(public.as_slice()).err(), too_large);
    assert_eq!(PublicKey::from_bytes(&TOY, &public).err(), mismatch);
    let value = relabel(&manager.value.to_bytes());
    assert_eq!(Accumulator::try_from(value.as_slice()).err(), too_large);
    assert_eq!(Accumulator::from_bytes(&TOY, &value).err(), mismatch);
    let witness_bytes = relabel(&witness.to_bytes().unwrap());
    assert_eq!(
        MembershipWitness::try_from(witness_bytes.as_slice()).err(),
        too_large
    );
    assert_eq!(
        MembershipWitness::from_bytes(&TOY, &witness_bytes).err(),
        mismatch
    );
}
