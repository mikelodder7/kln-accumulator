// SPDX-License-Identifier: MIT OR Apache-2.0
//! Six-format serde round trips shared by the integration test targets, included into each with
//! a `#[path]` attribute.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;

/// TOML needs a table at the top level, so every value rides in a one-field wrapper in every
/// format.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Wrap<T> {
    pub value: T,
}

/// Encodes in one format, decodes, and checks the value and the re-encoding; returns the size.
fn check<T, E: Debug>(
    wrapped: &Wrap<T>,
    encode: impl Fn(&Wrap<T>) -> Result<Vec<u8>, E>,
    decode: impl Fn(&[u8]) -> Wrap<T>,
    format: &str,
) -> usize
where
    T: PartialEq + Debug,
{
    let bytes = encode(wrapped).expect("serde round trip");
    let back = decode(&bytes);
    assert!(back == *wrapped, "{format}: value differs");
    assert_eq!(
        encode(&back).expect("serde round trip"),
        bytes,
        "{format}: re-encoding differs"
    );
    bytes.len()
}

/// Round-trips `value` byte-exactly in postcard, CBOR, BARE, JSON, TOML and YAML and prints the
/// encoded sizes.
pub fn round_trips<T>(name: &str, value: T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let wrapped = Wrap { value };
    let sizes = [
        check(
            &wrapped,
            postcard::to_stdvec,
            |b| postcard::from_bytes(b).expect("serde round trip"),
            "postcard",
        ),
        check(
            &wrapped,
            serde_cbor_2::to_vec,
            |b| serde_cbor_2::from_slice(b).expect("serde round trip"),
            "cbor",
        ),
        check(
            &wrapped,
            serde_bare::to_vec,
            |b| {
                let mut reader = std::io::Cursor::new(b);
                let value = serde_bare::from_reader(&mut reader).expect("serde round trip");
                assert_eq!(reader.position(), b.len() as u64, "bare: trailing bytes");
                value
            },
            "bare",
        ),
        check(
            &wrapped,
            |w| serde_json::to_string(w).map(String::into_bytes),
            |b| serde_json::from_slice(b).expect("serde round trip"),
            "json",
        ),
        check(
            &wrapped,
            |w| toml::to_string(w).map(String::into_bytes),
            |b| {
                toml::from_str(std::str::from_utf8(b).expect("serde round trip"))
                    .expect("serde round trip")
            },
            "toml",
        ),
        check(
            &wrapped,
            |w| yaml_serde::to_string(w).map(String::into_bytes),
            |b| yaml_serde::from_slice(b).expect("serde round trip"),
            "yaml",
        ),
    ];
    eprintln!(
        "{name}: postcard {} cbor {} bare {} json {} toml {} yaml {} bytes",
        sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], sizes[5]
    );
}
