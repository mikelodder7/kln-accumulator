// SPDX-License-Identifier: MIT OR Apache-2.0
//! The serde form of byte strings that may be secret: lowercase hex in human-readable formats
//! and raw bytes in binary ones, the form `serdect` gives the public values.
//!
//! Unlike `serdect`, the hex text is built in a buffer that is overwritten when dropped, the
//! decoded bytes are returned in one, and both directions run in time independent of the byte
//! values (the length is public). What a serializer or deserializer buffers internally, and the
//! output or input it is given, is beyond this crate's reach: callers that serialize secret
//! values should wipe that output themselves.

use core::fmt;
use serde::{Deserializer, Serializer, de};
use zeroize::Zeroizing;

/// Writes `bytes` as lowercase hex in human-readable formats and raw otherwise.
pub(crate) fn serialize<T: AsRef<[u8]> + ?Sized, S: Serializer>(
    bytes: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let bytes = bytes.as_ref();
    if serializer.is_human_readable() {
        let mut hex = Zeroizing::new(String::with_capacity(2 * bytes.len()));
        for byte in bytes {
            hex.push(char::from(hex_digit(byte >> 4)));
            hex.push(char::from(hex_digit(byte & 0x0f)));
        }
        serializer.serialize_str(&hex)
    } else {
        serializer.serialize_bytes(bytes)
    }
}

/// Reads what [`serialize`] writes; the hex may use either case.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<Vec<u8>>, D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(BytesVisitor)
    } else {
        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}

/// The lowercase hex digit of `nibble < 16`, without a branch or a table lookup on its value.
fn hex_digit(nibble: u8) -> u8 {
    let n = i16::from(nibble);
    // For n > 9, 9 − n is negative and its arithmetic shift is all ones, adding 'a' − '0' − 10.
    // In 0x30..=0x66; a checked conversion would branch on the secret nibble.
    (n + i16::from(b'0') + (((9 - n) >> 8) & 0x27)) as u8
}

/// The value of the hex digit `c`, or −1, without a branch or a table lookup on its value:
/// each range check yields an all-ones mask exactly when `c` lies in the range.
fn hex_value(c: u8) -> i16 {
    let c = i16::from(c);
    let in_range = |low: i16, high: i16| ((low - 1 - c) & (c - high - 1)) >> 8;
    -1 + (in_range(0x30, 0x39) & (c - 0x30 + 1))
        + (in_range(0x41, 0x46) & (c - 0x41 + 11))
        + (in_range(0x61, 0x66) & (c - 0x61 + 11))
}

/// Decodes hex into a buffer that is overwritten when dropped.
fn decode(hex: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (pairs, rest) = hex.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(pairs.len()));
    let mut invalid = 0i16;
    for [high, low] in pairs {
        let (high, low) = (hex_value(*high), hex_value(*low));
        invalid |= high | low;
        // In 0..=0xff unless a digit is invalid, and then the buffer is discarded; a checked
        // conversion would branch on the secret byte.
        out.push(((high << 4) | low) as u8);
    }
    (invalid >= 0).then_some(out)
}

/// The visitor of [`deserialize`].
struct BytesVisitor;

impl de::Visitor<'_> for BytesVisitor {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a hex string or a byte string")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        decode(v.as_bytes()).ok_or_else(|| E::custom("invalid hex string"))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(v.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(v))
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, hex_digit, hex_value};
    use proptest::prelude::*;

    #[test]
    fn digits_match_the_alphabet() {
        let lower = b"0123456789abcdef";
        let upper = b"0123456789ABCDEF";
        for (n, (&l, &u)) in lower.iter().zip(upper).enumerate() {
            assert_eq!(hex_digit(n as u8), l);
            assert_eq!(hex_value(l), n as i16);
            assert_eq!(hex_value(u), n as i16);
        }
        for c in (0..=u8::MAX).filter(|c| !c.is_ascii_hexdigit()) {
            assert_eq!(hex_value(c), -1, "{c}");
        }
    }

    #[test]
    fn decoding_refuses_odd_lengths_and_non_digits() {
        assert!(decode(b"abc").is_none());
        assert!(decode(b"0g").is_none());
        assert!(decode(b"g0").is_none());
        assert_eq!(decode(b"").map(|v| v.to_vec()), Some(Vec::new()));
    }

    proptest! {
        #[test]
        fn hex_matches_the_hex_crate(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let lower = hex::encode(&bytes);
            let encoded: String = bytes
                .iter()
                .flat_map(|b| [hex_digit(b >> 4), hex_digit(b & 0x0f)])
                .map(char::from)
                .collect();
            prop_assert_eq!(&encoded, &lower);
            prop_assert_eq!(decode(lower.as_bytes()).map(|v| v.to_vec()), Some(bytes.clone()));
            prop_assert_eq!(
                decode(lower.to_uppercase().as_bytes()).map(|v| v.to_vec()),
                Some(bytes)
            );
        }
    }
}
