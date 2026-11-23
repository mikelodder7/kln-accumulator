// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bit-packed coefficient encodings whose width is fixed by the parameter set, the size
//! accounting of Table 2: `⌈log₂ q⌉` bits per coefficient of a uniform value and
//! `⌈log₂(2β + 1)⌉` bits per coefficient of a value of infinity norm at most `β`.
//!
//! Coefficients are written least significant bit first and concatenated without gaps; the
//! last byte is padded with zero bits. Decoding rejects a short input, non-zero padding, a
//! uniform value `≥ q` and a short value of magnitude above `β`, so every value has exactly one
//! encoding.

use crate::{
    error::{Error, Result},
    params::{Params, ParamsSpec},
    poly::Poly,
    ring::Ring,
    secret_hex,
    vector::PolyVec,
    zq::Coeff,
};
use crypto_bigint::CheckedAdd;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Residues in `[0, q)`, `⌈log₂ q⌉` bits each: the uniform values of Table 2 (the accumulator
/// value and the public matrices).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Uniform {
    modulus: Coeff,
    width: u32,
}

impl Uniform {
    /// The layout for residues modulo the ring's `q`.
    pub(crate) fn new(ring: &Ring) -> Self {
        let modulus = *ring.modulus();
        Self {
            modulus,
            width: modulus.wrapping_sub(&Coeff::ONE).bit_width_vartime(),
        }
    }

    /// Appends the coefficients of `polys`, which must be reduced modulo `q`.
    pub(crate) fn write<'a>(&self, polys: impl IntoIterator<Item = &'a Poly>, out: &mut Vec<u8>) {
        write_raw(polys, self.width, out, |c| *c);
    }

    /// Reads exactly `count` polynomials of `degree` coefficients from the front of `bytes`.
    pub(crate) fn read<'b>(
        &self,
        bytes: &'b [u8],
        count: usize,
        degree: usize,
    ) -> Result<(PolyVec, &'b [u8])> {
        read_raw(bytes, count, degree, self.width, |raw| {
            if raw < self.modulus {
                Ok(raw)
            } else {
                Err(Error::CoefficientOutOfRange)
            }
        })
    }
}

/// Centred values in `[−β, β]`, each stored as `v + β ∈ [0, 2β]` in `⌈log₂(2β + 1)⌉` bits:
/// the short values of Table 2 (witnesses, and the trapdoor `T` of the succinct variant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Short {
    modulus: Coeff,
    bound: Coeff,
    width: u32,
}

impl Short {
    /// The layout for centred values of magnitude at most `bound` modulo the ring's `q`. Fails
    /// with [`Error::WitnessBoundTooLarge`] unless `2·bound < q`, which makes the centred value
    /// of every residue in range unique.
    pub(crate) fn new(bound: &Coeff, ring: &Ring) -> Result<Self> {
        let modulus = *ring.modulus();
        let twice = bound
            .checked_add(bound)
            .into_option()
            .filter(|twice| *twice < modulus)
            .ok_or(Error::WitnessBoundTooLarge)?;
        Ok(Self {
            modulus,
            bound: *bound,
            width: twice.bit_width_vartime(),
        })
    }

    /// Fails with [`Error::CoefficientOverBound`] when a centred coefficient of `polys`,
    /// residues modulo `q`, has magnitude above `β`.
    pub(crate) fn check<'a>(&self, polys: impl IntoIterator<Item = &'a Poly>) -> Result<()> {
        let floor = self.modulus.wrapping_sub(&self.bound);
        if polys
            .into_iter()
            .flat_map(Poly::coefficients)
            .all(|c| *c <= self.bound || *c >= floor)
        {
            Ok(())
        } else {
            Err(Error::CoefficientOverBound)
        }
    }

    /// Appends the coefficients of `polys` after [`Short::check`]; on an error nothing is
    /// written.
    pub(crate) fn write<'a>(
        &self,
        polys: impl IntoIterator<Item = &'a Poly> + Clone,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        self.check(polys.clone())?;
        self.write_in_range(polys, out);
        Ok(())
    }

    /// Appends the coefficients of `polys`, which [`Short::check`] accepted. A value `c ≤ β`
    /// is the centred value `c`, stored as `c + β`; a value `c ≥ q − β` is `c − q`, stored as
    /// `c − (q − β)`.
    pub(crate) fn write_in_range<'a>(
        &self,
        polys: impl IntoIterator<Item = &'a Poly>,
        out: &mut Vec<u8>,
    ) {
        let floor = self.modulus.wrapping_sub(&self.bound);
        write_raw(polys, self.width, out, |c| {
            if *c <= self.bound {
                c.wrapping_add(&self.bound)
            } else {
                c.wrapping_sub(&floor)
            }
        });
    }

    /// Reads exactly `count` polynomials of `degree` coefficients from the front of `bytes`.
    pub(crate) fn read<'b>(
        &self,
        bytes: &'b [u8],
        count: usize,
        degree: usize,
    ) -> Result<(PolyVec, &'b [u8])> {
        let twice = self.bound.wrapping_add(&self.bound);
        read_raw(bytes, count, degree, self.width, |raw| {
            if raw > twice {
                Err(Error::CoefficientOverBound)
            } else if raw >= self.bound {
                Ok(raw.wrapping_sub(&self.bound))
            } else {
                Ok(self.modulus.wrapping_sub(&self.bound.wrapping_sub(&raw)))
            }
        })
    }
}

/// A value bound to its parameter set whose coefficients are packed with a width the set
/// determines. Its byte encoding is the 64-byte [`ParamsSpec`] encoding followed by the packed body, and
/// its serde form is the set and the body (raw in binary formats, hex in human-readable ones).
pub(crate) trait Packed: Sized {
    /// The parameter set the value belongs to.
    fn params(&self) -> &Arc<Params>;

    /// Appends the packed coefficients.
    fn write_body(&self, out: &mut Vec<u8>) -> Result<()>;

    /// Decodes a body written by [`Packed::write_body`] at `params`, which must be consumed
    /// exactly, and checks the value against the set.
    fn read_body(params: Arc<Params>, body: &[u8]) -> Result<Self>;
}

/// the 64-byte [`ParamsSpec`] encoding followed by the packed body.
pub(crate) fn to_bytes<T: Packed>(value: &T) -> Result<Vec<u8>> {
    let mut out = <[u8; ParamsSpec::BYTES]>::from(*value.params().spec()).to_vec();
    value.write_body(&mut out)?;
    Ok(out)
}

/// [`to_bytes`] for a value whose body `write` appends and cannot fail.
pub(crate) fn to_bytes_with<T: Packed>(value: &T, write: impl FnOnce(&T, &mut Vec<u8>)) -> Vec<u8> {
    let mut out = <[u8; ParamsSpec::BYTES]>::from(*value.params().spec()).to_vec();
    write(value, &mut out);
    out
}

/// Decodes [`to_bytes`]: rebuilds and validates the parameter set, then the body.
pub(crate) fn from_bytes<T: Packed>(bytes: &[u8]) -> Result<T> {
    let (spec, body) = bytes
        .split_at_checked(ParamsSpec::BYTES)
        .ok_or(Error::InvalidEncodingLength(bytes.len()))?;
    T::read_body(
        Arc::new(Params::try_from(ParamsSpec::try_from(spec)?)?),
        body,
    )
}

/// Decodes [`to_bytes`] against `params`, which the result shares, without building a set
/// from the input: fails with [`Error::InvalidEncodingLength`] when `bytes` is shorter than a
/// [`ParamsSpec`] encoding and with [`Error::ParameterMismatch`] unless it starts with the
/// encoding of `params.spec()`. Every set's encoding is canonical, so comparing the bytes is
/// comparing the sets.
pub(crate) fn from_bytes_at<T: Packed>(params: &Arc<Params>, bytes: &[u8]) -> Result<T> {
    let (spec, body) = bytes
        .split_at_checked(ParamsSpec::BYTES)
        .ok_or(Error::InvalidEncodingLength(bytes.len()))?;
    if spec == <[u8; ParamsSpec::BYTES]>::from(*params.spec()) {
        T::read_body(Arc::clone(params), body)
    } else {
        Err(Error::ParameterMismatch)
    }
}

/// Fails with [`Error::InvalidEncodingLength`] unless `rest`, what follows a decoded body, is
/// empty.
pub(crate) fn finish<T>(value: T, rest: &[u8]) -> Result<T> {
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(Error::InvalidEncodingLength(rest.len()))
    }
}

/// The serde form of a [`Packed`] value.
pub(crate) fn serialize<T: Packed, S: Serializer>(
    value: &T,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error> {
    let mut body = Zeroizing::new(Vec::new());
    value
        .write_body(&mut body)
        .map_err(serde::ser::Error::custom)?;
    PackedRef {
        params: value.params().spec(),
        coefficients: &body,
    }
    .serialize(serializer)
}

/// Decodes [`serialize`].
pub(crate) fn deserialize<'de, T: Packed, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<T, D::Error> {
    let wire = PackedWire::deserialize(deserializer)?;
    Params::try_from(wire.params)
        .and_then(|params| T::read_body(Arc::new(params), &wire.coefficients))
        .map_err(serde::de::Error::custom)
}

/// The `from_bytes` method and the `TryFrom<&[u8]>`, `Serialize` and `Deserialize` impls of a
/// [`Packed`] type, forwarding to [`from_bytes_at`], [`from_bytes`], [`serialize`] and
/// [`deserialize`]. The documentation of the decoder and of the serializer, and the example of
/// the method, which differ between types, come with the invocation.
macro_rules! packed_impls {
    (
        $ty:ident,
        $(#[$decode:meta])* decode,
        $(#[$from_bytes:meta])* from_bytes,
        $(#[$serialize:meta])* serialize
    ) => {
        impl $ty {
            #[doc = concat!("Decodes [`", stringify!($ty), "::to_bytes`] against `params`, the set the")]
            /// caller expects, and shares `params` with the result. No set is built from the
            /// input: the 64-byte [`crate::ParamsSpec`] encoding at the front of `bytes` must be
            /// that of `params.spec()`, and the body is then read and checked as `TryFrom<&[u8]>`
            /// reads it. Use this for bytes from an untrusted source, so that the input cannot
            /// choose the set, and wherever the caller already holds the set.
            ///
            /// # Errors
            ///
            /// [`crate::Error::InvalidEncodingLength`] when `bytes` is shorter than a parameter
            /// set encoding, [`crate::Error::ParameterMismatch`] when the set it names is not
            /// `params`, and otherwise as `TryFrom<&[u8]>`.
            ///
            $(#[$from_bytes])*
            pub fn from_bytes(
                params: &::std::sync::Arc<$crate::params::Params>,
                bytes: &[u8],
            ) -> $crate::Result<Self> {
                $crate::packing::from_bytes_at(params, bytes)
            }
        }

        $(#[$decode])*
        #[doc = concat!(
            "It builds the set the bytes name, so for bytes from an untrusted source use [`",
            stringify!($ty),
            "::from_bytes`] with the set you expect."
        )]
        impl TryFrom<&[u8]> for $ty {
            type Error = $crate::Error;

            fn try_from(bytes: &[u8]) -> $crate::Result<Self> {
                $crate::packing::from_bytes(bytes)
            }
        }

        $(#[$serialize])*
        impl ::serde::Serialize for $ty {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                $crate::packing::serialize(self, serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                $crate::packing::deserialize(deserializer)
            }
        }
    };
}
pub(crate) use packed_impls;

/// The serialized form of a [`Packed`] value.
#[derive(Serialize)]
struct PackedRef<'a> {
    params: &'a ParamsSpec,
    #[serde(serialize_with = "secret_hex::serialize")]
    coefficients: &'a [u8],
}

/// The serialized form of a [`Packed`] value, before it is checked against its set; a field it
/// does not name is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackedWire {
    params: ParamsSpec,
    #[serde(deserialize_with = "secret_hex::deserialize")]
    coefficients: Zeroizing<Vec<u8>>,
}

/// Appends `encode(c)` in `width` bits for every coefficient of `polys`, then pads the last
/// byte with zero bits.
fn write_raw<'a>(
    polys: impl IntoIterator<Item = &'a Poly>,
    width: u32,
    out: &mut Vec<u8>,
    encode: impl Fn(&Coeff) -> Coeff,
) {
    let polys: Vec<&Poly> = polys.into_iter().collect();
    let count: usize = polys.iter().map(|p| p.coefficients().len()).sum();
    // Reserving the whole body first means `out` is never reallocated, and so never leaves a
    // copy of a secret value's bits behind, while it is written.
    out.reserve((count * width as usize).div_ceil(8));
    let mut writer = BitWriter {
        out,
        pending: 0,
        bits: 0,
    };
    for coefficient in polys.into_iter().flat_map(Poly::coefficients) {
        writer.push_coeff(&encode(coefficient), width);
    }
    writer.finish();
}

/// Reads `count · degree` coefficients of `width` bits from the front of `bytes`, maps each
/// through `decode`, and returns them as `count` polynomials with the bytes that follow.
fn read_raw(
    bytes: &[u8],
    count: usize,
    degree: usize,
    width: u32,
    decode: impl Fn(Coeff) -> Result<Coeff>,
) -> Result<(PolyVec, &[u8])> {
    let invalid = Error::InvalidEncodingLength(bytes.len());
    let bits = count
        .checked_mul(degree)
        .and_then(|n| n.checked_mul(usize::try_from(width).ok()?))
        .ok_or(invalid)?;
    let (head, rest) = bytes.split_at_checked(bits.div_ceil(8)).ok_or(invalid)?;
    let mut reader = BitReader {
        bytes: head.iter(),
        pending: 0,
        bits: 0,
    };
    let vector = (0..count)
        .map(|_| {
            // Allocated once at its full size and wiped when dropped, so neither a growth nor a
            // decode error leaves coefficients behind; `degree` is bounded by `bytes` above.
            let mut coefficients = Zeroizing::new(Vec::with_capacity(degree));
            for _ in 0..degree {
                coefficients.push(reader.pull_coeff(width).and_then(&decode)?);
            }
            Ok(Poly::from_reduced(core::mem::take(&mut *coefficients)))
        })
        .collect::<Result<PolyVec>>()?;
    reader.finish()?;
    Ok((vector, rest))
}

/// `2^bits − 1` for `bits ≤ 64`.
fn mask(bits: u32) -> u128 {
    (1u128 << bits) - 1
}

/// Writes bit fields least significant bit first.
struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    pending: u128,
    bits: u32,
}

impl BitWriter<'_> {
    /// Appends the low `width` bits of `value`, `width ≤ 64`.
    fn push(&mut self, value: u64, width: u32) {
        self.pending |= (u128::from(value) & mask(width)) << self.bits;
        self.bits += width;
        while self.bits >= 8 {
            self.out.push(self.pending.to_le_bytes()[0]);
            self.pending >>= 8;
            self.bits -= 8;
        }
    }

    /// Appends the low `width` bits of `value`, in 64-bit words.
    fn push_coeff(&mut self, value: &Coeff, width: u32) {
        let bytes = value.to_le_bytes();
        let mut left = width;
        for word in bytes.as_slice().as_chunks::<8>().0 {
            if left == 0 {
                break;
            }
            let take = left.min(u64::BITS);
            self.push(u64::from_le_bytes(*word), take);
            left -= take;
        }
    }

    /// Writes the last partial byte, padded with zero bits.
    fn finish(self) {
        if self.bits > 0 {
            self.out.push(self.pending.to_le_bytes()[0]);
        }
    }
}

/// Reads bit fields least significant bit first.
struct BitReader<'a> {
    bytes: core::slice::Iter<'a, u8>,
    pending: u128,
    bits: u32,
}

impl BitReader<'_> {
    /// The next `width ≤ 64` bits.
    fn pull(&mut self, width: u32) -> Result<u64> {
        while self.bits < width {
            let byte = self.bytes.next().ok_or(Error::InvalidEncodingLength(0))?;
            self.pending |= u128::from(*byte) << self.bits;
            self.bits += 8;
        }
        // Masked to `width ≤ 64` bits, so the value fits; a checked conversion would branch on
        // the coefficient bits.
        let value = (self.pending & mask(width)) as u64;
        self.pending >>= width;
        self.bits -= width;
        Ok(value)
    }

    /// The next `width` bits as a coefficient, in 64-bit words.
    fn pull_coeff(&mut self, width: u32) -> Result<Coeff> {
        let mut bytes = [0u8; Coeff::BYTES];
        let mut left = width;
        for word in bytes.as_chunks_mut::<8>().0 {
            if left == 0 {
                break;
            }
            let take = left.min(u64::BITS);
            *word = self.pull(take)?.to_le_bytes();
            left -= take;
        }
        Ok(Coeff::from_le_slice(&bytes))
    }

    /// Fails with [`Error::NonCanonicalEncoding`] unless the padding bits are zero. The input
    /// is cut to the packed length before reading, so no whole byte is left over.
    fn finish(self) -> Result<()> {
        if self.pending == 0 {
            Ok(())
        } else {
            Err(Error::NonCanonicalEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Short, Uniform};
    use crate::{
        error::Error,
        poly::Poly,
        test_util::{PAPER, TOY, arb_poly, arb_small_poly, signed_to_coeff},
        zq::Coeff,
    };
    use proptest::prelude::*;

    fn uniform_bytes(polys: &[Poly], layout: &Uniform) -> Vec<u8> {
        let mut out = Vec::new();
        layout.write(polys, &mut out);
        out
    }

    /// `⌈log₂ q⌉` bits per coefficient: 60 at the toy set, 100 at the 128-bit set; a short
    /// layout with bound `β` takes `⌈log₂(2β + 1)⌉` bits.
    #[test]
    fn widths_follow_the_parameters() {
        assert_eq!(Uniform::new(TOY.ring()).width, 60);
        assert_eq!(Uniform::new(PAPER.ring()).width, 100);
        let short = |bound: u64| {
            Short::new(&Coeff::from_u64(bound), TOY.ring())
                .unwrap()
                .width
        };
        assert_eq!(short(0), 0);
        assert_eq!(short(1), 2);
        assert_eq!(short(3), 3);
        assert_eq!(short(4), 4);
        // β = (q − 1)/2 is the largest bound with 2β < q.
        let half = TOY.ring().modulus().shr_vartime(1);
        assert_eq!(Short::new(&half, TOY.ring()).unwrap().width, 60);
        assert_eq!(
            Short::new(&half.wrapping_add(&Coeff::ONE), TOY.ring()).err(),
            Some(Error::WitnessBoundTooLarge)
        );
    }

    #[test]
    fn uniform_rejects_values_at_least_q_and_bad_padding_or_length() {
        let ring = TOY.ring();
        let layout = Uniform::new(ring);
        let mut coefficients = vec![Coeff::ZERO; 64];
        coefficients[0] = ring.modulus().wrapping_sub(&Coeff::ONE);
        let bytes = uniform_bytes(&[Poly::new(coefficients, ring).unwrap()], &layout);
        assert_eq!(bytes.len(), 64 * 60 / 8);
        assert!(layout.read(&bytes, 1, 64).is_ok());
        let mut at_q = bytes.clone();
        at_q[0] = at_q[0].wrapping_add(1);
        assert_eq!(
            layout.read(&at_q, 1, 64).err(),
            Some(Error::CoefficientOutOfRange)
        );
        assert!(matches!(
            layout.read(&bytes[1..], 1, 64),
            Err(Error::InvalidEncodingLength(_))
        ));
        // Three coefficients of 60 bits leave 4 padding bits in the last byte.
        let mut padded = vec![0u8; 23];
        assert!(layout.read(&padded, 1, 3).is_ok());
        padded[22] = 0x10;
        assert_eq!(
            layout.read(&padded, 1, 3).err(),
            Some(Error::NonCanonicalEncoding)
        );
    }

    #[test]
    fn short_rejects_values_over_the_bound() {
        let ring = TOY.ring();
        let layout = Short::new(&Coeff::from_u64(5), ring).unwrap();
        let over = signed_to_coeff(&[6; 64], ring);
        assert_eq!(
            layout.write([&over], &mut Vec::new()),
            Err(Error::CoefficientOverBound)
        );
        let under = signed_to_coeff(&[-6; 64], ring);
        assert_eq!(
            layout.write([&under], &mut Vec::new()),
            Err(Error::CoefficientOverBound)
        );
        // 2β = 10 in 4 bits; 11 is a field value above 2β.
        let mut bytes = Vec::new();
        layout
            .write([&signed_to_coeff(&[5; 64], ring)], &mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), 32);
        bytes[0] = 0xab;
        assert_eq!(
            layout.read(&bytes, 1, 64).err(),
            Some(Error::CoefficientOverBound)
        );
    }

    proptest! {
        #[test]
        fn uniform_round_trips(a in arb_poly(&TOY), b in arb_poly(&TOY)) {
            let layout = Uniform::new(TOY.ring());
            let polys = [a, b];
            let bytes = uniform_bytes(&polys, &layout);
            prop_assert_eq!(bytes.len(), 2 * 64 * 60 / 8);
            let (vector, rest) = layout.read(&bytes, 2, 64).unwrap();
            prop_assert!(rest.is_empty());
            prop_assert_eq!(vector.as_slice(), polys.as_slice());
        }

        #[test]
        fn uniform_round_trips_at_the_paper_modulus(a in arb_poly(&PAPER)) {
            let layout = Uniform::new(PAPER.ring());
            let bytes = uniform_bytes(core::slice::from_ref(&a), &layout);
            prop_assert_eq!(bytes.len(), 4096 * 100 / 8);
            let (vector, _) = layout.read(&bytes, 1, 4096).unwrap();
            prop_assert_eq!(&vector.as_slice()[0], &a);
        }

        /// Every value in `[−β, β]` round-trips, including both ends, and a trailing byte is
        /// left to the caller.
        #[test]
        fn short_round_trips(values in arb_small_poly(64, 1 << 40), bound in (1u64 << 40)..(1 << 50)) {
            let ring = TOY.ring();
            let mut values = values;
            values[0] = i64::try_from(bound).unwrap();
            values[1] = -values[0];
            let poly = signed_to_coeff(&values, ring);
            let layout = Short::new(&Coeff::from_u64(bound), ring).unwrap();
            let mut bytes = Vec::new();
            layout.write([&poly], &mut bytes).unwrap();
            let width = (2 * bound).ilog2() as usize + 1;
            prop_assert_eq!(bytes.len(), (64 * width).div_ceil(8));
            bytes.push(7);
            let (vector, rest) = layout.read(&bytes, 1, 64).unwrap();
            prop_assert_eq!(rest, [7u8].as_slice());
            prop_assert_eq!(&vector.as_slice()[0], &poly);
        }
    }
}
