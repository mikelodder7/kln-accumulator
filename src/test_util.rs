// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared test fixtures: the defined parameter sets, proptest strategies, and an independent
//! schoolbook multiplication.

use crate::{
    matrix::{PolyMatrix, Shape},
    params::{Params, ParamsSpec, TrapdoorDistribution},
    poly::Poly,
    ring::Ring,
    vector::PolyVec,
    zq::Coeff,
};
use crypto_bigint::{NonZero, U512};
use proptest::prelude::*;
use std::sync::LazyLock;

pub(crate) static TOY: LazyLock<Params> = LazyLock::new(|| Params::toy().unwrap());
pub(crate) static PAPER: LazyLock<Params> = LazyLock::new(|| Params::paper_128().unwrap());
pub(crate) static TOY_TERNARY: LazyLock<Params> = LazyLock::new(|| {
    Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary)).unwrap()
});
pub(crate) static PAPER_TERNARY: LazyLock<Params> = LazyLock::new(|| {
    Params::try_from(ParamsSpec::PAPER_128.with_trapdoor(TrapdoorDistribution::Ternary)).unwrap()
});

/// A value under one key, since TOML needs a table at the top level.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Wrap<T> {
    pub(crate) value: T,
}

/// `value` round-trips in postcard, CBOR, BARE, JSON, TOML and YAML, and every human-readable
/// form contains `text`. Returns the postcard, CBOR and BARE encodings.
pub(crate) fn six_formats<T>(value: T, text: &str) -> [Vec<u8>; 3]
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let wrapped = Wrap { value };
    let postcard = postcard::to_stdvec(&wrapped).unwrap();
    assert_eq!(postcard::from_bytes::<Wrap<T>>(&postcard).unwrap(), wrapped);
    let cbor = serde_cbor_2::to_vec(&wrapped).unwrap();
    assert_eq!(serde_cbor_2::from_slice::<Wrap<T>>(&cbor).unwrap(), wrapped);
    let bare = serde_bare::to_vec(&wrapped).unwrap();
    assert_eq!(serde_bare::from_slice::<Wrap<T>>(&bare).unwrap(), wrapped);
    let json = serde_json::to_string(&wrapped).unwrap();
    assert_eq!(serde_json::from_str::<Wrap<T>>(&json).unwrap(), wrapped);
    let toml = toml::to_string(&wrapped).unwrap();
    assert_eq!(toml::from_str::<Wrap<T>>(&toml).unwrap(), wrapped);
    let yaml = yaml_serde::to_string(&wrapped).unwrap();
    assert_eq!(yaml_serde::from_str::<Wrap<T>>(&yaml).unwrap(), wrapped);
    for readable in [&json, &toml, &yaml] {
        assert!(readable.contains(text), "{readable}");
    }
    [postcard, cbor, bare]
}

/// Compiles only when `T` overwrites its secret material when dropped.
pub(crate) fn wiped_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>() {}

/// A wide unsigned integer as the nearest `f64`, for statistics and comparisons in tests.
pub(crate) fn to_f64(value: &U512) -> f64 {
    value
        .as_words()
        .iter()
        .rev()
        .fold(0.0, |acc, &w| acc * 2f64.powi(64) + w as f64)
}

/// Every coefficient of `v` as its centred lift, in `f64`.
pub(crate) fn centred_f64(v: &PolyVec, ring: &Ring) -> Vec<f64> {
    v.as_slice()
        .iter()
        .flat_map(Poly::coefficients)
        .map(|c| {
            let centred = ring.center(c);
            let magnitude = to_f64(&centred.magnitude().resize());
            if centred.is_negative() {
                -magnitude
            } else {
                magnitude
            }
        })
        .collect()
}

/// A uniformly random polynomial, from 192 random bits per coefficient reduced mod `q`.
pub(crate) fn arb_poly(params: &'static Params) -> impl Strategy<Value = Poly> {
    arb_ring_poly(params.ring())
}

/// [`arb_poly`] for a ring that belongs to no parameter set.
pub(crate) fn arb_ring_poly(ring: &'static Ring) -> impl Strategy<Value = Poly> {
    prop::collection::vec(any::<[u64; 3]>(), ring.degree()).prop_map(move |words| {
        let q = NonZero::new(*ring.modulus()).unwrap();
        Poly::new(
            words
                .into_iter()
                .map(|w| Coeff::from_words(w).rem(&q))
                .collect(),
            ring,
        )
        .unwrap()
    })
}

pub(crate) fn arb_vec(params: &'static Params, len: usize) -> impl Strategy<Value = PolyVec> {
    prop::collection::vec(arb_poly(params), len).prop_map(PolyVec::from)
}

pub(crate) fn arb_matrix(
    params: &'static Params,
    shape: Shape,
) -> impl Strategy<Value = PolyMatrix> {
    prop::collection::vec(arb_poly(params), shape.rows * shape.cols)
        .prop_map(move |entries| PolyMatrix::new(shape, entries).unwrap())
}

/// `len` signed integers in `[−bound, bound]`.
pub(crate) fn arb_small_poly(len: usize, bound: i64) -> impl Strategy<Value = Vec<i64>> {
    prop::collection::vec(-bound..=bound, len)
}

/// Maps signed integers to their residues, independently of the crate's own reduction.
pub(crate) fn signed_to_coeff(values: &[i64], ring: &Ring) -> Poly {
    let q = *ring.modulus();
    Poly::new(
        values
            .iter()
            .map(|&v| {
                let magnitude = Coeff::from_u64(v.unsigned_abs());
                if v < 0 {
                    q.wrapping_sub(&magnitude)
                } else {
                    magnitude
                }
            })
            .collect(),
        ring,
    )
    .unwrap()
}

/// `a · b mod (X^d + 1, q)` by the quadratic definition, with crypto-bigint's non-Montgomery
/// `mul_mod`.
pub(crate) fn schoolbook_mul(a: &Poly, b: &Poly, ring: &Ring) -> Poly {
    let d = ring.degree();
    let q = NonZero::new(*ring.modulus()).unwrap();
    let mut c = vec![Coeff::ZERO; d];
    for (i, x) in a.coefficients().iter().enumerate() {
        for (j, y) in b.coefficients().iter().enumerate() {
            let product = x.mul_mod(y, &q);
            let k = i + j;
            if k < d {
                c[k] = c[k].add_mod(&product, &q);
            } else {
                c[k - d] = c[k - d].sub_mod(&product, &q);
            }
        }
    }
    Poly::new(c, ring).unwrap()
}
