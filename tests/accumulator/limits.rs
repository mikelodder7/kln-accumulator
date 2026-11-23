// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parameter sets named by untrusted bytes: a decoder refuses one beyond the caps, or one whose
//! dimensions overflow, with an error and before any table or large buffer is built.

use kln_accumulator::lattice::Coeff;
use kln_accumulator::{
    Accumulator, Error, MembershipWitness, Params, ParamsSpec, PublicKey, TrapdoorDistribution,
};
use std::time::{Duration, Instant};

/// Both trapdoor distributions of `spec`.
fn both(spec: ParamsSpec) -> [ParamsSpec; 2] {
    [
        TrapdoorDistribution::Gaussian,
        TrapdoorDistribution::Ternary,
    ]
    .map(|trapdoor| spec.with_trapdoor(trapdoor))
}

/// The 64-byte encoding of `spec` followed by `body`.
fn encoding(spec: ParamsSpec, body: &[u8]) -> Vec<u8> {
    let mut bytes = <[u8; ParamsSpec::BYTES]>::from(spec).to_vec();
    bytes.extend_from_slice(body);
    bytes
}

/// The toy set with `d = 2^26` and one body byte, 65 bytes in all, is refused with
/// `DegreeTooLarge` in well under a second. It used to build NTT tables of `2^26` entries per
/// auxiliary prime before any bound was checked: about 10 s and 3.7 GB in release.
#[test]
fn a_huge_degree_is_refused_before_any_table_is_built() {
    let spec = ParamsSpec {
        degree: 1 << 26,
        ..ParamsSpec::TOY
    };
    let bytes = encoding(spec, &[0]);
    assert_eq!(bytes.len(), 65);
    let refused = Err(Error::DegreeTooLarge(1 << 26));
    let start = Instant::now();
    assert_eq!(Accumulator::try_from(bytes.as_slice()).map(drop), refused);
    assert_eq!(PublicKey::try_from(bytes.as_slice()).map(drop), refused);
    assert_eq!(
        MembershipWitness::try_from(bytes.as_slice()).map(drop),
        refused
    );
    assert_eq!(Params::try_from(spec).map(drop), refused);
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_millis(100), "{elapsed:?}");
}

/// The toy set with `n = 2^63`: `n·k = 2^63·10` used to wrap to `m' = 0`, pass `m > m'`, and
/// panic in the bound computation (with overflow checks off) or at the product (on). The 64-byte
/// spec alone is now refused with an error, for both distributions and through every decoder.
#[test]
fn a_rank_whose_gadget_width_overflows_is_refused() {
    for spec in both(ParamsSpec {
        n: 1 << 63,
        ..ParamsSpec::TOY
    }) {
        let bytes = encoding(spec, &[]);
        let refused = Err(Error::WitnessBoundTooLarge);
        assert_eq!(Params::try_from(spec).map(drop), refused);
        assert_eq!(PublicKey::try_from(bytes.as_slice()).map(drop), refused);
        assert_eq!(Accumulator::try_from(bytes.as_slice()).map(drop), refused);
    }
}

/// `d = 1`, the 100-bit modulus of the 128-bit set, `n = 256`, `m = 2^56`, `b = 2`, `ℓ = 1`:
/// `n·m = 2^64` used to wrap, so the set was accepted and an 82 MB body decoded to a public key
/// whose `A` has shape `256 × 2^56` and no entries. The set is now refused from its spec, so
/// no body is needed to show it.
#[test]
fn a_set_whose_key_size_overflows_is_refused() {
    for spec in both(ParamsSpec {
        degree: 1,
        modulus: ParamsSpec::PAPER_128.modulus,
        n: 256,
        m: 1 << 56,
        base: 2,
        element_bits: 1,
        max_deletions: 1 << 32,
        trapdoor: TrapdoorDistribution::Gaussian,
    }) {
        let refused = Err(Error::WitnessBoundTooLarge);
        assert_eq!(Params::try_from(spec).map(drop), refused);
        let bytes = encoding(spec, &[0; 64]);
        assert_eq!(PublicKey::try_from(bytes.as_slice()).map(drop), refused);
    }
}

/// Every defined set is within the caps with room to spare, so the caps refuse nothing a
/// caller of the named sets builds.
#[test]
fn the_defined_sets_are_well_within_the_caps() {
    for spec in [
        ParamsSpec::TOY,
        ParamsSpec::PAPER_128,
        ParamsSpec::SUCCINCT_TOY,
        ParamsSpec::SUCCINCT_128,
    ]
    .into_iter()
    .flat_map(both)
    {
        let params = Params::try_from(spec).unwrap();
        let entries = spec.n * (spec.m + spec.element_bits as usize * params.m_prime());
        assert!(spec.degree * 2 <= ParamsSpec::MAX_DEGREE, "{spec:?}");
        assert!(entries * 16 <= ParamsSpec::MAX_MATRIX_ENTRIES, "{spec:?}");
    }
    // A modulus is not needed to refuse a degree: the cap is checked first.
    let composite = ParamsSpec {
        degree: ParamsSpec::MAX_DEGREE * 2,
        modulus: Coeff::from_u64(21),
        ..ParamsSpec::TOY
    };
    assert_eq!(
        Params::try_from(composite).map(drop),
        Err(Error::DegreeTooLarge(ParamsSpec::MAX_DEGREE * 2))
    );
}
