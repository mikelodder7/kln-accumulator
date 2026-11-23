// SPDX-License-Identifier: MIT OR Apache-2.0
//! Witness and public-key sizes of the succinct variant against the base scheme (C33), and its
//! bounds at both succinct sets.

use crate::fixture::{KEY, Manager, SET, element, log2, rng};
use kln_accumulator::lattice::Coeff;
use kln_accumulator::{
    Accumulator, ManagerState, MembershipWitness as BaseWitness, Params, ParamsSpec,
    SecretKey as BaseKey, succinct::Bounds,
};
use std::sync::Arc;

/// C33: at the same `(d, q, ℓ)`, the succinct witness (`m + m'` polynomials) is smaller than
/// the base witness (`m + ℓm'`) by the predicted factor `(m + m')/(m + ℓm')`, within 5%, both
/// in the byte encoding and in postcard, once each count is weighted by the packed width of its
/// coefficients, `⌈log₂(2β + 1)⌉` with `β_succ` for the succinct witness and `β₀` for the base
/// one (Table 2's accounting). At this set `β_succ ≈ 2^78` against `β₀ ≈ 2^38`, so the wider
/// coefficients cancel the halving of the count.
#[test]
fn succinct_witness_size_matches_the_width_weighted_prediction() {
    let params = &**SET;
    let (m, mp) = (params.spec().m, params.m_prime());
    let ell = params.spec().element_bits as usize;
    let base_key = BaseKey::new(
        Some(b"kln/test/c33-base, a 32-byte seed"),
        Arc::clone(&SET),
        &mut rng(0),
    )
    .unwrap();
    let mut value = Accumulator::new(&base_key);
    let mut state = ManagerState::new(&base_key);
    let x = element(3);
    value.add_assign(&base_key, &x, &mut state).unwrap();
    let base = BaseWitness::new(&x, &value, &base_key, &state).unwrap();
    assert!(base.verify(&x, &kln_accumulator::PublicKey::from(&base_key), &value));

    let mut manager = Manager::new(&KEY);
    let succinct = manager.add(&x);
    let succinct_width = short_width(&Bounds::try_from(params).unwrap().witness);
    let base_width = short_width(&params.bounds().witness);
    let predicted = ((m + mp) * succinct_width) as f64 / ((m + ell * mp) * base_width) as f64;
    for (format, base_size, succinct_size) in [
        (
            "to_bytes",
            base.to_bytes().unwrap().len(),
            succinct.to_bytes().unwrap().len(),
        ),
        (
            "postcard",
            postcard::to_stdvec(&base).unwrap().len(),
            postcard::to_stdvec(&succinct).unwrap().len(),
        ),
    ] {
        let ratio = succinct_size as f64 / base_size as f64;
        eprintln!(
            "C33 {format}: base witness {base_size} bytes ({} polynomials), succinct witness \
             {succinct_size} bytes ({} polynomials), ratio {ratio:.4}, predicted \
             (m + m')·{succinct_width}/((m + ℓm')·{base_width}) = {predicted:.4}",
            m + ell * mp,
            m + mp
        );
        assert!((ratio / predicted - 1.0).abs() < 0.05, "{format}: {ratio}");
    }
}

/// `⌈log₂(2β + 1)⌉`, the packed width of a coefficient of magnitude at most `β`.
fn short_width(bound: &Coeff) -> usize {
    bound.wrapping_add(bound).bit_width_vartime() as usize
}

/// The polynomials in `pp = (A, B₁, W, T₀, T₁, u)` at `spec`: the uniform ones `(A, B₁, W, u)`
/// and those of `T = [T₀; T₁]`, where `T₀` alone is a dense `ℓm × ℓm'` matrix.
struct PublicPolynomials {
    uniform: usize,
    trapdoor: usize,
    t0: usize,
}

fn public_polynomials(params: &Params) -> PublicPolynomials {
    let ParamsSpec { n, m, .. } = *params.spec();
    let (mp, ell) = (params.m_prime(), params.spec().element_bits as usize);
    let t0 = ell * m * ell * mp;
    PublicPolynomials {
        uniform: n * m + n * mp + n * ell * mp + n,
        trapdoor: t0 + mp * ell * mp,
        t0,
    }
}

/// The succinct bounds and public-key sizes at both succinct sets, checked against `2β < q`;
/// at the toy set the predicted size is the measured one. The 128-bit shape is evaluated only
/// for its parameters: its `T₀` alone would take hundreds of gigabytes.
#[test]
fn bounds_and_public_key_sizes_at_both_sets() {
    let measured = KEY.to_bytes().len();
    let public = kln_accumulator::succinct::PublicKey::from(&*KEY)
        .to_bytes()
        .len();
    for (name, params) in [
        ("succinct toy", Params::succinct_toy().unwrap()),
        ("succinct 128", Params::succinct_128().unwrap()),
    ] {
        let bounds = Bounds::try_from(&params).unwrap();
        let q = params.ring().modulus();
        assert!(log2(&bounds.witness) + 1.0 < log2(q));
        let polys = public_polynomials(&params);
        let d = params.ring().degree();
        let uniform_width = q.wrapping_sub(&Coeff::ONE).bit_width_vartime() as usize;
        let trapdoor_width = short_width(&bounds.trapdoor_entry);
        let packed = ParamsSpec::BYTES
            + (polys.uniform * d * uniform_width).div_ceil(8)
            + (polys.trapdoor * d * trapdoor_width).div_ceil(8);
        let spec = params.spec();
        // The paper's lower bound on the width of T for the ℓ-succinct assumption.
        let paper_width = 2.0
            * params.ring().degree() as f64
            * 2f64.powf(
                log2(q)
                    * (spec.n as f64 / spec.m as f64
                        + 2.0 / (params.ring().degree() * spec.m) as f64),
            );
        eprintln!(
            "{name}: q = 2^{:.2}, β₀ = 2^{:.2}, ς = 2^{:.2} (paper needs ς > 2^{:.2}), \
             τ = 2^{:.2}, β_succ = 2^{:.2}; pp has {} polynomials, {} of them in T₀ ({} × {}); \
             packed at {uniform_width} bits per uniform and {trapdoor_width} per T coefficient \
             it is {packed} bytes ({:.1} MiB), of which (A, B₁, W, u) is {:.1} MiB",
            log2(q),
            log2(&params.bounds().witness),
            log2(&bounds.trapdoor_width),
            paper_width.log2(),
            log2(&bounds.column),
            log2(&bounds.witness),
            polys.uniform + polys.trapdoor,
            polys.t0,
            spec.element_bits as usize * spec.m,
            spec.element_bits as usize * params.m_prime(),
            packed as f64 / f64::from(1 << 20),
            (polys.uniform * d * uniform_width) as f64 / 8.0 / f64::from(1 << 20),
        );
        if name == "succinct toy" {
            assert_eq!(public, packed);
        }
    }
    assert_eq!(measured, ParamsSpec::BYTES + 32);
}
