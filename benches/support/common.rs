// SPDX-License-Identifier: MIT OR Apache-2.0
//! What every benchmark target and the size report share: the error type, parameter sets
//! under a chosen trapdoor distribution, deterministic randomness and base elements.

use kln_accumulator::{Element, Params, ParamsSpec, TrapdoorDistribution};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// The result of building a fixture or running a target: any error, boxed.
pub type Outcome<T> = Result<T, Box<dyn std::error::Error>>;

/// The parameter set `spec` with its trapdoor drawn from `trapdoor`.
///
/// # Errors
///
/// As [`Params::try_from`], when the set is refused under that distribution.
pub fn params(spec: ParamsSpec, trapdoor: TrapdoorDistribution) -> Outcome<Arc<Params>> {
    Ok(Arc::new(Params::try_from(spec.with_trapdoor(trapdoor))?))
}

/// The lowercase name of a trapdoor distribution, as benchmark IDs and the size report print
/// it.
pub fn trapdoor_name(trapdoor: TrapdoorDistribution) -> String {
    format!("{trapdoor:?}").to_lowercase()
}

/// A deterministic RNG, so that every run benchmarks the same keys and values.
pub fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// The base element whose first byte is `index` and whose other `⌈ℓ/8⌉ − 1` bytes are zero.
/// Distinct indices give distinct elements of every named set, since each has `ℓ ≥ 4`.
///
/// # Errors
///
/// [`kln_accumulator::Error::InvalidElement`] when `index` does not fit in `ℓ` bits.
pub fn base_element(index: u8, params: &Params) -> Outcome<Element> {
    let mut bytes = vec![0u8; (params.spec().element_bits as usize).div_ceil(8)];
    if let Some(first) = bytes.first_mut() {
        *first = index;
    }
    let element = Element::try_from(bytes.as_slice())?;
    element.validate(params)?;
    Ok(element)
}
