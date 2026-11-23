// SPDX-License-Identifier: MIT OR Apache-2.0
//! The deterministic test RNG shared by the integration test targets, included into each with a
//! `#[path]` attribute.

use rand::{SeedableRng, rngs::StdRng};

/// A deterministic test RNG.
pub fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}
