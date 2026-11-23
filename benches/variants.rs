// SPDX-License-Identifier: MIT OR Apache-2.0
//! The adaptive variant (Construction 4.2) at the toy set and the `ℓ`-succinct variant at the
//! succinct toy set, under both trapdoor distributions: the same lifecycle operations as
//! Construction 4.1, with the batch update over eight deletions.

#[path = "support/adaptive.rs"]
pub mod adaptive;
#[path = "support/common.rs"]
pub mod common;
#[path = "support/harness.rs"]
pub mod harness;
#[path = "support/lifecycle.rs"]
pub mod lifecycle;
#[path = "support/succinct.rs"]
pub mod succinct;
#[path = "support/variant.rs"]
pub mod variant;

use kln_accumulator::ParamsSpec;

/// Deletions in the batch-update benchmarks; at most `γ = 16` at the succinct toy set.
const BATCH: usize = 8;

fn main() {
    let mut criterion = harness::criterion();
    lifecycle::lifecycle::<adaptive::Adaptive>(&mut criterion, "toy", ParamsSpec::TOY, Some(BATCH));
    lifecycle::lifecycle::<succinct::Succinct>(
        &mut criterion,
        "succinct-toy",
        ParamsSpec::SUCCINCT_TOY,
        Some(BATCH),
    );
    criterion.final_summary();
}
