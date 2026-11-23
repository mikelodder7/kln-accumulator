// SPDX-License-Identifier: MIT OR Apache-2.0
//! Construction 4.1 (the crate-root types) at the toy set, under both trapdoor distributions:
//! key generation, public-key derivation, addition, witness issuance and verification,
//! deletion, and witness updates over one deletion and over a batch of eight.

#[path = "support/base.rs"]
pub mod base;
#[path = "support/common.rs"]
pub mod common;
#[path = "support/harness.rs"]
pub mod harness;
#[path = "support/lifecycle.rs"]
pub mod lifecycle;
#[path = "support/variant.rs"]
pub mod variant;

use kln_accumulator::ParamsSpec;

/// Deletions in the batch-update benchmark.
const BATCH: usize = 8;

fn main() {
    let mut criterion = harness::criterion();
    lifecycle::lifecycle::<base::Base>(&mut criterion, "toy", ParamsSpec::TOY, Some(BATCH));
    criterion.final_summary();
}
