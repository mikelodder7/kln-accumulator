// SPDX-License-Identifier: MIT OR Apache-2.0
//! The paper's 128-bit set (`ParamsSpec::PAPER_128`), under both trapdoor distributions:
//! Construction 4.1's lifecycle operations and the trapdoor samplers. Operations take up to
//! about ten seconds each, so this target runs alone.

#[path = "support/base.rs"]
pub mod base;
#[path = "support/common.rs"]
pub mod common;
#[path = "support/harness.rs"]
pub mod harness;
#[path = "support/lifecycle.rs"]
pub mod lifecycle;
#[path = "support/samplers.rs"]
pub mod samplers;
#[path = "support/variant.rs"]
pub mod variant;

use kln_accumulator::ParamsSpec;

fn main() {
    let mut criterion = harness::criterion();
    lifecycle::lifecycle::<base::Base>(&mut criterion, "paper-128", ParamsSpec::PAPER_128, None);
    samplers::samplers(&mut criterion, "paper-128", ParamsSpec::PAPER_128);
    criterion.final_summary();
}
