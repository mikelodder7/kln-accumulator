// SPDX-License-Identifier: MIT OR Apache-2.0
//! The trapdoor samplers on their own at the toy set, under both trapdoor distributions:
//! `TrapGen`, `SamplePre` and `SampleLeft`. The 128-bit samplers are in the `paper_128` target.

#[path = "support/common.rs"]
pub mod common;
#[path = "support/harness.rs"]
pub mod harness;
#[path = "support/samplers.rs"]
pub mod samplers;

use kln_accumulator::ParamsSpec;

fn main() {
    let mut criterion = harness::criterion();
    samplers::samplers(&mut criterion, "toy", ParamsSpec::TOY);
    criterion.final_summary();
}
