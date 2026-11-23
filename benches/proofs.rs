// SPDX-License-Identifier: MIT OR Apache-2.0
//! Membership proofs at the toy set, the only set where they run, under both trapdoor
//! distributions: `prove`, `verify`, `verify_with` against a setup the fixture prepares,
//! `MembershipProof::compress` at one, two and three LaBRADOR levels, and verification of each
//! compressed proof.

#[path = "support/base.rs"]
pub mod base;
#[path = "support/common.rs"]
pub mod common;
#[path = "support/harness.rs"]
pub mod harness;
#[path = "support/proving.rs"]
pub mod proving;
#[path = "support/variant.rs"]
pub mod variant;

use common::{Outcome, params, rng};
use harness::bench;
use kln_accumulator::{
    CompressionLevels, ParamsSpec, TrapdoorDistribution, prove, verify, verify_with,
};
use merlin::Transcript;
use proving::{LABEL, LEVELS, Proving};
use std::cell::LazyCell;
use strum::IntoEnumIterator;

fn main() -> Outcome<()> {
    let mut criterion = harness::criterion();
    for trapdoor in TrapdoorDistribution::iter() {
        let fixture = LazyCell::new(move || Proving::new(params(ParamsSpec::TOY, trapdoor)?));
        let mut group = harness::group(&mut criterion, "proof", "toy", trapdoor);
        let mut prover = rng(3);
        bench(
            &mut group,
            "prove",
            &fixture,
            |_| (),
            |p, ()| {
                let linked = &p.linked;
                prove(
                    &linked.statement(),
                    &linked.secret(),
                    &linked.proof_params,
                    &mut Transcript::new(LABEL),
                    &mut prover,
                )
            },
        );
        bench(
            &mut group,
            "verify",
            &fixture,
            |_| (),
            |p, ()| {
                let linked = &p.linked;
                verify(
                    &linked.statement(),
                    &p.proof,
                    &linked.proof_params,
                    &mut Transcript::new(LABEL),
                )
            },
        );
        bench(
            &mut group,
            "verify_prepared",
            &fixture,
            |_| (),
            |p, ()| {
                let linked = &p.linked;
                verify_with(
                    &linked.statement(),
                    &p.proof,
                    &linked.proof_params,
                    &p.setup,
                    &mut Transcript::new(LABEL),
                )
            },
        );
        for (index, levels) in LEVELS.into_iter().enumerate() {
            let compression = CompressionLevels::try_from(levels)?;
            bench(
                &mut group,
                &format!("compress/{levels}"),
                &fixture,
                |_| (),
                |p, ()| {
                    let linked = &p.linked;
                    p.framed.compress(
                        &linked.statement(),
                        &linked.proof_params,
                        &p.challenge,
                        compression,
                    )
                },
            );
            bench(
                &mut group,
                &format!("verify_compressed/{levels}"),
                &fixture,
                |_| (),
                |p, ()| {
                    let linked = &p.linked;
                    p.compressed[index].finalize(
                        &linked.fixture.value,
                        &linked.proof_params,
                        &linked.fixture.public,
                        &p.challenge,
                        &linked.relation,
                    )
                },
            );
        }
        group.finish();
    }
    criterion.final_summary();
    Ok(())
}
