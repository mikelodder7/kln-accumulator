// SPDX-License-Identifier: MIT OR Apache-2.0
//! The lifecycle benchmarks of one variant at one parameter set, under both trapdoor
//! distributions.

use crate::{
    common::{params, rng},
    harness::{bench, group},
    variant::{Fixture, Variant},
};
use criterion::Criterion;
use kln_accumulator::{ParamsSpec, TrapdoorDistribution};
use std::cell::LazyCell;
use strum::IntoEnumIterator;

/// Registers, for each trapdoor distribution, the group `V::NAME/set/trapdoor` with key
/// generation, public-key derivation, one addition, witness issuance, witness verification,
/// one deletion and the witness update for one deletion; with `batch = Some(n)`, also the
/// manager's batch update (`n` deletions and half as many additions in one call) and the
/// witness update over a batch of `n` deletions.
///
/// Additions and deletions run on a fresh copy of the value and state in every iteration:
/// Construction 4.1 never adds or deletes an element twice, and deletions are bounded by `γ`.
pub fn lifecycle<V: Variant>(
    criterion: &mut Criterion,
    set: &str,
    spec: ParamsSpec,
    batch: Option<usize>,
) {
    for trapdoor in TrapdoorDistribution::iter() {
        let fixture =
            LazyCell::new(move || Fixture::<V>::new(params(spec, trapdoor)?, batch.unwrap_or(1)));
        let mut group = group(criterion, V::NAME, set, trapdoor);
        let mut keys = rng(1);
        let fresh_copy = |f: &Fixture<V>| (f.value.clone(), f.state.clone());
        bench(
            &mut group,
            "key_generation",
            &fixture,
            |_| (),
            |f, ()| V::key(&f.params, &mut keys),
        );
        bench(
            &mut group,
            "public_key",
            &fixture,
            |_| (),
            |f, ()| V::public(&f.key),
        );
        bench(
            &mut group,
            "add",
            &fixture,
            fresh_copy,
            |f, (value, state)| V::add(value, &f.key, &f.fresh[0], state),
        );
        bench(
            &mut group,
            "issue_witness",
            &fixture,
            |_| (),
            |f, ()| V::issue(&f.member, &f.value, &f.key, &f.state),
        );
        bench(
            &mut group,
            "verify_witness",
            &fixture,
            |_| (),
            |f, ()| V::verify(&f.witness, &f.member, &f.public, &f.value),
        );
        bench(
            &mut group,
            "delete",
            &fixture,
            fresh_copy,
            |f, (value, state)| V::apply(value, &f.key, &[], &f.deleted[..1], state),
        );
        bench(
            &mut group,
            "update_witness/1",
            &fixture,
            |_| (),
            |f, ()| {
                V::update(
                    &f.witness,
                    &f.member,
                    &f.handles[..1],
                    &f.coefficients[..1],
                    &f.public,
                )
            },
        );
        if let Some(n) = batch {
            bench(
                &mut group,
                &format!("update/{n}"),
                &fixture,
                fresh_copy,
                |f, (value, state)| V::apply(value, &f.key, &f.fresh, &f.deleted, state),
            );
            bench(
                &mut group,
                &format!("update_witness/{n}"),
                &fixture,
                |_| (),
                |f, ()| {
                    V::update(
                        &f.witness,
                        &f.member,
                        &f.handles,
                        &f.coefficients,
                        &f.public,
                    )
                },
            );
        }
        group.finish();
    }
}
