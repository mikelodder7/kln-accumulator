// SPDX-License-Identifier: MIT OR Apache-2.0
//! The trapdoor samplers on their own: `TrapGen`, `SamplePre` and `SampleLeft`.

use crate::{
    common::{Outcome, params},
    harness::{bench, group},
};
use criterion::Criterion;
use kln_accumulator::lattice::{
    DomainLabel, PolyMatrix, PolyVec, Seed, Shape, Trapdoor, UniformSampler,
};
use kln_accumulator::{Params, ParamsSpec, TrapdoorDistribution};
use std::{cell::LazyCell, sync::Arc};
use strum::IntoEnumIterator;

/// A trapdoor with targets for both samplers.
#[derive(Debug)]
pub struct Sampling {
    /// The parameter set.
    pub params: Arc<Params>,
    /// The seed `TrapGen` runs from, and the samplers' randomness.
    pub seed: Seed,
    /// `A = [Ā | G − Ā·T_A]`.
    pub a: PolyMatrix,
    /// `T_A`.
    pub trapdoor: Trapdoor,
    /// A uniform target for `SamplePre` under `A`.
    pub u: PolyVec,
    /// `H = [A | B']` with `B'` uniform of `ℓm'` columns, the width of the matrix whose
    /// preimage witness issuance samples.
    pub h: PolyMatrix,
    /// A uniform target for `SampleLeft` under `H`.
    pub c: PolyVec,
}

impl Sampling {
    /// Generates the trapdoor and the targets, and checks one preimage from each sampler.
    ///
    /// # Errors
    ///
    /// As [`Trapdoor::generate`], [`Trapdoor::sample_pre`] and [`Trapdoor::sample_left`], or
    /// a preimage that misses its target.
    pub fn new(params: Arc<Params>) -> Outcome<Self> {
        let ring = params.ring();
        let n = params.spec().n;
        let seed = Seed::from([1; 32]);
        let (a, trapdoor) = Trapdoor::generate(&params, &seed)?;
        let mut uniform = UniformSampler::new(
            &Seed::from([2; 32]),
            DomainLabel::from(&b"kln/bench/samplers"[..]),
        );
        let u = uniform.vector(n, ring);
        let cols = params.spec().element_bits as usize * params.m_prime();
        let h = a.hconcat(&uniform.matrix(Shape { rows: n, cols }, ring))?;
        let c = uniform.vector(n, ring);
        if a.mul_vec(&trapdoor.sample_pre(&params, &a, &u, &seed)?, ring)? != u {
            return Err("SamplePre missed its target".into());
        }
        if h.mul_vec(&trapdoor.sample_left(&params, &h, &c, &seed)?, ring)? != c {
            return Err("SampleLeft missed its target".into());
        }
        Ok(Self {
            params,
            seed,
            a,
            trapdoor,
            u,
            h,
            c,
        })
    }
}

/// Registers, for each trapdoor distribution, the group `samplers/set/trapdoor` with
/// `TrapGen` ([`Trapdoor::generate`]), `SamplePre` ([`Trapdoor::sample_pre`]) and `SampleLeft`
/// ([`Trapdoor::sample_left`]) over `ℓm'` extra columns.
pub fn samplers(criterion: &mut Criterion, set: &str, spec: ParamsSpec) {
    for trapdoor in TrapdoorDistribution::iter() {
        let fixture = LazyCell::new(move || Sampling::new(params(spec, trapdoor)?));
        let mut group = group(criterion, "samplers", set, trapdoor);
        bench(
            &mut group,
            "trapdoor_generate",
            &fixture,
            |_| (),
            |f, ()| Trapdoor::generate(&f.params, &f.seed),
        );
        bench(
            &mut group,
            "sample_pre",
            &fixture,
            |_| (),
            |f, ()| f.trapdoor.sample_pre(&f.params, &f.a, &f.u, &f.seed),
        );
        bench(
            &mut group,
            "sample_left",
            &fixture,
            |_| (),
            |f, ()| f.trapdoor.sample_left(&f.params, &f.h, &f.c, &f.seed),
        );
        group.finish();
    }
}
