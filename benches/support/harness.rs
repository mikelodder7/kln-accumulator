// SPDX-License-Identifier: MIT OR Apache-2.0
//! The criterion configuration every benchmark target shares, and the one way benchmarks are
//! registered: against a fixture that is built on first use.

use crate::common::{Outcome, trapdoor_name};
use criterion::{BatchSize, BenchmarkGroup, Criterion, SamplingMode, measurement::WallTime};
use kln_accumulator::TrapdoorDistribution;
use std::{cell::LazyCell, time::Duration};

/// Samples per benchmark: criterion's minimum.
const SAMPLES: usize = 10;

/// Warm-up per benchmark. An operation slower than this still runs once.
const WARM_UP: Duration = Duration::from_secs(1);

/// Measurement time per benchmark. Operations of milliseconds fill it with thousands of
/// iterations; an operation slower than a tenth of it runs once per sample, ten times in all,
/// which is the least criterion allows (it then prints a warning that the time was exceeded).
const MEASUREMENT: Duration = Duration::from_secs(5);

/// A fixture built the first time a benchmark that needs it runs, so that listing benchmarks
/// or filtering them out never generates keys or proofs.
pub type Lazy<F, I> = LazyCell<Outcome<F>, I>;

/// The configuration of every target: [`SAMPLES`] samples, a short warm-up, flat sampling (set
/// per group in [`group`]), no plots, then the command-line arguments.
pub fn criterion() -> Criterion {
    Criterion::default()
        .sample_size(SAMPLES)
        .warm_up_time(WARM_UP)
        .measurement_time(MEASUREMENT)
        .without_plots()
        .configure_from_args()
}

/// The group named `variant/set/trapdoor`, with flat sampling: every sample runs the same
/// number of iterations, which suits operations of seconds.
pub fn group<'c>(
    criterion: &'c mut Criterion,
    variant: &str,
    set: &str,
    trapdoor: TrapdoorDistribution,
) -> BenchmarkGroup<'c, WallTime> {
    let mut group =
        criterion.benchmark_group(format!("{variant}/{set}/{}", trapdoor_name(trapdoor)));
    let _ = group.sampling_mode(SamplingMode::Flat);
    group
}

/// Registers the benchmark `id` in `group`. Each iteration gets a fresh input from `setup`,
/// untimed, and times `routine` on it; the fixture is built, untimed, the first time the
/// benchmark runs. An operation that needs no fresh input takes `|_| ()` as `setup`.
///
/// # Panics
///
/// When the fixture cannot be built: criterion's benchmark closures return nothing, so there
/// is no error to return. Every fixture checks, before any timing, that the operations it
/// benchmarks succeed.
pub fn bench<F, I, O>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    id: &str,
    fixture: &Lazy<F, impl FnOnce() -> Outcome<F>>,
    mut setup: impl FnMut(&F) -> I,
    mut routine: impl FnMut(&F, &mut I) -> O,
) {
    let _ = group.bench_function(id, |bencher| {
        let fixture = LazyCell::force(fixture)
            .as_ref()
            .expect("the benchmark fixture could not be built");
        bencher.iter_batched_ref(
            || setup(fixture),
            |input| routine(fixture, input),
            BatchSize::SmallInput,
        );
    });
}
