// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared keys, elements and a small manager that keeps the update log.

pub use crate::rng::rng;
use kln_accumulator::{
    Accumulator, Coefficient, Element, ManagerState, MembershipWitness, Params, ParamsSpec,
    PublicKey, SecretKey, TrapdoorDistribution,
};
use std::sync::{Arc, LazyLock};

/// The toy set.
pub static TOY: LazyLock<Arc<Params>> =
    LazyLock::new(|| Arc::new(Params::toy().expect("test fixture")));

/// A toy-set key from a fixed seed.
pub static KEY: LazyLock<SecretKey> = LazyLock::new(|| {
    SecretKey::new(
        Some(b"kln/test/key, a 32-byte test seed"),
        Arc::clone(&TOY),
        &mut rng(0),
    )
    .expect("test fixture")
});

/// The toy set with deletion bound `γ`.
pub fn with_bound(max_deletions: u64) -> Arc<Params> {
    bounded(max_deletions, TrapdoorDistribution::Gaussian)
}

/// The toy set with deletion bound `γ` and the given trapdoor distribution.
fn bounded(max_deletions: u64, trapdoor: TrapdoorDistribution) -> Arc<Params> {
    Arc::new(
        Params::try_from(ParamsSpec {
            max_deletions,
            trapdoor,
            ..ParamsSpec::TOY
        })
        .expect("test fixture"),
    )
}

/// The fixtures of the tests that run under both trapdoor distributions, Gaussian here.
pub mod gaussian {
    pub use super::{KEY, Manager, TOY, element, rng, with_bound};
}

/// The same fixtures with the ternary trapdoor.
pub mod ternary {
    use super::{Arc, LazyLock, Params, ParamsSpec, SecretKey, TrapdoorDistribution, bounded};
    pub use super::{Manager, element, rng};

    /// The toy set with the ternary trapdoor.
    pub static TOY: LazyLock<Arc<Params>> = LazyLock::new(|| {
        Arc::new(
            Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))
                .expect("test fixture"),
        )
    });

    /// A key at [`TOY`] from a fixed seed.
    pub static KEY: LazyLock<SecretKey> = LazyLock::new(|| {
        SecretKey::new(
            Some(b"kln/test/key, a 32-byte test seed"),
            Arc::clone(&TOY),
            &mut rng(0),
        )
        .expect("test fixture")
    });

    /// [`TOY`] with deletion bound `γ`.
    pub fn with_bound(max_deletions: u64) -> Arc<Params> {
        bounded(max_deletions, TrapdoorDistribution::Ternary)
    }
}

/// The element whose single byte is `i` (`ℓ = 8` at the toy set, so all 256 are distinct).
pub fn element(i: u8) -> Element {
    Element::try_from([i].as_slice()).expect("test fixture")
}

/// An accumulator under one key, with its state and the log of published deletions.
pub struct Manager<'a> {
    pub key: &'a SecretKey,
    pub public: PublicKey,
    pub value: Accumulator,
    pub state: ManagerState,
}

impl<'a> Manager<'a> {
    /// The key's accumulator, empty, at its genesis value.
    pub fn new(key: &'a SecretKey) -> Self {
        let value = Accumulator::new(key);
        Self {
            key,
            public: PublicKey::from(key),
            state: ManagerState::new(key),
            value,
        }
    }

    /// Adds `x` and issues its witness.
    pub fn add(&mut self, x: &Element) -> MembershipWitness {
        self.value
            .add_assign(self.key, x, &mut self.state)
            .expect("test fixture");
        self.witness(x)
    }

    /// Deletes `y` and returns its update message.
    pub fn remove(&mut self, y: &Element) -> Coefficient {
        let mut coefficients = self
            .value
            .update_assign(self.key, &[], std::slice::from_ref(y), &mut self.state)
            .expect("test fixture");
        coefficients.pop().expect("test fixture")
    }

    /// `MemWitCreate` for `x` at the current value.
    pub fn witness(&self, x: &Element) -> MembershipWitness {
        MembershipWitness::new(x, &self.value, self.key, &self.state).expect("test fixture")
    }
}
