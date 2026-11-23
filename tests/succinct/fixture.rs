// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared keys, elements, a small manager and matrix helpers for the succinct variant.

pub use crate::rng::rng;
use kln_accumulator::lattice::{Coeff, PolyMatrix, PolyVec, Shape};
use kln_accumulator::{
    Accumulator, Element, ManagerState, Params, ParamsSpec, TrapdoorDistribution,
    succinct::{MembershipWitness, PublicKey, SecretKey},
};
use std::sync::{Arc, LazyLock};

/// The succinct toy set.
pub static SET: LazyLock<Arc<Params>> =
    LazyLock::new(|| Arc::new(Params::succinct_toy().expect("test fixture")));

/// A succinct key at the succinct toy set, from a fixed seed.
pub static KEY: LazyLock<SecretKey> = LazyLock::new(|| {
    SecretKey::new(
        Some(b"kln/test/succinct-key, a 32-byte seed"),
        Arc::clone(&SET),
        &mut rng(0),
    )
    .expect("test fixture")
});

/// The fixtures of the tests that run under both trapdoor distributions, Gaussian here.
pub mod gaussian {
    pub use super::{KEY, Manager, SET, build, element, log2};
}

/// The same fixtures with the ternary trapdoor.
pub mod ternary {
    use super::{Arc, LazyLock, Params, ParamsSpec, SecretKey, TrapdoorDistribution, rng};
    pub use super::{Manager, build, element, log2};

    /// The succinct toy set with the ternary trapdoor.
    pub static SET: LazyLock<Arc<Params>> = LazyLock::new(|| {
        Arc::new(
            Params::try_from(ParamsSpec::SUCCINCT_TOY.with_trapdoor(TrapdoorDistribution::Ternary))
                .expect("test fixture"),
        )
    });

    /// A succinct key at [`SET`] from a fixed seed.
    pub static KEY: LazyLock<SecretKey> = LazyLock::new(|| {
        SecretKey::new(
            Some(b"kln/test/succinct-key, a 32-byte seed"),
            Arc::clone(&SET),
            &mut rng(0),
        )
        .expect("test fixture")
    });
}

/// The element whose single byte is `i < 16` (`ℓ = 4` at the succinct toy set).
pub fn element(i: u8) -> Element {
    Element::try_from([i].as_slice()).expect("test fixture")
}

/// `log₂` of a coefficient, for printing.
pub fn log2(value: &Coeff) -> f64 {
    value
        .as_words()
        .iter()
        .rev()
        .fold(0.0, |acc, &w| acc * 2f64.powi(64) + w as f64)
        .log2()
}

/// An accumulator under the succinct key: the base value and state, with succinct witnesses.
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

    /// Adds `x` and issues its succinct witness.
    pub fn add(&mut self, x: &Element) -> MembershipWitness {
        self.value
            .add_assign(self.key, x, &mut self.state)
            .expect("test fixture");
        self.witness(x)
    }

    /// `MemWitCreate` for `x` at the current value.
    pub fn witness(&self, x: &Element) -> MembershipWitness {
        MembershipWitness::new(x, &self.value, self.key, &self.state).expect("test fixture")
    }
}

/// The matrix with the given shape whose entry `(r, c)` is `entry(r, c)`.
pub fn build(
    shape: Shape,
    entry: impl Fn(usize, usize) -> kln_accumulator::lattice::Poly,
) -> PolyMatrix {
    let entries = (0..shape.rows)
        .flat_map(|r| (0..shape.cols).map(move |c| (r, c)))
        .map(|(r, c)| entry(r, c))
        .collect();
    PolyMatrix::new(shape, entries).expect("test fixture")
}

/// `I_ℓ ⊗ M`.
pub fn block_diagonal(m: &PolyMatrix, ell: usize, params: &Params) -> PolyMatrix {
    let Shape { rows, cols } = m.shape();
    let zero = kln_accumulator::lattice::Poly::zero(params.ring());
    build(
        Shape {
            rows: ell * rows,
            cols: ell * cols,
        },
        |r, c| {
            if r / rows == c / cols {
                m.get(r % rows, c % cols).expect("test fixture").clone()
            } else {
                zero.clone()
            }
        },
    )
}

/// `[top; bottom]`.
pub fn stack(top: &PolyMatrix, bottom: &PolyMatrix) -> PolyMatrix {
    let (t, b) = (top.shape(), bottom.shape());
    assert_eq!(t.cols, b.cols);
    build(
        Shape {
            rows: t.rows + b.rows,
            cols: t.cols,
        },
        |r, c| {
            if r < t.rows {
                top.get(r, c)
            } else {
                bottom.get(r - t.rows, c)
            }
            .expect("test fixture")
            .clone()
        },
    )
}

/// Column `c` of `m`.
pub fn column(m: &PolyMatrix, c: usize) -> PolyVec {
    (0..m.shape().rows)
        .map(|r| m.get(r, c).expect("test fixture").clone())
        .collect()
}
