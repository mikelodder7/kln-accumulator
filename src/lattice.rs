// SPDX-License-Identifier: MIT OR Apache-2.0
//! The lattice building blocks the accumulator is built on.
//!
//! These are the ring `R_q = Z_q[X]/(X^d + 1)` and its coefficients, vectors and matrices over
//! it, the gadget matrix `G` and its decomposition, the gadget trapdoor with its preimage
//! samplers and the seeded uniform sampler, and the homomorphic evaluation of the indicator
//! function. The accumulator API at the crate root is built on them, and most users never need
//! them. The book's chapter "The lattice building blocks" describes each one.

pub use crate::eval::{BitString, Indicator};
pub use crate::gadget::Gadget;
pub use crate::matrix::{NttMatrix, PolyMatrix, Shape};
pub use crate::poly::Poly;
pub use crate::ring::Ring;
pub use crate::sample::{DomainLabel, Seed, UniformSampler};
pub use crate::trapdoor::Trapdoor;
pub use crate::vector::PolyVec;
pub use crate::zq::{CenteredCoeff, Coeff};
