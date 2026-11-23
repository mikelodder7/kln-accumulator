// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests of the `ℓ`-succinct variant (claims C31–C33, C51 and C68–C71), at the
//! succinct toy set; the lifecycle runs with each trapdoor distribution.

mod fixture;
mod genesis;
mod keys;
#[path = "../support/rng.rs"]
mod rng;
#[path = "../support/serde_formats.rs"]
mod serde_formats;
mod serialization;
mod size;
mod state_tag;

/// Add, delete, update and verify for the succinct variant (C32). With the default Gaussian
/// trapdoor. The tests of `lifecycle.rs` are included rather than declared as a module, so that one
/// file serves both distributions.
mod gaussian {
    use crate::fixture::gaussian as fixture;
    include!("lifecycle.rs");
}

/// The tests of `lifecycle.rs` with the ternary trapdoor.
mod ternary {
    use crate::fixture::ternary as fixture;
    include!("lifecycle.rs");
}
