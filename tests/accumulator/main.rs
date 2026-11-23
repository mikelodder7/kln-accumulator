// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests of Construction 4.1 through the vb20-shaped API (claims C16–C26, C51 and
//! C68–C71), at the toy parameter set; the lifecycle runs with each trapdoor distribution.

mod fixture;
mod genesis;
mod keys;
mod limits;
mod norm;
#[path = "../support/rng.rs"]
mod rng;
#[path = "../support/serde_formats.rs"]
mod serde_formats;
mod serialization;
mod state_tag;

/// Keys, additions, deletions and witness updates (C16–C22, C24). With the default Gaussian
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
