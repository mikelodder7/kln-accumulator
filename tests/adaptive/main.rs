// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests of the adaptive accumulator of Construction 4.2 (claims C27–C30, C51 and
//! C68–C71), at the toy parameter set; the lifecycle runs with each trapdoor distribution.

mod binding;
mod fixture;
mod genesis;
mod handles;
mod keys;
#[path = "../support/rng.rs"]
mod rng;
#[path = "../support/serde_formats.rs"]
mod serde_formats;
mod serialization;
mod state_tag;

/// Keys, additions, deletions, re-additions and witness updates of the adaptive accumulator (C27,
/// C28, C30). With the default Gaussian trapdoor. The tests of `lifecycle.rs` are included rather
/// than declared as a module, so that one file serves both distributions.
mod gaussian {
    use crate::fixture::gaussian as fixture;
    include!("lifecycle.rs");
}

/// The tests of `lifecycle.rs` with the ternary trapdoor.
mod ternary {
    use crate::fixture::ternary as fixture;
    include!("lifecycle.rs");
}
