// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests of the LNP membership proof of Appendix D.2 through the public API (claims
//! C35, C36, C38 and C44), and of its LaBRADOR compression of Appendix D.3 (C39, C40, C46), at
//! the toy parameter set. A proof takes several seconds there, so the targets share the few
//! proofs the fixtures make.

mod api;
mod compressed;
mod fixture;
#[path = "../support/rng.rs"]
mod rng;
#[path = "../support/serde_formats.rs"]
mod serde_formats;
mod serialization;
mod setup;
mod statement;
