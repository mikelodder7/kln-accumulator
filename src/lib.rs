// SPDX-License-Identifier: MIT OR Apache-2.0
//! The lattice-based positive dynamic accumulator of ePrint 2025/1099, in pure Rust.
//!
//! A manager holds a [`SecretKey`] and keeps an accumulator value `c` and a [`ManagerState`].
//! Adding an element is free: the value does not change, and the manager issues the element's
//! holder a [`MembershipWitness`]. Deleting an element changes the value and publishes one
//! update message, from which every other holder updates its witness without the secret key.
//! A holder proves membership of a hidden element in zero knowledge with [`prove`]. The API
//! mirrors the vb20 pairing accumulator, with the same type and method names.
//!
//! **Status.** This is a research implementation: it is not audited and not constant time,
//! the preimage sampler's floating-point loss is measured rather than proven, and the concrete
//! security of the proofs after Fiat–Shamir is cited rather than derived. The toy parameter
//! sets give no security. [`ParamsSpec::PAPER_128`] is the 128-bit shape of the paper's
//! Table 2; the 128-bit label is the paper's, and the crate does not estimate the hardness of
//! the lattice problems at it. Membership proofs run only at the toy sets. The `README.md` at
//! the repository root states what is and is not established.
//!
//! # Quick start
//!
//! The manager adds two elements and issues a witness; the holder verifies it, and after the
//! manager deletes the other element, updates it from the published message alone.
//!
//! ```
//! use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
//! use kln_accumulator::{PublicKey, SecretKey};
//! use rand::{SeedableRng, rngs::StdRng};
//! use std::sync::Arc;
//!
//! let mut rng = StdRng::seed_from_u64(0);
//! let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
//! let pk = PublicKey::from(&key);
//! let mut acc = Accumulator::new(&key);
//! let mut state = ManagerState::new(&key);
//! let (x, y) = (Element::hash(b"x", key.params()), Element::hash(b"y", key.params()));
//! acc.add_elements_assign(&key, &[x.clone(), y.clone()], &mut state)?;
//! let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
//! assert!(witness.verify(&x, &pk, &acc));
//!
//! let (new_acc, coefficients) = acc.update(&key, &[], &[y.clone()], &mut state)?;
//! let witness = witness.batch_update(&x, &[], &[y], &coefficients, &pk)?;
//! assert!(witness.verify(&x, &pk, &new_acc));
//! # Ok::<(), kln_accumulator::Error>(())
//! ```
//!
//! The programs in `examples/` run the whole lifecycle of each variant and print each step:
//! `cargo run --release --example base`, `adaptive` or `succinct`.
//!
//! # The public surface
//!
//! - **Construction 4.1, at the crate root.** [`SecretKey`] and [`PublicKey`], the value
//!   [`Accumulator`] with its [`ManagerState`], [`Element`] and the update message
//!   [`Coefficient`], and for holders [`MembershipWitness`], [`Delta`] and [`evaluate_delta`].
//! - **Parameters.** A [`Params`] is built from a [`ParamsSpec`] and owns the ring, the
//!   gadget and the [`Bounds`]; the [`TrapdoorDistribution`] is part of the set.
//! - **[`adaptive`]**, Construction 4.2: accepts an element again after its deletion, by
//!   accumulating a fresh PRF handle per addition and signing it with ML-DSA-65.
//! - **[`succinct`]**, the `ℓ`-succinct variant of Section 4: witnesses of `m + m'` entries
//!   instead of `m + ℓm'`, at the price of a far larger public key.
//! - **Membership proofs** of Appendix D.2: [`prove`] and [`verify`], the vb20 three-step form
//!   [`MembershipProofCommitting`], [`MembershipProof`] and [`MembershipProofFinal`], and
//!   [`CompressedMembershipProof`] (LaBRADOR, Appendix D.3). A [`ProofSetup`] expands the
//!   commitment key of about 160 MB once for [`prove_with`], [`verify_with`] and the other
//!   `_with` operations.
//! - **[`lattice`]**: the ring, vectors and matrices over it, the gadget, the trapdoor with its
//!   preimage samplers, and indicator evaluation. Most users never need them.
//! - **[`Error`]**: one error type for the whole crate.
//!
//! The variants carry the same type and method names as the crate root.
//!
//! # Parameter sets
//!
//! | set | use | `d` | `q` | `ℓ` | `γ` | witness norm bound |
//! |---|---|---|---|---|---|---|
//! | [`ParamsSpec::TOY`] | tests, examples, proofs | 64 | 60-bit | 8 | 256 | `β = 2^41.68` |
//! | [`ParamsSpec::PAPER_128`] | the 128-bit shape of Table 2 | 4096 | 100-bit | 32 | `2^32` | `β = 2^87.66` |
//! | [`ParamsSpec::SUCCINCT_TOY`] | tests of [`crate::succinct`] | 64 | 90-bit | 4 | 16 | `β_succ = 2^79.70` |
//! | [`ParamsSpec::SUCCINCT_128`] | the succinct 128-bit shape | 4096 | 162-bit | 32 | `2^32` | `β_succ = 2^138.25` |
//!
//! The toy sets exist so that tests and examples run in seconds. The 128-bit set runs every
//! accumulator operation, at seconds per witness. Key generation at
//! [`ParamsSpec::SUCCINCT_128`] would build a public key of about 110 GiB and is not practical.
//! [`TrapdoorDistribution::Gaussian`] is the default and the paper's Theorem 2.1;
//! [`TrapdoorDistribution::Ternary`] narrows the preimage sampler's least width, at the cost of
//! an assumption: `A` is then only pseudorandom, under Module-LWE with ternary secrets.
//!
//! # Security in brief
//!
//! Each point below is argued in the book's chapter "Guarantees and their limits"
//! (`book/src/security.md`). Where the code departs from the paper:
//!
//! - A witness is sampled for the genesis value `c₀` with randomness `F_k(x)`, not for the value
//!   at the epoch of its addition, so no state, forked or rolled back, makes the key sample twice.
//! - The genesis value is derived from the key, so a key keeps exactly one accumulator.
//! - In [`adaptive`], the inner witness for a handle depends on the handle alone.
//! - The paper's errata are corrected in the code, each cited where it applies.
//!
//! What is not established, or not covered:
//!
//! - The manager is trusted; nothing protects holders or verifiers from it.
//! - Only a few steps are written to run in time independent of secrets; the rest is not.
//! - The preimage sampler's floating-point loss is measured in tests, not bounded by proof.
//! - Determinism across platforms assumes IEEE-754 binary64 without x87 extended precision.
//! - Fiat–Shamir concrete security of the proofs is cited, not derived.
//! - Module-SIS ranks in the proof layers come from a root-Hermite-factor rule.
//! - Membership proofs run only at ring degree 64, that is at the toy sets.
//! - The manager-state tag does not detect rollback to an older state the key once tagged.
//! - The paper states no separate security theorem for the succinct variant.
//!
//! # Secret handling
//!
//! Every public type's documentation says whether it is secret (owner only), holder-private
//! (a witness: private to its holder and used in proofs) or public. Secret and holder-private
//! values are overwritten when dropped (`zeroize::ZeroizeOnDrop`), are not `Copy`, print no
//! secret through `Debug`, and are encoded into and decoded from buffers that are overwritten
//! when dropped. Inside the crate every intermediate that depends on a secret is wiped on every
//! return path, including the SHAKE256 state that absorbed one. Copies outside the crate's
//! reach, such as the output of a serializer the caller runs, are the caller's to wipe.
//!
//! # Where to read more
//!
//! The book under `book/` (`mdbook build book`) explains every public type, and its examples
//! run as doc tests of this crate:
//!
//! - "Getting started", then "Parameter sets and trapdoor distributions", "Keys", "Elements
//!   and the accumulator value", "Manager state and its tag" and "Witnesses and updates";
//! - "The adaptive variant", "The succinct variant" and "Membership proofs";
//! - "Serialization", "Errors" and "The lattice building blocks";
//! - "Guarantees and their limits" and "Misuse: what the code refuses and what it leaves to
//!   you";
//! - "Benchmarks and sizes", and "Correspondence with the vb20 pairing accumulator", which maps
//!   every public item of the vb20 pairing accumulator to its counterpart here.
//!
//! The `README.md` summarises the status and the variants and lists the examples, and
//! `cargo bench` runs the benchmarks that the book's benchmarks chapter records.

#![forbid(unsafe_code)]

/// The README's examples, compiled and run as doc tests so that they cannot fall out of date.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// The book's "Your first accumulator" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/tutorial.md")]
struct BookTutorialDoctests;

/// The book's "Which variant and which settings" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/choosing.md")]
struct BookChoosingDoctests;

/// The book's "How do I…" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/recipes.md")]
struct BookRecipesDoctests;

/// The book's "Deploying it" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/deploying.md")]
struct BookDeployingDoctests;

/// The book's "Troubleshooting" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/troubleshooting.md")]
struct BookTroubleshootingDoctests;

/// The book's "Getting started" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/getting-started.md")]
struct BookGettingStartedDoctests;

/// The book's "Parameter sets and trapdoor distributions" chapter, compiled and run as doc
/// tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/parameters.md")]
struct BookParametersDoctests;

/// The book's "Keys" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/keys.md")]
struct BookKeysDoctests;

/// The book's "Elements and the accumulator value" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/elements.md")]
struct BookElementsDoctests;

/// The book's "Manager state and its tag" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/state.md")]
struct BookStateDoctests;

/// The book's "Witnesses and updates" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/witnesses.md")]
struct BookWitnessesDoctests;

/// The book's "The adaptive variant" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/adaptive.md")]
struct BookAdaptiveDoctests;

/// The book's "The succinct variant" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/succinct.md")]
struct BookSuccinctDoctests;

/// The book's "Membership proofs" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/proofs.md")]
struct BookProofsDoctests;

/// The book's "Serialization" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/serialization.md")]
struct BookSerializationDoctests;

/// The book's "Errors" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/errors.md")]
struct BookErrorsDoctests;

/// The book's "The lattice building blocks" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/lattice.md")]
struct BookLatticeDoctests;

/// The book's "Misuse" chapter, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../book/src/misuse.md")]
struct BookMisuseDoctests;

mod accumulator;
pub mod adaptive;
mod error;
mod eval;
mod gadget;
mod gaussian;
mod key;
pub mod lattice;
mod matrix;
mod packing;
mod params;
mod poly;
mod preimage;
mod proof;
mod ring;
mod sample;
mod secret_hex;
mod state;
pub mod succinct;
#[cfg(test)]
mod test_util;
mod trapdoor;
mod vector;
#[cfg(test)]
mod wiping;
mod witness;
mod zq;

pub use accumulator::{Accumulator, Coefficient, Element};
pub use error::{Error, Result};
pub use key::{MIN_SEED_BYTES, PublicKey, SecretKey};
pub use params::{Bounds, Params, ParamsSpec, TrapdoorDistribution};
pub use proof::{
    Challenge, CompressedMembershipProof, CompressionLevels, LinkingOpening, LinkingRelation,
    LnpParameters, MembershipProof, MembershipProofCommitting, MembershipProofFinal,
    MembershipSecret, MembershipStatement, ProofParams, ProofSetup, SubringMap, prove, prove_with,
    verify, verify_with,
};
pub use state::{ManagerState, Operation, Record};
pub use witness::{Delta, MembershipWitness, evaluate_delta, evaluate_deltas};
