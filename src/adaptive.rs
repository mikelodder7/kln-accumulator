// SPDX-License-Identifier: MIT OR Apache-2.0
//! The adaptively secure accumulator of Construction 4.2 (ePrint 2025/1099): the compiler of the
//! work titled "Accumulators with applications to anonymity-preserving revocation" (EuroS&P
//! 2017), cited by ePrint 2025/1099, applied to the replacement-free accumulator of
//! Construction 4.1, with ML-DSA as the signature `Σ`.
//!
//! Adding `x ∈ V` derives a handle `r_x = F_k(x, i) ∈ {0, 1}^ℓ` with a SHAKE256 PRF, adds `r_x`
//! to the inner accumulator and signs `(x, r_x)`; the witness is `(r_x, σ_x, w̃)`, with `w̃` the
//! inner witness for `r_x`. Deleting `x` deletes `r_x` from the inner accumulator, and the
//! published update message is the inner one: it names the handle, never `x`. Verification
//! checks the signature over `(x, r_x)` and the inner witness for `r_x`.
//!
//! # Handles
//!
//! The index `i` starts at 0 for an element never added, and at `j + 1` for one whose last
//! handle was drawn at index `j` and deleted; it is incremented while the inner accumulator has
//! already seen the handle, live or deleted, or an earlier addition of the same batch took it
//! (Add step 3). So handles are never reused and Construction 4.1 stays replacement-free, and
//! no addition is refused for a collision.
//!
//! Which index an element gets therefore depends on the order of additions: when two
//! elements' first handles collide, the one added first takes it and the other moves on. A
//! fork that adds them in the other order gives each element a different live handle than the
//! original did. That is a matter of reproducibility, not a leak: the inner witness for a
//! handle is sampled for the inner key's genesis value with randomness derived from the handle
//! alone and corrected for the deleted handles, so whichever element holds a handle, on the
//! original, a fork or a rebuilt state, the key samples one preimage for it. The signature is
//! deterministic, so the same element and handle give the same signature. A lost state is
//! rebuilt from the published log of deleted handles and the manager's records of its members
//! as (element, handle) pairs ([`ManagerState::rebuild`]); every holder carries its handle in
//! its witness, so the records can be collected from the holders if the manager lost them.
//!
//! The types carry the names and method names of the base types, so that code written against
//! one reads the same against the other: [`SecretKey`], [`PublicKey`], [`Element`],
//! [`Accumulator`], [`ManagerState`] and [`MembershipWitness`]. The update message
//! [`Coefficient`], the per-holder [`Delta`] and the state [`Record`] are the base types,
//! re-exported here. A holder computes its [`Delta`] with [`crate::evaluate_delta`] for its
//! handle ([`MembershipWitness::handle`]) under [`PublicKey::inner`].
//!
//! - The domain `V` is `{0, 1}^256`: an [`Element`] is 32 bytes, hashed from arbitrary data by
//!   [`Element::hash`] as the base `Element::hash` does. It does not depend on the parameter
//!   set.
//! - `Σ` is ML-DSA-65 (FIPS 204, NIST category 3), the parameter set the `ml-dsa` crate
//!   recommends, in its deterministic variant with an empty context string. The signed message
//!   is `kln/adaptive/sign ‖ x ‖ r_x`; `x` has a fixed length and `r_x` has `⌈ℓ/8⌉` bytes at
//!   the key's set, so the encoding is injective. Signing is deterministic, so
//!   [`MembershipWitness::new`] returns the same witness for the same history.
//! - Keys are a function of the parameter set and a 32-byte root seed, as in the base. The
//!   ML-DSA seed `ξ`, the root seed of the inner key, the PRF key `k` and the state-tag key are
//!   SHAKE256, under four labels, of a hash of the root seed and the 64-byte encoded set, so
//!   one root seed under two sets gives unrelated keys; the ML-DSA key pair is
//!   `ML-DSA.KeyGen_internal(ξ)`.
//! - A handle has `ℓ` bits, so at most `2^ℓ` additions, counting re-additions, are possible
//!   over the life of an accumulator; the next one fails with
//!   [`crate::Error::HandleSpaceExhausted`]. At the toy set `ℓ = 8`, so handles collide often
//!   and the counter loop runs in ordinary use.
//!
//! # Why use it
//!
//! The base accumulator never accepts an element again once it was added (Remark 4.2): a
//! revoked credential handle stays revoked. Here an element may be deleted and added again;
//! each time it gets a fresh handle, so the inner accumulator still sees every value once. The
//! price is a signature per witness (3309 bytes), an ML-DSA verification per witness check,
//! and a manager state that also maps elements to PRF indices.
//!
//! # Secret handling
//!
//! - [`SecretKey`] is secret: its seeds, the ML-DSA signing key and the inner key with its
//!   trapdoor are overwritten when it is dropped.
//! - [`MembershipWitness`] is holder-private: its handle, signature and inner witness are
//!   overwritten when it is dropped, and its encodings use buffers wiped on drop. A holder
//!   reveals its handle only when its element is deleted, when the update message publishes it.
//! - [`Element`], [`Accumulator`], [`PublicKey`] and the update messages are public;
//!   [`ManagerState`] is the manager's private record but holds no key.
//!
//! ```
//! use kln_accumulator::Params;
//! use kln_accumulator::adaptive::{
//!     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
//! };
//! use rand::{SeedableRng, rngs::StdRng};
//! use std::sync::Arc;
//!
//! let mut rng = StdRng::seed_from_u64(0);
//! let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
//! let pk = PublicKey::from(&key);
//! let mut acc = Accumulator::new(&key);
//! let mut state = ManagerState::new(&key);
//! let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
//! acc.add_elements_assign(&key, &[x, y], &mut state)?;
//! let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
//! assert!(witness.verify(&x, &pk, &acc));
//!
//! // Deleting y publishes its handle; x's holder updates with it.
//! let (new_acc, coefficients) = acc.update(&key, &[], &[y], &mut state)?;
//! let handles: Vec<_> = coefficients.iter().map(|c| c.element().clone()).collect();
//! let witness = witness.batch_update(&x, &[], &handles, &coefficients, &pk)?;
//! assert!(witness.verify(&x, &pk, &new_acc));
//!
//! // y can be added again, under a new handle.
//! let mut acc = new_acc;
//! acc.add_assign(&key, &y, &mut state)?;
//! let again = MembershipWitness::new(&y, &acc, &key, &state)?;
//! assert!(again.verify(&y, &pk, &acc));
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

mod accumulator;
mod key;
mod state;
mod witness;

pub use crate::{
    accumulator::Coefficient,
    state::{Operation, Record},
    witness::Delta,
};
pub use accumulator::{Accumulator, Element};
pub use key::{PublicKey, SecretKey};
pub use state::ManagerState;
pub use witness::MembershipWitness;
