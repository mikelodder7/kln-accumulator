// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `ℓ`-succinct variant of Construction 4.1 ("Reducing the size of witnesses", Section 4),
//! whose witnesses have `m + m'` entries instead of `m + ℓm'`, under the `ℓ`-succinct M-SIS
//! assumption (Definition 2.10, Remark 2.3).
//!
//! `Gen` draws `B₁ ∈ R_q^{n×m'}` and `W ∈ R_q^{nℓ×m'}` uniformly and samples, column by column
//! with `T_A`, a short `T = [T₀; T₁]` with `T₀ ∈ R^{ℓm×ℓm'}`, `T₁ ∈ R^{m'×ℓm'}` and
//! `[I_ℓ⊗A | W]·T = I_ℓ⊗G`; `pp = (A, B₁, W, T₀, T₁, u)`. The manager then runs Construction 4.1
//! unchanged with `B := −B₁·T₁`: `Add` samples `s̃_x` with `[A | −B₁T₁ − xᵀ⊗G]·s̃_x = c`, and
//! `Delete` adds `B_{1y}·G⁻¹(u)` for that `B`. A witness is the image of `s̃_x` under
//! `S_x = [I_m, −(xᵀ⊗I_m)T₀; 0, −T₁]`, and `MemWitUp` adds `[−(xᵀ⊗I_m)T₀; −T₁]·H_{1y,x}·G⁻¹(u)`.
//! By Remark 2.3, `[A | B₁ + (xᵀ⊗I_n)W]·S_x = [A | −B₁T₁ − xᵀ⊗G]`, so verification checks
//! `[A | B₁ + (xᵀ⊗I_n)W]·s_x = c` and `‖s_x‖ ≤ β_succ` ([`Bounds`]).
//!
//! The paper does not say which `B` `Delete` and `MemWitUp` evaluate `1_y` on, since `pp` holds
//! no `B`; it can only be `−B₁T₁`, the `B` of the Construction 4.1 instance being run (p. 19–20).
//!
//! So the manager side is the base scheme: the accumulator value, the manager state, the
//! elements and the update messages are the base [`Accumulator`], [`ManagerState`], [`Element`]
//! and [`Coefficient`], re-exported here. [`SecretKey`] and [`PublicKey`] dereference to the base
//! keys for `B = −B₁T₁`, so `Accumulator::add(&key, …)` and the other base methods take a
//! succinct key as they are. Only the witness, its [`Delta`] and the bounds are new. The base
//! witness is the one base method a succinct key refuses
//! ([`crate::Error::CompressedWitnessOnly`]): a holder receives the compressed vector only.
//!
//! The public key is large: `T₀` is a dense `ℓm × ℓm'` matrix, `ℓ²·m·m'` polynomials, which the
//! paper's "a factor of `O(ℓ)`" larger public parameters understates by a factor of about `m`
//! (its Table 1 does say `ℓ²·poly(λ)`). At [`crate::ParamsSpec::SUCCINCT_TOY`] that is 7200 of
//! the key's 8206 polynomials, and the packed key is 2,149,984 bytes. At
//! [`crate::ParamsSpec::SUCCINCT_128`] it would be 5,935,258 polynomials and about 110 GiB;
//! Table 2's 171.7 MB counts only `(A, B₁, W, u)`. Key generation at that set is not practical,
//! and only its parameters and bounds are tested.
//!
//! # When it pays
//!
//! A succinct witness has `m + m'` polynomials instead of `m + ℓm'`, but its coefficients are
//! wider, since `β_succ` is far above `β₀` ([`Bounds`]). At the succinct toy set (`ℓ = 4`) the
//! succinct witness is 29,224 bytes against 28,144 for a base witness at the same set: the
//! saving needs `ℓ` large enough to outweigh the wider coefficients. The trapdoor
//! distribution matters here: a ternary `T_A` ([`crate::TrapdoorDistribution::Ternary`])
//! narrows `T` and lowers `β_succ` from `2^79.70` to `2^67.53` at the succinct toy set.
//!
//! # Secret handling
//!
//! [`SecretKey`] is secret and overwritten when dropped, together with the seeds and sampler
//! state used to draw `T` at key generation; `T` itself is public. [`MembershipWitness`] and
//! [`Delta`] are holder-private and overwritten when dropped. Everything else is public.
//!
//! ```
//! use kln_accumulator::{Accumulator, Element, ManagerState, Params};
//! use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
//! use rand::{SeedableRng, rngs::StdRng};
//! use std::sync::Arc;
//!
//! let mut rng = StdRng::seed_from_u64(0);
//! let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
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

mod bounds;
mod key;
mod witness;

pub use crate::{
    accumulator::{Accumulator, Coefficient, Element},
    state::ManagerState,
};
pub use bounds::Bounds;
pub use key::{PublicKey, SecretKey};
pub use witness::{Delta, MembershipWitness, evaluate_delta, evaluate_deltas};
