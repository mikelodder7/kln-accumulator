// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `ℓ`-succinct variant (`kln_accumulator::succinct`), as a [`crate::variant::Variant`].
//! Its accumulator value, manager state, elements and update messages are those of
//! Construction 4.1, and its keys dereference to the base keys, so the manager's operations are
//! the base methods.

use crate::{common::base_element, variant::impl_variant};
use kln_accumulator::{
    Accumulator, Element, ManagerState,
    succinct::{MembershipWitness, PublicKey, SecretKey},
};

/// The `ℓ`-succinct witness variant of Section 4 of ePrint 2025/1099.
#[derive(Debug)]
pub struct Succinct;

impl_variant!(
    Succinct, "succinct",
    key: SecretKey, public: PublicKey, value: Accumulator, state: ManagerState,
    element: Element = base_element, witness: MembershipWitness,
);
