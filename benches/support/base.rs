// SPDX-License-Identifier: MIT OR Apache-2.0
//! Construction 4.1, the crate-root types, as a [`crate::variant::Variant`].

use crate::{common::base_element, variant::impl_variant};
use kln_accumulator::{
    Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
};

/// Construction 4.1 of ePrint 2025/1099, the replacement-free accumulator.
#[derive(Debug)]
pub struct Base;

impl_variant!(
    Base, "construction-4.1",
    key: SecretKey, public: PublicKey, value: Accumulator, state: ManagerState,
    element: Element = base_element, witness: MembershipWitness,
);
