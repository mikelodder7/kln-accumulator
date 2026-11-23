// SPDX-License-Identifier: MIT OR Apache-2.0
//! Construction 4.2, the adaptive variant (`kln_accumulator::adaptive`), as a
//! [`crate::variant::Variant`].

use crate::{common::Outcome, variant::impl_variant};
use kln_accumulator::{
    Params,
    adaptive::{Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey},
};

/// Construction 4.2 of ePrint 2025/1099: elements can be deleted and added again.
#[derive(Debug)]
pub struct Adaptive;

/// The adaptive element numbered `index`: the hash of that one byte. Adaptive elements are
/// 32-byte strings whatever the set, so `params` is not needed.
///
/// # Errors
///
/// None; the signature is that of [`crate::variant::Variant::element`].
pub fn adaptive_element(index: u8, _params: &Params) -> Outcome<Element> {
    Ok(Element::hash(&[index]))
}

impl_variant!(
    Adaptive, "adaptive",
    key: SecretKey, public: PublicKey, value: Accumulator, state: ManagerState,
    element: Element = adaptive_element, witness: MembershipWitness,
);
