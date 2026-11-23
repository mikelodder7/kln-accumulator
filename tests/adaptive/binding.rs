// SPDX-License-Identifier: MIT OR Apache-2.0
//! The signature binds the element to its handle (C29).

use crate::fixture::{KEY, Manager, element};
use kln_accumulator::{Accumulator as InnerAccumulator, Error, adaptive::MembershipWitness};

/// The witness `(r, σ, w̃)` assembled from parts.
fn assemble(
    handle: &kln_accumulator::Element,
    signature: &[u8],
    inner: &kln_accumulator::MembershipWitness,
) -> MembershipWitness {
    MembershipWitness::try_from((handle.clone(), signature.to_vec(), inner.clone()))
        .expect("test fixture")
}

/// C29: verification fails when the signature is over a different `(x, r_x)` pair even though
/// the inner witness is valid for the handle it carries, and fails with a valid signature over
/// `(x, r_x)` when the inner witness is for a different handle. An update for another element
/// is refused, and so is a tampered signature.
#[test]
fn signature_must_cover_the_element_and_its_handle() {
    let mut manager = Manager::new(&KEY);
    let (x1, x2) = (element(1), element(2));
    let w1 = manager.add(&x1);
    let w2 = manager.add(&x2);
    let public = &manager.public;
    let value = &manager.value;
    let inner_value = InnerAccumulator::from(value.clone());
    assert!(w1.verify(&x1, public, value) && w2.verify(&x2, public, value));

    // σ₁ is over (x₁, r₁); the inner witness is valid for r₂.
    let foreign_signature = assemble(w2.handle(), w1.signature(), w2.inner());
    assert!(
        foreign_signature
            .inner()
            .verify(w2.handle(), public.inner(), &inner_value)
    );
    assert!(!foreign_signature.verify(&x2, public, value));
    assert!(!foreign_signature.verify(&x1, public, value));

    // σ₁ is a valid signature over (x₁, r₁); the inner witness is for r₂, not r₁.
    let foreign_inner = assemble(w1.handle(), w1.signature(), w2.inner());
    assert!(
        !foreign_inner
            .inner()
            .verify(w1.handle(), public.inner(), &inner_value)
    );
    assert!(!foreign_inner.verify(&x1, public, value));

    assert!(!w1.verify(&x2, public, value));
    let mut signature = w1.signature().to_vec();
    signature[40] ^= 1;
    assert!(!assemble(w1.handle(), &signature, w1.inner()).verify(&x1, public, value));

    assert_eq!(
        w1.batch_update(&x2, &[], &[], &[], public),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        w1.multi_batch_update::<Vec<_>, Vec<_>, Vec<_>>(&x2, &[], public),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        w1.update(&x2, value, value, &[], &[], public),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        MembershipWitness::try_from((w1.handle().clone(), vec![0; 10], w1.inner().clone())),
        Err(Error::InvalidEncodingLength(10))
    );
}
