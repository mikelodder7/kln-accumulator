// SPDX-License-Identifier: MIT OR Apache-2.0
//! One interface over the three accumulator variants, and the fixture every lifecycle
//! benchmark and the size report start from.

use crate::common::{Outcome, rng};
use kln_accumulator::{Coefficient, Element, Params, Result};
use rand::rngs::StdRng;
use std::{fmt::Debug, sync::Arc};

/// The operations of one accumulator variant that the benchmarks time, and the encodings the
/// size report measures. Every method is the variant's own public API, called directly.
pub trait Variant {
    /// The variant's name in benchmark IDs and in the size report.
    const NAME: &'static str;
    /// The manager's secret key.
    type Key: Debug;
    /// The public key holders and verifiers use.
    type Public: Debug;
    /// The accumulator value.
    type Value: Clone + Debug;
    /// The manager state.
    type State: Clone + Debug;
    /// An element the accumulator holds.
    type Element: Debug;
    /// A membership witness.
    type Witness: Debug;

    /// Key generation, from 32 bytes of `rng`.
    ///
    /// # Errors
    ///
    /// As the variant's `SecretKey::new`.
    fn key(params: &Arc<Params>, rng: &mut StdRng) -> Result<Self::Key>;

    /// Public-key derivation.
    fn public(key: &Self::Key) -> Self::Public;

    /// The element numbered `index`; distinct indices give distinct elements.
    ///
    /// # Errors
    ///
    /// When `index` names no element of the set.
    fn element(index: u8, params: &Params) -> Outcome<Self::Element>;

    /// The key's accumulator at its genesis value, with a fresh manager state and no elements.
    ///
    /// # Errors
    ///
    /// As the variant's `Accumulator::with_elements`.
    fn start(key: &Self::Key) -> Result<(Self::Value, Self::State)>;

    /// `Add` of one element, in place.
    ///
    /// # Errors
    ///
    /// As the variant's `Accumulator::add_assign`.
    fn add(
        value: &mut Self::Value,
        key: &Self::Key,
        element: &Self::Element,
        state: &mut Self::State,
    ) -> Result<()>;

    /// The manager's batch update, in place: `Add` of every element of `additions` and
    /// `Delete` of every element of `deletions`; returns the update messages.
    ///
    /// # Errors
    ///
    /// As the variant's `Accumulator::update_assign`.
    fn apply(
        value: &mut Self::Value,
        key: &Self::Key,
        additions: &[Self::Element],
        deletions: &[Self::Element],
        state: &mut Self::State,
    ) -> Result<Vec<Coefficient>>;

    /// Witness issuance for `element` at `value`.
    ///
    /// # Errors
    ///
    /// As the variant's `MembershipWitness::new`.
    fn issue(
        element: &Self::Element,
        value: &Self::Value,
        key: &Self::Key,
        state: &Self::State,
    ) -> Result<Self::Witness>;

    /// Witness verification.
    fn verify(
        witness: &Self::Witness,
        element: &Self::Element,
        public: &Self::Public,
        value: &Self::Value,
    ) -> bool;

    /// The holder's update over one batch of deletions, named by `handles` (what the update
    /// messages name) and carried by `coefficients`.
    ///
    /// # Errors
    ///
    /// As the variant's `MembershipWitness::batch_update`.
    fn update(
        witness: &Self::Witness,
        element: &Self::Element,
        handles: &[Element],
        coefficients: &[Coefficient],
        public: &Self::Public,
    ) -> Result<Self::Witness>;

    /// The length of the secret key's packed encoding.
    fn key_bytes(key: &Self::Key) -> usize;

    /// The length of the public key's packed encoding.
    fn public_bytes(public: &Self::Public) -> usize;

    /// The length of the accumulator value's packed encoding.
    fn value_bytes(value: &Self::Value) -> usize;

    /// The length of the witness's packed encoding.
    ///
    /// # Errors
    ///
    /// As the variant's `MembershipWitness::to_bytes`.
    fn witness_bytes(witness: &Self::Witness) -> Result<usize>;
}

/// Implements [`Variant`] for `$variant` by calling the methods of the same name on the given
/// types, which every variant module of the crate shares; `$element` builds the element
/// numbered `index`.
macro_rules! impl_variant {
    (
        $variant:ty, $name:literal,
        key: $key:ty, public: $public:ty, value: $value:ty, state: $state:ty,
        element: $element_ty:ty = $element:expr, witness: $witness:ty $(,)?
    ) => {
        impl $crate::variant::Variant for $variant {
            const NAME: &'static str = $name;
            type Key = $key;
            type Public = $public;
            type Value = $value;
            type State = $state;
            type Element = $element_ty;
            type Witness = $witness;

            fn key(
                params: &std::sync::Arc<kln_accumulator::Params>,
                rng: &mut rand::rngs::StdRng,
            ) -> kln_accumulator::Result<$key> {
                <$key>::new(None, std::sync::Arc::clone(params), rng)
            }

            fn public(key: &$key) -> $public {
                <$public>::from(key)
            }

            fn element(
                index: u8,
                params: &kln_accumulator::Params,
            ) -> $crate::common::Outcome<$element_ty> {
                $element(index, params)
            }

            fn start(key: &$key) -> kln_accumulator::Result<($value, $state)> {
                <$value>::with_elements(key, &[])
            }

            fn add(
                value: &mut $value,
                key: &$key,
                element: &$element_ty,
                state: &mut $state,
            ) -> kln_accumulator::Result<()> {
                value.add_assign(key, element, state)
            }

            fn apply(
                value: &mut $value,
                key: &$key,
                additions: &[$element_ty],
                deletions: &[$element_ty],
                state: &mut $state,
            ) -> kln_accumulator::Result<Vec<kln_accumulator::Coefficient>> {
                value.update_assign(key, additions, deletions, state)
            }

            fn issue(
                element: &$element_ty,
                value: &$value,
                key: &$key,
                state: &$state,
            ) -> kln_accumulator::Result<$witness> {
                <$witness>::new(element, value, key, state)
            }

            fn verify(
                witness: &$witness,
                element: &$element_ty,
                public: &$public,
                value: &$value,
            ) -> bool {
                witness.verify(element, public, value)
            }

            fn update(
                witness: &$witness,
                element: &$element_ty,
                handles: &[kln_accumulator::Element],
                coefficients: &[kln_accumulator::Coefficient],
                public: &$public,
            ) -> kln_accumulator::Result<$witness> {
                witness.batch_update(element, &[], handles, coefficients, public)
            }

            fn key_bytes(key: &$key) -> usize {
                key.to_bytes().len()
            }

            fn public_bytes(public: &$public) -> usize {
                public.to_bytes().len()
            }

            fn value_bytes(value: &$value) -> usize {
                value.to_bytes().len()
            }

            fn witness_bytes(witness: &$witness) -> kln_accumulator::Result<usize> {
                witness.to_bytes().map(|bytes| bytes.len())
            }
        }
    };
}

pub(crate) use impl_variant;

/// A manager and one holder, ready for every lifecycle operation: elements `0` (the member)
/// and `1..=deletions` are added, the member holds a witness at that value, and the deletion
/// of the others has been run once, on copies, to produce the update messages.
#[derive(Debug)]
pub struct Fixture<V: Variant> {
    /// The parameter set.
    pub params: Arc<Params>,
    /// The manager's key.
    pub key: V::Key,
    /// Its public key.
    pub public: V::Public,
    /// The value after the additions; nothing is deleted from it.
    pub value: V::Value,
    /// The state that goes with `value`.
    pub state: V::State,
    /// The member that holds `witness`.
    pub member: V::Element,
    /// The member's witness at `value`.
    pub witness: V::Witness,
    /// Elements never added, half as many as `deleted` (rounded up): the first for the addition
    /// benchmark, all of them for the batch update.
    pub fresh: Vec<V::Element>,
    /// The elements whose deletion the update messages announce; all present in `value`.
    pub deleted: Vec<V::Element>,
    /// What the update messages name: the deleted elements, or their handles.
    pub handles: Vec<Element>,
    /// The update messages of deleting `deleted` from `value`, in order.
    pub coefficients: Vec<Coefficient>,
}

impl<V: Variant> Fixture<V> {
    /// Generates a key, adds the member and `deletions` further elements, issues the member's
    /// witness, deletes the others from copies, and checks that the issued and the updated
    /// witness both verify.
    ///
    /// # Errors
    ///
    /// Any error of those operations, or a witness that does not verify.
    pub fn new(params: Arc<Params>, deletions: usize) -> Outcome<Self> {
        let mut rng = rng(0);
        let key = V::key(&params, &mut rng)?;
        let public = V::public(&key);
        let member = V::element(0, &params)?;
        let deleted = (1..=u8::MAX)
            .take(deletions)
            .map(|index| V::element(index, &params))
            .collect::<Outcome<Vec<_>>>()?;
        let fresh = (deletions + 1..=deletions + deletions.div_ceil(2))
            .map(|index| V::element(u8::try_from(index)?, &params))
            .collect::<Outcome<Vec<_>>>()?;
        let (mut value, mut state) = V::start(&key)?;
        for element in core::iter::once(&member).chain(&deleted) {
            V::add(&mut value, &key, element, &mut state)?;
        }
        let witness = V::issue(&member, &value, &key, &state)?;
        if !V::verify(&witness, &member, &public, &value) {
            return Err("the issued witness does not verify".into());
        }
        let (mut after, mut after_state) = (value.clone(), state.clone());
        let coefficients = V::apply(&mut after, &key, &[], &deleted, &mut after_state)?;
        let handles: Vec<Element> = coefficients.iter().map(|c| c.element().clone()).collect();
        let updated = V::update(&witness, &member, &handles, &coefficients, &public)?;
        if !V::verify(&updated, &member, &public, &after) {
            return Err("the updated witness does not verify".into());
        }
        Ok(Self {
            params,
            key,
            public,
            value,
            state,
            member,
            witness,
            fresh,
            deleted,
            handles,
            coefficients,
        })
    }
}
