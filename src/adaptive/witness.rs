// SPDX-License-Identifier: MIT OR Apache-2.0
//! Membership witnesses of Construction 4.2: `MemWitCreate`, `MemVer` and `MemWitUp`.

use super::{
    accumulator::{Accumulator, Element},
    key::{PublicKey, SIGNATURE_BYTES, SecretKey},
    state::ManagerState,
};
use crate::{
    accumulator::{Coefficient, Element as Handle},
    error::{Error, Result},
    params::Params,
    secret_hex,
    witness::{Delta, MembershipWitness as InnerWitness},
};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// The length of the handle-length prefix in [`MembershipWitness::to_bytes`].
const LENGTH_BYTES: usize = 8;

/// A membership witness `w_x = (r_x, σ_x, w̃)` of Construction 4.2: the handle `r_x`, the
/// ML-DSA-65 signature `σ_x` over `kln/adaptive/sign ‖ x ‖ r_x` (deterministic variant, empty
/// context), and the inner witness `w̃` for `r_x`.
///
/// Its inner witness is bound to its parameter set; [`MembershipWitness::validate`] checks the
/// handle against a set and that the inner witness belongs to it.
/// Serialized as its three parts, the signature raw in binary formats and hex in human-readable
/// ones; deserialization checks the signature length.
///
/// **Holder-private.** The handle, the signature and the inner witness are overwritten when the
/// witness is dropped ([`ZeroizeOnDrop`]); its encodings use buffers wiped on drop;
/// [`fmt::Debug`] prints only the inner witness's parameter set. It is `Clone`, as the vb20 API
/// returns updated witnesses by value. Splitting it into its parts with
/// `From<MembershipWitness> for (Handle, Vec<u8>, InnerWitness)` hands the signature out in a
/// plain `Vec`, which the caller must wipe.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::Params;
/// # use kln_accumulator::adaptive::{
/// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
/// # };
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
/// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// # // Deleting publishes handles; the holder updates with the handles in the messages.
/// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
/// #     c.iter().map(|m| m.element().clone()).collect()
/// # };
/// assert!(witness.verify(&x, &pk, &acc));
/// assert!(!witness.verify(&y, &pk, &acc));
/// witness.validate(key.params())?;
/// assert_eq!(witness.signature().len(), 3309);
/// assert_eq!(witness.handle().to_bytes().len(), 1);
/// assert!(witness.inner().verify(witness.handle(), pk.inner(), &acc.clone().into()));
/// let bytes = witness.to_bytes()?;
/// assert_eq!(MembershipWitness::try_from(bytes.as_slice())?, witness);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WitnessWire")]
pub struct MembershipWitness {
    handle: Handle,
    #[serde(serialize_with = "secret_hex::serialize")]
    signature: Zeroizing<Vec<u8>>,
    inner: InnerWitness,
}

impl MembershipWitness {
    /// `MemWitCreate` (Construction 4.2), which also issues the witness at `Add` time: the
    /// handle `r_x = F_k(x, i)` for the index `i` recorded for `element`, the inner witness from
    /// the inner `MemWitCreate` for `r_x`, and `σ_x`. Both are deterministic, so the same
    /// history always gives the same witness. Before anything else it fails with
    /// [`Error::InvalidStateTag`] unless the tag of `state` verifies under `secret_key`, and
    /// then with [`Error::AccumulatorMismatch`] unless `accumulator` is the state's current
    /// value. Fails with [`Error::ElementNotPresent`] unless `element` is present, and as the
    /// inner `MemWitCreate` does otherwise.
    ///
    /// # Errors
    ///
    /// As above, and [`Error::SigningFailed`] if ML-DSA signing gives up, which does not happen
    /// in practice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// // The same history gives the same witness.
    /// assert_eq!(MembershipWitness::new(&x, &acc, &key, &state)?, witness);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new(
        element: &Element,
        accumulator: &Accumulator,
        secret_key: &SecretKey,
        state: &ManagerState,
    ) -> Result<Self> {
        state.authenticate(secret_key)?;
        state.inner().check_current(accumulator.inner())?;
        let handle = state.handle(secret_key, element)?;
        let inner = InnerWitness::new(
            &handle,
            accumulator.inner(),
            secret_key.inner(),
            state.inner(),
        )?;
        let signature = secret_key.sign(element, &handle)?;
        Ok(Self {
            handle,
            signature,
            inner,
        })
    }

    /// `MemVer` (Construction 4.2): whether `σ_x` is a signature over `(y, r_x)` and the inner
    /// witness verifies for `r_x` against `accumulator`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y])?;
    /// let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// assert!(!witness.verify(&y, &pk, &acc)); // the signature binds the witness to x
    /// // Deleting x and adding it again gives it a fresh handle; the old witness stays revoked.
    /// acc.remove_assign(&key, &x, &mut state)?;
    /// acc.add_assign(&key, &x, &mut state)?;
    /// assert!(!witness.verify(&x, &pk, &acc));
    /// assert!(MembershipWitness::new(&x, &acc, &key, &state)?.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn verify(&self, y: &Element, pubkey: &PublicKey, accumulator: &Accumulator) -> bool {
        pubkey.signs(y, &self.handle, &self.signature)
            && self
                .inner
                .verify(&self.handle, pubkey.inner(), accumulator.inner())
    }

    /// The witness with `delta`, computed for its handle, applied to the inner witness.
    ///
    /// # Errors
    ///
    /// [`Error::ParameterMismatch`] when `delta` is for another parameter set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let coefficients = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let delta = kln_accumulator::evaluate_delta(
    ///     witness.handle(), &[], &handles(&coefficients), &coefficients, pk.inner(),
    /// )?;
    /// assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn apply_delta(&self, delta: &Delta) -> Result<Self> {
        self.inner.apply_delta(delta).map(|inner| self.with(inner))
    }

    /// [`MembershipWitness::apply_delta`] in place; on an error the witness is unchanged.
    ///
    /// # Errors
    ///
    /// As [`MembershipWitness::apply_delta`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let coefficients = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let delta = kln_accumulator::evaluate_delta(
    ///     witness.handle(), &[], &handles(&coefficients), &coefficients, pk.inner(),
    /// )?;
    /// let mut witness = witness;
    /// witness.apply_delta_assign(&delta)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn apply_delta_assign(&mut self, delta: &Delta) -> Result<()> {
        *self = self.apply_delta(delta)?;
        Ok(())
    }

    /// `MemWitUp` (Construction 4.2) through the inner `MemWitUp`: `additions` and `deletions`
    /// are the handles the batch added and deleted. Fails with [`Error::InvalidSignature`]
    /// unless the witness is for `y`, and as the inner [`InnerWitness::update`] does otherwise:
    /// the witness must verify against `old_accumulator` and the result against
    /// `new_accumulator`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let old = acc.clone();
    /// let coefficients = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let updated = witness.update(&x, &old, &acc, &[], &handles(&coefficients), &pk)?;
    /// assert!(updated.verify(&x, &pk, &acc));
    /// // A witness for x is not a witness for z.
    /// assert!(witness.update(&z, &old, &acc, &[], &handles(&coefficients), &pk).is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn update(
        &self,
        y: &Element,
        old_accumulator: &Accumulator,
        new_accumulator: &Accumulator,
        additions: &[Handle],
        deletions: &[Handle],
        pubkey: &PublicKey,
    ) -> Result<Self> {
        let handle = self.handle_for(y, pubkey)?;
        self.inner
            .update(
                handle,
                old_accumulator.inner(),
                new_accumulator.inner(),
                additions,
                deletions,
                pubkey.inner(),
            )
            .map(|inner| self.with(inner))
    }

    /// [`MembershipWitness::update`] in place; on an error the witness is unchanged.
    ///
    /// # Errors
    ///
    /// As [`MembershipWitness::update`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let old = acc.clone();
    /// let coefficients = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let mut witness = witness;
    /// witness.update_assign(&x, &old, &acc, &[], &handles(&coefficients), &pk)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn update_assign(
        &mut self,
        y: &Element,
        old_accumulator: &Accumulator,
        new_accumulator: &Accumulator,
        additions: &[Handle],
        deletions: &[Handle],
        pubkey: &PublicKey,
    ) -> Result<()> {
        *self = self.update(
            y,
            old_accumulator,
            new_accumulator,
            additions,
            deletions,
            pubkey,
        )?;
        Ok(())
    }

    /// The witness updated through one published batch of handles, via
    /// [`InnerWitness::batch_update`]; [`Error::InvalidSignature`] unless the witness is for
    /// `y`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSignature`] as above, and as [`InnerWitness::batch_update`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let coefficients = acc.update_assign(&key, &[], &[y, z], &mut state)?;
    /// let updated = witness.batch_update(&x, &[], &handles(&coefficients), &coefficients, &pk)?;
    /// assert!(updated.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn batch_update(
        &self,
        y: &Element,
        additions: &[Handle],
        deletions: &[Handle],
        coefficients: &[Coefficient],
        pubkey: &PublicKey,
    ) -> Result<Self> {
        let handle = self.handle_for(y, pubkey)?;
        self.inner
            .batch_update(handle, additions, deletions, coefficients, pubkey.inner())
            .map(|inner| self.with(inner))
    }

    /// [`MembershipWitness::batch_update`] in place; on an error the witness is unchanged.
    ///
    /// # Errors
    ///
    /// As [`MembershipWitness::batch_update`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let coefficients = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let mut witness = witness;
    /// witness.batch_update_assign(&x, &[], &handles(&coefficients), &coefficients, &pk)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn batch_update_assign(
        &mut self,
        y: &Element,
        additions: &[Handle],
        deletions: &[Handle],
        coefficients: &[Coefficient],
        pubkey: &PublicKey,
    ) -> Result<()> {
        *self = self.batch_update(y, additions, deletions, coefficients, pubkey)?;
        Ok(())
    }

    /// The witness updated through several published batches of handles, in order, via
    /// [`InnerWitness::multi_batch_update`]; [`Error::InvalidSignature`] unless the witness is
    /// for `y`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSignature`] as above, and as [`InnerWitness::multi_batch_update`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let c1 = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let c2 = acc.update_assign(&key, &[], &[z], &mut state)?;
    /// let batches = [
    ///     (Vec::new(), handles(&c1), c1),
    ///     (Vec::new(), handles(&c2), c2),
    /// ];
    /// let updated = witness.multi_batch_update(&x, &batches, &pk)?;
    /// assert!(updated.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn multi_batch_update<A, D, C>(
        &self,
        y: &Element,
        deltas: &[(A, D, C)],
        pubkey: &PublicKey,
    ) -> Result<Self>
    where
        A: AsRef<[Handle]>,
        D: AsRef<[Handle]>,
        C: AsRef<[Coefficient]>,
    {
        let handle = self.handle_for(y, pubkey)?;
        self.inner
            .multi_batch_update(handle, deltas, pubkey.inner())
            .map(|inner| self.with(inner))
    }

    /// [`MembershipWitness::multi_batch_update`] in place; on an error the witness is
    /// unchanged.
    ///
    /// # Errors
    ///
    /// As [`MembershipWitness::multi_batch_update`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{
    /// #     Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
    /// # };
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y, z) = (Element::hash(b"x"), Element::hash(b"y"), Element::hash(b"z"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y, z])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// # // Deleting publishes handles; the holder updates with the handles in the messages.
    /// # let handles = |c: &[kln_accumulator::Coefficient]| -> Vec<kln_accumulator::Element> {
    /// #     c.iter().map(|m| m.element().clone()).collect()
    /// # };
    /// let c1 = acc.update_assign(&key, &[], &[y], &mut state)?;
    /// let batches = [(Vec::new(), handles(&c1), c1)];
    /// let mut witness = witness;
    /// witness.multi_batch_update_assign(&x, &batches, &pk)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn multi_batch_update_assign<A, D, C>(
        &mut self,
        y: &Element,
        deltas: &[(A, D, C)],
        pubkey: &PublicKey,
    ) -> Result<()>
    where
        A: AsRef<[Handle]>,
        D: AsRef<[Handle]>,
        C: AsRef<[Coefficient]>,
    {
        *self = self.multi_batch_update(y, deltas, pubkey)?;
        Ok(())
    }

    /// The encoding: the handle length as a little-endian `u64`, the handle, the 3309-byte
    /// signature, then [`InnerWitness::to_bytes`], in a buffer that is overwritten when dropped.
    /// `TryFrom<&[u8]>` decodes it, failing with [`Error::InvalidEncodingLength`] or as the
    /// parts' decodings do.
    ///
    /// # Errors
    ///
    /// As [`InnerWitness::to_bytes`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::adaptive::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let x = Element::hash(b"x");
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x])?;
    /// let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let to_send = witness.to_bytes()?; // send to x's holder alone; wiped when dropped
    /// let inner = witness.inner().to_bytes()?;
    /// assert_eq!(to_send.len(), 8 + witness.handle().to_bytes().len() + 3309 + inner.len());
    /// let received = MembershipWitness::from_bytes(pk.params(), &to_send)?;
    /// assert!(received.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        Zeroizing::<Vec<u8>>::try_from(self)
    }

    /// Checks the handle with [`Handle::validate`] and the inner witness with
    /// [`InnerWitness::validate`]. The signature is checked by
    /// [`MembershipWitness::verify`]. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidElement`] or [`Error::ParameterMismatch`].
    pub fn validate(&self, params: &Params) -> Result<()> {
        self.handle.validate(params)?;
        self.inner.validate(params)
    }

    /// The handle `r_x`; see the type's example.
    #[must_use]
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// The encoded signature `σ_x`, 3309 bytes; see the type's example.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The inner witness `w̃` for the handle; see the type's example.
    #[must_use]
    pub fn inner(&self) -> &InnerWitness {
        &self.inner
    }

    /// Decodes [`MembershipWitness::to_bytes`] against `params`, the set the caller expects:
    /// the inner witness is decoded with [`InnerWitness::from_bytes`], so no set is built from
    /// the input and the result shares `params`, and the handle is then checked with
    /// [`Handle::validate`]. Use this for bytes from an untrusted source. The signature is
    /// checked by [`MembershipWitness::verify`].
    ///
    /// # Errors
    ///
    /// As `TryFrom<&[u8]>`, but [`Error::ParameterMismatch`] when the bytes name another set,
    /// and [`Error::InvalidElement`] for a handle that is not an element at `params`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params};
    /// use kln_accumulator::adaptive::{Accumulator, Element, MembershipWitness, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let params = Arc::new(Params::toy()?);
    /// let key = SecretKey::new(None, Arc::clone(&params), &mut StdRng::seed_from_u64(0))?;
    /// let x = Element::hash(b"x");
    /// let (acc, state) = Accumulator::with_elements(&key, &[x])?;
    /// let bytes = MembershipWitness::new(&x, &acc, &key, &state)?.to_bytes()?;
    /// let witness = MembershipWitness::from_bytes(&params, &bytes)?;
    /// assert!(Arc::ptr_eq(witness.inner().params(), &params));
    /// // The bytes of a witness at another set are refused.
    /// let other = Arc::new(Params::succinct_toy()?);
    /// assert_eq!(MembershipWitness::from_bytes(&other, &bytes).map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_bytes(params: &Arc<Params>, bytes: &[u8]) -> Result<Self> {
        let witness = Self::decode(bytes, |inner| InnerWitness::from_bytes(params, inner))?;
        witness.handle.validate(params)?;
        Ok(witness)
    }

    /// Decodes [`MembershipWitness::to_bytes`], reading the inner witness with `inner`.
    fn decode<'b>(
        bytes: &'b [u8],
        inner: impl FnOnce(&'b [u8]) -> Result<InnerWitness>,
    ) -> Result<Self> {
        let invalid = Error::InvalidEncodingLength(bytes.len());
        let (length, rest) = bytes.split_first_chunk::<LENGTH_BYTES>().ok_or(invalid)?;
        let length = usize::try_from(u64::from_le_bytes(*length)).map_err(|_| invalid)?;
        let (handle, rest) = rest.split_at_checked(length).ok_or(invalid)?;
        let (signature, rest) = rest.split_at_checked(SIGNATURE_BYTES).ok_or(invalid)?;
        Self::assemble(
            Handle::try_from(handle)?,
            Zeroizing::new(signature.to_vec()),
            inner(rest)?,
        )
    }

    /// The handle, once the signature shows the witness is for `y`.
    fn handle_for(&self, y: &Element, pubkey: &PublicKey) -> Result<&Handle> {
        if pubkey.signs(y, &self.handle, &self.signature) {
            Ok(&self.handle)
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// `(r_x, σ_x, w̃)`, or [`Error::InvalidEncodingLength`] unless the signature has the
    /// ML-DSA-65 length.
    fn assemble(
        handle: Handle,
        signature: Zeroizing<Vec<u8>>,
        inner: InnerWitness,
    ) -> Result<Self> {
        if signature.len() == SIGNATURE_BYTES {
            Ok(Self {
                handle,
                signature,
                inner,
            })
        } else {
            Err(Error::InvalidEncodingLength(signature.len()))
        }
    }

    /// The witness with the same handle and signature and the inner witness `inner`.
    fn with(&self, inner: InnerWitness) -> Self {
        Self {
            handle: self.handle.clone(),
            signature: self.signature.clone(),
            inner,
        }
    }
}

/// Assembles `(r_x, σ_x, w̃)`; fails with [`Error::InvalidEncodingLength`] unless the signature
/// has the ML-DSA-65 length. The signature is moved into a buffer that is overwritten when the
/// witness, or the refused input, is dropped.
impl TryFrom<(Handle, Vec<u8>, InnerWitness)> for MembershipWitness {
    type Error = Error;

    fn try_from((handle, signature, inner): (Handle, Vec<u8>, InnerWitness)) -> Result<Self> {
        Self::assemble(handle, Zeroizing::new(signature), inner)
    }
}

/// Splits the witness into its parts; the signature leaves the wiped buffer, so wiping it is
/// then the caller's job.
impl From<MembershipWitness> for (Handle, Vec<u8>, InnerWitness) {
    fn from(mut witness: MembershipWitness) -> Self {
        let signature = core::mem::take(&mut *witness.signature);
        (witness.handle, signature, witness.inner)
    }
}

/// The handle, the signature and the inner witness are overwritten when the witness is
/// dropped.
impl ZeroizeOnDrop for MembershipWitness {}

/// Prints the parameter set of the inner witness, not the handle, the signature or the
/// coefficients.
impl fmt::Debug for MembershipWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MembershipWitness")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

/// Decodes [`MembershipWitness::to_bytes`]; check the result with
/// [`MembershipWitness::validate`]. It builds the set the bytes name, so for bytes from an
/// untrusted source use [`MembershipWitness::from_bytes`] with the set you expect.
impl TryFrom<&[u8]> for MembershipWitness {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, InnerWitness::try_from)
    }
}

/// The serialized form of [`MembershipWitness`], before the signature length is checked; a
/// field it does not name is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessWire {
    handle: Handle,
    #[serde(deserialize_with = "secret_hex::deserialize")]
    signature: Zeroizing<Vec<u8>>,
    inner: InnerWitness,
}

impl TryFrom<WitnessWire> for MembershipWitness {
    type Error = Error;

    fn try_from(wire: WitnessWire) -> Result<Self> {
        Self::assemble(wire.handle, wire.signature, wire.inner)
    }
}

/// The encoding of [`MembershipWitness::to_bytes`], which calls this, in a buffer wiped on
/// drop; fails as that method does.
impl TryFrom<&MembershipWitness> for Zeroizing<Vec<u8>> {
    type Error = Error;

    fn try_from(value: &MembershipWitness) -> Result<Self> {
        let handle = value.handle.as_bytes();
        let inner = value.inner.to_bytes()?;
        let mut out = Zeroizing::new(Vec::with_capacity(
            LENGTH_BYTES + handle.len() + value.signature.len() + inner.len(),
        ));
        out.extend_from_slice(&(handle.len() as u64).to_le_bytes());
        out.extend_from_slice(handle);
        out.extend_from_slice(&value.signature);
        out.extend_from_slice(&inner);
        Ok(out)
    }
}
