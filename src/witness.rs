// SPDX-License-Identifier: MIT OR Apache-2.0
//! Membership witnesses of Construction 4.1: `MemWitCreate`, `MemVer` and `MemWitUp`, with the
//! batched forms of the vb20 pairing accumulator.
//!
//! # The holder's side
//!
//! See the book's chapter "Witnesses and updates".

use crate::{
    accumulator::{Accumulator, Coefficient, Element},
    error::{Error, Result, check_dimension},
    key::{PublicKey, SecretKey, WitnessForm},
    matrix::PolyMatrix,
    packing::{self, Packed, Short, packed_impls},
    params::Params,
    ring::Ring,
    sample::{DomainLabel, hash_to_seed},
    state::ManagerState,
    vector::PolyVec,
    zq::Coeff,
};
use core::fmt;
use crypto_bigint::U512;
use std::sync::Arc;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Label of the PRF `F_k(x)` that fixes the randomness of `SampleLeft`.
const LABEL_PRF: &[u8] = b"kln/memwit/prf";

/// A membership witness `s_x ∈ R^{m+ℓm'}`: a short vector with `[A | B − xᵀ⊗G]·s_x = c` and
/// `‖s_x‖₂ ≤ β`, held as residues modulo `q` (the centred lift is the integer vector).
///
/// It is bound to its parameter set, which fixes its shape and its encoding;
/// [`MembershipWitness::validate`] checks that the set is the one an operation uses. Encoded as
/// the set and the `(m + ℓm')·d` centred coefficients in `⌈log₂(2β + 1)⌉` bits each (Table 2):
/// 34,464 bytes at the toy set, 15,493,184 bytes (14.775 MiB, Table 2: 14.72 MB) at the
/// 128-bit set.
///
/// **Holder-private.** The witness belongs to its element's holder, who shows it to no one and
/// uses it in membership proofs. Its coefficients are overwritten when it is dropped
/// ([`ZeroizeOnDrop`]); [`MembershipWitness::to_bytes`] and the serde form encode it in
/// buffers wiped on drop; [`fmt::Debug`] prints only the parameter set. It is `Clone`, because
/// the vb20 API it mirrors returns updated witnesses by value; every clone wipes itself too.
/// `From<MembershipWitness> for PolyVec` hands out the vector, which is wiped when dropped as
/// every [`PolyVec`] is.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
/// # use kln_accumulator::{PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let element = |name: &[u8]| Element::hash(name, key.params());
/// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// assert!(witness.verify(&x, &pk, &acc));
/// assert!(!witness.verify(&y, &pk, &acc));
/// witness.validate(key.params())?;
/// assert_eq!(witness.params(), key.params());
/// assert!(format!("{witness:?}").starts_with("MembershipWitness { params:"));
/// let bytes = witness.to_bytes()?;
/// assert_eq!(bytes.len(), 64 + 100 * 64 * 43 / 8);
/// assert_eq!(MembershipWitness::try_from(bytes.as_slice())?, witness);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, derive_more::Into)]
pub struct MembershipWitness {
    #[into(skip)]
    params: Arc<Params>,
    vector: PolyVec,
}

impl MembershipWitness {
    /// `MemWitCreate` (Construction 4.1), which also issues the witness at `Add` time, for a
    /// present element `x`:
    ///
    /// 1. derive the sampling seed `r = F_k(x)` with SHAKE256 keyed by the PRF key;
    /// 2. sample `s_x ← SampleLeft([A | B − xᵀ⊗G], T_A, c₀, s; r)` for the key's genesis value
    ///    `c₀`;
    /// 3. add `[0; H_{1y,x}·G⁻¹(u)]` for every element `y` the state records as deleted.
    ///
    /// Deviation (Construction 4.1, MemWitCreate): the paper samples for `c_i`, the value at the
    /// epoch `i` of the addition, with randomness `F_k(x, c_i)`, and corrects only for the
    /// deletions after `i`. Sampling for `c₀` makes the witness a function of the key, the
    /// element and the *set* of deletions alone: the order of the deletions, the epoch of the
    /// addition and the state's history do not enter, so a fresh, forked, older or rebuilt
    /// state can only reproduce the one preimage the key has for `x`. Since adding does not
    /// change the value, every run of this code is a run of the paper's scheme in which every
    /// element was added at epoch 0 and its witness handed out later (a match of runs, not a
    /// reduction to the theorem as stated); see the book's chapter "Guarantees and their
    /// limits", section "Where this crate departs from the paper".
    ///
    /// This is the only code path that samples a preimage, and it returns the same witness for
    /// the same element and deletions, never a fresh one (Remark 4.1). Before anything else it
    /// fails with [`Error::InvalidStateTag`] unless the tag of `state` verifies under
    /// `secret_key`, and then with [`Error::AccumulatorMismatch`] unless `accumulator` is the
    /// state's current value ([`ManagerState::current`]). Fails with
    /// [`Error::ElementNotPresent`] unless `element` is in the accumulator.
    ///
    /// The cost is one `SampleLeft` (a wide integer Gaussian draw over `m + ℓm'` entries and a
    /// trapdoor-stage preimage of `A`) plus one correction per deletion made so far, not only
    /// per deletion since the addition: milliseconds at the toy set, seconds at the 128-bit
    /// set (the `paper_128` benchmark measures it). The wide draw is not constant time: it is a
    /// table search whose memory access and length depend on the draw.
    ///
    /// # Errors
    ///
    /// As above, and [`Error::ParameterMismatch`] or [`Error::InvalidElement`] for inputs of
    /// another set. [`Error::CompressedWitnessOnly`] for the base key inside a succinct key,
    /// which issues succinct witnesses only.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// // Recreating the witness returns the same one, never a fresh preimage (Remark 4.1).
    /// assert_eq!(MembershipWitness::new(&x, &acc, &key, &state)?, witness);
    /// let w = Element::hash(b"never added", key.params());
    /// assert_eq!(
    ///     MembershipWitness::new(&w, &acc, &key, &state),
    ///     Err(kln_accumulator::Error::ElementNotPresent)
    /// );
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new(
        element: &Element,
        accumulator: &Accumulator,
        secret_key: &SecretKey,
        state: &ManagerState,
    ) -> Result<Self> {
        match secret_key.witness_form() {
            WitnessForm::Full => Self::issue(element, accumulator, secret_key, state),
            WitnessForm::Compressed => Err(Error::CompressedWitnessOnly),
        }
    }

    /// [`MembershipWitness::new`] for a base key of either [`WitnessForm`]: the preimage the
    /// succinct variant compresses is issued here.
    pub(crate) fn issue(
        element: &Element,
        accumulator: &Accumulator,
        secret_key: &SecretKey,
        state: &ManagerState,
    ) -> Result<Self> {
        state.authenticate(secret_key)?;
        let public = secret_key.public();
        let params = &**public.params();
        let ring = params.ring();
        accumulator.validate(params)?;
        state.validate(params)?;
        state.check_current(accumulator)?;
        let bits = element.to_bits(params)?;
        state.check_present(element)?;
        // Deviation (see above): the randomness is F_k(x) and the target the genesis value.
        let seed = hash_to_seed(
            DomainLabel::from(LABEL_PRF),
            &[secret_key.prf_key().as_bytes(), element.as_bytes()],
        );
        let matrix = public.membership_matrix(&bits)?;
        // Erratum (Construction 4.1, p. 17): MemWitCreate step 6 samples with width s1; Add
        // samples with s, and the two must agree for MemWitCreate to reproduce the witness Add
        // issued.
        let sample = secret_key.trapdoor().sample_left(
            params,
            &matrix,
            secret_key.genesis().value(),
            &seed,
        )?;
        let witness = Self {
            params: Arc::clone(public.params()),
            vector: sample,
        }
        .corrected(&public.correction(element, state.deleted())?, params)?;
        if matrix.mul_vec(&witness.vector, ring)? == *accumulator.value() {
            Ok(witness)
        } else {
            Err(Error::AccumulatorMismatch)
        }
    }

    /// `MemVer` (Construction 4.1): whether `[A | B − yᵀ⊗G]·s = c` and `‖s‖₂ ≤ β`. Returns
    /// false as well when `y`, the witness or the accumulator does not fit the parameters of
    /// `pubkey`. One product of an `n × (m + ℓm')` matrix with the witness; about 0.13 s at the
    /// 128-bit set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y) = (element(b"x"), element(b"y"));
    /// # let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
    /// let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// assert!(!witness.verify(&y, &pk, &acc)); // the witness is for x alone
    /// // After any deletion the old witness no longer verifies until it is updated.
    /// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// assert!(!witness.verify(&x, &pk, &acc));
    /// let witness = witness.batch_update(&x, &[], &[y], &coefficients, &pk)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn verify(&self, y: &Element, pubkey: &PublicKey, accumulator: &Accumulator) -> bool {
        self.check(y, pubkey, accumulator).unwrap_or(false)
    }

    /// The witness with `delta` added to its last `ℓm'` coordinates.
    ///
    /// # Errors
    ///
    /// [`Error::ParameterMismatch`] when `delta` is for another parameter set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let (new_acc, coefficients) = acc.update(&key, &[], &[y.clone()], &mut state)?;
    /// let delta = kln_accumulator::evaluate_delta(&x, &[], &[y], &coefficients, &pk)?;
    /// let updated = witness.apply_delta(&delta)?;
    /// assert!(updated.verify(&x, &pk, &new_acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn apply_delta(&self, delta: &Delta) -> Result<Self> {
        self.corrected(&delta.correction, &delta.params)
    }

    /// Adds `delta` to the last `ℓm'` coordinates in place; on an error the witness is
    /// unchanged.
    ///
    /// # Errors
    ///
    /// As [`MembershipWitness::apply_delta`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let mut witness = witness;
    /// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// witness.apply_delta_assign(&kln_accumulator::evaluate_delta(&x, &[], &[y], &coefficients, &pk)?)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn apply_delta_assign(&mut self, delta: &Delta) -> Result<()> {
        *self = self.apply_delta(delta)?;
        Ok(())
    }

    /// `MemWitUp` (Construction 4.1) for every deletion: the witness for `y` with
    /// `[0; H_{1d,y}·G⁻¹(u)]` added for each `d ∈ deletions`. Additions are free and change
    /// nothing; they are checked as update messages and must not contain `y`. The witness must
    /// verify against `old_accumulator` and the result against `new_accumulator`, else
    /// [`Error::AccumulatorMismatch`]; [`Error::ElementDeleted`] when `y` is among the
    /// deletions.
    ///
    /// # Errors
    ///
    /// As above, and [`Error::ElementAlreadyAdded`] when `y` is among the additions,
    /// [`Error::InvalidElement`] for an addition of another set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let old = acc.clone();
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// let updated = witness.update(&x, &old, &acc, &[], &[y.clone()], &pk)?;
    /// assert!(updated.verify(&x, &pk, &acc));
    /// // The update is checked against both values: swapping them fails.
    /// assert!(witness.update(&x, &acc, &old, &[], &[y.clone()], &pk).is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn update(
        &self,
        y: &Element,
        old_accumulator: &Accumulator,
        new_accumulator: &Accumulator,
        additions: &[Element],
        deletions: &[Element],
        pubkey: &PublicKey,
    ) -> Result<Self> {
        if !self.verify(y, pubkey, old_accumulator) {
            return Err(Error::AccumulatorMismatch);
        }
        let updated = self.apply_delta(&delta(y, additions, deletions, pubkey)?)?;
        if updated.verify(y, pubkey, new_accumulator) {
            Ok(updated)
        } else {
            Err(Error::AccumulatorMismatch)
        }
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
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let old = acc.clone();
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// let mut witness = witness;
    /// witness.update_assign(&x, &old, &acc, &[], &[y.clone()], &pk)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn update_assign(
        &mut self,
        y: &Element,
        old_accumulator: &Accumulator,
        new_accumulator: &Accumulator,
        additions: &[Element],
        deletions: &[Element],
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

    /// The witness updated through one published batch, via [`evaluate_delta`]: `additions`
    /// and `deletions` as passed to [`Accumulator::update`], and the update messages it
    /// returned.
    ///
    /// # Errors
    ///
    /// As [`evaluate_delta`] and [`MembershipWitness::apply_delta`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let coefficients = acc.update_assign(&key, &[], &[y.clone(), z.clone()], &mut state)?;
    /// let updated = witness.batch_update(&x, &[], &[y, z], &coefficients, &pk)?;
    /// assert!(updated.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn batch_update(
        &self,
        y: &Element,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
        pubkey: &PublicKey,
    ) -> Result<Self> {
        self.apply_delta(&evaluate_delta(
            y,
            additions,
            deletions,
            coefficients,
            pubkey,
        )?)
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
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let mut witness = witness;
    /// witness.batch_update_assign(&x, &[], &[y.clone()], &coefficients, &pk)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// // x's own deletion cannot be followed.
    /// let coefficients = acc.update_assign(&key, &[], &[x.clone()], &mut state)?;
    /// assert_eq!(
    ///     witness.batch_update_assign(&x, &[], &[x.clone()], &coefficients, &pk),
    ///     Err(kln_accumulator::Error::ElementDeleted)
    /// );
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn batch_update_assign(
        &mut self,
        y: &Element,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
        pubkey: &PublicKey,
    ) -> Result<()> {
        *self = self.batch_update(y, additions, deletions, coefficients, pubkey)?;
        Ok(())
    }

    /// The witness updated through several published batches, in order, via
    /// [`evaluate_deltas`]; each batch is `(additions, deletions, update messages)`. The book's
    /// chapter "Witnesses and updates" uses it in a full lifecycle.
    ///
    /// # Errors
    ///
    /// As [`evaluate_deltas`] and [`MembershipWitness::apply_delta`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// // A holder that was offline for two published batches catches up in one call.
    /// let c1 = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let c2 = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
    /// let batches = [(vec![], vec![y], c1), (vec![], vec![z], c2)];
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
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        self.apply_delta(&evaluate_deltas(y, deltas, pubkey)?)
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
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let c1 = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let c2 = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
    /// let mut witness = witness;
    /// let batches = [(vec![], vec![y], c1), (vec![], vec![z], c2)];
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
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        *self = self.multi_batch_update(y, deltas, pubkey)?;
        Ok(())
    }

    /// The witness `vector ∈ R^{m+ℓm'}` at `params`, as residues modulo `q`. Fails with
    /// [`Error::DimensionMismatch`] unless it has `m + ℓm'` entries of degree `d`, and with
    /// [`Error::CoefficientOutOfRange`] unless every coefficient is below `q`. The norm is
    /// checked by [`MembershipWitness::verify`].
    ///
    /// # Errors
    ///
    /// As above.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let element = |name: &[u8]| Element::hash(name, key.params());
    /// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let vector = kln_accumulator::lattice::PolyVec::from(witness.clone());
    /// assert_eq!(MembershipWitness::from_vector(vector, key.params())?, witness);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn from_vector(vector: PolyVec, params: &Arc<Params>) -> Result<Self> {
        let len = params.witness_len();
        check_dimension(len, vector.len())?;
        vector.validate(params.ring())?;
        Ok(Self {
            params: Arc::clone(params),
            vector,
        })
    }

    /// The encoding: the 64-byte [`crate::ParamsSpec`] encoding, then the `(m + ℓm')·d` coefficients
    /// centred and offset by `β`, in `⌈log₂(2β + 1)⌉` bits each, least significant bit first,
    /// the last byte padded with zero bits. Fails with [`Error::CoefficientOverBound`] when a
    /// coefficient has magnitude above `β`, which no witness that verifies has.
    ///
    /// The bytes are returned in a buffer that is overwritten when dropped. `TryFrom<&[u8]>`
    /// decodes them, rebuilding the set, and fails with [`Error::InvalidEncodingLength`],
    /// [`Error::NonCanonicalEncoding`] or [`Error::CoefficientOverBound`] on a malformed input.
    ///
    /// # Errors
    ///
    /// As above.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, MembershipWitness, Params};
    /// # use kln_accumulator::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let x = Element::hash(b"x", key.params());
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let to_send = witness.to_bytes()?; // send to x's holder alone; wiped when dropped
    /// assert_eq!(to_send.len(), 64 + 100 * 64 * 43 / 8); // set, then (m + ℓm')·d 43-bit coefficients
    /// // The holder decodes against the set of the manager's public key.
    /// let received = MembershipWitness::from_bytes(pk.params(), &to_send)?;
    /// assert!(received.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        Zeroizing::<Vec<u8>>::try_from(self)
    }

    /// Fails with [`Error::ParameterMismatch`] unless the witness belongs to `params`. Its
    /// shape and range were checked against its set when it was made or decoded; the norm is
    /// checked by [`MembershipWitness::verify`]. See the type's example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn validate(&self, params: &Params) -> Result<()> {
        self.params.check_same(params)
    }

    /// The parameter set the witness belongs to; see the type's example.
    #[must_use]
    pub fn params(&self) -> &Arc<Params> {
        &self.params
    }

    /// The witness vector `s_x`, borrowed.
    pub(crate) fn vector(&self) -> &PolyVec {
        &self.vector
    }

    /// The packed layout of the coefficients: centred, of magnitude at most `β`.
    fn layout(params: &Params) -> Result<Short> {
        Short::new(&params.bounds().witness, params.ring())
    }

    /// [`MembershipWitness::verify`], with malformed inputs as errors.
    fn check(&self, y: &Element, pubkey: &PublicKey, accumulator: &Accumulator) -> Result<bool> {
        let params = &**pubkey.params();
        let ring = params.ring();
        self.validate(params)?;
        accumulator.validate(params)?;
        let matrix = pubkey.membership_matrix(&y.to_bits(params)?)?;
        satisfies(
            &matrix,
            &self.vector,
            accumulator.value(),
            &params.bounds().witness,
            ring,
        )
    }

    /// `s + [0_m; correction]`.
    fn corrected(&self, correction: &PolyVec, params: &Params) -> Result<Self> {
        self.validate(params)?;
        let ring = params.ring();
        let padded = PolyVec::zero(params.spec().m, ring).concat(correction);
        Ok(Self {
            params: Arc::clone(&self.params),
            vector: self.vector.add(&padded, ring)?,
        })
    }
}

/// Whether `matrix · vector = value` and `‖vector‖₂ ≤ bound`: the verification equation of a
/// witness under the matrix its element selects.
pub(crate) fn satisfies(
    matrix: &PolyMatrix,
    vector: &PolyVec,
    value: &PolyVec,
    bound: &Coeff,
    ring: &Ring,
) -> Result<bool> {
    let beta: U512 = bound.resize();
    Ok(matrix.mul_vec(vector, ring)? == *value
        && vector.norm_l2_squared(ring) <= beta.wrapping_mul(&beta))
}

/// Witnesses are equal when they belong to the same set and have the same coefficients.
impl PartialEq for MembershipWitness {
    fn eq(&self, other: &Self) -> bool {
        self.params.spec() == other.params.spec() && self.vector == other.vector
    }
}

impl Eq for MembershipWitness {}

/// The coefficients are overwritten when the witness is dropped.
impl ZeroizeOnDrop for MembershipWitness {}

/// Prints the parameter set, not the coefficients.
impl fmt::Debug for MembershipWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MembershipWitness")
            .field("params", self.params.spec())
            .finish_non_exhaustive()
    }
}

/// The correction is overwritten when the delta is dropped.
impl ZeroizeOnDrop for Delta {}

/// Prints the parameter set, not the correction.
impl fmt::Debug for Delta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delta")
            .field("params", self.params.spec())
            .finish_non_exhaustive()
    }
}

impl Packed for MembershipWitness {
    fn params(&self) -> &Arc<Params> {
        &self.params
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        Self::layout(&self.params)?.write(self.vector.as_slice(), out)
    }

    fn read_body(params: Arc<Params>, body: &[u8]) -> Result<Self> {
        let len = params.witness_len();
        let (vector, rest) = Self::layout(&params)?.read(body, len, params.ring().degree())?;
        packing::finish(Self::from_vector(vector, &params)?, rest)
    }
}

packed_impls! {
    MembershipWitness,
    /// Decodes [`MembershipWitness::to_bytes`], rebuilding and validating the parameter set; the
    /// input must be consumed exactly.
    decode,
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Accumulator, Element, Error, MembershipWitness, Params, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let params = Arc::new(Params::toy()?);
    /// let key = SecretKey::new(None, Arc::clone(&params), &mut StdRng::seed_from_u64(0))?;
    /// let x = Element::hash(b"x", &params);
    /// let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// let bytes = MembershipWitness::new(&x, &acc, &key, &state)?.to_bytes()?;
    /// let witness = MembershipWitness::from_bytes(&params, &bytes)?;
    /// assert!(Arc::ptr_eq(witness.params(), &params));
    /// // The bytes of a witness at another set are refused.
    /// let other = Arc::new(Params::succinct_toy()?);
    /// assert_eq!(MembershipWitness::from_bytes(&other, &bytes).map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    from_bytes,
    /// Serialized as the parameter set and the packed coefficients of
    /// [`MembershipWitness::to_bytes`] (raw in binary formats, hex in human-readable ones);
    /// serialization fails as [`MembershipWitness::to_bytes`] does.
    serialize
}

/// The correction a sequence of deletions makes to one holder's witness: the sum
/// `Σ_y H_{1y,x}·G⁻¹(u) ∈ R^{ℓm'}` over the deleted `y`, added to the last `ℓm'` coordinates by
/// [`MembershipWitness::apply_delta`]. It is specific to the holder's element `x`.
///
/// **Holder-private**: it is computed by the holder from public data, but it depends on the
/// holder's element. It is overwritten when dropped and [`fmt::Debug`] prints only the set. Not
/// serialized; the vb20 `Delta { d, p }` it replaces was not either.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
/// # use kln_accumulator::{PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let element = |name: &[u8]| Element::hash(name, key.params());
/// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
/// let delta = kln_accumulator::evaluate_delta(&x, &[], &[y], &coefficients, &pk)?;
/// assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Delta {
    params: Arc<Params>,
    correction: PolyVec,
}

impl Delta {
    /// The correction `Σ_y H_{1y,x}·G⁻¹(u) ∈ R^{ℓm'}`.
    pub(crate) fn correction(&self) -> &PolyVec {
        &self.correction
    }
}

/// The [`Delta`] for the holder of `y` from one published batch. The update messages must name
/// the deletions, in order ([`Error::CoefficientMismatch`]); additions are free and contribute
/// nothing, but must be valid elements other than `y`. Fails with [`Error::ElementDeleted`]
/// when `y` is among the deletions.
///
/// # Errors
///
/// As above, and [`Error::ElementAlreadyAdded`] when `y` is among the additions,
/// [`Error::InvalidElement`] for an element that is not an `ℓ`-bit string of the set.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
/// # use kln_accumulator::{PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let element = |name: &[u8]| Element::hash(name, key.params());
/// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
/// let delta = kln_accumulator::evaluate_delta(&x, &[], &[y.clone()], &coefficients, &pk)?;
/// assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
/// // The messages must name the deletions.
/// assert_eq!(
///     kln_accumulator::evaluate_delta(&x, &[], &[z], &coefficients, &pk),
///     Err(kln_accumulator::Error::CoefficientMismatch)
/// );
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub fn evaluate_delta<A, D, C>(
    y: &Element,
    additions: A,
    deletions: D,
    coefficients: C,
    pubkey: &PublicKey,
) -> Result<Delta>
where
    A: AsRef<[Element]>,
    D: AsRef<[Element]>,
    C: AsRef<[Coefficient]>,
{
    let deletions = deletions.as_ref();
    let coefficients = coefficients.as_ref();
    let named = coefficients.len() == deletions.len()
        && coefficients
            .iter()
            .zip(deletions)
            .all(|(coefficient, d)| coefficient.element() == d);
    if !named {
        return Err(Error::CoefficientMismatch);
    }
    delta(y, additions.as_ref(), deletions, pubkey)
}

/// The [`Delta`] for the holder of `y` from several published batches, in order: the sum of
/// their [`evaluate_delta`]. Each batch is `(additions, deletions, update messages)`.
///
/// # Errors
///
/// As [`evaluate_delta`], for the first batch that fails.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
/// # use kln_accumulator::{PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # let element = |name: &[u8]| Element::hash(name, key.params());
/// # let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// let c1 = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
/// let c2 = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
/// let batches = [(vec![], vec![y], c1), (vec![], vec![z], c2)];
/// let delta = kln_accumulator::evaluate_deltas(&x, &batches, &pk)?;
/// assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
pub fn evaluate_deltas<A, D, C>(
    y: &Element,
    deltas: &[(A, D, C)],
    pubkey: &PublicKey,
) -> Result<Delta>
where
    A: AsRef<[Element]>,
    D: AsRef<[Element]>,
    C: AsRef<[Coefficient]>,
{
    let params = pubkey.params();
    let ring = params.ring();
    let width = params.extension_len();
    let correction = deltas.iter().try_fold(
        PolyVec::zero(width, ring),
        |sum, (additions, deletions, coefficients)| {
            let batch = evaluate_delta(y, additions, deletions, coefficients, pubkey)?;
            sum.add(&batch.correction, ring)
        },
    )?;
    Ok(Delta {
        params: Arc::clone(params),
        correction,
    })
}

/// The [`Delta`] of `deletions` for the holder of `y`, after checking `additions`.
pub(crate) fn delta(
    y: &Element,
    additions: &[Element],
    deletions: &[Element],
    pubkey: &PublicKey,
) -> Result<Delta> {
    let params = pubkey.params();
    for x in additions {
        x.validate(params)?;
        if x == y {
            return Err(Error::ElementAlreadyAdded);
        }
    }
    Ok(Delta {
        params: Arc::clone(params),
        correction: pubkey.correction(y, deletions)?,
    })
}

/// The encoding of [`MembershipWitness::to_bytes`], which calls this, in a buffer wiped on
/// drop; fails as that method does.
impl TryFrom<&MembershipWitness> for Zeroizing<Vec<u8>> {
    type Error = Error;

    fn try_from(value: &MembershipWitness) -> Result<Self> {
        packing::to_bytes(value).map(Zeroizing::new)
    }
}

#[cfg(test)]
mod tests {
    use super::MembershipWitness;
    use crate::{
        accumulator::{Accumulator, Element},
        key::SecretKey,
        sample::Seed,
        state::ManagerState,
        test_util::TOY,
        vector::PolyVec,
    };
    use crypto_bigint::U512;
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::Arc;

    /// C23 at the boundary: two trapdoor preimages of one target differ by a short `k` with
    /// `A·k = 0`, so `s + t·[k; 0]` satisfies the equation for every integer `t`. `verify`
    /// accepts exactly the multiples whose norm is at most `β` and refuses the first one above.
    #[test]
    fn norm_bound_decides_between_preimages() {
        let mut rng = StdRng::seed_from_u64(23);
        let key = SecretKey::new(
            Some(b"kln/test/c23, a 32-byte test seed"),
            Arc::new((*TOY).clone()),
            &mut rng,
        )
        .unwrap();
        let params = &**key.params();
        let ring = params.ring();
        let public = key.public();
        let mut value = Accumulator::new(&key);
        let mut state = ManagerState::new(&key);
        let x = Element::try_from([5u8].as_slice()).unwrap();
        value.add_assign(&key, &x, &mut state).unwrap();
        let witness = MembershipWitness::new(&x, &value, &key, &state).unwrap();
        let sample = |byte| {
            key.trapdoor()
                .sample_pre(params, public.a(), value.value(), &Seed::from([byte; 32]))
                .unwrap()
        };
        let short = sample(1).sub(&sample(2), ring).unwrap();
        assert_eq!(
            public.a().mul_vec(&short, ring).unwrap(),
            PolyVec::zero(1, ring)
        );
        let width = params.spec().element_bits as usize * params.m_prime();
        let kernel = short.concat(&PolyVec::zero(width, ring));
        let matrix = public
            .membership_matrix(&x.to_bits(params).unwrap())
            .unwrap();
        let beta: U512 = params.bounds().witness.resize();
        let limit = beta.wrapping_mul(&beta);
        let mut shifted = witness.vector.clone();
        let mut accepted = 0;
        loop {
            shifted = shifted.add(&kernel, ring).unwrap();
            assert_eq!(matrix.mul_vec(&shifted, ring).unwrap(), *value.value());
            let over = shifted.norm_l2_squared(ring) > limit;
            let candidate = MembershipWitness::from_vector(shifted.clone(), key.params()).unwrap();
            assert_eq!(
                candidate.verify(&x, public, &value),
                !over,
                "t = {accepted}"
            );
            if over {
                break;
            }
            accepted += 1;
            assert!(accepted < 100);
        }
        assert!(accepted >= 1, "no multiple fell inside β");
        eprintln!(
            "C23: s + t·k verifies for t = 1..={accepted} and is refused at t = {}",
            accepted + 1
        );
    }
}
