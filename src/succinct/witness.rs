// SPDX-License-Identifier: MIT OR Apache-2.0
//! Membership witnesses of the `ℓ`-succinct variant: `Add`'s map of the base preimage,
//! `MemVer` and `MemWitUp`.

use super::{
    bounds::Bounds,
    key::{PublicKey, SecretKey},
};
use crate::{
    accumulator::{Accumulator, Coefficient, Element},
    error::{Error, Result, check_dimension},
    packing::{self, Packed, Short, packed_impls},
    params::Params,
    state::ManagerState,
    vector::PolyVec,
    witness::{self as base, MembershipWitness as InnerWitness},
};
use core::fmt;
use std::sync::Arc;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A succinct membership witness `s_x ∈ R^{m+m'}`: a short vector with
/// `[A | B₁ + (xᵀ⊗I_n)·W]·s_x = c` and `‖s_x‖₂ ≤ β_succ`, held as residues modulo `q`.
///
/// It is bound to its parameter set, which fixes its shape and its encoding;
/// [`MembershipWitness::validate`] checks that the set is the one an operation uses. Encoded as
/// the set and the `(m + m')·d` centred coefficients in `⌈log₂(2β_succ + 1)⌉` bits each:
/// 29,224 bytes at [`crate::ParamsSpec::SUCCINCT_TOY`], where the base witness at the same set
/// would be 28,144 bytes; the saving needs a large `ℓ` (see the [module documentation](super)).
///
/// **Holder-private**, as the base [`InnerWitness`]: overwritten when dropped
/// ([`ZeroizeOnDrop`]), encoded in buffers wiped on drop, printed by [`fmt::Debug`] as its
/// parameter set only, and `Clone` because the API returns updated witnesses by value.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
/// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
/// # let element = |bits: u8| Element::try_from(&[bits][..]);
/// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// assert!(witness.verify(&x, &pk, &acc));
/// assert!(!witness.verify(&y, &pk, &acc));
/// witness.validate(key.params())?;
/// assert_eq!(witness.params(), key.params());
/// let bytes = witness.to_bytes()?;
/// assert_eq!(bytes.len(), 29_224);
/// assert_eq!(MembershipWitness::try_from(bytes.as_slice())?, witness);
/// let vector = kln_accumulator::lattice::PolyVec::from(witness.clone());
/// assert_eq!(vector.len(), key.params().spec().m + key.params().m_prime());
/// assert_eq!(MembershipWitness::from_vector(vector, key.params())?, witness);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, derive_more::Into)]
pub struct MembershipWitness {
    #[into(skip)]
    params: Arc<Params>,
    vector: PolyVec,
}

impl MembershipWitness {
    /// `MemWitCreate`, which also issues the witness at `Add` time (Section 4, `Add` bullet):
    /// the base `MemWitCreate` gives `s̃_x` with `[A | −B₁T₁ − xᵀ⊗G]·s̃_x = c`, and the witness
    /// is `s_x = [I_m, −(xᵀ⊗I_m)T₀; 0, −T₁]·s̃_x`. Fails as [`InnerWitness::new`] does, which
    /// first refuses a `state` whose tag does not verify under `secret_key` with
    /// [`crate::Error::InvalidStateTag`], and then an `accumulator` that is not the state's
    /// current value with [`crate::Error::AccumulatorMismatch`].
    ///
    /// # Errors
    ///
    /// As [`InnerWitness::new`], and [`Error::InvalidElement`] for an element of another set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// assert_eq!(MembershipWitness::new(&x, &acc, &key, &state)?, witness);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new(
        element: &Element,
        accumulator: &Accumulator,
        secret_key: &SecretKey,
        state: &ManagerState,
    ) -> Result<Self> {
        let public = secret_key.public();
        let params = &**public.params();
        let ring = params.ring();
        let (m, mp) = (params.spec().m, params.m_prime());
        let mut tilde = Vec::from(PolyVec::from(InnerWitness::issue(
            element,
            accumulator,
            secret_key,
            state,
        )?));
        let tail: PolyVec = tilde.split_off(m).into_iter().collect();
        let head: PolyVec = tilde.into_iter().collect();
        let mapped = public.compress(&element.to_bits(params)?, &tail)?;
        Ok(Self {
            params: Arc::clone(public.params()),
            vector: head.concat(&PolyVec::zero(mp, ring)).add(&mapped, ring)?,
        })
    }

    /// `MemVer` (Section 4, `Verify` bullet): whether `[A | B₁ + (yᵀ⊗I_n)W]·s = c` and
    /// `‖s‖₂ ≤ β_succ`. Returns false as well when `y`, the witness or the accumulator does
    /// not fit the parameters of `pubkey`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, Error, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
    /// let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// assert!(!witness.verify(&y, &pk, &acc));
    /// // Misuse: the base witness constructor refuses a succinct key.
    /// let base = kln_accumulator::MembershipWitness::new(&x, &acc, &key, &state);
    /// assert_eq!(base.map(drop), Err(Error::CompressedWitnessOnly));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn verify(&self, y: &Element, pubkey: &PublicKey, accumulator: &Accumulator) -> bool {
        self.check(y, pubkey, accumulator).unwrap_or(false)
    }

    /// The witness with `delta` added.
    ///
    /// # Errors
    ///
    /// [`Error::ParameterMismatch`] when `delta` is for another parameter set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let delta = kln_accumulator::succinct::evaluate_delta(&x, &[], &[y], &coefficients, &pk)?;
    /// assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn apply_delta(&self, delta: &Delta) -> Result<Self> {
        self.validate(&delta.params)?;
        Ok(Self {
            params: Arc::clone(&self.params),
            vector: self.vector.add(&delta.correction, delta.params.ring())?,
        })
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
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let delta = kln_accumulator::succinct::evaluate_delta(&x, &[], &[y], &coefficients, &pk)?;
    /// let mut witness = witness;
    /// witness.apply_delta_assign(&delta)?;
    /// assert!(witness.verify(&x, &pk, &acc));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn apply_delta_assign(&mut self, delta: &Delta) -> Result<()> {
        *self = self.apply_delta(delta)?;
        Ok(())
    }

    /// `MemWitUp` (Section 4, `MemWitUp` bullet) for every deletion: the witness for `y` with
    /// `[−(yᵀ⊗I_m)T₀; −T₁]·H_{1d,y}·G⁻¹(u)` added for each `d ∈ deletions`, where `H` is
    /// evaluated on `B = −B₁T₁`. As in the base, additions change nothing, the witness must
    /// verify against `old_accumulator` and the result against `new_accumulator`
    /// ([`Error::AccumulatorMismatch`]), and [`Error::ElementDeleted`] when `y` is deleted.
    ///
    /// # Errors
    ///
    /// As above, and as [`evaluate_delta`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let old = acc.clone();
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// let updated = witness.update(&x, &old, &acc, &[], &[y.clone()], &pk)?;
    /// assert!(updated.verify(&x, &pk, &acc));
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
        let delta = compressed(y, base::delta(y, additions, deletions, pubkey)?, pubkey)?;
        let updated = self.apply_delta(&delta)?;
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
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let old = acc.clone();
    /// acc.remove_assign(&key, &y, &mut state)?;
    /// let mut witness = witness;
    /// witness.update_assign(&x, &old, &acc, &[], &[y], &pk)?;
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

    /// The witness updated through one published batch, via [`evaluate_delta`].
    ///
    /// # Errors
    ///
    /// As [`evaluate_delta`] and [`MembershipWitness::apply_delta`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
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
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let mut witness = witness;
    /// witness.batch_update_assign(&x, &[], &[y], &coefficients, &pk)?;
    /// assert!(witness.verify(&x, &pk, &acc));
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
    /// [`evaluate_deltas`].
    ///
    /// # Errors
    ///
    /// As [`evaluate_deltas`] and [`MembershipWitness::apply_delta`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let c1 = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let c2 = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
    /// let batches = [(vec![], vec![y], c1), (vec![], vec![z], c2)];
    /// assert!(witness.multi_batch_update(&x, &batches, &pk)?.verify(&x, &pk, &acc));
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
    /// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
    /// # let element = |bits: u8| Element::try_from(&[bits][..]);
    /// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
    /// # let (mut acc, mut state) =
    /// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
    /// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let c1 = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    /// let mut witness = witness;
    /// witness.multi_batch_update_assign(&x, &[(vec![], vec![y], c1)], &pk)?;
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

    /// The witness `vector ∈ R^{m+m'}` at `params`, as residues modulo `q`. Fails with
    /// [`Error::DimensionMismatch`] unless it has `m + m'` entries of degree `d`, and with
    /// [`Error::CoefficientOutOfRange`] unless every coefficient is below `q`. The norm is
    /// checked by [`MembershipWitness::verify`]. See the type's example.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn from_vector(vector: PolyVec, params: &Arc<Params>) -> Result<Self> {
        let len = vector_len(params)?;
        check_dimension(len, vector.len())?;
        vector.validate(params.ring())?;
        Ok(Self {
            params: Arc::clone(params),
            vector,
        })
    }

    /// The encoding: the 64-byte [`crate::ParamsSpec`] encoding, then the `(m + m')·d` coefficients
    /// centred and offset by `β_succ` ([`Bounds::witness`]), in `⌈log₂(2β_succ + 1)⌉` bits
    /// each, least significant bit first, the last byte padded with zero bits. Fails with
    /// [`Error::CoefficientOverBound`] when a coefficient has magnitude above `β_succ`, which no
    /// witness that verifies has. The bytes are returned in a buffer that is overwritten when
    /// dropped; `TryFrom<&[u8]>` decodes them.
    ///
    /// # Errors
    ///
    /// As above.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Accumulator, Element, Params};
    /// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// # let pk = PublicKey::from(&key);
    /// # let x = Element::try_from(&[1u8][..])?;
    /// # let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    /// let to_send = witness.to_bytes()?; // send to x's holder alone; wiped when dropped
    /// assert_eq!(to_send.len(), 29_224); // m + m' polynomials, but wider coefficients
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

    /// The packed layout of the coefficients: centred, of magnitude at most `β_succ`.
    fn layout(params: &Params) -> Result<Short> {
        Short::new(&Bounds::try_from(params)?.witness, params.ring())
    }

    /// [`MembershipWitness::verify`], with malformed inputs as errors.
    fn check(&self, y: &Element, pubkey: &PublicKey, accumulator: &Accumulator) -> Result<bool> {
        let params = &**pubkey.params();
        let ring = params.ring();
        self.validate(params)?;
        accumulator.validate(params)?;
        let matrix = pubkey.verification_matrix(&y.to_bits(params)?)?;
        base::satisfies(
            &matrix,
            &self.vector,
            accumulator.value(),
            &pubkey.bounds().witness,
            ring,
        )
    }
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

/// `m + m'`, the length of a succinct witness at `params`; [`Error::WitnessBoundTooLarge`] on
/// overflow.
fn vector_len(params: &Params) -> Result<usize> {
    params
        .spec()
        .m
        .checked_add(params.m_prime())
        .ok_or(Error::WitnessBoundTooLarge)
}

impl Packed for MembershipWitness {
    fn params(&self) -> &Arc<Params> {
        &self.params
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        Self::layout(&self.params)?.write(self.vector.as_slice(), out)
    }

    fn read_body(params: Arc<Params>, body: &[u8]) -> Result<Self> {
        let len = vector_len(&params)?;
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
    /// use kln_accumulator::{Accumulator, Element, Error, Params};
    /// use kln_accumulator::succinct::{MembershipWitness, SecretKey};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let params = Arc::new(Params::succinct_toy()?);
    /// let key = SecretKey::new(None, Arc::clone(&params), &mut StdRng::seed_from_u64(0))?;
    /// let x = Element::try_from(&[1u8][..])?;
    /// let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
    /// let bytes = MembershipWitness::new(&x, &acc, &key, &state)?.to_bytes()?;
    /// let witness = MembershipWitness::from_bytes(&params, &bytes)?;
    /// assert!(Arc::ptr_eq(witness.params(), &params));
    /// // The bytes of a witness at another set are refused.
    /// let other = Arc::new(Params::toy()?);
    /// assert_eq!(MembershipWitness::from_bytes(&other, &bytes).map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    from_bytes,
    /// Serialized as the parameter set and the packed coefficients of
    /// [`MembershipWitness::to_bytes`] (raw in binary formats, hex in human-readable ones);
    /// serialization fails as [`MembershipWitness::to_bytes`] does.
    serialize
}

/// The correction a sequence of deletions makes to one holder's succinct witness:
/// `[−(xᵀ⊗I_m)T₀; −T₁]·Σ_y H_{1y,x}·G⁻¹(u) ∈ R^{m+m'}`, added by
/// [`MembershipWitness::apply_delta`]. It is specific to the holder's element `x`.
///
/// **Holder-private**, as the base [`base::Delta`]: overwritten when dropped, printed by
/// [`fmt::Debug`] as its parameter set only, not serialized.
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
/// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
/// # let element = |bits: u8| Element::try_from(&[bits][..]);
/// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
/// let delta = kln_accumulator::succinct::evaluate_delta(&x, &[], &[y], &coefficients, &pk)?;
/// assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Delta {
    params: Arc<Params>,
    correction: PolyVec,
}

/// The [`Delta`] for the holder of `y` from one published batch, as the base
/// [`crate::evaluate_delta`] for `B = −B₁T₁`, mapped into `R^{m+m'}`.
///
/// # Errors
///
/// As the base [`crate::evaluate_delta`].
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
/// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
/// # let element = |bits: u8| Element::try_from(&[bits][..]);
/// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
/// let delta = kln_accumulator::succinct::evaluate_delta(&x, &[], &[y], &coefficients, &pk)?;
/// assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
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
    let delta = base::evaluate_delta(y, additions, deletions, coefficients, pubkey)?;
    compressed(y, delta, pubkey)
}

/// The [`Delta`] for the holder of `y` from several published batches, in order. The map into
/// `R^{m+m'}` is linear, so it is applied once to the summed base correction.
///
/// # Errors
///
/// As the base [`crate::evaluate_deltas`].
///
/// # Examples
///
/// ```
/// # use kln_accumulator::{Accumulator, Element, ManagerState, Params};
/// # use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
/// # use rand::{SeedableRng, rngs::StdRng};
/// # use std::sync::Arc;
/// # let mut rng = StdRng::seed_from_u64(0);
/// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
/// # let pk = PublicKey::from(&key);
/// # // ℓ = 4 at this set: name the elements directly, since hashes of three names may collide.
/// # let element = |bits: u8| Element::try_from(&[bits][..]);
/// # let (x, y, z) = (element(1)?, element(2)?, element(3)?);
/// # let (mut acc, mut state) =
/// #     Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
/// # let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
/// let c1 = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
/// let c2 = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
/// let batches = [(vec![], vec![y], c1), (vec![], vec![z], c2)];
/// let delta = kln_accumulator::succinct::evaluate_deltas(&x, &batches, &pk)?;
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
    compressed(y, base::evaluate_deltas(y, deltas, pubkey)?, pubkey)
}

/// The base correction for `y`, in `R^{ℓm'}`, mapped into `R^{m+m'}`.
fn compressed(y: &Element, delta: base::Delta, pubkey: &PublicKey) -> Result<Delta> {
    let params = pubkey.params();
    Ok(Delta {
        params: Arc::clone(params),
        correction: pubkey.compress(&y.to_bits(params)?, delta.correction())?,
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
    use super::{InnerWitness, MembershipWitness};
    use crate::{
        accumulator::{Accumulator, Element},
        params::{Params, ParamsSpec, TrapdoorDistribution},
        succinct::{PublicKey, SecretKey},
        vector::PolyVec,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::Arc;

    /// `s_x = [s̃₁ − (xᵀ⊗I_m)·T₀·s̃₂ ; −T₁·s̃₂]` from a base preimage `s̃`, computed from
    /// `T₀` and `T₁` without the key's own map.
    fn mapped(pk: &PublicKey, x: &Element, tilde: &PolyVec) -> PolyVec {
        let params = &**pk.params();
        let ring = params.ring();
        let m = params.spec().m;
        let (s1, s2) = tilde.as_slice().split_at(m);
        let s2: PolyVec = s2.iter().cloned().collect();
        let t0_s2 = pk.t0().mul_vec(&s2, ring).unwrap();
        let bits = x.to_bits(params).unwrap();
        let top = bits
            .as_slice()
            .iter()
            .enumerate()
            .filter(|(_, bit)| **bit)
            .fold(s1.iter().cloned().collect::<PolyVec>(), |top, (i, _)| {
                let block: PolyVec = t0_s2.as_slice()[i * m..(i + 1) * m]
                    .iter()
                    .cloned()
                    .collect();
                top.sub(&block, ring).unwrap()
            });
        top.concat(&pk.t1().mul_vec(&s2, ring).unwrap().neg(ring).unwrap())
    }

    /// C32: the succinct witness is the paper's map of the base preimage for
    /// `[A | −B₁T₁ − xᵀ⊗G]`, which verifies under the base key; under both trapdoor
    /// distributions. The base preimage is reached through the crate-private path, because the
    /// public base constructor refuses a succinct key.
    #[test]
    fn the_witness_is_the_map_of_the_base_preimage() {
        for distribution in [
            TrapdoorDistribution::Gaussian,
            TrapdoorDistribution::Ternary,
        ] {
            let spec = ParamsSpec::SUCCINCT_TOY.with_trapdoor(distribution);
            let params = Arc::new(Params::try_from(spec).unwrap());
            let key = SecretKey::new(
                Some(b"kln/test/succinct-map, a 32-byte seed"),
                params,
                &mut StdRng::seed_from_u64(0),
            )
            .unwrap();
            let pk = PublicKey::from(&key);
            let x = Element::try_from(&[5u8][..]).unwrap();
            let (value, state) =
                Accumulator::with_elements(&key, core::slice::from_ref(&x)).unwrap();
            let tilde = InnerWitness::issue(&x, &value, &key, &state).unwrap();
            assert!(tilde.verify(&x, &pk, &value));
            let witness = MembershipWitness::new(&x, &value, &key, &state).unwrap();
            assert_eq!(
                mapped(&pk, &x, &PolyVec::from(tilde)),
                PolyVec::from(witness)
            );
        }
    }
}
