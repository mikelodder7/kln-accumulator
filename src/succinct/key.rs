// SPDX-License-Identifier: MIT OR Apache-2.0
//! The keys of the `ℓ`-succinct variant: `Gen` with `pp = (A, B₁, W, T₀, T₁, u)`.

use super::bounds::Bounds;
use crate::{
    error::{Error, Result, check_dimension},
    eval::BitString,
    key::{
        PublicKey as InnerPublicKey, RootSeeded, SecretKey as InnerSecretKey, WitnessForm,
        derivation_seed, root_seeded_impls,
    },
    matrix::{PolyMatrix, Shape},
    packing::{self, Packed, Short, Uniform, packed_impls},
    params::Params,
    poly::Poly,
    sample::{DomainLabel, Seed, UniformSampler, hash_to_seed, xof},
    trapdoor::{Trapdoor, least_width_vector},
    vector::PolyVec,
};
use core::fmt;
use rand_core::CryptoRng;
use std::sync::Arc;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Label that hashes the caller's seed into the root seed of a succinct key.
const LABEL_ROOT: &[u8] = b"kln/succinct/keygen/root";

/// Label of the root seed of the inner Construction 4.1 key (trapdoor, `u`, PRF key).
const LABEL_INNER: &[u8] = b"kln/succinct/keygen/inner";

/// Label of the uniform matrix `B₁`.
const LABEL_B1: &[u8] = b"kln/succinct/keygen/b1";

/// Label of the uniform matrix `W`.
const LABEL_W: &[u8] = b"kln/succinct/keygen/w";

/// Label of the secret seed the columns of `T` are sampled from.
const LABEL_T: &[u8] = b"kln/succinct/keygen/t";

/// Label of the Gaussian draw of a column of `T₁`.
const LABEL_T1: &[u8] = b"kln/succinct/keygen/t1";

/// The manager's secret key of the `ℓ`-succinct variant: the base key for `B = −B₁·T₁`, which
/// it dereferences to, with the succinct public key.
///
/// The base key derives its trapdoor, `u`, genesis value, PRF key and state-tag key under a
/// label of its own, so its bytes (the base [`crate::SecretKey::to_bytes`], reached through the
/// dereference), decoded as a [`crate::SecretKey`], give an unrelated Construction 4.1 key,
/// which refuses this key's states with [`Error::InvalidStateTag`].
///
/// Everything is derived from a 32-byte root seed and the parameter set, so the serialized form
/// is the parameter set and that seed. The seeds that drive the trapdoor and the sampling of `T` are secret: the
/// Gaussian draws behind `T₀` together with `T₀` would reveal `T_A`.
///
/// **Secret (owner only).** The root seed and the base key with its trapdoor are overwritten
/// when the key is dropped ([`ZeroizeOnDrop`]), as are the seeds and sampler state used to
/// draw `T` during key generation; the key is neither `Copy` nor `Clone`; [`fmt::Debug`] prints
/// none of it; [`SecretKey::to_bytes`] and the serde forms use buffers wiped on drop.
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
/// assert_eq!(SecretKey::try_from(key.to_bytes().as_slice())?, key);
/// // The base key it dereferences to runs the manager's operations.
/// let base: &kln_accumulator::SecretKey = &key;
/// assert_eq!(base.params(), key.params());
/// assert_eq!(format!("{key:?}"), "SecretKey { .. }");
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(derive_more::Deref)]
pub struct SecretKey {
    seed: Seed,
    /// The base Construction 4.1 key for `B = −B₁·T₁`, on which the accumulator operations
    /// run; the key dereferences to it.
    #[deref]
    inner: InnerSecretKey,
    public: PublicKey,
}

impl SecretKey {
    /// `Gen`: a key for `params`. With `Some(seed)` the key is a function of `seed` and the set
    /// alone, and a seed shorter than [`crate::MIN_SEED_BYTES`] is refused with
    /// [`Error::SeedTooShort`] before any work; with `None` the seed is 32 bytes from `rng`.
    /// `B₁`, `W`, `T` and the base key are derived from a hash of the root seed and the 64-byte
    /// encoded set, so one seed under two sets gives unrelated keys. Fails with
    /// [`Error::WitnessBoundTooLarge`] when the set's modulus is too small for the succinct
    /// bound (see [`Bounds`]).
    ///
    /// The cost is the base key generation plus `ℓm'` columns of `T`, each `ℓ` trapdoor-stage
    /// preimages: far more than a base key at [`crate::ParamsSpec::SUCCINCT_TOY`] (the
    /// `variants` benchmark measures it). At
    /// [`crate::ParamsSpec::SUCCINCT_128`] the public key would be about 110 GiB, so key generation
    /// there is not practical.
    ///
    /// # Errors
    ///
    /// [`Error::WitnessBoundTooLarge`] as above, and as [`crate::SecretKey::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::{Params, ParamsSpec};
    /// # use kln_accumulator::succinct::SecretKey;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// assert_eq!(key.params().spec(), &ParamsSpec::SUCCINCT_TOY);
    /// // The base toy set's modulus is too small for the succinct bound.
    /// assert!(SecretKey::new(None, Arc::new(Params::toy()?), &mut rng).is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn new<R: CryptoRng + ?Sized>(
        seed: Option<&[u8]>,
        params: Arc<Params>,
        rng: &mut R,
    ) -> Result<Self> {
        Self::from_input(seed, params, rng)
    }

    /// The encoding: the 64-byte [`crate::ParamsSpec`] encoding followed by the 32-byte root
    /// seed, 96 bytes. It is the whole secret, and is overwritten when dropped.
    /// `TryFrom<&[u8]>` decodes it and rebuilds every key, `T` included, from the seed, so
    /// reloading costs a key generation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::succinct::SecretKey;
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// let stored = key.to_bytes(); // wiped when `stored` is dropped
    /// assert_eq!(stored.len(), 96); // the 2 MiB public key is rebuilt, not stored
    /// assert_eq!(SecretKey::try_from(stored.as_slice())?, key);
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::<Vec<u8>>::from(self)
    }

    /// The succinct public key.
    pub(super) fn public(&self) -> &PublicKey {
        &self.public
    }
}

impl RootSeeded for SecretKey {
    const LABEL_ROOT: &'static [u8] = LABEL_ROOT;

    fn from_root(seed: Seed, params: Arc<Params>) -> Result<Self> {
        let bounds = Bounds::try_from(&*params)?;
        let derived = derivation_seed(&seed, &params);
        let base = derived.as_bytes().as_slice();
        let inner_seed = hash_to_seed(DomainLabel::from(LABEL_INNER), &[base]);
        let t_seed = hash_to_seed(DomainLabel::from(LABEL_T), &[base]);
        let generated = InnerSecretKey::with_b(
            inner_seed,
            params,
            WitnessForm::Compressed,
            |params, _, a, trapdoor| {
                let ring = params.ring();
                let [b1_shape, w_shape, _, _] = Parts::shapes(params)?;
                let b1 = UniformSampler::new(&derived, DomainLabel::from(LABEL_B1))
                    .matrix(b1_shape, ring);
                let w =
                    UniformSampler::new(&derived, DomainLabel::from(LABEL_W)).matrix(w_shape, ring);
                let (t0, t1) = sample_t(params, (a, trapdoor), &w, &t_seed)?;
                let b = b1.mul(&t1, ring)?.neg(ring)?;
                Ok((b, (b1, w, t0, t1)))
            },
        );
        let (inner, (b1, w, t0, t1)) = generated?;
        let public = PublicKey {
            trapdoor: PublicKey::trapdoor_layout(inner.params(), &bounds, &t0, &t1)?,
            inner: InnerPublicKey::from(&inner),
            b1,
            w,
            t0,
            t1,
            bounds,
        };
        Ok(Self {
            seed,
            inner,
            public,
        })
    }

    fn root(&self) -> &Seed {
        &self.seed
    }

    fn root_params(&self) -> &Arc<Params> {
        self.inner.params()
    }
}

/// Samples `T = [T₀; T₁]` with `[I_ℓ⊗A | W]·T = I_ℓ⊗G` (Section 4, `Gen` bullet; Remark 2.3)
/// one column at a time. For column `j`, the target is column `j` of `I_ℓ⊗G`, which is column
/// `j mod m'` of `G` in block `⌊j/m'⌋` and zero elsewhere. This is `SampleLeft` on
/// `[I_ℓ⊗A | W]` at the preimage sampler's least width `ς`: `T₁`'s column is a width-`ς`
/// Gaussian in `R^{m'}`, and then block `i` of `T₀`'s column is `SamplePre(A, T_A, t_i − W_i·t₁,
/// ς)` for the target's block `t_i`, since `I_ℓ⊗A` is block diagonal.
///
/// Erratum (Section 4, p. 19): the bullet types `T` over `R_q`; it is a short matrix over `R`,
/// held as residues below `q/2` like every preimage here. Remark 2.3 (p. 12) writes
/// `T₀ ∈ R^{ℓm×ℓm}`, `T₁ ∈ R^{m×ℓm}` and `[A | (xᵀ⊗I_n)W] ∈ R^{n×2m}`, with `m` for the gadget
/// width as in Definition 2.10; with the gadget width `m'` of Section 4 they are
/// `T₀ ∈ R^{ℓm×ℓm'}`, `T₁ ∈ R^{m'×ℓm'}` and `n × (m + m')`, as the Section 4 bullet says.
fn sample_t(
    params: &Params,
    (a, trapdoor): (&PolyMatrix, &Trapdoor),
    w: &PolyMatrix,
    seed: &Seed,
) -> Result<(PolyMatrix, PolyMatrix)> {
    let ring = params.ring();
    let (n, mp) = (params.spec().n, params.m_prime());
    let [_, _, t0_shape, _] = Parts::shapes(params)?;
    let g = PolyMatrix::from(params.gadget());
    let columns = (0..t0_shape.cols)
        .map(|j| {
            let column_seed = hash_to_seed(
                DomainLabel::from(LABEL_T),
                &[seed.as_bytes(), &(j as u64).to_le_bytes()],
            );
            let t1 = least_width_vector(
                params,
                &mut xof(&column_seed, DomainLabel::from(LABEL_T1)),
                mp,
            );
            let w_t1 = Vec::from(w.mul_vec(&t1, ring)?);
            let gadget_column = (0..n)
                .map(|r| g.get(r, j % mp).cloned())
                .collect::<Option<PolyVec>>()
                .ok_or(Error::DimensionMismatch {
                    expected: mp,
                    found: j % mp,
                })?;
            let mut t0 = Vec::with_capacity(t0_shape.rows);
            for (i, w_t1_block) in w_t1.chunks_exact(n).enumerate() {
                let w_t1_block: PolyVec = w_t1_block.iter().cloned().collect();
                let target = if i == j / mp {
                    gadget_column.sub(&w_t1_block, ring)?
                } else {
                    w_t1_block.neg(ring)?
                };
                let block_seed = hash_to_seed(
                    DomainLabel::from(LABEL_T),
                    &[column_seed.as_bytes(), &(i as u64).to_le_bytes()],
                );
                let block = trapdoor.sample_left_least(params, a, &target, &block_seed)?;
                t0.extend(Vec::from(block));
            }
            Ok((t0, Vec::from(t1)))
        })
        .collect::<Result<Vec<_>>>()?;
    let (t0, t1): (Vec<_>, Vec<_>) = columns.into_iter().unzip();
    Ok((from_columns(t0, t0_shape.rows)?, from_columns(t1, mp)?))
}

/// The matrix with `rows` rows whose columns are `columns`.
fn from_columns(columns: Vec<Vec<Poly>>, rows: usize) -> Result<PolyMatrix> {
    let shape = Shape {
        rows,
        cols: columns.len(),
    };
    let mut iters: Vec<_> = columns.into_iter().map(Vec::into_iter).collect();
    let mut entries = Vec::with_capacity(shape.len().ok_or(Error::WitnessBoundTooLarge)?);
    for _ in 0..rows {
        entries.extend(iters.iter_mut().filter_map(Iterator::next));
    }
    PolyMatrix::new(shape, entries)
}

impl From<&SecretKey> for PublicKey {
    /// The succinct public key `pp = (A, B₁, W, T₀, T₁, u)` of `secret_key`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::succinct::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// let pk = PublicKey::from(&key);
    /// assert!(Arc::ptr_eq(pk.params(), key.params()));
    /// // It dereferences to the base public key (A, −B₁·T₁, u) of the base key inside.
    /// let base: &kln_accumulator::PublicKey = &pk;
    /// assert_eq!(*base, kln_accumulator::PublicKey::from(&*key));
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    fn from(secret_key: &SecretKey) -> Self {
        secret_key.public.clone()
    }
}

root_seeded_impls! {
    SecretKey,
    /// Decodes [`SecretKey::to_bytes`] and rebuilds every key from the seed.
    decode,
    /// The root seed and the inner key overwrite themselves when dropped, so the key needs no
    /// `Drop` of its own.
    wipe
}

/// The public parameters `pp = (A, B₁, W, T₀, T₁, u)` of the `ℓ`-succinct variant with their
/// parameter set and [`Bounds`]. It dereferences to the base public key `(A, −B₁T₁, u)`, so
/// [`crate::PublicKey::b`] through it is `−B₁·T₁`.
///
/// A deserialized or decoded key has its set rebuilt and validated, the shapes and ranges of
/// every matrix checked against it, `−B₁·T₁` recomputed, and the bounds derived again.
///
/// **Public.** It is large: `T₀` is dense, `ℓm × ℓm'` polynomials. At
/// [`crate::ParamsSpec::SUCCINCT_TOY`] the key has 8206 polynomials, 7200 of them in `T₀`, and
/// encodes to 2,149,984 bytes (2.1 MiB); at [`crate::ParamsSpec::SUCCINCT_128`] it would have
/// 5,935,258 polynomials and encode to about 110 GiB, of which `(A, B₁, W, u)`, the part
/// Table 2's 171.7 MB counts, is 171.7 MiB.
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
/// let spec = key.params().spec();
/// let (ell, mp) = (spec.element_bits as usize, key.params().m_prime());
/// assert_eq!(pk.t0().shape().rows, ell * spec.m);
/// assert_eq!(pk.t0().shape().cols, ell * mp);
/// assert_eq!(pk.t1().shape().rows, mp);
/// assert_eq!(pk.b1().shape().cols, mp);
/// assert_eq!(pk.w().shape().rows, spec.n * ell);
/// assert!(pk.bounds().witness > key.params().bounds().witness);
/// let bytes = pk.to_bytes();
/// assert_eq!(bytes.len(), 2_149_984);
/// assert_eq!(PublicKey::try_from(bytes.as_slice())?, pk);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Deref)]
pub struct PublicKey {
    /// The base public key `(A, −B₁·T₁, u)` on which the base algorithms run; the key
    /// dereferences to it.
    #[deref]
    inner: InnerPublicKey,
    b1: PolyMatrix,
    w: PolyMatrix,
    t0: PolyMatrix,
    t1: PolyMatrix,
    bounds: Bounds,
    trapdoor: Short,
}

impl PublicKey {
    /// `B₁ ∈ R_q^{n×m'}`. See the type's example.
    #[must_use]
    pub fn b1(&self) -> &PolyMatrix {
        &self.b1
    }

    /// `W ∈ R_q^{nℓ×m'}`. See the type's example.
    #[must_use]
    pub fn w(&self) -> &PolyMatrix {
        &self.w
    }

    /// `T₀ ∈ R^{ℓm×ℓm'}`, dense. See the type's example.
    #[must_use]
    pub fn t0(&self) -> &PolyMatrix {
        &self.t0
    }

    /// `T₁ ∈ R^{m'×ℓm'}`. See the type's example.
    #[must_use]
    pub fn t1(&self) -> &PolyMatrix {
        &self.t1
    }

    /// The width of `T` and the witness bound at this key's set. See the type's example.
    #[must_use]
    pub fn bounds(&self) -> &Bounds {
        &self.bounds
    }

    /// The encoding: the 64-byte [`crate::ParamsSpec`] encoding, then the coefficients of `A`, `B₁` and `W`
    /// (entries row-major) in `⌈log₂ q⌉` bits each, of `T₀` and `T₁` centred in
    /// `⌈log₂(2t + 1)⌉` bits each for `t` = [`Bounds::trapdoor_entry`], and of `u` in
    /// `⌈log₂ q⌉` bits each; each part is written least significant bit first with its last
    /// byte padded with zero bits. `TryFrom<&[u8]>` decodes it and checks everything again.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kln_accumulator::Params;
    /// # use kln_accumulator::succinct::{PublicKey, SecretKey};
    /// # use rand::{SeedableRng, rngs::StdRng};
    /// # use std::sync::Arc;
    /// # let mut rng = StdRng::seed_from_u64(0);
    /// # let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::succinct_toy()?), &mut rng)?;
    /// let pk = PublicKey::from(&key);
    /// let published = pk.to_bytes();
    /// assert_eq!(published.len(), 2_149_984);
    /// assert_eq!(PublicKey::from_bytes(key.params(), &published)?, pk);
    /// // Misuse: through the base key it dereferences to, `to_bytes` drops B₁, W and T.
    /// let base: &kln_accumulator::PublicKey = &pk;
    /// assert!(base.to_bytes().len() < published.len());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    /// Appends the packed coefficients of `A`, `B₁`, `W`, `T₀`, `T₁` and `u`. Every key was
    /// built through [`PublicKey::trapdoor_layout`], so its `T` is within the layout.
    fn write_coefficients(&self, out: &mut Vec<u8>) {
        let uniform = Uniform::new(self.params().ring());
        let matrices = [self.a(), &self.b1, &self.w];
        uniform.write(matrices.into_iter().flat_map(PolyMatrix::entries), out);
        self.trapdoor
            .write_in_range(self.t0.entries().iter().chain(self.t1.entries()), out);
        uniform.write(self.u().as_slice(), out);
    }

    /// The packed layout of `T₀` and `T₁` at `params`, after checking them against it.
    fn trapdoor_layout(
        params: &Params,
        bounds: &Bounds,
        t0: &PolyMatrix,
        t1: &PolyMatrix,
    ) -> Result<Short> {
        let layout = Short::new(&bounds.trapdoor_entry, params.ring())?;
        layout.check(t0.entries().iter().chain(t1.entries()))?;
        Ok(layout)
    }

    /// `[A | B₁ + (xᵀ⊗I_n)·W]`, the matrix a witness for `x` is a short preimage under.
    pub(super) fn verification_matrix(&self, x: &BitString) -> Result<PolyMatrix> {
        let ring = self.params().ring();
        let n = self.params().spec().n;
        let right = self.selected(x, &self.w, n)?.add(&self.b1, ring)?;
        self.a().hconcat(&right)
    }

    /// `[−(xᵀ⊗I_m)·T₀·v ; −T₁·v] ∈ R^{m+m'}` for `v ∈ R^{ℓm'}`: the image under `S_x` of
    /// `[0; v]`, which is how a correction to the last `ℓm'` entries of a base witness reaches
    /// the succinct one.
    pub(super) fn compress(&self, x: &BitString, v: &PolyVec) -> Result<PolyVec> {
        let ring = self.params().ring();
        let m = self.params().spec().m;
        let top = self.selected(x, &self.t0, m)?.mul_vec(v, ring)?.neg(ring)?;
        let bottom = self.t1.mul_vec(v, ring)?.neg(ring)?;
        Ok(top.concat(&bottom))
    }

    /// `(xᵀ⊗I_h)·M = Σ_{i : x_i = 1} M_i` for `M` made of `ℓ` row blocks `M_i` of height `h`.
    fn selected(&self, x: &BitString, matrix: &PolyMatrix, height: usize) -> Result<PolyMatrix> {
        let ring = self.params().ring();
        let ell = self.params().spec().element_bits as usize;
        check_dimension(ell, x.as_slice().len())?;
        let zero = PolyMatrix::zero(
            Shape {
                rows: height,
                cols: matrix.shape().cols,
            },
            ring,
        );
        x.as_slice()
            .iter()
            .enumerate()
            .filter(|(_, bit)| **bit)
            .try_fold(zero, |sum, (i, _)| {
                sum.add(&matrix.row_block(i * height, height)?, ring)
            })
    }

    /// Checks every shape and range against `params` and derives `−B₁·T₁` and the bounds.
    fn from_parts(params: Arc<Params>, a: PolyMatrix, rest: Parts) -> Result<Self> {
        let bounds = Bounds::try_from(&*params)?;
        let ring = params.ring();
        let (b1, w, t0, t1, u) = (rest.b1, rest.w, rest.t0, rest.t1, rest.u);
        for (matrix, shape) in [&b1, &w, &t0, &t1].into_iter().zip(Parts::shapes(&params)?) {
            if matrix.shape() != shape {
                return Err(Error::DimensionMismatch {
                    expected: shape.saturating_len(),
                    found: matrix.shape().saturating_len(),
                });
            }
            matrix.validate(ring)?;
        }
        let trapdoor = Self::trapdoor_layout(&params, &bounds, &t0, &t1)?;
        let b = b1.mul(&t1, ring)?.neg(ring)?;
        Ok(Self {
            inner: InnerPublicKey::from_parts(params, a, b, u)?,
            b1,
            w,
            t0,
            t1,
            bounds,
            trapdoor,
        })
    }
}

/// `B₁`, `W`, `T₀`, `T₁` and `u` of an encoded or serialized key.
struct Parts {
    b1: PolyMatrix,
    w: PolyMatrix,
    t0: PolyMatrix,
    t1: PolyMatrix,
    u: PolyVec,
}

impl Parts {
    /// The shapes of `B₁`, `W`, `T₀` and `T₁` at `params`: `n × m'`, `nℓ × m'`, `ℓm × ℓm'` and
    /// `m' × ℓm'`. Fails with [`Error::WitnessBoundTooLarge`] when a dimension overflows.
    fn shapes(params: &Params) -> Result<[Shape; 4]> {
        let spec = params.spec();
        let (n, m, mp, wide) = (spec.n, spec.m, params.m_prime(), params.extension_len());
        let ell = spec.element_bits as usize;
        let times_ell = |dimension: usize| {
            dimension
                .checked_mul(ell)
                .ok_or(Error::WitnessBoundTooLarge)
        };
        Ok([
            Shape { rows: n, cols: mp },
            Shape {
                rows: times_ell(n)?,
                cols: mp,
            },
            Shape {
                rows: times_ell(m)?,
                cols: wide,
            },
            Shape {
                rows: mp,
                cols: wide,
            },
        ])
    }
}

impl Packed for PublicKey {
    fn params(&self) -> &Arc<Params> {
        self.inner.params()
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.write_coefficients(out);
        Ok(())
    }

    fn read_body(params: Arc<Params>, body: &[u8]) -> Result<Self> {
        let bounds = Bounds::try_from(&*params)?;
        let uniform = Uniform::new(params.ring());
        let trapdoor = Short::new(&bounds.trapdoor_entry, params.ring())?;
        let degree = params.ring().degree();
        let spec = params.spec();
        let a_shape = Shape {
            rows: spec.n,
            cols: spec.m,
        };
        let [b1, w, t0, t1] = Parts::shapes(&params)?;
        let size = |shapes: &[Shape]| {
            shapes
                .iter()
                .try_fold(0usize, |total, shape| {
                    shape.len().and_then(|len| total.checked_add(len))
                })
                .ok_or(Error::WitnessBoundTooLarge)
        };
        let (head, rest) = uniform.read(body, size(&[a_shape, b1, w])?, degree)?;
        let (tail, rest) = trapdoor.read(rest, size(&[t0, t1])?, degree)?;
        let (u, rest) = uniform.read(rest, spec.n, degree)?;
        let mut head = Vec::from(head).into_iter();
        let mut tail = Vec::from(tail).into_iter();
        let matrix = |entries: &mut std::vec::IntoIter<Poly>, shape: Shape| {
            let len = shape.len().ok_or(Error::WitnessBoundTooLarge)?;
            PolyMatrix::new(shape, entries.take(len).collect())
        };
        let a = matrix(&mut head, a_shape)?;
        let parts = Parts {
            b1: matrix(&mut head, b1)?,
            w: matrix(&mut head, w)?,
            t0: matrix(&mut tail, t0)?,
            t1: matrix(&mut tail, t1)?,
            u,
        };
        packing::finish(Self::from_parts(params, a, parts)?, rest)
    }
}

packed_impls! {
    PublicKey,
    /// Decodes [`PublicKey::to_bytes`], rebuilding and validating the parameter set; the input must
    /// be consumed exactly.
    decode,
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::{Error, Params, succinct::{PublicKey, SecretKey}};
    /// use rand::{SeedableRng, rngs::StdRng};
    /// use std::sync::Arc;
    ///
    /// let params = Arc::new(Params::succinct_toy()?);
    /// let key = SecretKey::new(None, Arc::clone(&params), &mut StdRng::seed_from_u64(0))?;
    /// let bytes = PublicKey::from(&key).to_bytes();
    /// let pk = PublicKey::from_bytes(&params, &bytes)?;
    /// assert!(Arc::ptr_eq(pk.params(), &params));
    /// // The bytes of a key at another set are refused.
    /// let other = Arc::new(Params::toy()?);
    /// assert_eq!(PublicKey::from_bytes(&other, &bytes).map(drop), Err(Error::ParameterMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    from_bytes,
    /// Serialized as the parameter set and the packed coefficients of [`PublicKey::to_bytes`] (raw
    /// in binary formats, hex in human-readable ones).
    serialize
}

/// The encoding of [`PublicKey::to_bytes`], which calls this.
impl From<&PublicKey> for Vec<u8> {
    fn from(value: &PublicKey) -> Self {
        packing::to_bytes_with(value, PublicKey::write_coefficients)
    }
}
