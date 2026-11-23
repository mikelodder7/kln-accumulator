# The succinct variant

> **In short.** The [succinct variant](glossary.md#succinct-variant) makes witnesses whose size
> does not grow with the length of an element, at the cost of a very large public key and a
> different assumption. Today it is for study only: it runs at a toy set that gives no
> security, keys at its 128-bit set are too large to generate, and it has no membership proofs.
>
> **Read this when** you are studying shorter witnesses for long elements.
>
> **New here?** You can skip this chapter. Use the base variant for working code;
> [The succinct variant today](choosing.md#the-succinct-variant-today) says why.

The module `kln_accumulator::succinct` is the `ℓ`-succinct variant of Construction 4.1
("Reducing the size of witnesses", Section 4 of ePrint 2025/1099). Use it when witnesses must
be short and the [element length](glossary.md#element-length) `ℓ` is large.

## Why it exists

A base witness has `m + ℓm'` [ring](glossary.md#ring-and-ring-degree) elements: it grows with the element length. The succinct
variant has witnesses of `m + m'` ring elements, whatever `ℓ` is.

It pays for that in three ways.

- **A very large public key.** The public key gains a dense matrix `T₀` of `ℓm × ℓm'` ring
  elements. At the succinct toy set that is 7200 of the key's 8206 polynomials, and the key
  encodes to 2,149,984 bytes.
- **A larger modulus.** The witness [norm bound](glossary.md#norm-bound) `β_succ` is far above the base bound, so the
  modulus must be larger and every coefficient of the witness is wider.
- **A different [assumption](glossary.md#assumption).** It rests on the `ℓ`-succinct Module-SIS assumption
  (Definition 2.10 of the paper) in place of Module-SIS.

## When it pays

A succinct witness has fewer polynomials, but wider coefficients. At the succinct toy set,
where `ℓ = 4`, a succinct witness is 29,224 bytes against 28,144 bytes for a base witness at
the same set: it is *larger*. The saving needs `ℓ` large enough to outweigh the wider
coefficients.

At the succinct 128-bit shape the public key would be about 110 GiB, almost all of it `T₀`.
The paper's Table 2 figure of 171.7 MB for the succinct public parameters counts only
`(A, B₁, W, u)` and leaves `T₀` and `T₁` out. Key generation there is not practical. Only the parameters and bounds of that set are tested.
So today this variant can be studied at the succinct toy set and nowhere else.

The [trapdoor distribution](glossary.md#trapdoor-distribution) matters more here than in the base scheme: a ternary trapdoor
lowers `β_succ` from `2^79.70` to `2^67.53` at the succinct toy set. See
[Parameter sets and trapdoor distributions](parameters.md).

## What stays the same

The manager's side is the base scheme. The accumulator value, the manager state, the elements
and the update messages are the base `Accumulator`, `ManagerState`, `Element` and
`Coefficient`, re-exported from this module; their sections are in
[Elements](elements.md) and [Manager state](state.md). The succinct keys dereference to base
keys, so `Accumulator::add(&key, …)` and the other manager methods take a succinct key as they
are. Only the keys, the witness, its `Delta` and the bounds are new.

One base method refuses a succinct key: the base `MembershipWitness::new` returns
`Error::CompressedWitnessOnly`. A holder of this variant receives the compressed witness only,
from `succinct::MembershipWitness::new`.

The base key's own bytes do not lead around that refusal. The base key inside a succinct key
derives its trapdoor, `u`, genesis value, PRF key and state-tag key under a label of its own,
so its `to_bytes`, decoded as a Construction 4.1 `SecretKey`, gives an unrelated key: another
`A`, another `u`, another genesis value, and a key that refuses the succinct key's states.
Witnesses from it are witnesses of a different accumulator.

```rust
use kln_accumulator::{Accumulator, Element, Error, Params};
use kln_accumulator::succinct::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut StdRng::seed_from_u64(0))?;
let x = Element::try_from(&[1u8][..])?;
let (value, state) = Accumulator::with_elements(&key, &[x.clone()])?;

// The base key it dereferences to refuses to issue a base witness.
let inner: &kln_accumulator::SecretKey = &key;
let refused = kln_accumulator::MembershipWitness::new(&x, &value, inner, &state);
assert_eq!(refused.map(drop), Err(Error::CompressedWitnessOnly));

// Its bytes decode as a Construction 4.1 key, but an unrelated one.
let reimported = kln_accumulator::SecretKey::try_from(inner.to_bytes().as_slice())?;
let (ours, theirs) = (kln_accumulator::PublicKey::from(inner), kln_accumulator::PublicKey::from(&reimported));
assert_ne!(ours.a(), theirs.a());
assert_ne!(Accumulator::new(&key), Accumulator::new(&reimported));
let foreign = kln_accumulator::MembershipWitness::new(&x, &value, &reimported, &state);
assert_eq!(foreign.map(drop), Err(Error::InvalidStateTag));
# Ok::<(), kln_accumulator::Error>(())
```

The base rules carry over unchanged. The accumulator starts at the base key's genesis value; a
succinct witness is the image of the base witness, which is sampled for that genesis value and
corrected for the set of deletions, so a fork, an older copy or a state rebuilt with
`ManagerState::rebuild` issues the same succinct witness.

```rust
use kln_accumulator::{Accumulator, Element, ManagerState, Params};
use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut StdRng::seed_from_u64(0))?;
let pk = PublicKey::from(&key);
// ℓ = 4 at this set: name the elements directly.
let (x, y, z) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?, Element::try_from(&[3u8][..])?);
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
let mut log = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
log.extend(acc.update_assign(&key, &[], &[z.clone()], &mut state)?);
let issued = MembershipWitness::new(&x, &acc, &key, &state)?;
assert!(issued.verify(&x, &pk, &acc));

// A state rebuilt from the log, in the other order, issues the same succinct witness.
log.reverse();
let (value, rebuilt) = ManagerState::rebuild(&key, &log, &[x.clone()])?;
assert_eq!(value, acc);
assert_eq!(MembershipWitness::new(&x, &value, &key, &rebuilt)?, issued);
# Ok::<(), kln_accumulator::Error>(())
```

## A complete run

```rust
use kln_accumulator::{Accumulator, Element, Params};
use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut rng)?;
let pk = PublicKey::from(&key);

// ℓ = 4 at this set: sixteen elements exist, so name them directly.
let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);

// Manager: the base accumulator methods take the succinct key.
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
assert!(witness.verify(&x, &pk, &acc));

// Manager: delete y. Holder of x: update from public data.
let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
let witness = witness.batch_update(&x, &[], &[y], &coefficients, &pk)?;
assert!(witness.verify(&x, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

## `succinct::SecretKey`

**What it is**

The manager's secret key of the succinct variant: a base secret key for a particular choice of
the public matrix `B`, together with the succinct public key. It dereferences to the base key.
Like the other keys it is a function of a parameter set and a 32-byte root seed, and every value
derived from the seed, `B₁`, `W` and `T` included, depends on the set as well.

**Why it exists**

Key generation here does more than in the base scheme: it uses the trapdoor to sample the
public matrix `T = [T₀; T₁]`, column by column. The seeds that drive that sampling are secret:
the Gaussian draws behind `T₀`, together with `T₀`, would reveal the trapdoor. The type keeps
those seeds with the key and wipes them with it.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::succinct::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut StdRng::seed_from_u64(0))?;
let bytes = key.to_bytes();
assert_eq!(bytes.len(), 96);
assert_eq!(SecretKey::try_from(bytes.as_slice())?, key);

// The base key it dereferences to runs the manager's operations.
let base: &kln_accumulator::SecretKey = &key;
assert_eq!(base.params(), key.params());
assert_eq!(format!("{key:?}"), "SecretKey { .. }");
# Ok::<(), kln_accumulator::Error>(())
```

Key generation takes far longer than in the base scheme, because it samples `T` column by
column; [Benchmarks and sizes](benchmarks.md) has the figure at the succinct toy set. Decoding a
key regenerates everything from the seed, so it costs the same.

**Security**

Secret, owner only. The root seed and the base key with its trapdoor are overwritten when it
is dropped, as are the seeds and sampler state used to draw `T` during key generation. It is
neither `Copy` nor `Clone`; `Debug` prints nothing secret; `to_bytes` returns a wiped buffer.
`T` itself is public.

```rust,compile_fail
use kln_accumulator::Params;
use kln_accumulator::succinct::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut StdRng::seed_from_u64(0))?;
let copy = key.clone(); // error: no method named `clone` found
# Ok::<(), kln_accumulator::Error>(())
```

**Using it safely**

The code refuses a parameter set whose modulus is too small for the succinct bound:
`Error::WitnessBoundTooLarge`. The base toy set is one. It refuses a caller's seed shorter than
32 bytes with `Error::SeedTooShort`, before any key generation work. One seed under the
Gaussian and the ternary succinct toy sets gives two unrelated keys, and neither accepts a
state the other tagged.

```rust
use kln_accumulator::{Accumulator, Error, MIN_SEED_BYTES, ManagerState, Params, ParamsSpec};
use kln_accumulator::TrapdoorDistribution;
use kln_accumulator::succinct::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let refused = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0));
assert_eq!(refused.map(drop), Err(Error::WitnessBoundTooLarge));

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::succinct_toy()?);
let short = SecretKey::new(Some(&[4u8; MIN_SEED_BYTES - 1]), Arc::clone(&params), &mut rng);
assert_eq!(short.map(drop), Err(Error::SeedTooShort(31)));

let seed = [4u8; MIN_SEED_BYTES];
let ternary = ParamsSpec::SUCCINCT_TOY.with_trapdoor(TrapdoorDistribution::Ternary);
let key = SecretKey::new(Some(&seed), Arc::clone(&params), &mut rng)?;
let other = SecretKey::new(Some(&seed), Arc::new(Params::try_from(ternary)?), &mut rng)?;
assert_ne!(PublicKey::from(&key).b1(), PublicKey::from(&other).b1());
let state = ManagerState::new(&key);
assert_eq!(state.authenticate(&other), Err(Error::InvalidStateTag));
# Ok::<(), kln_accumulator::Error>(())
```

Your job is everything listed for the base [`SecretKey`](keys.md). In addition: do not try to
generate a key at `ParamsSpec::SUCCINCT_128`. Its public key would be about 110 GiB, and the
crate's documentation calls key generation there impractical.

## `succinct::PublicKey`

**What it is**

The public parameters `(A, B₁, W, T₀, T₁, u)` of the succinct variant, with their parameter
set and their `succinct::Bounds`. It dereferences to a base public key `(A, −B₁·T₁, u)`.

**Why it exists**

Verification uses the short matrix `[A | B₁ + (xᵀ⊗I)·W]`, built from `A`, `B₁` and `W`.
Updating uses `T₀` and `T₁` to map the base correction into the short witness. The base public
key it dereferences to is what the manager's deletion and the holder's update evaluate on.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::succinct::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut StdRng::seed_from_u64(0))?;
let pk = PublicKey::from(&key);
let spec = key.params().spec();
let (ell, m_prime) = (spec.element_bits as usize, key.params().m_prime());

assert_eq!(pk.t0().shape().rows, ell * spec.m);
assert_eq!(pk.t0().shape().cols, ell * m_prime);
assert_eq!(pk.t1().shape().rows, m_prime);
assert_eq!(pk.b1().shape().cols, m_prime);
assert_eq!(pk.w().shape().rows, spec.n * ell);
// β_succ is far above the base bound β.
assert!(pk.bounds().witness > key.params().bounds().witness);

let bytes = pk.to_bytes();
assert_eq!(bytes.len(), 2_149_984);
assert_eq!(PublicKey::try_from(bytes.as_slice())?, pk);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy, `T₀` and `T₁` included. Nothing in it needs wiping; its polynomials
overwrite themselves on drop like every polynomial, which has no security meaning for a public
value. Decoding rebuilds the parameter set, checks the shape and range of every matrix,
recomputes `−B₁·T₁` and derives the bounds again.

**Using it safely**

The code refuses a malformed encoding (`Error::InvalidEncodingLength`,
`Error::NonCanonicalEncoding`, `Error::CoefficientOutOfRange`) and a coefficient of `T` above
the bound its encoding allows (`Error::CoefficientOverBound`).

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::succinct::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut StdRng::seed_from_u64(0))?;
let bytes = PublicKey::from(&key).to_bytes();
assert!(matches!(
    PublicKey::try_from(&bytes[..bytes.len() - 1]),
    Err(Error::InvalidEncodingLength(_))
));
# Ok::<(), kln_accumulator::Error>(())
```

Your job: distribute it authentically, as every public key, and plan for its size. Every
holder and verifier needs all of it.

## `succinct::Bounds`

**What it is**

The Gaussian width of the public matrix `T` and the norm bounds of the succinct variant at one
parameter set: `trapdoor_width`, `column`, `witness` (this is `β_succ`) and `trapdoor_entry`.
A `Copy` struct with public fields.

**Why it exists**

A succinct witness is the image of a base witness under a matrix made of `T₀` and `T₁`, so its
norm is the base norm multiplied by a factor that depends on how large `T` is. This type makes
that factor concrete, and it is what decides whether a parameter set can carry the variant at
all: `2·β_succ` must stay below the modulus.

**How to use it**

```rust
use kln_accumulator::{Error, Params, ParamsSpec, TrapdoorDistribution, succinct::Bounds};

let bounds = Bounds::try_from(&Params::succinct_toy()?)?;
assert_eq!(bounds.witness.bit_width_vartime(), 80); // β_succ = 2^79.70
assert!(bounds.trapdoor_width < bounds.column);

// A ternary trapdoor narrows T and lowers the bound.
let ternary = Params::try_from(ParamsSpec::SUCCINCT_TOY.with_trapdoor(TrapdoorDistribution::Ternary))?;
assert_eq!(Bounds::try_from(&ternary)?.witness.bit_width_vartime(), 68); // 2^67.53

// The base toy set's 60-bit modulus is too small.
assert_eq!(Bounds::try_from(&Params::toy()?), Err(Error::WitnessBoundTooLarge));

// At the 128-bit shape the bound is derived even though key generation is impractical.
assert_eq!(Bounds::try_from(&Params::succinct_128()?)?.witness.bit_width_vartime(), 139);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. Like the base bounds,
every field is an upper bound and rests on a Gaussian tail bound, so honest values satisfy it
with overwhelming probability.

**Using it safely**

The code refuses a set that cannot carry the variant: `Error::WitnessBoundTooLarge`, shown
above. There is nothing else to misuse; the fields are derived.

## `succinct::MembershipWitness`

**What it is**

A short vector `s_x` of `m + m'` ring elements with `[A | B₁ + (xᵀ⊗I)·W]·s_x = c` and
`‖s_x‖₂ ≤ β_succ`. It encodes to 29,224 bytes at the succinct toy set.

**Why it exists**

It is the point of the variant: a witness whose length does not grow with `ℓ`. The manager
makes it by sampling a base witness and mapping it through `T₀` and `T₁`.

**How to use it**

It has the same methods as the base witness: `new`, `verify`, `update`, `batch_update`,
`multi_batch_update`, `apply_delta`, their `_assign` forms, `to_bytes`, `from_vector` and
`validate`. The complete run above shows the usual path.

```rust
use kln_accumulator::{Accumulator, Element, Params};
use kln_accumulator::lattice::PolyVec;
use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
let (acc, state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;

assert!(witness.verify(&x, &pk, &acc));
assert!(!witness.verify(&y, &pk, &acc));
let bytes = witness.to_bytes()?;
assert_eq!(bytes.len(), 29_224);
assert_eq!(MembershipWitness::try_from(bytes.as_slice())?, witness);

// m + m' entries, whatever ℓ is.
let vector = PolyVec::from(witness.clone());
assert_eq!(vector.len(), key.params().spec().m + key.params().m_prime());
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Holder-private, as the base witness: overwritten when dropped, encoded in wiped buffers,
printed by `Debug` as its parameter set only, `Clone` with self-wiping clones.

The paper presents this variant as resting on the `ℓ`-succinct Module-SIS assumption in place
of Module-SIS, and says that correctness and compactness carry over. It states no separate
security theorem for it, and this book claims none.

The crate's membership proof takes a base witness. There is no zero-knowledge proof for a
succinct witness, and the type system says so:

```rust,compile_fail
use kln_accumulator::{Accumulator, Element, MembershipSecret, Params};
use kln_accumulator::lattice::PolyVec;
use kln_accumulator::succinct::{MembershipWitness, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut rng)?;
let x = Element::try_from(&[1u8][..])?;
let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
let r = PolyVec::zero(1, key.params().ring());
// error: expected `&kln_accumulator::MembershipWitness`, found `&succinct::MembershipWitness`
let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
# Ok::<(), kln_accumulator::Error>(())
```

**Using it safely**

The code refuses what the base witness refuses, with the same errors; see
[Witnesses and updates](witnesses.md). A succinct witness cannot be checked against a base
public key or the other way round: the types differ, so that is a compile error.

```rust
use kln_accumulator::{Accumulator, Element, Error, Params};
use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let for_y = MembershipWitness::new(&y, &acc, &key, &state)?;
let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

// The deleted element's witness: no longer verifies, cannot be updated or reissued.
assert!(!for_y.verify(&y, &pk, &acc));
assert_eq!(
    for_y.batch_update(&y, &[], &[y.clone()], &coefficients, &pk).map(drop),
    Err(Error::ElementDeleted)
);
assert_eq!(
    MembershipWitness::new(&y, &acc, &key, &state).map(drop),
    Err(Error::ElementNotPresent)
);
# Ok::<(), kln_accumulator::Error>(())
```

Your job is what it is for the base witness: verify after every update, apply every batch
exactly once, keep the witness private, and wipe the copies you make.

## `succinct::Delta`

**What it is**

The correction a sequence of deletions makes to one holder's succinct witness: the base
correction, mapped through `T₀` and `T₁` into `m + m'` ring elements.

**Why it exists**

For the same reason as the base `Delta`: it separates computing a correction from applying
it. The map is linear, so over several batches it is applied once, to the summed base
correction.

**How to use it**

The module has its own `evaluate_delta` and `evaluate_deltas`, with the argument order of the
base functions and a succinct public key.

```rust
use kln_accumulator::{Accumulator, Element, Params};
use kln_accumulator::succinct::{MembershipWitness, PublicKey, SecretKey};
use kln_accumulator::succinct::{evaluate_delta, evaluate_deltas};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let element = |i: u8| Element::try_from(&[i][..]);
let (x, y, z) = (element(1)?, element(2)?, element(3)?);
let members = [x.clone(), y.clone(), z.clone()];
let (mut acc, mut state) = Accumulator::with_elements(&key, &members)?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;

let first = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
let delta = evaluate_delta(&x, &[], &[y.clone()], &first, &pk)?;
assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));

let second = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
let batches = [(vec![], vec![y], first), (vec![], vec![z], second)];
let delta = evaluate_deltas(&x, &batches, &pk)?;
assert!(witness.apply_delta(&delta)?.verify(&x, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Holder-private, as the base `Delta`: overwritten when dropped, printed by `Debug` as its
parameter set only, not serialized.

**Using it safely**

The code refuses what the base functions refuse: `Error::ElementDeleted`,
`Error::CoefficientMismatch`, `Error::ElementAlreadyAdded`, `Error::InvalidElement`, and
`Error::ParameterMismatch` at `apply_delta`. A base `Delta` cannot be applied to a succinct
witness; the types differ.

```rust
use kln_accumulator::{Accumulator, Element, Error, Params};
use kln_accumulator::succinct::{PublicKey, SecretKey, evaluate_delta};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::succinct_toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y.clone()])?;
let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
let own = evaluate_delta(&y, &[], &[y.clone()], &coefficients, &pk);
assert_eq!(own.map(drop), Err(Error::ElementDeleted));
# Ok::<(), kln_accumulator::Error>(())
```

Your job is the same as for the base `Delta`: apply it once, to the right witness, and verify
afterwards.
