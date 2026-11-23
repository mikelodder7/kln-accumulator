# The adaptive variant

> **In short.** The [adaptive variant](glossary.md#adaptive-variant) lets a deleted element be
> added again: a guest who was removed can come back, which the base variant forbids. Inside,
> the accumulator holds a [handle](glossary.md#handle) for each element, a stand-in for it, so
> update messages name handles rather than elements. Its security proof is stronger too. It
> costs a signature in every witness and a lifetime cap on additions.
>
> **Read this when** a member must be able to leave and come back, or you weigh it against the
> base variant.
>
> **New here?** Read [The three variants](concepts.md#the-three-variants) and
> [Which variant and which settings](choosing.md) first. You can skip this chapter while every
> element is added at most once.

The module `kln_accumulator::adaptive` is [Construction 4.2](glossary.md#construction-41-construction-42) of ePrint 2025/1099. Use it when
an element must be able to leave the accumulator and come back, or when you want the stronger
security notion it gives.

## Why it exists

Construction 4.1 has two limits.

- It is **[replacement-free](glossary.md#replacement-free)**: an element that was ever added can never be added again. Its
  security theorem assumes that, since in the paper's scheme a second addition samples a
  second witness for the same element, which would leak the trapdoor; the code refuses.
- Its security proof is **[selective](glossary.md#selective-and-adaptive-security)**: the attacker has to name the element it will forge a
  witness for before it sees the public key.

Construction 4.2 removes both with one idea, the compiler of the work titled "Accumulators
with applications to anonymity-preserving revocation" (EuroS&P 2017), cited by ePrint
2025/1099. The accumulator no longer holds your element. It holds a *handle*, a pseudorandom
`ℓ`-bit string derived from your element and an index. A signature binds the element to its
handle.

- Adding `x` derives a handle `r_x`, adds `r_x` to an inner Construction 4.1 accumulator, and
  signs the pair `(x, r_x)` with [ML-DSA-65](glossary.md#ml-dsa-65) (FIPS 204).
- The witness is the handle, the signature, and the inner witness for the handle.
- Deleting `x` deletes its handle. Adding `x` again derives a *new* handle, so the inner
  accumulator still sees every value once.
- The index counts past every handle the inner accumulator has seen, live or deleted, so two
  elements whose handles collide get different ones, and no addition is refused for a
  collision. Which of the two moves on depends on which was added first.
- Update messages name the handle, never `x`.

## What it costs

- A signature in every witness: 3309 bytes.
- An ML-DSA verification in every witness check.
- A manager state that also maps elements to handle counters.
- A bound on additions. A handle has `ℓ` bits and handles are never reused, so at most `2^ℓ`
  additions, counting re-additions, are possible over the life of an accumulator.

## What stays the same

The types carry the names and the method names of the base types. The update message
`Coefficient`, the per-holder `Delta` and the state entries `Record` and `Operation` *are* the
base types, re-exported from this module; see [Elements](elements.md),
[Witnesses](witnesses.md) and [Manager state](state.md) for their sections.

## A complete run

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::{
    Accumulator, Element, ManagerState, MembershipWitness, PublicKey, SecretKey,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));

// Manager: add both, issue the witness for x.
acc.add_elements_assign(&key, &[x, y], &mut state)?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
assert!(witness.verify(&x, &pk, &acc));

// Manager: delete y. The update message names y's handle, not y.
let coefficients = acc.update_assign(&key, &[], &[y], &mut state)?;
let handles: Vec<_> = coefficients.iter().map(|c| c.element().clone()).collect();

// Holder of x: update with the published handles.
let witness = witness.batch_update(&x, &[], &handles, &coefficients, &pk)?;
assert!(witness.verify(&x, &pk, &acc));

// Manager: y comes back, under a new handle.
acc.add_assign(&key, &y, &mut state)?;
let again = MembershipWitness::new(&y, &acc, &key, &state)?;
assert!(again.verify(&y, &pk, &acc));
assert_ne!(again.handle(), &handles[0]);
# Ok::<(), kln_accumulator::Error>(())
```

## `adaptive::SecretKey`

**What it is**

The manager's secret key of Construction 4.2: the ML-DSA-65 signing key, the inner
Construction 4.1 key with its trapdoor, the PRF key that derives handles, and the key that
tags the manager state. Everything is derived from a 32-byte root seed together with the
encoded parameter set, so its encoding is the parameter set and that seed, 96 bytes, and one
seed under two sets gives two unrelated keys, ML-DSA key and handle PRF included.

**Why it exists**

Issuing an adaptive witness takes two secret operations: sampling the inner witness and
signing the pair of element and handle. This key holds both capabilities in one opaque value,
and derives them from one seed so that there is one thing to back up.

**How to use it**

Exactly as the base key: `SecretKey::new(seed, params, rng)`, `to_bytes`, `TryFrom<&[u8]>`,
`PublicKey::from(&key)`. The complete run above uses it.

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let bytes = key.to_bytes();
assert_eq!(bytes.len(), 96);
assert_eq!(SecretKey::try_from(bytes.as_slice())?, key);
assert_eq!(format!("{key:?}"), "SecretKey { .. }");
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Secret, owner only. The seeds, the ML-DSA signing key and the inner key with its trapdoor are
overwritten when it is dropped; the signing key through the `zeroize` feature of the `ml-dsa`
crate, whose internals beyond that feature the crate cannot wipe. It is neither `Copy` nor
`Clone`, `Debug` prints nothing secret, equality compares the seed in constant time, and
`to_bytes` returns a wiped buffer.

It is not `Clone`:

```rust,compile_fail
use kln_accumulator::Params;
use kln_accumulator::adaptive::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let copy = key.clone(); // error: no method named `clone` found
# Ok::<(), kln_accumulator::Error>(())
```

**Using it safely**

Everything said for the base [`SecretKey`](keys.md) applies: the seed must be secret and
unpredictable, one seed makes one key per parameter set, serializer outputs are yours to wipe,
and operations other than the trapdoor's draws at key generation are not constant time. The code refuses a caller's seed shorter than 32 bytes
with `Error::SeedTooShort`, a malformed encoding with `Error::InvalidEncodingLength` and an
invalid parameter set with the errors of `Params::try_from`.

```rust
use kln_accumulator::{Error, MIN_SEED_BYTES, Params, ParamsSpec, TrapdoorDistribution};
use kln_accumulator::adaptive::{Accumulator, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let short = [3u8; MIN_SEED_BYTES - 1];
let refused = SecretKey::new(Some(&short), Arc::clone(&params), &mut rng);
assert_eq!(refused.map(drop), Err(Error::SeedTooShort(31)));

// One seed under two sets: different ML-DSA keys, and neither key accepts the other's state.
let seed = [3u8; MIN_SEED_BYTES];
let ternary = Arc::new(Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))?);
let key = SecretKey::new(Some(&seed), Arc::clone(&params), &mut rng)?;
let other = SecretKey::new(Some(&seed), ternary, &mut rng)?;
assert_ne!(PublicKey::from(&key).to_bytes()[..1952], PublicKey::from(&other).to_bytes()[..1952]);
let (_, state) = Accumulator::with_elements(&key, &[])?;
assert_eq!(state.authenticate(&other), Err(Error::InvalidStateTag));
# Ok::<(), kln_accumulator::Error>(())
```

One point is specific to this key: signing is deterministic, so the same history gives the
same witness, signature included. That is intended; it is what makes a recreated witness equal
to the issued one.

## `adaptive::PublicKey`

**What it is**

The public parameters of Construction 4.2: the ML-DSA-65 verifying key, 1952 bytes, and the
inner public key `(A, B, u)` with its parameter set.

**Why it exists**

Verifying an adaptive witness takes two checks, the signature and the inner witness, and each
needs its own public key. Holders also need the inner key to update: the correction is
computed for the handle under the inner key.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let pk = PublicKey::from(&key);
assert_eq!(pk.params(), key.params());

// The verifying key, then the inner public key.
let bytes = pk.to_bytes();
assert_eq!(bytes.len(), 1952 + pk.inner().to_bytes().len());
assert_eq!(PublicKey::try_from(bytes.as_slice())?, pk);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping; its polynomials overwrite themselves on
drop like every polynomial, which has no security meaning for a public value.

**Using it safely**

The code refuses a truncated or over-long encoding (`Error::InvalidEncodingLength`) and
whatever the inner key's decoding refuses. As for the base key, decoding cannot tell you whose
key it is: distribute it over an authenticated channel.

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::adaptive::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let bytes = PublicKey::from(&key).to_bytes();
assert!(matches!(
    PublicKey::try_from(&bytes[..1000]),
    Err(Error::InvalidEncodingLength(_))
));
# Ok::<(), kln_accumulator::Error>(())
```

## `adaptive::Element`

**What it is**

An element of the adaptive accumulator's domain: 32 bytes. Unlike the base `Element` it does
not depend on the parameter set, and it is `Copy`.

**Why it exists**

The inner accumulator only ever sees handles, so the outer element is free of the `ℓ`-bit
limit. With 256 bits, hashing arbitrary identifiers does not run into the collisions
that the base `Element::hash` has at small `ℓ`.

**How to use it**

```rust
use kln_accumulator::adaptive::Element;
use rand::{SeedableRng, rngs::StdRng};

let x = Element::hash(b"credential 42");
assert_eq!(x.to_bytes().len(), Element::BYTES);
assert_eq!(Element::BYTES, 32);
assert_eq!(Element::try_from(&x.to_bytes()[..])?, x);
assert_eq!(Element::from(x.to_bytes()), x);
let _random = Element::random(&mut StdRng::seed_from_u64(0));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public. The crate does not hide it: it is `Copy` and it is not wiped on drop. What stands for
it inside the accumulator is its handle, which is holder-private and lives in the witness.

**Using it safely**

The code refuses a byte string that is not 32 bytes long: `Error::InvalidElement`.

```rust
use kln_accumulator::Error;
use kln_accumulator::adaptive::Element;

assert!(matches!(Element::try_from(&[0u8; 31][..]), Err(Error::InvalidElement)));
```

Your job: the manager sees every element, and anyone who verifies a witness in the clear sees
the element too. If the element is sensitive, hash a secret-salted identifier, or keep the
witness check inside a zero-knowledge proof.

## `adaptive::Accumulator`

**What it is**

The accumulator value of Construction 4.2. It is the value of the inner accumulator of
handles, wrapped so that the manager's methods take adaptive elements.

**Why it exists**

It gives the adaptive variant the same manager API as the base: `add`, `remove`, `update` and
their batch and in-place forms, with the same argument order. Behind them, `add` derives a
fresh handle and `remove` looks the handle up, so the caller only ever names elements.

**How to use it**

As in the complete run above. Additions leave the value unchanged; deletions move it and
return update messages that name handles.

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let x = Element::hash(b"x");
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x])?;
let before = acc.clone();
acc.remove_assign(&key, &x, &mut state)?;
assert_ne!(acc, before);

let bytes = acc.to_bytes();
assert_eq!(Accumulator::try_from(bytes.as_slice())?, acc);
acc.validate(key.params())?;
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping; its polynomials overwrite themselves on
drop like every polynomial, which has no security meaning for a public value. Under the
assumptions listed in [Guarantees and their limits](security.md), nobody without the secret key
can produce a witness that verifies against this value for an element that is not in the set,
and here the attacker may choose that element adaptively.

**Using it safely**

The code refuses:

| misuse | error |
|---|---|
| adding an element that is present, or twice in one batch | `Error::ElementAlreadyAdded` |
| deleting an element that is not present | `Error::ElementNotPresent` |
| adding once all `2^ℓ` handles are used | `Error::HandleSpaceExhausted` |
| deleting once `γ` deletions were made | `Error::DeletionBoundReached` |
| a state that was altered or tagged by another key | `Error::InvalidStateTag` |
| a value that is not the state's current one: unrelated, or an earlier value | `Error::AccumulatorMismatch` |
| a value of another parameter set | `Error::ParameterMismatch` |

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));

acc.add_assign(&key, &x, &mut state)?;
assert_eq!(acc.add_assign(&key, &x, &mut state), Err(Error::ElementAlreadyAdded));
assert_eq!(acc.remove_assign(&key, &y, &mut state), Err(Error::ElementNotPresent));

// Unlike Construction 4.1, a deleted element can come back.
acc.remove_assign(&key, &x, &mut state)?;
acc.add_assign(&key, &x, &mut state)?;

// A value that is not the current one, here the one from before the deletion, is refused, and
// nothing changes.
let mut stale = Accumulator::new(&key);
let before = state.clone();
assert_eq!(stale.add_assign(&key, &y, &mut state), Err(Error::AccumulatorMismatch));
assert_eq!(state, before);

// The toy set has ℓ = 8: 256 handles in all. Two are used; 254 more additions fit.
let more: Vec<Element> = (0u32..254).map(|i| Element::hash(&i.to_le_bytes())).collect();
acc.add_elements_assign(&key, &more, &mut state)?;
assert_eq!(
    acc.add_assign(&key, &Element::hash(b"one too many"), &mut state),
    Err(Error::HandleSpaceExhausted)
);
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **Budget additions as well as deletions.** `2^ℓ` counts every addition ever made,
  re-additions included. At the 128-bit set `ℓ = 32`.
- **Keep value and state together, never roll the state back.** A value other than the
  state's current one is refused, but all of [Manager state and its tag](state.md) applies.

## `adaptive::ManagerState`

**What it is**

The manager's state for Construction 4.2: the state of the inner accumulator of handles, a
dictionary from elements to their `Record`, and a tag over both. Here a record's `epoch` is
the handle counter: for a present element, the index its current handle was drawn at; for a
deleted one, the index its next handle starts from.

**Why it exists**

The manager has to remember, for every element, which handle stands for it now and which
indices were already used, so that a re-added element gets a handle the inner accumulator has
never seen. The inner state alone knows handles, not elements.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, Operation, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
let x = Element::hash(b"x");

acc.add_assign(&key, &x, &mut state)?;
assert_eq!(state.record(&x).map(|r| r.operation), Some(Operation::Add));
assert_eq!(state.inner().counter(), 0);
acc.remove_assign(&key, &x, &mut state)?;
assert_eq!(state.record(&x).map(|r| r.operation), Some(Operation::Del));
assert_eq!(state.inner().counter(), 1);
state.validate(key.params())?;

// It serializes like the base state; the tag is checked at the next keyed use, or on its own.
let stored = serde_json::to_string(&state)?;
let loaded: ManagerState = serde_json::from_str(&stored)?;
assert_eq!(loaded, state);
loaded.authenticate(&key)?;
// The inner state records the current value.
assert_eq!(loaded.inner().current(), &kln_accumulator::Accumulator::from(acc.clone()));
# Ok::<(), Box<dyn std::error::Error>>(())
```

**Security**

Manager-private, not key material. It maps every element ever added to its handle counter, so
together with the PRF key it links elements to handles; on its own it holds no key. It carries
two tags: the inner state's, under the inner key, and a second one over everything, the inner
tag included, under the adaptive key. Both give integrity under the secret key, the current
value included; `ManagerState::authenticate` checks the outer one, which covers the inner.
Neither gives freshness. Its elements are not wiped on drop: an adaptive element is public.

**Using it safely**

The code refuses a state that was altered or tagged under another key, at every keyed
operation and at `ManagerState::authenticate`: `Error::InvalidStateTag`. After the tag, every
keyed operation refuses a value that is not the inner state's current one:
`Error::AccumulatorMismatch`.

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, MembershipWitness, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::clone(&params), &mut rng)?;
let other = SecretKey::new(Some(b"someone else's seed, 32 bytes long"), Arc::clone(&params), &mut rng)?;
let x = Element::hash(b"x");
let (mut acc, state) = Accumulator::with_elements(&key, &[x])?;

let mut foreign = ManagerState::new(&other);
let y = Element::hash(b"y");
assert_eq!(acc.add_assign(&key, &y, &mut foreign), Err(Error::InvalidStateTag));
assert_eq!(
    MembershipWitness::new(&x, &acc, &other, &state).map(drop),
    Err(Error::InvalidStateTag)
);
assert_eq!(foreign.authenticate(&key), Err(Error::InvalidStateTag));
state.authenticate(&key)?;

// A value that is not the state's current one.
let unrelated = Accumulator::random(&mut rng, &params);
assert_eq!(
    MembershipWitness::new(&x, &unrelated, &key, &state).map(drop),
    Err(Error::AccumulatorMismatch)
);
# Ok::<(), kln_accumulator::Error>(())
```

Handles are assigned in the order of additions, so on a fork that adds two colliding elements
in the other order each gets a different live handle than on the original. That is a matter
of reproducibility, not a leak: the inner witness for a handle is sampled for the inner
genesis value, with randomness derived from the handle, and corrected for the deleted
handles, so whichever element holds a handle, on the original, a fork or a rebuilt state, it
is the same inner witness, and the key samples once per handle. A lost state is rebuilt from
the key, the published update messages (which name deleted handles) and the manager's records
of its members as (element, handle) pairs. The handle is not secret from the manager, and
every holder carries its own in its witness (`MembershipWitness::handle`), so the records can
be collected from the holders if the manager lost them. The rebuild checks each record: the
handle must be an `ℓ`-bit string of the set, checked before anything else
(`Error::InvalidElement`), it must be one the addition rule could give the element, and it must
not be deleted. The
rebuilt dictionary holds the members only: the log does not say which element a deleted handle
belonged to, and in this variant a deleted element may come back anyway, with the handle the
lost state would have given it.

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::{Accumulator, Element, ManagerState, MembershipWitness, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
let (start, start_state) = Accumulator::with_elements(&key, &[x, y])?;

// One copy deletes x, then y, then adds x again; a fork deletes y, then x, then adds x again.
let (mut acc, mut state) = (start.clone(), start_state.clone());
let mut log = acc.update_assign(&key, &[], &[x], &mut state)?;
log.extend(acc.update_assign(&key, &[], &[y], &mut state)?);
acc.add_assign(&key, &x, &mut state)?;
let (mut fork, mut fork_state) = (start, start_state);
fork.remove_elements_assign(&key, &[y, x], &mut fork_state)?;
fork.add_assign(&key, &x, &mut fork_state)?;
assert_eq!(fork, acc);
let issued = MembershipWitness::new(&x, &acc, &key, &state)?;
// Here nothing collides, so the fork gives x the same handle, and the same witness.
assert_eq!(MembershipWitness::new(&x, &fork, &key, &fork_state)?, issued);

// Rebuilt from the log of deleted handles and the record (x, its handle): the same witness.
let records = [(x, issued.handle().clone())];
let (value, rebuilt) = ManagerState::rebuild(&key, &log, &records)?;
assert_eq!(value, acc);
assert_eq!(MembershipWitness::new(&x, &value, &key, &rebuilt)?, issued);
# Ok::<(), kln_accumulator::Error>(())
```

Your job is everything listed for the base [`ManagerState`](state.md): keep only the latest
state and one manager per key, so that you publish one history; keep the published log and
the member records with their handles, which rebuild a lost state; persist before you publish; and check a loaded
state with `ManagerState::authenticate` before you read it.

## `adaptive::MembershipWitness`

**What it is**

A witness of Construction 4.2: the handle `r_x`, the ML-DSA-65 signature over the element and
the handle, and the inner witness for the handle.

**Why it exists**

Membership of `x` now has two halves. The inner witness shows that *some handle* is in the
accumulator. The signature shows that this handle is the one the manager assigned to `x`.
Without the signature, a holder could present its handle as standing for any element.

**How to use it**

The complete run above shows issuing, verifying and updating. The update methods take the
*handles* a batch added and deleted, since that is what the manager publishes.

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
let (acc, state) = Accumulator::with_elements(&key, &[x, y])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;

assert!(witness.verify(&x, &pk, &acc));
witness.validate(key.params())?;
assert_eq!(witness.signature().len(), 3309);
assert_eq!(witness.handle().to_bytes().len(), 1); // ℓ = 8 at the toy set

// The inner witness is a base witness for the handle under the inner public key.
let inner_value: kln_accumulator::Accumulator = acc.clone().into();
assert!(witness.inner().verify(witness.handle(), pk.inner(), &inner_value));

let bytes = witness.to_bytes()?;
assert_eq!(MembershipWitness::try_from(bytes.as_slice())?, witness);
# Ok::<(), kln_accumulator::Error>(())
```

A holder that wants a `Delta` computes it with the base `evaluate_delta` for its handle under
`pk.inner()`, and applies it with `apply_delta`.

**Security**

Holder-private. The handle, the signature and the inner witness are overwritten when it is
dropped; its encodings use wiped buffers; `Debug` prints only the parameter set. It is
`Clone`, and every clone wipes itself.

The handle stays private to its holder until the element is deleted. At that point the update
message publishes it.

The crate's zero-knowledge proof takes a base element and a base witness. For an adaptive
witness that means the handle and the inner witness: such a proof shows that a handle is
accumulated. It does not cover the signature, so it does not show which element the handle
stands for. The crate has no proof for the signature half.

**Using it safely**

The code refuses:

| misuse | result |
|---|---|
| a witness presented for another element | `false` from `verify`; `Error::InvalidSignature` from the update methods |
| issuing for an element that is not present | `Error::ElementNotPresent` |
| a witness from before its element was deleted and re-added | `false` from `verify` |
| a signature of the wrong length in an encoding | `Error::InvalidEncodingLength` |
| everything the inner witness refuses | see [Witnesses and updates](witnesses.md) |

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::adaptive::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y])?;
let for_x = MembershipWitness::new(&x, &acc, &key, &state)?;

// Presented for y: the signature is over (x, handle), not (y, handle).
assert!(!for_x.verify(&y, &pk, &acc));
assert_eq!(
    for_x.batch_update(&y, &[], &[], &[], &pk).map(drop),
    Err(Error::InvalidSignature)
);

// Delete x and add it again: the old witness is for a deleted handle.
let coefficients = acc.update_assign(&key, &[], &[x], &mut state)?;
acc.add_assign(&key, &x, &mut state)?;
assert!(!for_x.verify(&x, &pk, &acc));
// Its handle is the one the deletion published.
assert_eq!(coefficients[0].element(), for_x.handle());
// The reissued witness has a new handle and verifies.
let reissued = MembershipWitness::new(&x, &acc, &key, &state)?;
assert!(reissued.verify(&x, &pk, &acc));
assert_ne!(reissued.handle(), for_x.handle());
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **Verify after every update**, as for the base witness.
- **Wipe the signature if you split the witness.** Converting a witness into its three parts
  hands the signature out in a plain `Vec<u8>`.
- **Remember what a verifier in the clear learns.** `verify` takes the element, and the
  witness contains the handle. Showing a witness to a verifier reveals both.
