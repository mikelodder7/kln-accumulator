# Keys

> **In short.** The [secret key](glossary.md#secret-key) is the manager's stamp: whoever holds
> it can make a witness, a pass, for any element. The [public key](glossary.md#public-key) is
> derived from it and published once, so that anyone can check witnesses and holders can
> refresh theirs. This chapter says how both are made, what they contain and how to handle
> them.
>
> **Read this when** you generate, store or load a key, or hand the public key to holders and
> verifiers.
>
> **New here?** Read [Accumulators in plain words](concepts.md) and the rule
> [Make each key from a good seed, once](rules.md#make-each-key-from-a-good-seed-once) first.

The manager holds a `SecretKey`. Everyone else holds the `PublicKey` derived from it. This
chapter covers the keys of [Construction 4.1](glossary.md#construction-41-construction-42); the [adaptive](adaptive.md) and
[succinct](succinct.md) variants have their own keys with the same method names.

## How a key is made

A key is a function of two things: its parameter set and a 32-byte *[root seed](glossary.md#root-seed)*.

`SecretKey::new(seed, params, rng)` hashes the caller's seed (or 32 bytes from the generator
when `seed` is `None`) into the root seed with [SHAKE256](glossary.md#shake256). A caller's seed shorter than
`MIN_SEED_BYTES`, 32 bytes, is refused with `Error::SeedTooShort`. The root seed is then hashed
together with the 64-byte encoding of the parameter set, and from that hash it derives, each
under its own label:

- the seed that trapdoor generation runs from, which gives the public matrix `A` and the
  secret [trapdoor](glossary.md#trapdoor) `T_A`;
- the public matrix `B` and the public vector `u`, both uniform;
- the [PRF](glossary.md#prf) key `k` that fixes the randomness of every witness;
- the key that tags the [manager state](state.md);
- the [genesis value](glossary.md#genesis-value) `c₀`, uniform in `R_q^n`, where the key's one accumulator starts
  (`Accumulator::new(&key)`). It is public: the first value the manager publishes.

So the whole secret is 96 bytes: the 64-byte parameter set and the 32-byte root seed. Decoding
those bytes rebuilds everything. Because every derived value depends on the set as well as the
seed, one root seed under two parameter sets gives two unrelated keys: they share no trapdoor,
no matrix, no PRF key and no state-tag key.

## `SecretKey`

**What it is**

The manager's secret key: the trapdoor `T_A`, the PRF key `k`, the key that tags the manager
state, the genesis value of its accumulator, and the public key they belong to.

**Why it exists**

Only the trapdoor can produce a short vector that the public matrix maps to the accumulator
value, and that short vector is a witness. Whoever holds the secret key can therefore make a
witness for any element, member or not. The type exists to keep that power in one opaque
value: it never exposes the trapdoor or the PRF key, and the only operation that uses the
trapdoor is `MembershipWitness::new`.

**How to use it**

```rust
use kln_accumulator::{Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

// A fixed seed keeps the example reproducible. Real code seeds from the operating system.
let mut rng = StdRng::seed_from_u64(1);
let params = Arc::new(Params::toy()?);

// With None, the seed is 32 bytes from the generator.
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
assert_eq!(pk.params(), key.params());

// The encoding is the set and the root seed, in a buffer that is wiped when dropped.
let bytes = key.to_bytes();
assert_eq!(bytes.len(), 96);
let restored = SecretKey::try_from(bytes.as_slice())?;
assert_eq!(restored, key);
assert_eq!(PublicKey::from(&restored), pk);

// With Some(seed), the key is a function of the seed and the set alone. The seed must be at
// least 32 bytes.
let a = SecretKey::new(Some(b"the same seed, at least 32 bytes"), Arc::clone(&params), &mut rng)?;
let b = SecretKey::new(Some(b"the same seed, at least 32 bytes"), Arc::clone(&params), &mut rng)?;
assert_eq!(a, b);
assert_ne!(a, key);
# Ok::<(), kln_accumulator::Error>(())
```

The manager passes `&key` to every operation that changes the accumulator and to
`MembershipWitness::new`. Nothing else needs it.

**Security**

Secret, owner only. Whoever learns the root seed can issue witnesses for any element and can
tag any manager state.

- It is overwritten when dropped: the root seed, the PRF key, the state-tag key and the
  trapdoor.
- It is neither `Copy` nor `Clone`, so there is exactly one copy unless you serialize it.
- `Debug` prints `SecretKey { .. }` and nothing else. There is no `Display`.
- Equality compares the parameter set and the root seed, the seed in constant time.
- `to_bytes` returns a `Zeroizing<Vec<u8>>`. The serde forms build and parse their hex in
  wiped buffers.

The type system enforces the "one copy" rule. Neither of these compiles:

```rust,compile_fail
use kln_accumulator::{Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(1))?;
let copy = key.clone(); // error: no method named `clone` found for struct `SecretKey`
# Ok::<(), kln_accumulator::Error>(())
```

```rust,compile_fail
use kln_accumulator::{Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(1))?;
let moved = key;
let again = key; // error: use of moved value: `key`
# Ok::<(), kln_accumulator::Error>(())
```

And printing it shows no secret:

```rust
use kln_accumulator::{Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(1))?;
assert_eq!(format!("{key:?}"), "SecretKey { .. }");
# Ok::<(), kln_accumulator::Error>(())
```

**Using it safely**

The code refuses:

- a caller's seed shorter than 32 bytes (`MIN_SEED_BYTES`), empty included:
  `Error::SeedTooShort`, carrying the length given;
- an encoding of the wrong length: `Error::InvalidEncodingLength`;
- an encoding whose parameter set is malformed or invalid, with the errors of
  [`ParamsSpec` and `Params`](parameters.md);
- a key that cannot be generated because no acceptable trapdoor was drawn:
  `Error::InvalidTrapdoor`. That happens with negligible probability at a valid set.

```rust
use kln_accumulator::{Error, MIN_SEED_BYTES, ManagerState, Params, ParamsSpec, PublicKey};
use kln_accumulator::{Accumulator, SecretKey, TrapdoorDistribution};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut StdRng::seed_from_u64(1))?;
let bytes = key.to_bytes();
assert!(matches!(
    SecretKey::try_from(&bytes[..95]),
    Err(Error::InvalidEncodingLength(_))
));

// Short seeds: empty, and one byte short of the floor.
let mut rng = StdRng::seed_from_u64(1);
let empty = SecretKey::new(Some(b""), Arc::clone(&params), &mut rng);
assert_eq!(empty.map(drop), Err(Error::SeedTooShort(0)));
let short = [7u8; MIN_SEED_BYTES - 1];
let refused = SecretKey::new(Some(&short), Arc::clone(&params), &mut rng);
assert_eq!(refused.map(drop), Err(Error::SeedTooShort(31)));

// One seed under two parameter sets: unrelated keys. Neither accepts the other's state.
let seed = [7u8; MIN_SEED_BYTES];
let ternary = Arc::new(Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))?);
let gaussian_key = SecretKey::new(Some(&seed), Arc::clone(&params), &mut rng)?;
let ternary_key = SecretKey::new(Some(&seed), Arc::clone(&ternary), &mut rng)?;
assert_ne!(PublicKey::from(&gaussian_key).a(), PublicKey::from(&ternary_key).a());
let state = ManagerState::new(&gaussian_key);
assert_eq!(state.authenticate(&gaussian_key), Ok(()));
assert_eq!(state.authenticate(&ternary_key), Err(Error::InvalidStateTag));
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **The seed must be secret and unpredictable.** With `Some(seed)` the key is a deterministic
  function of the seed and the parameter set. The code refuses a seed shorter than 32 bytes,
  but it cannot measure entropy: 32 bytes of a guessable string pass. Pass 32 bytes from a
  cryptographic generator, or pass `None` with a generator seeded from the operating system.
  The string literals in this book's examples are for reproducibility only.
- **One seed, one key per set.** A seed reused under another parameter set gives an unrelated
  key, so that reuse is harmless. A seed reused for a second key of the *same* set gives the
  same key, and the code cannot tell: two managers started from one seed are two managers on
  one key. That no longer leaks the key, but the two publish two histories of one
  accumulator; see [Misuse](misuse.md).
- **Wipe what you serialize.** `to_bytes` wipes its own buffer. The output of a serializer you
  call does not: a `String` from `serde_json::to_string(&key)` holds the root seed in hex until
  you wipe it. Wrap such outputs in `Zeroizing`. See [Serialization](serialization.md).
- **Back up the key; keep the deletion log and the member list.** With the key, the published
  update messages and the list of current members, `ManagerState::rebuild` remakes a lost
  state, and the rebuilt state issues the same witnesses; see
  [Manager state and its tag](state.md).
- **Timing.** Key generation draws a Gaussian trapdoor's coefficients with a scan of the whole
  sampling table that does not branch on the draw (checked in the assembly of one x86-64 build;
  no dynamic test), which makes it slower than a table search would; see
  [Benchmarks and sizes](benchmarks.md). Issuing a witness is not constant time: its wide
  Gaussian draw uses a table search whose memory access and length depend on the draw. Do not
  let an attacker time the manager; [Guarantees and their limits](security.md#timing-what-is-and-is-not-constant-time)
  lists what is constant time and on what evidence.

## `PublicKey`

**What it is**

The public parameters `(A, B, u)` of Construction 4.1 with their parameter set. `A` is the
matrix with the trapdoor, `B` and `u` are uniform.

**Why it exists**

Holders and verifiers need exactly these three values. A witness for `x` is a short vector
that the matrix `[A | B − xᵀ⊗G]` maps to the accumulator value; verifying it needs `A` and
`B`. Updating a witness after a deletion needs `B` and `u`. The type keeps the three together
with their set, so that shapes and ranges are checked once, when the key is built or decoded.

**How to use it**

```rust
use kln_accumulator::{Params, PublicKey, SecretKey};
use kln_accumulator::lattice::Shape;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;

// The manager derives it and publishes it.
let pk = PublicKey::from(&key);
let spec = pk.params().spec();
assert_eq!(pk.a().shape(), Shape { rows: spec.n, cols: spec.m });
assert_eq!(pk.b().shape(), Shape { rows: spec.n, cols: 8 * 10 }); // ℓ·m'
assert_eq!(pk.u().len(), spec.n);

// Holders and verifiers decode it. Decoding rebuilds the set and checks A, B and u against it.
let bytes = pk.to_bytes();
assert_eq!(bytes.len(), 48_544);
assert_eq!(PublicKey::try_from(bytes.as_slice())?, pk);
# Ok::<(), kln_accumulator::Error>(())
```

At the 128-bit set the public key is 17,459,264 bytes. It is sent once to every holder and
verifier.

**Security**

Public value, no secrecy. Nothing in it needs wiping; its polynomials overwrite themselves on
drop like every polynomial, which has no security meaning for a public value. With the Gaussian
trapdoor `A` is statistically close to uniform (Theorem 2.1 of ePrint 2025/1099); with the
ternary trapdoor it is pseudorandom under Module-LWE with ternary secrets. Either way the
public key is meant to reveal nothing useful about the trapdoor.

**Using it safely**

The code refuses a malformed encoding:

- truncated, or with trailing bytes: `Error::InvalidEncodingLength`;
- with a coefficient that is not reduced modulo `q`: `Error::CoefficientOutOfRange`;
- with non-zero padding or reserved bytes: `Error::NonCanonicalEncoding`;
- with an invalid parameter set: the errors of `Params::try_from`.

```rust
use kln_accumulator::{Error, Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let bytes = PublicKey::from(&key).to_bytes();

assert!(matches!(
    PublicKey::try_from(&bytes[..bytes.len() - 1]),
    Err(Error::InvalidEncodingLength(_))
));
// The first coefficient of A, set to all ones, is not below q.
let mut out_of_range = bytes.clone();
out_of_range[64..72].fill(0xff);
assert!(matches!(
    PublicKey::try_from(out_of_range.as_slice()),
    Err(Error::CoefficientOutOfRange)
));
// A reserved byte of the parameter-set prefix that is not zero.
let mut reserved = bytes.clone();
reserved[5] = 1;
assert!(matches!(
    PublicKey::try_from(reserved.as_slice()),
    Err(Error::NonCanonicalEncoding)
));
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **Authenticity.** Decoding checks that a key is well formed. It cannot check that the key is
  the manager's. A holder or verifier that accepts a public key from an attacker accepts the
  attacker's accumulator. Distribute the public key over an authenticated channel, or pin its
  hash.
- **The right set.** The key carries its parameter set. If you expect the 128-bit set, check
  `pk.params().spec()` against it; a well-formed key at the toy set decodes just as well.
