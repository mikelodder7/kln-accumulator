# Elements and the accumulator value

> **In short.** An [element](glossary.md#element) is one entry on the guest list: a short
> string of bits that you assign to a member. The [accumulator value](glossary.md#accumulator-value)
> is the code on the door, one public value that stands for the whole list. An
> [update message](glossary.md#update-message), the type `Coefficient`, is the notice the
> manager publishes when it deletes an element.
>
> **Read this when** you decide which element stands for which member, add or delete elements
> as the manager, or publish and receive accumulator values.
>
> **New here?** Read [Accumulators in plain words](concepts.md) and the rule
> [Give each member its own element](rules.md#give-each-member-its-own-element) first.

This chapter covers what the manager puts into the accumulator (`Element`), what it publishes
when it takes one out (`Coefficient`), and the value that represents the set (`Accumulator`).

## `Element`

**What it is**

An element of the domain `{0, 1}^ℓ`: a string of [`ℓ`](glossary.md#element-length) bits, stored in `⌈ℓ/8⌉` bytes. `ℓ` is
`element_bits` of the parameter set: 8 at the [toy set](glossary.md#toy-set), 32 at the [128-bit set](glossary.md#128-bit-set). An element
carries no parameters; it is checked against a set whenever it is used.

**Why it exists**

The accumulator does not hold arbitrary data. It holds bit strings of a fixed, short length,
because the scheme evaluates a function on the bits of the element one by one, and the witness
and the public key grow with `ℓ`. In a credential system the element is a [revocation handle](glossary.md#revocation-handle):
a short identifier the issuer assigns to a credential.

**How to use it**

```rust
use kln_accumulator::{Element, Params};
use rand::{SeedableRng, rngs::StdRng};

let params = Params::toy()?; // ℓ = 8, so an element is one byte

// From bytes you chose yourself.
let x = Element::try_from(&[0b0000_0101u8][..])?;
x.validate(&params)?;
assert_eq!(x.to_bytes(), vec![5]);
assert_eq!(x.to_bits(&params)?.as_slice()[..3], [true, false, true]);

// By hashing an identifier down to ℓ bits.
let hashed = Element::hash(b"revocation handle 17", &params);
hashed.validate(&params)?;

// At random.
let random = Element::random(&mut StdRng::seed_from_u64(0), &params);
random.validate(&params)?;
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public to the manager, who records it, and public to everyone once it is deleted, because the
update message names it. While it is in the accumulator its holder keeps it private: it is the
hidden input of a membership proof. For that reason the crate's own copies are overwritten
when dropped, and its serde form is built and parsed in wiped buffers. `Element::to_bytes`
returns a plain copy that is not wiped, and `Debug` prints the element's bytes, so do not log a
private one. A witness update does the same products whatever the element, so their number
does not show how much of the element a deleted one shares (see
[Witnesses and updates](witnesses.md)).

**Using it safely**

The code refuses:

- an empty byte string, at `TryFrom<&[u8]>`: `Error::InvalidElement`;
- an element of the wrong length for the set, or with a bit set at or above position `ℓ`, at
  `Element::validate` and at every operation that takes an element: `Error::InvalidElement`.

```rust
use kln_accumulator::{Element, Error, Params};

let params = Params::toy()?;
assert!(matches!(Element::try_from(&[0u8; 0][..]), Err(Error::InvalidElement)));
// Two bytes at a set whose elements are one byte.
let wide = Element::try_from(&[0u8, 0][..])?;
assert_eq!(wide.validate(&params), Err(Error::InvalidElement));
// Bit 4 set at the succinct toy set, where ℓ = 4.
let high = Element::try_from(&[0b0001_0000u8][..])?;
assert_eq!(high.validate(&Params::succinct_toy()?), Err(Error::InvalidElement));
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **Elements are scarce, and hashing collides.** There are only `2^ℓ` elements.
  `Element::hash` truncates SHAKE256 to `ℓ` bits, so two different identifiers map to the same
  element after about `2^(ℓ/2)` of them: `2^4` at the toy set, and `2^16` at the 128-bit set, where
  `ℓ = 32`. Two credentials that collide share one element: the
  second cannot be added (`Error::ElementAlreadyAdded`), and if you ignore that error they
  share a witness and are revoked together. Prefer to assign elements yourself, for example
  from a counter, and keep the mapping from credential to element in your own records.
- **An element is not a secret from the manager.** The manager sees every element it adds.
  The membership proof hides the element from *verifiers*.
- **Wipe the copies you make.** `to_bytes` hands you an ordinary `Vec<u8>`.

The collision is easy to see at the toy set, where 257 identifiers cannot all be distinct:

```rust
use kln_accumulator::{Element, Params};
use std::collections::HashMap;

let params = Params::toy()?;
let mut seen = HashMap::new();
let collision = (0u32..257).find_map(|i| {
    let element = Element::hash(&i.to_le_bytes(), &params);
    seen.insert(element, i).map(|earlier| (earlier, i))
});
let (first, second) = collision.ok_or(kln_accumulator::Error::InvalidElement)?;
assert_ne!(first, second);
assert_eq!(
    Element::hash(&first.to_le_bytes(), &params),
    Element::hash(&second.to_le_bytes(), &params),
);
# Ok::<(), kln_accumulator::Error>(())
```

## `Coefficient`

**What it is**

The update message of one deletion. It wraps the deleted element and nothing else. The name is
kept from the update coefficient of the [vb20 pairing accumulator](glossary.md#vb20-pairing-accumulator).

**Why it exists**

A holder needs to know *which* element was deleted to bring its witness up to date. The
correction to the witness of `x` after `y` is deleted is a function of `x`, `y` and the public
key. So the message the manager publishes is just `y`. Additions publish nothing, because they
leave the accumulator value unchanged.

**How to use it**

The manager gets coefficients from `Accumulator::update` or `Accumulator::update_assign` and
publishes them, in order, with the [batch](glossary.md#batch) they belong to. Holders pass them to
`MembershipWitness::batch_update`.

```rust
use kln_accumulator::{Accumulator, Coefficient, Element, Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let y = Element::hash(b"y", key.params());
let (mut acc, mut state) = Accumulator::with_elements(&key, &[y.clone()])?;

let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
assert_eq!(coefficients.len(), 1);
assert_eq!(coefficients[0].element(), &y);

// On the wire it is the element's bytes.
let bytes = coefficients[0].to_bytes();
let received = Coefficient::try_from(bytes.as_slice())?;
received.validate(key.params())?;
assert_eq!(received, Coefficient::from(y));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy: the manager publishes it to every holder. Publishing it reveals
which element was deleted. In Construction 4.1 that is the element itself; in the
[adaptive variant](adaptive.md) it is a handle that stands for the element. Its inner element
is overwritten on drop, like every `Element`.

**Using it safely**

The code refuses a coefficient whose element does not fit the parameter set
(`Error::InvalidElement`), and a batch whose coefficients do not name its deletions in order
(`Error::CoefficientMismatch`, shown in [Witnesses and updates](witnesses.md)).

Your job:

- **Publish every coefficient, in order, to every holder.** A holder that misses one cannot
  update, and its witness stops verifying.
- **Authenticate what you publish.** A coefficient carries no signature. A holder that applies
  a message the manager never sent ends up with a witness that does not verify. That is a
  denial of service on the holder, not a forgery, and the holder detects it by verifying
  against the published value; but the published value has to be authentic for that check to
  mean anything.
- **A deletion is public.** Anyone who sees the update messages learns which elements were
  revoked. If that must not link back to a credential, use the adaptive variant, or make sure
  the element itself reveals nothing.

## `Accumulator`

**What it is**

The accumulator value `c`, a vector of `n` [ring](glossary.md#ring-and-ring-degree) elements. It represents the current set. It is
bound to its parameter set. At the toy set it encodes to 544 bytes, at the 128-bit set to
51,264 bytes.

**Why it exists**

This is the one short public value that every witness is checked against. Additions never
change it. Deleting `y` moves it to `c + B_{1y}·G⁻¹(u)`, a public function of `y` and the
public key, and that move is what makes the witness of `y` stop verifying.

The type also carries the manager's operations, with the method names of the vb20 pairing
accumulator: `add`, `remove`, `update` and their batch and in-place forms.

**How to use it**

```rust
use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let element = |name: &[u8]| Element::hash(name, &params);
let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));

// Start: the key's genesis value and a state tagged under the key.
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
let initial = acc.clone();

// Adding is free: the value does not move.
acc.add_assign(&key, &x, &mut state)?;
acc.add_elements_assign(&key, &[y.clone(), z.clone()], &mut state)?;
assert_eq!(acc, initial);

// Deleting moves it.
acc.remove_assign(&key, &y, &mut state)?;
assert_ne!(acc, initial);

// update adds and deletes in one atomic step and returns the update messages.
let w = element(b"w");
let (next, coefficients) = acc.update(&key, &[w], &[z.clone()], &mut state)?;
assert_eq!(coefficients.len(), 1);
assert_eq!(coefficients[0].element(), &z);

// The published form: 64 bytes of parameter set, then 64 coefficients of 60 bits.
let bytes = next.to_bytes();
assert_eq!(bytes.len(), 544);
assert_eq!(Accumulator::try_from(bytes.as_slice())?, next);
# Ok::<(), kln_accumulator::Error>(())
```

The methods that take `&self` (`add`, `remove`, `update`, and so on) return the new value and
still update the state in place. The `_assign` forms update both in place.
`Accumulator::with_elements` makes a fresh value and a state that already holds some elements.

Every adding and removing method goes through `update_assign`. It checks the state's tag
first, then that the value it is called on is the state's current one, then every operation of
the batch, and only then applies them, recording the new value in the state. On any error
neither the value nor the state changes.

**Security**

Public value, no secrecy: it is published after every deletion. Nothing in it needs wiping; its
polynomials overwrite themselves on drop like every polynomial, which has no security meaning
for a public value.

What it gives you is the soundness of the accumulator: without the secret key, nobody can
produce a witness that verifies against this value for an element that is not in the set. The
exact statement and its assumptions are in [Guarantees and their limits](security.md).

**Using it safely**

The code refuses:

| misuse | error |
|---|---|
| adding an element that was ever added, present or deleted | `Error::ElementAlreadyAdded` |
| adding the same element twice in one batch | `Error::ElementAlreadyAdded` |
| deleting an element that is not present | `Error::ElementNotPresent` |
| deleting once `γ` deletions were made | `Error::DeletionBoundReached` |
| an element that does not fit the set | `Error::InvalidElement` |
| a value of another parameter set than the key's | `Error::ParameterMismatch` |
| a state that was altered, or tagged by another key | `Error::InvalidStateTag` |
| a value that is not the state's current one: unrelated, or an earlier value | `Error::AccumulatorMismatch` |
| a malformed encoding | `Error::InvalidEncodingLength`, `Error::NonCanonicalEncoding`, `Error::CoefficientOutOfRange` |

```rust
use kln_accumulator::{Accumulator, Element, Error, Params, ParamsSpec, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
// The toy shape with a deletion bound of 2, to reach the bound quickly.
let params = Arc::new(Params::try_from(ParamsSpec { max_deletions: 2, ..ParamsSpec::TOY })?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let element = |i: u8| Element::try_from(&[i][..]);
let (a, b, c, d) = (element(1)?, element(2)?, element(3)?, element(4)?);
let members = [a.clone(), b.clone(), c.clone()];
let (mut acc, mut state) = Accumulator::with_elements(&key, &members)?;

// Adding twice.
assert_eq!(acc.add_assign(&key, &a, &mut state), Err(Error::ElementAlreadyAdded));
// Deleting what is not there.
assert_eq!(acc.remove_assign(&key, &d, &mut state), Err(Error::ElementNotPresent));
// Re-adding a deleted element: Construction 4.1 is replacement-free.
acc.remove_assign(&key, &a, &mut state)?;
assert_eq!(acc.add_assign(&key, &a, &mut state), Err(Error::ElementAlreadyAdded));
// The deletion bound: two deletions are allowed, the third is refused.
acc.remove_assign(&key, &b, &mut state)?;
assert_eq!(acc.remove_assign(&key, &c, &mut state), Err(Error::DeletionBoundReached));

// A batch is atomic: the valid addition of d is not applied when the deletion fails.
let before = (acc.clone(), state.clone());
assert_eq!(
    acc.update_assign(&key, &[d.clone()], &[c], &mut state),
    Err(Error::DeletionBoundReached)
);
assert_eq!((acc.clone(), state.clone()), before);
assert!(state.record(&d).is_none());

// A value that is not the current one: the genesis value, from before the deletions.
let mut stale = Accumulator::new(&key);
assert_eq!(stale.add_assign(&key, &d, &mut state), Err(Error::AccumulatorMismatch));
assert_eq!((acc.clone(), state.clone()), before);
assert_eq!(state.current(), &acc);
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **Keep the value and the state together.** The state records the current value, and every
  keyed operation refuses another one with `Error::AccumulatorMismatch`, so a stale or
  unrelated value cannot move the state ([Misuse](misuse.md) shows it). Store and update the
  two together all the same: `ManagerState::current` gives the value back once the state's
  tag has been checked.
- **Publish the new value after every deletion, authentically.** Verifiers must check proofs
  against the current value. A verifier that still uses an old value accepts a revoked holder.
- **`γ` is a lifetime budget.** When it is spent you need a new accumulator.
- **Never re-add by going around the check.** `Error::ElementAlreadyAdded` protects the secret
  key. If an element has to come back, use the [adaptive variant](adaptive.md).
