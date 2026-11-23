# Witnesses and updates

> **In short.** A [witness](glossary.md#witness) is a holder's pass. The manager issues it
> once. After each deletion the holder brings it up to date on its own, from the published
> update messages and the public key, with no secret. This chapter covers issuing, checking and
> updating witnesses, and the four ways to apply updates.
>
> **Read this when** you write the holder's side: receiving a witness, checking it, and keeping
> it current as deletions are published.
>
> **New here?** Read steps 5 to 8 of [Your first accumulator](tutorial.md) and the rule
> [Apply every update once, in order, and check the result](rules.md#apply-every-update-once-in-order-and-check-the-result)
> first.

A witness is what a [holder](glossary.md#holder) has to show for its element. The manager issues it once. From then
on the holder keeps it current on its own, from public data.

## The life of a witness

1. The manager adds `x` and calls `MembershipWitness::new`. The result goes to the holder of
   `x` over a private channel.
2. The holder checks it with `verify` against the public key and the current value.
3. Additions by the manager change nothing for the holder.
4. Each time the manager deletes elements, it publishes the new value and the [update
   messages](glossary.md#update-message). The holder applies them and checks the result.
5. If the holder's own element is deleted, its witness cannot be updated and never verifies
   again.

There are four ways to apply updates. They compute the same thing.

| method | input | checks |
|---|---|---|
| `update` | one [batch](glossary.md#batch), with the old and the new accumulator value | the witness against the old value, the result against the new one |
| `batch_update` | one batch, with its update messages | that the messages name the deletions |
| `multi_batch_update` | several batches, in order | as `batch_update`, per batch |
| `evaluate_delta` then `apply_delta` | one batch, split into "compute" and "add" | as `batch_update` |

Each has an in-place `_assign` form. `evaluate_deltas` is `evaluate_delta` over several
batches.

## `MembershipWitness`

**What it is**

A short vector `s_x` with `[A | B − xᵀ⊗G]·s_x = c` and `‖s_x‖₂ ≤ β`, where `c` is the
accumulator value and `β` the [witness bound](glossary.md#norm-bound) of the parameter set. It is bound to its parameter
set. It encodes to 34,464 bytes at the toy set and 15,493,184 bytes at the 128-bit set.

**Why it exists**

It is the proof of membership. Finding a short vector that a public matrix maps to a given
target is hard without a [trapdoor](glossary.md#trapdoor); the manager has the trapdoor and hands out one such vector
per member. The equation ties the witness to the element `x` and to the value `c`, and the
norm bound is what makes it hard to forge.

**How to use it**

The manager issues; the holder verifies and updates.

```rust
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let element = |name: &[u8]| Element::hash(name, key.params());
let (x, y, z, w) = (element(b"x"), element(b"y"), element(b"z"), element(b"w"));
let members = [x.clone(), y.clone(), z.clone()];
let (mut acc, mut state) = Accumulator::with_elements(&key, &members)?;

// Manager: issue. The same element and deletions always give the same witness.
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
assert_eq!(MembershipWitness::new(&x, &acc, &key, &state)?, witness);

// Holder: verify against the public key and the current value.
assert!(witness.verify(&x, &pk, &acc));
assert!(!witness.verify(&y, &pk, &acc)); // it is a witness for x only

// Manager: a batch that adds w and deletes y.
let old = acc.clone();
let coefficients = acc.update_assign(&key, &[w.clone()], &[y.clone()], &mut state)?;

// Holder, single batch with both values: checks before and after.
let updated = witness.update(&x, &old, &acc, &[w.clone()], &[y.clone()], &pk)?;
assert!(updated.verify(&x, &pk, &acc));

// Holder, single batch with the update messages: the same result.
let batched = witness.batch_update(&x, &[w.clone()], &[y.clone()], &coefficients, &pk)?;
assert_eq!(batched, updated);

// Manager: a second batch. Holder: catch up over both at once from the original witness.
let second = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
let batches = [(vec![w], vec![y], coefficients), (vec![], vec![z], second)];
let caught_up = witness.multi_batch_update(&x, &batches, &pk)?;
assert!(caught_up.verify(&x, &pk, &acc));

// Stored form: in a buffer that is wiped when dropped.
let bytes = caught_up.to_bytes()?;
assert_eq!(bytes.len(), 34_464);
assert_eq!(MembershipWitness::try_from(bytes.as_slice())?, caught_up);
# Ok::<(), kln_accumulator::Error>(())
```

`MembershipWitness::new` is the only code path that samples a witness. It samples the element's
preimage for the key's genesis value, with randomness derived from the element alone, and adds
the correction of every deletion the state records. So a witness is a function of the key, the
element and the set of deletions: recreating it later, from this state, a copy, a fork or a
rebuilt state, gives the one issued at addition, brought up to date, never a fresh one. Its
cost grows with the number of deletions made so far, not only those since the element was
added.

```rust
use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params};
use kln_accumulator::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let pk = PublicKey::from(&key);
let element = |name: &[u8]| Element::hash(name, key.params());
let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));

// x added before the deletions of y and z, in one order...
let (mut early, mut early_state) = Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
early.remove_elements_assign(&key, &[y.clone(), z.clone()], &mut early_state)?;
// ...and x added after them, in the other order.
let (mut late, mut late_state) = Accumulator::with_elements(&key, &[y.clone(), z.clone()])?;
late.remove_elements_assign(&key, &[z.clone(), y.clone()], &mut late_state)?;
late.add_assign(&key, &x, &mut late_state)?;

assert_eq!(late, early);
let witness = MembershipWitness::new(&x, &early, &key, &early_state)?;
assert_eq!(MembershipWitness::new(&x, &late, &key, &late_state)?, witness);
assert!(witness.verify(&x, &pk, &early));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Holder-private. The witness belongs to its element's holder, who shows it to no one and uses
it as the secret input of a membership proof.

- Its coefficients are overwritten when it is dropped. It is `Clone`, because the API returns
  updated witnesses by value; every clone wipes itself too.
- `to_bytes` and the serde form encode it in buffers that are wiped on drop.
- `Debug` prints only the parameter set.
- An update does the same products whatever the holder's element: every block of the
  correction is computed and multiplied by 0 or 1, so the work does not show how long a
  prefix the element shares with a deleted one. That is by source reading; no timing test was
  run, and it costs about twice what skipping the zero blocks would. Issuing a witness
  is not constant time; see
  [Guarantees and their limits](security.md#timing-what-is-and-is-not-constant-time).

What it guarantees: a witness that verifies for `x` against the current value shows that `x`
is in the set, provided nobody but the manager can produce such witnesses. That is the
collision-freeness of the accumulator; see [Guarantees and their limits](security.md).

Anyone who obtains a holder's witness and element can prove membership as that holder. The
witness is a bearer secret.

**Using it safely**

The code refuses:

| misuse | result |
|---|---|
| issuing for an element that is not present (never added, or deleted) | `Error::ElementNotPresent` |
| issuing with a state whose tag fails | `Error::InvalidStateTag` |
| issuing against a value that is not the state's current value | `Error::AccumulatorMismatch` |
| updating a witness whose own element is among the deletions | `Error::ElementDeleted` |
| update messages that do not name the deletions, in order | `Error::CoefficientMismatch` |
| a batch whose additions contain the holder's own element | `Error::ElementAlreadyAdded` |
| `update` with a witness that does not verify against the old value, or whose result does not verify against the new one | `Error::AccumulatorMismatch` |
| a witness or a delta of another parameter set | `Error::ParameterMismatch`, or `false` from `verify` |
| a vector whose norm exceeds `β` | `false` from `verify`; `Error::CoefficientOverBound` from `to_bytes` |
| an encoding with a coefficient above the bound, truncated, or not canonical | `Error::CoefficientOverBound`, `Error::InvalidEncodingLength`, `Error::NonCanonicalEncoding` |

```rust
use kln_accumulator::{Accumulator, Element, Error, MembershipWitness, Params};
use kln_accumulator::lattice::{Poly, PolyVec};
use kln_accumulator::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::hash(b"x", &params), Element::hash(b"y", &params));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let for_x = MembershipWitness::new(&x, &acc, &key, &state)?;
let for_y = MembershipWitness::new(&y, &acc, &key, &state)?;
let old = acc.clone();
let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

// The deleted element: its witness no longer verifies, cannot be updated, cannot be reissued.
assert!(!for_y.verify(&y, &pk, &acc));
assert_eq!(
    for_y.batch_update(&y, &[], &[y.clone()], &coefficients, &pk).map(drop),
    Err(Error::ElementDeleted)
);
assert_eq!(
    MembershipWitness::new(&y, &acc, &key, &state).map(drop),
    Err(Error::ElementNotPresent)
);

// Issuing against a stale value.
assert_eq!(
    MembershipWitness::new(&x, &old, &key, &state).map(drop),
    Err(Error::AccumulatorMismatch)
);

// Update messages that do not match the deletions.
assert_eq!(
    for_x.batch_update(&x, &[], &[y.clone()], &[], &pk).map(drop),
    Err(Error::CoefficientMismatch)
);

// update() with the wrong "old" value.
assert_eq!(
    for_x.update(&x, &acc, &acc, &[], &[y.clone()], &pk).map(drop),
    Err(Error::AccumulatorMismatch)
);

// A vector that is far too long: it does not verify, and it has no encoding.
let quarter = params.ring().modulus().wrapping_shr_vartime(2);
let entry = Poly::new(vec![quarter; params.ring().degree()], params.ring())?;
let long = MembershipWitness::from_vector(PolyVec::from(vec![entry; 100]), &params)?;
assert!(!long.verify(&x, &pk, &acc));
assert_eq!(long.to_bytes().map(drop), Err(Error::CoefficientOverBound));

// A stored witness with a coefficient pushed over the bound.
let good = for_x.batch_update(&x, &[], &[y], &coefficients, &pk)?;
let mut bytes = good.to_bytes()?.to_vec();
bytes[64..70].fill(0xff);
assert_eq!(
    MembershipWitness::try_from(bytes.as_slice()).map(drop),
    Err(Error::CoefficientOverBound)
);
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **Verify after every update.** `batch_update`, `multi_batch_update` and `apply_delta` do
  not check the result against an accumulator value. If you skip a batch, or apply one twice,
  they succeed and return a witness that does not verify. Call `verify` against the new
  published value, or use `update`, which checks both ends. The example below shows a skipped
  and a repeated batch.
- **Apply every batch exactly once.** Keep track of the last value you are current for.
- **Keep it private, and wipe copies.** `to_bytes` returns a wiped buffer; a `Vec` you copy it
  into is yours to wipe.
- **Issue over a private, authenticated channel.** The manager sends the witness to the holder
  and to nobody else.
- **Manager: do not hand a witness to anyone but the holder, and do not cache witnesses in
  the clear.** You can always recreate one.

```rust
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::hash(b"x", key.params()), Element::hash(b"y", key.params()));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

// Skipped: the old witness against the new value.
assert!(!witness.verify(&x, &pk, &acc));
// Applied once: fine.
let once = witness.batch_update(&x, &[], &[y.clone()], &coefficients, &pk)?;
assert!(once.verify(&x, &pk, &acc));
// Applied twice: no error from the update, but the result does not verify.
let twice = once.batch_update(&x, &[], &[y], &coefficients, &pk)?;
assert!(!twice.verify(&x, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

## `Delta`

**What it is**

The correction that a sequence of deletions makes to one holder's witness. It is the sum, over
the deleted elements `y`, of `H_{1y,x}·G⁻¹(u)`, and it is added to the tail of the witness of
`x`. It is specific to the holder's element.

**Why it exists**

Computing the correction is the expensive part of an update, and adding it is trivial.
Splitting the two lets a holder compute a delta once, perhaps in the background or over
several batches, and apply it later. It mirrors the `Delta` of the vb20 pairing accumulator.

**How to use it**

```rust
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
use kln_accumulator::{evaluate_delta, evaluate_deltas};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let element = |name: &[u8]| Element::hash(name, key.params());
let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
let members = [x.clone(), y.clone(), z.clone()];
let (mut acc, mut state) = Accumulator::with_elements(&key, &members)?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;

// One batch: compute the delta, then add it.
let first = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
let delta = evaluate_delta(&x, &[], &[y.clone()], &first, &pk)?;
let after_first = witness.apply_delta(&delta)?;
assert!(after_first.verify(&x, &pk, &acc));

// Several batches: one delta for all of them.
let second = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
let batches = [(vec![], vec![y], first), (vec![], vec![z], second)];
let delta = evaluate_deltas(&x, &batches, &pk)?;
let mut current = witness.clone();
current.apply_delta_assign(&delta)?;
assert!(current.verify(&x, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

`evaluate_delta(y, additions, deletions, coefficients, pubkey)` takes the holder's element
first, then the batch as the manager published it. `evaluate_deltas(y, deltas, pubkey)` takes
a slice of `(additions, deletions, coefficients)` triples, in order, and returns the sum.

**Security**

Holder-private. It is computed from public data, but it depends on the holder's element, so it
is treated like the witness: overwritten when dropped, and `Debug` prints only the parameter
set. It is not serialized.

**Using it safely**

The code refuses, in `evaluate_delta` and `evaluate_deltas`:

- the holder's own element among the deletions: `Error::ElementDeleted`;
- update messages that do not name the deletions in order: `Error::CoefficientMismatch`;
- the holder's own element among the additions: `Error::ElementAlreadyAdded`;
- an element that does not fit the set: `Error::InvalidElement`;

and in `apply_delta`, a delta of another parameter set: `Error::ParameterMismatch`.

```rust
use kln_accumulator::{Accumulator, Element, Error, Params, PublicKey, SecretKey, evaluate_delta};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y) = (Element::hash(b"x", key.params()), Element::hash(b"y", key.params()));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

// The holder of y asks for its own delta.
let own = evaluate_delta(&y, &[], &[y.clone()], &coefficients, &pk);
assert_eq!(own.map(drop), Err(Error::ElementDeleted));
// Messages missing.
let none: [kln_accumulator::Coefficient; 0] = [];
let missing = evaluate_delta(&x, &[], &[y.clone()], &none, &pk);
assert_eq!(missing.map(drop), Err(Error::CoefficientMismatch));
// The holder's element listed as an addition.
let listed = evaluate_delta(&x, &[x.clone()], &[y], &coefficients, &pk);
assert_eq!(listed.map(drop), Err(Error::ElementAlreadyAdded));
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **A delta is for one witness state.** It carries no record of which batches it covers.
  Apply it to the witness that was current before those batches, once. Applying it to the
  wrong witness, or twice, gives a witness that does not verify, and `apply_delta` does not
  tell you. Verify afterwards.
- **Do not send it anywhere.** A delta is a function of the holder's element. Asking a third
  party to compute it means telling that party which element is yours.
