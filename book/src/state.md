# Manager state and its tag

> **In short.** The [manager state](glossary.md#manager-state) is the manager's private ledger:
> every element ever added, which ones were deleted, how many deletions have been made, and the
> current accumulator value. A [tag](glossary.md#state-tag) binds it to the secret key, so a
> state altered in storage is refused. An older copy of the state is not refused.
>
> **Read this when** you decide how the manager stores its state, loads it again, or rebuilds
> it after a loss.
>
> **New here?** Read the rules
> [One key, one accumulator, one manager](rules.md#one-key-one-accumulator-one-manager) and
> [Save the state before you publish](rules.md#save-the-state-before-you-publish-and-never-go-back-to-an-older-copy)
> first. Then read this chapter before you build the manager's storage.

The algorithms of ePrint 2025/1099 keep state between calls: which elements were added, which
were deleted, and when. The [vb20 pairing accumulator](glossary.md#vb20-pairing-accumulator), whose API this crate mirrors, keeps
none. So here the state is an explicit value, `ManagerState`, and every operation that needs
the secret key takes the state as its last argument.

The state is the most delicate thing the manager owns after the key. Read **Using it safely**
under [`ManagerState`](#managerstate) before you design storage for it.

## What the state records

- the current accumulator value `c`, the one the last keyed operation left (the key's [genesis
  value](glossary.md#genesis-value) `c₀` at first; the key, not the state, holds `c₀`);
- the deletion counter `ctr`, the number of deletions made so far;
- a dictionary from every element ever added to a `Record`: whether it is present or deleted,
  and at which *[epoch](glossary.md#epoch)*;
- a tag that binds all of the above to the secret key.

Epochs count deletions. An element added before any deletion has epoch 0. The `j`-th deletion
records epoch `j`. The epochs are a record of the history only; no witness depends on them.

## Why the state matters for security

A witness is a short [preimage](glossary.md#preimage-preimage-sampler), sampled with the [trapdoor](glossary.md#trapdoor). Two *different* short preimages for
the same element under the same matrix give away a short vector of that matrix's kernel, and
enough of them give away a trapdoor (Remark 4.1 and Remark 4.2 of ePrint 2025/1099). So the
manager must never sample twice, differently, for one element.

The crate makes that independent of the state. A key keeps one accumulator, which starts at a
genesis value `c₀` the key derives. `MembershipWitness::new` samples each element's preimage
for `c₀`, with a seed that is a PRF of the element alone, and then adds the public correction
of every deletion the state records. So a witness is a function of the key, the element and
the *set* of deletions: the order of the deletions, the epoch of the addition and the state's
past do not enter. This departs from the paper, which samples for the value at the epoch of
the addition; [Guarantees and their limits](security.md) gives the reason and why security is
kept.

What the state still decides is *which* witnesses the manager issues and against which value:
who is a member, what was deleted, how many deletions are left. The tag keeps that record the
one the key's own operations wrote.

## `ManagerState`

**What it is**

What the manager keeps between operations: the counter, the current value, the dictionary and
the tag. It is `Clone`, comparable and serializable.

**Why it exists**

Without it the manager could not refuse a second addition of an element, could not count
deletions against `γ`, could not tell which deletions a witness must be corrected for, and
could not tell the current accumulator value from any other. It is the paper's `st`, minus the
PRF key and `c₀`, which live in the secret key, plus the current value, which the paper's
algorithms receive as an argument. The current value is stored rather than recomputed:
recomputing it from `c₀` costs one deletion offset per past deletion.

**How to use it**

```rust
use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;

// A fresh state for an accumulator that starts at `acc`, tagged under the key.
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
assert_eq!(state.counter(), 0);
assert_eq!(&Accumulator::new(&key), &acc);
assert_eq!(state.current(), &acc);

// Every keyed operation takes it last and updates it, the current value included.
let y = Element::hash(b"y", &params);
acc.add_assign(&key, &y, &mut state)?;
acc.remove_assign(&key, &y, &mut state)?;
assert_eq!(state.counter(), 1);
assert_eq!(state.current(), &acc);
state.validate(&params)?;

// Persist it after every change. The tag travels with it and is checked at the next keyed use.
let stored = serde_json::to_string(&state)?;
let loaded: ManagerState = serde_json::from_str(&stored)?;
assert_eq!(loaded, state);
// Check the tag of a loaded state under the key before reading it; this changes nothing.
loaded.authenticate(&key)?;
assert_eq!(loaded.current(), &acc);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Accumulator::with_elements` makes the value and the state together.

**Security**

Manager-private, but not key material. It holds no key. Its disclosure reveals the history:
every element ever added, and when each was added and deleted. It does not reveal how to forge
witnesses. Its elements are overwritten on drop, as every `Element` is. It is not otherwise
treated as a secret.

The tag gives **integrity of the state under the secret key**. It is SHAKE256 keyed by prefix
with a 32-byte key derived from the secret key's root seed and parameter set, over the initial
value, the current value, the counter and the whole dictionary. Every keyed operation checks it
first, in constant time, and refuses a state that fails with `Error::InvalidStateTag`, leaving
the value and the state as they were; `ManagerState::authenticate` runs the same check on its
own. Every operation that changes the state records the new value and tags the state again. So
a state that was altered in any field, or that another key tagged, never decides a witness or a
deletion.

The stored current value ties the state to **one accumulator value**. After the tag, every
keyed operation (add, remove, update and their forms, and `MembershipWitness::new`) checks that
the value it is called on is the state's current one, and refuses any other with
`Error::AccumulatorMismatch`, again changing nothing. An unrelated value, or an earlier value of
the same accumulator, cannot move the state.

The tag does **not** give freshness. An older state that the same key once tagged verifies as
well as the current one. Nothing monotonic lives outside the state, so the crate cannot tell
the latest state from an earlier one. That no longer endangers the key: an older, forked or
fresh state reproduces the same witnesses for the same deletions. It does still issue witnesses
for its own, older value.

**Using it safely**

The code refuses:

- a state tagged under another key, or altered in any field, at every keyed operation and at
  `ManagerState::authenticate`: `Error::InvalidStateTag`;
- a value that is not the state's current one, at every keyed operation:
  `Error::AccumulatorMismatch`;
- a serialized state whose history Construction 4.1 cannot produce (deletion epochs that are
  not exactly `1, …, ctr`, or an addition epoch above `ctr`), at deserialization:
  `Error::InconsistentState`;
- a state of another parameter set: `Error::ParameterMismatch`, and `ManagerState::validate`
  reports `Error::InvalidElement` or `Error::InconsistentState` for a state that does not fit
  a set; a serialized state whose current value belongs to another set than its initial value
  does not deserialize (`Error::ParameterMismatch`).

```rust
use kln_accumulator::{Accumulator, Element, Error, ManagerState, MembershipWitness, Params};
use kln_accumulator::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::clone(&params), &mut rng)?;
let other = SecretKey::new(Some(b"someone else's seed, 32 bytes long"), Arc::clone(&params), &mut rng)?;
let (x, y) = (Element::hash(b"x", &params), Element::hash(b"y", &params));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
acc.remove_assign(&key, &y, &mut state)?;

// 1. A state tagged under another key.
let mut foreign = ManagerState::new(&other);
let z = Element::hash(b"z", &params);
assert_eq!(acc.add_assign(&key, &z, &mut foreign), Err(Error::InvalidStateTag));

// 2. A stored state with one field altered: x's addition epoch moved from 0 to 1. The history
//    is still one the construction could produce, so it deserializes; the tag catches it.
let stored = serde_json::to_string(&state)?;
let altered = stored.replace(r#""operation":"Add","epoch":0"#, r#""operation":"Add","epoch":1"#);
assert_ne!(altered, stored);
let mut tampered: ManagerState = serde_json::from_str(&altered)?;
assert_eq!(
    MembershipWitness::new(&x, &acc, &key, &tampered).map(drop),
    Err(Error::InvalidStateTag)
);
assert_eq!(acc.add_assign(&key, &z, &mut tampered), Err(Error::InvalidStateTag));

// 3. A stored state whose history is impossible: one deletion recorded, counter set to 0.
let impossible = stored.replace(r#""counter":1"#, r#""counter":0"#);
assert_ne!(impossible, stored);
let refused = serde_json::from_str::<ManagerState>(&impossible).map(drop);
let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
assert!(message.contains(&Error::InconsistentState.to_string()));

// 4. The tag check on its own: the honest state passes, the altered one does not.
state.authenticate(&key)?;
assert_eq!(tampered.authenticate(&key), Err(Error::InvalidStateTag));

// 5. A value that is not the state's current one: the value from before the deletion, and an
//    unrelated value. Both are refused, and neither the value nor the state changes.
let before = state.clone();
let mut stale = Accumulator::new(&key);
assert_eq!(stale.add_assign(&key, &z, &mut state), Err(Error::AccumulatorMismatch));
let mut unrelated = Accumulator::random(&mut rng, &params);
assert_eq!(unrelated.remove_assign(&key, &x, &mut state), Err(Error::AccumulatorMismatch));
assert_eq!((&stale, &state), (&Accumulator::new(&key), &before));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Your job, and this is the important part:

- **Never go back to an older state.** Rollback is not detected. It cannot leak the key, but
  an earlier state issues witnesses for the earlier value, and if the manager continues from
  it, it publishes a second history next to the first; holders and verifiers can follow only
  one. [Misuse](misuse.md) shows both.
- **Persist the state before you publish.** Write the new state durably, then publish the new
  value and update messages, then hand out witnesses. If you publish first and crash, you
  restart from a state that is older than what the world saw: a rollback.
- **Never run two managers on one key.** Two processes that each hold the key and a copy of
  the state publish two histories from their first diverging operation.
- **Keep the deletion log; it is the backup.** Every update message the manager publishes
  names a deletion. With the key, the log in any order and the list of current members,
  `ManagerState::rebuild` remakes a lost state and its value, and the rebuilt state issues the
  same witnesses. The member list is yours to keep (in the [adaptive variant](adaptive.md),
  with each member's handle): a wrong one cannot leak the key, but it
  makes the manager issue a witness it should not, or refuse one it should issue. A fresh
  `ManagerState` is at the genesis value, so it refuses the live value; rebuild instead.
- **Check a loaded state before you read it.** Deserialization has no key, so `record`,
  `counter` and `current` on a freshly loaded state return unverified data. Call
  `ManagerState::authenticate` with the key first, as in the example above; it checks the tag
  and changes nothing.
- **Mind its growth.** Checking and re-tagging hash the whole state, so every keyed operation
  costs time linear in the number of elements ever added.
- **Keep it private.** It lists every element and its history.

### Rebuilding a lost state

The manager published two batches and then lost its state. It rebuilds it from the key, the
update messages in the order it happens to hold them, and its members, and carries on.

```rust
use kln_accumulator::{Accumulator, Element, Error, ManagerState, MembershipWitness, Params};
use kln_accumulator::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let pk = PublicKey::from(&key);
let e = |name: &[u8]| Element::hash(name, key.params());
let (a, b, c, d) = (e(b"a"), e(b"b"), e(b"c"), e(b"d"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[a.clone(), b.clone(), c.clone()])?;
let mut log = acc.update_assign(&key, &[d.clone()], &[b.clone()], &mut state)?;
log.extend(acc.update_assign(&key, &[], &[c.clone()], &mut state)?);
let issued = [
    MembershipWitness::new(&a, &acc, &key, &state)?,
    MembershipWitness::new(&d, &acc, &key, &state)?,
];
drop(state);

// The log, newest first, and the members a and d.
log.reverse();
let (mut value, mut rebuilt) = ManagerState::rebuild(&key, &log, &[a.clone(), d.clone()])?;
assert_eq!(value, acc);
assert_eq!(rebuilt.counter(), 2);
assert_eq!(MembershipWitness::new(&a, &value, &key, &rebuilt)?, issued[0]);
assert_eq!(MembershipWitness::new(&d, &value, &key, &rebuilt)?, issued[1]);

// It carries on as the lost state would have: b stays deleted, a can be deleted, and the
// witness of d follows.
assert_eq!(value.add_assign(&key, &b, &mut rebuilt), Err(Error::ElementAlreadyAdded));
let more = value.update_assign(&key, &[], &[a.clone()], &mut rebuilt)?;
let d_now = issued[1].batch_update(&d, &[], &[a.clone()], &more, &pk)?;
assert_eq!(d_now, MembershipWitness::new(&d, &value, &key, &rebuilt)?);
assert!(d_now.verify(&d, &pk, &value));

// A log that names an element twice, or a member that is in the log, is refused.
let twice = [log.clone(), log[..1].to_vec()].concat();
assert_eq!(ManagerState::rebuild(&key, &twice, &[]).map(drop), Err(Error::ElementNotPresent));
assert_eq!(ManagerState::rebuild(&key, &log, &[b.clone()]).map(drop), Err(Error::ElementAlreadyAdded));
# Ok::<(), kln_accumulator::Error>(())
```

## `Record`

**What it is**

One entry of the dictionary: what last happened to an element (`operation`) and at which
epoch (`epoch`). A `Copy` struct with two public fields.

**Why it exists**

The epoch at which an element was added decides which accumulator value its witness is sampled
against, and the epoch of each deletion decides which corrections that witness needs. The
record is how `MembershipWitness::new` finds both.

**How to use it**

Read it with `ManagerState::record`. `None` means the element was never added.

```rust
use kln_accumulator::{Accumulator, Element, Operation, Params, Record, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let element = |name: &[u8]| Element::hash(name, key.params());
let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
acc.remove_assign(&key, &y, &mut state)?;
acc.add_assign(&key, &z, &mut state)?;

// x was added before any deletion. y was the first deletion. z was added after it.
assert_eq!(state.record(&x), Some(Record { operation: Operation::Add, epoch: 0 }));
assert_eq!(state.record(&y), Some(Record { operation: Operation::Del, epoch: 1 }));
assert_eq!(state.record(&z), Some(Record { operation: Operation::Add, epoch: 1 }));
assert_eq!(state.record(&element(b"never added")), None);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value in itself, no secrecy; as part of the manager state it is manager-private,
because it says when an element was added and whether it was revoked. Nothing is wiped on
drop.

**Using it safely**

You cannot write a record into a state: the dictionary is private and changes only through
the keyed operations. A record altered in a serialized state is caught by the tag
(`Error::InvalidStateTag`) or, if it makes the history impossible, at deserialization
(`Error::InconsistentState`); the example under `ManagerState` shows both. Your job is only to
remember that a record read from a state whose tag has not been checked yet is unverified.

## `Operation`

**What it is**

An enum with two variants: `Add`, the element is in the accumulator, and `Del`, it was
deleted.

**Why it exists**

It is the paper's `Op ∈ {Add, Del}`. Construction 4.1 never forgets an element: a deleted
element stays in the dictionary as `Del`, which is how a second addition is refused.

**How to use it**

Match on the `operation` field of a `Record`, as in the example above. As a byte it is 0 for
`Add` and 1 for `Del`; that byte is what the state tag absorbs.

```rust
use kln_accumulator::Operation;

assert_eq!(u8::from(Operation::Add), 0);
assert_eq!(u8::from(Operation::Del), 1);
assert_eq!(serde_json::to_string(&Operation::Del)?, r#""Del""#);
# Ok::<(), serde_json::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped.

**Using it safely**

Nothing to misuse: it is only ever read. There is no third state "never added"; that is the
`None` of `ManagerState::record`, and you should treat it differently from `Del`. A deleted
element can never come back in Construction 4.1; an element that was never added can still be
added.
