# Troubleshooting

This page starts from what you see and works back to the cause. [Errors](errors.md) goes the
other way, from each `Error` variant to its meaning; the tables here link to the entry there
where one exists. Many problems give no error at all, only a `false` from `verify`, so those
come first.

The words are those of [Accumulators in plain words](concepts.md). The examples use the toy
parameter set and the crates `rand` and `serde_json`, like the [recipes](recipes.md).

| what you see | section |
|---|---|
| `verify` returns `false` for a witness that used to pass | [A witness stops verifying](#a-witness-stops-verifying) |
| a holder's update returns an error | [A witness update is refused](#a-witness-update-is-refused) |
| decoding bytes returns an error | [A decode fails](#a-decode-fails) |
| an operation of the manager returns an error | [A keyed operation is refused](#a-keyed-operation-is-refused) |
| the value is the same after adding members | [The value did not change after adding](#the-value-did-not-change-after-adding) |
| everything takes seconds | [It is slow](#it-is-slow) |
| keys, witnesses or stored files are megabytes | [Sizes are larger than expected](#sizes-are-larger-than-expected) |
| `verify` of a membership proof returns an error | [A proof does not verify](#a-proof-does-not-verify) |

## A witness stops verifying

`MembershipWitness::verify` answers only `true` or `false`. It answers `false` for a witness
that does not fit, and also for an element, a public key or a value of another parameter set,
so it cannot tell you which. Go through the causes in this order.

| cause | fix | see |
|---|---|---|
| **The witness was not updated.** A batch with deletions was published, and the holder has not applied it, or skipped one. | Apply every batch since the last one the witness verified for, in order. `multi_batch_update` takes several at once. | [Bring a holder's witness up to date](recipes.md#bring-a-holders-witness-up-to-date) |
| **A batch was applied twice.** The update gives no error; the result just does not verify. | Keep the last witness that verified, with the sequence number of its batch, and apply from there. | [Witnesses and updates](witnesses.md#membershipwitness) |
| **It is checked against the wrong value.** A value from before or after the batches the witness is current for, or a value of another accumulator. | Check against the value of the record the witness was last updated to; a verifier uses the newest value it has. | [Deploying it](deploying.md#the-publish-and-fetch-flow) |
| **The element was deleted.** Its witness never verifies again. | Nothing to fix: the holder was revoked. Its update says so with `Error::ElementDeleted`. | [`ElementDeleted`](errors.md#witness-updates) |
| **The public key is another manager's.** Or the witness was issued under another key. | Use the public key you got from the manager over an authenticated channel. | [Keys](keys.md#publickey) |
| **The element is not the witness's own.** | Pass the element the witness was issued for. | [Check a witness](recipes.md#check-a-witness) |
| **An input belongs to another parameter set.** | Call `validate(&params)` on the element, the witness and the value; the one that fails is from another set. | [Serialization](serialization.md#decoding-against-the-set-you-expect) |

```rust
use kln_accumulator::{Accumulator, Element, Error, MembershipWitness, Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
let element = |n: u8| Element::try_from(&[n][..]);
let (x, y) = (element(1)?, element(2)?);
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
let old = acc.clone();
let messages = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

// Not updated: it fits the old value, not the new one.
assert!(!witness.verify(&x, &pk, &acc));
assert!(witness.verify(&x, &pk, &old));
let current = witness.batch_update(&x, &[], &[y.clone()], &messages, &pk)?;
assert!(current.verify(&x, &pk, &acc));

// Applied twice: no error, and a witness that does not verify.
let twice = current.batch_update(&x, &[], &[y.clone()], &messages, &pk)?;
assert!(!twice.verify(&x, &pk, &acc));

// Checked against the wrong value: the current witness fails against the old one.
assert!(!current.verify(&x, &pk, &old));

// Another manager's public key, of the same set.
let other = PublicKey::from(&SecretKey::new(None, Arc::clone(&params), &mut rng)?);
assert!(!current.verify(&x, &other, &acc));

// Another element.
assert!(!current.verify(&y, &pk, &acc));

// An input of another set, here a four-byte element of the 128-bit set: verify only says
// false, validate says which input it is.
let wide = Element::try_from(&[1u8, 0, 0, 0][..])?;
assert!(!current.verify(&wide, &pk, &acc));
assert_eq!(wide.validate(&params), Err(Error::InvalidElement));
assert_eq!(current.validate(&params), Ok(()));
assert_eq!(acc.validate(&params), Ok(()));
# Ok::<(), kln_accumulator::Error>(())
```

## A witness update is refused

`batch_update`, `multi_batch_update` and `evaluate_delta` check the batch against the holder's
element before they change the witness: a refused update leaves it as it was.

| error | cause | fix | see |
|---|---|---|---|
| `Error::ElementDeleted` | the holder's own element is among the deletions | the holder was revoked: stop presenting | [`ElementDeleted`](errors.md#witness-updates) |
| `Error::CoefficientMismatch` | the update messages do not name the deletions, in order: a message is missing, or the deletions were listed in another order | take the deletions from the messages themselves, as the recipe does, or fetch the batch again | [`CoefficientMismatch`](errors.md#witness-updates) |
| `Error::ElementAlreadyAdded` | the holder's own element is in the batch's additions | pass the additions as published, or an empty list: additions never change a witness | [Witnesses and updates](witnesses.md#membershipwitness) |
| `Error::InvalidSignature` | in the adaptive variant, the witness is not for this element | pass the element the witness was issued for | [`InvalidSignature`](errors.md#witness-updates) |
| `Error::AccumulatorMismatch` | `update` with the old and the new value: the witness does not verify against the old one, or the result does not verify against the new one | pass the value the witness was current for as the old value | [`AccumulatorMismatch`](errors.md#accumulator-operations) |

In the adaptive variant the update messages name [handles](glossary.md#handle), and the
deletions a holder passes are those handles, not elements; see
[Re-add a removed member](recipes.md#re-add-a-removed-member).

```rust
# use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# let element = |n: u8| Element::try_from(&[n][..]);
# let (x, y, z) = (element(1)?, element(2)?, element(3)?);
# let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
use kln_accumulator::Error;

let messages = acc.update_assign(&key, &[], &[y.clone(), z.clone()], &mut state)?;

// The deletions in another order than the messages.
let swapped = witness.batch_update(&x, &[], &[z.clone(), y.clone()], &messages, &pk);
assert_eq!(swapped.map(drop), Err(Error::CoefficientMismatch));

// The fix: take the deletions from the messages.
let deletions: Vec<_> = messages.iter().map(|m| m.element().clone()).collect();
let current = witness.batch_update(&x, &[], &deletions, &messages, &pk)?;
assert!(current.verify(&x, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

## A decode fails

| error | cause | fix | see |
|---|---|---|---|
| `Error::InvalidEncodingLength` | the bytes were cut short, or have bytes left over | send the bytes exactly as `to_bytes` made them | [`InvalidEncodingLength`](errors.md#shapes-and-encodings) |
| `Error::ParameterMismatch` from `from_bytes` | the bytes belong to another parameter set than the one you passed: the toy set and the 128-bit set, the Gaussian and the ternary trapdoor, or a succinct set | decode against the set the sender uses | [Decoding against the set you expect](serialization.md#decoding-against-the-set-you-expect) |
| `Error::ParameterMismatch` from `from_bytes`, for a set that is right | the bytes are not the packed encoding of this type: they are another variant's, such as an adaptive public key decoded as a base one, or a serde form such as a JSON text | decode with the type and variant that made the bytes; decode a serde form with the same serde format | [Serialization](serialization.md#two-ways-to-encode) |
| `Error::NonCanonicalEncoding`, `Error::CoefficientOutOfRange`, `Error::CoefficientOverBound` | the bytes were altered: padding or reserved bytes set, a coefficient not below `q`, or a witness coefficient above its bound | fetch the value again; never repair it | [What decoding refuses](serialization.md#what-decoding-refuses) |
| `Error::InconsistentState` when loading a manager state | the stored state describes a history that cannot happen | the stored copy is corrupt: load another, or rebuild | [Manager state and its tag](state.md#managerstate) |

A base packed encoding starts with its 64-byte parameter set, and `from_bytes` compares those
bytes with the set you pass before it reads anything else; the adaptive types look for the set
further in, after their own fields. Bytes laid out some other way are therefore reported as
another set: an adaptive public key, which starts with its ML-DSA-65 verifying key, handed to
the base decoder, a base witness handed to the adaptive one, or a JSON text. `TryFrom<&[u8]>` tries to read a set from those first bytes
instead, and fails with whichever check they happen to break. Packed bytes and the serde forms
are two different encodings: bytes from `to_bytes` decode with `from_bytes` or
`TryFrom<&[u8]>`, and a serde form decodes with the serde format that wrote it.

```rust
# use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# let x = Element::try_from(&[1u8][..])?;
# let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
use kln_accumulator::{Error, ParamsSpec, TrapdoorDistribution, adaptive};

let bytes = pk.to_bytes();

// Cut short, or with a byte left over.
let short = PublicKey::from_bytes(&params, &bytes[..bytes.len() - 1]);
assert!(matches!(short, Err(Error::InvalidEncodingLength(_))));
let mut longer = bytes.clone();
longer.push(0);
assert!(matches!(PublicKey::from_bytes(&params, &longer), Err(Error::InvalidEncodingLength(_))));

// Another parameter set: here the same toy shape with the ternary trapdoor.
let ternary = Arc::new(Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))?);
assert_eq!(PublicKey::from_bytes(&ternary, &bytes).map(drop), Err(Error::ParameterMismatch));

// Another variant at the same set, both ways round: the layouts differ, so the decoder does
// not find the set where it looks for it.
let adaptive_key = adaptive::SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let adaptive_bytes = adaptive::PublicKey::from(&adaptive_key).to_bytes();
assert_eq!(PublicKey::from_bytes(&params, &adaptive_bytes).map(drop), Err(Error::ParameterMismatch));
let witness_bytes = witness.to_bytes()?;
assert_eq!(adaptive::MembershipWitness::from_bytes(&params, &witness_bytes).map(drop), Err(Error::ParameterMismatch));

// A serde form handed to the packed decoder.
let json = serde_json::to_string(&witness)?;
assert_eq!(
    MembershipWitness::from_bytes(&params, json.as_bytes()).map(drop),
    Err(Error::ParameterMismatch)
);
assert_eq!(serde_json::from_str::<MembershipWitness>(&json)?, witness);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## A keyed operation is refused

Every operation that adds, deletes or issues a witness takes the key and the manager state, and checks both before
it changes anything. A refusal leaves the value and the state as they were. Do not work around
one by starting a fresh state: the manager would forget who was added and deleted.

| error | cause | fix | see |
|---|---|---|---|
| `Error::AccumulatorMismatch` | the value is not the state's current one: a copy kept from before a deletion, or a value and a state loaded from two different saves | use `state.current()`; store the value and the state as one record | [`AccumulatorMismatch`](errors.md#accumulator-operations) |
| `Error::InvalidStateTag` | the state was altered in storage, or another key tagged it: the wrong key was loaded, or a key was made from the same seed under another parameter set | load the key and the state that belong together; do not build a new state | [`InvalidStateTag`](errors.md#accumulator-operations) |
| `Error::ElementAlreadyAdded` | the element was added before, and may since have been deleted; or two identifiers hashed to one element | in the base variant an element is added at most once; assign elements yourself, or use the adaptive variant for members who return | [`ElementAlreadyAdded`](errors.md#accumulator-operations) |
| `Error::ElementNotPresent` | deleting, or issuing a witness for, an element that was never added or was deleted | check the member list | [`ElementNotPresent`](errors.md#accumulator-operations) |
| `Error::DeletionBoundReached`, `Error::HandleSpaceExhausted` | a lifetime budget is spent | start a new accumulator | [Plan for the budgets](rules.md#plan-for-the-budgets) |
| `Error::CompressedWitnessOnly` | a base witness was asked of a succinct key | use `succinct::MembershipWitness::new` | [`CompressedWitnessOnly`](errors.md#accumulator-operations) |

```rust
# use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let element = |n: u8| Element::try_from(&[n][..]);
# let (x, y, z) = (element(1)?, element(2)?, element(3)?);
use kln_accumulator::Error;

let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let stale = acc.clone();
acc.remove_assign(&key, &y, &mut state)?;

// A copy of the value from before the deletion.
assert_eq!(
    MembershipWitness::new(&x, &stale, &key, &state).map(drop),
    Err(Error::AccumulatorMismatch)
);
// The fix: the state names its own value.
assert!(MembershipWitness::new(&x, state.current(), &key, &state).is_ok());

// The state of another key.
let other = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let mut foreign = ManagerState::new(&other);
assert_eq!(acc.add_assign(&key, &z, &mut foreign), Err(Error::InvalidStateTag));

// The deleted element, added again in the base variant.
assert_eq!(acc.add_assign(&key, &y, &mut state), Err(Error::ElementAlreadyAdded));
# Ok::<(), kln_accumulator::Error>(())
```

## The value did not change after adding

That is expected. In this scheme an addition leaves the accumulator value as it is: the manager
records the element in its state and issues a witness that fits the value already published.
Nothing is published, and no holder has to do anything. Only a deletion moves the value. See
[Why adding is free](concepts.md#why-adding-is-free).

```rust
# use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
# let element = |n: u8| Element::try_from(&[n][..]);
# let (x, y) = (element(1)?, element(2)?);
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
let before = acc.clone();
acc.add_elements_assign(&key, &[x, y.clone()], &mut state)?;
assert_eq!(acc, before);
acc.remove_assign(&key, &y, &mut state)?;
assert_ne!(acc, before);
# Ok::<(), kln_accumulator::Error>(())
```

## It is slow

| cause | fix | see |
|---|---|---|
| **An unoptimised build.** The crate does heavy arithmetic, and a debug build runs it far more slowly. Its own tests are optimised, but the default build of your project is not. | Build and run with `--release`, or optimise the crate in your debug builds as shown below. | [Your first accumulator](tutorial.md#before-you-start) |
| **The 128-bit set is this slow.** There, generating a key takes 1.49 s, issuing a witness 1.96 s, verifying one 128 ms, a deletion 751 ms, and each holder's update 1.00 s per deletion. | Plan for these figures; they come from one machine, so measure yours with `cargo bench`. | [Benchmarks and sizes](benchmarks.md#timings) |
| **Key generation with the Gaussian trapdoor.** It takes 1.49 s at the 128-bit set against 109 ms with the ternary trapdoor, and changes nothing else. | Choose the trapdoor distribution before you make the key. | [The trapdoor distribution](choosing.md#the-trapdoor-distribution) |
| **Issuing a witness after many deletions.** Issuing adds one correction for every deletion the state records, each about the cost of one holder update, so it grows with the deletions made so far, not only those since the element was added. | Expect it: a member who joins late, or a witness issued again, costs more than one issued before any deletion. | [Benchmarks and sizes](benchmarks.md#lifecycle-operations-construction-variants-paper_128) |
| **A large state.** Every keyed operation checks and re-tags the whole state, so its cost grows with the number of elements ever added, deleted ones included. | Expect it, and plan the move to a new accumulator. | [Manager state and its tag](state.md#managerstate) |
| **A holder catching up.** Its update grows in proportion to the number of deletions it applies, about 1 s each at the 128-bit set. | Nothing to fix: the total is the same either way, and updating after every batch spreads it out. | [Witnesses and updates](witnesses.md) |
| **Membership proofs.** At the toy set proving takes 4.32 s on average and verifying 568 ms, and each one-shot verification expands a commitment key of about 160 MB. | A verifier of many proofs builds a `ProofSetup` once and calls `verify_with`; that took about a third of the time of `verify` in a later run. | [`ProofSetup`](proofs.md#proofsetup) |

To optimise this crate and the crates it uses for hashing and big integers in the debug builds
of your own project, add this to your project's `Cargo.toml` (`"*"` covers every dependency,
and leaves your own code unoptimised):

```toml
[profile.dev.package."*"]
opt-level = 3
```

Naming only `kln-accumulator` there is not enough: its dependencies would stay unoptimised.
This advice has not been measured.

## Sizes are larger than expected

The sizes are what they are; [Benchmarks and sizes](benchmarks.md#sizes) has every one. Some
grow further depending on how you store them.

| what | how big | why | see |
|---|---|---|---|
| public key, witness | at the 128-bit set about 16.65 MiB and 14.78 MiB; at the toy set 48,544 and 34,464 bytes | that is the scheme at those settings | [Which variant and which settings](choosing.md#the-parameter-set) |
| any value in JSON, TOML or YAML | about twice its packed bytes | human-readable serde forms write bytes as hex, two characters a byte | [Serialization](serialization.md#two-ways-to-encode) |
| an adaptive witness | 37,782 bytes at the toy set, against 34,464 | it also carries a signature binding the element to its handle | [The adaptive variant](adaptive.md#what-it-costs) |
| a succinct public key | 2,149,984 bytes at the succinct toy set with the Gaussian trapdoor, 1,372,384 with the ternary one | the succinct variant trades a very large public key for shorter witnesses | [The succinct variant](succinct.md) |
| a membership proof | 9,100,960 bytes at the toy set; 852,816 bytes compressed in three levels | proof values are encoded at 24 bytes per coefficient, not packed, so these figures overstate what a packed encoding needs | [Membership proofs](proofs.md#compression) |
| the stored manager state | grows with every element ever added | deleted elements stay in it, so that they are never added again | [Manager state and its tag](state.md#what-the-state-records) |

```rust
# use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
# let x = Element::try_from(&[1u8][..])?;
# let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
let packed = witness.to_bytes()?;
assert_eq!(packed.len(), 34_464);
// JSON writes the same bytes as hex: more than twice the size.
let json = serde_json::to_string(&witness)?;
assert!(json.len() > 2 * packed.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Store and send the packed bytes, or a binary serde format such as postcard, when size matters.

## A proof does not verify

Proofs run only at the toy sets, which give no security; this section is for study. A
verifier accepts only on `Ok`; every error means "rejected".

| error | cause | fix | see |
|---|---|---|---|
| `Error::ProofRejected` | the two transcripts differ: another protocol label, another nonce, or the same messages appended in another order | build the transcript the same way on both sides, before proving and before verifying | [Transcripts: what to bind](proofs.md#transcripts-what-to-bind) |
| `Error::ProofRejected` | the statement differs: the verifier holds another accumulator value than the prover used (a deletion came between), another public key, or another linking relation | the holder updates its witness and proves against the newest value; both sides build the statement from the same public key and relation | [Misuse](misuse.md#g-proofs-the-verifier) |
| `Error::ProofRejected` | the proof parameters differ: `ProofParams::new` was called with another entropy input on one side (`None` and `Some(&[])` differ) | derive them the same way on both sides | [`ProofParams`](proofs.md#proofparams) |
| `Error::ProofRejected`, `Error::InvalidEncodingLength` | the proof was altered or cut short in transit | fetch it again | [`MembershipProof`](proofs.md#membershipproof) |
| `Error::RelationUnsatisfied`, from `prove` | the prover's inputs do not fit the statement: a witness that does not verify against the value, an `r` that is not binary, or a relation the element and `r` do not satisfy | update the witness and check it with `verify` first; check the relation | [`RelationUnsatisfied`](errors.md#proofs) |
| `Error::UnsupportedProofDegree` | the parameter set is not a toy set: proofs need ring degree 64 | none today: proofs do not run at the 128-bit set | [`UnsupportedProofDegree`](errors.md#proofs) |

A proof is bound to its proof parameters, public key, accumulator value and linking relation
through the transcript, so any difference on either side shows up as the same
`Error::ProofRejected`. The examples that trigger each case are in
[Misuse](misuse.md#g-proofs-the-verifier).
