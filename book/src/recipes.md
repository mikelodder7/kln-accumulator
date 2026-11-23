# How do I…

Each recipe says when you need it, gives the code, and names the one pitfall that matters
most. The code is compiled, and almost all of it run, by the crate's tests. Each block hides
its setup lines (a key, an accumulator, a few members); the eye button at the top right of a
block shows them. Every recipe uses the toy parameter set, which gives no security; at the
128-bit set only the set and the element length change.

Besides the crate, the recipes use three crates you add to your `Cargo.toml` as the
[tutorial](tutorial.md#before-you-start) does for `rand`: `rand` for the random number
generator, `serde_json` where they store the manager state (any serde format works), and
`merlin` for the transcripts of membership proofs.

The words are those of [Accumulators in plain words](concepts.md). The rules behind the
"watch out" lines are collected in [The rules that keep you safe](rules.md).

## Set up a manager

You need this once, when you start a new accumulator.

```rust
use kln_accumulator::{Accumulator, ManagerState, Params, ParamsSpec, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

// Real code uses a generator seeded by the operating system, such as rand::make_rng().
let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
let acc = Accumulator::new(&key);
let state = ManagerState::new(&key);

// Publish the public key and the first value.
let published = (pk.to_bytes(), acc.to_bytes());

// Keep the secret key: 96 bytes, returned in a buffer that is wiped when dropped.
let key_bytes = key.to_bytes();
let reloaded = SecretKey::try_from(key_bytes.as_slice())?;
assert_eq!(reloaded, key);
assert_eq!(reloaded.params().spec(), &ParamsSpec::TOY);
# let _ = (published, state);
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** those 96 bytes are the whole secret. Store them encrypted, readable only by the
one manager process. See [Keys](keys.md#secretkey).

## Add members and hand out witnesses

You need this each time someone joins.

```rust
# use kln_accumulator::{Accumulator, ManagerState, Params, PublicKey, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
use kln_accumulator::{Element, MembershipWitness};

// Give out elements yourself, for example from a counter. At the toy set an element is one
// byte; at the 128-bit set it is four, as in Element::try_from(&n.to_le_bytes()[..]).
let first = Element::try_from(&[1u8][..])?;
let second = Element::try_from(&[2u8][..])?;
acc.add_elements_assign(&key, &[first.clone(), second.clone()], &mut state)?;
// Save the new state before issuing (see "Save and reload the manager's state" below).

// One witness per member. Send each to its member alone, over a private channel.
let witness = MembershipWitness::new(&first, &acc, &key, &state)?;
let to_send = witness.to_bytes()?;
# assert!(MembershipWitness::from_bytes(&params, &to_send)?.verify(&first, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** `Element::hash` maps identifiers to elements, but there are only 256 elements at
the toy set and about 4.3 billion at the 128-bit set, so hashed identifiers collide after
about 16 and about 65,536 of them. Assign elements yourself and keep the mapping. See
[Elements](elements.md#element) and [Witnesses and updates](witnesses.md#membershipwitness).

## Check a witness

A holder needs this when it receives or updates a witness. A verifier needs it when a holder
shows a witness in the clear.

```rust
# use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
# let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
// The element, the public key and the current value; the answer is true or false.
assert!(witness.verify(&x, &pk, &acc));
assert!(!witness.verify(&y, &pk, &acc)); // a witness is for its own element only

// After y is deleted, y's witness fails against the current value...
let old = acc.clone();
let _messages = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
assert!(!witness_y.verify(&y, &pk, &acc));
// ...but still passes against the old one.
assert!(witness_y.verify(&y, &pk, &old));
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** always check against the current value, as the last line shows. Showing a
witness to a verifier also hands it over; to stay private, prove membership instead (below).
See [Witnesses and updates](witnesses.md#membershipwitness).

## Remove a member and publish the update

You need this when a member leaves or a credential is revoked.

```rust
# use kln_accumulator::{Accumulator, Element, Params, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
# let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
/// What the manager publishes for one batch. Your code adds a signature over these fields,
/// for example with a post-quantum signature scheme; the crate does not sign anything.
struct PublishedBatch {
    /// Counts batches from 1, so that a holder can tell when it missed one.
    sequence: u64,
    /// The new accumulator value.
    value: Vec<u8>,
    /// One update message per deletion, in order. Each names the element it deletes, so
    /// holders recover the deletions from them.
    messages: Vec<Vec<u8>>,
}

// One call adds and deletes; it returns one update message per deletion.
let messages = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

// First, save the new state durably. This uses the serde_json crate; any serde format works.
let stored = serde_json::to_string(&state)?;

// Then publish the record.
let batch = PublishedBatch {
    sequence: 1,
    value: acc.to_bytes(),
    messages: messages.iter().map(|m| m.to_bytes()).collect(),
};
# let _ = (stored, batch.sequence, batch.value, batch.messages);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The crate has no transport or storage of its own: writing the state, signing the record and
delivering it to every holder are up to you, and so are where the board lives and how
verifiers fetch the latest value. The record leaves out the batch's additions.
Holders do not need them, since additions never change a witness, and publishing them would
show everyone the new members' elements.
[Deploying it](deploying.md) shows the whole publish-and-fetch flow around this record.

**Watch out:** save before you publish. If you publish and then crash, you restart from a
state older than what everyone saw. See [Manager state and its tag](state.md#managerstate)
and the publishing list in [Misuse](misuse.md#a-checklist-for-deploying).

## Bring a holder's witness up to date

A holder needs this every time the manager publishes a batch.

```rust
# use kln_accumulator::{Accumulator, Element, Error, MembershipWitness, Params, PublicKey, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
# let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
# let messages = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
// The deletions are the elements the update messages name.
let deletions: Vec<_> = messages.iter().map(|m| m.element().clone()).collect();
// The holder's own element, the additions (which never change the result, so an empty list
// is fine), the deletions, the messages and the public key. No secret.
let current = witness.batch_update(&x, &[], &deletions, &messages, &pk)?;
// batch_update does not check its result: verify against the newly published value.
assert!(current.verify(&x, &pk, &acc));

// For the deleted member, the update is refused: this error means "you were removed".
let refused = witness_y.batch_update(&y, &[], &deletions, &messages, &pk);
assert_eq!(refused.map(drop), Err(Error::ElementDeleted));
# Ok::<(), kln_accumulator::Error>(())
```

A holder that was offline catches up over every batch it missed in one call, in the order the
manager published them:

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
# let first = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
# let second = acc.update_assign(&key, &[], &[z.clone()], &mut state)?;
// Each batch is (additions, deletions, update messages); the additions may be empty.
let missed = [(vec![], vec![y], first), (vec![], vec![z], second)];
let caught_up = witness.multi_batch_update(&x, &missed, &pk)?;
assert!(caught_up.verify(&x, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** apply every batch exactly once, in order. A skipped or repeated batch gives no
error, only a witness that does not verify, so keep track of the last batch you applied. See
[Witnesses and updates](witnesses.md#membershipwitness).

## Save and reload the manager's state

The manager needs this after every change, and when it restarts.

```rust
# use kln_accumulator::{Accumulator, Element, Params, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let (x, y, z) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?, Element::try_from(&[3u8][..])?);
# let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
# acc.remove_assign(&key, &y, &mut state)?;
use kln_accumulator::ManagerState;

// Any serde format works; the state holds the current value too.
let stored = serde_json::to_string(&state)?;

// On restart: load, check the tag with the key before reading anything, take the value.
let mut loaded: ManagerState = serde_json::from_str(&stored)?;
loaded.authenticate(&key)?;
let mut acc = loaded.current().clone();
acc.add_assign(&key, &z, &mut loaded)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

**Watch out:** never load an older copy than the last one you published from. The crate cannot
tell an old state from the current one, and an old one issues witnesses for an old value.
Store the state where an older copy cannot replace a newer one. See
[Manager state and its tag](state.md#managerstate).

## Rebuild a lost state from the public deletion log

You need this if the manager's state is lost but the key survives.

```rust
# use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let element = |n: u8| Element::try_from(&[n][..]);
# let (x, y, z) = (element(1)?, element(2)?, element(3)?);
# let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
# let mut log = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
# log.extend(acc.update_assign(&key, &[], &[z.clone()], &mut state)?);
# let issued = MembershipWitness::new(&x, &acc, &key, &state)?;
# drop(state);
use kln_accumulator::ManagerState;

// What survives: the key, every update message ever published (in any order), and your own
// list of current members.
let members = [x.clone()];
let (value, rebuilt) = ManagerState::rebuild(&key, &log, &members)?;
assert_eq!(value, acc);
// The rebuilt state issues the same witnesses as the lost one.
assert_eq!(MembershipWitness::new(&x, &value, &key, &rebuilt)?, issued);
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** the log names only deletions, so the member list is yours to keep, and a wrong
one makes the manager issue or refuse witnesses wrongly. Do not start a fresh state instead.
In the adaptive variant the members are element and handle pairs. See
[Rebuilding a lost state](state.md#rebuilding-a-lost-state).

## Send a key, value or witness over the wire, and decode it safely

You need this whenever one party sends a value to another.

```rust
# use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# let (x, y) = (Element::try_from(&[1u8][..])?, Element::try_from(&[2u8][..])?);
# let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
# let messages = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
use kln_accumulator::{Coefficient, Error, ParamsSpec, TrapdoorDistribution};

// Sender: packed bytes. The witness's bytes are in a buffer that is wiped when dropped.
let pk_bytes = pk.to_bytes();
let value_bytes = acc.to_bytes();
let witness_bytes = witness.to_bytes()?;
let message_bytes = messages[0].to_bytes();

// Receiver: decode against the parameter set it expects.
let pk = PublicKey::from_bytes(&params, &pk_bytes)?;
let acc = Accumulator::from_bytes(&params, &value_bytes)?;
let witness = MembershipWitness::from_bytes(&params, &witness_bytes)?;
let message = Coefficient::try_from(message_bytes.as_slice())?;
message.validate(&params)?;
assert!(witness.verify(&x, &pk, &acc));

// Bytes of any other set are refused, even well-formed ones.
let ternary = Arc::new(Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))?);
assert_eq!(PublicKey::from_bytes(&ternary, &pk_bytes).map(drop), Err(Error::ParameterMismatch));
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** `TryFrom<&[u8]>` and the serde forms accept any valid parameter set, the toy
set included. For bytes from anyone else, use `from_bytes` with the set you expect. See
[Serialization](serialization.md#decoding-against-the-set-you-expect).

## Prove membership without revealing the element

A holder needs this to show it is a member without saying which one. Proofs run only at the
toy sets, which give no security, so this is for study. The blocks below are compiled but not
run: a proof takes seconds and about 160 MB of memory even at the toy set.

A proof needs a **linking relation**, which ties the hidden element to something the verifier
knows, and the holder's matching secret vector `r`. The hidden lines build a placeholder from
the lattice types, as [Membership proofs](proofs.md#building-a-statement) does: a relation
made from a fixed public seed, which ties the element to nothing a verifier cares about. It
shows the API and nothing more. A real relation ties the element to a commitment inside your
credential; [Why there is a linking relation](proofs.md#why-there-is-a-linking-relation)
describes what it must do. Designing it is your protocol's job, and the crate does not do it
for you. The recipe also uses the `merlin` crate for transcripts.

```rust,no_run
// no_run: proving takes seconds and about 160 MB at the toy set.
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use kln_accumulator::lattice::{Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
# let pk = PublicKey::from(&key);
# let params = Arc::clone(key.params());
# let ring = params.ring();
# let x = Element::hash(b"x", &params);
# let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let constant = |bit: bool| {
#     let mut c = vec![Coeff::ZERO; ring.degree()];
#     c[0] = Coeff::from_u64(u64::from(bit));
#     Poly::new(c, ring)
# };
# let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
# let r = PolyVec::from(vec![constant(true)?]);
# let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
# let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
# let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
# let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
# let relation = LinkingRelation::new(a1, a2, t)?;
# let nonce = b"fresh bytes from the verifier";
use kln_accumulator::{MembershipSecret, MembershipStatement, ProofParams, prove, verify};
use merlin::Transcript;

// Both sides derive the same proof parameters from the public key.
let proof_params = ProofParams::new(&pk, None)?;
// The claim: membership under this key and this value, linked by `relation`.
let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };

// Holder: the hidden inputs, and a transcript that starts with the session's context.
let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
let mut transcript = Transcript::new(b"my-protocol presentation v1");
transcript.append_message(b"verifier nonce", nonce);
let proof = prove(&statement, &secret, &proof_params, &mut transcript, &mut rng)?;

// Verifier: the same context, its own current value; only Ok means accept.
let mut transcript = Transcript::new(b"my-protocol presentation v1");
transcript.append_message(b"verifier nonce", nonce);
verify(&statement, &proof, &proof_params, &mut transcript)?;
# Ok::<(), kln_accumulator::Error>(())
```

To verify many proofs, build a `ProofSetup` once. Without one, every call expands a
[commitment key](glossary.md#commitment-key) of about 160 MB; with one, that happens once for every proof of the same shape. The
holder's side has `prove_with` in the same way.

```rust,no_run
// no_run: proving takes seconds and about 160 MB at the toy set.
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipSecret, MembershipStatement,
#     MembershipWitness, Params, ProofParams, PublicKey, SecretKey, prove,
# };
# use kln_accumulator::lattice::{Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler};
# use merlin::Transcript;
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# let mut rng = StdRng::seed_from_u64(0);
# let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
# let pk = PublicKey::from(&key);
# let params = Arc::clone(key.params());
# let ring = params.ring();
# let x = Element::hash(b"x", &params);
# let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let constant = |bit: bool| {
#     let mut c = vec![Coeff::ZERO; ring.degree()];
#     c[0] = Coeff::from_u64(u64::from(bit));
#     Poly::new(c, ring)
# };
# let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
# let r = PolyVec::from(vec![constant(true)?]);
# let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
# let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
# let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
# let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
# let relation = LinkingRelation::new(a1, a2, t)?;
# let proof_params = ProofParams::new(&pk, None)?;
# let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
# let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
# let nonce = b"fresh bytes from the verifier".to_vec();
# let mut transcript = Transcript::new(b"my-protocol presentation v1");
# transcript.append_message(b"verifier nonce", &nonce);
# let proof = prove(&statement, &secret, &proof_params, &mut transcript, &mut rng)?;
# let incoming = vec![(proof, nonce)];
use kln_accumulator::{ProofSetup, verify_with};

// One setup per public key, proof parameters and relation shape. Keep it while proofs arrive.
let setup = ProofSetup::new(&pk, &proof_params, &relation)?;

// Here every proof is for one statement; in practice each holder brings its own, and one
// setup serves every relation of the same shape.
for (proof, nonce) in &incoming {
    let mut transcript = Transcript::new(b"my-protocol presentation v1");
    transcript.append_message(b"verifier nonce", nonce);
    verify_with(&statement, proof, &proof_params, &setup, &mut transcript)?;
}
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** put a protocol label and a fresh nonce from the verifier into the
[transcript](glossary.md#transcript), on both sides, before proving. Without them a proof can be replayed to another verifier. See
[Membership proofs](proofs.md#transcripts-what-to-bind) and
[`ProofSetup`](proofs.md#proofsetup).

## Re-add a removed member

You need the adaptive variant for this; the base variant refuses a second addition of an
element. The adaptive accumulator holds a [handle](glossary.md#handle) for each element, and an
element that comes back gets a new one.

```rust
use kln_accumulator::Params;
use kln_accumulator::adaptive::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
// The adaptive Element is a different type: a fixed 32-byte value, so it needs no parameter
// set and is copied freely.
let (x, y) = (Element::hash(b"x"), Element::hash(b"y"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x, y])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;

// Delete y. The update messages name y's handle, not y; holders pass the handles to
// batch_update as the deletions.
let messages = acc.update_assign(&key, &[], &[y], &mut state)?;
let handles: Vec<_> = messages.iter().map(|m| m.element().clone()).collect();
let witness = witness.batch_update(&x, &[], &handles, &messages, &pk)?;
assert!(witness.verify(&x, &pk, &acc));

// y comes back under a new handle, with a new witness.
acc.add_assign(&key, &y, &mut state)?;
let again = MembershipWitness::new(&y, &acc, &key, &state)?;
assert!(again.verify(&y, &pk, &acc));
# Ok::<(), kln_accumulator::Error>(())
```

**Watch out:** additions, re-additions included, are capped over the accumulator's life at the
number of possible handles, 256 at the toy set, since handles are never reused; past that, an addition is refused with
`Error::HandleSpaceExhausted`. See [The adaptive variant](adaptive.md).
