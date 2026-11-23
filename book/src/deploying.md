# Deploying it

The crate computes. It does not store, send, sign or schedule anything. This page lists what a
system built around it needs: who keeps which value, what the manager publishes and in what
order, how holders and verifiers follow it, and the jobs that stay with you. Each step links to
the recipe that shows the code and to the reference chapter that has the details.

> **Research code.** Nothing on this page makes the crate fit to protect anything real. It
> has not been audited, it is not constant time, and its membership proofs run only at the toy
> settings, which give no security. Read this page as the shape of a deployment you run to
> evaluate the scheme, and as the list of what a real one would still need.
> [What this means for an integrator](security.md#what-this-means-for-an-integrator) says what
> you can and cannot run today.

The words are those of [Accumulators in plain words](concepts.md). The examples use the toy
parameter set, like the [recipes](recipes.md), and the crates `rand` and `serde_json`.

## Who holds what

| value | class | kept by | published |
|---|---|---|---|
| secret key | secret | the manager alone | never |
| [manager state](glossary.md#manager-state) | private to the manager | the manager alone | never |
| list of current members | private to the manager | the manager, apart from the state | never |
| public key | public | everyone | once, at setup |
| accumulator value | public | everyone who checks; verifiers keep the latest | after every batch that deletes |
| update messages, and the [deletion log](glossary.md#deletion-log) they make up | public | the manager keeps all of them; anyone may | after every batch that deletes |
| an element and its witness | [holder-private](glossary.md#classes-secret-holder-private-public) | each holder its own, and nobody else | never; the witness goes to its holder over a private channel |

The member list is not in the crate. It is your own record of who is a member now, kept
somewhere other than the state, because it is what you need when the state is gone.

### The secret key

It is 96 bytes: the parameter set and the 32-byte [root seed](glossary.md#root-seed). Whoever
has those bytes has the key.

- **If it leaks,** whoever has it can do everything the manager can, including issuing a
  witness that verifies for any element. The guarantee that nobody else can make a working
  witness is gone. Nothing in the crate revokes a key. Start a new accumulator under a new
  key, issue a new witness to every current member, and tell holders and verifiers to stop
  trusting the old public key.
- **If it is lost,** nobody can delete or issue any more. The witnesses already issued still
  verify against the last published value, but no member can be revoked from then on, so the
  accumulator has to be retired the same way: new key, new accumulator, new witnesses.
- **So back it up,** encrypted and readable only by the manager process, and keep every copy
  you serialize in a buffer that is wiped when dropped. See
  [Keys](keys.md#secretkey) and [Secrets and serializers](serialization.md#secrets-and-serializers).

### The manager state

The state holds no key material. It records every element ever added, which were deleted and
when, the deletion count and the current value, under a [tag](glossary.md#state-tag) that only
the key can make.

- **If it leaks,** everyone learns that history: every element ever added and when each was
  deleted. It does not tell anyone how to make a witness.
- **If it is lost,** rebuild it with `ManagerState::rebuild` from the key, the deletion log and
  your member list (in the adaptive variant, each member with its handle). The rebuilt state
  issues the same witnesses as the lost one. Do not start a fresh state instead: once a
  deletion has been made, a fresh state refuses the live value.
  See [Rebuild a lost state](recipes.md#rebuild-a-lost-state-from-the-public-deletion-log).
- **If an old copy comes back,** the crate cannot tell. The section
  [Rollback](#rollback-what-the-crate-checks-and-what-it-does-not) below says what to do about it.

### A holder's element and witness

The two together are a [bearer secret](glossary.md#bearer-secret): anyone who has both can act
as that holder.

- **If they leak,** the only remedy is to delete the element. In the base variant it can then
  never be added again; the [adaptive variant](adaptive.md) can add it again under a new
  [handle](glossary.md#handle).
- **If the witness is lost,** the manager can issue it again. In the base variant a witness
  depends only on the key, the element and the set of deletions, so the new one is the same
  witness, brought up to date. See [Witnesses and updates](witnesses.md#membershipwitness).

## The publish-and-fetch flow

### Setup

The manager generates the key, publishes the public key once, and publishes the key's first
accumulator value, its [genesis value](glossary.md#genesis-value). Holders and verifiers must
get the public key over a channel they can trust, or pin a hash of it: decoding checks that a
key is well formed, not that it is the manager's. See
[Set up a manager](recipes.md#set-up-a-manager) and
[Get the public key over an authenticated channel](rules.md#get-the-public-key-over-an-authenticated-channel).

### Adding a member

An addition does not change the value, so it publishes nothing. The manager records the
element, saves the state, then issues the witness and sends it to the new holder alone. See
[Add members and hand out witnesses](recipes.md#add-members-and-hand-out-witnesses).

### Each batch that deletes

A [batch](glossary.md#batch) is one call to `update_assign`: it adds and deletes together and
returns one update message per deletion. After it, in this order:

1. **Save the new state durably,** and the member list with it. The state holds the new value.
2. **Append the update messages to your own copy of the deletion log.**
3. **Sign the record of the batch and publish it.** The record is described in the next
   section.
4. **Then issue witnesses** for the members the batch added.

Saving comes first because a manager that publishes and then crashes restarts from a state
older than what everyone saw. See
[Save the state before you publish](rules.md#save-the-state-before-you-publish-and-never-go-back-to-an-older-copy).

### Holders

A holder remembers the sequence number of the last record it applied. When it comes online, it
fetches every later record, in order, and for each one:

1. checks the signature, and that the sequence number is exactly one more than the last it
   applied; if a record is missing, it stops and fetches again;
2. decodes the value and the messages against the parameter set it expects;
3. takes the deletions from the messages (each names the element it deletes, or in the adaptive
   variant its handle), and calls `batch_update`;
4. checks the result with `verify` against the record's value, and only then stores the new
   witness and the new sequence number.

An `Error::ElementDeleted` means the holder was removed: it stops presenting. A holder that was
away for several batches can apply them in one call with `multi_batch_update`; it costs about
1 s per missed deletion at the 128-bit set. See
[Bring a holder's witness up to date](recipes.md#bring-a-holders-witness-up-to-date).

### Verifiers

A verifier keeps the public key and the record with the highest sequence number it has
checked. It takes a new record only if the signature checks and the sequence number is higher
than the one it holds, so an old record replayed to it changes nothing. It checks every
witness or proof against that value. See
[Check witnesses and proofs against the current value](rules.md#check-witnesses-and-proofs-against-the-current-value).

### How a verifier knows it has the latest value

It cannot learn that from the crate, and a sequence number alone does not tell it either: a
sequence number shows that one record is newer than another, not that no newer one exists.
Until a verifier sees a deletion, a holder deleted in it still passes against the verifier's
older value.

How much delay you accept is your protocol's choice. A verifier can fetch the latest record
before each check. Or the manager can sign the latest sequence number together with the time at
a fixed interval, even when nothing changed, and verifiers refuse to check against a value
whose newest signature is older than the delay they accept. The crate has nothing for either.

## A record for each batch

The record below carries what holders and verifiers need, in the packed bytes they decode
against the set they expect. It has no list of deletions: in the base variant each update
message is the deleted element, so the messages are the deletions, and in the adaptive variant
the messages name handles, which are what holders pass instead. It has no list of additions
either: additions never change a witness, and publishing them would show everyone the new
members' elements.

```rust
use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// What the manager publishes for each batch. Your code signs these fields, for example with a
/// post-quantum signature scheme, and publishes the signature with them; the crate does not
/// sign anything.
struct PublishedBatch {
    /// 0 for the genesis value, then one more for every batch, so that a holder can tell when
    /// it missed one and a verifier can refuse an older record.
    sequence: u64,
    /// The accumulator value after the batch, from `Accumulator::to_bytes`.
    value: Vec<u8>,
    /// The batch's update messages, in order, from `Coefficient::to_bytes`.
    messages: Vec<Vec<u8>>,
}

// Real code uses a generator seeded by the operating system.
let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let element = |n: u8| Element::try_from(&[n][..]);
let (x, y, z) = (element(1)?, element(2)?, element(3)?);

// Stand-ins for your storage: the state, kept newest last, and the manager's copy of the log.
let mut storage: Vec<String> = Vec::new();
let mut log = Vec::new();

// Setup: record 0 is the genesis value.
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
let mut board = vec![PublishedBatch { sequence: 0, value: acc.to_bytes(), messages: vec![] }];

// Additions publish nothing: save the state, then issue.
acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
storage.push(serde_json::to_string(&state)?);
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;

// Two batches, each deleting one member: update, save, log, publish, in that order.
for (sequence, deleted) in [(1, y), (2, z)] {
    let messages = acc.update_assign(&key, &[], &[deleted], &mut state)?;
    storage.push(serde_json::to_string(&state)?);
    log.extend(messages.iter().cloned());
    board.push(PublishedBatch {
        sequence,
        value: acc.to_bytes(),
        messages: messages.iter().map(|m| m.to_bytes()).collect(),
    });
}
assert_eq!(board.len(), 3);
# let _ = (witness, log);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The holder and the verifier read the same board. The holder applies every record after the
last one it applied; the verifier keeps the newest it has seen.

```rust
# use kln_accumulator::{Accumulator, Element, ManagerState, MembershipWitness, Params, PublicKey, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# struct PublishedBatch { sequence: u64, value: Vec<u8>, messages: Vec<Vec<u8>> }
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# let element = |n: u8| Element::try_from(&[n][..]);
# let (x, y, z) = (element(1)?, element(2)?, element(3)?);
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let mut board = vec![PublishedBatch { sequence: 0, value: acc.to_bytes(), messages: vec![] }];
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# for (sequence, deleted) in [(1, y), (2, z)] {
#     let messages = acc.update_assign(&key, &[], &[deleted], &mut state)?;
#     board.push(PublishedBatch {
#         sequence,
#         value: acc.to_bytes(),
#         messages: messages.iter().map(|m| m.to_bytes()).collect(),
#     });
# }
use kln_accumulator::{Coefficient, Error};

// Holder: its witness came with record 0. Apply every later record, in order.
let (mut witness, mut last) = (witness, 0);
for record in &board {
    if record.sequence <= last {
        continue; // already applied
    }
    // Your code checks the signature here. A gap means a missed record: stop and fetch again.
    if record.sequence != last + 1 {
        break;
    }
    // Decode against the set you expect.
    let value = Accumulator::from_bytes(&params, &record.value)?;
    let messages = record
        .messages
        .iter()
        .map(|bytes| {
            let message = Coefficient::try_from(bytes.as_slice())?;
            message.validate(&params)?;
            Ok(message)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let deletions: Vec<_> = messages.iter().map(|m| m.element().clone()).collect();
    // Error::ElementDeleted here means this holder was removed.
    let updated = witness.batch_update(&x, &[], &deletions, &messages, &pk)?;
    // batch_update does not check its result: store it only once it verifies.
    if !updated.verify(&x, &pk, &value) {
        break;
    }
    (witness, last) = (updated, record.sequence);
}
assert_eq!(last, 2);

// Verifier: keeps the newest record it has checked. An older one, replayed, changes nothing.
let mut newest = (0, Accumulator::from_bytes(&params, &board[0].value)?);
for record in board.iter().rev() {
    if record.sequence > newest.0 {
        newest = (record.sequence, Accumulator::from_bytes(&params, &record.value)?);
    }
}
assert_eq!(newest.0, 2);
assert!(witness.verify(&x, &pk, &newest.1));
# Ok::<(), kln_accumulator::Error>(())
```

## Rollback: what the crate checks and what it does not

The tag on the state shows that the key's own operations wrote it. It does not show that it is
the latest copy: an older state that the key once tagged passes just as well. An older state
cannot leak the key, since it issues the same witnesses for the same deletions, but it issues
them for an older value, and a manager that continues from it publishes a second history next
to the first. See
[The manager state tag: integrity, not freshness](security.md#the-manager-state-tag-integrity-not-freshness).

Store the state where an older copy cannot replace a newer one, for example an append-only log
or a version counter kept outside the state, and never restore a backup older than your last
publication. Your own board also gives you a check on restart: a state that is current has
made as many deletions as the board has messages, and its value is the newest record's value.
In the base and succinct variants these are `state.counter()` and `state.current()`; in the
adaptive variant the same two through `state.inner()`. If they differ, the state and the
board disagree, and which way tells you what to do:

- **The state has fewer deletions.** It is behind what everyone saw: rebuild it from the log.
- **The state has more deletions.** A batch was saved (step 1 above) but its record never went
  out: publish that record before anything else. Rebuilding here would drop a deletion the
  state already made.

The check sees deletions only. Adding moves neither the counter nor the value, so a copy saved
before the latest additions passes it, and then refuses to issue witnesses for the members
added since (`Error::ElementNotPresent`). Compare such a copy against your member list too.

```rust
# use kln_accumulator::{Accumulator, Element, ManagerState, Params, SecretKey};
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
# struct PublishedBatch { sequence: u64, value: Vec<u8>, messages: Vec<Vec<u8>> }
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let element = |n: u8| Element::try_from(&[n][..]);
# let (x, y, z) = (element(1)?, element(2)?, element(3)?);
# let mut storage: Vec<String> = Vec::new();
# let mut log = Vec::new();
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let mut board = vec![PublishedBatch { sequence: 0, value: acc.to_bytes(), messages: vec![] }];
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# storage.push(serde_json::to_string(&state)?);
# for (sequence, deleted) in [(1, y), (2, z)] {
#     let messages = acc.update_assign(&key, &[], &[deleted], &mut state)?;
#     storage.push(serde_json::to_string(&state)?);
#     log.extend(messages.iter().cloned());
#     board.push(PublishedBatch {
#         sequence,
#         value: acc.to_bytes(),
#         messages: messages.iter().map(|m| m.to_bytes()).collect(),
#     });
# }
# let members = [x.clone()];
// Is a loaded state as far along as the board? Check the tag first, then compare.
let published_deletions: usize = board.iter().map(|record| record.messages.len()).sum();
let newest = board.last().ok_or("empty board")?;
let is_current = |state: &ManagerState| -> Result<bool, Box<dyn std::error::Error>> {
    state.authenticate(&key)?;
    Ok(state.counter() == u64::try_from(published_deletions)?
        && state.current().to_bytes() == newest.value)
};

// The newest stored copy passes.
let latest: ManagerState = serde_json::from_str(storage.last().ok_or("no stored state")?)?;
assert!(is_current(&latest)?);

// An older copy, restored by mistake, passes the tag check but not this one.
let restored: ManagerState = serde_json::from_str(&storage[1])?;
assert!(!is_current(&restored)?);

// Rebuild from the key, the log and the member list instead.
let (value, rebuilt) = ManagerState::rebuild(&key, &log, &members)?;
assert!(is_current(&rebuilt)?);
assert_eq!(value.to_bytes(), newest.value);
# Ok::<(), Box<dyn std::error::Error>>(())
```

This check is only as good as the board: if the board itself can be rolled back, it proves
nothing. Holders and verifiers are protected from an old record by the signature and the
sequence number, as above. See
[Misuse](misuse.md#n1-rollback-and-forks-reproduce-the-same-witnesses).

## What the crate leaves to you

- **Transport.** Publishing the public key and the records, delivering each witness to its
  holder over a private, authenticated channel, and sending proofs. At the 128-bit set the
  public key is about 16.65 MiB, sent once to every holder and verifier; a value is about
  50.06 KiB per batch; an update message is 4 bytes; a witness is about 14.78 MiB per holder.
  See [Benchmarks and sizes](benchmarks.md#sizes).
- **Durable storage.** The state, the member list and the deletion log on the manager's side;
  each witness and the last applied sequence number on each holder's side. The crate has no
  storage of its own. See [Save and reload the manager's state](recipes.md#save-and-reload-the-managers-state).
- **Ordering and sequencing.** Numbering the records, delivering every one of them, and keeping
  every batch available for holders who come back late. A skipped or repeated batch gives no
  error, only a witness that does not verify. See
  [Apply every update once, in order, and check the result](rules.md#apply-every-update-once-in-order-and-check-the-result).
- **Authenticating what you publish.** The crate signs nothing. Sign every record, with a
  post-quantum signature scheme if the rest of the system is to stay post-quantum.
- **Preventing rollback.** The crate refuses a state that was altered or that another key
  tagged, and a value that is not the state's current one. It does not refuse an older copy of
  the state, or two managers running on one key. Keeping one manager process per key, with no
  standby that can act on its own copy, is yours too. See
  [One key, one accumulator, one manager](rules.md#one-key-one-accumulator-one-manager).
- **Key backup.** The 96 bytes of the key, encrypted at rest, ideally in a hardware module or
  a secrets manager; the crate provides neither. Keep the key on one kind of machine and one
  crate version for its whole life; see
  [Keep each key on one platform and one crate version](rules.md#keep-each-key-on-one-platform-and-one-crate-version).
- **Choosing the 128-bit set.** Nothing refuses the toy sets, and nothing marks a key as a toy
  key. For anything beyond learning, generate the key under `Params::paper_128()` and compare
  the set of every key and value you load with `ParamsSpec::PAPER_128`. Membership proofs do
  not run at that set, so there a holder can only show its witness in the clear, which hands it
  to the verifier. See [Which variant and which settings](choosing.md#the-parameter-set) and
  [Do not rely on the toy settings](rules.md#do-not-rely-on-the-toy-settings).
- **The budgets.** An accumulator takes 2^32 deletions at the 128-bit set over its whole life,
  and the adaptive variant caps additions there at 2^32 as well. Plan the move to a new
  accumulator, with a new witness for every holder, before they run out. See
  [Plan for the budgets](rules.md#plan-for-the-budgets).
- **Timing.** Issuing a witness and proving are not constant time. Do not let an attacker time
  the manager or a prover. See
  [Timing](security.md#timing-what-is-and-is-not-constant-time).

The [checklist for deploying](misuse.md#a-checklist-for-deploying) in Misuse lists most of
these as lines to tick, and [Troubleshooting](troubleshooting.md) helps when something in the
flow goes wrong.
