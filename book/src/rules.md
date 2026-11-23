# The rules that keep you safe

The crate refuses many mistakes on its own: adding an element twice, deleting one that is not
there, mixing values of two parameter sets, a manager state that was tampered with. This page
is about the mistakes it cannot refuse. Each rule says what to do, why in one sentence, and
where the details are. [Misuse](misuse.md) lists every case, refused or not, with an example.

None of these rules makes the crate fit to protect anything real. It is research code; see
[the last rule](#know-what-the-crate-does-not-protect-against).

## Know what is secret and what is public

The secret key is secret. The manager state is private to the manager. A holder's witness,
its element and the vector [`r`](glossary.md#r) it uses in proofs are private to that holder. The public key,
the accumulator values, the update messages, the proofs and the parameter sets are public.

An element on its own opens nothing. In the base and succinct variants it becomes public when
it is deleted, because the update message names it; in the adaptive variant the message names
its handle instead. While the member is live, keep it private anyway: anyone who sees it
can link that member's uses to each other.

**Why:** anyone with the secret key can make witnesses, and anyone with a holder's witness and
element can act as that holder.

So store the secret key encrypted, readable only by the manager process. Send each witness
only to its holder, over a private, authenticated channel. When you serialize a secret key or
a witness yourself, wrap the output in `Zeroizing`, from the `zeroize` crate, so that it is wiped. See
[Serialization](serialization.md#secrets-and-serializers) and the security section of each
type.

## Make each key from a good seed, once

Pass `None` with a generator seeded by the operating system, or pass at least 32 bytes from
one. Never make two keys of the same parameter set from one seed.

**Why:** the key is a function of its seed and its set, so whoever guesses the seed has the key,
and two keys from one seed are the same key. The crate refuses seeds shorter than 32 bytes but
cannot tell a guessable one. See [Keys](keys.md#secretkey).

## Keep each key on one platform and one crate version

Run a key's manager on one kind of machine, with one version of this crate, for the key's whole
life. If you must move or upgrade, first check that the new setup issues byte-identical
witnesses for the same key and elements.

**Why:** a manager that issues two different witnesses for one element can give away its
secret key, and the crate gives the same witness every time only while its sampler produces
the same bits, which is assumed, not proved, across machines and crate versions; nothing in a
key records the version that made it. See
[Guarantees and their limits](security.md#what-is-not-established).

## One key, one accumulator, one manager

A key keeps exactly one accumulator. Run one manager process per key, with no standby copy
that can act on its own.

**Why:** two processes with the same key and their own copies of the state publish two
histories, and holders and verifiers can follow only one. See
[Manager state and its tag](state.md#managerstate).

## Save the state before you publish, and never go back to an older copy

After every change: write the new state durably first, then publish, then issue witnesses.
After loading a state, call `ManagerState::authenticate` with the key before reading it.
Store the state where an older copy cannot replace a newer one.

**Why:** the crate cannot tell an older state from the current one, and an older state issues
witnesses for an old value; a manager that continues from it publishes a second history, which
holders cannot follow. It cannot leak the key: witnesses do not depend on the state's history,
so an old state reproduces the same ones. See
[Manager state and its tag](state.md#managerstate).

## Publish every deletion, and keep what you need to rebuild

For every batch, publish the new accumulator value, the batch's update messages in order, and
a sequence number, all authenticated: for example signed with a
[post-quantum](concepts.md#lattice-based-and-post-quantum) signature scheme. The crate does not sign what you publish. Keep every update
message in an append-only log, and keep your own list of current members. Holders recover
the deletions from the messages. The additions never change a witness, so publishing them is
optional, and it shows everyone the new members' elements.

**Why:** holders need every batch to stay current, and act on whatever they receive. The log and
the member list, with the key, are your backup: they rebuild a lost state. See
[Rebuilding a lost state](state.md#rebuilding-a-lost-state) and the publishing list in
[Misuse](misuse.md#a-checklist-for-deploying).

## Get the public key over an authenticated channel

Holders and verifiers must obtain the public key in a way they can trust, or pin a hash of it.

**Why:** decoding checks that a key is well formed, not that it is the manager's; a holder that
accepts an attacker's key accepts the attacker's accumulator. See
[Keys](keys.md#publickey).

## Give each member its own element

Assign elements yourself, for example from a counter, and keep the mapping from member to
element. Do not rely on hashing identifiers.

**Why:** there are only 256 elements at the toy set and about 4.3 billion at the 128-bit set,
so hashed identifiers collide early, and two members who share an element share one witness and
one revocation. See [Elements](elements.md#element).

## Apply every update once, in order, and check the result

A holder applies each published batch exactly once, in the order published, and verifies its
witness against the new value afterwards.

**Why:** a skipped or repeated batch gives no error, only a witness that does not verify. An
`Error::ElementDeleted` from an update means the holder was removed: it should stop
presenting. See [Witnesses and updates](witnesses.md#membershipwitness).

## Check witnesses and proofs against the current value

A verifier builds what it checks from its own copy of the public key and of the latest
published accumulator value.

**Why:** against an old value, a member deleted since still passes. See
[Misuse](misuse.md#a-checklist-for-deploying).

## Bind every proof to its session and to its credential

Before proving, both sides put a protocol label and a fresh [nonce](glossary.md#nonce) from the
verifier into the [transcript](glossary.md#transcript), the same way. The
[linking relation](glossary.md#linking-relation) must tie the hidden element to the credential
being presented. Only an `Ok` from verification is acceptance; a proof that merely decoded has
been checked for layout only. In the [three-step form](glossary.md#one-shot-form-three-step-form), the verifier rederives the challenge from
its own transcript and compares it.

**Why:** without a nonce a proof can be replayed to another verifier; with a relation that binds
nothing, a proof says only that the prover knows *some* member. See
[Membership proofs](proofs.md#transcripts-what-to-bind) and
[Why there is a linking relation](proofs.md#why-there-is-a-linking-relation).

## Decode untrusted bytes against the set you expect

For anything that arrives from someone else, use `from_bytes(&params, bytes)` with the
parameter set you expect, not `TryFrom<&[u8]>` or a serde form.

**Why:** the other decoders accept any valid set, so a toy-set public key decodes as readily as a
128-bit one. See
[Serialization](serialization.md#decoding-against-the-set-you-expect).

## Do not rely on the toy settings

The toy sets give no security. Nothing in the code marks a key as a toy key, so compare the set
of every key you load with the one you expect.

**Why:** every operation runs at the toy sets, and nothing refuses them. See
[Misuse](misuse.md#n3-the-toy-set-is-not-refused).

## Plan for the budgets

An accumulator takes a fixed number of deletions over its whole life: 256 at the toy set, 2^32
at the 128-bit set. The adaptive variant also caps additions, re-additions included, at the
number of possible [handles](glossary.md#handle), since every addition takes a new one and
handles are never reused: 256 at the toy set, 2^32 at the 128-bit set. Plan how you will move to a new accumulator before they run out.

**Why:** the crate refuses further deletions or additions once a budget is spent, and a new
accumulator means a new witness for every holder. See
[Parameter sets](parameters.md#bounds).

## Know what the crate does not protect against

- **A dishonest manager.** The manager is trusted. It can issue a witness for any element,
  and nothing in the crate protects holders or verifiers from it.
- **Timing.** The crate is not constant time. Issuing a witness and proving take time, and touch
  memory, in ways that depend on secrets. Do not let an attacker time the manager or a prover,
  for example on a shared machine.
- **Reading memory.** Wiping secrets on drop shortens how long they stay in memory. It is no
  defence against an attacker who can read the process's memory while a secret is in use.
- **Who was removed.** Update messages name the deleted element, in the adaptive variant a
  handle for it, so everyone learns what was revoked.
- **Anything unaudited.** The code has not been audited, and some of its foundations are
  measured rather than proved. Membership proofs run only at the toy sets.

[Guarantees and their limits](security.md#what-is-not-established) has the full list of what
is not established.

## Under the hood

Two further responsibilities arise only if you use the lattice types of
`kln_accumulator::lattice` directly, which the rest of this part never does: validating a
decoded polynomial before you use it, and never calling the preimage samplers twice with two
seeds for one target. [The lattice building blocks](lattice.md) and
[Misuse](misuse.md#parameter-sets-and-encodings) cover them.
