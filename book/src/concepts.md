# Accumulators in plain words

This page explains what the crate does with one everyday picture: a venue with a guest list.
Each idea appears once in **bold**, with the word the crate uses for it. There is no
mathematics here. The [Glossary](glossary.md) repeats every term in one place.

## The picture

A venue runs a private event. A manager keeps the guest list. Each guest receives a pass when
they are put on the list.

At the door, a doorkeeper checks each pass against one code posted on the door. The code is
the same length however many guests there are, and it does not list them. A pass works only
for its own guest, and only while that guest is on the list.

Adding a guest changes nothing at the door. The manager writes the guest into a private
ledger and hands them a pass. Nobody else has to do anything.

Removing a guest changes the code on the door. The removed guest's pass stops working. The
manager pins a notice to a public board: "entry 17 was removed". Every other guest reads the
notice and refreshes their own pass, without asking the manager for anything. After the
refresh their pass works against the new code. The removed guest's pass cannot be refreshed.

That is what an accumulator is: a way to represent a set by one public value, so that each
member can show membership and a removed member cannot.

## The words

Here is each part of the picture with the crate's word for it.

The **manager** is the party that keeps the list. It alone holds the **secret key**, the
stamp that makes passes (`SecretKey`). The scheme is built so that nobody without the secret
key can make a pass that works; [Guarantees and their limits](security.md) says what that
rests on.

An **element** is one entry on the list. In the base and succinct variants an element is a
short string of bits, not a name: 8 bits at the [toy settings](#settings-parameter-sets), so
only 256 elements exist, and 32 bits at the realistic settings. In the
[adaptive variant](#the-three-variants) an element is 32 bytes at every setting, and the short
string of bits is a stand-in for it, its handle. You decide which element stands for which
member, for example by giving out numbers from a counter (`Element`). An element on its own
opens nothing: without its witness it proves nothing. In the base and succinct variants it
becomes public when it is deleted, because the update message names it; in the adaptive
variant the message names its handle instead. While the member is live, keep it private all the same: anyone who sees it can link
that member's uses to each other.

The **accumulator value** is the code on the door. It stands for the whole list at once, and
anyone may see it. Its size does not depend on how many members there are (`Accumulator`).

A **witness** is a guest's pass. The manager makes one for each element and sends it
privately to that member. It works only for its own element, and only against the current
accumulator value (`MembershipWitness`).

A **holder** is the member who keeps an element and its witness. Anyone who obtains both can
act as that holder, so the holder shows them to nobody.

A **verifier** is the doorkeeper: anyone who checks a witness, or a membership proof, against
the current accumulator value.

The **public key** is what the manager publishes once, so that verifiers can check witnesses
and holders can refresh them. It is derived from the secret key, and it is meant not to let
anyone make passes (`PublicKey`).

The **manager state** is the manager's private ledger: every element ever added, which ones
were removed, how many removals have been made, and the current accumulator value. Every
operation that uses the secret key also takes the state (`ManagerState`).

An **update message** is a notice on the board. There is one for each removed element, and in
the [base variant](#the-three-variants) it is simply the removed element. Holders apply the messages to refresh
their witness. The crate's type is `Coefficient`, a name kept from the
[vb20 pairing accumulator](glossary.md#vb20-pairing-accumulator) whose API this crate mirrors.

A **parameter set** is the group of settings that sizes everything: how long an element is,
how many removals the list can ever take, how large keys and witnesses are, and how hard a
pass is to forge (`Params`). [Settings](#settings-parameter-sets) below says more.

A **membership proof** is designed to let a holder show the doorkeeper that they hold a
working pass, without showing the pass and without saying which guest they are.
[What a membership proof adds](#what-a-membership-proof-adds) below says more.

## The roles

| role | holds | does |
|---|---|---|
| manager | the secret key, the accumulator value, the manager state | generates keys, adds and removes elements, issues witnesses, publishes the value and the update messages |
| holder | its element, its witness, the public key | checks and updates its witness, proves membership |
| verifier | the public key, the current accumulator value | checks membership proofs, or witnesses shown to it |

**The manager is trusted.** The paper assumes an honest manager, a trusted issuer of the
credentials. A manager can issue a witness for any element at any
time. Nothing in the crate protects holders or verifiers from a manager that misbehaves.

## Why adding is free

In this scheme the accumulator value does not change when an element is added. So an addition
publishes nothing, and no holder has to do anything. The manager records the element in its
state and issues the element's witness: with the secret key it makes a pass that fits the
code already on the door.

Recording the addition takes 288 µs at the 128-bit set. Issuing the witness is the costly
part, 1.96 s there. [Benchmarks and sizes](benchmarks.md) has every figure.

## What a removal costs, and who pays

The crate calls a removal a *deletion*. When the manager deletes an element:

- **The value moves.** The manager publishes the new accumulator value and one update message
  for each deleted element. One deletion takes the manager 751 ms at the 128-bit set, and its
  update message is 4 bytes.
- **Every remaining holder updates.** Each applies the update messages to its own witness,
  using only the public key. It needs no secret and does not contact the manager. One
  deletion costs each holder 1.00 s at the 128-bit set, more than it cost the manager, and the
  cost grows in proportion to the number of deletions caught up on.
- **The deleted holder is out.** Its witness no longer verifies and cannot be updated.
- **A holder that misses a message falls behind.** Its witness does not verify against the new
  value until it applies every message it missed. It can catch up over several batches at
  once.
- **Everyone learns what was deleted.** The update message names the deleted element. The
  [adaptive variant](adaptive.md) names a stand-in for it instead.
- **Deletions are budgeted.** A parameter set fixes how many deletions an accumulator can ever
  take: 256 at the toy set and 2^32, about 4.3 billion, at the 128-bit set. After that you need a new accumulator,
  and every holder needs a new witness.

A verifier must check against the *current* value. A verifier that uses an old value still
lets in a holder who was deleted since.

## Positive and dynamic

The accumulator is **positive**: it shows that an element is in the set, never that an
element is not. It is **dynamic**: elements can be added and deleted over time, after the
accumulator is set up.

## What a membership proof adds

A holder can show its element and witness to a verifier, and the verifier can check them. But
that tells the verifier exactly which member the holder is, so two visits can be linked. It
also hands the verifier everything it needs to act as that holder.

A membership proof avoids both. The holder convinces the verifier that it knows an element and
a witness that work against the current value, and is designed to reveal nothing else: not the
element, not the witness. Proofs designed this way are called **zero knowledge**. For this
proof the paper describes how to set it up and refers to other work for the argument that it
holds; it gives no proof of its own, and [Guarantees and their limits](security.md#the-membership-proof)
says what else is not established.

A proof that says only "I know some member" is of little use on its own. So the proof also
ties the hidden element to something the verifier knows about, usually a credential the holder
presents in the same exchange. That tie is the **linking relation**. With it, the proof says
"the credential in front of you is not revoked", without saying which credential it is.

Two limits apply today. Proofs run only at the toy settings, which give no security, so the
crate has no setting at which you get both a secure accumulator and a proof for it. And proofs
are slow and large: at the toy set, proving takes 4.32 s on average and verifying 568 ms, and
a proof is 9,100,960 bytes. The crate can compress a proof in one to eight rounds, called
levels, each making it smaller and slower to verify: with three levels it is 852,816 bytes,
which then takes 1.83 s to verify.

## Lattice-based and post-quantum

**Lattice-based** means the security rests on problems about lattices, regular grids of points
in many dimensions, that are believed to be hard. Making a witness that works, without the
secret key, comes down to one of those problems.

**Post-quantum** means the scheme is designed to resist an attacker with a large quantum
computer. Such a computer would break the schemes most systems use today, such as RSA, elliptic
curves, and the pairings behind the vb20 pairing accumulator. Lattice problems are believed to
resist quantum computers as well.

"Believed" is the honest word. Nobody has proved these problems hard, for ordinary or quantum
computers, so the security rests on **assumptions**: problems believed, not proved, to be
hard; the same is true of all public-key cryptography in use. The crate uses no classical
cryptography anywhere. Where it needs signatures, in the adaptive variant, it uses ML-DSA-65,
a post-quantum signature standard (FIPS 204). Being post-quantum does not make this research
code safe to deploy; every limit in [Guarantees and their limits](security.md) still applies.

## Settings: parameter sets

Every key, value and witness carries its parameter set, and values of different sets refuse
to work together. You choose the set once, when you generate the key. The crate defines four.
"128-bit" in a set's name means the paper estimates that breaking it takes about 2^128
operations. This crate has not checked that estimate; treat it as the paper's claim.

| set | what it is for |
|---|---|
| toy | learning, tests and examples; runs in milliseconds; gives **no security** |
| 128-bit (`PAPER_128`) | realistic sizes and timings; "128-bit" is the paper's estimate of its strength, not checked by this crate |
| succinct toy | learning and tests of the succinct variant; no security |
| succinct 128-bit | nothing yet: only its parameters are tested, and its keys are too large to generate |

Part of the set is the **trapdoor distribution**, a choice of how the secret key is drawn. It
changes the speed of key generation and, in the succinct variant, some sizes.
[Which variant and which settings](choosing.md) helps you choose both.

## The lifecycle

```text
manager                              holder of x                     verifier
-------                              -----------                     --------
SecretKey::new            ── pk ──────────────────────────────────►  (public key)
Accumulator::new          ── genesis value ───────────────────────►  (current value)
ManagerState::new
acc.add(x)                 (value unchanged, nothing published)
MembershipWitness::new(x) ── witness ──► verify(x, pk, acc)

acc.update(.., [y])       ── new value, update messages ─────────►  (current value)
                                        batch_update(x, .., pk)
                                        verify(x, pk, new acc)

                                        prove(statement, secret)  ── proof ──► verify(statement, proof)
```

In words:

1. **Setup.** The manager chooses a parameter set, generates a secret key, derives the public
   key, and starts the manager state at the key's first value, its **genesis value**. It
   publishes the public key and that value.
2. **Add.** The manager records the element in its state. The value does not change. The
   manager issues the element's witness and sends it to the holder over a private channel.
3. **Delete.** The manager deletes an element. The value changes. The manager publishes the new
   value and one update message per deletion.
4. **Update.** Every remaining holder applies the update messages to its witness, using only
   the public key, and checks the result against the new value.
5. **Prove.** A holder proves to a verifier that it knows an element and a witness that verify
   against the current value, without revealing them.

[Your first accumulator](tutorial.md) runs steps 1 to 4 as a program.

## The three variants

| variant | where | use it when |
|---|---|---|
| base (the paper's Construction 4.1) | crate root | an element is added at most once over the life of the accumulator; it has the weaker of the two security guarantees |
| adaptive (Construction 4.2) | `adaptive` | an element must be deleted and then added again, or you want the stronger guarantee |
| succinct | `succinct` | you are studying shorter witnesses for long elements, at the cost of a very large public key |

The three share names: each has a `SecretKey`, a `PublicKey` and a `MembershipWitness` with
the same method names. [Which variant and which settings](choosing.md) compares them with
real figures.

## In short

What sets this scheme apart:

- **Adding is free.** An addition does not change the accumulator value and publishes nothing.
  The manager only records the element and issues its witness.
- **A deletion publishes one short message.** The message names the deleted element. Every
  other holder updates its witness from that message and the public key, with no secret.
- **Membership is proved in zero knowledge, by design.** A holder proves that it knows an
  element and a witness for it, in a way designed to show neither, and links the element to an
  outer credential.
- **The assumptions are lattice assumptions.** No classical cryptography is used anywhere in
  the crate.

That is the shape of credential revocation. The issuer of the credentials acts as manager and
puts a **revocation handle**, a short identifier, for each credential into the accumulator. A
credential holder shows, in zero knowledge, that its handle is still in the set. Revoking a
credential is one deletion.

## What the picture gets wrong

- **Passes are not small.** A witness is 34,464 bytes at the toy set and about 14.78 MiB at
  the 128-bit set, and the public key there is about 16.65 MiB.
- **Showing a pass gives it away.** A witness together with its element lets anyone act as its
  holder. Real presentations use a membership proof, not the pass.
- **Nobody checks the manager.** The manager can make a pass for anyone, and the crate cannot
  stop it.
- **The notices are public.** Everyone sees which entry was removed.
- **The list is small and removals are rationed.** There are only 256 possible entries at the
  toy set, and every parameter set has a lifetime budget of deletions.
- **In the base variant, a removed guest can never come back.** The same element cannot be
  added twice. The adaptive variant lifts that rule.
- **The ledger forgets nothing.** The manager state keeps every element ever added, deleted or
  not.
