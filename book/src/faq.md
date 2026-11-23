# Frequently asked questions

## Is this safe for production?

No. It is research code that has not been audited, it is not constant time, and its membership
proofs run only at the toy settings, which give no security. Use it to learn the scheme and to
measure what it would cost. [Guarantees and their limits](security.md) lists what is
established and what is not.

## Do I need to understand lattices to use it?

No. You need the ideas on [Accumulators in plain words](concepts.md) and the rules on
[The rules that keep you safe](rules.md). The lattice types appear only if you build a
[linking relation](glossary.md#linking-relation) for a membership proof. The
[proof recipe](recipes.md#prove-membership-without-revealing-the-element) hides a placeholder
relation that binds nothing useful; designing a real one is protocol work, described in
[Why there is a linking relation](proofs.md#why-there-is-a-linking-relation). The reference
chapters use some mathematics; the [Glossary](glossary.md) says what each term is for.

## What is a witness, really?

It is a long list of small numbers that the manager computes with the secret key, for one
element and the current accumulator value. Anyone with the public key can check that it fits
both, and it is meant to be infeasible to compute one without the secret key. It is large:
34,464 bytes at the toy set and about 14.78 MiB at the 128-bit set. See
[Witnesses and updates](witnesses.md).

## Why is adding free?

Because in this scheme an addition does not change the accumulator value. The manager makes a
witness that fits the value as it already is, so nothing is published and no other holder has
to do anything. Issuing the new member's witness still costs the manager, 1.96 s at the
128-bit set. See [Why adding is free](concepts.md#why-adding-is-free).

## How big are things, and how slow?

At the 128-bit set: the public key is about 16.65 MiB, the accumulator value about
50.06 KiB, a witness about 14.78 MiB, and an update message 4 bytes. Generating a key takes
1.49 s, issuing a witness 1.96 s, verifying one 128 ms, a deletion 751 ms, and each holder's
update for one deletion 1.00 s. [Which variant and which settings](choosing.md#the-parameter-set)
has the table, and [Benchmarks and sizes](benchmarks.md) every figure.

## What happens if I lose the manager's state?

If you still have the key, the published update messages and your list of current members,
`ManagerState::rebuild` remakes the state, and the rebuilt state issues the same witnesses as
the lost one. Without the member list you cannot tell who is still a member, since the log
names only deletions. Without the key, you need a new accumulator. See
[How do I…](recipes.md#rebuild-a-lost-state-from-the-public-deletion-log).

## What if a holder is offline for a long time?

Its witness stops verifying at the first deletion it misses, but it is not lost. When the holder
comes back it applies every batch it missed, in order, in one call to `multi_batch_update`,
using only public data. It pays about 1 s per missed deletion at the 128-bit set. It needs
every batch, so the manager must keep them available. See
[How do I…](recipes.md#bring-a-holders-witness-up-to-date).

## Can a removed member come back?

Not in the base variant: the same element can never be added twice, and the code refuses it.
The [adaptive variant](adaptive.md) allows it, by giving the element a new [handle](glossary.md#handle) each
time it is added. See [How do I…](recipes.md#re-add-a-removed-member).

## What is the difference between verifying a witness and verifying a proof?

Verifying a witness means the holder shows its element and witness, and the verifier checks
them. It takes 330 µs at the toy set, but the verifier learns which member the holder is, and
could then act as that holder. Verifying a membership proof means the holder proves it has a
working witness, in a way designed to show neither it nor the element. It takes 568 ms at the toy set, a proof is
megabytes, and proofs run only at the toy sets today. See
[What a membership proof adds](concepts.md#what-a-membership-proof-adds).

## What does "post-quantum" buy me?

The scheme rests on lattice problems that are believed to resist quantum computers, which
would break RSA, elliptic curves and pairings. That matters for anything that must stay
secure for many years. It does not make this implementation safe to deploy, and "believed" is
the honest word: nobody has proved these problems hard. See
[Lattice-based and post-quantum](concepts.md#lattice-based-and-post-quantum).

## Which numbers in this book can I trust?

The sizes are exact: they are the lengths of real encodings, and the tests check many of them.
Proof sizes overstate what a tighter encoding would need, since proof values are not packed.
The timings come from one run on one machine, on 21 November 2026, while other work was
running, so treat them as rough and as a way to compare operations. Run `cargo bench` to get
your own; [Benchmarks and sizes](benchmarks.md) explains how.
