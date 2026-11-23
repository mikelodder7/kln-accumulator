# Glossary

Every term this book uses, in alphabetical order, with what it is for and where it is
explained. Names in `code` are the crate's types and functions. Where a reference chapter
writes a term as a symbol, the entry gives the symbol so that you can recognise it.

## Numbers

### 128-bit set

`ParamsSpec::PAPER_128`, built by `Params::paper_128()`: the parameter set with the shape of
the paper's 128-bit parameters, for realistic sizes and timings. "128-bit" is the paper's
estimate of its strength, not checked by this crate. See [Which variant and which settings](choosing.md#the-parameter-set).

## A

### Accumulator

A way to represent a set by one public value, so that each member can show membership and a
removed member cannot. See [Accumulators in plain words](concepts.md).

### Accumulator value

The one public value that stands for the current set, and that every witness is checked
against (`Accumulator`). It changes when an element is deleted, not when one is added. See
[Elements and the accumulator value](elements.md#accumulator).

### Adaptive variant

The variant in `kln_accumulator::adaptive`, the paper's Construction 4.2. A deleted element can
be added again, and its security proof lets the attacker pick its target at any time. See
[The adaptive variant](adaptive.md).

### Assumption

A problem that is believed, not proved, to be hard, on which a security proof rests. This crate's
are lattice problems with names such as Module-SIS and Module-LWE, plus the security of SHAKE256
and, in the adaptive variant, of ML-DSA-65. See [Guarantees and their limits](security.md).

## B

### Base variant

The variant at the crate root, the paper's Construction 4.1. An element can be added at most
once over the life of the accumulator. It is the only variant with membership proofs. See
[The three variants](concepts.md#the-three-variants).

### Batch

One call to the manager's `update`: a list of additions and a list of deletions, made together,
with the update messages it returns. Only its deletions change holders' witnesses. Holders
apply batches in the order they were published.
See [Witnesses and updates](witnesses.md).

### Bearer secret

A secret whose holder is whoever has it. A witness together with its element is one: anyone who
has both can prove membership as that holder. See
[Witnesses and updates](witnesses.md#membershipwitness).

### Bounds

The size limits that a parameter set derives, such as the norm bound a witness must stay under
(`Bounds`). You read them; you never set them. See
[Parameter sets and trapdoor distributions](parameters.md#bounds).

## C

### Challenge

The random value a proof answers. It is drawn from the transcript, which is what ties a proof
to one session (`Challenge`). See [Membership proofs](proofs.md#challenge).

### Classes: secret, holder-private, public

The three labels the book gives every type: secret (owner only), holder-private (private to
one holder, used in proofs) and public (may be published). See
[Introduction](introduction.md#how-the-reference-chapters-are-organised).

### Coefficient

The crate's name for an update message, kept from the vb20 pairing accumulator. In the reference
chapters on lattices, "coefficient" also means one of the numbers inside a polynomial. See
[Elements and the accumulator value](elements.md#coefficient).

### Collision-freeness

The paper's name for the main security property: without the secret key, nobody can make a
witness that verifies for an element that is not in the set. See
[Guarantees and their limits](security.md#the-accumulator-soundness).

### Commitment key

A large public key, about 160 MB at the toy set, that membership proofs use. Both sides expand
it from the proof parameters, so it is never sent. See [Membership proofs](proofs.md#proofparams).

### Compression levels

How many rounds of compression a membership proof gets, from one to eight
(`CompressionLevels`). More levels give a smaller proof that takes longer to verify. The
compression is the LaBRADOR proof system. See [Membership proofs](proofs.md#compression).

### Constant time

Code whose running time and memory access do not depend on secrets, so that timing it reveals
nothing. Only a few steps of this crate are written that way. See
[Guarantees and their limits](security.md#timing-what-is-and-is-not-constant-time).

### Construction 4.1, Construction 4.2

The paper's names for the base and the adaptive variant. See
[The three variants](concepts.md#the-three-variants).

### Credential

What an accumulator usually serves in practice: a document an issuer gives a holder, which can
later be revoked. The accumulator holds a revocation handle for each credential. See
[In short](concepts.md#in-short).

## D

### Delete, deletion

Removing an element from the accumulator. It moves the accumulator value and publishes one
update message. See [What a removal costs](concepts.md#what-a-removal-costs-and-who-pays).

### Deletion bound

The number of deletions an accumulator can take over its whole life: 256 at the toy set, 2^32 at
the 128-bit set. The reference chapters write it `γ`. See
[Parameter sets and trapdoor distributions](parameters.md#bounds).

### Deletion log

Every update message the manager has published, kept in an append-only store. With the key and
the member list it rebuilds a lost manager state. See
[Rebuilding a lost state](state.md#rebuilding-a-lost-state).

### Delta

The correction a run of deletions makes to one holder's witness, computed separately so that it
can be added later (`Delta`). It depends on the holder's element, so it stays private. See
[Witnesses and updates](witnesses.md#delta).

### Dynamic

Elements can be added and deleted after the accumulator is set up. See
[Positive and dynamic](concepts.md#positive-and-dynamic).

## E

### Element

One entry of the set (`Element`). In the base and succinct variants it is a short string of
bits, 8 at the toy set and 32 at the 128-bit set. In the adaptive variant it is 32 bytes at
every set, and the short string of bits is its handle. You choose which element stands for
which member. It opens nothing without its witness, and in the base and succinct variants it
becomes public when it is deleted; keep it private while the member is live, so
that the member's uses cannot be linked. See
[Elements and the accumulator value](elements.md#element).

### Element length

How many bits an element has in the base and succinct variants, or a handle has in the
adaptive variant, fixed by the parameter set. It decides how many elements, or handles, exist
and how large keys and witnesses are. The reference chapters write it `ℓ`. See
[Parameter sets and trapdoor distributions](parameters.md#the-defined-sets).

### ePrint 2025/1099

The research paper that defines the scheme this crate implements; the book calls it "the
paper". See [References](references.md#the-scheme).

### Epoch

A number the manager state records for each element. In the base and succinct variants it
counts deletions, to date events: an element added before any deletion has epoch 0, and it is
a record of history only, on which no witness depends. In the adaptive variant it is the
handle counter: for a present element, the index its current handle was drawn at; for a
deleted one, the index its next handle starts from. See
[Manager state and its tag](state.md#what-the-state-records) and
[The adaptive variant](adaptive.md#adaptivemanagerstate).

### Error

The crate's one error type (`Error`). Every fallible operation returns it instead of panicking,
and most variants name a misuse. See [Errors](errors.md).

## F

### Fiat–Shamir

The standard way to turn an interactive proof into one message, by drawing the challenge from a
transcript. The crate uses it; a concrete security bound for that step is cited, not derived.
See [Guarantees and their limits](security.md#what-is-not-established).

## G

### Gadget

A fixed public matrix that lets the scheme break large numbers into small digits. It is part of
how witnesses are checked and updated, and you never handle it directly. See
[The lattice building blocks](lattice.md#gadget).

### Gaussian trapdoor

The default way of drawing the trapdoor. It makes the public key provably close to random, so
it adds no assumption, at the cost of slower key generation. See
[Which variant and which settings](choosing.md#the-trapdoor-distribution).

### Genesis value

The first accumulator value of a key, derived from the key itself. Every witness is made for it
and then corrected for the deletions since. See
[Keys](keys.md#how-a-key-is-made).

## H

### Handle

In the adaptive variant, a pseudorandom stand-in for an element, as long as the set's element
length: 8 bits at the toy set, 32 at the 128-bit set. The accumulator inside holds handles,
update messages name handles, and an element that is added again gets a new one. Handles are
never reused, so additions, re-additions included, are capped at the number of possible
handles: 256 at the toy set, 2^32 at the 128-bit set. See
[The adaptive variant](adaptive.md).

### Holder

The member who keeps an element and its witness, updates the witness, and proves membership.
See [The roles](concepts.md#the-roles).

## I

### Issue

What the manager does to make a witness, with `MembershipWitness::new`, the only operation that
makes one. It needs the secret key and the manager state. See
[Witnesses and updates](witnesses.md#membershipwitness).

## L

### LaBRADOR

The proof system the crate uses to compress membership proofs. See
[Membership proofs](proofs.md#compression).

### Lattice

A regular grid of points in many dimensions. Some problems about lattices are believed hard,
even for quantum computers, and the scheme's security rests on them. See
[Lattice-based and post-quantum](concepts.md#lattice-based-and-post-quantum).

### Lattice building blocks

The types underneath the accumulator, in `kln_accumulator::lattice`: polynomials (`Poly`),
vectors and matrices of them (`PolyVec`, `PolyMatrix`), seeds, samplers and the trapdoor. You
meet them only when you build a linking relation or work on the crate. See
[The lattice building blocks](lattice.md).

### Linking relation

The part of a membership proof that ties the hidden element to something the verifier knows,
usually a commitment inside a credential (`LinkingRelation`). Without it a proof says only that
the prover knows *some* member. See
[Membership proofs](proofs.md#why-there-is-a-linking-relation).

### Linking opening

The linking relation together with the holder's secret vector `r` that satisfies it, as the
prover passes them (`LinkingOpening`). See [Membership proofs](proofs.md#linkingopening).

### LnpParameters

The sizes and widths a membership proof runs with, derived from the parameter set
(`LnpParameters`). You rarely touch them. See [Membership proofs](proofs.md#lnpparameters).

## M

### Manager

The party that holds the secret key, adds and deletes elements, issues witnesses and publishes
values. It is trusted. See [The roles](concepts.md#the-roles).

### Manager state

The manager's private ledger: every element ever added, which were deleted, the number of
deletions and the current value, with a tag that binds it to the key (`ManagerState`). See
[Manager state and its tag](state.md).

### Membership proof

A proof that the holder has an element and a witness that work against the current value,
designed to reveal neither. It runs only at the toy sets today. See [Membership proofs](proofs.md).

### Membership statement, membership secret

The public and the private inputs of a proof. The statement is the public key, the accumulator
value and the linking relation (`MembershipStatement`); the secret is the element, the witness
and `r` (`MembershipSecret`). See [Membership proofs](proofs.md#membershipstatement).

### Membership witness

The full name of a witness (`MembershipWitness`). See [Witness](#witness).

### ML-DSA-65

A post-quantum signature standard (FIPS 204). The adaptive variant signs each element with its
handle using it. See [The adaptive variant](adaptive.md).

### Module-LWE, Module-SIS

The names of the lattice problems the security proofs assume to be hard. See
[Guarantees and their limits](security.md#the-accumulator-soundness).

## N

### Nonce

A fresh random value the verifier supplies for one session and both sides put into the
transcript, so that a proof cannot be replayed elsewhere. See
[Membership proofs](proofs.md#transcripts-what-to-bind).

### Norm bound

The limit on how large a witness's numbers may be. A witness verifies only if it fits the
public equation and stays under this bound. The reference chapters write it `β`. See
[Parameter sets and trapdoor distributions](parameters.md#bounds).

### NTT

A fast way to multiply polynomials, used inside the arithmetic (`NttMatrix`). See
[The lattice building blocks](lattice.md#nttmatrix).

## O

### One-shot form, three-step form

The two ways to make a proof. One-shot is a single `prove` and `verify`. Three-step
(`MembershipProofCommitting`, `Challenge`, `MembershipProof::finalize`) fits a proof into a
larger presentation that shares one challenge; there the verifier must rederive the challenge
and compare it. See [Membership proofs](proofs.md#two-forms).

## P

### Parameter set

The settings that size everything: element length, deletion bound, key and witness sizes, and
the trapdoor distribution (`Params`, described by `ParamsSpec`). Every value carries its set.
See [Parameter sets and trapdoor distributions](parameters.md).

### Positive

The accumulator shows membership only, never non-membership. See
[Positive and dynamic](concepts.md#positive-and-dynamic).

### Post-quantum

Designed to resist an attacker with a large quantum computer. See
[Lattice-based and post-quantum](concepts.md#lattice-based-and-post-quantum).

### Preimage, preimage sampler

A preimage is a short vector that a public matrix maps to a given target; a witness is one. The
preimage sampler makes them, using the trapdoor. Two different preimages for one target would
leak the trapdoor, which the crate's design prevents. See
[Parameter sets and trapdoor distributions](parameters.md#what-the-samplers-do-under-each-distribution).

### PRF

A pseudorandom function: a keyed function whose outputs look random to anyone without the key.
The crate uses SHAKE256 as one, to fix the randomness of each witness. See
[Guarantees and their limits](security.md#construction-41).

### Proof parameters

A 32-byte public seed, derived from the public key and an optional input, from which both sides
expand the commitment key (`ProofParams`). See [Membership proofs](proofs.md#proofparams).

### ProofSetup

The commitment key and proof sizes, derived once and reused, so that verifying many proofs does
not expand the 160 MB key each time. It is passed to the `_with` functions such as
`verify_with`. See [Membership proofs](proofs.md#proofsetup).

### Public key

What the manager publishes once, so that holders can update witnesses and anyone can check them
(`PublicKey`). See [Keys](keys.md#publickey).

## R

### `r`

The holder's secret binary vector in a membership proof. With the element it satisfies the
linking relation, typically as the randomness of a commitment. See
[Membership proofs](proofs.md#what-is-proved).

### Rebuild

Remaking a lost manager state from the key, the deletion log and the member list, with
`ManagerState::rebuild`. See [Rebuilding a lost state](state.md#rebuilding-a-lost-state).

### Rejection sampling

The reason proving time varies: the prover throws away attempts that could leak its secrets
and starts again; about 20 attempts are expected. See [Membership proofs](proofs.md#two-forms).

### Replacement-free

The base variant's rule that an element, once added, is never added again, not even after
deletion. Its security proof assumes it, and the code enforces it. See
[Guarantees and their limits](security.md#construction-41).

### Revocation handle

The short identifier a credential issuer puts into the accumulator for each credential. In this
crate it is an element. See [In short](concepts.md#in-short).

### Ring and ring degree

The numbers the scheme computes with are polynomials of a fixed length; together they form a
ring. The ring degree is that length: 64 at the toy sets and 4096 at the 128-bit sets.
Membership proofs run only at degree 64. See
[Parameter sets and trapdoor distributions](parameters.md#the-defined-sets).

### Rollback

Going back to an older copy of the manager state. The crate cannot detect it. It makes the manager
publish a second history; it cannot leak the key, because witnesses do not depend on the
state's history, so an old state reproduces the same ones. See
[Misuse](misuse.md#n1-rollback-and-forks-reproduce-the-same-witnesses).

### Root seed

The 32 secret bytes from which, together with the parameter set, the whole key is derived. See
[Keys](keys.md#how-a-key-is-made).

## S

### Secret key

What the manager alone holds: the trapdoor and the keys derived with it, encoded in 96 bytes
(`SecretKey`). See [Keys](keys.md#secretkey).

### Selective and adaptive security

Two strengths of security proof. Selective: the attacker must name the element it will attack
before it sees the public key, as for the base variant. Adaptive: it may choose at any time, as
for the adaptive variant. See [Guarantees and their limits](security.md#the-accumulator-soundness).

### SHAKE256

A standard hash function (SHA-3 family). The crate derives keys, witness randomness and the
state tag from it. See [Guarantees and their limits](security.md).

### State tag

A keyed checksum inside the manager state that the key verifies before every use, so that a
state altered in storage, or made by another key, is refused. It does not detect an older
copy. See [Manager state and its tag](state.md#managerstate).

### Subring map

A tested piece that would carry a 128-bit statement into the proof's smaller ring; it is not yet
wired into the proofs (`SubringMap`). See [Membership proofs](proofs.md#subringmap).

### Succinct variant

The variant in `kln_accumulator::succinct`, whose witnesses do not grow with the element length,
at the cost of a very large public key. It is for study only today. See
[The succinct variant](succinct.md).

## T

### Ternary trapdoor

The other way of drawing the trapdoor. Key generation is faster, and succinct sizes are smaller,
at the price of one more assumption. See
[Which variant and which settings](choosing.md#the-trapdoor-distribution).

### Toy set

`ParamsSpec::TOY` and `ParamsSpec::SUCCINCT_TOY`: small parameter sets for learning and tests.
They give no security. See [Which variant and which settings](choosing.md#the-parameter-set).

### Transcript

A running record, from the `merlin` crate, that prover and verifier feed with the same context.
The proof's challenge is drawn from it, which binds the proof to that context. See
[Membership proofs](proofs.md#transcripts-what-to-bind).

### Trapdoor

The secret part of the key that lets the manager make witnesses (`Trapdoor`, inside
`SecretKey`). Without it, making a witness comes down to a hard lattice problem. See
[The lattice building blocks](lattice.md#trapdoor).

### Trapdoor distribution

How the trapdoor is drawn: `Gaussian` (the default) or `Ternary` (`TrapdoorDistribution`). It is
part of the parameter set. See
[Parameter sets and trapdoor distributions](parameters.md#trapdoordistribution).

## U

### Update message

What the manager publishes for each deletion: the deleted element, or in the adaptive variant
its handle (`Coefficient`). Holders apply it to their witnesses. See
[Elements and the accumulator value](elements.md#coefficient).

### Update a witness

What a holder does after each batch, from public data alone: `batch_update`,
`multi_batch_update`, `update`, or `evaluate_delta` with `apply_delta`. See
[Witnesses and updates](witnesses.md#the-life-of-a-witness).

## V

### vb20 pairing accumulator

An earlier, pairing-based accumulator whose type and method names this crate mirrors. Pairings
are not post-quantum. See
[Correspondence with the vb20 pairing accumulator](vb20.md).

### Verifier

Anyone who checks a witness or a membership proof against the public key and the current value.
See [The roles](concepts.md#the-roles).

### Verify

For a witness, `MembershipWitness::verify`, which answers `true` or `false`. For a proof,
`verify` or `verify_with`, where only `Ok` means accept. See
[Witnesses and updates](witnesses.md#membershipwitness) and
[Membership proofs](proofs.md#prove-and-verify).

## W

### Wiping

Overwriting a secret in memory when it is dropped, so that it does not linger. It shortens how
long a secret stays in memory; it does not stop an attacker who can read the memory while the
secret is in use. See [Guarantees and their limits](security.md#secret-handling).

### Witness

A holder's proof of membership: a long list of small numbers that fits its element and the
current accumulator value, and that is meant to be infeasible to make without the secret key. It is 34,464 bytes at the toy
set and about 14.78 MiB at the 128-bit set. See [Witnesses and updates](witnesses.md).

## Z

### Zero knowledge

A proof is zero knowledge when it reveals nothing beyond the fact being proved. Membership
proofs are designed to be, so that the verifier learns neither the element nor the witness;
the paper refers to other work for the argument and gives no proof of its own. See
[What a membership proof adds](concepts.md#what-a-membership-proof-adds).
