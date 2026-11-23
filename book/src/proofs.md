# Membership proofs

> **In short.** A [membership proof](glossary.md#membership-proof) lets a holder convince a
> verifier that it holds a working witness, without showing the witness or saying which element
> it is for. A [linking relation](glossary.md#linking-relation) ties the hidden element to the
> credential being presented. Proofs run only at the toy sets, which give no security, and they
> are slow and large.
>
> **Read this when** you make or check a proof, or bind one to a session and a credential.
>
> **New here?** Read [What a membership proof adds](concepts.md#what-a-membership-proof-adds)
> and the rule
> [Bind every proof to its session and to its credential](rules.md#bind-every-proof-to-its-session-and-to-its-credential)
> first. To make and check a proof, read this chapter from here to [Costs](#costs), then
> [`prove` and `verify`](#prove-and-verify). The sections from [`Challenge`](#challenge) to
> [`CompressedMembershipProof`](#compressedmembershipproof) cover the three-step form and
> compression; read them when you use those. The last two, [`LnpParameters`](#lnpparameters)
> and [`SubringMap`](#subringmap), describe internals. They are advanced, and using the crate
> does not require them.

A witness shows membership to anyone who sees it, but showing it also shows the element. In a
[credential](glossary.md#credential) system that would make every presentation linkable. A membership proof lets the
holder convince a verifier that it *knows* an element and a witness that verify against the
current accumulator value, without revealing either.

> Membership proofs are implemented only where the accumulator ring has degree 64, that is at
> the toy parameter sets, which give no security. Treat this chapter as a description of the
> protocol and its API, not of something you can deploy.

## What is proved

The holder proves knowledge of an element `x`, a binary vector [`r`](glossary.md#r) and a witness `s_x` such
that

- `s_x` is a valid witness for `x` under the public key and the accumulator value, and
- `A₁·x + A₂·r = t`, the **linking relation**.

The proof system is the commit-and-prove argument of Appendix D.2 of ePrint 2025/1099, made
non-interactive over merlin [transcripts](glossary.md#transcript). It can be compressed with [LaBRADOR](glossary.md#labrador) (ePrint
2022/1341), as Appendix D.3 describes.

### Why there is a linking relation

A proof that says only "I know some member of the set" is of little use on its own: it does
not say that the member is *yours*. In a credential presentation the element is an attribute
of the credential, and the same presentation proves other things about that credential. The
linking relation ties the two together. `A₁`, `A₂` and `t` are public; `t` is typically a
commitment to `x` with randomness `r` that the outer credential proof also speaks about. The
membership proof then shows that the committed value is in the accumulator.

The bits of `x` enter the relation as constant polynomials, and `r` must be binary. A relation
with no rows gives a proof of bare membership.

Choosing `A₁`, `A₂` so that `t` binds and hides `x` is the outer protocol's job. The crate
checks the relation; it does not judge it.

## Building a statement

The examples in this chapter share a setup: a manager with one member `x`, the holder's
witness, and a linking relation with one row and a one-entry `r`. Here it is in full. Later
examples hide it.

```rust
use kln_accumulator::{
    Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
    SecretKey,
};
use kln_accumulator::lattice::{Coeff, DomainLabel, Poly, PolyVec, Seed, Shape, UniformSampler};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;
let pk = PublicKey::from(&key);
let params = Arc::clone(key.params());
let ring = params.ring();
let x = Element::hash(b"x", &params);
let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
assert!(witness.verify(&x, &pk, &acc));

// A bit as a constant polynomial.
let constant = |bit: bool| {
    let mut c = vec![Coeff::ZERO; ring.degree()];
    c[0] = Coeff::from_u64(u64::from(bit));
    Poly::new(c, ring)
};
// x's bits, and the holder's binary vector r.
let bits = x.to_bits(&params)?.as_slice().iter().map(|&b| constant(b)).collect::<Result<PolyVec, _>>()?;
let r = PolyVec::from(vec![constant(true)?]);

// Public A₁ and A₂ from a public seed, and t = A₁·x + A₂·r computed by the holder.
let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"link"[..]));
let a1 = sampler.matrix(Shape { rows: 1, cols: bits.len() }, ring);
let a2 = sampler.matrix(Shape { rows: 1, cols: r.len() }, ring);
let t = a1.mul_vec(&bits, ring)?.add(&a2.mul_vec(&r, ring)?, ring)?;
let relation = LinkingRelation::new(a1, a2, t)?;

// Public proof parameters, the same for prover and verifier.
let proof_params = ProofParams::new(&pk, None)?;
assert_eq!(relation.a1().shape(), Shape { rows: 1, cols: 8 });
# let _ = proof_params;
# Ok::<(), kln_accumulator::Error>(())
```

## Two forms

**One-shot.** `prove` and `verify` each take a merlin transcript. The prover commits, absorbs
the statement and its commitment into the transcript, draws the [challenge](glossary.md#challenge) from it and
responds. The verifier does the same on a transcript in the same state.

```rust,no_run
// no_run: proving takes 2 to 12 s and about 160 MB at the toy set. The same call runs, with
// its refusals, in the chapter on misuse.
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::{MembershipSecret, MembershipStatement, prove, verify};
use merlin::Transcript;

let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
let secret = MembershipSecret { element: &x, witness: &witness, r: &r };

// Both sides put the session context into the transcript first.
let mut prover = Transcript::new(b"my-protocol presentation v1");
prover.append_message(b"verifier nonce", b"fresh bytes from the verifier");
let proof = prove(&statement, &secret, &proof_params, &mut prover, &mut rng)?;

let mut verifier = Transcript::new(b"my-protocol presentation v1");
verifier.append_message(b"verifier nonce", b"fresh bytes from the verifier");
verify(&statement, &proof, &proof_params, &mut verifier)?;
# Ok::<(), kln_accumulator::Error>(())
```

**Three-step.** This is the shape of the vb20 pairing accumulator's proof API, for use inside
a larger presentation that has one shared challenge.

```text
MembershipProofCommitting::new(…)            prover: commit to (x, r, witness)
  .get_bytes_for_challenge(&mut transcript)  prover: absorb the statement digest and t_A
Challenge::from_transcript(label, &mut transcript)
  .gen_proof(&challenge)                     prover: run the protocol, restarting on aborts
MembershipProof::finalize(…, &challenge, …)  verifier: every check
  .get_bytes_for_challenge(&mut transcript)  verifier: rederive the challenge and compare
```

The prover uses rejection sampling, which makes it restart with fresh masks. A restart
invalidates the prover's first message, so the outer transcript sees only the part that stays
fixed across restarts: the statement digest and the commitment `t_A`. The restarts happen
inside `gen_proof`, on an inner transcript seeded by the outer challenge.

The example below runs the whole three-step flow, then compresses the proof. It is one of the
two examples in this book that really proves, so it costs one proof and several
verifications.

```rust
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::{
    Challenge, CompressedMembershipProof, CompressionLevels, LinkingOpening, MembershipProof,
    MembershipProofCommitting, MembershipStatement,
};
use merlin::Transcript;

// Prover, step 1: commit.
let committing = MembershipProofCommitting::new(
    &x,
    &witness,
    &proof_params,
    &pk,
    &acc,
    LinkingOpening { relation: &relation, r: &r },
    &mut rng,
)?;

// Prover, step 2: the outer transcript absorbs the session context, then this proof's part,
// and the challenge is drawn from it.
let mut transcript = Transcript::new(b"my-protocol presentation v1");
transcript.append_message(b"verifier nonce", b"fresh bytes from the verifier");
committing.get_bytes_for_challenge(&mut transcript);
let challenge = Challenge::from_transcript(b"challenge", &mut transcript);

// Prover, step 3: respond.
let proof: MembershipProof = committing.gen_proof(&challenge)?;
drop(committing); // the prover's secrets are wiped here

// The proof travels as bytes. With a one-entry r it is 9,100,960 bytes at the toy set.
let wire = proof.to_bytes();
assert_eq!(wire.len(), 9_100_960);
let received = MembershipProof::try_from(wire.as_slice())?;

// Verifier: run every check for the claimed challenge...
let finalized = received.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
// ...then rederive the challenge from its own transcript and compare. Without this
// comparison the proof is not bound to the session.
let mut verifier = Transcript::new(b"my-protocol presentation v1");
verifier.append_message(b"verifier nonce", b"fresh bytes from the verifier");
finalized.get_bytes_for_challenge(&mut verifier);
assert_eq!(Challenge::from_transcript(b"challenge", &mut verifier), challenge);

// A verifier with another nonce derives another challenge, and the comparison fails.
let mut stale = Transcript::new(b"my-protocol presentation v1");
stale.append_message(b"verifier nonce", b"a different session");
finalized.get_bytes_for_challenge(&mut stale);
assert_ne!(Challenge::from_transcript(b"challenge", &mut stale), challenge);

// The proof does not verify for a challenge it was not made for.
let other = Challenge::from([7u8; 64]);
assert!(matches!(
    received.finalize(&acc, &proof_params, &pk, &other, &relation),
    Err(kln_accumulator::Error::ProofRejected)
));

// Compression: the responses are public, so anyone holding the proof can compress it.
let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
let levels = CompressionLevels::try_from(1)?;
let compressed: CompressedMembershipProof =
    received.compress(&statement, &proof_params, &challenge, levels)?;
assert_eq!(compressed.levels(), 1);
let compressed_wire = Vec::from(&compressed);
assert_eq!(compressed_wire.len(), 2_172_640);
let compressed = CompressedMembershipProof::try_from(compressed_wire.as_slice())?;
// It verifies the same way and yields the same transcript contribution.
let finalized_compressed = compressed.finalize(&acc, &proof_params, &pk, &challenge, &relation)?;
assert_eq!(finalized_compressed, finalized);
# Ok::<(), kln_accumulator::Error>(())
```

## Transcripts: what to bind

A proof is valid for exactly one challenge, and the challenge is whatever the transcript
makes it. The crate puts the *statement* into the transcript for you: a digest of the proof
parameters, the public key, the accumulator value and the linking relation, and the
commitment `t_A`. Everything else is yours to put in, before the proof's part:

- a protocol label and version, so that proofs of one protocol are not accepted in another;
- a verifier [nonce](glossary.md#nonce) or session identifier, so that a proof cannot be replayed to another
  verifier or at another time;
- the rest of the presentation, if this proof is one part of it.

The prover and the verifier must feed their transcripts identically. A verifier whose
transcript differs in any byte rejects the proof.

## Compression

An uncompressed proof is large because of its responses. Compression replaces the two large
responses by a LaBRADOR proof that responses satisfying the verifier's equations exist. A
compressed proof has one to eight LaBRADOR levels; more levels give a smaller proof.
At the toy set a proof for a one-row relation with a one-entry `r`, as in the example above,
is 9,100,960 bytes uncompressed and 2,172,640, 1,117,976 and 852,816 bytes at one, two and
three levels. The uncompressed size grows slightly with the relation. Proof values
are stored at 24 bytes per coefficient and are not bit-packed, so all of these overstate what
a packed encoding would need.

There are two ways to get a compressed proof: `MembershipProofCommitting::gen_compressed_proof`
makes one directly, and `MembershipProof::compress` turns an existing proof into one. The
second needs no secret.

## Costs

At the toy set with an optimised build, proving takes 2 to 12 s (about 20 [rejection-sampling](glossary.md#rejection-sampling)
attempts are expected), verifying 0.6 s, and verifying a compressed proof 1.3 to 1.8 s. Proving and
verifying each expand a [commitment key](glossary.md#commitment-key) of about 160 MB, unless they are given a `ProofSetup`,
which expands it once for every call that uses it (see below). See
[Benchmarks and sizes](benchmarks.md) for measurements.

## `ProofParams`

**What it is**

The public parameters of membership proofs: a 32-byte seed from which the proof's commitment
key is expanded. It is derived from the accumulator's public key and an optional entropy
input. It is `Copy`.

**Why it exists**

Prover and verifier must use the same commitment key, and that key is about 160 MB, far too
large to ship. Deriving it from a seed that both sides can compute means nothing has to be
exchanged. The optional entropy lets a deployment separate its proofs from another
deployment's under the same public key.

**How to use it**

```rust
use kln_accumulator::{Params, ProofParams, PublicKey, SecretKey};
use merlin::Transcript;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let pk = PublicKey::from(&key);

// A function of the public key and the entropy input.
let params = ProofParams::new(&pk, Some(b"deployment 1"))?;
assert_eq!(params, ProofParams::new(&pk, Some(b"deployment 1"))?);
assert_ne!(params, ProofParams::new(&pk, None)?);
assert_ne!(params, ProofParams::new(&pk, Some(b"deployment 2"))?);

// For protocols that want it in their outer transcript.
params.add_to_transcript(&mut Transcript::new(b"my-protocol presentation v1"));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. It fixes the
commitment key; the proof's soundness needs that key to be binding, which is a Module-SIS
assumption on the expanded matrices.

**Using it safely**

The code refuses a public key whose ring degree is not 64: `Error::UnsupportedProofDegree`.
A proof made under one `ProofParams` and checked under another is rejected
(`Error::ProofRejected`; shown in [Misuse](misuse.md)).

```rust
use kln_accumulator::{Error, LnpParameters, Params};

// The same refusal, from the parameter computation that every proof operation runs.
let refused = LnpParameters::new(&Params::paper_128()?, 1);
assert_eq!(refused.map(drop), Err(Error::UnsupportedProofDegree(4096)));
# Ok::<(), kln_accumulator::Error>(())
```

Your job: make the entropy input part of your protocol's public configuration. Both sides
must pass the same bytes, and `None` is different from `Some(b"")`.

## `ProofSetup`

**What it is**

The values every proof operation derives from the parameter set, the `ProofParams` and the
shape of the linking relation, derived once: the `LnpParameters`, with the Gaussian samplers of
the prover's masks, and the commitment key expanded from the `ProofParams` seed, about 160 MB
at the toy set. `ProofSetup::new(&pk, &proof_params, &relation)` builds it; only the shapes of
`A₁` and `A₂` are read from the relation.

**Why it exists**

`prove`, `verify`, `MembershipProofCommitting::new`, `MembershipProof::finalize`,
`MembershipProof::compress` and `CompressedMembershipProof::finalize` derive these values on
every call, so a verifier that checks many proofs for one public key pays the key expansion
per proof. Each has a sibling with a `_with` suffix (`prove_with`, `verify_with`,
`MembershipProofCommitting::new_with`, `MembershipProof::finalize_with`,
`MembershipProof::compress_with`, `CompressedMembershipProof::finalize_with`) that takes a
`&ProofSetup` instead. The operations without the suffix build a setup and call their sibling,
so both forms make the same proofs, byte for byte, and accept the same proofs.

**How to use it**

Build one setup per public key, `ProofParams` and relation shape, keep it as long as proofs of
that kind arrive, and pass it to every call. `MembershipProofCommitting::new_with` takes the
element, witness and `r` as a `MembershipSecret` and the public key, accumulator and relation
as a `MembershipStatement`.

```rust,no_run
// no_run: proving takes 2 to 12 s and about 160 MB at the toy set.
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::{
    Error, MembershipSecret, MembershipStatement, ProofSetup, prove_with, verify_with,
};
use merlin::Transcript;

let setup = ProofSetup::new(&pk, &proof_params, &relation)?;
let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
let proof = prove_with(&statement, &secret, &proof_params, &setup, &mut Transcript::new(b"t"), &mut rng)?;

// Any number of verifications, one key expansion.
for _ in 0..3 {
    verify_with(&statement, &proof, &proof_params, &setup, &mut Transcript::new(b"t"))?;
}

// A setup is refused for proof parameters other than its own, before any work.
let other = ProofParams::new(&pk, Some(b"another deployment"))?;
assert_eq!(
    verify_with(&statement, &proof, &other, &setup, &mut Transcript::new(b"t")),
    Err(Error::ParameterMismatch)
);
# Ok::<(), kln_accumulator::Error>(())
```

The compression layer's own keys are not part of the setup: their shapes depend on the number
of LaBRADOR levels, so `compress_with` and `CompressedMembershipProof::finalize_with` still
expand them per call.

**Security**

Public value, no secrecy: it holds parameters and a key that anyone can derive from the public
key and the `ProofParams`, so nothing in it needs wiping. The prover's secrets stay in
`MembershipProofCommitting`, which keeps a handle on the setup's values and wipes its own
secrets as before. It has no serde form; it is derived, never stored or sent. `Debug` prints
what the setup was built for and the `LnpParameters`, not the key. Clones share the derived
values.

**Using it safely**

Every operation that takes a setup refuses, with `Error::ParameterMismatch` and before any
other work, one built for another parameter set, for other `ProofParams`, or for a relation
whose `A₁` or `A₂` has another shape. A refused call leaves its transcript and its random
number generator as they were. A long-lived setup holds about 160 MB for as long as it lives.

## `LinkingRelation`

**What it is**

The public triple `(A₁, A₂, t)` of the relation `A₁·x + A₂·r = t`. `A₁` has `ℓ` columns, one
per bit of the element; `A₂` has one column per entry of `r`; `t` has one entry per row.

**Why it exists**

See [Why there is a linking relation](#why-there-is-a-linking-relation). It is the only
connection between this proof and the rest of a presentation.

**How to use it**

The setup example above builds one. The accessors return its parts.

```rust
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
assert_eq!(relation.a1().shape(), Shape { rows: 1, cols: 8 });
assert_eq!(relation.a2().shape(), Shape { rows: 1, cols: 1 });
assert_eq!(relation.t().len(), 1);
// What the statement digest absorbs: four shape words, then 8 + 1 + 1 polynomials.
assert_eq!(Vec::from(&relation).len(), 32 + 10 * 64 * 24);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy: it is part of the statement. It is covered by the statement digest,
so a proof made for one relation does not verify for another. Its polynomials are wiped on
drop like every polynomial, which has no security meaning here.

**Using it safely**

The code refuses:

- parts with different row counts, at `LinkingRelation::new`: `Error::DimensionMismatch`;
- an `A₁` that does not have `ℓ` columns, when a proof is made or verified:
  `Error::DimensionMismatch`;
- a coefficient that is not reduced modulo `q`, when a proof is made or verified:
  `Error::CoefficientOutOfRange`.

```rust
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::{Error, LinkingOpening, MembershipProofCommitting};
use kln_accumulator::lattice::PolyMatrix;

// Row counts that differ.
let two_rows = PolyVec::zero(2, ring);
let mismatched = LinkingRelation::new(relation.a1().clone(), relation.a2().clone(), two_rows);
assert!(matches!(mismatched, Err(Error::DimensionMismatch { expected: 2, found: 1 })));

// An A₁ with seven columns for an eight-bit element: accepted by new, refused at use.
let narrow = PolyMatrix::zero(Shape { rows: 1, cols: 7 }, ring);
let wrong_shape = LinkingRelation::new(narrow, relation.a2().clone(), relation.t().clone())?;
let refused = MembershipProofCommitting::new(
    &x, &witness, &proof_params, &pk, &acc,
    LinkingOpening { relation: &wrong_shape, r: &r },
    &mut rng,
);
assert!(matches!(refused, Err(Error::DimensionMismatch { expected: 8, found: 7 })));

// A t decoded from bytes that are not reduced modulo q.
let unreduced = PolyVec::from(vec![Poly::try_from(&[0xffu8; 24 * 64][..])?]);
let bad = LinkingRelation::new(relation.a1().clone(), relation.a2().clone(), unreduced)?;
let refused = MembershipProofCommitting::new(
    &x, &witness, &proof_params, &pk, &acc,
    LinkingOpening { relation: &bad, r: &r },
    &mut rng,
);
assert!(matches!(refused, Err(Error::CoefficientOutOfRange)));
# Ok::<(), kln_accumulator::Error>(())
```

Your job: the relation's meaning. The crate proves that the hidden `x` and `r` satisfy it. It
does not check that `A₁` and `A₂` make `t` a binding or hiding commitment, or that `t` is the
value the rest of your presentation talks about. A verifier must take `A₁`, `A₂` and `t` from
its own protocol state, not from the prover unchecked.

## `LinkingOpening`

**What it is**

The prover's side of the linking relation: a reference to the public relation and a reference
to the secret vector `r`. Two borrowed fields; it is `Copy`.

**Why it exists**

The committing step needs the public relation and the secret `r` that opens it. This struct
carries the two together as one argument, with named fields, so that they cannot be passed in
the wrong order.

**How to use it**

Build it in place: `LinkingOpening { relation: &relation, r: &r }`. The three-step example
above does.

```rust
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::LinkingOpening;

let opening = LinkingOpening { relation: &relation, r: &r };
// Debug prints the public relation and leaves r out.
assert!(!format!("{opening:?}").contains(" r:"));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Holder-private, by reference. It owns nothing, so it has nothing to wipe; the `PolyVec` it
points to wipes itself when its owner drops it. `Debug` does not print `r`.

**Using it safely**

The code refuses an `r` that is not binary, or that does not satisfy the relation with the
element: `Error::RelationUnsatisfied`; see `MembershipProofCommitting` below. Your job: `r`
is as secret as the witness. If `t` is a commitment to `x`, anyone who learns `r` can test
guesses for `x`.

## `MembershipStatement`

**What it is**

The public statement of a proof, for the one-shot functions: references to the public key, the
accumulator value and the linking relation. It is `Copy`.

**Why it exists**

`prove` and `verify` must agree on exactly what is being proved. Collecting the three public
inputs in one value gives one thing to digest into the transcript and one argument that the
prover and the verifier build the same way.

**How to use it**

`MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation }`, as in the
one-shot example above.

**Security**

Public value, no secrecy. It only borrows, so it has nothing to wipe. A digest of the
statement, together with the proof parameters, goes
into both transcripts. That is what binds a proof to its public key, accumulator value and
relation: change any of them and the proof is rejected.

**Using it safely**

The code refuses a proof checked against a different statement: `Error::ProofRejected`. The
running example in [Misuse](misuse.md) checks a different accumulator value and a different
public key. Parts from different parameter sets are `Error::ParameterMismatch`.

Your job: the verifier must build the statement from *its own* view: the public key it
trusts, the *current* accumulator value, and the relation its protocol defines. A proof
against an old accumulator value proves membership in the old set. That is how a revoked
holder gets accepted by a verifier that is behind.

## `MembershipSecret`

**What it is**

The prover's secret inputs, for the one-shot `prove`: references to the element, its witness
and the vector `r`. It is `Copy`.

**Why it exists**

It keeps the three secrets together and apart from the public statement, so that a call to
`prove` reads as "this statement, with this secret".

**How to use it**

`MembershipSecret { element: &x, witness: &witness, r: &r }`, as in the one-shot example
above.

```rust
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::MembershipSecret;

let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
assert_eq!(format!("{secret:?}"), "MembershipSecret { .. }");
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Holder-private, by reference. It owns nothing to wipe; the values it points to wipe themselves
when their owners drop them. `Debug` prints none of it.

**Using it safely**

The element field takes an `Element`, which is a string of bits by construction. A value that
is not binary cannot be put there:

```rust,compile_fail
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::MembershipSecret;

// A polynomial with arbitrary coefficients where the element belongs.
let not_bits: Poly = sampler.poly(ring);
// error: mismatched types, expected `&Element`, found `&Poly`
let secret = MembershipSecret { element: &not_bits, witness: &witness, r: &r };
# Ok::<(), kln_accumulator::Error>(())
```

The code refuses a secret that does not satisfy the statement with
`Error::RelationUnsatisfied`; the example under `MembershipProofCommitting` shows the cases.

## `prove` and `verify`

`prove(statement, secret, proof_params, transcript, rng)` returns a `MembershipProof`.
`verify(statement, proof, proof_params, transcript)` returns `Ok(())` or
`Error::ProofRejected`. Both are shown in the one-shot example above, and they run in
[Misuse](misuse.md). `prove_with` and `verify_with` take a `ProofSetup` after
`proof_params` and are otherwise the same (see `ProofSetup` above).

They are the three-step form with the challenge handling done for you: each appends the
statement digest and `t_A` to the transcript and draws the challenge from it under a fixed
label. Because `verify` draws the challenge itself, there is no comparison for the caller to
forget.

`prove` fails with `Error::RelationUnsatisfied` when the secret does not satisfy the
statement, `Error::UnsupportedProofDegree` at a degree other than 64,
`Error::ParameterMismatch` for inputs of different sets, and `Error::ProverAborted` if every
one of 1000 attempts aborts, which the crate's documentation says does not happen in practice.

## `Challenge`

**What it is**

The outer [Fiat–Shamir](glossary.md#fiatshamir) challenge of the [three-step form](glossary.md#one-shot-form-three-step-form): 64 bytes drawn from a merlin
transcript. It is `Copy`.

**Why it exists**

In the vb20 pairing accumulator the challenge is a field element. Here an element has only
`ℓ` bits, far too few for a challenge, so the challenge has its own type. It seeds the proof's
inner transcript, which is why a proof is valid for exactly one challenge.

**How to use it**

```rust
use kln_accumulator::Challenge;
use merlin::Transcript;

let draw = |nonce: &[u8]| {
    let mut transcript = Transcript::new(b"my-protocol presentation v1");
    transcript.append_message(b"verifier nonce", nonce);
    Challenge::from_transcript(b"challenge", &mut transcript)
};
// The same transcript gives the same challenge; a different one does not.
assert_eq!(draw(b"42"), draw(b"42"));
assert_ne!(draw(b"42"), draw(b"43"));

// It converts to and from its 64 bytes.
let bytes: [u8; 64] = draw(b"42").into();
assert_eq!(Challenge::from(bytes), draw(b"42"));
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. Its security role is
to be unpredictable to the prover before the prover has committed, which holds when it is drawn
from a transcript that already absorbed the commitment.

**Using it safely**

A proof checked against a challenge it was not made for is rejected: `Error::ProofRejected`,
shown in the three-step example.

Your job:

- **Draw it from the transcript, after `get_bytes_for_challenge`.** `Challenge::from(bytes)`
  exists for transport. A prover that picks its own challenge bytes is no longer running a
  sound protocol, and nothing in `gen_proof` can tell.
- **Verifier: rederive and compare.** `finalize` checks the proof *for the challenge you pass
  it*. It cannot know whether that challenge came from your transcript. Rebuild the transcript,
  call `get_bytes_for_challenge` on the finalized proof, draw the challenge and compare it with
  the one the proof was checked under. Skip that and proofs can be replayed across sessions.

## `MembershipProofCommitting`

**What it is**

The prover's state after the first step: the commitment `t_A` to the element, `r` and the
witness, together with the secrets the later rounds use.

**Why it exists**

The three-step form needs a value that exists between "I have committed" and "I have the
challenge". This is it. It also lets one commitment be used for a compressed and an
uncompressed proof.

**How to use it**

`new`, then `get_bytes_for_challenge`, then `gen_proof` or `gen_compressed_proof`; the
three-step example above shows the sequence. Committing is cheap next to responding.

**Security**

Secret, prover only. It holds the committed message, the commitment randomness, their
transforms and the mask seed, all in buffers that are overwritten when it is dropped. It is
neither `Copy` nor `Clone`. `Debug` prints the public parameters and `t_A` only.

It may answer more than one challenge: each answer uses masks derived from its seed and from
that challenge.

**Using it safely**

The code refuses inputs that do not satisfy the relation being proved, before it commits to
anything: `Error::RelationUnsatisfied`. That covers a witness that does not verify for the
element against the accumulator value, an `r` that is not binary, and an `r` that does not
satisfy the linking relation.

```rust
# use kln_accumulator::{
#     Accumulator, Element, LinkingRelation, MembershipWitness, Params, ProofParams, PublicKey,
#     SecretKey,
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
# let proof_params = ProofParams::new(&pk, None)?;
use kln_accumulator::{Error, LinkingOpening, MembershipProofCommitting};

let commit = |element: &Element, r: &PolyVec, relation: &LinkingRelation| {
    let opening = LinkingOpening { relation, r };
    let mut rng = StdRng::seed_from_u64(1);
    MembershipProofCommitting::new(element, &witness, &proof_params, &pk, &acc, opening, &mut rng)
        .map(drop)
};

// The honest inputs are accepted.
assert_eq!(commit(&x, &r, &relation), Ok(()));

// A witness for another element.
let y = Element::hash(b"y", &params);
assert_eq!(commit(&y, &r, &relation), Err(Error::RelationUnsatisfied));

// A binary r that does not satisfy the relation.
let zero = PolyVec::from(vec![constant(false)?]);
assert_eq!(commit(&x, &zero, &relation), Err(Error::RelationUnsatisfied));

// An r that is not binary, with a relation built to match it: A₁·x + A₂·r = t holds, and the
// prover still refuses.
let two = PolyVec::from(vec![constant(true)?.mul_small(2, ring)?]);
let t = relation.a1().mul_vec(&bits, ring)?.add(&relation.a2().mul_vec(&two, ring)?, ring)?;
let matching = LinkingRelation::new(relation.a1().clone(), relation.a2().clone(), t)?;
assert_eq!(commit(&x, &two, &matching), Err(Error::RelationUnsatisfied));
# Ok::<(), kln_accumulator::Error>(())
```

Your job:

- **Drop it when you are done.** Dropping wipes it. Do not keep it across presentations.
- **Use a good generator.** The commitment randomness and the mask seed come from the `rng`
  you pass.
- **Timing and memory.** The prover is not constant time: its masks are drawn by a table
  search whose memory access and length depend on the draw, and the number of restarts
  varies.

## `MembershipProof`

**What it is**

An uncompressed membership proof: the prover's messages and responses. The verifier rederives
every challenge from them.

**Why it exists**

It is what the holder sends. It also mirrors the `MembershipProof` of the vb20 pairing
accumulator, with `finalize` in the same place.

**How to use it**

`gen_proof` or `prove` makes one. `to_bytes` and `TryFrom<&[u8]>` carry it; `finalize` or
`verify` checks it; `compress` shrinks it. All of that is in the three-step example.

**Security**

Public value, no secrecy: it is meant to be sent. Nothing in it needs wiping; its polynomials
overwrite themselves on drop like every polynomial, which has no security meaning for a public
value. Under the zero-knowledge property of the proof system it reveals nothing about the
element, the witness or `r` beyond the truth of the statement. Under its knowledge soundness, a
proof that verifies shows that the prover knew an element, a binary `r` and a short witness
satisfying the statement. Both properties, and how far they are established here, are in
[Guarantees and their limits](security.md).

**Using it safely**

The code refuses, at `finalize` and `verify`, a proof that fails any check of the protocol:
`Error::ProofRejected`. That includes a proof for another statement, another challenge,
another transcript or other proof parameters, and a proof with any field altered. A byte
string that is not a proof encoding is refused by `TryFrom<&[u8]>` with
`Error::InvalidEncodingLength`.

```rust
use kln_accumulator::{Error, MembershipProof};

assert!(matches!(
    MembershipProof::try_from(&[0u8; 7][..]),
    Err(Error::InvalidEncodingLength(_))
));
```

Your job:

- **Decoding is not verifying.** `TryFrom<&[u8]>` checks only the layout. Shapes and ranges
  are checked by `finalize` and `verify`. Do not act on a decoded proof.
- **Size.** A proof is megabytes. Bound what you are willing to read from a peer before you
  decode.

## `MembershipProofFinal`

**What it is**

What a verified proof contributes to the verifier's outer transcript: the statement digest
and the commitment `t_A`.

**Why it exists**

It is the verifier's half of the challenge check. `finalize` returns it only after every
check has passed; `get_bytes_for_challenge` then appends the same bytes the prover's
committing step appended, so that the verifier can rederive the challenge.

**How to use it**

Call `get_bytes_for_challenge` on a transcript that is in the state the prover's was in before
*its* `get_bytes_for_challenge`, draw the challenge with the same label, and compare. The
three-step example shows it.

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. Holding one means the
proof passed every check for the challenge that was given to `finalize`.

**Using it safely**

There is no way to construct one except through a successful `finalize`, so holding one cannot
be faked within the API. Your job is the comparison: a `MembershipProofFinal` says "the proof
is valid for *that* challenge". Only the comparison says "and that challenge is the one my
transcript produces".

## `CompressionLevels`

**What it is**

The number of LaBRADOR levels of a compressed proof, from 1 to `CompressionLevels::MAX`,
which is 8.

**Why it exists**

One level sends its opening in the clear. Each further level proves the previous level's
verification instead of sending it, which shrinks the proof. The newtype keeps
the count within the supported range.

**How to use it**

```rust
use kln_accumulator::{CompressionLevels, Error};

let levels = CompressionLevels::try_from(3)?;
assert_eq!(levels.get(), 3);
assert_eq!(CompressionLevels::MAX, 8);
assert_eq!(CompressionLevels::try_from(0), Err(Error::InvalidCompressionLevels(0)));
assert_eq!(CompressionLevels::try_from(9), Err(Error::InvalidCompressionLevels(9)));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. The knowledge error of
the compression layer grows linearly with the number of levels (ePrint 2022/1341, Lemma 3.7).
The crate's source computes it per level; that figure is for the interactive protocol and is
not a statement about the non-interactive proof.

**Using it safely**

The code refuses 0 and anything above 8: `Error::InvalidCompressionLevels`, shown above. The
number of levels is absorbed into the proof's transcript, so a proof made for one count does
not verify as another. Your job is only to choose the count; see
[Benchmarks and sizes](benchmarks.md) for what each costs.

## `CompressedMembershipProof`

**What it is**

A membership proof whose two large responses are replaced by a LaBRADOR proof that suitable
responses exist. Only the part of the response that concerns the element's bits is still sent
in the clear.

**Why it exists**

Size. The uncompressed proof is dominated by its responses, which are linear in the length of
the witness.

**How to use it**

`MembershipProofCommitting::gen_compressed_proof(&challenge, levels)` or
`MembershipProof::compress(&statement, &proof_params, &challenge, levels)` makes one.
`finalize` checks it with the same arguments as for an uncompressed proof and returns the same
`MembershipProofFinal`. `Vec::from(&proof)` and `TryFrom<&[u8]>` carry it. The three-step
example ends with all of these.

**Security**

Public value, no secrecy. Nothing in it needs wiping; its polynomials overwrite themselves on
drop like every polynomial, which has no security meaning for a public value. The compression
layer needs no zero knowledge of its own: what it hides behind a proof of knowledge are the
responses, which the uncompressed proof sends in the clear anyway. Its soundness adds the
LaBRADOR layer's knowledge error to that of the proof it compresses, and its security after the
Fiat–Shamir transform is cited, not derived.

**Using it safely**

The code refuses a compressed proof that fails any check, at `finalize`:
`Error::ProofRejected`. `compress` refuses a proof whose responses do not satisfy the
verifier's equations for the given statement and challenge: `Error::RelationUnsatisfied`. A
malformed encoding is `Error::InvalidEncodingLength`.

```rust
use kln_accumulator::{CompressedMembershipProof, Error};

assert!(matches!(
    CompressedMembershipProof::try_from(&[0u8; 7][..]),
    Err(Error::InvalidEncodingLength(_))
));
```

Your job is the same as for `MembershipProof`: decoding is not verifying, and the verifier
must still rederive and compare the challenge.

## `LnpParameters`

**What it is**

The dimensions, Gaussian widths and norm bounds of the proof for one statement shape, computed
from the formulas of Appendix D.2.3 of the paper. A struct with public fields.

**Why it exists**

The proof has its own parameters, separate from the accumulator's: how long the committed
message is, how wide the masks are, what rank the commitment needs. They depend on the
parameter set and on the length of `r`. This type computes them once, in exact integer
arithmetic, and checks the conditions the appendix places on the modulus.

**How to use it**

You rarely need it: every proof operation computes it internally. It is public so that the
parameters can be inspected.

```rust
use kln_accumulator::{LnpParameters, Params};

let lnp = LnpParameters::new(&Params::toy()?, 2)?;
assert_eq!((lnp.degree, lnp.element_bits, lnp.r_len), (64, 8, 2));
assert_eq!(lnp.witness_len, 100); // m + ℓm'
assert_eq!(lnp.digits, 43);       // binary digits per witness coefficient
assert_eq!(lnp.m1, lnp.element_bits + lnp.r_len + lnp.witness_len * lnp.digits);
assert_eq!((lnp.m2, lnp.n, lnp.tau), (1564, 18, 3));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. The commitment rank
`n` is the least rank for which a root-Hermite-factor rule (`δ < 1.0044`) calls the underlying
Module-SIS problem hard. That rule is not the paper's Core-SVP estimate, and the two have not
been shown to agree.

**Using it safely**

The code refuses a parameter set of degree other than 64 (`Error::UnsupportedProofDegree`,
shown under `ProofParams`) and a modulus that fails a condition of Appendix D.2.3
(`Error::ProofModulusTooSmall`). There is nothing for the caller to get wrong; the fields are
derived.

## `SubringMap`

**What it is**

The map between a ring of degree `d` and vectors over a smaller ring of degree `d_S` with the
same modulus, on polynomials, vectors and matrices, with its inverse.

**Why it exists**

The proof runs over a ring of degree 64. The 128-bit accumulator lives in a ring of degree
4096. This map is how a statement over the large ring would be carried into the small one. It
is built and tested, but **the proof does not use it yet**: that is why proofs are refused at
any degree other than 64.

**How to use it**

```rust
use kln_accumulator::{Params, SubringMap};
use kln_accumulator::lattice::{DomainLabel, Seed, Shape, UniformSampler};

let ring = Params::paper_128()?.ring().clone();
let map = SubringMap::new(&ring, 1024)?;
assert_eq!(map.rank(), 4);
assert_eq!(map.small().degree(), 1024);

let mut sampler = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"m"[..]));
let m = sampler.matrix(Shape { rows: 2, cols: 3 }, &ring);
let v = sampler.vector(3, &ring);
// Splitting commutes with multiplication, and combine inverts split.
let lhs = map.split_vector(&m.mul_vec(&v, &ring)?)?;
let rhs = map.split_matrix(&m)?.mul_vec(&map.split_vector(&v)?, map.small())?;
assert_eq!(lhs, rhs);
assert_eq!(map.combine_vector(&map.split_vector(&v)?)?, v);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. It only permutes coefficients, so it preserves every norm. The
values it returns wipe themselves on drop like every polynomial.

**Using it safely**

The code refuses a small degree that is not a power of two (`Error::DegreeNotPowerOfTwo`), one
that exceeds the large ring's degree, and inputs of the wrong shape
(`Error::DimensionMismatch`).

```rust
use kln_accumulator::{Error, Params, SubringMap};

let params = Params::toy()?;
assert!(matches!(SubringMap::new(params.ring(), 48), Err(Error::DegreeNotPowerOfTwo(48))));
assert!(matches!(
    SubringMap::new(params.ring(), 128),
    Err(Error::DimensionMismatch { .. })
));
# Ok::<(), kln_accumulator::Error>(())
```

Your job: do not read its presence as support for proofs at the 128-bit set. There is none.
