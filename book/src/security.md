# Guarantees and their limits

> **In short.** What the crate is meant to guarantee, what each guarantee rests on, and what
> is not established. It is research code: it has not been audited, it is not
> [constant time](glossary.md#constant-time), its toy settings protect nothing, and membership
> proofs run only at those toy settings. Do not use it to protect anything real.
>
> **Read this when** you decide whether, and for what, to use the crate, or need to know what a
> guarantee assumes.
>
> **New here?** Read the short version below,
> [Who is trusted](#who-is-trusted), the list under
> [What is not established](#what-is-not-established) and
> [What this means for an integrator](#what-this-means-for-an-integrator). The sections between
> them argue each guarantee from the paper's theorems and
> [assumptions](glossary.md#assumption). They are advanced, and you do not need them to use the
> crate.

This chapter says what the crate is meant to guarantee, what each guarantee rests on, and what
is not established. The next chapter, [Misuse](misuse.md), goes through the ways the API can
be used wrongly.

> **The short version.** This is a research implementation. It has not been audited. It is not
> constant time. Its toy parameter sets give no security. Membership proofs run only at the
> toy sets. Use the crate to study and evaluate the scheme. Do not use it to protect anything
> real.

## How to read the claims

Each guarantee below is one of four kinds, and the text says which.

- **Proved in the paper, under stated assumptions.** ePrint 2025/1099 states a theorem. The
  claim holds for the scheme as the paper defines it, at parameters that meet the theorem's
  hypotheses, if the assumptions hold.
- **Stated in the paper without a formal proof there.** The paper describes the property and
  refers to prior work for its proof.
- **A property of this code.** Something the implementation does, checked by its tests.
- **Not established.** Listed plainly in the section [What is not established](#what-is-not-established).

A theorem about a scheme is not a theorem about an implementation of it. Between the two sit
the things the last section lists.

## Who is trusted

**The manager is trusted.** The security definition of ePrint 2025/1099 is for accumulator
values generated honestly, and the paper puts a trusted authority, the issuer, in the
manager's role. A manager can issue a witness for any element at any time. Nothing in this
crate protects a holder or a verifier from the manager.

**The attacker** sees everything public: the public key, every accumulator value, every update
message, every proof. It may hold witnesses of its own, for elements it was given. It does not
see the secret key, the manager state, or other holders' witnesses.

**Side channels are out of scope.** The crate writes a few secret-dependent steps so that
their timing does not depend on the secret, listed under
[Timing](#timing-what-is-and-is-not-constant-time), and leaves the rest as it is. An attacker
who can time the manager or a prover is outside what any guarantee below covers.

## The accumulator: soundness

**What it means.** Nobody without the secret key can produce a witness that verifies, against
the current accumulator value, for an element that is not in the set. That covers an element
that was never added and an element that was deleted. The paper calls this
*[collision-freeness](glossary.md#collision-freeness)* (Definition 3.3).

### Construction 4.1

**Proved in the paper, under stated assumptions** (Theorem 4.3): Construction 4.1 is a
*[selectively](glossary.md#selective-and-adaptive-security)* collision-free, *[replacement-free](glossary.md#replacement-free)* accumulator, provided that

- the [PRF](glossary.md#prf) that fixes the sampling randomness is secure,
- two [Module-LWE](glossary.md#module-lwe-module-sis) assumptions with small secrets hold, one of them with ternary secrets, and
- Module-SIS holds for the norm bound the theorem derives.

The paper notes that the Module-LWE assumption can be removed in exchange for larger
parameters.

Two words in that statement limit it.

- **Selective.** The attacker must name the element it will forge a witness for *before* it
  sees the public key and the initial value. This is weaker than letting the attacker choose
  its target after watching the system. Construction 4.1 on its own gives no more.
- **Replacement-free.** The guarantee is for an accumulator in which an element, once added,
  is never added again, not even after it was deleted (Remark 4.2 of the paper). If that rule
  is broken, a trapdoor for the element's matrix can be recovered, and with it witnesses can be
  forged. The code enforces the rule: a second addition is `Error::ElementAlreadyAdded`.

**A property of this code.** The PRF is SHAKE256 keyed with a key derived from the root seed
and the parameter set. That it behaves as a secure PRF is an assumption about SHAKE256.

### Construction 4.2, the adaptive variant

**Proved in the paper, under stated assumptions** (Theorem 4.4): Construction 4.2 is an
*adaptively* collision-free positive dynamic accumulator, provided that

- the PRF that derives handles is secure,
- the signature scheme is existentially unforgeable under chosen-message attack, and
- the inner accumulator is a selectively collision-free replacement-free accumulator, that is,
  Theorem 4.3 applies.

Here the attacker may choose its target at any time, and elements may be deleted and added
again. In this crate the signature scheme is ML-DSA-65 (FIPS 204), in its deterministic
variant, and the PRF is again SHAKE256.

### The succinct variant

**Stated in the paper without a formal proof there.** The paper presents the succinct variant
as resting on the `ℓ`-succinct Module-SIS assumption (its Definition 2.10) in place of
Module-SIS, and says that correctness and compactness carry over. It states no separate
security theorem for the variant. This book claims none.

The succinct secret key dereferences to the base key its accumulator runs on, and the base
`MembershipWitness::new` refuses that key with `Error::CompressedWitnessOnly`. The uncompressed
witness is the same sample the succinct witness is a public linear image of, not a second
preimage, so it would not leak the key the way Remark 4.1 describes. But in the paper a succinct
holder receives only the compressed vector, and whether the variant's argument covers handing
out the uncompressed one is not established here, so the crate does not hand it out.

**A property of this code.** The base key inside a succinct key derives its trapdoor, `u`,
genesis value, PRF key and state-tag key under a label of its own. Its bytes, which the base
`to_bytes` returns through the dereference, therefore decode as a Construction 4.1 key that
shares nothing with it: another `A`, another `u`, another genesis value, and a state-tag key
that refuses the succinct key's states (`Error::InvalidStateTag`). Were the two keys to share
the trapdoor and the PRF key, each would sample a witness for the same element under its own
matrix, and the two witnesses together would give information about the trapdoor away. A
test decodes a succinct key's base key bytes and checks all of this.

### What the parameter sets add

The theorems hold at parameters that meet their hypotheses and at which the lattice problems
are hard.

- **The toy sets give no security.** They are sized so that tests run in seconds.
- **`ParamsSpec::PAPER_128`** takes its shape from Table 2 of the paper. The crate derives the
  Gaussian widths and norm bounds that the theorems ask for at that shape, and its sizes are
  within 0.4% of the paper's table. The crate does not estimate the hardness of the resulting
  lattice problems. The 128-bit label is the paper's.

## Witnesses: correctness, update and privacy

**Proved in the paper** (Theorem 4.2, correctness): an honestly issued witness verifies, and
keeps verifying after it is updated through deletions, as long as no more than `γ` deletions
are made. The bound `β` is sized for that: it leaves room for everything `γ` deletions can
add. Holders update from public data alone: the public key and the update messages.

**A property of this code.** Witness issuance is deterministic and does not depend on the
manager state's history. `MembershipWitness::new` is the only code path that samples a
witness preimage (the succinct constructor calls the same sampler once and compresses the
result, and succinct key generation samples the public matrix `T`, not a witness); it samples for the key's genesis value with randomness that is a PRF of the element
alone, and adds the public correction of every deletion the state records. So a witness is a
function of the key, the element and the set of deletions, and the key samples exactly one
preimage per element over its whole life, whatever state it is handed: fresh, forked, rolled
back, rebuilt or forged. This is what protects the trapdoor against the leak of Remark 4.1 of
the paper. It departs from the paper's `MemWitCreate`; see
[the deviation below](#where-this-crate-departs-from-the-paper). Two further properties back
the rule up. The preimage sampler hashes its seed together with the matrix, the target and the
sampling mode before it draws anything, so a seed reused for another target or another matrix
shares no randomness with the first draw. And the bytes of the base key inside a succinct key
decode to an unrelated key, as [the succinct variant](#the-succinct-variant) above says.

**Privacy.** A witness is [holder-private](glossary.md#classes-secret-holder-private-public): it is shown to no one. Three things are *not*
private.

- The manager knows every element and can compute every witness.
- An update message names the deleted element. Everyone learns which element was revoked. In
  the adaptive variant the message names the element's handle instead, which hides the
  element from those who do not know the mapping; the manager knows it.
- Verifying a witness in the clear shows the verifier the element and the witness. Only the
  membership proof hides them.

Updating a witness is a local computation. It sends nothing, so it reveals nothing.

## The manager state tag: integrity, not freshness

**A property of this code.** Every keyed operation checks the tag of the manager state before
it does anything else, and refuses a state whose tag does not verify
(`Error::InvalidStateTag`); `ManagerState::authenticate` runs that check alone. The tag is
SHAKE256 keyed by prefix with a key derived from the secret key's root seed and parameter set,
over the current value, the counter and the whole dictionary. A state that was altered in any
field, or that another key tagged, therefore never decides which witnesses are issued, against
which value, or how many deletions remain. Because the key that tags depends on the parameter set, a key made from the same seed
for another set is "another key" too. After the tag, every keyed operation refuses a value
other than the state's current one (`Error::AccumulatorMismatch`), so the state moves only
with the value it records. That this construction is unforgeable is, again, an assumption
about SHAKE256.

**What it does not give.** The tag does not stop [rollback](glossary.md#rollback). An older state that the same key
once tagged verifies as well as the current one. Nothing monotonic lives outside the state.
Since witnesses do not depend on the history, an older or forked state cannot make the key
leak: it reproduces the same witnesses for the same deletions. It still issues witnesses for
its own, older value, and a manager that continues from it publishes a second history next to
the first. Keeping only the latest state is the manager's job. [Misuse](misuse.md) shows both.

## Where this crate departs from the paper

**Witnesses are sampled for the genesis value.** The paper's `MemWitCreate` samples the
preimage for an element `x` against `c_i`, the accumulator value at the epoch `i` at which `x`
was added, with randomness `F_k(x, c_i)`, and corrects it for the deletions after `i`. This
crate samples for the genesis value `c₀`, which the key derives and holds, with randomness
`F_k(x)`, and corrects it for every deletion the state records.

- **Why.** Only the state knows the epoch of an addition. With the paper's rule, a fresh state
  for a live accumulator, a fork (one copy adds `z` and then deletes `y`, another deletes `y`
  and then adds `z`), or a rolled-back state makes the key sample a second, different preimage
  for one element and one target: the leak of Remark 4.1. With this rule each of those states
  can only reproduce the one preimage the key has for the element, plus public corrections.
- **Why security is kept.** Adding does not change the value. So the values and witnesses of
  any run of this code are those of a run of the paper's scheme on the same key in which every
  element was added at epoch 0, before any deletion, and its witness was handed out by
  `MemWitCreate` at the moment this code issues it. In that run the paper samples for `c₀`
  with randomness `F_k(x, c₀)`, a fixed function of `x` for the key, and corrects for every
  deletion so far, which is what this code computes. The deletions, the replacement-free rule
  and the bound `γ` are those of the run itself. This matches runs one by one; it is not by
  itself a reduction to Theorem 4.3, because the game lets the adversary choose additions
  after seeing deletions, and such an element could not have been added at epoch 0. The
  theorem's proof (Appendix C) still goes through, read step by step: the randomness is
  already replaced by a random function of the element alone; the epoch of an addition enters
  only in the hybrids that move the challenge element's witness to a preimage of `c₀` plus
  the corrections, which is this code's real distribution, so those hybrids coincide and the
  divergence step between them is not needed; the remaining steps sample for a target they do
  not constrain; and the norm lemma needs only at most `γ` deletions, which each state
  enforces. That reading is this crate's own and has no separate proof written out. What the
  argument does not cover is the time before an element's addition: in
  the reinterpreted run the element is a member from epoch 0. Neither scheme tells those times
  apart, since a holder can move a witness back to any earlier value by subtracting the public
  corrections of the deletions in between, and this crate claims nothing more there.
- **Cost.** Issuing a witness replays every deletion made so far, one `H_{1y,x}·G⁻¹(u)` each,
  not only those since the element was added.

**The genesis value comes from the key.** `Gen` step 2 samples `c₀` uniformly. Here it is drawn
by SHAKE256 from the key's seed and parameter set under its own label, which is uniform under
the same assumption as every other value the key derives, and the secret key holds it, so a
key keeps exactly one accumulator and every state starts there. It is not derivable from the
public key: that would change the public key's encoding or rest on hashing public data into a
uniform value, and `c₀` is public anyway as the first value the manager publishes.

**Adaptive inner witnesses depend on the handle alone.** The adaptive variant keeps the
paper's handle rule (Construction 4.2, Add step 3): the index counts past every handle the
inner accumulator has seen, so no addition is refused for a collision, and which of two
colliding elements moves on depends on which was added first. A fork may therefore give an
element a different live handle than the original did. That is a matter of reproducibility,
not a leak: under genesis sampling the inner preimage for a handle is a function of the handle
alone, so no assignment of handles, on the original, a fork or a rebuilt state, can make the
key sample twice for one target. A lost adaptive state is rebuilt from the log and the
manager's member records as (element, handle) pairs, which every holder can supply from its
witness.

## Errata the code corrects

The code corrects four slips in Construction 4.1 as printed (p. 17 of the paper) and cites the
step at each correction:

- `Delete` records the incremented counter as the deletion epoch, so that the `j`-th deletion
  carries epoch `j`.
- The deletion bound refuses once `ctr ≥ γ`; the printed check admits `γ + 1` deletions.
- `MemWitCreate` samples with width `s`, not the printed `s₁`: in the paper the two widths must
  agree for `MemWitCreate` to reproduce the witness `Add` issued.
- `Delete` does not take the witness, which the printed algorithm takes and never uses.

## The trapdoor distributions

- **`TrapdoorDistribution::Gaussian`** (the default). **Proved in the paper** (Theorem 2.1):
  with a Gaussian trapdoor of the width the theorem asks for, the public matrix `A` is
  statistically close to uniform. No computational assumption enters at this step.
- **`TrapdoorDistribution::Ternary`.** `A` is then only *pseudorandom*, under Module-LWE with
  ternary secrets. That is a computational assumption. The crate's documentation notes that
  Theorem 4.3 already makes an assumption of this kind.

In both cases the preimage sampler's widths are derived, per parameter set, from the smoothing
conditions of ePrint 2011/501 and ePrint 2017/308 at `ε = 2^-128`, and the preimage equation
holds exactly: the sampler checks it before it returns a preimage, and refuses with
`Error::InvalidTrapdoor` when the matrix it is given is not the one its trapdoor was generated
with. What is not proved is the sampler's floating-point loss; see below.

## The membership proof

**What it means.**

- *[Zero knowledge](glossary.md#zero-knowledge)*: a proof reveals nothing about the element, the witness or `r` beyond the
  fact that the statement is true.
- *Knowledge soundness*: a prover that makes the verifier accept knows an element, a binary
  `r` and a short witness that satisfy the statement.

**Stated in the paper without a formal proof there.** Appendix D.2.3 of ePrint 2025/1099
describes how to set parameters for completeness, *honest-verifier* zero knowledge and
knowledge soundness of the commit-and-prove argument, and refers to prior work for the proofs.
The pieces are:

- zero knowledge from rejection sampling and from the hiding of the commitment, the latter by
  a leftover-hash-lemma argument over rings;
- knowledge soundness from the binding of the commitment, which is a Module-SIS assumption,
  and from conditions on the modulus that the crate checks
  (`Error::ProofModulusTooSmall`).

**The compression layer** (Appendix D.3, with LaBRADOR, ePrint 2022/1341) replaces the
proof's large responses by a proof of knowledge of them. It needs no zero knowledge of its
own, because the responses are what the uncompressed proof sends in the clear. One level is a
knowledge-sound proof in the sense of Theorem 5.1 of ePrint 2022/1341, and composing levels
adds their knowledge errors (its Lemma 3.7). The notes at the head of `src/proof/labrador.rs`
work out the knowledge error of one level for the crate's challenge set.

**A property of this code.** The verifier runs every check of the protocol, and the crate's
tests check that each tampered field of a proof is refused and that a non-binary element is
refused even when the prover's own check is bypassed. A proof is bound, through the
transcript, to its proof parameters, public key, accumulator value and linking relation.

Three limits apply, all listed in the next section: the proofs are interactive in the paper
and made non-interactive here, with no concrete bound for that step; the Module-SIS ranks are
chosen by a rule of thumb; and the proofs run only at the toy sets.

## Secret handling

**A property of this code.** Every type is classified as secret, holder-private or public.

| type | class | protection |
|---|---|---|
| `SecretKey` (all three variants), `Trapdoor`, `Seed` | secret | wiped on drop, not `Copy` or `Clone`, `Debug` prints no secret, constant-time equality |
| `MembershipProofCommitting` | secret (prover) | wiped on drop, not `Clone` |
| `MembershipWitness` (all three), `Delta` | holder-private | wiped on drop, `Debug` prints the parameter set only, encoded in wiped buffers |
| `MembershipSecret`, `LinkingOpening` | holder-private, by reference | borrow only; `Debug` prints no secret |
| `Element`, `BitString` | public, hidden in proofs | wiped on drop; `Element` is hex-coded in wiped buffers; `BitString`'s `Debug` prints its length only, `Element`'s prints its bytes |
| `Poly`, `PolyVec`, `PolyMatrix`, `NttMatrix` | public value types | wiped on drop, since secrets are made of them |
| `PublicKey`, `Accumulator`, `Coefficient`, proofs, parameters | public | none needed |
| `ManagerState` | manager-private, no key material | its elements are wiped on drop; `Debug` prints counts only |

Inside the crate, every intermediate that depends on a secret is wiped when it goes out of
scope, on every return path: derived seeds, PRF outputs, the SHAKE256 state that absorbed a
secret (through the `zeroize` feature of `sha3`), the sampler's draws and buffers, the
prover's masks and rejected responses, and the byte buffers that secret values are encoded
into or decoded from.

**What the crate cannot wipe:**

- copies in the output or input buffers of a serializer you call;
- a small padding block inside the hash function's finalisation;
- scalar values in registers and on the stack;
- the internals of the ML-DSA signer beyond what its own wiping feature covers.

Wiping reduces how long a secret stays in memory. It is not a defence against an attacker who
can read the process's memory while the secret is in use.

## Timing: what is and is not constant time

**A property of this code, at the evidence level given for each item.** The crate as a whole
is not constant time. A few steps that handle secrets are written so that neither their running
time nor the memory they touch depends on the secret. No dynamic constant-time test has been
run on any of them.

Written to run in time independent of the secret:

- **The draws of a Gaussian trapdoor's coefficients**, at key generation in every variant, and
  again whenever a key is decoded, since decoding regenerates the key from its seed. Each
  uniform value is looked up in the sampler's cumulative table by reading every entry and
  counting the entries not above it, each comparison taken from the borrow of a subtraction.
  Evidence: the assembly of one x86-64 release build, in which the loop is compare, subtract
  with borrow and count, and the only jumps are on the loop counter. The scan reads the whole
  table for every draw, which makes key generation slower than a search would;
  [Benchmarks](benchmarks.md) has the figures.
- **The sign handling of the `Z_q` arithmetic** under every product with a secret: reducing a
  signed integer, lifting a residue to its centred representative, and the last correction of
  the Chinese remaindering after the multi-prime NTT. Each selects its result by mask instead of
  branching on the secret comparison it makes. Evidence: in the assembly of the same build, the signed reduction and the
  centred lift have no jump of their own; the Chinese remaindering is inlined there and was
  checked by source reading only. The unsigned reduction that the signed one calls still
  branches on whether the magnitude is below `q`; at every defined set but the 60-bit toy set,
  the modulus alone decides that branch.
- **The block evaluation of a witness update.** Updating a witness for a deletion computes
  every block of `H_{1y,x}·G⁻¹(u)` and multiplies it by 0 or 1, so the number of products does
  not depend on how long a prefix the holder's element shares with the deleted one. Evidence:
  source reading. An update costs about twice what skipping the zero blocks would.
- **Equality of secrets** (`SecretKey`, `Trapdoor`, `Seed`, the state tag) goes through the
  constant-time comparisons of `ctutils`, and **the hex codec of secret and holder-private
  values** builds and parses hex without a branch or a table lookup on the bytes. Evidence:
  source reading.

Not constant time:

- **The wide draw of every witness.** Issuing a witness draws its `m + ℓm'` wide Gaussian
  coefficients by a table search guided by the top bits of each draw: which guide entry it
  reads and how long the search runs depend on the draw, and the wide draw is most of the
  holder-private witness. A scan here too would make issuing a witness more than ten times
  slower at the 128-bit set, and the crate does not use one.
- **The prover's masks**, drawn by the same search.
- **The real-centre sampler** behind the perturbation, the G-lattice step and the extension of
  every preimage. It works in floating point and by rejection, reads a number of stream words
  that depends on the value it draws, and divides secret words.
- **Everything else.** The crate makes no timing claim for any step outside the first list,
  the ternary trapdoor's byte sampler included.

## What is not established

Each item here is a reason the guarantees above may not hold for this implementation.

1. **It is a research implementation, and it has not been audited.** It is not published to
   crates.io.

2. **It is not constant time.** Only the steps listed under
   [Timing](#timing-what-is-and-is-not-constant-time) are written to run in time independent of
   secrets, on the evidence stated there: one build's assembly or the source, not a dynamic
   test. Issuing a witness, proving and the preimage sampler run in time, and touch memory, in
   ways that depend on the trapdoor, the witness and the prover's inputs.

3. **The preimage sampler's floating-point loss is measured, not proven.** The sampler of
   ePrint 2017/308 uses `f64`. That paper's analysis assumes a 64-bit mantissa where `f64` has
   53, and gives no floating-point analysis of its perturbation sampler. The crate refuses a
   trapdoor whose perturbation pivots fall below a floor, and its tests measure the error of
   the computed centres. That is evidence, not a bound. If the sampler's output distribution
   were further from the ideal than measured, witnesses could leak information about the
   trapdoor.

4. **Determinism across platforms is assumed.** The same element must give the same sampled
   preimage on every machine. That holds for IEEE-754 binary64 arithmetic without x87
   extended precision. On a platform where it failed, a manager moved between machines could
   issue two different witnesses for one element. The same holds across versions of this
   crate: a key has one preimage per element only while the sampler, the PRF label and the
   key derivations produce the same bits. Nothing in a key records the version that made it.
   The test suites pin the witness bytes for a fixed key in all three variants, so a change
   that moves them fails a test; such a change must not be used with existing keys.

5. **Fiat–Shamir concrete security is cited, not derived.** The proofs are interactive in the
   paper and made non-interactive here. No bound for that transform is computed. The paper
   defers it to the work it cites titled "Aggregating falcon signatures with labrador" (CRYPTO
   2024), and so does this crate.

6. **Module-SIS ranks in the proof layers come from a rule of thumb.** They are chosen by a
   root-Hermite-factor rule (`δ < 1.0044`), not by the paper's Core-SVP estimate, and the two
   have not been shown to agree.

7. **Membership proofs run only where the accumulator ring has degree 64**, that is at the toy
   sets, which give no security. The map that would carry the 128-bit statement into the proof
   ring is built and tested but not wired into the proof. So there is, today, no parameter set
   at which this crate gives both a secure accumulator and a membership proof for it.

8. **The manager-state tag does not stop rollback** to an older state the key once tagged.
   Rollback no longer leaks the key, since witnesses do not depend on the history; but an old
   state still issues witnesses for the old value, and a manager running two states publishes
   two histories.

9. **Proof values are not bit-packed.** They are encoded at 24 bytes per coefficient, so the
   proof sizes the crate reports overstate what a packed encoding would need. This is about
   size, not security.

10. **The toy sets give no security.** Nothing in the code stops you from using them.

## What this means for an integrator

- You can run a complete manager, holder and verifier flow *without proofs* at
  `ParamsSpec::PAPER_128`, and study its costs.
- You can run the proof flow at the toy sets, and study its API and its costs.
- You cannot, with this crate as it stands, deploy a system in which a holder proves
  membership in zero knowledge at a secure parameter set.
- Whatever you run, every item above applies.
