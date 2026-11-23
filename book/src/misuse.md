# Misuse: what the code refuses and what it leaves to you

> **In short.** Every way the API can be used wrongly, and for each whether the crate refuses
> it or leaves it to you, with an example. Avoiding every misuse listed here does not make the
> crate safe to deploy: it is research code, it has not been audited, and its toy settings
> protect nothing.
>
> **Read this when** you review an integration, or want to know whether a particular mistake is
> caught.
>
> **New here?** Read [The rules that keep you safe](rules.md) first; it covers the cases left
> to you in plain words. Then use the table here to look up one mistake, and the
> [checklist](#a-checklist-for-deploying) at the end before you run the crate for evaluation.

This chapter lists the ways the API can be used wrongly. For each it says whether the code
refuses the misuse or whether preventing it is your responsibility, and why it matters.

Every row marked **refused** is backed by an example in this book that performs the misuse and
asserts the refusal. The examples are run by the crate's test suite. Rows marked **your
responsibility** are things the code does not, or cannot, stop. Several of those have an
example too, showing that the misuse goes through.

"Refused" means the operation returns the named `Error` variant, or `false`, and changes
nothing; or that the program does not compile.

## The table

### Running a manager

| # | misuse | outcome | why it matters | shown in |
|---|---|---|---|---|
| 1 | adding an element twice | **refused**: `Error::ElementAlreadyAdded` | the record would count one element twice; in the paper's scheme the second addition samples a second witness, which leaks the trapdoor | [A](#a-manager-operations) |
| 2 | re-adding a deleted element in Construction 4.1 | **refused**: `Error::ElementAlreadyAdded` | the scheme is [replacement-free](glossary.md#replacement-free) (Remark 4.2), which its security theorem assumes; a deleted element stays revoked | [A](#a-manager-operations) |
| 3 | deleting an element that is not present | **refused**: `Error::ElementNotPresent` | the value would move for nothing and holders would chase a deletion that never was | [A](#a-manager-operations) |
| 4 | more than [`γ`](glossary.md#deletion-bound) deletions | **refused**: `Error::DeletionBoundReached` | beyond `γ` updated witnesses can exceed the norm bound and stop verifying | [A](#a-manager-operations) |
| 5 | more than `2^ℓ` additions in the adaptive variant | **refused**: `Error::HandleSpaceExhausted` | a handle would have to be reused, which is a re-addition in the inner accumulator | [adaptive](adaptive.md#adaptiveaccumulator) |
| 6 | a manager state altered in storage | **refused**: `Error::InvalidStateTag`, or `Error::InconsistentState` at deserialization | a forged history would decide which witnesses are issued, against which value, and how many deletions are left | [B](#b-manager-state) |
| 7 | a manager state tagged by another key | **refused**: `Error::InvalidStateTag` | the same. Another key includes the Construction 4.1 key that the bytes of a succinct key's base key decode to | [B](#b-manager-state), [succinct](succinct.md#what-stays-the-same) |
| 8 | [rolling](glossary.md#rollback) the manager state back to an older copy | **your responsibility**: not detected. It cannot leak the key: an older state reproduces the same witnesses for the same deletions | the old state issues witnesses for the old value, and moving it on publishes a second history that holders of the first cannot follow | [N1](#n1-rollback-and-forks-reproduce-the-same-witnesses) |
| 9 | two managers running on one key | **your responsibility**: not detected. It cannot leak the key either | two managers publish two histories, two current values | [N1](#n1-rollback-and-forks-reproduce-the-same-witnesses) |
| 10 | losing the state and starting a fresh one for a live accumulator | **refused** with the live value once a deletion has been made: a fresh state is at the key's genesis value, so `Error::AccumulatorMismatch`. Before the first deletion the live value is the genesis value, so a fresh state is accepted and has forgotten who was added (policy, not safety). A fresh state moved on through the same deletions, or one rebuilt from the published log with `ManagerState::rebuild`, issues the same witnesses as the lost one. **Your responsibility**: the member list a rebuild takes | a wrong member list makes the manager issue a witness it should not, or refuse one; it cannot leak the key | [N2](#n2-a-lost-state-is-rebuilt-from-the-log) |
| 11 | calling `add`, `remove` or `update` on a value that is not the state's current value | **refused**: `Error::AccumulatorMismatch` | the state would record a deletion that was never published and lose the real value | [H](#h-a-value-that-is-not-current) |
| 12 | issuing a witness for an absent or deleted element | **refused**: `Error::ElementNotPresent` | it would be a forgery made by the manager itself | [C](#c-witnesses) |
| 13 | issuing a witness against a value that is not current | **refused**: `Error::AccumulatorMismatch` | the witness would not verify for anyone | [C](#c-witnesses) |
| 14 | a short, guessable or reused key seed | **refused** when shorter than 32 bytes, empty included: `Error::SeedTooShort`. **Your responsibility**: a guessable seed of 32 bytes or more, and one seed for two keys of the same set, which are then one key. Reusing a seed under another parameter set is harmless: the keys are unrelated | the key is a function of the seed and the set; whoever guesses the seed has the key | [I](#i-key-seeds) |
| 15 | cloning or copying a secret key | **refused**: does not compile | every copy is one more place to leak from and to forget to wipe | [D](#d-secret-keys) |
| 16 | printing a secret key | **refused**: `Debug` prints `SecretKey { .. }`; there is no `Display` | logs outlive processes | [D](#d-secret-keys) |
| 17 | leaving a serialized secret key or witness in a plain buffer | **your responsibility** | the crate cannot wipe a serializer's output | [serialization](serialization.md#secrets-and-serializers) |
| 18 | hashing identifiers to elements and ignoring collisions | **your responsibility**: a collision looks like `Error::ElementAlreadyAdded` | two credentials share one element, one witness and one revocation | [elements](elements.md#element) |
| 19 | publishing before the new state is durable | **your responsibility** | a crash then restarts from an older state, which issues witnesses for an old value; rebuild from the published log instead | [checklist](#a-checklist-for-deploying) |
| 20 | publishing the public key, values or update messages without authentication | **your responsibility** | holders and verifiers act on whatever they receive | [checklist](#a-checklist-for-deploying) |
| 21 | calling the preimage samplers directly with two seeds for one target | **your responsibility**: not detected | two short preimages of one target reveal a short kernel vector. One seed for two targets or two matrices is not this mistake: the sampler binds the seed to both | [lattice](lattice.md#trapdoor) |
| 22 | a succinct key at a set whose modulus is too small | **refused**: `Error::WitnessBoundTooLarge` | witnesses would not be determined by their residues | [succinct](succinct.md#succinctsecretkey) |
| 23 | using a toy parameter set for something real | **your responsibility**: not refused | the toy sets give no security | [N3](#n3-the-toy-set-is-not-refused) |
| 24 | letting an attacker time the manager | **your responsibility**: not prevented | only a few steps, such as the trapdoor's draws at key generation, are written to be constant time; issuing a witness and proving are not ([Timing](security.md#timing-what-is-and-is-not-constant-time)) | none: no example can show an absence |

### Parameter sets and encodings

| # | misuse | outcome | why it matters | shown in |
|---|---|---|---|---|
| 25 | mixing values of two parameter sets | **refused**: `Error::ParameterMismatch`, or `false` from `verify` | the arithmetic would be meaningless, and silently so | [E](#e-parameter-sets-and-encodings) |
| 26 | mixing values of the two [trapdoor distributions](glossary.md#trapdoor-distribution) | **refused**: `Error::ParameterMismatch` | they are different sets with different assumptions | [E](#e-parameter-sets-and-encodings) |
| 27 | a truncated encoding, or one with trailing bytes | **refused**: `Error::InvalidEncodingLength` | a value must have one encoding | [E](#e-parameter-sets-and-encodings) |
| 28 | non-zero padding or reserved bytes | **refused**: `Error::NonCanonicalEncoding` | the same; encodings are hashed into digests and tags | [E](#e-parameter-sets-and-encodings) |
| 29 | a coefficient that is not reduced modulo `q` | **refused**: `Error::CoefficientOutOfRange` | unreduced values break the arithmetic's preconditions | [E](#e-parameter-sets-and-encodings) |
| 30 | an unknown trapdoor distribution byte | **refused**: `Error::InvalidTrapdoorDistribution` | the set would be undefined | [E](#e-parameter-sets-and-encodings) |
| 31 | an element that does not fit the set | **refused**: `Error::InvalidElement` | bits beyond `ℓ` would be silently ignored | [E](#e-parameter-sets-and-encodings) |
| 32 | accepting a well-formed value of a set you did not expect | **your responsibility**: decoding accepts any valid set | a public key at the toy set decodes as well as one at the 128-bit set | [E](#e-parameter-sets-and-encodings) |
| 33 | using a decoded `Poly`, `PolyVec` or `PolyMatrix` without `validate` | **your responsibility** in your own code; the accumulator and proof operations validate their inputs | these types carry no parameters | [serialization](serialization.md#values-that-are-not-checked-at-decoding) |
| 59 | decoding a value whose parameter set is beyond the caps: `d` above `ParamsSpec::MAX_DEGREE`, or more than `ParamsSpec::MAX_MATRIX_ENTRIES` polynomials in `[A \| B]` | **refused**: `Error::DegreeTooLarge` or `Error::WitnessBoundTooLarge`, before any table is built | a few bytes naming a huge set would otherwise cost memory and time in proportion to the set | [E](#e-parameter-sets-and-encodings) |

### Holding a witness

| # | misuse | outcome | why it matters | shown in |
|---|---|---|---|---|
| 34 | a witness whose norm exceeds the [bound](glossary.md#norm-bound) | **refused**: `false` from `verify`; `Error::CoefficientOverBound` from encoding and decoding | without the norm check any solution of the linear equation would pass, and those are easy to find | [C](#c-witnesses) |
| 35 | a witness for a deleted element | **refused**: `false` from `verify`; `Error::ElementDeleted` from every update | this is what revocation is | [C](#c-witnesses) |
| 36 | a witness presented for another element | **refused**: `false` from `verify`; `Error::InvalidSignature` in the adaptive variant's updates | a witness is for one element only | [C](#c-witnesses), [adaptive](adaptive.md#adaptivemembershipwitness) |
| 37 | update messages that do not match the deletions | **refused**: `Error::CoefficientMismatch` | the holder would apply a correction for the wrong elements | [C](#c-witnesses) |
| 38 | `update` with a wrong old or new value | **refused**: `Error::AccumulatorMismatch` | the result would not verify | [C](#c-witnesses) |
| 39 | skipping a batch, or applying one twice, with `batch_update` or `apply_delta` | **your responsibility**: the update succeeds; the result does not verify | a holder that does not check presents a dead witness | [witnesses](witnesses.md#membershipwitness) |
| 40 | passing a witness of one variant where another is expected | **refused**: does not compile | the variants have different equations | [succinct](succinct.md#succinctmembershipwitness) |
| 41 | disclosing a witness, an element or `r` | **your responsibility** | a witness with its element is a [bearer secret](glossary.md#bearer-secret) | [checklist](#a-checklist-for-deploying) |

### Proving and verifying

| # | misuse | outcome | why it matters | shown in |
|---|---|---|---|---|
| 42 | proving with an element that is not binary | **refused**: does not compile; an `Element` is a bit string | the relation is only sound for binary `x` | [F](#f-proofs-the-prover) |
| 43 | proving with an `r` that is not binary | **refused**: `Error::RelationUnsatisfied` | the same, for `r` | [F](#f-proofs-the-prover) |
| 44 | proving with a witness that does not fit the element, the value or the relation | **refused**: `Error::RelationUnsatisfied` | the prover would run for seconds and produce a proof that cannot verify | [F](#f-proofs-the-prover) |
| 45 | proving at a parameter set of ring degree other than 64 | **refused**: `Error::UnsupportedProofDegree` | the proof is not implemented there | [F](#f-proofs-the-prover) |
| 46 | verifying under a different [transcript](glossary.md#transcript) label or context | **refused**: `Error::ProofRejected` | this is what stops replay across protocols and sessions | [G](#g-proofs-the-verifier) |
| 47 | verifying against a different accumulator value or linking relation | **refused**: `Error::ProofRejected` | a proof is for one statement | [G](#g-proofs-the-verifier) |
| 48 | verifying under a different public key | **refused**: `Error::ProofRejected` | the same | [G](#g-proofs-the-verifier) |
| 49 | verifying under different proof parameters | **refused**: `Error::ProofRejected` | the commitment key differs | [G](#g-proofs-the-verifier) |
| 50 | a proof altered in transit | **refused**: `Error::ProofRejected` | | [G](#g-proofs-the-verifier) |
| 51 | a truncated proof encoding | **refused**: `Error::InvalidEncodingLength` | | [G](#g-proofs-the-verifier) |
| 52 | three-step form: a proof checked for a challenge it was not made for | **refused**: `Error::ProofRejected` | a proof is valid for exactly one challenge | [proofs](proofs.md#two-forms) |
| 53 | three-step form: not rederiving the challenge and comparing it | **your responsibility** | `finalize` checks the proof for the challenge you hand it; only the comparison ties it to your session | [proofs](proofs.md#two-forms) |
| 54 | putting no session context (nonce) into the transcript | **your responsibility** | a proof can then be replayed to another verifier | [proofs](proofs.md#transcripts-what-to-bind) |
| 55 | verifying against an accumulator value that is not current | **your responsibility** | a revoked holder still proves membership in the old set | [checklist](#a-checklist-for-deploying) |
| 56 | a linking relation that does not bind `x` to anything | **your responsibility** | the proof then says only that the prover knows *some* member | [proofs](proofs.md#why-there-is-a-linking-relation) |
| 57 | zero or more than eight compression levels | **refused**: `Error::InvalidCompressionLevels` | | [proofs](proofs.md#compressionlevels) |
| 58 | acting on a proof that was decoded but not verified | **your responsibility** | decoding checks layout only | [proofs](proofs.md#membershipproof) |

## Examples of refusals

### A. Manager operations

Rows 1 to 4.

```rust
use kln_accumulator::{Accumulator, Element, Error, Params, ParamsSpec, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
// The toy shape with a deletion bound of 2, so that the bound is reached quickly.
let params = Arc::new(Params::try_from(ParamsSpec { max_deletions: 2, ..ParamsSpec::TOY })?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let element = |i: u8| Element::try_from(&[i][..]);
let (a, b, c, d) = (element(1)?, element(2)?, element(3)?, element(4)?);
let members = [a.clone(), b.clone(), c.clone()];
let (mut acc, mut state) = Accumulator::with_elements(&key, &members)?;

// Row 1: adding twice.
assert!(matches!(acc.add_assign(&key, &a, &mut state), Err(Error::ElementAlreadyAdded)));
// Row 3: deleting an element that is not present.
assert!(matches!(acc.remove_assign(&key, &d, &mut state), Err(Error::ElementNotPresent)));
// Row 2: re-adding a deleted element.
acc.remove_assign(&key, &a, &mut state)?;
assert!(matches!(acc.add_assign(&key, &a, &mut state), Err(Error::ElementAlreadyAdded)));
// Row 4: the third deletion at γ = 2.
acc.remove_assign(&key, &b, &mut state)?;
assert!(matches!(acc.remove_assign(&key, &c, &mut state), Err(Error::DeletionBoundReached)));
# Ok::<(), kln_accumulator::Error>(())
```

### B. Manager state

Rows 6 and 7.

```rust
use kln_accumulator::{Accumulator, Element, Error, ManagerState, MembershipWitness, Params};
use kln_accumulator::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::clone(&params), &mut rng)?;
let other = SecretKey::new(Some(b"someone else's seed, 32 bytes long"), Arc::clone(&params), &mut rng)?;
let element = |name: &[u8]| Element::hash(name, &params);
let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
acc.remove_assign(&key, &y, &mut state)?;

// Row 7: a state that another key tagged.
let mut foreign = ManagerState::new(&other);
assert!(matches!(acc.add_assign(&key, &z, &mut foreign), Err(Error::InvalidStateTag)));

// Row 6: a stored state with x's addition epoch changed from 0 to 1. It still describes a
// possible history, so it loads; the tag refuses it at the first keyed use.
let stored = serde_json::to_string(&state)?;
let altered = stored.replace(r#""operation":"Add","epoch":0"#, r#""operation":"Add","epoch":1"#);
assert_ne!(altered, stored);
let mut tampered: ManagerState = serde_json::from_str(&altered)?;
assert!(matches!(
    MembershipWitness::new(&x, &acc, &key, &tampered),
    Err(Error::InvalidStateTag)
));
assert!(matches!(acc.add_assign(&key, &z, &mut tampered), Err(Error::InvalidStateTag)));
assert!(matches!(acc.remove_assign(&key, &x, &mut tampered), Err(Error::InvalidStateTag)));

// Row 6, second form: a stored state with an impossible history is refused when it is loaded.
let impossible = stored.replace(r#""counter":1"#, r#""counter":0"#);
assert_ne!(impossible, stored);
let refused = serde_json::from_str::<ManagerState>(&impossible).map(drop);
let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
assert!(message.contains(&Error::InconsistentState.to_string()));

// The tag check on its own, as a manager runs it on a state it has just loaded.
assert_eq!(tampered.authenticate(&key), Err(Error::InvalidStateTag));
assert_eq!(foreign.authenticate(&key), Err(Error::InvalidStateTag));
state.authenticate(&key)?;

// The honest state still works.
assert!(acc.add_assign(&key, &z, &mut state).is_ok());
# Ok::<(), Box<dyn std::error::Error>>(())
```

### C. Witnesses

Rows 12, 13 and 34 to 38.

```rust
use kln_accumulator::{Accumulator, Element, Error, MembershipWitness, Params};
use kln_accumulator::lattice::{Poly, PolyVec};
use kln_accumulator::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
let element = |name: &[u8]| Element::hash(name, &params);
let (x, y, never) = (element(b"x"), element(b"y"), element(b"never added"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let for_x = MembershipWitness::new(&x, &acc, &key, &state)?;
let for_y = MembershipWitness::new(&y, &acc, &key, &state)?;
let old = acc.clone();
let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

// Row 12: issuing for an element that was never added, and for one that was deleted.
assert!(matches!(
    MembershipWitness::new(&never, &acc, &key, &state),
    Err(Error::ElementNotPresent)
));
assert!(matches!(MembershipWitness::new(&y, &acc, &key, &state), Err(Error::ElementNotPresent)));

// Row 13: issuing against the value from before the deletion.
assert!(matches!(
    MembershipWitness::new(&x, &old, &key, &state),
    Err(Error::AccumulatorMismatch)
));

// Row 35: the deleted element's witness is dead.
assert!(!for_y.verify(&y, &pk, &acc));
assert!(matches!(
    for_y.batch_update(&y, &[], &[y.clone()], &coefficients, &pk),
    Err(Error::ElementDeleted)
));
assert!(matches!(
    for_y.update(&y, &old, &acc, &[], &[y.clone()], &pk),
    Err(Error::ElementDeleted)
));

// Row 36: a witness presented for another element.
let current = for_x.batch_update(&x, &[], &[y.clone()], &coefficients, &pk)?;
assert!(current.verify(&x, &pk, &acc));
assert!(!current.verify(&never, &pk, &acc));

// Row 37: update messages that do not match the deletions.
assert!(matches!(
    for_x.batch_update(&x, &[], &[y.clone()], &[], &pk),
    Err(Error::CoefficientMismatch)
));

// Row 38: update() told the wrong old value.
assert!(matches!(
    for_x.update(&x, &acc, &acc, &[], &[y.clone()], &pk),
    Err(Error::AccumulatorMismatch)
));

// Row 34: a vector that is far too long. It is a well-formed vector of the right shape, but it
// does not verify and has no encoding.
let quarter = params.ring().modulus().wrapping_shr_vartime(2);
let entry = Poly::new(vec![quarter; params.ring().degree()], params.ring())?;
let long = MembershipWitness::from_vector(PolyVec::from(vec![entry; 100]), &params)?;
assert!(!long.verify(&x, &pk, &acc));
assert!(matches!(long.to_bytes(), Err(Error::CoefficientOverBound)));
// And a stored witness with a coefficient pushed over the bound does not decode.
let mut bytes = current.to_bytes()?.to_vec();
bytes[64..70].fill(0xff);
assert!(matches!(
    MembershipWitness::try_from(bytes.as_slice()),
    Err(Error::CoefficientOverBound)
));
# Ok::<(), kln_accumulator::Error>(())
```

### D. Secret keys

Rows 15 and 16. A secret key cannot be cloned:

```rust,compile_fail
use kln_accumulator::{Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let second = key.clone(); // error[E0599]: no method named `clone` found for struct `SecretKey`
# Ok::<(), kln_accumulator::Error>(())
```

It cannot be copied; using it after a move is an error:

```rust,compile_fail
use kln_accumulator::{Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let moved = key;
let again = key; // error[E0382]: use of moved value: `key`
# Ok::<(), kln_accumulator::Error>(())
```

It has no `Display`:

```rust,compile_fail
use kln_accumulator::{Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let text = format!("{key}"); // error[E0277]: `SecretKey` doesn't implement `std::fmt::Display`
# Ok::<(), kln_accumulator::Error>(())
```

And `Debug` prints nothing of it, for all three variants and for a witness:

```rust
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, SecretKey, adaptive};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let seed_hex = hex::encode(&key.to_bytes()[64..]);
let printed = format!("{key:?}");
assert_eq!(printed, "SecretKey { .. }");
assert!(!printed.contains(&seed_hex));

let adaptive_key = adaptive::SecretKey::new(None, Arc::clone(&params), &mut rng)?;
assert_eq!(format!("{adaptive_key:?}"), "SecretKey { .. }");

// A witness prints its parameter set and no coefficient.
let x = Element::hash(b"x", &params);
let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
let printed = format!("{witness:?}");
assert!(printed.starts_with("MembershipWitness { params:"));
assert!(printed.ends_with(".. }"));
# Ok::<(), kln_accumulator::Error>(())
```

### E. Parameter sets and encodings

Rows 25 to 32, and 59.

```rust
use kln_accumulator::{Accumulator, Element, Error, ManagerState, MembershipWitness, Params};
use kln_accumulator::{ParamsSpec, PublicKey, SecretKey, TrapdoorDistribution};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let gaussian = Arc::new(Params::toy()?);
let ternary = Arc::new(Params::try_from(
    ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary),
)?);
let other_shape = Arc::new(Params::succinct_toy()?);

// One manager per set.
let key = SecretKey::new(None, Arc::clone(&gaussian), &mut rng)?;
let pk = PublicKey::from(&key);
let x = Element::hash(b"x", &gaussian);
let (acc, state) = Accumulator::with_elements(&key, &[x.clone()])?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
let key_t = SecretKey::new(None, Arc::clone(&ternary), &mut rng)?;
let pk_t = PublicKey::from(&key_t);
let key_s = SecretKey::new(None, Arc::clone(&other_shape), &mut rng)?;
let pk_s = PublicKey::from(&key_s);

// Row 26: a Gaussian-set value with a ternary-set key; a Gaussian-set witness under a
// ternary-set public key.
let mut state_t = ManagerState::new(&key_t);
let mut value = acc.clone();
assert!(matches!(value.add_assign(&key_t, &x, &mut state_t), Err(Error::ParameterMismatch)));
// The Gaussian manager's own state is refused by the ternary key even earlier, at the tag.
assert!(matches!(value.add_assign(&key_t, &x, &mut state.clone()), Err(Error::InvalidStateTag)));
assert!(!witness.verify(&x, &pk_t, &acc));
assert!(matches!(acc.validate(&ternary), Err(Error::ParameterMismatch)));
assert!(matches!(witness.validate(&ternary), Err(Error::ParameterMismatch)));

// Row 25: the same with a set of another shape.
let mut state_s = ManagerState::new(&key_s);
assert!(matches!(value.add_assign(&key_s, &x, &mut state_s), Err(Error::ParameterMismatch)));
assert!(!witness.verify(&x, &pk_s, &acc));
assert!(matches!(
    MembershipWitness::new(&x, &acc, &key_s, &state_s),
    Err(Error::ParameterMismatch | Error::InvalidElement)
));

// Row 31: an element with a bit set beyond ℓ = 4 of the other set.
let high = Element::try_from(&[0b1000_0000u8][..])?;
assert!(matches!(high.validate(&other_shape), Err(Error::InvalidElement)));
let mut value_s = Accumulator::new(&key_s);
let mut state_s = ManagerState::new(&key_s);
assert!(matches!(value_s.add_assign(&key_s, &high, &mut state_s), Err(Error::InvalidElement)));

// Rows 27 to 30: malformed encodings of an accumulator value.
let bytes = acc.to_bytes();
let decode = |bytes: &[u8]| Accumulator::try_from(bytes).map(drop);
assert!(matches!(decode(&bytes[..bytes.len() - 1]), Err(Error::InvalidEncodingLength(_))));
let mut trailing = bytes.clone();
trailing.push(0);
assert!(matches!(decode(&trailing), Err(Error::InvalidEncodingLength(_))));
let mut reserved = bytes.clone();
reserved[5] = 1;
assert!(matches!(decode(&reserved), Err(Error::NonCanonicalEncoding)));
let mut unreduced = bytes.clone();
unreduced[64..72].fill(0xff);
assert!(matches!(decode(&unreduced), Err(Error::CoefficientOutOfRange)));
let mut unknown = bytes.clone();
unknown[4] = 7;
assert!(matches!(decode(&unknown), Err(Error::InvalidTrapdoorDistribution(7))));

// The same for a public key and a witness.
let pk_bytes = pk.to_bytes();
assert!(matches!(
    PublicKey::try_from(&pk_bytes[..pk_bytes.len() - 1]),
    Err(Error::InvalidEncodingLength(_))
));
let witness_bytes = witness.to_bytes()?;
assert!(matches!(
    MembershipWitness::try_from(&witness_bytes[..witness_bytes.len() - 1]),
    Err(Error::InvalidEncodingLength(_))
));

// Row 59: 65 bytes naming a degree above the cap, refused before any table is built; and a
// set whose [A | B] would be too large.
let wide = ParamsSpec { degree: ParamsSpec::MAX_DEGREE * 2, ..ParamsSpec::TOY };
let mut huge = <[u8; ParamsSpec::BYTES]>::from(wide).to_vec();
huge.push(0);
assert!(matches!(decode(&huge), Err(Error::DegreeTooLarge(_))));
let long = ParamsSpec { element_bits: 1 << 13, ..ParamsSpec::TOY };
assert!(matches!(Params::try_from(long), Err(Error::WitnessBoundTooLarge)));

// Row 32, NOT refused: a well-formed public key of another set decodes. Compare the set.
let decoded = PublicKey::try_from(pk_t.to_bytes().as_slice())?;
assert_ne!(decoded.params().spec(), &ParamsSpec::TOY);
# Ok::<(), kln_accumulator::Error>(())
```

### F. Proofs: the prover

Rows 42 to 45. These refusals happen before any proving work is done, so the example is
cheap.

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
use kln_accumulator::{Error, LnpParameters, MembershipSecret, MembershipStatement, prove};
use merlin::Transcript;

let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
let mut attempt = |statement: &MembershipStatement<'_>, element: &Element, r: &PolyVec| {
    let secret = MembershipSecret { element, witness: &witness, r };
    prove(statement, &secret, &proof_params, &mut Transcript::new(b"demo"), &mut rng).map(drop)
};

// Row 44: a witness that is not for the element.
let y = Element::hash(b"y", &params);
assert_eq!(attempt(&statement, &y, &r), Err(Error::RelationUnsatisfied));

// Row 44: a binary r that does not satisfy the linking relation.
let zero = PolyVec::from(vec![constant(false)?]);
assert_eq!(attempt(&statement, &x, &zero), Err(Error::RelationUnsatisfied));

// Row 44: a statement about another accumulator value.
let elsewhere = Accumulator::random(&mut StdRng::seed_from_u64(9), &params);
let wrong_value = MembershipStatement { pubkey: &pk, accumulator: &elsewhere, relation: &relation };
assert_eq!(attempt(&wrong_value, &x, &r), Err(Error::RelationUnsatisfied));

// Row 43: an r that is not binary. The relation is rebuilt so that A₁·x + A₂·r = t does hold;
// the prover refuses all the same.
let two = PolyVec::from(vec![constant(true)?.mul_small(2, ring)?]);
let t = relation.a1().mul_vec(&bits, ring)?.add(&relation.a2().mul_vec(&two, ring)?, ring)?;
let matching = LinkingRelation::new(relation.a1().clone(), relation.a2().clone(), t)?;
let non_binary = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &matching };
assert_eq!(attempt(&non_binary, &x, &two), Err(Error::RelationUnsatisfied));

// Row 45: the 128-bit set has ring degree 4096.
let refused = LnpParameters::new(&Params::paper_128()?, 1);
assert_eq!(refused.map(drop), Err(Error::UnsupportedProofDegree(4096)));
# Ok::<(), kln_accumulator::Error>(())
```

Row 42. The element of a proof is an `Element`, a string of bits. There is no way to hand the
prover a value with other coefficients:

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

let not_bits: Poly = sampler.poly(ring);
// error[E0308]: mismatched types: expected `&Element`, found `&Poly`
let secret = MembershipSecret { element: &not_bits, witness: &witness, r: &r };
# Ok::<(), kln_accumulator::Error>(())
```

The verifier also rejects a non-binary element when the prover's check is bypassed. That
cannot be shown through the public API; the crate's own tests cover it.

### G. Proofs: the verifier

Rows 46 to 51. This example makes one real proof and then checks it six wrong ways. It is the
second of the two examples in this book that really proves, so it costs one proof and several
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
use kln_accumulator::{Error, MembershipProof, MembershipSecret, MembershipStatement, prove, verify};
use merlin::Transcript;

let statement = MembershipStatement { pubkey: &pk, accumulator: &acc, relation: &relation };
let secret = MembershipSecret { element: &x, witness: &witness, r: &r };
let session = |label: &'static [u8], nonce: &[u8]| {
    let mut transcript = Transcript::new(label);
    transcript.append_message(b"verifier nonce", nonce);
    transcript
};

let proof = prove(&statement, &secret, &proof_params, &mut session(b"protocol v1", b"n1"), &mut rng)?;

// The honest check passes.
verify(&statement, &proof, &proof_params, &mut session(b"protocol v1", b"n1"))?;

// Row 46: another transcript label, and another session nonce.
let rejected = Err(Error::ProofRejected);
assert_eq!(verify(&statement, &proof, &proof_params, &mut session(b"protocol v2", b"n1")), rejected);
assert_eq!(verify(&statement, &proof, &proof_params, &mut session(b"protocol v1", b"n2")), rejected);

// Row 47: another accumulator value.
let elsewhere = Accumulator::random(&mut rng, &params);
let moved = MembershipStatement { pubkey: &pk, accumulator: &elsewhere, relation: &relation };
assert_eq!(verify(&moved, &proof, &proof_params, &mut session(b"protocol v1", b"n1")), rejected);

// Row 48: another public key.
let other_key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let other_pk = PublicKey::from(&other_key);
let foreign = MembershipStatement { pubkey: &other_pk, accumulator: &acc, relation: &relation };
assert_eq!(verify(&foreign, &proof, &proof_params, &mut session(b"protocol v1", b"n1")), rejected);

// Row 49: other proof parameters.
let other_params = ProofParams::new(&pk, Some(b"another deployment"))?;
assert_eq!(verify(&statement, &proof, &other_params, &mut session(b"protocol v1", b"n1")), rejected);

// Row 50: one bit of the encoded proof flipped.
let mut bytes = proof.to_bytes();
let last = bytes.len() - 1;
bytes[last] ^= 1;
let altered = MembershipProof::try_from(bytes.as_slice())?;
assert_eq!(verify(&statement, &altered, &proof_params, &mut session(b"protocol v1", b"n1")), rejected);

// Row 51: the encoding cut short.
assert!(matches!(
    MembershipProof::try_from(&bytes[..last]),
    Err(Error::InvalidEncodingLength(_))
));
# Ok::<(), kln_accumulator::Error>(())
```

### H. A value that is not current

Row 11. The state records the accumulator value the last keyed operation left. Every keyed
operation checks, right after the tag, that the value it is called on is that one, and refuses
any other value with `Error::AccumulatorMismatch`, changing nothing: an unrelated value of the
same set, or an earlier value of the same accumulator.

```rust
use kln_accumulator::{Accumulator, Element, Error, MembershipWitness, Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let element = |name: &[u8]| Element::hash(name, &params);
let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
let before = state.clone();

// An unrelated value of the same parameter set, used with the real state: add, remove and
// update are all refused, and neither the value nor the state changes.
let mut unrelated = Accumulator::random(&mut rng, &params);
let kept = unrelated.clone();
let refused = Err(Error::AccumulatorMismatch);
assert_eq!(unrelated.add(&key, &z, &mut state).map(drop), refused);
assert_eq!(unrelated.remove_assign(&key, &y, &mut state), refused);
assert_eq!(unrelated.update(&key, &[z.clone()], &[y.clone()], &mut state).map(drop), refused);
assert_eq!((&unrelated, &state), (&kept, &before));

// An earlier value of the same accumulator, after a deletion moved it: refused as well.
let stale = acc.clone();
acc.remove_assign(&key, &y, &mut state)?;
let mut old = stale.clone();
assert_eq!(old.add_assign(&key, &z, &mut state), refused);
assert_eq!(MembershipWitness::new(&x, &stale, &key, &state).map(drop), refused);

// The state names the value it belongs to, and that value works.
assert_eq!(state.current(), &acc);
assert!(MembershipWitness::new(&x, &acc, &key, &state).is_ok());
# Ok::<(), kln_accumulator::Error>(())
```

### I. Key seeds

Row 14. A caller's seed shorter than `MIN_SEED_BYTES`, 32 bytes, is refused with
`Error::SeedTooShort`, carrying the length given, in all three variants. Every value of a key
is derived from the root seed together with the encoded parameter set, so one seed under two
sets gives two unrelated keys, and neither accepts a state the other tagged. What the code
cannot refuse is a seed of 32 bytes or more that someone can guess, or one seed used for two
keys of the same set: those are the same key, as the last lines show.

```rust
use kln_accumulator::{Accumulator, Error, MIN_SEED_BYTES, ManagerState, Params, ParamsSpec};
use kln_accumulator::{PublicKey, SecretKey, TrapdoorDistribution, adaptive, succinct};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(1);
let params = Arc::new(Params::toy()?);

// An empty seed, and a seed one byte short, in every variant. Refused before any work.
let empty = SecretKey::new(Some(b""), Arc::clone(&params), &mut rng);
assert_eq!(empty.map(drop), Err(Error::SeedTooShort(0)));
let short = [9u8; MIN_SEED_BYTES - 1];
let base = SecretKey::new(Some(&short), Arc::clone(&params), &mut rng);
assert_eq!(base.map(drop), Err(Error::SeedTooShort(31)));
let adaptive = adaptive::SecretKey::new(Some(&short), Arc::clone(&params), &mut rng);
assert_eq!(adaptive.map(drop), Err(Error::SeedTooShort(31)));
let succinct = succinct::SecretKey::new(Some(&short), Arc::new(Params::succinct_toy()?), &mut rng);
assert_eq!(succinct.map(drop), Err(Error::SeedTooShort(31)));

// One seed under the Gaussian and the ternary toy sets: unrelated keys. A state tagged by one
// fails the other's tag check.
let seed = [9u8; MIN_SEED_BYTES];
let ternary = Arc::new(Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))?);
let gaussian_key = SecretKey::new(Some(&seed), Arc::clone(&params), &mut rng)?;
let ternary_key = SecretKey::new(Some(&seed), Arc::clone(&ternary), &mut rng)?;
assert_ne!(PublicKey::from(&gaussian_key).a(), PublicKey::from(&ternary_key).a());
let state = ManagerState::new(&gaussian_key);
assert_eq!(state.authenticate(&ternary_key), Err(Error::InvalidStateTag));

// NOT refused: the same seed under the same set is the same key, whatever the generator holds.
let again = SecretKey::new(Some(&seed), Arc::clone(&params), &mut StdRng::seed_from_u64(2))?;
assert_eq!(again, gaussian_key);
# Ok::<(), kln_accumulator::Error>(())
```

What to do: pass `None` and a generator seeded from the operating system, or pass 32 bytes
from one. Never derive two keys of one set from one seed.

## Examples of what is not refused

These examples run, and they assert what the code lets through. They are here so that what
remains your job is concrete.

### N1. Rollback and forks reproduce the same witnesses

Rows 8 and 9. The manager has a state with one member, `y`. From that state two things happen
in two different orders. On one path `z` is added and then `y` is deleted. On the other, which
starts from a copy of the old state, `y` is deleted and then `z` is added. Nothing refuses the
old copy: a restored backup, a crash after publishing and two processes sharing one key are all
this picture. Both paths end at the same accumulator value, and they issue the *same* witness
for `z`: a witness is sampled for the key's genesis value and corrected for the set of
deletions, so neither the order nor the copy enters.

```rust
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey};
use kln_accumulator::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
let (x, y, z) = (Element::hash(b"x", &params), Element::hash(b"y", &params), Element::hash(b"z", &params));
let (acc, state) = Accumulator::with_elements(&key, &[y.clone()])?;

// Path one: add z, then delete y.
let (mut acc_one, mut state_one) = (acc.clone(), state.clone());
acc_one.add_assign(&key, &z, &mut state_one)?;
acc_one.remove_assign(&key, &y, &mut state_one)?;

// Path two, from a copy of the old state: delete y, then add z. Nothing refuses the old state.
let (mut acc_two, mut state_two) = (acc.clone(), state.clone());
acc_two.remove_assign(&key, &y, &mut state_two)?;
acc_two.add_assign(&key, &z, &mut state_two)?;

// The same published value, and the same witness for z from both paths.
assert_eq!(acc_one, acc_two);
let one = MembershipWitness::new(&z, &acc_one, &key, &state_one)?;
let two = MembershipWitness::new(&z, &acc_two, &key, &state_two)?;
assert!(one.verify(&z, &pk, &acc_one));
assert_eq!(one, two);

// NOT refused: the old copy still works, for the old value. Moved on differently, here by
// adding x instead of deleting y, it publishes a second history next to the first.
let (mut acc_old, mut state_old) = (acc.clone(), state.clone());
acc_old.add_assign(&key, &x, &mut state_old)?;
assert!(MembershipWitness::new(&x, &acc_old, &key, &state_old)?.verify(&x, &pk, &acc));
assert_ne!(acc_old, acc_one);
# Ok::<(), kln_accumulator::Error>(())
```

What to do: treat the state as append-only all the same. Store it where an older copy cannot
replace a newer one, never restore a backup older than the last thing you published with that
key, and never give the key to two processes: the key is safe either way, but holders and
verifiers can follow only one history.

### N2. A lost state is rebuilt from the log

Row 10. The manager lost its state. It still has the key, the update messages it published
(the deletion log, which is public) and its own list of current members. Once a deletion
has been made a fresh state cannot be used with the live value: it starts at the key's
genesis value, and the live value is refused. Before the first deletion the two are equal, so
a fresh state is accepted and only the member list is lost. `ManagerState::rebuild` remakes the state and the value from the key, the log, in any
order, and the members; every witness it issues equals the one the lost state issued, and the
deleted elements stay deleted. A fresh state moved on through the same additions and deletions
reaches the same value and issues the same witnesses too.

```rust
use kln_accumulator::{Accumulator, Element, Error, ManagerState, MembershipWitness, Params};
use kln_accumulator::{PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
let element = |name: &[u8]| Element::hash(name, &params);
let (x, y, z) = (element(b"x"), element(b"y"), element(b"z"));
let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
// The published log: every update message, kept by the manager and by anyone who follows.
let mut log = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
log.extend(acc.update_assign(&key, &[], &[z.clone()], &mut state)?);
let original = MembershipWitness::new(&x, &acc, &key, &state)?;
drop(state); // the state is lost

// A fresh state is at the genesis value, so the live value is refused.
let mut fresh = ManagerState::new(&key);
let mut live = acc.clone();
assert_eq!(live.add_assign(&key, &x, &mut fresh), Err(Error::AccumulatorMismatch));

// Rebuilt from the key, the log in another order, and the member list.
log.reverse();
let (value, mut rebuilt) = ManagerState::rebuild(&key, &log, &[x.clone()])?;
assert_eq!(value, acc);
let again = MembershipWitness::new(&x, &value, &key, &rebuilt)?;
assert_eq!(again, original);
assert!(again.verify(&x, &pk, &acc));
// The deleted elements stay deleted.
let mut value = value;
assert_eq!(value.add_assign(&key, &y, &mut rebuilt), Err(Error::ElementAlreadyAdded));

// A fresh state moved on through the same operations gives the same witness as well.
let (mut replayed, mut replayed_state) = Accumulator::with_elements(&key, &[x.clone(), y.clone(), z.clone()])?;
replayed.remove_elements_assign(&key, &[z.clone(), y.clone()], &mut replayed_state)?;
assert_eq!(replayed, acc);
assert_eq!(MembershipWitness::new(&x, &replayed, &key, &replayed_state)?, original);
# Ok::<(), kln_accumulator::Error>(())
```

What to do: keep every update message you publish, in an append-only store; with the key it is
the backup of the state. Keep the list of current members yourself, since the log names only
deletions. If the state is lost, rebuild it; do not start a fresh state for a live accumulator.

### N3. The toy set is not refused

Row 23. `Params::toy()` builds a parameter set and every operation runs on it. Nothing marks a
key as "toy". The only defence is to check the set of every key you load against the one your
deployment expects.

```rust
use kln_accumulator::{Params, ParamsSpec, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut StdRng::seed_from_u64(0))?;
let pk = PublicKey::from(&key);
// What a deployment should do with every key it loads.
let expected = ParamsSpec::PAPER_128;
assert_ne!(pk.params().spec(), &expected);
# Ok::<(), kln_accumulator::Error>(())
```

## A checklist for deploying

This list assumes you have read [Guarantees and their limits](security.md) and decided to run
the crate anyway, for evaluation.

**Parameters**

- [ ] Use `ParamsSpec::PAPER_128` or a set you have analysed yourself. Never a toy set.
- [ ] Decide the trapdoor distribution before generating a key.
- [ ] On every key, value and witness you load, compare its parameter set with the one you
  expect.
- [ ] Decode untrusted bytes against the set you expect: `from_bytes(&params, bytes)`, not
  `TryFrom<&[u8]>`, which builds whatever set the bytes name.
- [ ] Budget `γ` deletions for the life of the accumulator, and `2^ℓ` additions in the
  adaptive variant. Plan how you will move to a new accumulator before they run out.
- [ ] A custom set must fit `ParamsSpec::MAX_DEGREE` and `ParamsSpec::MAX_MATRIX_ENTRIES`.
  Decoding refuses any other set before it builds a table.

**The key seed**

- [ ] Generate the seed from the operating system's generator: pass `None` with such a
  generator, or pass at least 32 random bytes. Shorter seeds are refused; a guessable one of
  32 bytes is not.
- [ ] One seed for one key. A seed reused under another parameter set gives an unrelated key;
  reused for a second key of the same set, for example in another environment, it gives the
  same key.
- [ ] Store the 96-byte key encoding encrypted, with access limited to the manager process.
- [ ] Keep every serialized copy in a buffer that is wiped on drop.

**The manager state**

- [ ] Store the accumulator value and the state as one record.
- [ ] After every operation that changes them: write the new record durably *first*, then
  publish, then issue witnesses.
- [ ] Keep every update message you publish in an append-only store. That public deletion log,
  with the key, is the backup of the state: `ManagerState::rebuild` remakes the state from it.
- [ ] Keep the list of current members yourself; the log names only deletions. In the adaptive
  variant keep each member's handle with it; every holder also has its handle in its witness.
  A wrong list cannot leak the key, but it issues or withholds witnesses wrongly.
- [ ] Make it impossible for an older record to replace a newer one: an append-only log or a
  version counter kept outside the record. An older record cannot leak the key, but it issues
  witnesses for an old value.
- [ ] One manager process per key. No hot standby that can act on its own copy: two managers
  publish two histories.
- [ ] Do not let an attacker time the manager. Issuing a witness is not constant time; see
  [Timing](security.md#timing-what-is-and-is-not-constant-time).
- [ ] After loading, call `ManagerState::authenticate` with the key before reading the state.
- [ ] If the state is lost: rebuild it from the key, the published log and the member list.
  Do not start a fresh state for a live accumulator.

**What to publish on a deletion**

- [ ] The new accumulator value.
- [ ] The batch: its deletions and the update messages, in order. `batch_update` also takes the
  batch's additions, but only to refuse a batch that names the holder's own element: they change
  no witness and may be passed empty. Publishing them is optional, and it shows everyone the new
  members' elements.
- [ ] A sequence number, so that holders can tell whether they missed a batch.
- [ ] All of it authenticated, for example signed by the manager with a post-quantum signature
  scheme. The crate does not sign what you publish.

**What holders must check**

- [ ] The public key is the manager's, obtained over an authenticated channel.
- [ ] A new witness verifies against the current value before it is stored.
- [ ] After every update, the witness verifies against the new published value.
- [ ] Batches are applied in order, each exactly once.
- [ ] `Error::ElementDeleted` means revocation. Stop presenting.

**What verifiers must check**

- [ ] The statement is built from the verifier's own public key, its own *current*
  accumulator value, and the linking relation its protocol defines.
- [ ] The transcript contains a protocol label and a fresh nonce from the verifier.
- [ ] In the three-step form: the challenge is rederived and compared.
- [ ] Only `Ok` is acceptance.

**What you must wipe yourself**

- [ ] The output of any serializer run on a secret key or a witness.
- [ ] The array a `Seed` was built from.
- [ ] Copies of `Element::to_bytes` for elements that are still private.
- [ ] The signature `Vec` if you split an adaptive witness into its parts.
- [ ] Any `Vec<u8>` made from a `PolyVec` that holds something private.
