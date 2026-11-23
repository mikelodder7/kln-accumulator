# Getting started

> **In short.** How to add the crate to a Rust project, build and test it, and run the whole
> cycle once: make a key, add members, issue a [witness](glossary.md#witness), delete a member
> and bring the remaining witness up to date.
>
> **Read this when** you want the crate to build in your own project, or want to run its tests,
> including the slow ones at the 128-bit set.
>
> **New here?** Read [Your first accumulator](tutorial.md) first. It runs the same steps one at
> a time and explains each in plain words.

## Adding the crate

The crate is not published to crates.io. Depend on it by path or by Git revision.

```toml
[dependencies]
kln-accumulator = { path = "../kln-accumulator" }
```

The examples in this book also use `rand` for a seedable generator and `merlin` for proof
transcripts.

The crate is pure Rust, with no `unsafe` code (`#![forbid(unsafe_code)]`) and no C
dependencies. Every crate in the normal dependency graph is offered under MIT or Apache-2.0;
`unicode-ident`, used at build time by the derive macros, also carries Unicode-3.0 for its
data tables. `deny.toml` holds the licence and source policy that `cargo deny check` enforces,
and new dependencies are added only after review. The cryptographic building blocks are SHA-3
and SHAKE256 (`sha3`), ML-DSA-65 (`ml-dsa`), merlin transcripts, constant-time comparisons
(`ctutils`), big integers (`crypto-bigint`) and `zeroize`. No classical cryptography is used.

## Building and testing

```sh
cargo build
cargo test --all-features               # unit, integration and doc tests, this book included
cargo test --all-features --release -- --ignored   # the 128-bit set and other slow tests
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --all-features --no-deps
```

The tests sample lattice [preimages](glossary.md#preimage-preimage-sampler) and build proofs, so they run far longer than they compile.
The crate's test profile is optimised for that reason, and a plain `cargo test` is an optimised
build.

The tests check every correctness equation of the paper at a toy parameter set. The ignored
tests run add, delete, witness update and verification at the 128-bit set and check the sizes
of the witness, the accumulator value and the public key against Table 2 of the paper. They
take about a minute together. The `ignored` job in `.github/workflows/kln-accumulator.yml` runs
them on the weekly schedule and on manual runs, not on every pull request.

The programs in `examples/` narrate a run step by step. Three run the whole lifecycle of
each variant: `cargo run --release --example base`, `adaptive` or `succinct`. Four more show
one task each: `proofs` (membership proofs, one and then several with a prepared setup),
`persistence` (save, reload and rebuild the manager state), `offline_holder` (a holder
catching up after missed batches) and `wire` (encoding everything published and decoding it
safely).

## A complete run

The example below plays all three roles in one function. Each step is explained after it.

```rust
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

fn main() -> Result<(), kln_accumulator::Error> {
    // A fixed seed keeps the example reproducible. Real code seeds from the operating system.
    let mut rng = StdRng::seed_from_u64(0);

    // Manager: parameters, key, public key.
    let params = Arc::new(Params::toy()?);
    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);

    // Manager: an accumulator holding x and y, and the state that goes with it.
    let (x, y) = (Element::hash(b"x", &params), Element::hash(b"y", &params));
    let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;

    // Manager: issue the witness for x. Holder: check it.
    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    assert!(witness.verify(&x, &pk, &acc));

    // Manager: delete y. The value moves and one update message comes out.
    let before = acc.clone();
    let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    assert_ne!(acc, before);
    assert_eq!(coefficients.len(), 1);

    // Holder of x: the old witness no longer verifies; update it from public data alone.
    assert!(!witness.verify(&x, &pk, &acc));
    let witness = witness.batch_update(&x, &[], &[y], &coefficients, &pk)?;
    assert!(witness.verify(&x, &pk, &acc));
    Ok(())
}
```

1. **Parameters.** `Params::toy()` builds the [toy parameter set](glossary.md#toy-set). Parameters are runtime data:
   every key and value carries its set and refuses values of another. See
   [Parameter sets and trapdoor distributions](parameters.md).
2. **Keys.** `SecretKey::new` with `None` draws a 32-byte seed from the generator; a seed of
   your own must be at least 32 bytes. The public key is derived from the secret key and sent
   to everyone. See [Keys](keys.md).
3. **The accumulator and its state.** A key keeps one accumulator. `Accumulator::with_elements`
   starts it at the key's [genesis value](glossary.md#genesis-value) and records the elements in a new `ManagerState`. The
   state is the manager's record of everything that was ever added or deleted. Every keyed
   operation takes it as its last argument, and a lost one is rebuilt from the published
   [update messages](glossary.md#update-message) with `ManagerState::rebuild`. See [Manager state and its tag](state.md).
4. **Issuing a witness.** `MembershipWitness::new` is the only operation that samples a
   witness. It needs the secret key and the state. The witness depends only on the key, the
   element and the set of deletions, so issuing it again, from any state, gives the same one.
   See [Witnesses and updates](witnesses.md).
5. **Deleting.** `update_assign` adds and deletes in one atomic step and returns one update
   message per deletion. The manager publishes the new value and the messages.
6. **Updating.** `batch_update` takes the holder's own element, the batch as the manager
   published it, and the public key. It needs no secret.

## The same run at the 128-bit set

Nothing changes but the parameter set, the length of an element and the time it takes. The
benchmarks measure, at this set, verifying a witness at 0.13 s and one deletion at 0.75 s;
[Benchmarks and sizes](benchmarks.md) has these and the figures for key generation, issuing a
witness and updating a witness.

```rust,no_run
// no_run: every step takes seconds at the 128-bit set, and the public key is 16.65 MiB.
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

fn main() -> Result<(), kln_accumulator::Error> {
    // Real code seeds this generator from the operating system.
    let mut rng = StdRng::seed_from_u64(0);
    let params = Arc::new(Params::paper_128()?);
    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);

    // ℓ = 32 here: an element is four bytes.
    let x = Element::try_from(&1u32.to_le_bytes()[..])?;
    let y = Element::try_from(&2u32.to_le_bytes()[..])?;
    let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;
    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    assert!(witness.verify(&x, &pk, &acc));

    let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;
    let witness = witness.batch_update(&x, &[], &[y], &coefficients, &pk)?;
    assert!(witness.verify(&x, &pk, &acc));
    Ok(())
}
```

## Where to go next

| you want to | read |
|---|---|
| choose a parameter set | [Parameter sets and trapdoor distributions](parameters.md) |
| generate, store and load keys | [Keys](keys.md), [Serialization](serialization.md) |
| run a manager | [Elements and the accumulator value](elements.md), [Manager state and its tag](state.md) |
| run a holder | [Witnesses and updates](witnesses.md) |
| delete and re-add the same element | [The adaptive variant](adaptive.md) |
| have shorter witnesses | [The succinct variant](succinct.md) |
| prove membership in zero knowledge | [Membership proofs](proofs.md) |
| know what can go wrong | [Guarantees and their limits](security.md), [Misuse](misuse.md) |
| see costs and sizes | [Benchmarks and sizes](benchmarks.md) |
