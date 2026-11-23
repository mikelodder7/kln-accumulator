# kln-accumulator

![Apache2/MIT licensed][license-image]
![build](https://github.com/mikelodder7/kln-accumulator/actions/workflows/kln-accumulator.yml/badge.svg)
[![codecov](https://codecov.io/gh/mikelodder7/kln-accumulator/branch/main/graph/badge.svg)](https://codecov.io/gh/mikelodder7/kln-accumulator)
![MSRV][msrv-image]

A pure-Rust implementation of the lattice-based positive dynamic accumulator of
[ePrint 2025/1099](https://eprint.iacr.org/2025/1099): an accumulator with free additions,
deletions that publish one short update message, witnesses that holders update from public
data alone, and zero-knowledge proofs of membership. Its API mirrors the vb20 pairing
accumulator (same type and method names), so code written against one reads the same against
the other.

## Correspondence with the paper

The paper gives the constructions and parameters but no code, and no known-answer tests exist
to check against, so this crate claims no byte-level agreement with another implementation.
What is checked instead:

- every algorithm's correctness equation, by tests at the toy parameter sets, for all three
  variants;
- at the 128-bit set, adding, deleting, updating a witness and verifying run, and the public
  key, the accumulator value and a witness are each within 0.4% of the sizes in Table 2 of the
  paper (tests marked `#[ignore]`, run weekly in CI);
- the bytes of each variant's witnesses, public key and accumulator value after a fixed history
  are pinned by digest, so another platform can confirm it produces the same output;
- the code points to the parts of the paper it implements, and each deliberate difference is
  listed in [`security.md`](book/src/security.md) with its reason.

## ⚠️ Security Warning

This is a research implementation. Use it to study and evaluate the scheme, not to protect
anything.

- **It has not been audited**, and it is not published to crates.io.
- **It is not constant time.** A few steps that handle secrets are written so that their
  timing does not depend on the secret. Issuing a witness, proving and the preimage sampler
  are not: someone who can time them may learn secrets.
- **The toy parameter sets give no security.** The tests and examples use them so that they run
  in seconds. `ParamsSpec::PAPER_128` is the only set that is both meant for 128-bit security
  and runs; the 128-bit label is the paper's, and the crate does not re-derive a hardness
  estimate for it.
- **Membership proofs run only at the toy sets.** No parameter set gives, today, both a secure
  accumulator and a membership proof for it.
- **It departs from the paper in one place on purpose:** a witness is sampled for the key's
  genesis value and corrected through every deletion, so that a fresh, forked or rolled-back
  manager state cannot make the key leak its trapdoor.

The book's chapter [`book/src/security.md`](book/src/security.md) says what is proved, under
which assumptions, and what is not established. [`SECURITY.md`](SECURITY.md) says how to
report a vulnerability.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

This crate requires **Rust 1.98.1** at a minimum, the toolchain pinned in
`rust-toolchain.toml` and tested in CI.

We may change the MSRV in the future, but it will be accompanied by a minor version bump.

## Details

This crate provides:

- [x] Construction 4.1, at the crate root ✅
- [x] Construction 4.2, the adaptive variant with ML-DSA-65 handles, in `adaptive` ✅
- [x] the `ℓ`-succinct variant, in `succinct` ✅ (runs at its toy set only)
- [x] zero-knowledge membership proofs (Appendix D.2), one-shot and in the vb20 three-step
  form ✅ (toy sets only)
- [x] LaBRADOR compression of a membership proof, one to eight levels ✅
- [x] `ProofSetup`, which expands the proof commitment key once for many proofs ✅
- [x] Gaussian and ternary trapdoor distributions, Gaussian the default ✅

Parameter sets:

- [x] `ParamsSpec::TOY` and `ParamsSpec::SUCCINCT_TOY`: for tests and examples, no security ✅
- [x] `ParamsSpec::PAPER_128`: the 128-bit shape of Table 2 of the paper ✅
- [ ] `ParamsSpec::SUCCINCT_128`: parameters and bounds only; key generation is not practical

A secret key is a function of its parameter set and a seed of at least 32 bytes, so keys can be
generated deterministically with `SecretKey::new(Some(seed), params, rng)`. Treat the seed with
the same care as the key.

## Examples

Each program in `examples/` runs one task from start to finish and prints one line per step.
Most take a few seconds; `proofs` takes longer, since one proof takes about 4 to 5 s on
average at the toy set, varying widely from proof to proof:

```sh
cargo run --release --example base            # Construction 4.1, the crate root
cargo run --release --example adaptive        # Construction 4.2: delete an element and add it again
cargo run --release --example succinct        # the ℓ-succinct variant, at its toy set
cargo run --release --example proofs          # membership proofs: one, then many with a prepared setup
cargo run --release --example persistence     # save, reload and rebuild the manager state
cargo run --release --example offline_holder  # a holder catches up after several missed batches
cargo run --release --example wire            # encode everything published and decode it safely
```

## Quick start

```rust
use kln_accumulator::{Accumulator, Element, MembershipWitness, Params, PublicKey, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

fn main() -> Result<(), kln_accumulator::Error> {
    let mut rng = StdRng::seed_from_u64(0);

    // The manager: a key, an accumulator value and the manager state.
    let key = SecretKey::new(Some(b"manager seed, 32 bytes or longer"), Arc::new(Params::toy()?), &mut rng)?;
    let pk = PublicKey::from(&key);
    let (x, y) = (Element::hash(b"x", key.params()), Element::hash(b"y", key.params()));
    let (mut acc, mut state) = Accumulator::with_elements(&key, &[x.clone(), y.clone()])?;

    // Adding is free; the witness is issued separately and handed to the holder of x.
    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    assert!(witness.verify(&x, &pk, &acc));

    // Deleting y moves the value and publishes one update message.
    let coefficients = acc.update_assign(&key, &[], &[y.clone()], &mut state)?;

    // The holder of x updates from public data alone.
    let witness = witness.batch_update(&x, &[], &[y], &coefficients, &pk)?;
    assert!(witness.verify(&x, &pk, &acc));
    Ok(())
}
```

The example seeds its generator with a constant so that it is reproducible; real code seeds it
from the operating system. Every keyed operation takes the `ManagerState` last: it records the
current value and carries a tag keyed from the secret key, and the manager keeps it private.

## The three variants

| variant | module | use it when |
|---|---|---|
| Construction 4.1 | crate root | elements are added at most once over the life of the accumulator |
| Construction 4.2, adaptive | `adaptive` | an element must be deleted and added again |
| `ℓ`-succinct | `succinct` | for study only: it runs at the succinct toy set, where its witness is not yet shorter than the base one, and key generation at the 128-bit shape is not practical |

[`book/src/choosing.md`](book/src/choosing.md) compares them with real sizes and timings and
gives a default for the unsure.

## Read more

The book under `book/` explains the scheme from the start and documents every type. Its code
blocks are compiled and run by `cargo test`.

- First steps: [`introduction.md`](book/src/introduction.md),
  [`concepts.md`](book/src/concepts.md) (accumulators in plain words),
  [`tutorial.md`](book/src/tutorial.md) (your first accumulator),
  [`recipes.md`](book/src/recipes.md) (how do I…), [`rules.md`](book/src/rules.md) (the rules
  that keep you safe).
- Building, testing and the 128-bit run: [`getting-started.md`](book/src/getting-started.md).
- Parameter sets, their sizes and the two trapdoor distributions:
  [`parameters.md`](book/src/parameters.md).
- Keys, values, state and witnesses: [`keys.md`](book/src/keys.md),
  [`elements.md`](book/src/elements.md), [`state.md`](book/src/state.md),
  [`witnesses.md`](book/src/witnesses.md).
- The other variants: [`adaptive.md`](book/src/adaptive.md),
  [`succinct.md`](book/src/succinct.md).
- Membership proofs, their compression and `ProofSetup`: [`proofs.md`](book/src/proofs.md).
- Encodings and safe decoding: [`serialization.md`](book/src/serialization.md); every error:
  [`errors.md`](book/src/errors.md).
- Security: [`security.md`](book/src/security.md) (guarantees and their limits, secret
  handling, timing) and [`misuse.md`](book/src/misuse.md) (what the code refuses and what it
  leaves to you).
- Timings and sizes: [`benchmarks.md`](book/src/benchmarks.md).
- The lattice layer, the item-by-item map to the vb20 pairing accumulator, and the papers:
  [`lattice.md`](book/src/lattice.md), [`vb20.md`](book/src/vb20.md),
  [`references.md`](book/src/references.md).

To read it as a website, build it with [mdBook](https://rust-lang.github.io/mdBook/):

```sh
mdbook build book    # writes the HTML to book/book/
```

## Serialization

Every type that is sent or stored implements `serde`, and has been tested against the
following formats (byte strings are raw in binary formats and lowercase hex in human-readable
ones):

- [x] serde_bare
- [x] postcard
- [x] serde_cbor_2
- [x] serde_json
- [x] yaml_serde
- [x] toml

The public types also have a packed `to_bytes`, and `from_bytes` decodes against the parameter
set the receiver already holds; see [`serialization.md`](book/src/serialization.md).

## References

- ePrint 2025/1099, [Lattice-Based Accumulator and Application to Anonymous Credential
  Revocation](https://eprint.iacr.org/2025/1099): the scheme this crate implements.
- ePrint 2022/1341, [LaBRADOR: Compact Proofs for R1CS from
  Module-SIS](https://eprint.iacr.org/2022/1341): the proof compression layer.
- ePrint 2017/308, [Faster Gaussian Sampling for Trapdoor Lattices with Arbitrary
  Modulus](https://eprint.iacr.org/2017/308): the preimage sampler.
- ePrint 2011/501, [Trapdoors for Lattices: Simpler, Tighter, Faster,
  Smaller](https://eprint.iacr.org/2011/501): gadget trapdoors.
- ePrint 2007/432, [Trapdoors for Hard Lattices and New Cryptographic
  Constructions](https://eprint.iacr.org/2007/432): the sampler's underlying theorems.

[`references.md`](book/src/references.md) lists every work the book cites and where each is used.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) gives the toolchain, the gate commands and the house
rules. [`CHANGELOG.md`](CHANGELOG.md) records what each version provides.

## License

Licensed under

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

[//]: # (badges)

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.98.1+-blue.svg
