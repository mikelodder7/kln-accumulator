# Contributing

This file says how to build and test the crate, which checks a change must pass, and the rules
the code follows. Before you change anything that bears on security, read
[`book/src/security.md`](book/src/security.md); to report a vulnerability, follow
[`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## Toolchain

`rust-toolchain.toml` pins Rust 1.98.1 with `clippy` and `rustfmt`, and `rustup` picks it up
inside the repository. The pin is bumped deliberately, together with a lockfile refresh, never
implicitly. `Cargo.lock` is not edited by hand.

The other tools the checks below use are [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)
and [mdBook](https://rust-lang.github.io/mdBook/).

## Building and testing

```sh
cargo build
cargo test --all-features                          # unit, integration and doc tests
cargo test --release --all-features -- --ignored   # the 128-bit set and other slow tests
```

The tests sample lattice preimages and build proofs, so they run far longer than they compile.
`[profile.test]` in `Cargo.toml` therefore sets `opt-level = 3`, and a plain `cargo test` is an
optimised build.

The tests marked `#[ignore]` run at the 128-bit parameter set and take about a minute together.
The `ignored` job in `.github/workflows/kln-accumulator.yml` runs them only on the weekly
schedule and on manual runs, so run them yourself when a change reaches the samplers, the
parameter sets, the encodings or anything else the 128-bit set exercises.

The README and the book's chapters are compiled and run as doc tests: `src/lib.rs` includes
each file under `cfg(doctest)`. A chapter's code blocks are tested only if `src/lib.rs`
includes it, so a new chapter with Rust code needs an entry there. A block marked `no_run`
says why it is not run.

The programs in `examples/` run with `cargo run --release --example <name>`.

### Benchmarks

```sh
cargo bench --no-run               # build every bench target without running it
cargo bench --bench construction   # one target; see book/src/benchmarks.md for each
cargo bench --bench sizes          # print the size table
cargo bench -- --list              # list every benchmark ID
```

There are six targets: `construction`, `variants`, `samplers`, `proofs`, `paper_128` and
`sizes`. A plain `cargo bench` runs all of them and takes the better part of an hour. Timings
are only worth recording on an otherwise idle machine, with frequency scaling pinned if the
platform allows it, one target at a time; figures taken beside other load do not go in the
book. [`book/src/benchmarks.md`](book/src/benchmarks.md) describes every target and holds the
recorded run.

### The book

```sh
mdbook build book   # writes the HTML to book/book/
```

## The gates

A change is complete when each of these exits 0:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo deny check
mdbook build book
```

The GitHub Actions workflow in `.github/workflows/kln-accumulator.yml` runs these gates on
every push to `main` and every pull request, and also builds, runs the seven examples, measures
coverage, runs the unit tests under `cargo careful`, and checks for unused and outdated
dependencies. Its `ignored` job runs the 128-bit tests on the weekly schedule and on manual runs
only.

## House rules

- **Pure Rust, edition 2024.** No C anywhere in the tree, the development dependencies
  included: `deny.toml` refuses `cc`, `cmake`, `bindgen` and `pkg-config`. This is why
  `criterion` is pinned to 0.7 (0.8 depends on a crate that compiles C) and why there is no fuzz
  target (the fuzzing runtimes compile C or C++); property tests stand in.
- **Dependencies are asked for first.** Explain why the standard library or an existing
  dependency will not do. Every crate must be offered under MIT or Apache-2.0 (`unicode-ident`
  also carries Unicode-3.0 for its data tables, which `deny.toml` allows), and come from a
  registry `deny.toml` allows; `cargo deny check` enforces both.
- **No `unsafe`.** The crate root has `#![forbid(unsafe_code)]`.
- **No `unwrap`, `expect` or `panic!` outside tests.** `clippy::unwrap_used` is denied and
  `clippy::panic` and `clippy::panic_in_result_fn` warn, which `-D warnings` turns into errors;
  `.clippy.toml` allows `unwrap` only in tests and constants. Fallible operations return
  `Result` and propagate with `?`.
- **No `#[allow(...)]`** to make a lint pass. Fix the cause.
- **Errors use `thiserror`**, through the crate's one `Error` type in `src/error.rs`.
- **Every public item is documented** with `///`, with a runnable example where it helps.
  `missing_docs` and `missing_debug_implementations` are denied, with the other lints in
  `[lints]` in `Cargo.toml`.
- **No `mod.rs`.** A module with children is `name.rs` plus `name/child.rs`.
- **Unit tests live in the file they test**, in `#[cfg(test)] mod tests`. Integration tests
  live in `tests/`, one directory per suite with a `main.rs`.
- **Serde only on types that are serialized.** Each such type is round-trip tested in postcard,
  CBOR (`serde_cbor_2`), BARE (`serde_bare`), JSON, TOML and YAML (`yaml_serde`). Byte strings
  are raw in binary formats and lowercase hex in human-readable ones.
- **No classical cryptography**, in code or in tests. The signature of the adaptive variant is
  ML-DSA-65; hashing, PRFs and XOFs are SHA-3 and SHAKE256.
- **Secrets follow the crate's classes.** A type is secret, holder-private or public, as
  [`book/src/security.md`](book/src/security.md) lists; a new secret or holder-private type is
  wiped on drop and its `Debug` prints no secret.
- **Parameters are data.** One parameter-set definition per security target, not literals
  scattered through the code.
- **Papers are cited by ePrint number.** A work with no ePrint number is cited by title, as
  printed in the bibliography of the paper that cites it. Other
  implementations are not named.
- **No personal names** in code, comments, tests or commit messages.
- **`Cargo.toml` stays sorted**: the keys in each section, alphabetically.

## Commits

Commits are GPG-signed (`git commit -S`) and use conventional commit messages: `feat:`, `fix:`,
`docs:`, `refactor:`, `test:` and so on. Commit only a tree that passes the gates.

## Licence

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as below,
without any additional terms or conditions:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT licence (`LICENSE-MIT`)

at your option: `MIT OR Apache-2.0`.

Every `.rs` file starts with the line `// SPDX-License-Identifier: MIT OR Apache-2.0`, above
its `//!` docs. A new file needs it too.
