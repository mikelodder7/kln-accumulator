# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

The first version, 0.1.0: a research implementation of the lattice-based positive dynamic
accumulator of ePrint 2025/1099. It has not been audited, it is not constant time, and its toy
parameter sets give no security; see `SECURITY.md`.

- **Three variants**, with the type and method names of the vb20 pairing accumulator:
  Construction 4.1, the replacement-free accumulator, at the crate root; Construction 4.2, the
  adaptive accumulator, in `adaptive`, with ML-DSA-65 signing each element and its handle; and
  the `ℓ`-succinct witness variant of Section 4 in `succinct`.
- **Four parameter sets** as runtime data (`ParamsSpec::TOY`, `PAPER_128`, `SUCCINCT_TOY`,
  `SUCCINCT_128`), with every Gaussian width and norm bound derived per set and custom sets
  validated by `Params::try_from`. At `PAPER_128` the witness, the accumulator value and the
  public key are within 0.4% of the sizes in the paper's Table 2.
- **Both trapdoor distributions**, chosen with `ParamsSpec::with_trapdoor`:
  `TrapdoorDistribution::Gaussian`, the default and the paper's Theorem 2.1, and
  `TrapdoorDistribution::Ternary`. The choice is part of the encoded parameter set.
- **The preimage sampler of ePrint 2017/308**, perturbation and G-lattice sampling, with its
  smoothing conditions derived and enforced per set.
- **Genesis sampling.** A witness is sampled for the key's genesis value with randomness that
  depends on the element alone, and corrected through every deletion, so that a fresh, forked,
  rolled-back or rebuilt manager state reproduces the same witness. This departs from the
  paper's `MemWitCreate` on purpose; `book/src/security.md` gives the argument and its limits.
- **The manager state and its tag.** `ManagerState` records the current value, the members
  and the deletions under a SHAKE256 tag keyed from the secret key; every keyed operation
  checks the tag and the current value first. `ManagerState::authenticate` checks the tag
  alone, and `ManagerState::rebuild` remakes a lost state from the published update messages
  and the member list (in the adaptive variant, the member records with their handles).
- **Membership proofs** (Appendix D.2): the commit-and-prove argument, made
  non-interactive over merlin transcripts, as a one-shot `prove` and `verify` and in the vb20
  three-step form, with a linking relation `A₁·x + A₂·r = t` to an outer credential. Proofs
  run at ring degree 64 only, that is at the toy sets.
- **LaBRADOR compression** (Appendix D.3, ePrint 2022/1341) of a membership proof, with one to
  eight levels.
- **`ProofSetup`**, which expands the proof commitment key once for every proof under one
  public key, `ProofParams` and relation shape, passed to `prove_with`, `verify_with` and the
  other `_with` operations.
- **Encodings.** Packed `to_bytes` with `⌈log₂ q⌉` bits per uniform coefficient and
  `⌈log₂(2β + 1)⌉` bits per witness coefficient, canonical-only on decode. `from_bytes` on the
  packed public types decodes against a parameter set the caller already holds and refuses
  bytes of another set. Parameter sets read from bytes are refused beyond the caps
  `ParamsSpec::MAX_DEGREE` and `ParamsSpec::MAX_MATRIX_ENTRIES` before any table is built.
  Serde on every type that is sent or stored, tested in postcard, CBOR, BARE, JSON, TOML and
  YAML.
- **Secret handling.** Secret and holder-private types, and the intermediates that depend on
  them, are wiped on drop; secret keys are neither `Copy` nor `Clone`, compare in constant
  time and print no secret. Key seeds shorter than 32 bytes are refused.
- **The book** under `book/`: a part for newcomers, a reference chapter per area of the API,
  the security and misuse chapters, the benchmarks, the lattice layer and the item-by-item map
  to the vb20 pairing accumulator. Its code blocks run as doc tests.
- **Examples** in `examples/`: `base`, `adaptive` and `succinct` run each variant's lifecycle;
  `proofs`, `persistence`, `offline_holder` and `wire` show membership proofs, keeping the
  manager state, a holder catching up, and encoding and decoding what is published.
- **Benchmarks**: five criterion targets (`construction`, `variants`, `samplers`, `proofs`,
  `paper_128`) timing every operation under both trapdoor distributions, and a size report,
  `sizes`.
