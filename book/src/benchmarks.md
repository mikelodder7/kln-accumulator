# Benchmarks

> **In short.** The measured timings and sizes that the rest of the book quotes, and how to run
> the benchmarks yourself. The timings come from one run on one machine: use them to compare
> operations with each other, not as a promise of speed on yours.
>
> **Read this when** you need a time or a size to plan with, or want to reproduce the figures.
>
> **New here?** [Which variant and which settings](choosing.md) quotes the figures that matter
> for a first choice. Come here when you need the rest.

The crate's benchmarks time every operation of the accumulator of ePrint 2025/1099 through its
public API, under both trapdoor distributions, and a separate report gives the encoded size of
every key, value, witness, update message and proof. They are split into six targets so that the
slow ones can be run alone.

## The targets

| target | what it measures | parameter sets | rough run time |
|---|---|---|---|
| `construction` | Construction 4.1 (the crate-root types): the lifecycle operations below | `TOY` | 2 minutes |
| `variants` | the adaptive variant (Construction 4.2) and the `ℓ`-succinct variant: the same operations | `TOY`, `SUCCINCT_TOY` | 4 minutes |
| `samplers` | the trapdoor samplers on their own | `TOY` | 1 minute |
| `paper_128` | Construction 4.1's lifecycle operations and the samplers at the paper's 128-bit set | `PAPER_128` | 5 minutes |
| `proofs` | membership proofs: proving, verifying, compressing and verifying compressed proofs | `TOY` | 10 minutes |
| `sizes` | not a benchmark: prints the size table | all but `SUCCINCT_128` | about 1.5 minutes |

Every criterion target runs each benchmark under both trapdoor distributions,
`TrapdoorDistribution::Gaussian` and `TrapdoorDistribution::Ternary`, each parameter set being
built with `ParamsSpec::with_trapdoor` and `Params::try_from`.

### Lifecycle operations (`construction`, `variants`, `paper_128`)

| benchmark | operation |
|---|---|
| `key_generation` | `SecretKey::new` with a fresh 32-byte seed from the RNG |
| `public_key` | `PublicKey::from(&key)` |
| `add` | one addition (`add_assign`) of an element never added before |
| `issue_witness` | `MembershipWitness::new` for a present element; one further correction per deletion the state records, about the cost of `update_witness/1` each |
| `verify_witness` | `MembershipWitness::verify` |
| `delete` | one deletion (`update_assign` with one element to delete), which publishes one update message |
| `update/8` | the manager's batch update: one `update_assign` call that deletes eight elements and adds four (toy sets only). Additions do not move the value, so the cost is that of the deletions |
| `update_witness/1` | the holder's `batch_update` over one deletion |
| `update_witness/8` | the holder's `batch_update` over a batch of eight deletions (toy sets only) |

Each fixture adds a member and eight further elements (one at the 128-bit set), issues the
member's witness, deletes the others from copies to obtain the update messages, and checks that
the issued and the updated witness both verify, all before anything is timed.

Construction 4.1 is replacement-free: an element can never be added twice or deleted twice, and
the number of deletions is bounded by `γ` (256 at the toy set, 16 at the succinct toy set). So
`add`, `delete` and `update/8` run on a fresh copy of the accumulator value and the manager state in every
iteration; making the copy is not timed. Every other operation leaves its inputs unchanged and
reuses them.

### Samplers (`samplers`, `paper_128`)

| benchmark | operation |
|---|---|
| `trapdoor_generate` | `Trapdoor::generate`: `TrapGen` of ePrint 2011/501, which draws `Ā` and the trapdoor `T_A` |
| `sample_pre` | `Trapdoor::sample_pre`: a preimage under `A` of a uniform target (ePrint 2017/308) |
| `sample_left` | `Trapdoor::sample_left`: a preimage under `[A | B']` with `B'` of `ℓm'` columns, the shape witness issuance samples from |

### Membership proofs (`proofs`)

| benchmark | operation |
|---|---|
| `prove` | the one-shot `prove`, rejection sampling included (about 20 attempts are expected) |
| `verify` | the one-shot `verify` |
| `verify_prepared` | the one-shot `verify_with`, against a `ProofSetup` built once in the fixture, so the commitment key is not expanded per call |
| `compress/1`, `compress/2`, `compress/3` | `MembershipProof::compress` with one, two and three LaBRADOR levels (ePrint 2022/1341) |
| `verify_compressed/1`, `/2`, `/3` | verification of the compressed proof, `CompressedMembershipProof::finalize` |

Proofs run only where the accumulator ring has degree 64, so only at the toy set, and only for
Construction 4.1: the proof statement takes the crate-root public key, accumulator value and
witness. The compression benchmarks start from a proof made in the three-step form
(`MembershipProofCommitting`), since compression needs the outer challenge.

## Running

Each target runs on its own with `--bench`:

```sh
cargo bench --bench construction
cargo bench --bench variants
cargo bench --bench samplers
cargo bench --bench paper_128
cargo bench --bench proofs
cargo bench --bench sizes
```

A plain `cargo bench` runs every target in turn, the slow ones and the size report included,
and takes the better part of an hour. To see every benchmark ID without running anything:

```sh
cargo bench -- --list
```

IDs read `variant/set/trapdoor/operation`, for example
`construction-4.1/paper-128/ternary/issue_witness`. An argument after `--` is a filter that
criterion matches against the ID as a regular expression, so a subset of a slow target runs on
its own:

```sh
cargo bench --bench paper_128 -- 'gaussian/(key_generation|verify_witness)'
cargo bench --bench proofs -- 'ternary/(verify|verify_compressed)'
```

Fixtures (keys, witnesses, proofs) are built the first time a benchmark that needs them runs,
and their construction is never timed. Listing builds nothing, and a filter skips building the
fixtures of every group in which no benchmark matches. Building a fixture can itself take a
while: at the 128-bit set it generates a key, issues a witness and runs a deletion and an
update, several seconds; for proofs it proves twice and compresses three times, about a minute.

For figures worth publishing, run on an otherwise idle machine, with frequency scaling pinned
if the platform allows it, and one target at a time.

## Reading criterion's output

Every target uses ten samples per benchmark (criterion's minimum), a one-second warm-up, five
seconds of measurement and flat sampling, under which every sample runs the same number of
iterations. For each benchmark criterion prints a block of this form:

```text
construction-4.1/toy/gaussian/issue_witness
                        time:   [<lower> ms <estimate> ms <upper> ms]
```

The middle figure is criterion's estimate of the time of one call; the outer two bound
its 95% confidence interval. With flat sampling the estimate is the mean over all iterations.
On a second run criterion also prints a `change:` line comparing against the previous run kept
under `target/criterion/`, and says whether the difference is significant; `--save-baseline
<name>` and `--baseline <name>` compare against a named run instead. Lines about outliers
count samples far from the rest; with ten samples a single slow sample is common and mostly
reflects other activity on the machine.

Operations slower than half a second (key generation in the succinct variant, and most of the
128-bit set and the proofs) fill each sample with a single call, so criterion runs them ten
times plus one warm-up call and prints

```text
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to …
```

The warning is expected and harmless: under flat sampling criterion prints it whenever a sample
holds one iteration, whatever the measurement time, and raising the time would only double the
run (two calls per sample) without adding samples. Ten calls of a multi-second operation still
give a usable mean, but its confidence interval is wider than for the fast operations, and a
proof's time varies with the number of rejection-sampling attempts.

Criterion keeps raw data and estimates in `target/criterion/<group>/<benchmark>/`. The crate
builds criterion without plotting or HTML reports, so no plots or `report/index.html` are
written.

## The size report

`cargo bench --bench sizes` prints one GitHub-flavoured markdown table to standard output. Its
rows are variant × parameter set × trapdoor distribution; its columns are the encoded size in
bytes of the secret key, the public key, the accumulator value, a membership witness, one
update message (a `Coefficient`), and a membership proof uncompressed and compressed at one, two
and three LaBRADOR levels.

Every figure is the length of a real value's packed encoding (`to_bytes()`, or the
`From<&T> for Vec<u8>` conversion), made by running the operations, never computed from a
formula. A secret key is its parameter set and its 32-byte root seed; a witness is packed at
`⌈log₂(2β + 1)⌉` bits per coefficient; proof values are encoded at 24 bytes per coefficient,
not bit-packed, so proof sizes overstate.

Cells that cannot exist print `n/a`: proofs for any row but Construction 4.1 at the toy set.
The succinct 128-bit set is left out entirely: its public key would be about 110 GiB, and key
generation there is not practical.

## Timings

One run, 21 November 2026: AMD Ryzen AI 9 HX 370 (24 logical CPUs, frequency scaling left on),
Linux 7.3.4, Rust 1.98.1, the `bench` profile. The machine was not fully idle: other work held
a load average of about 4 throughout. The crate is single-threaded. Each figure is criterion's
estimate for one call. They are one machine's figures, to compare operations and distributions
with, not a specification.

### Lifecycle, toy sets

| operation | Construction 4.1, Gaussian | Construction 4.1, ternary | adaptive, Gaussian | adaptive, ternary | succinct, Gaussian | succinct, ternary |
|---|---:|---:|---:|---:|---:|---:|
| `key_generation` | 7.36 ms | 871 µs | 7.61 ms | 1.10 ms | 902 ms | 879 ms |
| `public_key` | 25.0 µs | 24.2 µs | 36.4 µs | 37.2 µs | 2.26 ms | 2.27 ms |
| `add` | 5.80 µs | 5.77 µs | 15.9 µs | 13.7 µs | 6.85 µs | 6.85 µs |
| `issue_witness` | 6.37 ms | 6.47 ms | 8.31 ms | 6.59 ms | 12.7 ms | 12.8 ms |
| `verify_witness` | 330 µs | 330 µs | 413 µs | 439 µs | 194 µs | 194 µs |
| `delete` | 1.51 ms | 1.51 ms | 1.51 ms | 1.56 ms | 1.74 ms | 1.72 ms |
| `update/8` | 12.3 ms | 12.1 ms | 11.9 ms | 12.0 ms | 13.7 ms | 13.6 ms |
| `update_witness/1` | 2.19 ms | 2.17 ms | 2.25 ms | 2.27 ms | 7.54 ms | 7.52 ms |
| `update_witness/8` | 18.1 ms | 17.3 ms | 17.0 ms | 17.2 ms | 22.4 ms | 22.4 ms |

Construction 4.1 and the adaptive variant run at `TOY`, the succinct variant at `SUCCINCT_TOY`.

### Lifecycle, 128-bit set (`PAPER_128`, Construction 4.1)

| operation | Gaussian | ternary |
|---|---:|---:|
| `key_generation` | 1.49 s | 109 ms |
| `public_key` | 4.00 ms | 3.29 ms |
| `add` | 288 µs | 289 µs |
| `issue_witness` | 1.96 s | 1.93 s |
| `verify_witness` | 128 ms | 126 ms |
| `delete` | 751 ms | 754 ms |
| `update_witness/1` | 1.00 s | 1.01 s |

### Samplers

| operation | toy, Gaussian | toy, ternary | 128-bit, Gaussian | 128-bit, ternary |
|---|---:|---:|---:|---:|
| `trapdoor_generate` | 7.11 ms | 714 µs | 1.45 s | 56.8 ms |
| `sample_pre` | 2.26 ms | 2.24 ms | 200 ms | 200 ms |
| `sample_left` | 5.98 ms | 6.01 ms | 1.77 s | 1.80 s |

### Membership proofs (`TOY`, Construction 4.1)

| operation | Gaussian | ternary |
|---|---:|---:|
| `prove` | 4.32 s (2.78 to 6.14) | 5.26 s (2.03 to 9.35) |
| `verify` | 568 ms | 566 ms |
| `compress/1` | 1.53 s | 1.55 s |
| `verify_compressed/1` | 1.37 s | 1.28 s |
| `compress/2` | 1.99 s | 1.99 s |
| `verify_compressed/2` | 1.60 s | 1.63 s |
| `compress/3` | 2.49 s | 2.17 s |
| `verify_compressed/3` | 1.83 s | 1.76 s |

The range after `prove` is criterion's 95% confidence interval.

`verify_prepared` was added after this run and measured on its own, on the same machine: 191 ms
against 584 ms for `verify` in that later run (Gaussian trapdoor), about a third. A second
measurement under heavy load gave the same ratio for both distributions.

### What the figures show

- **A Gaussian trapdoor makes key generation slow, and the trapdoor distribution changes
  nothing else.** The draws that are a Gaussian trapdoor's coefficients read the whole
  cumulative table for every draw, so that neither time nor memory access depends on them (see
  [Security](security.md)): 1.45 s of the 1.49 s at the 128-bit set. A ternary trapdoor needs
  no table and is drawn in 57 ms. Every other operation is within noise of its counterpart:
  preimage sampling costs the same under both, because its cost is set by the dimensions, not
  by the width.
- **The two `prove` columns do not show a difference between distributions.** Proving time is
  dominated by the number of rejection-sampling attempts, which varies from call to call; ten
  samples give confidence intervals that overlap almost entirely.
- **Adding is free in time as well as in size**: microseconds, against milliseconds to seconds
  for a deletion.
- **Issuing a witness is `sample_left` plus bookkeeping**: 1.77 s of the 1.96 s at the 128-bit
  set. The rest is the hash that binds the sampler's seed to the matrix and the target, and the
  check of the result.
- **A holder's update costs more than the manager's deletion** (1.00 s against 0.75 s at the
  128-bit set), because the update evaluates every block whatever the element, so that its
  time does not show how long a prefix the element shares with the deleted one. It grows
  linearly with the number of deletions caught up on (2.2 ms for one, 18 ms for eight, at the
  toy set).
- **Most of a verification is expanding the commitment key.** With a `ProofSetup` built once,
  `verify_prepared` takes about a third of the one-shot `verify`.
- **A compressed proof is smaller but slower to verify** than the uncompressed one: 1.3 to
  1.8 s against 0.57 s. Each extra level saves bytes and adds time on both sides.
- **Succinct key generation is slow** (0.9 s at a toy set) because it builds the dense public
  matrix `T₀`.

## Sizes

Printed by `cargo bench --bench sizes` in the same run. Bytes.

| variant | parameter set | trapdoor | secret key | public key | accumulator | witness | update message | proof | proof, 1 level | proof, 2 levels | proof, 3 levels |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| construction-4.1 | toy | gaussian | 96 | 48544 | 544 | 34464 | 1 | 9100960 | 2172640 | 1117976 | 852816 |
| construction-4.1 | toy | ternary | 96 | 48544 | 544 | 34464 | 1 | 9100960 | 2172640 | 1117976 | 852816 |
| construction-4.1 | paper-128 | gaussian | 96 | 17459264 | 51264 | 15493184 | 4 | n/a | n/a | n/a | n/a |
| construction-4.1 | paper-128 | ternary | 96 | 17459264 | 51264 | 15493184 | 4 | n/a | n/a | n/a | n/a |
| adaptive | toy | gaussian | 96 | 50496 | 544 | 37782 | 1 | n/a | n/a | n/a | n/a |
| adaptive | toy | ternary | 96 | 50496 | 544 | 37782 | 1 | n/a | n/a | n/a | n/a |
| succinct | succinct-toy | gaussian | 96 | 2149984 | 784 | 29224 | 1 | n/a | n/a | n/a | n/a |
| succinct | succinct-toy | ternary | 96 | 1372384 | 784 | 24904 | 1 | n/a | n/a | n/a | n/a |

- The secret key is 96 bytes everywhere: the 64-byte parameter set and the 32-byte root seed.
  Everything else is derived from the two together.
- An update message is the deleted element: `ℓ` bits, so one byte at the toy sets and four at
  the 128-bit set.
- The trapdoor distribution changes sizes only in the succinct variant, where the ternary
  trapdoor's narrower bound shrinks the public key by 36% and the witness by 15%. In
  Construction 4.1 and the adaptive variant the bounds are set by the update bound, so the
  encodings are identical.
- The proof is for a linking relation with one row and a one-entry `r`; a larger relation
  gives a slightly larger uncompressed proof.
- At the 128-bit set the public key is 16.65 MiB, the accumulator value 50.06 KiB and a
  witness 14.78 MiB, each within 0.4% of Table 2 of ePrint 2025/1099.
