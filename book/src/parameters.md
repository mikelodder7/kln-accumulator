# Parameter sets and trapdoor distributions

> **In short.** A [parameter set](glossary.md#parameter-set) is the group of settings that
> sizes everything: how long an element is, how many deletions the accumulator can ever take,
> how large keys and witnesses are, and how the secret key is drawn. This chapter gives the
> exact figures of the four sets the crate defines, and the types that hold them.
>
> **Read this when** you need the exact numbers of a set, want to define a set of your own, or
> must choose between the two [trapdoor distributions](glossary.md#trapdoor-distribution).
>
> **New here?** Read [Which variant and which settings](choosing.md) first: it makes the same
> choices in plain words. The last section, on what the samplers do, is advanced; you can skip
> it.

Everything in the scheme is sized by a parameter set: the [ring](glossary.md#ring-and-ring-degree), the modulus, the shape of the
matrices, the length of an element, how many deletions the accumulator can take, and how the
[trapdoor](glossary.md#trapdoor) is drawn. The set also fixes every Gaussian width and every [norm bound](glossary.md#norm-bound).

Parameters are runtime data. A key carries its set, a value made by that key carries the same
set, and every operation refuses a value of another set. You choose a set once, at key
generation, and it is then part of every encoded key, accumulator value and witness.

## The defined sets

| set | `d` | `q` | `n` | `m` | `b` | `ℓ` | `γ` | purpose |
|---|---|---|---|---|---|---|---|---|
| `ParamsSpec::TOY` | 64 | 60-bit | 1 | 20 | 64 | 8 | 256 | tests, examples, membership proofs |
| `ParamsSpec::PAPER_128` | 4096 | 100-bit | 1 | 20 | 1024 | 32 | `2^32` | the 128-bit shape of Table 2 of ePrint 2025/1099 |
| `ParamsSpec::SUCCINCT_TOY` | 64 | 90-bit | 1 | 30 | 64 | 4 | 16 | tests of the succinct variant |
| `ParamsSpec::SUCCINCT_128` | 4096 | 162-bit | 1 | 90 | 6 | 32 | `2^32` | the succinct 128-bit shape |

The symbols are those of Section 4 of the paper: the ring is `R_q = Z_q[X]/(X^d + 1)`, the
public matrix `A` has `n` rows and `m` columns, the [gadget](glossary.md#gadget) has base `b`, an element has `ℓ`
bits, and at most `γ` deletions can ever be made.

How to choose:

- **The toy sets give no security.** They exist so that tests and examples run in seconds.
  `ℓ = 8` means there are only 256 distinct elements.
- **`PAPER_128` is the only set that is both meant for 128-bit security and runs.** Every
  accumulator operation works there and takes seconds; see
  [Benchmarks and sizes](benchmarks.md). Its 128-bit label is the paper's, for that shape.
  This crate does not re-derive a hardness estimate for it.
- **Membership proofs run only at ring degree 64**, so only at the toy sets. You cannot today
  have both a 128-bit accumulator and a membership proof for it from this crate.
- **`SUCCINCT_128` cannot generate keys in practice.** Its public key would be about 110 GiB.
  Only its parameters and bounds are tested.

Every modulus is a prime `q ≡ 5 (mod 8)`, which the proof layer needs.

## `ParamsSpec`

**What it is**

The free choices of a parameter set, as a plain struct with public fields: `degree`, `modulus`,
`n`, `m`, `base`, `element_bits`, `max_deletions` and `trapdoor`. It is `Copy`. The four
defined sets are associated constants.

**Why it exists**

A parameter set has to travel with keys and values, and it has to be comparable. `ParamsSpec`
is the small, serializable description; `Params` is the validated, precomputed form built from
it. The byte form of a spec is the 64-byte prefix of every encoded key, accumulator value and
witness, which is how a decoder knows which set a value belongs to.

**How to use it**

Use a defined constant, or fill in the fields for a custom set and pass the spec to
`Params::try_from`.

```rust
use kln_accumulator::{Error, Params, ParamsSpec, TrapdoorDistribution};

// The 64-byte encoding round-trips.
let bytes = <[u8; ParamsSpec::BYTES]>::from(ParamsSpec::TOY);
assert_eq!(bytes.len(), 64);
assert_eq!(ParamsSpec::try_from(&bytes[..])?, ParamsSpec::TOY);

// The same shape with the other trapdoor distribution is a different set.
let ternary = ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary);
assert_ne!(ternary, ParamsSpec::TOY);

// A custom set: the toy shape with room for two deletions only.
let small = ParamsSpec { max_deletions: 2, ..ParamsSpec::TOY };
let params = Params::try_from(small)?;
assert_eq!(params.spec().max_deletions, 2);

// A spec is only a description. An unusable one is refused when it is validated.
let too_narrow = ParamsSpec { m: 10, ..ParamsSpec::TOY };
assert!(matches!(Params::try_from(too_narrow), Err(Error::TooFewColumns { m: 10, m_prime: 10 })));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. The spec decides the
security of everything built on it, so its integrity matters: a holder or verifier who accepts
a public key also accepts the spec inside it.

**Using it safely**

The code refuses:

- a 64-byte encoding whose reserved bytes are not zero: `Error::NonCanonicalEncoding`;
- an encoding that names an unknown trapdoor distribution:
  `Error::InvalidTrapdoorDistribution`;
- a spec that `Params::try_from` cannot serve, with the errors listed under `Params` below.

Your job:

- A spec that validates is not thereby secure. `Params::try_from` checks that the scheme is
  *correct* at the set (the bounds fit under the modulus, the sampler has room). It does not
  estimate lattice hardness. `ParamsSpec::TOY` validates and gives no security.
- If you accept parameter sets from outside, compare them against the set you expect. Do not
  run with whatever set a peer sends.

## `Params`

**What it is**

A validated parameter set with everything derived from it precomputed: the ring and its
multiplication tables, the gadget, the Gaussian widths and norm bounds, and the samplers.

**Why it exists**

Validation and precomputation happen once. Keys take an `Arc<Params>` and share it with every
value they make, so the public types need no type parameters and a mismatch of sets is a
runtime check on one pointer-sized field.

**How to use it**

```rust
use kln_accumulator::{Params, ParamsSpec};
use std::sync::Arc;

let params = Arc::new(Params::toy()?);
assert_eq!(params.spec(), &ParamsSpec::TOY);
assert_eq!(params.ring().degree(), 64);
assert_eq!(params.digits(), 10);                    // k = ⌈log_b q⌉
assert_eq!(params.m_prime(), 10);                   // m' = n·k
assert_eq!(params.gadget().base(), 64);
assert_eq!(params.bounds().witness.bit_width_vartime(), 42); // β = 2^41.68

// The named constructors are shorthand for try_from on the named specs.
assert_eq!(Params::try_from(ParamsSpec::TOY)?, *params);
# Ok::<(), kln_accumulator::Error>(())
```

Building a `Params` is cheap next to any operation at it. Build one, wrap it in an `Arc`, and
hand clones of the `Arc` to `SecretKey::new` and to the methods that ask for one.

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped.

**Using it safely**

`Params::try_from` refuses a spec with one of these errors. The caps on `d` and on the size
of `[A | B]`, and the checks on `b`, `m` and `ℓ`, run first in integer arithmetic, so a spec
read from untrusted bytes is refused before any NTT table is built.

| error | condition |
|---|---|
| `Error::DegreeNotPowerOfTwo` | `d` is not a power of two |
| `Error::DegreeTooLarge` | `d` exceeds `ParamsSpec::MAX_DEGREE = 2^13` |
| `Error::ModulusNotPrime` | `q` is not prime |
| `Error::ModulusNotFiveModEight` | `q` is not congruent to 5 modulo 8 |
| `Error::BaseTooSmall` | the gadget base is below 2 |
| `Error::ZeroRank` | `n` is zero |
| `Error::TooFewColumns` | `m` does not exceed `m' = n·k` |
| `Error::ZeroElementBits` | `ℓ` is zero |
| `Error::WidthTooSmall` | the Gaussian width the set realises is below the preimage sampler's least width |
| `Error::WitnessBoundTooLarge` | the witness bound `β` is not below `q/2`, a dimension overflows, or `[A \| B]` would hold more than `ParamsSpec::MAX_MATRIX_ENTRIES = 2^16` polynomials |

```rust
use kln_accumulator::{Error, Params, ParamsSpec};
use kln_accumulator::lattice::Coeff;

let refuse = |spec| Params::try_from(spec).map(drop);
assert_eq!(refuse(ParamsSpec { degree: 48, ..ParamsSpec::TOY }), Err(Error::DegreeNotPowerOfTwo(48)));
assert_eq!(refuse(ParamsSpec { base: 1, ..ParamsSpec::TOY }), Err(Error::BaseTooSmall(1)));
assert_eq!(refuse(ParamsSpec { n: 0, ..ParamsSpec::TOY }), Err(Error::ZeroRank));
assert_eq!(refuse(ParamsSpec { element_bits: 0, ..ParamsSpec::TOY }), Err(Error::ZeroElementBits));
// 21 = 3·7 is composite; 97 is prime but 97 ≡ 1 (mod 8).
let modulus = |q| ParamsSpec { modulus: Coeff::from_u64(q), ..ParamsSpec::TOY };
assert_eq!(refuse(modulus(21)), Err(Error::ModulusNotPrime));
assert_eq!(refuse(modulus(97)), Err(Error::ModulusNotFiveModEight));
// With a single deletion the update bound, and so the width, is too small for the sampler.
assert_eq!(refuse(ParamsSpec { max_deletions: 1, ..ParamsSpec::TOY }), Err(Error::WidthTooSmall));
```

Your job is the same as for `ParamsSpec`: validation is about correctness, not about security.

## `Bounds`

**What it is**

The Gaussian widths and norm bounds of one parameter set, each rounded up to an integer, as a
`Copy` struct with public fields:

| field | meaning |
|---|---|
| `update` | `T`, the bound on everything `γ` deletions add to a witness |
| `width` | `s`, the Gaussian width a witness is sampled with; `s ≥ T` |
| `witness` | `β`, the norm bound a witness must meet to verify |
| `trapdoor_width` | `ς`, the width of the trapdoor's coefficients |
| `spectral` | `S`, the bound on the trapdoor's largest singular value |
| `least_width` | the least width at which the preimage sampler can run |

**Why it exists**

Verification is "the equation holds *and* the witness is short". `β` is what "short" means. It
has to be large enough that an honest witness still fits after [`γ`](glossary.md#deletion-bound) deletions, and small enough
that finding a short vector is hard. The other fields are how `β` is reached: a witness is
sampled at width `s`, and each deletion adds a correction whose total is at most `T`.

**How to use it**

You read bounds; you do not set them. They follow from the spec.

```rust
use kln_accumulator::Params;

let params = Params::toy()?;
let bounds = params.bounds();
assert!(bounds.width >= bounds.update);                       // s ≥ T
let twice = bounds.witness.wrapping_add(&bounds.witness);
assert!(twice < *params.ring().modulus());                    // 2β < q
assert_eq!(bounds.witness.bit_width_vartime(), 42);           // β = 2^41.68
assert_eq!(bounds.least_width.bit_width_vartime(), 29);       // 2^28.11
# Ok::<(), kln_accumulator::Error>(())
```

Realised values (`log₂`, Gaussian trapdoor), from the crate's documentation:

| set | `T` | `s` | `β` | `ς` | `S` | least width |
|---|---|---|---|---|---|---|
| toy | 35.341 | 35.341 | 41.681 | 13.188 | 19.598 | 28.108 |
| 128-bit | 77.457 | 77.457 | 87.663 | 23.005 | 32.774 | 45.394 |
| succinct toy | 31.607 | 31.615 | 37.880 | 13.188 | 19.814 | 28.324 |
| succinct 128-bit | 66.087 | 66.087 | 77.608 | 19.003 | 29.553 | 34.896 |

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. Every field is an
upper bound: irrational factors are bounded in the safe direction, so the inequalities the
analysis needs hold for the realised values. The bounds rest on Gaussian tail bounds, so an
honest witness satisfies them with overwhelming probability, not with certainty.

**Using it safely**

There is nothing to misuse here: the fields are derived, and a set whose bounds do not fit is
refused at `Params::try_from` (`Error::WidthTooSmall`, `Error::WitnessBoundTooLarge`). What
remains your job is to respect `γ`: `max_deletions` is a lifetime budget, not a rate. When it
is spent the accumulator refuses further deletions (`Error::DeletionBoundReached`) and you
need a new accumulator, which means new witnesses for every holder.

## `TrapdoorDistribution`

**What it is**

An enum with two variants, [`Gaussian`](glossary.md#gaussian-trapdoor) (the default) and [`Ternary`](glossary.md#ternary-trapdoor). It says how key generation
draws the coefficients of the secret trapdoor `T_A`.

**Why it exists**

The trapdoor is what lets the manager sample witnesses. Its size decides how wide those samples
must be, and how it is drawn decides what the public matrix `A` looks like to an attacker. The
paper's Theorem 2.1 uses a Gaussian trapdoor. A ternary one is much smaller, which buys
narrower sampling, at the price of an extra assumption. The crate offers both and makes the
choice part of the parameter set.

| | `Gaussian` | `Ternary` |
|---|---|---|
| coefficients of `T_A` | discrete Gaussian of width `ς` | uniform in `{−1, 0, 1}` |
| what `A` is | statistically close to uniform (Theorem 2.1) | pseudorandom, under Module-LWE with ternary secrets |
| least width, toy | `2^28.11` | `2^15.95` |
| least width, 128-bit | `2^45.39` | `2^23.42` |
| `β_succ`, succinct toy | `2^79.70` | `2^67.53` |
| `β_succ`, succinct 128-bit | `2^138.25` | `2^120.28` |

How to choose:

- **Take `Gaussian` unless you have a reason not to.** It is the default and it is the paper's
  construction. `A` is then statistically close to uniform, so this step adds no computational
  assumption.
- **`Ternary` barely helps the base scheme.** There the width `s` and the bound `β` are set by
  the update bound `T`, not by the sampler's least width, so they hardly move.
- **`Ternary` helps the succinct variant.** Its public matrix `T` is sampled at the least
  width, so a narrower least width lowers `β_succ` by 12 to 18 bits.
- **The cost of `Ternary` is an assumption.** `A` is then only pseudorandom, under Module-LWE
  with ternary secrets. The crate's documentation notes that the paper's security theorem for
  Construction 4.1 already makes an assumption of that kind.

**How to use it**

```rust
use kln_accumulator::{Params, ParamsSpec, TrapdoorDistribution};

assert_eq!(TrapdoorDistribution::default(), TrapdoorDistribution::Gaussian);
assert_eq!(ParamsSpec::TOY.trapdoor, TrapdoorDistribution::Gaussian);

let gaussian = Params::toy()?;
let ternary = Params::try_from(ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary))?;
assert_eq!(gaussian.bounds().least_width.bit_width_vartime(), 29); // 2^28.11
assert_eq!(ternary.bounds().least_width.bit_width_vartime(), 16);  // 2^15.95
// β keeps its size: it is set by the update bound.
assert_eq!(
    gaussian.bounds().witness.bit_width_vartime(),
    ternary.bounds().witness.bit_width_vartime(),
);
// The distribution is one byte of the encoded set: 0 for Gaussian, 1 for Ternary.
assert_eq!(u8::from(TrapdoorDistribution::Ternary), 1);
assert_eq!(TrapdoorDistribution::try_from(0u8).ok(), Some(TrapdoorDistribution::Gaussian));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. The variant chosen changes the assumption the public key rests on,
as the table above says. Nothing in it needs wiping when it is dropped.

**Using it safely**

The code refuses a value made under one distribution when it is used under the other, because
the distribution is part of the set: `Error::ParameterMismatch`, or `false` from `verify`. An
unknown distribution byte in an encoding is `Error::InvalidTrapdoorDistribution`.

```rust
use kln_accumulator::{Accumulator, Element, Error, ManagerState, Params, ParamsSpec, SecretKey};
use kln_accumulator::TrapdoorDistribution;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let mut rng = StdRng::seed_from_u64(0);
let gaussian = Arc::new(Params::toy()?);
let ternary = Arc::new(Params::try_from(
    ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary),
)?);
let key = SecretKey::new(None, Arc::clone(&ternary), &mut rng)?;

// An accumulator value of the Gaussian set, used with a key of the ternary set.
let mut acc = Accumulator::random(&mut rng, &gaussian);
let mut state = ManagerState::new(&key);
let x = Element::hash(b"x", &ternary);
assert_eq!(acc.add_assign(&key, &x, &mut state), Err(Error::ParameterMismatch));

// An encoding that names a distribution that does not exist.
let mut bytes = acc.to_bytes();
bytes[4] = 7;
assert!(matches!(
    Accumulator::try_from(bytes.as_slice()),
    Err(Error::InvalidTrapdoorDistribution(7))
));
# Ok::<(), kln_accumulator::Error>(())
```

Your job: decide on the distribution before you generate a key. It cannot be changed
afterwards without generating a new key and reissuing every witness.

## What the samplers do under each distribution

Three samplers sit behind a key. They are the same code for both distributions; only the
numbers they run at differ.

1. **Trapdoor generation.** `TrapGen` draws a uniform block `Ā` and the trapdoor `T_A` from
   the chosen distribution, and publishes `A = [Ā | G − Ā·T_A]`. A drawn trapdoor is kept only
   if the [preimage sampler](glossary.md#preimage-preimage-sampler) can work with it; otherwise the next one is drawn.
2. **Preimage sampling.** To issue a witness the manager samples a short vector that the
   public matrix maps to the accumulator value. The crate builds that sample from two parts
   whose variances add: a wide draw made with integer arithmetic only, and a trapdoor-stage
   sample at the *least width*, made with the perturbation method of ePrint 2011/501 and the
   samplers of ePrint 2017/308. The least width is proportional to the size of the trapdoor,
   which is why a ternary trapdoor lowers it.
3. **Uniform sampling.** The public matrices and every derived seed come from SHAKE256 streams
   of a 32-byte seed under distinct labels.

The trapdoor-stage sampler uses `f64`. Its floating-point loss is measured in tests, not
bounded by proof. See [Guarantees and their limits](security.md).

The types behind these samplers are described in
[The lattice building blocks](lattice.md).
