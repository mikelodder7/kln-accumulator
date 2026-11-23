# Which variant and which settings

You make three choices before you generate a key: the variant, the parameter set and the
trapdoor distribution. All three are fixed for the life of the key. Changing any of them later
means a new key, a new accumulator, and a new witness for every holder.

The figures on this page come from [Benchmarks and sizes](benchmarks.md). They are one
machine's figures from one run, on 21 November 2026, made while other work was running. Use
them to compare operations with each other, not as a promise of speed.

## The variant

Work down this list and stop at the first line that fits.

1. **A removed member must be able to come back.** Use the
   [adaptive variant](adaptive.md), in `kln_accumulator::adaptive`.
2. **Witnesses are too large to ship, and a very large public key is acceptable.** This is
   what the [succinct variant](succinct.md), in `kln_accumulator::succinct`, is for. Read
   [The succinct variant today](#the-succinct-variant-today) first: at present it is for study
   only.
3. **Otherwise**, use the base variant at the crate root. It is the smallest and fastest, and
   it is the only one with membership proofs.

That default has a price: the base variant's security guarantee is the weaker of the two. Its
proof covers an attacker who names the element it will attack before it sees the public key.
The adaptive variant's covers an attacker who chooses later, after watching the system. If
your attacker can wait and choose, that is a reason to take the adaptive variant even without
re-adding.

| | base | adaptive | succinct |
|---|---|---|---|
| module | crate root | `adaptive` | `succinct` |
| a deleted element can be added again | no, refused | yes, under a new [handle](glossary.md#handle) | no, refused |
| membership proofs | yes, at the toy set only | no | no |
| what the paper proves, under stated assumptions | security against an attacker who names its target before it sees the public key | security against an attacker who picks its target at any time | no separate theorem |
| an update message names | the deleted element | a handle standing for it | the deleted element |
| witness size, toy set | 34,464 bytes | 37,782 bytes | 29,224 bytes (succinct toy set) |
| public key size, toy set | 48,544 bytes | 50,496 bytes | 2,149,984 bytes (succinct toy set) |
| key generation, toy set | 7.36 ms | 7.61 ms | 902 ms (succinct toy set) |
| measured at a 128-bit set | yes | no | no; the public key would be about 110 GiB |

The adaptive variant pays for re-adding with a signature in every witness, 3,309 bytes of
[ML-DSA-65](glossary.md#ml-dsa-65), and a signature check in every witness check. Its handles also cap the number of
additions, counting re-additions, at the number of possible handles, since handles are never
reused: 256 at the toy set, 2^32 at the 128-bit set. Its elements themselves are 32 bytes at
every set. In
return, its update messages do not show the deleted element to anyone who does not know which
handle stands for which element. The manager knows.

All three variants share type and method names, so moving between them changes imports more
than code. [Guarantees and their limits](security.md) states each security claim in full.

### The succinct variant today

In principle a succinct witness stays the same size however long the elements are, while a base
witness grows with them. In practice:

- At the succinct toy set, the only set where it runs, its witness is 29,224 bytes. A base
  witness at that same set is 28,144 bytes, as [The succinct variant](succinct.md) shows. The
  saving needs long elements, and the toy set's are 4 bits.
- Its public key is 2,149,984 bytes at that set, and key generation takes 902 ms.
- At the 128-bit shape its public key would be about 110 GiB, and generating a key there is
  not practical.
- The paper states no separate security theorem for it.

So use it to study the idea, not to save space.

## The parameter set

| set | elements (base, succinct) or handles (adaptive) | deletions, ever | use it for |
|---|---|---|---|
| `TOY` (`Params::toy()`) | 8 bits: 256 elements | 256 | learning, tests, membership proofs; **no security** |
| `PAPER_128` (`Params::paper_128()`) | 32 bits: about 4.3 billion | 2^32 | realistic sizes and timings |
| `SUCCINCT_TOY` (`Params::succinct_toy()`) | 4 bits: 16 elements | 16 | trying the succinct variant; **no security** |
| `SUCCINCT_128` | 32 bits | 2^32 | nothing yet: keys are too large to generate |

**The toy sets protect nothing.** They exist so that tests run in seconds. Nothing in the
code marks a key as a toy key, so check the set of every key you load.

**`PAPER_128` is the set for realistic figures.** It takes its shape from the paper's
128-bit parameters, and its sizes are within 0.4% of the paper's table. "128-bit" is the
paper's estimate of its strength, not checked by this crate: the crate does not estimate how
hard the underlying problems are at this set.
Membership proofs do not run here.

Here is what one accumulator costs at each of the two base sets, with the default trapdoor.

| | toy | 128-bit |
|---|---:|---:|
| secret key | 96 bytes | 96 bytes |
| public key | 48,544 bytes | 17,459,264 bytes (16.65 MiB) |
| accumulator value | 544 bytes | 51,264 bytes (50.06 KiB) |
| witness | 34,464 bytes | 15,493,184 bytes (14.78 MiB) |
| update message, per deletion | 1 byte | 4 bytes |
| generate a key | 7.36 ms | 1.49 s |
| add an element | 5.80 µs | 288 µs |
| issue a witness | 6.37 ms | 1.96 s |
| verify a witness | 330 µs | 128 ms |
| delete an element (manager) | 1.51 ms | 751 ms |
| update a witness over one deletion (holder) | 2.19 ms | 1.00 s |

Three things to plan for:

- **Issuing gets slower over time.** Issuing a witness also corrects it for every deletion
  made so far, at about the cost of one holder update each. The figure above is for an
  accumulator with no deletions yet.
- **Holders pay for every deletion.** Each deletion costs every remaining holder about 1 s at
  the 128-bit set, and a holder catching up on several pays for each.
- **The deletion budget is for life.** When it runs out, the accumulator refuses further
  deletions, and you need a new one.

## The trapdoor distribution

The trapdoor is the secret part of the key that lets the manager make witnesses. It can be
drawn in two ways, `Gaussian` (the default) or `Ternary`. The choice is part of the parameter
set, so values made under one refuse to work with values made under the other.

What it changes in practice:

- **Key generation time.** At the 128-bit set a key takes 1.49 s with `Gaussian` and 109 ms
  with `Ternary`; at the toy set, 7.36 ms and 871 µs. Every other operation takes about the
  same time under both.
- **Sizes, in the succinct variant only.** At the succinct toy set `Ternary` makes the public
  key 1,372,384 bytes instead of 2,149,984, and the witness 24,904 bytes instead of 29,224.
  In the base and adaptive variants the sizes are identical.

What it changes in security: with `Gaussian` the public key is provably close to random,
whatever the attacker's computing power, so this step adds no assumption. With `Ternary` it only looks random if
one more lattice problem is hard. That is an extra unproven assumption, though the paper's
security proof for the base variant already relies on one of the same kind.

**If you are unsure, use `Gaussian`.** It is the default and the paper's construction, and it
adds no assumption. Its only cost is slower key generation, which you pay once per key.

## In code

```rust
use kln_accumulator::{Params, ParamsSpec, TrapdoorDistribution};
use std::sync::Arc;

// Learning and tests: the toy set. It gives no security.
let toy = Arc::new(Params::toy()?);
assert_eq!(toy.spec().element_bits, 8);
assert_eq!(toy.spec().max_deletions, 256);

// Realistic sizes and timings: the 128-bit set, with the default Gaussian trapdoor.
let realistic = Arc::new(Params::paper_128()?);
assert_eq!(realistic.spec().trapdoor, TrapdoorDistribution::Gaussian);
assert_eq!(realistic.spec().element_bits, 32);

// The same shape with a ternary trapdoor is a different parameter set.
let ternary = Params::try_from(ParamsSpec::PAPER_128.with_trapdoor(TrapdoorDistribution::Ternary))?;
assert_ne!(ternary.spec(), realistic.spec());
# Ok::<(), kln_accumulator::Error>(())
```

The variant is chosen by the module you take the key from: `kln_accumulator::SecretKey`,
`kln_accumulator::adaptive::SecretKey` or `kln_accumulator::succinct::SecretKey`. Each takes
the parameter set when the key is made. [Parameter sets and trapdoor distributions](parameters.md)
covers custom sets and every setting in detail.
