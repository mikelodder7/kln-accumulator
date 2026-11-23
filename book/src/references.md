# References

> **In short.** The papers and the standard this book cites, by ePrint number or by title, and
> where in the book each is used.
>
> **Read this when** you want to check a claim against its source.
>
> **New here?** You can skip this chapter. The paper behind the whole crate is ePrint
> 2025/1099; the others are works and a standard that it builds on.

Works are cited by their ePrint number when they have one, and otherwise by title, as printed
in the bibliography of the paper that cites them. Each ePrint paper is at
`https://eprint.iacr.org/<number>`, for example
[eprint.iacr.org/2025/1099](https://eprint.iacr.org/2025/1099). A bracketed number such as "[41] of ePrint 2017/308" is that paper's own numbering.

## The scheme

- **ePrint 2025/1099**: the accumulator, its succinct variant, the adaptive variant and the
  membership proofs (Constructions 4.1 and 4.2, Section 4, Appendix D). Everything in this
  book that says "the paper" means this one.
- **"Accumulators with applications to anonymity-preserving revocation"** (EuroS&P 2017),
  cited by ePrint 2025/1099: the compiler behind the adaptive variant.

## Trapdoors and sampling

- **ePrint 2011/501**: gadget trapdoors, `TrapGen` and `SampleD`.
- **ePrint 2017/308**: the G-lattice and perturbation samplers.
- **ePrint 2007/432**, and reference [55] of ePrint 2017/308 ("An efficient and parallel
  gaussian sampler for lattices", CRYPTO 2010): the nearest-plane and convolution theorems the
  sampler's analysis rests on.
- Reference [41] of ePrint 2017/308 (**"Sampling exactly from the normal distribution"**, ACM
  Transactions on Mathematical Software 42(1), 2016): the exact one-dimensional discrete
  Gaussian sampler.

## Proofs

- **ePrint 2025/1099, Appendix D.2**: the commit-and-prove argument for membership.
- **ePrint 2022/1341**: LaBRADOR, the compression layer of Appendix D.3.
- **"Aggregating falcon signatures with labrador"** (CRYPTO 2024), cited by ePrint 2025/1099:
  the work the paper defers to for the security of the non-interactive proofs. This crate
  cites it and derives nothing from it.
- **"Shorter lattice-based group signatures via 'almost free' encryption and other
  optimizations"** (ASIACRYPT 2021), cited by ePrint 2025/1099: the source of the ring map
  that `SubringMap` implements.

## Standards

- **FIPS 204**: ML-DSA, the signature scheme of the adaptive variant.

## Where each is used in this book

| topic | chapter | reference |
|---|---|---|
| Constructions 4.1 and 4.2, the succinct variant | [Elements](elements.md), [Adaptive](adaptive.md), [Succinct](succinct.md) | ePrint 2025/1099 |
| the security theorems | [Guarantees and their limits](security.md) | ePrint 2025/1099, Theorems 2.1, 4.2, 4.3, 4.4 |
| trapdoor generation and preimage sampling | [Parameters](parameters.md), [Lattice building blocks](lattice.md) | ePrint 2011/501, ePrint 2017/308, ePrint 2007/432 |
| membership proofs and compression | [Membership proofs](proofs.md) | ePrint 2025/1099 Appendix D, ePrint 2022/1341 |
| the adaptive variant's signature | [Adaptive](adaptive.md) | FIPS 204 |
