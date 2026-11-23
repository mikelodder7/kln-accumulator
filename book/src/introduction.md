# Introduction

`kln-accumulator` is a Rust library for keeping a list of members, in which each member can show
that they are on the list and anyone can check that against one short public value. When a
member is removed, their proof of membership stops working and everyone else brings theirs up
to date from a public notice.

It is a pure-Rust implementation of the lattice-based positive dynamic accumulator of the
research paper ePrint 2025/1099, which this book calls "the paper". The chapter [Accumulators in plain words](concepts.md) explains what each of those
words means.

> **Read this first.** This is research code. It has not been audited. It is not constant
> time: how long some of its operations take depends on secrets, so someone who can time them
> may learn those secrets. Its toy settings, which the examples use, protect nothing at all. Membership proofs run only at those toy settings. Use the crate to learn, study and
> evaluate the scheme. Do not use it to guard anything real yet. The chapter
> [Guarantees and their limits](security.md) lists what is established and what is not.

## Who this book is for

- **You want to understand what an accumulator is** and what this one can do. Read
  [Accumulators in plain words](concepts.md). No cryptography is assumed.
- **You are evaluating a [post-quantum](concepts.md#lattice-based-and-post-quantum)
  revocation scheme** for credentials or access lists, and want real sizes and timings. Read [Which variant and which settings](choosing.md) and
  [Benchmarks and sizes](benchmarks.md).
- **You are writing a prototype** and want code that compiles. Start with
  [Your first accumulator](tutorial.md), then look up tasks in [How do I…](recipes.md).
- **You know the field already** and want each type in detail. Go straight to the reference
  chapters, starting at [Parameter sets and trapdoor distributions](parameters.md).

## How to read this book

The book has five parts.

1. **Start here.** Read these pages in order. They take you from no knowledge of accumulators
   to a working program and to the right page for any task. They use no mathematics.
   - [Accumulators in plain words](concepts.md): the ideas and the words, with one everyday
     picture.
   - [Your first accumulator](tutorial.md): a complete program, step by step.
   - [Which variant and which settings](choosing.md): the decisions you make before you write
     code, with real figures.
   - [How do I…](recipes.md): short, task-first code.
   - [Deploying it](deploying.md): who keeps what, and what to publish in which order.
   - [Troubleshooting](troubleshooting.md): from a symptom to its cause and fix.
   - [The rules that keep you safe](rules.md): what the crate leaves to you.
   - [Frequently asked questions](faq.md) and the [Glossary](glossary.md).
2. **Reference: the types, one by one.** One chapter per area of the API. Use these by need;
   each recipe links to the one that covers it.
3. **Security.** [Guarantees and their limits](security.md) says what is proved, under which
   assumptions, and what is not established. [Misuse](misuse.md) lists every way the API can
   be used wrongly, and whether the code refuses it or leaves it to you.
4. **Measurements.** [Benchmarks and sizes](benchmarks.md) has the timings and sizes that the
   rest of the book quotes.
5. **Under the hood (advanced).** The lattice types underneath the accumulator, how the API
   maps to the [vb20 pairing accumulator](glossary.md#vb20-pairing-accumulator), and the
   papers cited. You can skip this part unless you build
   [linking relations](glossary.md#linking-relation) for proofs or work on the crate itself.

## How the reference chapters are organised

Every public struct and enum has its own section, and every section has the same five parts.

- **What it is**: the value and its place in the scheme.
- **Why it exists**: the problem it solves, or the mistake it prevents.
- **How to use it**: an example that is compiled and run by the crate's test suite, or a
  pointer to one.
- **Security**: what it guarantees and under what assumption, whether it is secret,
  holder-private or public, and what happens when it is dropped.
- **Using it safely**: what the code refuses on its own, with the `Error` variant it returns,
  and what remains your job.

The crate sorts every type into one of three classes, and the book uses the same words.

| class | meaning |
|---|---|
| secret | owner only; disclosure breaks the scheme |
| holder-private | private to one holder; shown to no one, used in proofs |
| public | may be published |

Secret and holder-private values are overwritten in memory when they are dropped. What that
covers, and what it cannot cover, is set out in [Guarantees and their limits](security.md).

## The examples

Every Rust example in this book is compiled by `cargo test`, and almost all are also run. The
few that are only compiled say why: they prove membership, which takes seconds, or they run
the accumulator at the 128-bit [parameter set](concepts.md#settings-parameter-sets). Some examples are meant *not* to compile: they
show a misuse that the type system forbids, and the test suite checks that they fail.

The examples seed their random number generator with a constant so that they are
reproducible. Real code must use a generator seeded from the operating system.

The examples use the toy parameter sets. The toy sets give no security.
