# Security policy

## Status

`kln-accumulator` is a research implementation of the accumulator of ePrint 2025/1099. Use it
to study and evaluate the scheme. Do not use it to protect anything real.

- **It has not been audited.** It is not published to crates.io.
- **It is not constant time.** Only a few steps that handle secrets are written so that neither
  their running time nor the memory they touch depends on the secret:
  - the draws of a Gaussian trapdoor's coefficients, at key generation and whenever a key is
    decoded;
  - the sign handling of the `Z_q` arithmetic under every product with a secret (except one
    branch on the magnitude at the 60-bit toy set, which gives no security; see the book);
  - the block evaluation of a witness update;
  - equality of secrets, and the hex codec of secret and holder-private values.

  The evidence is the assembly of one x86-64 release build for the first two (the last
  correction of the Chinese remaindering by source reading only) and source reading for the
  rest. No dynamic constant-time test has been run on any of them. Everything else is not
  constant time, in particular the wide Gaussian draw of every witness, the prover's masks and
  the real-centre sampler behind every preimage. An attacker who can time the manager or a
  prover is outside every guarantee the crate states.
- **The toy parameter sets give no security.** `ParamsSpec::TOY` and `ParamsSpec::SUCCINCT_TOY`
  exist so that tests and examples run in seconds, and nothing in the code stops you from using
  them.
- **`ParamsSpec::PAPER_128` is the only set meant for security that runs.** Its shape and its
  128-bit label come from Table 2 of the paper; the crate derives the widths and bounds the
  paper's theorems ask for, but does not estimate the hardness of the resulting lattice
  problems. Keys cannot be generated in practice at `ParamsSpec::SUCCINCT_128`.
- **Membership proofs run only at the toy sets**, so no set gives both a secure accumulator and
  a membership proof for it.

The details, with the evidence for each item, are in the book:

- [`book/src/security.md`](book/src/security.md): what is proved and under which assumptions,
  who is trusted, secret handling, what is and is not constant time, and what is not
  established.
- [`book/src/misuse.md`](book/src/misuse.md): every way the API can be used wrongly, and for
  each whether the code refuses it or leaves it to you.

## What to report

In scope:

- **The crate's code.** For example: a witness or a proof that verifies for a statement that is
  false; a way to make the key sample a second preimage for one element; a keyed operation that
  accepts a manager state it should refuse; a decoder that accepts non-canonical bytes or does
  work out of proportion to its input; a panic reachable through the public API; a secret left
  unwiped where the book says it is wiped; a step listed as constant time that is not.
- **Its parameter derivations.** A Gaussian width, norm bound, modulus or rank that the crate
  derives and that does not meet the condition it cites, or a place where the code departs from
  the paper without saying so.
- **Its documentation, where it promises more than the code does.** The book, the API
  documentation or the README stating a guarantee, a refusal or a constant-time property that
  the code does not deliver.

Out of scope:

- **The papers themselves.** A flaw in a scheme or a theorem as published belongs to its
  authors. How the crate reads or implements a paper is in scope.
- **The toy parameter sets.** That they give no security is stated everywhere they appear.
- **What the book already lists as left to the caller or not established**, unless you show it
  is worse than the book says: the rows of the misuse chapter marked "your responsibility"
  (rollback and forks of the manager state, guessable seeds, unauthenticated publication,
  serializer buffers, transcript context, verifying against a value that is not current, and
  the others listed there), the items under "What is not established" in the security chapter,
  and timing of the steps listed there as not constant time.
- **Attacks by the manager.** The manager is trusted; nothing in the crate protects a holder or
  a verifier from it.

## How to report

Report privately through GitHub's private vulnerability reporting: on the repository's
**Security** tab, choose **Report a vulnerability**. Do not open a public issue or pull request,
or post about it elsewhere, for a suspected vulnerability.

Please include:

- the commit you tested;
- the variant, the parameter set and the trapdoor distribution;
- the steps, or better a test, that reproduce it;
- what you expected, what happened, and which statement of the book or the documentation it
  contradicts, if any.
