# Errors

> **In short.** Every operation that can fail returns the crate's one
> [error](glossary.md#error) type instead of panicking. Most of its variants name a mistake the
> crate refused to go along with, such as adding an element twice. This chapter lists every
> variant, what it means and, where it helps, what to do.
>
> **Read this when** an operation returned an `Error` and you want to know why, or you decide
> how your code should react to each kind of refusal.
>
> **New here?** You can skip this chapter until an operation returns an error.
> [The rules that keep you safe](rules.md) covers the mistakes the crate cannot refuse.

Every fallible operation in the crate returns `Result<T, Error>`. Nothing panics on bad input.
Where the [vb20 pairing accumulator](glossary.md#vb20-pairing-accumulator) returned a value, unwrapped, or silently skipped an
operation, this crate returns an error.

## `Error`

**What it is**

The crate's one error type: a `Copy` enum with one variant per reason an operation can refuse.
`kln_accumulator::Result<T>` is `Result<T, Error>`.

**Why it exists**

A refusal is how this crate protects you: most variants name a misuse that would otherwise
give a wrong answer or leak the key. Having one enum with specific variants lets you tell "the
peer sent garbage" from "you are about to break the scheme" and act on each differently.

**How to use it**

Match on the variant. The messages are stable enough to log, and they contain no secret.

```rust
use kln_accumulator::{Element, Error, Params};

let params = Params::toy()?;
let wide = Element::try_from(&[0u8, 0][..])?;
let outcome = wide.validate(&params);
assert_eq!(outcome, Err(Error::InvalidElement));
assert_eq!(Error::InvalidElement.to_string(), "element is not an ℓ-bit string");

// Some variants carry the offending value.
let error = Error::DimensionMismatch { expected: 64, found: 32 };
assert_eq!(error.to_string(), "dimension mismatch: expected 64, found 32");

// It implements std::error::Error, so `?` converts it into a boxed error.
fn check(element: &Element, params: &Params) -> Result<(), Box<dyn std::error::Error>> {
    element.validate(params)?;
    Ok(())
}
assert!(check(&wide, &params).is_err());
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. The variants carry no secret data, so an error can be logged as it
is. Nothing in it needs wiping when it is dropped.

Errors are not uniform in time: an operation that refuses early returns sooner than one that
succeeds. Do not rely on error paths to hide anything.

**Using it safely**

- **Do not retry around a refusal.** `ElementAlreadyAdded`, `InvalidStateTag`,
  `InconsistentState` and `AccumulatorMismatch` mean the manager's view is wrong or the
  request is unsafe. Building a fresh state, or renaming the element, to make the error go away
  cannot leak the key, but it makes the manager forget who was added or deleted and issue
  witnesses it should not.
- **`verify` returns `bool`, not `Result`.** `MembershipWitness::verify` answers `false` for a
  witness that does not verify *and* for inputs that do not fit the public key's parameter
  set. It cannot tell you which. If you need to know, call `validate` on the inputs first.
- **Treat every proof error as "rejected".** `ProofRejected`, `UnsupportedProofDegree`,
  `ParameterMismatch`, `DimensionMismatch` and `CoefficientOutOfRange` can all come out of
  proof verification. A verifier accepts only on `Ok`.
- **Do not show internal errors to peers in more detail than you need.** They carry no
  secrets, but which check failed can still help someone probing your service.

## The variants

### Parameter sets

| variant | meaning |
|---|---|
| `DegreeNotPowerOfTwo(d)` | the [ring degree](glossary.md#ring-and-ring-degree) is not a power of two |
| `DegreeTooLarge(d)` | the ring degree exceeds `ParamsSpec::MAX_DEGREE = 2^13` |
| `ModulusNotPrime` | the modulus is not prime |
| `ModulusNotFiveModEight` | the modulus is not congruent to 5 modulo 8 |
| `BaseTooSmall(b)` | the [gadget](glossary.md#gadget) base is below 2 |
| `ZeroRank` | the module rank `n` is zero |
| `TooFewColumns { m, m_prime }` | `m` does not exceed the gadget width `m'` |
| `ZeroElementBits` | the element length `ℓ` is zero |
| `WidthTooSmall` | the Gaussian width is below the preimage sampler's least width |
| `WitnessBoundTooLarge` | a [norm bound](glossary.md#norm-bound) is not below `q/2`, a dimension of the set overflows, or `[A \| B]` would hold more than `ParamsSpec::MAX_MATRIX_ENTRIES = 2^16` polynomials; also returned when a set cannot carry the succinct variant |
| `InvalidTrapdoorDistribution(byte)` | an encoded set names a distribution that does not exist |
| `ParameterMismatch` | a value belongs to another parameter set than the one it is used with |

### Shapes and encodings

| variant | meaning |
|---|---|
| `DimensionMismatch { expected, found }` | operands, or an operand and the ring, have incompatible dimensions |
| `CoefficientOutOfRange` | a coefficient is not reduced modulo `q` |
| `CoefficientOverBound` | a coefficient of a short value is larger than its encoding allows |
| `NonCanonicalEncoding` | padding bits or reserved bytes are not zero |
| `InvalidEncodingLength(len)` | an encoding is truncated, has trailing bytes, or is not a whole number of coefficients |
| `InvalidElement` | an element is empty, has the wrong length, or sets a bit at or above `ℓ` |
| `InvalidTrapdoor` | a trapdoor does not fit its set, key generation drew no acceptable one, or a preimage was asked under a matrix the trapdoor was not generated with |
| `SeedTooShort(len)` | a caller's key seed of `len` bytes is shorter than `MIN_SEED_BYTES`, 32; pass 32 bytes from a cryptographic generator, or `None` |

### Accumulator operations

| variant | meaning | what to do |
|---|---|---|
| `ElementAlreadyAdded` | the element was added before, and is present or deleted | do not add it; use the adaptive variant if elements must return |
| `ElementNotPresent` | the element was never added, or was deleted | nothing to delete, no witness to issue |
| `DeletionBoundReached` | [`γ`](glossary.md#deletion-bound) deletions were made | start a new accumulator |
| `HandleSpaceExhausted` | all `2^ℓ` [handles](glossary.md#handle) of the adaptive accumulator are used | start a new accumulator |
| `CompressedWitnessOnly` | a base witness was asked of a succinct key | issue it with `succinct::MembershipWitness::new` |
| `InvalidStateTag` | the manager state was altered, or another key tagged it | find the right state; do not build a new one |
| `InconsistentState` | a manager state describes a history that cannot happen | the stored state is corrupt |
| `AccumulatorMismatch` | a witness, a value and a state do not belong together; every keyed operation returns it for a value that is not the state's current one | use the value `ManagerState::current` names |

### Witness updates

| variant | meaning | what to do |
|---|---|---|
| `ElementDeleted` | the holder's own element is among the deletions | the holder was revoked; its witness is dead |
| `CoefficientMismatch` | the update messages do not name the deletions, in order | fetch the batch again |
| `InvalidSignature` | an adaptive witness's signature does not bind the element to its handle | the witness is not for that element |
| `SigningFailed` | ML-DSA signing gave up | report it; the crate's documentation says it does not happen in practice |

### Proofs

| variant | meaning |
|---|---|
| `UnsupportedProofDegree(d)` | proofs need ring degree 64 and the set has another |
| `ProofModulusTooSmall` | the modulus fails a condition of Appendix D.2.3, or the length of the committed message overflows, as for a linking matrix with `usize::MAX` columns |
| `RelationUnsatisfied` | the prover's inputs do not satisfy the statement |
| `ProverAborted` | every attempt of the prover's [rejection-sampling](glossary.md#rejection-sampling) loop aborted |
| `ProofRejected` | a membership proof failed verification |
| `CompressionParameters` | no LaBRADOR parameters fit this relation and modulus |
| `InvalidCompressionLevels(n)` | the number of levels is zero or above the maximum |

The examples that trigger each refusal are in the chapter of the type that returns it, and
[Misuse](misuse.md) collects the ones that matter for security.
