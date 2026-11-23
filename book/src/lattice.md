# The lattice building blocks

> **In short.** The pieces underneath the accumulator: polynomials, vectors and matrices of
> them, the [gadget](glossary.md#gadget), the [trapdoor](glossary.md#trapdoor) with its
> samplers, and seeded random sampling. This chapter is advanced. Using the accumulator does not
> require it.
>
> **Read this when** you build a [linking relation](glossary.md#linking-relation) for a
> membership proof, inspect a public key, write tests at this level, or work on the crate
> itself.
>
> **New here?** You can skip this chapter. Come back when you build a linking relation;
> [Prove membership without revealing the element](recipes.md#prove-membership-without-revealing-the-element)
> shows the few calls you need.

Underneath the accumulator sits a small linear-algebra layer: a polynomial [ring](glossary.md#ring-and-ring-degree), vectors and
matrices over it, the gadget matrix, the trapdoor with its [preimage samplers](glossary.md#preimage-preimage-sampler), and seeded
uniform sampling. Most integrations never touch these types directly. You meet them in three
places: building a [linking relation](proofs.md) for a membership proof, inspecting a public
key, and writing tests.

These types live in the module `kln_accumulator::lattice`, not at the crate root, which holds
the accumulator API built on them. Import them from there; the crate root does not re-export
them.

```rust,compile_fail
use kln_accumulator::Poly; // error[E0432]: unresolved import `kln_accumulator::Poly`
```

The sections here are brief. Each still has the five parts.

One rule holds for the whole layer: **the value types carry no parameters.** A `Poly` is a
list of coefficients; it does not know its ring. Every operation takes the ring as an
argument and fails with `Error::DimensionMismatch` when an operand does not fit. A value
decoded from bytes is not checked against any ring until you call `validate`.

The coefficient type itself, `Coeff`, is a type alias for a 192-bit unsigned integer from the
`crypto-bigint` crate, wide enough for the largest modulus the crate defines. It is an alias,
not a struct, so it has no section of its own.

## `Ring`

**What it is**

The polynomial ring `R_q = Z_q[X]/(X^d + 1)`, for `d` a power of two and `q` a prime with
`q ≡ 5 (mod 8)`, with the precomputed tables its multiplication needs.

**Why it exists**

Every value in the scheme is made of elements of this ring. The moduli are chosen so that
`X^d + 1` splits into exactly two factors modulo `q`, which the membership proof needs. Such
moduli have no fast transform of their own, so the ring multiplies exactly over the integers,
with transforms modulo several auxiliary word-size primes, and reduces afterwards.

**How to use it**

You do not build one. A parameter set owns it: `params.ring()`.

```rust
use kln_accumulator::Params;

let params = Params::toy()?;
let ring = params.ring();
assert_eq!(ring.degree(), 64);
assert_eq!(ring.modulus().bit_width_vartime(), 60);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped. Arithmetic in the ring
is not hardened against timing or other side channels, apart from the sign handling listed in
[Guarantees and their limits](security.md#timing-what-is-and-is-not-constant-time).

**Using it safely**

The ring is validated with its parameter set, so a `Ring` you hold is well formed.
`Ring::center` on a value that is not below `q` gives a meaningless result: validate values
from outside first.

## `CenteredCoeff`

**What it is**

The representative of a residue in `(−q/2, q/2]`, as a sign and a magnitude. It is what
`Ring::center` returns.

**Why it exists**

Short vectors, such as witnesses, are integer vectors with small positive and negative
entries, but they are stored as residues modulo `q`. Norms are taken over the integers. The
centred lift recovers the integer, and it is exact because every parameter set keeps short
values below `q/2`.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::Coeff;

let params = Params::toy()?;
let ring = params.ring();
let three = ring.center(&Coeff::from_u64(3));
assert!(!three.is_negative());
assert_eq!(*three.magnitude(), Coeff::from_u64(3));
// q − 3 is the residue of −3.
let minus_three = ring.center(&ring.modulus().wrapping_sub(&Coeff::from_u64(3)));
assert!(minus_three.is_negative());
assert_eq!(*minus_three.magnitude(), Coeff::from_u64(3));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped.

**Using it safely**

Nothing is refused here. Your job is the precondition of `Ring::center`: pass a reduced value.

## `Poly`

**What it is**

An element of the ring: `d` coefficients in `[0, q)`, constant term first.

**Why it exists**

It is the atom every vector and matrix is built from. Besides the ring operations it has the
automorphism `σ₋₁: X ↦ X⁻¹` of the ring, `Poly::sigma_minus_one`, which the membership proof
uses.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{Coeff, Poly};

let params = Params::toy()?;
let ring = params.ring();
let mut coefficients = vec![Coeff::ZERO; ring.degree()];
coefficients[0] = Coeff::from_u64(3);
let three = Poly::new(coefficients, ring)?;

let six = three.add(&three, ring)?;
assert_eq!(six, three.mul_small(2, ring)?);
assert_eq!(six.sub(&three, ring)?, three);
assert_eq!(three.neg(ring)?.add(&three, ring)?, Poly::zero(ring));
assert_eq!(three.mul(&three, ring)?.norm_inf(ring), Coeff::from_u64(9));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

A public type that is wiped on drop. A polynomial is a general value, but every secret the
crate holds is made of polynomials, so its coefficients are overwritten whenever one is
dropped. `Debug` prints the coefficients; the wrapper types that hold secrets print none.

**Using it safely**

The code refuses, at `Poly::new` and `Poly::validate`, a wrong number of coefficients
(`Error::DimensionMismatch`) and a coefficient that is not below `q`
(`Error::CoefficientOutOfRange`); and at `TryFrom<&[u8]>`, a length that is not a whole number
of coefficients (`Error::InvalidEncodingLength`).

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::lattice::{Coeff, Poly};

let params = Params::toy()?;
let ring = params.ring();
let short = Poly::new(vec![Coeff::ZERO; 3], ring);
assert!(matches!(short, Err(Error::DimensionMismatch { expected: 64, found: 3 })));
let unreduced = Poly::new(vec![*ring.modulus(); 64], ring);
assert!(matches!(unreduced, Err(Error::CoefficientOutOfRange)));
# Ok::<(), kln_accumulator::Error>(())
```

Your job: a polynomial decoded from bytes or through serde is not checked against any ring.
Call `validate` before you use it. And do not `Debug`-print a polynomial that holds something
private.

## `PolyVec`

**What it is**

A column vector of polynomials. The accumulator value, the public vector `u`, witnesses and
the vectors of a proof are all of this type underneath.

**Why it exists**

It gives vectors their arithmetic, their norms and a self-describing byte form, which the
proofs use.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{Coeff, Poly, PolyVec};

let params = Params::toy()?;
let ring = params.ring();
let mut c = vec![Coeff::ZERO; ring.degree()];
c[0] = Coeff::from_u64(2);
let two = Poly::new(c, ring)?;
let v = PolyVec::from(vec![two.clone(), Poly::zero(ring)]);

assert_eq!(v.len(), 2);
assert_eq!(v.as_slice()[0], two);
assert_eq!(v.mul_small(3, ring)?.norm_inf(ring), Coeff::from_u64(6));
assert_eq!(v.sub(&v, ring)?, PolyVec::zero(2, ring));
assert_eq!(v.concat(&v).len(), 4);
// The self-describing byte form round-trips.
let bytes = Vec::<u8>::from(&v);
assert_eq!(PolyVec::try_from(bytes.as_slice())?, v);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

A public type that is wiped on drop, because its entries are. `From<&PolyVec> for Vec<u8>`
writes into a plain `Vec` that is not wiped: do not use it on a vector that holds a secret.

**Using it safely**

The code refuses operands of different lengths or of the wrong degree
(`Error::DimensionMismatch`). Decoding refuses an encoding that would not re-encode to the same
bytes, such as an empty vector with a non-zero degree word. As for `Poly`, a decoded vector is
unchecked until you call `validate`.

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::lattice::PolyVec;

let params = Params::toy()?;
let ring = params.ring();
let mismatched = PolyVec::zero(2, ring).add(&PolyVec::zero(3, ring), ring);
assert!(matches!(mismatched, Err(Error::DimensionMismatch { .. })));
# Ok::<(), kln_accumulator::Error>(())
```

## `Shape`

**What it is**

The dimensions of a matrix: `rows` and `cols`, two public fields. It is `Copy`.

**Why it exists**

Functions that take or return matrix dimensions would otherwise take two bare integers, which
are easy to swap. A named pair cannot be passed the wrong way round without it showing.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{PolyMatrix, Shape};

let params = Params::toy()?;
let shape = Shape { rows: 1, cols: params.spec().m };
assert_eq!(PolyMatrix::zero(shape, params.ring()).shape(), shape);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped.

**Using it safely**

Nothing to refuse; it is a pair of numbers. The operations that receive a shape check it
against their operands.

## `PolyMatrix`

**What it is**

A matrix of polynomials, stored row by row. The public matrices `A` and `B`, the matrices of a
linking relation and the succinct variant's extra matrices are of this type.

**Why it exists**

It gives matrices their arithmetic and their products with vectors.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{DomainLabel, PolyMatrix, Seed, Shape, UniformSampler};

let params = Params::toy()?;
let ring = params.ring();
let mut sampler = UniformSampler::new(&Seed::from([1; 32]), DomainLabel::from(&b"doc"[..]));
let a = sampler.matrix(Shape { rows: 2, cols: 3 }, ring);
let v = sampler.vector(3, ring);

assert_eq!(a.mul_vec(&v, ring)?.len(), 2);
assert_eq!(a.sub(&a, ring)?, PolyMatrix::zero(a.shape(), ring));
assert_eq!(a.hconcat(&a)?.shape(), Shape { rows: 2, cols: 6 });
assert!(a.get(0, 2).is_some());
assert!(a.get(2, 0).is_none());
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

A public type that is wiped on drop, because its entries are.

**Using it safely**

The code refuses an entry count that does not match the shape, a shape whose `rows · cols`
overflows, a shape with zero rows and some columns or the reverse (it would need no entries,
so its other dimension would be bounded by nothing; `PolyMatrix::zero` still builds one), and
operands whose shapes do not fit (`Error::DimensionMismatch`). Deserialization checks the entry count against the shape
but not the coefficients: call `validate` before use.

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::lattice::{Poly, PolyMatrix, Shape};

let params = Params::toy()?;
let ring = params.ring();
let too_few = PolyMatrix::new(Shape { rows: 2, cols: 2 }, vec![Poly::zero(ring); 3]);
assert!(matches!(too_few, Err(Error::DimensionMismatch { expected: 4, found: 3 })));
# Ok::<(), kln_accumulator::Error>(())
```

## `NttMatrix`

**What it is**

A matrix with every entry kept in transformed form, ready for multiplication.

**Why it exists**

Speed. A product with a `PolyMatrix` transforms both operands every time. A matrix that is
multiplied many times, such as a public key's, is transformed once into an `NttMatrix`, after
which each product costs only the transforms of the other operand and the result.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{DomainLabel, NttMatrix, Seed, Shape, UniformSampler};

let params = Params::toy()?;
let ring = params.ring();
let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"n"[..]));
let a = sampler.matrix(Shape { rows: 2, cols: 3 }, ring);
let x = sampler.vector(3, ring);

let cached = NttMatrix::new(&a, ring)?;
assert_eq!(cached.shape(), a.shape());
assert_eq!(cached.mul_vec(&x, ring)?, a.mul_vec(&x, ring)?);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

A public type that is wiped on drop: the sampler keeps the trapdoor in this form, so every
transformed entry overwrites itself. `Debug` prints the transformed values.

**Using it safely**

The code refuses operands that do not fit (`Error::DimensionMismatch`). Your job: do not
`Debug`-print one that you built from something private.

## `Gadget`

**What it is**

The gadget matrix `G` of a parameter set and its inverse `G⁻¹`, the base-`b` digit
decomposition of Section 2.1 of ePrint 2025/1099. `G⁻¹(u)` is the unique vector with coefficients in `[0, b)` that `G` maps back
to `u`.

**Why it exists**

The gadget is what makes the trapdoor work, and digit decomposition is how the scheme keeps
things short: a deletion adds `B_{1y}·G⁻¹(u)` to the accumulator value, and a witness update
adds a vector made of small digits.

**How to use it**

A parameter set owns it: `params.gadget()`.

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{DomainLabel, Seed, Shape, UniformSampler};

let params = Params::toy()?;
let gadget = params.gadget();
assert_eq!(gadget.base(), 64);
assert_eq!(gadget.digits(), 10);
assert_eq!(gadget.shape(), Shape { rows: 1, cols: 10 });

// G · G⁻¹(u) = u.
let u = UniformSampler::new(&Seed::from([0; 32]), DomainLabel::from(&b"doc"[..]))
    .vector(params.spec().n, params.ring());
let digits = gadget.inverse_vec(&u)?;
assert_eq!(digits.len(), 10);
assert_eq!(gadget.mul_vec(&digits)?, u);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped.

**Using it safely**

The code refuses a vector or matrix of the wrong height (`Error::DimensionMismatch`).

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::lattice::PolyVec;

let params = Params::toy()?;
let too_long = PolyVec::zero(2, params.ring());
let refused = params.gadget().inverse_vec(&too_long);
assert!(matches!(refused, Err(Error::DimensionMismatch { .. })));
# Ok::<(), kln_accumulator::Error>(())
```

## `BitString`

**What it is**

A string of `ℓ` bits, as a list of booleans. It is what `Element::to_bits` returns.

**Why it exists**

The scheme evaluates a function on the bits of an element one at a time. `Element` stores bits
packed in bytes; `BitString` is the unpacked form the evaluation walks over. It is also the
form in which an element's bits go into a linking relation.

**How to use it**

```rust
use kln_accumulator::{Element, Params};
use kln_accumulator::lattice::BitString;

let params = Params::toy()?;
let element = Element::try_from(&[0b0000_0101u8][..])?;
let bits: BitString = element.to_bits(&params)?;
assert_eq!(bits.as_slice(), &[true, false, true, false, false, false, false, false]);
assert_eq!(BitString::from(vec![true, false]).as_slice(), &[true, false]);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

As public or as private as the element it came from. Like the element, it is overwritten when
dropped, since in a membership proof the element is the prover's hidden input.

**Using it safely**

`Element::to_bits` validates the element against the set first (`Error::InvalidElement`). A
`BitString` built with `From<Vec<bool>>` has whatever length you gave it; `Indicator::new`
refuses one that does not have `ℓ` bits (`Error::DimensionMismatch`).

## `Indicator`

**What it is**

The indicator function `1_y`, "is the input equal to `y`", evaluated homomorphically on the
public matrix `B` (Theorem 2.2 and Corollary 2.2.1 of ePrint 2025/1099).

**Why it exists**

It is the mechanism of deletion. Deleting `y` adds `B_{1y}·G⁻¹(u)` to the accumulator value,
where `B_{1y}` is this evaluation. For every `x ≠ y` there is a short matrix `H` that carries
the witness of `x` along; for `x = y` there is none, and that is why the deleted element's
witness dies. The accumulator and witness types use it internally; it is public so that the
equations can be checked.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{BitString, DomainLabel, Indicator, Seed, Shape, UniformSampler};

let params = Params::toy()?;
let ring = params.ring();
let ell = params.spec().element_bits as usize;
let mut sampler = UniformSampler::new(&Seed::from([9; 32]), DomainLabel::from(&b"i"[..]));
let b = sampler.matrix(Shape { rows: params.spec().n, cols: ell * params.m_prime() }, ring);
let u = sampler.vector(params.spec().n, ring);
let y = BitString::from(vec![false; ell]);
let x = BitString::from(vec![true; ell]);

let indicator = Indicator::new(&params, &y, &b)?;
// The vector forms equal the matrix forms applied to G⁻¹(u).
let digits = params.gadget().inverse_vec(&u)?;
assert_eq!(indicator.eval_f_vec(&u)?, indicator.eval_f()?.mul_vec(&digits, ring)?);
assert_eq!(indicator.eval_fx_vec(&x, &u)?, indicator.eval_fx(&x)?.mul_vec(&digits, ring)?);
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy: it borrows a public matrix and a bit string. Nothing of its own is
wiped on drop.

**Using it safely**

The code refuses a bit string that does not have `ℓ` bits, and a matrix that is not
`n × ℓm'` (`Error::DimensionMismatch`).

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::lattice::{BitString, Indicator, PolyMatrix, Shape};

let params = Params::toy()?;
let b = PolyMatrix::zero(Shape { rows: 1, cols: 80 }, params.ring());
let short = BitString::from(vec![true; 3]);
assert!(matches!(Indicator::new(&params, &short, &b), Err(Error::DimensionMismatch { .. })));
# Ok::<(), kln_accumulator::Error>(())
```

## `Seed`

**What it is**

A 32-byte sampling seed: the input of a SHAKE256 stream.

**Why it exists**

Everything random in the crate that must be reproducible comes from a seed: the public
matrices, the trapdoor, the randomness of each witness, the prover's masks. A key needs to
keep only one root seed, and derives the rest under distinct labels.

**How to use it**

Build one from 32 bytes with `Seed::from`.

```rust
use kln_accumulator::lattice::Seed;

let seed = Seed::from([1; 32]);
assert_eq!(seed, Seed::from([1; 32]));
assert_ne!(seed, Seed::from([2; 32]));
assert_eq!(format!("{seed:?}"), "Seed { .. }");
```

**Security**

Secret. A seed may be secret or public depending on its use, so the crate treats every seed as
secret: it is overwritten when dropped, it is neither `Copy` nor `Clone`, equality is constant
time, and `Debug` prints no bytes. The crate never hands out the bytes of a seed it derives.

```rust,compile_fail
use kln_accumulator::lattice::Seed;

let seed = Seed::from([1; 32]);
let copy = seed.clone(); // error: no method named `clone` found for struct `Seed`
```

**Using it safely**

Your job: `Seed::from(array)` takes a copy. The array you built it from is still yours, and
still holds the bytes: wipe it.

## `DomainLabel`

**What it is**

A byte-string label that separates independent streams drawn from one seed.

**Why it exists**

One seed feeds many purposes. If two purposes read the same stream they would get the same
values. A label per purpose makes the streams independent. The stream absorbs the label's
length before the label, so no two labels collide.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{DomainLabel, Seed, UniformSampler};

let params = Params::toy()?;
let seed = Seed::from([0; 32]);
let draw = |label: &[u8]| UniformSampler::new(&seed, DomainLabel::from(label)).poly(params.ring());
assert_ne!(draw(b"one"), draw(b"two"));
assert_eq!(draw(b"one"), draw(b"one"));
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public value, no secrecy. Nothing in it needs wiping when it is dropped.

**Using it safely**

Nothing is refused. Your job: if you draw from a seed yourself, use a label of your own for
each purpose. The crate's labels have the form `kln/<component>/<purpose>`; stay out of that
namespace.

## `UniformSampler`

**What it is**

A SHAKE256 stream of uniform elements of `Z_q`, drawn by rejection sampling, with methods that
return uniform polynomials, vectors and matrices.

**Why it exists**

Public matrices must be uniform and reproducible from a seed, so that a key can be rebuilt
from its root seed and so that two parties can expand the same matrix from a shared seed. In
this book it also builds the matrices of a linking relation.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{DomainLabel, Seed, Shape, UniformSampler};

let params = Params::toy()?;
let ring = params.ring();
let mut sampler = UniformSampler::new(&Seed::from([3; 32]), DomainLabel::from(&b"doc"[..]));
let p = sampler.poly(ring);
let v = sampler.vector(4, ring);
let m = sampler.matrix(Shape { rows: 1, cols: 20 }, ring);
assert_eq!(p.coefficients().len(), ring.degree());
assert_eq!(v.len(), 4);
assert_eq!(m.shape(), Shape { rows: 1, cols: 20 });
// Every coefficient is reduced modulo q.
assert!(p.validate(ring).is_ok() && v.validate(ring).is_ok() && m.validate(ring).is_ok());
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Public output, secret state. The values drawn are as public as the seed allows. The stream's
internal state gives back the seed, so it is overwritten when the sampler is dropped, and
`Debug` does not print it.

**Using it safely**

Nothing is refused. Your job: the output is only as unpredictable as the seed. A sampler
seeded with a public constant, as in the example, produces public values.

## `Trapdoor`

**What it is**

The secret matrix `T_A` that goes with the public matrix `A`, with coefficients drawn from the
parameter set's `TrapdoorDistribution`, and the two preimage samplers that use it,
`sample_pre` and `sample_left`. They are `SamplePre` (Theorem 2.1 of ePrint 2025/1099) and
`SampleLeft` (its Lemma 2.6), built on the perturbation method of ePrint 2011/501 with the
samplers of ePrint 2017/308.

**Why it exists**

It is the manager's capability: with `T_A`, and only with it, one can sample a short vector
that a public matrix maps to a chosen target. The accumulator's `SecretKey` holds one and
never exposes it. The type is public so that the samplers can be studied and tested on their
own.

**How to use it**

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{DomainLabel, Seed, Trapdoor, UniformSampler};

let params = Params::toy()?;
let ring = params.ring();
let (a, trapdoor) = Trapdoor::generate(&params, &Seed::from([1; 32]))?;
let u = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"u"[..]))
    .vector(params.spec().n, ring);

// A short preimage of u under A, determined by the seed.
let v = trapdoor.sample_pre(&params, &a, &u, &Seed::from([3; 32]))?;
assert_eq!(a.mul_vec(&v, ring)?, u);
assert_eq!(trapdoor.sample_pre(&params, &a, &u, &Seed::from([3; 32]))?, v);
assert_eq!(format!("{trapdoor:?}"), "Trapdoor { .. }");
# Ok::<(), kln_accumulator::Error>(())
```

**Security**

Secret. Its coefficients, its transformed forms and every intermediate of a draw are
overwritten when dropped. It is neither `Copy` nor `Clone`; equality is constant time in the
coefficients; `Debug` prints nothing; its encodings are built and parsed in wiped buffers.

What the sampler gives: the preimage equation holds exactly, and the widths are derived per
parameter set from the smoothing conditions of ePrint 2011/501 and ePrint 2017/308. What it
does not give: a proven bound on its floating-point loss. The sampler uses `f64`; a trapdoor
is refused unless its perturbation pivots are above a floor, and the tests measure the error
of the computed centres. That is evidence, not a bound.

```rust,compile_fail
use kln_accumulator::Params;
use kln_accumulator::lattice::{Seed, Trapdoor};

let (_a, trapdoor) = Trapdoor::generate(&Params::toy()?, &Seed::from([1; 32]))?;
let copy = trapdoor.clone(); // error: no method named `clone` found for struct `Trapdoor`
# Ok::<(), kln_accumulator::Error>(())
```

**Using it safely**

The code refuses a trapdoor that does not fit its parameter set, and reports
`Error::InvalidTrapdoor` when key generation draws no acceptable one, when a draw falls beyond
the sampler's tail cut repeatedly, and when the matrix is not the one the trapdoor was
generated with: the sampler checks that its result is a preimage before it returns it.
Matrices and targets of the wrong shape are `Error::DimensionMismatch`.

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::lattice::{DomainLabel, PolyVec, Seed, Trapdoor, UniformSampler};

let params = Params::toy()?;
let (a, trapdoor) = Trapdoor::generate(&params, &Seed::from([1; 32]))?;
// A target with two entries where n = 1.
let target = PolyVec::zero(2, params.ring());
let refused = trapdoor.sample_pre(&params, &a, &target, &Seed::from([3; 32]));
assert!(matches!(refused, Err(Error::DimensionMismatch { .. })));
// A matrix generated with another trapdoor: the draw would not be a preimage.
let (foreign, _) = Trapdoor::generate(&params, &Seed::from([2; 32]))?;
let u = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"u"[..]))
    .vector(params.spec().n, params.ring());
let withheld = trapdoor.sample_pre(&params, &foreign, &u, &Seed::from([3; 32]));
assert!(matches!(withheld, Err(Error::InvalidTrapdoor)));
# Ok::<(), kln_accumulator::Error>(())
```

Your job, if you call the samplers directly:

- **One seed per target, and never two different preimages for one target.** Two different
  short preimages of one target under one matrix give away a short vector of its kernel, and
  enough of them give away the trapdoor. The accumulator keeps this rule for you by deriving
  every sampling seed from a PRF. `sample_pre` and `sample_left` do not: they sample from
  whatever seed you pass, as the example below shows. The reverse, one seed for two targets or
  two matrices, does not repeat a draw: the sampler hashes the seed together with the matrix, the target
  and the sampling mode before it draws, so the two draws share no randomness.
- **Prefer not to call them.** Use `MembershipWitness::new`.

```rust
use kln_accumulator::Params;
use kln_accumulator::lattice::{DomainLabel, Seed, Trapdoor, UniformSampler};

let params = Params::toy()?;
let ring = params.ring();
let (a, trapdoor) = Trapdoor::generate(&params, &Seed::from([1; 32]))?;
let u = UniformSampler::new(&Seed::from([2; 32]), DomainLabel::from(&b"u"[..]))
    .vector(params.spec().n, ring);

// NOT refused: two seeds, one target, two different short preimages.
let first = trapdoor.sample_pre(&params, &a, &u, &Seed::from([3; 32]))?;
let second = trapdoor.sample_pre(&params, &a, &u, &Seed::from([4; 32]))?;
assert_ne!(first, second);
// Their difference is a non-zero short vector that A maps to zero, which is exactly what must
// stay hard to find.
let kernel = first.sub(&second, ring)?;
assert_eq!(a.mul_vec(&kernel, ring)?, kln_accumulator::lattice::PolyVec::zero(params.spec().n, ring));
# Ok::<(), kln_accumulator::Error>(())
```
