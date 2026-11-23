# Serialization

> **In short.** Every key, accumulator value, witness, update message and proof can be turned
> into bytes or text and read back. This chapter says which encodings each type has, what
> decoding checks and refuses, and where secrets end up when you encode them.
>
> **Read this when** you store a key or the manager state, publish a value, send a witness or a
> proof, or decode bytes that someone else sent you.
>
> **New here?** Read steps 9 and 10 of [Your first accumulator](tutorial.md) and the rule
> [Decode untrusted bytes against the set you expect](rules.md#decode-untrusted-bytes-against-the-set-you-expect)
> first.

Keys are stored, accumulator values and update messages are published, witnesses are sent to
holders, proofs are sent to verifiers. This chapter says how each value is encoded, what
decoding checks, and where secrets end up when you serialize them.

## Two ways to encode

**Packed bytes.** Keys, accumulator values and witnesses have `to_bytes` and `TryFrom<&[u8]>`.
The encoding starts with the 64-byte [parameter set](glossary.md#parameter-set) and then packs coefficients tightly:
`⌈log₂ q⌉` bits per coefficient of a uniform value, and `⌈log₂(2β + 1)⌉` bits per coefficient
of a witness. That is how Table 2 of ePrint 2025/1099 counts sizes. Decoding rebuilds and
validates the parameter set from the prefix.

**Serde.** Every type that is sent or stored implements `serde::Serialize` and
`serde::Deserialize`. Byte strings are raw bytes in binary formats and lowercase hex in
human-readable formats. The crate's tests round-trip its types in postcard, CBOR, BARE, JSON,
TOML and YAML.

Reading, the serde forms of keys, accumulator values, witnesses, parameter sets, matrices and
the base manager state refuse a field they do not name. Hex is read in upper or lower case,
and the proofs, the adaptive manager state, `Shape` and `Record` still accept a field they do
not name. A human-readable form is therefore not a canonical encoding: two texts can decode to
one value. Compare decoded values, or their packed bytes, not the text.

Each `to_bytes` is a thin call to a conversion trait, so `Vec::<u8>::from(&value)` gives the
same bytes for public values, and `Zeroizing::<Vec<u8>>::from(&key)` or
`Zeroizing::<Vec<u8>>::try_from(&witness)` for secret and holder-private ones.

## What each type offers

| type | packed bytes | serde | carries its parameter set | decoding checks |
|---|---|---|---|---|
| `ParamsSpec` | 64 bytes | yes | it is the set | reserved bytes, distribution byte |
| `SecretKey` (all variants) | 96 bytes, wiped buffer | yes | yes | length, the set |
| `PublicKey` (all variants) | yes | yes | yes | length, canonical form, shape and range of every matrix |
| `Accumulator` | yes | yes | yes | length, canonical form, range |
| `MembershipWitness` (all variants) | yes, wiped buffer | yes | yes | length, canonical form, coefficient bound |
| `Element`, `Coefficient` | the element's bytes | yes | no | only that it is not empty; `validate` checks it against a set |
| `ManagerState` | no | yes | through its current value | that the history is possible; the tag is checked at the next keyed use or by `authenticate` |
| `MembershipProof`, `CompressedMembershipProof` | yes | yes | no | layout only; everything else at `finalize` |
| `Poly`, `PolyVec`, `PolyMatrix` | `Poly` and `PolyVec` | yes | no | layout only; call `validate` against a ring |
| `Trapdoor` | yes, wiped buffer | yes | no | layout only; checked against a set when used |
| `Delta` | no | no | yes | not serialized |

Sizes at the defined sets, from the crate's tests:

| value | toy | 128-bit |
|---|---|---|
| secret key (set and root seed) | 96 B | 96 B |
| public key `(A, B, u)` | 48,544 B | 17,459,264 B |
| accumulator value | 544 B | 51,264 B |
| membership witness | 34,464 B | 15,493,184 B |

[Benchmarks and sizes](benchmarks.md) has the full tables.

## Six formats, one value

```rust
use kln_accumulator::{Accumulator, Params};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let params = Arc::new(Params::toy()?);
let acc = Accumulator::random(&mut StdRng::seed_from_u64(0), &params);

// Packed bytes: the 64-byte set, then 64 coefficients of 60 bits.
let packed = acc.to_bytes();
assert_eq!(packed.len(), 544);
assert_eq!(Accumulator::try_from(packed.as_slice())?, acc);

// Binary formats carry the coefficient bytes raw.
let postcard = postcard::to_allocvec(&acc)?;
assert_eq!(postcard::from_bytes::<Accumulator>(&postcard)?, acc);
let cbor = serde_cbor_2::to_vec(&acc)?;
assert_eq!(serde_cbor_2::from_slice::<Accumulator>(&cbor)?, acc);
let bare = serde_bare::to_vec(&acc)?;
assert_eq!(serde_bare::from_slice::<Accumulator>(&bare)?, acc);

// Human-readable formats carry them as lowercase hex.
let hex_body = hex::encode(&packed[64..]);
let json = serde_json::to_string(&acc)?;
assert!(json.contains(&hex_body));
assert_eq!(serde_json::from_str::<Accumulator>(&json)?, acc);
let toml = toml::to_string(&acc)?;
assert!(toml.contains(&hex_body));
assert_eq!(toml::from_str::<Accumulator>(&toml)?, acc);
let yaml = yaml_serde::to_string(&acc)?;
assert!(yaml.contains(&hex_body));
assert_eq!(yaml_serde::from_str::<Accumulator>(&yaml)?, acc);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What decoding refuses

Decoding is strict. For the packed encodings:

| input | error |
|---|---|
| truncated, or with trailing bytes | `Error::InvalidEncodingLength` |
| non-zero padding bits, or non-zero reserved bytes in the parameter-set prefix | `Error::NonCanonicalEncoding` |
| a coefficient not below `q` | `Error::CoefficientOutOfRange` |
| a witness coefficient above the bound | `Error::CoefficientOverBound` |
| an unknown trapdoor distribution byte | `Error::InvalidTrapdoorDistribution` |
| a parameter set beyond `ParamsSpec::MAX_DEGREE` or `ParamsSpec::MAX_MATRIX_ENTRIES` | `Error::DegreeTooLarge` or `Error::WitnessBoundTooLarge`, before any table is built |
| a parameter set that does not validate | the errors of `Params::try_from` |
| with `from_bytes`, any parameter set other than the one given | `Error::ParameterMismatch`, before the body is read |

Strictness matters because encodings get hashed: the statement digest of a proof and the tag
of the manager state both absorb encodings. If one value had two encodings, two parties could
hold "the same" value and derive different digests.

```rust
use kln_accumulator::{Accumulator, Error, Params};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let params = Arc::new(Params::toy()?);
let bytes = Accumulator::random(&mut StdRng::seed_from_u64(0), &params).to_bytes();
let decode = |bytes: &[u8]| Accumulator::try_from(bytes).map(drop);

// Truncated, and with a trailing byte.
assert!(matches!(decode(&bytes[..bytes.len() - 1]), Err(Error::InvalidEncodingLength(_))));
let mut longer = bytes.clone();
longer.push(0);
assert!(matches!(decode(&longer), Err(Error::InvalidEncodingLength(_))));

// A reserved byte of the parameter-set prefix set.
let mut reserved = bytes.clone();
reserved[5] = 1;
assert_eq!(decode(&reserved), Err(Error::NonCanonicalEncoding));

// The first coefficient set to all ones, which is not below q.
let mut out_of_range = bytes.clone();
out_of_range[64..72].fill(0xff);
assert_eq!(decode(&out_of_range), Err(Error::CoefficientOutOfRange));

// The distribution byte flipped to Ternary: a well-formed value of *another* set. It decodes,
// and is then refused wherever the Gaussian set is expected.
let mut other_set = bytes.clone();
other_set[4] = 1;
let decoded = Accumulator::try_from(other_set.as_slice())?;
assert_eq!(decoded.validate(&params), Err(Error::ParameterMismatch));
# Ok::<(), kln_accumulator::Error>(())
```

The last case deserves attention. A value carries its own parameter set, and decoding accepts
any *valid* set. Decoding tells you the value is well formed; it does not tell you it belongs
to the set you expected. The operations check that: every one compares the sets of its inputs.
If you inspect a decoded value before passing it to an operation, call `validate(&params)`
with the set you expect.

## Decoding against the set you expect

`TryFrom<&[u8]>` builds the parameter set the bytes name, ring tables included, before it reads
the body. That is a rebuild on every decode, and for bytes from an untrusted source it lets the
input choose the set, within the limits above. Every type whose packed encoding carries its set
therefore also has `from_bytes(&params, bytes)`: the public keys, accumulator values and
witnesses of all three variants. It compares the 64-byte prefix with `params`, refuses any
other set with `Error::ParameterMismatch`, reads the body against `params` and shares that
`Arc` with the result. No set is built from the input.

Use `from_bytes` whenever you know which set to expect: for anything that arrives from a
holder, a verifier or the network, and whenever you already hold the set. Use `TryFrom<&[u8]>`
when the bytes are trusted and the set is what you want to learn from them, such as values you
stored yourself under several sets. The serde forms build the set they name, as `TryFrom`
does; there is no serde counterpart of `from_bytes`, so for untrusted input prefer the packed
bytes.

```rust
use kln_accumulator::{Accumulator, Error, Params, ParamsSpec, TrapdoorDistribution};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

let params = Arc::new(Params::toy()?);
let bytes = Accumulator::random(&mut StdRng::seed_from_u64(0), &params).to_bytes();

// The decoded value shares the caller's set: nothing was rebuilt.
let acc = Accumulator::from_bytes(&params, &bytes)?;
assert!(Arc::ptr_eq(acc.params(), &params));

// A value of another set is refused, where `TryFrom` builds that set and decodes it.
let ternary = Arc::new(Params::try_from(
    ParamsSpec::TOY.with_trapdoor(TrapdoorDistribution::Ternary),
)?);
let other = Accumulator::random(&mut StdRng::seed_from_u64(1), &ternary).to_bytes();
assert_eq!(Accumulator::from_bytes(&params, &other).map(drop), Err(Error::ParameterMismatch));
assert!(Accumulator::try_from(other.as_slice()).is_ok());

// So is a set the crate would refuse to build, which `TryFrom` reaches and refuses itself.
let wide = ParamsSpec { degree: ParamsSpec::MAX_DEGREE * 2, ..ParamsSpec::TOY };
let mut too_large = bytes.clone();
too_large[..ParamsSpec::BYTES].copy_from_slice(&<[u8; ParamsSpec::BYTES]>::from(wide));
assert_eq!(Accumulator::from_bytes(&params, &too_large).map(drop), Err(Error::ParameterMismatch));
assert_eq!(
    Accumulator::try_from(too_large.as_slice()).map(drop),
    Err(Error::DegreeTooLarge(ParamsSpec::MAX_DEGREE * 2))
);
# Ok::<(), kln_accumulator::Error>(())
```

## Values that are not checked at decoding

Three kinds of value are decoded without a parameter set to check them against.

- **`Poly`, `PolyVec`, `PolyMatrix`.** They carry no parameters. Decoding checks the layout
  only. Call `validate(ring)` before using one that came from outside; the accumulator and
  proof operations do this for their own inputs.
- **`Element`, `Coefficient`.** Decoding refuses only the empty string. `validate(&params)`
  checks the length and the high bits, and every operation calls it.
- **`ManagerState`.** Deserialization has no key, so it cannot check the tag. It checks that
  the history is possible, and leaves the tag to the first keyed operation or to
  `ManagerState::authenticate`. Until then, what you read from the state is unverified.

```rust
use kln_accumulator::{Error, Params};
use kln_accumulator::lattice::Poly;

let params = Params::toy()?;
// 64 coefficients of 24 bytes, all ones: far above q, and decoding does not notice.
let decoded = Poly::try_from(&[0xffu8; 64 * 24][..])?;
assert_eq!(decoded.validate(params.ring()), Err(Error::CoefficientOutOfRange));
// Not a whole number of coefficients.
assert!(matches!(Poly::try_from(&[0u8; 25][..]), Err(Error::InvalidEncodingLength(25))));
# Ok::<(), kln_accumulator::Error>(())
```

## Secrets and serializers

The crate [wipes](glossary.md#wiping) every buffer it owns. It cannot wipe buffers that belong to a serializer you
call, or the output you asked for.

- `SecretKey::to_bytes` and `MembershipWitness::to_bytes` return `Zeroizing<Vec<u8>>`, which
  is wiped when dropped.
- The serde implementations of secret and holder-private types, and of `Element`, build and
  parse their hex in wiped buffers, without a branch or a table lookup on the bytes (by source
  reading).
- Packed witnesses are decoded into buffers allocated at full size and wiped on drop, so a
  failed decode leaves no coefficients behind either.
- The `Vec<u8>` or `String` a serializer returns to you holds the secret in the clear. Wrap it
  in `Zeroizing` at once.
- Internal buffers of the serializer are out of reach.

```rust
use kln_accumulator::{Params, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use zeroize::Zeroizing;

let mut rng = StdRng::seed_from_u64(0);
let key = SecretKey::new(None, Arc::new(Params::toy()?), &mut rng)?;

// The serialized forms contain the root seed. This is the misuse to avoid: a plain String.
let seed_hex = hex::encode(&key.to_bytes()[64..]);
let exposed: String = serde_json::to_string(&key)?;
assert!(exposed.contains(&seed_hex));
// What to do instead: keep every output in a buffer that is wiped on drop.
let exposed = Zeroizing::new(exposed);
let binary = Zeroizing::new(postcard::to_allocvec(&key)?);

assert_eq!(serde_json::from_str::<SecretKey>(&exposed)?, key);
assert_eq!(postcard::from_bytes::<SecretKey>(&binary)?, key);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Wiping is best effort in any case. It does not reach copies the allocator, the operating
system or a swap file made. For a real deployment the key belongs in a hardware module or a
secrets manager, encrypted at rest; this crate does not provide that.
