# Your first accumulator

This page builds a complete program one step at a time. It is the program in
`examples/base.rs`, and it plays all three roles: manager, holder and verifier. Each step shows
a few lines of code, says what they do, and gives the line the program prints. The words come
from [Accumulators in plain words](concepts.md).

Every block on this page is compiled and run by the crate's tests. Each block hides the lines
of the steps before it; the eye button at the top right of a block shows them.

## Before you start

The quickest way to see the program run is in the crate's own directory:

```sh
cargo run --release --example base
```

It takes a few seconds. Keep `--release`: the crate does heavy arithmetic, and an unoptimised
build runs it far more slowly.

To write the program in a project of your own, depend on the crate by path or by Git revision,
since it is not published to crates.io, and on `rand` for the random number generator:

```toml
[dependencies]
kln-accumulator = { path = "../kln-accumulator" }
rand = "0.10"
```

The program's `main` returns `Result<(), Box<dyn std::error::Error>>`, so every fallible call
ends in `?`.

## 1. Choose the settings

Every value in the crate belongs to a [parameter set](concepts.md#settings-parameter-sets).
`Params::toy()` builds the toy set: small and fast, and it protects nothing. The `Arc` lets
every key and value share one copy of it.

The random number generator starts from a fixed number, so that the run is the same every
time. Real code must use a generator seeded by the operating system; with the default
features of `rand` 0.10, `rand::make_rng::<StdRng>()` gives one.

```rust
use kln_accumulator::{
    Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

// A fixed seed keeps the run reproducible. Real code seeds from the operating system.
let mut rng = StdRng::seed_from_u64(0);
let params = Arc::new(Params::toy()?);
let degree = params.ring().degree();
println!("parameters: the toy set, ring degree {degree}");
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
parameters: the toy set, ring degree 64
```

The ring degree is one of the set's size settings. You do not need it to use the crate;
the [Glossary](glossary.md#ring-and-ring-degree) says what it is.

## 2. Make the keys

The manager generates a secret key. With `None` as its first argument, `SecretKey::new`
takes a fresh 32-byte seed from the generator and derives the whole key from it. The public
key is derived from the secret key. The manager sends the public key to everyone and keeps
the secret key to itself.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
let pk = PublicKey::from(&key);
println!("manager: generated a key and derived its public key");
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
manager: generated a key and derived its public key
```

## 3. Start the accumulator

A key keeps exactly one accumulator. `Accumulator::new` starts it at the key's
[genesis value](glossary.md#genesis-value), and `ManagerState::new` starts the manager's private ledger. The manager publishes this
first value.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
let mut acc = Accumulator::new(&key);
let mut state = ManagerState::new(&key);
let size = acc.to_bytes().len();
println!("manager: started the accumulator at the key's genesis value, {size} bytes");
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
manager: started the accumulator at the key's genesis value, 544 bytes
```

The value stays 544 bytes at the toy set however many members it holds.

## 4. Add three members

From here on the program uses a small helper, `step`. It prints a line when what the line
says is true, and stops the program with an error when it is not.

`Element::hash` turns a name into an element by hashing it down to the set's element length,
8 bits here. `add_elements_assign` records the three elements in the state. Then `step`
checks that the value did not change.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
#
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let size = acc.to_bytes().len();
# println!("manager: started the accumulator at the key's genesis value, {size} bytes");
/// Prints one step of the run, or ends the run with an error when what the step shows is false.
fn step(holds: bool, line: &str) -> Result<(), String> {
    if holds {
        println!("{line}");
        Ok(())
    } else {
        Err(format!("this step does not hold: {line}"))
    }
}

let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
let before = acc.clone();
acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
step(
    acc == before,
    "manager: added x, y and z; the value did not change and nothing was published",
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
manager: added x, y and z; the value did not change and nothing was published
```

With only 256 elements at the toy set, hashed names soon collide. A real system gives out
elements itself; [How do I…](recipes.md#add-members-and-hand-out-witnesses) shows how.

## 5. Issue the witnesses

`MembershipWitness::new` is the only operation that makes a witness, and it needs the
secret key and the state. The program makes one for `x` and one for `y`. In a real system
each goes to its holder over a private channel.

The holder of `x` checks its witness with `verify`. It takes the element, the public key and
the current value, and answers `true` or `false`.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
#
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let size = acc.to_bytes().len();
# println!("manager: started the accumulator at the key's genesis value, {size} bytes");
#
# /// Prints one step of the run, or ends the run with an error when what the step shows is false.
# fn step(holds: bool, line: &str) -> Result<(), String> {
#     if holds {
#         println!("{line}");
#         Ok(())
#     } else {
#         Err(format!("this step does not hold: {line}"))
#     }
# }
#
# let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
# let before = acc.clone();
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# step(
#     acc == before,
#     "manager: added x, y and z; the value did not change and nothing was published",
# )?;
let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
step(
    witness.verify(&x, &pk, &acc),
    "holder of x: received a witness and it verifies",
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
holder of x: received a witness and it verifies
```

## 6. Delete a member

`update_assign` adds and deletes in one step. Here it adds nothing and deletes `y`. It
returns the update messages, one per deletion. The value moves, so `step` compares it with
the value from before the additions.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
#
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let size = acc.to_bytes().len();
# println!("manager: started the accumulator at the key's genesis value, {size} bytes");
#
# /// Prints one step of the run, or ends the run with an error when what the step shows is false.
# fn step(holds: bool, line: &str) -> Result<(), String> {
#     if holds {
#         println!("{line}");
#         Ok(())
#     } else {
#         Err(format!("this step does not hold: {line}"))
#     }
# }
#
# let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
# let before = acc.clone();
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# step(
#     acc == before,
#     "manager: added x, y and z; the value did not change and nothing was published",
# )?;
#
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
# step(
#     witness.verify(&x, &pk, &acc),
#     "holder of x: received a witness and it verifies",
# )?;
let deleted = std::slice::from_ref(&y);
let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
let message: usize = coefficients.iter().map(|c| c.to_bytes().len()).sum();
step(
    acc != before,
    &format!(
        "manager: deleted y; the value moved, and the update message is y, {message} byte"
    ),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
manager: deleted y; the value moved, and the update message is y, 1 byte
```

Each update message is the deleted element itself, so it is one byte at this set. The
manager now publishes the new value and the messages.

## 7. Bring a witness up to date

The holder of `x` sees that its old witness fails against the new value. It applies the
published batch with `batch_update`, which takes its own element, the batch's additions, its
deletions, its update messages and the public key. Only the deletions and the messages change
the result. The additions are only checked (each must be a valid element other than the
holder's own), so an empty list is always accepted; this batch had none. No secret is
involved, and the manager is not contacted.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
#
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let size = acc.to_bytes().len();
# println!("manager: started the accumulator at the key's genesis value, {size} bytes");
#
# /// Prints one step of the run, or ends the run with an error when what the step shows is false.
# fn step(holds: bool, line: &str) -> Result<(), String> {
#     if holds {
#         println!("{line}");
#         Ok(())
#     } else {
#         Err(format!("this step does not hold: {line}"))
#     }
# }
#
# let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
# let before = acc.clone();
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# step(
#     acc == before,
#     "manager: added x, y and z; the value did not change and nothing was published",
# )?;
#
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
# step(
#     witness.verify(&x, &pk, &acc),
#     "holder of x: received a witness and it verifies",
# )?;
#
# let deleted = std::slice::from_ref(&y);
# let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
# let message: usize = coefficients.iter().map(|c| c.to_bytes().len()).sum();
# step(
#     acc != before,
#     &format!(
#         "manager: deleted y; the value moved, and the update message is y, {message} byte"
#     ),
# )?;
let stale = !witness.verify(&x, &pk, &acc);
let witness = witness.batch_update(&x, &[], deleted, &coefficients, &pk)?;
step(
    stale && witness.verify(&x, &pk, &acc),
    "holder of x: the old witness fails; the updated one verifies against the new value",
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
holder of x: the old witness fails; the updated one verifies against the new value
```

`batch_update` does not check its result against the new value. The program does, with
`verify`, and your code should too.

## 8. See a deleted member fail

The holder of `y` tries the same. Its witness no longer verifies, and `batch_update`
refuses with `Error::ElementDeleted`. That error is how a holder learns that it was removed.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
#
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let size = acc.to_bytes().len();
# println!("manager: started the accumulator at the key's genesis value, {size} bytes");
#
# /// Prints one step of the run, or ends the run with an error when what the step shows is false.
# fn step(holds: bool, line: &str) -> Result<(), String> {
#     if holds {
#         println!("{line}");
#         Ok(())
#     } else {
#         Err(format!("this step does not hold: {line}"))
#     }
# }
#
# let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
# let before = acc.clone();
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# step(
#     acc == before,
#     "manager: added x, y and z; the value did not change and nothing was published",
# )?;
#
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
# step(
#     witness.verify(&x, &pk, &acc),
#     "holder of x: received a witness and it verifies",
# )?;
#
# let deleted = std::slice::from_ref(&y);
# let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
# let message: usize = coefficients.iter().map(|c| c.to_bytes().len()).sum();
# step(
#     acc != before,
#     &format!(
#         "manager: deleted y; the value moved, and the update message is y, {message} byte"
#     ),
# )?;
#
# let stale = !witness.verify(&x, &pk, &acc);
# let witness = witness.batch_update(&x, &[], deleted, &coefficients, &pk)?;
# step(
#     stale && witness.verify(&x, &pk, &acc),
#     "holder of x: the old witness fails; the updated one verifies against the new value",
# )?;
let refused = witness_y.batch_update(&y, &[], deleted, &coefficients, &pk);
step(
    !witness_y.verify(&y, &pk, &acc) && matches!(refused, Err(Error::ElementDeleted)),
    "holder of y: its witness no longer verifies and cannot be updated",
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
holder of y: its witness no longer verifies and cannot be updated
```

## 9. Turn values into bytes

The public key, the accumulator value and the witness travel as bytes. `to_bytes` gives
the packed encoding. A witness is private, so its bytes come in a buffer that is wiped when it
is dropped.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
#
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let size = acc.to_bytes().len();
# println!("manager: started the accumulator at the key's genesis value, {size} bytes");
#
# /// Prints one step of the run, or ends the run with an error when what the step shows is false.
# fn step(holds: bool, line: &str) -> Result<(), String> {
#     if holds {
#         println!("{line}");
#         Ok(())
#     } else {
#         Err(format!("this step does not hold: {line}"))
#     }
# }
#
# let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
# let before = acc.clone();
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# step(
#     acc == before,
#     "manager: added x, y and z; the value did not change and nothing was published",
# )?;
#
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
# step(
#     witness.verify(&x, &pk, &acc),
#     "holder of x: received a witness and it verifies",
# )?;
#
# let deleted = std::slice::from_ref(&y);
# let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
# let message: usize = coefficients.iter().map(|c| c.to_bytes().len()).sum();
# step(
#     acc != before,
#     &format!(
#         "manager: deleted y; the value moved, and the update message is y, {message} byte"
#     ),
# )?;
#
# let stale = !witness.verify(&x, &pk, &acc);
# let witness = witness.batch_update(&x, &[], deleted, &coefficients, &pk)?;
# step(
#     stale && witness.verify(&x, &pk, &acc),
#     "holder of x: the old witness fails; the updated one verifies against the new value",
# )?;
#
# let refused = witness_y.batch_update(&y, &[], deleted, &coefficients, &pk);
# step(
#     !witness_y.verify(&y, &pk, &acc) && matches!(refused, Err(Error::ElementDeleted)),
#     "holder of y: its witness no longer verifies and cannot be updated",
# )?;
let witness_bytes = witness.to_bytes()?;
let pk_bytes = pk.to_bytes();
let acc_bytes = acc.to_bytes();
let (w, p, a) = (witness_bytes.len(), pk_bytes.len(), acc_bytes.len());
println!("wire: witness {w} bytes, public key {p} bytes, accumulator value {a} bytes");
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
wire: witness 34464 bytes, public key 48544 bytes, accumulator value 544 bytes
```

## 10. Read them back

The verifier decodes all three with `from_bytes`, passing the parameter set it expects,
and checks the witness against the decoded value. Bytes of any other set are refused with
`Error::ParameterMismatch`. Use `from_bytes` for every value that comes from someone else.

```rust
# use kln_accumulator::{
#     Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
# };
# use rand::{SeedableRng, rngs::StdRng};
# use std::sync::Arc;
#
# // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
# let mut rng = StdRng::seed_from_u64(0);
# let params = Arc::new(Params::toy()?);
# let degree = params.ring().degree();
# println!("parameters: the toy set, ring degree {degree}");
#
# let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
# let pk = PublicKey::from(&key);
# println!("manager: generated a key and derived its public key");
#
# let mut acc = Accumulator::new(&key);
# let mut state = ManagerState::new(&key);
# let size = acc.to_bytes().len();
# println!("manager: started the accumulator at the key's genesis value, {size} bytes");
#
# /// Prints one step of the run, or ends the run with an error when what the step shows is false.
# fn step(holds: bool, line: &str) -> Result<(), String> {
#     if holds {
#         println!("{line}");
#         Ok(())
#     } else {
#         Err(format!("this step does not hold: {line}"))
#     }
# }
#
# let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
# let before = acc.clone();
# acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
# step(
#     acc == before,
#     "manager: added x, y and z; the value did not change and nothing was published",
# )?;
#
# let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
# let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
# step(
#     witness.verify(&x, &pk, &acc),
#     "holder of x: received a witness and it verifies",
# )?;
#
# let deleted = std::slice::from_ref(&y);
# let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
# let message: usize = coefficients.iter().map(|c| c.to_bytes().len()).sum();
# step(
#     acc != before,
#     &format!(
#         "manager: deleted y; the value moved, and the update message is y, {message} byte"
#     ),
# )?;
#
# let stale = !witness.verify(&x, &pk, &acc);
# let witness = witness.batch_update(&x, &[], deleted, &coefficients, &pk)?;
# step(
#     stale && witness.verify(&x, &pk, &acc),
#     "holder of x: the old witness fails; the updated one verifies against the new value",
# )?;
#
# let refused = witness_y.batch_update(&y, &[], deleted, &coefficients, &pk);
# step(
#     !witness_y.verify(&y, &pk, &acc) && matches!(refused, Err(Error::ElementDeleted)),
#     "holder of y: its witness no longer verifies and cannot be updated",
# )?;
#
# let witness_bytes = witness.to_bytes()?;
# let pk_bytes = pk.to_bytes();
# let acc_bytes = acc.to_bytes();
# let (w, p, a) = (witness_bytes.len(), pk_bytes.len(), acc_bytes.len());
# println!("wire: witness {w} bytes, public key {p} bytes, accumulator value {a} bytes");
let decoded_pk = PublicKey::from_bytes(&params, &pk_bytes)?;
let decoded_acc = Accumulator::from_bytes(&params, &acc_bytes)?;
let decoded_witness = MembershipWitness::from_bytes(&params, &witness_bytes)?;
step(
    decoded_witness.verify(&x, &decoded_pk, &decoded_acc),
    "verifier: decoded all three against the toy set; the witness still verifies",
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

It prints:

```text
verifier: decoded all three against the toy set; the witness still verifies
```

## The whole program

Here is the program in one piece. It is `examples/base.rs` without its opening comment.

```rust
use kln_accumulator::{
    Accumulator, Element, Error, ManagerState, MembershipWitness, Params, PublicKey, SecretKey,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Prints one step of the run, or ends the run with an error when what the step shows is false.
fn step(holds: bool, line: &str) -> Result<(), String> {
    if holds {
        println!("{line}");
        Ok(())
    } else {
        Err(format!("this step does not hold: {line}"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A fixed seed keeps the run reproducible. Real code seeds from the operating system.
    let mut rng = StdRng::seed_from_u64(0);
    let params = Arc::new(Params::toy()?);
    let degree = params.ring().degree();
    println!("parameters: the toy set, ring degree {degree}");

    let key = SecretKey::new(None, Arc::clone(&params), &mut rng)?;
    let pk = PublicKey::from(&key);
    println!("manager: generated a key and derived its public key");

    let mut acc = Accumulator::new(&key);
    let mut state = ManagerState::new(&key);
    let size = acc.to_bytes().len();
    println!("manager: started the accumulator at the key's genesis value, {size} bytes");

    let [x, y, z] = [b"x", b"y", b"z"].map(|name| Element::hash(name, &params));
    let before = acc.clone();
    acc.add_elements_assign(&key, &[x.clone(), y.clone(), z.clone()], &mut state)?;
    step(
        acc == before,
        "manager: added x, y and z; the value did not change and nothing was published",
    )?;

    let witness = MembershipWitness::new(&x, &acc, &key, &state)?;
    let witness_y = MembershipWitness::new(&y, &acc, &key, &state)?;
    step(
        witness.verify(&x, &pk, &acc),
        "holder of x: received a witness and it verifies",
    )?;

    let deleted = std::slice::from_ref(&y);
    let coefficients = acc.update_assign(&key, &[], deleted, &mut state)?;
    let message: usize = coefficients.iter().map(|c| c.to_bytes().len()).sum();
    step(
        acc != before,
        &format!(
            "manager: deleted y; the value moved, and the update message is y, {message} byte"
        ),
    )?;

    let stale = !witness.verify(&x, &pk, &acc);
    let witness = witness.batch_update(&x, &[], deleted, &coefficients, &pk)?;
    step(
        stale && witness.verify(&x, &pk, &acc),
        "holder of x: the old witness fails; the updated one verifies against the new value",
    )?;

    let refused = witness_y.batch_update(&y, &[], deleted, &coefficients, &pk);
    step(
        !witness_y.verify(&y, &pk, &acc) && matches!(refused, Err(Error::ElementDeleted)),
        "holder of y: its witness no longer verifies and cannot be updated",
    )?;

    let witness_bytes = witness.to_bytes()?;
    let pk_bytes = pk.to_bytes();
    let acc_bytes = acc.to_bytes();
    let (w, p, a) = (witness_bytes.len(), pk_bytes.len(), acc_bytes.len());
    println!("wire: witness {w} bytes, public key {p} bytes, accumulator value {a} bytes");

    let decoded_pk = PublicKey::from_bytes(&params, &pk_bytes)?;
    let decoded_acc = Accumulator::from_bytes(&params, &acc_bytes)?;
    let decoded_witness = MembershipWitness::from_bytes(&params, &witness_bytes)?;
    step(
        decoded_witness.verify(&x, &decoded_pk, &decoded_acc),
        "verifier: decoded all three against the toy set; the witness still verifies",
    )?;
    Ok(())
}
```

Run it from the crate's directory:

```sh
cargo run --release --example base
```

It prints:

```text
parameters: the toy set, ring degree 64
manager: generated a key and derived its public key
manager: started the accumulator at the key's genesis value, 544 bytes
manager: added x, y and z; the value did not change and nothing was published
holder of x: received a witness and it verifies
manager: deleted y; the value moved, and the update message is y, 1 byte
holder of x: the old witness fails; the updated one verifies against the new value
holder of y: its witness no longer verifies and cannot be updated
wire: witness 34464 bytes, public key 48544 bytes, accumulator value 544 bytes
verifier: decoded all three against the toy set; the witness still verifies
```

## What just happened

- **Steps 1 to 3: setup.** The manager chose a [parameter set](concepts.md#settings-parameter-sets),
  made the **secret key** and the **public key**, and started the **accumulator value** and the
  **manager state**.
- **Step 4: adding is free.** Three **elements** went in, and the value did not move. See
  [Why adding is free](concepts.md#why-adding-is-free).
- **Step 5: witnesses.** The manager issued a **witness** for each **holder**, and the holder of
  `x` checked its own.
- **Step 6: a deletion.** The value moved and one **update message** came out. See
  [What a removal costs](concepts.md#what-a-removal-costs-and-who-pays).
- **Steps 7 and 8: updates.** The remaining holder updated from public data alone; the deleted
  holder could not.
- **Steps 9 and 10: the wire.** The witness, the public key and the accumulator value went to
  bytes and back, decoded against the set the receiver expected, as a **verifier** would
  receive them.

The program did not prove membership. A membership proof takes seconds even at the toy set,
and [How do I…](recipes.md#prove-membership-without-revealing-the-element) shows one.

## Where next

| you want to | read |
|---|---|
| choose a variant and a parameter set for real figures | [Which variant and which settings](choosing.md) |
| do one task: store the state, update after missed batches, decode safely, prove | [How do I…](recipes.md) |
| know what you must get right | [The rules that keep you safe](rules.md) |
| run the same program at the 128-bit set | [Getting started](getting-started.md#the-same-run-at-the-128-bit-set) |
| see the other two variants run | `cargo run --release --example adaptive`, `cargo run --release --example succinct` |
