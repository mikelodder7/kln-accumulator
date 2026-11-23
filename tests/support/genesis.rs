// SPDX-License-Identifier: MIT OR Apache-2.0
//! The history harness of the genesis tests of the base and succinct variants, included into
//! each with a `#[path]` attribute. Each suite adds the witness of a run for its own key and
//! witness types; the value and the state are those of Construction 4.1 in both.

use crate::fixture::element;
use kln_accumulator::{Accumulator, Coefficient, ManagerState, SecretKey};
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::ops::Range;

/// A value, its state, the update messages its deletions published, and its members.
#[derive(Clone)]
pub struct Run {
    pub value: Accumulator,
    pub state: ManagerState,
    pub log: Vec<Coefficient>,
    pub members: BTreeSet<u8>,
}

impl Run {
    /// The key's accumulator at its genesis value.
    pub fn fresh(key: &SecretKey) -> Self {
        Self {
            value: Accumulator::new(key),
            state: ManagerState::new(key),
            log: Vec::new(),
            members: BTreeSet::new(),
        }
    }

    /// Adds `i` if it was never added and deletes it if it is present.
    pub fn step(&mut self, key: &SecretKey, i: u8) {
        let x = element(i);
        if self.state.record(&x).is_none() {
            self.value
                .add_assign(key, &x, &mut self.state)
                .expect("test fixture");
            let _ = self.members.insert(i);
        } else {
            let mut log = self
                .value
                .update_assign(key, &[], &[x], &mut self.state)
                .expect("test fixture");
            self.log.append(&mut log);
            let _ = self.members.remove(&i);
        }
    }
}

/// Members and deleted elements, drawn from `0..12`, with two schedules of the same operations
/// (each member added once, each deleted element added and later deleted), a point at which
/// to copy the state, and the member whose witness is compared.
#[derive(Clone, Debug)]
pub struct Histories {
    pub members: Vec<u8>,
    pub first: Vec<u8>,
    pub second: Vec<u8>,
    pub copy_at: usize,
    pub target: u8,
}

/// A schedule lists a member once and a deleted element twice: its first appearance adds it,
/// its second deletes it. `sizes` bounds the number of elements chosen.
pub fn histories(sizes: Range<usize>) -> impl Strategy<Value = Histories> {
    (
        prop::sample::subsequence((0u8..12).collect::<Vec<_>>(), sizes),
        any::<prop::sample::Index>(),
    )
        .prop_flat_map(|(chosen, split)| {
            let cut = 1 + split.index(chosen.len());
            let (members, deleted) = chosen.split_at(cut);
            let schedule: Vec<u8> = members
                .iter()
                .chain(deleted)
                .chain(deleted)
                .copied()
                .collect();
            let len = schedule.len();
            (
                Just(members.to_vec()),
                Just(schedule.clone()).prop_shuffle(),
                Just(schedule).prop_shuffle(),
                0..=len,
                prop::sample::select(members.to_vec()),
            )
        })
        .prop_map(|(members, first, second, copy_at, target)| Histories {
            members,
            first,
            second,
            copy_at,
            target,
        })
}

/// One public call in the programs of `no_two_witnesses_for_one_element_and_value`. Slots
/// index a pool of runs, taken modulo its length.
#[derive(Clone, Debug)]
pub enum Call {
    /// Adds an element in a slot.
    Add(u8, usize),
    /// Deletes an element in a slot.
    Remove(u8, usize),
    /// Issues a witness in a slot.
    Issue(u8, usize),
    /// Copies a slot into a new one: a fork.
    Fork(usize),
    /// A fresh state for the key, in a new slot.
    Fresh,
    /// Serializes a slot.
    Save(usize),
    /// Deserializes a saved copy into a new slot: an older state, rolled back to.
    Restore(usize),
    /// Rebuilds a slot from its log and members into a new slot.
    Rebuild(usize),
}

pub fn call() -> impl Strategy<Value = Call> {
    let element = 0u8..8;
    let slot = 0usize..4;
    prop_oneof![
        4 => (element.clone(), slot.clone()).prop_map(|(e, s)| Call::Add(e, s)),
        3 => (element.clone(), slot.clone()).prop_map(|(e, s)| Call::Remove(e, s)),
        4 => (element, slot.clone()).prop_map(|(e, s)| Call::Issue(e, s)),
        1 => slot.clone().prop_map(Call::Fork),
        1 => Just(Call::Fresh),
        1 => slot.clone().prop_map(Call::Save),
        1 => (0usize..4).prop_map(Call::Restore),
        1 => slot.prop_map(Call::Rebuild),
    ]
}
