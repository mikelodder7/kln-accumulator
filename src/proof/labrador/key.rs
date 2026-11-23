// SPDX-License-Identifier: MIT OR Apache-2.0
//! The commitment keys of one LaBRADOR level: `A ∈ R_q^{κ×n}` for the inner commitments
//! `tᵢ = A·sᵢ`, and on a committed level `B ∈ R_q^{κ₁×(|t|+|g|)}` and
//! `D ∈ R_q^{κ₁×|h|}` for the outer commitments `u₁ = B·(t ‖ g)` and `u₂ = D·h` of the
//! decomposed garbage.
//!
//! Paper counterpart (ePrint 2022/1341, Figure 2 caption): the common reference string holds
//! `A`, `B_ik`, `C_ijk` and `D_ijk`. Here `B` is the concatenation of every `B_ik` and `C_ijk`
//! (Figure 3, line 19: `u₁` commits to `t` and `g`), and `D` that of every `D_ijk` (line 20),
//! all with the one outer rank `κ₁` (Theorem 5.1 takes `κ₁ = κ₂`).
//!
//! Every key is uniform, expanded from the proof parameters' seed and the level's index.
//! Difference: the paper's keys are a common reference string; expanding them from a public
//! seed is the usual instantiation and gives every level its own keys.

use super::params::{Kind, LevelParams};
use crate::{
    error::Result,
    matrix::{NttMatrix, Shape},
    proof::abdlop::uniform_ntt,
    ring::Ring,
    sample::{DomainLabel, Seed, hash_to_seed},
};

/// Label of a level's key seed.
const LABEL_LEVEL: &[u8] = b"kln/labrador/key";
/// Label of `A`.
const LABEL_INNER: &[u8] = b"kln/labrador/key/a";
/// Label of `B`.
const LABEL_GARBAGE: &[u8] = b"kln/labrador/key/b";
/// Label of `D`.
const LABEL_LINEAR: &[u8] = b"kln/labrador/key/d";

/// The keys of one level.
#[derive(Debug)]
pub(crate) struct LevelKeys {
    /// `A`.
    pub(crate) inner: NttMatrix,
    /// `B` and `D`, on a committed level.
    pub(crate) outer: Option<OuterKeys>,
}

/// The outer commitment keys of a committed level.
#[derive(Debug)]
pub(crate) struct OuterKeys {
    /// `B`, for `u₁ = B·(t ‖ g)`.
    pub(crate) garbage: NttMatrix,
    /// `D`, for `u₂ = D·h`.
    pub(crate) linear: NttMatrix,
}

impl LevelKeys {
    /// The keys of level `index` with parameters `params`.
    pub(crate) fn expand(
        seed: &Seed,
        index: usize,
        params: &LevelParams,
        ring: &Ring,
    ) -> Result<Self> {
        let seed = hash_to_seed(
            DomainLabel::from(LABEL_LEVEL),
            &[seed.as_bytes(), &(index as u64).to_le_bytes()],
        );
        let inner = uniform_ntt(
            &seed,
            LABEL_INNER,
            Shape {
                rows: params.kappa,
                cols: params.width,
            },
            ring,
        )?;
        let outer = match params.kind {
            Kind::Tail => None,
            Kind::Committed => Some(OuterKeys {
                garbage: uniform_ntt(
                    &seed,
                    LABEL_GARBAGE,
                    Shape {
                        rows: params.outer_rank,
                        cols: params.t_len() + params.g_len(),
                    },
                    ring,
                )?,
                linear: uniform_ntt(
                    &seed,
                    LABEL_LINEAR,
                    Shape {
                        rows: params.outer_rank,
                        cols: params.g_len(),
                    },
                    ring,
                )?,
            }),
        };
        Ok(Self { inner, outer })
    }
}
