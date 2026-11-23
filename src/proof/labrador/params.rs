// SPDX-License-Identifier: MIT OR Apache-2.0
//! The parameters of one LaBRADOR level, derived in exact integer arithmetic from the shape of
//! the relation, its norm bound and the modulus. "The paper" is ePrint 2022/1341; each formula
//! is set against the paper below, with every difference and its reason.
//!
//! * Witness vectors (Section 5.3, "we write the vectors as a concatenation of `ν` … and `μ`
//!   vectors … zero-pad all to length `n′`"): every block is split into vectors of at most `n`
//!   polynomials (the rank), each zero-padded to `n`. Difference: the paper splits `z⁽⁰⁾`,
//!   `z⁽¹⁾` into `ν` vectors and `t ‖ g ‖ h` into `μ`; here every block of the relation is
//!   split on its own, so the opening's blocks `z⁽⁰⁾`, `z⁽¹⁾`, `t̂`, `ĝ`, `ĥ` never share a
//!   vector. Same relation, slightly more padding; it keeps the quadratic terms within runs of
//!   equally shaped vectors (see `level.rs`).
//! * Rank selection: `n` is chosen among `⌈len/j⌉` for every block length and `j ≤ 64` to
//!   minimise the polynomials the level outputs.
//!   No counterpart: Section 5.3 only asks for `n/ν ≈ m/μ`, Section 5.7 for `2n ≈ m`.
//! * `‖z‖ ≤ γ` (Section 5.2, equation (2); Figure 3 consolidates it into line 14):
//!   `γ² = T²·r·β²`, because `z = Σ cᵢ·sᵢ` and `‖cᵢ·sᵢ‖ ≤ T·‖sᵢ‖`, so `‖z‖ ≤ T·Σ‖sᵢ‖ ≤ T·√r·β`.
//!   Difference: Section 5.4 sets the heuristic `γ = β·√τ`, which an honest run can exceed;
//!   this worst case makes completeness unconditional.
//! * Decomposition of `z` (Section 5.3, "Decomposing the witness", `z = z⁽⁰⁾ + b·z⁽¹⁾` with
//!   centred digits): on a committed level `z` is decomposed when `64·β²‖c‖²/(n·d) > 2^{26}`,
//!   with `log₂ b = round(log₂(12·β²‖c‖²/(n·d))/4)`. That is Section 5.4's `b = √(√(12rτ)·s)`
//!   for `s = β/√(rnd)`, rounded to a power of two. The threshold has no counterpart in the
//!   paper; Section 6.1 decomposes `z` on every level but the second to last.
//! * Decomposition of `t`, `g`, `h` (Section 5.2, "`tᵢ = tᵢ⁽⁰⁾ + … + tᵢ⁽ᵗ¹⁻¹⁾·b₁^{t₁−1}`";
//!   Section 5.4, `t₁ = round(log q/log b)`, `b₁ = ⌈q^{1/t₁}⌉`): `f = ⌊(log₂ q + log₂ b/2)/log₂ b⌋`
//!   centred digits of `⌈log₂ q/f⌉` bits. Differences: `g` takes the digits
//!   of `t` and `h` instead of its own `t₂`, `b₂` (Section 5.4), which costs size only; and
//!   `f = 1` is allowed where Section 5.2 asks for `t₁ ≥ 2`, also size only.
//! * Next level's bound `β′²` (Section 5.3, equation (5); Figure 3, line 14): the sum of the
//!   worst-case squared norms of every part of the opening: `n·d·(b/2)²` for `z⁽⁰⁾`,
//!   `((γ + ‖z⁽⁰⁾‖)/b)²` for `z⁽¹⁾`, and for the digits of `t`, `g`, `h` `(b/2)²` per lower digit
//!   and the bound left for the top digit after removing the others from `q/2`. Difference:
//!   Section 5.4's `γ₁`, `γ₂`, `β′` are heuristic standard-deviation estimates, which the paper
//!   says an honest run can exceed; these are worst cases, so honest openings always pass.
//! * Projection slack `S = √(337/30) ≈ 3.35` ([`projection_slack_squared`]). Difference: the
//!   paper's verifier checks `‖p‖ ≤ √128·β` (Section 5.2, "Projecting"), which an honest
//!   projection fails about half the time, and lets the prover ask for new projection
//!   matrices; its slack is `√(128/30) ≈ 2.07` (Theorem 5.1). A Fiat–Shamir prover cannot ask
//!   for a fresh `Π` without a retry counter in the transcript, so the check here is
//!   `‖p‖ ≤ √337·β`, Lemma 4.1's upper tail, which an honest prover fails with probability
//!   about `2^{−128}`. Every place the paper uses `√(128/30)` uses `S` instead: the lemma
//!   condition, both Module-SIS bounds below, and the norm the LNP layer must be binding for
//!   (`proof/params.rs`).
//! * Inner rank `κ` (Theorem 5.1: Module-SIS of rank `κ` hard for
//!   `max(8T(b+1)β′, 2(b+1)β′ + 4T·√(128/30)·β)`): Module-SIS with bound
//!   `max(8T·Z, 2Z + 4T·S·β)`, `Z` the bound the verifier learns on `‖z‖` (the paper's
//!   `(b + 1)β′`, from `‖z‖ = ‖z⁽⁰⁾ + b·z⁽¹⁾‖ ≤ (1 + b)β′`, page 15). On a committed
//!   level that is `(1 + b)·S·β′`, the opening's norm being known only through the next level's
//!   projection (Remark 5.2: "the bounds for the Module-SIS hardness must also be increased by
//!   this factor"), or `S·β′` when `z` is not decomposed; on the tail, `γ`, because the tail's
//!   `z` is checked exactly. `(x + y)² ≤ 2x² + 2y²` bounds the second term from above.
//! * Outer rank `κ₁` of committed levels (Theorem 5.1: rank `κ₁ = κ₂` hard for `2β′`):
//!   Module-SIS with bound `2·S·β′`, again with Remark 5.2's factor. The
//!   paper's two outer commitments share this rank; `key.rs` records how they are laid out.
//! * Module-SIS hardness (no counterpart): the crate's estimate for the LNP commitment, root
//!   Hermite factor `2^{(log₂ B)²/(4·n·d·log₂ q)}` below `1.0044` and `B < q`. Section 6.1 instead sizes every rank for 128-bit Core-SVP
//!   hardness with the BDGL sieve. The rule here has not been shown to give that level at these
//!   ranks and moduli; it is the largest unverified security input of the layer.
//! * Lemma conditions (Theorem 5.1: `β ≤ √(30/128)·q/125`, Lemma 4.2's `b ≤ q/125` for
//!   `b = √(128/30)·β`): `S·β < q/125`, with `S` for the paper's slack as
//!   above.
//! * Invertible challenge differences (Section 2, "Challenge Space"): `2·4² < q`, see
//!   `challenge.rs`; checked once per derivation.
//! * Implementation bounds with no counterpart in the paper: `4γ² < q²`, so that the tail's
//!   norm check on centred coefficients is the norm over the integers; the projection's
//!   integer sums fit an `i64` (`(n·d)²·β² < 2^{124}`); `q < 2^{126}`, so digits fit an `i128`;
//!   ranks at most 64; at most 64 vectors per block.

use super::{
    challenge::{NORM_SQUARED, OPERATOR_NORM, differences_are_invertible},
    relation::Wide,
};
use crate::{
    error::{Error, Result},
    params::{ceil_div, ceil_sqrt, product, sum},
    proof::params::msis_is_hard,
    ring::Ring,
};

/// The rows of the Johnson–Lindenstrauss projection `Π ∈ {−1, 0, 1}^{256×nd}` (Section 4;
/// Section 5.2, "Projecting").
pub(crate) const PROJECTION_ROWS: usize = 256;
/// The verifier accepts `‖Πs‖² ≤ 337·β²` (Lemma 4.1, third bound). The paper
/// checks `128·β²` instead (Section 5.2); see the module documentation for why.
pub(crate) const PROJECTION_BOUND: u64 = 337;
/// Lemma 4.2's lower factor: a witness with `‖s‖ ≥ b` projects to `‖Πs mod q‖² ≥ 30·b²` except
/// with probability `2^{−128}`, so a passing projection bounds the witness by `√(337/30)·β`.
const PROJECTION_LOWER: u64 = 30;
/// Lemma 4.2 needs `b ≤ q/125`, here `√(337/30)·β < q/125`.
const PROJECTION_MODULUS_DIVISOR: u64 = 125;
/// The security parameter of the first aggregation: `⌈128/log q⌉` lifts (Section 5.2,
/// "Aggregating"), computed with `⌊log₂ q⌋`, which is at least as many.
const SECURITY: u64 = 128;
/// The largest Module-SIS rank tried (no counterpart in the paper).
const MAX_RANK: usize = 64;
/// The most vectors one block is split into (no counterpart in the paper).
const MAX_SPLIT: usize = 64;
/// Decomposing `z` pays off when `64·Var(z) > 2^26` (no counterpart in the paper).
const DECOMPOSE_Z_THRESHOLD: u64 = 1 << 26;
/// The widest supported modulus: digits are computed on `i128` centred lifts.
const MAX_MODULUS_BITS: u32 = 126;

/// Whether a level commits to its garbage and hands its opening to the next level (Section 5.2
/// with the recursion of Section 5.3), or is the last level and sends `t`, `g`, `h` and `z` in
/// the clear (Section 5.6, "No Outer Commitments"; without that section's interactive
/// reduction of the garbage terms, see `level.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Outer commitments `u₁`, `u₂`; the opening `(z⁽⁰⁾, z⁽¹⁾, t̂, ĝ, ĥ)` is the next witness.
    Committed,
    /// `t`, `g`, `h` and `z` in the clear (Section 5.6).
    Tail,
}

/// One witness vector of the level: a run of the flattened witness inside one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Chunk {
    /// The offset in the flattened witness.
    pub(crate) start: usize,
    /// The number of polynomials.
    pub(crate) len: usize,
}

/// Centred base-`2^bits` digits of `parts` digits each, the last taking what remains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Digits {
    /// The number of digits.
    pub(crate) parts: usize,
    /// `log₂` of the base.
    pub(crate) bits: u32,
}

/// The parameters of one level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LevelParams {
    /// Committed or tail.
    pub(crate) kind: Kind,
    /// The witness vectors `s₁, …, s_r`.
    pub(crate) chunks: Vec<Chunk>,
    /// For every block, its first vector and how many it has.
    pub(crate) block_chunks: Vec<(usize, usize)>,
    /// `n`, the length of the longest vector and of `z`.
    pub(crate) width: usize,
    /// The number of polynomials of the witness.
    pub(crate) total: usize,
    /// `κ`, the rank of the inner commitments `tᵢ = A·sᵢ`.
    pub(crate) kappa: usize,
    /// `κ₁`, the rank of `u₁` and `u₂` (zero on the tail).
    pub(crate) outer_rank: usize,
    /// The decomposition of `z` (one part when it is not decomposed).
    pub(crate) z_digits: Digits,
    /// The decomposition of `t`, `g` and `h` (one part on the tail).
    pub(crate) digits: Digits,
    /// `⌈λ/log₂ q⌉`, the number of lifted constant-coefficient constraints.
    pub(crate) lifts: usize,
    /// `β²` of the level's own witness.
    pub(crate) beta_squared: Wide,
    /// `γ²`, the bound on `‖z‖²`.
    pub(crate) gamma_squared: Wide,
    /// `β'²`, the bound on the opening of a committed level (`γ²` on the tail).
    pub(crate) next_beta_squared: Wide,
}

impl LevelParams {
    /// The parameters of least output size for a relation with these block lengths and bound.
    /// Fails with [`Error::CompressionParameters`] when differences of challenges need not be
    /// invertible modulo `q` or no split satisfies the conditions.
    pub(crate) fn derive(
        blocks: &[usize],
        beta_squared: &Wide,
        kind: Kind,
        ring: &Ring,
    ) -> Result<Self> {
        if !differences_are_invertible(&ring.modulus().resize()) {
            return Err(Error::CompressionParameters);
        }
        let mut widths: Vec<usize> = blocks
            .iter()
            .filter(|&&len| len > 0)
            .flat_map(|&len| (1..=MAX_SPLIT.min(len)).map(move |j| len.div_ceil(j)))
            .collect();
        widths.sort_unstable();
        widths.dedup();
        widths
            .into_iter()
            .filter_map(|width| Self::with_width(blocks, beta_squared, kind, ring, width).ok())
            .min_by_key(Self::cost)
            .ok_or(Error::CompressionParameters)
    }

    /// The parameters for vectors of at most `width` polynomials.
    fn with_width(
        blocks: &[usize],
        beta_squared: &Wide,
        kind: Kind,
        ring: &Ring,
        width: usize,
    ) -> Result<Self> {
        let infeasible = Error::CompressionParameters;
        let modulus_bits = ring.modulus().bit_width_vartime();
        if modulus_bits > MAX_MODULUS_BITS || width == 0 {
            return Err(infeasible);
        }
        let mut chunks = Vec::new();
        let mut block_chunks = Vec::with_capacity(blocks.len());
        let mut offset = 0;
        for &len in blocks {
            let first = chunks.len();
            chunks.extend((0..len).step_by(width).map(|start| Chunk {
                start: offset + start,
                len: width.min(len - start),
            }));
            block_chunks.push((first, chunks.len() - first));
            offset += len;
        }
        let total = offset;
        let width = chunks.iter().map(|c| c.len).max().ok_or(infeasible)?;
        let r = chunks.len();
        let pairs = r * (r + 1) / 2;
        let w = |x: usize| Wide::from_u64(x as u64);
        let d = ring.degree();
        let q: Wide = ring.modulus().resize();
        let q_squared = product(&[q, q])?;
        let log_q_floor = u64::from(modulus_bits - 1);
        let beta = *beta_squared;

        // Lemma 4.2 with Theorem 5.1's hypothesis: √(337/30)·β < q/125. And the projection's
        // integer sums fit an i64.
        let lemma = product(&[
            Wide::from_u64(PROJECTION_BOUND * PROJECTION_MODULUS_DIVISOR.pow(2)),
            beta,
        ])?;
        let coefficients = w(total * d);
        if lemma >= product(&[Wide::from_u64(PROJECTION_LOWER), q_squared])?
            || product(&[coefficients, coefficients, beta])? >= Wide::ONE.shl_vartime(124)
        {
            return Err(infeasible);
        }

        // γ² = T²·r·β², the worst case of equation (2).
        let t_squared = Wide::from_u64(OPERATOR_NORM * OPERATOR_NORM);
        let gamma_squared = product(&[t_squared, w(r), beta])?;
        if product(&[Wide::from_u64(4), gamma_squared])? >= q_squared {
            return Err(infeasible);
        }
        let lifts = usize::try_from(SECURITY.div_ceil(log_q_floor)).map_err(|_| infeasible)?;

        // log₂(12·Var(z)) with Var(z) = β²‖c‖²/(n·d), as a bit width (Section 5.4's
        // `12·r·τ·s²` for `s² = β²/(r·n·d)`).
        let variance = ceil_div(
            &product(&[beta, Wide::from_u64(NORM_SQUARED)])?,
            &w(width * d),
        )?;
        let log_variance = product(&[Wide::from_u64(12), variance])?.bit_width_vartime();
        let (z_digits, digits) = match kind {
            Kind::Tail => (
                Digits { parts: 1, bits: 0 },
                Digits {
                    parts: 1,
                    bits: modulus_bits,
                },
            ),
            Kind::Committed => {
                let decompose = product(&[Wide::from_u64(64), variance])?
                    > Wide::from_u64(DECOMPOSE_Z_THRESHOLD);
                let (parts, bits) = if decompose {
                    (2, ((log_variance + 2) / 4).max(1))
                } else {
                    (1, log_variance.div_ceil(2).max(1))
                };
                let unif_parts = ((modulus_bits + bits / 2) / bits).max(1);
                (
                    Digits { parts, bits },
                    Digits {
                        parts: unif_parts as usize,
                        bits: modulus_bits.div_ceil(unif_parts),
                    },
                )
            }
        };

        // Worst-case squared norms of the opening's parts; their sum is equation (5)'s β′².
        let z_squared = if z_digits.parts == 2 {
            let half = Wide::ONE.shl_vartime(z_digits.bits - 1);
            let low = product(&[w(width * d), half, half])?;
            let base = Wide::ONE.shl_vartime(z_digits.bits);
            let high_root = sum(ceil_sqrt(&gamma_squared), ceil_sqrt(&low))?;
            sum(
                low,
                ceil_div(&product(&[high_root, high_root])?, &product(&[base, base])?)?,
            )?
        } else {
            gamma_squared
        };
        let per_coefficient = digit_bound_squared(digits, &q)?;
        let next = |kappa: usize| -> Result<Wide> {
            match kind {
                Kind::Tail => Ok(gamma_squared),
                Kind::Committed => sum(
                    z_squared,
                    product(&[w(r * kappa + 2 * pairs), w(d), per_coefficient])?,
                ),
            }
        };
        let slack = projection_slack_squared;
        let secure = |bound_squared: &Wide, rank: usize| -> Result<bool> {
            Ok(*bound_squared < q_squared && msis_is_hard(bound_squared, rank, d, log_q_floor)?)
        };

        let z_base = Wide::ONE.shl_vartime(z_digits.bits);
        let mut kappa = 0;
        let mut next_beta_squared = Wide::ZERO;
        for rank in 1..=MAX_RANK {
            next_beta_squared = next(rank)?;
            let checked = match kind {
                Kind::Tail => gamma_squared,
                Kind::Committed if z_digits.parts == 2 => {
                    let factor = sum(Wide::ONE, z_base)?;
                    slack(&product(&[factor, factor, next_beta_squared])?)?
                }
                Kind::Committed => slack(&next_beta_squared)?,
            };
            // Theorem 5.1 with Remark 5.2: max((8T·Z)², (2Z + 4T·S·β)²), with
            // (x + y)² ≤ 2x² + 2y².
            let binding = product(&[Wide::from_u64(64), t_squared, checked])?.max(sum(
                product(&[Wide::from_u64(8), checked])?,
                product(&[Wide::from_u64(32), t_squared, slack(&beta)?])?,
            )?);
            if secure(&binding, rank)? {
                kappa = rank;
                break;
            }
        }
        if kappa == 0 {
            return Err(infeasible);
        }
        // Theorem 5.1 with Remark 5.2: (2·S·β′)².
        let outer_rank = match kind {
            Kind::Tail => 0,
            Kind::Committed => {
                let binding = product(&[Wide::from_u64(4), slack(&next_beta_squared)?])?;
                (1..=MAX_RANK)
                    .find(|&rank| secure(&binding, rank).unwrap_or(false))
                    .ok_or(infeasible)?
            }
        };
        Ok(Self {
            kind,
            chunks,
            block_chunks,
            width,
            total,
            kappa,
            outer_rank,
            z_digits,
            digits,
            lifts,
            beta_squared: beta,
            gamma_squared,
            next_beta_squared,
        })
    }

    /// `r`, the number of witness vectors.
    pub(crate) fn r(&self) -> usize {
        self.chunks.len()
    }

    /// `r(r+1)/2`, the number of garbage terms `g_ij` (and `h_ij`) with `i ≤ j`.
    pub(crate) fn pairs(&self) -> usize {
        self.r() * (self.r() + 1) / 2
    }

    /// The polynomials of the decomposed inner commitments.
    pub(crate) fn t_len(&self) -> usize {
        self.r() * self.kappa * self.digits.parts
    }

    /// The polynomials of the decomposed `g` (and of `h`).
    pub(crate) fn g_len(&self) -> usize {
        self.pairs() * self.digits.parts
    }

    /// The blocks of the opening: the parts of `z`, then `t`, `g` and `h`.
    pub(crate) fn opening_blocks(&self) -> Vec<usize> {
        core::iter::repeat_n(self.width, self.z_digits.parts)
            .chain([self.t_len(), self.g_len(), self.g_len()])
            .collect()
    }

    /// The polynomials this level adds to the proof and hands on: its messages and, for a
    /// committed level, its opening; for the tail, `t`, `g`, `h` and `z`. The rank search
    /// minimises it (no counterpart in the paper, see the module documentation).
    fn cost(&self) -> usize {
        let opening: usize = self.opening_blocks().iter().sum();
        opening + 2 * self.outer_rank + self.lifts
    }
}

/// `S²·x = 337·x/30`, rounded up: the square of the norm a passing projection of a witness of
/// squared norm `x` guarantees (Lemma 4.2 with this layer's check `‖p‖² ≤ 337·β²`).
pub(crate) fn projection_slack_squared(x: &Wide) -> Result<Wide> {
    ceil_div(
        &product(&[Wide::from_u64(PROJECTION_BOUND), *x])?,
        &Wide::from_u64(PROJECTION_LOWER),
    )
}

/// `(f − 1)·(b/2)² + M²` for `f` digits of base `b`: the largest squared contribution of one
/// coefficient of `(−q/2, q/2]`, whose lower digits lie in `[−b/2, b/2)` and whose top digit
/// is at most `M`, with `M` obtained from `q/2` by `f − 1` steps `M ↦ ⌊(M + b/2)/b⌋`. This is
/// the worst case that replaces Section 5.4's heuristic `γ₁`, `γ₂` in equation (5).
fn digit_bound_squared(digits: Digits, q: &Wide) -> Result<Wide> {
    if digits.parts == 1 {
        let half = q.shr_vartime(1);
        return product(&[half, half]);
    }
    let half_base = Wide::ONE.shl_vartime(digits.bits - 1);
    let mut top = q.shr_vartime(1);
    for _ in 1..digits.parts {
        top = sum(top, half_base)?.shr_vartime(digits.bits);
    }
    sum(
        product(&[
            Wide::from_u64(digits.parts as u64 - 1),
            half_base,
            half_base,
        ])?,
        product(&[top, top])?,
    )
}

/// The position of `g_ij` (`i ≤ j`) among the `r(r+1)/2` pairs, row by row.
pub(crate) fn pair_index(i: usize, j: usize, r: usize) -> usize {
    i * r - i * i.saturating_sub(1) / 2 + (j - i)
}
