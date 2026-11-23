// SPDX-License-Identifier: MIT OR Apache-2.0
//! The crate's one error type.

/// Errors returned by this crate. Every fallible operation returns one; nothing panics on bad
/// input. The variants carry no secret data, so an error can be logged as it is.
///
/// # Examples
///
/// ```
/// use kln_accumulator::{Element, Error, Params};
///
/// let params = Params::toy()?;
/// // The toy set has ℓ = 8, so an element is one byte.
/// let wide = Element::try_from(&[0u8, 0][..])?;
/// assert_eq!(wide.validate(&params), Err(Error::InvalidElement));
/// assert_eq!(Error::InvalidElement.to_string(), "element is not an ℓ-bit string");
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The ring degree `d` is not a power of two.
    #[error("ring degree {0} is not a power of two")]
    DegreeNotPowerOfTwo(usize),
    /// The modulus `q` is not prime.
    #[error("modulus is not prime")]
    ModulusNotPrime,
    /// The modulus `q` is not congruent to 5 modulo 8, so `X^d + 1` does not split into exactly
    /// two irreducible factors modulo `q`, which the proof layer's challenge space requires.
    #[error("modulus is not congruent to 5 modulo 8")]
    ModulusNotFiveModEight,
    /// The ring degree `d` exceeds the largest supported: [`crate::ParamsSpec::MAX_DEGREE`]
    /// for a parameter set, and `2^31`, the largest the multi-prime NTT's auxiliary primes
    /// support, for a ring.
    #[error("ring degree {0} exceeds the largest supported degree")]
    DegreeTooLarge(usize),
    /// The gadget base `b` is less than 2.
    #[error("gadget base {0} is less than 2")]
    BaseTooSmall(u32),
    /// The module rank `n` is zero.
    #[error("module rank n must be at least 1")]
    ZeroRank,
    /// The width `m` of `A` does not exceed the gadget width `m' = n·k`.
    #[error("m = {m} does not exceed m' = n·k = {m_prime}")]
    TooFewColumns {
        /// The requested width `m`.
        m: usize,
        /// The gadget width `m' = n·k`.
        m_prime: usize,
    },
    /// Two operands, or an operand and the ring, have incompatible dimensions.
    #[error("dimension mismatch: expected {expected}, found {found}")]
    DimensionMismatch {
        /// The dimension the operation requires.
        expected: usize,
        /// The dimension it was given.
        found: usize,
    },
    /// A coefficient is not reduced modulo `q`.
    #[error("coefficient is not reduced modulo q")]
    CoefficientOutOfRange,
    /// A coefficient of a short value (a witness, or the trapdoor `T` of the succinct variant)
    /// has centred magnitude above the bound its packed encoding allows.
    #[error("coefficient magnitude exceeds the bound of its encoding")]
    CoefficientOverBound,
    /// The padding bits of a packed encoding, or the reserved bytes of a parameter-set
    /// encoding, are not zero.
    #[error("packed encoding has non-zero padding bits")]
    NonCanonicalEncoding,
    /// A value belongs to a different parameter set than the one it is used with.
    #[error("value belongs to a different parameter set")]
    ParameterMismatch,
    /// An encoding is truncated, has trailing bytes, or is not a whole number of coefficients.
    #[error("encoding of length {0} does not have the expected layout")]
    InvalidEncodingLength(usize),
    /// A parameter-set encoding names a trapdoor distribution other than Gaussian (0) and
    /// Ternary (1).
    #[error("trapdoor distribution {0} is not defined")]
    InvalidTrapdoorDistribution(u8),
    /// The element bit length `ℓ` is zero.
    #[error("element bit length ℓ must be at least 1")]
    ZeroElementBits,
    /// The realised Gaussian width `s` is below the least width of the preimage sampler,
    /// `√(2π·V₀)` (see [`crate::Bounds::least_width`]).
    #[error("Gaussian width s is below the preimage sampler's least width")]
    WidthTooSmall,
    /// The witness bound `β`, or the largest coefficient a preimage can take, is at least `q/2`,
    /// so short vectors would not be determined by their residues; or a width or variance of the
    /// set exceeds what its samplers can represent; or a dimension of the set overflows, or its
    /// matrix `[A | B]` would hold more than [`crate::ParamsSpec::MAX_MATRIX_ENTRIES`]
    /// polynomials.
    #[error("witness norm bound β is not below q/2")]
    WitnessBoundTooLarge,
    /// A trapdoor does not fit its parameter set: a coefficient lies beyond the tail cut of the
    /// set's trapdoor distribution, its perturbation covariance has a pivot below `V₀/4`, or
    /// key generation drew no acceptable trapdoor. Also returned by the preimage samplers when
    /// the matrix is not the one the trapdoor was generated with, so the draw is no preimage.
    #[error("trapdoor does not fit the parameter set")]
    InvalidTrapdoor,
    /// A caller's seed for key generation is shorter than [`crate::MIN_SEED_BYTES`] (32 bytes);
    /// it carries the length given. Whoever guesses a short seed has the key.
    #[error("key seed of {0} bytes is shorter than the {min} bytes required", min = crate::MIN_SEED_BYTES)]
    SeedTooShort(usize),
    /// An element is empty, is not `⌈ℓ/8⌉` bytes long, or sets a bit at or above position `ℓ`.
    #[error("element is not an ℓ-bit string")]
    InvalidElement,
    /// The element was added before, and is present or deleted. Construction 4.1 is
    /// replacement-free (Remark 4.2): an element is never added a second time.
    #[error("element was already added")]
    ElementAlreadyAdded,
    /// The element is not in the accumulator: it was never added, or it was deleted.
    #[error("element is not in the accumulator")]
    ElementNotPresent,
    /// The accumulator has already performed its `γ` deletions.
    #[error("the deletion bound γ has been reached")]
    DeletionBoundReached,
    /// The holder's own element is among the deletions, so its witness cannot be updated; the
    /// counterpart of the vb20 pairing accumulator's "no inverse exists".
    #[error("the witness holder's element was deleted")]
    ElementDeleted,
    /// The update messages do not name the deletions they accompany, in the same order.
    #[error("update messages do not match the deletions")]
    CoefficientMismatch,
    /// A witness does not verify against the accumulator value it was supplied with, or the
    /// manager state and the accumulator value describe different accumulators.
    #[error("witness, accumulator value and manager state do not agree")]
    AccumulatorMismatch,
    /// The manager state is not a history Construction 4.1 can produce: the deletion epochs are
    /// not exactly `1, …, ctr`, or an addition epoch exceeds `ctr`.
    #[error("manager state is inconsistent")]
    InconsistentState,
    /// The tag of a manager state does not verify under the secret key it is used with: a field
    /// of the state was altered after the key tagged it, or another key tagged it.
    #[error("manager state tag does not verify under the secret key")]
    InvalidStateTag,
    /// A base witness was asked of the base key inside a succinct key. Such a key issues
    /// succinct witnesses only, as in the paper, where a holder of the `ℓ`-succinct variant
    /// receives the compressed vector and never the preimage it is the image of.
    #[error("a succinct key issues succinct witnesses only")]
    CompressedWitnessOnly,
    /// Every one of the `2^ℓ` handles of the adaptive accumulator was used: handles are never
    /// reused (Construction 4.2, Add step 3), so no further element can be added.
    #[error("all 2^ℓ handles of the adaptive accumulator are used")]
    HandleSpaceExhausted,
    /// The signature of an adaptive witness is not a valid ML-DSA signature over its element and
    /// handle.
    #[error("the signature does not bind the element to its handle")]
    InvalidSignature,
    /// ML-DSA signing failed (its rejection loop gave up).
    #[error("ML-DSA signing failed")]
    SigningFailed,
    /// Membership proofs are implemented over the degree-64 proof ring only, and the accumulator
    /// ring of this parameter set has another degree.
    #[error("membership proofs support ring degree 64 only, found {0}")]
    UnsupportedProofDegree(usize),
    /// The modulus fails a condition Appendix D.2.3 places on it, or no Module-SIS rank up to
    /// the search limit makes the commitment binding; or the length `m̄₁` of the committed
    /// message overflows, as for a linking vector `r` of `usize::MAX` entries.
    #[error("the modulus does not satisfy the conditions of Appendix D.2.3")]
    ProofModulusTooSmall,
    /// The prover's inputs do not satisfy relation D.2: the witness does not verify against the
    /// accumulator, `r` is not binary, `A1·x + A2·r ≠ t`, or a witness coefficient does not fit
    /// its digit decomposition.
    #[error("the prover's inputs do not satisfy the membership relation")]
    RelationUnsatisfied,
    /// Every attempt of the prover's rejection-sampling loop aborted.
    #[error("the prover aborted on every attempt")]
    ProverAborted,
    /// A membership proof failed verification.
    #[error("the membership proof does not verify")]
    ProofRejected,
    /// No LaBRADOR level parameters satisfy the Module-SIS and Johnson–Lindenstrauss conditions
    /// for the relation at this modulus.
    #[error("no LaBRADOR parameters satisfy the conditions for this relation and modulus")]
    CompressionParameters,
    /// The number of LaBRADOR levels is zero or above the supported maximum.
    #[error("the number of LaBRADOR levels {0} is not between 1 and the maximum")]
    InvalidCompressionLevels(u8),
}

/// Result type of this crate: `core::result::Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

/// Fails with [`Error::DimensionMismatch`], carrying `expected` and `found`, unless the two are
/// equal.
pub(crate) fn check_dimension(expected: usize, found: usize) -> Result<()> {
    if expected == found {
        Ok(())
    } else {
        Err(Error::DimensionMismatch { expected, found })
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn display_names_the_offending_values() {
        let err = Error::TooFewColumns { m: 10, m_prime: 10 };
        assert_eq!(err.to_string(), "m = 10 does not exceed m' = n·k = 10");
        let err = Error::DimensionMismatch {
            expected: 64,
            found: 32,
        };
        assert_eq!(err.to_string(), "dimension mismatch: expected 64, found 32");
        assert_eq!(
            Error::SeedTooShort(31).to_string(),
            "key seed of 31 bytes is shorter than the 32 bytes required"
        );
    }
}
