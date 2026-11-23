// SPDX-License-Identifier: MIT OR Apache-2.0
//! Matrices over `R_q`, in coefficient form and in a cached multi-prime NTT form for repeated
//! products: the public matrices `A`, `B` (and `B₁`, `W`, `T₀`, `T₁` of the succinct variant),
//! the gadget `G`, and the trapdoor `T_A` inside the sampler.
//!
//! A product transforms its operands with the ring's multi-prime NTT, accumulates pointwise
//! over the inner index, and inverts once per output entry (see [`Ring`]). A matrix that is
//! multiplied many times is worth converting to an [`NttMatrix`] once.
//!
//! ```
//! use kln_accumulator::Params;
//! use kln_accumulator::lattice::{DomainLabel, NttMatrix, Seed, Shape, UniformSampler};
//!
//! let params = Params::toy()?;
//! let ring = params.ring();
//! let mut sampler = UniformSampler::new(&Seed::from([4; 32]), DomainLabel::from(&b"m"[..]));
//! let a = sampler.matrix(Shape { rows: 2, cols: 3 }, ring);
//! let x = sampler.vector(3, ring);
//! let cached = NttMatrix::new(&a, ring)?;
//! assert_eq!(cached.mul_vec(&x, ring)?, a.mul_vec(&x, ring)?);
//! # Ok::<(), kln_accumulator::Error>(())
//! ```

use crate::{
    error::{Error, Result, check_dimension},
    poly::Poly,
    ring::{NttPoly, Ring},
    vector::PolyVec,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The dimensions of a matrix. **Public.**
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{PolyMatrix, Shape};
///
/// let params = Params::toy()?;
/// let shape = Shape { rows: 1, cols: params.spec().m };
/// assert_eq!(PolyMatrix::zero(shape, params.ring()).shape(), shape);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shape {
    /// The number of rows.
    pub rows: usize,
    /// The number of columns.
    pub cols: usize,
}

impl Shape {
    /// `rows · cols`, or `None` when the product overflows.
    pub(crate) fn len(self) -> Option<usize> {
        self.rows.checked_mul(self.cols)
    }

    /// `rows · cols`, saturated at `usize::MAX`, for error reports.
    pub(crate) fn saturating_len(self) -> usize {
        self.rows.saturating_mul(self.cols)
    }
}

/// A matrix over `R_q`, stored row-major.
///
/// **Public type, wiped on drop**: its entries are [`Poly`]s, which overwrite their
/// coefficients when dropped. Serialized as its shape and its entries; deserialization checks
/// the shape as [`PolyMatrix::new`] does but not the coefficients, so call
/// [`PolyMatrix::validate`] before use.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{Poly, PolyMatrix, Shape};
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let one = Poly::new(
///     (0..ring.degree()).map(|i| kln_accumulator::lattice::Coeff::from_u64(u64::from(i == 0))).collect(),
///     ring,
/// )?;
/// let shape = Shape { rows: 2, cols: 2 };
/// let identity = PolyMatrix::new(shape, vec![one.clone(), Poly::zero(ring), Poly::zero(ring), one])?;
/// let m = PolyMatrix::zero(shape, ring).add(&identity, ring)?.mul_small(5, ring)?;
/// assert_eq!(m.mul(&identity, ring)?, m);
/// assert_eq!(m.sub(&m, ring)?, PolyMatrix::zero(shape, ring));
/// assert_eq!(m.neg(ring)?.add(&m, ring)?, PolyMatrix::zero(shape, ring));
/// assert_eq!(m.get(0, 1), Some(&Poly::zero(ring)));
/// assert_eq!(m.get(2, 0), None);
/// let wide = m.hconcat(&identity)?;
/// assert_eq!(wide.shape(), Shape { rows: 2, cols: 4 });
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MatrixParts")]
pub struct PolyMatrix {
    shape: Shape,
    entries: Vec<Poly>,
}

/// The unchecked serialized form of [`PolyMatrix`]; a field it does not name is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixParts {
    shape: Shape,
    entries: Vec<Poly>,
}

impl TryFrom<MatrixParts> for PolyMatrix {
    type Error = Error;

    fn try_from(parts: MatrixParts) -> Result<Self> {
        Self::new(parts.shape, parts.entries)
    }
}

impl PolyMatrix {
    /// Builds a matrix from `rows · cols` entries in row-major order; see the type's example.
    /// The entries are not checked against a ring.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] unless there are exactly `rows · cols` entries, with
    /// `rows · cols` computed without overflow. A shape with zero rows and some columns, or
    /// the reverse, is refused too (`expected: 0`, `found` the other dimension): it needs no
    /// entries whatever its other dimension, so that dimension would be bounded by nothing.
    /// [`PolyMatrix::zero`] still builds such a shape.
    ///
    /// ```
    /// use kln_accumulator::Error;
    /// use kln_accumulator::lattice::{PolyMatrix, Shape};
    ///
    /// let empty = |rows, cols| PolyMatrix::new(Shape { rows, cols }, Vec::new());
    /// assert!(empty(0, 0).is_ok());
    /// assert_eq!(empty(0, 5), Err(Error::DimensionMismatch { expected: 0, found: 5 }));
    /// // rows · cols overflows.
    /// let wrapped = Error::DimensionMismatch { expected: usize::MAX, found: 0 };
    /// assert_eq!(empty(usize::MAX, 2), Err(wrapped));
    /// ```
    pub fn new(shape: Shape, entries: Vec<Poly>) -> Result<Self> {
        if (shape.rows == 0) != (shape.cols == 0) {
            return Err(Error::DimensionMismatch {
                expected: 0,
                found: shape.rows.max(shape.cols),
            });
        }
        if shape.len() == Some(entries.len()) {
            Ok(Self { shape, entries })
        } else {
            Err(Error::DimensionMismatch {
                expected: shape.saturating_len(),
                found: entries.len(),
            })
        }
    }

    /// Wraps entries whose count the caller guarantees is `rows · cols`.
    pub(crate) fn from_parts(shape: Shape, entries: Vec<Poly>) -> Self {
        Self { shape, entries }
    }

    /// The zero matrix of `shape`; see the type's example. A shape whose `rows · cols`
    /// overflows cannot be allocated, as for `vec!` of that length.
    #[must_use]
    pub fn zero(shape: Shape, ring: &Ring) -> Self {
        Self::from_parts(shape, vec![Poly::zero(ring); shape.saturating_len()])
    }

    /// The dimensions; see the type's example.
    #[must_use]
    pub fn shape(&self) -> Shape {
        self.shape
    }

    /// The entry at `(row, col)`, or `None` when out of bounds; see the type's example.
    #[must_use]
    pub fn get(&self, row: usize, col: usize) -> Option<&Poly> {
        if row < self.shape.rows && col < self.shape.cols {
            self.entries.get(row * self.shape.cols + col)
        } else {
            None
        }
    }

    /// Checks every entry with [`Poly::validate`].
    ///
    /// # Errors
    ///
    /// As [`Poly::validate`], for the first entry that fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use kln_accumulator::Params;
    /// use kln_accumulator::lattice::{PolyMatrix, Shape};
    ///
    /// let (toy, paper) = (Params::toy()?, Params::paper_128()?);
    /// let m = PolyMatrix::zero(Shape { rows: 1, cols: 2 }, toy.ring());
    /// assert!(m.validate(toy.ring()).is_ok());
    /// assert!(m.validate(paper.ring()).is_err());
    /// # Ok::<(), kln_accumulator::Error>(())
    /// ```
    pub fn validate(&self, ring: &Ring) -> Result<()> {
        self.entries.iter().try_for_each(|p| p.validate(ring))
    }

    /// `self + rhs`, entry by entry; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when the shapes differ or an entry does not have degree
    /// `d`.
    pub fn add(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        self.zip_with(rhs, |a, b| a.add(b, ring))
    }

    /// `self − rhs`, entry by entry; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when the shapes differ or an entry does not have degree
    /// `d`.
    pub fn sub(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        self.zip_with(rhs, |a, b| a.sub(b, ring))
    }

    /// `−self`; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when an entry does not have degree `d`.
    pub fn neg(&self, ring: &Ring) -> Result<Self> {
        self.map(|p| p.neg(ring))
    }

    /// `scalar · self` for a signed integer `scalar`; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when an entry does not have degree `d`.
    pub fn mul_small(&self, scalar: i64, ring: &Ring) -> Result<Self> {
        self.map(|p| p.mul_small(scalar, ring))
    }

    /// `self · rhs`. Transforms both operands; when `self` is reused, build an [`NttMatrix`] once
    /// instead. See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when `rhs` has not as many rows as `self` has columns, or
    /// an entry does not have degree `d`.
    pub fn mul(&self, rhs: &Self, ring: &Ring) -> Result<Self> {
        NttMatrix::new(self, ring)?.mul_matrix(rhs, ring)
    }

    /// `self · vector`. Transforms `self`; when `self` is reused, build an [`NttMatrix`] once
    /// instead. See [`NttMatrix`]'s example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when `vector` has not as many entries as `self` has
    /// columns, or an entry does not have degree `d`.
    pub fn mul_vec(&self, vector: &PolyVec, ring: &Ring) -> Result<PolyVec> {
        NttMatrix::new(self, ring)?.mul_vec(vector, ring)
    }

    /// The `size × size` identity matrix.
    pub(crate) fn identity(size: usize, ring: &Ring) -> Self {
        let one = Poly::constant(1, ring);
        let zero = Poly::zero(ring);
        Self::from_parts(
            Shape {
                rows: size,
                cols: size,
            },
            (0..size * size)
                .map(|i| {
                    if i % (size + 1) == 0 {
                        one.clone()
                    } else {
                        zero.clone()
                    }
                })
                .collect(),
        )
    }

    /// The columns `[start, start + width)`.
    pub(crate) fn column_block(&self, start: usize, width: usize) -> Result<Self> {
        if start + width > self.shape.cols {
            return Err(Error::DimensionMismatch {
                expected: self.shape.cols,
                found: start + width,
            });
        }
        Ok(Self::from_parts(
            Shape {
                rows: self.shape.rows,
                cols: width,
            },
            self.row_slices()
                .flat_map(|row| row[start..start + width].iter().cloned())
                .collect(),
        ))
    }

    /// The rows `[start, start + height)`.
    pub(crate) fn row_block(&self, start: usize, height: usize) -> Result<Self> {
        if start + height > self.shape.rows {
            return Err(Error::DimensionMismatch {
                expected: self.shape.rows,
                found: start + height,
            });
        }
        Ok(Self::from_parts(
            Shape {
                rows: height,
                cols: self.shape.cols,
            },
            self.row_slices()
                .skip(start)
                .take(height)
                .flatten()
                .cloned()
                .collect(),
        ))
    }

    /// The vertical concatenation of `blocks`, which must share one column count.
    pub(crate) fn vstack(blocks: Vec<Self>) -> Result<Self> {
        let cols = blocks.first().map_or(0, |b| b.shape.cols);
        let mut rows = 0;
        let mut entries = Vec::new();
        for block in blocks {
            check_dimension(cols, block.shape.cols)?;
            rows += block.shape.rows;
            entries.extend(block.entries);
        }
        Ok(Self::from_parts(Shape { rows, cols }, entries))
    }

    /// The horizontal concatenation `[self | rhs]`, as in `[A | B − xᵀ⊗G]`; see the type's
    /// example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when the row counts differ.
    pub fn hconcat(&self, rhs: &Self) -> Result<Self> {
        check_dimension(self.shape.rows, rhs.shape.rows)?;
        let entries = self
            .row_slices()
            .zip(rhs.row_slices())
            .flat_map(|(left, right)| left.iter().chain(right).cloned())
            .collect();
        Ok(Self::from_parts(
            Shape {
                rows: self.shape.rows,
                cols: self.shape.cols + rhs.shape.cols,
            },
            entries,
        ))
    }

    /// The entries, row-major.
    pub(crate) fn entries(&self) -> &[Poly] {
        &self.entries
    }

    /// Appends every coefficient, entries row-major, as in [`Poly::write_coefficients`].
    pub(crate) fn write_coefficients(&self, out: &mut Vec<u8>) {
        self.entries.iter().for_each(|p| p.write_coefficients(out));
    }

    fn row_slices(&self) -> impl Iterator<Item = &[Poly]> {
        let cols = self.shape.cols;
        (0..self.shape.rows).map(move |i| &self.entries[i * cols..(i + 1) * cols])
    }

    fn map(&self, f: impl Fn(&Poly) -> Result<Poly>) -> Result<Self> {
        Ok(Self::from_parts(
            self.shape,
            self.entries.iter().map(f).collect::<Result<_>>()?,
        ))
    }

    fn zip_with(&self, rhs: &Self, f: impl Fn(&Poly, &Poly) -> Result<Poly>) -> Result<Self> {
        if self.shape != rhs.shape {
            return Err(Error::DimensionMismatch {
                expected: self.shape.saturating_len(),
                found: rhs.shape.saturating_len(),
            });
        }
        Ok(Self::from_parts(
            self.shape,
            self.entries
                .iter()
                .zip(&rhs.entries)
                .map(|(a, b)| f(a, b))
                .collect::<Result<_>>()?,
        ))
    }
}

/// A matrix over `R_q` with every entry kept in the multi-prime NTT form of its integer
/// coefficients, so that each product with it costs only the transforms of the other operand
/// and of the result.
///
/// **Public type, wiped on drop**: the sampler keeps `T_A` in this form, so every transformed
/// entry overwrites itself when dropped. [`fmt::Debug`](core::fmt::Debug) prints the
/// transformed values; the sampler never exposes its copy.
///
/// # Examples
///
/// ```
/// use kln_accumulator::Params;
/// use kln_accumulator::lattice::{DomainLabel, NttMatrix, Seed, Shape, UniformSampler};
///
/// let params = Params::toy()?;
/// let ring = params.ring();
/// let mut sampler = UniformSampler::new(&Seed::from([5; 32]), DomainLabel::from(&b"n"[..]));
/// let a = sampler.matrix(Shape { rows: 2, cols: 3 }, ring);
/// let b = sampler.matrix(Shape { rows: 3, cols: 2 }, ring);
/// let cached = NttMatrix::new(&a, ring)?;
/// assert_eq!(cached.shape(), a.shape());
/// assert_eq!(cached.mul_matrix(&b, ring)?, a.mul(&b, ring)?);
/// let x = sampler.vector(3, ring);
/// assert_eq!(cached.mul_vec(&x, ring)?, a.mul_vec(&x, ring)?);
/// # Ok::<(), kln_accumulator::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NttMatrix {
    shape: Shape,
    entries: Vec<NttPoly>,
}

impl NttMatrix {
    /// Transforms every entry of `matrix`: one forward transform per entry and auxiliary prime.
    /// See the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when an entry does not have degree `d`.
    pub fn new(matrix: &PolyMatrix, ring: &Ring) -> Result<Self> {
        Ok(Self {
            shape: matrix.shape,
            entries: transform(&matrix.entries, ring)?,
        })
    }

    /// Wraps entries already in NTT form whose count the caller guarantees is `rows · cols`.
    pub(crate) fn from_parts(shape: Shape, entries: Vec<NttPoly>) -> Self {
        Self { shape, entries }
    }

    /// The dimensions; see the type's example.
    #[must_use]
    pub fn shape(&self) -> Shape {
        self.shape
    }

    /// `lhs · self`, transforming only `lhs`.
    pub(crate) fn left_mul(&self, lhs: &PolyMatrix, ring: &Ring) -> Result<PolyMatrix> {
        let lhs = Self::new(lhs, ring)?;
        lhs.check_inner(self.shape.rows)?;
        Ok(PolyMatrix::from_parts(
            Shape {
                rows: lhs.shape.rows,
                cols: self.shape.cols,
            },
            lhs.product(&self.entries, self.shape.cols, ring),
        ))
    }

    /// `self · vector`, transforming only `vector`; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when `vector` has not as many entries as `self` has
    /// columns, or an entry does not have degree `d`.
    pub fn mul_vec(&self, vector: &PolyVec, ring: &Ring) -> Result<PolyVec> {
        self.mul_entries(vector.as_slice(), ring)
    }

    /// `self · v` for the vector `v` with entries `entries`, without building `v`.
    pub(crate) fn mul_entries(&self, entries: &[Poly], ring: &Ring) -> Result<PolyVec> {
        self.check_inner(entries.len())?;
        let rhs = transform(entries, ring)?;
        Ok(self.product(&rhs, 1, ring).into())
    }

    /// `self · rhs`, transforming only `rhs`; see the type's example.
    ///
    /// # Errors
    ///
    /// [`Error::DimensionMismatch`] when `rhs` has not as many rows as `self` has columns, or
    /// an entry does not have degree `d`.
    pub fn mul_matrix(&self, rhs: &PolyMatrix, ring: &Ring) -> Result<PolyMatrix> {
        self.check_inner(rhs.shape.rows)?;
        let transformed = transform(&rhs.entries, ring)?;
        Ok(PolyMatrix::from_parts(
            Shape {
                rows: self.shape.rows,
                cols: rhs.shape.cols,
            },
            self.product(&transformed, rhs.shape.cols, ring),
        ))
    }

    fn check_inner(&self, rhs_rows: usize) -> Result<()> {
        check_dimension(self.shape.cols, rhs_rows)
    }

    /// Row-major product with a `cols × rhs_cols` right operand in NTT form: pointwise
    /// accumulation over the inner index and, whenever the inner dimension fits one
    /// transformed sum, a single inverse transform per output entry.
    fn product(&self, rhs: &[NttPoly], rhs_cols: usize, ring: &Ring) -> Vec<Poly> {
        let inner = self.shape.cols;
        (0..self.shape.rows)
            .flat_map(|i| (0..rhs_cols).map(move |j| (i, j)))
            .map(|(i, j)| {
                ring.sum_of_products(
                    (0..inner).map(|t| (&self.entries[i * inner + t], &rhs[t * rhs_cols + j])),
                )
            })
            .collect()
    }
}

/// Overwrites every entry.
impl Zeroize for NttMatrix {
    fn zeroize(&mut self) {
        self.entries.iter_mut().for_each(Zeroize::zeroize);
    }
}

/// Every entry is a transformed polynomial that overwrites its values when dropped.
impl ZeroizeOnDrop for NttMatrix {}

/// Overwrites every entry.
impl Zeroize for PolyMatrix {
    fn zeroize(&mut self) {
        self.entries.iter_mut().for_each(Zeroize::zeroize);
    }
}

/// Every entry is a [`Poly`], which overwrites its coefficients when dropped.
impl ZeroizeOnDrop for PolyMatrix {}

/// The multi-prime NTT form of every entry.
pub(crate) fn transform(polys: &[Poly], ring: &Ring) -> Result<Vec<NttPoly>> {
    polys.iter().map(|p| ring.ntt(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::{NttMatrix, PolyMatrix, Shape};
    use crate::{
        error::Error,
        poly::Poly,
        test_util::{TOY, arb_matrix, arb_vec, six_formats},
        vector::PolyVec,
    };
    use proptest::prelude::*;

    /// A matrix and a shape round-trip in the six formats; the matrix's polynomials are hex in
    /// the human-readable forms.
    #[test]
    fn serde_six_formats() {
        let ring = TOY.ring();
        let shape = Shape { rows: 1, cols: 2 };
        let _ = six_formats(shape, "rows");
        let entry = Poly::constant(9, ring);
        let mut bytes = Vec::new();
        entry.write_coefficients(&mut bytes);
        let m = PolyMatrix::new(shape, vec![entry.clone(), entry]).unwrap();
        let _ = six_formats(m, &hex::encode(&bytes));
    }

    const TWO_BY_THREE: Shape = Shape { rows: 2, cols: 3 };

    /// Entry-by-entry definition of the product, independent of the NTT accumulation.
    fn naive_mul(a: &PolyMatrix, b: &PolyMatrix) -> PolyMatrix {
        let ring = TOY.ring();
        let shape = Shape {
            rows: a.shape().rows,
            cols: b.shape().cols,
        };
        let entries = (0..shape.rows)
            .flat_map(|i| (0..shape.cols).map(move |j| (i, j)))
            .map(|(i, j)| {
                (0..a.shape().cols).fold(Poly::zero(ring), |acc, t| {
                    let term = a
                        .get(i, t)
                        .unwrap()
                        .mul(b.get(t, j).unwrap(), ring)
                        .unwrap();
                    acc.add(&term, ring).unwrap()
                })
            })
            .collect();
        PolyMatrix::new(shape, entries).unwrap()
    }

    #[test]
    fn new_checks_entry_count() {
        let ring = TOY.ring();
        assert!(PolyMatrix::new(TWO_BY_THREE, vec![Poly::zero(ring); 6]).is_ok());
        assert_eq!(
            PolyMatrix::new(TWO_BY_THREE, vec![Poly::zero(ring); 5]),
            Err(Error::DimensionMismatch {
                expected: 6,
                found: 5
            })
        );
    }

    /// A shape whose `rows · cols` overflows, or with rows but no columns (or the reverse), is
    /// refused with an error in every build profile, by `new` and by deserialization: with
    /// overflow checks off the product used to wrap to the entry count, and a degenerate shape
    /// needs no entries at all.
    #[test]
    fn overflowing_and_degenerate_shapes_are_refused() {
        let wrapped = Error::DimensionMismatch {
            expected: usize::MAX,
            found: 0,
        };
        let degenerate = Error::DimensionMismatch {
            expected: 0,
            found: usize::MAX,
        };
        for (shape, error) in [
            (
                Shape {
                    rows: 1 << 32,
                    cols: 1 << 32,
                },
                wrapped,
            ),
            (
                Shape {
                    rows: 1 << 63,
                    cols: 2,
                },
                wrapped,
            ),
            (
                Shape {
                    rows: usize::MAX,
                    cols: 0,
                },
                degenerate,
            ),
            (
                Shape {
                    rows: 0,
                    cols: usize::MAX,
                },
                degenerate,
            ),
        ] {
            assert_eq!(PolyMatrix::new(shape, Vec::new()), Err(error));
            let json = format!(
                r#"{{"shape":{{"rows":{},"cols":{}}},"entries":[]}}"#,
                shape.rows, shape.cols
            );
            let refused = serde_json::from_str::<PolyMatrix>(&json).unwrap_err();
            assert!(
                refused.to_string().starts_with(&error.to_string()),
                "{refused}"
            );
        }
        assert_eq!(
            PolyMatrix::new(Shape { rows: 0, cols: 0 }, Vec::new()).map(|m| m.shape()),
            Ok(Shape { rows: 0, cols: 0 })
        );
    }

    #[test]
    fn zero_shape_get_validate() {
        let ring = TOY.ring();
        let zero = PolyMatrix::zero(TWO_BY_THREE, ring);
        assert_eq!(zero.shape(), TWO_BY_THREE);
        assert_eq!(zero.get(1, 2), Some(&Poly::zero(ring)));
        assert_eq!(zero.get(2, 0), None);
        assert_eq!(zero.get(0, 3), None);
        assert!(zero.validate(ring).is_ok());
        let ntt = NttMatrix::new(&zero, ring).unwrap();
        assert_eq!(ntt.shape(), TWO_BY_THREE);
    }

    #[test]
    fn dimension_errors() {
        let ring = TOY.ring();
        let a = PolyMatrix::zero(TWO_BY_THREE, ring);
        let b = PolyMatrix::zero(Shape { rows: 3, cols: 3 }, ring);
        assert!(a.add(&b, ring).is_err());
        assert!(a.sub(&b, ring).is_err());
        assert!(a.mul(&a, ring).is_err());
        assert!(a.mul_vec(&PolyVec::zero(2, ring), ring).is_err());
        assert_eq!(
            a.hconcat(&b),
            Err(Error::DimensionMismatch {
                expected: 2,
                found: 3
            })
        );
    }

    #[test]
    fn hconcat_with_empty_columns() {
        let ring = TOY.ring();
        let empty = PolyMatrix::zero(Shape { rows: 2, cols: 0 }, ring);
        let a = PolyMatrix::zero(TWO_BY_THREE, ring);
        assert_eq!(empty.hconcat(&a).unwrap(), a);
        assert_eq!(a.hconcat(&empty).unwrap(), a);
    }

    #[test]
    fn identity_blocks_and_stacking() {
        let ring = TOY.ring();
        let id = PolyMatrix::identity(3, ring);
        assert_eq!(id.get(1, 1), Some(&Poly::constant(1, ring)));
        assert_eq!(id.get(1, 2), Some(&Poly::zero(ring)));
        let a = PolyMatrix::zero(TWO_BY_THREE, ring);
        assert_eq!(
            a.column_block(2, 2),
            Err(Error::DimensionMismatch {
                expected: 3,
                found: 4
            })
        );
        assert_eq!(
            PolyMatrix::vstack(vec![a.clone(), id.clone()])
                .unwrap()
                .shape(),
            Shape { rows: 5, cols: 3 }
        );
        assert!(PolyMatrix::vstack(vec![a, PolyMatrix::identity(2, ring)]).is_err());
        assert_eq!(
            PolyMatrix::vstack(Vec::new()).unwrap().shape(),
            Shape { rows: 0, cols: 0 }
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn blocks_reassemble(a in arb_matrix(&TOY, Shape { rows: 2, cols: 5 }), b in arb_matrix(&TOY, Shape { rows: 3, cols: 2 })) {
            let ring = TOY.ring();
            let left = a.column_block(0, 2).unwrap();
            let right = a.column_block(2, 3).unwrap();
            prop_assert_eq!(left.hconcat(&right).unwrap(), a.clone());
            let stacked = PolyMatrix::vstack(vec![a.column_block(0, 2).unwrap(), b.clone()]).unwrap();
            prop_assert_eq!(stacked.get(2, 1).unwrap(), b.get(0, 1).unwrap());
            prop_assert_eq!(PolyMatrix::identity(2, ring).mul(&left, ring).unwrap(), left.clone());
            let cached = NttMatrix::new(&b, ring).unwrap();
            prop_assert_eq!(cached.left_mul(&left, ring), Err(Error::DimensionMismatch { expected: 2, found: 3 }));
            prop_assert_eq!(NttMatrix::new(&right, ring).unwrap().left_mul(&b, ring).unwrap(), b.mul(&right, ring).unwrap());
        }

        #[test]
        fn elementwise_operations(
            a in arb_matrix(&TOY, TWO_BY_THREE),
            b in arb_matrix(&TOY, TWO_BY_THREE),
            k in -5i64..5,
        ) {
            let ring = TOY.ring();
            let sum = a.add(&b, ring).unwrap();
            let difference = a.sub(&b, ring).unwrap();
            let negated = a.neg(ring).unwrap();
            let scaled = a.mul_small(k, ring).unwrap();
            for (i, j) in (0..2).flat_map(|i| (0..3).map(move |j| (i, j))) {
                let (x, y) = (a.get(i, j).unwrap(), b.get(i, j).unwrap());
                prop_assert_eq!(sum.get(i, j).unwrap(), &x.add(y, ring).unwrap());
                prop_assert_eq!(difference.get(i, j).unwrap(), &x.sub(y, ring).unwrap());
                prop_assert_eq!(negated.get(i, j).unwrap(), &x.neg(ring).unwrap());
                prop_assert_eq!(scaled.get(i, j).unwrap(), &x.mul_small(k, ring).unwrap());
            }
        }

        #[test]
        fn products_match_naive(
            a in arb_matrix(&TOY, TWO_BY_THREE),
            b in arb_matrix(&TOY, Shape { rows: 3, cols: 2 }),
            v in arb_vec(&TOY, 3),
        ) {
            let ring = TOY.ring();
            prop_assert_eq!(a.mul(&b, ring).unwrap(), naive_mul(&a, &b));
            let column = PolyMatrix::new(Shape { rows: 3, cols: 1 }, v.as_slice().to_vec()).unwrap();
            let expected: Vec<Poly> = naive_mul(&a, &column).entries;
            prop_assert_eq!(a.mul_vec(&v, ring).unwrap(), PolyVec::from(expected));
            let cached = NttMatrix::new(&a, ring).unwrap();
            prop_assert_eq!(cached.mul_vec(&v, ring).unwrap(), a.mul_vec(&v, ring).unwrap());
            prop_assert_eq!(cached.mul_matrix(&b, ring).unwrap(), a.mul(&b, ring).unwrap());
        }

        #[test]
        fn hconcat_places_blocks(
            a in arb_matrix(&TOY, TWO_BY_THREE),
            b in arb_matrix(&TOY, Shape { rows: 2, cols: 1 }),
            v in arb_vec(&TOY, 3),
            w in arb_vec(&TOY, 1),
        ) {
            let ring = TOY.ring();
            let joined = a.hconcat(&b).unwrap();
            prop_assert_eq!(joined.shape(), Shape { rows: 2, cols: 4 });
            prop_assert_eq!(joined.get(1, 3).unwrap(), b.get(1, 0).unwrap());
            prop_assert_eq!(joined.get(1, 2).unwrap(), a.get(1, 2).unwrap());
            // [A | B]·[v; w] = A·v + B·w.
            let left = joined.mul_vec(&v.concat(&w), ring).unwrap();
            let right = a.mul_vec(&v, ring).unwrap().add(&b.mul_vec(&w, ring).unwrap(), ring).unwrap();
            prop_assert_eq!(left, right);
        }
    }
}
