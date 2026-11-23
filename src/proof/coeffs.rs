// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integer views of short vectors and the ring-by-vector products the proof repeats.

pub(crate) use crate::matrix::transform;
use crate::{
    error::{Error, Result, check_dimension},
    matrix::{NttMatrix, PolyMatrix, Shape},
    poly::Poly,
    ring::{NttPoly, Ring},
    vector::PolyVec,
    zq::Coeff,
};
use crypto_bigint::U64;
use zeroize::Zeroizing;

/// The centred lift of every coefficient of `v`, entries in order. Fails with
/// [`Error::ProofRejected`] when a coefficient does not fit an `i64`, which no honest short
/// vector of this crate's parameter sets does.
///
/// The vectors lifted are the prover's secrets, so the result is overwritten when dropped,
/// and it is allocated at its full length up front so that growing it leaves no copy behind.
pub(crate) fn centred(v: &PolyVec, ring: &Ring) -> Result<Zeroizing<Vec<i64>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(v.len() * ring.degree()));
    for c in v.as_slice().iter().flat_map(Poly::coefficients) {
        out.push(centred_coefficient(c, ring)?);
    }
    Ok(out)
}

/// The centred lift of one reduced coefficient as an `i64`.
pub(crate) fn centred_coefficient(c: &Coeff, ring: &Ring) -> Result<i64> {
    let centred = ring.center(c);
    if centred.magnitude().bit_width_vartime() >= i64::BITS {
        return Err(Error::ProofRejected);
    }
    let magnitude = u64::from(centred.magnitude().resize::<{ U64::LIMBS }>()).cast_signed();
    Ok(if centred.is_negative() {
        -magnitude
    } else {
        magnitude
    })
}

/// The vector whose coefficients, entries in order and `d` per entry, are `values` reduced
/// modulo `q`.
pub(crate) fn from_integers(values: &[i64], ring: &Ring) -> Result<PolyVec> {
    let d = ring.degree();
    if !values.len().is_multiple_of(d) {
        return Err(Error::DimensionMismatch {
            expected: values.len().next_multiple_of(d),
            found: values.len(),
        });
    }
    Ok(values
        .chunks_exact(d)
        .map(|chunk| Poly::from_signed(chunk, ring))
        .collect())
}

/// `Σ_k a_k·b_k` over two sequences of transformed polynomials of equal length.
pub(crate) fn inner(a: &[NttPoly], b: &[NttPoly], ring: &Ring) -> Result<Poly> {
    check_dimension(a.len(), b.len())?;
    Ok(ring.sum_of_products(a.iter().zip(b)))
}

/// `c · v`, the ring element `c` times every entry of `v`, transforming `c` once.
pub(crate) fn mul_each(c: &Poly, v: &PolyVec, ring: &Ring) -> Result<PolyVec> {
    mul_each_transformed(c, &transform(v.as_slice(), ring)?, ring)
}

/// `wᵀ·M` for `M ∈ R_q^{rows×cols}` and `w ∈ R_q^{rows}`, one entry per column: the
/// coefficients of the linear form `s ↦ ⟨w, M·s⟩`.
pub(crate) fn transposed_product(m: &NttMatrix, w: &[Poly], ring: &Ring) -> Result<Vec<Poly>> {
    let cols = m.shape().cols;
    let row = PolyMatrix::new(
        Shape {
            rows: 1,
            cols: w.len(),
        },
        w.to_vec(),
    )?;
    let product = m.left_mul(&row, ring)?;
    (0..cols)
        .map(|col| {
            product
                .get(0, col)
                .cloned()
                .ok_or(Error::DimensionMismatch {
                    expected: cols,
                    found: col,
                })
        })
        .collect()
}

/// `c · v` for `v` already transformed.
pub(crate) fn mul_each_transformed(c: &Poly, v: &[NttPoly], ring: &Ring) -> Result<PolyVec> {
    let c = ring.ntt(c)?;
    Ok(v.iter().map(|p| ring.sum_of_products([(&c, p)])).collect())
}

#[cfg(test)]
mod tests {
    use super::{centred, from_integers, inner, mul_each, transform};
    use crate::{poly::Poly, test_util::TOY, zq::Coeff};

    #[test]
    fn integer_views_round_trip() {
        let ring = TOY.ring();
        let values: Vec<i64> = (0..128).map(|i| i * 7 - 300).collect();
        let v = from_integers(&values, ring).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(*centred(&v, ring).unwrap(), values);
        assert!(from_integers(&values[..100], ring).is_err());
    }

    #[test]
    fn products_match_the_ring_operations() {
        let ring = TOY.ring();
        let values: Vec<i64> = (0..192).map(|i| (i * 31) % 17 - 8).collect();
        let v = from_integers(&values, ring).unwrap();
        let c = v.as_slice()[0].clone();
        let each = mul_each(&c, &v, ring).unwrap();
        for (p, q) in v.as_slice().iter().zip(each.as_slice()) {
            assert_eq!(c.mul(p, ring).unwrap(), *q);
        }
        let expected = v.as_slice().iter().fold(Poly::zero(ring), |acc, p| {
            acc.add(&p.mul(p, ring).unwrap(), ring).unwrap()
        });
        let t = transform(v.as_slice(), ring).unwrap();
        assert_eq!(inner(&t, &t, ring).unwrap(), expected);
        assert!(inner(&t, &t[1..], ring).is_err());
        assert_eq!(
            Poly::scale(&c, &Coeff::from_u64(3), ring),
            c.mul_small(3, ring).unwrap()
        );
    }
}
