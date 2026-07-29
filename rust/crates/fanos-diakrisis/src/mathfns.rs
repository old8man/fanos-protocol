//! A minimal float-math shim so DIAKRISIS builds on both `std` and `no_std` targets.
//!
//! `f64::abs`/`signum` live in `core`, but `sqrt` needs a math backend: on `std` we use the
//! hardware intrinsic, on `no_std` the `libm` software implementation. Everything else in
//! the crate calls [`sqrt`] rather than the inherent method so the two builds share code.

/// Square root, dispatched to the hardware intrinsic (`std`) or `libm` (`no_std`).
#[inline]
#[must_use]
pub(crate) fn sqrt(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.sqrt()
    }
    #[cfg(all(not(feature = "std"), feature = "libm"))]
    {
        libm::sqrt(x)
    }
    #[cfg(all(not(feature = "std"), not(feature = "libm")))]
    {
        compile_error!("fanos-diakrisis on no_std requires the `libm` feature for sqrt")
    }
}

/// Base-2 logarithm, dispatched like [`sqrt`].
///
/// Needed by the admission control law, whose whole derivation is in bits: proof-of-work at `b` bits admits
/// attempts at rate `2^-b`, so the inverse of that relation is a `log2`.
#[inline]
#[must_use]
pub(crate) fn log2(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.log2()
    }
    #[cfg(all(not(feature = "std"), feature = "libm"))]
    {
        libm::log2(x)
    }
    #[cfg(all(not(feature = "std"), not(feature = "libm")))]
    {
        compile_error!("fanos-diakrisis on no_std requires the `libm` feature for log2")
    }
}

/// Natural logarithm, dispatched like [`sqrt`].
///
/// Needed by the epoch-cadence bound, whose derivation is a geometric sum: solving "the residual disturbance
/// must fit in the headroom" for the period gives a `ln`.
#[inline]
#[must_use]
pub(crate) fn ln(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.ln()
    }
    #[cfg(all(not(feature = "std"), feature = "libm"))]
    {
        libm::log(x)
    }
    #[cfg(all(not(feature = "std"), not(feature = "libm")))]
    {
        compile_error!("fanos-diakrisis on no_std requires the `libm` feature for ln")
    }
}

/// `base^exp` for a non-negative integer exponent, by square-and-multiply. Pure
/// multiplication, so it needs no math backend (works identically on `std` and `no_std`).
#[inline]
#[must_use]
pub(crate) fn powi(mut base: f64, mut exp: u32) -> f64 {
    let mut acc = 1.0;
    while exp > 0 {
        if exp & 1 == 1 {
            acc *= base;
        }
        base *= base;
        exp >>= 1;
    }
    acc
}
