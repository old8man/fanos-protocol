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

/// Round toward `+∞`, dispatched like [`sqrt`].
///
/// Needed wherever a real-valued bound becomes a whole number of *things* — rounds, epochs, hops — and the
/// direction is the safety argument: a bound that says "at least `x`" must become `⌈x⌉`, since `⌊x⌋` would
/// silently under-provision the very margin the derivation computed.
#[inline]
#[must_use]
pub(crate) fn ceil(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.ceil()
    }
    #[cfg(all(not(feature = "std"), feature = "libm"))]
    {
        libm::ceil(x)
    }
    #[cfg(all(not(feature = "std"), not(feature = "libm")))]
    {
        compile_error!("fanos-diakrisis on no_std requires the `libm` feature for ceil")
    }
}

/// Round to the nearest integer (halfway away from zero), dispatched like [`sqrt`].
#[inline]
#[must_use]
pub(crate) fn round(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.round()
    }
    #[cfg(all(not(feature = "std"), feature = "libm"))]
    {
        libm::round(x)
    }
    #[cfg(all(not(feature = "std"), not(feature = "libm")))]
    {
        compile_error!("fanos-diakrisis on no_std requires the `libm` feature for round")
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

/// The real `n`-th root `x^(1/n)` for `x ≥ 0` and `n ≥ 1`, as `exp(ln(x)/n)`.
///
/// The inverse of [`powi`], and needed for the same reason: a requirement stated over `n` *consecutive*
/// observations — a dwell — is a product of `n` per-observation probabilities, so solving it for the
/// per-observation figure is an `n`-th root. Dispatched like [`sqrt`]; `exp` is the one primitive the shim
/// still lacked and this is its only caller.
#[inline]
#[must_use]
pub(crate) fn nth_root(x: f64, n: u32) -> f64 {
    if n == 0 || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return 0.0;
    }
    let y = ln(x) / f64::from(n);
    #[cfg(feature = "std")]
    {
        y.exp()
    }
    #[cfg(all(not(feature = "std"), feature = "libm"))]
    {
        libm::exp(y)
    }
    #[cfg(all(not(feature = "std"), not(feature = "libm")))]
    {
        compile_error!("fanos-diakrisis on no_std requires the `libm` feature for exp")
    }
}
