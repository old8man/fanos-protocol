//! Float-math shim so the security/mixing math builds on `std` and `no_std` alike.
//!
//! `powi` is pure multiplication (no backend); `log2` needs one, so it dispatches to the
//! hardware intrinsic on `std` and `libm` on `no_std`.

/// `base^exp` for an integer exponent, by square-and-multiply (negative exponents reciprocate).
#[inline]
#[must_use]
pub(crate) fn powi(base: f64, exp: i32) -> f64 {
    if exp < 0 {
        return 1.0 / powi(base, exp.unsigned_abs() as i32);
    }
    let mut acc = 1.0;
    let mut b = base;
    let mut e = exp.unsigned_abs();
    while e > 0 {
        if e & 1 == 1 {
            acc *= b;
        }
        b *= b;
        e >>= 1;
    }
    acc
}

/// Base-2 logarithm, dispatched by target.
///
/// **Not correctly-rounded** — `std`'s hardware `f64::log2` and `no_std`'s `libm::log2` may differ by
/// an ULP. Its only caller is [`crate::mixing::anonymity_entropy_bits`], an informational metric that
/// gates no wire-visible behaviour, so the divergence is harmless. Any new caller feeding a protocol
/// decision must first quantize the result to a backend-independent form (determinism invariant).
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
        compile_error!("fanos-nyx on no_std requires the `libm` feature for log2")
    }
}
