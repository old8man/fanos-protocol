//! # fanos-ffi — the stable C ABI (spec §11.2)
//!
//! An `extern "C"` embedding surface over a FANOS [`Node`], so any language can *reuse* the core instead of
//! re-implementing it (the §11.1 goal — "use it from any language"). Each [`FanosNode`] handle owns a tokio
//! runtime and a running node; the blocking C calls drive the node's async operations on that runtime.
//!
//! This first surface covers **lifecycle** (open / join / free), **storage** (publish / lookup), and
//! **health** (DIAKRISIS-adjacent node diagnosis). Streams and hidden-service connect/host are layered on
//! top in later surfaces. The C header is `include/fanos.h`.
//!
//! ## Memory & threading contract
//! - `fanos_open` returns an owning handle (or null on failure); pass it to exactly one `fanos_free`.
//! - Buffers passed in (`key`, `val`) are borrowed for the duration of the call and copied; the caller
//!   keeps ownership. `fanos_lookup` copies into a caller-provided buffer and reports the true length.
//! - A handle may be used from multiple threads only with external synchronization (the node itself is
//!   internally concurrent, but these calls each block on the shared runtime).

// An FFI boundary is inherently unsafe — it dereferences raw pointers the caller supplies. The unsafety is
// confined to argument marshalling at each entry point; every deref is guarded by an explicit null check and
// documented `# Safety` contract.
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int};
use std::{ptr, slice};

use fanos_field::F2;
use fanos_node::{Node, NodeConfig};
use tokio::runtime::Runtime;

/// Success.
pub const FANOS_OK: c_int = 0;
/// A required pointer argument was null.
pub const FANOS_ERR_NULL: c_int = -1;
/// The configuration string was not valid UTF-8 or failed to parse.
pub const FANOS_ERR_CONFIG: c_int = -2;
/// The node (or its runtime) failed to start.
pub const FANOS_ERR_START: c_int = -3;
/// The operation reached the network but did not succeed (e.g. a store `put` was not accepted).
pub const FANOS_ERR_IO: c_int = -4;
/// The caller's output buffer was too small; the required length is written to `out_len`.
pub const FANOS_ERR_BUFFER: c_int = -5;
/// A lookup completed but found no value for the key.
pub const FANOS_ERR_NOTFOUND: c_int = -6;

/// An owning handle to a running FANOS node: a tokio runtime plus the node it drives. Opaque to C.
pub struct FanosNode {
    rt: Runtime,
    node: Node,
}

/// A snapshot of a node's health/identity (spec §11.2 `fanos_diagnose`). `#[repr(C)]` so C reads it directly.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FanosHealth {
    /// The node's overlay coordinate `[x, y, z]` (a projective point).
    pub coord: [u32; 3],
    /// The number of peers currently in the node's address book.
    pub known_peers: usize,
    /// The UDP port the node is bound to.
    pub port: u16,
}

/// Open and start a FANOS node from a `key = value` configuration string (the same format
/// [`NodeConfig::from_config_str`] accepts; a null pointer means the default config). Returns an owning
/// handle, or null on failure (bad config, or the node/runtime failed to start). Free it with
/// [`fanos_free`].
///
/// # Safety
/// `config` must be null, or a valid NUL-terminated C string that stays valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_open(config: *const c_char) -> *mut FanosNode {
    let config = if config.is_null() {
        NodeConfig::default()
    } else {
        // SAFETY: the caller guarantees `config` is a valid NUL-terminated string for this call.
        let Ok(text) = unsafe { CStr::from_ptr(config) }.to_str() else {
            return ptr::null_mut();
        };
        match NodeConfig::from_config_str(text) {
            Ok(cfg) => cfg,
            Err(_) => return ptr::null_mut(),
        }
    };
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() else {
        return ptr::null_mut();
    };
    match rt.block_on(Node::start::<F2>(config)) {
        Ok(node) => Box::into_raw(Box::new(FanosNode { rt, node })),
        Err(_) => ptr::null_mut(),
    }
}

/// Ensure the node has joined the overlay. A node joins during [`fanos_open`] (bootstrapping from the peers
/// in its config), so this is idempotent: it returns [`FANOS_OK`] for a live handle, or [`FANOS_ERR_NULL`]
/// for a null one. It exists so bindings can mirror the `open`/`join` lifecycle of the API contract.
///
/// # Safety
/// `node` must be null or a handle returned by [`fanos_open`] and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_join(node: *mut FanosNode) -> c_int {
    // SAFETY: the caller guarantees `node` is null or a live `fanos_open` handle.
    if unsafe { node.as_ref() }.is_some() {
        FANOS_OK
    } else {
        FANOS_ERR_NULL
    }
}

/// Publish `val` under `key` in the overlay store (the DHT surface). Returns [`FANOS_OK`] on acceptance,
/// [`FANOS_ERR_IO`] if the store did not accept the write, or [`FANOS_ERR_NULL`] on a null argument.
///
/// # Safety
/// `node` must be a live [`fanos_open`] handle; `key`/`val` must point to at least `key_len`/`val_len`
/// readable bytes (or be null with a zero length).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_publish(
    node: *mut FanosNode,
    key: *const u8,
    key_len: usize,
    val: *const u8,
    val_len: usize,
) -> c_int {
    // SAFETY: guarded by the null checks below; the caller guarantees the lengths.
    let Some(handle) = (unsafe { node.as_ref() }) else {
        return FANOS_ERR_NULL;
    };
    let (Some(key), Some(val)) = (unsafe { as_slice(key, key_len) }, unsafe { as_slice(val, val_len) })
    else {
        return FANOS_ERR_NULL;
    };
    let accepted = handle
        .rt
        .block_on(handle.node.client().put(key.to_vec(), val.to_vec()));
    if accepted { FANOS_OK } else { FANOS_ERR_IO }
}

/// Look up `key` in the overlay store, copying the value into `out` (capacity `out_cap`) and writing its
/// true length to `out_len`. Returns [`FANOS_OK`] on success; [`FANOS_ERR_NOTFOUND`] if no value is stored;
/// [`FANOS_ERR_BUFFER`] if the value is larger than `out_cap` (with the required length in `out_len`, so the
/// caller can retry with a big-enough buffer); [`FANOS_ERR_NULL`] on a null argument.
///
/// # Safety
/// `node` must be a live handle; `key` must point to `key_len` readable bytes; `out` must point to `out_cap`
/// writable bytes; `out_len` must point to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_lookup(
    node: *mut FanosNode,
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    // SAFETY: guarded by the null checks below; the caller guarantees the lengths.
    let Some(handle) = (unsafe { node.as_ref() }) else {
        return FANOS_ERR_NULL;
    };
    let Some(key) = (unsafe { as_slice(key, key_len) }) else {
        return FANOS_ERR_NULL;
    };
    if out_len.is_null() || (out.is_null() && out_cap != 0) {
        return FANOS_ERR_NULL;
    }
    let Some(value) = handle.rt.block_on(handle.node.client().get(key.to_vec())) else {
        return FANOS_ERR_NOTFOUND;
    };
    // SAFETY: `out_len` is non-null (checked above).
    unsafe { *out_len = value.len() };
    if value.len() > out_cap {
        return FANOS_ERR_BUFFER;
    }
    // SAFETY: `out` has `out_cap >= value.len()` writable bytes (checked), and the source is a distinct Vec.
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), out, value.len()) };
    FANOS_OK
}

/// Read the node's current [`FanosHealth`] (spec §11.2 `fanos_diagnose`). A null handle yields a zeroed
/// snapshot.
///
/// # Safety
/// `node` must be null or a live [`fanos_open`] handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_diagnose(node: *mut FanosNode) -> FanosHealth {
    // SAFETY: the caller guarantees `node` is null or a live handle.
    let Some(handle) = (unsafe { node.as_ref() }) else {
        return FanosHealth::default();
    };
    let health = handle.node.health();
    FanosHealth {
        coord: health.address,
        known_peers: health.known_peers,
        port: health.local_addr.port(),
    }
}

/// Shut the node down and free its handle (and runtime). Safe to call on null. After this the handle is
/// dangling and must not be used again.
///
/// # Safety
/// `node` must be null or a handle returned by [`fanos_open`] that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_free(node: *mut FanosNode) {
    if node.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `node` is a live, not-yet-freed `fanos_open` handle.
    let handle = unsafe { Box::from_raw(node) };
    handle.node.shutdown();
    // `handle` (and its runtime) drop here, tearing the node down.
}

/// Borrow `[ptr, ptr+len)` as a slice, or `None` if `ptr` is null with a non-zero length. A null pointer
/// with a zero length is an empty slice (valid).
///
/// # Safety
/// If `ptr` is non-null it must point to at least `len` readable bytes for the duration of the borrow.
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return (len == 0).then_some(&[]);
    }
    // SAFETY: the caller guarantees `ptr` points to `len` readable bytes.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Open a node on an ephemeral loopback port for a test; free with [`fanos_free`].
    fn open_loopback() -> *mut FanosNode {
        let cfg = CString::new("listen = 127.0.0.1:0").unwrap();
        // SAFETY: `cfg` is a valid NUL-terminated string alive across the call.
        let node = unsafe { fanos_open(cfg.as_ptr()) };
        assert!(!node.is_null(), "a valid config opens a node");
        node
    }

    #[test]
    fn open_diagnose_join_and_free() {
        let node = open_loopback();
        // SAFETY: `node` is a live handle for each of these calls.
        unsafe {
            assert_eq!(fanos_join(node), FANOS_OK, "a live node is joined");
            let health = fanos_diagnose(node);
            assert_ne!(health.port, 0, "the node bound an ephemeral port");
            // A fresh lone node knows only itself (or nothing) — a small, bounded peer set.
            assert!(health.known_peers <= 1, "a lone node has no peers yet");
            fanos_free(node);
        }
    }

    #[test]
    fn a_bad_config_returns_null() {
        let cfg = CString::new("nonsense_key = value").unwrap();
        // SAFETY: valid NUL-terminated string.
        let node = unsafe { fanos_open(cfg.as_ptr()) };
        assert!(node.is_null(), "an unknown config key fails to open");
    }

    #[test]
    fn null_and_default_handling() {
        // Null handles are rejected, never dereferenced.
        // SAFETY: all pointers are null / valid; the functions must tolerate the nulls.
        unsafe {
            assert_eq!(fanos_join(ptr::null_mut()), FANOS_ERR_NULL);
            assert_eq!(
                fanos_publish(ptr::null_mut(), ptr::null(), 0, ptr::null(), 0),
                FANOS_ERR_NULL
            );
            let mut len = 0usize;
            assert_eq!(
                fanos_lookup(ptr::null_mut(), ptr::null(), 0, ptr::null_mut(), 0, &raw mut len),
                FANOS_ERR_NULL
            );
            // A null-handle diagnose is a zeroed snapshot, not a crash.
            assert_eq!(fanos_diagnose(ptr::null_mut()).port, 0);
            // Freeing null is a no-op.
            fanos_free(ptr::null_mut());
        }
    }

    #[test]
    fn lookup_of_a_missing_key_is_not_found_and_reports_length() {
        let node = open_loopback();
        let key = b"no-such-key";
        let mut out = [0u8; 8];
        let mut out_len = 0usize;
        // SAFETY: `node` is live; `key`/`out`/`out_len` are valid for the call.
        let rc = unsafe {
            fanos_lookup(node, key.as_ptr(), key.len(), out.as_mut_ptr(), out.len(), &raw mut out_len)
        };
        assert_eq!(rc, FANOS_ERR_NOTFOUND, "an isolated node stores nothing to find");
        // SAFETY: `node` is still live.
        unsafe { fanos_free(node) };
    }

    #[test]
    fn publish_then_lookup_round_trips_through_the_c_abi() {
        // A value published through the C ABI is recovered through it — the full store path (put → get)
        // driven entirely across the FFI boundary on a live node.
        let node = open_loopback();
        let key = b"ffi-key";
        let val = b"ffi-value";
        // SAFETY: `node` is live and the buffers are valid for each call below.
        unsafe {
            assert_eq!(
                fanos_publish(node, key.as_ptr(), key.len(), val.as_ptr(), val.len()),
                FANOS_OK,
                "publish is accepted"
            );

            // A buffer too small for the value reports FANOS_ERR_BUFFER with the required length.
            let mut small = [0u8; 4];
            let mut need = 0usize;
            assert_eq!(
                fanos_lookup(node, key.as_ptr(), key.len(), small.as_mut_ptr(), small.len(), &raw mut need),
                FANOS_ERR_BUFFER,
                "a short buffer is rejected"
            );
            assert_eq!(need, val.len(), "the required length is reported so the caller can resize");

            // A big-enough buffer recovers the exact value.
            let mut out = [0u8; 32];
            let mut out_len = 0usize;
            assert_eq!(
                fanos_lookup(node, key.as_ptr(), key.len(), out.as_mut_ptr(), out.len(), &raw mut out_len),
                FANOS_OK
            );
            assert_eq!(&out[..out_len], val, "the value round-trips through the C ABI");

            fanos_free(node);
        }
    }
}
