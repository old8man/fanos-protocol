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

use fanos_diaulos::{StaticKeypair, bundle_from_kem_public};
use fanos_field::F2;
use fanos_node::{
    Epoch, Node, NodeConfig, NodeResolver, ServiceResolver, dial_service, publish_service, serve,
};
use fanos_onoma::Address;
use fanos_pqcrypto::rng::SeedRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::{Handle, Runtime};
use tokio::sync::mpsc;

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

/// An owning handle to a DIAULOS byte stream to a hidden service. Holds a runtime [`Handle`] so the blocking
/// read/write can drive the async stream. Opaque to C.
///
/// **Lifetime**: a stream borrows its node's runtime, so every `fanos_stream*` must be freed *before* the
/// [`fanos_free`] that closes its node.
pub struct FanosStream {
    handle: Handle,
    stream: DuplexStream,
}

/// Connect to a CALYPSO hidden service by its `.fanos` `addr` (spec §11.2 `fanos_service_connect`): resolve
/// the name to the service's `(coordinate, key)` through the overlay, then open a DIAULOS byte stream to it.
/// Returns an owning [`FanosStream`] handle, or null if the argument is bad, the name does not resolve, or
/// the dial fails. Free it with [`fanos_stream_free`] (before freeing the node).
///
/// # Safety
/// `node` must be a live [`fanos_open`] handle; `addr` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_service_connect(
    node: *mut FanosNode,
    addr: *const c_char,
) -> *mut FanosStream {
    // SAFETY: guarded by the null checks; the caller guarantees a valid `addr` string.
    let Some(handle) = (unsafe { node.as_ref() }) else {
        return ptr::null_mut();
    };
    if addr.is_null() {
        return ptr::null_mut();
    }
    let Ok(name) = unsafe { CStr::from_ptr(addr) }.to_str() else {
        return ptr::null_mut();
    };
    // Resolve the `.fanos` name to the service coordinate + KEM key (min_pow 0 — the caller's descriptor
    // policy is a higher-level concern), then dial a DIAULOS session with fresh per-dial ephemeral keys.
    let resolver = NodeResolver::new(handle.node.client(), Epoch::ZERO, 0);
    let Some((coord, public)) = handle.rt.block_on(resolver.resolve(name)) else {
        return ptr::null_mut();
    };
    let mut seed = [0u8; 32];
    if getrandom::fill(&mut seed).is_err() {
        return ptr::null_mut();
    }
    let mut rng = SeedRng::from_seed(&seed);
    // `dial_service` spawns the session's transport bridge, so it must run inside the runtime context.
    let stream = {
        let _guard = handle.rt.enter();
        dial_service(handle.node.client(), coord, &public, &mut rng)
    };
    Box::into_raw(Box::new(FanosStream {
        handle: handle.rt.handle().clone(),
        stream,
    }))
}

/// An owning handle to a hosted hidden service: the accept channel its incoming client streams arrive on,
/// plus a runtime [`Handle`] to block on. Opaque to C. Its `.fanos` address is returned by
/// [`fanos_service_host`]. Free with [`fanos_service_free`] (before its node).
pub struct FanosService {
    handle: Handle,
    incoming: mpsc::Receiver<DuplexStream>,
}

/// Capacity of a hosted service's accept queue — incoming client streams buffer here until
/// [`fanos_service_accept`] drains them.
const ACCEPT_QUEUE: usize = 64;

/// Host a CALYPSO hidden service on `node` (spec §11.2 `fanos_service_host`). The service identity is
/// derived deterministically from `seed` (so its `.fanos` name is stable across restarts); the name is
/// written NUL-terminated into `addr_out` (capacity `addr_out_cap` — at least ~70 bytes). The service's
/// descriptor is published to the overlay so clients can [`fanos_service_connect`] to it by name. Returns an
/// owning [`FanosService`] handle whose incoming streams are taken with [`fanos_service_accept`], or null on
/// failure (null argument, `addr_out` too small, or the descriptor publish failed).
///
/// # Safety
/// `node` must be a live [`fanos_open`] handle; `seed` must point to `seed_len` readable bytes; `addr_out`
/// must point to `addr_out_cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_service_host(
    node: *mut FanosNode,
    seed: *const u8,
    seed_len: usize,
    addr_out: *mut c_char,
    addr_out_cap: usize,
) -> *mut FanosService {
    // SAFETY: guarded by the null checks; the caller guarantees the buffer lengths.
    let Some(handle) = (unsafe { node.as_ref() }) else {
        return ptr::null_mut();
    };
    let Some(seed_bytes) = (unsafe { as_slice(seed, seed_len) }) else {
        return ptr::null_mut();
    };
    if addr_out.is_null() {
        return ptr::null_mut();
    }
    // The deterministic service identity and its self-certifying `.fanos` name.
    let keypair = StaticKeypair::generate(&mut SeedRng::from_seed(seed_bytes));
    let bundle = bundle_from_kem_public(keypair.public());
    let name = Address::from_bundle(&bundle).to_name();
    let name_bytes = name.as_bytes();
    // Write the name plus a NUL terminator into the caller's buffer, or fail if it doesn't fit.
    if name_bytes.len() + 1 > addr_out_cap {
        return ptr::null_mut();
    }
    // SAFETY: `addr_out` has `addr_out_cap > name_bytes.len()` writable bytes; the source is a distinct str.
    unsafe {
        ptr::copy_nonoverlapping(name_bytes.as_ptr(), addr_out.cast::<u8>(), name_bytes.len());
        *addr_out.add(name_bytes.len()) = 0;
    }

    // Host the service: each accepted client session is forwarded onto the accept queue (its own fresh OS
    // entropy seeds every session's ephemeral keys), and the descriptor is published for name resolution.
    let (tx, rx) = mpsc::channel::<DuplexStream>(ACCEPT_QUEUE);
    let mut serve_seed = [0u8; 32];
    if getrandom::fill(&mut serve_seed).is_err() {
        return ptr::null_mut();
    }
    {
        let _guard = handle.rt.enter();
        serve(
            handle.node.client(),
            keypair,
            SeedRng::from_seed(&serve_seed),
            move |stream| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(stream).await;
                }
            },
        );
    }
    let published = handle.rt.block_on(publish_service(
        &handle.node.client(),
        &bundle,
        handle.node.address(),
        Epoch::ZERO,
        0,
        &[],
    ));
    if published.is_err() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(FanosService {
        handle: handle.rt.handle().clone(),
        incoming: rx,
    }))
}

/// Accept the next incoming client stream on a hosted `service`, blocking until one arrives. Returns an
/// owning [`FanosStream`] handle, or null if the service has stopped (its node freed) or on a null argument.
///
/// # Safety
/// `service` must be a live [`fanos_service_host`] handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_service_accept(service: *mut FanosService) -> *mut FanosStream {
    // SAFETY: the caller guarantees `service` is null or a live handle.
    let Some(service) = (unsafe { service.as_mut() }) else {
        return ptr::null_mut();
    };
    match service.handle.block_on(service.incoming.recv()) {
        Some(stream) => Box::into_raw(Box::new(FanosStream {
            handle: service.handle.clone(),
            stream,
        })),
        None => ptr::null_mut(),
    }
}

/// Stop hosting and free a service handle (safe on null). Must be called before the owning node is freed.
///
/// # Safety
/// `service` must be null or a handle from [`fanos_service_host`] that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_service_free(service: *mut FanosService) {
    if service.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `service` is a live, not-yet-freed handle.
    drop(unsafe { Box::from_raw(service) });
}

/// Read up to `len` bytes from `stream` into `buf`, blocking until some data arrives. Returns the number of
/// bytes read (`>= 0`; `0` means the stream closed / EOF), [`FANOS_ERR_IO`] on a transport error, or
/// [`FANOS_ERR_NULL`] on a null argument.
///
/// # Safety
/// `stream` must be a live [`fanos_service_connect`] handle; `buf` must point to `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_stream_read(
    stream: *mut FanosStream,
    buf: *mut u8,
    len: usize,
) -> c_int {
    // SAFETY: guarded by the null check; the caller guarantees `buf` has `len` writable bytes.
    let Some(stream) = (unsafe { stream.as_mut() }) else {
        return FANOS_ERR_NULL;
    };
    if len == 0 {
        return 0;
    }
    if buf.is_null() {
        return FANOS_ERR_NULL;
    }
    let cap = len.min(i32::MAX as usize);
    // SAFETY: `buf` is non-null with `cap <= len` writable bytes.
    let dst = unsafe { slice::from_raw_parts_mut(buf, cap) };
    match stream.handle.block_on(stream.stream.read(dst)) {
        Ok(n) => n as c_int, // n <= cap <= i32::MAX
        Err(_) => FANOS_ERR_IO,
    }
}

/// Write all `len` bytes of `buf` to `stream`, blocking until sent (and flushed). Returns `len` on success,
/// [`FANOS_ERR_IO`] on a transport error, or [`FANOS_ERR_NULL`] on a null argument. `len` must not exceed
/// `INT_MAX`.
///
/// # Safety
/// `stream` must be a live [`fanos_service_connect`] handle; `buf` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_stream_write(
    stream: *mut FanosStream,
    buf: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: guarded by the null checks; the caller guarantees `buf` has `len` readable bytes.
    let Some(stream) = (unsafe { stream.as_mut() }) else {
        return FANOS_ERR_NULL;
    };
    let Some(src) = (unsafe { as_slice(buf, len) }) else {
        return FANOS_ERR_NULL;
    };
    let result = stream.handle.block_on(async {
        stream.stream.write_all(src).await?;
        stream.stream.flush().await
    });
    match result {
        Ok(()) => len.min(i32::MAX as usize) as c_int,
        Err(_) => FANOS_ERR_IO,
    }
}

/// Close and free a stream handle (safe on null). Must be called before the owning node is freed.
///
/// # Safety
/// `stream` must be null or a handle from [`fanos_service_connect`] that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fanos_stream_free(stream: *mut FanosStream) {
    if stream.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `stream` is a live, not-yet-freed handle. Dropping it closes the stream.
    drop(unsafe { Box::from_raw(stream) });
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
    use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

    // Each test that opens a node stands up a real QUIC endpoint; running several at once overloads the
    // loopback transport and stalls handshakes. Serialize them behind one lock (as the node crate's
    // real-QUIC suites do).
    static SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

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
        let _serial = serial();
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
        let _serial = serial();
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
        let _serial = serial();
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

    // Heavy 2-node real-QUIC E2E: needs cross-node ONOMA descriptor resolution, which is unreliable when the
    // full-workspace run saturates the loopback transport with other crates' QUIC tests. Reliable in
    // isolation — run with `cargo test -p fanos-ffi -- --ignored`. The FFI marshalling/lifecycle is covered
    // by the always-on unit tests; the underlying dial/host over QUIC by fanos-node's real-QUIC suites.
    #[test]
    #[ignore = "heavy 2-node real-QUIC E2E; run in isolation (see comment)"]
    fn connect_to_a_hosted_service_and_echo_over_the_c_abi() {
        use std::thread::sleep;
        use std::time::Duration;

        use fanos_diaulos::{StaticKeypair, bundle_from_kem_public};
        use fanos_node::{publish_service, serve};
        use fanos_onoma::Address;

        let _serial = serial();
        // Node A hosts the echo service; node B (bootstrapped to A) dials it by name — a hidden-service dial
        // is between two nodes (a node does not self-deliver to its own coordinate).
        let a = open_loopback();
        // SAFETY: `a` is a live handle the test owns.
        let a_handle = unsafe { &*a };
        // SAFETY: `a` is live.
        let a_health = unsafe { fanos_diagnose(a) };
        let [x, y, z] = a_health.coord;
        let a_port = a_health.port;

        let keypair = StaticKeypair::generate(&mut SeedRng::from_seed(b"ffi-svc-key"));
        let bundle = bundle_from_kem_public(keypair.public());
        let name = Address::from_bundle(&bundle).to_name();
        let a_coord = a_handle.node.address();
        {
            let _guard = a_handle.rt.enter();
            serve(
                a_handle.node.client(),
                keypair,
                SeedRng::from_seed(b"ffi-svc-rng"),
                |mut stream: DuplexStream| async move {
                    let mut buf = vec![0u8; 4096];
                    if let Ok(n) = stream.read(&mut buf).await
                        && n > 0
                    {
                        let _ = stream.write_all(&buf[..n]).await;
                        let _ = stream.flush().await;
                    }
                },
            );
        }
        a_handle
            .rt
            .block_on(publish_service(&a_handle.node.client(), &bundle, a_coord, Epoch::ZERO, 0, &[]))
            .expect("publish the service descriptor");

        // Node B, bootstrapped to A.
        let b_cfg = CString::new(format!(
            "listen = 127.0.0.1:0\nbootstrap = {x}:{y}:{z}@127.0.0.1:{a_port}"
        ))
        .unwrap();
        // SAFETY: `b_cfg` is a valid string alive across the call.
        let b = unsafe { fanos_open(b_cfg.as_ptr()) };
        assert!(!b.is_null(), "node B opened and bootstrapped");

        // Resolve+dial by name through the C ABI, retrying while the overlay connects and the descriptor
        // propagates (a real-QUIC store put/handshake takes a moment). Bounded, so a failure never hangs.
        let cname = CString::new(name).unwrap();
        let mut stream = ptr::null_mut();
        for _ in 0..60 {
            // SAFETY: `b` is live; `cname` outlives the call.
            stream = unsafe { fanos_service_connect(b, cname.as_ptr()) };
            if !stream.is_null() {
                break;
            }
            sleep(Duration::from_millis(500));
        }
        assert!(!stream.is_null(), "B resolved and dialed A's service through the C ABI");

        let msg = b"hello over the c abi";
        // SAFETY: `stream` is live; the buffers are valid for each call.
        unsafe {
            assert_eq!(
                fanos_stream_write(stream, msg.as_ptr(), msg.len()),
                msg.len() as c_int,
                "wrote the whole message"
            );
            let mut out = [0u8; 64];
            let n = fanos_stream_read(stream, out.as_mut_ptr(), out.len());
            assert!(n > 0, "the echo came back");
            assert_eq!(&out[..n as usize], msg, "the payload round-trips through the C-ABI stream");
            fanos_stream_free(stream);
            fanos_free(b);
            fanos_free(a);
        }
    }

    #[test]
    fn stream_functions_reject_null() {
        let mut buf = [0u8; 4];
        // SAFETY: all handles null; the functions must return error codes, never deref.
        unsafe {
            assert_eq!(fanos_stream_read(ptr::null_mut(), buf.as_mut_ptr(), buf.len()), FANOS_ERR_NULL);
            assert_eq!(fanos_stream_write(ptr::null_mut(), buf.as_ptr(), buf.len()), FANOS_ERR_NULL);
            fanos_stream_free(ptr::null_mut()); // no-op
            let addr = CString::new("x.fanos").unwrap();
            assert!(fanos_service_connect(ptr::null_mut(), addr.as_ptr()).is_null());
            // Host/accept/free also reject null, never deref.
            let mut out = [0u8; 16];
            assert!(
                fanos_service_host(ptr::null_mut(), ptr::null(), 0, out.as_mut_ptr().cast::<c_char>(), out.len())
                    .is_null()
            );
            assert!(fanos_service_accept(ptr::null_mut()).is_null());
            fanos_service_free(ptr::null_mut()); // no-op
        }
    }

    // Heavy 2-node real-QUIC E2E — see the note on `connect_to_a_hosted_service…`. Run with
    // `cargo test -p fanos-ffi -- --ignored`.
    #[test]
    #[ignore = "heavy 2-node real-QUIC E2E; run in isolation (see comment)"]
    fn host_a_service_and_serve_a_client_over_the_c_abi() {
        use std::thread::sleep;
        use std::time::Duration;

        let _serial = serial();

        // Node A hosts a service entirely through the C ABI.
        let a = open_loopback();
        // SAFETY: `a` is live.
        let a_health = unsafe { fanos_diagnose(a) };
        let [x, y, z] = a_health.coord;
        let a_port = a_health.port;

        let seed = b"ffi-host-seed-0123456789abcdef01"; // a stable service identity
        let mut addr = [0u8; 128];
        // SAFETY: `a` is live; `seed`/`addr` are valid for the call.
        let service = unsafe {
            fanos_service_host(a, seed.as_ptr(), seed.len(), addr.as_mut_ptr().cast::<c_char>(), addr.len())
        };
        assert!(!service.is_null(), "the service is hosted and its descriptor published");
        // SAFETY: `fanos_service_host` wrote a NUL-terminated name into `addr`.
        let name = unsafe { CStr::from_ptr(addr.as_ptr().cast::<c_char>()) }
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(name.rsplit_once('.').map(|(_, tld)| tld), Some("fanos"), "a .fanos name: {name}");

        // Node B, bootstrapped to A, dials the hosted service by name.
        let b_cfg = CString::new(format!(
            "listen = 127.0.0.1:0\nbootstrap = {x}:{y}:{z}@127.0.0.1:{a_port}"
        ))
        .unwrap();
        // SAFETY: `b_cfg` outlives the call.
        let b = unsafe { fanos_open(b_cfg.as_ptr()) };
        assert!(!b.is_null());

        let cname = CString::new(name).unwrap();
        let mut client = ptr::null_mut();
        for _ in 0..60 {
            // SAFETY: `b` is live; `cname` outlives the call.
            client = unsafe { fanos_service_connect(b, cname.as_ptr()) };
            if !client.is_null() {
                break;
            }
            sleep(Duration::from_millis(500));
        }
        assert!(!client.is_null(), "B dialed the hosted service");

        let msg = b"c-abi service host echo";
        // SAFETY: all handles are live; the buffers are valid for each call.
        unsafe {
            // B writes; A accepts the incoming stream and echoes it; B reads it back.
            assert_eq!(fanos_stream_write(client, msg.as_ptr(), msg.len()), msg.len() as c_int);
            let incoming = fanos_service_accept(service);
            assert!(!incoming.is_null(), "A accepted the client's stream");
            let mut buf = [0u8; 64];
            let n = fanos_stream_read(incoming, buf.as_mut_ptr(), buf.len());
            assert!(n > 0, "the host received the client's bytes");
            assert_eq!(&buf[..n as usize], msg);
            assert_eq!(
                fanos_stream_write(incoming, buf.as_ptr(), n as usize),
                n,
                "the host echoes the bytes back"
            );
            let mut out = [0u8; 64];
            let m = fanos_stream_read(client, out.as_mut_ptr(), out.len());
            assert!(m > 0, "the echo came back to the client");
            assert_eq!(&out[..m as usize], msg, "the payload round-trips client → host → client");

            fanos_stream_free(incoming);
            fanos_stream_free(client);
            fanos_service_free(service);
            fanos_free(b);
            fanos_free(a);
        }
    }
}
