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
    // Validate the caller's out-buffer *before* the lookup: a malformed triple is an argument error, not a
    // verdict about the key.
    if !out_buffer_is_valid(out, out_cap, out_len) {
        return FANOS_ERR_NULL;
    }
    let Some(value) = handle.rt.block_on(handle.node.client().get(key.to_vec())) else {
        return FANOS_ERR_NOTFOUND;
    };
    // SAFETY: the caller guarantees `out`/`out_len` are writable for the stated capacity, and the value is a
    // freshly-read Vec distinct from the caller's buffer.
    unsafe { write_out(&value, out, out_cap, out_len) }
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
    // The deterministic service identity and its self-certifying `.fanos` name.
    let keypair = StaticKeypair::generate(&mut SeedRng::from_seed(seed_bytes));
    let bundle = bundle_from_kem_public(keypair.public());
    let name = Address::from_bundle(&bundle).to_name();
    // Check the caller's buffer up front — before standing anything up — but write into it only once the
    // service is actually hosted, so a failed call leaves it untouched, as the null return implies.
    if !cstr_fits(&name, addr_out, addr_out_cap) {
        return ptr::null_mut();
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
    // SAFETY: `cstr_fits` held above — `addr_out` is non-null with room for the name and its terminator, and
    // the name is a local `String` distinct from the caller's buffer.
    unsafe { write_cstr(&name, addr_out) };
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
    // The read is capped at `i32::MAX` so the returned byte count always fits the C return type.
    // SAFETY: the caller guarantees `buf` has `len` writable bytes; a null buffer with a non-zero length is
    // rejected rather than borrowed.
    let Some(dst) = (unsafe { as_slice_mut(buf, len.min(i32::MAX as usize)) }) else {
        return FANOS_ERR_NULL;
    };
    if dst.is_empty() {
        return 0;
    }
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

// ---- The runtime-free half of the ABI ------------------------------------------------------------------
//
// Every raw-pointer operation in this crate that is *not* a handle dereference lives below: borrowing the
// caller's buffers, and copying results back into them. Keeping it separate from the async dispatch above is
// what makes the crate's memory-safety-critical surface *executable* under Miri — Miri cannot run the handle
// paths (they need a real reactor: `kqueue`/`epoll` are unsupported foreign calls), so a raw-pointer contract
// checked only through a live node is a contract Miri never sees. Each function pairs a safe predicate that
// *decides* with an unsafe routine that *writes*, so the decision is testable without a pointer at all.

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

/// Borrow `[ptr, ptr+len)` as a mutable slice under the same convention as [`as_slice`].
///
/// # Safety
/// If `ptr` is non-null it must point to at least `len` writable bytes, unaliased for the borrow.
unsafe fn as_slice_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if ptr.is_null() {
        return (len == 0).then_some(&mut []);
    }
    // SAFETY: the caller guarantees `ptr` points to `len` writable, unaliased bytes.
    Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

/// Whether a caller's out-buffer triple is well-formed: a writable slot for the length, and either a buffer
/// with capacity or the size-probe form (a null buffer with zero capacity). A null buffer with a non-zero
/// capacity is a lie about capacity and is rejected.
fn out_buffer_is_valid(out: *const u8, out_cap: usize, out_len: *const usize) -> bool {
    !out_len.is_null() && (!out.is_null() || out_cap == 0)
}

/// Copy `value` into a caller's out-buffer under the ABI's size-probe contract: `out_len` always receives the
/// value's *true* length (so a caller that guessed too small can resize and retry), and the bytes are copied
/// only if they fit. Returns [`FANOS_OK`], [`FANOS_ERR_BUFFER`] if the value is larger than `out_cap`, or
/// [`FANOS_ERR_NULL`] for a malformed triple.
///
/// # Safety
/// `out_len` must be null or point to a writable `usize`; if `out` is non-null it must point to `out_cap`
/// writable bytes, distinct from `value`.
unsafe fn write_out(value: &[u8], out: *mut u8, out_cap: usize, out_len: *mut usize) -> c_int {
    if !out_buffer_is_valid(out, out_cap, out_len) {
        return FANOS_ERR_NULL;
    }
    // SAFETY: `out_len` is non-null (checked) and the caller guarantees it is writable.
    unsafe { *out_len = value.len() };
    if value.len() > out_cap {
        return FANOS_ERR_BUFFER;
    }
    // Only copy a non-empty value: a size probe passes `out` null, and a null `dst` is UB for
    // `copy_nonoverlapping` even at a zero count. An empty value has nothing to write and the reported
    // length (0) already conveys it.
    if !value.is_empty() {
        // SAFETY: `out_cap >= value.len() > 0` writable bytes, so `out` is non-null here, and the caller
        // guarantees the source is a distinct allocation.
        unsafe { ptr::copy_nonoverlapping(value.as_ptr(), out, value.len()) };
    }
    FANOS_OK
}

/// Whether `text` *and* its NUL terminator fit in a caller's C-string buffer of capacity `cap`.
fn cstr_fits(text: &str, out: *const c_char, cap: usize) -> bool {
    !out.is_null() && text.len() < cap
}

/// Write `text` into a caller's buffer as a NUL-terminated C string.
///
/// # Safety
/// [`cstr_fits`] must hold for `text`, `out` and the buffer's capacity: `out` non-null with at least
/// `text.len() + 1` writable bytes, distinct from `text`.
unsafe fn write_cstr(text: &str, out: *mut c_char) {
    // SAFETY: the caller guarantees `out` is non-null with `text.len() + 1` writable bytes, so both the copy
    // and the terminator one past it are in bounds.
    unsafe {
        ptr::copy_nonoverlapping(text.as_bytes().as_ptr(), out.cast::<u8>(), text.len());
        *out.add(text.len()) = 0;
    }
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
    #[cfg_attr(miri, ignore = "opens a node; Miri has no reactor (kqueue/epoll are unsupported foreign calls)")]
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
        // Every entry point rejects a null handle, never dereferences it. All thirteen are covered: a C
        // caller reaching any of them with a null handle is the single most likely ABI mistake.
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
            // The service and stream surface: a null owning handle yields a null handle / an error, and the
            // frees tolerate null.
            assert!(fanos_service_connect(ptr::null_mut(), ptr::null()).is_null());
            assert!(
                fanos_service_host(ptr::null_mut(), ptr::null(), 0, ptr::null_mut(), 0).is_null()
            );
            assert!(fanos_service_accept(ptr::null_mut()).is_null());
            fanos_service_free(ptr::null_mut());
            assert_eq!(fanos_stream_read(ptr::null_mut(), ptr::null_mut(), 0), FANOS_ERR_NULL);
            assert_eq!(fanos_stream_write(ptr::null_mut(), ptr::null(), 0), FANOS_ERR_NULL);
            fanos_stream_free(ptr::null_mut());
        }
    }

    #[test]
    fn a_non_utf8_config_string_is_rejected_without_opening_anything() {
        // The config bytes are decoded before any runtime is built, so an undecodable string is a pure
        // argument failure — no node, no port, no teardown.
        let cfg = CString::new(vec![b'l', 0xff, 0xfe]).unwrap();
        // SAFETY: a valid NUL-terminated C string (of invalid UTF-8 bytes).
        assert!(unsafe { fanos_open(cfg.as_ptr()) }.is_null(), "invalid UTF-8 cannot be a config");
    }

    // ---- The runtime-free ABI boundary ------------------------------------------------------------------
    //
    // These exercise every raw-pointer operation in the crate that is not a handle dereference, with no
    // reactor involved — so `cargo miri test -p fanos-ffi --lib` executes them and checks the crate's
    // `unsafe` for UB. That matters because this is the workspace's *only* crate with `unsafe`: every other
    // crate denies it, so a Miri job pointed anywhere else checks code that cannot contain the bug.

    #[test]
    fn a_null_pointer_borrows_as_a_slice_only_at_length_zero() {
        let bytes = [1u8, 2, 3];
        let mut buf = [0u8; 2];
        // SAFETY: the non-null pointers address live buffers of exactly the stated lengths.
        unsafe {
            assert_eq!(as_slice(ptr::null(), 0), Some(&[][..]), "null + 0 is the empty slice");
            assert_eq!(as_slice(ptr::null(), 1), None, "a null pointer with a length is a lie");
            assert_eq!(as_slice(bytes.as_ptr(), 3), Some(&bytes[..]));
            assert_eq!(as_slice_mut(ptr::null_mut(), 0).map(|s| s.len()), Some(0));
            assert!(as_slice_mut(ptr::null_mut(), 1).is_none());
            assert_eq!(as_slice_mut(buf.as_mut_ptr(), 2).map(|s| s.len()), Some(2));
        }
    }

    #[test]
    fn a_size_probe_reports_the_required_length_and_writes_nothing() {
        let value = b"nine-byte";
        // The probe form: no buffer at all, only a length slot. It must learn the exact allocation it needs.
        let mut need = usize::MAX;
        // SAFETY: `need` is a writable `usize`; a null buffer with zero capacity is the probe form.
        let rc = unsafe { write_out(value, ptr::null_mut(), 0, &raw mut need) };
        assert_eq!(rc, FANOS_ERR_BUFFER, "a probe cannot hold the value");
        assert_eq!(need, value.len(), "the probe learns the exact length to allocate");

        // A real buffer that is too small behaves identically, and is left untouched.
        let mut short = [0u8; 4];
        let mut need = 0usize;
        // SAFETY: `short` has 4 writable bytes and `need` is writable.
        let rc = unsafe { write_out(value, short.as_mut_ptr(), short.len(), &raw mut need) };
        assert_eq!(rc, FANOS_ERR_BUFFER);
        assert_eq!(need, value.len());
        assert_eq!(short, [0u8; 4], "a rejected write leaves the caller's buffer untouched");
    }

    #[test]
    fn a_buffer_one_byte_short_is_rejected_rather_than_overrun() {
        // The boundary the capacity check must get exactly right: a value one byte longer than the buffer.
        // Kept in its own heap allocation of exactly that size, so an off-by-one in the check shows up as a
        // Miri-visible overrun instead of a silent write into a stack frame's slack.
        let value = b"ten-bytes!";
        let mut out = vec![0u8; value.len() - 1];
        let mut need = 0usize;
        // SAFETY: `out` has `value.len() - 1` writable bytes, distinct from `value`; `need` is writable.
        let rc = unsafe { write_out(value, out.as_mut_ptr(), out.len(), &raw mut need) };
        assert_eq!(rc, FANOS_ERR_BUFFER, "one byte short is too short");
        assert_eq!(need, value.len(), "the caller still learns the length it needs");
        assert!(out.iter().all(|&b| b == 0), "a rejected write touches nothing");
    }

    #[test]
    fn an_exactly_sized_buffer_is_filled_without_overrunning() {
        // Sized to the value exactly, in its own heap allocation: under Miri a one-byte overrun is caught
        // here, where a stack array would leave it in bounds of the frame.
        let value = b"exact-fit";
        let mut out = vec![0u8; value.len()];
        let mut len = 0usize;
        // SAFETY: `out` has exactly `value.len()` writable bytes, distinct from `value`; `len` is writable.
        let rc = unsafe { write_out(value, out.as_mut_ptr(), out.len(), &raw mut len) };
        assert_eq!(rc, FANOS_OK);
        assert_eq!(len, value.len());
        assert_eq!(&out[..], value, "the whole value is copied out");
    }

    #[test]
    fn an_empty_value_never_forms_a_copy_from_a_null_buffer() {
        // An empty value must skip the copy rather than rely on the count: `core::ptr`'s validity rule is
        // that "for memory accesses of size zero, *every non-null pointer* is valid" — null is not, even at a
        // zero count. Unlike the two overrun tests above, Miri does *not* currently flag a zero-count copy
        // from a null `dst` (verified by deleting the guard: the suite still passed), so this test pins the
        // observable contract — OK with a reported length of 0 — while the guard itself rests on the
        // documented rule rather than on a tool that would catch its removal.
        let mut len = usize::MAX;
        // SAFETY: `len` is writable; a null buffer with zero capacity is the probe form.
        let rc = unsafe { write_out(&[], ptr::null_mut(), 0, &raw mut len) };
        assert_eq!(rc, FANOS_OK, "an empty value fits any capacity, including none");
        assert_eq!(len, 0, "the reported length conveys the emptiness");
    }

    #[test]
    fn a_malformed_out_buffer_is_rejected_before_anything_is_written() {
        let value = b"value";
        let mut out = [0u8; 8];
        let mut len = 0usize;
        // A null length slot leaves the caller nowhere to learn the length: an argument error.
        assert!(!out_buffer_is_valid(out.as_ptr(), out.len(), ptr::null()));
        // SAFETY: `out` is writable; the null length slot must be rejected, not dereferenced.
        let rc = unsafe { write_out(value, out.as_mut_ptr(), out.len(), ptr::null_mut()) };
        assert_eq!(rc, FANOS_ERR_NULL);
        assert_eq!(out, [0u8; 8], "a rejected call writes nothing");
        // A null buffer with a non-zero capacity is a lie about capacity.
        assert!(!out_buffer_is_valid(ptr::null(), 8, &raw const len));
        // SAFETY: `len` is writable; the null buffer must be rejected, not written through.
        assert_eq!(unsafe { write_out(value, ptr::null_mut(), 8, &raw mut len) }, FANOS_ERR_NULL);
        // The two well-formed shapes: a real buffer, and a zero-capacity size probe.
        assert!(out_buffer_is_valid(out.as_ptr(), out.len(), &raw const len));
        assert!(out_buffer_is_valid(ptr::null(), 0, &raw const len));
    }

    #[test]
    fn a_c_string_is_written_with_its_terminator_and_only_when_it_fits() {
        let name = "abcdef.fanos";
        let probe = [0 as c_char; 4];
        // Capacity must hold the text *and* the terminator, so an exactly-text-sized buffer does not fit.
        assert!(!cstr_fits(name, ptr::null(), 1024), "a null buffer never fits");
        assert!(!cstr_fits(name, probe.as_ptr(), name.len()), "no room for the terminator");
        assert!(cstr_fits(name, probe.as_ptr(), name.len() + 1), "text plus terminator is enough");

        // Written into an allocation sized to exactly text + NUL, then read back the way C reads it (by
        // scanning to the terminator) — so an off-by-one terminator is either a Miri error or a bad string.
        let mut buf = vec![0 as c_char; name.len() + 1];
        assert!(cstr_fits(name, buf.as_ptr(), buf.len()));
        // SAFETY: `cstr_fits` holds — `buf` is non-null with `name.len() + 1` writable bytes, and `name` is a
        // distinct `&'static str`.
        unsafe { write_cstr(name, buf.as_mut_ptr()) };
        // SAFETY: `write_cstr` NUL-terminated the buffer, so it is a valid C string for the read.
        let read_back = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(read_back.to_str().unwrap(), name, "the name round-trips as a C string");
    }

    #[test]
    #[cfg_attr(miri, ignore = "opens a node; Miri has no reactor (kqueue/epoll are unsupported foreign calls)")]
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
    #[cfg_attr(miri, ignore = "opens a node; Miri has no reactor (kqueue/epoll are unsupported foreign calls)")]
    fn lookup_of_an_empty_value_with_a_size_probe_is_safe() {
        // An empty value probed with a null buffer + zero capacity must not pass a null `dst` to
        // `copy_nonoverlapping` (UB even for a zero count) — it returns OK with length 0, or NOTFOUND if the
        // store doesn't serve an empty value; never a crash.
        let _serial = serial();
        let node = open_loopback();
        let key = b"empty-value-key";
        // SAFETY: `node` is live; `key` is valid; a null value pointer with length 0 is an empty value.
        unsafe {
            fanos_publish(node, key.as_ptr(), key.len(), ptr::null(), 0);
            let mut out_len = usize::MAX;
            let rc =
                fanos_lookup(node, key.as_ptr(), key.len(), ptr::null_mut(), 0, &raw mut out_len);
            assert!(rc == FANOS_OK || rc == FANOS_ERR_NOTFOUND, "a defined result, got {rc}");
            if rc == FANOS_OK {
                assert_eq!(out_len, 0, "an empty value reports length 0");
            }
            fanos_free(node);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "opens a node; Miri has no reactor (kqueue/epoll are unsupported foreign calls)")]
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
