/*
 * fanos.h — the stable C ABI for FANOS (spec §11.2).
 *
 * Link against libfanos_ffi (staticlib or cdylib). Each fanos_node* handle owns a runtime and a running
 * node; the calls block on it. Open with fanos_open, free with fanos_free (exactly once).
 *
 * This header is hand-maintained to match crates/fanos-ffi/src/lib.rs; keep the two in sync.
 */
#ifndef FANOS_H
#define FANOS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result codes (0 = OK). */
#define FANOS_OK            0
#define FANOS_ERR_NULL     (-1) /* a required pointer argument was null */
#define FANOS_ERR_CONFIG   (-2) /* the config string was invalid */
#define FANOS_ERR_START    (-3) /* the node/runtime failed to start */
#define FANOS_ERR_IO       (-4) /* the operation reached the network but did not succeed */
#define FANOS_ERR_BUFFER   (-5) /* the output buffer was too small (out_len holds the needed length) */
#define FANOS_ERR_NOTFOUND (-6) /* a lookup found no value */

/* Opaque node handle. */
typedef struct FanosNode FanosNode;

/* Opaque hidden-service byte-stream handle. Must be freed before its node. */
typedef struct FanosStream FanosStream;

/* A node health/identity snapshot (spec §11.2 fanos_diagnose). */
typedef struct FanosHealth {
    uint32_t coord[3];   /* the node's overlay coordinate [x, y, z] */
    size_t   known_peers;/* peers currently in the address book */
    uint16_t port;       /* the bound UDP port */
} FanosHealth;

/* Open and start a node from a `key = value` config string (NULL = default config). Returns an owning
 * handle, or NULL on failure. Free with fanos_free. */
FanosNode *fanos_open(const char *config);

/* Ensure the node has joined the overlay (idempotent; it joins during fanos_open). FANOS_OK / FANOS_ERR_NULL. */
int fanos_join(FanosNode *node);

/* Publish `val` (val_len bytes) under `key` (key_len bytes) in the overlay store. */
int fanos_publish(FanosNode *node, const uint8_t *key, size_t key_len,
                  const uint8_t *val, size_t val_len);

/* Look up `key`, copying the value into `out` (capacity out_cap) and writing its true length to *out_len.
 * FANOS_OK / FANOS_ERR_NOTFOUND / FANOS_ERR_BUFFER (value larger than out_cap) / FANOS_ERR_NULL. */
int fanos_lookup(FanosNode *node, const uint8_t *key, size_t key_len,
                 uint8_t *out, size_t out_cap, size_t *out_len);

/* Read the node's current health (a zeroed snapshot for a NULL handle). */
FanosHealth fanos_diagnose(FanosNode *node);

/* Connect to a CALYPSO hidden service by its "<addr>.fanos" name. Returns an owning stream handle, or NULL
 * (bad argument / name did not resolve / dial failed). Free with fanos_stream_free, before fanos_free. */
FanosStream *fanos_service_connect(FanosNode *node, const char *addr);

/* Read up to `len` bytes into `buf`. Returns the count (>= 0; 0 = EOF), FANOS_ERR_IO, or FANOS_ERR_NULL. */
int fanos_stream_read(FanosStream *stream, uint8_t *buf, size_t len);

/* Write all `len` bytes of `buf` (flushed). Returns `len` on success, FANOS_ERR_IO, or FANOS_ERR_NULL.
 * `len` must not exceed INT_MAX. */
int fanos_stream_write(FanosStream *stream, const uint8_t *buf, size_t len);

/* Close and free a stream (safe on NULL). Call before freeing the node. */
void fanos_stream_free(FanosStream *stream);

/* Shut the node down and free its handle (safe on NULL). */
void fanos_free(FanosNode *node);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FANOS_H */
