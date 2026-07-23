# Single-Use Reply Block (SURB) — closing the reply-relay correlator (S1-H3)

> Closes audit §5 S1-H3: a client that receives anonymous replies through a **rendezvous relay** registers its
> session cookie against its **real coordinate** in cleartext (`RdvRegister`, `rendezvous_relay.rs`), so the
> relay learns `cookie → client_coord`. Because S1-C1 now routes *clearnet* through the same machinery, a
> **reply-relay + exit collusion re-links client ↔ target** — the one correlation the mixnet is meant to
> prevent. The fix is a SURB: the client pre-builds an encrypted return path so the relay forwards a reply
> *without ever learning the client's coordinate*.

## 0. Why a plaintext registration leaks, and why the client can't just be its own rendezvous

The service→relay leg is already anonymous: the client names a `reply_circuit` (hop lines ending at the relay's
line) inside its first `Request`, and the service seals replies to it (`seal_forward`). The **relay** (the
combiner of that last line) peels the reply, sees the 16-byte `cookie`, and must deliver the payload to the
client. But a client **cannot be its own reply rendezvous** — only `t`-of-`(q+1)` line members are combiners
(Fano: 4 of 7) *and* every coordinate reshuffles each epoch — so it engages a relay and, today, tells that relay
its coordinate. That single hop is the leak.

The naïve fixes fail:
- *Onion-wrap the registration only* — hides the coordinate from the *sender* field, but the relay still
  forwards the reply to whatever coordinate it holds, so it still learns `cookie → coord`.
- *Second relay* — moves the leak one hop; relay₁+relay₂+exit collusion still links.
- *Relay re-seals into a client circuit whose innermost layer names the coord* — the relay would have to write
  the coordinate into that layer, so it learns it.

The property we need is a **separation of knowledge**: the node that learns the **cookie** (the reply-relay)
must be a *different* node from the one that learns the **coordinate** (a delivery node), and neither learns both.
That requires the classic **Sphinx/Loopix header–payload split**: the client pre-seals the *routing* (including
the final coordinate, sealed to the delivery node), and the relay inserts only the *payload*.

## 1. Construction (FANOS-native, additive — the forward onion is untouched)

A **SURB** is what the client registers instead of its coordinate. It is built by the client over a **return
circuit** `r₁ … r_L` (hop lines it chooses, the last being a *delivery node* line) and consists of:

- `first_hop` — the coordinate of `r₁`, the only node the reply-relay sees;
- `header` — a nested KEM-sealed **routing-only** onion over `r₁…r_L` (each layer `CMD_NEXT‖next`, the innermost
  `CMD_DELIVER‖client_coord`), reusing the `sealed` layer format but carrying **no payload**;
- (kept secret by the client) `SurbKeys` — the per-hop session keys `s₁…s_L`, derived at build time from the
  same KEM encapsulations, so the client can later strip every hop's payload mask.

The reply payload rides in a **separate fixed-size block** alongside the header:

1. The reply-relay peels the incoming reply → `(cookie, reply_payload)`, looks up the SURB for `cookie`, and
   emits `header ‖ mask(s₁, reply_payload)` to `first_hop`. (The reply payload is already DIAULOS-encrypted
   end-to-end, so the relay masking it under `s₁` only serves cross-hop unlinkability, not confidentiality.)
2. Each return hop `r_k` peels its header layer (standard KEM decapsulation → `s_k`, `CMD_NEXT` → next hop) **and
   re-masks the payload block** with a keystream from `s_k` (a length-preserving XOR, so size stays constant and
   the block is bitwise-unlinkable across hops), then forwards `inner_header ‖ mask(s_k, block)`.
3. The delivery node `r_L` peels → `CMD_DELIVER ‖ client_coord`, masks once more under `s_L`, and sends the
   (still-masked) block to `client_coord`. It learns the coordinate but **never the cookie** (peeled away at the
   relay) and never the plaintext reply.
4. The client receives the block and strips every mask with `SurbKeys` (`s₁…s_L`, order-independent XOR),
   recovering the DIAULOS ciphertext, which it decrypts end-to-end.

**Single-use.** The relay consumes a SURB on first use and drops it (replay-refused); the client registers a
fresh SURB per expected reply (or a small pool). A replayed SURB packet is dropped by each hop via the reply
ratchet's grace-window nonce check, exactly as a forward onion is.

## 2. Why it is correct (the separation, precisely)

| Party | learns cookie? | learns client_coord? |
|---|---|---|
| reply-relay (peels the reply) | **yes** | no — it only holds the opaque SURB `header` + `first_hop` |
| return hops `r₁…r_{L-1}` | no | no |
| delivery node `r_L` | no | **yes** — but it never saw the cookie and forwards an opaque masked block |
| a global passive observer | no (masking + constant size ⇒ hops unlinkable) | no |

So `cookie → coord` is knowable only by **relay + delivery-node collusion** — a strictly stronger requirement
than today's single relay, and independent of the exit/service. With `L ≥ 2` honest-with-probability return
hops, this matches the Loopix reply guarantee. The holonomy authenticator (spec §5.4, S1-M1) still rides the
innermost DELIVER layer, so the client verifies the reply traversed the exact return circuit it built.

## 3. Implementation plan

- **`fanos-aphantos::surb`** (new module, additive — does not modify `build`/`peel`): `Surb`, `SurbKeys`,
  `build_surb(return_circuit, return_keys, client_coord, seed) -> (Surb, SurbKeys)`,
  `process_surb_hop(packet, kem_secret) -> {Forward{next, packet} | Deliver{coord, block}}`,
  `inject_reply(&Surb, reply) -> packet`, `open_reply(block, &SurbKeys) -> reply`. Reuses the crate's KEM/AEAD
  helpers + `hash_xof` keystream. Unit-proven round-trip + the knowledge-separation invariants in isolation.
- **`fanos-rendezvous`**: extend `RdvRegister` to carry a `Surb` (not a bare cookie→coord); the service reply
  still seals to `reply_circuit` unchanged.
- **`fanos-node::rendezvous_relay`**: store `cookie → Surb`; on a peeled reply, `inject_reply` and emit to
  `first_hop` (single-use eviction), replacing the plaintext `Command::Emit { to: client_coord }`.
- **Return hops** run the existing relay/router path over `process_surb_hop`; the client opens with `open_reply`.
- Sim + real-QUIC: a reply reaches the client with the relay never holding its coordinate.

## 4. Sources

Sphinx (Danezis–Goldberg, S&P 2009) — the SURB header/payload split and the reverse-mask payload; Loopix
(USENIX Sec 2017) — single-use reply blocks over a mix return path; Tor rend-spec v3 — rendezvous cookies. The
separation-of-knowledge argument (relay knows cookie xor coord) is the reply-path analogue of the forward-path
"no single relay links source and destination" invariant this codebase already upholds (`sealed.rs` module doc).
