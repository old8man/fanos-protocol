# FANOS conformance vectors

These are the **language-agnostic known-answer tests (KATs)** that pin the FANOS wire and
algebra (spec Part VII §7.9). Any implementation in any language interoperates iff it
reproduces these vectors bit-for-bit and rejects the listed non-canonical inputs.

The rule is **canonical encoding**: exactly one valid byte sequence for every object, so
hashes, signatures, and MACs agree across implementations. A conformant decoder MUST reject
everything else.

## Files

| File | Contents | Spec |
|---|---|---|
| [`vectors/algebra.json`](vectors/algebra.json) | `PG(2,q)` parameters, cross-product rendezvous, the Fano cell, the DIAKRISIS syndrome table | §2, §6.3 |
| [`vectors/wire.json`](vectors/wire.json) | canonical varints, field-element widths, point/line encodings, frame types, and non-canonical inputs to reject | §7.1–§7.5 |
| [`vectors/diakrisis.json`](vectors/diakrisis.json) | coherence-measure thresholds and the health-monitor constants | §2.7, §6 |
| [`vectors/services.json`](vectors/services.json) | L4 storage addressing, CALYPSO `.fanos` addresses, PROTEUS epoch shaping, health-view gossip layout | §L4, XII, §13, §6.4 |
| [`vectors/diaulos.json`](vectors/diaulos.json) | DIAULOS connection-layer frames, the constant-size AEAD cell, and the 1-RTT hybrid-KEM handshake derivation | §7, XII |
| [`vectors/names.json`](vectors/names.json) | ONOMA addresses (bech32m PQ commitments), mnemonics, and per-epoch descriptor derivations | §L-pet |
| [`vectors/telemetry.json`](vectors/telemetry.json) | the canonical `CoherenceFrame` wire format and the 3-bit Fano/Hamming syndrome | §2.7, §6 |
| [`vectors/angelos.json`](vectors/angelos.json) | ANGELOS messenger wire formats: the message envelope, the bot command grammar, and the session/group/media crypto planes | platform §6 |
| [`vectors/thesauros.json`](vectors/thesauros.json) | THESAUROS content addressing: the position-bound Merkle CID, the retrievability proof, and the manifest layout | platform §7 |

## Provenance

Every value here is asserted by the Rust reference test suite (`rust/`), so the vectors cannot
drift silently: change the implementation and the tests fail. The reference verifier
(`cargo run -p fanos-cli`) reproduces the numeric claims (V1–V22) end to end.

Byte strings are lower-case hex. Integers are decimal unless noted. A porting checklist:

1. Implement `GF(2^m)` and `GF(p)` arithmetic; check the cross-product KATs in `algebra.json`.
2. Implement canonical varints and projective encoding; match `wire.json` and reject its
   `reject` list.
3. Implement the Hamming(7,4) syndrome and the mediator map; match the `fano` and `syndrome`
   sections of `algebra.json`.
4. (Optional, for the diagnosis plane) implement the coherence measures against
   `diakrisis.json`.
