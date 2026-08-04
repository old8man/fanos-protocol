# Reference-solution audit — best known, or merely working?

> Answers one question per load-bearing mechanism: **is this the best available solution, or a working
> one that a better published result has since overtaken?** Written against the standing directive that
> a chosen-but-inferior mechanism, where a stronger one is known, is a defect of the same kind as a bug —
> and that the fix, where one exists, should be named precisely enough to cost.
>
> Method, per mechanism: (1) what FANOS does, cited to the file and the derivation it claims — not the
> marketing; (2) the current best known approach, cited to a paper (venue, year); (3) a verdict —
> **BEST-KNOWN** (matches or exceeds the frontier), **ADEQUATE-BUT-BETTER-EXISTS** (name the better one,
> cost the adoption), or **BEHIND** (measurably worse, on a stated axis). Where the literature itself does
> not resolve cleanly, the verdict says so — an honest gap outranks an invented citation.
>
> Six mechanisms, in the order asked. A verdict table and a ranked shortlist close the document.

---

## 1. Consensus — TAXIS: masking-quorum PBFT over `PG(2,q)`, with a secret-leader lottery

### 1.1 What FANOS does

TAXIS runs inside one projective cell: `n = q²+q+1` validators, quorum `Q = ⌈(n+f+1)/2⌉`,
`f = ⌊(n−1)/3⌋` tolerated Byzantine faults (`docs/design-taxis.md` §2). The Fano default is tight:
`n=7, f=2, Q=5` — any two quorums intersect in `2Q−n ≥ f+1` validators, giving safety by a masking
argument and liveness because `n−f ≥ Q` always holds (§2.1, proved for every prime-power `q`). The round
is classical: **PROPOSE → PREPARE → COMMIT**, three message phases per height, each a `Q`-quorum of
hybrid-PQ-signed votes, plus a fourth **REVEAL** phase (opening the anti-MEV threshold mempool) that runs
*after* finality and does not gate it (`docs/design-taxis.md` §4). View-change follows Tendermint's
locking rule, hardened by a proof-of-lock justification (§4.1) after a measured liveness bug. Leader
election is a beacon-VRF over the epoch DVRF seed (§3), and — because a *public* per-height leader is a
targeting oracle (Heimbach et al. located >15% of Ethereum's validators from 4 vantage points in 3 days,
USENIX Security 2025, arXiv 2509.24955) — round 0 runs a **min-ticket secret-leader election**: every
member of the beacon-elected line proposes, attaches a post-quantum Merkle-VRF ticket, and replicas
PREPARE the lowest after a measured collection window (§3.1). Anti-MEV is a threshold-encrypted mempool
reusing the same Shamir-`t`-of-`(q+1)` KEM-sealed-share primitive NYX uses for onion hops (§5). Data
availability gates finality by **full reconstruction**, not sampling: `on_propose` refuses to PREPARE
unless `Block::reconstruct_payload` succeeds against the committed erasure shards (§6) — affordable
because the cell is small, not because of a sampling argument.

### 1.2 The current best known approach

Two independent axes of the BFT literature bear on this, and TAXIS's own design doc already surveys the
first correctly:

- **DAG-BFT mempools** (Narwhal/Tusk, EuroSys 2022, arXiv 2105.11827; Bullshark, CCS 2022; Mysticeti,
  NDSS 2025, arXiv 2310.14821; Sailfish, IEEE S&P 2025, IACR eprint 2024/472) decouple *data
  dissemination* (every validator gossips its own batch in parallel) from *ordering* (a lightweight pass
  over tiny certificates), removing the single-proposer bandwidth bottleneck. The wins are large at the
  committee sizes these papers benchmark: Narwhal/Tusk sustain 100k–170k tx/s with sub-3.5s latency at
  committees of 10–50; Sailfish gets DAG-BFT down to one reliable-broadcast round plus network delay for a
  *leader-every-round* commit, closing the latency gap DAG mempools used to trade for their throughput.
- **Two-phase classical BFT.** HotStuff-2 (Malkhi & Nayak, IACR eprint 2023/397) and Jolteon (Gelashvili,
  Kokoris-Kogias, Sonnino, Spiegelman, Xiang, FC 2022) show that the original three-phase HotStuff/PBFT
  round (PREPARE, PRE-COMMIT/lock, COMMIT) is not needed: pipelining the lock across views collapses the
  happy path to **two phases**, a measured minimum commit latency of `5δ` versus three-phase's `7δ`+,
  with no change to the quorum system, no new trust assumption, and (per the paper) "adding no substantive
  complexity to the original HotStuff protocol."

### 1.3 Verdict

**`ADEQUATE-BUT-BETTER-EXISTS`, on the round protocol; the committee core itself is the right choice at
this shape.**

The direct question — is a DAG mempool *strictly* better for TAXIS's shape — is **no**, and the reason is
size. DAG-BFT's headline throughput comes from removing a single leader's egress bottleneck, and that
bottleneck scales with committee size: at Narwhal's benchmarked 10–50 validators a lone proposer would
need to out-broadcast 9–49 peers; at TAXIS's default Fano cell (`n=7`) the ratio is 6:1, and TAXIS already
absorbs most of that gap structurally — the block payload is erasure-shredded and dispersed one shard per
validator rather than fully broadcast (§6, a Turbine-style fanout the design doc names explicitly), and
the anti-MEV mempool already orders over *commitments*, not transaction bodies (§5), which is the same
"defer the bulk data, order the small thing" move a DAG mempool makes, achieved without one. A DAG rewrite
would also complicate exactly the part of TAXIS that turned out to be delicate in practice — the
proof-of-lock/view-change interaction (§4.1, a real measured liveness bug) — for a bandwidth win that is
small at the shape TAXIS actually runs. **Sharding by cell (§7, `protocol.md` §L1) is FANOS's answer to
DAG-BFT's throughput case, and it is a reasonable one**: many small classical-BFT shards in parallel,
rather than one large DAG-BFT committee.

The round protocol is a different matter. TAXIS is *literally* the three-phase family HotStuff-2/Jolteon
superseded — the design doc's own §4 heading says "PBFT-class, three phases + reveal," and its own
locking-rule citations are to the *original* Tendermint/HotStuff argument, not the two-phase successor.
Adopting HotStuff-2's collapse costs one network round-trip per block, unconditionally, forever — on the
finality path that gates DROMOS's execution pipeline, OBOLOS settlement, and every other layer above it.
**Cost of adopting it:** `Q`, `f`, committee selection, and the SSLE lottery (§3.1) are untouched — the
change is confined to how PREPARE/COMMIT pipeline across views — but TAXIS's own proof-of-lock hardening
(§4.1) shows this system's view-change edge cases are not free to re-derive; a two-phase collapse needs
the same care applied to a new locking invariant, not a drop-in swap.

The secret-leader election itself (§3.1) is, separately, **`BEST-KNOWN`**: the design doc's own survey of
Whisk/EIP-7441, Sassafras (ring-VRF, IACR eprint 2023/002), and PQ-SSLE (Qelect, AFT 2023) correctly
rejects them as either non-PQ or dominated by synchronous-shuffle liveness cliffs at `q+1 ≤ 8`, and the
min-ticket-with-Merkle-VRF construction it ships instead is sound against a real, specific attack the
design doc found in ML-DSA (Fiat–Shamir-with-aborts lets a Byzantine member grind `H(signature)` — a
non-VRF ticket is fully riggable, not merely biased). Nothing in the surveyed literature does better at
this committee size.

---

## 2. The mixnet hop — the threshold line, `t`-of-`(q+1)`, vs. Sphinx / Loopix / Nym / MPC-onion

### 2.1 What FANOS does

A NYX onion layer is peeled by a **line**, not a node: the sender Shamir-splits a fresh per-layer key into
`q+1` shares at threshold `t`, hybrid-KEM-seals each share individually to one line member (sender-dealt,
no line DKG — `spec/protocol.md` §5.2), and below `t` members the reconstructed key is information-
theoretically unrecoverable (perfect Shamir secrecy). The threshold `t` was, until 2026-07-29, a hardcoded
constant (`MIX_THRESHOLD = 2`) that only preserved its intended margin at the Fano default and collapsed
to near-zero anonymity at larger `q` (`docs/design-anonymity-substrate.md` §4a); it is now derived,
`t = ⌈2(q+1)/3⌉`, and generalizes correctly (`rust/crates/fanos-node/src/node.rs::mix_threshold`, tested
against the ceiling at every `q`). Packets are Sphinx-shaped and fixed-width regardless of hop position
(the S1-M6 fixed-slot layout, `fanos_aphantos::slots`, closing a per-hop size-decrement fingerprint).
Mixing is Loopix-class Poisson delay at `λ/μ ≥ 2`, `≥3` layers.

### 2.2 The current best known approach

- **Single-relay onion + SURB.** Sphinx (Danezis & Goldberg, IEEE S&P 2009) is the format every deployed
  mixnet (Loopix, USENIX Security 2017; Nym) still uses; its formal security was only closed in 2024
  (Scherer, Weis, Strufe, PoPETs 2024 — DDH alone is insufficient, a Gap-DH assumption plus a format fix
  were required), and Kuhn, Beck & Strufe (IEEE S&P 2020) showed reply-payload tampering on single-relay
  reply paths can break whole-protocol anonymity.
- **Committee/MPC onion hops.** The nearest published constructions to a threshold peel are Duo/Hydra
  Onions (CMS 2004, `1`-of-`k` — the *dual* of below-threshold: any one member peels), Poly Onions (TCC
  2022, threshold-gated only on the *backup* path, computational), and the anytrust-committee designs
  (Atom, SOSP 2017; Trellis, NDSS 2023) that need `≥1` honest member and are computational throughout.
  MPC-mix systems (MCMix, AsynchroMix, Blinder, Clarion) achieve genuine `t`-of-`n` thresholds but for one
  mixing committee, not a multi-hop routed path.
- **Compulsion resistance.** Danezis & Clulow (IH 2005) named the property a threshold hop buys — an
  adversary who can compel one machine at a time needs `t` *simultaneous* compulsions per hop instead of
  one sequential subpoena per hop — and, per the design doc's own literature sweep, no published
  construction had delivered it for a routed path before this one.

### 2.3 Verdict

**`BEST-KNOWN`**, on the specific axis the construction targets, with an honestly-scoped and non-trivial
cost.

The design doc's own systematic sweep (Camenisch–Lysyanskaya CRYPTO 2005 through the 2024 MPC-mix and
committee-hop lines) is thorough enough to trust on its central claim: no published onion format peels a
layer by `t`-of-`n` threshold decryption such that a below-threshold subset learns *nothing* about the
routing, for a *multi-hop path* (as opposed to one mixing committee). That is a real, checkable gap in
`{per-hop committee} × {IT below threshold}`, and NOSTOS/NYX occupy it. It is a genuine improvement over
Sphinx's single-relay peel on the property that matters most under legal/physical compulsion, which is a
documented, real-world threat class (Tor relay seizures) that Sphinx's format was never designed to
resist.

**The honest cost, stated precisely rather than left implicit.** A threshold hop needs `t` members to each
decapsulate their own share and combine — a network round-trip this document can now put a number on,
because the platform's own hardening work measured it: a share-request answers in **1.05 ms under
`release` and 47 ms under `dev`** on one machine (`fanos-aphantos/tests/gather_cost.rs`), and the
RFC-6298-style adaptive gather deadline this feeds settles at **500–800 ms per hop** on a real seven-node
cell over QUIC (`docs/design-hidden-service-hardening.md` §6.3). A Sphinx single-relay peel is one local
AES/ChaCha decrypt with no round-trip at all. So the per-hop cost of the threshold construction, in the
regime this platform actually runs, is on the order of **two to three orders of magnitude** in per-hop
latency versus classical Sphinx — the price NYX pays for turning `f` (a linear compromise budget) into
`P_break = Pr[Binomial(q+1,f) ≥ t]` (exponentially small in `q` for `f < t/(q+1)`, §4 of the anonymity
substrate doc). That trade is exactly what `APHANTOS-Full`/the MIX lane is for, and it is declared, not
hidden — `APHANTOS-Lite` (single-node Sphinx-class) exists precisely because this cost is not always
worth paying.

The one item on this axis genuinely still open is the honest scope limit the design doc itself states: the
information-theoretic guarantee is *per-hop*, composed with only *computational* security end-to-end
(the onion body between hops is ciphertext, not IT-shared) — an accurate, not inflated, claim, correctly
distinguished in the Kuhn et al. (PoPETs 2019) privacy-notions hierarchy rather than mis-sold as end-to-end
IT anonymity.

---

## 3. Receiver anonymity — NOSTOS vs. SURBs, PIR-based systems, Arke

### 3.1 What FANOS does

NOSTOS replaces the single-use reply block with a **geometric dead-drop**: the reply returns on one of the
receiver's own `q+1` lines, computed by cross-product from a shared secret and the epoch beacon, so there
is no "delivery node" with a coordinate to leak — the receiver is hidden inside a `q+1`-node anonymity set,
and the return hop is peeled the same threshold way as a forward hop (`docs/design-anonymity-substrate.md`
§3). §3b extends the same construction symmetrically to **hosting**: a service registers as a NOSTOS
receiver too, so the meeting-line combiner relays to the operator's own dead-drop line without ever
learning the operator's coordinate — closing what the audit had flagged as the platform's headline
critical (hidden services reachable off their meeting combiner, over real QUIC,
`rendezvous-host-hosting.md`). POROS (§6) generalizes the same beacon-blinded, threshold-hosted
construction to censorship-resistant *ingress* (ML-DSA/LRC/DVRF composed for bootstrap, not conversation).

### 3.2 The current best known approach

- **SURBs.** Sphinx single-use reply blocks (Danezis & Goldberg 2009) are what NOSTOS explicitly retires,
  for the reasons in §2.2 above (Kuhn et al. IEEE S&P 2020 tampering result; the 2024 formal-proof gap).
- **PIR-based mailbox systems.** Pung, Talek, and **Addra** (Ahmad, Yang, Agrawal, El Abbadi, Gupta,
  **USENIX OSDI 2021**, IACR eprint 2021/044 — not IEEE S&P, correcting the venue) all put messages in a
  mailbox on a semi-trusted server and retrieve them via private information retrieval, so *retrieval* is
  unlinkable to the mailbox index but the architecture needs a fixed host (or a small anytrust cluster of
  hosts) that every user's mailbox lives on. Riposte, Express, Spectrum extend the same family.
- **Discovery/rendezvous without a directory.** Arke (unlinkable ID-NIKE over an untrusted store,
  consensus-free, Byzantine-robust, CCS 2024) and Pudding (username discovery on Loopix, `<1/3`
  malicious, IEEE S&P 2024) are the strongest current systems for the *lookup* half of the problem.
- **Reply-notification.** Oblivious Message Retrieval (PerfOMR, USENIX Security 2024; Myco, IEEE S&P 2025)
  and Private Signaling (USENIX Security 2022) solve "tell the recipient a message is theirs" against a
  semi-trusted server pair, without a dedicated per-user mailbox host.

### 3.3 Verdict

**`BEST-KNOWN`** on the property the design doc claims — a routed reply path with no fixed mailbox host and
below-threshold information-theoretic secrecy — **but with two concrete, currently-open defects that keep
it from being unconditionally so**, and the second is the one the team's own audit already flagged as
blocked on a missing primitive.

The structural comparison holds up: every PIR-based system in §3.2 (Pung/Talek/Addra/Express/Riposte/
Spectrum) requires a semi-trusted server or a small fixed anytrust cluster the mailbox lives on; every
OMR/Private-Signaling system requires a semi-trusted server pair for notification. NOSTOS needs neither —
the "mailbox" is a rotating `q+1`-line inside the same substrate everything else routes on, and Pynchon
Gate (WPES 2005) is the only prior IT-below-threshold receiver-privacy guarantee this document's authors
could find, and it is a *retrieval* system, not an in-network *path*. That is a real, citable gap NOSTOS
occupies, not a marketing claim.

**The first open defect** is the `service_tag = H(identity ‖ epoch)` construction (§3b/POROS): the tag
rotates so a combiner cannot follow one service across epochs by the tag alone, but the registration also
carries the identity bundle *in the clear beside it* (so the combiner can verify the binding), which makes
every meeting combiner a linkable, timestamped record of which services exist and when
(`docs/design-anonymity-substrate.md` §6, the POROS section; measured over eight epochs in
`fanos-rendezvous`). The claim that the substrate is "proven non-linkable across epochs" is true of the
*client's* dead-drop line (T2, proven) and does **not** currently extend to a hidden service's own
registration — a distinction the design doc itself now states explicitly, correcting an earlier
overstatement.

**The second, and the one this survey can now answer directly, is the blinding question.** The fix Tor v3
uses for the identical problem is key-blinding: register under `Blind(vk, epoch, nonce)` and verify the
binding without the combiner ever seeing the unblinded identity. This survey checked, across every PQ
signature family, whether an audited scheme with that property exists:

| Family | Candidate | Status |
|---|---|---|
| Lattice (FANOS's own, ML-DSA) | none standardized | ML-DSA (FIPS 204) has no blinding operation; academic MLWE/Kyber-Dilithium blind-signature constructions exist only as unaudited research proposals (e.g. a 2025 IoT-blockchain application paper) |
| Isogeny / class-group action | **CSI-Otter** (Katsumata et al., **CRYPTO 2023**) | the first *provably-secure* PQ (partially) blind signature — 128 B public key, 4–8 KB signature under CSIDH-512 — but isogeny-based, not lattice-based, and CSIDH-family schemes carry less deployed confidence post-SIDH (2022) |
| Hash-based (SLH-DSA/SPHINCS+, FIPS 205) | none found | no blind variant located in this survey |

So the precise answer is: **something exists (CSI-Otter), it is peer-reviewed at a top venue, and it is
the closest published thing to what NOSTOS/POROS need — but it is not a drop-in.** Adopting it means
introducing a *second* post-quantum hardness family (isogenies/class-group actions) purely for this one
feature, directly against the platform's own stated discipline of composing vetted primitives on **one**
pairing-free trust base rather than importing a second one for a single narrow use (the same discipline
that already kept BLS pairings out of the beacon and VRF, `spec/protocol.md` §L6). Signature size (4–8 KB)
is comparable to ML-DSA-65's 3.3 KB, but isogeny group-action computation is materially slower than lattice
arithmetic, and CSI-Otter has had none of ML-DSA's multi-year NIST public-scrutiny process. The design
doc's own conclusion — "this is research (task #39), not a patch" — is therefore corroborated rather than
overtaken: a candidate now has a name and a citation, but taking it is a real architectural cost, not a
library upgrade, and the honest verdict for the underlying PQ-blind-signature *field* is that it remains
behind what a mature deployment would want, for everyone, not just FANOS.

---

## 4. The PQ signature and KEM choices

### 4.1 The hybrid construction

**What FANOS does.** Signatures are `Ed25519 ‖ ML-DSA-65` — both computed over the same message, both must
verify (`rust/crates/fanos-pqcrypto/src/sig.rs`). KEM is `X25519 ‖ ML-KEM-768`, combined via SHAKE256 over
the *entire* transcript — both shared secrets, the ciphertext, and the recipient's static key
(`rust/crates/fanos-pqcrypto/src/kem.rs::combine`), explicitly citing X-Wing/MAL-BIND-style binding and
tested against exactly the re-encapsulation/context-reuse regression that binding a partial transcript
would permit (the `combine` doc comment cites audit finding B5).

**The current best known approach.** Hybrid (classical + PQ) key exchange is the sanctioned transition
posture: NIST does not yet support hybrid *signatures* under a dedicated FIPS validation path but does
permit hybrid schemes to be FIPS-140-3-validated as long as one component is separately NIST-approved, and
NIST IR 8547's roadmap (deprecating classical-only algorithms by 2030, removing them by 2035) is the
posture every current deployment is building against. X-Wing (Connolly et al.,
`draft-connolly-cfrg-xwing-kem`, an active IETF CFRG draft as of 2026) is *precisely* FANOS's KEM shape —
X25519 + ML-KEM-768, combined by a single hash over the full transcript, chosen because "if either X25519
or ML-KEM-768 is secure, X-Wing is secure." The IETF LAMPS working group's composite-signature and
composite-KEM drafts are the standards-track analogue for signatures.

**Verdict: `BEST-KNOWN`.** FANOS's hybrid combiners are not merely *a* reasonable hybrid — the KEM combiner
is structurally the same construction as the leading IETF draft for exactly this purpose, done independently
and defended against the identical attack (non-contributory low-order-point rejection, checked in constant
time on both encapsulate and decapsulate — `kem.rs` tests `a_low_order_x25519_ephemeral_is_rejected_on_decapsulate`
and its encapsulate-side twin). Nothing in the current standards landscape or research literature suggests a
materially better hybrid shape exists at this time; X-Wing itself is still a draft, not an RFC, which is the
honest state of the whole field, not a FANOS-specific gap.

### 4.2 The blinding question

Covered in full in §3.3 above, since it is load-bearing there, not here: **no audited, NIST-track PQ
signature scheme supports public-key blinding.** The one peer-reviewed candidate (CSI-Otter, CRYPTO 2023)
is isogeny-based and would import a second PQ hardness family. Verdict: **`BEHIND`** the ideal — but
against no adoptable alternative, since the field itself has not produced one on FANOS's chosen (lattice)
trust base. This is the one mechanism in this survey where the honest finding is that the frontier, not
just FANOS, is short of what a mature deployment needs.

---

## 5. The shielded currency — OBOLOS vs. Zcash Orchard/Halo2 and the PQ-ZK frontier

### 5.1 What FANOS does

OBOLOS's accounting model — the note/commitment/nullifier layer, independent of which proof system attests
it — already tracks the Zcash Orchard lineage closely, and the codebase says so directly rather than
leaving it implicit: re-randomized per-spend value commitments so a spend's public `input_value` cannot be
matched to its creating commitment (`rust/crates/fanos-obolos/src/tx.rs`, fixing audit finding O-C2, "the
Zcash-Orchard pattern"), a tree-position-bound nullifier so two notes sharing a commitment still nullify
distinctly (O-M1), and a split spend/nullifier/incoming-viewing key hierarchy for selective disclosure
without spend authority (`wallet.rs`, "the Zcash Sapling/Orchard viewing-key discipline"). The proof
backend is where FANOS necessarily diverges, because Orchard's classical curves (Pallas/Vesta) are not
post-quantum: OBOLOS instead builds confidentiality (balance + aggregated range proofs) and untraceability
(zero-knowledge Merkle membership via a SIS hash whose relation is linear over the ring, following
Libert–Ling–Nguyen–Wang) on a ring-BDLOP commitment over a Goldilocks cyclotomic ring
(`docs/design-obolos-zk.md`), reducing to Module-SIS/Module-LWE. It is empirically verified — completeness,
soundness, binding, ZK re-randomization on every primitive — but a **single 1-in/1-out shielded transaction
proof is 145 MiB at the shallowest possible tree depth**, after four rounds of derived (not guessed)
constant-factor compaction reaching a measured ceiling of ~126 MiB for the spend proof alone. The design
doc's own §5 names this the blocker: "recursive/succinct proof rather than paying for it directly... is
the only route to a shippable spend proof," left as future work with no named construction.

### 5.2 The current best known approach

- **Deployable today, classical.** Zcash Orchard runs on Halo2 (Bowe, Grigg, Hopwood — the "Halo" recursive
  proof composition, IACR eprint 2019/1021, without a trusted setup) — live in production since 2022, with
  proofs in the low kilobytes and verification in milliseconds. It is not post-quantum: the underlying
  Pallas/Vesta curve discrete log breaks under Shor's algorithm exactly as Ed25519 does.
- **The PQ-ZK frontier, and it moved recently.** LaBRADOR (Beullens & Seiler, CRYPTO 2023, IACR eprint
  2022/1341) is a transparent, Module-SIS-based lattice proof system achieving **~50–60 KB** proofs for
  large arithmetic circuits via recursive amortization. Greyhound (IACR eprint 2024/1293, composing with
  LaBRADOR) is a lattice polynomial-commitment scheme reaching **53 KB** evaluation proofs for
  degree-`2^30` polynomials with a square-root-time verifier — commentary from the field (Dan Boneh) frames
  this as the first point where a post-quantum SNARK plausibly outperforms a pre-quantum one on some axes,
  and describes a "lattice SNARK race" with rapid improvement since. Neither is referenced anywhere in
  FANOS's own OBOLOS design doc or code — this survey found no prior evaluation of either against the
  ring-BDLOP stack.

### 5.3 Verdict

**Split verdict, and the two halves must not be conflated.** The **accounting model** (what is committed,
what is revealed, the key hierarchy) is **`BEST-KNOWN`** — it already mirrors Orchard's hardened design at
the primitive level, not merely in spirit, per the code's own citations. The **proof backend that makes it
privacy-preserving today** is **`BEHIND`**, and by a stark, measured margin: FANOS ships **zero** privacy
currently (`TransparentProof` is "the accounting oracle every adversarial scenario checks against" — i.e.
the reference implementation reveals everything, by the design doc's own description), against Orchard's
live-since-2022, kilobyte-proof deployment. The gap is roughly **four to five orders of magnitude** in
proof size (145 MiB vs. Halo2's low-KB proofs), which is exactly why the shielded backend is correctly
marked `[P]` rather than shipped.

The more useful finding is `ADEQUATE-BUT-BETTER-EXISTS` on the **specific blocker**, not the whole
subsystem: the design doc's roadmap already identifies "recursive compaction" as the *only* route to a
shippable proof but names no construction. LaBRADOR/Greyhound are exactly that construction, purpose-built
for this shape (compose many small relations — a hash step, a range check, a membership path — into one
sublinear proof) and published in 2023–2025, i.e. concurrent with or after this design's own dated
sections. **What adopting it would cost:** it does not change OBOLOS's hardness assumptions (both stacks
reduce to Module-SIS/Module-LWE on a similar cyclotomic-ring family, so the note/nullifier/commitment layer
and its Orchard-derived properties are undisturbed) — it replaces the proof-*composition* layer, folding
the existing per-input `ring_note`/`ring_untraceable`/`ring_membership` sub-proofs and the balance/range
proofs through a LaBRADOR-style amortization rather than concatenating them directly. That is real,
nontrivial engineering — not a library swap — but it is confined to `fanos-obolos`'s proof layer; it does
not touch the ledger, the nullifier set, the tree, or TAXIS/DROMOS integration, all of which the design doc
already reports as complete and waiting on exactly this.

---

## 6. Erasure and storage — the `[7,3,4]` projective LRC vs. Azure LRC, Clay codes, and DA-sampling

### 6.1 What FANOS does

The base cell's store uses the **`[7,3,4]` projective LRC**, the simplex dual of Hamming(7,4): `N=7`,
`K=3`, redundancy `N/K = 7/3 ≈ 2.33×`, tolerating any ≤3 simultaneous point losses cell-wide
(`spec/protocol.md` §L4, §2.4). This is the deliberately *stronger* of two availability regimes the plane
supports: a lost point recovers from **any of its `q+1` disjoint lines** ("availability-`(q+1)`"), not just
one fixed recovery set ("availability-1", whose asymptotic floor is the oft-quoted `(q+1)/q → 1`) — the
platform explicitly trades that lower floor for the stronger multi-recovery-set guarantee, framed against
Gopalan et al.'s locality theory (IEEE Trans. IT 2012) and the multiple-disjoint-recovery-set framing of
Pámies-Juárez–Hollmann–Oggier (ISIT 2013). Repair is unoptimized beyond that: recovering one lost shard
reads the other `q` members of one full line and recomputes — no sub-packetization, no partial-symbol
transfer. Placement is the same `MapToPoint` coordinate the network already uses for consensus committees
and threshold-crypto lines, so the code's locality and the network's routing geometry are one structure,
not two. **The codec itself is Fano-specific** (`q=2` only) — larger objects scale by sharding across many
base cells, not by a bigger single code (`docs/design-storage.md` §10, an explicitly named honest limit).
Availability for the consensus-critical path is enforced by **full reconstruction** at every validator
(`docs/design-taxis.md` §6), not by sampling; sampling (`DA_SAMPLES=3`, soundness `(1/7)^k`) is used only
by the general-purpose L4 store for objects no single party is obligated to hold in full.

### 6.2 The current best known approach

- **Deployed cloud LRC.** Azure Storage's LRC (Huang, Simitci et al., USENIX ATC 2012) — a `(k, l, g)`
  scheme with local and global parity — was deployed first as `(16,12,6)` and then `(18,14,7)`, at
  **1.29× overhead** versus a comparable Reed-Solomon's 1.5×. It targets accidental single/occasional-double
  node loss in a datacenter, with one designated recovery group per fragment, not multiple disjoint ones.
- **Repair-bandwidth-optimal codes.** Clay codes (Vajha et al., "Moulding MDS Codes to Yield an MSR Code,"
  USENIX FAST 2018) are simultaneously optimal in storage overhead, repair bandwidth, and sub-packetization
  — deployed and measured in Ceph at **1.25× overhead** with a **2.9× reduction in repair network traffic**
  (3.4× in disk reads, 3× in repair time) versus a plain MDS code at similar overhead. (Honest caveat: the
  Ceph CLAY plugin has since been marked deprecated for removal in a later Ceph release — the construction's
  merit is independent of that one deployment's fate, but "currently shipping in Ceph" should not be
  overstated as a permanent fact.)
- **Data-availability sampling at scale.** Celestia's `rsmt2d` 2D Reed-Solomon encoding lets a light client
  confirm availability of a 4096-piece (64×64) block to 99% confidence from **15 samples**, reconstructing
  from any 75% of the extended data. Ethereum's PeerDAS (deployed December 2025) does the 1D analogue per
  blob (64 columns extended to 128, rate 1/2); full Danksharding's 2D scheme is the still-pending next
  step. Both are built for **light clients** — parties that hold none of the data and must gain confidence
  sublinearly.

### 6.3 Verdict

**Three separate axes, three separate verdicts — collapsing them into one number would misstate the
comparison.**

**Redundancy overhead (2.33× vs. Azure's 1.29–1.5×): not directly comparable, and calling it `BEHIND` would
be unfair.** FANOS is buying a strictly stronger property — recovery from *any* of `q+1` independent
lines, the multi-disjoint-recovery-set guarantee Pámies-Juárez–Hollmann–Oggier formalize — that Azure's
single-recovery-group LRC does not attempt, and it is buying that property *on the same geometric structure*
that also serves as the BFT committee and threshold-crypto substrate, a reuse Azure's storage-only system
has no reason to want. `ADEQUATE`, on a knowingly-paid, derived premium, not a defect.

**Repair bandwidth for a *given* redundancy: `ADEQUATE-BUT-BETTER-EXISTS`, and concretely so.** Nothing
about the plane's geometry forces the naive "read all `q` line-mates and recompute" repair procedure — Clay
codes show a repair-bandwidth-optimal (MSR) procedure is achievable *at* FANOS's own overhead class
(1.25× in the FAST18 evaluation, below FANOS's 2.33×) with a measured 2.9–3.4× cut in repair traffic and
time. **Cost of adopting:** this is a repair-*procedure* change layered on the existing projective
placement, not a placement or redundancy change — `MapToPoint`, the `[7,3,4]` distance/tolerance
properties, and the geometric reuse for consensus/threshold-crypto are all untouched; what changes is how a
recovering node reads and reconstructs (sub-packetized partial reads instead of whole-line reads). This
matters concretely for FANOS specifically because the platform's own self-healing loop (DIAKRISIS's
`Φ→Φ/9` reroute budget, `docs/architecture.md`) is latency- and bandwidth-sensitive during exactly the
degraded periods a repair fires in.

**Sampling at scale: `NOT ESTABLISHED` as a gap, because FANOS has not taken on the problem Celestia/
Danksharding solve.** Those systems build one enormous shared data-availability layer that light clients
with no data must gain sublinear confidence in; FANOS's own scaling strategy is the opposite — many small,
closed Fano (`q=2`) cells, each cheap enough for every validator to fully reconstruct, rather than one
large `q`. The `(1/7)^k` sampling bound the L4 store uses is a byproduct of that smallness, not an
independent achievement to compare against Celestia's 15-samples-per-4096-piece figure — the two systems
are sampling different-sized objects for different consumers (a full validator vs. a light client with
zero local data). **If FANOS ever wants a genuine light-client mode, or a single large-`q` cell** (which
`docs/design-storage.md` §10 already flags as not yet built), it would need Celestia/Danksharding-class
probabilistic sampling machinery it does not currently have reason to build — a forward-looking gap, not a
present one, and not one to close pre-emptively per the "do not recommend a rewrite lightly" rule.

---

## Verdict table

| # | Mechanism | Verdict | One-line reason |
|---|---|---|---|
| 1 | Consensus core (masking-quorum PBFT, `n=q²+q+1`) | `ADEQUATE` | right core at this committee size; DAG-BFT's win is bandwidth-driven and small at `n=7` |
| 1a | Consensus round protocol (3-phase) | `ADEQUATE-BUT-BETTER-EXISTS` | HotStuff-2/Jolteon (2023) collapse to 2 phases, `5δ` vs `7δ`+, no quorum-math change |
| 1b | Secret-leader election (min-ticket Merkle-VRF) | `BEST-KNOWN` | correctly rejects non-PQ/dominated alternatives (Whisk, Sassafras, Qelect) for this shape |
| 2 | The mixnet hop (`t`-of-`(q+1)` threshold line) | `BEST-KNOWN` | occupies a real literature gap (per-hop IT below threshold, multi-hop); costs 2–3 orders of magnitude in per-hop latency vs. Sphinx, declared not hidden |
| 3 | Receiver anonymity (NOSTOS geometric dead-drop) | `BEST-KNOWN`, with 2 open defects | no fixed mailbox host, unlike every PIR-based system surveyed; service-registration linkability and the blinding gap are real and named |
| 4a | PQ KEM/signature hybrid construction | `BEST-KNOWN` | KEM combiner matches the leading IETF draft (X-Wing) independently |
| 4b | PQ signature public-key blinding | `BEHIND`, field-wide | no audited lattice scheme; CSI-Otter (CRYPTO 2023, isogeny) is the nearest, at the cost of a second PQ hardness family |
| 5a | OBOLOS accounting model | `BEST-KNOWN` | tracks Zcash Orchard's hardened design at the primitive level, explicitly |
| 5b | OBOLOS proof backend | `BEHIND` | 145 MiB/proof vs. Halo2's low-KB, live since 2022; zero privacy currently ships |
| 6a | Erasure redundancy (2.33×) | `ADEQUATE` | pays for a strictly stronger multi-recovery-set property Azure's LRC doesn't attempt |
| 6b | Erasure repair bandwidth | `ADEQUATE-BUT-BETTER-EXISTS` | Clay codes (FAST 2018) get MSR-optimal repair at FANOS's own overhead class |
| 6c | DA sampling at scale | `NOT ESTABLISHED` | FANOS hasn't taken on the light-client/large-`q` problem Celestia/Danksharding solve |

---

## Ranked shortlist — best value ÷ disruption

**1. Collapse TAXIS's round protocol from three phases to two (HotStuff-2/Jolteon).**
Paper: Malkhi & Nayak, "HotStuff-2: Optimal Two-Phase Responsive BFT," IACR eprint 2023/397 (see also
Jolteon, FC 2022). Cost: confined to how PREPARE/COMMIT pipeline across views; `Q`, `f`, committee
selection, SSLE (§3.1), DA-gating (§6), and anti-MEV (§5) are all untouched — but TAXIS's own §4.1
proof-of-lock hardening shows this system's view-change edge cases bite in practice, so the new locking
invariant needs the same care, not a drop-in swap. Value: removes one full network round-trip from *every*
block's finality, unconditionally, on the path that gates DROMOS execution, OBOLOS settlement, and every
layer above consensus. **Worth doing once someone can re-derive the proof-of-lock argument for the
two-phase pipeline with the same rigor §4.1 already demonstrates this codebase can produce.**

**2. Adopt a LaBRADOR/Greyhound-style recursive proof composition for the OBOLOS spend proof.**
Papers: Beullens & Seiler, "LaBRADOR," CRYPTO 2023 (eprint 2022/1341); "Greyhound: Fast Polynomial
Commitments from Lattices," eprint 2024/1293. Cost: real, nontrivial engineering — folding the existing
`ring_note`/`ring_untraceable`/`ring_membership`/balance/range sub-proofs through an amortization layer
instead of concatenating them — but it changes no hardness assumption (still Module-SIS/Module-LWE, still
FANOS's own ring family) and touches nothing outside `fanos-obolos`'s proof layer; the ledger, nullifier
set, tree, and TAXIS/DROMOS integration are already built and waiting. Value: this is the named blocker
between OBOLOS and shipping *any* privacy — currently four to five orders of magnitude too large to be
gossipable, against a target the design doc's own roadmap already calls "the only route to a shippable
spend proof" without naming a construction. **Worth doing because it is not a maybe — it is the one thing
standing between the platform's crown-jewel subsystem and existing at all.**

**3. Replace the projective LRC's naive whole-line repair with an MSR/Clay-style sub-packetized procedure.**
Paper: Vajha et al., "Clay Codes: Moulding MDS Codes to Yield an MSR Code," USENIX FAST 2018. Cost: confined
to the repair path — `MapToPoint` placement, the `[7,3,4]` code's distance/tolerance properties, and the
geometric reuse of lines for consensus/threshold-crypto are all untouched; only how a recovering node reads
and reconstructs changes. Value: a measured 2.9–3.4× cut in repair bandwidth/time at a comparable overhead
class, which matters specifically because DIAKRISIS's self-healing loop is latency-sensitive during exactly
the degraded windows a repair fires in. **Worth doing as a bounded, self-contained optimization — lowest
disruption of the three, and the only one with no proof-theoretic re-derivation required.**

**Deliberately excluded from the shortlist, and why.** The PQ-signature-blinding gap (§3.3, §4.2) is real
but has no adoptable fix — CSI-Otter's cost (a second PQ hardness family) is not a "value ÷ disruption"
tradeoff, it is a standing research bet the whole field is behind on, correctly left as `docs/`-tracked
research rather than a change to cost here. A full DAG-BFT rewrite of TAXIS is excluded for the reason §1.3
gives: its main benefit does not compound at Fano's committee size, and the design doc's existing
cell-sharding answer already captures the throughput case DAG-BFT exists for. Upgrading SSLE to a
batch/whole-set scheme (Whisk, Sassafras) is excluded because the design doc already evaluated and
correctly rejected it as strictly dominated at `q+1 ≤ 8` — re-litigating a call the team already got right
would not be an improvement.
