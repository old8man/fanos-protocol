//! # NOSTOS (νόστος, "the homecoming") — derived-native **receiver anonymity**.
//!
//! A reply "comes home" to its receiver `R` without any relay, the replying peer, or a network
//! observer ever learning `R`'s coordinate. It is **not** a Sphinx single-use reply block (which
//! routes through single relays to a coordinate the delivery node learns, and which Kuhn et al.
//! *IEEE S&P 2020* showed is deanonymizable by reply-payload tampering). It is derived from
//! FANOS's own structure — the projective plane `PG(2, q)`, the below-threshold-ZK line hop
//! ([`crate::threshold`]), and the VRF-rotated coordinate.
//!
//! ## The construction
//!
//! 1. **The dead-drop is the receiver's own line.** `R` picks one of the `q+1` lines through its
//!    point, `L ∈ lines_through(R)`, with the index **blinded by a secret it shares with the
//!    peer and the epoch beacon** ([`select_drop_line`]). Because `L` passes through `R`, `R` is a
//!    member of `L`'s `q+1`-node multicast bus and receives anything delivered to `L`
//!    *passively* — no active anonymous polling. `R` is hidden as **1-of-`(q+1)`** on `L`.
//! 2. **The reply is threshold-routed to `L`.** The peer wraps the reply in a threshold onion
//!    ([`crate::threshold::seal_onion`]) whose **final hop line is `L`**. Every return hop is a
//!    line, peeled `t`-of-`(q+1)`; below `t` a corrupt subset learns *nothing* about the next hop
//!    (real ZK, [`crate::threshold`]).
//! 3. **Only `R` can read it — not even `L`'s members.** The reply is first **end-to-end sealed**
//!    to `R`'s ephemeral reply key ([`seal_to_receiver`] / [`ReplyKeys`]). The threshold members of
//!    `L` who peel the final layer obtain only that *ciphertext* — a **geometric dead-drop** — and
//!    multicast it to `points_on(L)`. `R`, one of the `q+1`, decrypts; every other member (and the
//!    combiner) sees only ciphertext.
//!
//! ## What is hidden, and from whom (the honest scope)
//!
//! * `R`'s coordinate never appears on the wire. The replying peer learns only the **line `L`**, so
//!   even the peer's knowledge of `R` is the `q+1`-member anonymity set of `L`.
//! * The information-theoretic guarantee is **per hop**: below `t` members of any return line, the
//!   joint view is independent of that layer's next hop (Shamir-perfect, KEM-sealed shares). The
//!   reply *body* between hops is a ciphertext, so end-to-end unlinkability across the whole path is
//!   *computational* — the correct claim is "per-hop below-threshold IT secrecy composed with
//!   computational onion security", never "IT end-to-end".
//! * **The blinding precondition is not optional** (Gnilke et al. *DCC 2019*: a naked unique-meet
//!   over a projective plane is a deanonymization primitive). Here two independent blinds hold: `R`
//!   itself is `MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))` (needs `R`'s VRF secret), and the choice
//!   of *which* of `R`'s `q+1` lines needs the shared secret. So `L` is unpredictable to anyone who
//!   lacks *both*, and it rotates each epoch with `R`.
//! * **Cross-epoch intersection resistance is a theorem, not a free lunch** (design `T3`). Because
//!   the peer is handed only *one* of `R`'s lines per epoch (two would leak `R = L₁.meet(L₂)`), and
//!   because `R`'s coordinate rotates, a static drop cannot be intersected within an epoch; the
//!   cross-epoch bound rests on session-unlinkability (the mix lane) and the threshold hop's
//!   exponentially-small break probability. This module provides the mechanism; the bound is proven
//!   separately.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point};
use fanos_pqcrypto::kem::CIPHERTEXT_LEN;
use fanos_pqcrypto::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_primitives::hash_labeled;

use crate::threshold::{HopLine, ThresholdError, seal_onion};

/// AEAD nonce width (matches [`crate::threshold`]).
const NONCE_LEN: usize = 12;

/// Domain labels — one source of truth so seal and open can never drift onto different derivations.
const E2E_SEED_LABEL: &str = "FANOS-v1/nostos-e2e-seed";
const ONION_SEED_LABEL: &str = "FANOS-v1/nostos-onion-seed";
const E2E_KEY_LABEL: &str = "FANOS-v1/nostos-e2e-key";
const E2E_NONCE_LABEL: &str = "FANOS-v1/nostos-e2e-nonce";
const DROP_LINE_LABEL: &str = "FANOS-v1/nostos-drop-line";

/// Select the receiver's **dead-drop line** — one of the `q+1` lines through its point `R`, with
/// the index blinded by the secret `R` shares with the peer and the epoch `beacon` (spec §5, NOSTOS).
///
/// The returned line always passes through `R` (`R.is_on(&L)`), so `R` receives deliveries to `L`
/// as a member of its multicast bus. Only a party that knows **both** `R` *and* `shared_secret` can
/// compute `L`; a network observer sees `L` on the wire but learns only that `R ∈ points_on(L)` — the
/// `q+1`-member anonymity set. **Caller invariant:** hand a peer at most *one* of `R`'s lines
/// (per contact), because any two of them meet exactly at `R` (`L₁.meet(L₂) == R`) — handing out two
/// would leak the coordinate NOSTOS exists to hide.
#[must_use]
pub fn select_drop_line<F: Field>(
    receiver: Point<F>,
    shared_secret: &[u8],
    epoch: u64,
    beacon: &[u8],
) -> Line<F> {
    let mut material = Vec::with_capacity(shared_secret.len() + 8 + beacon.len());
    material.extend_from_slice(shared_secret);
    material.extend_from_slice(&epoch.to_be_bytes());
    material.extend_from_slice(beacon);
    let digest = hash_labeled(DROP_LINE_LABEL, &material);
    // `q + 1` lines pass through any point; pick one by the blinded digest. The high 8 bytes give a
    // uniform-enough index for the small `q+1` modulus.
    let line_size = Plane::<F>::LINE_SIZE as usize;
    let raw = u64::from_be_bytes(
        digest
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 8]),
    );
    let idx = (raw % line_size as u64) as usize;
    // `lines_through` always yields exactly `q+1` lines and `idx < q+1`, so `nth` is always `Some`;
    // the `Line::at(0)` fallback is unreachable but keeps the function total without an `unwrap`.
    Plane::<F>::lines_through(receiver)
        .nth(idx)
        .unwrap_or_else(|| Line::<F>::at(0))
}

/// The receiver's **ephemeral reply key** — a fresh hybrid-KEM keypair whose public half travels to
/// the peer inside the reply handle and whose secret half stays with the receiver. It is what makes
/// the dead-drop end-to-end: the threshold members of the delivery line obtain only ciphertext sealed
/// to this key, so they (and the combiner) cannot read the reply — only the receiver can.
///
/// Distinct from the receiver's long-term line-member KEM key: that authenticates its slot on the
/// line; this seals the reply *body*. Generate a **fresh** `ReplyKeys` per reply handle.
pub struct ReplyKeys {
    secret: HybridKemSecret,
}

impl ReplyKeys {
    /// Derive a fresh reply keypair from `seed` (a real CSPRNG draw in production; a fixed seed under
    /// the deterministic simulator). Returns the keypair and the public half to place in the handle.
    #[must_use]
    pub fn generate(seed: &[u8]) -> (Self, HybridKemPublic) {
        let mut rng = SeedRng::from_seed(seed);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        (Self { secret }, public)
    }

    /// Open the end-to-end-sealed reply body delivered to the dead-drop line. Returns the plaintext,
    /// or `None` if this key did not seal it (a different member's ciphertext, or tamper). Only the
    /// receiver holding this key succeeds — every other member of the line sees just ciphertext.
    #[must_use]
    pub fn open(&self, inner: &[u8]) -> Option<Vec<u8>> {
        let kem_ct = HybridCiphertext::from_bytes(inner.get(..CIPHERTEXT_LEN)?)?;
        let session = self.secret.decapsulate(&kem_ct)?;
        let key = hash_labeled(E2E_KEY_LABEL, &session);
        let nonce = e2e_nonce(&session)?;
        let ct = inner.get(CIPHERTEXT_LEN..)?;
        fanos_primitives::aead::open(&key, &nonce, ct)
    }
}

/// The AEAD nonce for the end-to-end layer, derived from the KEM session so both parties compute it
/// without a shared nonce on the wire (the fresh per-reply session keeps `(key, nonce)` unique).
fn e2e_nonce(session: &[u8; 32]) -> Option<[u8; NONCE_LEN]> {
    hash_labeled(E2E_NONCE_LABEL, session)
        .get(..NONCE_LEN)
        .and_then(|b| b.try_into().ok())
}

/// **End-to-end seal** `payload` so that only the holder of the matching [`ReplyKeys`] can open it —
/// a hybrid-KEM encapsulation to `reply_pub` then AEAD under a session-derived key:
/// `inner = kem_ct ‖ AEAD(k(session), n(session), payload)`.
///
/// `seed` MUST be a fresh CSPRNG draw per call: the session (hence the AEAD `(key, nonce)`) is
/// deterministic in it, so a repeated seed with a different payload reuses a one-time nonce.
///
/// # Errors
/// [`ThresholdError::NonContributory`] if the KEM's X25519 leg is non-contributory; [`ThresholdError::Aead`]
/// if sealing fails.
pub fn seal_to_receiver(
    reply_pub: &HybridKemPublic,
    payload: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    let mut rng = SeedRng::from_seed(seed);
    let (kem_ct, session) = reply_pub
        .encapsulate(&mut rng)
        .ok_or(ThresholdError::NonContributory)?;
    let key = hash_labeled(E2E_KEY_LABEL, &session);
    let nonce = e2e_nonce(&session).ok_or(ThresholdError::Malformed)?;
    let ct = fanos_primitives::aead::seal(&key, &nonce, payload).ok_or(ThresholdError::Aead)?;
    let mut out = Vec::with_capacity(CIPHERTEXT_LEN + ct.len());
    out.extend_from_slice(&kem_ct.to_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The 4-byte marker prefixing a NOSTOS dead-drop payload. When a threshold onion delivers a payload
/// carrying this prefix, the delivery line's combiner **multicasts the remaining bytes** (the
/// end-to-end sealed reply) to `points_on(line)` — the receiver, hidden 1-of-`(q+1)`, decrypts —
/// rather than consuming the delivery itself. It marks the *delivery mode*, not the reply content;
/// reply integrity is the end-to-end AEAD ([`ReplyKeys::open`]), which is why an anonymous sender who
/// cannot MAC an unknown reply still gets tamper-evidence ("implicit integrity", Kuhn et al. ASIACRYPT'21).
pub const DEADDROP_TAG: [u8; 4] = *b"NDD1";

/// Wrap an end-to-end-sealed reply body in the dead-drop envelope ([`DEADDROP_TAG`] ‖ body).
#[must_use]
pub fn deaddrop_envelope(e2e_ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEADDROP_TAG.len() + e2e_ct.len());
    out.extend_from_slice(&DEADDROP_TAG);
    out.extend_from_slice(e2e_ct);
    out
}

/// If `payload` is a dead-drop envelope, return its end-to-end body (the bytes after [`DEADDROP_TAG`]);
/// otherwise `None` (a normal delivery, consumed in place by the delivering line's combiner).
#[must_use]
pub fn parse_deaddrop(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(&DEADDROP_TAG)
}

/// Seal a full **NOSTOS reply**: end-to-end seal `payload` to the receiver, wrap it in the dead-drop
/// envelope, then wrap *that* in a threshold onion over `return_hops` whose final hop is the receiver's
/// dead-drop line `L`.
///
/// The peer calls this with the reply handle the receiver gave it: `reply_pub` (the [`ReplyKeys`]
/// public), `return_hops` (the return circuit ending at `L`, built by the receiver so it controls
/// its own path home), and `threshold`. `L`'s combiner recognizes the [`DEADDROP_TAG`] and multicasts
/// only the end-to-end ciphertext to `points_on(L)`; only the receiver opens it. `seed` MUST be fresh
/// per reply (see [`seal_to_receiver`] and [`crate::threshold::seal_onion`]).
///
/// # Errors
/// Propagates [`ThresholdError`] from the end-to-end seal or the onion build (e.g. [`ThresholdError::TooLong`]
/// if the return path is too deep for the fixed onion bucket).
pub fn seal_reply(
    reply_pub: &HybridKemPublic,
    return_hops: &[HopLine<'_>],
    threshold: u8,
    payload: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    // Separate the end-to-end seed from the onion seed so neither reuses the other's key material.
    let e2e_seed = hash_labeled(E2E_SEED_LABEL, seed);
    let onion_seed = hash_labeled(ONION_SEED_LABEL, seed);
    let inner = seal_to_receiver(reply_pub, payload, &e2e_seed)?;
    // The dead-drop envelope tells the delivery line's combiner to multicast the E2E body to the
    // line's q+1 members (the geometric dead-drop) instead of consuming it.
    let enveloped = deaddrop_envelope(&inner);
    seal_onion(return_hops, threshold, &enveloped, &onion_seed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use fanos_field::F7;
    use fanos_geometry::Point;

    use super::*;
    use crate::threshold::{ThresholdPeel, member_partial, peel_onion, peel_onion_with_shares};

    /// A line of `n` KEM keypairs (a stand-in for a directory of the line's members).
    fn line_members(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[seed, i as u8]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect()
    }

    /// The receiver's dead-drop line always passes through the receiver, and depends on *both* the
    /// coordinate and the shared secret + beacon (the two independent blinds).
    #[test]
    fn the_drop_line_is_the_receivers_own_line_and_is_beacon_blinded() {
        let r = Point::<F7>::at(11);
        let l = select_drop_line(r, b"shared-secret", 7, b"beacon-epoch-7");
        assert!(r.is_on(&l), "the receiver is a member of its own dead-drop line");

        // A different shared secret, epoch, or beacon can move the line — and whatever it is, the
        // receiver is still on it (it is always one of R's own q+1 lines).
        let l_other_secret = select_drop_line(r, b"other-secret", 7, b"beacon-epoch-7");
        let l_other_epoch = select_drop_line(r, b"shared-secret", 8, b"beacon-epoch-8");
        assert!(r.is_on(&l_other_secret));
        assert!(r.is_on(&l_other_epoch));
        // Over the q+1 = 8 lines, the blinds land on more than one line (not a constant) — sampled
        // across secrets so the assertion does not hinge on one arbitrary pair colliding.
        let mut seen = alloc::collections::BTreeSet::new();
        for s in 0u8..16 {
            seen.insert(select_drop_line(r, &[s], 7, b"b").coords());
        }
        assert!(seen.len() > 1, "the blinded index actually varies the line");
    }

    /// Two of the receiver's own lines meet exactly at the receiver — the pairwise-meet trap the
    /// caller invariant (hand out only one line) exists to avoid. This pins *why* the invariant holds.
    #[test]
    fn any_two_of_the_receivers_lines_meet_at_the_receiver() {
        let r = Point::<F7>::at(23);
        let lines: Vec<Line<F7>> = Plane::<F7>::lines_through(r).collect();
        for i in 0..lines.len() {
            for j in (i + 1)..lines.len() {
                assert_eq!(
                    lines[i].meet(&lines[j]),
                    Some(r),
                    "handing a peer two of R's lines would reveal R = L_i ∩ L_j",
                );
            }
        }
    }

    /// The end-to-end round trip: a reply threshold-routed to the receiver's line is opened by the
    /// receiver — and by no one else, including the members of the delivery line who peel the onion.
    #[test]
    fn a_reply_comes_home_and_only_the_receiver_opens_it() {
        let t = 3u8;
        // The receiver and its dead-drop line L (a real line through R).
        let r = Point::<F7>::at(11);
        let l = select_drop_line(r, b"session-key", 7, b"beacon-7");
        assert!(r.is_on(&l));

        // The receiver's ephemeral reply key (the end-to-end seal target).
        let (reply_keys, reply_pub) = ReplyKeys::generate(b"reply-keypair-seed");

        // Two return hops: one intermediate mix line, then the delivery line L. Each is a line of
        // q+1 = 8 members with a KEM keypair apiece.
        let mix = line_members(8, 40);
        let drop = line_members(8, 41);
        let mix_pub: Vec<&HybridKemPublic> = mix.iter().map(|(_, p)| p).collect();
        let drop_pub: Vec<&HybridKemPublic> = drop.iter().map(|(_, p)| p).collect();
        let return_hops = [
            HopLine {
                line: Line::<F7>::at(3).coords(),
                members: &mix_pub,
            },
            HopLine {
                line: l.coords(),
                members: &drop_pub,
            },
        ];

        let payload = b"the homecoming reply";
        let onion = seal_reply(&reply_pub, &return_hops, t, payload, b"fresh-reply-seed").unwrap();

        // Peel the intermediate mix hop (a threshold subset of its members).
        let mix_secrets: Vec<(usize, &HybridKemSecret)> = mix
            .iter()
            .take(usize::from(t))
            .enumerate()
            .map(|(i, (sk, _))| (i, sk))
            .collect();
        let inner_onion = match peel_onion(&onion, &mix_secrets).unwrap() {
            ThresholdPeel::Forward { onion, .. } => crate::threshold::pad_onion(&onion).unwrap(),
            ThresholdPeel::Deliver { .. } => panic!("the first hop forwards, it does not deliver"),
        };

        // The delivery line's members gather partials; the combiner peels the final layer and gets
        // only the END-TO-END CIPHERTEXT (the dead-drop), which it multicasts to points_on(L).
        let partials: Vec<_> = (0..usize::from(t))
            .map(|i| member_partial(&inner_onion, i, &drop[i].0).unwrap())
            .collect();
        let delivered = match peel_onion_with_shares(&inner_onion, &partials).unwrap() {
            ThresholdPeel::Deliver { payload, .. } => payload,
            ThresholdPeel::Forward { .. } => panic!("the final hop delivers"),
        };
        // The combiner of L recognizes the dead-drop envelope and multicasts only the E2E body to
        // points_on(L); the receiver — one of the q+1 — opens it.
        let e2e_ciphertext = parse_deaddrop(&delivered).expect("the reply is a dead-drop envelope");
        assert_eq!(
            reply_keys.open(e2e_ciphertext).as_deref(),
            Some(&payload[..]),
            "the receiver recovers the reply intact",
        );
        // No one else can: neither the combiner nor any other member of L (a different reply key).
        let (foreign_keys, _) = ReplyKeys::generate(b"someone-else");
        assert_eq!(
            foreign_keys.open(e2e_ciphertext),
            None,
            "the delivering line and every non-receiver see only ciphertext",
        );
    }

    /// Below threshold, a return hop's members cannot peel — the reply's routing is ZK to any
    /// `< t`-member subset of a line (inherited from the threshold onion, pinned here for NOSTOS).
    #[test]
    fn below_threshold_return_hop_members_learn_nothing() {
        let t = 4u8;
        let (_, reply_pub) = ReplyKeys::generate(b"rk");
        let drop = line_members(8, 50);
        let drop_pub: Vec<&HybridKemPublic> = drop.iter().map(|(_, p)| p).collect();
        let r = Point::<F7>::at(5);
        let l = select_drop_line(r, b"s", 1, b"b");
        let return_hops = [HopLine {
            line: l.coords(),
            members: &drop_pub,
        }];
        let onion = seal_reply(&reply_pub, &return_hops, t, b"secret", b"seed").unwrap();
        // Only t-1 members cooperate: the reconstructed key is wrong, AEAD auth fails — no routing
        // command, no payload, nothing.
        let too_few: Vec<(usize, &HybridKemSecret)> = drop
            .iter()
            .take(usize::from(t) - 1)
            .enumerate()
            .map(|(i, (sk, _))| (i, sk))
            .collect();
        assert_eq!(peel_onion(&onion, &too_few), Err(ThresholdError::Aead));
    }

    /// The end-to-end seal is opaque to the delivery line even with the full onion in hand: the
    /// threshold members peel to a ciphertext that carries no plaintext of the reply.
    #[test]
    fn the_delivering_line_cannot_read_the_reply() {
        let (reply_keys, reply_pub) = ReplyKeys::generate(b"rk2");
        let plaintext = b"top secret homecoming";
        let inner = seal_to_receiver(&reply_pub, plaintext, b"e2e-seed").unwrap();
        // The end-to-end block never contains the plaintext verbatim.
        assert!(
            !inner.windows(plaintext.len()).any(|w| w == plaintext),
            "the reply plaintext must not appear in the sealed dead-drop block",
        );
        // Only the receiver's key recovers it.
        assert_eq!(reply_keys.open(&inner).as_deref(), Some(&plaintext[..]));
    }
}
