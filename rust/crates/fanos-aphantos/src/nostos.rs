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
//!    ([`crate::threshold_onion::seal_onion`]) whose **final hop line is `L`**. Every return hop is a
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

use crate::threshold::ThresholdError;
use crate::threshold_onion::{HopLine, seal_onion};

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
///
/// `usable` is the caller's own condition on the result — in practice "every member of this line is in my
/// mix directory, so an onion can be sealed to it". It is a **parameter and not an afterthought** because a
/// drop line the peer cannot seal to is a reply path that carries nothing, for the whole life of the
/// session, in silence: `seal_forward` fails on a circuit if any member of any hop is missing, and the
/// client's drop line is that circuit's last hop. Callers with no such condition pass `|_| true` and say so.
///
/// The blinded index chooses where the search **starts**, not what it returns, so the walk costs no
/// unpredictability: an observer who cannot compute the digest cannot compute the starting point either, and
/// `usable` is a public property of the plane.
///
/// **`None` when no line through `receiver` qualifies**, and that is the whole point of the return type. It
/// used to fall back to the blinded choice — handing back an UNUSABLE line typed exactly like a usable one,
/// so a caller could not tell the two apart. Only `q + 1` lines pass through a point (three on the Fano
/// plane), so "none usable" is one absent directory entry away, not a degenerate corner. The hidden-service
/// host was the caller that did not re-check: it laid every circuit around an unsealable drop line, `onion`
/// then returned `None`, and the service went unregistered for the whole epoch without a word (#163).
#[must_use]
pub fn select_drop_line<F: Field>(
    receiver: Point<F>,
    shared_secret: &[u8],
    epoch: u64,
    beacon: &[u8],
    usable: impl Fn(Line<F>) -> bool,
) -> Option<Line<F>> {
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
    // Walk the `q+1` lines through `receiver` from the blinded index to the first the caller can use.
    // `lines_through` always yields exactly `q+1` and every index is reduced mod that, so `nth` is always
    // `Some`; the `Line::at(0)` fallback is unreachable and keeps the function total without an `unwrap`.
    (0..line_size).find_map(|k| {
        let line = Plane::<F>::lines_through(receiver).nth((idx + k) % line_size)?;
        usable(line).then_some(line)
    })
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
/// per reply (see [`seal_to_receiver`] and [`crate::threshold_onion::seal_onion`]).
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
    use crate::threshold_onion::{ThresholdPeel, member_partial, peel_onion, peel_onion_with_shares};
    use fanos_field::F2;

    /// A line of `n` KEM keypairs (a stand-in for a directory of the line's members).
    fn line_members(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[seed, i as u8]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect()
    }

    /// **What the ACCEPT branch of `rendezvous_host`'s loop pays — the other half of #248's ratio.**
    ///
    /// `open_forwarded` walks a ring of `MAX_REPLY_KEYS = 1 + HOST_GRACE_EPOCHS = 2` keys and calls
    /// [`ReplyKeys::open`] on each until one succeeds, so a **hit** costs one or two decapsulations and a
    /// **miss** — a direct request, which is not dead-dropped at all — costs the whole ring and then returns
    /// the payload unchanged. `fanos-rendezvous`'s `measure_the_cost_of_sealing_one_reply` measured the
    /// other arm and deliberately said this one was NOT measured; without it, "the accept branch is 5000x
    /// cheaper" is a claim about `ingest` alone rather than about accepting a request.
    ///
    /// A `measure_` name: prints for a person, never gates. Run on a quiet box —
    /// `cargo test -p fanos-aphantos --release measure_ -- --nocapture`.
    #[test]
    fn measure_the_cost_of_opening_a_dead_dropped_request() {
        use std::time::Instant as Clock;

        const ROUNDS: u32 = 50;
        /// `fanos_node::rendezvous_host::MAX_REPLY_KEYS`, restated because that crate depends on this one
        /// and not the other way round. A measurement, not a bound — nothing derives from this copy.
        const RING: usize = 2;

        let ring: Vec<(ReplyKeys, HybridKemPublic)> =
            (0..RING).map(|i| ReplyKeys::generate(&[b'e', i as u8])).collect();
        // Sealed to the key the walk reaches LAST, so the hit costs the whole ring. Sealing to the first —
        // the obvious fixture — measures the cheapest hit and reads as if the ring were free.
        let sealed = seal_to_receiver(&ring[RING - 1].1, b"a forwarded request", b"a-fresh-seed-per-reply")
            .expect("the e2e seal succeeds");
        // A direct request is not dead-dropped, so every key in the ring refuses it. **It must be long
        // enough to reach decapsulation**: `ReplyKeys::open` slices `..CIPHERTEXT_LEN` first, so a short
        // payload is rejected on length before any crypto runs — the first version of this fixture was 44
        // bytes and measured 0.0 us, which was the length check, not the ring. A production direct request
        // carrying a real DIAULOS body is comfortably past that boundary.
        let direct = vec![0xABu8; CIPHERTEXT_LEN + 64];

        let walk = |payload: &[u8]| {
            for (keys, _) in &ring {
                if let Some(opened) = keys.open(payload) {
                    return Some(opened);
                }
            }
            None
        };
        assert!(walk(&sealed).is_some(), "the hit case must actually open");
        assert!(walk(&direct).is_none(), "the miss case must actually walk the whole ring");

        for (name, payload) in [("hit (dead-dropped)", &sealed), ("MISS (direct request)", &direct)] {
            let start = Clock::now();
            for _ in 0..ROUNDS {
                let _ = walk(payload);
            }
            let each = start.elapsed() / ROUNDS;
            println!(
                "MEASURE open_forwarded {name}: {:>8.1} us each over {ROUNDS} rounds, ring of {RING} (#248)",
                each.as_secs_f64() * 1e6
            );
        }
    }

    /// The receiver's dead-drop line always passes through the receiver, and depends on *both* the
    /// coordinate and the shared secret + beacon (the two independent blinds).
    #[test]
    fn the_drop_line_is_the_receivers_own_line_and_is_beacon_blinded() {
        let r = Point::<F7>::at(11);
        let l = select_drop_line(r, b"shared-secret", 7, b"beacon-epoch-7", |_| true).expect("every line usable");
        assert!(r.is_on(&l), "the receiver is a member of its own dead-drop line");

        // A different shared secret, epoch, or beacon can move the line — and whatever it is, the
        // receiver is still on it (it is always one of R's own q+1 lines).
        let l_other_secret = select_drop_line(r, b"other-secret", 7, b"beacon-epoch-7", |_| true).expect("usable");
        let l_other_epoch = select_drop_line(r, b"shared-secret", 8, b"beacon-epoch-8", |_| true).expect("usable");
        assert!(r.is_on(&l_other_secret));
        assert!(r.is_on(&l_other_epoch));
        // Over the q+1 = 8 lines, the blinds land on more than one line (not a constant) — sampled
        // across secrets so the assertion does not hinge on one arbitrary pair colliding.
        let mut seen = alloc::collections::BTreeSet::new();
        for s in 0u8..16 {
            seen.insert(select_drop_line(r, &[s], 7, b"b", |_| true).expect("usable").coords());
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

    /// When NOTHING is usable, the answer is `None` — not a line the caller cannot use.
    ///
    /// The complement of `a_drop_line_is_always_one_the_caller_can_use`, and the half that did not exist.
    /// The old fallback returned the blinded line when the walk found nothing, typed identically to a usable
    /// one, so a caller had no way to distinguish "here is your line" from "nothing worked" (#163). Only
    /// `q + 1` lines pass through a point — three on Fano — so this state is one absent directory entry
    /// away, not a pathological input.
    ///
    /// Assert the `Some` side in the same test, or a `select_drop_line` that returned `None` unconditionally
    /// would satisfy the interesting half.
    #[test]
    fn no_usable_line_yields_none_rather_than_an_unusable_one() {
        for p in 0..57usize {
            let r = Point::<F7>::at(p);
            assert!(
                select_drop_line(r, b"secret", 7, b"beacon", |_| false).is_none(),
                "point {p}: with every line rejected there is no drop line, and saying so is the contract"
            );
            assert!(
                select_drop_line(r, b"secret", 7, b"beacon", |_| true).is_some(),
                "point {p}: …and with every line accepted there certainly is one"
            );
        }
    }

    /// The end-to-end round trip: a reply threshold-routed to the receiver's line is opened by the
    /// receiver — and by no one else, including the members of the delivery line who peel the onion.
    /// **The chosen drop line must be one the caller can use**, and the blinded index must only decide where
    /// the search starts.
    ///
    /// A drop line is the last hop of the reply circuit, and `seal_forward` fails on the whole circuit if any
    /// member of any hop is missing — so an unusable choice is a reply path that carries nothing for the life
    /// of the session, silently. The index alone cannot guarantee that, because it is a hash.
    ///
    /// Two properties, and the second is what stops the fix from being a downgrade:
    ///   * every line returned satisfies `usable`, for every receiver and every rejected subset;
    ///   * the choice still depends on the secret — two secrets that would start at different indices must
    ///     not be collapsed onto one answer by the walk.

    #[test]
    fn a_drop_line_is_always_one_the_caller_can_use() {
        use alloc::collections::BTreeSet;
        for p in 0..57usize {
            let r = Point::<F7>::at(p);
            // Reject all but one of the receiver's lines: the walk has to find it wherever it starts.
            let only = Plane::<F7>::lines_through(r).next().expect("a point lies on q+1 lines");
            for secret in 0u8..32 {
                let l = select_drop_line(r, &[secret], 7, b"beacon", |cand| cand.coords() == only.coords())
                    .expect("exactly one line is permitted and it is reachable from any start");
                assert_eq!(
                    l.coords(),
                    only.coords(),
                    "point {p}, secret {secret}: the walk must reach the one usable line, not stop at the \
                     blinded index"
                );
                assert!(r.is_on(&l), "the drop line must still pass through the receiver");
            }
        }

        // And with nothing rejected, the secret must still spread the choice — a walk that always returned
        // the same line would satisfy the assertion above while destroying the blinding it is built on.
        let r = Point::<F7>::at(11);
        let spread: BTreeSet<_> =
            (0u8..64).map(|s| select_drop_line(r, &[s], 7, b"b", |_| true).expect("usable").coords()).collect();
        assert!(
            spread.len() > 1,
            "the blinded index must still choose: {} distinct lines over 64 secrets",
            spread.len()
        );
    }

    #[test]
    fn a_reply_comes_home_and_only_the_receiver_opens_it() {
        let t = 3u8;
        // The receiver and its dead-drop line L (a real line through R).
        let r = Point::<F7>::at(11);
        let l = select_drop_line(r, b"session-key", 7, b"beacon-7", |_| true).expect("usable");
        assert!(r.is_on(&l));

        // The receiver's ephemeral reply key (the end-to-end seal target).
        let (reply_keys, reply_pub) = ReplyKeys::generate(b"reply-keypair-seed");

        // Two return hops: one intermediate mix line, then the delivery line L.
        //
        // Lines of 3 (the Fano plane), not 8. A reply needs **two** slots of the fixed-slot onion header, and
        // `slots::depth_for` reserves one nested threshold seal of payload — so a plane whose lines hold 8 points carries
        // only a single hop inside `THRESHOLD_ONION_LEN` and cannot express this circuit at all. That is a genuine budget
        // constraint on wide planes (recorded against the plane-order decision), not a property of the reply mechanism this
        // test is about.
        let mix = line_members(3, 40);
        let drop = line_members(3, 41);
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
        let inner_onion = match peel_onion::<F2>(&onion, &mix_secrets).unwrap() {
            ThresholdPeel::Forward { onion, .. } => crate::threshold::pad_onion(&onion).unwrap(),
            ThresholdPeel::Deliver { .. } => panic!("the first hop forwards, it does not deliver"),
        };

        // The delivery line's members gather partials; the combiner peels the final layer and gets
        // only the END-TO-END CIPHERTEXT (the dead-drop), which it multicasts to points_on(L).
        let partials: Vec<_> = (0..usize::from(t))
            .map(|i| member_partial::<F2>(&inner_onion, i, &drop[i].0).unwrap())
            .collect();
        let delivered = match peel_onion_with_shares::<F2>(&inner_onion, &partials).unwrap() {
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

        // **And this is what carries delivery INTEGRITY on the shipped path, so it is asserted here rather
        // than assumed.** Spec §5.4's path authenticator is verified by "a verifier that already knows the
        // circuit" — in §5.6's rendezvous that is both endpoints, because the meeting line is derived from a
        // shared secret. NOSTOS deliberately does not derive the circuit: the return hops are drawn freshly,
        // because a predictable circuit is a targetable one. So no party at delivery holds the circuit, the
        // holonomy check has no verifier on this path, and the guarantee that a delivered body is the one the
        // sender sealed rests entirely on this AEAD.
        //
        // A stronger guarantee than the holonomy, incidentally: the path authenticator says "it came the
        // agreed way", this says "it came from the party holding the agreed key".
        for i in [0usize, e2e_ciphertext.len() / 2, e2e_ciphertext.len() - 1] {
            let mut tampered = e2e_ciphertext.to_vec();
            tampered[i] ^= 0x01;
            assert_eq!(
                reply_keys.open(&tampered),
                None,
                "a dead-drop body altered at byte {i} must not open — this is the delivery integrity the \
                 shipped reply path actually has",
            );
        }
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
        let l = select_drop_line(r, b"s", 1, b"b", |_| true).expect("usable");
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
        assert_eq!(peel_onion::<F7>(&onion, &too_few), Err(ThresholdError::Aead));
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
