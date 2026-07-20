//! Threshold-hosted CALYPSO end to end over the sim overlay (spec §12.3): a service hosted `t`-of-
//! `(q+1)` across its service-line, with no single member ever alone. A client seals its `RDV_INTRO`
//! to the whole line (`fanos_calypso::hosting::SealedIntro`); the line's designated combiner gathers
//! `t` members' PartialDecs over the network, recovers the intro, "delivers" it to the service
//! application, and replies — the request/response completes. The below-threshold scenario shows the
//! same service-line, with too few members reachable, never completing at all: the service *is* the
//! line, not any one member.
//!
//! **Scope.** This exercises mechanism 2 of `fanos_calypso::hosting` — per-intro threshold
//! decryption, the thing that needs live network cooperation. Mechanism 1 (dealt-and-sealed
//! **identity**-secret custody, `deal_service_key`/`open_service_share`/`recover_service_key`) has no
//! wire protocol of its own — dealing is a one-time bootstrap step and recovery is a local combine —
//! so its own positive/below-threshold controls are already exercised directly in
//! `fanos-calypso/src/hosting.rs`'s unit tests; re-running them over the network here would add a
//! wire wrapper around the same local computation, not exercise anything new.
//!
//! This test builds its own minimal `ServiceMember`/`Client` engines — a combiner-gather protocol
//! mirroring `fanos_aphantos::threshold_router::ThresholdRouter`, simplified for this demonstration
//! (a single in-flight intro per member; no req-id multiplexing, no mixing/cover traffic — those are
//! NYX transport concerns, orthogonal to CALYPSO's own threshold-hosting crypto) — rather than wiring
//! into `fanos_rendezvous::RendezvousService`, which (per the integration TODO on
//! `fanos_calypso::hosting`) still needs that live-wiring pass; `ServiceMember` here is the worked
//! template for it.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fanos_calypso::hosting::{SealedIntro, Share};
use fanos_field::F2;
use fanos_geometry::{Point, Triple};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_primitives::hash_labeled;
use fanos_runtime::{Duration, Effect, Engine, Input, Instant, Notification};
use fanos_sim::Sim;
use fanos_wire::Wire;

// --- minimal hand-rolled framing (test-only scaffolding around the real `fanos_calypso::hosting`
// crypto; production wiring is the deferred `RendezvousService` integration) ---

const TAG_INTRO: u8 = 0;
const TAG_REQ: u8 = 1;
const TAG_REP: u8 = 2;
const TAG_REPLY: u8 = 3;

fn encode_intro(intro: &SealedIntro) -> Vec<u8> {
    let mut v = vec![TAG_INTRO];
    v.extend_from_slice(&intro.to_wire());
    v
}

fn decode_intro(body: &[u8]) -> Option<SealedIntro> {
    SealedIntro::from_wire(body).ok()
}

fn encode_req(combiner: Triple, intro: &SealedIntro) -> Vec<u8> {
    let mut v = vec![TAG_REQ];
    v.extend_from_slice(&fanos_geometry::encode_triple(combiner));
    v.extend_from_slice(&intro.to_wire());
    v
}

fn decode_req(body: &[u8]) -> Option<(Triple, SealedIntro)> {
    let combiner = fanos_geometry::decode_triple(body.get(..12)?)?;
    let intro = SealedIntro::from_wire(body.get(12..)?).ok()?;
    Some((combiner, intro))
}

fn encode_rep(share: &Share) -> Vec<u8> {
    let mut v = vec![TAG_REP, share.x()];
    v.extend_from_slice(share.y());
    v
}

fn decode_rep(body: &[u8]) -> Option<Share> {
    let (&x, y) = body.split_first()?;
    Some(Share::new(x, y.to_vec()))
}

fn encode_reply(nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let mut v = vec![TAG_REPLY];
    v.extend_from_slice(nonce);
    v.extend_from_slice(ciphertext);
    v
}

fn decode_reply(body: &[u8]) -> Option<([u8; 12], &[u8])> {
    let nonce: [u8; 12] = body.get(..12)?.try_into().ok()?;
    Some((nonce, body.get(12..)?))
}

/// The client's reply-key/nonce derivation: `H(label ‖ cookie)`. Both the client (who chose the
/// cookie) and the combiner (who learned it by threshold-decrypting the intro) can compute it; no
/// third party ever does, since no third party ever recovers the intro plaintext.
const REPLY_KEY_LABEL: &str = "FANOS-v1/threshold-calypso-test-reply-key";
const REPLY_NONCE_LABEL: &str = "FANOS-v1/threshold-calypso-test-reply-nonce";
const COOKIE_LEN: usize = 16;
const RESPONSE_BODY: &[u8] = b"here is the content you asked for";

fn reply_nonce(cookie: &[u8]) -> [u8; 12] {
    let digest = hash_labeled(REPLY_NONCE_LABEL, cookie);
    let mut n = [0u8; 12];
    n.copy_from_slice(&digest[..12]);
    n
}

// --- the two engines ---

/// One member of a threshold-hosted CALYPSO service-line (spec §12.3): serves its own PartialDec for
/// any intro addressed to the line, and — for an intro addressed directly to *it* — acts as the
/// line's combiner, gathering `>= threshold` PartialDecs, recovering the intro, "delivering" it to
/// the service application, and replying to the client.
struct ServiceMember {
    coord: Triple,
    secret: HybridKemSecret,
    /// All service-line member coordinates, in the same order their public keys were given to
    /// `SealedIntro::seal` — a member's position in this list is its share index.
    line: Vec<Triple>,
    threshold: usize,
    pending: Option<Pending>,
    /// How many requests this member has fully served as combiner — the non-vacuous control (mirrors
    /// `withholding.rs`'s `withheld` counter): a passing test must show this is actually `> 0`.
    served: Arc<AtomicUsize>,
}

struct Pending {
    intro: SealedIntro,
    client: Triple,
    shares: Vec<Share>,
}

impl ServiceMember {
    fn my_index(&self) -> Option<usize> {
        self.line.iter().position(|&c| c == self.coord)
    }

    /// An intro was delivered addressed to us: seed our own PartialDec (if we are a line member) and
    /// fan out share-requests to the rest of the line, mirroring
    /// `ThresholdRouter::on_onion`.
    fn on_intro(&mut self, client: Triple, intro: SealedIntro) -> Vec<Effect> {
        let mut shares = Vec::new();
        if let Some(i) = self.my_index()
            && let Some(share) = intro.member_partial(i, &self.secret)
        {
            shares.push(share);
        }
        let mut effects = Vec::new();
        for &member in &self.line {
            if member != self.coord {
                effects.push(Effect::Send {
                    to: member,
                    frame: encode_req(self.coord, &intro),
                });
            }
        }
        self.pending = Some(Pending {
            intro,
            client,
            shares,
        });
        effects.extend(self.try_serve());
        effects
    }

    /// A combiner asked for our PartialDec of `intro`: compute and reply (if we are a member).
    fn on_request(&self, combiner: Triple, intro: &SealedIntro) -> Vec<Effect> {
        let Some(i) = self.my_index() else {
            return Vec::new();
        };
        let Some(share) = intro.member_partial(i, &self.secret) else {
            return Vec::new();
        };
        vec![Effect::Send {
            to: combiner,
            frame: encode_rep(&share),
        }]
    }

    /// A member's PartialDec arrived for our pending intro: fold it in and retry.
    fn on_reply(&mut self, share: Share) -> Vec<Effect> {
        let Some(pending) = &mut self.pending else {
            return Vec::new();
        };
        pending.shares.push(share);
        self.try_serve()
    }

    /// If we have gathered `>= threshold` PartialDecs, recover the intro, "deliver" it to the
    /// service application (a `Notify`), and seal+send the reply. Below threshold this is a no-op —
    /// the pending state simply waits for more PartialDecs (or the test ends without one arriving).
    fn try_serve(&mut self) -> Vec<Effect> {
        let Some(pending) = &self.pending else {
            return Vec::new();
        };
        if pending.shares.len() < self.threshold {
            return Vec::new();
        }
        let Ok(request) = pending.intro.open(&pending.shares) else {
            return Vec::new();
        };
        let Some(Pending { client, .. }) = self.pending.take() else {
            return Vec::new();
        };
        self.served.fetch_add(1, Ordering::Relaxed);

        let split = COOKIE_LEN.min(request.len());
        let (cookie, body) = request.split_at(split);
        let mut effects = vec![Effect::Notify(Notification::Delivered {
            from: client,
            payload: body.to_vec(),
        })];
        let reply_key = hash_labeled(REPLY_KEY_LABEL, cookie);
        let nonce = reply_nonce(cookie);
        if let Some(ciphertext) = fanos_primitives::aead::seal(&reply_key, &nonce, RESPONSE_BODY) {
            effects.push(Effect::Send {
                to: client,
                frame: encode_reply(&nonce, &ciphertext),
            });
        }
        effects
    }
}

impl Engine for ServiceMember {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        let Input::Message { from, frame } = input else {
            return Vec::new();
        };
        match frame.split_first() {
            Some((&TAG_INTRO, body)) => decode_intro(body).map_or_else(Vec::new, |intro| {
                self.on_intro(from, intro)
            }),
            Some((&TAG_REQ, body)) => decode_req(body)
                .map_or_else(Vec::new, |(combiner, intro)| self.on_request(combiner, &intro)),
            Some((&TAG_REP, body)) => decode_rep(body).map_or_else(Vec::new, |share| self.on_reply(share)),
            _ => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord
    }
}

/// The client half: receives the sealed reply and opens it under the key its own cookie derives —
/// the same key only the combiner (who threshold-decrypted the intro to learn the cookie) can also
/// compute.
struct Client {
    coord: Triple,
    cookie: [u8; COOKIE_LEN],
}

impl Engine for Client {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        let Input::Message { from, frame } = input else {
            return Vec::new();
        };
        let Some((&TAG_REPLY, body)) = frame.split_first() else {
            return Vec::new();
        };
        let Some((nonce, ciphertext)) = decode_reply(body) else {
            return Vec::new();
        };
        let key = hash_labeled(REPLY_KEY_LABEL, &self.cookie);
        let Some(payload) = fanos_primitives::aead::open(&key, &nonce, ciphertext) else {
            return Vec::new();
        };
        vec![Effect::Notify(Notification::Delivered { from, payload })]
    }

    fn address(&self) -> Triple {
        self.coord
    }
}

/// Spawn an `n`-member service-line (threshold `t`) at Fano points `0..n`. Returns the line's
/// coordinates (in seal order), the members' public keys (for the client to seal an intro to), and
/// the shared `served` counter.
fn spawn_line(sim: &mut Sim, n: usize, threshold: usize) -> (Vec<Triple>, Vec<HybridKemPublic>, Arc<AtomicUsize>) {
    let served = Arc::new(AtomicUsize::new(0));
    let mut line = Vec::new();
    let mut pubs = Vec::new();
    let mut secrets = Vec::new();
    for i in 0..n {
        let mut rng = SeedRng::from_seed(&[0x9C, i as u8]);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        line.push(Point::<F2>::at(i).coords());
        pubs.push(public);
        secrets.push(secret);
    }
    for (i, secret) in secrets.into_iter().enumerate() {
        sim.add(Box::new(ServiceMember {
            coord: line[i],
            secret,
            line: line.clone(),
            threshold,
            pending: None,
            served: served.clone(),
        }));
    }
    (line, pubs, served)
}

/// Seal a fixed test intro (`cookie ‖ request body`) to `pubs` at `threshold`, and register a client
/// at `client_coord` that can open the reply keyed on `cookie`.
fn seal_test_intro(
    sim: &mut Sim,
    client_coord: Triple,
    pubs: &[HybridKemPublic],
    threshold: u8,
) -> (SealedIntro, [u8; COOKIE_LEN], &'static [u8]) {
    let cookie: [u8; COOKIE_LEN] = *b"client-cookie-01";
    let request_body: &[u8] = b"please serve my content";
    let mut payload = cookie.to_vec();
    payload.extend_from_slice(request_body);

    let pub_refs: Vec<&HybridKemPublic> = pubs.iter().collect();
    let intro = SealedIntro::seal(&payload, threshold, &pub_refs, b"client-intro-seed").unwrap();
    sim.add(Box::new(Client {
        coord: client_coord,
        cookie,
    }));
    (intro, cookie, request_body)
}

#[test]
fn t_of_q_plus_1_members_cooperate_to_serve_a_request_and_reply() {
    // A service hosted 3-of-5 across its line: no single member ever holds the whole intro, but the
    // line as a whole answers.
    let mut sim = Sim::new(0xCA1);
    let (line, pubs, served) = spawn_line(&mut sim, 5, 3);
    let client_coord = Point::<F2>::at(5).coords();
    let (intro, _cookie, request_body) = seal_test_intro(&mut sim, client_coord, &pubs, 3);

    // The client sends its threshold-sealed intro to the line's designated combiner (its first
    // member, by convention — mirrors `ThresholdRouter::combiner_of`).
    sim.inject_frame(client_coord, line[0], encode_intro(&intro));
    sim.run_for(Duration::from_millis(2000));

    // The service (the combiner, cooperating with the line) received and decrypted the request.
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == client_coord && bytes == request_body),
        "the line, cooperating at threshold, decrypted and delivered the request"
    );
    // The client received and decrypted the reply — the round trip completes.
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == client_coord && from == line[0] && bytes == RESPONSE_BODY),
        "the client received and decrypted the service's reply"
    );
    // Non-vacuous: the combiner genuinely served via threshold cooperation exactly once.
    assert_eq!(
        served.load(Ordering::Relaxed),
        1,
        "the combiner's serve path actually ran (else the test proves nothing)"
    );
}

#[test]
fn any_surviving_subset_of_threshold_members_still_serves() {
    // The SAME 3-of-5 line, but now with two SPECIFIC, non-adjacent members down (crashed/seized) —
    // a different subset than whichever happened to answer first in the baseline above. Availability
    // is not pinned to one fixed quorum: any surviving `t` members serve.
    let mut sim = Sim::new(0xCA2);
    let (line, pubs, served) = spawn_line(&mut sim, 5, 3);
    let client_coord = Point::<F2>::at(5).coords();
    let (intro, _cookie, request_body) = seal_test_intro(&mut sim, client_coord, &pubs, 3);

    sim.crash(line[1]);
    sim.crash(line[3]);
    // {line[0], line[2], line[4]} remain — exactly `t` = 3, a different subset than "the first 3
    // to reply" in an all-alive run.

    sim.inject_frame(client_coord, line[0], encode_intro(&intro));
    sim.run_for(Duration::from_millis(2000));

    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == client_coord && bytes == request_body),
        "the surviving 3-of-5 subset {{0,2,4}} still serves the request"
    );
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == client_coord && from == line[0] && bytes == RESPONSE_BODY),
        "and still replies to the client"
    );
    assert_eq!(served.load(Ordering::Relaxed), 1);
}

#[test]
fn below_threshold_seized_members_cannot_recover_the_intro_and_nothing_is_served() {
    // D5/seizure control: with only 2 of the 5 members reachable (below the threshold of 3), the
    // combiner can never gather enough PartialDecs. Per `fanos_calypso::hosting::SealedIntro::open`,
    // a below-threshold share set reconstructs the WRONG AEAD key, so this is not merely a timeout —
    // decryption itself is impossible (0-knowledge below `t`, spec §12.3). Mirrors
    // `threshold_routing.rs`'s below-threshold scenario and `withholding.rs`'s non-vacuous-control
    // discipline.
    let mut sim = Sim::new(0xCA3);
    let (line, pubs, served) = spawn_line(&mut sim, 5, 3);
    let client_coord = Point::<F2>::at(5).coords();
    let (intro, _cookie, _request_body) = seal_test_intro(&mut sim, client_coord, &pubs, 3);

    sim.crash(line[1]);
    sim.crash(line[2]);
    sim.crash(line[3]);
    // Only {line[0], line[4]} remain — 2 of 5, below the threshold of 3.

    sim.inject_frame(client_coord, line[0], encode_intro(&intro));
    sim.run_for(Duration::from_millis(2000));

    assert!(
        sim.report().deliveries().next().is_none(),
        "below threshold, the service never decrypts the request and never replies — nothing is \
         delivered anywhere"
    );
    assert_eq!(
        served.load(Ordering::Relaxed),
        0,
        "the combiner's serve path never completed — the control is genuine, not vacuous"
    );
}
