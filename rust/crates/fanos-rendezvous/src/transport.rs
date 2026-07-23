//! Reusable, sans-I/O rendezvous transport.
//!
//! The [`RendezvousClient`] and [`RendezvousService`] halves hold everything an anonymous DIAULOS
//! session needs *except* I/O: they seal outbound payloads into threshold onions bound for the right
//! rendezvous line, manage fresh per-onion key material, and (on the service side) demultiplex
//! concurrent clients by cookie and route each reply back through the circuit that client named. A
//! driver — the deterministic simulator, or an async node over real QUIC — only moves the [`Forward`]s
//! these produce and feeds back the plaintext deliveries. Keeping the onion machinery here means every
//! driver shares exactly one verified core, and the async wiring on top is a thin adapter.
//!
//! Directions are two independent forward circuits (aphantos onions are forward-only):
//!
//! * **client → service** — [`RendezvousClient::seal_send`] wraps the DIAULOS bytes in a [`Request`]
//!   (carrying the client's cookie and reply circuit) and seals an onion whose last hop is the
//!   service's meeting line;
//! * **service → client** — [`RendezvousService::ingest`] records the cookie→reply-circuit binding and
//!   surfaces the inner bytes; [`RendezvousService::seal_reply`] seals the response back through that
//!   client's reply circuit, which ends at the combiner the client listens on.

use core::marker::PhantomData;
use std::collections::BTreeMap;

use fanos_aphantos::nostos::ReplyKeys;
use fanos_aphantos::surb::{Surb, SurbKeys, build_surb};
use fanos_field::Field;
use fanos_geometry::{Point, Triple};
use fanos_nyx::build_circuit;
use fanos_pqcrypto::rng::SeedRng;

use crate::{Forward, MixDirectory, Request, combiner_for, seal_forward, seal_nostos_reply};

/// A per-session cookie the service demultiplexes concurrent clients by, without learning who they are.
pub type SessionId = [u8; 16];

/// Domain label for the per-session NOSTOS reply-keypair derivation.
const REPLY_KEYPAIR_LABEL: &[u8] = b"FANOS-v1/nostos-session-reply";

/// Derive a session's **NOSTOS reply keypair** deterministically from its `secret`: the [`ReplyKeys`]
/// (kept by the dialing driver to open replies delivered to the client's own line) and the serialized
/// public key (which the [`RendezvousClient`] advertises in every [`Request`], so the service
/// end-to-end-seals to it). Both the client and its driver call this with the same session secret, so
/// they agree on the keypair without the secret ever being shared between the sending and opening halves
/// — which lets them run as independent concurrent tasks with no shared mutable state.
#[must_use]
pub fn session_reply_keypair(secret: &[u8]) -> (ReplyKeys, Vec<u8>) {
    let mut seed = Vec::with_capacity(REPLY_KEYPAIR_LABEL.len() + secret.len());
    seed.extend_from_slice(REPLY_KEYPAIR_LABEL);
    seed.extend_from_slice(secret);
    let (keys, public) = ReplyKeys::generate(&seed);
    (keys, public.encode())
}

/// The client half of an anonymous session.
///
/// It seals outbound DIAULOS payloads into onions routed to the service's meeting line, naming its own
/// reply rendezvous inside each [`Request`], and knows the combiner coordinate ([`Self::reply_combiner`])
/// where the service's replies land. Sans-I/O: a driver launches each returned [`Forward`] and delivers
/// whatever arrives at the reply combiner back into the DIAULOS session.
///
/// A fresh seed is drawn from an internal CSPRNG for every onion, so no two onions share per-hop key
/// material — the constructor's `secret` is the only entropy input (OS entropy in production, a fixed
/// value under the deterministic simulator).
pub struct RendezvousClient<F: Field> {
    cookie: SessionId,
    forward_circuit: Vec<Triple>,
    reply_circuit: Vec<Triple>,
    directory: MixDirectory,
    threshold: u8,
    rng: SeedRng,
    /// This session's NOSTOS reply public key, derived from the session secret via
    /// [`session_reply_keypair`]. It rides every [`Request`] so the service end-to-end-seals its replies
    /// to it; the matching secret half stays with the dialing driver, which opens the dead-drop delivered
    /// at the client's own reply line — so no relay ever learns the client.
    reply_pub: Vec<u8>,
    _f: PhantomData<F>,
}

impl<F: Field> RendezvousClient<F> {
    /// Build a client half.
    ///
    /// * `forward_circuit` — hop lines to the service, ending at its [`meeting_line`](crate::meeting_line);
    /// * `reply_circuit` — hop lines to the client's reply rendezvous. For NOSTOS the last hop is one of
    ///   the client's own lines (a dead-drop it receives as a line member);
    /// * `directory` — the mixnet members' KEM keys the onions seal to;
    /// * `threshold` — how many of each hop line's `q+1` members must cooperate to peel it;
    /// * `secret` — session entropy: the cookie and every onion seed are derived from it via a CSPRNG;
    /// * `reply_pub` — this session's **NOSTOS reply public key** ([`session_reply_keypair`]), advertised
    ///   in every [`Request`] so the service end-to-end-seals its replies as a dead-drop to the client's
    ///   own line. Pass **empty** to select the legacy path — the service cookie-tags the reply for a
    ///   rendezvous relay to forward — for a client that cannot be a line member (a bare-overlay proxy).
    #[must_use]
    pub fn new(
        forward_circuit: Vec<Triple>,
        reply_circuit: Vec<Triple>,
        directory: MixDirectory,
        threshold: u8,
        secret: &[u8],
        reply_pub: Vec<u8>,
    ) -> Self {
        let mut rng = SeedRng::from_seed(secret);
        let mut cookie = [0u8; 16];
        rng.fill(&mut cookie);
        Self {
            cookie,
            forward_circuit,
            reply_circuit,
            directory,
            threshold,
            rng,
            reply_pub,
            _f: PhantomData,
        }
    }

    /// This session's cookie — the service tags its replies with it, so the driver can route deliveries
    /// arriving at [`Self::reply_combiner`] back to the correct session.
    #[must_use]
    pub fn cookie(&self) -> SessionId {
        self.cookie
    }

    /// The combiner coordinate this client listens on for the service's replies (the reply circuit's
    /// destination). `None` only if the reply circuit is empty.
    #[must_use]
    pub fn reply_combiner(&self) -> Option<Triple> {
        combiner_for::<F>(*self.reply_circuit.last()?)
    }

    /// Build a **SURB reply block** (audit §5 S1-H3): a pre-sealed single-hop return path from this session's
    /// reply combiner (the injecting relay) through a **delivery relay** to `client_coord`, so the rendezvous
    /// relay forwards the service's reply WITHOUT ever learning `client_coord`. Register the returned [`Surb`]
    /// with the relay in place of the coordinate; keep the [`SurbKeys`] to [`open_reply`](fanos_aphantos::surb::open_reply)
    /// the delivered block. `None` if the directory offers no delivery relay distinct from the reply combiner
    /// and the client. Each call draws fresh path randomness, so successive SURBs are unlinkable.
    pub fn build_reply_surb(&mut self, client_coord: Triple) -> Option<(Surb, SurbKeys)> {
        let combiner = self.reply_combiner()?;
        let source = Point::<F>::new(combiner)?;
        let mut seed = [0u8; 32];
        self.rng.fill(&mut seed);
        let (&delivery, delivery_key) =
            self.directory.entries().find(|&(&c, _)| c != combiner && c != client_coord)?;
        let dest = Point::<F>::new(delivery)?;
        let circuit = build_circuit(source, dest, 1, &seed)?;
        build_surb(&circuit, &[delivery_key], client_coord, &seed).ok()
    }

    /// Seal `payload` (a DIAULOS `ClientHello` or cell) into an onion bound for the service's meeting
    /// line, wrapped in a [`Request`] carrying this session's cookie and reply circuit. `None` if a
    /// member key is missing or the circuit is empty.
    #[must_use]
    pub fn seal_send(&mut self, payload: &[u8]) -> Option<Forward> {
        let wrapped = Request {
            cookie: self.cookie,
            reply_circuit: self.reply_circuit.clone(),
            payload: payload.to_vec(),
            reply_pub: self.reply_pub.clone(),
        }
        .encode();
        let mut seed = [0u8; 32];
        self.rng.fill(&mut seed);
        seal_forward::<F>(
            &self.forward_circuit,
            &self.directory,
            self.threshold,
            &wrapped,
            &seed,
        )
    }

    /// This session's NOSTOS reply public key (serialized), as it rides each [`Request`]. The service
    /// end-to-end-seals replies to it; the dialing driver opens them with the matching [`ReplyKeys`] from
    /// [`session_reply_keypair`] (a member of its own reply line, it decrypts what lands there).
    #[must_use]
    pub fn reply_pub(&self) -> &[u8] {
        &self.reply_pub
    }
}

/// A client's recorded return path: the reply circuit (hop lines ending at the client's own dead-drop
/// line) and its NOSTOS reply public key (empty on the legacy pre-NOSTOS path).
#[derive(Clone)]
struct ReplyRoute {
    circuit: Vec<Triple>,
    reply_pub: Vec<u8>,
}

/// The service half of an anonymous session.
///
/// It [`ingest`](Self::ingest)s requests delivered at its meeting line — recording each cookie's reply
/// circuit so it can answer without ever learning who the client is — and [`seal_reply`](Self::seal_reply)s
/// responses back through the named circuit. One service instance fronts arbitrarily many concurrent
/// clients, demultiplexed entirely by cookie.
pub struct RendezvousService<F: Field> {
    directory: MixDirectory,
    threshold: u8,
    rng: SeedRng,
    routes: BTreeMap<SessionId, ReplyRoute>,
    _f: PhantomData<F>,
}

impl<F: Field> RendezvousService<F> {
    /// Build a service half. `secret` seeds the CSPRNG that supplies a fresh seed for every reply onion.
    #[must_use]
    pub fn new(directory: MixDirectory, threshold: u8, secret: &[u8]) -> Self {
        Self {
            directory,
            threshold,
            rng: SeedRng::from_seed(secret),
            routes: BTreeMap::new(),
            _f: PhantomData,
        }
    }

    /// Ingest a request delivered at the meeting line: bind the cookie to its reply circuit and return
    /// `(cookie, inner payload)` for the DIAULOS session keyed by that cookie. `None` if the wrapper is
    /// malformed. A repeated cookie refreshes the stored circuit, so a client may re-send it each cell.
    pub fn ingest(&mut self, delivery: &[u8]) -> Option<(SessionId, Vec<u8>)> {
        let req = Request::decode(delivery)?;
        if !req.reply_circuit.is_empty() {
            self.routes.insert(
                req.cookie,
                ReplyRoute {
                    circuit: req.reply_circuit,
                    reply_pub: req.reply_pub,
                },
            );
        }
        Some((req.cookie, req.payload))
    }

    /// Whether a reply route is known for `cookie` (i.e. at least one request has been ingested for it).
    #[must_use]
    pub fn knows(&self, cookie: &SessionId) -> bool {
        self.routes.contains_key(cookie)
    }

    /// Seal `payload` back through `cookie`'s recorded reply circuit. `None` if the cookie is unknown,
    /// a member key is missing, or sealing fails.
    ///
    /// **NOSTOS path** (the client registered a reply key): the reply is **end-to-end sealed** to that
    /// key and delivered as a dead-drop to the client's own reply line — the delivery line's members see
    /// only ciphertext, the client (one of the `q+1` members) decrypts, and no cookie tag is needed
    /// because the reply key is itself the demultiplexer. No relay ever learns the client.
    ///
    /// **Legacy path** (no reply key): the reply is tagged with the 16-byte session cookie so a shared
    /// rendezvous relay at the reply combiner can forward it to the registering client.
    #[must_use]
    pub fn seal_reply(&mut self, cookie: &SessionId, payload: &[u8]) -> Option<Forward> {
        let route = self.routes.get(cookie)?.clone();
        if route.reply_pub.is_empty() {
            let mut seed = [0u8; 32];
            self.rng.fill(&mut seed);
            let mut tagged = Vec::with_capacity(cookie.len() + payload.len());
            tagged.extend_from_slice(cookie);
            tagged.extend_from_slice(payload);
            return seal_forward::<F>(&route.circuit, &self.directory, self.threshold, &tagged, &seed);
        }
        // NOSTOS: end-to-end seal to the client's reply key, then dead-drop to its own line. Two
        // independent seeds — the end-to-end nonce and the onion key material must not share entropy.
        let mut e2e_seed = [0u8; 32];
        let mut onion_seed = [0u8; 32];
        self.rng.fill(&mut e2e_seed);
        self.rng.fill(&mut onion_seed);
        seal_nostos_reply::<F>(
            &route.reply_pub,
            &route.circuit,
            &self.directory,
            self.threshold,
            payload,
            &e2e_seed,
            &onion_seed,
        )
    }

    /// The number of distinct client sessions (cookies) this service is currently tracking.
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use fanos_field::F2;
    use fanos_geometry::{Line, Point};
    use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};

    use super::*;
    use crate::meeting_line;

    /// A directory with a hybrid KEM key at every Fano point — enough to seal onions through any line.
    fn fano_directory() -> MixDirectory {
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let mut rng = SeedRng::from_seed(&[0x0D, i]);
            let (_secret, public) = HybridKemSecret::generate(&mut rng);
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }
        dir
    }

    fn line(i: usize) -> Triple {
        Line::<F2>::at(i).coords()
    }

    #[test]
    fn cookie_is_deterministic_in_the_secret_and_distinct_across_secrets() {
        let dir = fano_directory();
        let cookie = |secret: &[u8]| {
            RendezvousClient::<F2>::new(vec![line(0)], vec![line(1)], dir.clone(), 2, secret, vec![])
                .cookie()
        };
        assert_eq!(
            cookie(b"alpha"),
            cookie(b"alpha"),
            "same secret → same cookie"
        );
        assert_ne!(
            cookie(b"alpha"),
            cookie(b"beta"),
            "distinct secrets → distinct cookies"
        );
        // Many independent secrets stay collision-free (the cookie space is a 128-bit CSPRNG draw).
        let mut all = std::collections::BTreeSet::new();
        for i in 0..256u32 {
            assert!(
                all.insert(cookie(&i.to_be_bytes())),
                "cookie collision at {i}"
            );
        }
    }

    #[test]
    fn seal_send_draws_fresh_key_material_per_onion() {
        let dir = fano_directory();
        let meeting = meeting_line::<F2>(
            b"svc",
            crate::Epoch::new(1),
            &crate::BeaconSeed::new([0x0E; 32]),
        )
        .coords();
        let hop = (0..7).map(line).find(|&l| l != meeting).unwrap();
        let mut c =
            RendezvousClient::<F2>::new(vec![hop, meeting], vec![line(3)], dir, 2, b"secret", vec![]);
        let a = c.seal_send(b"hello").unwrap();
        let b = c.seal_send(b"hello").unwrap();
        assert_eq!(
            a.combiner, b.combiner,
            "same first hop → same launch combiner"
        );
        assert_ne!(
            a.frame, b.frame,
            "a fresh per-onion seed must change the sealed frame — no key-material reuse"
        );
    }

    #[test]
    fn reply_combiner_is_the_reply_circuit_destination() {
        let dir = fano_directory();
        let rp = line(4);
        let c = RendezvousClient::<F2>::new(vec![line(0)], vec![line(1), rp], dir, 2, b"s", vec![]);
        assert_eq!(c.reply_combiner(), combiner_for::<F2>(rp));
    }

    #[test]
    fn ingest_binds_the_cookie_and_unknown_cookies_have_no_reply() {
        let dir = fano_directory();
        let mut svc = RendezvousService::<F2>::new(dir, 2, b"svc");
        let cookie = *b"a-client-cookie!";
        let rp = line(2);
        let hop = line(3);

        // Before any request, the cookie is unknown and cannot be answered.
        assert!(!svc.knows(&cookie));
        assert!(svc.seal_reply(&cookie, b"resp").is_none());
        assert_eq!(svc.sessions(), 0);

        // Ingesting a request binds the cookie to its reply circuit and surfaces the inner bytes.
        let req = Request {
            cookie,
            reply_circuit: vec![hop, rp],
            payload: b"inner".to_vec(),
            reply_pub: vec![],
        }
        .encode();
        let (got, payload) = svc.ingest(&req).unwrap();
        assert_eq!(got, cookie);
        assert_eq!(payload, b"inner");
        assert!(svc.knows(&cookie));
        assert_eq!(svc.sessions(), 1);
        // Now a reply seals through the recorded circuit (legacy cookie-tagged path — no reply key).
        let reply = svc.seal_reply(&cookie, b"resp").unwrap();
        assert_eq!(reply.combiner, combiner_for::<F2>(hop).unwrap());
    }

    #[test]
    fn a_later_empty_reply_circuit_does_not_unbind_the_cookie() {
        let dir = fano_directory();
        let mut svc = RendezvousService::<F2>::new(dir, 2, b"svc");
        let cookie = *b"sticky-cookie-01";

        svc.ingest(
            &Request {
                cookie,
                reply_circuit: vec![line(3), line(2)],
                payload: vec![],
                reply_pub: vec![],
            }
            .encode(),
        )
        .unwrap();
        assert!(svc.knows(&cookie));

        // A follow-up cell for the same session need not repeat the route; an empty circuit must keep
        // the prior binding rather than erase it.
        let (got, payload) = svc
            .ingest(
                &Request {
                    cookie,
                    reply_circuit: vec![],
                    payload: b"more".to_vec(),
                    reply_pub: vec![],
                }
                .encode(),
            )
            .unwrap();
        assert_eq!(got, cookie);
        assert_eq!(payload, b"more");
        assert!(
            svc.knows(&cookie),
            "an empty reply circuit does not unbind the cookie"
        );
        assert!(svc.seal_reply(&cookie, b"resp").is_some());
        assert_eq!(svc.sessions(), 1, "still exactly one session");
    }

    #[test]
    fn ingest_rejects_a_malformed_wrapper() {
        let dir = fano_directory();
        let mut svc = RendezvousService::<F2>::new(dir, 2, b"svc");
        // Too short to even hold the 16-byte cookie.
        assert!(svc.ingest(&[0u8; 8]).is_none());
        // Cookie present but a truncated hop line (count says 1, no 12 bytes follow).
        let mut bad = vec![0u8; 16];
        bad.push(1);
        assert!(svc.ingest(&bad).is_none());
        assert_eq!(svc.sessions(), 0, "no session bound from malformed input");
    }

    #[test]
    fn seal_forward_rejects_empty_circuits_and_missing_member_keys() {
        let dir = fano_directory();
        assert!(
            seal_forward::<F2>(&[], &dir, 2, b"x", b"seed").is_none(),
            "an empty circuit has no first hop"
        );
        assert!(
            seal_forward::<F2>(&[line(0)], &MixDirectory::new(), 2, b"x", b"seed").is_none(),
            "an empty directory cannot supply the line's member keys"
        );
    }

    #[test]
    fn seal_forward_is_deterministic_in_the_seed() {
        let dir = fano_directory();
        let circuit = [line(0), line(1)];
        let a = seal_forward::<F2>(&circuit, &dir, 2, b"payload", b"seed-1").unwrap();
        let b = seal_forward::<F2>(&circuit, &dir, 2, b"payload", b"seed-1").unwrap();
        let c = seal_forward::<F2>(&circuit, &dir, 2, b"payload", b"seed-2").unwrap();
        assert_eq!(
            a.frame, b.frame,
            "same seed → identical onion (reproducible under the sim)"
        );
        assert_ne!(a.frame, c.frame, "a different seed changes the onion");
    }

    #[test]
    fn a_client_built_surb_returns_a_reply_without_exposing_the_coordinate() {
        use fanos_aphantos::surb::{SurbOutcome, inject_reply, open_reply, process_surb_hop};
        let client_coord = Point::<F2>::at(6).coords();
        let mut rclient = RendezvousClient::<F2>::new(vec![line(0)], vec![line(1)], fano_directory(), 2, b"surb-session", vec![]);
        let combiner = rclient.reply_combiner().unwrap();

        // The client builds a SURB return path; its first hop is a delivery relay ≠ the injecting relay, ≠ self.
        let (surb, keys) = rclient.build_reply_surb(client_coord).expect("a delivery relay exists");
        let delivery = surb.first_hop;
        assert_ne!(delivery, combiner, "the delivery relay is not the injecting relay");
        assert_ne!(delivery, client_coord, "nor the client itself");

        // The injecting relay attaches a peeled reply (cookie ‖ cell) to the SURB — no coordinate anywhere.
        let mut reply = rclient.cookie().to_vec();
        reply.extend_from_slice(b"the-service-cell");
        let packet = inject_reply(&surb, &reply).unwrap();

        // The delivery relay peels it with its onion secret (regenerated from the directory's seeding) — only it
        // learns the coordinate — and the client opens the delivered block back to the exact reply.
        let i = (0..7).find(|&i| Point::<F2>::at(i).coords() == delivery).unwrap();
        let (delivery_secret, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x0D, i as u8]));
        match process_surb_hop(&packet, &delivery_secret).unwrap() {
            SurbOutcome::Deliver { coord, block } => {
                assert_eq!(coord, client_coord, "only the delivery relay learns the coordinate");
                assert_eq!(open_reply(&block, &keys).unwrap(), reply, "the client recovers the exact reply");
            }
            SurbOutcome::Forward { .. } => panic!("a single-hop SURB delivers, it does not forward"),
        }
    }

    #[test]
    fn a_client_advertises_a_reply_key_whose_secret_the_driver_derives() {
        use fanos_aphantos::nostos::seal_to_receiver;
        // The client advertises reply_pub; the dialing driver derives the matching ReplyKeys from the
        // SAME session secret via session_reply_keypair. A reply sealed to the advertised key opens with
        // those keys — and with no other session's keys.
        let secret = b"nostos-session";
        let (reply_keys, reply_pub) = session_reply_keypair(secret);
        let client = RendezvousClient::<F2>::new(
            vec![line(0)],
            vec![line(1)],
            fano_directory(),
            2,
            secret,
            reply_pub.clone(),
        );
        assert_eq!(
            client.reply_pub(),
            reply_pub.as_slice(),
            "the client advertises the NOSTOS reply key it was built with",
        );
        let public = HybridKemPublic::decode(client.reply_pub()).unwrap();
        let body = seal_to_receiver(&public, b"the homecoming reply", b"e2e-seed").unwrap();
        assert_eq!(
            reply_keys.open(&body).as_deref(),
            Some(&b"the homecoming reply"[..]),
            "the driver's keys open a reply sealed to the advertised public key",
        );
        let (other_keys, _) = session_reply_keypair(b"a-different-session");
        assert!(
            other_keys.open(&body).is_none(),
            "another session's keys do not open this reply — the key is the demultiplexer",
        );
    }

    #[test]
    fn the_service_seals_a_nostos_reply_when_a_reply_key_is_registered() {
        use fanos_aphantos::nostos::ReplyKeys;
        let mut svc = RendezvousService::<F2>::new(fano_directory(), 2, b"svc-nostos");
        let cookie = *b"nostos-cookie-16";
        let l = line(2);
        let (_keys, reply_pub) = ReplyKeys::generate(b"client-reply-key");
        svc.ingest(
            &Request {
                cookie,
                reply_circuit: vec![l],
                payload: vec![],
                reply_pub: reply_pub.encode(),
            }
            .encode(),
        )
        .unwrap();
        // The NOSTOS reply seals (end-to-end + dead-drop) and launches at the reply line's combiner; the
        // line's members route it and the client, a member, decrypts. Fresh seeds keep replies unlinkable.
        let a = svc.seal_reply(&cookie, b"resp").unwrap();
        assert_eq!(a.combiner, combiner_for::<F2>(l).unwrap());
        let b = svc.seal_reply(&cookie, b"resp").unwrap();
        assert_ne!(
            a.frame, b.frame,
            "each NOSTOS reply draws fresh seeds — no key-material reuse",
        );
    }
}
