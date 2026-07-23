//! `ThresholdRendezvous` — a **genuinely threshold-hosted rendezvous service** (spec §12.3–§12.6, the
//! #99 follow-up wiring flagged in `fanos_calypso::hosting`).
//!
//! The single-host [`RendezvousService`](fanos_rendezvous::RendezvousService) has two seizure/deanonymization
//! weaknesses: whichever host runs it **reads every client request alone** (its cookie, reply circuit, and
//! payload), and **alone holds the service identity** it was booted with. This composite removes both by
//! hosting the service across the members of a **service-line**, composing the two engines that already
//! exist rather than duplicating either:
//!
//! * **Request confidentiality (part b)** — the client seals its whole [`Request`] inside a
//!   [`SealedIntro`](fanos_calypso::hosting::SealedIntro) to the line, and the per-member gather engine
//!   [`ThresholdService`] threshold-decrypts it: a designated combiner collects `≥ threshold` members'
//!   PartialDecs before the request surfaces, so **no single member ever reads a request alone** (0-knowledge
//!   below threshold, the same guarantee NYX §5.2 gives onion hops). This adds a payload-confidentiality layer
//!   *inside* the threshold onion transport, which only protected routing — so the delivering combiner can no
//!   longer read what it delivers.
//! * **Identity custody (part a)** — the service's identity secret is dealt as one
//!   [`SealedShare`](fanos_calypso::hosting::SealedShare) per member ([`open_identity_share`] opens this
//!   member's slot with its own KEM secret), reconstructed on demand from `≥ threshold` opened shares
//!   ([`reconstruct_identity`]) only when the service must authenticate — e.g. re-signing an epoch cert
//!   (spec §12.6). So **no single host holds the service identity in the clear**; seizing `< threshold`
//!   members can neither read requests nor impersonate the service.
//!
//! Once a request is threshold-decrypted, its reply travels back over the client's own reply circuit exactly
//! as the single-host service already does — the combiner that decrypted it holds the route binding and
//! [`seal_reply`](Self::seal_reply)s the response through it. Reply sealing is deliberately single-member
//! (only the decrypting combiner learned the route), matching the existing NYX reply path; the threshold
//! guarantee is on *reading the request*, not on emitting the reply onion.
//!
//! ## Composition
//!
//! One `ThresholdRendezvous` runs per line member. Its [`step`](fanos_runtime::Engine::step) drives the
//! embedded [`ThresholdService`] for the wire gather ([`RdvIntro`](fanos_wire::FrameType::RdvIntro) /
//! [`SvcShareReq`](fanos_wire::FrameType::SvcShareReq) / [`SvcPartial`](fanos_wire::FrameType::SvcPartial))
//! and intercepts each decrypted request it surfaces: it parses the [`Request`], binds the cookie→reply-route
//! in the embedded [`RendezvousService`], and re-surfaces `cookie ‖ inner-payload` as an anonymous
//! [`Notification::Delivered`] ([`split_delivery`] undoes the framing). This is the "lift the `ServiceMember`
//! template into a real engine" the TODO asks for — reusing [`ThresholdService`] (the lift) and
//! [`RendezvousService`] (route + reply), not a third copy of either.

use core::marker::PhantomData;

use fanos_calypso::hosting::{SealedIntro, SealedShare, ServiceLine, Share, recover_service_key};
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_rendezvous::{ANONYMOUS, Forward, MixDirectory, Request, RendezvousService, SessionId};
use fanos_runtime::{Duration, Effect, Engine, Input, Instant, Notification};

use crate::threshold_service::{ThresholdService, intro_frame};

/// A genuinely threshold-hosted rendezvous service — one instance per service-line member (see the module
/// docs). Composes the per-member intro-gather ([`ThresholdService`]) with the route-binding + reply path
/// ([`RendezvousService`]), and custodies the service identity as a per-member [`SealedShare`].
pub struct ThresholdRendezvous<F: Field> {
    /// The intro-gather engine: threshold-decrypts each client's `SealedIntro`-wrapped [`Request`].
    gather: ThresholdService,
    /// The route-binding + reply path: parses the decrypted request, binds cookie→reply-circuit, seals replies.
    service: RendezvousService<F>,
    /// This member's identity-custody share of the service's threshold-hosted identity secret (part a).
    /// `None` for a service that does not custody an authenticating identity (request confidentiality only).
    identity_share: Option<SealedShare>,
    _f: PhantomData<F>,
}

impl<F: Field> ThresholdRendezvous<F> {
    /// Build one line member's threshold-rendezvous engine.
    ///
    /// * `coord` — this member's overlay coordinate (must equal its position in `line`);
    /// * `secret` — this member's hybrid-KEM secret: opens both its per-intro share slots and its
    ///   [`identity_share`](Self::open_identity_share) (a member's one identity key serves both);
    /// * `line` — every member's coordinate in **seal order** (position = Shamir share index), the order the
    ///   client sealed their public keys in the [`ServiceLine`];
    /// * `threshold` — how many members must cooperate to decrypt a request (`t`-of-`line.len()`);
    /// * `directory` — the mixnet members' KEM keys the **reply** onions seal to (the [`RendezvousService`]);
    /// * `reply_secret` — **local** entropy seeding this member's reply-onion CSPRNG (NOT the shared identity:
    ///   replies are unlinkable regardless of which member's local RNG seals them);
    /// * `identity_share` — this member's [`SealedShare`] of the service identity secret, or `None`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coord: Triple,
        secret: fanos_pqcrypto::HybridKemSecret,
        line: Vec<Triple>,
        threshold: usize,
        directory: MixDirectory,
        reply_secret: &[u8],
        identity_share: Option<SealedShare>,
    ) -> Self {
        let gather = ThresholdService::new(coord, secret, line, threshold);
        let service = RendezvousService::new(directory, threshold as u8, reply_secret);
        Self { gather, service, identity_share, _f: PhantomData }
    }

    /// Override the combiner's intro-gather deadline (default 2 s) — see [`ThresholdService::with_gather_timeout`].
    #[must_use]
    pub fn with_gather_timeout(mut self, timeout: Duration) -> Self {
        self.gather = self.gather.with_gather_timeout(timeout);
        self
    }

    /// The number of intros currently gathering (combiner state) — for tests and observability.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.gather.pending()
    }

    /// The number of distinct client sessions (cookies) whose reply route this member has bound.
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.service.sessions()
    }

    /// Whether a reply route is known for `cookie` (a request under it has been threshold-decrypted here).
    #[must_use]
    pub fn knows(&self, cookie: &SessionId) -> bool {
        self.service.knows(cookie)
    }

    /// Open this member's **identity-custody share** with its own KEM secret (part a): the recovered Shamir
    /// [`Share`] of the service identity secret, or `None` if this member custodies no identity. A combiner
    /// gathers `≥ threshold` such shares and [`reconstruct_identity`](Self::reconstruct_identity)s the identity
    /// only when the service must authenticate (spec §12.6) — so no single host holds it in the clear.
    #[must_use]
    pub fn open_identity_share(&self) -> Option<Share> {
        self.gather.open_identity_share(self.identity_share.as_ref()?)
    }

    /// Reconstruct the service identity secret from `threshold` (or more) members' opened identity
    /// [`Share`](Self::open_identity_share)s. `None` below threshold, or if the shares are inconsistent. The
    /// caller uses the recovered secret transiently (e.g. to sign an epoch cert) and discards it — the identity
    /// lives at rest only as the per-member sealed shares.
    #[must_use]
    pub fn reconstruct_identity(shares: &[Share]) -> Option<Vec<u8>> {
        recover_service_key(shares).ok()
    }

    /// Seal `payload` back through `cookie`'s recorded reply circuit — the response to a threshold-decrypted
    /// request. Delegates to [`RendezvousService::seal_reply`] (NOSTOS dead-drop when the client registered a
    /// reply key, else the legacy cookie-tagged path). `None` if the cookie is unknown to this member (only the
    /// combiner that decrypted the request bound its route), a member key is missing, or sealing fails.
    #[must_use]
    pub fn seal_reply(&mut self, cookie: &SessionId, payload: &[u8]) -> Option<Forward> {
        self.service.seal_reply(cookie, payload)
    }
}

impl<F: Field> Engine for ThresholdRendezvous<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        // Drive the intro-gather (it no-ops on non-service frames, commands, and foreign timers).
        let raw = self.gather.step(now, input);
        let mut out = Vec::with_capacity(raw.len());
        for effect in raw {
            match effect {
                // A gather completed: `payload` is a decrypted `Request`. Bind its reply route and re-surface
                // `cookie ‖ inner` for the application; a malformed inner request is dropped (the gather already
                // AEAD-authenticated the plaintext, so this only guards against a non-`Request` inner body).
                Effect::Notify(Notification::Delivered { payload, .. }) => {
                    if let Some((cookie, inner)) = self.service.ingest(&payload) {
                        let mut body = Vec::with_capacity(cookie.len() + inner.len());
                        body.extend_from_slice(&cookie);
                        body.extend_from_slice(&inner);
                        out.push(Effect::Notify(Notification::Delivered { from: ANONYMOUS, payload: body }));
                    }
                }
                other => out.push(other),
            }
        }
        out
    }

    fn address(&self) -> Triple {
        self.gather.address()
    }
}

/// Split a [`ThresholdRendezvous`] delivery (`cookie(16) ‖ inner`) back into `(cookie, inner)`, the inverse of
/// the framing [`step`](ThresholdRendezvous::step) surfaces. `None` if shorter than a 16-byte cookie. A driver
/// feeds `inner` to the DIAULOS session keyed by `cookie`, then answers via
/// [`seal_reply`](ThresholdRendezvous::seal_reply).
#[must_use]
pub fn split_delivery(payload: &[u8]) -> Option<(SessionId, &[u8])> {
    let cookie: SessionId = payload.get(..16)?.try_into().ok()?;
    Some((cookie, payload.get(16..)?))
}

/// Client side: seal a [`Request`] to a threshold-hosted service `line` and build the
/// [`RdvIntro`](fanos_wire::FrameType::RdvIntro) frame to send to its combiner ([`ServiceLine::combiner`]).
/// The whole request — cookie, reply circuit, reply key, and payload — is threshold-sealed, so the delivering
/// combiner learns nothing until `≥ threshold` members cooperate. `seed` supplies the seal's key material
/// (fresh randomness per request in production). `None` if the roster is malformed.
#[must_use]
pub fn seal_request_to_line(request: &Request, line: &ServiceLine, seed: &[u8]) -> Option<Vec<u8>> {
    let intro = line.seal_intro(&request.encode(), seed).ok()?;
    Some(intro_frame(&intro))
}

/// Seal a [`Request`] to a service `line`, returning the raw [`SealedIntro`] (for a caller that wraps it in
/// its own transport rather than the direct [`RdvIntro`](fanos_wire::FrameType::RdvIntro) frame). `None` if the
/// roster is malformed.
#[must_use]
pub fn seal_request_intro(request: &Request, line: &ServiceLine, seed: &[u8]) -> Option<SealedIntro> {
    line.seal_intro(&request.encode(), seed).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use fanos_calypso::hosting::{LineMember, ServiceLine, deal_service_key};
    use fanos_field::F2;
    use fanos_geometry::Point;
    use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
    use fanos_rendezvous::MixDirectory;
    use fanos_wire::{FrameType, decode_frame};

    use super::*;

    const T: usize = 2;
    const N: usize = 3;

    /// A directory with a hybrid KEM key at every Fano point (for the reply onions).
    fn fano_directory() -> MixDirectory {
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let (_s, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x0D, i]));
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }
        dir
    }

    /// `N` line-member KEM keypairs, deterministic per index.
    fn member_keys() -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..N).map(|i| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x5C, i as u8]))).collect()
    }

    /// The published roster for a `T`-of-`N` service line seated at Fano points `0..N`.
    fn service_line(pubs: &[HybridKemPublic]) -> ServiceLine {
        ServiceLine {
            threshold: T as u8,
            members: (0..N)
                .map(|i| LineMember {
                    member_pubkey: pubs[i].encode(),
                    coordinate: Point::<F2>::at(i).coords(),
                })
                .collect(),
        }
    }

    /// Build the `N` member engines (no identity custody), returning them in line order.
    fn line_members(dir: &MixDirectory) -> (Vec<ThresholdRendezvous<F2>>, ServiceLine) {
        let keys = member_keys();
        let pubs: Vec<HybridKemPublic> = keys.iter().map(|(_, p)| p.clone()).collect();
        let coords: Vec<Triple> = (0..N).map(|i| Point::<F2>::at(i).coords()).collect();
        let line = service_line(&pubs);
        let members = keys
            .into_iter()
            .enumerate()
            .map(|(i, (secret, _))| {
                ThresholdRendezvous::<F2>::new(
                    coords[i],
                    secret,
                    coords.clone(),
                    T,
                    dir.clone(),
                    &[0xAB, i as u8],
                    None,
                )
            })
            .collect();
        (members, line)
    }

    fn a_request() -> Request {
        Request {
            cookie: *b"threshold-cookie",
            reply_circuit: vec![Point::<F2>::at(4).coords()],
            payload: b"the hidden request body".to_vec(),
            reply_pub: vec![],
        }
    }

    #[test]
    fn a_threshold_line_decrypts_a_request_no_single_member_reads_it_and_replies() {
        let dir = fano_directory();
        let (mut members, line) = line_members(&dir);
        let req = a_request();
        let intro_frame_bytes = seal_request_to_line(&req, &line, b"seal-seed").unwrap();

        // The client sends the sealed intro to the line's combiner (member 0).
        let combiner_effects =
            members[0].step(Instant(0), Input::Message { from: Point::<F2>::at(6).coords(), frame: intro_frame_bytes });

        // The combiner cannot decrypt alone (T = 2): no delivery yet, and it fanned share-requests to the others.
        assert!(
            !combiner_effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Delivered { .. }))),
            "the combiner alone (1 < t) surfaces nothing — no single member reads the request",
        );
        let share_reqs: Vec<Vec<u8>> = combiner_effects
            .iter()
            .filter_map(|e| match e {
                Effect::Send { to: _, frame } => Some(frame.clone()),
                _ => None,
            })
            .collect();
        assert!(!share_reqs.is_empty(), "the combiner fans SvcShareReq to the rest of the line");

        // Deliver one share-request to member 1; route its PartialDec back to the combiner.
        let mut delivered_cookie = None;
        let partials = members[1].step(Instant(1), Input::Message { from: line.combiner().unwrap(), frame: share_reqs[0].clone() });
        for e in partials {
            if let Effect::Send { frame, .. } = e {
                for served in members[0].step(Instant(2), Input::Message { from: Point::<F2>::at(1).coords(), frame }) {
                    if let Effect::Notify(Notification::Delivered { payload, .. }) = served {
                        let (cookie, inner) = split_delivery(&payload).unwrap();
                        assert_eq!(&cookie, &req.cookie, "the surfaced cookie is the client's");
                        assert_eq!(inner, req.payload.as_slice(), "the surfaced inner payload is the request body");
                        delivered_cookie = Some(cookie);
                    }
                }
            }
        }
        let cookie = delivered_cookie.expect("a threshold (t = 2) of members decrypted and surfaced the request");

        // The combiner bound the reply route and seals a reply back through it.
        assert!(members[0].knows(&cookie), "the decrypting combiner bound the reply route");
        let reply = members[0].seal_reply(&cookie, b"the response").expect("a reply seals through the bound circuit");
        assert_eq!(reply.combiner, fanos_rendezvous::combiner_for::<F2>(req.reply_circuit[0]).unwrap());

        // A non-combiner member never bound the route (it only sent a PartialDec) — it cannot reply.
        assert!(!members[1].knows(&cookie), "a member that only served a PartialDec did not learn the route");
    }

    #[test]
    fn below_threshold_reveals_nothing() {
        // A degenerate line with threshold = 2 where only the combiner participates never surfaces the request.
        let dir = fano_directory();
        let (mut members, line) = line_members(&dir);
        let req = a_request();
        let frame = seal_request_to_line(&req, &line, b"seed2").unwrap();
        let effects = members[0].step(Instant(0), Input::Message { from: Point::<F2>::at(6).coords(), frame });
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Delivered { .. }))),
            "with only 1 < t member cooperating, the request stays sealed — 0-knowledge below threshold",
        );
        assert_eq!(members[0].sessions(), 0, "no route is bound from an unopened request");
    }

    #[test]
    fn the_service_identity_is_threshold_custodied() {
        // Part (a): the service identity is dealt one SealedShare per member; each member opens its own with
        // its KEM secret, any threshold reconstruct the identity, and below threshold learns nothing.
        let dir = fano_directory();
        let keys = member_keys();
        let pubs: Vec<&HybridKemPublic> = keys.iter().map(|(_, p)| p).collect();
        let identity = b"the rendezvous service's long-term signing identity";
        let key_rnd = vec![0x77u8; identity.len() * (T - 1) + 8];
        let sealed = deal_service_key(identity, T as u8, &pubs, &key_rnd, b"id-kem-seed").unwrap();
        assert_eq!(sealed.len(), N);

        let coords: Vec<Triple> = (0..N).map(|i| Point::<F2>::at(i).coords()).collect();
        // Each member holds ONLY its own identity share.
        let members: Vec<ThresholdRendezvous<F2>> = keys
            .into_iter()
            .enumerate()
            .map(|(i, (secret, _))| {
                ThresholdRendezvous::<F2>::new(
                    coords[i], secret, coords.clone(), T, dir.clone(), &[0xCD, i as u8], Some(sealed[i].clone()),
                )
            })
            .collect();

        // Each member opens its own identity share; a threshold reconstruct the identity, one alone does not.
        let opened: Vec<Share> = members.iter().map(|m| m.open_identity_share().expect("member opens its own share")).collect();
        assert_eq!(
            ThresholdRendezvous::<F2>::reconstruct_identity(&opened[0..T]).as_deref(),
            Some(&identity[..]),
            "any t = 2 members reconstruct the service identity",
        );
        assert_eq!(
            ThresholdRendezvous::<F2>::reconstruct_identity(&opened[1..N]).as_deref(),
            Some(&identity[..]),
            "a different t-subset reconstructs the same identity",
        );
        assert_ne!(
            ThresholdRendezvous::<F2>::reconstruct_identity(&opened[0..1]).as_deref(),
            Some(&identity[..]),
            "one member's share alone reconstructs nothing — no single host holds the identity",
        );
    }

    #[test]
    fn a_member_not_on_the_line_cannot_open_an_identity_share_sealed_to_another() {
        // The seal is real: member 1's identity share does not open under member 0's secret.
        let keys = member_keys();
        let pubs: Vec<&HybridKemPublic> = keys.iter().map(|(_, p)| p).collect();
        let key_rnd = vec![0x33u8; 8 * (T - 1) + 8];
        let sealed = deal_service_key(b"identity!", T as u8, &pubs, &key_rnd, b"seed").unwrap();
        let coords: Vec<Triple> = (0..N).map(|i| Point::<F2>::at(i).coords()).collect();
        let (secret0, _) = keys.into_iter().next().unwrap();
        // Member 0's engine given member 1's sealed share: it cannot open it (not sealed to member 0).
        let m0 = ThresholdRendezvous::<F2>::new(
            coords[0], secret0, coords.clone(), T, fano_directory(), b"r", Some(sealed[1].clone()),
        );
        assert!(m0.open_identity_share().is_none(), "a share sealed to another member does not open here");
    }

    #[test]
    fn the_intro_frame_is_a_well_formed_rdv_intro() {
        let (_members, line) = line_members(&fano_directory());
        let frame = seal_request_to_line(&a_request(), &line, b"s").unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();
        assert_eq!(decoded.frame_type(), Some(FrameType::RdvIntro), "the client's frame is an RdvIntro");
        assert!(seal_request_intro(&a_request(), &line, b"s").is_some(), "the raw SealedIntro form is also available");
    }
}
