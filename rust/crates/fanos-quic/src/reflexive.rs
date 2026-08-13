//! `ReflexiveAddr` — learn this node's **public (reflexive) address** from peers' observations, the
//! STUN-like foundation of NAT traversal (#119).
//!
//! A node behind NAT (or bound to `0.0.0.0`) does not know the address remote peers actually reach it at
//! — its own `local_addr()` is a private/wildcard bind, not the NAT-mapped public endpoint. But every
//! peer that a node dials **observes** that NAT-mapped source address, and can report it back
//! ([`FrameType::ObservedAddr`](fanos_wire::FrameType::ObservedAddr)). This aggregator collects those
//! reports and decides, with confidence, the address to advertise (and, later, to be hole-punched at).
//!
//! **Why a quorum, not the first report.** A single peer could be malicious (report a wrong address to
//! mis-advertise or redirect the node) or simply misconfigured. So an address is **confirmed** only once
//! at least `quorum` *distinct* peers independently report the **same** one. This is the same
//! honest-majority discipline the rest of FANOS uses, applied to address discovery: one liar cannot move
//! a node's advertised address; it takes `quorum` colluding observers, which the overlay's structural
//! Sybil cap already bounds. A NAT rebinding (the mapping genuinely changes) simply re-reaches quorum on
//! the new address and the confirmation moves — the plurality is recomputed on every observation.

use std::collections::HashMap;
use std::net::SocketAddr;

use fanos_geometry::Triple;

/// A bound on the number of distinct peers whose observations are retained — memory safety against an
/// observation flood. A node's honest peer set is far smaller; beyond it, new peers are ignored (the
/// confirmed address is already determined by the peers that reached quorum first).
const MAX_OBSERVERS: usize = 256;

/// Aggregates peers' observations of this node's reflexive address into a quorum-confirmed public address.
/// One current vote per peer (keyed by the peer's cryptographically-proven overlay coordinate, so an
/// observation is attributable and a peer cannot stuff the ballot).
pub struct ReflexiveAddr {
    quorum: usize,
    votes: HashMap<Triple, SocketAddr>,
    confirmed: Option<SocketAddr>,
}

impl ReflexiveAddr {
    /// A fresh aggregator confirming an address once `quorum` (at least 1) distinct peers agree on it.
    #[must_use]
    pub fn new(quorum: usize) -> Self {
        Self {
            quorum: quorum.max(1),
            votes: HashMap::new(),
            confirmed: None,
        }
    }

    /// Record that `peer` observes this node at `addr` (its latest report replaces any prior one), then
    /// recompute the plurality. Returns the confirmed public address if one currently meets quorum.
    pub fn observe(&mut self, peer: Triple, addr: SocketAddr) -> Option<SocketAddr> {
        // Bound retained observers; an already-known peer always updates its own vote.
        if self.votes.len() >= MAX_OBSERVERS && !self.votes.contains_key(&peer) {
            return self.confirmed;
        }
        self.votes.insert(peer, addr);
        self.recompute();
        self.confirmed
    }

    /// Forget a peer's observation (e.g. when its connection drops), then recompute — so a departed
    /// observer no longer props up a stale address.
    pub fn forget(&mut self, peer: Triple) {
        if self.votes.remove(&peer).is_some() {
            self.recompute();
        }
    }

    /// The plurality address among all current votes, confirmed iff it meets quorum. Deterministic tie-break
    /// (highest `SocketAddr` ordering) so the outcome does not depend on map iteration order.
    fn recompute(&mut self) {
        let mut tally: HashMap<SocketAddr, usize> = HashMap::new();
        for &addr in self.votes.values() {
            *tally.entry(addr).or_insert(0) += 1;
        }
        self.confirmed = tally
            .into_iter()
            .filter(|&(_, n)| n >= self.quorum)
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
            .map(|(addr, _)| addr);
    }

    /// The current quorum-confirmed public address, if any.
    #[must_use]
    pub fn confirmed(&self) -> Option<SocketAddr> {
        self.confirmed
    }

    /// How many distinct peers have reported an observation.
    #[must_use]
    pub fn observers(&self) -> usize {
        self.votes.len()
    }
}

/// Encode a [`SocketAddr`] as an [`ObservedAddr`](fanos_wire::FrameType::ObservedAddr) body:
/// `family(1B: 4|6) ‖ ip(4|16) ‖ port(2B BE)`.
#[must_use]
pub(crate) fn encode_addr(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match addr {
        SocketAddr::V4(a) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(6);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// Decode a [`SocketAddr`] from an [`ObservedAddr`](fanos_wire::FrameType::ObservedAddr) body, or `None`
/// if malformed (unknown family or wrong length).
#[must_use]
pub(crate) fn decode_addr(body: &[u8]) -> Option<SocketAddr> {
    let (&family, rest) = body.split_first()?;
    match family {
        4 => {
            let ip: [u8; 4] = rest.get(..4)?.try_into().ok()?;
            let port = u16::from_be_bytes(rest.get(4..6)?.try_into().ok()?);
            Some(SocketAddr::from((ip, port)))
        }
        6 => {
            let ip: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            let port = u16::from_be_bytes(rest.get(16..18)?.try_into().ok()?);
            Some(SocketAddr::from((ip, port)))
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }
    fn peer(n: u32) -> Triple {
        [n, 0, 0]
    }

    #[test]
    fn one_observation_below_quorum_does_not_confirm() {
        let mut r = ReflexiveAddr::new(2);
        assert_eq!(r.observe(peer(1), addr(9000)), None);
        assert_eq!(r.confirmed(), None, "one report is not enough at quorum 2");
        assert_eq!(r.observers(), 1);
    }

    #[test]
    fn a_quorum_of_agreeing_peers_confirms_the_public_address() {
        let mut r = ReflexiveAddr::new(2);
        assert_eq!(r.observe(peer(1), addr(9000)), None);
        assert_eq!(
            r.observe(peer(2), addr(9000)),
            Some(addr(9000)),
            "two distinct peers agreeing confirms the address"
        );
        assert_eq!(r.confirmed(), Some(addr(9000)));
    }

    #[test]
    fn one_peer_cannot_move_the_address_by_repeating() {
        // A single peer reporting many times is still ONE vote — no ballot-stuffing.
        let mut r = ReflexiveAddr::new(2);
        r.observe(peer(1), addr(9000));
        r.observe(peer(1), addr(9000));
        r.observe(peer(1), addr(9000));
        assert_eq!(r.confirmed(), None, "one peer is one vote regardless of repeats");
        assert_eq!(r.observers(), 1);
    }

    /// **When TWO addresses both clear quorum, the better-supported one wins — and nothing tested that**
    /// (#325). Measured by falsification: turning `recompute`'s `max_by` into `min_by` left the whole
    /// `reflexive` suite at 9/9 green, so the plurality rule was inert to every fixture here. The quorum
    /// filter was carrying all of them, because no test ever put two addresses above it at once.
    ///
    /// That gap is worth a test rather than a comment, because the flipped rule is a live attack: a
    /// coalition of `quorum` liars would take the confirmed address away from a LARGER honest majority, and
    /// the confirmed address is this node's coordinate (#50). One character, no red.
    ///
    /// Falsified by that same `max_by` → `min_by`: this test goes red on the majority assertion while the
    /// eight around it stay green — which is the discrimination, not merely a failure.
    #[test]
    fn the_better_supported_address_wins_when_two_both_clear_quorum() {
        let mut r = ReflexiveAddr::new(2);
        // Three honest peers on :9000, two liars on :6666 — BOTH sides clear a quorum of 2.
        r.observe(peer(1), addr(9000));
        r.observe(peer(2), addr(9000));
        r.observe(peer(3), addr(9000));
        r.observe(peer(4), addr(6666));
        r.observe(peer(5), addr(6666));
        assert_eq!(
            r.confirmed(),
            Some(addr(9000)),
            "with both addresses over quorum the MAJORITY must win — a `min_by` here would hand this \
             node's coordinate to a smaller coalition, and the quorum filter cannot catch it because both \
             sides pass"
        );
        assert_eq!(r.observers(), 5, "and the setup really did seat five distinct voters");
    }

    #[test]
    fn a_lone_liar_cannot_override_the_honest_quorum() {
        let mut r = ReflexiveAddr::new(2);
        r.observe(peer(1), addr(9000));
        r.observe(peer(2), addr(9000)); // honest quorum on :9000
        assert_eq!(r.confirmed(), Some(addr(9000)));
        // A third peer lies about a different address — it does not reach quorum, so it cannot override.
        r.observe(peer(3), addr(6666));
        assert_eq!(
            r.confirmed(),
            Some(addr(9000)),
            "a lone dissenter below quorum cannot move the confirmed address"
        );
    }

    #[test]
    fn a_genuine_rebinding_moves_confirmation_when_the_new_address_reaches_quorum() {
        let mut r = ReflexiveAddr::new(2);
        r.observe(peer(1), addr(9000));
        r.observe(peer(2), addr(9000));
        assert_eq!(r.confirmed(), Some(addr(9000)));
        // The NAT mapping changes; peers re-observe the new port. Once quorum re-forms, it moves.
        r.observe(peer(1), addr(9100));
        assert_eq!(r.confirmed(), None, "one moved, one stale — neither address has quorum now");
        r.observe(peer(2), addr(9100));
        assert_eq!(
            r.confirmed(),
            Some(addr(9100)),
            "both peers now agree on the new mapping"
        );
    }

    #[test]
    fn forgetting_a_departed_observer_can_drop_confirmation() {
        let mut r = ReflexiveAddr::new(2);
        r.observe(peer(1), addr(9000));
        r.observe(peer(2), addr(9000));
        assert_eq!(r.confirmed(), Some(addr(9000)));
        r.forget(peer(1));
        assert_eq!(
            r.confirmed(),
            None,
            "with only one observer left, quorum-2 confirmation lapses"
        );
    }

    #[test]
    fn socket_addr_round_trips_both_families() {
        for a in [
            SocketAddr::from(([203, 0, 113, 7], 9000)),
            SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
        ] {
            assert_eq!(decode_addr(&encode_addr(a)), Some(a), "{a} round-trips");
        }
        assert_eq!(decode_addr(&[]), None);
        assert_eq!(decode_addr(&[9, 1, 2, 3]), None, "unknown family rejected");
        assert_eq!(decode_addr(&[4, 1, 2]), None, "truncated v4 rejected");
    }

    #[test]
    fn the_observer_table_is_bounded() {
        let mut r = ReflexiveAddr::new(2);
        for n in 0..(MAX_OBSERVERS as u32 + 50) {
            r.observe(peer(n), addr(1000));
        }
        assert!(r.observers() <= MAX_OBSERVERS, "the observer table is capped");
        // Quorum was still reached from the retained observers.
        assert_eq!(r.confirmed(), Some(addr(1000)));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod fault_budget {
    use super::ReflexiveAddr;
    use crate::driver::reflexive_quorum;
    use std::net::SocketAddr;

    /// **A coalition the platform promises to survive must not be able to move this node's address.**
    ///
    /// The quorum was the constant `2`, justified as "so one lying peer cannot move it". But FANOS sizes every
    /// other coalition bound to `f = ⌊(n−1)/3⌋`, which is **2** at the Fano base cell — so two colluding peers
    /// were *inside* the tolerated budget and two agreeing reports was exactly the quorum. An adversary within
    /// what the platform explicitly promises to survive could set the address a node advertises and a hub uses
    /// to broker a hole-punch.
    ///
    /// Asserted from both sides, since raising a quorum is only a fix if it still confirms: `f` liars fail,
    /// `f + 1` honest peers succeed.
    #[test]
    fn a_tolerated_coalition_cannot_confirm_an_address_but_one_more_peer_can() {
        for q in [2u32, 5, 8] {
            let n = (q as usize) * (q as usize) + (q as usize) + 1;
            let f = (n - 1) / 3;
            let mut r = ReflexiveAddr::new(reflexive_quorum(q));

            let lie: SocketAddr = "203.0.113.9:9".parse().expect("a literal address parses");
            for i in 0..f {
                let confirmed = r.observe([i as u32, 0, 0], lie);
                assert!(
                    confirmed.is_none(),
                    "q={q}: {} of the tolerated {f} liars must not confirm — the budget says they exist",
                    i + 1
                );
            }
            // One more agreeing peer is one more than the adversary can field, so it confirms.
            assert_eq!(
                r.observe([f as u32, 0, 0], lie),
                Some(lie),
                "q={q}: f+1 = {} agreeing peers must confirm, or the quorum is unreachable rather than safe",
                f + 1
            );
        }
    }
}

