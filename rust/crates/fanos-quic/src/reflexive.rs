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
