//! **Which addresses this node may put packets at, and why the answer differs by consumer (#170, #171).**
//!
//! Two call sites in the whole workspace dial a remote address a *peer* chose: the clearnet exit
//! (`fanos-node/src/exit.rs`) and the NAT hole-punch (`driver.rs::accept_holepunch`). #170 gave the exit a
//! deny-by-default filter; the punch path had none, and its own doc-comment names the harm precisely — "a
//! fleet of FANOS nodes becomes a reflector aimed at a third party who never joined anything" — before
//! bounding two *other* properties. No directory write before the coordinate is proven, and at most one
//! outstanding punch per coordinate, are both correct and both derived. **Neither constrains where the
//! Initials go.** Bounding the count limits the rate; it does not limit the target.
//!
//! # The two policies are not one policy with a flag
//!
//! They differ because the questions differ, and collapsing them would break one of the two:
//!
//! * [`Policy::Clearnet`](crate::dial_policy::Policy::Clearnet) — an exit relays for an anonymous third party to a destination **the operator never
//!   chose**. The operator's own networks must therefore be unreachable, so: globally routable only. Private,
//!   CGNAT and link-local are all refused, which is what keeps `169.254.169.254` — every cloud's credential
//!   endpoint — out of reach.
//! * [`Policy::Overlay`](crate::dial_policy::Policy::Overlay) — a punch dials a **claimed member of this overlay**. A FANOS peer legitimately sits
//!   on `10/8` or `192.168/16`: a datacenter deployment, a home LAN, a local testnet — and NAT traversal is
//!   exactly what that topology needs. Applying the exit's rule here would break the feature. What is never
//!   legitimate is an address that cannot *be* a distinct peer.
//!
//! IPv4 link-local (`169.254/16`) is refused by BOTH, and it earns its own line rather than being smuggled in
//! with the rest: a link-local-only deployment cannot do NAT traversal at all, so it is not a topology the
//! punch path serves, while the metadata endpoint provably lives there.
//!
//! # What is deliberately NOT here
//!
//! This says nothing about whether an address is *reachable*, only whether it may be dialled. And it is not a
//! substitute for the coordinate proof: the punch path still inserts nothing into the directory until a QUIC
//! handshake completes and the dialled coordinate is proven, so a victim that is not a FANOS node cannot be
//! recorded as a peer. This narrows what can be *aimed at*; that guard is what stops it being *believed*.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Which realm a dial is allowed to reach.
///
/// A named policy per consumer, with the derivation on each variant, rather than one predicate and a boolean:
/// a `bool` argument at a call site says nothing about which rule the caller meant, and the two rules disagree
/// on a range (`10/8`) that a reader would otherwise have to infer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    /// **Globally routable only** — for a dial to a destination the operator did not choose (the exit).
    Clearnet,
    /// **Anything that can be a distinct peer** — for a dial to a claimed member of this overlay (the punch).
    ///
    /// Permits private and CGNAT ranges, because a deployment behind NAT is the case NAT traversal exists for.
    ///
    /// **And permits loopback, which the first version of this refused.** The derivation for refusing it was
    /// "another node is never at OUR 127/8" — and that is simply false: several nodes on one host sit at
    /// `127.0.0.1` on different ports, which is how a local testnet, a developer's box and this project's own
    /// `hole_punch.rs` all run. Two of those tests went red on the refusal, and a test contradicting a
    /// derivation is evidence about the derivation. The harm from permitting it is a QUIC Initial at our own
    /// machine — no amplification, nothing we could not already send; the harm from refusing it is a whole
    /// class of deployment that cannot traverse. The address that actually matters, `169.254.169.254`, is
    /// refused here as it is everywhere.
    Overlay,
    /// [`Clearnet`](Self::Clearnet) plus loopback, for a test that runs its target on `127.0.0.1`.
    ///
    /// A named variant rather than a builder method, so a production caller cannot reach it by forgetting to
    /// set something — the hole it re-opens is the one #170 closed.
    ClearnetOrLoopback,
}

/// Whether `addr` may be dialled under `policy`.
///
/// Deny-by-default in both realms: every arm lists what is refused, so a range nobody thought about is
/// refused rather than permitted.
#[must_use]
pub fn may_dial(addr: &IpAddr, policy: Policy) -> bool {
    if policy == Policy::ClearnetOrLoopback && addr.is_loopback() {
        return true;
    }
    match addr {
        IpAddr::V4(v4) => v4_ok(*v4, policy),
        IpAddr::V6(v6) => v6_ok(*v6, policy),
    }
}

/// The ranges no dial may ever reach, in either realm — an address that cannot *be* a distinct peer.
fn v4_never(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_broadcast()                         // 255.255.255.255
        || v4.is_multicast()                         // 224/4      RFC 5771
        || v4.is_unspecified()                       // 0.0.0.0
        || o[0] == 0                                 // 0/8        RFC 1122 "this network"
        || v4.is_link_local()                        // 169.254/16 RFC 3927 — the metadata endpoint lives here
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)   // 192.0.0/24 RFC 6890
        || v4.is_documentation()                     // 192.0.2/24, 198.51.100/24, 203.0.113/24  RFC 5737
        || (o[0] == 198 && (o[1] & 0xfe) == 18)      // 198.18/15  RFC 2544 benchmarking
        || (o[0] & 0xf0) == 240 // 240/4      RFC 1112 reserved
}

fn v4_ok(v4: Ipv4Addr, policy: Policy) -> bool {
    if v4_never(v4) {
        return false;
    }
    match policy {
        // A peer behind NAT — or on this very host, at another port — is the case the punch exists for.
        Policy::Overlay => true,
        Policy::Clearnet | Policy::ClearnetOrLoopback => {
            let o = v4.octets();
            !(v4.is_loopback()                       // 127/8      RFC 1122
                || v4.is_private()                   // 10/8, 172.16/12, 192.168/16   RFC 1918
                || (o[0] == 100 && (64..128).contains(&o[1]))) // 100.64/10  RFC 6598 CGNAT
        }
    }
}

/// The v6 half. IPv4-mapped and IPv4-compatible forms recurse into the v4 rules so no range is reachable by
/// wrapping it — the bypass an address filter is most likely to have.
fn v6_ok(v6: Ipv6Addr, policy: Policy) -> bool {
    let seg = v6.segments();
    let never = v6.is_unspecified()                       // ::
        || v6.is_multicast()                         // ff00::/8
        || (seg[0] & 0xffc0) == 0xfe80               // fe80::/10  RFC 4291 link-local
        || (seg[0] == 0x2001 && seg[1] == 0xdb8);    // 2001:db8::/32 RFC 3849 documentation
    if never {
        return false;
    }
    if let Some(m) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4())
        && !v4_ok(m, policy)
    {
        return false;
    }
    match policy {
        Policy::Overlay => true,
        // fc00::/7 RFC 4193 unique-local — the v6 analogue of RFC 1918, and refused for the same reason.
        Policy::Clearnet | Policy::ClearnetOrLoopback => (seg[0] & 0xfe00) != 0xfc00 && !v6.is_loopback(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// **The two policies disagree, and this is the assertion that pins them apart.**
    ///
    /// A `10/8` peer is punchable and is not relayable-to. If someone later collapses the two into one
    /// predicate, exactly one of these two lines goes red whichever way they collapse it — which is the only
    /// reason to have a test for a disagreement rather than for each rule separately.
    #[test]
    fn a_private_peer_is_punchable_and_is_never_an_exit_destination() {
        for private in ["10.0.0.7", "192.168.1.5", "172.16.4.4", "100.64.0.1"] {
            assert!(may_dial(&ip(private), Policy::Overlay), "{private}: a peer behind NAT is dialable");
            assert!(
                !may_dial(&ip(private), Policy::Clearnet),
                "{private}: an exit must never reach the operator's own network"
            );
        }
        // The v6 analogue, so the disagreement is not accidentally v4-only.
        assert!(may_dial(&ip("fc00::1"), Policy::Overlay), "unique-local is a legitimate peer");
        assert!(!may_dial(&ip("fc00::1"), Policy::Clearnet), "and never an exit destination");
    }

    /// What no realm may ever dial. Every entry is a range that cannot host a distinct peer, plus the one
    /// that can and must not: the cloud metadata endpoint.
    ///
    /// Plain loopback is deliberately absent — [`Policy::ClearnetOrLoopback`] exists to permit it, and its own
    /// test covers the other two realms. **The v4-compatible form `::127.0.0.1` stays**, and the asymmetry is
    /// the point: the hatch opens on `IpAddr::is_loopback()`, which is `::1` and `127/8` only, so a wrapped
    /// loopback is refused even in the test realm. A filter whose exemption is wider than its author thinks is
    /// how this class of hole is usually reopened.
    #[test]
    fn an_address_that_cannot_be_a_peer_is_refused_by_both_policies() {
        let forbidden = [
            ("unspecified", "0.0.0.0"),
            ("this network", "0.1.2.3"),
            ("multicast", "224.0.0.1"),
            ("broadcast", "255.255.255.255"),
            ("link-local / METADATA", "169.254.169.254"),
            ("RFC 6890", "192.0.0.1"),
            ("documentation", "192.0.2.1"),
            ("benchmarking", "198.18.0.1"),
            ("reserved", "240.0.0.1"),
            ("v6 unspecified", "::"),
            ("v6 multicast", "ff02::1"),
            ("v6 link-local", "fe80::1"),
            ("v6 documentation", "2001:db8::1"),
            ("v4-mapped metadata", "::ffff:169.254.169.254"),

        ];
        for (what, addr) in forbidden {
            for policy in [Policy::Overlay, Policy::Clearnet, Policy::ClearnetOrLoopback] {
                assert!(!may_dial(&ip(addr), policy), "{what} ({addr}) must be refused under {policy:?}");
            }
        }
    }

    /// And the ordinary case still works, in both realms — a filter that refuses everything is not a filter.
    #[test]
    fn a_globally_routable_address_is_dialable_everywhere() {
        for addr in ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            for policy in [Policy::Overlay, Policy::Clearnet, Policy::ClearnetOrLoopback] {
                assert!(may_dial(&ip(addr), policy), "{addr} under {policy:?}");
            }
        }
    }

    /// Loopback is refused by the EXIT realm and by nothing else — the two ways it can be reached are the
    /// named test policy and the overlay, and each has its own reason on its own variant.
    #[test]
    fn loopback_is_refused_by_the_exit_realm_and_reachable_by_the_other_two() {
        assert!(may_dial(&ip("127.0.0.1"), Policy::ClearnetOrLoopback));
        assert!(may_dial(&ip("::1"), Policy::ClearnetOrLoopback));
        assert!(!may_dial(&ip("127.0.0.1"), Policy::Clearnet));
        assert!(
            may_dial(&ip("127.0.0.1"), Policy::Overlay),
            "several nodes on one host sit at 127.0.0.1 on different ports — a local testnet, a developer's \
             box, and this crate's own hole_punch.rs. Refusing it broke two of those tests, which is how the \
             first derivation here ('a peer is never at OUR loopback') was found to be false."
        );
    }
}
