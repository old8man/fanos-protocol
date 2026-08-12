//! # The node's memory budget, summed — and the deficit that summing reveals
//!
//! **This module exists because the sum was never taken (#213), and taking it shows the accounting does not
//! close.** Three subsystems each reserved "a share of the 256 MiB node" — `fanos_runtime`'s
//! `STORE_MEMORY_BUDGET` (128 MiB), `fanos_diaulos::budget`'s `SESSION_MEMORY_BUDGET` (64 MiB),
//! `fanos_aphantos`'s `GATHER_MEMORY_BUDGET` (64 MiB) — written by three authors who could not see one
//! another. They sum to **exactly the whole recommendation**, leaving nothing for the process's own resident
//! set, and nothing for two further consumers that cost gigabytes:
//!
//! | term | bytes | stated where |
//! |---|---|---|
//! | store | 128 MiB | derived in #118 |
//! | sessions | 64 MiB | derived in #205 |
//! | gathers | 64 MiB | per-entry cost corrected in #218 |
//! | exit datagrams | 16 MiB | named in #254 — spent all along, counted only now |
//! | proxy associations | 8 MiB | named in #254 — and the naming is what created the bound |
//! | threshold router queues | 40 MiB | named in #294 — one of the two was spent all along, the other had no bound |
//! | **process resident** | **45 MiB** | measured, quoted by `fanos_diaulos::budget`'s header |
//! | inbound QUIC credit | **unnamed** | ≈250 MB *per connection* by quinn's defaults (#245) |
//!
//! So the named shares plus the measured resident cost are **365 MiB against a 256 MiB recommendation** — a
//! 109 MiB overcommit before the transport takes a byte. Unnamed is not zero; it is unbounded.
//!
//! **The overcommit rising is the module working, not the node getting heavier.** It read 45 MiB when three
//! shares were named, 61 once the exit's receive buffers were, and 109 once the router's were; nothing was
//! allocated at any of those steps — see each share's own doc for which of the two reasons applies. Every
//! future naming moves it the same way, and a reader who treats the figure as a health score rather than as
//! a coverage report will draw the opposite conclusion from the one the evidence supports. The VPN datapath
//! left this table on the other side: #247 cut its per-flow buffer by 51× and it now fits inside ordinary
//! process residency rather than needing a share.
//!
//! ## Why this module states the deficit instead of removing it
//!
//! Rebalancing is a decision with measurements behind it: `STORE_MEMORY_BUDGET` is derived in #118 and
//! `SESSION_MEMORY_BUDGET` in #205, each against its own subsystem's admission rule. Quietly shrinking them
//! here would replace three derivations with one author's preference — the very move that produced the
//! problem, one level up. What was missing was never a smaller number; it was **the sum**.
//!
//! `fanos_aphantos`'s own doc states the rule this module implements: *"a budget that is not a constant
//! cannot be summed with its neighbours."* Each share is now a constant in one place, the deficit is a
//! number, and `tests::the_overcommit_does_not_grow` is a ratchet: a new share, or a larger one, fails
//! there instead of being discovered in production. #207 (deriving `MemoryMax=`) is unblocked by the
//! accounting existing, not by it closing — an enforcement figure set above a known overcommit is a decision
//! someone can now take with the number in front of them.
//!
//! ## These are the shares themselves, not copies of them
//!
//! The first draft of this module restated the three numbers and a guard compared them against their
//! owners, because `fanos-primitives` sits below every consumer and cannot import from them. The direction
//! was available the other way round: all four consumers already depend on this crate, so
//! `STORE_MEMORY_BUDGET`, `SESSION_MEMORY_BUDGET` and `GATHER_MEMORY_BUDGET` now *take* their value from
//! here. Drift is deleted rather than detected — which is why the guard that remains
//! (`no_subsystem_declares_its_memory_share_as_a_literal`, in `fanos-cli`'s architecture suite) watches the
//! door back rather than the numbers.
//!
//! Each subsystem keeps its own name for its share, and keeps deriving everything downstream from it —
//! `MAX_STORE_ENTRIES` from the store's (#118), `MAX_SESSIONS` from the sessions' (#205). What moved is only
//! where the quantity is stated, which is the one place it can be summed.

/// The memory a FANOS node is documented to run within.
///
/// Not a limit the code enforces — it is the figure the deployment guide gives an operator and the figure
/// every subsystem's share is a fraction of.
pub const NODE_MEMORY_BUDGET: usize = 256 * 1024 * 1024;

/// Measured resident cost of the process outside every named share: allocator arenas, task stacks, rustls
/// state, the engine's own structures.
///
/// Quoted by `fanos_diaulos::budget`'s header as "~45 MiB is measured resident for everything else". Named
/// here so it is part of the sum rather than a sentence beside it.
pub const PROCESS_RESIDENT: usize = 45 * 1024 * 1024;

/// The erasure-coded content store (`fanos_runtime::overlay::STORE_MEMORY_BUDGET`, derived in #118).
pub const STORE_SHARE: usize = 128 * 1024 * 1024;

/// DIAULOS session queues (`fanos_diaulos::budget::SESSION_MEMORY_BUDGET`, derived in #205).
pub const SESSION_SHARE: usize = 64 * 1024 * 1024;

/// APHANTOS pending gathers (`fanos_aphantos`'s `GATHER_MEMORY_BUDGET`; per-entry cost corrected in #218).
pub const GATHER_SHARE: usize = 64 * 1024 * 1024;

/// Clearnet exit UDP receive buffers (`fanos_node::exit::EXIT_DATAGRAM_MEMORY_BUDGET`) — one
/// `MAX_DATAGRAM_LEN` per live session, and `MAX_UDP_DATAGRAM_SESSIONS` is what this share then buys (#254).
///
/// **A ceiling this share grants, not a copy of a product computed elsewhere.** The real cost is
/// `fanos_diaulos::budget::MAX_SESSIONS × fanos_node::exit::MAX_DATAGRAM_LEN`, and this crate sits below
/// both and cannot see either — the same direction problem this module's header describes. So the share is
/// the budgeted ceiling, and `fanos-node`'s
/// `the_exit_datagram_buffers_fit_the_share_the_budget_grants_them` proves the product fits under it. That
/// is the shape `STORE_SHARE → MAX_STORE_ENTRIES` already uses, one crate over.
///
/// 65535 per session is **not** the #247 defect repeated. That one was a buffer sized for a datagram the
/// stack could not produce; this is a raw UDP socket facing the internet, where the kernel really does
/// reassemble up to 65507 bytes. The size is right and the *accounting* was missing: 246 sessions × 64 KiB
/// = 15.4 MiB that no share named. 16 MiB is the next binary step above it, so a session count that moves
/// slightly does not immediately breach.
pub const EXIT_DATAGRAM_SHARE: usize = 16 * 1024 * 1024;

/// SOCKS5 UDP association receive buffers (`fanos_proxy::udp::ASSOCIATION_MEMORY_BUDGET`) — one
/// `MAX_UDP` per live association, and `MAX_ASSOCIATIONS` is what this share then buys (#254).
///
/// **The one place in this table where naming the share also had to create the bound.** The exit's count was
/// capped already and only the accounting was missing; here nothing limited how many associations could
/// exist — the accept loop spawns per connection and never counts — so "unbounded, but the client is local
/// and trusted" was a qualification living in an author's head rather than in the code. A share with no
/// enforcement is a wish.
///
/// 8 MiB is half the exit's, and the asymmetry is the point: the exit serves a cell, a SOCKS5 proxy serves
/// one operator's own applications. 128 concurrent UDP associations is far past what a desktop's browser,
/// resolver and torrent client hold at once, and the bound exists to stop a runaway loop taking the node
/// down with it, not to ration ordinary use.
pub const PROXY_ASSOCIATION_SHARE: usize = 8 * 1024 * 1024;

/// The threshold router's **send-side queues** (`fanos_aphantos`'s `ROUTER_QUEUE_MEMORY_BUDGET`) — the
/// constant-rate `outbox` when cover traffic is on, and `mix_pending` when it is off (#294, #295).
///
/// **One share for two queues, because the two modes are mutually exclusive.** `forward_send` branches on
/// `cover_interval`: non-zero queues to the outbox and returns, zero falls through to the per-cell mix
/// delay. A router in cover mode never fills `mix_pending`; a router without cover never fills the outbox.
/// So the share is what *whichever one is active* may hold, and both counts divide it — splitting it would
/// reserve half for a queue that is provably empty.
///
/// 40 MiB is not a new cost. It is what the existing `MAX_OUTBOX = 2048` already held at
/// `THRESHOLD_ONION_LEN` per cell, now named so it can be summed — which is the whole subject of #213, and
/// this is the third consumer to be found outside the sum after the two the doc below already names. Naming
/// it raises the reported [`overcommit`] rather than lowering it, and that is the honest direction: the
/// memory was always being used.
///
/// **The second queue had no bound at all**, and naming the share is what created one. `mix_pending` grew
/// with the offered rate on a configuration the tree presents as a supported trade (`cover_interval = 0`,
/// "an operator can zero them to trade anonymity for bandwidth/latency") — with one live timer per entry
/// and no admission check. The remedy could not be a per-source quota, the shape #211 used for shards,
/// because an onion router deliberately does not know the source. A global cap was the only form available,
/// which is precisely why the sibling branch already had one.
pub const THRESHOLD_ROUTER_SHARE: usize = 40 * 1024 * 1024;

/// Every named share, so a reader cannot see the sum without seeing the terms.
pub const SHARES: [(&str, usize); 6] = [
    ("store", STORE_SHARE),
    ("sessions", SESSION_SHARE),
    ("gathers", GATHER_SHARE),
    ("exit datagrams", EXIT_DATAGRAM_SHARE),
    ("proxy associations", PROXY_ASSOCIATION_SHARE),
    ("threshold router queues", THRESHOLD_ROUTER_SHARE),
];

/// The sum of every **named** share. Two known consumers are absent from it by their own defect, not by
/// design: inbound QUIC credit (#245) and the VPN datapath (#247) have never claimed one.
///
/// A third was absent until #294 — the threshold router's send queues — and it was absent from *this list of
/// absentees* too, which is the part worth keeping in view: a register of known gaps is not a proof that the
/// gaps are known. It was found by scanning every `MAX_*` bound for a per-item size, not by reading here.
#[must_use]
pub const fn allocated() -> usize {
    STORE_SHARE
        + SESSION_SHARE
        + GATHER_SHARE
        + EXIT_DATAGRAM_SHARE
        + PROXY_ASSOCIATION_SHARE
        + THRESHOLD_ROUTER_SHARE
}

/// How far the named shares plus the measured resident cost exceed the recommendation. **Zero would mean the
/// accounting closes**; today it does not, and the figure is the point of this module.
#[must_use]
pub const fn overcommit() -> usize {
    (allocated() + PROCESS_RESIDENT).saturating_sub(NODE_MEMORY_BUDGET)
}

/// What a subsystem without a share could ask for. `0` while [`overcommit`] is non-zero — which is precisely
/// the state #245 and #247 were allocated *from*.
#[must_use]
pub const fn unallocated() -> usize {
    (NODE_MEMORY_BUDGET.saturating_sub(PROCESS_RESIDENT)).saturating_sub(allocated())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: usize = 1024 * 1024;

    /// **The ratchet.** The overcommit is 109 MiB today. It may shrink — a rebalance is exactly the decision
    /// this module exists to inform — but it must not grow, and a further subsystem taking "a share" must
    /// fail here rather than in a deployment.
    ///
    /// **It went 45 → 61 → 69 → 109 MiB as #254 named two consumers and #294 a third, and no step is a
    /// regression.** The exit's 16 MiB were already being spent, every day, on every node running the exit
    /// role; the proxy's 8 MiB were *unbounded* until the share created the bound. What changed is that the
    /// sum can see them. A reader who takes the rise as "the node got heavier" has it exactly backwards: 45
    /// was understated, and the consumer this module's header still lists as unnamed means 109 is
    /// understated too. The figure only becomes trustworthy by going *up* first.
    ///
    /// **The 40 MiB #294 added are not new bytes, and they repeat #254's two reasons at once** — which is
    /// possible because [`THRESHOLD_ROUTER_SHARE`] is one share over two mutually exclusive queues. With
    /// cover traffic on, the `outbox` held `2048 × THRESHOLD_ONION_LEN` = exactly 40 MiB before anyone
    /// summed it, so those are *newly counted*, the exit's case. With cover traffic off, `mix_pending` had
    /// no bound at all and the share is what created one, so those are *newly bounded*, the proxy's case.
    /// Neither queue was made to hold a byte it could not hold the day before.
    ///
    /// **This ratchet was red at `237e0e1` and the commit that moved the sum is what left it so.** That
    /// commit added the share, updated `allocated()`, and even corrected the citation in `fanos-node`'s
    /// exit tests to 109 — while this bound, in the crate that owns the number, stayed at 69. A per-crate
    /// gate cannot see it: the share is declared here and spent two crates away.
    #[test]
    fn the_overcommit_does_not_grow() {
        assert!(
            overcommit() <= 109 * MIB,
            "the named shares plus the measured resident cost now exceed the node recommendation by {} MiB, \
             up from 109. Either a share grew or one was added. If it was added, that is progress and this \
             bound moves WITH a note saying whether the bytes are new or merely newly counted; if a share \
             grew, it is a decision to take against this sum rather than against a comment in one subsystem \
             (#213, #254, #294).",
            overcommit() / MIB
        );
    }

    /// The arithmetic the tree could not do before, kept as a number rather than a memory — the shape
    /// `fanos_diaulos::budget` already uses for the bound it replaced.
    #[test]
    fn the_stated_shares_leave_nothing_for_the_process_or_the_wire() {
        assert_eq!(
            STORE_SHARE + SESSION_SHARE + GATHER_SHARE,
            256 * MIB,
            "the three shares written before anyone summed them were exactly the whole recommendation"
        );
        assert_eq!(
            allocated(),
            320 * MIB,
            "and the three consumers found outside the sum since — #254's two and #294's router queues — \
             are 64 MiB on top of a recommendation the first three had already spent whole"
        );
        assert_eq!(unallocated(), 0, "a further consumer would be dividing zero");
        assert_eq!(overcommit(), 109 * MIB, "before the transport takes a byte");
    }

    /// Every share is listed, so the sum cannot drift away from the terms it is made of.
    #[test]
    fn the_list_and_the_sum_are_the_same_numbers() {
        let listed: usize = SHARES.iter().map(|(_, v)| v).sum();
        assert_eq!(listed, allocated(), "SHARES and allocated() must not drift apart");
    }

    /// **The two consumers that never claimed a share are the reason this is not merely tidy.**
    ///
    /// A share of zero does not make a cost of zero: measured, these two dwarf every stated share put
    /// together. Pinned so that closing #245/#247 has a number to close *against*.
    #[test]
    fn the_unnamed_consumers_were_the_large_ones() {
        // #245: quinn's defaults credited 100 uni + 100 bidi streams at 1.25 MB, plus send and datagram
        // buffers — per inbound connection, before the application read a byte.
        //
        // Units matter here and cost me a first draft: quinn's figures are decimal MB, the shares are binary
        // MiB. 262 MB is *less* than 256 MiB (268 435 456 B), so "exceeds every share combined" was false by
        // 2% — the true statement is the sharper one below, against the largest single share.
        let per_connection = (100 + 100) * 1_250_000 + 8 * 1_250_000 + 1_250_000 + 1_000_000;
        assert!(
            per_connection > 2 * (STORE_SHARE - STORE_SHARE / 20),
            "one inbound connection's default credit ({} MB) was nearly twice the largest stated share \
             (store, {} MiB) — and MAX_INBOUND_CONNECTIONS admits 512 of them",
            per_connection / 1_000_000,
            STORE_SHARE / (1024 * 1024)
        );

        // #247: MAX_UDP_FLOWS × 2 directions × UDP_TUNNEL_BUFFER × the packet ceiling.
        let tunnels: usize = 4096 * 2 * 64 * 65_535;
        assert!(
            tunnels > 100 * NODE_MEMORY_BUDGET,
            "the tunnel map's ceiling ({} GB) was over a hundred whole node budgets",
            tunnels / 1_000_000_000
        );
    }
}
