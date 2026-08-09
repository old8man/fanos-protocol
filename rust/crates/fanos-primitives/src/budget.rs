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
//! | **process resident** | **45 MiB** | measured, quoted by `fanos_diaulos::budget`'s header |
//! | inbound QUIC credit | **unnamed** | ≈250 MB *per connection* by quinn's defaults (#245) |
//! | VPN tunnel queues | **unnamed** | 34 GB across the tunnel map (#247) |
//!
//! So the three stated shares plus the measured resident cost are **301 MiB against a 256 MiB
//! recommendation** — a 45 MiB overcommit before the transport and the datapath take a byte. Unnamed is not
//! zero; it is unbounded.
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

/// Every named share, so a reader cannot see the sum without seeing the terms.
pub const SHARES: [(&str, usize); 3] =
    [("store", STORE_SHARE), ("sessions", SESSION_SHARE), ("gathers", GATHER_SHARE)];

/// The sum of every **named** share. Two known consumers are absent from it by their own defect, not by
/// design: inbound QUIC credit (#245) and the VPN datapath (#247) have never claimed one.
#[must_use]
pub const fn allocated() -> usize {
    STORE_SHARE + SESSION_SHARE + GATHER_SHARE
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

    /// **The ratchet.** The overcommit is 45 MiB today. It may shrink — a rebalance is exactly the decision
    /// this module exists to inform — but it must not grow, and a fourth subsystem taking "a share" must fail
    /// here rather than in a deployment.
    #[test]
    fn the_overcommit_does_not_grow() {
        assert!(
            overcommit() <= 45 * MIB,
            "the named shares plus the measured resident cost now exceed the node recommendation by {} MiB, \
             up from 45. Either a share grew or one was added; both are decisions that must be taken against \
             this sum rather than against a comment in one subsystem (#213).",
            overcommit() / MIB
        );
    }

    /// The arithmetic the tree could not do before, kept as a number rather than a memory — the shape
    /// `fanos_diaulos::budget` already uses for the bound it replaced.
    #[test]
    fn the_three_stated_shares_leave_nothing_for_the_process_or_the_wire() {
        assert_eq!(allocated(), 256 * MIB, "exactly the whole recommendation, before anything else");
        assert_eq!(unallocated(), 0, "a fourth consumer would be dividing zero");
        assert_eq!(overcommit(), 45 * MIB, "and the process's own resident set is already over the line");
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
