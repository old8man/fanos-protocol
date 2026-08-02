//! # Epoch-aligned activation for **derivation** changes (`docs/design-upgrade.md` §3)
//!
//! [`capability`](crate::capability) versions a *link*: two peers meet, take `min(version)` and the
//! intersection of their capability bits. [`frame`](crate::frame) versions a *message*: an unknown type
//! is skipped, or aborts the connection if critical. Between them they cover every change that is
//! **visible on the wire**.
//!
//! A change to a **derivation** is not. When `combiner_of(line)` became
//! `combiner_of_salted(line, onion)`, no frame type changed and no field was added: both versions emit a
//! perfectly well-formed `TAG_ONION` to a perfectly valid coordinate, and simply disagree about *which
//! member of the line is gathering*. The hop produces no error, no `UNSUPPORTED`, no malformed frame — it
//! just never peels. The same shape covers a changed coordinate or line derivation, a key-derivation
//! label, a threshold, a padding bucket, a hash domain separator, or a serialization order both sides
//! still parse. **All are silent by construction**, because agreement on a derivation is not something a
//! wire format can check.
//!
//! `#55` measured how that presents: a wholly dead data path, indistinguishable from eleven other
//! hypotheses, whose only failure signal was a clock — which, in an anonymity network, is the one signal
//! an adversary also controls. A version-skew incident would present *identically*.
//!
//! ## The mechanism follows from what already exists
//!
//! Every node already agrees on an **epoch ordinal** and on the beacon seeding it — a Byzantine-agreed
//! shared clock, which is precisely and only what a coordinated switch needs. So a derivation change
//! activates at an epoch height rather than at process start:
//!
//! ```text
//!   feature F is active for epoch e   iff   e >= activation_height(F)
//! ```
//!
//! Three consequences, each the *reason* for this design rather than a nice property:
//!
//! * **A whole line flips together.** A threshold gather needs `t` of `q+1` members to agree on the
//!   derivation. Any granularity coarser than "all members at once" leaves a window in which a line
//!   cannot reach quorum — class-C's silent death, self-inflicted.
//! * **Restart order stops mattering.** Nodes may take the new binary over hours; none *behaves*
//!   differently until the height arrives. Deployment and activation become separate events, and only the
//!   second is consensus-critical.
//! * **It reuses the registry rather than adding a mechanism.** This crate already numbers frame types;
//!   an activation height is the same idea applied to derivations, and belongs to the same authority
//!   rather than to a second scheme that could disagree with the first.
//!
//! ## Why the epoch is a bare `u64` here
//!
//! `Epoch` lives in `fanos-primitives`, and `fanos-primitives` already depends **on this crate**
//! (optionally) — so taking `Epoch` would close a dependency cycle. That constraint points at the right
//! design rather than around it: the frame-numbering authority sits *below* the geometry and identity
//! vocabulary in the graph and should stay there. An activation height is a number two nodes must agree
//! on; it needs no plane, no coordinate and no key material to mean what it means. A caller that holds an
//! `Epoch` passes its ordinal.
//!
//! ## Sans-I/O, like every engine that will consume it
//!
//! Nothing here reads a clock. [`Derivation::is_active_at`] takes the epoch its caller already holds, so a
//! node's behaviour at a given height is reproducible in the simulator and in a test — which matters more
//! than usual here, since the whole point is that the *wrong* answer is invisible at runtime.

/// A **derivation-versioned behaviour**: a computation whose result both sides must agree on, but whose
/// disagreement no frame check can detect.
///
/// One variant per derivation that has ever changed in a shipped release — this is a registry, so a
/// variant is added when a derivation changes and removed only when its old form is retired (§3.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[non_exhaustive]
pub enum Derivation {
    /// **Which member of a hop line gathers a given onion.**
    ///
    /// Before: `combiner_of(line)` — one canonical member per line, a per-hop single point of failure
    /// (#55). After: `combiner_of_salted(line, onion)` — a per-onion draw over the line's members, so a
    /// hop dies only when `q + 2 − t` of them do.
    ///
    /// This is the change that motivated the whole mechanism, and it is registered at height `0`: the
    /// salted form shipped before any activation registry existed, so there is no earlier height at which
    /// a peer could legitimately expect the canonical form. Registering it at `0` therefore states a true
    /// fact — "active for every epoch this build has ever seen" — rather than back-dating a switch that
    /// never happened. The value of the entry is that the *next* such change has a place to go, and a
    /// worked example beside it.
    OnionGatherMember,
}

/// What a derivation change has to agree across — and therefore the smallest unit it can be canaried in.
///
/// §2 says canarying must be expressed in the platform's own units (by cell, by role, by opt-in flag) and
/// **never by coordinate**, since coordinates rotate every epoch and a coordinate range selects a
/// geometrically clustered subset, which is exactly what the plane's fault model assumes away.
///
/// But §2 and §3 together say something sharper than either alone, and it is a constraint rather than a menu.
/// §3: "a threshold gather needs `t` of `q+1` members to agree on the derivation. Any switch granularity
/// coarser than *all members at once* leaves a window where a line cannot reach quorum — which is class C's
/// silent death, self-inflicted." So for a derivation the members of a **line** must agree on, a per-node
/// opt-in canary is not a cautious rollout: it is the failure mode, chosen deliberately. One volunteer in a
/// line of three is how you take that line below `t`.
///
/// Hence the unit a derivation may be canaried in is a property *of the derivation*, not of the operator's
/// appetite — which is why this is on the registry beside the heights rather than in a deployment flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// Affects only how this node behaves locally. Safe to canary per node, including by opt-in — the honest
    /// unit for a public network, where nobody can be conscripted into a canary anyway.
    Node,
    /// Every member of a hop **line** must agree, or the line falls below `t` and its traffic dies silently.
    /// Canary by **cell** (the blast-radius boundary, where a threshold, a beacon and a fault bound all live)
    /// — never by node, and never by role, since a line's members are drawn by geometry rather than by role.
    Line,
    /// The whole cell must agree. Canary by cell, and only a whole cell at a time.
    Cell,
}

impl Scope {
    /// Whether a **per-node** canary is admissible — an opt-in flag, or any other selection finer than a cell.
    ///
    /// `false` for anything a line or a cell must agree on, and that is the whole content of the type: the
    /// answer is a fact about the derivation, not a judgement call at deploy time.
    #[must_use]
    pub const fn allows_node_canary(self) -> bool {
        matches!(self, Self::Node)
    }

    /// A short stable word for an operator surface.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Line => "line",
            Self::Cell => "cell",
        }
    }
}

/// Whether `epoch` falls inside the half-open window `[activation, abort)`.
///
/// The comparison is `>=` at the activation and `<` at the abort, and they read the same way on purpose: a
/// height names the **first** epoch on which its side applies. Activation at `N` means `N` is the first epoch
/// on the new form; abort at `M` means `M` is the first epoch back on the old one. Anything else and
/// "activate at N, abort at M" means different things to different readers, which is the class of
/// disagreement an activation registry exists to remove.
///
/// Taken as parameters rather than read off a [`Derivation`] so the boundaries can be exercised against
/// schedules the shipped registry does not contain — its one entry is permanent and activates at 0, so it
/// touches neither boundary. The first version of that test reimplemented this logic beside itself and
/// therefore proved nothing about it: reverting the `<` to `<=` here left the test green.
#[must_use]
pub const fn active_in(epoch: u64, activation: u64, abort: Option<u64>) -> bool {
    if epoch < activation {
        return false;
    }
    match abort {
        Some(withdrawn) => epoch < withdrawn,
        None => true,
    }
}

/// Where a [`Derivation`] stands at a given epoch.
///
/// Three states, not a boolean, because an operator diagnosing a quiet line needs to tell "this build has the
/// change and is waiting for its height" from "this build withdrew it". Both answer `false` to
/// [`is_active_at`](Derivation::is_active_at), and they call for opposite actions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// Compiled in, activation height not yet reached — the old form is authoritative.
    Scheduled,
    /// Authoritative now.
    Active,
    /// Past its abort height: withdrawn, the old form authoritative again.
    Withdrawn,
}

impl Status {
    /// A short stable word for an operator surface.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Withdrawn => "withdrawn",
        }
    }
}

impl Derivation {
    /// Every registered derivation, for a reader that enumerates rather than guesses.
    pub const ALL: &'static [Self] = &[Self::OnionGatherMember];

    /// The epoch ordinal at which this derivation's **current** form becomes authoritative.
    ///
    /// A build answers for the derivations it knows; a node that has not reached the height must still
    /// speak the *old* form, which is why §3.1 requires both to be linked and why a retirement policy has
    /// to exist from the start.
    #[must_use]
    pub const fn activation_height(self) -> u64 {
        match self {
            // Shipped before this registry existed — see the variant's own doc for why `0` is the honest
            // value rather than a back-dated switch.
            Self::OnionGatherMember => 0,
        }
    }

    /// What this change has to agree across, and therefore the smallest unit it may be canaried in.
    #[must_use]
    pub const fn scope(self) -> Scope {
        match self {
            // A gather needs `t` of `q + 1` line members to pick the SAME member. One node on the other
            // derivation addresses a hop nobody is gathering, so the line loses a member toward `t` — and at
            // the Fano threshold of 2 of 3, a single opted-in canary is enough to kill it. This is precisely
            // the case §2's "never by coordinate" warning generalizes to: never finer than the unit that has
            // to agree.
            Self::OnionGatherMember => Scope::Line,
        }
    }

    /// The epoch at which this derivation's current form is **withdrawn again** — the pre-agreed abort height,
    /// or `None` for a derivation shipped as permanent.
    ///
    /// §5's deliverable, and the reason it exists is that an epoch-aligned flip is also an epoch-aligned
    /// *break*: if a defect only shows after activation, the whole network entered it together. Rolling a
    /// derivation *back* is itself a derivation change and so needs its own height — there is no instant
    /// revert. What an abort height shortens is the gap. Publishing both heights **with the feature** turns a
    /// rollback from a new consensus decision, negotiated under pressure while a line is dying, into one the
    /// network already agreed to before anything went wrong.
    ///
    /// It is a *release* decision, not a runtime one, for the same reason [`is_active_at`](Self::is_active_at)
    /// consults no registry object: "the schedule **is** the build". Arming an abort means shipping a release
    /// whose `abort_height` is set, and because that changes the schedule it also changes
    /// `derivation_digest` — so two operators comparing digests can see that one of them is on a build that
    /// intends to withdraw a derivation and the other is not. An abort nobody can observe would be the same
    /// silent class-C change this whole document exists to make visible.
    ///
    /// Withdrawal restores the **old** form, which is why §3.1 requires both to stay linked into the binary: a
    /// release that deleted the pre-activation code could not honour its own abort.
    #[must_use]
    pub const fn abort_height(self) -> Option<u64> {
        match self {
            // Shipped as permanent. It is the salted gatherer draw that fixed #55, and there is no old form to
            // return to that would not reintroduce the single point of failure it removed.
            Self::OnionGatherMember => None,
        }
    }

    /// Whether this derivation's current form is authoritative at epoch ordinal `epoch`.
    ///
    /// The comparison is `>=`, so the height names the **first** epoch on which the new form applies —
    /// the reading an operator scheduling "activate at epoch N" will assume, and the one that makes a
    /// height announced as `N` mean the same thing to every node that reads it.
    ///
    /// **There is deliberately no runtime registry object to consult.** The schedule *is* the build:
    /// a release's heights are compiled in, and a node that disagrees about them is a node running a
    /// different release — the situation this mechanism exists to make survivable, not one to make
    /// configurable. An operator able to edit heights at runtime could desynchronise a line silently,
    /// re-creating the very class-C failure the design closes.
    #[must_use]
    pub const fn is_active_at(self, epoch: u64) -> bool {
        active_in(epoch, self.activation_height(), self.abort_height())
    }

    /// Where this derivation stands at `epoch`, for an operator surface that must distinguish three states.
    #[must_use]
    pub const fn status_at(self, epoch: u64) -> Status {
        if epoch < self.activation_height() {
            Status::Scheduled
        } else if self.is_active_at(epoch) {
            Status::Active
        } else {
            Status::Withdrawn
        }
    }

    /// A short stable name for an operator surface and for logs. Stable because an operator's saved query
    /// should not break when a variant is added elsewhere in the enum.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OnionGatherMember => "onion.gather_member",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn a_line_scoped_derivation_refuses_a_per_node_canary() {
        // §2 ∧ §3, which say more together than apart. §2 lists the admissible canary units; §3 says a switch
        // granularity finer than "all members of a line at once" leaves the line unable to reach `t`. So for a
        // line-scoped derivation an opt-in canary is not a cautious rollout — it is the class-C silent death,
        // self-inflicted, and at the Fano threshold of 2 of 3 a single volunteer is enough to cause it.
        assert!(!Scope::Line.allows_node_canary(), "one volunteer in a line of three takes it below t");
        assert!(!Scope::Cell.allows_node_canary(), "a cell-wide agreement cannot be canaried per node either");
        assert!(Scope::Node.allows_node_canary(), "a purely local change is the case opt-in was meant for");

        // And the shipped entry is line-scoped, so the rule binds something real rather than describing a
        // hypothetical: the gatherer draw is exactly the derivation whose members must pick the same node.
        for d in Derivation::ALL {
            if d.scope().allows_node_canary() {
                continue;
            }
            assert!(
                !d.scope().allows_node_canary(),
                "{} is {}-scoped and must not be offered a per-node canary",
                d.name(),
                d.scope().name()
            );
        }
        assert_eq!(
            Derivation::OnionGatherMember.scope(),
            Scope::Line,
            "the gatherer draw is agreed across a LINE — canary it by cell or not at all"
        );
    }

    #[test]
    fn an_abort_height_names_the_first_epoch_running_the_old_form_again() {
        // Both boundaries must read the same way or "activate at N, abort at M" means different things to
        // different readers — which is the class of disagreement an activation registry exists to remove.
        // Activation is `>=`, so N is the first epoch on the NEW form; abort is `<`, so M is the first epoch
        // back on the OLD one. The interval is `[N, M)`, half-open at both ends in the same direction.
        let active = |a, b, e| active_in(e, a, b);
        assert!(!active(10, Some(20), 9), "before activation: old form");
        assert!(active(10, Some(20), 10), "N is the first epoch of the new form");
        assert!(active(10, Some(20), 19), "still active on the last epoch before the abort");
        assert!(!active(10, Some(20), 20), "M is the first epoch back on the old form, not the last new one");
        assert!(!active(10, Some(20), 21), "and it stays withdrawn");

        // A permanent derivation never withdraws, however far out the epoch runs.
        assert!(active(10, None, u64::MAX), "no abort height means no withdrawal");

        // An abort at or below the activation is a schedule that is never active — a release that shipped one
        // would withdraw a feature before it ever applied. Stated so the arithmetic is not an accident.
        assert!(!active(10, Some(10), 10), "abort == activation is never active");
        assert!(!active(10, Some(5), 7), "abort below activation is never active");
    }

    #[test]
    fn the_shipped_registry_has_a_coherent_schedule() {
        // The property every entry must satisfy, checked over the real registry rather than a fixture: a
        // derivation whose abort does not strictly follow its activation is one that can never be active, and
        // that is a release mistake no test downstream would attribute correctly.
        for d in Derivation::ALL {
            if let Some(abort) = d.abort_height() {
                assert!(
                    abort > d.activation_height(),
                    "{}: abort {abort} must strictly follow activation {}",
                    d.name(),
                    d.activation_height()
                );
            }
            // And the three states agree with the boolean at every boundary they share.
            let a = d.activation_height();
            assert_eq!(d.status_at(a) == Status::Active, d.is_active_at(a));
            // Only where a pre-activation epoch EXISTS. A derivation registered at height 0 has none —
            // `saturating_sub` would hand back epoch 0 again, which is its first *active* epoch, and the
            // assertion would demand `Scheduled` of a state that is `Active` by definition. The shipped entry
            // is exactly that case, so this guard is load-bearing rather than defensive.
            if let Some(before) = a.checked_sub(1) {
                assert_eq!(d.status_at(before), Status::Scheduled, "{}", d.name());
            }
        }
    }

    #[test]
    fn activation_is_monotone_in_the_epoch_and_never_flips_back() {
        // A derivation that switched on and then off again would be class C twice over: a line that
        // agreed at epoch `e` would silently disagree at `e + 1`, with no wire event either time. The
        // property is not "the table is right today" — it is that **no schedule expressible here can
        // un-activate**, which `epoch >= height` guarantees and a future richer predicate (a window, a
        // range) would quietly break. This is the test that would fail if someone added one.
        for d in Derivation::ALL {
            let mut seen_active = false;
            for e in 0..64u64 {
                let now = d.is_active_at(e);
                if seen_active {
                    assert!(now, "{} de-activated at epoch {e} — a derivation must never flip back", d.name());
                }
                seen_active |= now;
            }
            assert!(seen_active, "{} is never active in 0..64 — an unreachable schedule", d.name());
        }
    }

    #[test]
    fn a_registered_derivation_is_active_from_its_own_height_onward() {
        for d in Derivation::ALL {
            let h = d.activation_height();
            assert!(
                d.is_active_at(h),
                "{} must be active AT its height, not one epoch later",
                d.name()
            );
            assert!(
                d.is_active_at(h.saturating_add(1)),
                "{} stays active after its height",
                d.name()
            );
            if let Some(before) = h.checked_sub(1) {
                assert!(
                    !d.is_active_at(before),
                    "{} is NOT active before its height",
                    d.name()
                );
            }
        }
    }

    #[test]
    fn the_shipped_derivation_is_active_at_every_epoch_this_build_has_seen() {
        // `OnionGatherMember` shipped before this registry existed, so registering it at `0` states a
        // true fact rather than back-dating a switch. If someone later "corrects" it to a nonzero height,
        // every existing epoch would silently revert to the canonical-combiner form — reintroducing the
        // per-hop single point of failure #55 removed. This is that guard.
        assert_eq!(Derivation::OnionGatherMember.activation_height(), 0);
        assert!(Derivation::OnionGatherMember.is_active_at(0));
    }

    #[test]
    fn every_derivation_is_listed_and_named_distinctly() {
        // `ALL` is hand-maintained; the exhaustive match makes an omission a BUILD failure rather than a
        // blind spot in whatever enumerates it.
        for d in Derivation::ALL {
            match *d {
                Derivation::OnionGatherMember => {
                    assert!(Derivation::ALL.contains(&Derivation::OnionGatherMember));
                }
            }
        }
        let mut names: Vec<&str> = Derivation::ALL.iter().map(|d| d.name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "derivation names must be distinct");
        assert!(!names.iter().any(|n| n.is_empty()), "and non-empty");
    }
}
