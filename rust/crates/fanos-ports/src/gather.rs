//! The **measured gather deadline**: RFC 6298 applied to a threshold engine's share-gather.
//!
//! Every threshold engine in the platform has the same wait — a combiner fans a share request to its
//! line and gathers `t` replies, abandoning the hop/intro/serve at a deadline. That deadline was the
//! same chosen constant (2000 ms) in three engines at once, and
//! `fanos-aphantos/tests/gather_cost.rs` measures why no constant can be right: answering one share
//! request costs **47 ms under `dev` and 1.05 ms under `release` on one machine** — a 45× spread from
//! a build flag alone, before any hardware or load variation. A gather's wall-clock is
//! `RTT + C_partial + Q`, and `Q` — queueing behind requests already accepted — dominates under
//! exactly the contention that matters and fits no formula. #55 measured the constant's cost: gathers
//! expiring at 1 of `t = 2` by the hundreds, turning a demonstrated censorship-survival property into
//! a run-to-run coin flip.
//!
//! So the deadline is **measured**. Each completed gather contributes its elapsed time — all three
//! terms together, under the load the next gather will meet — smoothed in the shape RFC 6298 gives
//! TCP's RTO: `SRTT + 4·RTTVAR`, gains `1/8` and `1/4` unchanged (inventing different ones would be a
//! chosen constant wearing a derivation's clothes). Expiries back off exponentially (§5.5) and
//! contribute **no sample** (Karn's algorithm): an expiry says the deadline was too short, not how
//! long the gather would have taken.
//!
//! Sans-I/O: samples come from the `now` a driver already passes to
//! [`Engine::step`](crate::Engine::step), never from a wall clock — so the simulator reproduces every
//! deadline decision. An engine adopting this must FIRST bound its pending-gather map **by count**,
//! or the deadline becomes a memory-safety parameter the moment it is free to grow.

use crate::Duration;

/// The deadline used **before the first gather completes**, when there is nothing measured to derive
/// one from — the bootstrap slot RFC 6298 fills with its 1 s initial RTO, for the same reason.
///
/// It is generous on purpose and it is *not* the operating value: one completed gather replaces it
/// with a measurement. Being wrong here costs at most a cold node's first gather, which the
/// reliability layer retransmits; being wrong *permanently* is what the former 2000 ms constant did.
pub const INITIAL_GATHER_DEADLINE: Duration = Duration::from_millis(2000);

/// Floor on the derived deadline. Not a tuning knob: it stops a run of unusually fast gathers (an
/// idle node on a loopback) from collapsing the estimate so far that the first genuinely loaded
/// gather is abandoned before its replies can physically arrive. One millisecond is below any real
/// `RTT + C_partial` — the measured `C_partial` alone is 1.05 ms in release — so it can never bind in
/// operation, only in pathology.
pub const MIN_GATHER_DEADLINE: Duration = Duration::from_millis(1);

/// Ceiling on the derived deadline. In-flight gathers are capped by count in every adopting engine,
/// so this does not bound memory; it bounds how long a *dead* hop is believed in — which is what an
/// adversary would stretch by answering ever more slowly to pin gather slots. Ten seconds is far
/// above any honest `RTT + C_partial + Q` measured and far below a stall an operator would not
/// notice.
pub const MAX_GATHER_DEADLINE: Duration = Duration::from_millis(10_000);

/// Cap on the consecutive-expiry exponent. **Sized so that it never binds before
/// [`MAX_GATHER_DEADLINE`] does**, which is a correctness requirement rather than a safety margin:
/// the widest span the backoff must cross is `MIN → MAX`, a factor of `10⁴`, and `2¹⁶ = 65536 > 10⁴`.
/// A smaller exponent cap would silently strand the fastest cells — one whose gathers settle at 1 ms
/// could widen only to `2^k` ms and would keep expiring under a load spike no matter how many times
/// it backed off, which is precisely the failure this mechanism exists to end. So the CEILING is the
/// bound that binds, and this constant only keeps the shift total.
const MAX_GATHER_BACKOFF: u32 = 16;

/// The adaptive gather deadline: an EWMA of observed gather latency plus a margin from its variation,
/// in the shape RFC 6298 gives TCP's RTO (`SRTT`, `RTTVAR`, `RTO = SRTT + 4·RTTVAR`, ×2 backoff on
/// expiry, Karn's rule on samples).
///
/// Shared by every threshold gather in the platform (`ThresholdRouter`, `ThresholdService`,
/// `PorosHost`) because they share the wait's structure — and because the estimate itself
/// ([`srtt`](Self::srtt)/[`var`](Self::var)) is the gather-path load signal the observability plane
/// exports (`docs/design-observability.md` §4.1): it is already computed, so exposing it is free.
#[derive(Clone, Copy, Default)]
pub struct GatherClock {
    /// Smoothed latency estimate; `None` until the first gather completes.
    srtt: Option<Duration>,
    /// Smoothed mean deviation of that estimate.
    var: Duration,
    /// Consecutive expiries since the last completed gather — the exponent of RFC 6298's backoff.
    ///
    /// **Smoothing without backoff is not RFC 6298, and the difference is a measured defect.** An
    /// estimator fed only by *completions* converges to the mean of a quiet period and then holds no
    /// margin for a loud one: when load arrives, gathers expire, and — because an expiry produces no
    /// sample — the estimate never learns that it is now too tight. It expires at the same short
    /// deadline forever. Measured in this codebase: `fanos-sim`'s role-convergence test passed 2/2 at
    /// baseline and failed 2/4 with a backoff-less adaptive deadline, because failing hops starved
    /// the capability directory the role controller reads. RFC 6298 §5.5 is exactly this repair —
    /// `RTO ← RTO × 2` on every timeout, reset on success — and it is what makes the scheme *safe
    /// when the estimate is wrong*, which a pure smoother never is.
    backoff: u32,
}

impl GatherClock {
    /// A cold clock: no sample yet, bootstrap deadline, no backoff.
    #[must_use]
    pub const fn new() -> Self {
        Self { srtt: None, var: Duration(0), backoff: 0 }
    }

    /// A gather's deadline fired without reaching `t`: back off, per RFC 6298 §5.5.
    ///
    /// No latency *sample* is taken here — that is Karn's algorithm, and it matters: an expiry tells
    /// us the deadline was too short, not how long the gather would have taken, so folding a
    /// fabricated duration into `srtt` would corrupt the estimator with a number nobody measured.
    pub fn expired(&mut self) {
        self.backoff = (self.backoff + 1).min(MAX_GATHER_BACKOFF);
    }

    /// Fold in one completed gather's elapsed time, and clear the backoff — the estimate is trusted
    /// again.
    pub fn observe(&mut self, sample: Duration) {
        self.backoff = 0;
        match self.srtt {
            // RFC 6298 (2.2): the first measurement seeds both terms.
            None => {
                self.srtt = Some(sample);
                self.var = Duration(sample.as_nanos() / 2);
            }
            // RFC 6298 (2.3): var ← ¾·var + ¼·|srtt − sample|; srtt ← ⅞·srtt + ⅛·sample.
            Some(srtt) => {
                let (s, m) = (srtt.as_nanos(), sample.as_nanos());
                let delta = s.abs_diff(m);
                self.var = Duration((self.var.as_nanos() / 4).saturating_mul(3) + delta / 4);
                self.srtt = Some(Duration((s / 8).saturating_mul(7) + m / 8));
            }
        }
    }

    /// Fold in a gather that answered **after its deadline had already fired** — the one sample the
    /// estimator was structurally blind to.
    ///
    /// [`Self::observe`] only ever sees gathers that finished *inside* the current deadline, so its sample
    /// set is truncated at exactly the quantity it is supposed to predict. That is self-reinforcing: anything
    /// slower than the deadline expires, yields no sample under Karn, and so can never move the estimate that
    /// would have admitted it. The deadline stays where it is because everything past it is invisible.
    /// Measured: 158 shares in one run arrived for gathers already given up on, while `backoff` sat at zero.
    ///
    /// A late share is not a Karn violation. Karn's rule forbids attributing an **ambiguous** sample — one
    /// that could belong to either of two transmissions. This share carries its gather's `req_id`, so it is
    /// unambiguously the answer to that one gather, and `now − armed_at` is a duration that was genuinely
    /// measured rather than fabricated. It is the tail of the real distribution, arriving late precisely
    /// because the estimate was short.
    ///
    /// The backoff is **not** cleared, which is the difference from [`Self::observe`]: the gather did fail,
    /// and only a gather that completes on time restores confidence in the estimate.
    pub fn observe_late(&mut self, sample: Duration) {
        let backoff = self.backoff;
        self.observe(sample);
        self.backoff = backoff;
    }

    /// The deadline to arm the next gather with: `(SRTT + 4·RTTVAR) << backoff`, clamped to
    /// `[`[`MIN_GATHER_DEADLINE`]`, `[`MAX_GATHER_DEADLINE`]`]`.
    #[must_use]
    pub fn deadline(self) -> Duration {
        let Some(srtt) = self.srtt else {
            // Even the bootstrap backs off: a node whose very first gathers all expire must widen,
            // or a cold start into a loaded cell never completes a gather and so never gets a sample
            // at all.
            return Duration(
                INITIAL_GATHER_DEADLINE
                    .as_nanos()
                    .saturating_mul(1u64 << self.backoff)
                    .min(MAX_GATHER_DEADLINE.as_nanos()),
            );
        };
        let raw = srtt
            .as_nanos()
            .saturating_add(self.var.as_nanos().saturating_mul(4))
            .saturating_mul(1u64 << self.backoff);
        Duration(raw.clamp(MIN_GATHER_DEADLINE.as_nanos(), MAX_GATHER_DEADLINE.as_nanos()))
    }

    /// The smoothed gather latency — `None` until a gather has completed. This is the gather-path
    /// health reading the observability plane exports (design §4.1); it is already computed here, so
    /// exposing it costs nothing.
    #[must_use]
    pub const fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// The smoothed mean deviation of [`Self::srtt`] — the margin term, and the load-variance signal.
    #[must_use]
    pub const fn var(&self) -> Duration {
        self.var
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A deadline trained only on what beat it can never learn that it is short.**
    ///
    /// `observe` is fed by completions, and a completion is by construction a gather that finished inside
    /// the current deadline — so the sample set is truncated at exactly the quantity being estimated. Feed a
    /// clock a fast workload and then a slow one whose gathers all miss: under `observe` alone the estimate
    /// cannot move, because the slow gathers produce no samples. `observe_late` is the missing evidence, and
    /// it is a real measurement rather than a fabricated one — the share carries its own `req_id`, so there
    /// is no ambiguity for Karn's rule to protect against.
    #[test]
    fn a_deadline_trained_only_on_what_beat_it_never_widens() {
        let fast = Duration(1_000_000); // 1 ms
        let slow = Duration(80_000_000); // 80 ms — past any deadline the fast samples can justify

        // A clock that has only ever seen the fast workload.
        let mut blind = GatherClock::new();
        for _ in 0..64 {
            blind.observe(fast);
        }
        let settled = blind.deadline();
        assert!(settled < slow, "the premise: {settled:?} must be shorter than the slow gathers at {slow:?}");

        // The workload slows down. Every gather now misses, so under `observe` alone the estimator sees
        // NOTHING — expiries carry no sample, by Karn — and only the backoff moves.
        let mut deaf = blind;
        for _ in 0..8 {
            deaf.expired();
        }
        assert_eq!(
            deaf.srtt(),
            blind.srtt(),
            "expiries must not fabricate a sample — that is Karn, and it is why the estimate is stuck"
        );

        // The same eight gathers, with their late answers folded in. Now the estimate moves toward the
        // truth, because a late share IS the measurement.
        let mut learning = blind;
        for _ in 0..8 {
            learning.expired();
            learning.observe_late(slow);
        }
        assert!(
            learning.srtt() > blind.srtt(),
            "a late share must move the estimate: {:?} vs {:?}",
            learning.srtt(),
            blind.srtt()
        );
        assert!(
            learning.deadline() > deaf.deadline(),
            "learning from late shares must widen the deadline further than backoff alone: {:?} vs {:?}",
            learning.deadline(),
            deaf.deadline()
        );

        // And it must not clear the backoff — the gathers still failed, so confidence is not restored.
        let mut backed_off = GatherClock::new();
        backed_off.observe(fast);
        backed_off.expired();
        let widened = backed_off.deadline();
        backed_off.observe_late(slow);
        assert!(
            backed_off.deadline() >= widened,
            "observe_late must keep the backoff it inherited, not reset it like a clean completion"
        );
    }

    #[test]
    fn the_gather_deadline_tracks_measured_latency_instead_of_a_constant() {
        // The #14 property: the deadline is a function of what the node OBSERVES, so the same code
        // adapts to a machine where a share answer costs 1 ms and to one where it costs 47 ms — a 45x
        // spread measured between build profiles alone (`fanos-aphantos/tests/gather_cost.rs`), which
        // is why no constant can be correct.
        let mut clock = GatherClock::new();

        // Before any sample there is nothing to derive from, so the bootstrap stands.
        assert_eq!(
            clock.deadline(),
            INITIAL_GATHER_DEADLINE,
            "a cold node uses the bootstrap deadline, not a measurement it does not have"
        );

        // A fast cell: gathers complete in ~2 ms. The deadline must settle FAR below the old 2 s
        // constant — that constant's real cost was believing a dead hop for a thousand round trips.
        for _ in 0..40 {
            clock.observe(Duration::from_millis(2));
        }
        let fast = clock.deadline();
        assert!(
            fast < Duration::from_millis(50),
            "after 40 samples of 2 ms the deadline settles near the observation, not at 2000 ms: {fast:?}"
        );

        // The same code on a loaded/slow cell: gathers take ~800 ms. The deadline must rise ABOVE the
        // old constant's usable margin rather than abandoning honest hops — the failure #55 measured.
        let mut slow = GatherClock::new();
        for _ in 0..40 {
            slow.observe(Duration::from_millis(800));
        }
        let slow_deadline = slow.deadline();
        assert!(
            slow_deadline > Duration::from_millis(700),
            "a cell whose gathers take 800 ms must wait for them: {slow_deadline:?}"
        );
        assert!(
            slow_deadline > fast,
            "the deadline is a function of observed latency — slow cell {slow_deadline:?} must exceed \
             fast cell {fast:?}, which a constant could never do"
        );

        // Variance widens the margin: the same MEAN with jitter must yield a strictly larger deadline
        // than without, or a deadline would abandon the slow half of a bimodal cell.
        let mut steady = GatherClock::new();
        let mut jittery = GatherClock::new();
        for i in 0..40 {
            steady.observe(Duration::from_millis(100));
            jittery.observe(Duration::from_millis(if i % 2 == 0 { 20 } else { 180 }));
        }
        assert!(
            jittery.deadline() > steady.deadline(),
            "jitter must widen the margin: jittery {:?} vs steady {:?}",
            jittery.deadline(),
            steady.deadline()
        );

        // And it is bounded at both ends, so neither a pathological run of instant gathers nor an
        // adversary answering ever more slowly can drive it to zero or to forever.
        let mut instant = GatherClock::new();
        for _ in 0..40 {
            instant.observe(Duration(0));
        }
        assert_eq!(instant.deadline(), MIN_GATHER_DEADLINE, "floored");
        let mut forever = GatherClock::new();
        for _ in 0..40 {
            forever.observe(Duration::from_millis(600_000));
        }
        assert_eq!(forever.deadline(), MAX_GATHER_DEADLINE, "capped");
    }

    #[test]
    fn an_expiring_gather_backs_off_so_a_too_tight_estimate_can_recover() {
        // **The half of RFC 6298 that smoothing alone does not give**, and the one a real test caught
        // missing: an estimator fed only by COMPLETIONS converges to a quiet period's mean and then
        // holds no margin. When load arrives its gathers expire — and an expiry yields no sample, so
        // nothing ever tells it that it is now too tight. It expires at the same short deadline
        // forever.
        //
        // Measured before this existed: fanos-sim's role-convergence test passed 2/2 at baseline and
        // failed 2/4 with a backoff-less adaptive deadline, because starved hops starved the
        // capability directory the role controller reads. That is the failure mode this asserts
        // against.
        let mut clock = GatherClock::new();
        for _ in 0..40 {
            clock.observe(Duration::from_millis(2));
        }
        let settled = clock.deadline();

        // Each expiry must WIDEN the deadline — strictly, and monotonically.
        let mut prev = settled;
        for _ in 0..4 {
            clock.expired();
            let widened = clock.deadline();
            assert!(
                widened > prev,
                "every expiry must widen the deadline: {widened:?} did not exceed {prev:?}"
            );
            prev = widened;
        }
        assert!(
            prev.as_nanos() >= settled.as_nanos().saturating_mul(8),
            "four doublings must reach at least 8x the settled estimate: {prev:?} vs {settled:?}"
        );

        // A completed gather clears the backoff — the estimate is trusted again, so the deadline
        // returns to tracking observation rather than staying permanently inflated by one bad patch
        // of load.
        clock.observe(Duration::from_millis(2));
        assert!(
            clock.deadline() < prev,
            "a completed gather must clear the backoff, not leave the deadline inflated forever"
        );

        // And the backoff is bounded, so a node under sustained failure cannot inflate without limit.
        let mut runaway = GatherClock::new();
        for _ in 0..40 {
            runaway.observe(Duration::from_millis(50));
        }
        for _ in 0..64 {
            runaway.expired();
        }
        assert_eq!(runaway.deadline(), MAX_GATHER_DEADLINE, "backoff is capped by the ceiling");
    }

    #[test]
    fn the_bootstrap_deadline_itself_backs_off_before_the_first_sample() {
        // A cold start into a loaded cell: every early gather expires, there is no sample yet, and
        // the bootstrap must widen — or the node never completes a gather and never gets a sample.
        let mut cold = GatherClock::new();
        cold.expired();
        assert!(
            cold.deadline() > INITIAL_GATHER_DEADLINE,
            "one pre-sample expiry widens the bootstrap"
        );
        for _ in 0..8 {
            cold.expired();
        }
        assert_eq!(
            cold.deadline(),
            MAX_GATHER_DEADLINE,
            "sustained pre-sample expiries saturate at the ceiling, never past it"
        );
    }
}
