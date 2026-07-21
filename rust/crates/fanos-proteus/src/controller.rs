//! Morph **auto-fallback** (spec §13.7): rotate to the next morph in the environment chain when the current
//! one starts failing, and settle back on success.
//!
//! This is a **circuit breaker** — `trip` consecutive connection failures abandon the current morph and
//! advance the chain — not an ML detector: a small debounce so transient loss does not rotate, but a morph
//! that a censor has actually blocked is dropped quickly. The rotation is a *local* decision: every
//! codec-using morph shares one wire codec (they differ only in the size/timing profile, transparent to a
//! peer's decode), so a node can walk `polymorph → fronted → webrtc` without any renegotiation. Only the
//! `plain` boundary changes the codec and needs both ends to agree (§7.4 HELLO capability negotiation) —
//! and `plain` is the head of the `open` (uncensored) chain, where fallback rarely fires.

use crate::morph::{Environment, Morph};

/// Consecutive connection failures that trip a morph rotation. A standard circuit-breaker debounce (enough
/// to tell a blocked morph from a transient loss), not a tuned classifier threshold.
pub const DEFAULT_TRIP: u32 = 3;

/// The auto-fallback state machine for one node: the environment policy, the morph currently in use, and a
/// consecutive-failure breaker. Feed it connection outcomes with [`record`](Self::record); when a rotation
/// is due it returns the new morph to install on the shaper.
#[derive(Clone, Debug)]
pub struct MorphController {
    env: Environment,
    current: Morph,
    consecutive_failures: u32,
    trip: u32,
}

impl MorphController {
    /// A controller for `env`, starting at its preferred morph with the [`DEFAULT_TRIP`] breaker.
    #[must_use]
    pub fn new(env: Environment) -> Self {
        Self::with_trip(env, DEFAULT_TRIP)
    }

    /// A controller for `env` that trips after `trip` consecutive failures (clamped to at least 1).
    #[must_use]
    pub fn with_trip(env: Environment, trip: u32) -> Self {
        Self {
            env,
            current: env.preferred_morph(),
            consecutive_failures: 0,
            trip: trip.max(1),
        }
    }

    /// The morph currently in use.
    #[must_use]
    pub fn current(&self) -> Morph {
        self.current
    }

    /// The environment policy this controller follows.
    #[must_use]
    pub fn environment(&self) -> Environment {
        self.env
    }

    /// Record one connection outcome. A success resets the breaker. A failure counts toward the trip; at the
    /// threshold the breaker resets and the morph rotates to the next in the environment chain — wrapping to
    /// the preferred morph when the chain is exhausted (a censor blocking every morph is met by re-trying the
    /// cycle, per §13.8's "re-enumerate every epoch"). Returns `Some(new_morph)` exactly when the morph
    /// changed (install it on the shaper), else `None`.
    pub fn record(&mut self, success: bool) -> Option<Morph> {
        if success {
            self.consecutive_failures = 0;
            return None;
        }
        self.consecutive_failures += 1;
        if self.consecutive_failures < self.trip {
            return None;
        }
        self.consecutive_failures = 0;
        let next = self
            .env
            .fallback_after(self.current)
            .unwrap_or_else(|| self.env.preferred_morph());
        (next != self.current).then(|| {
            self.current = next;
            next
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_burst_below_the_trip_does_not_rotate() {
        let mut c = MorphController::new(Environment::DeepCensorship);
        assert_eq!(c.current(), Morph::Polymorph);
        for _ in 0..DEFAULT_TRIP - 1 {
            assert_eq!(c.record(false), None, "under the trip, no rotation");
        }
        assert_eq!(c.current(), Morph::Polymorph);
    }

    #[test]
    fn the_trip_rotates_to_the_next_morph_in_the_chain() {
        let mut c = MorphController::with_trip(Environment::DeepCensorship, 2);
        assert_eq!(c.record(false), None);
        // DeepCensorship = [Polymorph, Fronted, Webrtc].
        assert_eq!(c.record(false), Some(Morph::Fronted), "trips to the next morph");
        assert_eq!(c.current(), Morph::Fronted);
    }

    #[test]
    fn a_success_resets_the_breaker() {
        let mut c = MorphController::with_trip(Environment::DeepCensorship, 3);
        assert_eq!(c.record(false), None);
        assert_eq!(c.record(false), None);
        c.record(true); // reset
        assert_eq!(c.record(false), None, "counter restarted after the success");
        assert_eq!(c.record(false), None);
        assert_eq!(c.record(false), Some(Morph::Fronted), "trips only after 3 fresh failures");
    }

    #[test]
    fn the_chain_wraps_back_to_the_preferred_morph_when_exhausted() {
        let mut c = MorphController::with_trip(Environment::DeepCensorship, 1);
        assert_eq!(c.record(false), Some(Morph::Fronted));
        assert_eq!(c.record(false), Some(Morph::Webrtc));
        assert_eq!(c.record(false), Some(Morph::Polymorph), "wraps to preferred, re-trying the cycle");
    }
}
