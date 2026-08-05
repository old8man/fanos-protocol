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

use alloc::vec::Vec;

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
    /// Whether this node has a [`MorphCodec`](crate::MorphCodec) plugged, and therefore whether the
    /// cover-protocol morphs in the environment's chain are real here. Without one they are dropped from
    /// the walk instead of being rotated into — see [`Morph::requires_codec`].
    has_codec: bool,
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
        Self::with_trip_and_codec(env, trip, false)
    }

    /// A controller that knows whether a [`MorphCodec`](crate::MorphCodec) is plugged.
    ///
    /// **The default is `false`, deliberately.** A stock build ships no cover-protocol tunnel (the "Parrot
    /// is Dead" rule keeps them out of the core), so a controller that assumed otherwise would walk a chain
    /// of morphs it cannot honour — which is what it used to do, silently applying the polymorph codec under
    /// a cover-protocol shaping profile and reporting a rotation that changed nothing a codec-level censor
    /// can see.
    #[must_use]
    pub fn with_trip_and_codec(env: Environment, trip: u32, has_codec: bool) -> Self {
        let current = env
            .effective_chain(has_codec)
            .first()
            .copied()
            .unwrap_or(Morph::Polymorph);
        Self { env, current, consecutive_failures: 0, trip: trip.max(1), has_codec }
    }

    /// The chain this node can actually walk — see [`Environment::effective_chain`]. A length of one means
    /// the auto-fallback has nowhere to go: the operator's remedy is to plug a codec, and this is what says
    /// so.
    #[must_use]
    pub fn effective_chain(&self) -> Vec<Morph> {
        self.env.effective_chain(self.has_codec)
    }

    /// Whether this node has any fallback at all. `false` is not a fault — it is the stock state of a build
    /// with no plugged transport — but it is a state an operator running under censorship needs to see,
    /// because a blocked morph then has no successor.
    #[must_use]
    pub fn has_fallback(&self) -> bool {
        self.effective_chain().len() > 1
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
        // Walk the **effective** chain: a morph this build cannot honour is not a fallback, it is the same
        // codec wearing a different shaping profile, and rotating into it would report an action that a
        // codec-level censor cannot even observe.
        let chain = self.effective_chain();
        let next = chain
            .iter()
            .position(|&m| m == self.current)
            .and_then(|i| chain.get(i + 1).copied())
            .or_else(|| chain.first().copied())
            .unwrap_or(Morph::Polymorph);
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
    fn the_trip_rotates_to_the_next_morph_the_build_can_honour() {
        // With a codec plugged the full chain is real: DeepCensorship = [Polymorph, Fronted, Webrtc].
        let mut c = MorphController::with_trip_and_codec(Environment::DeepCensorship, 2, true);
        assert_eq!(c.record(false), None);
        assert_eq!(c.record(false), Some(Morph::Fronted), "trips to the next morph");
        assert_eq!(c.current(), Morph::Fronted);
    }

    #[test]
    fn a_success_resets_the_breaker() {
        let mut c = MorphController::with_trip_and_codec(Environment::DeepCensorship, 3, true);
        assert_eq!(c.record(false), None);
        assert_eq!(c.record(false), None);
        c.record(true); // reset
        assert_eq!(c.record(false), None, "counter restarted after the success");
        assert_eq!(c.record(false), None);
        assert_eq!(c.record(false), Some(Morph::Fronted), "trips only after 3 fresh failures");
    }

    #[test]
    fn the_chain_wraps_back_to_the_preferred_morph_when_exhausted() {
        let mut c = MorphController::with_trip_and_codec(Environment::DeepCensorship, 1, true);
        assert_eq!(c.record(false), Some(Morph::Fronted));
        assert_eq!(c.record(false), Some(Morph::Webrtc));
        assert_eq!(c.record(false), Some(Morph::Polymorph), "wraps to preferred, re-trying the cycle");
    }

    /// **A stock build's censorship chain is one morph deep, and it now says so** (#113).
    ///
    /// The four cover-protocol morphs need a plugged `MorphCodec` — the "Parrot is Dead" rule keeps them
    /// out of the core. Before this, rotating into one applied the *polymorph* codec under a cover-protocol
    /// shaping profile, so the controller would walk `Polymorph → Fronted → Webrtc` emitting the same codec
    /// three times while an operator's configuration said domain-fronting and WebRTC. That defeats a
    /// size/timing detector and cannot defeat a codec-level one, and nothing distinguished the two.
    #[test]
    fn without_a_plugged_codec_the_chain_is_only_what_the_build_can_honour() {
        for env in [Environment::DpiCorporate, Environment::SniFilter, Environment::DeepCensorship] {
            let stock = env.effective_chain(false);
            assert_eq!(
                stock,
                alloc::vec![Morph::Polymorph],
                "{}: a stock build's real chain is polymorph alone, not the {} names in the policy",
                env.name(),
                env.chain().len(),
            );
            assert!(
                env.chain().len() > stock.len(),
                "{}: the policy chain must be longer than the effective one, or this test proves nothing",
                env.name(),
            );
        }

        // …and the controller therefore has no fallback to report, which is the operator's cue.
        let c = MorphController::new(Environment::DeepCensorship);
        assert!(!c.has_fallback(), "a stock deep-censorship node has nowhere to rotate to");
        assert!(
            MorphController::with_trip_and_codec(Environment::DeepCensorship, 3, true).has_fallback(),
            "with a codec plugged it does — so `has_fallback` tracks the build, not the policy",
        );

        // `sni-filter` is the sharp case: its *preferred* morph is unavailable, so a stock node never runs
        // the transport its environment names, and used to do so without saying anything.
        assert!(Environment::SniFilter.preferred_morph().requires_codec());
        assert_eq!(MorphController::new(Environment::SniFilter).current(), Morph::Polymorph);
    }

    /// A rotation the shaper cannot honour is refused rather than approximated.
    #[test]
    fn the_shaper_refuses_a_morph_that_needs_a_codec() {
        use crate::ProteusShaper;
        let mut shaper = ProteusShaper::new(b"s".to_vec(), fanos_primitives::Epoch::ZERO);
        assert!(!shaper.set_morph(Morph::Fronted), "a cover-protocol morph without a codec is refused");
        assert_eq!(shaper.morph(), Morph::Polymorph, "and the shaper keeps the morph it could honour");
        assert!(shaper.set_morph(Morph::Plain), "a built-in morph is installed");
        assert_eq!(shaper.morph(), Morph::Plain);
    }
}
