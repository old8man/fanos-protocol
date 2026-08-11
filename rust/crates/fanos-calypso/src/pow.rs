//! Introduction proof-of-work for DoS resistance (spec §12.5).
//!
//! A small memory-hard-*ish* hashcash is attached to each `RDV_INTRO`: the client finds a
//! nonce whose hash has `difficulty` leading zero bits, and the service-line only threshold-
//! decrypts intros above the difficulty it broadcasts (and **raises adaptively under load**).
//! Because the rendezvous line rotates each epoch and admission is throttled at the *line*
//! (not a single node), there is no fixed target to flood.

use alloc::vec::Vec;

use fanos_primitives::hash_labeled;

const POW_LABEL: &str = "FANOS-v1/calypso-pow";

/// The number of leading zero bits of a 32-byte hash.
#[must_use]
fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// The PoW hash of a challenge and nonce.
#[must_use]
pub fn hash(challenge: &[u8], nonce: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(challenge.len() + 8);
    data.extend_from_slice(challenge);
    data.extend_from_slice(&nonce.to_be_bytes());
    hash_labeled(POW_LABEL, &data)
}

/// Whether `nonce` solves `challenge` at the given difficulty (leading zero bits).
#[must_use]
pub fn verify(challenge: &[u8], nonce: u64, difficulty: u32) -> bool {
    leading_zero_bits(&hash(challenge, nonce)) >= difficulty
}

/// Find a nonce solving `challenge` at `difficulty`. The expected work is `2^difficulty`
/// hashes; keep `difficulty` modest for interactive use.
#[must_use]
pub fn solve(challenge: &[u8], difficulty: u32) -> u64 {
    let mut nonce = 0u64;
    while !verify(challenge, nonce, difficulty) {
        nonce += 1;
    }
    nonce
}

/// An adaptive introduction-PoW difficulty controller (spec §12.5): the service-line broadcasts a
/// difficulty and **raises it under load**, so admission cost tracks demand. Each `+1` of difficulty
/// roughly doubles a client's work, halving the request rate a fixed-compute flooder can sustain —
/// so the controller tightens by `+1` whenever a window admits more than `target` intros and eases
/// by `-1` (with hysteresis, to avoid oscillation) when a window runs well under target, bounded to
/// `[floor, ceil]`. It is a pure state machine: the driver counts admitted intros per window and
/// calls [`observe_window`](Self::observe_window); [`difficulty`](Self::difficulty) is what to
/// broadcast and gate on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AdaptiveDifficulty {
    difficulty: u32,
    floor: u32,
    ceil: u32,
    target: u32,
}

impl AdaptiveDifficulty {
    /// A controller over `[floor, ceil]` difficulty, targeting `target` admitted intros per window.
    /// Starts at `floor` (cheap when idle). `ceil` is clamped `>= floor`; `target` is at least `1`.
    #[must_use]
    pub fn new(floor: u32, ceil: u32, target: u32) -> Self {
        let ceil = ceil.max(floor);
        Self {
            difficulty: floor,
            floor,
            ceil,
            target: target.max(1),
        }
    }

    /// The difficulty to broadcast and require right now.
    #[must_use]
    pub fn difficulty(self) -> u32 {
        self.difficulty
    }

    /// Fold in a completed window's `admitted` intro count and adjust the difficulty:
    /// tighten (`+1`) over target, ease (`-1`) below half target, otherwise hold — always within
    /// `[floor, ceil]`.
    ///
    /// **Why the dead band is exactly `[target/2, target]`, derived rather than chosen.** The type's own
    /// doc states the actuator's gain: one step of difficulty roughly doubles a client's work, so it halves
    /// the request rate a fixed-compute flooder sustains. The band must therefore be **exactly one actuator
    /// step wide**, and both inequalities pin it:
    ///
    /// * *Narrower oscillates.* A raise fired at `admitted = target + ε` lands the next window at about
    ///   `target/2`. If the ease threshold sat anywhere above `target/2` — say `¾·target` — that very
    ///   window would fire an ease, undoing the raise, and the controller would ring at every step.
    /// * *Wider leaves steady-state error.* Easing only below `target/4` means tolerating a window running
    ///   four times under target: admission stays priced for load that is not there, which is the cost the
    ///   controller exists to avoid paying.
    ///
    /// Same argument in the other direction: an ease fired at `target/2 − ε` lands at just under `target`,
    /// inside the band, so it does not immediately re-tighten. The band is symmetric because the actuator
    /// is, and a factor of 2 is the only width with both properties. "Hysteresis, to avoid oscillation" —
    /// what this said before — is the requirement, not the derivation, and it does not pick a number.
    pub fn observe_window(&mut self, admitted: u32) {
        if admitted > self.target {
            self.difficulty = (self.difficulty + 1).min(self.ceil);
        } else if admitted < self.target.div_ceil(2) {
            // `admitted < ⌈target/2⌉` is exactly `2·admitted < target` over the integers, and unlike the
            // multiply it cannot wrap. The old form was unreachable-but-real: a `u32` window count past
            // 2³¹ would wrap to a small number, satisfy the test, and *lower* the difficulty at the very
            // moment admission is highest — a controller inverted by its own guard. Not reachable through
            // any admission cap this crate enforces, and removed rather than argued (the #110 precedent:
            // close it, or state the reason at the site; closing is cheaper here).
            self.difficulty = self.difficulty.saturating_sub(1).max(self.floor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solved_nonce_verifies() {
        let challenge = b"rdv-intro-cookie";
        let nonce = solve(challenge, 12);
        assert!(verify(challenge, nonce, 12));
    }

    #[test]
    fn a_wrong_nonce_fails() {
        let challenge = b"cookie";
        let nonce = solve(challenge, 10);
        assert!(!verify(challenge, nonce.wrapping_add(1), 20));
    }

    #[test]
    fn higher_difficulty_is_harder() {
        // A solution for difficulty D also satisfies any lower difficulty.
        let challenge = b"c";
        let nonce = solve(challenge, 14);
        assert!(verify(challenge, nonce, 8));
        assert!(verify(challenge, nonce, 14));
    }

    #[test]
    fn adaptive_difficulty_raises_under_load_and_eases_when_idle() {
        let mut ctl = AdaptiveDifficulty::new(4, 20, 10);
        assert_eq!(ctl.difficulty(), 4, "starts cheap at the floor");

        // Sustained overload climbs to the ceiling.
        for _ in 0..50 {
            ctl.observe_window(1000);
        }
        assert_eq!(ctl.difficulty(), 20, "overload tightens to the ceiling");

        // Going idle eases back down to the floor.
        for _ in 0..50 {
            ctl.observe_window(0);
        }
        assert_eq!(ctl.difficulty(), 4, "idle eases to the floor");
    }

    #[test]
    fn adaptive_difficulty_holds_near_target() {
        let mut ctl = AdaptiveDifficulty::new(6, 20, 10);
        for _ in 0..20 {
            ctl.observe_window(8); // near target (not > target, not < target/2)
        }
        assert_eq!(
            ctl.difficulty(),
            6,
            "steady load at target holds difficulty"
        );
    }

    /// **The dead band is exactly one actuator step, and a correction lands inside it.**
    ///
    /// The band's width is not a literal to pin — `observe_window`'s doc derives it, and a test that
    /// re-asserted `target/2` would only restate the constant. What the derivation actually claims is a
    /// *closed-loop* property: because one difficulty step halves the rate a fixed-compute flooder
    /// sustains, a correction must move the load INTO the band rather than past it. That is what settles
    /// the factor, so that is what is checked, against a plant that models the stated gain.
    ///
    /// Falsified by widening the ease threshold to `¾·target`: the raise below then over-corrects into an
    /// ease and the controller rings, which is the oscillation the band exists to prevent.
    #[test]
    fn one_correction_lands_inside_the_dead_band_in_both_directions() {
        const TARGET: u32 = 100;
        // The plant, as the type's doc states it: each +1 of difficulty halves the sustainable rate.
        let rate = |load: u32, from: u32, to: u32| -> u32 {
            if to >= from { load >> (to - from) } else { load << (from - to) }
        };

        // TIGHTENING. Load a hair over target fires a raise; the halved load must not fire an ease back.
        let mut ctl = AdaptiveDifficulty::new(4, 20, TARGET);
        ctl.observe_window(TARGET + 1);
        let after_raise = ctl.difficulty();
        assert_eq!(after_raise, 5, "over target must tighten by exactly one step");
        let settled = rate(TARGET + 1, 4, after_raise);
        ctl.observe_window(settled);
        assert_eq!(
            ctl.difficulty(),
            after_raise,
            "the raise put the load at {settled} against target {TARGET}, and the controller immediately \
             undid it — the band is narrower than one actuator step, so every correction rings (#244)"
        );

        // EASING, the same argument mirrored: a hair under half target eases, and the doubled load must
        // land under target rather than over it.
        //
        // The controller has to be lifted OFF its floor first, and the first draft of this test was not —
        // `new` starts at `floor`, so the ease it fired was clamped straight back and the assertion read as
        // "the controller refuses to ease". The floor was doing that, not the band.
        let mut ctl = AdaptiveDifficulty::new(4, 20, TARGET);
        ctl.observe_window(TARGET + 1);
        ctl.observe_window(TARGET + 1);
        assert_eq!(ctl.difficulty(), 6, "two raises lift the controller clear of its floor");
        ctl.observe_window(TARGET / 2 - 1);
        let after_ease = ctl.difficulty();
        assert_eq!(after_ease, 5, "below half target must ease by exactly one step");
        let settled = rate(TARGET / 2 - 1, 6, after_ease);
        ctl.observe_window(settled);
        assert_eq!(
            ctl.difficulty(),
            after_ease,
            "the ease put the load at {settled} against target {TARGET}, and the controller immediately \
             re-tightened — the band is not symmetric with the actuator it drives (#244)"
        );
    }

    /// A window count large enough to wrap `admitted * 2` must not read as *below* half target.
    ///
    /// Not reachable through any admission cap this crate enforces, and pinned anyway: the old form
    /// inverted the controller exactly where load is highest, and an unreachable inversion in a
    /// **defensive** control loop is worth one assertion rather than a paragraph of reassurance.
    #[test]
    fn an_enormous_window_tightens_rather_than_wrapping_into_an_ease() {
        let mut ctl = AdaptiveDifficulty::new(4, 20, 10);
        ctl.observe_window(u32::MAX);
        assert_eq!(ctl.difficulty(), 5, "the largest possible window is over target, so it tightens");
    }
}
