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
    /// tighten (`+1`) over target, ease (`-1`) when comfortably under it (below half target),
    /// otherwise hold — always within `[floor, ceil]`.
    pub fn observe_window(&mut self, admitted: u32) {
        if admitted > self.target {
            self.difficulty = (self.difficulty + 1).min(self.ceil);
        } else if admitted * 2 < self.target {
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
}
