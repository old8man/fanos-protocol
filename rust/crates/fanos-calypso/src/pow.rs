//! Introduction proof-of-work for DoS resistance (spec §12.5).
//!
//! A small memory-hard-*ish* hashcash is attached to each `RDV_INTRO`: the client finds a
//! nonce whose hash has `difficulty` leading zero bits, and the service-line only threshold-
//! decrypts intros above the difficulty it broadcasts (and **raises adaptively under load**).
//! Because the rendezvous line rotates each epoch and admission is throttled at the *line*
//! (not a single node), there is no fixed target to flood.

use alloc::vec::Vec;

use fanos_crypto::hash_labeled;

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
}
