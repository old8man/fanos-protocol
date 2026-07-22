//! The holonomic ratchet — a **path authenticator** over a geometric circuit (spec §5.4).
//!
//! On the incidence bundle a connection `A` is defined over each incident pair; the hop factor
//! is `β_k = KDF(state ‖ A(p_{k-1}, p_k))`, a one-way KDF chain whose ordered composition along the
//! path — followed by a **length-binding finalization** `Hol = H(state_L ‖ L)` — is the **holonomy**.
//! Both endpoints, knowing the algebraic path, compute the same `Hol`; inserting or substituting any hop
//! changes an `A_k` and so breaks it, exactly as a nontrivial holonomy signals an incorrect contour in gap
//! theory. The onion carries `Hol` as a compact tamper-evident tag — encrypted end-to-end in the innermost
//! layer, so it is not a cleartext cross-hop correlator (see `fanos_aphantos::sealed`).
//!
//! **Security (spec §5.4 `[P]`).** The finalization `Hol = H(FINAL ‖ state_L ‖ L)` folds in the hop count `L`
//! and is one-way in the secret cascade state, so an adversary who sees a finalized tag can neither recover
//! `state_L` nor extend the chain to a longer path. The precise EUF-CMA reduction is to **secret-prefix BLAKE3
//! as a PRF**: the seed is the secret prefix of every keyed input (`H(label ‖ 0x1f ‖ seed ‖ A_1)`, …), and
//! BLAKE3's root-finalization flag makes that construction **not** length-extendable — which is exactly why the
//! naive extension `H("nyx-ratchet", Hol ‖ A)` is independent of the true extended tag. This is a *keyed-MAC*
//! guarantee, but note it is **not textbook NMAC** — `hash_labeled` is unkeyed BLAKE3 with the key carried in
//! the message (there is no independent outer key), so the assumption is secret-prefix-BLAKE3-PRF (equivalently
//! a ROM argument), which is standard for BLAKE3 but stronger than a plain native-keyed-PRF assumption. The
//! full reduction and a deterministic attack experiment covering every tamper class are in
//! `docs/design-holonomy-security.md` and [`tests`]/[`attack_experiment`](self::attack_experiment).
//!
//! **On forward secrecy (audit correction).** The ratchet is a path *authenticator*, not a source of forward
//! secrecy, and neither is "the per-hop KEM" on its own: every layer key, KEM ephemeral, and this holonomy key
//! is derived deterministically from the sender's per-onion **build seed**, so that seed is a *universal
//! trapdoor* while it lives — anyone who obtains it recovers the whole circuit (keys, path, holonomy). Forward
//! secrecy therefore holds **only under the operational contract** that the per-onion seed is a fresh CSPRNG
//! draw and is **zeroized immediately after the onion is built** (plus the relay ratcheting its own onion key);
//! it does *not* come for free from "recovering a hop key needs a relay's long-term secret." The routed onion's
//! confidentiality against a network adversary still reduces to the hybrid KEM (`fanos_aphantos::sealed`); the
//! seed-hygiene requirement is the FS caveat.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_primitives::hash_labeled;

use crate::path::Circuit;

/// The domain label for the ratchet KDF (the per-hop cascade step).
const RATCHET_LABEL: &str = "FANOS-v1/nyx-ratchet";
/// The domain label for the ratchet **finalization** — a length-binding outer step (see [`Ratchet::finalize`]).
const RATCHET_FINAL_LABEL: &str = "FANOS-v1/nyx-ratchet-final";

/// A one-way key ratchet advanced once per hop.
#[derive(Clone, Debug)]
pub struct Ratchet {
    state: [u8; 32],
}

impl Ratchet {
    /// Start a ratchet from a shared seed.
    #[must_use]
    pub fn new(seed: &[u8; 32]) -> Self {
        Self { state: *seed }
    }

    /// Advance by one hop given the incidence connection bytes `A_k`, returning the hop factor
    /// `β_k` and updating the internal (one-way) state.
    pub fn advance(&mut self, connection: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(32 + connection.len());
        input.extend_from_slice(&self.state);
        input.extend_from_slice(connection);
        let beta = hash_labeled(RATCHET_LABEL, &input);
        self.state = beta;
        beta
    }

    /// The current (non-finalized) cascade state — the accumulated hop chain so far. This is the raw
    /// cascade output; a path authenticator should use [`finalize`](Self::finalize), which binds the length.
    #[must_use]
    pub fn holonomy(&self) -> [u8; 32] {
        self.state
    }

    /// The **finalized** holonomy: `H(FINAL ‖ state_L ‖ L)`, a length-binding outer step over the cascade of
    /// `hops` hops. This turns the front-keyed cascade (a secure PRF only for a *prefix-free* / fixed-length
    /// message space) into a length-bound keyed MAC over an arbitrary-length hop sequence: because the outer
    /// step folds in the hop count `L` and is one-way in the internal state, an adversary who learns a
    /// finalized tag can neither recover `state_L` nor extend the chain to a longer path — closing the cascade
    /// length-extension gap. (The reduction is to secret-prefix BLAKE3-as-a-PRF, not textbook NMAC — the module
    /// doc's "on forward secrecy / security" note is precise; spec §5.4 `[P]`, `docs/design-holonomy-security.md`.)
    #[must_use]
    pub fn finalize(&self, hops: u32) -> [u8; 32] {
        let mut input = [0u8; 32 + 4];
        input[..32].copy_from_slice(&self.state);
        input[32..].copy_from_slice(&hops.to_be_bytes());
        hash_labeled(RATCHET_FINAL_LABEL, &input)
    }
}

/// The incidence connection bytes for a hop: the two relay coordinates and the hop line,
/// encoded big-endian. This is `A(p_{k-1}, p_k)` on the incidence bundle (spec §2.6, §5.4).
fn connection_bytes(from: Triple, to: Triple, line: Triple) -> [u8; 36] {
    let mut out = [0u8; 36];
    let (chunks, _rest) = out.as_chunks_mut::<4>();
    for (chunk, value) in chunks
        .iter_mut()
        .zip(from.into_iter().chain(to).chain(line))
    {
        *chunk = value.to_be_bytes();
    }
    out
}

/// The holonomy `Hol` of a circuit under a shared seed — the path authenticator (spec §5.4).
/// Both endpoints compute this identically; any tampered hop yields a different tag.
#[must_use]
pub fn circuit_holonomy<F: Field>(circuit: &Circuit<F>, seed: &[u8; 32]) -> [u8; 32] {
    let mut ratchet = Ratchet::new(seed);
    let relays = circuit.relays();
    let mut hops = 0u32;
    for (k, hop) in circuit.hops().iter().enumerate() {
        let (Some(a), Some(b)) = (relays.get(k), relays.get(k + 1)) else {
            break;
        };
        let conn = connection_bytes(a.coords(), b.coords(), hop.coords());
        ratchet.advance(&conn);
        hops += 1;
    }
    // Length-binding finalization — makes the tag a length-bound keyed MAC (secret-prefix BLAKE3-PRF), not just
    // a front-keyed cascade, so its security no longer rests on the tag being kept secret (spec §5.4).
    ratchet.finalize(hops)
}

/// Verify a `claimed` holonomy against the circuit and seed the verifying party independently
/// knows (spec §5.4) — `true` iff it matches [`circuit_holonomy`] recomputed from `circuit`/`seed`.
/// Meaningful only for a verifier who already has legitimate knowledge of `circuit` (it built the
/// circuit, or was told it end-to-end) — see `fanos_aphantos::sealed::verify_delivery` for why that
/// precondition matters and where it holds in practice. Any inserted or substituted hop moves an
/// `A_k` in [`circuit_holonomy`]'s chain and so is caught here.
#[must_use]
pub fn verify_holonomy<F: Field>(circuit: &Circuit<F>, seed: &[u8; 32], claimed: [u8; 32]) -> bool {
    circuit_holonomy(circuit, seed) == claimed
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::path::build_circuit;
    use fanos_field::F31;
    use fanos_geometry::Point;

    #[test]
    fn endpoints_agree_on_the_holonomy() {
        // The sender and receiver, both knowing the circuit and seed, compute the same tag.
        let circuit = build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"c").unwrap();
        let seed = [5u8; 32];
        let sender = circuit_holonomy(&circuit, &seed);
        let receiver = circuit_holonomy(&circuit, &seed);
        assert_eq!(sender, receiver);
    }

    #[test]
    fn verify_holonomy_accepts_the_honest_circuit_and_rejects_a_substituted_one() {
        // The verification primitive itself, in both directions: the exact circuit the tag was
        // computed under passes; a different (substituted-hop) circuit under the SAME seed fails.
        let seed = [5u8; 32];
        let honest = build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"c").unwrap();
        let substituted = build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"c2").unwrap();
        let claimed = circuit_holonomy(&honest, &seed);
        assert!(
            verify_holonomy(&honest, &seed, claimed),
            "the circuit the tag was built under verifies"
        );
        assert!(
            !verify_holonomy(&substituted, &seed, claimed),
            "a substituted circuit does not"
        );
    }

    #[test]
    fn tampering_a_hop_breaks_the_tag() {
        let seed = [5u8; 32];
        let good = build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"c").unwrap();
        // A different path (different relays) → different holonomy.
        let tampered = build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"c2").unwrap();
        assert_ne!(
            circuit_holonomy(&good, &seed),
            circuit_holonomy(&tampered, &seed)
        );
    }

    #[test]
    fn ratchet_is_one_way_and_advances() {
        let mut r = Ratchet::new(&[0u8; 32]);
        let b1 = r.advance(b"hop-1");
        let b2 = r.advance(b"hop-2");
        assert_ne!(b1, b2);
        assert_eq!(r.holonomy(), b2);
        // A different seed gives a different chain (key-separation of the keyed cascade).
        let mut r2 = Ratchet::new(&[1u8; 32]);
        assert_ne!(r2.advance(b"hop-1"), b1);
    }

    #[test]
    fn different_seeds_give_different_holonomy() {
        let circuit = build_circuit(Point::<F31>::at(1), Point::<F31>::at(2), 4, b"c").unwrap();
        assert_ne!(
            circuit_holonomy(&circuit, &[7u8; 32]),
            circuit_holonomy(&circuit, &[8u8; 32])
        );
    }

    #[test]
    fn the_finalization_binds_the_hop_count() {
        // Two ratchets with the SAME accumulated state but different declared lengths finalize differently —
        // the length-binding that defeats cascade length extension.
        let mut r = Ratchet::new(&[3u8; 32]);
        r.advance(b"only-hop");
        assert_ne!(r.finalize(1), r.finalize(2), "the finalization folds in the hop count");
        // And the finalized tag is not the raw cascade state (so exposing the tag reveals no cascade state).
        assert_ne!(r.finalize(1), r.holonomy(), "the tag is finalized, not the raw cascade state");
    }
}

/// The holonomy-authentication **attack experiment** (spec §5.4 `[P]`, `docs/design-holonomy-security.md` §5).
///
/// Deterministic — no timing, no RNG — so it is a stable CI guard, not a flaky measurement. Over many
/// synthetic paths it applies every tamper class and asserts the finalized tag changes, checks
/// forgery-without-seed fails, confirms the length-binding finalization blocks the classic cascade
/// length-extension attack, and runs a collision Monte-Carlo plus an avalanche-diffusion check.
#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod attack_experiment {
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;

    use fanos_primitives::hash_labeled;

    use super::{Ratchet, RATCHET_LABEL};

    /// A tiny deterministic PRG (`splitmix64`) — reproducible synthetic connection bytes.
    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A distinct 36-byte connection block (the `A_k` width) derived from `tag`.
    fn block(tag: u64) -> Vec<u8> {
        let mut s = tag ^ 0x5DEE_CE66_D1CE_B00Bu64;
        let mut v = Vec::with_capacity(36);
        while v.len() < 36 {
            v.extend_from_slice(&splitmix(&mut s).to_be_bytes());
        }
        v.truncate(36);
        v
    }

    fn random_path(seed_val: u64, len: usize) -> Vec<Vec<u8>> {
        (0..len as u64).map(|i| block(seed_val.wrapping_mul(1000).wrapping_add(i))).collect()
    }

    /// The finalized holonomy of a raw connection path (mirrors `circuit_holonomy` at the ratchet level).
    fn tag(seed: &[u8; 32], path: &[Vec<u8>]) -> [u8; 32] {
        let mut r = Ratchet::new(seed);
        for a in path {
            r.advance(a);
        }
        r.finalize(path.len() as u32)
    }

    const SEED: [u8; 32] = [0x42; 32];

    #[test]
    fn every_tamper_class_changes_the_tag() {
        for trial in 0..300u64 {
            let path = random_path(trial, 5);
            let base = tag(&SEED, &path);
            let fresh = block(0xF00D_0000 ^ trial);

            // Substitute an interior hop.
            let mut sub = path.clone();
            sub[2] = fresh.clone();
            assert_ne!(tag(&SEED, &sub), base, "substitution must break the tag (trial {trial})");

            // Insert a hop.
            let mut ins = path.clone();
            ins.insert(2, fresh.clone());
            assert_ne!(tag(&SEED, &ins), base, "insertion must break the tag");

            // Delete a hop.
            let mut del = path.clone();
            del.remove(2);
            assert_ne!(tag(&SEED, &del), base, "deletion must break the tag");

            // Reorder two hops.
            let mut ord = path.clone();
            ord.swap(1, 3);
            assert_ne!(tag(&SEED, &ord), base, "reordering must break the tag");

            // Truncate the last hop (length attack).
            assert_ne!(tag(&SEED, &path[..4]), base, "truncation must break the tag");

            // Extend by a hop (length-extension attack surface).
            let mut ext = path.clone();
            ext.push(fresh.clone());
            assert_ne!(tag(&SEED, &ext), base, "extension must break the tag");

            // Flip a single bit of one hop.
            let mut bit = path.clone();
            bit[0][0] ^= 1;
            assert_ne!(tag(&SEED, &bit), base, "a single-bit tamper must break the tag");
        }
    }

    #[test]
    fn forgery_without_the_seed_fails() {
        // An adversary who does not hold `seed` cannot produce the tag for a target path: any wrong seed
        // yields a different tag (the authenticator is keyed).
        let path = random_path(7, 4);
        let real = tag(&SEED, &path);
        for k in 0..64u8 {
            let mut guess = SEED;
            guess[0] ^= k.wrapping_add(1); // any non-zero change → a different seed
            assert_ne!(tag(&guess, &path), real, "a wrong seed must not forge the tag");
        }
    }

    #[test]
    fn the_finalization_blocks_cascade_length_extension() {
        // The classic attack on the UN-finalized cascade: given the tag of an L-hop path (treated as the raw
        // cascade state state_L), compute H("nyx-ratchet", tag ‖ A) to forge the (L+1)-hop tag WITHOUT the
        // seed. With the length-binding finalization the real extended tag is independent of that value.
        for trial in 0..100u64 {
            let path = random_path(trial, 4);
            let base = tag(&SEED, &path);
            let a = block(0xBEEF ^ trial);

            let mut extended = path.clone();
            extended.push(a.clone());
            let real_extended = tag(&SEED, &extended);

            // What an attacker on the raw cascade would compute from the (finalized) tag it sees.
            let mut naive_input = Vec::with_capacity(32 + a.len());
            naive_input.extend_from_slice(&base);
            naive_input.extend_from_slice(&a);
            let naive_extension = hash_labeled(RATCHET_LABEL, &naive_input);

            assert_ne!(
                naive_extension, real_extended,
                "the finalization must make the tag non-extendable from itself (trial {trial})"
            );
        }
    }

    #[test]
    fn no_collisions_over_thousands_of_random_paths() {
        // Monte-Carlo: many distinct random paths (varying length and content) yield distinct tags — the
        // tamper-evidence claim's statistical face (a collision would be a 2^-256 event).
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut n = 0;
        for seed_val in 0..1_500u64 {
            let len = 2 + (seed_val % 6) as usize; // lengths 2..=7
            let t = tag(&SEED, &random_path(seed_val, len));
            assert!(seen.insert(t), "tag collision at seed {seed_val}");
            n += 1;
        }
        assert_eq!(seen.len(), n, "every path produced a unique tag");
    }

    #[test]
    fn a_single_bit_change_diffuses_across_the_tag() {
        // Avalanche: flipping one bit of the path flips ≈ half the 256 tag bits (good diffusion, from BLAKE3).
        let path = random_path(11, 5);
        let base = tag(&SEED, &path);
        let mut total_diff = 0u32;
        let trials = 64u32;
        for i in 0..trials {
            let mut tampered = path.clone();
            let byte = (i as usize) % tampered[0].len();
            tampered[0][byte] ^= 1 << (i % 8);
            let t = tag(&SEED, &tampered);
            total_diff += base.iter().zip(t.iter()).map(|(x, y)| (x ^ y).count_ones()).sum::<u32>();
        }
        let mean = f64::from(total_diff) / f64::from(trials);
        assert!((96.0..160.0).contains(&mean), "avalanche mean {mean} bits is far from the ideal 128");
    }
}
