//! The KEM-sealed onion — APHANTOS-Lite with real per-hop hybrid KEM (spec §L5, §5.7).
//!
//! Each hop's layer key is established by a **hybrid KEM encapsulation to that relay's public
//! key** (`X25519 ‖ ML-KEM-768`), not carried in the packet, so only the intended relay can
//! peel its layer. Layers are nested AEAD (ChaCha20-Poly1305), the holonomy travels as the
//! path authenticator, and the whole onion is a byte string on the wire — the same code the
//! simulator routes and a real transport would carry.
//!
//! ```text
//! onion = VERSION(1) ‖ HOLONOMY(32) ‖ hop
//! hop   = kem_ciphertext(1120) ‖ nonce(12) ‖ AEAD(key, nonce, cmd ‖ inner)
//! cmd   = DELIVER | NEXT ‖ next_coord(12)
//! ```

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use fanos_crypto::hash_labeled;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_nyx::{Circuit, circuit_holonomy};
use fanos_pqcrypto::kem::CIPHERTEXT_LEN;
use fanos_pqcrypto::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SeedRng};

const VERSION: u8 = 1;
const CMD_DELIVER: u8 = 0;
const CMD_NEXT: u8 = 1;
const NONCE_LEN: usize = 12;
const HOLONOMY_LEN: usize = 32;
const HEADER_LEN: usize = 1 + HOLONOMY_LEN;

/// Errors from sealing or peeling an onion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealedError {
    /// The onion bytes were malformed (bad length, version, or command).
    Malformed,
    /// A KEM ciphertext failed to parse.
    Kem,
    /// AEAD authentication failed (wrong relay / tampered layer).
    Aead,
    /// The circuit and relay-key list disagreed in length.
    KeyMismatch,
}

/// The result of peeling one hop.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PeelOutcome {
    /// Forward the inner onion to the relay at `next`.
    Forward {
        /// The next relay's coordinate.
        next: Triple,
        /// The re-headed inner onion bytes.
        onion: Vec<u8>,
    },
    /// The payload reached its destination; the carried holonomy authenticator is returned.
    Deliver {
        /// The delivered payload.
        payload: Vec<u8>,
        /// The path-authenticator holonomy tag.
        holonomy: [u8; 32],
    },
}

fn hop_key(session: &[u8; 32]) -> [u8; 32] {
    hash_labeled("FANOS-v1/aphantos-hopkey", session)
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], pt: &[u8]) -> Result<Vec<u8>, SealedError> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SealedError::Aead)?
        .encrypt(&Nonce::from(*nonce), pt)
        .map_err(|_| SealedError::Aead)
}

fn aead_open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ct: &[u8]) -> Result<Vec<u8>, SealedError> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SealedError::Aead)?
        .decrypt(&Nonce::from(*nonce), ct)
        .map_err(|_| SealedError::Aead)
}

fn coord_to_bytes(coord: Triple) -> [u8; 12] {
    let mut out = [0u8; 12];
    let (chunks, _) = out.as_chunks_mut::<4>();
    for (chunk, value) in chunks.iter_mut().zip(coord) {
        *chunk = value.to_be_bytes();
    }
    out
}

fn coord_from_bytes(bytes: &[u8]) -> Option<Triple> {
    let (chunks, _) = bytes.get(..12)?.as_chunks::<4>();
    Some([
        u32::from_be_bytes(*chunks.first()?),
        u32::from_be_bytes(*chunks.get(1)?),
        u32::from_be_bytes(*chunks.get(2)?),
    ])
}

/// Build a KEM-sealed onion for `circuit` carrying `payload`, sealing hop `k` to
/// `relay_keys[k-1]` (the public key of relay `r_k`). All randomness derives from `seed`.
///
/// `relay_keys.len()` must equal `circuit.hop_count()` (one key per peeling relay `r_1…r_L`).
pub fn build<F: Field>(
    circuit: &Circuit<F>,
    relay_keys: &[&HybridKemPublic],
    payload: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, SealedError> {
    let hops = circuit.hop_count();
    if relay_keys.len() != hops {
        return Err(SealedError::KeyMismatch);
    }
    let relays = circuit.relays();
    let holonomy = circuit_holonomy(circuit, &hash_labeled("FANOS-v1/aphantos-holoseed", seed));

    let mut inner = payload.to_vec();
    for k in (1..=hops).rev() {
        let public = relay_keys.get(k - 1).ok_or(SealedError::KeyMismatch)?;
        // Per-hop deterministic randomness for encapsulation and the nonce.
        let mut hop_seed = seed.to_vec();
        hop_seed.extend_from_slice(&(k as u32).to_be_bytes());
        let mut rng = SeedRng::from_seed(&hop_seed);
        let (kem_ct, session) = public.encapsulate(&mut rng);
        let key = hop_key(&session);
        let nonce_full = hash_labeled("FANOS-v1/aphantos-nonce", &hop_seed);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_full.get(..NONCE_LEN).ok_or(SealedError::Malformed)?);

        // Routing command: forward to the next relay, or deliver.
        let mut plaintext = Vec::new();
        if k == hops {
            plaintext.push(CMD_DELIVER);
        } else {
            plaintext.push(CMD_NEXT);
            let next = relays.get(k + 1).ok_or(SealedError::Malformed)?;
            plaintext.extend_from_slice(&coord_to_bytes(next.coords()));
        }
        plaintext.extend_from_slice(&inner);

        let layer_ct = aead_seal(&key, &nonce, &plaintext)?;
        // hop = kem_ct ‖ nonce ‖ layer_ct
        let mut hop = Vec::with_capacity(CIPHERTEXT_LEN + NONCE_LEN + layer_ct.len());
        hop.extend_from_slice(&kem_ct.to_bytes());
        hop.extend_from_slice(&nonce);
        hop.extend_from_slice(&layer_ct);
        inner = hop;
    }

    // onion = VERSION ‖ HOLONOMY ‖ hop
    let mut onion = Vec::with_capacity(HEADER_LEN + inner.len());
    onion.push(VERSION);
    onion.extend_from_slice(&holonomy);
    onion.extend_from_slice(&inner);
    Ok(onion)
}

/// Peel the current hop of a sealed onion with a relay's KEM secret key (spec §5.7).
pub fn peel(onion: &[u8], kem_secret: &HybridKemSecret) -> Result<PeelOutcome, SealedError> {
    if onion.first().copied() != Some(VERSION) {
        return Err(SealedError::Malformed);
    }
    let holonomy_bytes = onion.get(1..HEADER_LEN).ok_or(SealedError::Malformed)?;
    let mut holonomy = [0u8; 32];
    holonomy.copy_from_slice(holonomy_bytes);
    let hop = onion.get(HEADER_LEN..).ok_or(SealedError::Malformed)?;

    let kem_ct_bytes = hop.get(..CIPHERTEXT_LEN).ok_or(SealedError::Malformed)?;
    let nonce_bytes = hop
        .get(CIPHERTEXT_LEN..CIPHERTEXT_LEN + NONCE_LEN)
        .ok_or(SealedError::Malformed)?;
    let layer_ct = hop
        .get(CIPHERTEXT_LEN + NONCE_LEN..)
        .ok_or(SealedError::Malformed)?;

    let kem_ct = HybridCiphertext::from_bytes(kem_ct_bytes).ok_or(SealedError::Kem)?;
    let session = kem_secret.decapsulate(&kem_ct);
    let key = hop_key(&session);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    let plaintext = aead_open(&key, &nonce, layer_ct)?;
    let (&cmd, rest) = plaintext.split_first().ok_or(SealedError::Malformed)?;
    match cmd {
        CMD_DELIVER => Ok(PeelOutcome::Deliver {
            payload: rest.to_vec(),
            holonomy,
        }),
        CMD_NEXT => {
            let next = coord_from_bytes(rest).ok_or(SealedError::Malformed)?;
            let inner = rest.get(12..).ok_or(SealedError::Malformed)?;
            // Re-head the inner onion for the next relay.
            let mut forwarded = Vec::with_capacity(HEADER_LEN + inner.len());
            forwarded.push(VERSION);
            forwarded.extend_from_slice(&holonomy);
            forwarded.extend_from_slice(inner);
            Ok(PeelOutcome::Forward {
                next,
                onion: forwarded,
            })
        }
        _ => Err(SealedError::Malformed),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F31;
    use fanos_geometry::Point;
    use fanos_nyx::build_circuit;

    /// A tiny relay directory for the tests: coordinate → (secret, public).
    fn relays(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[seed, i as u8]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect()
    }

    #[test]
    fn onion_routes_through_every_relay() {
        let circuit =
            build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"circuit").unwrap();
        let keypairs = relays(circuit.hop_count(), 1);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();

        let payload = b"anonymous hello";
        let mut onion = build(&circuit, &pubkeys, payload, b"onion-seed").unwrap();

        // Each hop is peeled only by the correct relay's secret key.
        for (secret, _) in &keypairs {
            match peel(&onion, secret).unwrap() {
                PeelOutcome::Forward { onion: inner, .. } => onion = inner,
                PeelOutcome::Deliver { payload: got, .. } => {
                    assert_eq!(got, payload);
                    return;
                }
            }
        }
        panic!("onion never delivered");
    }

    #[test]
    fn a_wrong_relay_cannot_peel() {
        let circuit = build_circuit(Point::<F31>::at(1), Point::<F31>::at(2), 2, b"c").unwrap();
        let keypairs = relays(circuit.hop_count(), 2);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
        let onion = build(&circuit, &pubkeys, b"x", b"s").unwrap();
        // The second relay's key cannot peel the first hop.
        assert_eq!(peel(&onion, &keypairs[1].0), Err(SealedError::Aead));
    }
}
