//! The Tessera onion — nested threshold-sheaf layers over a geometric circuit (spec §5.7).
//!
//! The sender wraps a payload in one AEAD layer per hop, keyed by the holonomic ratchet
//! ([`crate::ratchet`]) and unlockable only by a threshold `t` of the hop line's members
//! (each layer key is Shamir-shared across the `q+1` members). Peeling a hop reveals *only*
//! the next hop; the innermost layer delivers the payload. The accumulated holonomy travels
//! with the packet as a path authenticator.
//!
//! Fidelity note: this is a real nested onion with real AEAD and real threshold sharing. The
//! constant-size Sphinx padding (length indistinguishability) is the wire refinement pinned in
//! [`fanos_wire::tessera`]; here the body shrinks by one layer per hop, which is the
//! transparent form used for the simulator and tests.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use fanos_primitives::hash::xof_reader;
use fanos_primitives::{hash_labeled, shamir};
use fanos_field::Field;

use crate::path::Circuit;
use crate::ratchet::circuit_holonomy;
use crate::sheaf::NyxError;

const CMD_DELIVER: u8 = 0;
const CMD_NEXT: u8 = 1;
const NONCE_LABEL: &str = "FANOS-v1/nyx-nonce";
const KEY_LABEL: &str = "FANOS-v1/nyx-hopkey";
const SHARE_LABEL: &str = "FANOS-v1/nyx-shares";

/// One hop's header: the AEAD nonce and the `q+1` Shamir shares of that hop's layer key.
#[derive(Clone, PartialEq, Eq, Debug)]
struct HopHeader {
    nonce: [u8; 12],
    shares: Vec<shamir::Share>,
}

/// A NYX onion packet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tessera {
    body: Vec<u8>,
    hops: Vec<HopHeader>,
    holonomy: [u8; 32],
}

/// The outcome of peeling one hop.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PeelResult {
    /// Forward the inner packet to the line with this projective index.
    Forward {
        /// The next hop line's index.
        next_line: u32,
        /// The re-addressed inner packet.
        packet: Tessera,
    },
    /// The payload has reached its destination.
    Deliver {
        /// The delivered payload.
        payload: Vec<u8>,
    },
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8]) -> Result<Vec<u8>, NyxError> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| NyxError::Aead)?
        .encrypt(&Nonce::from(*nonce), pt)
        .map_err(|_| NyxError::Aead)
}

fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>, NyxError> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| NyxError::Aead)?
        .decrypt(&Nonce::from(*nonce), ct)
        .map_err(|_| NyxError::Aead)
}

/// Derive the per-hop nonce from the circuit seed and hop index.
fn hop_nonce(seed: &[u8; 32], hop: usize) -> [u8; 12] {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&(hop as u32).to_be_bytes());
    let digest = hash_labeled(NONCE_LABEL, &input);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

/// Derive the per-hop layer key (the holonomic hop key) from the seed and hop index.
fn hop_key(seed: &[u8; 32], hop: usize) -> [u8; 32] {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&(hop as u32).to_be_bytes());
    hash_labeled(KEY_LABEL, &input)
}

impl Tessera {
    /// The path authenticator (accumulated holonomy).
    #[must_use]
    pub fn holonomy(&self) -> [u8; 32] {
        self.holonomy
    }

    /// The number of hops still wrapped.
    #[must_use]
    pub fn remaining_hops(&self) -> usize {
        self.hops.len()
    }

    /// The shares held by the *current* hop's line members (the outermost layer). In the
    /// network these are distributed one per member; a caller supplies `t` of them to peel.
    #[must_use]
    pub fn current_hop_shares(&self) -> &[shamir::Share] {
        self.hops.first().map_or(&[], |h| &h.shares)
    }

    /// Build a Tessera for `circuit` carrying `payload`, with `threshold`-of-`line_size` hops.
    /// All per-hop keys, nonces, and sharing randomness derive from `seed` (the sender's
    /// ephemeral secret).
    pub fn build<F: Field>(
        circuit: &Circuit<F>,
        payload: &[u8],
        threshold: u8,
        line_size: u8,
        seed: &[u8; 32],
    ) -> Result<Self, NyxError> {
        let hop_count = circuit.hop_count();
        let per_hop_rnd = usize::from(threshold.saturating_sub(1)) * 32;
        let mut rng = xof_reader(SHARE_LABEL, seed);

        // Pre-draw sharing randomness for every hop so the (inside-out) build order is clean.
        let mut randomness = Vec::with_capacity(hop_count);
        for _ in 0..hop_count {
            let mut buf = alloc::vec![0u8; per_hop_rnd];
            rng.fill(&mut buf);
            randomness.push(buf);
        }

        let mut body = payload.to_vec();
        let mut hops: Vec<HopHeader> = Vec::with_capacity(hop_count);
        for k in (0..hop_count).rev() {
            // Routing command: forward to the next hop line, or deliver.
            let mut plaintext = Vec::with_capacity(body.len() + 5);
            if k + 1 == hop_count {
                plaintext.push(CMD_DELIVER);
            } else {
                let next_line = circuit
                    .hops()
                    .get(k + 1)
                    .ok_or(NyxError::KeyLength)?
                    .index();
                plaintext.push(CMD_NEXT);
                plaintext.extend_from_slice(&(next_line as u32).to_be_bytes());
            }
            plaintext.extend_from_slice(&body);

            let key = hop_key(seed, k);
            let nonce = hop_nonce(seed, k);
            body = aead_seal(&key, &nonce, &plaintext)?;
            let rnd = randomness.get(k).ok_or(NyxError::KeyLength)?;
            let shares = shamir::split(&key, threshold, line_size, rnd)?;
            hops.push(HopHeader { nonce, shares });
        }
        hops.reverse(); // hops[0] is now the outermost (first) hop

        Ok(Self {
            body,
            hops,
            holonomy: circuit_holonomy(circuit, seed),
        })
    }

    /// Peel the current (outermost) hop using `member_shares` (at least `t` of the hop's
    /// shares). Returns the next hop to forward to, or the delivered payload. Fewer than `t`
    /// shares reconstruct the wrong key and AEAD authentication fails (spec §5.2).
    pub fn peel(mut self, member_shares: &[shamir::Share]) -> Result<PeelResult, NyxError> {
        if self.hops.is_empty() {
            return Err(NyxError::KeyLength);
        }
        let header = self.hops.remove(0);
        let key = shamir::reconstruct(member_shares)?;
        if key.len() != 32 {
            return Err(NyxError::KeyLength);
        }
        let mut key32 = [0u8; 32];
        key32.copy_from_slice(&key);
        let plaintext = aead_open(&key32, &header.nonce, &self.body)?;

        let (&tag, rest) = plaintext.split_first().ok_or(NyxError::Aead)?;
        match tag {
            CMD_DELIVER => Ok(PeelResult::Deliver {
                payload: rest.to_vec(),
            }),
            CMD_NEXT => {
                let idx_bytes: [u8; 4] = rest
                    .get(..4)
                    .ok_or(NyxError::Aead)?
                    .try_into()
                    .map_err(|_| NyxError::Aead)?;
                let next_line = u32::from_be_bytes(idx_bytes);
                let inner = rest.get(4..).ok_or(NyxError::Aead)?.to_vec();
                Ok(PeelResult::Forward {
                    next_line,
                    packet: Tessera {
                        body: inner,
                        hops: self.hops,
                        holonomy: self.holonomy,
                    },
                })
            }
            _ => Err(NyxError::Aead),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::path::build_circuit;
    use fanos_field::F31;
    use fanos_geometry::Point;

    /// Drive a Tessera through its whole circuit, peeling each hop with a threshold subset.
    fn route(circuit: &Circuit<F31>, payload: &[u8], t: u8, line_size: u8) -> Vec<u8> {
        let seed = [11u8; 32];
        let mut packet = Tessera::build(circuit, payload, t, line_size, &seed).unwrap();
        let end_holonomy = packet.holonomy();
        loop {
            let shares: Vec<_> = packet.current_hop_shares()[..usize::from(t)].to_vec();
            match packet.peel(&shares).unwrap() {
                PeelResult::Forward { packet: inner, .. } => {
                    assert_eq!(inner.holonomy(), end_holonomy, "holonomy is carried intact");
                    packet = inner;
                }
                PeelResult::Deliver { payload } => return payload,
            }
        }
    }

    #[test]
    fn onion_delivers_through_every_hop() {
        let circuit =
            build_circuit(Point::<F31>::at(0), Point::<F31>::at(700), 3, b"circuit").unwrap();
        let payload = b"the secret message";
        assert_eq!(route(&circuit, payload, 6, 8), payload);
    }

    #[test]
    fn each_hop_needs_the_threshold() {
        let circuit = build_circuit(Point::<F31>::at(0), Point::<F31>::at(700), 2, b"c").unwrap();
        let seed = [11u8; 32];
        let packet = Tessera::build(&circuit, b"hi", 6, 8, &seed).unwrap();
        // Five shares (t-1) fail to peel the first hop.
        let too_few: Vec<_> = packet.current_hop_shares()[..5].to_vec();
        assert_eq!(packet.peel(&too_few), Err(NyxError::Aead));
    }

    #[test]
    fn a_single_node_cannot_peel() {
        let circuit = build_circuit(Point::<F31>::at(1), Point::<F31>::at(2), 1, b"c").unwrap();
        let seed = [11u8; 32];
        let packet = Tessera::build(&circuit, b"x", 6, 8, &seed).unwrap();
        // One member's share is far below threshold.
        let one: Vec<_> = packet.current_hop_shares()[..1].to_vec();
        assert_eq!(packet.peel(&one), Err(NyxError::Aead));
    }

    #[test]
    fn longer_circuits_still_deliver() {
        let circuit =
            build_circuit(Point::<F31>::at(3), Point::<F31>::at(900), 5, b"long").unwrap();
        assert_eq!(route(&circuit, b"payload!", 6, 8), b"payload!");
    }
}
