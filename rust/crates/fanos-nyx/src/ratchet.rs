//! The holonomic ratchet — forward secrecy and a path authenticator (spec §5.4).
//!
//! On the incidence bundle a connection `A` is defined over each incident pair; the hop factor
//! is `β_k = KDF(state ‖ A(p_{k-1}, p_k))`, and the ordered composition along the path is the
//! **holonomy** `Hol = state_L`. Two consequences (spec §5.4):
//!
//! * **Forward secrecy** — the chain is one-way (a KDF chain), so compromising the current hop
//!   reveals nothing about past ones.
//! * **A compact path authenticator** — both endpoints, knowing the algebraic path, compute
//!   the same `Hol`; inserting or substituting any hop changes an `A_k` and so breaks it,
//!   exactly as a nontrivial holonomy signals an incorrect contour in gap theory.

use alloc::vec::Vec;

use fanos_crypto::hash_labeled;
use fanos_field::Field;
use fanos_geometry::Triple;

use crate::path::Circuit;

/// The domain label for the ratchet KDF.
const RATCHET_LABEL: &str = "FANOS-v1/nyx-ratchet";

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

    /// The current holonomy (accumulated state).
    #[must_use]
    pub fn holonomy(&self) -> [u8; 32] {
        self.state
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
    for (k, hop) in circuit.hops().iter().enumerate() {
        let (Some(a), Some(b)) = (relays.get(k), relays.get(k + 1)) else {
            break;
        };
        let conn = connection_bytes(a.coords(), b.coords(), hop.coords());
        ratchet.advance(&conn);
    }
    ratchet.holonomy()
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
        // A different seed gives a different chain (forward-secret separation).
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
}
