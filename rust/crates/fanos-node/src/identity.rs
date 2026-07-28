//! The node's durable, self-certifying identity.
//!
//! A node's overlay coordinate is its **verifiable** VRF coordinate `MapToPoint(VRF(vrf_sk,
//! cert‖epoch‖beacon))` — the VRF key is derived from its mutual-TLS certificate, so it is
//! self-authenticating (a peer checks the coordinate proof against the handshake, no directory trust) and
//! unforgeable (spec §L0/§7.3). Persisting the [`NodeCredentials`] keeps the **same identity — and so the
//! same genesis coordinate — across restarts**.

use std::path::Path;

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_quic::{NodeCredentials, verifiable_coordinate};
use fanos_rendezvous::{BeaconSeed, Epoch};

use crate::error::NodeError;

/// Load the identity from `path`, or generate and persist a new one there. With `path = None` a
/// fresh, ephemeral identity is generated (a new coordinate each run).
///
/// # Errors
/// [`NodeError::Io`] on a filesystem error, [`NodeError::Identity`] if generation or parsing fails.
pub fn load_or_generate(path: Option<&Path>) -> Result<NodeCredentials, NodeError> {
    match path {
        Some(p) if p.exists() => {
            let bytes = std::fs::read(p)?;
            NodeCredentials::from_bytes(&bytes).ok_or(NodeError::Identity)
        }
        Some(p) => {
            let creds = NodeCredentials::generate().map_err(|_| NodeError::Identity)?;
            write_secret(p, &creds.to_bytes())?;
            Ok(creds)
        }
        None => NodeCredentials::generate().map_err(|_| NodeError::Identity),
    }
}

/// Write a node's long-term secret so that only its owner can read it.
///
/// The mode is set **at creation**, not applied afterwards: a key created world-readable and `chmod`-ed a
/// microsecond later *was* world-readable, and on a shared host that window is the whole of the exposure. Before
/// this, `load_or_generate` used a plain `fs::write` and the identity landed at the process umask — 0644 on a
/// stock system, which makes a node's permanent identity readable by every account on the machine. Found by
/// running `fanos init` and looking at what it had produced.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), NodeError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f =
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// The overlay coordinate a set of credentials resolves to over the field `F` — its **genesis** verifiable
/// coordinate `MapToPoint(VRF(vrf_sk, cert‖0‖GENESIS))`, the same point the live engine is seated at.
#[must_use]
pub fn coordinate<F: Field>(credentials: &NodeCredentials) -> Triple {
    verifiable_coordinate::<F>(credentials, Epoch::ZERO, &BeaconSeed::GENESIS)
        .0
        .coords()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    #[test]
    fn generated_identity_has_a_stable_coordinate() {
        let creds = load_or_generate(None).unwrap();
        // Deterministic function of the cert: two reads agree.
        assert_eq!(coordinate::<F2>(&creds), coordinate::<F2>(&creds));
    }

    #[test]
    fn persisted_identity_survives_a_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fanos-id-test-{}.bin", std::process::id()));
        let first = load_or_generate(Some(&path)).unwrap();
        let coord1 = coordinate::<F2>(&first);
        // A second load reads the same file → same coordinate.
        let second = load_or_generate(Some(&path)).unwrap();
        assert_eq!(coord1, coordinate::<F2>(&second));
        let _ = std::fs::remove_file(&path);
    }
}
