//! The node's durable, self-certifying identity.
//!
//! A node's overlay coordinate is `MapToPoint(H(cert))` — derived from its mutual-TLS certificate,
//! so it is self-authenticating (a peer checks the coordinate against the handshake, no directory
//! trust). Persisting the [`NodeCredentials`] keeps the **same coordinate across restarts**.

use std::path::Path;

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_quic::{NodeCredentials, coordinate_from_cert};

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
            std::fs::write(p, creds.to_bytes())?;
            Ok(creds)
        }
        None => NodeCredentials::generate().map_err(|_| NodeError::Identity),
    }
}

/// The overlay coordinate a set of credentials resolves to over the field `F`.
#[must_use]
pub fn coordinate<F: Field>(credentials: &NodeCredentials) -> Triple {
    coordinate_from_cert::<F>(credentials.cert_der()).coords()
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
