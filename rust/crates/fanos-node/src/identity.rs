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

use tracing::info;

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
            // **Three operator mistakes used to share one sentence** (#309). `ok_or(NodeError::Identity)`
            // said "node identity could not be loaded or generated" for a truncated file, a mistyped
            // `--identity` pointing at something else, and a file from a build with a different layout —
            // and the operator's next action differs in each.
            match NodeCredentials::from_bytes(&bytes) {
                Ok(creds) => Ok(creds),
                // Written before the frame existed and still perfectly valid. Said once, at `info`, because
                // an operator has no other way to learn that this file is on the old layout — and NOT
                // refused, since the file IS the coordinate and refusing it would return the node to its
                // cell as a stranger.
                Err(fanos_quic::IdentityFormat::Legacy(creds)) => {
                    info!(
                        path = %p.display(),
                        "identity file predates the format frame (#309) — read as layout 0 and still valid; \
                         it will be rewritten framed only if this node is ever re-provisioned"
                    );
                    Ok(*creds)
                }
                Err(fanos_quic::IdentityFormat::OtherVersion(v)) => Err(NodeError::Config(format!(
                    "the identity at {} was written at layout version {v}; this build reads {}. Do not \
                     delete it — the coordinate is derived from this file, so a node that loses it rejoins \
                     the cell as a stranger. Run the build that wrote it, or migrate deliberately.",
                    p.display(),
                    fanos_quic::IDENTITY_FORMAT_VERSION,
                ))),
                Err(fanos_quic::IdentityFormat::Corrupt) => Err(NodeError::Config(format!(
                    "the identity at {} did not decode — it is truncated, corrupt, or not an identity file \
                     at all. Check that --identity names the right path before replacing it: a NEW identity \
                     is a new coordinate, and the cell sees the old node vanish.",
                    p.display(),
                ))),
            }
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

/// The overlay coordinate a set of credentials resolves to over the field `F` **on the network whose genesis
/// seed is `genesis`** — its verifiable coordinate `MapToPoint(VRF(vrf_sk, cert‖0‖genesis))`, the same point
/// the live engine is seated at ([`crate::node::genesis_seed`], `docs/design-genesis.md` §6).
///
/// **The seed is a parameter, and that is the whole point.** It used to be `BeaconSeed::GENESIS`, a
/// compile-time constant, which made a credential's coordinate the same on every FANOS network in existence —
/// the defect §3 of that note calls out. Once the seed is derived per network, a coordinate printed without
/// one is not merely less informative, it is **wrong**: bootstrap addresses are `coord@host:port` and the pin
/// is checked, so an operator pasting a constant-seed coordinate onto a network with a beacon publishes an
/// address no node will match. Taking it as an argument is what stops a caller from forgetting there is a
/// question to answer; [`crate::config::NodeConfig::genesis_seed`] answers it from the config already in hand.
#[must_use]
pub fn coordinate<F: Field>(credentials: &NodeCredentials, genesis: &BeaconSeed) -> Triple {
    verifiable_coordinate::<F>(credentials, Epoch::ZERO, genesis).0.coords()
}

#[cfg(test)]
// `indexing_slicing` joins the sibling modules' pair (#309): the format test builds a legacy body by
// slicing off a header it has just written, and an index out of range there IS the failure it is looking
// for — a `get(..)` would turn "the header is not the width we wrote" into a silent `None`.
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    #[test]
    fn generated_identity_has_a_stable_coordinate() {
        let creds = load_or_generate(None).unwrap();
        // Deterministic function of the cert *and the network*: two reads on one network agree.
        let g = BeaconSeed::GENESIS;
        assert_eq!(coordinate::<F2>(&creds, &g), coordinate::<F2>(&creds, &g));
    }

    #[test]
    fn persisted_identity_survives_a_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fanos-id-test-{}.bin", std::process::id()));
        let first = load_or_generate(Some(&path)).unwrap();
        let coord1 = coordinate::<F2>(&first, &BeaconSeed::GENESIS);
        // A second load reads the same file → same coordinate.
        let second = load_or_generate(Some(&path)).unwrap();
        assert_eq!(coord1, coordinate::<F2>(&second, &BeaconSeed::GENESIS));
        let _ = std::fs::remove_file(&path);
    }

    /// **The four things an identity file can be, told apart** (#309).
    ///
    /// The defect was one sentence for three operator mistakes, and the second cost is the one with teeth:
    /// while an unframed file is indistinguishable from a corrupt one, the layout can never change, because
    /// adding a field would make every live node's identity unreadable — and this file IS the coordinate, so
    /// an unreadable one returns that node to its cell as a stranger.
    ///
    /// **Legacy is asserted first and hardest**, because it is the migration decision: a file written before
    /// the frame existed must still load, and the node must keep its coordinate byte for byte. Refusing it
    /// would not be strictness, it would be deleting every deployed node.
    ///
    /// Falsified by making `from_bytes` treat `Unframed` as `Corrupt`: the legacy assertion goes red on the
    /// coordinate comparison, which is the sentence "this deployment just lost its identities".
    #[test]
    fn an_identity_file_says_which_of_four_things_it_is() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fanos-id-format-{}.bin", std::process::id()));
        let creds = load_or_generate(None).unwrap();
        let framed = creds.to_bytes();
        let coord = coordinate::<F2>(&creds, &BeaconSeed::GENESIS);

        // 1. This build's frame.
        std::fs::write(&path, &framed).unwrap();
        let back = load_or_generate(Some(&path)).unwrap();
        assert_eq!(coordinate::<F2>(&back, &BeaconSeed::GENESIS), coord, "a framed file round-trips");

        // 2. LEGACY: the body with no frame at all, which is exactly what every file written before #309
        //    looks like. It must load, and to the SAME coordinate — the node keeps its seat.
        let legacy = &framed[fanos_wire::stored::HEADER_LEN..];
        std::fs::write(&path, legacy).unwrap();
        let back = load_or_generate(Some(&path)).expect("an unframed identity must still load");
        assert_eq!(
            coordinate::<F2>(&back, &BeaconSeed::GENESIS),
            coord,
            "a pre-frame identity must keep its coordinate — refusing it would return every deployed node \
             to its cell as a stranger, which is not strictness but data loss"
        );

        // 3. Another layout version: refused, and the refusal must say NOT to delete the file, because the
        //    obvious reaction to "cannot read your identity" is to regenerate it and lose the coordinate.
        let mut future = framed.clone();
        future[fanos_wire::stored::HEADER_LEN - 1] = fanos_quic::IDENTITY_FORMAT_VERSION.wrapping_add(1);
        std::fs::write(&path, &future).unwrap();
        let msg = load_or_generate(Some(&path)).expect_err("a future layout must not be guessed at").to_string();
        assert!(msg.contains("layout version"), "the refusal names the layout: {msg}");
        assert!(msg.contains("Do not"), "and warns against deleting the file: {msg}");

        // 4. Corrupt/foreign: this build's frame over a body that does not decode.
        let mut broken = framed.clone();
        broken.truncate(fanos_wire::stored::HEADER_LEN + 3);
        std::fs::write(&path, &broken).unwrap();
        let msg = load_or_generate(Some(&path)).expect_err("a truncated body must not load").to_string();
        assert!(msg.contains("did not decode"), "corrupt is its own sentence: {msg}");
        // And the three refusals are DIFFERENT sentences — the whole point, and the thing a single
        // `NodeError::Identity` could not do.
        assert!(!msg.contains("layout version"), "corrupt must not be reported as a version mismatch: {msg}");

        let _ = std::fs::remove_file(&path);
    }

    /// **One identity, two networks, two seats — and the display path must show it.**
    ///
    /// The live path already separates them (`Directory::for_network`), so the risk this pins is a *reporting*
    /// one: a CLI that prints a coordinate without knowing the network prints a bootstrap address that no node
    /// on that network will match. Written as a property of `coordinate` itself so it fails at the source
    /// rather than three call sites downstream.
    #[test]
    fn one_identity_seats_differently_on_two_networks() {
        let creds = load_or_generate(None).unwrap();
        let a = coordinate::<F2>(&creds, &BeaconSeed::GENESIS);
        // Any distinct seed; the Fano plane has 7 points, so a single draw is not proof on its own —
        // sweep until one differs, and fail if the seed is being ignored altogether.
        let moved = (1u8..=64).any(|i| coordinate::<F2>(&creds, &BeaconSeed::new([i; 32])) != a);
        assert!(moved, "the genesis seed must move the seat — otherwise `coordinate` is ignoring it");
    }
}
