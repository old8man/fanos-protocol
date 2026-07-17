//! Moving-target bridges — no static list to block (spec §13.6, V22).
//!
//! The plain bootstrap is a blockable static list. PROTEUS replaces it with the same
//! computed-rendezvous trick as CALYPSO: a client holding a community bridge-secret `s` derives
//! the current entry set from the beacon, `bridge = MapToLine(VRF(s, epoch))`, which **rotates
//! every epoch**. A censor who enumerates and blocks this epoch's bridges finds the list decayed
//! next epoch, and to block a client's entry in a single epoch must cover **all `q+1`** of its
//! bridge-lines (anti-eclipse) — which differ the following epoch.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Line;

use fanos_crypto::map_to_line;

const BRIDGE_LABEL: &str = "FANOS-v1/proteus-bridge";

/// A client's primary bridge line for an epoch (spec §13.6). Rotates every epoch.
#[must_use]
pub fn bridge_line<F: Field>(community_secret: &[u8], epoch: u32) -> Line<F> {
    let mut data = Vec::with_capacity(community_secret.len() + 4);
    data.extend_from_slice(community_secret);
    data.extend_from_slice(&epoch.to_be_bytes());
    map_to_line::<F>(BRIDGE_LABEL, &data)
}

/// A client's `count` bridge lines for an epoch (its `q+1` anti-eclipse entry points).
#[must_use]
pub fn client_bridge_lines<F: Field>(
    community_secret: &[u8],
    epoch: u32,
    count: usize,
) -> Vec<Line<F>> {
    (0..count)
        .map(|i| {
            let mut data = Vec::with_capacity(community_secret.len() + 8);
            data.extend_from_slice(community_secret);
            data.extend_from_slice(&epoch.to_be_bytes());
            data.extend_from_slice(&(i as u32).to_be_bytes());
            map_to_line::<F>(BRIDGE_LABEL, &data)
        })
        .collect()
}

/// The fraction of `epochs` in which a client's primary bridge escapes the censor's blocked
/// line-set — the moving-target advantage (spec §13.6, V22).
#[must_use]
pub fn reachable_fraction<F: Field>(
    community_secret: &[u8],
    blocked: &BTreeSet<usize>,
    epochs: u32,
) -> f64 {
    if epochs == 0 {
        return 1.0;
    }
    let reachable = (0..epochs)
        .filter(|&e| !blocked.contains(&bridge_line::<F>(community_secret, e).index()))
        .count();
    reachable as f64 / f64::from(epochs)
}

/// Whether a client is fully blocked in one epoch: the censor must cover **all** of its
/// `q+1` bridge lines (anti-eclipse, spec §13.6).
#[must_use]
pub fn is_blocked_this_epoch<F: Field>(
    community_secret: &[u8],
    epoch: u32,
    line_count: usize,
    blocked: &BTreeSet<usize>,
) -> bool {
    client_bridge_lines::<F>(community_secret, epoch, line_count)
        .iter()
        .all(|line| blocked.contains(&line.index()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::F31;

    #[test]
    fn bridges_rotate_every_epoch() {
        let secret = b"bridge-secret";
        assert_ne!(bridge_line::<F31>(secret, 0), bridge_line::<F31>(secret, 1));
    }

    #[test]
    fn moving_target_matches_spec_reachability() {
        // V22: blocking 184 of 993 lines still leaves a client reachable ~80% of epochs.
        let secret = b"community";
        let blocked: BTreeSet<usize> = (0..184).collect();
        let reachable = reachable_fraction::<F31>(secret, &blocked, 8000);
        // Expected ≈ 1 − 184/993 ≈ 0.815; allow sampling slack.
        assert!((reachable - 0.815).abs() < 0.03, "reachable={reachable}");
    }

    #[test]
    fn blocking_one_epoch_needs_all_q_plus_one_lines() {
        let secret = b"anti-eclipse";
        let epoch = 3;
        let lines = client_bridge_lines::<F31>(secret, epoch, 32);
        let all: BTreeSet<usize> = lines.iter().map(Line::index).collect();
        // Blocking all 32 lines blocks the epoch...
        assert!(is_blocked_this_epoch::<F31>(secret, epoch, 32, &all));
        // ...but missing even one leaves the client reachable.
        let mut minus_one = all.clone();
        let removed = *minus_one.iter().next().unwrap();
        minus_one.remove(&removed);
        assert!(!is_blocked_this_epoch::<F31>(secret, epoch, 32, &minus_one));
    }
}
