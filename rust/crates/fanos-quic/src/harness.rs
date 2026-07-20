//! Assemble a **known** cell over real QUIC — the devnet / multi-node-test seam.
//!
//! A self-certifying coordinate is `MapToPoint(H(cert))` (see [`identity`](crate::coordinate_from_cert)),
//! so a fresh node lands on a *random* Fano point (spec §L0): you cannot ask for point 3. But a cell
//! test needs all seven points occupied by *specific* nodes, so its DHT, rendezvous, and healing paths
//! can be driven end-to-end. This module closes that gap by **grinding** credentials — minting
//! identities until one hashes to the wanted point.
//!
//! This is not a backdoor around self-certification. Every node it produces is a genuine
//! self-certifying node (real certificate, real key, real `MapToPoint`), indistinguishable on the wire
//! from any other; only *which* coordinate it ends up on was chosen rather than accepted. It is exactly
//! the retry-until-**distinct** loop the self-certifying tests already run
//! (`tests/self_certifying.rs::spawn_distinct`) generalised to retry-until-**target**. And it is only
//! tractable because a cell has `N = 7` points (≈ 7 mints per point): grinding a large plane is
//! deliberately impractical — the same asymmetry that keeps a coordinate unforgeable in production.

use fanos_field::Field;
use fanos_geometry::Point;
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_runtime::Engine;

use crate::directory::Directory;
use crate::driver::{NodeHandle, QuicError, spawn_self_certifying_persistent};
use crate::identity::verifiable_coordinate;
use crate::tls::NodeCredentials;

/// Rejection-sampling bound for [`credentials_for_point`]. At a Fano cell's `N = 7` points the chance
/// of *missing* a target after this many mints is `(6/7)^4096 ≈ 10^-274`, so a real cell never
/// exhausts it; the bound exists only to keep a mis-parameterised call — an unreachable target, or a
/// plane far larger than a cell — from looping unboundedly.
pub const DEFAULT_GRIND_LIMIT: usize = 4096;

/// Mint self-certifying [`NodeCredentials`] whose coordinate `MapToPoint(H(cert))` is exactly
/// `target`, by rejection sampling up to `max_tries` mints. `None` if none matched within the bound.
///
/// The returned credential is an ordinary self-signed identity whose coordinate is *earned by its
/// certificate hash* — pass it to [`spawn_self_certifying_persistent`] (or [`spawn_pinned`]) to bring
/// the node up on the production path. See the module docs for why this is not a self-certification
/// bypass.
#[must_use]
pub fn credentials_for_point<F: Field>(
    target: Point<F>,
    max_tries: usize,
) -> Option<NodeCredentials> {
    (0..max_tries).find_map(|_| {
        // A failed mint (no entropy) yields `None` from this closure, so `find_map` simply tries again
        // — a transient generator error costs one wasted attempt, never a spurious match.
        let creds = NodeCredentials::generate().ok()?;
        (verifiable_coordinate::<F>(&creds, Epoch::ZERO, &BeaconSeed::GENESIS).0 == target)
            .then_some(creds)
    })
}

/// Bring up a self-certifying node **pinned to `target`** over real QUIC: grind credentials whose
/// coordinate is `target`, then spawn it through the ordinary persistent self-certifying path
/// ([`spawn_self_certifying_persistent`]). The node is a production node in every respect — only its
/// coordinate was *chosen* rather than accepted — and registers into `directory` like any other.
///
/// # Errors
/// [`QuicError::Grind`] if [`DEFAULT_GRIND_LIMIT`] mints did not hit `target` (impossible for a real
/// Fano cell — indicates an unreachable target or a plane far larger than a cell), else any TLS/I/O
/// error from the spawn itself.
pub async fn spawn_pinned<F: Field + 'static>(
    target: Point<F>,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
) -> Result<NodeHandle, QuicError> {
    let creds = credentials_for_point::<F>(target, DEFAULT_GRIND_LIMIT).ok_or(QuicError::Grind)?;
    spawn_self_certifying_persistent::<F>(&creds, make_engine, directory).await
}

/// A cell of nodes brought up over real QUIC at **known** coordinates, all sharing one [`Directory`]
/// so every member can route to every other by coordinate. Member `i` is seated at `Point::at(i)`.
pub struct Cell {
    /// The member handles; index `i` is the node at `Point::at(i)`.
    pub nodes: Vec<NodeHandle>,
    /// The shared address book binding every member's coordinate to its socket — the seam a real
    /// discovery layer replaces (it is filled here as each node spawns).
    pub directory: Directory,
}

impl Cell {
    /// The number of points in the plane `F` — the cell's full size (`7` for a Fano cell).
    #[must_use]
    pub fn size<F: Field>() -> usize {
        let q = F::Q as usize;
        q * q + q + 1
    }
}

/// Assemble the **full** cell of the plane `F` (all seven points, for a Fano cell) over real QUIC:
/// each node seated at `Point::at(i)` via [`spawn_pinned`], every member sharing one directory. The
/// engine at each point is built by `make_engine`. This is the fixture the e2e DHT / rendezvous /
/// healing tests drive — a genuine multi-node cell, not a loopback pair.
///
/// # Errors
/// Propagates the first [`spawn_pinned`] failure (grind exhaustion or TLS/I/O).
pub async fn spawn_cell<F: Field + 'static>(
    make_engine: impl Fn(Point<F>) -> Box<dyn Engine + Send>,
) -> Result<Cell, QuicError> {
    let directory = Directory::new();
    let n = Cell::size::<F>();
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        nodes.push(spawn_pinned::<F>(Point::at(i), &make_engine, directory.clone()).await?);
    }
    Ok(Cell { nodes, directory })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    /// The pure seam: for every one of the seven Fano points, grinding yields a *genuine*
    /// self-certifying identity whose **VRF genesis coordinate** is exactly that point — earned, not
    /// assigned (the identity's VRF key is derived from its certificate, so this is unforgeable).
    #[test]
    fn grinds_a_self_certifying_identity_for_every_fano_point() {
        for i in 0..Cell::size::<F2>() {
            let target = Point::<F2>::at(i);
            let creds = credentials_for_point::<F2>(target, DEFAULT_GRIND_LIMIT)
                .expect("a Fano point is reachable within the grind limit");
            assert_eq!(
                verifiable_coordinate::<F2>(&creds, Epoch::ZERO, &BeaconSeed::GENESIS).0,
                target,
                "point {i}: the minted identity's verifiable coordinate is the pinned point",
            );
        }
    }

    /// The grind bound is honoured: a zero-try budget matches nothing (no infinite loop, no false
    /// match), for every target — so a mis-parameterised call fails cleanly rather than hanging.
    #[test]
    fn a_zero_try_budget_matches_nothing() {
        for i in 0..Cell::size::<F2>() {
            assert!(
                credentials_for_point::<F2>(Point::<F2>::at(i), 0).is_none(),
                "point {i}: zero tries can never match",
            );
        }
    }
}
