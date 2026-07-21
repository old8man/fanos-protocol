//! Slowly-rotating **guard set** — the predecessor-attack bound with availability (threat-model C10).
//!
//! A single fixed guard (`build_circuit_via_guard`) turns "exposed with probability `f` per circuit"
//! into "exposed once, only if the adversary controls the guard" (≈ `f`, independent of the round count;
//! Wright–Adler–Levine–Shields). But one guard is brittle: if it goes down, the client must pick a new
//! entry, and re-picking *per circuit* rotates the first hop again — reopening the predecessor attack.
//!
//! A [`GuardSet`] closes that gap the way the Tor guard-spec does, without weakening the bound:
//!
//! * **Ordered, primary-first.** The set is a short priority list (`guards[0]` is the primary). A circuit
//!   uses the highest-priority *reachable* guard, so as long as the primary is up the entry is exactly the
//!   single-guard case — exposure stays ≈ `f`, **not** the `1 − (1−f)^k` a naive "any of k guards" set
//!   would suffer. Backups only carry traffic when higher-priority guards are down, a second-order event.
//! * **Churn-resilient.** When the primary drops, the entry falls to the next *stable* backup rather than
//!   rotating per circuit, so the predecessor bound survives guard failure.
//! * **Slow rotation.** The set is keyed by the client identity and a **coarse** window `epoch /
//!   rotation_period`, so it is identical for every epoch inside a window and only re-draws at a window
//!   boundary. Lifetime exposure grows with the number of *distinct primaries* a client uses (≈ `f` per
//!   window), so a long `rotation_period` keeps it low — the reason Tor rotates guards over months, not
//!   circuits.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Point;
use fanos_primitives::hash::xof_reader;

use crate::path::{Circuit, build_circuit_via_guard, draw_point};

/// The domain label for guard-set derivation (distinct from the per-circuit path label).
const GUARD_LABEL: &str = "FANOS-v1/nyx-guard";

/// A client's ordered guard set for one rotation window: `guards[0]` is the stable primary, the rest are
/// priority-ordered backups. Derive it with [`GuardSet::derive`]; pick the entry with
/// [`GuardSet::active_guard`]; build through it with [`GuardSet::build_circuit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardSet<F: Field> {
    guards: Vec<Point<F>>,
    window: u64,
}

impl<F: Field> GuardSet<F> {
    /// Derive a client's guard set of up to `size` distinct guards, **stable across `rotation_period`
    /// epochs** (slow rotation): the set is keyed by `client_id` and the coarse window `epoch /
    /// rotation_period`, so it is identical for every epoch in a window and (almost surely) re-draws at
    /// the boundary. `avoid` (typically the client's own coordinate) is never chosen, and the guards are
    /// distinct and priority-ordered by draw. `rotation_period` is treated as at least 1.
    ///
    /// On a tiny plane the set may come back shorter than `size` (it stops rather than loop forever); a
    /// caller wanting a guaranteed non-empty set should check [`GuardSet::is_empty`].
    #[must_use]
    pub fn derive(
        client_id: &[u8],
        epoch: u64,
        rotation_period: u64,
        size: usize,
        avoid: Point<F>,
    ) -> Self {
        let window = epoch / rotation_period.max(1);
        let mut seed = Vec::with_capacity(client_id.len() + 8);
        seed.extend_from_slice(client_id);
        seed.extend_from_slice(&window.to_le_bytes());
        let mut reader = xof_reader(GUARD_LABEL, &seed);

        let mut guards: Vec<Point<F>> = Vec::with_capacity(size);
        for _ in 0..size {
            // Draw the next guard distinct from `avoid` and every guard already chosen. The closure's
            // borrow of `guards` ends when `draw_point` returns, so the subsequent push is unconflicted.
            match draw_point(&mut reader, |p| *p != avoid && !guards.contains(p)) {
                Some(p) => guards.push(p),
                None => break, // exhausted the small plane — return what we have
            }
        }
        Self { guards, window }
    }

    /// The primary guard (used preferentially), or `None` for an empty set.
    #[must_use]
    pub fn primary(&self) -> Option<Point<F>> {
        self.guards.first().copied()
    }

    /// The priority-ordered guards (primary first).
    #[must_use]
    pub fn guards(&self) -> &[Point<F>] {
        &self.guards
    }

    /// The rotation window this set belongs to (`epoch / rotation_period`). Two derivations agree iff they
    /// fall in the same window — the observable "slow rotation" boundary.
    #[must_use]
    pub fn window(&self) -> u64 {
        self.window
    }

    /// The number of guards in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.guards.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    /// The highest-priority **reachable** guard (primary preferred; a backup only if every
    /// higher-priority guard is down), or `None` if all guards are down. Because the primary is used
    /// whenever it is up, predecessor exposure stays ≈ the primary's compromise probability rather than
    /// growing with the set size.
    #[must_use]
    pub fn active_guard(&self, is_up: impl Fn(Point<F>) -> bool) -> Option<Point<F>> {
        self.guards.iter().copied().find(|&g| is_up(g))
    }

    /// Build an `hops`-length circuit `source → active-guard → … → dest`, pinning the entry to the
    /// highest-priority reachable guard (so the interior still rotates per `seed`, only the entry is
    /// stable). `None` if every guard is down or the request is degenerate.
    #[must_use]
    pub fn build_circuit(
        &self,
        source: Point<F>,
        dest: Point<F>,
        hops: usize,
        seed: &[u8],
        is_up: impl Fn(Point<F>) -> bool,
    ) -> Option<Circuit<F>> {
        let guard = self.active_guard(is_up)?;
        build_circuit_via_guard(source, guard, dest, hops, seed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::{F7, F31};

    const CLIENT: &[u8] = b"initiator-secret-seed";

    #[test]
    fn a_guard_set_is_distinct_ordered_and_avoids_the_client() {
        let me = Point::<F31>::at(3);
        let set = GuardSet::derive(CLIENT, 0, 100, 3, me);
        assert_eq!(set.len(), 3);
        assert_eq!(set.primary(), Some(set.guards()[0]));
        // Distinct, and none is the avoided point.
        for (i, g) in set.guards().iter().enumerate() {
            assert_ne!(*g, me, "a guard must never be the client's own coordinate");
            assert!(
                !set.guards()[..i].contains(g),
                "guards must be distinct and priority-ordered"
            );
        }
    }

    #[test]
    fn the_set_is_stable_within_a_window_and_rotates_slowly_across_windows() {
        let me = Point::<F31>::at(3);
        let period = 100;
        // Every epoch inside window 0 yields the identical set (slow rotation — no per-epoch churn).
        let base = GuardSet::<F31>::derive(CLIENT, 0, period, 3, me);
        for epoch in [1, 42, 99] {
            let same = GuardSet::<F31>::derive(CLIENT, epoch, period, 3, me);
            assert_eq!(same, base, "the guard set is stable across a rotation window");
            assert_eq!(same.window(), 0);
        }
        // Crossing the boundary re-draws (a new window index, almost surely a different primary).
        let next = GuardSet::<F31>::derive(CLIENT, period, period, 3, me);
        assert_eq!(next.window(), 1);
        assert_ne!(next.primary(), base.primary(), "the primary rotates across windows");
    }

    #[test]
    fn active_guard_prefers_the_primary_and_falls_back_on_churn() {
        let me = Point::<F31>::at(3);
        let set = GuardSet::derive(CLIENT, 0, 100, 3, me);
        let [g0, g1, g2] = [set.guards()[0], set.guards()[1], set.guards()[2]];

        // All up ⇒ the primary carries traffic.
        assert_eq!(set.active_guard(|_| true), Some(g0));
        // Primary down ⇒ the next stable backup, not a re-rotation.
        assert_eq!(set.active_guard(|g| g != g0), Some(g1));
        // Two down ⇒ the last backup.
        assert_eq!(set.active_guard(|g| g != g0 && g != g1), Some(g2));
        // All down ⇒ no entry.
        assert_eq!(set.active_guard(|_| false), None);
    }

    #[test]
    fn a_built_circuit_pins_the_active_guard_as_the_first_hop() {
        let me = Point::<F7>::at(0);
        let dest = Point::<F7>::at(30);
        let set = GuardSet::derive(CLIENT, 0, 100, 3, me);
        let primary = set.primary().unwrap();

        let circuit = set.build_circuit(me, dest, 4, b"c-1", |_| true).unwrap();
        assert!(circuit.is_valid_flag_chain());
        assert_eq!(circuit.source(), me);
        assert_eq!(circuit.dest(), dest);
        assert_eq!(circuit.relays()[1], primary, "the entry is the primary while it is up");

        // With the primary down the entry becomes the first backup — still a *stable* pinned entry.
        let backup = set.guards()[1];
        let rerouted = set.build_circuit(me, dest, 4, b"c-2", |g| g != primary).unwrap();
        assert_eq!(rerouted.relays()[1], backup, "the entry falls back to a stable backup on churn");
    }
}
