//! **Timeline analysis** — the sans-I/O half of the fleet observatory.
//!
//! The motivating fact (`docs/design-testing.md` §5.3.1): a *frozen* system and a *finished* system are
//! indistinguishable from any single sample. The role loop kept its startup-race assignment forever, and the standing
//! assertion passed the whole time; what exposed it was printing a timeline and noticing a value that never moved. This
//! module turns that act of noticing into something assertable, so the class of defect is caught by the suite rather
//! than by whoever happens to be reading the output.
//!
//! It deliberately holds **no** I/O: a [`Timeline`] is a recorded observation, and every property below is a pure
//! function of it. That keeps the instrument itself unit-testable at T0 — an instrument that lies is worse than none,
//! so its own analysis is pinned by known-answer timelines at the bottom of this file.
//!
//! Three properties, three distinct defect classes:
//!
//! | Property | Healthy value | The defect it names |
//! |---|---|---|
//! | [`frozen`](Timeline::frozen) | `false` | a missing trigger — the system never moves at all |
//! | [`stable_agreement_at`](Timeline::stable_agreement_at) | `Some(t)` | permanent disagreement — nodes hold different views forever |
//! | [`changes_after`](Timeline::changes_after) | `0` | oscillation — the system moves but never settles |
//!
//! No single final-state assertion can express any of the three, which is precisely why they were unguarded.

use core::fmt::Debug;
use core::fmt::Write as _;
use core::time::Duration;

/// A recorded timeline of one observable across every node of a fleet: each sample pairs the elapsed time with the
/// value every node reported at that moment, in node order.
#[derive(Clone, Debug, Default)]
pub struct Timeline<T> {
    samples: Vec<(Duration, Vec<T>)>,
}

impl<T> Timeline<T> {
    /// Build a timeline from `(elapsed, per-node values)` samples, in observation order.
    #[must_use]
    pub const fn new(samples: Vec<(Duration, Vec<T>)>) -> Self { Self { samples } }

    /// The recorded samples, in observation order.
    #[must_use]
    pub fn samples(&self) -> &[(Duration, Vec<T>)] { &self.samples }

    /// The values at the last sample, or empty if nothing was observed.
    #[must_use]
    pub fn last(&self) -> &[T] { self.samples.last().map_or(&[], |(_, v)| v.as_slice()) }

    /// Project each node's value through `f`, keeping the sample times.
    ///
    /// One observation pass can therefore answer questions about *different* observables without re-sampling at
    /// different times — necessary because the properties above do not all apply to the same quantity. A roster is a
    /// cell-wide aggregate every node must **agree** on; a role set is per-node and must **not** be expected to match,
    /// yet is exactly where oscillation would show. Sampling them separately would compare different instants.
    #[must_use]
    pub fn map<U>(&self, f: impl Fn(&T) -> U) -> Timeline<U> {
        Timeline::new(self.samples.iter().map(|(t, v)| (*t, v.iter().map(&f).collect())).collect())
    }
}

impl<T: Eq> Timeline<T> {
    /// Total number of per-node value changes across the window.
    #[must_use]
    pub fn transitions(&self) -> usize { self.changes_from(0) }

    /// `true` if **no** node's value ever changed across the whole window.
    ///
    /// Over a window longer than the expected convergence time this is evidence of a *missing trigger*, not of
    /// stability — the shape of the defect this module exists for.
    #[must_use]
    pub fn frozen(&self) -> bool { self.transitions() == 0 }

    /// The elapsed time of the first sample at which every node reports the same value, whether or not it holds.
    #[must_use]
    pub fn first_agreement_at(&self) -> Option<Duration> {
        self.samples.iter().find(|(_, v)| Self::unanimous(v)).map(|(t, _)| *t)
    }

    /// The elapsed time of the first sample at which every node agrees **and keeps agreeing** to the end of the window,
    /// or `None` if the fleet never reached a lasting agreement.
    ///
    /// Requiring persistence is what separates convergence from a coincidence in flight; comparing this against
    /// [`first_agreement_at`](Self::first_agreement_at) tells you whether agreement was reached once or reached, lost,
    /// and reached again.
    #[must_use]
    pub fn stable_agreement_at(&self) -> Option<Duration> {
        let last_split = self.samples.iter().rposition(|(_, v)| !Self::unanimous(v));
        let from = last_split.map_or(0, |i| i.saturating_add(1));
        self.samples.get(from).map(|(t, _)| *t)
    }

    /// Per-node changes occurring at or after elapsed time `at` — the flap counter.
    ///
    /// Zero is the healthy value once the observable has settled. A positive count on a fleet whose membership never
    /// changed means the system is oscillating rather than converging; for role assignment that is churn in the
    /// anonymity set, and no assertion over the final state can see it.
    #[must_use]
    pub fn changes_after(&self, at: Duration) -> usize {
        let from = self.samples.iter().position(|(t, _)| *t >= at).unwrap_or(self.samples.len());
        self.changes_from(from)
    }

    /// The elapsed time of the last sample at which any node's value changed, or `None` if nothing ever moved.
    ///
    /// The honest reference point for "has this settled?" when the observable is *not* expected to become unanimous —
    /// a per-node quantity has no agreement to anchor to, but it still must stop moving.
    #[must_use]
    pub fn last_change_at(&self) -> Option<Duration> {
        self.samples
            .windows(2)
            .rev()
            .find_map(|w| match w {
                [(_, a), (at, b)] if a.iter().zip(b).any(|(x, y)| x != y) => Some(*at),
                _ => None,
            })
    }

    /// Changes among the samples from index `from` onward.
    fn changes_from(&self, from: usize) -> usize {
        self.samples
            .get(from..)
            .unwrap_or_default()
            .windows(2)
            .map(|w| match w {
                [(_, a), (_, b)] => a.iter().zip(b).filter(|(x, y)| x != y).count(),
                _ => 0,
            })
            .sum()
    }

    /// Whether every node reported the same value in this sample. An empty fleet is vacuously unanimous.
    fn unanimous(values: &[T]) -> bool {
        values.split_first().is_none_or(|(head, rest)| rest.iter().all(|v| v == head))
    }
}

impl<T: Debug> Timeline<T> {
    /// The timeline as one line per sample — what a failure message should carry, because the *shape* over time is the
    /// evidence, not any single value.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (at, values) in &self.samples {
            let _ = writeln!(out, "t={:>4}s  {values:?}", at.as_secs());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a timeline at 1-second samples from per-sample value rows.
    fn at_1s<T: Clone>(rows: &[&[T]]) -> Timeline<T> {
        Timeline::new(
            rows.iter().enumerate().map(|(i, r)| (Duration::from_secs(i as u64), r.to_vec())).collect(),
        )
    }

    #[test]
    fn a_frozen_timeline_is_recognised_however_it_disagrees() {
        // The exact measured shape of the defect: three nodes, three views, unchanged for the whole window. Note it is
        // frozen *and* never agreeing — a single final-state check sees a plausible-looking [1, 1, 2] and passes.
        let stuck = at_1s(&[&[1, 1, 2], &[1, 1, 2], &[1, 1, 2]]);
        assert!(stuck.frozen(), "no node ever moved");
        assert_eq!(stuck.transitions(), 0);
        assert_eq!(stuck.stable_agreement_at(), None, "and it never agreed");
    }

    #[test]
    fn convergence_reports_when_agreement_became_lasting() {
        let converging = at_1s(&[&[0, 0, 0], &[1, 2, 3], &[3, 3, 3], &[3, 3, 3]]);
        assert!(!converging.frozen());
        // t=0 is unanimous by coincidence (every node still at its initial value), so the *first* agreement is t=0 —
        // but it does not hold, and the lasting one is t=2. Distinguishing these is the point of having both.
        assert_eq!(converging.first_agreement_at(), Some(Duration::ZERO));
        assert_eq!(converging.stable_agreement_at(), Some(Duration::from_secs(2)));
        assert_eq!(converging.changes_after(Duration::from_secs(2)), 0, "settled");
    }

    #[test]
    fn oscillation_is_distinguished_from_convergence() {
        // Agrees, then flaps apart, then agrees again on a different value. Final state is unanimous, so a final-state
        // assertion passes — yet the system never settled, and `changes_after` is what says so.
        let flapping = at_1s(&[&[1, 1, 1], &[1, 2, 1], &[2, 2, 2], &[2, 1, 2], &[1, 1, 1]]);
        assert_eq!(flapping.first_agreement_at(), Some(Duration::ZERO));
        assert_eq!(flapping.stable_agreement_at(), Some(Duration::from_secs(4)), "only the last sample holds");
        assert!(flapping.changes_after(Duration::ZERO) > 0, "movement after the first agreement is a flap");
        assert!(!flapping.frozen());
    }

    #[test]
    fn projection_keeps_sample_times_so_observables_stay_comparable() {
        let pairs = at_1s(&[&[(1, 'a'), (1, 'b')], &[(2, 'a'), (2, 'a')]]);
        let firsts = pairs.map(|(n, _)| *n);
        let seconds = pairs.map(|(_, c)| *c);
        assert_eq!(firsts.stable_agreement_at(), Some(Duration::ZERO), "the aggregate agrees throughout");
        assert_eq!(seconds.stable_agreement_at(), Some(Duration::from_secs(1)), "the per-node value agrees later");
        assert_eq!(seconds.transitions(), 1);
    }

    #[test]
    fn an_empty_or_single_sample_timeline_answers_without_panicking() {
        let empty = Timeline::<u8>::new(Vec::new());
        assert!(empty.frozen() && empty.last().is_empty());
        assert_eq!(empty.stable_agreement_at(), None);
        assert_eq!(empty.changes_after(Duration::from_secs(9)), 0);
        let one = at_1s(&[&[5, 5]]);
        assert!(one.frozen(), "one sample cannot show movement — a window of one proves nothing");
        assert_eq!(one.stable_agreement_at(), Some(Duration::ZERO));
    }

    #[test]
    fn a_rendered_timeline_carries_the_shape_not_a_value() {
        let t = at_1s(&[&[1, 2], &[2, 2]]);
        assert_eq!(t.render(), "t=   0s  [1, 2]\nt=   1s  [2, 2]\n");
    }
}
