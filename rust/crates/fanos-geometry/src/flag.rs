//! Flags — incident point–line pairs — the atoms of a NYX path (spec §5.3).

use fanos_field::Field;

use crate::plane::{Line, Point};

/// An incident point–line pair `(p ∈ L)`.
///
/// A NYX anonymous path is a **geometric flag chain** `p₀ ∈ L₁ ∋ p₁ ∈ L₂ ∋ …` (spec §5.3):
/// adjacent lines always meet (dual Steiner), and the meet is the relaying node. Because
/// `PGL(3,q)` acts transitively on flags, a path built from flags is provably uniform — the
/// property NYX relies on for unbiased path selection.
#[derive(Clone, Copy)]
pub struct Flag<F: Field> {
    point: Point<F>,
    line: Line<F>,
}

impl<F: Field> PartialEq for Flag<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point && self.line == other.line
    }
}
impl<F: Field> Eq for Flag<F> {}
impl<F: Field> core::fmt::Debug for Flag<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Flag({:?} ∈ {:?})", self.point, self.line)
    }
}

impl<F: Field> Flag<F> {
    /// Build a flag, checking incidence. Returns `None` if `point` is not on `line`.
    #[inline]
    #[must_use]
    pub fn new(point: Point<F>, line: Line<F>) -> Option<Self> {
        point.is_on(&line).then_some(Self { point, line })
    }

    /// The incident point.
    #[inline]
    #[must_use]
    pub fn point(&self) -> Point<F> {
        self.point
    }

    /// The incident line.
    #[inline]
    #[must_use]
    pub fn line(&self) -> Line<F> {
        self.line
    }
}
