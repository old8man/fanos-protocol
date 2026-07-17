//! Points, lines, and the plane `PG(2, q)` as typed objects (spec §2.1–§2.3).

use core::marker::PhantomData;

use fanos_field::Field;

use crate::element::{Triple, canonicalize, dot, is_valid};

/// A point of `PG(2, q)`: a projective coordinate `[x:y:z]` in canonical form.
///
/// A FANOS node's network address is exactly such a point (spec §L0). Every value of this
/// type is canonical (first non-zero coordinate `1`), so `==` and `Hash` are the true
/// projective equality.
///
/// `Clone`/`Copy` are derived (`Field: Copy` guarantees them with no extra bound); the other
/// traits are implemented by hand over `coords` only, so `F` needs no `Eq`/`Hash`/`Debug`.
#[derive(Clone, Copy)]
pub struct Point<F: Field> {
    coords: Triple,
    _field: PhantomData<fn() -> F>,
}

/// A line of `PG(2, q)`: a projective coordinate `[a:b:c]` in canonical form.
///
/// A line is a FANOS **quorum / multicast bus** of `q+1` nodes (spec §L1). By self-duality a
/// line is encoded exactly like a point; the two are distinct Rust types to keep joins and
/// meets from being confused.
#[derive(Clone, Copy)]
pub struct Line<F: Field> {
    coords: Triple,
    _field: PhantomData<fn() -> F>,
}

// --- Manual trait impls: keyed on `coords` only, so no `Eq`/`Hash`/`Debug` bound leaks. ---
macro_rules! impl_projective_traits {
    ($t:ident) => {
        impl<F: Field> PartialEq for $t<F> {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.coords == other.coords
            }
        }
        impl<F: Field> Eq for $t<F> {}
        impl<F: Field> core::hash::Hash for $t<F> {
            #[inline]
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.coords.hash(state);
            }
        }
        impl<F: Field> core::fmt::Debug for $t<F> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let [x, y, z] = self.coords;
                write!(f, "{}[{}:{}:{}]", stringify!($t), x, y, z)
            }
        }
        impl<F: Field> $t<F> {
            #[inline]
            const fn wrap(coords: Triple) -> Self {
                Self {
                    coords,
                    _field: PhantomData,
                }
            }
            /// The canonical coordinate triple.
            #[inline]
            #[must_use]
            pub const fn coords(&self) -> Triple {
                self.coords
            }
        }
    };
}
impl_projective_traits!(Point);
impl_projective_traits!(Line);

impl<F: Field> Point<F> {
    /// Construct a point from raw coordinates, validating and canonicalizing.
    ///
    /// Returns `None` if the triple is the zero vector or has an out-of-range coordinate.
    #[inline]
    #[must_use]
    pub fn new(coords: Triple) -> Option<Self> {
        if !is_valid::<F>(coords) {
            return None;
        }
        canonicalize::<F>(coords).map(Self::wrap)
    }

    /// The point's index in the canonical enumeration `0..N` (spec §L0 addressing).
    ///
    /// The enumeration is: `[1:y:z]` → `y·q + z`, then `[0:1:z]` → `q² + z`, then
    /// `[0:0:1]` → `q² + q`. This is a bijection with `0..q²+q+1`.
    #[inline]
    #[must_use]
    pub fn index(&self) -> usize {
        let q = F::Q as usize;
        match self.coords {
            [1, y, z] => (y as usize) * q + z as usize,
            [0, 1, z] => q * q + z as usize,
            _ => q * q + q, // [0:0:1]
        }
    }

    /// The point at a given canonical index (inverse of [`Point::index`]).
    ///
    /// # Panics
    /// If `i >= N` (`i` is not a valid point index for this plane).
    #[inline]
    #[must_use]
    pub fn at(i: usize) -> Self {
        let q = F::Q as usize;
        let n = q * q + q + 1;
        assert!(i < n, "point index {i} out of range for PG(2,{})", F::Q);
        if i < q * q {
            Self::wrap([1, (i / q) as u32, (i % q) as u32])
        } else if i < q * q + q {
            Self::wrap([0, 1, (i - q * q) as u32])
        } else {
            Self::wrap([0, 0, 1])
        }
    }

    /// The unique line through `self` and `other` — the O(1) rendezvous `u × v` (spec §L1).
    ///
    /// Returns `None` iff the two points are equal (there is no unique line then). For
    /// distinct points this is the **Steiner property**: any two points lie on exactly one
    /// common line.
    #[inline]
    #[must_use]
    pub fn join(&self, other: &Self) -> Option<Line<F>> {
        canonicalize::<F>(crate::element::cross::<F>(self.coords, other.coords)).map(Line::wrap)
    }

    /// Whether this point lies on `line` (spec §2.1, incidence `p · L = 0`).
    #[inline]
    #[must_use]
    pub fn is_on(&self, line: &Line<F>) -> bool {
        dot::<F>(self.coords, line.coords) == 0
    }
}

impl<F: Field> Line<F> {
    /// Construct a line from raw coordinates, validating and canonicalizing.
    #[inline]
    #[must_use]
    pub fn new(coords: Triple) -> Option<Self> {
        if !is_valid::<F>(coords) {
            return None;
        }
        canonicalize::<F>(coords).map(Self::wrap)
    }

    /// The line's index in the canonical enumeration `0..N` (dual to [`Point::index`]).
    #[inline]
    #[must_use]
    pub fn index(&self) -> usize {
        let q = F::Q as usize;
        match self.coords {
            [1, y, z] => (y as usize) * q + z as usize,
            [0, 1, z] => q * q + z as usize,
            _ => q * q + q,
        }
    }

    /// The line at a given canonical index (inverse of [`Line::index`]).
    ///
    /// # Panics
    /// If `i >= N`.
    #[inline]
    #[must_use]
    pub fn at(i: usize) -> Self {
        let q = F::Q as usize;
        let n = q * q + q + 1;
        assert!(i < n, "line index {i} out of range for PG(2,{})", F::Q);
        if i < q * q {
            Self::wrap([1, (i / q) as u32, (i % q) as u32])
        } else if i < q * q + q {
            Self::wrap([0, 1, (i - q * q) as u32])
        } else {
            Self::wrap([0, 0, 1])
        }
    }

    /// The unique intersection point of `self` and `other` — the O(1) **bridge** node
    /// between two quorums (spec §L1). Returns `None` iff the lines are equal.
    ///
    /// For distinct lines this is the **dual Steiner property** (Maekawa): any two lines
    /// meet in exactly one point, so any two quorums intersect.
    #[inline]
    #[must_use]
    pub fn meet(&self, other: &Self) -> Option<Point<F>> {
        canonicalize::<F>(crate::element::cross::<F>(self.coords, other.coords)).map(Point::wrap)
    }

    /// Whether `point` lies on this line.
    #[inline]
    #[must_use]
    pub fn contains(&self, point: &Point<F>) -> bool {
        dot::<F>(self.coords, point.coords) == 0
    }
}

/// The projective plane `PG(2, q)` — a FANOS **cell** (spec §3.1), the unit of locality.
///
/// This is a zero-sized namespace carrying the plane's compile-time constants and the
/// enumeration/incidence iterators. Everything is generic over the field `F`, so the same
/// code serves the base Fano cell `PG(2, 2)` and the large prime cells alike.
pub struct Plane<F: Field>(PhantomData<fn() -> F>);

impl<F: Field> Plane<F> {
    /// The field order `q`.
    pub const Q: u32 = F::Q;
    /// The number of points, which equals the number of lines: `N = q² + q + 1`.
    pub const N: u32 = F::Q * F::Q + F::Q + 1;
    /// Points per line, and lines per point: `q + 1` (spec §2.1).
    pub const LINE_SIZE: u32 = F::Q + 1;

    /// Iterate every point of the plane in canonical-index order.
    #[inline]
    pub fn points() -> impl Iterator<Item = Point<F>> + Clone {
        (0..Self::N as usize).map(Point::at)
    }

    /// Iterate every line of the plane in canonical-index order.
    #[inline]
    pub fn lines() -> impl Iterator<Item = Line<F>> + Clone {
        (0..Self::N as usize).map(Line::at)
    }

    /// Iterate the `q + 1` points incident to `line`.
    #[inline]
    pub fn points_on(line: Line<F>) -> impl Iterator<Item = Point<F>> + Clone {
        Self::points().filter(move |p| p.is_on(&line))
    }

    /// Iterate the `q + 1` lines through `point`.
    ///
    /// Uses self-duality: the lines through `[a:b:c]` are exactly the points on the line
    /// with coordinates `[a:b:c]`, reinterpreted as lines.
    #[inline]
    pub fn lines_through(point: Point<F>) -> impl Iterator<Item = Line<F>> + Clone {
        let dual = Line::wrap(point.coords());
        Self::points_on(dual).map(|p| Line::wrap(p.coords()))
    }
}

/// The order of the collineation group `PGL(3, q)` (spec §2.3): the count of symmetries of
/// the plane. `|PGL(3,q)| = (q³−1)(q³−q)(q³−q²)/(q−1)`. For `q = 2` this is `168`.
#[must_use]
pub fn pgl3_order(q: u32) -> u128 {
    let q = u128::from(q);
    let q3 = q * q * q;
    (q3 - 1) * (q3 - q) * (q3 - q * q) / (q - 1)
}
