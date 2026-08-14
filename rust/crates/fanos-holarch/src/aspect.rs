//! The fixed alphabet of the model: the seven UHM **aspects** and the three system-wide **flows**.

/// The number of aspects — the fixed septicity of the UHM (`κ_bootstrap = 1/7`).
pub const N: usize = 7;
/// The number of system-wide flows (the T-262 control/data/supply trichotomy).
pub const FLOWS: usize = 3;

/// **The alphabet must match the theory, and the theory is what says how many.**
///
/// Deliberately an assertion and *not* a derivation. Writing `N = variant_count::<Aspect>()` would read
/// the same today and invert the authority: an eighth variant would silently redefine `κ_bootstrap`
/// instead of failing. Two quantities that happen to be equal are still two quantities — the septicity is
/// an input from the UHM corpus, the variant count is a fact about this file, and this is where they are
/// required to agree.
///
/// It also makes `ALL` complete for free: `[Aspect; N]` cannot hold six entries, and `N` cannot drift
/// from the enum, so the list and the alphabet are pinned to each other from both ends.
const _: () = assert!(
    N == core::mem::variant_count::<Aspect>(),
    "the UHM septicity is seven; Aspect has a different number of variants"
);
const _: () = assert!(
    FLOWS == core::mem::variant_count::<Flow>(),
    "T-262 gives three flows; Flow has a different number of variants"
);

/// One of the seven aspects every holon is read through (`core/structure/dimension-*`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Aspect {
    /// **A** — Articulation: how the holon presents and ingests (its ports).
    A,
    /// **S** — Structure: its schema and invariant form.
    S,
    /// **D** — Dynamics: how it changes and forwards over time.
    D,
    /// **L** — Logic: its law — routing, crypto, consensus.
    L,
    /// **E** — intEriority: the hidden internal state (the anonymity / private resource).
    E,
    /// **O** — grOund: the substrate it stands on (transport, stake, compute).
    O,
    /// **U** — Unity: the organ that makes it one thing (topology, canonical head).
    U,
}

impl Aspect {
    /// All seven aspects in canonical order (`A S D L E O U`).
    pub const ALL: [Aspect; N] =
        [Aspect::A, Aspect::S, Aspect::D, Aspect::L, Aspect::E, Aspect::O, Aspect::U];

    /// This aspect's index into a `Γ` row/column (`A=0 … U=6`).
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Aspect::A => 0,
            Aspect::S => 1,
            Aspect::D => 2,
            Aspect::L => 3,
            Aspect::E => 4,
            Aspect::O => 5,
            Aspect::U => 6,
        }
    }

    /// The single-letter glyph (`A`…`U`).
    #[must_use]
    pub const fn glyph(self) -> char {
        match self {
            Aspect::A => 'A',
            Aspect::S => 'S',
            Aspect::D => 'D',
            Aspect::L => 'L',
            Aspect::E => 'E',
            Aspect::O => 'O',
            Aspect::U => 'U',
        }
    }

    /// The canonical English name (`coherences.ts` SSOT).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Aspect::A => "Articulation",
            Aspect::S => "Structure",
            Aspect::D => "Dynamics",
            Aspect::L => "Logic",
            Aspect::E => "Interiority",
            Aspect::O => "Ground",
            Aspect::U => "Unity",
        }
    }
}

/// One of the three system-wide flows a holon runs; an aspect's participation in the flows *derives*
/// its couplings (see [`crate::Gamma::from_modes`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Flow {
    /// Control — the law / decision plane (routing, consensus, orchestration).
    Control,
    /// Data — the payload plane (ingress → forwarding → execution).
    Data,
    /// Supply — the substrate plane (transport, stake, compute, cover budget).
    Supply,
}

impl Flow {
    /// All three flows in canonical order (control, data, supply).
    pub const ALL: [Flow; FLOWS] = [Flow::Control, Flow::Data, Flow::Supply];

    /// This flow's index into a participation triple (`control=0, data=1, supply=2`).
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Flow::Control => 0,
            Flow::Data => 1,
            Flow::Supply => 2,
        }
    }

    /// The flow's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Flow::Control => "control",
            Flow::Data => "data",
            Flow::Supply => "supply",
        }
    }
}
