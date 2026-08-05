//! **The founding ceremony's engine wrapper** — how a real DKG run hands its result to the process that
//! must write a provisioning file, without the share ever travelling on a channel.
//!
//! [`fanos_keygen::DkgNode`] is a sans-I/O `Engine` and `fanos-quic` will run any `Engine` on the shipped
//! mutual-TLS transport (`tests/dkg_quic.rs` proves seven of them agree over real QUIC). What it does not
//! give back is the *output*: the driver owns the engine, so `final_share()` and `aggregate_commitment()`
//! are unreachable once it is spawned, and the only thing that comes out is
//! [`Notification::DkgComplete`], which carries the joint **public** key alone.
//!
//! **Widening that notification would be the wrong fix, and it is worth saying why rather than just not
//! doing it.** A node's notification stream is a `broadcast` every subscriber receives — the CLI, the
//! observatory, any task that called `subscribe()`. Putting a beacon share on it would hand this node's
//! secret to every present and future reader of a stream designed for telemetry, which is the same shape as
//! a store read cloned to twenty-one subscribers that all discard it, except that here the payload is the
//! key material the whole DKG exists to keep un-held.
//!
//! So the result goes into a cell the ceremony already owns, written by the engine at the one moment it
//! becomes true. The secret stays in this process's memory and reaches exactly one reader.

use std::sync::{Arc, Mutex, PoisonError};

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_keygen::DkgNode;
use fanos_runtime::{Effect, Engine, Input, Instant, Notification};
use fanos_vrf::vss::{VssCommitment, VssShare};

/// What a completed ceremony hands back — exactly the three things a beacon provisioning file needs, and
/// nothing else.
#[derive(Clone)]
pub struct CeremonyOutcome {
    /// The joint group commitment every participant agreed on — `BeaconParams::commitment`.
    pub commitment: VssCommitment,
    /// **This participant's** final share — `BeaconParams::share`. A secret; it is why this type is not
    /// `Debug`.
    pub share: VssShare,
    /// The joint public key, as announced. Carried so a caller can cross-check that the commitment it is
    /// about to write is the one the cell agreed on rather than one it merely computed.
    pub joint_key: [u8; 32],
}

/// The cell a ceremony's result is delivered into: `None` until the DKG completes here.
pub type OutcomeSlot = Arc<Mutex<Option<CeremonyOutcome>>>;

/// A [`DkgNode`] that captures its own outcome on completion.
///
/// Delegates every step; the only thing it adds is noticing the completion the engine already announces and
/// reading the two values off the engine *at that moment* — the engine is the only holder, and after the
/// driver takes ownership nothing else can ask it.
pub struct DkgCeremony<F: Field> {
    inner: DkgNode<F>,
    outcome: OutcomeSlot,
}

impl<F: Field> DkgCeremony<F> {
    /// Wrap `node`, delivering its outcome into `outcome` when it completes.
    #[must_use]
    pub fn new(node: DkgNode<F>, outcome: OutcomeSlot) -> Self {
        Self { inner: node, outcome }
    }

    /// A fresh, empty outcome slot.
    #[must_use]
    pub fn slot() -> OutcomeSlot {
        Arc::new(Mutex::new(None))
    }
}

impl<F: Field> Engine for DkgCeremony<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.inner.step(now, input);
        // Read the outcome at the step that announces it. Recorded once: a DKG completes once, and a later
        // overwrite could only come from a second ceremony this engine is not part of.
        let announced = effects.iter().find_map(|e| match e {
            Effect::Notify(Notification::DkgComplete(y)) => Some(*y),
            _ => None,
        });
        if let Some(joint_key) = announced
            && let Some(commitment) = self.inner.aggregate_commitment()
        {
            let mut slot = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
            if slot.is_none() {
                *slot = Some(CeremonyOutcome {
                    commitment,
                    share: self.inner.final_share(),
                    joint_key,
                });
            }
        }
        effects
    }

    fn address(&self) -> Triple {
        self.inner.address()
    }
}
