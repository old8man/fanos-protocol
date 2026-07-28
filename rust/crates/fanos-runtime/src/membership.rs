//! The overlay's **membership view and admission policy**, split out of `overlay.rs` (task 7a).
//!
//! `Membership` is the cell's key distribution — coordinate → announced info, learned by flooding JOIN announcements —
//! plus the Sybil-admission policy that gates entry to it. Onion routing reads this map; `on_announce` writes it.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_geometry::Triple;

use fanos_core::AdmissionPolicy;
/// The membership concern factored out of [`OverlayNode`] (audit #125 decompose): this node's own
/// long-term **credentials** for joining a cell — its identity bundle, signed descriptor, and Sybil
/// admission proof — plus the [`AdmissionPolicy`] it checks *others* against, and the learned **key view**
/// of who else is in the cell. The facade orchestrates the JOIN/Announce frame flow (flood, self-cert,
/// re-flood); this owns the credential/view state and the invariant that must not be got wrong — the
/// fail-closed admission check ([`admits`](Membership::admits)).
#[derive(Default)]
pub(crate) struct Membership {
    /// This node's long-term identity bytes (spec §L0): its hybrid **signature public-key bundle**
    /// `Ed25519(32) ‖ ML-DSA-65(1952)`, which both derives its self-certifying address (`MapToPoint`) and
    /// verifies its descriptor signature. Carried in this node's `Announce`. Empty when self-certification
    /// is not in use (the address is trusted without proof).
    pub(crate) identity: Vec<u8>,
    /// The signature over this node's descriptor `coord ‖ hier ‖ id`, produced once by its hybrid signing
    /// key at deployment (the secret never enters the engine). Carried in the `Announce` and checked by
    /// peers under self-certified membership, so an attacker cannot announce a *different* transport
    /// coordinate for an identity's address without that identity's private key (§79/§80, the
    /// transport-hijack defence). Empty when unsigned.
    pub(crate) descriptor_sig: Vec<u8>,
    /// This node's own Sybil-admission proof (spec §L3), attached to its `Announce` when it joins. Empty
    /// when admission is not in use for this deployment — a peer that requires admission then rejects it
    /// (fail closed), exactly as an empty `identity`/`descriptor_sig` is rejected under
    /// `require_self_certified_membership`.
    pub(crate) admission_proof: Vec<u8>,
    /// This node's Sybil admission policy (spec §L3): checked against a peer's announced proof when
    /// `config.require_admission` is set. `None` even with the flag set means this node enforces the check
    /// but has no policy to check *against* — it then rejects every peer (fail closed, never fail open)
    /// rather than silently admitting for want of configuration.
    pub(crate) admission_policy: Option<Box<dyn AdmissionPolicy>>,
    /// The PoW difficulty this node solves its OWN admission proof at (spec §L3). `Some(d)` when the node
    /// runs PoW admission via [`OverlayNode::with_admission_pow`]: its proof is then **re-solved for the
    /// new `(coordinate, epoch)` on every reshuffle** ([`on_reseat`](OverlayNode::on_reseat)), so a peer's
    /// per-epoch admission check keeps passing as the coordinate rotates — the "re-paid every epoch" cost
    /// that makes a grinded seat un-maintainable (`anti_eclipse_reshuffle`). `None` = the proof is fixed
    /// (set once via [`with_admission_proof`](OverlayNode::with_admission_proof)) or absent.
    pub(crate) paid_difficulty: Option<u32>,
    /// The membership view: cell coordinate → announced info (public keys, capabilities), learned by
    /// flooding JOIN announcements (spec §7.8). This is the key distribution onion routing reads.
    pub(crate) members: BTreeMap<Triple, Vec<u8>>,
}

impl Membership {
    /// Whether an announced `proof` admits a joiner under this node's installed policy (spec §L3, §7.8).
    /// **Fails closed**: with no policy installed this returns `false`, so a node that *requires* admission
    /// but was handed no policy rejects every peer rather than silently admitting for want of
    /// configuration. The caller gates this on `config.require_admission`.
    /// The difficulty the installed policy currently demands, when it can say.
    ///
    /// `None` for a policy with no notion of a price (a stake or web-of-trust profile, or no policy at all) —
    /// which a rejection then carries as "no guidance" rather than as zero, since retrying at zero against a
    /// gate that wants work is an infinite loop.
    pub(crate) fn required_difficulty(&self) -> Option<u32> {
        self.admission_policy.as_ref().and_then(|p| p.required_difficulty())
    }

    pub(crate) fn admits(&self, challenge: &[u8], proof: &[u8]) -> bool {
        self.admission_policy
            .as_deref()
            .is_some_and(|policy| policy.admits(challenge, proof))
    }
}
