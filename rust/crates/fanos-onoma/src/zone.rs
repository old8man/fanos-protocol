//! **Zones, records, delegation, and subdomain resolution** — the L-pet human layer.
//!
//! A [`Zone`] is a *signed* set of [`Record`]s mapping a label to a [`Target`] (either a terminal
//! self-certifying [`Address`] or a delegation to another zone). This is the GNS/DNS insight: a
//! readable name like `blog.alice.fanos` resolves by starting at a namespace root, delegating
//! `alice` to Alice's zone, then looking up `blog` — needing **no global consensus** because names
//! are relative to a trust root you choose. Subdomains fall out for free: every dotted label is one
//! resolution hop. Zone signatures are verified through a caller-supplied closure, so ONOMA is
//! **signature-agnostic** (matching CALYPSO-Balance), and the real hybrid PQ signatures live above.

use alloc::string::String;
use alloc::vec::Vec;

use fanos_primitives::Epoch;

use crate::address::Address;
use crate::error::OnomaError;
use crate::name::Name;

/// The apex label — a zone's own address (like a DNS apex `@` record).
pub const APEX: &str = "@";

/// Maximum delegation hops when resolving a name (loop / abuse guard).
pub const MAX_DELEGATION_DEPTH: usize = 16;

/// A 32-byte zone public key (the owner identity a zone is signed by).
pub type ZoneKey = [u8; 32];

/// What a record points to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    /// A terminal self-certifying address.
    Address(Address),
    /// A delegation to another zone (its public key) — enables subdomains.
    Delegate(ZoneKey),
}

impl Target {
    fn extend_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Address(a) => {
                out.push(0x01);
                out.extend_from_slice(&a.payload());
            }
            Self::Delegate(k) => {
                out.push(0x02);
                out.extend_from_slice(k);
            }
        }
    }
}

/// One `label → target` mapping inside a zone.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// The label (LDH, or [`APEX`] for the zone's own address).
    pub label: String,
    /// The target it resolves to.
    pub target: Target,
}

/// A signed zone: an owner key, an epoch (for rotation/freshness), records, and a signature over
/// the canonical [`Zone::signing_bytes`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Zone {
    /// The zone's owner public key (also the delegation target that points here).
    pub key: ZoneKey,
    /// The epoch this zone revision was signed at (monotone; newer supersedes older).
    pub epoch: Epoch,
    /// The records.
    pub records: Vec<Record>,
    /// The owner's signature over [`Zone::signing_bytes`] (scheme-agnostic bytes).
    pub sig: Vec<u8>,
}

impl Zone {
    /// A new unsigned zone (fill [`Zone::sig`] via the owner's signer).
    #[must_use]
    pub fn new(key: ZoneKey, epoch: Epoch, records: Vec<Record>) -> Self {
        Self {
            key,
            epoch,
            records,
            sig: Vec::new(),
        }
    }

    /// Look up a label within this zone (linear; zones are small).
    #[must_use]
    pub fn get(&self, label: &str) -> Option<&Target> {
        self.records
            .iter()
            .find(|r| r.label == label)
            .map(|r| &r.target)
    }

    /// The canonical bytes an owner signs: domain-tag ‖ key ‖ epoch ‖ records.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"FANOS-v1/onoma-zone");
        b.push(0x1f);
        b.extend_from_slice(&self.key);
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for r in &self.records {
            b.push(r.label.len() as u8);
            b.extend_from_slice(r.label.as_bytes());
            r.target.extend_canonical(&mut b);
        }
        b
    }

    /// Verify the zone signature with a scheme-agnostic verifier `verify(key, message, sig)`.
    #[must_use]
    pub fn verify<V>(&self, verify: V) -> bool
    where
        V: Fn(&ZoneKey, &[u8], &[u8]) -> bool,
    {
        verify(&self.key, &self.signing_bytes(), &self.sig)
    }
}

/// A source of resolution data: the namespace root (top-level readable names) and delegated zones.
///
/// Implementations are expected to have **already verified** signatures/registrations when they
/// return data, so [`resolve`] stays a pure walk (crypto lives at the source boundary, as in
/// CALYPSO-Balance).
pub trait ZoneSource {
    /// Resolve a top-level readable label in the namespace root (the registry).
    fn root(&self, label: &str) -> Option<Target>;
    /// Fetch a delegated zone by its key.
    fn zone(&self, key: &ZoneKey) -> Option<Zone>;
}

/// Resolve a [`Name`] under `tld` to a self-certifying [`Address`].
///
/// Dispatch: a self-certifying `<label>.tld` is decoded directly; otherwise the readable labels are
/// walked through the namespace root and delegated zones (subdomains), following an apex `@` record
/// when a name terminates on a zone.
///
/// # Errors
/// [`OnomaError`] on a wrong TLD, a missing record, or a too-deep delegation chain.
pub fn resolve(name: &Name, tld: &str, src: &dyn ZoneSource) -> Result<Address, OnomaError> {
    // 1. Self-certifying names decode without any lookup.
    if let Ok(addr) = Address::parse_in_tld(&name.to_dotted(), tld) {
        return Ok(addr);
    }
    // 2. Readable names walk the namespace.
    let labels = name.labels_under(tld).ok_or(OnomaError::WrongTld)?;
    let mut iter = labels.iter().rev();
    let top = iter.next().ok_or(OnomaError::NotFound)?;
    let mut target = src.root(top).ok_or(OnomaError::NotFound)?;

    for (depth, lbl) in iter.enumerate() {
        if depth >= MAX_DELEGATION_DEPTH {
            return Err(OnomaError::TooDeep);
        }
        let key = match target {
            Target::Delegate(k) => k,
            Target::Address(_) => return Err(OnomaError::NotFound), // can't descend under a terminal
        };
        let zone = src.zone(&key).ok_or(OnomaError::NotFound)?;
        target = *zone.get(lbl).ok_or(OnomaError::NotFound)?;
    }

    match target {
        Target::Address(a) => Ok(a),
        // A name ending on a zone resolves to that zone's apex address, if present.
        Target::Delegate(key) => {
            let zone = src.zone(&key).ok_or(OnomaError::NotFound)?;
            match zone.get(APEX) {
                Some(Target::Address(a)) => Ok(*a),
                _ => Err(OnomaError::NotFound),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn signing_bytes_bind_records() {
        let a = Address::from_bundle(b"svc");
        let z1 = Zone::new(
            [1u8; 32],
            Epoch::new(1),
            alloc::vec![Record {
                label: "a".to_string(),
                target: Target::Address(a)
            }],
        );
        let z2 = Zone::new(
            [1u8; 32],
            Epoch::new(1),
            alloc::vec![Record {
                label: "b".to_string(),
                target: Target::Address(a)
            }],
        );
        assert_ne!(z1.signing_bytes(), z2.signing_bytes());
    }

    #[test]
    fn verify_uses_the_closure() {
        let z = Zone::new([9u8; 32], Epoch::ZERO, Vec::new());
        assert!(z.verify(|_, _, _| true));
        assert!(!z.verify(|_, _, _| false));
    }
}
