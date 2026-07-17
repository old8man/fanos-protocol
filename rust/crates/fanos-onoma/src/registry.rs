//! **Purchasable / issued global names** — the optional L-global layer, plus a concrete
//! in-memory namespace for the local (L-pet) and testing cases.
//!
//! A [`Registration`] is a signed claim binding a top-level readable label (`alice`) to a
//! [`Target`] (usually a delegation to the owner's zone, which then controls every subdomain
//! `*.alice.fanos`). *Who arbitrates global uniqueness* is a policy of the [`Registry`] backend:
//!
//! * [`LocalRegistry`] — a self-hosted / imported namespace with no global consensus (L-pet, and
//!   the substrate for tests). Available now.
//! * A coherent-chain backend (L-global, Phase 6) — first-come/commit-reveal issuance settled on
//!   the FANOS blockchain — implements the same [`Registry`] trait, so resolution code is identical
//!   regardless of how a name was issued. Interface only, today.
//!
//! Keeping issuance behind a trait is the justified seam: the *resolution* machinery (readable
//! names + subdomains) works today; the *settlement* backend can evolve without touching it.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::OnomaError;
use crate::name::is_valid_label;
use crate::zone::{Target, Zone, ZoneKey, ZoneSource};

/// A signed claim binding a top-level label to a target (the issuance/purchase record).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Registration {
    /// The claimed top-level label (LDH), e.g. `alice`.
    pub label: String,
    /// What it resolves to (usually [`Target::Delegate`] to the owner's zone).
    pub target: Target,
    /// The owner public key that signs (and may later renew/transfer) the claim.
    pub owner: ZoneKey,
    /// The epoch the claim is valid from (renewal/expiry policy lives in the backend).
    pub epoch: u64,
    /// The owner's signature over [`Registration::signing_bytes`].
    pub sig: Vec<u8>,
}

impl Registration {
    /// The canonical bytes an owner signs to claim a name.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"FANOS-v1/onoma-reg");
        b.push(0x1f);
        b.push(self.label.len() as u8);
        b.extend_from_slice(self.label.as_bytes());
        b.extend_from_slice(&self.owner);
        b.extend_from_slice(&self.epoch.to_le_bytes());
        let mut t = Vec::new();
        target_canonical(&self.target, &mut t);
        b.extend_from_slice(&t);
        b
    }

    /// Verify the claim signature with a scheme-agnostic verifier `verify(owner, message, sig)`.
    #[must_use]
    pub fn verify<V>(&self, verify: V) -> bool
    where
        V: Fn(&ZoneKey, &[u8], &[u8]) -> bool,
    {
        verify(&self.owner, &self.signing_bytes(), &self.sig)
    }
}

fn target_canonical(target: &Target, out: &mut Vec<u8>) {
    match target {
        Target::Address(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.payload());
        }
        Target::Delegate(k) => {
            out.push(0x02);
            out.extend_from_slice(k);
        }
    }
}

/// The namespace root: resolves top-level readable labels to targets. Backends differ only in how a
/// registration is *authorized* (local trust vs. chain consensus).
pub trait Registry {
    /// Resolve a top-level readable label to its target, if registered.
    fn lookup(&self, label: &str) -> Option<Target>;
}

/// An in-memory namespace root with no global consensus (L-pet / self-hosted / tests).
#[derive(Clone, Default, Debug)]
pub struct LocalRegistry {
    entries: BTreeMap<String, Target>,
}

impl LocalRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or overwrite) a top-level label locally.
    ///
    /// # Errors
    /// [`OnomaError::BadLabel`] if the label is not a valid LDH label.
    pub fn insert(&mut self, label: &str, target: Target) -> Result<(), OnomaError> {
        if !is_valid_label(label) {
            return Err(OnomaError::BadLabel);
        }
        self.entries.insert(label.to_string(), target);
        Ok(())
    }

    /// Apply a *verified* registration (call [`Registration::verify`] first).
    ///
    /// # Errors
    /// [`OnomaError::BadLabel`] if the label is invalid.
    pub fn apply(&mut self, reg: &Registration) -> Result<(), OnomaError> {
        self.insert(&reg.label, reg.target)
    }
}

impl Registry for LocalRegistry {
    fn lookup(&self, label: &str) -> Option<Target> {
        self.entries.get(label).copied()
    }
}

/// A complete in-memory namespace: a [`Registry`] root plus a store of delegated zones. Implements
/// [`ZoneSource`], so `zone::resolve` works end-to-end (readable names + subdomains) with no I/O —
/// used by the resolver's local cache and by the test/simulation harness.
#[derive(Clone, Default, Debug)]
pub struct MemoryNamespace {
    /// The top-level registry root.
    pub registry: LocalRegistry,
    zones: BTreeMap<ZoneKey, Zone>,
}

impl MemoryNamespace {
    /// An empty namespace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a delegated zone (index by its key).
    pub fn add_zone(&mut self, zone: Zone) {
        self.zones.insert(zone.key, zone);
    }
}

impl ZoneSource for MemoryNamespace {
    fn root(&self, label: &str) -> Option<Target> {
        self.registry.lookup(label)
    }

    fn zone(&self, key: &ZoneKey) -> Option<Zone> {
        self.zones.get(key).cloned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::name::Name;
    use crate::zone::{Record, resolve};
    use alloc::vec;

    fn ns_with_subdomains() -> (MemoryNamespace, Address, Address) {
        let apex_addr = Address::from_bundle(b"alice-apex");
        let blog_addr = Address::from_bundle(b"alice-blog");
        let alice_key = [0xAAu8; 32];

        let alice_zone = Zone::new(
            alice_key,
            1,
            vec![
                Record {
                    label: "@".to_string(),
                    target: Target::Address(apex_addr),
                },
                Record {
                    label: "blog".to_string(),
                    target: Target::Address(blog_addr),
                },
            ],
        );

        let mut ns = MemoryNamespace::new();
        ns.registry
            .insert("alice", Target::Delegate(alice_key))
            .unwrap();
        ns.add_zone(alice_zone);
        (ns, apex_addr, blog_addr)
    }

    #[test]
    fn resolves_apex_and_subdomain() {
        let (ns, apex, blog) = ns_with_subdomains();
        let apex_name = Name::parse("alice.fanos").unwrap();
        let sub_name = Name::parse("blog.alice.fanos").unwrap();
        assert_eq!(resolve(&apex_name, "fanos", &ns).unwrap(), apex);
        assert_eq!(resolve(&sub_name, "fanos", &ns).unwrap(), blog);
    }

    #[test]
    fn unknown_names_are_not_found() {
        let (ns, _, _) = ns_with_subdomains();
        let missing = Name::parse("nope.alice.fanos").unwrap();
        assert_eq!(resolve(&missing, "fanos", &ns), Err(OnomaError::NotFound));
        let missing_root = Name::parse("bob.fanos").unwrap();
        assert_eq!(
            resolve(&missing_root, "fanos", &ns),
            Err(OnomaError::NotFound)
        );
    }

    #[test]
    fn self_certifying_name_bypasses_the_registry() {
        let (ns, _, _) = ns_with_subdomains();
        let direct = Address::from_bundle(b"direct-service");
        let name = Name::parse(&direct.to_name()).unwrap();
        assert_eq!(resolve(&name, "fanos", &ns).unwrap(), direct);
    }

    #[test]
    fn registration_signing_is_bound_and_verifiable() {
        let reg = Registration {
            label: "alice".to_string(),
            target: Target::Delegate([7u8; 32]),
            owner: [7u8; 32],
            epoch: 3,
            sig: vec![0xEE; 4],
        };
        // Scheme-agnostic verify: the closure receives the bound message.
        let expected = reg.signing_bytes();
        let ok = reg.verify(|owner, msg, sig| {
            owner == &[7u8; 32] && sig == [0xEE; 4] && msg == expected.as_slice()
        });
        assert!(ok);
    }
}
