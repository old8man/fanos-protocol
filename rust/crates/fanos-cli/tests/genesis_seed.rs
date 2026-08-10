//! **Epoch 0 belongs to a network, not to a constant** — a ratchet on the shape that made one security fix
//! break the genesis epoch of every deployment that had a beacon.
//!
//! `BeaconSeed::GENESIS` was the seed every FANOS network drew its epoch-0 coordinates against. That is the
//! defect `docs/design-genesis.md` names: with a compile-time constant, one offline grinding effort buys a
//! chosen placement on **every** network anyone will ever found, and at genesis there is no reshuffle yet, so
//! on the base cell nothing else defends placement at all. The seed is now derived per network,
//! `H("FANOS-v1/genesis-beacon" ‖ commitment)`, from material every participant already holds.
//!
//! The wiring is where this gets dangerous, and it is worth stating exactly why. Deriving the seed moves the
//! node's *seat*. Every task that starts before the first beacon round — the mix-key publisher, the directory
//! feeder a combiner seals through, the capability publisher, the role loop, the POROS ingress host, four CLI
//! verbs — separately named the constant. Each producer on the constant still agrees with each verifier on the
//! constant, so nothing errors; they simply describe a network no node is on. Measured, that was an **empty
//! mix directory for the whole genesis epoch**, caught by one library test rather than by review.
//!
//! So the rule this file enforces is narrow and mechanical: inside `fanos-node`'s sources, the constant may
//! appear **only** as the fallback of the derivation itself. Anywhere else it is a task that has decided what
//! network it is on without asking, which is the defect, whatever the surrounding comment says.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fanos_testkit::corpus::rust_sources;


/// The lines of `text` that are neither documentation nor inside the file's test module.
///
/// The property — "a running node decided its network by naming a constant" — is not expressible in the type
/// system, so this is a text scan; what it must not be is a scan that quietly reads less than the file.
///
/// It used to truncate at the first `#[cfg(test)]`, justified by "test modules sit at the bottom of a file in
/// this workspace". That was untrue in thirteen files and shipping code in three of them (#252). The shared
/// slice keeps the real line numbers, which a truncate-then-enumerate cannot.
fn production_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    fanos_testkit::source::shipping_lines(text)
        .into_iter()
        .map(|(n, l)| (n, l.trim()))
        .filter(|(_, l)| !l.starts_with("//"))
}

/// The one legitimate shape: `…map_or(BeaconSeed::GENESIS, …genesis_seed)` — "derive it, and fall back to the
/// constant only when this deployment has no beacon at all". A deployment with no beacon has no epoch clock
/// and no reshuffle either, so it has no placement defence at any epoch; the constant is the honest answer
/// there and a lie anywhere else.
fn is_the_derivation_fallback(line: &str) -> bool {
    line.contains("map_or(") && line.contains("genesis_seed")
}

#[test]
fn nothing_in_a_running_node_picks_its_network_by_naming_the_constant() {
    // The corpus reports its own coverage — every crate reached, every file actually read (#253). The
    // `files.len() > 20` this used to carry was a number someone picked; the shared walk derives the floor
    // from the workspace layout instead, and a read that fails is fatal rather than skipped.
    let files: Vec<_> =
        rust_sources().into_iter().filter(|s| s.krate == "fanos-node" && s.is_crate_src()).collect();
    assert!(!files.is_empty(), "fanos-node contributed no source — the filter, not the crate, is empty");

    let mut offenders = Vec::new();
    for file in &files {
        for (n, line) in production_lines(&file.text) {
            if line.contains("BeaconSeed::GENESIS") && !is_the_derivation_fallback(line) {
                offenders.push(format!("{}:{n}: {line}", file.rel));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these lines decide what network they are on by naming `BeaconSeed::GENESIS`:\n  {}\n\n\
         Epoch 0 is drawn against the network's genesis seed (`docs/design-genesis.md` §4), which is\n\
         `H(\"FANOS-v1/genesis-beacon\" | commitment)` — not a constant. Read it from where the node already\n\
         knows: `Client::genesis()` inside a spawned task, `NodeConfig::genesis_seed()` or\n\
         `CellComposition::genesis_seed()` from provisioning, `beacon_arg()` in the CLI.\n\n\
         The failure is silent. A publisher on the constant and a reader on the constant agree with each\n\
         other and disagree with the node's own seat, so records verify against nothing and the directory is\n\
         simply empty for the whole genesis epoch.",
        offenders.join("\n  ")
    );
}

/// The derivation itself must stay one function. Two copies of `H(label ‖ commitment)` is two chances for a
/// label to drift, and a drifted label partitions the network into two sets that each think the other is
/// grinding — the exact failure the derivation exists to prevent.
#[test]
fn the_genesis_seed_has_exactly_one_derivation() {
    let label = "FANOS-v1/genesis-beacon";
    let mut sites = Vec::new();
    // Shipping code only: this file names the label too, and a test that counts itself never passes.
    for file in rust_sources().iter().filter(|f| f.is_crate_src()) {
        for (n, line) in production_lines(&file.text) {
            if line.contains(label) && !line.starts_with('*') {
                sites.push(format!("{}:{n}", file.rel));
            }
        }
    }

    assert_eq!(
        sites.len(),
        1,
        "the genesis-seed label must be hashed in exactly one place (found {}): {}. \
         Every other caller reaches it through `fanos_node::node::genesis_seed`.",
        sites.len(),
        sites.join(", ")
    );
}
