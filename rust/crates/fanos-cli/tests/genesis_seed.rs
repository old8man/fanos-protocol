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

use std::path::{Path, PathBuf};

fn rust_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Every `.rs` file under a directory, recursively.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The lines of `text` that are neither documentation nor inside the file's test module.
///
/// Crude on purpose. The property — "a running node decided its network by naming a constant" — is not
/// expressible in the type system, and a scan that a reader can verify by eye is worth more here than a
/// precise one they must trust. Test modules sit at the bottom of a file in this workspace, so truncating at
/// the first `#[cfg(test)]` is exact for the layout that actually exists.
fn production_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .take_while(|l| !l.trim_start().starts_with("#[cfg(test)]"))
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
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
    let root = rust_root().join("crates/fanos-node/src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() > 20, "the source scan found {} files — it is looking in the wrong place", files.len());

    let mut offenders = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        for (n, line) in production_lines(&text) {
            if line.contains("BeaconSeed::GENESIS") && !is_the_derivation_fallback(line) {
                let rel = file.strip_prefix(rust_root()).unwrap_or(file);
                offenders.push(format!("{}:{n}: {line}", rel.display()));
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
    let root = rust_root().join("crates");
    let mut files = Vec::new();
    sources(&root, &mut files);

    let label = "FANOS-v1/genesis-beacon";
    let mut sites = Vec::new();
    // Shipping code only: this file names the label too, and a test that counts itself never passes.
    for file in files.iter().filter(|f| f.components().any(|c| c.as_os_str() == "src")) {
        let text = std::fs::read_to_string(file).unwrap();
        for (n, line) in production_lines(&text) {
            if line.contains(label) && !line.starts_with('*') {
                let rel = file.strip_prefix(rust_root()).unwrap_or(file);
                sites.push(format!("{}:{n}", rel.display()));
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
