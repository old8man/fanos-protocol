//! **Reachability as a checked number.** Which workspace crates are actually linked into something the
//! project ships — and which are libraries that nothing wires up.
//!
//! This exists because the prose form of the claim rotted twice inside one audit. It was written as "34 of
//! 43 crates are reachable from the shipped node", with `fanos-holarch` and `fanos-observatory` listed as
//! "not in the binary at all" — both own or are linked by shipped binaries — and with six crates listed as
//! "never exercised over any transport", of which three (`fanos-session`, `fanos-stream`,
//! `fanos-threshold`) are reached through `fanos-diaulos` / `fanos-aphantos` by the real-QUIC suites. Every
//! one of those errors came from grepping for a crate's *name* where it is used through an intermediary.
//! A closure computed over the manifests cannot make that mistake, and a test cannot go stale quietly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Crates that are deliberately linked by nothing in this workspace, each with the reason it is exempt.
///
/// Two classes live here, and the distinction is the point of the list. **Embedding surfaces** exist to be
/// linked by code *outside* this repository, so having no internal consumer is correct. **Orphans** are the
/// real "library ahead of its wiring": built, tested in isolation, and reachable from nothing the project
/// ships — the platform makes a claim in prose that no deployed path exercises.
/// Crates that are **legitimately** linked by nothing this project ships.
///
/// An embedding surface exists to be called from outside — a C header, a wasm entry point, a benchmark harness.
/// Nothing of ours linking it is the expected shape, not a defect, and this list is stable by design.
const EMBEDDING_SURFACE: &[(&str, &str)] = &[
    ("fanos-bench", "the benchmark harness, run by `cargo bench`, linked by nothing"),
    ("fanos-ffi", "the C ABI, for foreign callers rather than our own binaries"),
    ("fanos-wasm", "the wasm entry points, same reason as the C ABI"),
];

/// Crates that are **orphans** — real capability nobody can reach. A defect list, and a ratchet.
///
/// Kept separate from [`EMBEDDING_SURFACE`] because the two mean opposite things and one list conflated them.
/// An embedding surface is finished; an orphan is a product with no door. `fanos-angelos` is a complete
/// messenger — sessions, double ratchet, groups, media, call signalling, a bot SDK — and no shipped binary can
/// reach a line of it.
///
/// The list may **shrink and never grow** (asserted below). Deleting the crate is the other admissible way to
/// shrink it; for these two it is the wrong one, because the work is real and what is missing is a driver and a
/// verb, not the capability.
const ORPHANS: &[(&str, &str)] = &[
    ("fanos-ergon", "the effect-algebra execution model: DROMOS executes without it (plan I.1)"),
];

/// Every crate that is allowed to be unlinked, for either reason.
fn unlinked() -> Vec<(&'static str, &'static str)> {
    EMBEDDING_SURFACE.iter().chain(ORPHANS).copied().collect()
}

/// Parse one manifest's *normal* workspace dependencies (dev- and build-dependencies are not shipping
/// edges, and counting them would make every crate look wired by its own test harness).
fn normal_deps(manifest: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(manifest).unwrap();
    let mut deps = BTreeSet::new();
    let mut shipping = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // `[dependencies]` and `[target.'cfg(..)'.dependencies]` ship; dev/build do not.
            shipping = section.ends_with("dependencies")
                && !section.contains("dev-dependencies")
                && !section.contains("build-dependencies");
            continue;
        }
        if !shipping || !line.starts_with("fanos-") {
            continue;
        }
        let name = line.split(['.', ' ', '=']).next().unwrap_or_default();
        if !name.is_empty() {
            deps.insert(name.to_owned());
        }
    }
    deps
}

/// Every crate in `crates/`, with its shipping dependencies and whether it owns a binary.
fn workspace() -> (BTreeMap<String, BTreeSet<String>>, BTreeSet<String>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let mut deps = BTreeMap::new();
    let mut binaries = BTreeSet::new();
    for entry in std::fs::read_dir(root.join("crates")).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        // A crate ships a binary if it has `src/main.rs`, any `src/bin/*.rs`, or a `[[bin]]` section.
        let has_main = dir.join("src/main.rs").is_file();
        let has_bin_dir = std::fs::read_dir(dir.join("src/bin"))
            .is_ok_and(|d| d.filter_map(Result::ok).any(|e| e.path().extension().is_some_and(|x| x == "rs")));
        let declares_bin = std::fs::read_to_string(&manifest).unwrap().contains("[[bin]]");
        if has_main || has_bin_dir || declares_bin {
            binaries.insert(name.clone());
        }
        deps.insert(name, normal_deps(&manifest));
    }
    (deps, binaries)
}

/// The transitive closure of `roots` over shipping edges, including the roots themselves.
fn closure(deps: &BTreeMap<String, BTreeSet<String>>, roots: &BTreeSet<String>) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = roots.clone();
    let mut stack: Vec<String> = roots.iter().cloned().collect();
    while let Some(c) = stack.pop() {
        for d in deps.get(&c).into_iter().flatten() {
            if seen.insert(d.clone()) {
                stack.push(d.clone());
            }
        }
    }
    seen
}

/// Every crate is reachable from something this project ships, except the ones [`UNLINKED`] names.
///
/// Failing this test means one of two things, and the message says which to check: a new crate was added
/// and nothing wires it up (write the wiring, or add it to the list with its reason), or an orphan was
/// finally wired (delete its row — the list is the record of what remains unwired).
#[test]
fn every_crate_is_reachable_from_a_shipped_binary_or_declared_unlinked() {
    let (deps, binaries) = workspace();
    assert!(binaries.len() >= 4, "expected the shipped binaries to be discoverable, found {binaries:?}");

    let reachable = closure(&deps, &binaries);
    let unreachable: BTreeSet<String> = deps.keys().filter(|c| !reachable.contains(*c)).cloned().collect();
    let declared: BTreeSet<String> = unlinked().iter().map(|(c, _)| (*c).to_owned()).collect();

    let unexpected: Vec<&String> = unreachable.difference(&declared).collect();
    assert!(
        unexpected.is_empty(),
        "these crates are linked by nothing the project ships: {unexpected:?}\n\
         Either wire them into a binary, or add each to EMBEDDING_SURFACE (if it exists to be called from \
         outside) or ORPHANS (if it is capability with no door) with the reason."
    );
    let wired: Vec<&String> = declared.difference(&unreachable).collect();
    assert!(
        wired.is_empty(),
        "these are listed as unlinked but are now reachable: {wired:?} — delete their rows, the list is \
         the record of what remains unwired."
    );
}

/// The reachability figures the audit quotes, computed rather than remembered.
///
/// Pinned so a change has to be noticed: silently dropping a crate out of the node's closure is exactly the
/// "wiring behind the libraries" regression this file exists to catch, and it would otherwise show up only
/// as prose going stale.
///
/// Each closure counts its own root, and counts optional dependencies — `fanos-dromos` and `fanos-obolos`
/// are feature-gated behind `validator`, so the node reaches them only in that build. They are *shipped*
/// code either way, which is what this measures; whether CI *builds* both feature configurations is a
/// separate question, answered by the two clippy/test steps in `.github/workflows/ci.yml`.
#[test]
fn the_reachability_figures_are_what_the_audit_states() {
    let (deps, binaries) = workspace();
    let total = deps.len();
    let from_node = closure(&deps, &BTreeSet::from(["fanos-node".to_owned()]));
    let from_any = closure(&deps, &binaries);

    assert_eq!(total, 43, "the workspace crate count changed");
    assert_eq!(from_node.len(), 35, "reachable from fanos-node (itself included): {from_node:?}");
    assert_eq!(from_any.len(), 39, "reachable from any shipped binary");
    assert_eq!(total - from_any.len(), unlinked().len(), "the unlinked set must account for the remainder");
}

/// The orphan list may shrink and never grow.
///
/// A ratchet rather than a rule that could be satisfied by writing a better excuse. An orphan is capability
/// nobody can reach: it reads as a shipped feature, it is maintained and compiled and tested, and no user can
/// touch it. Two is the count at the time this ratchet was set (2026-07-29); the only admissible directions are
/// wiring one up or deleting it.
///
/// It started at two. `fanos-angelos` came off it when `fanos message serve` gave the messenger a door — the
/// capability had been finished for a long time and only the composition was missing, which is the shape of
/// every orphan.
#[test]
fn the_orphan_list_only_shrinks() {
    const AT_RATCHET: usize = 1;
    assert!(
        ORPHANS.len() <= AT_RATCHET,
        "the orphan list grew to {} — a new crate was added that nothing can reach. Wire it, or delete it; \
         adding a row is not one of the options.",
        ORPHANS.len()
    );
    // …and when it shrinks, lower the ratchet, so the gain is locked in rather than left as slack.
    assert!(
        ORPHANS.len() == AT_RATCHET,
        "an orphan was resolved — lower AT_RATCHET to {} so the ground gained cannot be given back.",
        ORPHANS.len()
    );
}

/// An embedding surface is not an orphan, and the two lists must not overlap.
#[test]
fn the_two_exemptions_stay_distinct() {
    for (crate_name, _) in EMBEDDING_SURFACE {
        assert!(
            !ORPHANS.iter().any(|(o, _)| o == crate_name),
            "`{crate_name}` is listed as both an embedding surface and an orphan — they mean opposite things"
        );
    }
}
