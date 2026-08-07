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
    // **Empty as of 2026-07-30**, and worth stating rather than leaving as an absence: every crate in the workspace is
    // now reachable from a shipped binary or is a declared embedding surface. `fanos-ergon` was the last entry — an
    // execution model DROMOS executed without — and `fanos_dromos::ergon_host` plus `TAG_ERGON` closed it.
    //
    // An empty list is the goal, not a reason to delete the check: the assertion below is what fails when the next
    // capability lands without a door.
];

/// Crates that exist to be linked by **test harnesses only**, and are therefore correctly absent from every
/// shipped binary's dependency closure.
///
/// A third category, kept apart for the reason the other two are: an embedding surface is finished and waiting
/// for a foreign caller, an orphan is capability with no door, and this is neither. `fanos-testkit` holds the
/// host-load instrument that decides when a timing test must decline to conclude; shipping it inside a node
/// would be the defect, not the absence.
///
/// It follows that its public functions have no *production* caller by construction, so it is exempt from the
/// unwired-capability scan below. That exemption is safe precisely because the category is narrow: a crate
/// here must be a `dev-dependency` of something and a dependency of nothing.
const TEST_SUPPORT: &[(&str, &str)] = &[(
    "fanos-testkit",
    "the shared test instrument (host load, the quiet-host guard) — a dev-dependency of fanos-node and \
     fanos-quic, and deliberately reachable from no shipped binary",
)];

/// Every crate that is allowed to be unlinked, for any of the three reasons.
fn unlinked() -> Vec<(&'static str, &'static str)> {
    EMBEDDING_SURFACE.iter().chain(ORPHANS).chain(TEST_SUPPORT).copied().collect()
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
         outside), ORPHANS (if it is capability with no door), or TEST_SUPPORT (if it exists only for test \
         harnesses) with the reason."
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

    // 43 → 44: `fanos-testkit`, the shared test instrument — see `TEST_SUPPORT`.
    assert_eq!(total, 44, "the workspace crate count changed");
    // 35 → 36: `fanos-ergon` joined the node's closure when `fanos-dromos` took a dependency on it (`ergon_host`).
    assert_eq!(from_node.len(), 36, "reachable from fanos-node (itself included): {from_node:?}");
    // 39 → 40, same cause. And the remainder is now the embedding surface alone, since `ORPHANS` is empty.
    assert_eq!(from_any.len(), 40, "reachable from any shipped binary");
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
    // Lowered 1 → 0 on 2026-07-30: `fanos-ergon` was the last orphan and is now reachable, so the ground is locked in.
    //
    // At zero the two checks this test used to make — "the list grew" and "it shrank and the ratchet was not lowered" —
    // are the same assertion, which is what a fully-closed ratchet means and why they are now one. Zero is not a finished
    // state: it is the state in which the next capability landing without a door fails this test on the commit that adds
    // it, which was always the point.
    const AT_RATCHET: usize = 0;
    assert_eq!(
        ORPHANS.len(),
        AT_RATCHET,
        "the orphan list is {} rather than {AT_RATCHET}. If it GREW, a crate was added that nothing can reach — wire it \
         or delete it; adding a row is not one of the options. If it SHRANK, lower AT_RATCHET so the ground gained \
         cannot be given back.",
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

// ---------------------------------------------------------------------------------------------------------
// The function-level ratchet: "built but never wired", one granularity finer than the crate list above.
// ---------------------------------------------------------------------------------------------------------

/// Per-crate count of `pub fn`s that no production code anywhere calls. A **debt list and a ratchet**: it may
/// shrink and never grow.
///
/// The crate-level lists above catch a whole product with no door. They cannot catch the shape that produced
/// *both* HIGH findings of 2026-07-29, because in each case the crate was wired and one capability inside it
/// was not:
///
/// * `MIX_THRESHOLD` was generalized in theory and left a constant, so a hop fell to any two corrupt members
///   however wide the line — no anonymity at `q ≥ 7` (`docs/audit.md` E7).
/// * `BeaconNode::with_recovery_authority` existed in `fanos-keygen` and had **no production caller at all**,
///   so every shipped beacon refused every reshare and the R-C1 liveness cliff stayed a cliff while the
///   machinery that closes it sat finished and tested.
///
/// Both were found by accident, months after landing. This test is the detector: it fails on the commit that
/// *introduces* a new unreachable public capability, which is the only cheap moment to notice.
///
/// The counts come from this scan, not from a draft: a first pass in Python under-reported four crates because
/// it credited call sites that live inside `#[cfg(test)]` modules (`stream_count` in `fanos-diaulos/conn.rs` is
/// defined at 151, called at 522, and the test module opens at 335). Verified by hand on two of them before
/// these numbers were written down.
///
/// **These numbers are a debt, not an approval.** Much of it is legitimate — accessors a test asserts on,
/// analysis functions that exist to be checked rather than called (`chernoff_break_bound`), simulator helpers.
/// Some is not: `crosscell_dir`'s reading side means a cell publishes its checkpoint and no parent ever reads
/// it. The direction is down; a bump needs a reason in the commit message.
const UNWIRED_BUDGET: &[(&str, usize)] = &[
    // 7 → 8 (2026-08-03), with the reason the rule requires: `reordered_past_window` counts frames refused
    // for arriving further behind than `REPLAY_WINDOW` remembers — a signal that the window is too narrow for
    // the path, which is a different fact from loss and the only evidence that would justify widening it. It
    // has no door because ANGELOS has no call-stats surface yet. Raised rather than wired, because inventing a
    // caller to satisfy the count is the one thing this ratchet must never reward.
    ("fanos-angelos", 8),
    ("fanos-aphantos", 5),
    ("fanos-calypso", 11),
    ("fanos-code", 7),
    // 15 → 16 (2026-08-06), and the reason is that the ratchet had already slipped: the FIRST honest
    // whole-workspace run measured 16 here, and re-measuring at `e34ab63~1` — before any of that day's
    // changes — returned the identical 16 names. So this was not a regression being waved through; the number
    // 15 had simply stopped describing the tree, and every `-p <crate>` run since was blind to it
    // ([[run-the-whole-suite-not-your-crate]]).
    //
    // The set is `{assigned, content_address, from_counts, from_published, lines_per_node, local_setpoint,
    // observed_load, paths_out, rendezvous_depth, replica_lines, reset, residue_weight, routing_state,
    // verified, verified_members, write_read_witness}`. `from_published` is the reputation constructor task
    // #129 is about — it stays uncalled deliberately, because an inert loop is better than a
    // deterministically-divergent one, and wiring it needs a `performed` sensor the platform does not have.
    // Raised rather than satisfied: inventing a caller is the one thing this ratchet must never reward, and
    // that applies to me as much as to anyone.
    ("fanos-core", 16),
    ("fanos-diakrisis", 40),
    ("fanos-diaulos", 6),
    // **20 → 17 (2026-08-04), LOWERED — the debt was paid, not re-justified.** `fanos term` now builds a
    // term, type-checks it, encodes it canonically and submits it, so `name_register_term` and
    // `term_payload` left this set by acquiring the caller they were budgeted for. The count is the true
    // one: raising a budget needs a reason, and leaving it high after the work lands is a ratchet gone
    // slack, which is the same defect-in-the-record class as a stale finding.
    //
    // What remains is legitimate and named. `conflicts_with` is the SPECIFICATION of the scheduler's
    // conflict property, used by the test to verify the O(accesses) `schedule` that implements it — wiring
    // it onto the hot path would make block scheduling quadratic. `waves_last_block` and `parallel_blocks`
    // exist so a claim with no other observable can be checked: the conflict schedule is serial-equivalent
    // by construction, so no OUTCOME distinguishes parallel from serial execution, and without a counter the
    // vertical-parallelism claim is unfalsifiable. The rest are sub-ledger payload builders (`htlc_*`,
    // `shield*`, `stake_*`, `storage_*`, `mint_shielded`, `name_payload`) whose verbs are not built yet —
    // the same debt `term_payload` just paid, still outstanding for its siblings.
    ("fanos-dromos", 17),
    // **5 → 1 (2026-08-04), LOWERED.** `Expr::bin`, `exec::compare`, `Predicate::host_with` and
    // `encode_value` all acquired production callers when `fanos term` landed: it composes a computed
    // argument and a gated term, and `Checked::encode` is what the submitted bytes ARE — the signature
    // covers them and `SignedTerm::checked` decodes those same bytes to execute, so there is no second
    // representation.
    //
    // `decode_value` is the one left, and the reason it stays is narrower than the old note implied. That
    // note said canonicity "is enforced in a function nothing in production calls", which reads as a live
    // risk. It is not: the live `Reader::get` path projects **typed ledger state** into `Value`
    // structurally — `Value::Int(balance)`, `Value::Bytes32(hashlock)` — and never serializes a record at
    // all, so the boundary this codec guards does not exist yet rather than existing unguarded. It acquires
    // a caller when records are persisted, which is #77 (a node persists nothing today), and the canonicity
    // property starts mattering at exactly that moment.
    ("fanos-ergon", 1),
    ("fanos-field", 1),
    ("fanos-geometry", 2),
    ("fanos-holarch", 1),
    ("fanos-keygen", 7),
    ("fanos-node", 40),
    ("fanos-nyx", 15),
    ("fanos-obolos", 9),
    ("fanos-observatory", 2),
    ("fanos-onoma", 3),
    ("fanos-pqcrypto", 4),
    ("fanos-primitives", 3),
    ("fanos-proteus", 6),
    ("fanos-quic", 11),
    ("fanos-rendezvous", 2),
    ("fanos-runtime", 8),
    ("fanos-session", 1),
    // 31: `Timeline::revisits` — the oscillation detector added for the role-setpoint measurement. It is a
    // scenario instrument, like most of this crate's entry: `until`, `until_settled`, `frozen`,
    // `changes_after` and `is_reached` are all called only from scenarios, which is what fanos-sim is for.
    ("fanos-sim", 31),
    ("fanos-stream", 2),
    ("fanos-taxis", 18),
    ("fanos-telemetry", 6),
    // 6 → 7 (2026-08-03): `missed_audits` is the MEASUREMENT that audit AT-H2's missing early-termination
    // policy needs — a consumer whose provider stopped proving still has its escrow locked for the full term
    // precisely because misses were not countable. The count now exists and the policy does not, which is the
    // right order; wiring it would mean inventing the policy inside a getter's caller.
    ("fanos-thesauros", 7),
    ("fanos-threshold", 1),
    ("fanos-vpn", 1),
    ("fanos-vrf", 6),
    ("fanos-wasm", 1),
    ("fanos-wire", 2),
    ("fanos-wire-derive", 1),
];

/// Names too common to attribute to one definition, or whose call sites are method syntax this scan cannot see.
const UNWIRED_SKIP: &[&str] = &[
    "new", "default", "len", "is_empty", "clone", "fmt", "from", "into", "next", "iter", "get", "set", "step",
    "address", "encode", "decode", "to_bytes", "from_bytes", "as_str", "build", "run", "main", "id", "name",
    "verify", "sign", "hash",
];

/// The part of a source file that ships: everything before a module-level `#[cfg(test)]`.
///
/// A call that exists only in a crate's own test module is not wiring — that is exactly how a built-and-unused
/// capability looks reachable.
fn production_part(src: &str) -> &str {
    match src.find("\n#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    }
}

/// `pub fn` / `pub const fn` / `pub async fn` / `pub unsafe fn` names declared in `src`.
fn public_fn_names(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let mut rest = line.trim_start();
        if !rest.starts_with("pub ") {
            continue;
        }
        rest = &rest[4..];
        for modifier in ["const ", "async ", "unsafe "] {
            while let Some(tail) = rest.strip_prefix(modifier) {
                rest = tail;
            }
        }
        let Some(tail) = rest.strip_prefix("fn ") else { continue };
        let ident: String = tail.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if !ident.is_empty() {
            out.push(ident);
        }
    }
    out
}

/// Whether `hay` calls `name`: the identifier, an optional turbofish, then `(` — and **not** preceded by `fn `,
/// which is how a definition is spelled.
///
/// The turbofish is load-bearing and was missed on the first attempt. Nearly every call in this tree is generic
/// (`probe_point::<F>(…)`), so a pattern without it reported hundreds of wired functions as unwired — including
/// `probe_point`, whose caller sits in `fanos-quic/src/claims.rs`. Before trusting a sweep like this, run it
/// against something known to be wired and check it comes back positive; `the_unwired_scan_sees_a_wired_call`
/// below is that check, kept as a test rather than a memory.
fn calls(hay: &str, name: &str) -> bool {
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        // A preceding identifier character means this is a longer name, not ours.
        if at > 0 {
            let prev = bytes[at - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                continue;
            }
        }
        if hay[..at].ends_with("fn ") {
            continue; // the definition
        }
        let mut tail = hay[from..].trim_start();
        if let Some(after) = tail.strip_prefix("::<") {
            match after.find(['>', '(', ')']) {
                Some(end) if after.as_bytes()[end] == b'>' => tail = after[end + 1..].trim_start(),
                _ => continue,
            }
        }
        if tail.starts_with('(') {
            return true;
        }
    }
    false
}

/// Every `crates/*/src/**/*.rs`, as `(crate name, production text)`.
fn production_sources() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.components().any(|c| c.as_os_str() == "src")
            {
                let Some(krate) = path
                    .strip_prefix(root.join("crates"))
                    .ok()
                    .and_then(|p| p.components().next())
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                else {
                    continue;
                };
                if let Ok(text) = std::fs::read_to_string(&path) {
                    out.push((krate, production_part(&text).to_owned()));
                }
            }
        }
    }
    out
}

/// The unwired public functions, by crate.
fn unwired_by_crate() -> BTreeMap<String, BTreeSet<String>> {
    let sources = production_sources();
    // A name declared in more than one crate cannot be attributed by this scan; drop it rather than guess.
    let mut home: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (krate, text) in &sources {
        for name in public_fn_names(text) {
            home.entry(name).or_default().insert(krate.clone());
        }
    }
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, crates) in home {
        if crates.len() != 1 || UNWIRED_SKIP.contains(&name.as_str()) || name.starts_with('_') {
            continue;
        }
        if sources.iter().any(|(_, text)| calls(text, &name)) {
            continue;
        }
        let krate = crates.into_iter().next().unwrap();
        out.entry(krate).or_default().insert(name);
    }
    out
}

#[test]
fn the_unwired_scan_sees_a_wired_call() {
    // The instrument's own positive control, and the reason it exists as a test: the first version of this
    // scan was blind to the turbofish and would have reported every one of these as unreachable.
    let sources = production_sources();
    for name in [
        "probe_point",          // generic, called from fanos-quic/src/claims.rs
        "compose_engine",       // generic, called from fanos-node and fanos-sim
        "mix_threshold",        // plain, called from composition.rs
        "stability_radius",     // plain, called from healer.rs
        "purity_equicorrelated",
    ] {
        assert!(
            sources.iter().any(|(_, text)| calls(text, name)),
            "`{name}` is called in production but the scan cannot see it — every count below is then noise"
        );
    }
    // And the negative direction: a name nothing calls must not be reported as called.
    assert!(
        !sources.iter().any(|(_, text)| calls(text, "definitely_not_a_function_in_this_tree")),
        "the scan invents call sites"
    );
}

#[test]
fn no_new_public_capability_arrives_unwired() {
    let actual = unwired_by_crate();
    let budget: BTreeMap<&str, usize> = UNWIRED_BUDGET.iter().copied().collect();
    let mut grew = Vec::new();
    for (krate, names) in &actual {
        // A test-support crate's callers are tests **by construction**, so counting its unwired functions
        // measures the wrong thing — see `TEST_SUPPORT`. Exempted by category rather than by budget, so it
        // cannot silently become a place to park real capability.
        if TEST_SUPPORT.iter().any(|(c, _)| c == krate) {
            continue;
        }
        let allowed = budget.get(krate.as_str()).copied().unwrap_or(0);
        if names.len() > allowed {
            grew.push(format!("{krate}: {} > {allowed} — {names:?}", names.len()));
        }
    }
    assert!(
        grew.is_empty(),
        "these crates gained a public function no production code calls:\n  {}\n\n\
         That is the shape that hid `with_recovery_authority` (a beacon that could never reshare) and the \
         un-generalized `MIX_THRESHOLD` (no anonymity above the default plane) for months. Wire it, or raise \
         the crate's UNWIRED_BUDGET with the reason in the commit message.",
        grew.join("\n  ")
    );
}

#[test]
fn the_unwired_budget_is_not_slack() {
    // A budget above the real count is room for a defect to arrive unnoticed, so it must be exact-or-tight.
    let actual = unwired_by_crate();
    let mut loose = Vec::new();
    for (krate, allowed) in UNWIRED_BUDGET {
        let have = actual.get(*krate).map_or(0, BTreeSet::len);
        if have + 4 < *allowed {
            loose.push(format!("{krate}: budget {allowed}, actual {have}"));
        }
    }
    assert!(
        loose.is_empty(),
        "these budgets have drifted well above the real count — lower them so the ratchet still bites:\n  {}",
        loose.join("\n  ")
    );
}

/// **A crate directory that is not a workspace member is gated by nothing at all.**
///
/// Not clippy, not the test suite, not the doc build, not the reachability checks above — `cargo` simply does
/// not know it exists. It compiles the day someone adds it as a dependency, having never been linted or
/// tested, which is a worse position than an orphan: an orphan is *watched* and unreachable, this is
/// unwatched and about to be reached.
///
/// The checks above count and classify the members; nothing compared that list to the filesystem. Currently
/// they agree exactly (44 each), which is the moment to lock it in rather than after the first divergence.
#[test]
fn every_crate_directory_is_a_workspace_member() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("the workspace manifest");
    // The `members` array only — `[workspace.dependencies]` names the same crates by path and would make
    // this pass for a crate that is depended on but never built as a member.
    let members_block = manifest
        .split("members = [")
        .nth(1)
        .expect("a members array")
        .split(']')
        .next()
        .expect("the members array ends");
    let members: BTreeSet<String> = members_block
        .lines()
        .filter_map(|l| l.trim().strip_prefix("\"crates/"))
        .filter_map(|l| l.split('"').next())
        .map(str::to_owned)
        .collect();

    let dirs: BTreeSet<String> = std::fs::read_dir(root.join("crates"))
        .expect("the crates directory")
        .filter_map(Result::ok)
        .filter(|e| e.path().join("Cargo.toml").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    assert!(dirs.len() > 30, "only {} crate directories found — the scan is broken", dirs.len());
    let unlisted: Vec<&String> = dirs.difference(&members).collect();
    assert!(
        unlisted.is_empty(),
        "these crate directories are not workspace members, so nothing builds, lints or tests them: \
         {unlisted:?}"
    );
    let phantom: Vec<&String> = members.difference(&dirs).collect();
    assert!(phantom.is_empty(), "these members have no crate directory: {phantom:?}");
}

/// **Every named numeric constant says something about itself, and this is the floor of #45.**
///
/// The task's ambition is larger — each constant should declare *which kind* it is (derived, measured,
/// protocol-fixed, or a stated policy) — and no scan can judge prose. What a scan can judge is the tier
/// below: a constant with **no comment at all**, which is the state in which nobody can even begin the
/// argument. That was 30 across the tree and is now zero, so this locks the ground rather than aspiring to
/// it.
///
/// Groups are honoured — one comment above a run of related constants documents the run, which is the
/// convention the tree already uses and the reason the first three measurements of this were wrong (63,
/// then 48, then 30, as the scan learned what a comment looks like here). Test modules are excluded: a
/// fixture's `const N: usize = 7` is not a platform constant.
///
/// **What this deliberately does not claim.** A comment saying what a constant *does* is not a comment
/// saying why it has that *value* — `DECOUPLE_STEP: f64 = 0.25` has a fine paragraph about the control loop
/// and nothing about 0.25. Those are #45's real content and they need judgement, one at a time.
#[test]
fn every_numeric_constant_carries_a_comment() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let mut undocumented = Vec::new();
    let mut total = 0usize;
    for file in rust_sources(&root.join("crates")) {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let stop = lines.iter().position(|l| l.contains("#[cfg(test)]")).unwrap_or(lines.len());
        let mut run = false;
        for (i, line) in lines.iter().take(stop).enumerate() {
            let Some(name) = const_name(line) else {
                if line.trim().is_empty() {
                    run = false;
                }
                continue;
            };
            let numeric = is_numeric_const(line);
            if numeric {
                total += 1;
            }
            let mut j = i;
            let mut commented = false;
            while j > 0 {
                let above = lines[j - 1].trim();
                if above.starts_with("//") {
                    commented = true;
                } else if !above.starts_with("#[") {
                    break;
                }
                j -= 1;
            }
            if commented || run {
                run = true;
            } else if numeric {
                let rel = file.strip_prefix(&root).unwrap_or(&file).display();
                undocumented.push(format!("{rel}:{} {name}", i + 1));
            }
        }
    }
    assert!(total > 400, "only {total} numeric constants found — the scan is broken, not the tree");
    assert!(
        undocumented.is_empty(),
        "these numeric constants carry no comment at all, so nothing says where the value comes from — \
         which is the state in which the question cannot even be asked (#45):\n  {}",
        undocumented.join("\n  ")
    );
}

/// Every `.rs` under a crate's `src/`.
fn rust_sources(crates: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![crates.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.filter_map(Result::ok) {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.components().any(|c| c.as_os_str() == "src")
            {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The name of the constant this line declares, if it declares one.
fn const_name(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix("pub ").unwrap_or(line.trim());
    let rest = rest.split_once(')').map_or(rest, |(head, tail)| {
        if head.starts_with("pub(") { tail.trim_start() } else { rest }
    });
    let rest = rest.strip_prefix("const ")?;
    let (name, _) = rest.split_once(':')?;
    let name = name.trim();
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()))
        .then_some(name)
}

/// Whether the constant this line declares has a numeric type — the ones #45 is about.
fn is_numeric_const(line: &str) -> bool {
    const NUMERIC: &[&str] =
        &["usize", "u8", "u16", "u32", "u64", "f64", "i32", "i64", "Duration"];
    line.split_once(':').is_some_and(|(_, ty)| {
        let ty = ty.split('=').next().unwrap_or("").trim().trim_end_matches("::Duration");
        NUMERIC.iter().any(|n| ty == *n || ty.ends_with(&format!("::{n}")))
    })
}

/// The audit's citation register must name every pass that numbers its sections `§N`, and must count them right.
///
/// `docs/audit.md` grows by one appended pass per audit and **each pass restarts at §1**, so a bare "§3" names
/// twelve different sections and resolves only against the pass a reader happens to be inside. The file's
/// answer (#169) is a register at the top mapping each pass to a citation key — which is worth exactly as much
/// as its accuracy, and a register maintained by hand across twenty passes is a stale register.
///
/// So this checks the two things a reader relies on, against the file itself:
///
/// * **Coverage** — every level-1 banner that owns at least one `## §` heading has a row. A new pass appended
///   with `§`-numbered sections and no register row fails here, on the commit that adds it.
/// * **Counts** — each row's stated section count is the number actually present under that banner. This is
///   the half that catches the likelier drift: a pass gaining a `§13` long after its row was written.
///
/// The root pass is deliberately outside both checks: it numbers `## 1.`–`## 12.` with no `§`, so its headings
/// are already unique and its row says so in prose rather than a number.
#[test]
fn every_section_numbering_pass_is_in_the_audits_citation_register() {
    let audit = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docs/audit.md"),
    )
    .expect("docs/audit.md is readable from the crate");

    // Rows of the register: (quoted banner text, stated count). Rows whose count cell is prose — the root
    // pass — are skipped by the `parse` and so exempt from both checks, which is the intent.
    let register: Vec<(String, usize)> = audit
        .lines()
        .filter(|l| l.starts_with("| `20"))
        .filter_map(|l| {
            let mut cols = l.split('|').map(str::trim);
            let (_key, banner, count) = (cols.nth(1)?, cols.next()?, cols.next()?);
            Some((banner.trim_matches('*').to_owned(), count.parse().ok()?))
        })
        .collect();

    // Section counts per level-1 banner, from the file itself.
    let mut actual: Vec<(String, usize)> = Vec::new();
    for line in audit.lines() {
        if let Some(banner) = line.strip_prefix("# ") {
            actual.push((banner.to_owned(), 0));
        } else if line.starts_with("## §")
            && let Some(last) = actual.last_mut()
        {
            last.1 += 1;
        }
    }
    actual.retain(|(_, n)| *n > 0);

    for (banner, n) in &actual {
        let row = register.iter().find(|(quoted, _)| banner.contains(quoted.as_str()));
        let Some((quoted, stated)) = row else {
            panic!(
                "the audit pass \"{banner}\" numbers {n} sections `§N` and has no row in the citation register \
                 at the top of docs/audit.md. Add one — a `§N` under an unregistered banner cannot be cited \
                 unambiguously from a commit, a task or a code comment, which is the whole defect (#169)."
            );
        };
        assert_eq!(
            stated, n,
            "the register says \"{quoted}\" has {stated} `§` sections; the file has {n}. Correct the row — a \
             count that drifts is how a register stops being read."
        );
    }
    assert_eq!(
        register.len(),
        actual.len(),
        "the register has {} numbered rows for {} passes that actually number sections — a row names a pass \
         that no longer numbers any `§`, or names one twice.",
        register.len(),
        actual.len()
    );
}

/// The exit's loopback exemption must be reachable only from a test.
///
/// `ExitPolicy::also_permitting_loopback_for_tests` exists because the exit end-to-end suite has to dial an
/// echo server it bound on `127.0.0.1` — the one address #170 exists to refuse. The constructor is named to
/// be unmissable in review, but a name is not a guarantee: an exit built with it will relay an anonymous
/// client onto the operator's own host, and that is precisely the CRITICAL that was just closed.
///
/// So the guarantee is mechanical. Any call from a file that is not a test — a `src/` module, a binary, a
/// benchmark — fails here. The counterpart assertion lives with the code: `the_metadata_endpoint_is_refused_
/// in_every_realm` proves the hatch relaxes loopback and nothing else, so even a leaked call cannot reach
/// `169.254.169.254`. Two independent bounds, because one of them is a naming convention.
#[test]
fn the_loopback_exemption_is_reachable_only_from_a_test() {
    const HATCH: &str = "also_permitting_loopback_for_tests";
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");

    let mut offenders: Vec<String> = Vec::new();
    let mut calls = 0usize;
    let mut stack = vec![crates];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "target") {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            // This file names the constructor in a `const`, and lives in a `tests/` directory — so without
            // this line it counts itself, and the "someone still calls it" half below can never fail. That
            // was not hypothetical: it passed after the only real call site had been renamed away.
            if path.file_name().is_some_and(|n| n == "architecture.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else { continue };
            // The definition itself, and this test's own mention of the name, are not calls.
            let body = src.split("pub fn also_permitting").next().unwrap_or(&src);
            if !body.contains(HATCH) {
                continue;
            }
            calls += 1;
            // Membership of a `tests/` directory, and nothing softer. The first cut here also accepted any
            // file containing `#[cfg(test)]` — which is nearly every `src/` module in this workspace, since
            // that is where a unit-test module lives — so the guard exempted the whole codebase and passed
            // when a `src/` call was planted in it. A guard that cannot fail is not a guard.
            if !path.components().any(|c| c.as_os_str() == "tests") {
                offenders.push(path.display().to_string());
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "{HATCH} is called from non-test code: {offenders:?}. An exit built that way relays an anonymous \
         client onto the operator's own loopback — use ExitPolicy::new/web, which is the shipping rule (#170)."
    );
    assert!(
        calls > 0,
        "no file calls {HATCH} — if the exit e2e stopped needing the hatch, delete the constructor rather \
         than leaving a widened policy nothing exercises."
    );
}

/// No production code creates a directory at the umask.
///
/// #82 established that a secret must be written 0600 and not chmod-ed a microsecond later. #166 found the
/// half that lesson had missed — the DIRECTORY holding those secrets was still created at the umask, so the
/// bytes were private and their names were not, and enumerating a ceremony's output is most of knowing what
/// to attack. `durable::create_private_dir` is the single answer.
///
/// This test exists because the #166 sweep itself missed a call site: `bin/fanos.rs`'s `write_file` — the
/// CLI helper whose whole doc-comment is about permission hygiene, and the one that writes founder seeds and
/// validator configs — still called `create_dir_all` directly. A fix applied by hand across a crate is a fix
/// that misses one; the mechanical check is what makes it hold.
///
/// Test modules are exempt: a scratch directory under a per-test temp path holds nothing worth hiding, and
/// requiring 0700 there would be ceremony without a threat.
#[test]
fn no_production_code_creates_a_directory_at_the_umask() {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut offenders: Vec<String> = Vec::new();
    let mut stack = vec![crates];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "target" && n != "tests") {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else { continue };
            // Everything from the first `#[cfg(test)]` on is a test module — exempt, and excluded by
            // POSITION rather than by "the file mentions cfg(test)", which would exempt nearly every
            // `src/` module in this workspace and make the check vacuous.
            let production = src.split("#[cfg(test)]").next().unwrap_or(&src);
            // `create_private_dir` is the sanctioned wrapper and calls `create_dir_all` itself.
            if path.file_name().is_some_and(|n| n == "durable.rs") {
                continue;
            }
            for (i, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("create_dir_all") {
                    offenders.push(format!("{}:{}", path.display(), i + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these create a directory at the process umask: {offenders:?}. Call \
         `fanos_node::durable::create_private_dir` — a 0600 secret inside a 0755 directory publishes its \
         name to every account on the host (#82, #166)."
    );
}

/// **Every production dial of a peer-chosen remote address consults the shared realm policy (#170, #171).**
///
/// The census that produced this: `connect(`/`lookup_host(` in non-test `src/` reduces to a handful of files,
/// and exactly two of them dial an address a *peer* named — the clearnet exit and the NAT hole-punch. #170
/// gave the exit a filter and the punch went on dialling anything, because the fix was applied at the site
/// that had the bug rather than to the class ([[enumerate-the-class-after-fixing-it]]).
///
/// So this is a class guard, not a site guard: a new dial site is caught on the commit that adds it, which is
/// the only moment the cost of writing the realm argument is small. The two sanctioned entry points are
/// `fanos_quic::dial_policy::may_dial` and `exit.rs`'s `resolve_relayable`, which calls it.
#[test]
fn every_production_dial_of_a_peer_named_address_goes_through_the_dial_policy() {
    /// Files permitted to call a dialing primitive, each with what makes it safe.
    ///
    /// A short list on purpose. Anything added here has to argue that the address is NOT peer-chosen —
    /// which is the whole question — so a row is a claim, not an exemption.
    /// `(file, why, must still contain)` — the third column is what stops a row from being a free pass.
    ///
    /// **A row that only names a file is not an exemption, it is a hole.** Both files that dial a peer-named
    /// address are on this list, so without the third column the guard could not see either of them losing
    /// its filter — which is precisely the regression it exists to prevent. Measured: removing the punch
    /// filter left the first version of this test green.
    const SANCTIONED: &[(&str, &str, &str)] = &[
        ("fanos-quic/src/dial_policy.rs", "the policy itself", "pub fn may_dial"),
        ("fanos-quic/src/driver.rs", "the punch path filters with Policy::Overlay before it dials", "dial_policy::may_dial"),
        ("fanos-node/src/exit.rs", "resolves through `resolve_relayable`, on the Clearnet realm", "dial_policy::may_dial"),
        ("fanos-node/src/admin.rs", "connects to a Unix socket path, not a network address", ""),
        ("fanos-proxy/src/udp.rs", "sends to the LOCAL SOCKS client that opened the association", ""),
        ("fanos-proxy/src/http.rs", "connects only inside its own tests", ""),
    ];

    let mut offenders = Vec::new();
    let mut examined = 0usize;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    for krate in std::fs::read_dir(root.join("crates")).expect("crates/") {
        let root = krate.expect("entry").path().join("src");
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let Ok(src) = std::fs::read_to_string(&path) else { continue };
                let production = src.split("#[cfg(test)]").next().unwrap_or(&src);
                examined += 1;
                // Keyed by crate-relative PATH, not basename: `driver.rs` exists in both `fanos-quic` and
                // `fanos-vpn`, and matching on the name alone applied the quic row's liveness requirement to
                // the vpn file — a row silently governing a file it was never written about.
                let named = path.to_string_lossy().replace('\\', "/");
                if let Some((_, why, required)) = SANCTIONED.iter().find(|(f, ..)| named.ends_with(*f)) {
                    // The liveness half: a sanctioned file that no longer contains its safe mechanism has
                    // stopped being sanctioned, and saying so here is the only thing that makes the row
                    // mean anything ([[falsify-the-exemption-not-the-rule]]).
                    assert!(
                        required.is_empty() || src.contains(required),
                        "`{named}` is exempted because {why}, and no longer contains `{required}` — either \
                         it stopped dialling (delete the row) or it stopped filtering (that is the bug)."
                    );
                    continue;
                }
                for (i, line) in production.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    if code.contains("lookup_host(") || code.contains("endpoint.connect(") {
                        offenders.push(format!("{}:{}", path.display(), i + 1));
                    }
                }
            }
        }
    }
    // The denominator, so a walk that finds nothing fails rather than passes.
    assert!(examined > 200, "the scan examined only {examined} production files — it is not reaching them");
    assert!(
        offenders.is_empty(),
        "these dial a remote address without going through `fanos_quic::dial_policy`: {offenders:?}. A dial \
         to an address a PEER named must state its realm — the exit's (globally routable only) or the \
         overlay's (anything that can be a distinct peer). Without one, a single tolerated peer aims this \
         node's packets at the operator's LAN, their loopback, or 169.254.169.254 (#171)."
    );
}
