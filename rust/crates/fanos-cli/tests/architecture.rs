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
    ("fanos-core", 15),
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
