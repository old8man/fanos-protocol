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

use fanos_testkit::corpus::{self, RustSource, rust_sources as corpus};
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
/// The shipping-code slice, shared (#252). Seven copies of it existed; each cut at the FIRST
/// `#[cfg(test)]` and so examined only the head of any file with a test module in the middle.
use fanos_testkit::source::{code_only, production_part};

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
/// **+58 across 21 crates on 2026-08-08, and NOT because anything was added** (#227). The scan read
/// comments as code: [`calls`] accepts a name followed by an opening paren, which is ordinary English
/// punctuation, so a doc line reading "the cascade `lead` (`-1` = none)" registered as a call to `lead()`.
/// [`code_only`] now strips whole-line comments and the counts below are what was always true.
///
/// **The blindness was biased toward exactly what this guard is for.** The more consequential a function,
/// the likelier a neighbouring comment names it — so the names it hid are not a random sample.
/// `loadbalance::balance_exact` is the §6.7 rebalance, the platform's ONLY response that could raise `Φ`;
/// its sole real caller is a test, and the comment that "wired" it is the healer's own prose *describing*
/// the response (#139). `dispersion` is the second-dimension discriminator no production reader consumes
/// (#225/#226). Both were found by hand, days apart, while this guard reported them wired.
///
/// Each of the 58 is a **candidate**, not an accepted finding: some are reached by paths the scan cannot
/// model, which is why the positive-control list below exists. Triaging them is its own work.
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
    ("fanos-angelos", 10),
    ("fanos-aphantos", 5),
    ("fanos-calypso", 12),
    ("fanos-code", 11),
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
    ("fanos-core", 17),
    ("fanos-diakrisis", 43),
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
    ("fanos-dromos", 20),
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
    ("fanos-ergon", 3),
    ("fanos-field", 1),
    ("fanos-geometry", 2),
    ("fanos-holarch", 1),
    ("fanos-keygen", 7),
    ("fanos-node", 42),
    ("fanos-nyx", 21),
    ("fanos-obolos", 11),
    ("fanos-observatory", 2),
    ("fanos-onoma", 5),
    ("fanos-pqcrypto", 6),
    ("fanos-primitives", 3),
    ("fanos-proteus", 7),
    ("fanos-quic", 11),
    ("fanos-rendezvous", 2),
    ("fanos-runtime", 9),
    ("fanos-session", 1),
    // 31: `Timeline::revisits` — the oscillation detector added for the role-setpoint measurement. It is a
    // scenario instrument, like most of this crate's entry: `until`, `until_settled`, `frozen`,
    // `changes_after` and `is_reached` are all called only from scenarios, which is what fanos-sim is for.
    ("fanos-sim", 37),
    ("fanos-stream", 3),
    ("fanos-taxis", 22),
    ("fanos-telemetry", 9),
    // 6 → 7 (2026-08-03): `missed_audits` is the MEASUREMENT that audit AT-H2's missing early-termination
    // policy needs — a consumer whose provider stopped proving still has its escrow locked for the full term
    // precisely because misses were not countable. The count now exists and the policy does not, which is the
    // right order; wiring it would mean inventing the policy inside a getter's caller.
    ("fanos-thesauros", 9),
    ("fanos-threshold", 1),
    ("fanos-vpn", 1),
    ("fanos-vrf", 12),
    ("fanos-wasm", 1),
    ("fanos-wire", 6),
    ("fanos-wire-derive", 1),
];

/// Names too common to attribute to one definition, or whose call sites are method syntax this scan cannot see.
const UNWIRED_SKIP: &[&str] = &[
    "new", "default", "len", "is_empty", "clone", "fmt", "from", "into", "next", "iter", "get", "set", "step",
    "address", "encode", "decode", "to_bytes", "from_bytes", "as_str", "build", "run", "main", "id", "name",
    "verify", "sign", "hash",
];

/// **No second walk.** Nothing outside `fanos-testkit` may roll its own recursive scan of the tree (#253).
///
/// Fourteen guards did, and each one ended a failed read with `else { continue }` or `unwrap_or_default()`.
/// That makes two silent holes: a wrong root yields an empty corpus, so "no file does X" holds for the
/// emptiest of reasons; and a file that exists but cannot be opened is dropped, which is precisely the file a
/// permissions accident removes from the scan. Neither shows up as anything but green — the reason this rule
/// has to be about the SHAPE, checked from outside, like its sibling below.
///
/// `fanos_testkit::corpus::rust_sources` is the one walk that reports what it reached: unreadable directory,
/// unreadable file and a crate that contributed nothing are all fatal there.
///
/// **The rule is about walks of the SOURCE TREE, not about `read_dir`.** Its first version flagged every
/// listing and immediately reported `ceremony_secrets.rs`, which lists the temp directory a ceremony just
/// wrote — a different act, and one that `.expect()`s rather than skipping. Reading the site showed the rule
/// was wrong, not the code, so the discriminator is now how the walk finds its ROOT: a file that reaches for
/// `CARGO_MANIFEST_DIR` and then lists directories is scanning the tree; one listing a path it was handed is
/// not ([[falsify-the-exemption-not-the-rule]], applied to the rule itself).
///
/// **Self-exemption by position, and it is the one exemption.** This file has to name the pattern to look for
/// it, so it is excluded by `file!()` rather than by a list — a list of exempt files is the hole, not the fix
/// (#227's rule, applied to itself). The corpus module itself is excluded for the same structural reason: it
/// *is* the walk, and a rule that forbade the only sanctioned implementation would forbid the fix.
#[test]
fn no_guard_rolls_its_own_walk_of_the_tree() {
    let myself = corpus::workspace_root().join(file!()).canonicalize().ok();
    let home = corpus::workspace_root().join("crates/fanos-testkit/src/corpus.rs");
    // Assembled rather than written, so this file holds no literal `read_dir` for itself to find.
    let needle = format!("read{}", "_dir(");
    let rooted = format!("CARGO_MANIFEST{}", "_DIR");

    let mut offenders: Vec<String> = Vec::new();
    let mut examined = 0usize;
    for file in corpus() {
        if file.path.canonicalize().ok() == myself || file.path == home {
            continue;
        }
        // Not a tree walk unless it roots itself in the tree — see the paragraph above.
        if !file.text.contains(&rooted) {
            continue;
        }
        examined += 1;
        for (n, line) in file.text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains(&needle) {
                offenders.push(format!("{}:{}", file.rel, n + 1));
            }
        }
    }

    assert!(examined > 0, "the scan examined nothing — which is the failure it exists to catch, in itself");
    assert!(
        offenders.is_empty(),
        "these walk the tree themselves instead of calling `fanos_testkit::corpus::rust_sources`: \
         {offenders:?}. Every hand-rolled copy so far skipped an unreadable file in silence and passed green \
         about code it never opened — and an empty corpus passed for the same reason (#253)."
    );
}

/// **No second slice.** Nothing outside `fanos-testkit` may split a source file on the test attribute itself.
///
/// Seven places did, across five files, and every one shared the defect: cut at the FIRST marker, keep the
/// head, lose whatever ships below it. Two of the seven were in this very file. A guard reading less than it
/// claims cannot be caught by its own green result, so the rule has to be about the SHAPE, checked from
/// outside.
///
/// **The scanner cannot exempt itself, because it never spells the needle.** An allow-list would have to
/// name this file, and a scanner that skips a file is one edit away from skipping the file that matters
/// (#227's rule, applied to itself). Assembling the pattern at runtime means this source contains no literal
/// occurrence to find — the exemption is structural, not a decision anyone can widen.
#[test]
fn no_source_scan_rolls_its_own_test_block_slice() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let needle = format!("\"#[cfg{}\"", "(test)]");
    let home = root.join("crates/fanos-testkit/src/lib.rs");

    let mut offenders: Vec<String> = Vec::new();
    for file in corpus() {
        if file.path == home {
            continue;
        }
        for (n, line) in file.text.lines().enumerate() {
            if line.contains(&needle) && !line.trim_start().starts_with("//") {
                offenders.push(format!("{}:{}", file.rel, n + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these scan for the test attribute themselves instead of calling \
         `fanos_testkit::source::{{production_part, shipping_lines}}`: {offenders:?}. Every hand-rolled copy \
         so far cut at the FIRST marker and silently dropped the shipping code below it (#252) — including \
         the two that lived in this file."
    );
}

/// **The corpus half of #252**: these three files really do declare shipping code below a test module, and
/// every guard here had been examining them only down to that line.
///
/// A synthetic self-test cannot hold this — the old slice passed every synthetic case that did not put code
/// after a test block, which is exactly why it survived. Named files, so that restoring the cut-at-first
/// form fails with the name of what it would blind.
#[test]
fn the_slice_reaches_the_shipping_code_that_sits_below_a_test_module() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    // (file, a declaration that sits BELOW that file's first `#[cfg(test)]`)
    let cases = [
        ("crates/fanos-field/src/lib.rs", "pub trait Field"),
        ("crates/fanos-node/src/resolve.rs", "pub struct NodeResolver"),
        ("crates/fanos-node/src/telemetry_dir.rs", "pub struct Census"),
    ];
    for (path, decl) in cases {
        let src = std::fs::read_to_string(root.join(path)).expect("file is readable");
        let cut = src.find("\n#[cfg(test)]").expect("the file has a test block");
        let below = src[cut..].contains(decl);
        assert!(below, "{path} no longer declares `{decl}` below a test block — update this case, do not delete it");
        assert!(
            production_part(&src).contains(decl),
            "`{decl}` ships in {path} and the production slice does not see it. Every guard in this file \
             reads through that slice, so all of them would be quietly examining a subset (#252)."
        );
    }

    // And the other direction on the same corpus: a `#[cfg(test)]` fixture stays out. `PassThroughFabric` is
    // the one that matters — it implements `quinn::AsyncUdpSocket`, so admitting it would make the transport
    // guards read a test double as the shipping datapath.
    let driver = std::fs::read_to_string(root.join("crates/fanos-quic/src/driver.rs")).unwrap();
    assert!(
        !production_part(&driver).contains("struct PassThroughFabric"),
        "a #[cfg(test)] fixture must not be readmitted as production by the wider slice"
    );
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
    corpus()
        .into_iter()
        .filter(RustSource::is_crate_src)
        .map(|s| (s.krate, code_only(&s.text)))
        .collect()
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
    let mut undocumented = Vec::new();
    let mut total = 0usize;
    // One walk that reports what it reached (#253) and one slice that defines shipping code (#252).
    for file in corpus().into_iter().filter(RustSource::is_crate_src) {
        let text = production_part(&file.text);
        let lines: Vec<&str> = text.lines().collect();
        let stop = lines.len();
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
                undocumented.push(format!("{}:{} {name}", file.rel, i + 1));
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

/// **The transport's stream credit is derived from the number of openers — so a new opener must move it.**
///
/// `MAX_PEER_UNI_STREAMS` is not a comfortable number: `tuned_transport` credits a peer exactly as many
/// concurrent uni-streams as this crate has `open_uni()` sites, because every one of them writes a single
/// frame and finishes (#245). That derivation is only true while the count is true, and nothing else in the
/// build checks it: a fifth opener would compile, run, and silently contend for four credits — frames
/// delayed or dropped on a path whose failure mode is "the peer went quiet".
///
/// Counted by NAME, not by `open_uni(`, because a call may be written `conn.open_uni()` on its own line or
/// wrapped; and comments are stripped first, because a mention in prose is not a call (#227).
#[test]
fn the_uni_stream_credit_matches_the_number_of_openers() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let driver = root.join("crates/fanos-quic/src/driver.rs");
    let src = std::fs::read_to_string(&driver).expect("driver.rs is readable");
    let code = code_only(&src); // `code_only` already drops the test blocks

    let openers = code.matches("open_uni").count();
    let credit: usize = code
        .split("const MAX_PEER_UNI_STREAMS: u32 = ")
        .nth(1)
        .and_then(|t| t.split(';').next())
        .and_then(|t| t.trim().parse().ok())
        .expect("MAX_PEER_UNI_STREAMS is declared as a literal");

    assert_eq!(
        openers, credit,
        "`tuned_transport` credits a peer {credit} concurrent uni-streams because this crate opens streams \
         at {credit} sites — but production now has {openers}. Either raise the constant WITH the reason, or \
         route the new send through an existing opener. Leaving them apart makes the credit a chosen number \
         and the excess frames a silent loss (#245)."
    );
}

/// **No subsystem may declare its memory share as a literal** — it must take it from the one module that
/// sums them.
///
/// This started as a guard comparing copies, because `fanos-primitives` is below every consumer and cannot
/// import from them. Then the direction turned out to be available the other way: all four consumers already
/// depend on `fanos-primitives`, so the share can *live* there and each subsystem take it. That deletes the
/// drift instead of detecting it — the compiler now holds what a ratchet was going to watch. What remains
/// worth guarding is the door back: a new literal reintroduces the split silently, and it is one keystroke.
#[test]
fn no_subsystem_declares_its_memory_share_as_a_literal() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let crates = root.join("crates");
    let budget_path = crates.join("fanos-primitives/src/budget.rs");

    for file in corpus().into_iter().filter(RustSource::is_crate_src) {
        if file.path == budget_path {
            continue; // the register may not count itself (#227's rule)
        }
        for line in code_only(&file.text).lines() {
            let Some(name) = const_name(line) else { continue };
            if !name.ends_with("_MEMORY_BUDGET") {
                continue;
            }
            let value = line.split_once('=').map_or("", |(_, v)| v.trim());
            assert!(
                value.contains("fanos_primitives::budget::"),
                "{name} in {} is declared as `{value}` instead of taking its share from \
                 `fanos_primitives::budget`. Two numbers for one quantity is how #213 happened: three \
                 subsystems each sized their share against the same 256 MiB and no one could see the sum.",
                file.rel
            );
        }
    }
}

/// **A fourth subsystem reserving "a share" must appear in the sum**, or #213 is back with one more term.
///
/// The first three were invisible to each other because nothing enumerated them. Enumerating by name is the
/// cheapest thing that fails when a fourth arrives — and the failure lands on the author adding it, which is
/// the only moment anyone can weigh it against the rest.
#[test]
fn every_memory_budget_in_the_tree_is_one_of_the_summed_shares() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let crates = root.join("crates");
    let budget_path = crates.join("fanos-primitives/src/budget.rs");
    let budget = std::fs::read_to_string(&budget_path).expect("the budget module is readable");

    let mut found: Vec<String> = Vec::new();
    for file in corpus().into_iter().filter(RustSource::is_crate_src) {
        if file.path == budget_path {
            continue; // the register may not count itself (#227's rule)
        }
        for line in code_only(&file.text).lines() {
            if let Some(name) = const_name(line)
                && name.ends_with("_MEMORY_BUDGET")
            {
                found.push(format!("{name} ({})", file.rel));
                assert!(
                    budget.contains(name),
                    "{name} reserves a share of the node's memory and `fanos_primitives::budget` has never \
                     heard of it. Add it to SHARES with its derivation, and take the new overcommit against \
                     the sum rather than against a comment in its own crate (#213)."
                );
            }
        }
    }

    let summed = budget.split("SHARES: [(&str, usize); ").nth(1).and_then(|t| {
        t.split(']').next().and_then(|n| n.trim().parse::<usize>().ok())
    });
    assert_eq!(
        summed,
        Some(found.len()),
        "SHARES declares {summed:?} terms and the tree declares {} memory budgets: {found:?}. The two must \
         be the same list, or the sum is over a subset nobody chose.",
        found.len()
    );
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

    let mut offenders: Vec<String> = Vec::new();
    let mut calls = 0usize;
    for file in corpus() {
        // This file names the constructor in a `const`, and lives in a `tests/` directory — so without
        // this line it counts itself, and the "someone still calls it" half below can never fail. That
        // was not hypothetical: it passed after the only real call site had been renamed away.
        if file.path.file_name().is_some_and(|n| n == "architecture.rs") {
            continue;
        }
        // The definition itself, and this test's own mention of the name, are not calls.
        let body = file.text.split("pub fn also_permitting").next().unwrap_or(&file.text);
        if !body.contains(HATCH) {
            continue;
        }
        calls += 1;
        // Membership of a `tests/` directory, and nothing softer. The first cut here also accepted any
        // file containing `#[cfg(test)]` — which is nearly every `src/` module in this workspace, since
        // that is where a unit-test module lives — so the guard exempted the whole codebase and passed
        // when a `src/` call was planted in it. A guard that cannot fail is not a guard.
        if !file.path.components().any(|c| c.as_os_str() == "tests") {
            offenders.push(file.rel);
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
    let mut offenders: Vec<String> = Vec::new();
    // A whole `tests/` directory is exempt here, and that exemption now lives at the guard rather than
    // inside the walk — the corpus hands over everything, so a reader can see what this test declines to
    // look at instead of inferring it from a `stack.push` condition (#253).
    for file in corpus().into_iter().filter(|s| !Path::new(&s.rel).components().any(|c| c.as_os_str() == "tests"))
    {
        // Test modules are exempt, and excluded by POSITION rather than by "the file mentions
        // cfg(test)", which would exempt nearly every `src/` module here and make the check vacuous.
        // The slice is shared: cutting at the FIRST marker dropped shipping code below it (#252).
        let production = production_part(&file.text);
        // `create_private_dir` is the sanctioned wrapper and calls `create_dir_all` itself.
        if file.path.file_name().is_some_and(|n| n == "durable.rs") {
            continue;
        }
        for (i, line) in production.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("create_dir_all") {
                offenders.push(format!("{}:{}", file.rel, i + 1));
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
    // One pass over the whole corpus. The old shape looped the crates directory and walked each crate, so
    // "which crates did it reach" was the walk's private business; now it is the corpus's assertion (#253).
    {
        // `src/` only, as the per-crate walk this replaced did: a `tests/` file that dials is a test dialling,
        // which is what the SANCTIONED table is not about.
        for file in corpus().into_iter().filter(RustSource::is_crate_src) {
            let production = production_part(&file.text);
            examined += 1;
            // Keyed by crate-relative PATH, not basename: `driver.rs` exists in both `fanos-quic` and
            // `fanos-vpn`, and matching on the name alone applied the quic row's liveness requirement to
            // the vpn file — a row silently governing a file it was never written about.
            let named = file.rel.replace('\\', "/");
            if let Some((_, why, required)) = SANCTIONED.iter().find(|(f, ..)| named.ends_with(*f)) {
                // The liveness half: a sanctioned file that no longer contains its safe mechanism has
                // stopped being sanctioned, and saying so here is the only thing that makes the row
                // mean anything.
                assert!(
                    required.is_empty() || file.text.contains(required),
                    "`{named}` is exempted because {why}, and no longer contains `{required}` — either \
                     it stopped dialling (delete the row) or it stopped filtering (that is the bug)."
                );
                continue;
            }
            for (i, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("lookup_host(") || code.contains("endpoint.connect(") {
                    offenders.push(format!("{}:{}", file.rel, i + 1));
                }
            }
        }
    }
    // The denominator. `> 200` was a number someone picked; the corpus now derives its own floor — every
    // crate must contribute — so this only has to say the loop ran at all (#253).
    assert!(examined > 0, "the scan examined no production files — it is not reaching them");
    assert!(
        offenders.is_empty(),
        "these dial a remote address without going through `fanos_quic::dial_policy`: {offenders:?}. A dial \
         to an address a PEER named must state its realm — the exit's (globally routable only) or the \
         overlay's (anything that can be a distinct peer). Without one, a single tolerated peer aims this \
         node's packets at the operator's LAN, their loopback, or 169.254.169.254 (#171)."
    );
}

/// A test that spawns a concurrent peer must run on a runtime that can be concurrent.
///
/// `#[tokio::test]` defaults to the **current-thread** runtime. A test that `tokio::spawn`s a peer and then
/// drives the other side is asserting a concurrent property on an executor where the two can only interleave
/// at each other's await points — so a data race cannot manifest, a deadlock that needs true parallelism
/// cannot appear, and the ordering the test happens to observe gets certified as the ordering.
///
/// This is #84's class, and #84 was closed while **26 such tests across 12 files** remained. They were all
/// converted (#201); this guard is what stops the flavour drifting back, because the conversion is invisible
/// in a diff that only adds a `spawn` to an existing test.
///
/// The filter is `spawns ∧ current-thread`, not "is async" — a sequential async test needs no threads and
/// paying for them is waste.
///
/// **"Spawns" cannot mean the literal `tokio::spawn`, and reading it that way is how this guard came to
/// report a clean tree while fifteen tests had exactly the property it exists to prevent.** They raise their
/// peers through a *fixture* — `NodeFleet::spawn`, `spawn_cell`, `spawn_pinned`, `spawn_self_certifying` —
/// so the `tokio::spawn` happens one frame down, inside the helper, and never appears in the test's own
/// body. Fourteen were in `fanos-sim/src/fabric.rs`, whose fleet of five real nodes then interleaved on one
/// thread; one of them spent a 240 s convergence budget and failed the gate as an *uninterpretable* red,
/// which cost more to diagnose than the change it was accusing.
///
/// So the predicate is any `spawn`-shaped call, not one spelling of it. That is deliberately broader than
/// the property: a test that names `spawn` without creating a task pays one attribute, which is cheap, while
/// the alternative — a list of fixtures known to spawn — is a list of exemptions wearing a different hat,
/// and would go stale the first time a fixture is renamed.
///
/// **`worker_threads` is not checked here, and two is not the answer.** Two is the smallest count that makes
/// concurrency *possible*, which is a different property from making a race *observable* — the only
/// measurement in this tree says so directly: `fanos-quic/tests/proteus.rs` records "two workers see it 3
/// times in 8 where four see it 8 of 8". The conversions therefore use four. Reading "two is enough to
/// interleave" as a licence to halve them is the mistake this paragraph exists to stop; it was very nearly
/// made here, reasoning from the minimum that satisfies the definition instead of from the number that was
/// measured against the purpose.
#[test]
fn a_test_that_spawns_a_peer_does_not_run_on_a_current_thread_runtime() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    // **The scanner must not count itself.** This file quotes both `#[tokio::test` and `tokio::spawn` in the
    // text above, and the first run of this guard duly reported its own doc comment as an offender. Excluded
    // by `file!()` rather than by name, so the exclusion cannot drift onto some other file and cannot be
    // widened into a list — a list of exempt files is the hole, not the fix.
    let myself = root.join(file!()).canonicalize().ok();
    let mut offenders = Vec::new();
    let mut async_tests = 0usize;
    let mut files = 0usize;

    {
        for file in corpus() {
            if file.path.canonicalize().ok() == myself {
                continue;
            }
            let src = &file.text;
            if !src.contains("#[tokio::test") {
                continue;
            }
            files += 1;
                // Split on the attribute so each test's own body is examined, not the file's. A file-level
                // grep would clear a file that has one `spawn` in production code, which is most of them.
                for chunk in src.split("#[tokio::test").skip(1) {
                    async_tests += 1;
                    let (attr, body) = chunk.split_once('\n').unwrap_or((chunk, ""));
                    if attr.contains("multi_thread") {
                        continue;
                    }
                    let body = &body[..body.len().min(4000)];
                    // Any `spawn`-shaped call, per the paragraph above: `tokio::spawn`, `NodeFleet::spawn`,
                    // `spawn_cell(`, `spawn_self_certifying::<F>(`. Matching the bare word would also catch
                    // it inside a comment or a string, so the call shape is required — an identifier ending
                    // in `spawn`, optionally with a turbofish, followed by `(`.
                    let spawns = body.split("spawn").skip(1).any(|after| {
                        let rest = after.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_');
                        let rest = rest.strip_prefix("::<").map_or(rest, |t| {
                            t.split_once('>').map_or(t, |(_, tail)| tail.trim_start_matches("::"))
                        });
                        rest.starts_with('(')
                    });
                    if spawns {
                        let name = body
                            .split("async fn ")
                            .nth(1)
                            .and_then(|s| s.split('(').next())
                            .unwrap_or("<unnamed>");
                        offenders.push(format!("{}::{name}", file.rel));
                    }
                }
        }
    }

    // A scan that examined nothing is a pass by accident. The FILE floor is gone: the corpus derives its own
    // (every crate must contribute), so a count here would be a second, weaker claim about the same walk. The
    // test-count floor stays, because it is about the SPLIT rather than the walk (#253).
    assert!(files > 0, "the walk found no file with an async test; the scan is broken, not the tree");
    assert!(async_tests >= 100, "only {async_tests} async tests examined; the split is broken");
    assert!(
        offenders.is_empty(),
        "these tests spawn a peer on a current-thread runtime, where it cannot run concurrently \
         — give them `#[tokio::test(flavor = \"multi_thread\", worker_threads = N)]` (#201):\n  {}",
        offenders.join("\n  ")
    );
}

/// The types a literal must never reach: **key material**.
///
/// Keyed on the *type*, not on the constructor, and that distinction is the whole guard. `from_seed` has 85
/// call sites in production and a scan on the name alone would report all of them — the unreadable-first-run
/// failure #168's inflated 19-of-25 warned about. More to the point, most of those literals are **required**:
/// a `HashParams::from_seed(b"FANOS-obolos-v1/nullifier")` is a public common reference string, and a CRS
/// that is not a reproducible nothing-up-my-sleeve constant is itself the defect. So the noise and the signal
/// are not distinguished by the call — they are distinguished by what is being built.
///
/// The survey that produced this list, run before the guard was written: of the literal-argument calls in
/// production, most were CRS values and domain separators (`b"FANOS-obolos-v1/nullifier"` and siblings), two
/// were placeholders overwritten before use beside `Vec::new()`, one was a public network name — and exactly
/// two touched key material, both in `demo()`, both now justified in place.
///
/// **The counts are deliberately not quoted here.** That survey was a separate script with its own file
/// walk, and a number from one scan pasted into the doc of another is a claim about the wrong instrument.
/// The live figures travel with the failure message below, where they are measured by the code that reports
/// them.
const SECRET_TYPES: [&str; 5] =
    ["VrfSecret", "SeedRng", "HybridKemSecret", "EdSigningKey", "SigningKey"];

/// The marker a call site uses to declare a literal seed deliberate, with its reason **at the code**.
///
/// Not a path list in this file. A list here would let the justification rot away from the thing it
/// justifies, and it would make the exemption invisible to anyone reading the call — which is precisely how
/// a "temporary" fixed key survives into a release. The scanner counts markers, so an exemption that stops
/// being needed shows up as a marker with no call beneath it.
const JUSTIFIED: &str = "literal-seed-ok:";

/// **A secret key built from a literal is catastrophic, silent, and mechanically detectable** (#203).
///
/// Catastrophic because every node that ships the constant shares one identity — coordinates, VRF proofs and
/// signatures all collapse. Silent because nothing fails: the key is well-formed, the handshake completes,
/// and the network works right up until two nodes meet. Detectable because the literal is *right there in the
/// source*, which is what makes the absence of a guard worth fixing rather than worth arguing about.
///
/// This is the one class of this kind the tree did not guard. It guards five others — crate reachability,
/// unwired public capability, workspace membership, undocumented constants, single-threaded async tests —
/// and each exists because the defect it names is invisible to review at the moment it is introduced. So does
/// this one.
///
/// **What it does not claim.** It sees literals, not weakness. A seed read from a world-readable file, or
/// derived from a hostname, is just as fatal and completely invisible here. This closes the floor: the state
/// in which the key is a constant in the binary.
#[test]
fn no_key_material_is_built_from_a_literal() {
    let literal_arg = regex_literal_arg();
    let (mut examined, mut calls, mut justified) = (0usize, 0usize, 0usize);
    let mut offenders = Vec::new();
    // The corpus reads; a file it could not open is fatal there rather than an empty `text` here, which is
    // what `unwrap_or_default` used to turn an unreadable file into — zero key sites, silently (#253).
    for file in corpus().into_iter().filter(RustSource::is_crate_src) {
        let ships = production_part(&file.text);
        examined += 1;
        let lines: Vec<&str> = ships.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("from_seed(") {
                continue;
            }
            calls += 1;
            if !SECRET_TYPES.iter().any(|t| line.contains(&format!("{t}::from_seed("))) {
                continue; // a CRS, a domain separator, a network name — a literal there is the requirement
            }
            if !literal_arg(line) {
                continue;
            }
            // The justification may sit on the call's own line or the one above it, because rustfmt splits
            // long calls and a marker that only works on one of the two shapes is a marker that will be lost.
            let prev = i.checked_sub(1).and_then(|j| lines.get(j)).copied().unwrap_or("");
            if line.contains(JUSTIFIED) || prev.contains(JUSTIFIED) {
                justified += 1;
                continue;
            }
            offenders.push(format!("{}:{}  {}", file.rel, i + 1, line.trim()));
        }
    }
    // **Floors first, ratchets last, and the order is load-bearing.** These two say the scan can see; a scan
    // that examined nothing reports "clean", which is the third guard in this file to carry that floor.
    assert!(examined >= 200, "only {examined} production parts examined; the walk is broken, not the tree");
    assert!(calls >= 40, "only {calls} `from_seed` calls seen ({examined} files); the scan cannot discriminate");
    assert!(
        offenders.is_empty(),
        "these build KEY MATERIAL from a literal — every node shipping the constant shares one identity, and \
         nothing fails until two of them meet. Derive it from OS entropy, or write `{JUSTIFIED} <reason>` \
         directly above the call if it is a demonstration that must be reproducible (#203). \
         [examined {examined} files, {calls} from_seed calls, {justified} justified]:\n  {}",
        offenders.join("\n  ")
    );
    // **After** the finding, deliberately. This is a ratchet on the known exemptions, not evidence the scan
    // works — and put before the assertion above it masked the two real offenders on this guard's first run,
    // reporting "the markers are gone" about a tree that had simply never had them. A floor proves the
    // instrument; a ratchet guards a specific fact; only the first may pre-empt a finding.
    assert!(
        justified >= 2,
        "the two justified demo seeds are gone ({justified} markers) — if `demo()` stopped needing fixed \
         identities that is good news, and this floor should be lowered deliberately rather than drift"
    );
}

/// `Type::from_seed(<literal>)` — an array literal, a byte string or a string, with or without a leading `&`.
///
/// Hand-rolled rather than a regex crate: this test binary has no such dependency and the grammar is small.
/// A literal argument is one that starts with `[`, `b"` or `"` after the paren.
fn regex_literal_arg() -> impl Fn(&str) -> bool {
    |line: &str| {
        let Some(after) = line.split_once("from_seed(").map(|(_, r)| r) else { return false };
        let arg = after.trim_start().trim_start_matches('&').trim_start();
        arg.starts_with('[') || arg.starts_with("b\"") || arg.starts_with('"')
    }
}

/// The crates whose **duplication is a security fact rather than a build detail**.
///
/// Two copies of `itertools` cost binary size. Two copies of `curve25519-dalek` are two implementations of
/// the same curve in one address space: two audit surfaces, and a fix landing in one does not reach the
/// other, because the node ships both. That is the distinction this list draws, and it is why the guard is
/// keyed on a named set rather than on "any duplicate" — a scan that flags all fifteen of today's duplicates
/// reads as noise and gets an allow-all exemption within a week.
///
/// Everything here either holds key material, produces randomness, or is the arithmetic underneath something
/// that does.
const CRYPTO_TCB: &[&str] = &[
    "curve25519-dalek",
    "fiat-crypto",
    "ed25519-dalek",
    "x25519-dalek",
    "ml-kem",
    "ml-dsa",
    "module-lattice",
    "vrf-r255",
    "getrandom",
    "rand_core",
    "rand",
    "sha2",
    "blake3",
    "digest",
    "crypto-common",
    "block-buffer",
    "zeroize",
];

/// The duplications that exist today, each naming **what forces it** (#217).
///
/// The list may shrink and never grow. An entry is not an excuse — it is a statement that someone looked and
/// found the cause, which is the only thing that makes the next reader able to remove it.
///
/// They are one migration, not ten accidents: the RustCrypto `0.10 → 0.11` and `rand_core 0.6 → 0.10`
/// transition, held open on the old side by `vrf-r255 0.1.0`, which `fanos-vrf` — the crate that produces a
/// node's IDENTITY — depends on. Measured from the lock:
///
/// ```text
/// curve25519-dalek 4.1.3 -> fiat-crypto 0.2.9, rand_core 0.6.4
/// curve25519-dalek 5.0.0 -> fiat-crypto 0.3.0, rand_core 0.10.1, digest 0.11.3
/// ```
///
/// Two parallel stacks, down to the formally-verified field arithmetic.
const TOLERATED_DUPLICATES: &[(&str, &str)] = &[
    ("curve25519-dalek", "4.1.3 under vrf-r255 0.1.0 and fanos-vrf alone (the identity path); 5.0.0 everywhere else"),
    ("fiat-crypto", "one copy per curve25519-dalek major — the field arithmetic follows the curve"),
    ("rand_core", "0.6 pinned by the curve25519-dalek 4 branch; 0.9 by rand 0.9; 0.10 by everything current"),
    ("rand", "0.9.5 reached through rand_core 0.9; 0.10.2 is what this workspace names"),
    ("getrandom", "0.2 under ring (rustls' backend); 0.3 under rand_core 0.9; 0.4 for fanos' own key paths"),
    ("sha2", "0.10 and 0.11 — the RustCrypto transition, same root as the rest"),
    ("digest", "as sha2"),
    ("crypto-common", "as sha2"),
    ("block-buffer", "as sha2"),
];

/// Every `[[package]]` in `Cargo.lock`, as `name -> the versions the build links`.
fn locked_versions() -> BTreeMap<String, BTreeSet<String>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let text = std::fs::read_to_string(root.join("Cargo.lock")).expect("the workspace lock file");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let (mut name, mut version) = (None, None);
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("name = \"").and_then(|s| s.strip_suffix('"')) {
            name = Some(v.to_owned());
            version = None;
        } else if let Some(v) = line.strip_prefix("version = \"").and_then(|s| s.strip_suffix('"')) {
            version = Some(v.to_owned());
        }
        if let (Some(n), Some(v)) = (name.as_ref(), version.take()) {
            out.entry(n.clone()).or_default().insert(v);
        }
    }
    out
}

/// Everything that depends on `name version`, read from the lock's dependency lists.
fn dependents_of(name: &str, version: &str) -> BTreeSet<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let text = std::fs::read_to_string(root.join("Cargo.lock")).expect("the workspace lock file");
    let want = format!("{name} {version}");
    let mut out = BTreeSet::new();
    for block in text.split("[[package]]").skip(1) {
        let Some(who) = block.lines().find_map(|l| l.strip_prefix("name = \"").and_then(|s| s.strip_suffix('"')))
        else {
            continue;
        };
        for dep in block.lines().skip_while(|l| !l.starts_with("dependencies")).skip(1) {
            let dep = dep.trim().trim_matches(|c| c == '"' || c == ',');
            if dep == "]" {
                break;
            }
            if dep == want {
                out.insert(who.to_owned());
            }
        }
    }
    out
}

/// **The one dependency holding the curve split open, and a tripwire for the day it stops** (#217).
///
/// The split is down to a single external pin: `vrf-r255 0.1.0` needs `curve25519-dalek 4`, and `fanos-vrf`
/// — the crate that produces a node's IDENTITY — needs `vrf-r255`. Everything else in the tree is on 5.
/// `fanos-incentives` was the third member of that set and moved off it once measured, which is how the set
/// got small enough to pin here.
///
/// **Why the pin stays rather than being replaced.** The surface is narrow — three newtypes
/// (`VrfSecret`, `VrfPublic`, `VrfProof`) over seven operations, and none of `fanos-vrf`'s other 4 300 lines
/// touch the dependency — so replacing it *looks* cheap. It is not the right trade: the crate's own header
/// says it uses "the vetted `vrf_r255` crate" deliberately, and hand-rolling ECVRF-RISTRETTO255-SHA512 to
/// win a version unification would swap a stated duplication for an unvetted implementation of the
/// primitive that decides who a node *is*. A duplication you can see beats a primitive you wrote yourself.
///
/// So this is the tripwire instead. The obligation is conditional — "unify when the upstream moves" — and a
/// conditional obligation with nothing watching its condition is one that comes true unnoticed. If
/// `vrf-r255` publishes against curve 5, or if a *fourth* crate joins the old branch, this set changes and
/// someone has to look.
///
/// Falsified by expecting a third name: the assertion prints the set actually locked.
#[test]
fn the_old_curve_branch_is_held_by_vrf_r255_alone_and_nothing_else_has_joined_it() {
    let old: BTreeSet<String> = dependents_of("curve25519-dalek", "4.1.3");
    let expected: BTreeSet<String> = ["fanos-vrf", "vrf-r255"].iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        old, expected,
        "the dependents of curve25519-dalek 4.1.3 changed. If the set SHRANK, vrf-r255 has moved and the \
         whole split can now collapse — take the 4.x pin out of the workspace and delete its row from \
         TOLERATED_DUPLICATES. If it GREW, a new crate joined the old branch: that is the thing this guard \
         exists to stop, and the fix is to move that crate rather than to widen this expectation."
    );
}

/// **The same tripwire on the RNG half of the split, and it was already tripped** (#210/#217).
///
/// `TOLERATED_DUPLICATES` explains `rand_core 0.6` as "pinned by the curve25519-dalek 4 branch". That sentence
/// is a claim about *who*, and the version-set guard above cannot check it — a crate can sit on the old line
/// for no reason at all and every existing assertion stays green. One did: `fanos-sim` carried a local
/// `rand_core = "0.6"` whose comment cited the dalek ecosystem, while its only use was a test generator
/// feeding `fanos-incentives`. It had followed that crate onto the old line and stayed after it left, and
/// what surfaced it was not this guard but a **build break** — `--workspace --all-targets` failing once
/// `fanos-incentives` wanted `Rng` from 0.10. A dependency-set claim that only a compile error can falsify is
/// the thing this exists to convert into a test.
#[test]
fn the_old_rng_line_is_held_by_the_curve_branch_alone() {
    let old: BTreeSet<String> = dependents_of("rand_core", "0.6.4");
    let expected: BTreeSet<String> =
        ["curve25519-dalek", "fanos-vrf", "vrf-r255"].iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        old, expected,
        "the dependents of rand_core 0.6.4 changed. If it SHRANK, the curve branch has moved and the \
         `rand_core` row in TOLERATED_DUPLICATES can go with it. If it GREW, a crate joined the old RNG line \
         — check whether it has the dalek reason at all, because the last one to do this did not, and the \
         fix is to move it rather than to widen this expectation."
    );
}

/// Which `getrandom` each package reaches, read from the lock's dependency lists.
///
/// A version set alone cannot answer the question that matters here. `TOLERATED_DUPLICATES` says "0.4 for
/// fanos' own key paths" — a true sentence today and a *claim about who depends on what*, which the
/// version-set guard never touches. A new dependency could move the identity path onto ring's copy and every
/// existing assertion would stay green.
fn getrandom_reached_by(pkg: &str) -> BTreeSet<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let text = std::fs::read_to_string(root.join("Cargo.lock")).expect("the workspace lock file");
    let mut out = BTreeSet::new();
    for block in text.split("[[package]]") {
        let Some(name) = block.lines().find_map(|l| l.strip_prefix("name = \"").and_then(|s| s.strip_suffix('"')))
        else {
            continue;
        };
        if name != pkg {
            continue;
        }
        // The lock writes a dependency as `"name"` when the name is unambiguous and `"name version"` when it
        // is not — so a package reaching a DUPLICATED crate always names the version, which is exactly the
        // case this reads. A bare `"getrandom"` would mean the duplication had collapsed.
        for dep in block.lines().skip_while(|l| !l.starts_with("dependencies")).skip(1) {
            let dep = dep.trim().trim_matches(|c| c == '"' || c == ',');
            if dep == "]" {
                break;
            }
            if let Some(rest) = dep.strip_prefix("getrandom") {
                out.insert(rest.trim().to_owned());
            }
        }
    }
    out
}

/// **The identity path's entropy comes from ONE copy, and the lock says which** (#217).
///
/// Three `getrandom` majors are linked into one node — 0.2 under `ring` (rustls' backend), 0.3 under
/// `rand_core 0.9`, 0.4 for this workspace's own crates. That is tolerated and its cause is stated. What was
/// only *prose* is the part that matters: that a FANOS crate generating key material reaches the 0.4 copy
/// rather than the TLS stack's. Each has its own backend selection and its own fallback, so "which one
/// produced this key" had three possible answers and nothing in the tree checked the answer.
///
/// Falsified by expecting `0.2.17` instead: the assertion names the version actually reached.
#[test]
fn the_key_generating_crates_reach_exactly_one_getrandom_and_it_is_the_workspace_one() {
    // The crates that draw OS entropy for something a peer will trust: the node's identity and seat, the
    // C ABI that embeds it, and the driver that draws PROTEUS datagram nonces.
    for pkg in ["fanos-node", "fanos-ffi", "fanos-quic"] {
        let reached = getrandom_reached_by(pkg);
        assert_eq!(
            reached.len(),
            1,
            "{pkg} reaches {} getrandom copies ({reached:?}); a key path must have ONE source of OS entropy, \
             because each copy selects its backend and its fallback independently",
            reached.len()
        );
        let got = reached.iter().next().expect("checked non-empty above").clone();
        assert!(
            got.starts_with("0.4"),
            "{pkg} reaches getrandom {got}, not the 0.4 line this workspace names. If that is deliberate, \
             TOLERATED_DUPLICATES must say so — today it claims 0.4 serves fanos' own key paths."
        );
    }
}

/// **No cryptographic crate is linked at two versions without someone having said why** (#206, #217).
///
/// The supply-chain gap this closes is narrow and real. There is no `deny.toml`, and no `cargo audit`,
/// `cargo deny` or `cargo vet` in any of the five CI jobs — measured, not assumed. The `reproducible` job
/// makes that look covered and does not cover it: reproducibility proves you built what the lockfile says,
/// never that the lockfile is safe.
///
/// A full advisory pipeline needs a tool, a network fetch and a database. **This needs none of them**, runs
/// in the gate that already exists, and catches the one class that a duplicate-blind advisory scan would
/// miss anyway: a second copy of the curve arriving quietly under a new dependency, so that the node ships
/// two implementations and a patched advisory only reaches one.
///
/// It is deliberately not "no duplicates at all". Today the lock has fifteen, five of which are ordinary
/// transition noise (`hashbrown`, `itertools`, `windows-sys`, `bit-vec`, `r-efi`) that nobody should be
/// asked to justify.
#[test]
fn no_cryptographic_crate_is_duplicated_without_a_stated_cause() {
    let locked = locked_versions();
    let declared: BTreeSet<&str> = TOLERATED_DUPLICATES.iter().map(|(c, _)| *c).collect();
    let duplicated: BTreeSet<&str> = CRYPTO_TCB
        .iter()
        .copied()
        .filter(|c| locked.get(*c).is_some_and(|v| v.len() > 1))
        .collect();
    let undeclared: Vec<String> = duplicated
        .difference(&declared)
        .map(|c| format!("{c}: {:?}", locked.get(*c).cloned().unwrap_or_default()))
        .collect();

    // Floors first: a lock this parser failed to read reports "clean", and this guard's whole value is that
    // it cannot.
    assert!(locked.len() >= 300, "parsed only {} packages from Cargo.lock; the parser is broken", locked.len());
    assert!(
        !duplicated.is_empty(),
        "no TCB crate looks duplicated at all, which contradicts the measurement this guard was written from \
         — the name list and the lock have drifted apart"
    );
    assert!(
        undeclared.is_empty(),
        "these cryptographic crates are linked at two or more versions and nothing says why. Two copies of a \
         curve, an RNG or a digest are two audit surfaces, and a fix to one does not reach the other. Find \
         what pulls each and add it to TOLERATED_DUPLICATES with the cause, or remove the second copy \
         (#206, #217). [parsed {} packages, {} TCB crates duplicated, {} declared]:\n  {}",
        locked.len(),
        duplicated.len(),
        declared.len(),
        undeclared.join("\n  ")
    );

    // A ratchet, after the finding: an entry that is no longer duplicated is a migration someone finished,
    // and leaving it here would let the next real one hide behind a stale excuse.
    let stale: Vec<&str> = declared
        .iter()
        .copied()
        // `is_none_or`, and the `None` arm is deliberate rather than incidental: a declared crate that is not
        // in the lock at all is not linked, so its entry is stale for the same reason as one that stopped
        // being duplicated. (Worth stating because this combinator GRANTS on absence, which is how it once
        // denied a whole bootstrap when the predicate was a verification instead of a staleness test.)
        .filter(|c| locked.get(*c).is_none_or(|v| v.len() <= 1))
        .collect();
    assert!(
        stale.is_empty(),
        "these are no longer duplicated — good news, and the entry must go so it cannot shelter the next \
         one: {stale:?}"
    );
}
