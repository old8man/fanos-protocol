//! **`gate.sh` and `ci.yml` are two independent statements of what gets checked, and this keeps them in
//! step** (#303).
//!
//! `ci.yml` does not run `gate.sh` — it mentions it once, in a comment, and re-lists every cargo invocation
//! itself. So a check can exist in one and not the other, and both directions cost something: a check only
//! in CI cannot be run before pushing, which is what the gate is for; a check only in the gate does not
//! block a merge, which is what CI is for.
//!
//! The failure this guard was written for is not hypothetical. #302 added `test-vpn` and `test-sysinfo` to
//! `gate.sh` after measuring that two tests were compiled by clippy and never executed — and left the same
//! hole open in `ci.yml` for two commits. The fix to a half-applied rule was itself half-applied.
//!
//! # Why it compares (subcommand, packages, features) and nothing finer
//!
//! Equality of the two files is the wrong property: they legitimately differ. `ci.yml` runs `cargo doc`,
//! installs a toolchain and splits work across runners; `gate.sh` groups into named phases and prints their
//! cost. Counting lines would compare 24 against 33 and mean nothing.
//!
//! What must agree is **coverage**, so the comparison keeps only what decides coverage — which cargo
//! subcommand, over which packages, with which features — and deliberately drops `--no-fail-fast`,
//! `-- -D warnings`, `--all-targets` and every other flag that changes how a check reports rather than what
//! it covers. A guard that fails when someone reorders two flags is a formatting check wearing a coverage
//! guard's name, and the first person it inconveniences will learn to route around it.

#![allow(clippy::expect_used, reason = "a guard that cannot read the two files it compares has nothing to say, and a panic names which one")]

use std::collections::BTreeSet;
use std::path::PathBuf;

/// One check's coverage: the subcommand, the packages it selects, and the features it enables. Flags that
/// affect reporting rather than reach are not part of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Coverage {
    cmd: String,
    packages: Vec<String>,
    features: Vec<String>,
    /// Kept because it is what separates the fast checks from CI's heavy `--ignored` jobs, which the local
    /// gate deliberately does not replicate — see [`ci_only`].
    release: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().expect("repo root")
}

/// Pull the coverage triple out of one `cargo …` command line. `None` for invocations that are not checks
/// (`cargo doc`, `cargo fmt`, toolchain plumbing) — these are named in the exceptions below.
fn coverage_of(line: &str) -> Option<Coverage> {
    let line = line.trim();
    let rest = line.strip_prefix("cargo ")?;
    let mut words = rest.split_whitespace();
    let cmd = words.next()?.to_owned();
    if !matches!(cmd.as_str(), "test" | "clippy" | "check") {
        return None;
    }

    let mut packages = BTreeSet::new();
    let mut features = BTreeSet::new();
    let mut release = false;
    let mut words = words.peekable();
    while let Some(w) = words.next() {
        match w {
            "--" => break, // everything past `--` goes to the harness or the lint driver, not to coverage
            "-p" | "--package" => {
                if let Some(p) = words.next() {
                    packages.insert(p.to_owned());
                }
            }
            "--features" => {
                if let Some(f) = words.next() {
                    // `--features "alloc libm"` and `--features a,b` name the same kind of thing.
                    for one in f.trim_matches('"').split([',', ' ']).filter(|s| !s.is_empty()) {
                        features.insert(one.to_owned());
                    }
                }
            }
            "--workspace" => {
                packages.insert("<workspace>".to_owned());
            }
            "--exclude" => {
                if let Some(p) = words.next() {
                    packages.insert(format!("!{p}"));
                }
            }
            "--no-default-features" => {
                features.insert("<no-default>".to_owned());
            }
            "--release" => release = true,
            _ => {}
        }
    }
    Some(Coverage {
        cmd,
        packages: packages.into_iter().collect(),
        features: features.into_iter().collect(),
        release,
    })
}

fn gate_coverage() -> BTreeSet<Coverage> {
    let text = std::fs::read_to_string(repo_root().join("gate.sh")).expect("gate.sh");
    text.lines()
        .filter_map(|l| {
            // `run <name> <cargo-args…>` — the phase name is not part of the command.
            let rest = l.trim().strip_prefix("run ")?;
            let args = rest.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
            coverage_of(&format!("cargo {args}"))
        })
        .collect()
}

fn ci_coverage() -> BTreeSet<Coverage> {
    let text =
        std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
    text.lines()
        .filter_map(|l| {
            let t = l.trim();
            let t = t.strip_prefix("run: ").unwrap_or(t);
            coverage_of(t)
        })
        .collect()
}

/// **Coverage is a subsumption relation, not an equality one — and the guard's first run proved it.**
///
/// It fired on `cargo test -p fanos-cli`, which `gate.sh` runs as its own fast phase and `ci.yml` does not
/// name. Nothing was missing: CI's `cargo test --workspace` runs that crate's tests, so the coverage is
/// there under a different selector. Comparing sets treated `<workspace>` and `fanos-cli` as unrelated,
/// which is exactly the brittle-normalisation failure this guard was written to avoid — caught by the guard
/// itself before it could be committed as a rule.
///
/// So `need` is satisfied by `have` when the subcommand and features match and `have` either names the same
/// packages or covers the whole workspace without excluding what `need` selects.
fn covers(have: &Coverage, need: &Coverage) -> bool {
    if have.cmd != need.cmd || have.features != need.features {
        return false;
    }
    if have.packages == need.packages {
        return true;
    }
    let whole_workspace = have.packages.iter().any(|p| p == "<workspace>");
    if !whole_workspace {
        return false;
    }
    // `--workspace --exclude X` does not cover a check that selects X.
    !need
        .packages
        .iter()
        .any(|p| have.packages.iter().any(|h| h.strip_prefix('!') == Some(p.as_str())))
}

fn covered_by_any(need: &Coverage, pool: &BTreeSet<Coverage>) -> bool {
    pool.iter().any(|have| covers(have, need))
}

/// **Checks that live in CI alone, on purpose — and this list is APPLIED, not printed.**
///
/// The first version of this guard only put the list in the failure message. An exception list that
/// nothing consults is the same defect as a share nobody sums: it looks like a decision and enforces
/// nothing. The guard found that in itself on its second run.
///
/// `cargo doc` never appears here because [`coverage_of`] does not classify it as a check at all.
fn ci_only(c: &Coverage) -> Option<&'static str> {
    if c.release {
        return Some(
            "CI's heavy jobs run the `#[ignore]`d suites in release mode; replicating them in the local \
             gate would cost far more than a pre-push check is worth, and the gate states its own cost",
        );
    }
    None
}

/// **Every check reaches both files, in both directions.**
///
/// Falsification, and all three parts are required for this to be a coverage guard rather than a spelling
/// one: deleting a phase from `gate.sh` must redden it; deleting the matching step from `ci.yml` must
/// redden it; and RENAMING a phase while leaving its command alone must NOT.
#[test]
fn every_check_the_gate_runs_is_also_a_ci_step_and_the_reverse() {
    let gate = gate_coverage();
    let ci = ci_coverage();

    // Assert the scan before the finding: a parser that reads nothing agrees with everything.
    assert!(
        gate.len() >= 15,
        "gate.sh parsed to only {} checks, which is fewer than it plainly has — the parser broke before \
         the comparison could mean anything",
        gate.len()
    );
    assert!(
        ci.len() >= 8,
        "ci.yml parsed to only {} checks — same problem, and a guard that compares two empty sets passes \
         for the wrong reason",
        ci.len()
    );

    let only_gate: Vec<_> = gate.iter().filter(|g| !covered_by_any(g, &ci)).collect();
    let only_ci: Vec<_> =
        ci.iter().filter(|c| !covered_by_any(c, &gate) && ci_only(c).is_none()).collect();

    assert!(
        only_gate.is_empty(),
        "these checks run locally and do NOT gate a merge — someone can push past them:\n{only_gate:#?}\n\
         nothing here is exempt — a gate phase with no CI step is always a hole"
    );
    assert!(
        only_ci.is_empty(),
        "these checks gate a merge and cannot be run before pushing, which is what gate.sh exists for:\n\
         {only_ci:#?}",
    );
}
