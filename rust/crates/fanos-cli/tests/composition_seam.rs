//! **Production and the simulator assemble a node's engine through one function.**
//!
//! Plan item I.3. The standing rule is that the simulator differs from production only in *transport*; it did
//! not. `Node::start` layered an overlay, an admission gate, a beacon, a mixnet router and a threshold service
//! into one engine, while `fanos_sim::spawn_cell` instantiated a bare `OverlayNode` — so the instrument built to
//! find composition defects was, by construction, blind to the layer they live in. Every defect the 2026-07-28
//! audit found was in that layer.
//!
//! ## Why this is a source check and not a behavioural one
//!
//! The first attempt asserted it at runtime: stand up a composed cell, crash a node, watch it localize the
//! fault. It passed — and it passed just as well with the simulator put back to a bare overlay, because a bare
//! overlay localizes that crash identically. The property is not "a composed cell behaves differently"; it is
//! "there is one assembly function and both callers use it", and that is a fact about the text.
//!
//! So this greps, and says so. A grep is a weak instrument used where it is exactly right: the claim is a
//! reachability claim over source, the same shape as `architecture.rs` and `frame_handling.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

/// Constructors that assemble a node engine. Seeing one outside `composition.rs` means a second assembly path
/// has appeared, which is how the two sides drifted in the first place.
///
/// Named WITHOUT a turbofish, and the lines are normalised (below) before matching, because the first version
/// of this list wrote `"OverlayNode::<F>::new"` — the *generic* spelling — and `line.contains` cannot match
/// that against `OverlayNode::<F2>::new`, which is how a shipped binary spells it. The guard was therefore
/// unable to fire on the one file that violated it, and `fanos validator` assembled a bare overlay
/// unnoticed (#168). A pattern that names a monomorphisation is a pattern that misses every other one.
const ENGINE_CONSTRUCTORS: &[&str] =
    &["OverlayNode::new", "OverlayBeaconNode::new", "CellNode::new", "ServiceNode::new"];

/// Strip a turbofish (`::<…>`) so `Type::<F2>::new` and `Type::new` compare equal.
///
/// Deliberately not a regex dependency for one transform: scan for `::<`, drop through the matching `>`,
/// counting nesting so `::<Foo<Bar>>::new` closes correctly.
fn without_turbofish(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find("::<") {
        out.push_str(&rest[..at]);
        let mut depth = 0i32;
        let after = &rest[at + 2..];
        let mut end = None;
        for (i, c) in after.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(e) = end else {
            // Unterminated `::<` — a line we cannot parse. Keep the tail so the caller still sees the rest
            // of it rather than silently dropping a line that might hold a violation.
            rest = after;
            break;
        };
        rest = &after[e..];
    }
    out.push_str(rest);
    out
}

/// Crates that must go through `compose_engine` rather than assembling their own.
const MUST_COMPOSE: &[&str] = &["fanos-sim", "fanos-node"];

/// Files allowed to assemble directly, with the reason.
///
/// The boundary is what is being built. `CellComposition` expresses a node's **roles** — relay, beacon,
/// service, the price it charges — and folding every `OverlayNode` builder into it would turn it into a mirror
/// of that type rather than a statement about what a node *is*. These two build **topology fixtures**: gateways
/// wired across cells, hierarchical peers pinned by hand, to exercise routing between cells. That is a
/// different thing from standing up a node, and production has no such construction to share with them.
///
/// The claim this test defends is narrower and exact: *when the simulator stands up a cell, it stands up
/// production's engine.* A new entry here would need the same argument made again.
/// `unified.rs` came OFF this list in #180 and the reason is worth keeping: its row argued it must hand-wire
/// because a gateway needs hierarchical peers and `CellComposition` had no field for them. True at the time,
/// and the fix was to add the field rather than to keep the excuse — an exemption whose premise is "the
/// composition cannot express this" is a feature request wearing a carve-out's clothes.
const TOPOLOGY_FIXTURES: &[(&str, &str)] = &[(
    "hierarchy.rs",
    "a multi-level routing fixture: gateway roots and sub-cell descent paths pinned per node, to exercise \
     inter-cell routing rather than a node's role composition",
)];

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Every `.rs` file of `crate_name`, excluding the file that is allowed to assemble.
fn sources_of(crate_name: &str) -> Vec<(PathBuf, String)> {
    let root = workspace().join("crates").join(crate_name).join("src");
    let allowed = root.join("composition.rs");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path != allowed
                && !path
                    .file_name()
                    .is_some_and(|n| TOPOLOGY_FIXTURES.iter().any(|(f, _)| std::ffi::OsStr::new(f) == n))
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push((path, text));
            }
        }
    }
    out
}

/// Lines that are neither comments nor inside a `#[cfg(test)]` module — a test may build whatever it needs to
/// exercise one layer in isolation, which is a legitimate thing to do and not a second production path.
fn shipping_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_tests = false;
    let mut depth = 0i32;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("#[cfg(test)]") {
            in_tests = true;
            depth = 0;
        }
        if in_tests {
            depth += i32::try_from(t.matches('{').count()).unwrap_or(0);
            depth -= i32::try_from(t.matches('}').count()).unwrap_or(0);
            if depth <= 0 && t.contains('}') {
                in_tests = false;
            }
            continue;
        }
        if !t.starts_with("//") {
            out.push(line);
        }
    }
    out
}

#[test]
fn only_the_composition_module_assembles_a_node_engine() {
    let mut offenders = Vec::new();
    for crate_name in MUST_COMPOSE {
        for (path, text) in sources_of(crate_name) {
            for line in shipping_lines(&text) {
                let normalised = without_turbofish(line);
                for ctor in ENGINE_CONSTRUCTORS {
                    if normalised.contains(ctor) {
                        offenders.push(format!("{}: {}", path.display(), line.trim()));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these assemble a node engine outside `composition.rs`:\n{}\n\n\
         A second assembly path is how production and the simulator drifted apart in the first place — one \
         grew an admission gate, a beacon, a mixnet router and a threshold service while the other stayed a \
         bare overlay, and the instrument meant to catch that could not see it. Call `compose_engine`.",
        offenders.join("\n")
    );
}

#[test]
fn the_simulator_reaches_the_composition_function() {
    // The other half: no second path *and* the one path is actually taken. Without this, deleting the call
    // entirely would satisfy the check above.
    let calls = sources_of("fanos-sim")
        .iter()
        .any(|(_, text)| shipping_lines(text).iter().any(|l| l.contains("compose_engine")));
    assert!(calls, "the simulator no longer calls `compose_engine` — it has stopped running production's engine");
}

/// Fields of `CellComposition` that **no deployment ever sets** — `Node::start` pins all three to their empty
/// value with a comment saying that their absence is what a deployment means.
///
/// They exist for one reason: so a simulator scenario need not assemble its own engine to get them. A branch
/// like that with no scenario taking it is not merely untested, it is *evidence the migration it was added for
/// never happened* — which is exactly what #180 found. `cell_members`' own doc said it existed "because two
/// simulator scenarios needed it and were assembling their own engines to get it", and neither scenario ever
/// moved onto it, because each also wired hierarchical peers and there was no field for those.
const SCENARIO_BRANCHES: &[&str] = &["cell_members", "hier_path", "hier_peers"];

/// Every `.rs` file under `crates/fanos-sim` — **`src/` and `tests/` both**.
///
/// `sources_of` deliberately walks only `src/`, which is right for the rule it serves. It is wrong for these
/// two, because a simulator's product IS its `tests/` directory: that is where the scenarios live, and a
/// scenario standing up a bare cell is the defect this file exists to prevent, not a unit test exercising one
/// layer in isolation.
fn all_sim_files() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![
        workspace().join("crates/fanos-sim/src"),
        workspace().join("crates/fanos-sim/tests"),
    ];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push((path, text));
            }
        }
    }
    out
}

/// Lines that are not comments. Unlike [`shipping_lines`] this keeps `#[cfg(test)]` modules, because in
/// `fanos-sim` those hold scenarios rather than unit tests of one layer.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with("//"))
}

/// Seating a node in a cell roster goes through `compose_engine`, in `tests/` as much as in `src/`.
///
/// `with_cell_members` is the exact marker that a scenario is standing up a **cell** — its doc says it "seats a
/// node at a position in a provisioned 7-member roster". That is not a unit test of one layer, it is the thing
/// the seam rule is about, and four such sites called the raw builder while three of them sat in a directory
/// `sources_of` has never read (#180). Those cells therefore ran with no admission gate, no beacon, no mixnet
/// and no service, which is precisely the drift this file was written to make impossible.
#[test]
fn no_simulator_scenario_seats_a_cell_by_hand() {
    let files = all_sim_files();
    assert!(files.len() > 20, "the walk found only {} files — it is not reaching the scenarios", files.len());

    let offenders: Vec<String> = files
        .iter()
        .filter(|(_, text)| code_lines(text).any(|l| l.contains("with_cell_members")))
        .map(|(p, _)| p.display().to_string())
        .collect();
    assert!(
        offenders.is_empty(),
        "these seat a cell roster with the raw builder instead of `CellComposition::cell_members`:\n{}\n\n\
         A cell the simulator stands up must be the engine a deployment runs.",
        offenders.join("\n")
    );
}

/// The reverse direction, and the one that would have caught #180 on the commit that created it.
///
/// A scenario-only branch with no scenario is a field added for a migration that never happened. Asserting the
/// absence above is not enough on its own: deleting every cell scenario would satisfy it perfectly.
#[test]
fn every_scenario_only_branch_of_the_composition_is_taken_by_a_scenario() {
    let files = all_sim_files();
    for field in SCENARIO_BRANCHES {
        // The three ways a scenario sets one. `vec!` is listed because `hier_peers` is a `Vec`, not an
        // `Option`, so a matcher that only knew `Some` would have reported it unset while a scenario sets it —
        // and the fix for a branch reported unset is to DELETE it. A scan's blind spot in this direction does
        // not merely miss a defect, it invents one.
        let set = |l: &str| {
            l.contains(&format!("{field}: Some"))
                || l.contains(&format!("{field}: vec!"))
                || l.contains(&format!(".{field} ="))
        };
        let takers: Vec<String> = files
            .iter()
            .filter(|(_, text)| code_lines(text).any(set))
            .map(|(p, _)| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
            .collect();
        assert!(
            !takers.is_empty(),
            "`CellComposition::{field}` is a branch of `compose_engine` that no deployment sets and now no \
             scenario sets either, so nothing in the workspace can reach it. Either a scenario takes it or \
             the field and its branch come out — a parameter kept for a migration nobody performed is how \
             `cell_members` sat unreachable from the day it was added (#180)."
        );
    }
}

/// A declared topology fixture must still exist, and must still be assembling something.
///
/// The reverse direction, so the exemption list cannot outlive its reason: a file that stopped hand-assembling
/// comes off the list, or the list becomes a place where a stale excuse sits unexamined.
#[test]
fn every_declared_fixture_is_still_one() {
    for (file, reason) in TOPOLOGY_FIXTURES {
        let path = workspace().join("crates/fanos-sim/src").join(file);
        assert!(path.exists(), "`{file}` is exempted but no longer exists — delete its row");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            // Normalised, exactly as the forward check is. Changing the constants to the turbofish-free
            // spelling while leaving one of the two comparison sites raw is what made this test red: the
            // fixtures write `OverlayNode::<F>::new`, which no longer matches `OverlayNode::new` literally.
            ENGINE_CONSTRUCTORS.iter().any(|c| without_turbofish(&text).contains(c)),
            "`{file}` is exempted but assembles nothing — delete its row"
        );
        assert!(reason.len() > 60, "`{file}`'s reason is too short to be one");
    }
}
