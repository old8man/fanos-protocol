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
const TOPOLOGY_FIXTURES: &[(&str, &str)] = &[
    (
        "hierarchy.rs",
        "a multi-level routing fixture: gateway roots and sub-cell descent paths pinned per node, to exercise \
         inter-cell routing rather than a node's role composition",
    ),
    (
        "unified.rs",
        "the unified-topology fixture: one overlay root per cell plus hand-wired hierarchical peers between \
         them, for the same reason",
    ),
];

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
