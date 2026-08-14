//! **Every directory publish reports whether it landed** (#106) — a source ratchet plus the label table.
//!
//! All ten `publish_*` functions returned their `bool` faithfully; every per-epoch republish loop dropped it.
//! A node whose writes were failing kept running and believing otherwise, while it fell out of the mixdir (so
//! no circuit could route through it), the capability roster (so no role could be assigned to it), the exit
//! directory and the load balancer's input — all silently.
//!
//! The recorder lives *inside* each publisher rather than at the ten callers, so the eleventh caller cannot
//! forget it. What the eleventh *publisher* could forget is calling it at all, which is what this ratchet is
//! for: a `put_ephemeral` in this crate that no `note_publish` follows is a new silent directory.


use fanos_node::{Directory, Gate};

/// Read every `.rs` under `crates/fanos-node/src`, **truncated at its test module**, as `(path, text)`.
///
/// The cut matters and was learned by the guard firing on itself. `#115`'s end-to-end test publishes forged
/// bytes at a real slot with a bare `put_ephemeral` — deliberately, because placing a record an attacker
/// would place is the whole point, and reporting it would be reporting on behalf of a node that never sent
/// it. A production publisher and a test placing a record are different acts that happen to share a call,
/// so the scan must distinguish them by where they live.
///
/// A false positive is the right direction for this to fail in, and it did.
fn sources() -> Vec<(String, String)> {
    // The shared corpus (#253) and the shared slice (#252): one walk that reports its coverage, and one
    // definition of "shipping code" — the old form here cut at the first `#[cfg(test)]` and lost anything
    // below it, and skipped in silence any file it could not open.
    let out: Vec<(String, String)> = fanos_testkit::corpus::rust_sources()
        .into_iter()
        .filter(|s| s.krate == "fanos-node" && s.is_crate_src())
        .map(|s| (s.rel, fanos_testkit::source::production_part(&s.text)))
        .collect();
    assert!(!out.is_empty(), "fanos-node contributed no source — the filter, not the crate, is empty");
    out
}

/// Every `put_ephemeral` in this crate is followed by a `note_publish` in the same function.
///
/// Approximated by "within the next 6 lines", which is what the shape allows: each site is
/// `let landed = client.put_ephemeral(..).await;` then the report. The window is deliberately tight — a
/// generous one would pass on a `note_publish` belonging to a different publisher further down the file.
#[test]
fn every_directory_publish_in_this_crate_reports_whether_it_landed() {
    let mut sites = 0usize;
    let mut silent: Vec<String> = Vec::new();
    for (path, text) in sources() {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            // The definition itself, and doc comments naming it, are not call sites.
            if !line.contains(".put_ephemeral(") || line.trim_start().starts_with("//") {
                continue;
            }
            sites += 1;
            let window = lines.get(i..lines.len().min(i + 7)).unwrap_or_default().join("\n");
            if !window.contains("note_publish") {
                silent.push(format!("{path}:{}", i + 1));
            }
        }
    }
    // The denominator is a claim about the scan before it is a claim about the code: a regex that matched
    // nothing would report "no silent publishers" and mean "I did not look".
    assert!(sites >= 10, "the scan found only {sites} publish sites — it is not looking where it thinks");
    assert!(silent.is_empty(), "these directory publishes drop their outcome silently: {silent:#?}");
}

/// The tag an operator reads is stable and unambiguous.
///
/// Written out in `Directory::tag` rather than taken from variant order, so that reordering the enum — a
/// thing a later edit does without thinking — cannot renumber a counter an operator is watching.
#[test]
fn directory_tags_and_names_are_unique_and_pinned() {
    let mut tags: Vec<u64> = Directory::ALL.iter().map(|d| d.tag()).collect();
    let mut names: Vec<&str> = Directory::ALL.iter().map(|d| d.name()).collect();
    let (n_tags, n_names) = (tags.len(), names.len());
    tags.sort_unstable();
    tags.dedup();
    names.sort_unstable();
    names.dedup();
    assert_eq!(tags.len(), n_tags, "two directories share a tag, so their counters would merge");
    assert_eq!(names.len(), n_names, "two directories share a name");
    // Pinned values, not just distinct ones: an operator's dashboard reads these numbers.
    assert_eq!(Directory::MixKey.tag(), 0);
    assert_eq!(Directory::Health.tag(), 7);
    assert_eq!(Directory::Diagnosis.tag(), 8);
    // The tenth, and the deliberation this pin exists to force actually happened: #344 gave the hidden-service
    // descriptor a per-epoch republish loop, which made it a directory in the sense this list means — a slot
    // a node keeps current and reports the outcome of. It reddened here on the first run, which is the guard
    // working, not breaking.
    assert_eq!(Directory::ServiceDescriptor.tag(), 9);
    // Completeness is the compiler's job now (`const _` beside `impl Directory`): a variant missing from
    // `ALL` does not build. What this count still buys is *deliberation* — adding a directory changes a
    // stated number, so it cannot happen as a side effect of an unrelated change.
    assert_eq!(Directory::ALL.len(), 10, "the directory count changed; confirm the addition was intended");
}

/// The gate an operator reads is stable and unambiguous, for the same reason a directory's tag is (#109).
#[test]
fn gate_tags_and_names_are_unique_and_pinned() {
    let mut tags: Vec<u64> = Gate::ALL.iter().map(|g| g.tag()).collect();
    let mut names: Vec<&str> = Gate::ALL.iter().map(|g| g.name()).collect();
    let (n_tags, n_names) = (tags.len(), names.len());
    tags.sort_unstable();
    tags.dedup();
    names.sort_unstable();
    names.dedup();
    assert_eq!(tags.len(), n_tags, "two gates share a tag, so two different attacks would merge into one count");
    assert_eq!(names.len(), n_names, "two gates share a name");
    assert_eq!(Gate::ReshareSubShare.tag(), 0);
    assert_eq!(Gate::BoundCapabilityAdvertisement.tag(), 3);
    assert_eq!(Gate::IngressShare.tag(), 4);
    assert_eq!(Gate::ALL.len(), 5, "the gate count changed; confirm the addition was intended");
}

/// A `Directory` tag and a `Gate` tag are read under **different** stations, so they may collide freely —
/// pinned here so a later reader does not "fix" a collision that is not one, and so the two tables stay
/// separately meaningful rather than drifting into one shared numbering nobody maintains.
#[test]
fn directory_and_gate_tags_live_in_separate_namespaces() {
    let shared: Vec<u64> =
        Directory::ALL.iter().map(|d| d.tag()).filter(|t| Gate::ALL.iter().any(|g| g.tag() == *t)).collect();
    assert!(!shared.is_empty(), "the two tables overlap by construction; if they stopped, this test is stale");
}
