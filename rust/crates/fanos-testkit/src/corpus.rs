//! **The source corpus a guard scans, with the coverage it would otherwise have to trust** (#253).
//!
//! A guard that walks the tree and asserts "no file does X" is making two claims, and only one of them is
//! written down. The stated one is about the code. The unstated one is about the walk — that it reached the
//! files where X could be. Fourteen guards in this tree spelled the walk out by hand, and every one of them
//! ended a failed read with `else { continue }` or `.unwrap_or_default()`, so:
//!
//! * a **wrong root** — a moved crate, a renamed directory, a `read_dir` that fails — yields an empty corpus,
//!   and "no file does X" is then true for the emptiest of reasons;
//! * a **file that exists and cannot be read** is skipped in silence, so the one file that would have failed
//!   the guard is exactly the one a permissions accident removes from it.
//!
//! Neither shows up as anything but green. This module is the fix, in the shape #252 used for the same class:
//! one walk, in the crate every guard already depends on, that **cannot return a corpus without also having
//! checked it**.
//!
//! ## The floor is derived, not chosen
//!
//! "At least N files" would be a number someone picked, and it would rot. The workspace states the answer
//! instead: every directory under `crates/` holding a `Cargo.toml` is a crate, and a crate that contributes
//! **no** source to the harvest was not reached. That is a coverage assertion whose value comes from the
//! layout rather than from a guess, and it tightens by itself as crates are added.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// One harvested Rust source file.
#[derive(Clone, Debug)]
pub struct RustSource {
    /// Absolute path, for opening or for a message a reader can act on.
    pub path: PathBuf,
    /// Path relative to the workspace root — what a guard should print, and what it should match on.
    pub rel: String,
    /// The crate directory this file lives in (`fanos-node`, `fanos-quic`, …).
    pub krate: String,
    /// The file's contents. Read, not maybe-read: a failure to open is a panic, not a skip.
    pub text: String,
}

impl RustSource {
    /// Whether this file is part of a crate's **library or binary** source rather than its tests or benches.
    ///
    /// The distinction most guards want, and one that is easy to get subtly wrong by matching `"src"` as a
    /// substring — `crates/fanos-node/src/...` and a hypothetical `.../tests/src_helpers.rs` differ by a path
    /// separator, so this matches a whole component.
    #[must_use]
    pub fn is_crate_src(&self) -> bool {
        Path::new(&self.rel).components().any(|c| c.as_os_str() == "src")
    }
}

/// The workspace root — the directory holding the virtual manifest and `crates/`.
///
/// Derived from this crate's own manifest location at compile time, so it is correct however the caller was
/// invoked: a guard in `fanos-cli`'s `tests/` gets the same root as one in `fanos-node`'s.
///
/// # Panics
///
/// If the root does not resolve. Deliberate: every guard's corpus hangs off this path, and a wrong one
/// yields an empty scan that passes green — the failure this module exists to make impossible.
#[must_use]
pub fn workspace_root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = here.join("../..");
    root.canonicalize().unwrap_or_else(|e| panic!("the workspace root must resolve from {}: {e}", here.display()))
}

/// Every crate directory under `crates/` — a directory holding a `Cargo.toml`.
///
/// This is the denominator of the coverage check in [`rust_sources`], and it is read from the layout rather
/// than listed, so adding a crate tightens the guard instead of quietly leaving it behind.
///
/// # Panics
///
/// If `crates/` cannot be listed, or lists nothing. A denominator that silently came back empty would make
/// every coverage assertion built on it vacuous.
#[must_use]
pub fn crate_dirs() -> BTreeSet<String> {
    let crates = workspace_root().join("crates");
    let entries = std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("the crates directory must be listable at {}: {e}", crates.display()));
    let found: BTreeSet<String> = entries
        .map(|e| e.unwrap_or_else(|err| panic!("a crates/ entry must be readable: {err}")))
        .filter(|e| e.path().join("Cargo.toml").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!found.is_empty(), "no crate found under {} — the walk is looking in the wrong place", crates.display());
    found
}

/// **Every `.rs` file under `crates/`, read** — the corpus, plus the proof that it is one.
///
/// Three things a hand-rolled walk leaves to chance, all fatal here rather than skipped:
///
/// * a directory that exists and cannot be listed;
/// * a file that exists and cannot be read;
/// * a crate that contributed nothing, which is what a moved root or a mistyped filter looks like from the
///   inside — see the module doc for why the floor is per crate rather than a count.
///
/// `target/` is skipped, and only there: it is build output, not source, and it is the one directory whose
/// absence from a scan needs no argument. Everything else is harvested and handed over, so a guard's own
/// exemptions stay visible at the guard, where a reader can weigh them.
///
/// # Panics
///
/// On any of the three, by design — see above. A guard that cannot be told it scanned less than it thinks
/// is a guard whose green means nothing, so each of these is fatal rather than skipped.
#[must_use]
pub fn rust_sources() -> Vec<RustSource> {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut out: Vec<RustSource> = Vec::new();
    let mut stack = vec![crates.clone()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
            panic!("a directory inside the corpus must be listable — {}: {e}", dir.display())
        });
        for entry in entries {
            let entry = entry
                .unwrap_or_else(|e| panic!("an entry of {} must be readable: {e}", dir.display()));
            let path = entry.path();
            if path.is_dir() {
                // Build output only. Every other directory is walked, because "we did not look there" is the
                // failure this module exists to make impossible.
                if path.file_name().is_some_and(|n| n != "target") {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "a source file in the corpus must be readable — {}: {e}. Skipping it would leave the \
                     guard green about a file it never saw",
                    path.display()
                )
            });
            let rel = path.strip_prefix(&root).unwrap_or(&path).display().to_string();
            let Some(krate) = path
                .strip_prefix(&crates)
                .ok()
                .and_then(|p| p.components().next())
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
            else {
                panic!("a harvested file must sit under crates/: {}", path.display())
            };
            out.push(RustSource { path, rel, krate, text });
        }
    }

    // The coverage report, as an assertion rather than a printout: a crate that contributed nothing was not
    // reached, and every guard built on this corpus would have been silently blind to it. Every one is
    // named, not just the first — someone fixing one path wants to know whether three more sit behind it.
    let reached: BTreeSet<&str> = out.iter().map(|s| s.krate.as_str()).collect();
    let missed: Vec<String> = crate_dirs().into_iter().filter(|k| !reached.contains(k.as_str())).collect();
    assert!(
        missed.is_empty(),
        "the corpus reached no source in {} crate(s): {}. A guard scanning it would have passed green about \
         code it never opened",
        missed.len(),
        missed.join(", ")
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The corpus knows how much it looked at, and every crate is in it (#253).**
    ///
    /// This is the assertion the fourteen hand-rolled walks were each missing. It is not a smoke test: it
    /// fails the moment a crate stops being reached, which is what a moved directory, a renamed path or a
    /// mistyped filter looks like from inside a guard — indistinguishable, otherwise, from clean code.
    #[test]
    fn every_crate_contributes_to_the_corpus_and_every_file_was_actually_read() {
        let sources = rust_sources();
        let reached: BTreeSet<&str> = sources.iter().map(|s| s.krate.as_str()).collect();
        let all = crate_dirs();

        assert_eq!(
            reached.len(),
            all.len(),
            "every crate must contribute source, or a guard over this corpus is blind to it: \
             reached {reached:?}, expected {all:?}"
        );
        // A read that returned nothing is not a read. `lib.rs`/`main.rs` are never empty in this tree, and an
        // empty text is what a swallowed error used to look like.
        assert!(
            sources.iter().all(|s| !s.text.is_empty()),
            "a harvested file is empty, which is what `unwrap_or_default` used to produce from a failed read"
        );
        // `is_crate_src` must actually discriminate, or every guard's filter is a no-op.
        assert!(sources.iter().any(RustSource::is_crate_src), "no crate source found — the filter is broken");
        assert!(
            sources.iter().any(|s| !s.is_crate_src()),
            "no non-src file found — the filter admits everything, so filtering on it proves nothing"
        );
    }
}
