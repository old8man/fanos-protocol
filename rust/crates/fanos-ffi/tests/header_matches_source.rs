//! The hand-maintained C header must agree with the Rust surface, and something must say so.
//!
//! `include/fanos.h` is written by hand and its own comment asks the reader to "keep the two in sync". That is
//! a request, not a mechanism. A header that disagrees with the library is **not a compile error in this
//! repository** — it is undefined behaviour in somebody else's C program, discovered at their run time, with
//! the wrong argument counts and the wrong result-code meanings. The drift costs nothing to make and
//! everything to find, which is exactly the asymmetry a guard is for.
//!
//! Checked here rather than by generating the header: generation would also keep them equal, and would throw
//! away the prose the hand-written one carries (what each result code *means*, which handle owns what, which
//! call is safe before `fanos_open`). The point is agreement, not authorship.
//!
//! Text comparison, deliberately. Parsing C properly would need a C parser in the dev-dependencies of a crate
//! whose whole job is to have none; the declarations this header uses are one-per-line and regular, and a
//! parse that is too weak shows up as a FALSE FAILURE — noisy and safe — rather than a false pass.

use std::collections::{BTreeMap, BTreeSet};

const SRC: &str = include_str!("../src/lib.rs");
const HDR: &str = include_str!("../include/fanos.h");

/// Every `extern "C"` function name in the Rust source, with its argument count.
fn rust_fns() -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    let mut rest = SRC;
    while let Some(i) = rest.find("extern \"C\"") {
        rest = &rest[i + "extern \"C\"".len()..];
        let Some(fi) = rest.find("fn ") else { break };
        let after = &rest[fi + 3..];
        let Some(open) = after.find('(') else { break };
        let name = after[..open].trim().to_owned();
        let Some(close) = after[open..].find(')') else { break };
        let args = after[open + 1..open + close].trim().to_owned();
        let arity = if args.is_empty() { 0 } else { args.split(',').filter(|a| !a.trim().is_empty()).count() };
        out.insert(name, arity);
    }
    out
}

/// Every `fanos_*` declaration in the header, with its argument count (`void` reads as zero).
///
/// Comments are stripped first and the remainder is treated as one stream, because **a declaration wraps**:
/// `fanos_publish` and `fanos_lookup` each span two lines. A line-at-a-time parse missed exactly those and
/// reported them as drift — the false failure this file's header predicted, which is the safe direction and
/// still a bug in the parser rather than in the header.
fn header_fns() -> BTreeMap<String, usize> {
    // Strip `/* ... */` comments so a `fanos_` name mentioned in prose is not read as a declaration.
    let mut code = String::with_capacity(HDR.len());
    let mut rest = HDR;
    while let Some(start) = rest.find("/*") {
        code.push_str(&rest[..start]);
        rest = rest[start..].find("*/").map_or("", |end| &rest[start + end + 2..]);
    }
    code.push_str(rest);

    let mut out = BTreeMap::new();
    let mut rest = code.as_str();
    while let Some(i) = rest.find("fanos_") {
        let after = &rest[i..];
        let end = after.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(after.len());
        let (name, tail) = after.split_at(end);
        rest = tail;
        // A declaration, not a macro use: the name is followed by `(` and the group closes with `;`.
        let Some(open) = tail.find('(') else { continue };
        if !tail[..open].trim().is_empty() {
            continue;
        }
        let Some(close) = tail.find(')') else { continue };
        if !tail[close + 1..].trim_start().starts_with(';') {
            continue;
        }
        let args = tail[open + 1..close].trim();
        let arity = if args.is_empty() || args == "void" {
            0
        } else {
            args.split(',').filter(|a| !a.trim().is_empty()).count()
        };
        out.insert(name.to_owned(), arity);
        rest = &tail[close + 1..];
    }
    out
}

#[test]
fn the_header_declares_exactly_the_exported_functions() {
    let (rs, hs) = (rust_fns(), header_fns());
    assert!(!rs.is_empty(), "the parse found no exported functions, so this test is measuring itself");

    let rnames: BTreeSet<&String> = rs.keys().collect();
    let hnames: BTreeSet<&String> = hs.keys().collect();
    let missing: Vec<_> = rnames.difference(&hnames).collect();
    let extra: Vec<_> = hnames.difference(&rnames).collect();
    assert!(
        missing.is_empty(),
        "exported by the library and absent from fanos.h: {missing:?} — a caller cannot reach them, which is \
         the harmless direction, but the header no longer describes the library"
    );
    assert!(
        extra.is_empty(),
        "declared in fanos.h and NOT exported: {extra:?} — a caller compiles and then fails to link, or worse \
         links against something else with that name"
    );
}

#[test]
fn the_header_agrees_on_every_arity() {
    let (rs, hs) = (rust_fns(), header_fns());
    for (name, rn) in &rs {
        let Some(hn) = hs.get(name) else { continue }; // named by the test above
        assert_eq!(
            rn, hn,
            "{name} takes {rn} arguments and fanos.h declares {hn} — a caller built against this header pushes \
             the wrong frame, which no linker checks and no test in a C project would catch"
        );
    }
}

/// The result codes are the more dangerous half: a wrong NAME fails to link, a wrong VALUE succeeds and
/// silently means something else — `FANOS_ERR_TIMEOUT` read as `FANOS_ERR_IO` turns "retry is meaningful" into
/// "stop", which is the opposite instruction.
#[test]
fn the_header_agrees_on_every_result_code() {
    let mut rust: BTreeMap<String, i64> = BTreeMap::new();
    for line in SRC.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub const FANOS_")
            && let Some((name, value)) = rest.split_once(':')
            && let Some((_, v)) = value.split_once('=')
            && let Ok(n) = v.trim().trim_end_matches(';').parse::<i64>()
        {
            rust.insert(format!("FANOS_{}", name.trim()), n);
        }
    }
    let mut hdr: BTreeMap<String, i64> = BTreeMap::new();
    for line in HDR.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("#define FANOS_") {
            let mut it = rest.split_whitespace();
            let (Some(name), Some(v)) = (it.next(), it.next()) else { continue };
            let v = v.trim_matches(|c| c == '(' || c == ')');
            if let Ok(n) = v.parse::<i64>() {
                hdr.insert(format!("FANOS_{name}"), n);
            }
        }
    }
    assert!(rust.len() >= 8, "the parse found only {} Rust constants, so it is measuring itself", rust.len());
    for (name, rv) in &rust {
        let hv = hdr.get(name).unwrap_or_else(|| {
            panic!("{name} = {rv} is exported and fanos.h does not define it, so a caller cannot test for it")
        });
        assert_eq!(
            rv, hv,
            "{name} is {rv} in the library and {hv} in fanos.h — a caller comparing against the header's value \
             mis-classifies every occurrence, and the compiler has no way to notice"
        );
    }
}

/// The ABI version exists on both sides and agrees, so a caller can actually perform the check the constant
/// exists for.
#[test]
fn the_abi_version_is_declared_on_both_sides_and_agrees() {
    assert!(
        HDR.contains("uint32_t fanos_abi_version(void);"),
        "fanos.h must declare fanos_abi_version, or a caller has no way to detect a header/library mismatch"
    );
    assert_eq!(
        fanos_ffi::FANOS_ABI_VERSION,
        fanos_ffi::fanos_abi_version(),
        "the constant and the function disagree, so a caller that checks one is checking nothing"
    );
}
