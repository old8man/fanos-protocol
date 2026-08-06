//! No failing return may bypass the error channel.
//!
//! `fanos_last_error` is only worth having if it is always set, and "remember to set it" is the same kind of
//! instruction as "keep the header in sync" — it fails the same way, silently, on the one path nobody
//! exercised. So every failing return goes through `fail` or `fail_null`, and this asserts there are no bare
//! ones left.
//!
//! Structural rather than behavioural on purpose. A behavioural test would have to *reach* each failure, and
//! the interesting ones (the OS refusing entropy, a runtime that cannot be built) are exactly the ones a test
//! cannot provoke. A reader of the source can see all of them.

const FULL: &str = include_str!("../src/lib.rs");

/// The library's own source, with its `#[cfg(test)]` module cut off.
///
/// The unit tests CALL the exported functions with null arguments — that is their job — and those calls
/// mention the same constants a bare return would. Scanning them reported the tests as defects, which is the
/// scan measuring itself.
fn src() -> &'static str {
    FULL.split("#[cfg(test)]").next().unwrap_or(FULL)
}

/// The body of every function, with the two helpers' own definitions removed — they are where the bare
/// returns legitimately live.
fn body_without_helpers() -> String {
    let mut out = String::with_capacity(src().len());
    let mut rest = src();
    for marker in ["fn fail(code: c_int, msg: &str) -> c_int {", "fn fail_null<T>(msg: &str) -> *mut T {"] {
        if let Some(i) = rest.find(marker) {
            out.push_str(&rest[..i]);
            // Skip to the end of that (short, brace-balanced) function.
            let after = &rest[i..];
            let mut depth = 0usize;
            let mut end = after.len();
            for (j, c) in after.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = j + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            rest = &after[end..];
        }
    }
    out.push_str(rest);
    out
}

#[test]
fn no_error_code_is_returned_without_a_reason() {
    let body = body_without_helpers();
    let bare: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter(|l| {
            // A bare code return: mentions an error constant and does not go through `fail(`.
            l.contains("FANOS_ERR_") && !l.contains("fail(") && (l.starts_with("return ") || l.ends_with("FANOS_ERR_NULL,"))
        })
        .collect();
    assert!(
        bare.is_empty(),
        "these return an error code without setting fanos_last_error, so a C caller gets a class and no \
         reason: {bare:#?}"
    );
}

#[test]
fn no_null_is_returned_without_a_reason() {
    let body = body_without_helpers();
    let bare: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//") && !l.starts_with("///"))
        .filter(|l| l.contains("ptr::null_mut()") && !l.contains("fail_null("))
        .collect();
    assert!(
        bare.is_empty(),
        "these return NULL without setting fanos_last_error. NULL is the ENTIRE failure vocabulary of the \
         pointer-returning calls, so a bare one tells the caller nothing at all: {bare:#?}"
    );
}

/// The parse is not vacuous: it finds the helpers and it finds the sites that go through them.
#[test]
fn the_scan_can_see_what_it_is_scanning_for() {
    let body = body_without_helpers();
    let via_fail = body.matches("fail(FANOS_ERR_").count();
    let via_null = body.matches("fail_null(").count();
    assert!(via_fail >= 6, "only {via_fail} sites route a code through `fail`, so the scan is not seeing them");
    assert!(via_null >= 12, "only {via_null} sites route a null through `fail_null`, so the scan is blind");
    assert!(
        !body.contains("fn fail_null<T>(msg: &str) -> *mut T {"),
        "the helper's own definition was not removed, so its bare return would mask a real one"
    );
}
