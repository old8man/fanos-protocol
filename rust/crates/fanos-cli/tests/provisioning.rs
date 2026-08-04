//! **Every provisioning parameter must be checked before a node runs on it** — a ratchet on the surface that
//! produced three severe findings in one sweep.
//!
//! Operator-supplied configuration is a different surface from the wire, and the difference is why it went
//! unguarded. Wire decoders in this workspace are careful — they have had an audit pass, they bound every
//! length, they refuse trailing bytes. A provisioning file is newer, arrives through `from_config_str` or
//! `from_bytes` in `fanos-node::config` / `taxis_config`, and until 2026-08-04 every threshold on it was
//! either unchecked or checked one value too loosely:
//!
//! * `CellParams` decoded `q, n, f, quorum` as four independent integers. The three non-`q` fields are a pure
//!   function of `q`, and a `quorum` one below the derived value breaks `2Q > n + f` — two quorums can then be
//!   **disjoint**, so two conflicting blocks both finalize. A fork, from a typo.
//! * `ServiceParams` accepted `threshold = 1`, which makes "no single host holds the service identity in the
//!   clear" vacuous while every member of the line holds it whole.
//! * `BeaconParams.threshold` was never compared against the commitment, which knows its own degree — so a
//!   mismatched file produced a node that ran, flooded, and silently never adopted an epoch.
//!
//! Fixing three parameters does not fix the class. This test does: **a new params type, or a new field on an
//! existing one, must arrive with a startup check or fail here.** It is deliberately crude — it reads source
//! rather than types, because the property is "somebody thought about this", which no type expresses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The `*Params` types a node is provisioned with, and the function in `node.rs` that must validate each
/// before `Node::start` acts on it.
///
/// Listed rather than discovered, because the pairing is the claim: a reader should be able to see at a
/// glance which validator owns which type, and a type added without one is exactly what this catches.
const PROVISIONED: &[(&str, &str)] = &[
    ("BeaconParams", "beacon_params_checked"),
    ("ServiceParams", "service_params"),
    ("IngressParams", "ingress_params"),
    ("ExitParams", "exit_params"),
];

fn rust_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(rust_root().join(rel)).unwrap_or_default()
}

#[test]
fn every_provisioning_params_type_has_a_startup_validator() {
    let config = read("crates/fanos-node/src/config.rs");
    let node = read("crates/fanos-node/src/node.rs");

    let declared: BTreeSet<String> = config
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub struct "))
        .filter_map(|l| l.split(['{', ' ', '<']).next())
        .filter(|name| name.ends_with("Params"))
        .map(str::to_owned)
        .collect();

    let listed: BTreeSet<String> = PROVISIONED.iter().map(|(t, _)| (*t).to_owned()).collect();
    assert_eq!(
        declared, listed,
        "a `*Params` type was added to or removed from `fanos-node::config` without pairing it to a startup \
         validator here. Every one of these carries values an operator types into a file, and three of them \
         shipped with a threshold that was unchecked or one value too loose — one of which forks the cell. \
         Add the type and its validator to PROVISIONED, or say in the commit why this one needs none.",
    );

    for (ty, validator) in PROVISIONED {
        assert!(
            node.contains(&format!("fn {validator}(")),
            "{ty}'s validator `{validator}` is gone from node.rs — a params type whose check was deleted is \
             worse than one that never had it, because the pairing above still claims it is guarded",
        );
        assert!(
            node.contains(&format!("{validator}(&config)")),
            "{validator} exists but `Node::start` does not call it. That is the shape this workspace has \
             found four times over: a guard nothing invokes is a guard that is absent in production.",
        );
    }
}

#[test]
fn a_threshold_that_arrives_from_a_file_is_bounded_at_both_ends() {
    // The specific error that recurs: a threshold checked for `> line.len()` but not for a floor, or for
    // `== 0` when the meaningful floor is 2. A `t` of 1 over a multi-member line is not a weaker threshold —
    // it hands every member the whole secret, which is the inversion of the property being claimed.
    //
    // Asserted against the source rather than by calling `Node::start`, because the point is that the bound
    // is WRITTEN, not that one fixture happens to trip it.
    let node = read("crates/fanos-node/src/node.rs");
    for validator in ["service_params", "ingress_params"] {
        let Some(start) = node.find(&format!("fn {validator}(")) else {
            panic!("{validator} must exist — see the pairing test above")
        };
        let body = &node[start..node.len().min(start + 4000)];
        assert!(
            body.contains("threshold < 2"),
            "{validator} guards a threshold over a LINE, whose members number `q+1` by construction, so its \
             floor is 2 and not 1: at `t = 1` every member holds the secret whole while the design claims no \
             single host does. (The beacon is deliberately exempt — one anchor is a documented single-\
             operator deployment, and `BeaconParams` cannot tell that case from a multi-anchor one.)",
        );
    }
}
