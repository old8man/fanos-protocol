//! ONOMA conformance: pins the canonical address, mnemonic, and per-epoch derivations from
//! `conformance/vectors/names.json`. Any drift in the address codec, commitment label, or
//! derivation domains breaks these — the reference contract every implementation reproduces.
#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;

use fanos_field::F7;
use fanos_onoma::{Address, Epoch, derive, lookup_key};

const BUNDLE: &[u8] = b"fanos-onoma-conformance-service";

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn address_kat_matches_names_json() {
    let a = Address::from_bundle(BUNDLE);
    assert_eq!(
        hex(a.commitment()),
        "02659bc321a2475eec776ea6a3be81fb3b649d3328eb930353177c93833ce0d1"
    );
    assert_eq!(
        a.to_name(),
        "qypxtx7ryx3ywhhvwah2dga7s8ankeyaxv5whycr2vtheyur8nsdzwqysun.fanos"
    );
    assert_eq!(
        a.to_bech32(),
        "onoma1qypxtx7ryx3ywhhvwah2dga7s8ankeyaxv5whycr2vtheyur8nsdzwqysun"
    );
    assert_eq!(
        a.mnemonic(),
        "v1-banoj-nozag-fakof-hitiv-vudul-kupok-pavuv-malur-gotoh-nuhug-fogor-nasag-jasil-lufig-masus-vagid"
    );
    // The pinned name round-trips back to the same address.
    assert_eq!(Address::parse(&a.to_name()).unwrap(), a);
}

#[test]
fn derivation_kat_matches_names_json() {
    let a = Address::from_bundle(BUNDLE);
    assert_eq!(
        hex(&lookup_key(&a, Epoch::new(42))),
        "3936a45cef80a5c80bc7a1c137d0255082e65f32fa13265550b223627b98f689"
    );
    assert_eq!(
        hex(&derive::descriptor_key(&a, Epoch::new(42))),
        "54b6eb245c20efeae57d43aa59d89925fa99e63984c8188baf111788acf632f1"
    );
    assert_eq!(
        // The descriptor's storage anchor is storage_point(lookup_key) — where the resolver's put/get
        // actually land — not a direct MapToPoint of the lookup pre-image (audit #128/C5).
        derive::lookup_point::<F7>(&a, Epoch::new(42)).coords(),
        [1, 6, 1]
    );
}
