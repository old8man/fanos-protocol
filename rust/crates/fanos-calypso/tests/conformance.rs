//! Cross-language conformance KATs for CALYPSO addressing and L4 storage addressing, pinned to
//! `conformance/vectors/services.json`. Any implementation reproduces these exactly or it does not
//! interoperate.
#![allow(clippy::unwrap_used)]

use fanos_calypso::ServiceAddress;
use fanos_primitives::{hash::label, hash_labeled, map_to_point};
use fanos_field::F7;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[test]
fn l4_storage_addressing_matches_the_vector() {
    // services.json → storage_addressing, key "greeting".
    let digest = hash_labeled(label::STORAGE, b"greeting");
    assert_eq!(
        hex(&digest),
        "d507bd1e95611996b1f83b8c60576ad7d707ed37b9a07321aa68736e7e5779d5"
    );
    assert_eq!(
        map_to_point::<F7>(label::STORAGE, b"greeting").coords(),
        [1, 0, 0]
    );
}

#[test]
fn calypso_service_address_is_a_self_certifying_onoma_address() {
    // A CALYPSO service address is an ONOMA address (the canonical pinned address/mnemonic/
    // derivation vectors live in conformance/vectors/names.json + fanos-onoma/tests/conformance.rs).
    // Here we pin the *services-layer* property: the address self-certifies its bundle and no other.
    let bundle = b"fanos-conformance-service";
    let addr = ServiceAddress::from_bundle(bundle);
    assert!(addr.to_name().strip_suffix(".fanos").is_some());
    assert!(addr.verifies(bundle));
    assert!(!addr.verifies(b"a-different-service"));
    // Round-trips through the human-readable `.fanos` name.
    assert_eq!(ServiceAddress::parse(&addr.to_name()).unwrap(), addr);
}
