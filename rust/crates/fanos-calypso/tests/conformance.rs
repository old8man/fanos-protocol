//! Cross-language conformance KATs for CALYPSO addressing and L4 storage addressing, pinned to
//! `conformance/vectors/services.json`. Any implementation reproduces these exactly or it does not
//! interoperate.

use fanos_calypso::ServiceAddress;
use fanos_crypto::{hash::label, hash_labeled, map_to_point};
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
fn calypso_self_certifying_address_matches_the_vector() {
    // services.json → calypso_address, pubkey "fanos-conformance-service".
    let addr = ServiceAddress::from_pubkey(b"fanos-conformance-service");
    assert_eq!(
        addr.label(),
        "j4jleh2q7q6pxyufkfdf2efgpeq5evnyqx6srlcdctgqmuiwxfoq"
    );
    assert!(format!("{addr}").ends_with(".fanos"));
    // The address self-certifies the key it was derived from, and no other.
    assert!(addr.certifies(b"fanos-conformance-service"));
    assert!(!addr.certifies(b"a-different-service"));
}
