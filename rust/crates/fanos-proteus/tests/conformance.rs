//! Cross-language conformance KATs for PROTEUS epoch shaping, pinned to
//! `conformance/vectors/services.json`. The transport shape must be reproduced bit-for-bit by any
//! implementation sharing a community secret, or shaped frames will not interoperate.

use fanos_proteus::{Epoch, epoch_shape};

#[test]
#[allow(clippy::indexing_slicing)]
fn epoch_shape_matches_the_vector() {
    // services.json → proteus_shape, secret "conformance-secret", epoch 42.
    let shape = epoch_shape(b"conformance-secret", Epoch::new(42));
    assert_eq!(shape.junk_count, 5);
    assert_eq!(shape.junk_size, 44);
    assert_eq!(shape.padding_multiple, 155);
    assert_eq!(shape.junk_len(), 220);
    assert_eq!(&shape.scramble_seed[..4], &[228, 92, 91, 113]);
}
