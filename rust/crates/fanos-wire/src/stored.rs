//! **Frames for artefacts that live on a disk**: a magic that says which KIND, a version that says which
//! LAYOUT (#308, #309).
//!
//! FANOS versions its wire ([`capability::PROTOCOL_VERSION`](crate::capability::PROTOCOL_VERSION)), its C ABI
//! (`FANOS_ABI_VERSION`), its Tessera packet ([`tessera::VERSION`](crate::tessera::VERSION)) and its telemetry
//! snapshot (`FTS1`). The files an operator hands a node were the outlier, and the cost is two things rather
//! than one:
//!
//! * **three operator mistakes get one message.** A chain-info file handed to `fanos validator --config`, a
//!   file written by an older build, and a genuinely truncated file are different errors with different
//!   fixes; "malformed" is the refusal nobody can act on.
//! * **the layout can never change.** Add a field and every live node's file becomes indistinguishable from
//!   a corrupt one — which for a node's *identity* means its coordinate, so the change simply cannot be made.
//!
//! ## The machinery is shared; the version is not
//!
//! This module holds the framing — write a header, classify bytes against it, strip it. The VERSION stays
//! with each format's owner and is passed in. That split is deliberate and is the [`one constant, two
//! quantities`](crate::wire) question answered: the TAXIS provisioning family's layout and a node's identity
//! layout change for unrelated reasons, in different crates, for different audiences. One shared number would
//! make every identity file "old" the day a validator config gained a field.
//!
//! ## `no_std`
//!
//! Nothing here touches a filesystem — it reads and writes byte slices, so it sits in the crate every reader
//! of these formats already depends on rather than in the one that happens to own the first of them.

use alloc::vec::Vec;

/// A stored artefact's kind marker.
///
/// Four bytes, matching every other on-disk format in this tree (`FTS1` for a telemetry snapshot, `FVCF` for
/// a validator config, `FCIN` for chain info). Fixed rather than a slice so the header's width is a type-level
/// fact and a two-byte magic cannot be chosen later, which would make two kinds collide on their first bytes.
pub type Magic = [u8; 4];

/// The header's width: the magic, then one version byte.
pub const HEADER_LEN: usize = 5;

/// What a stored artefact's frame says about itself — the three answers an operator needs told apart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoredFormat {
    /// This kind, at this build's layout version. Decoding may still fail on the body, and that residual is
    /// the honest meaning of "corrupt or truncated".
    Current,
    /// This kind, written at a **different** layout version. The operator needs a file from a matching
    /// build, not a bug report.
    OtherVersion(u8),
    /// No frame of this kind at all: the magic does not match, or the bytes are too short to carry one.
    ///
    /// Deliberately **not** called "wrong kind". At this layer the two possibilities — a file of some other
    /// kind, and a file of *this* kind written before the framing existed — are byte-identical, and which
    /// one it is depends on whether that format ever shipped unframed. Only the format's owner knows that,
    /// so only the format's owner may decide: refuse, or read it as a legacy body.
    Unframed,
}

/// Append a frame header for `magic` at `version`. The caller appends the body.
///
/// Appends rather than returning a `Vec` because every caller is already building one: a helper that
/// allocated its own would make the shared path the slower one, and the copy would be the reason someone
/// writes the two lines by hand instead — which is how a format ends up with two framings.
pub fn write_header(out: &mut Vec<u8>, magic: Magic, version: u8) {
    out.extend_from_slice(&magic);
    out.push(version);
}

/// Classify `bytes` against `magic`/`version` **without decoding the body**.
///
/// Separate from [`unframe`] because the three answers are for a human and the body is for a parser: a
/// caller reports the kind and the layout distinctly, then decodes, and a decode failure after a `Current`
/// verdict is what "corrupt" honestly means.
#[must_use]
pub fn classify(bytes: &[u8], magic: Magic, version: u8) -> StoredFormat {
    let Some(rest) = bytes.strip_prefix(&magic) else {
        return StoredFormat::Unframed;
    };
    match rest.split_first() {
        Some((&v, _)) if v == version => StoredFormat::Current,
        Some((&v, _)) => StoredFormat::OtherVersion(v),
        // The magic with nothing after it is not a frame this build can read, and it is not a *version*
        // mismatch either — there is no version byte to have mismatched.
        None => StoredFormat::Unframed,
    }
}

/// Strip a frame this build can decode, or `None`.
///
/// The shared half of every framed `from_bytes`: a caller that only needs the body writes this, and a caller
/// that must explain itself to an operator calls [`classify`] first.
#[must_use]
pub fn unframe(bytes: &[u8], magic: Magic, version: u8) -> Option<&[u8]> {
    match classify(bytes, magic, version) {
        StoredFormat::Current => bytes.get(HEADER_LEN..),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const A: Magic = *b"FAAA";
    const B: Magic = *b"FBBB";

    /// **The three verdicts are distinguishable, which is the whole point of the frame.**
    ///
    /// Asserted on one buffer per case rather than one case, because collapsing any two of them back into
    /// "malformed" is precisely the state this module exists to leave: the operator's next action differs in
    /// each — re-run the ceremony, use a matching build, check the path.
    ///
    /// Falsified by returning `StoredFormat::Current` unconditionally from `classify`: the second and third
    /// assertions go red, and `unframe` starts handing a foreign body to a decoder.
    #[test]
    fn a_frame_tells_the_three_operator_mistakes_apart() {
        let mut framed = Vec::new();
        write_header(&mut framed, A, 1);
        framed.extend_from_slice(b"body");

        assert_eq!(classify(&framed, A, 1), StoredFormat::Current);
        assert_eq!(unframe(&framed, A, 1).expect("this build's frame"), b"body");

        // A file of this kind from another build: the version is the discriminator, and it is REPORTED
        // rather than folded into a failure, so the message can name the number.
        assert_eq!(classify(&framed, A, 2), StoredFormat::OtherVersion(1));
        assert_eq!(unframe(&framed, A, 2), None, "a body this build cannot read must not reach a decoder");

        // A file of another kind entirely — the mistyped path.
        assert_eq!(classify(&framed, B, 1), StoredFormat::Unframed);
        assert_eq!(unframe(&framed, B, 1), None);
    }

    /// The two short inputs, which are the ones a hand-written check gets wrong.
    ///
    /// `[]` and a bare magic both have to be `Unframed`, and for the same reason stated two ways: there is no
    /// version byte, so there is nothing to have mismatched. Calling a bare magic `OtherVersion(?)` would
    /// need a version it does not have, and calling it `Current` would hand `unframe` an empty body as if it
    /// were a real one.
    #[test]
    fn a_truncated_header_is_unframed_rather_than_a_version_mismatch() {
        assert_eq!(classify(&[], A, 1), StoredFormat::Unframed);
        assert_eq!(classify(&A, A, 1), StoredFormat::Unframed, "the magic alone carries no version");
        // The boundary: header and nothing else IS readable, and its body is empty. Whether an empty body is
        // acceptable is the format's own question, not the frame's.
        let mut header_only = Vec::new();
        write_header(&mut header_only, A, 1);
        assert_eq!(classify(&header_only, A, 1), StoredFormat::Current);
        assert_eq!(unframe(&header_only, A, 1), Some(&[][..]));
    }

    /// `HEADER_LEN` is the width [`write_header`] actually writes — asserted, not asserted-by-comment.
    ///
    /// The two live one line apart and a reader would not notice them disagreeing; `unframe` slices at
    /// `HEADER_LEN`, so a mismatch would silently shift every body by a byte.
    #[test]
    fn the_stated_header_width_is_the_written_one() {
        let mut out = Vec::new();
        write_header(&mut out, A, 7);
        assert_eq!(out.len(), HEADER_LEN);
    }
}
