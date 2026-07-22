//! ANGELOS conformance: pins the language-agnostic wire formats from `conformance/vectors/angelos.json`
//! (design: spec/platform.md §6). Any per-language messaging-bot SDK must reproduce these byte-for-byte to
//! interoperate; any drift in the message envelope, the command grammar, the AEAD/nonce construction, or a
//! key-derivation label breaks these — the reference contract every implementation mirrors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fmt::Write as _;

use fanos_angelos::call::{CallId, CallSignal, media_flags};
use fanos_angelos::{Attachment, Command, GroupSession, MediaKind, MediaSession, Message, MessageKind, Role, Session};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn message_kind_tags_match_angelos_json() {
    // The wire tag table is a stable contract; every tag round-trips and no tag outside 0..=8 decodes.
    let table = [
        (MessageKind::Text, 0u8),
        (MessageKind::Command, 1),
        (MessageKind::Join, 2),
        (MessageKind::Leave, 3),
        (MessageKind::Reaction, 4),
        (MessageKind::CallSignal, 5),
        (MessageKind::Payment, 6),
        (MessageKind::PaymentRequest, 7),
        (MessageKind::System, 8),
        (MessageKind::Attachment, 9),
    ];
    for (kind, tag) in table {
        assert_eq!(kind.tag(), tag, "tag of {kind:?}");
        assert_eq!(MessageKind::from_tag(tag), Some(kind), "from_tag({tag})");
    }
    assert_eq!(MessageKind::from_tag(10), None, "an unknown tag is rejected");
}

#[test]
fn message_envelope_kat_matches_angelos_json() {
    // A text post.
    let text = Message {
        channel: [0xAA; 32],
        sender: [0xBB; 32],
        seq: 72_623_859_790_382_856,
        kind: MessageKind::Text,
        content: b"hi".to_vec(),
    };
    let text_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080706050403020100020000006869";
    assert_eq!(hex(&text.to_bytes()), text_hex);
    assert_eq!(Message::from_bytes(&text.to_bytes()), Some(text), "envelope round-trips");

    // A payment carried in-chat — the wallet lives in the conversation.
    let pay = Message {
        channel: [0xCC; 32],
        sender: [0xDD; 32],
        seq: 3,
        kind: MessageKind::Payment,
        content: b"pay:100".to_vec(),
    };
    let pay_hex = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd030000000000000006070000007061793a313030";
    assert_eq!(hex(&pay.to_bytes()), pay_hex);
    assert_eq!(Message::from_bytes(&pay.to_bytes()), Some(pay), "payment envelope round-trips");
}

#[test]
fn command_grammar_matches_angelos_json() {
    let tip = Command::parse("/tip alice 100", '/').expect("a command");
    assert_eq!(tip.name, "tip");
    assert_eq!(tip.args, ["alice", "100"]);
    let ping = Command::parse("/ping", '/').expect("a no-arg command");
    assert_eq!(ping.name, "ping");
    assert!(ping.args.is_empty());
    assert!(Command::parse("hello", '/').is_none(), "no prefix → not a command");
    assert!(Command::parse("/", '/').is_none(), "empty name → not a command");
}

#[test]
fn attachment_kat_matches_angelos_json() {
    // A file pointer carried inside an (E2E-encrypted) message; its bytes are pinned in angelos.json.
    let a = Attachment::new([0xAB; 32], [0xCD; 32], 0x0102, "video/mp4");
    let mut expect = Vec::new();
    expect.extend_from_slice(&[0xAB; 32]); // cid
    expect.extend_from_slice(&[0xCD; 32]); // key
    expect.extend_from_slice(&0x0102u64.to_le_bytes()); // size
    expect.extend_from_slice(&9u16.to_le_bytes()); // media-type length
    expect.extend_from_slice(b"video/mp4");
    assert_eq!(a.to_bytes(), expect);
    assert_eq!(hex(&a.to_bytes()).len(), 166, "83 bytes");
    assert_eq!(Attachment::from_bytes(&a.to_bytes()), Some(a.clone()), "attachment round-trips");
    // An attachment rides inside a message and is recovered by kind.
    let m = Message::attachment([7; 32], [8; 32], 3, &a);
    assert_eq!(m.kind, MessageKind::Attachment);
    assert_eq!(m.as_attachment(), Some(a));
}

#[test]
fn call_signal_kat_matches_angelos_json() {
    // An audio+video invite encodes to the pinned bytes.
    let invite = CallSignal::Invite {
        call: CallId::new([0xAB; 16]),
        media_secret: [0xCD; 32],
        media: media_flags::AUDIO | media_flags::VIDEO,
    };
    let want = "00ababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd03";
    assert_eq!(hex(&invite.to_bytes()), want);
    assert_eq!(CallSignal::from_bytes(&invite.to_bytes()), Some(invite), "invite round-trips");
    // Invite → accept seeds interoperable media sessions.
    let (offer, mut caller) = CallSignal::invite(CallId::new([1; 16]), [2; 32], media_flags::AUDIO);
    let (_accept, callee) = CallSignal::from_bytes(&offer.to_bytes()).unwrap().accept().expect("accept");
    let frame = caller.seal_frame(MediaKind::Audio, b"hi");
    assert_eq!(callee.open_frame(&frame), Some((0, MediaKind::Audio, b"hi".to_vec())), "media interoperates");
}

#[test]
fn session_ratchet_kat_matches_angelos_json() {
    // The 1:1 symmetric ratchet over a fixed shared secret; the same plaintext seals differently as it ratchets.
    let mut init = Session::from_shared_secret(&[0x01; 32], Role::Initiator);
    assert_eq!(hex(&init.seal(b"gm")), "0000000000000000c0cb8122c87945ea433bed88baaa74687cdf");
    assert_eq!(hex(&init.seal(b"gm")), "0100000000000000d863f3c43e5e65ca6e3310e3123d6b4866ae");

    // A responder over the same secret opens what the initiator sealed (the b2a chain is the mirror).
    let mut init2 = Session::from_shared_secret(&[0x01; 32], Role::Initiator);
    let mut resp = Session::from_shared_secret(&[0x01; 32], Role::Responder);
    let sealed = init2.seal(b"gm");
    assert_eq!(resp.open(&sealed).as_deref(), Some(&b"gm"[..]), "the mirror session opens it");
}

#[test]
fn group_post_kat_matches_angelos_json() {
    // Member 1 posting to roster [1,2,3] over a fixed group key.
    let mut g = GroupSession::new(&[0x42; 32], 1, &[1, 2, 3]);
    assert_eq!(hex(&g.send(b"hello channel")), "00000000000000004b13f534da5fb2ab8458a032166e303c289ebb9616fb8da3310a18bc58");
    assert_eq!(hex(&g.send(b"hello channel")), "010000000000000070d8f717394e162e5e08f5dc84ea4d3437f5f2d8288537f9cfb568dfc3");

    // Another member reproduces the poster's chain from the group key and opens it.
    let mut a = GroupSession::new(&[0x42; 32], 1, &[1, 2, 3]);
    let mut b = GroupSession::new(&[0x42; 32], 2, &[1, 2, 3]);
    let post = a.send(b"hello channel");
    assert_eq!(b.recv(1, &post).as_deref(), Some(&b"hello channel"[..]), "a peer opens the post");
}

#[test]
fn media_frame_kat_matches_angelos_json() {
    // Epoch-0 frames over a fixed call secret.
    let mut tx = MediaSession::new(&[0x33; 32]);
    assert_eq!(hex(&tx.seal_frame(MediaKind::Audio, b"audio0")), "000000000000000000000000020e097db880b46b33d05a25b200f715de9c928d2d62f5");
    assert_eq!(hex(&tx.seal_frame(MediaKind::Video, b"video1")), "000000000100000000000000bcb21d09770aa5d025f1b5658276b40d71198e37bb733d");

    // The receiver opens either frame independently (loss-tolerant, order-independent).
    let mut tx2 = MediaSession::new(&[0x33; 32]);
    let rx = MediaSession::new(&[0x33; 32]);
    let a = tx2.seal_frame(MediaKind::Audio, b"audio0");
    assert_eq!(rx.open_frame(&a), Some((0, MediaKind::Audio, b"audio0".to_vec())));
}
