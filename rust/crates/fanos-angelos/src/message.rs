//! The **plaintext message envelope** — the language-agnostic object a bot SDK sees after decryption, with a
//! canonical wire encoding so every language's SDK serializes it identically (a KAT pins the bytes, in the
//! spirit of the network's `conformance/vectors`). This is the *content* plane (text, control, presence) carried
//! over the async mixnet transport; real-time media rides the separate [`crate::media`] plane.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What an ANGELOS message conveys.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageKind {
    /// A human text message.
    Text,
    /// A bot command (a `/`-prefixed text, also delivered parsed to bots).
    Command,
    /// A member joined a channel.
    Join,
    /// A member left a channel.
    Leave,
    /// A reaction to another message.
    Reaction,
    /// Call signaling (invite/accept/hangup) — sets up the real-time [`crate::media`] plane over the control plane.
    CallSignal,
    /// A **payment** carried in-chat — the content is a serialized value transfer (an OBOLOS shielded submission
    /// or a token transfer). Send money to a contact, tip in a channel: the wallet lives *in* the conversation.
    Payment,
    /// A **payment request** — the content asks the recipient to pay (amount + memo + a payment address).
    PaymentRequest,
    /// A system/control notice.
    System,
    /// An **attachment** — the content is a serialized [`crate::attachment::Attachment`] pointing at a file
    /// stored in THESAUROS (a content id + the key to decrypt it). The file itself is fetched out of band.
    Attachment,
}

impl MessageKind {
    /// The wire tag.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            MessageKind::Text => 0,
            MessageKind::Command => 1,
            MessageKind::Join => 2,
            MessageKind::Leave => 3,
            MessageKind::Reaction => 4,
            MessageKind::CallSignal => 5,
            MessageKind::Payment => 6,
            MessageKind::PaymentRequest => 7,
            MessageKind::System => 8,
            MessageKind::Attachment => 9,
        }
    }

    /// Decode a wire tag.
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(MessageKind::Text),
            1 => Some(MessageKind::Command),
            2 => Some(MessageKind::Join),
            3 => Some(MessageKind::Leave),
            4 => Some(MessageKind::Reaction),
            5 => Some(MessageKind::CallSignal),
            6 => Some(MessageKind::Payment),
            7 => Some(MessageKind::PaymentRequest),
            8 => Some(MessageKind::System),
            9 => Some(MessageKind::Attachment),
            _ => None,
        }
    }
}

/// A decrypted ANGELOS message — one channel post or direct message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    /// The channel or direct-conversation id this belongs to.
    pub channel: [u8; 32],
    /// The sender's identity id.
    pub sender: [u8; 32],
    /// The sender's per-sender sequence number (from the group/session ratchet).
    pub seq: u64,
    /// What the message conveys.
    pub kind: MessageKind,
    /// The payload (interpreted per `kind`: UTF-8 text, a reaction target + emoji, a call-signal blob, …).
    pub content: Vec<u8>,
}

impl Message {
    /// A text message to `channel` from `sender`.
    #[must_use]
    pub fn text(channel: [u8; 32], sender: [u8; 32], seq: u64, text: &str) -> Self {
        Self { channel, sender, seq, kind: MessageKind::Text, content: text.as_bytes().to_vec() }
    }

    /// The message's content as UTF-8 text, if it is valid UTF-8.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        core::str::from_utf8(&self.content).ok()
    }

    /// An attachment message to `channel` from `sender` — the file pointer travels inside the (E2E-encrypted)
    /// message; the file itself is fetched from THESAUROS.
    #[must_use]
    pub fn attachment(channel: [u8; 32], sender: [u8; 32], seq: u64, attachment: &crate::attachment::Attachment) -> Self {
        Self { channel, sender, seq, kind: MessageKind::Attachment, content: attachment.to_bytes() }
    }

    /// The message's content as an [`Attachment`](crate::attachment::Attachment), if it is an attachment message.
    #[must_use]
    pub fn as_attachment(&self) -> Option<crate::attachment::Attachment> {
        if self.kind != MessageKind::Attachment {
            return None;
        }
        crate::attachment::Attachment::from_bytes(&self.content)
    }

    /// Canonical bytes: `channel(32) ‖ sender(32) ‖ seq(8) ‖ kind(1) ‖ content_len(4) ‖ content`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(77 + self.content.len());
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.push(self.kind.tag());
        out.extend_from_slice(&(self.content.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.content);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / over-long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let channel = bytes.get(..32)?.try_into().ok()?;
        let sender = bytes.get(32..64)?.try_into().ok()?;
        let seq = u64::from_le_bytes(bytes.get(64..72)?.try_into().ok()?);
        let kind = MessageKind::from_tag(*bytes.get(72)?)?;
        let len = u32::from_le_bytes(bytes.get(73..77)?.try_into().ok()?) as usize;
        let content = bytes.get(77..77 + len)?.to_vec();
        if bytes.len() != 77 + len {
            return None; // no trailing garbage
        }
        Some(Self { channel, sender, seq, kind, content })
    }
}

/// A parsed bot **command** — a `/name arg arg …` text message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Command {
    /// The command name (without the prefix).
    pub name: String,
    /// The whitespace-separated arguments.
    pub args: Vec<String>,
}

impl Command {
    /// Parse `text` as a command if it starts with `prefix` (e.g. `'/'`): the first token (sans prefix) is the
    /// name, the rest are arguments. `None` if it does not start with the prefix or has no name.
    #[must_use]
    pub fn parse(text: &str, prefix: char) -> Option<Self> {
        let rest = text.strip_prefix(prefix)?;
        let mut tokens = rest.split_whitespace();
        let name = tokens.next()?.to_string();
        if name.is_empty() {
            return None;
        }
        let args = tokens.map(str::to_string).collect();
        Some(Self { name, args })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_message_round_trips_and_rejects_garbage() {
        let m = Message::text([1u8; 32], [2u8; 32], 7, "hello, world");
        let bytes = m.to_bytes();
        assert_eq!(Message::from_bytes(&bytes), Some(m.clone()));
        assert_eq!(Message::from_bytes(&bytes[..bytes.len() - 1]), None, "truncation rejected");
        assert_eq!(Message::from_bytes(&[bytes.as_slice(), b"x"].concat()), None, "trailing garbage rejected");
        assert_eq!(m.as_text(), Some("hello, world"));
    }

    #[test]
    fn the_message_wire_format_is_stable_a_known_answer() {
        // A fixed message must encode to fixed bytes, so every language's SDK agrees byte-for-byte.
        let m = Message { channel: [0xAA; 32], sender: [0xBB; 32], seq: 0x0102_0304_0506_0708, kind: MessageKind::Text, content: b"hi".to_vec() };
        let bytes = m.to_bytes();
        assert_eq!(&bytes[..32], &[0xAA; 32], "channel");
        assert_eq!(&bytes[32..64], &[0xBB; 32], "sender");
        assert_eq!(&bytes[64..72], &0x0102_0304_0506_0708_u64.to_le_bytes(), "seq (LE)");
        assert_eq!(bytes[72], 0, "kind tag Text = 0");
        assert_eq!(&bytes[73..77], &2u32.to_le_bytes(), "content length = 2 (LE)");
        assert_eq!(&bytes[77..], b"hi", "content");
        assert_eq!(bytes.len(), 79);
    }

    #[test]
    fn commands_parse_from_prefixed_text() {
        let c = Command::parse("/tip alice 100", '/').expect("a command");
        assert_eq!(c.name, "tip");
        assert_eq!(c.args, ["alice".to_string(), "100".to_string()]);
        assert_eq!(Command::parse("/ping", '/').unwrap().args.len(), 0, "a command may take no args");
        assert!(Command::parse("hello", '/').is_none(), "plain text is not a command");
        assert!(Command::parse("/", '/').is_none(), "an empty command name is rejected");
    }
}
