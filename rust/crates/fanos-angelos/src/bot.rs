//! The **bot SDK contract** — the language-agnostic, transport-agnostic model per-language messaging-bot SDKs
//! implement. A bot is a *pure* handler: it maps an [`Event`] to the [`Outgoing`] messages it wants to send,
//! with **no I/O**. That purity is deliberate — it makes bot logic portable across languages, testable entirely
//! off-network, and trivial to bind through the C ABI ([`fanos-ffi`]): the SDK runtime does the encryption
//! (`crate::session`/`crate::group`), the transport (over `fanos-node`), and the decryption, and hands the bot
//! only decrypted events, collecting its replies.
//!
//! Because ANGELOS is the platform's single face — chat *and* wallet *and* everything — an event or a reply can
//! carry value ([`crate::message::MessageKind::Payment`]): a bot can be tipped, can pay out, can invoice, all in
//! the flow of a conversation. The bot never touches keys or the network; it just decides what to say and send.

use alloc::vec::Vec;

use crate::message::{Command, Message, MessageKind};

/// Something that happens in a conversation that a bot reacts to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// A message arrived (any kind).
    Message(Message),
    /// A `/`-prefixed message parsed as a command — a convenience fired alongside the raw [`Message`] event.
    Command {
        /// The parsed command.
        command: Command,
        /// The message it came from (for the channel, sender, seq).
        message: Message,
    },
    /// A member joined a channel.
    Joined {
        /// The channel.
        channel: [u8; 32],
        /// The member who joined.
        member: [u8; 32],
    },
    /// A member left a channel.
    Left {
        /// The channel.
        channel: [u8; 32],
        /// The member who left.
        member: [u8; 32],
    },
}

/// A message a bot wants to send in reply — the SDK runtime encrypts and delivers it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Outgoing {
    /// The channel or conversation to send to.
    pub channel: [u8; 32],
    /// What kind of message.
    pub kind: MessageKind,
    /// The payload (per `kind`).
    pub content: Vec<u8>,
}

impl Outgoing {
    /// A text reply to `channel`.
    #[must_use]
    pub fn text(channel: [u8; 32], text: &str) -> Self {
        Self { channel, kind: MessageKind::Text, content: text.as_bytes().to_vec() }
    }

    /// A payment sent into `channel` (the content is a serialized value transfer — the app's wallet builds it).
    #[must_use]
    pub fn payment(channel: [u8; 32], payment: Vec<u8>) -> Self {
        Self { channel, kind: MessageKind::Payment, content: payment }
    }
}

/// A **bot** — a pure handler mapping an event to the messages it wants to send. Implement this once, in any
/// language, and the runtime carries it over the anonymous network.
pub trait Bot {
    /// React to `event`, returning the messages to send (possibly none).
    fn on_event(&mut self, event: &Event) -> Vec<Outgoing>;
}

/// Turn an incoming `message` into events and run `bot`, returning what it wants to send. A `Text`/`Command`
/// message whose text parses as a command (with `command_prefix`, e.g. `'/'`) fires a [`Event::Command`] event
/// **before** the raw [`Event::Message`], so a bot may handle either or both.
#[must_use]
pub fn dispatch(bot: &mut dyn Bot, message: Message, command_prefix: char) -> Vec<Outgoing> {
    let mut out = Vec::new();
    if matches!(message.kind, MessageKind::Text | MessageKind::Command)
        && let Some(command) = message.as_text().and_then(|t| Command::parse(t, command_prefix))
    {
        out.extend(bot.on_event(&Event::Command { command, message: message.clone() }));
    }
    out.extend(bot.on_event(&Event::Message(message)));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const CHANNEL: [u8; 32] = [0xC0; 32];
    const ALICE: [u8; 32] = [0xA1; 32];

    /// A bot that answers `/ping` with `pong` and tips 10 via `/tip` (a payment reply).
    struct DemoBot;
    impl Bot for DemoBot {
        fn on_event(&mut self, event: &Event) -> Vec<Outgoing> {
            match event {
                Event::Command { command, message } if command.name == "ping" => {
                    alloc::vec![Outgoing::text(message.channel, "pong")]
                }
                Event::Command { command, message } if command.name == "tip" => {
                    // The content here would be a real value transfer the app's wallet built; a stub for the test.
                    alloc::vec![Outgoing::payment(message.channel, alloc::vec![10])]
                }
                _ => Vec::new(),
            }
        }
    }

    #[test]
    fn a_command_bot_replies_to_its_commands_and_ignores_the_rest() {
        let mut bot = DemoBot;
        // "/ping" → a text "pong".
        let replies = dispatch(&mut bot, Message::text(CHANNEL, ALICE, 0, "/ping"), '/');
        assert_eq!(replies, alloc::vec![Outgoing::text(CHANNEL, "pong")]);
        // Plain chatter → nothing.
        assert!(dispatch(&mut bot, Message::text(CHANNEL, ALICE, 1, "hello everyone"), '/').is_empty());
        // "/tip" → a payment reply (the wallet-in-chat path).
        let tips = dispatch(&mut bot, Message::text(CHANNEL, ALICE, 2, "/tip"), '/');
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].kind, MessageKind::Payment);
        assert_eq!(tips[0].content, alloc::vec![10]);
    }

    #[test]
    fn a_bot_sees_both_the_command_and_the_raw_message() {
        // A bot that counts every event it sees, of either flavour.
        struct Counter(u32);
        impl Bot for Counter {
            fn on_event(&mut self, _event: &Event) -> Vec<Outgoing> {
                self.0 += 1;
                Vec::new()
            }
        }
        let mut c = Counter(0);
        let _ = dispatch(&mut c, Message::text(CHANNEL, ALICE, 0, "/help me"), '/');
        assert_eq!(c.0, 2, "a command message fires both a Command and a Message event");
        let mut c2 = Counter(0);
        let _ = dispatch(&mut c2, Message::text(CHANNEL, ALICE, 0, "just chatting"), '/');
        assert_eq!(c2.0, 1, "plain text fires only a Message event");
    }
}
