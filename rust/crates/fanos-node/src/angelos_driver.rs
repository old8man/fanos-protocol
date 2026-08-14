//! ANGELOS over a FANOS anonymous stream — the messenger's door.
//!
//! `fanos-angelos` is a complete messenger and, until this module, no shipped binary could reach a line of it:
//! sessions, a double ratchet, groups, media, call signalling and a bot SDK, all sans-I/O and all unreachable.
//! It was the larger of the two crate-level orphans the architecture test names.
//!
//! What was missing was never the capability. The node already hosts an anonymous service and dials one, so the
//! whole of this module is the *composition*: run ANGELOS's handshake over an established byte stream, then
//! carry sealed [`Message`]s across it.
//!
//! ## Two layers of encryption, and why that is not redundant
//!
//! The stream is already a DIAULOS session — authenticated, post-quantum, and encrypted. ANGELOS encrypts
//! again, and the difference is *what each protects against*:
//!
//! * **DIAULOS** secures the transport. It ends at whatever host terminates the stream, so a compromised
//!   service host reads everything crossing it.
//! * **ANGELOS** is end-to-end between the two correspondents, with forward secrecy and post-compromise
//!   security from its double ratchet. It survives a compromised host, a compromised relay, and the recovery of
//!   either party's long-term key after the fact.
//!
//! That second sentence was false for as long as this module existed (#282). It held a
//! `fanos_angelos::session::Session` — the **symmetric** half, whose own doc says the asymmetric KEM ratchet
//! "builds on it in `fanos_angelos::ratchet`" (that doc writes `crate::`, correct there and misleading here) — so the shipped conversation had forward secrecy and no healing after a
//! compromise, while `DoubleRatchet` sat exported from `lib.rs` with no caller anywhere, not even inside its
//! own crate. The argument for keeping two encryption layers rested on the property the wired half lacked.
//!
//! Collapsing them would trade the second property for one less encryption pass. That is the wrong trade for a
//! messenger, and it is exactly the trade a "the transport is already encrypted" argument talks you into.
//!
//! ## Framing
//!
//! Length-prefixed (`u32` big-endian) frames. The stream underneath is reliable and ordered, so this only has
//! to delimit — but it must delimit *explicitly*: a sealed message has no self-terminating structure, and
//! reading "whatever arrived" would split one ciphertext across two `open` calls and desynchronize the ratchet
//! permanently. A bound on the length is enforced, because the count is read from the wire before the body is.

use fanos_angelos::message::Message;
use fanos_angelos::ratchet::DoubleRatchet;
use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
use fanos_pqcrypto::rng::SeedRng;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The largest frame this driver will read, in bytes.
///
/// Read *before* the body, so it is the one number an unauthenticated peer can make this side act on: without a
/// bound, a four-byte header allocates four gigabytes. Sized for a media chunk with room over — ANGELOS
/// attachments are chunked by the crate that produces them, so a legitimate frame never approaches it.
///
/// **Re-exported from [`fanos_wire`], not defined here.** It was a second, independent copy of the same
/// number; the two were equal only by coincidence and nothing would have caught them diverging.
pub use fanos_wire::MAX_FRAME;

/// A messaging session bound to one byte stream.
pub struct Conversation<S> {
    stream: S,
    ratchet: DoubleRatchet,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conversation<S> {
    /// Open a conversation as the **initiator**: run the handshake toward `recipient`, then carry messages.
    ///
    /// `rng_seed` seeds the ephemeral handshake material. It must be fresh per conversation — reusing it
    /// reuses the ephemeral key, which is what forward secrecy is bought with.
    ///
    /// # Errors
    /// I/O on the stream, or a handshake the crate refuses to build.
    pub async fn initiate(
        mut stream: S,
        recipient: &HybridKemPublic,
        rng_seed: &[u8],
    ) -> std::io::Result<Self> {
        let (ratchet, handshake) = DoubleRatchet::initiate(recipient, rng_seed)
            .ok_or_else(|| std::io::Error::other("angelos: could not build the handshake"))?;
        write_frame(&mut stream, &handshake).await?;
        Ok(Self { stream, ratchet })
    }

    /// Accept a conversation as the **responder**: read the initiator's handshake and open with it.
    ///
    /// # Errors
    /// I/O on the stream, or a handshake that does not verify — which is refused rather than answered, since a
    /// responder that replies to a bad handshake tells an unauthenticated prober that it is a messenger.
    /// Takes the KEM secret **by value**: the ratchet owns it as its initial ratchet key and drops it for a
    /// fresh one on the first reply, which is what healing after a compromise means. A responder that kept a
    /// borrowed static key would be the symmetric half again.
    pub async fn respond(
        mut stream: S,
        kem_secret: HybridKemSecret,
        kem_public: &HybridKemPublic,
    ) -> std::io::Result<Self> {
        let handshake = read_frame(&mut stream).await?;
        let ratchet = DoubleRatchet::respond(kem_secret, kem_public, &handshake)
            .ok_or_else(|| std::io::Error::other("angelos: handshake did not verify"))?;
        Ok(Self { stream, ratchet })
    }

    /// Seal `message` and write it.
    ///
    /// Draws a **fresh OS seed per message**, because a ratchet step mints a new key pair and its randomness is
    /// what the healing is made of: a reused draw would re-derive the same ratchet key and buy nothing. An
    /// entropy failure refuses to send rather than falling back to a predictable draw — the same rule the DP
    /// export follows, for the same reason.
    ///
    /// # Errors
    /// I/O on the stream, no OS entropy, or a ratchet that refuses to seal.
    pub async fn send(&mut self, message: &Message) -> std::io::Result<()> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|_| std::io::Error::other("angelos: no OS entropy for the ratchet step"))?;
        let mut rng = SeedRng::from_seed(&seed);
        let sealed = self
            .ratchet
            .seal(&mut rng, &message.to_bytes())
            .ok_or_else(|| std::io::Error::other("angelos: the ratchet refused to seal"))?;
        write_frame(&mut self.stream, &sealed).await
    }

    /// Read and open the next message. `Ok(None)` at end of stream.
    ///
    /// # Errors
    /// I/O on the stream, or a frame that does not open — which ends the conversation rather than being
    /// skipped: the double ratchet advances per message, so a frame that cannot be opened means this side and
    /// the peer no longer agree on the chain, and every later frame would fail too. Continuing would present a
    /// desynchronized session as a working one.
    pub async fn recv(&mut self) -> std::io::Result<Option<Message>> {
        let Some(sealed) = read_frame_eof(&mut self.stream).await? else { return Ok(None) };
        let plain = self
            .ratchet
            .open(&sealed)
            .ok_or_else(|| std::io::Error::other("angelos: message did not open — the ratchet has diverged"))?;
        let message = Message::from_bytes(&plain)
            .ok_or_else(|| std::io::Error::other("angelos: opened bytes are not a message"))?;
        Ok(Some(message))
    }

    /// The underlying stream, for a caller that wants to close it deliberately.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

/// Write one length-prefixed frame.
async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::other("angelos: frame longer than the wire format allows"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Read one length-prefixed frame, treating end-of-stream as an error.
async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    read_frame_eof(stream)
        .await?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
}

/// Read one length-prefixed frame. `Ok(None)` if the stream ended cleanly at a frame boundary.
async fn read_frame_eof<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        // Refused before allocating. The length is attacker-supplied and is read before the body.
        return Err(std::io::Error::other(format!(
            "angelos: frame of {len} bytes exceeds the {MAX_FRAME}-byte bound"
        )));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(Some(body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A correspondent's long-term key pair.
    fn keypair(seed: &[u8]) -> (HybridKemSecret, HybridKemPublic) {
        HybridKemSecret::generate(&mut SeedRng::from_seed(seed))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_message_crosses_the_stream_and_arrives_intact() {
        let (secret, public) = keypair(b"angelos-driver-recipient-seed-32");
        let public_for_responder = public.clone();
        let (client, server) = tokio::io::duplex(64 * 1024);

        let responder = tokio::spawn(async move {
            let mut c = Conversation::respond(server, secret, &public_for_responder).await.expect("handshake");
            c.recv().await.expect("read").expect("a message")
        });

        let mut initiator =
            Conversation::initiate(client, &public, b"fresh-ephemeral-seed-for-this-one").await.unwrap();
        let sent = Message::text([1u8; 32], [2u8; 32], 7, "the door exists");
        initiator.send(&sent).await.unwrap();

        let received = responder.await.unwrap();
        assert_eq!(received.as_text(), Some("the door exists"));
        assert_eq!(received.seq, sent.seq);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_conversation_carries_many_messages_in_order() {
        // The ratchet advances per message, so the second and later ones are the real test: a framing bug that
        // splits or merges ciphertexts passes the first exchange and fails here.
        let (secret, public) = keypair(b"angelos-driver-many-messages-see");
        let public_for_responder = public.clone();
        let (client, server) = tokio::io::duplex(64 * 1024);

        let responder = tokio::spawn(async move {
            let mut c = Conversation::respond(server, secret, &public_for_responder).await.expect("handshake");
            let mut got = Vec::new();
            while let Some(m) = c.recv().await.expect("read") {
                got.push(m.as_text().unwrap_or_default().to_owned());
            }
            got
        });

        let mut initiator = Conversation::initiate(client, &public, b"another-fresh-ephemeral-seed").await.unwrap();
        for i in 0..16u64 {
            initiator.send(&Message::text([1u8; 32], [2u8; 32], i, &format!("message {i}"))).await.unwrap();
        }
        drop(initiator.into_inner());

        let got = responder.await.unwrap();
        assert_eq!(got.len(), 16, "every message must arrive: {got:?}");
        for (i, text) in got.iter().enumerate() {
            assert_eq!(text, &format!("message {i}"), "messages must arrive in order");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_clean_end_of_stream_is_not_an_error() {
        // The difference between "the conversation ended" and "the conversation broke" — a messenger that
        // cannot tell them apart reports a hang-up as a failure.
        let (secret, public) = keypair(b"angelos-driver-clean-eof-seedxxx");
        let public_for_responder = public.clone();
        let (client, server) = tokio::io::duplex(1024);
        let responder = tokio::spawn(async move {
            let mut c = Conversation::respond(server, secret, &public_for_responder).await.expect("handshake");
            c.recv().await
        });
        let initiator = Conversation::initiate(client, &public, b"eof-seed").await.unwrap();
        drop(initiator.into_inner());
        let result = responder.await.unwrap();
        assert!(matches!(result, Ok(None)), "a clean hang-up must read as end-of-conversation");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_oversize_length_is_refused_before_anything_is_allocated() {
        // The length is attacker-supplied and read *before* the body. Unbounded, a four-byte header is a
        // four-gigabyte allocation from an unauthenticated peer.
        let (client, mut server) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            let _ = server.write_all(&u32::MAX.to_be_bytes()).await;
            let _ = server.flush().await;
            // Hold the stream open so the reader cannot mistake a close for the refusal.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let mut client = client;
        let err = read_frame_eof(&mut client).await.expect_err("an oversize frame must be refused");
        assert!(err.to_string().contains("exceeds"), "got {err}");
        writer.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_handshake_that_does_not_verify_is_refused_rather_than_answered() {
        // A responder that replies to garbage tells an unauthenticated prober it is a messenger.
        let (secret, public_for_responder) = keypair(b"angelos-driver-bad-handshake-see");
        let (client, server) = tokio::io::duplex(4096);
        let responder = tokio::spawn(async move { Conversation::respond(server, secret, &public_for_responder).await.is_ok() });
        let mut client = client;
        write_frame(&mut client, b"not a handshake").await.unwrap();
        assert!(!responder.await.unwrap(), "a bad handshake must not open a session");
    }

    /// **The shipped conversation must ratchet asymmetrically** (#282) — the property the module doc uses to
    /// argue for two encryption layers, and the one the wired half did not have.
    ///
    /// `Session` and `DoubleRatchet` differ observably on the wire: a ratchet message (the first of a new
    /// sending chain) leads with flag `1` and carries a full ML-KEM ratchet public key, so it is *kilobytes*
    /// larger than an in-chain message (flag `0`, a 32-byte key id). `Session` produces neither flag nor key.
    /// Reverting the driver to `Session` fails this on the flag; a driver that merely holds a `DoubleRatchet`
    /// but never steps it fails on the size gap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_wired_conversation_takes_a_kem_ratchet_step_not_just_a_chain_step() {
        let (secret, public) = keypair(b"angelos-driver-pcs-ratchet-seedx");
        let public_for_responder = public.clone();
        let (client, server) = tokio::io::duplex(256 * 1024);

        let responder = tokio::spawn(async move {
            let mut c = Conversation::respond(server, secret, &public_for_responder).await.expect("handshake");
            // Receive, then reply — the reply is the responder's first send after seeing a peer ratchet key,
            // so the alternation invariant says it MUST be a ratchet message.
            let _first = c.recv().await.expect("read").expect("a message");
            c.send(&Message::text([3u8; 32], [4u8; 32], 1, "reply")).await.expect("reply seals");
            c.into_inner()
        });

        let mut initiator =
            Conversation::initiate(client, &public, b"pcs-fresh-ephemeral-seed-value").await.unwrap();
        initiator.send(&Message::text([1u8; 32], [2u8; 32], 0, "hello")).await.unwrap();

        // Read the reply's raw frame rather than opening it: the question is what went on the wire.
        let frame = read_frame(&mut initiator.stream).await.expect("the reply frame");
        let flag = *frame.first().expect("a non-empty frame");
        println!("reply frame: {} bytes, leading flag {flag}", frame.len());
        assert_eq!(flag, 1, "the responder's first reply must be a RATCHET message, not an in-chain one");
        assert!(
            frame.len() > 1024,
            "a ratchet message carries a full ML-KEM public key; {} bytes is an in-chain message wearing the \
             flag",
            frame.len()
        );

        // The other half, so the discriminator is demonstrated rather than asserted: the same plaintext
        // through the symmetric-only `Session` this driver used to hold.
        let (s_secret, s_public) = keypair(b"angelos-driver-pcs-session-halfx");
        let (mut a, hs) = fanos_angelos::session::Session::initiate(&s_public, b"seed-for-the-old-half").unwrap();
        let mut b = fanos_angelos::session::Session::respond(&s_secret, &hs).unwrap();
        let _ = b.open(&a.seal(b"hello").expect("a bounded plaintext always seals"));
        let session_frame =
            b.seal(&Message::text([3u8; 32], [4u8; 32], 1, "reply").to_bytes()).expect("a bounded plaintext always seals");
        println!("session frame: {} bytes, leading byte {}", session_frame.len(), session_frame.first().copied().unwrap_or(255));
        assert!(
            session_frame.len() < 1024,
            "the symmetric half carries no ratchet key, so it cannot reach the size this guard checks: {}",
            session_frame.len()
        );

        let _ = responder.await.unwrap();
    }
}
