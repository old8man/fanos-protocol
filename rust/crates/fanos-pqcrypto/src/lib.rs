//! # fanos-pqcrypto — real post-quantum hybrid primitives (spec §L6)
//!
//! FANOS binds a classical and a post-quantum primitive together so security holds if *either*
//! survives: hybrid signatures `Ed25519 ‖ ML-DSA-65` and a hybrid KEM `X25519 ‖ ML-KEM-768`
//! (combined with SHAKE256). This crate isolates the heavy vetted implementations
//! (`ed25519-dalek`, `x25519-dalek`, `ml-kem`, `ml-dsa`) so the light math core stays free of them.
//!
//! `#![no_std]` with `alloc`: all four vetted primitives are themselves `no_std`, and key generation
//! runs off a caller-supplied [`SeedRng`](rng::SeedRng) (never the OS `getrandom`), so the whole crate
//! — and the overlay engine that verifies membership with it — runs on an embedded target.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod identity;
pub mod kem;
pub mod rng;
pub mod sig;

pub use identity::{Identity, NodeId, PublicIdentity};
pub use kem::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SessionKey};
pub use rng::SeedRng;
pub use sig::{HybridSigSecret, HybridSignature, HybridVerifier};
