//! # fanos-pqcrypto — real post-quantum hybrid primitives (spec §L6)
//!
//! FANOS binds a classical and a post-quantum primitive together so security holds if *either*
//! survives: hybrid signatures `Ed25519 ‖ ML-DSA-65` and a hybrid KEM `X25519 ‖ ML-KEM-768`
//! (combined with SHAKE256). This crate isolates the heavy vetted implementations
//! (`ed25519-dalek`, `x25519-dalek`, `ml-kem`, `ml-dsa`) so the `no_std` math core stays light.

#![forbid(unsafe_code)]

pub mod identity;
pub mod kem;
pub mod rng;
pub mod sig;

pub use identity::{Identity, NodeId, PublicIdentity};
pub use kem::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SessionKey};
pub use rng::SeedRng;
pub use sig::{HybridSigSecret, HybridSignature, HybridVerifier};
