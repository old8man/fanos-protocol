//! # THESAUROS — the FANOS content-storage platform
//!
//! *Greek θησαυρός, a storehouse or treasury.* THESAUROS is the platform's **O — Foundation** organ: an
//! advanced, post-quantum, monetized IPFS analog built *on top of* the L4 projective-LRC erasure store, not
//! beside it (`docs/design-storage.md`, `spec/platform.md` §7). It adds the three things the substrate lacks —
//! **immutable content addressing**, a **proof of retrievability**, and a **capacity market** — while reusing
//! the `[7,3,4]` erasure codec, coordinate placement, DA sampling, roles/reputation, and the DROMOS payment
//! rails verbatim.
//!
//! This first module is the [`content`] model — the content-addressing layer everything else rests on. An
//! object is sealed at the edge, split into fixed-size leaves, and committed by a BLAKE3 **Merkle tree** whose
//! root *is* the content id ([`Cid`]): the content address and the storage commitment, one object. Large
//! objects are UnixFS-style [`Manifest`] DAGs of chunk CIDs. Leaf hashes are **position-bound**, so the same
//! bytes at a different index commit differently — the property a proof of retrievability needs to stop a
//! provider from answering every challenge with a single retained leaf.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod content;

pub use content::{Cid, ChunkRef, Manifest, MerkleProof, MerkleStep, chunk_cid, verify_leaf};
