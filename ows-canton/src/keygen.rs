//! Ed25519 and secp256k1 key generation with SLIP-0010 derivation.
//!
//! Generates key pairs from BIP-39 mnemonics using SLIP-0010 derivation paths,
//! encodes public keys in DER SubjectPublicKeyInfo format for Canton topology
//! transactions, and provides signing and verification operations.
//! See `specs/02-key-management.md` for the full specification.
