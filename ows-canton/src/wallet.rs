//! Canton wallet file format (create, read, write, encrypt, decrypt).
//!
//! Manages Canton wallet files stored in `~/.ows/wallets/`, including
//! AES-256-GCM encryption of mnemonic material with scrypt-derived keys.
//! See `specs/03-wallet-format.md` for the full specification.
