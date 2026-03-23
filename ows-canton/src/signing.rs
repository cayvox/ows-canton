//! Canton signing protocol for messages and DAML command submission.
//!
//! Implements the interactive submission protocol where DAML commands are
//! signed locally with the External Party's private key and submitted to the
//! Canton Ledger API. Policy evaluation occurs before any key decryption.
//! See `specs/04-signing.md` for the full specification.
