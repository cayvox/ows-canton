//! Canton Ledger API v2 client module.
//!
//! Provides an HTTP JSON API client for communicating with Canton participant
//! nodes, including command submission, topology management, party listing,
//! and contract queries.
//! See `specs/07-ledger-api.md` for the full specification.

pub mod client;
pub mod commands;
pub mod topology;
pub mod types;

pub use client::LedgerApiClient;
pub use types::*;
