//! Canton Network chain family plugin for Open Wallet Standard.
//!
//! This crate enables AI agents and developer tools to securely create, manage,
//! and use Canton Network wallets through the Open Wallet Standard. It provides:
//!
//! - Ed25519/secp256k1 key generation with SLIP-0010 derivation
//! - Canton External Party registration via topology transactions
//! - DAML command signing through the interactive submission protocol
//! - Pre-signing policy enforcement (template allowlists, spending limits, party scope)
//! - Canton-specific MCP tools for AI agent access
//! - CLI commands for wallet creation, signing, and management

pub mod audit;
#[cfg(feature = "cli")]
pub mod cli;
pub mod error;
pub mod identifier;
pub mod keygen;
pub mod ledger_api;
pub mod mcp;
pub mod onboarding;
pub mod policy;
pub mod signing;
pub mod wallet;

pub use error::CantonError;

/// A convenience type alias for results that return [`CantonError`].
pub type CantonResult<T> = Result<T, CantonError>;
