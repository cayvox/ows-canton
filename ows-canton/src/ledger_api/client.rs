//! HTTP JSON API client for the Canton Ledger API v2.
//!
//! Implements the `reqwest`-based client with authentication token injection,
//! retry logic (3x on connection error, 2x on 5xx), and error mapping from
//! HTTP status codes to [`CantonError`](crate::CantonError) variants.
