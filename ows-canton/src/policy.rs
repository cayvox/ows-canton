//! Canton-specific policy rule types and evaluation engine.
//!
//! Enforces pre-signing policies including template allowlists, choice restrictions,
//! party scope limits, simulation requirements, and synchronizer restrictions.
//! All policies are evaluated before any key material is decrypted.
//! See `specs/05-policy-engine.md` for the full specification.
