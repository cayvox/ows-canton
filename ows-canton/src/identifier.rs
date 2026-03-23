//! CAIP-2 and CAIP-10 Canton identifier parsing and validation.
//!
//! All chain references use CAIP-2 format (`canton:global`, `canton:devnet`).
//! All account references use CAIP-10 format (`canton:global:alice::1220abcd`).
//! See `specs/01-identifiers.md` for the full specification.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::CantonError;

/// The required CAIP-2 namespace for Canton identifiers.
const CANTON_NAMESPACE: &str = "canton";

/// Maximum length for the CAIP-2 reference portion.
const MAX_REFERENCE_LEN: usize = 32;

/// Maximum length for the party hint portion.
const MAX_HINT_LEN: usize = 64;

/// Minimum length for the fingerprint portion.
const MIN_FINGERPRINT_LEN: usize = 8;

/// Maximum length for the fingerprint portion.
const MAX_FINGERPRINT_LEN: usize = 64;

/// The `::` separator used in Canton party IDs.
const PARTY_SEPARATOR: &str = "::";

// ── CantonChainId ──────────────────────────────────────────────────

/// CAIP-2 Canton chain identifier.
///
/// Format: `canton:<reference>` where reference matches `[-_a-zA-Z0-9]{1,32}`.
///
/// # Examples
///
/// ```
/// use ows_canton::identifier::CantonChainId;
///
/// let chain = CantonChainId::parse("canton:global").unwrap();
/// assert_eq!(chain.reference, "global");
/// assert_eq!(chain.to_caip2(), "canton:global");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CantonChainId {
    /// Always `"canton"`.
    pub namespace: String,
    /// Synchronizer reference (e.g., `"global"`, `"devnet"`, `"sandbox"`).
    pub reference: String,
}

impl CantonChainId {
    /// CAIP-2 identifier for the Canton Global Synchronizer (production).
    pub const GLOBAL: &'static str = "canton:global";

    /// CAIP-2 identifier for the Canton Devnet (shared dev environment).
    pub const DEVNET: &'static str = "canton:devnet";

    /// CAIP-2 identifier for the local Canton Sandbox (Docker).
    pub const SANDBOX: &'static str = "canton:sandbox";

    /// Parse a CAIP-2 string into a `CantonChainId`.
    ///
    /// Returns `Err(CantonError::InvalidChainId)` if the format is invalid.
    pub fn parse(s: &str) -> Result<Self, CantonError> {
        s.parse()
    }

    /// Format as a CAIP-2 string (`canton:<reference>`).
    pub fn to_caip2(&self) -> String {
        format!("{}:{}", self.namespace, self.reference)
    }
}

/// Returns `true` if every character in `s` matches `[-_a-zA-Z0-9]`.
fn is_valid_reference(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl FromStr for CantonChainId {
    type Err = CantonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (namespace, reference) =
            s.split_once(':')
                .ok_or_else(|| CantonError::InvalidChainId {
                    detail: format!("missing ':' separator in \"{s}\""),
                })?;

        if namespace != CANTON_NAMESPACE {
            return Err(CantonError::InvalidChainId {
                detail: format!("namespace must be \"{CANTON_NAMESPACE}\", got \"{namespace}\""),
            });
        }

        if reference.is_empty() {
            return Err(CantonError::InvalidChainId {
                detail: "reference must not be empty".to_string(),
            });
        }

        if reference.len() > MAX_REFERENCE_LEN {
            return Err(CantonError::InvalidChainId {
                detail: format!(
                    "reference too long ({} chars, max {MAX_REFERENCE_LEN})",
                    reference.len()
                ),
            });
        }

        if !is_valid_reference(reference) {
            return Err(CantonError::InvalidChainId {
                detail: format!(
                    "reference contains invalid characters: \"{reference}\" (allowed: [-_a-zA-Z0-9])"
                ),
            });
        }

        Ok(Self {
            namespace: CANTON_NAMESPACE.to_string(),
            reference: reference.to_string(),
        })
    }
}

impl fmt::Display for CantonChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

// ── CantonPartyId ──────────────────────────────────────────────────

/// Canton party identifier.
///
/// Format: `<hint>::<fingerprint>` where hint is a human-readable label
/// and fingerprint is a hex-encoded SHA-256 prefix of the public key.
///
/// # Examples
///
/// ```
/// use ows_canton::identifier::CantonPartyId;
///
/// let party = CantonPartyId::parse("alice::1220abcd").unwrap();
/// assert_eq!(party.hint, "alice");
/// assert_eq!(party.fingerprint, "1220abcd");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CantonPartyId {
    /// Human-readable hint (e.g., `"alice"`, `"agent-treasury"`).
    pub hint: String,
    /// Namespace fingerprint — hex-encoded SHA-256 prefix of the public key.
    pub fingerprint: String,
}

/// Returns `true` if every character in `s` matches `[a-zA-Z0-9_-]`.
fn is_valid_hint(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Returns `true` if every character in `s` is lowercase hex (`[0-9a-f]`).
fn is_lowercase_hex(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

impl CantonPartyId {
    /// Parse a Canton party ID string (e.g., `"alice::1220abcd"`).
    ///
    /// Returns `Err(CantonError::InvalidPartyId)` if the format is invalid.
    pub fn parse(s: &str) -> Result<Self, CantonError> {
        s.parse()
    }
}

impl FromStr for CantonPartyId {
    type Err = CantonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hint, fingerprint) =
            s.split_once(PARTY_SEPARATOR)
                .ok_or_else(|| CantonError::InvalidPartyId {
                    detail: format!("missing \"::\" separator in \"{s}\""),
                })?;

        if hint.is_empty() {
            return Err(CantonError::InvalidPartyId {
                detail: "hint must not be empty".to_string(),
            });
        }

        if hint.len() > MAX_HINT_LEN {
            return Err(CantonError::InvalidPartyId {
                detail: format!("hint too long ({} chars, max {MAX_HINT_LEN})", hint.len()),
            });
        }

        if !is_valid_hint(hint) {
            return Err(CantonError::InvalidPartyId {
                detail: format!(
                    "hint contains invalid characters: \"{hint}\" (allowed: [a-zA-Z0-9_-])"
                ),
            });
        }

        if fingerprint.is_empty() {
            return Err(CantonError::InvalidPartyId {
                detail: "fingerprint must not be empty".to_string(),
            });
        }

        if fingerprint.len() < MIN_FINGERPRINT_LEN {
            return Err(CantonError::InvalidPartyId {
                detail: format!(
                    "fingerprint too short ({} chars, min {MIN_FINGERPRINT_LEN})",
                    fingerprint.len()
                ),
            });
        }

        if fingerprint.len() > MAX_FINGERPRINT_LEN {
            return Err(CantonError::InvalidPartyId {
                detail: format!(
                    "fingerprint too long ({} chars, max {MAX_FINGERPRINT_LEN})",
                    fingerprint.len()
                ),
            });
        }

        if !is_lowercase_hex(fingerprint) {
            return Err(CantonError::InvalidPartyId {
                detail: format!("fingerprint must be lowercase hex: \"{fingerprint}\""),
            });
        }

        Ok(Self {
            hint: hint.to_string(),
            fingerprint: fingerprint.to_string(),
        })
    }
}

impl fmt::Display for CantonPartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.hint, self.fingerprint)
    }
}

// ── CantonAccountId ────────────────────────────────────────────────

/// CAIP-10 Canton account identifier.
///
/// Format: `canton:<reference>:<hint>::<fingerprint>`.
///
/// The first colon after the reference separates the chain ID from the party ID.
/// The `::` within the party ID is part of Canton's party identifier format.
///
/// # Examples
///
/// ```
/// use ows_canton::identifier::CantonAccountId;
///
/// let acct = CantonAccountId::parse("canton:global:alice::1220abcd").unwrap();
/// assert_eq!(acct.chain_id.reference, "global");
/// assert_eq!(acct.party_id.hint, "alice");
/// assert_eq!(acct.to_caip10(), "canton:global:alice::1220abcd");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CantonAccountId {
    /// The CAIP-2 chain portion.
    pub chain_id: CantonChainId,
    /// The Canton party ID portion.
    pub party_id: CantonPartyId,
}

impl CantonAccountId {
    /// Parse a CAIP-10 string into a `CantonAccountId`.
    ///
    /// The expected format is `canton:<reference>:<party_id>` where `party_id`
    /// itself contains a `::` separator (e.g., `canton:global:alice::1220abcd`).
    ///
    /// Returns `Err(CantonError::InvalidAccountId)` if the format is invalid.
    pub fn parse(s: &str) -> Result<Self, CantonError> {
        s.parse()
    }

    /// Format as a CAIP-10 string.
    pub fn to_caip10(&self) -> String {
        format!("{}:{}", self.chain_id.to_caip2(), self.party_id)
    }
}

impl FromStr for CantonAccountId {
    type Err = CantonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split into exactly 3 parts on the first two single colons.
        // The format is: canton:<ref>:<party_id>
        // where party_id = <hint>::<fingerprint>
        //
        // Strategy: find the namespace ("canton"), then the reference (up to the
        // next ':'), then everything after that is the party_id.

        let (namespace, rest) = s
            .split_once(':')
            .ok_or_else(|| CantonError::InvalidAccountId {
                detail: format!("missing ':' separator in \"{s}\""),
            })?;

        if namespace != CANTON_NAMESPACE {
            return Err(CantonError::InvalidAccountId {
                detail: format!("namespace must be \"{CANTON_NAMESPACE}\", got \"{namespace}\""),
            });
        }

        // rest = "<reference>:<party_id>"
        // We need to split on the first single ':' that is NOT part of '::'
        // Find the position of the first ':' that is not immediately followed by another ':'
        // and not immediately preceded by another ':'.
        let (reference, party_str) =
            split_ref_and_party(rest).ok_or_else(|| CantonError::InvalidAccountId {
                detail: format!("cannot separate reference and party in \"{rest}\""),
            })?;

        let chain_id = CantonChainId::from_str(&format!("{CANTON_NAMESPACE}:{reference}"))
            .map_err(|e| CantonError::InvalidAccountId {
                detail: format!("invalid chain id: {e}"),
            })?;

        if party_str.is_empty() {
            return Err(CantonError::InvalidAccountId {
                detail: "party id must not be empty".to_string(),
            });
        }

        let party_id =
            CantonPartyId::from_str(party_str).map_err(|e| CantonError::InvalidAccountId {
                detail: format!("invalid party id: {e}"),
            })?;

        Ok(Self { chain_id, party_id })
    }
}

/// Split `"<reference>:<hint>::<fingerprint>"` into `("<reference>", "<hint>::<fingerprint>")`.
///
/// We scan for the first single `:` that is not part of a `::` sequence.
fn split_ref_and_party(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            // Check if this is part of "::" (look at the next character)
            if i + 1 < bytes.len() && bytes[i + 1] == b':' {
                // Skip the "::" pair
                i += 2;
                continue;
            }
            // Single ':', this is our split point
            return Some((&s[..i], &s[i + 1..]));
        }
        i += 1;
    }
    None
}

impl fmt::Display for CantonAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.chain_id, self.party_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CantonChainId tests ────────────────────────────────────────

    #[test]
    fn test_caip2_parse_global() {
        let chain = CantonChainId::parse("canton:global").unwrap();
        assert_eq!(chain.namespace, "canton");
        assert_eq!(chain.reference, "global");
    }

    #[test]
    fn test_caip2_parse_devnet() {
        let chain = CantonChainId::parse("canton:devnet").unwrap();
        assert_eq!(chain.reference, "devnet");
    }

    #[test]
    fn test_caip2_parse_custom() {
        let chain = CantonChainId::parse("canton:my-sync").unwrap();
        assert_eq!(chain.reference, "my-sync");
    }

    #[test]
    fn test_caip2_parse_invalid_ns() {
        let err = CantonChainId::parse("eip155:1").unwrap_err();
        assert!(matches!(err, CantonError::InvalidChainId { .. }));
    }

    #[test]
    fn test_caip2_parse_empty_ref() {
        let err = CantonChainId::parse("canton:").unwrap_err();
        assert!(matches!(err, CantonError::InvalidChainId { .. }));
    }

    #[test]
    fn test_caip2_parse_too_long() {
        let long_ref = "a".repeat(33);
        let input = format!("canton:{long_ref}");
        let err = CantonChainId::parse(&input).unwrap_err();
        assert!(matches!(err, CantonError::InvalidChainId { .. }));
    }

    #[test]
    fn test_caip2_parse_invalid_chars() {
        let err = CantonChainId::parse("canton:foo bar").unwrap_err();
        assert!(matches!(err, CantonError::InvalidChainId { .. }));
    }

    #[test]
    fn test_caip2_roundtrip() {
        let chain = CantonChainId::parse("canton:global").unwrap();
        let reparsed = CantonChainId::parse(&chain.to_caip2()).unwrap();
        assert_eq!(chain, reparsed);
    }

    #[test]
    fn test_caip2_display() {
        let chain = CantonChainId::parse("canton:sandbox").unwrap();
        assert_eq!(chain.to_string(), "canton:sandbox");
    }

    #[test]
    fn test_caip2_constants() {
        assert_eq!(CantonChainId::GLOBAL, "canton:global");
        assert_eq!(CantonChainId::DEVNET, "canton:devnet");
        assert_eq!(CantonChainId::SANDBOX, "canton:sandbox");

        // Constants must be parseable
        CantonChainId::parse(CantonChainId::GLOBAL).unwrap();
        CantonChainId::parse(CantonChainId::DEVNET).unwrap();
        CantonChainId::parse(CantonChainId::SANDBOX).unwrap();
    }

    #[test]
    fn test_caip2_serde_roundtrip() {
        let chain = CantonChainId::parse("canton:global").unwrap();
        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: CantonChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, deserialized);
    }

    #[test]
    fn test_caip2_no_colon() {
        let err = CantonChainId::parse("cantonglobal").unwrap_err();
        assert!(matches!(err, CantonError::InvalidChainId { .. }));
    }

    #[test]
    fn test_caip2_underscore_ref() {
        let chain = CantonChainId::parse("canton:my_sync").unwrap();
        assert_eq!(chain.reference, "my_sync");
    }

    // ── CantonPartyId tests ────────────────────────────────────────

    #[test]
    fn test_party_id_parse_valid() {
        let party = CantonPartyId::parse("alice::1220abcd").unwrap();
        assert_eq!(party.hint, "alice");
        assert_eq!(party.fingerprint, "1220abcd");
    }

    #[test]
    fn test_party_id_parse_no_hint() {
        let err = CantonPartyId::parse("::1220abcd").unwrap_err();
        assert!(matches!(err, CantonError::InvalidPartyId { .. }));
    }

    #[test]
    fn test_party_id_parse_no_fp() {
        let err = CantonPartyId::parse("alice::").unwrap_err();
        assert!(matches!(err, CantonError::InvalidPartyId { .. }));
    }

    #[test]
    fn test_party_id_parse_no_separator() {
        let err = CantonPartyId::parse("alice1220abcd").unwrap_err();
        assert!(matches!(err, CantonError::InvalidPartyId { .. }));
    }

    #[test]
    fn test_party_id_display() {
        let party = CantonPartyId::parse("alice::1220abcd").unwrap();
        assert_eq!(party.to_string(), "alice::1220abcd");
    }

    #[test]
    fn test_party_id_hyphen_hint() {
        let party = CantonPartyId::parse("agent-treasury::1220abcdef01").unwrap();
        assert_eq!(party.hint, "agent-treasury");
    }

    #[test]
    fn test_party_id_uppercase_hex_rejected() {
        let err = CantonPartyId::parse("alice::1220ABCD").unwrap_err();
        assert!(matches!(err, CantonError::InvalidPartyId { .. }));
    }

    #[test]
    fn test_party_id_fingerprint_too_short() {
        let err = CantonPartyId::parse("alice::1234567").unwrap_err(); // 7 chars < 8
        assert!(matches!(err, CantonError::InvalidPartyId { .. }));
    }

    #[test]
    fn test_party_id_serde_roundtrip() {
        let party = CantonPartyId::parse("bob::1220aabbccdd").unwrap();
        let json = serde_json::to_string(&party).unwrap();
        let deserialized: CantonPartyId = serde_json::from_str(&json).unwrap();
        assert_eq!(party, deserialized);
    }

    // ── CantonAccountId tests ──────────────────────────────────────

    #[test]
    fn test_caip10_parse_full() {
        let acct = CantonAccountId::parse("canton:global:alice::1220abcd").unwrap();
        assert_eq!(acct.chain_id.reference, "global");
        assert_eq!(acct.party_id.hint, "alice");
        assert_eq!(acct.party_id.fingerprint, "1220abcd");
    }

    #[test]
    fn test_caip10_parse_long_hint() {
        let acct = CantonAccountId::parse("canton:devnet:agent-treasury::1220abcd").unwrap();
        assert_eq!(acct.chain_id.reference, "devnet");
        assert_eq!(acct.party_id.hint, "agent-treasury");
    }

    #[test]
    fn test_caip10_parse_missing_party() {
        let err = CantonAccountId::parse("canton:global:").unwrap_err();
        assert!(matches!(err, CantonError::InvalidAccountId { .. }));
    }

    #[test]
    fn test_caip10_parse_no_separator() {
        let err = CantonAccountId::parse("canton:global:alice1220abcd").unwrap_err();
        assert!(matches!(err, CantonError::InvalidAccountId { .. }));
    }

    #[test]
    fn test_caip10_roundtrip() {
        let acct = CantonAccountId::parse("canton:global:alice::1220abcd").unwrap();
        let reparsed = CantonAccountId::parse(&acct.to_caip10()).unwrap();
        assert_eq!(acct, reparsed);
    }

    #[test]
    fn test_caip10_display() {
        let acct = CantonAccountId::parse("canton:sandbox:bob::aabbccdd").unwrap();
        assert_eq!(acct.to_string(), "canton:sandbox:bob::aabbccdd");
    }

    #[test]
    fn test_caip10_serde_roundtrip() {
        let acct = CantonAccountId::parse("canton:global:alice::1220abcd").unwrap();
        let json = serde_json::to_string(&acct).unwrap();
        let deserialized: CantonAccountId = serde_json::from_str(&json).unwrap();
        assert_eq!(acct, deserialized);
    }

    #[test]
    fn test_caip10_invalid_namespace() {
        let err = CantonAccountId::parse("eip155:1:alice::1220abcd").unwrap_err();
        assert!(matches!(err, CantonError::InvalidAccountId { .. }));
    }

    // ── split_ref_and_party tests ──────────────────────────────────

    #[test]
    fn test_split_ref_and_party_basic() {
        let (r, p) = split_ref_and_party("global:alice::1220abcd").unwrap();
        assert_eq!(r, "global");
        assert_eq!(p, "alice::1220abcd");
    }

    #[test]
    fn test_split_ref_and_party_no_single_colon() {
        // Only contains "::", no single ':'
        assert!(split_ref_and_party("alice::1220abcd").is_none());
    }
}
