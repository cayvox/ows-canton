//! Error types for the Canton Network plugin.
//!
//! All public functions in this crate return `Result<T, CantonError>`.
//! Error messages never expose private key material.

/// The unified error type for all Canton plugin operations.
#[derive(Debug, thiserror::Error)]
pub enum CantonError {
    // ── Identifier errors ──────────────────────────────────────────
    /// Invalid CAIP-2 chain identifier format.
    #[error("invalid chain id: {detail}")]
    InvalidChainId {
        /// Description of what makes the chain id invalid.
        detail: String,
    },

    /// Invalid CAIP-10 account identifier format.
    #[error("invalid account id: {detail}")]
    InvalidAccountId {
        /// Description of what makes the account id invalid.
        detail: String,
    },

    /// Invalid Canton party identifier format.
    #[error("invalid party id: {detail}")]
    InvalidPartyId {
        /// Description of what makes the party id invalid.
        detail: String,
    },

    // ── Key management errors ──────────────────────────────────────
    /// Key derivation failed (SLIP-0010 or BIP-32).
    #[error("key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// The underlying reason for the derivation failure.
        reason: String,
    },

    /// Invalid or corrupted BIP-39 mnemonic.
    #[error("invalid mnemonic: {reason}")]
    InvalidMnemonic {
        /// Description of what makes the mnemonic invalid.
        reason: String,
    },

    /// DER encoding of public key (SubjectPublicKeyInfo) failed.
    #[error("SPKI encoding failed: {reason}")]
    SpkiEncodingFailed {
        /// The underlying reason for the encoding failure.
        reason: String,
    },

    /// Ed25519 or secp256k1 signing operation failed.
    #[error("signing failed: {reason}")]
    SigningFailed {
        /// The underlying reason for the signing failure.
        reason: String,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// Public key is invalid or malformed.
    #[error("invalid public key: {reason}")]
    InvalidPublicKey {
        /// Description of what makes the public key invalid.
        reason: String,
    },

    /// Unsupported signing algorithm requested.
    #[error("unsupported signing algorithm: {algorithm}")]
    UnsupportedAlgorithm {
        /// The name of the unsupported algorithm.
        algorithm: String,
    },

    // ── Wallet errors ──────────────────────────────────────────────
    /// Wallet file not found on disk.
    #[error("wallet not found: {wallet_id}")]
    WalletNotFound {
        /// The wallet ID or name that was not found.
        wallet_id: String,
    },

    /// Invalid wallet file structure or schema.
    #[error("invalid wallet file: {reason}")]
    InvalidWalletFile {
        /// Description of what makes the wallet file invalid.
        reason: String,
    },

    /// AES-256-GCM decryption failed (wrong passphrase or corrupted data).
    #[error("decryption failed")]
    DecryptionFailed,

    /// AES-256-GCM encryption failed.
    #[error("encryption failed: {reason}")]
    EncryptionFailed {
        /// The underlying reason for the encryption failure.
        reason: String,
    },

    /// Passphrase does not meet minimum requirements (12+ characters).
    #[error("passphrase too short: minimum 12 characters required")]
    PassphraseTooShort,

    // ── Policy errors ──────────────────────────────────────────────
    /// Policy evaluation denied the requested operation.
    #[error("policy denied: {reason}")]
    PolicyDenied {
        /// Reason why the policy denied the operation.
        reason: String,
    },

    /// Policy evaluation encountered an error.
    #[error("policy evaluation failed: {reason}")]
    PolicyEvaluationFailed {
        /// The underlying reason for the evaluation failure.
        reason: String,
    },

    /// Invalid policy file structure.
    #[error("invalid policy: {reason}")]
    InvalidPolicy {
        /// Description of what makes the policy invalid.
        reason: String,
    },

    /// Policy requires simulation before proceeding.
    #[error("simulation required by policy")]
    SimulationRequired,

    // ── Onboarding errors ──────────────────────────────────────────
    /// Canton participant node is unreachable.
    #[error("participant unreachable: {url}")]
    ParticipantUnreachable {
        /// The URL that could not be reached.
        url: String,
    },

    /// Synchronizer is not connected to the participant.
    #[error("synchronizer not connected: {sync_id}")]
    SynchronizerNotConnected {
        /// The synchronizer ID that is not connected.
        sync_id: String,
    },

    /// Topology transaction was rejected by the synchronizer.
    #[error("topology rejected: {reason}")]
    TopologyRejected {
        /// The reason the topology was rejected.
        reason: String,
    },

    /// External Party registration failed.
    #[error("onboarding failed: {reason}")]
    OnboardingFailed {
        /// The underlying reason for the onboarding failure.
        reason: String,
    },

    // ── Ledger API errors ──────────────────────────────────────────
    /// HTTP connection to Ledger API failed.
    #[error("connection failed: {reason}")]
    ConnectionFailed {
        /// The underlying reason for the connection failure.
        reason: String,
    },

    /// Request to Ledger API timed out.
    #[error("request timed out after {ms}ms")]
    RequestTimeout {
        /// The timeout duration in milliseconds.
        ms: u64,
    },

    /// HTTP 401 — authentication required.
    #[error("unauthorized: authentication required")]
    Unauthorized,

    /// HTTP 403 — insufficient permissions.
    #[error("forbidden: {reason}")]
    Forbidden {
        /// Description of the permission issue.
        reason: String,
    },

    /// HTTP 5xx — server error from Canton participant.
    #[error("server error (HTTP {status}): {body}")]
    ServerError {
        /// The HTTP status code.
        status: u16,
        /// The response body.
        body: String,
    },

    /// Ledger API response was malformed or had unexpected format.
    #[error("invalid API response: {reason}")]
    InvalidApiResponse {
        /// Description of what makes the response invalid.
        reason: String,
    },

    /// Command submission to Ledger API failed.
    #[error("submission failed: {reason}")]
    SubmissionFailed {
        /// The underlying reason for the submission failure.
        reason: String,
    },

    /// Command simulation failed.
    #[error("simulation failed: {reason}")]
    SimulationFailed {
        /// The underlying reason for the simulation failure.
        reason: String,
    },

    // ── MCP tool errors ────────────────────────────────────────────
    /// Unknown MCP tool name.
    #[error("unknown tool: {tool_name}")]
    UnknownTool {
        /// The tool name that was not recognized.
        tool_name: String,
    },

    /// Invalid MCP tool arguments.
    #[error("invalid tool arguments: {reason}")]
    ToolArgumentError {
        /// Description of the argument error.
        reason: String,
    },

    // ── Generic errors ─────────────────────────────────────────────
    /// JSON serialization or deserialization failed.
    #[error("serialization error: {reason}")]
    SerializationError {
        /// The underlying reason for the serialization failure.
        reason: String,
    },

    /// File system I/O error.
    #[error("I/O error: {reason}")]
    IoError {
        /// The underlying reason for the I/O error.
        reason: String,
    },

    /// Audit log write failed.
    #[error("audit log write failed: {reason}")]
    AuditLogWriteFailed {
        /// The underlying reason for the audit log failure.
        reason: String,
    },
}

impl From<std::io::Error> for CantonError {
    fn from(err: std::io::Error) -> Self {
        CantonError::IoError {
            reason: err.to_string(),
        }
    }
}

impl From<serde_json::Error> for CantonError {
    fn from(err: serde_json::Error) -> Self {
        CantonError::SerializationError {
            reason: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CantonError::InvalidChainId {
            detail: "missing namespace".to_string(),
        };
        assert_eq!(err.to_string(), "invalid chain id: missing namespace");
    }

    #[test]
    fn test_policy_denied_display() {
        let err = CantonError::PolicyDenied {
            reason: "template not in allowlist".to_string(),
        };
        assert_eq!(err.to_string(), "policy denied: template not in allowlist");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let canton_err: CantonError = io_err.into();
        assert!(matches!(canton_err, CantonError::IoError { .. }));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CantonError>();
    }
}
