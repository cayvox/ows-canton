//! Request and response types for the Canton Ledger API v2.
//!
//! Defines the JSON-serializable types used in Ledger API communication,
//! including command submission requests, completion responses, party
//! information, and active contract queries.

use serde::{Deserialize, Serialize};

// ── Topology ───────────────────────────────────────────────────────

/// Request body for `POST /v2/parties/external/generate-topology`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateTopologyRequest {
    /// Base64-encoded DER public key (SPKI).
    pub public_key: String,
    /// Synchronizer identifier.
    pub synchronizer: String,
}

/// Response from `POST /v2/parties/external/generate-topology`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateTopologyResponse {
    /// Generated Canton party identifier.
    pub party_id: String,
    /// Base64-encoded topology transactions to be signed.
    pub transactions: Vec<String>,
}

/// Request body for `POST /v2/parties/external/allocate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocatePartyRequest {
    /// Synchronizer identifier.
    pub synchronizer: String,
    /// Signed topology transactions (base64).
    pub onboarding_transactions: Vec<String>,
    /// Signatures for the topology transactions.
    pub multi_hash_signatures: Vec<MultiHashSignatureRequest>,
}

/// Response from `POST /v2/parties/external/allocate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocatePartyResponse {
    /// Allocated Canton party identifier.
    pub party_id: String,
}

/// A Canton multi-hash signature object for API requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiHashSignatureRequest {
    /// Signature format (e.g. `"SIGNATURE_FORMAT_CONCAT"`).
    pub format: String,
    /// Base64-encoded signature bytes.
    pub signature: String,
    /// Key fingerprint.
    pub signed_by: String,
    /// Signing algorithm spec string.
    pub signing_algorithm_spec: String,
}

// ── Command Submission ─────────────────────────────────────────────

/// Request body for `POST /v2/commands/submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitCommandRequest {
    /// The command payload (actAs, readAs, commandId, commands).
    pub commands: serde_json::Value,
    /// Signatures for the submission.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub multi_hash_signatures: Vec<MultiHashSignatureRequest>,
}

/// Response from `POST /v2/commands/submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitCommandResponse {
    /// Command identifier echoed back.
    #[serde(default)]
    pub command_id: String,
    /// Completion offset.
    #[serde(default)]
    pub completion_offset: Option<String>,
    /// Transaction identifier (if committed).
    #[serde(default)]
    pub transaction_id: Option<String>,
}

/// Request body for `POST /v2/commands/simulate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateCommandRequest {
    /// The command payload.
    pub commands: serde_json::Value,
}

/// Response from `POST /v2/commands/simulate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateCommandResponse {
    /// Whether the simulation succeeded.
    #[serde(default)]
    pub success: bool,
    /// Error message if simulation failed.
    #[serde(default)]
    pub error_message: Option<String>,
}

// ── Parties ────────────────────────────────────────────────────────

/// Party details returned by `GET /v2/parties`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyDetails {
    /// Canton party identifier.
    pub party: String,
    /// Whether the party is local to this participant.
    pub is_local: bool,
    /// Participant permissions for this party.
    #[serde(default)]
    pub participant_permissions: Vec<serde_json::Value>,
}

/// Wrapper for the parties list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartiesResponse {
    /// List of party details.
    pub party_details: Vec<PartyDetails>,
}

// ── Active Contracts ───────────────────────────────────────────────

/// An active contract from `GET /v2/state/active-contracts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveContract {
    /// Contract identifier.
    pub contract_id: String,
    /// Fully qualified DAML template identifier.
    pub template_id: String,
    /// Contract payload (DAML values).
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Signatory parties.
    #[serde(default)]
    pub signatories: Vec<String>,
    /// Observer parties.
    #[serde(default)]
    pub observers: Vec<String>,
}

/// Wrapper for the active contracts response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveContractsResponse {
    /// List of active contracts.
    #[serde(default)]
    pub active_contracts: Vec<ActiveContract>,
}

// ── Completions ────────────────────────────────────────────────────

/// A command completion from `GET /v2/completions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Completion {
    /// Command identifier.
    pub command_id: String,
    /// Completion status.
    pub status: String,
    /// Ledger offset.
    #[serde(default)]
    pub offset: Option<String>,
    /// Transaction identifier (if committed).
    #[serde(default)]
    pub transaction_id: Option<String>,
}

/// Wrapper for the completions response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionsResponse {
    /// List of completions.
    #[serde(default)]
    pub completions: Vec<Completion>,
}

// ── Synchronizers ──────────────────────────────────────────────────

/// A connected synchronizer from `GET /v2/state/connected-synchronizers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectedSynchronizer {
    /// Full synchronizer identifier.
    pub synchronizer_id: String,
    /// Human-readable alias.
    pub alias: String,
}

/// Wrapper for connected synchronizers response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectedSynchronizersResponse {
    /// List of connected synchronizers.
    pub connected_synchronizers: Vec<ConnectedSynchronizer>,
}
