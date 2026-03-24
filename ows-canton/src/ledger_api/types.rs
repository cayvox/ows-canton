//! Request and response types for the Canton Ledger API v2.
//!
//! Types are derived from the actual Canton 3.4.10 HTTP JSON API responses.
//! All JSON fields use camelCase per the Canton HTTP API convention.

use serde::{Deserialize, Serialize};

// ── Topology (CN Quickstart / CN Network specific) ─────────────────

/// Request body for `POST /v2/parties/external/generate-topology`.
///
/// Note: this endpoint is only available on CN Network nodes (CN Quickstart),
/// not on the standalone Canton sandbox.
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

// ── Standard Party Allocation ──────────────────────────────────────

/// Request body for `POST /v2/parties` (standard party allocation).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocatePartyHintRequest {
    /// Party ID hint (becomes the party name prefix).
    pub party_id_hint: String,
    /// Human-readable display name.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub display_name: String,
    /// Identity provider ID (empty string for default).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub identity_provider_id: String,
}

/// Response from `POST /v2/parties`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocatePartyHintResponse {
    /// Details of the newly allocated party.
    pub party_details: PartyDetails,
}

// ── Command Submission ─────────────────────────────────────────────

/// Request body for `POST /v2/commands/submit-and-wait`.
///
/// In sandbox mode (no auth configured), `user_id` can be provided directly
/// in the request body to identify the submitting user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitCommandRequest {
    /// The command payload (actAs, readAs, commandId, commands).
    pub commands: serde_json::Value,
    /// Signatures for the submission.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub multi_hash_signatures: Vec<MultiHashSignatureRequest>,
}

/// Response from `POST /v2/commands/submit-and-wait`.
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

/// Local party metadata from `GET /v2/parties`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PartyLocalMetadata {
    /// Resource version for optimistic concurrency.
    #[serde(default)]
    pub resource_version: String,
    /// Arbitrary key-value annotations.
    #[serde(default)]
    pub annotations: serde_json::Value,
}

/// Party details returned by `GET /v2/parties` and `POST /v2/parties`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyDetails {
    /// Canton party identifier (`name::fingerprint`).
    pub party: String,
    /// Whether the party is local to this participant.
    pub is_local: bool,
    /// Local metadata (present for local parties).
    #[serde(default)]
    pub local_metadata: Option<PartyLocalMetadata>,
    /// Identity provider ID.
    #[serde(default)]
    pub identity_provider_id: String,
}

/// Wrapper for the parties list response (`GET /v2/parties`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartiesResponse {
    /// List of party details.
    pub party_details: Vec<PartyDetails>,
    /// Pagination token for the next page.
    #[serde(default)]
    pub next_page_token: String,
}

// ── Active Contracts ───────────────────────────────────────────────

/// Request body for `POST /v2/state/active-contracts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveContractsRequest {
    /// Filter for contracts (by party or template).
    pub filter: serde_json::Value,
    /// Include verbose contract payload.
    #[serde(default)]
    pub verbose: bool,
    /// Ledger offset at which to query active contracts (integer).
    pub active_at_offset: i64,
}

/// An active contract from `POST /v2/state/active-contracts`.
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

// ── Completions ────────────────────────────────────────────────────

/// Request body for `POST /v2/commands/completions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionsRequest {
    /// Parties to get completions for.
    pub parties: Vec<String>,
    /// Starting offset (exclusive), as an integer ledger offset.
    pub begin_exclusive: i64,
    /// User ID (for sandbox no-auth mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// A command completion from `POST /v2/commands/completions`.
///
/// The response is a JSON array of completion response objects.
/// Each element has a `completionResponse` discriminated union.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionWrapper {
    /// The completion response (discriminated union).
    pub completion_response: serde_json::Value,
}

/// A command completion entry (extracted from CompletionWrapper).
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

// ── Synchronizers ──────────────────────────────────────────────────

/// A connected synchronizer from `GET /v2/state/connected-synchronizers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectedSynchronizer {
    /// Full synchronizer identifier (`alias::fingerprint`).
    pub synchronizer_id: String,
    /// Human-readable synchronizer alias.
    pub synchronizer_alias: String,
    /// Participant permission on this synchronizer.
    #[serde(default)]
    pub permission: String,
}

/// Wrapper for connected synchronizers response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectedSynchronizersResponse {
    /// List of connected synchronizers.
    pub connected_synchronizers: Vec<ConnectedSynchronizer>,
}

// ── Ledger API Error ───────────────────────────────────────────────

/// Error response body from the Canton Ledger API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerApiError {
    /// Canton error code.
    pub code: String,
    /// Human-readable error cause.
    pub cause: String,
    /// Correlation ID (if provided in request).
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// Trace ID for distributed tracing.
    #[serde(default)]
    pub trace_id: Option<String>,
}
