# Spec 07 — Canton Ledger API v2 Client

## Overview

The Ledger API client is an async HTTP JSON client that communicates with a Canton Participant Node. It wraps the Canton Ledger API v2 endpoints needed for OWS operations.

## Base URL

Default: `http://localhost:7575` (Canton Sandbox default)
Override: `OWS_CANTON_PARTICIPANT_URL` env var, or wallet's `canton_config.participant_url`

## Client Structure

```rust
pub struct LedgerApiClient {
    http: reqwest::Client,
    base_url: String,
    auth_token: Option<String>,
    timeout: Duration,
}

impl LedgerApiClient {
    pub fn new(base_url: &str, auth_token: Option<String>) -> Self { ... }

    // ─── Party Management ───
    pub async fn generate_external_topology(
        &self, public_key_base64: &str, synchronizer: &str,
    ) -> Result<GenerateTopologyResponse, CantonError> { ... }

    pub async fn allocate_external_party(
        &self, req: &AllocatePartyRequest,
    ) -> Result<AllocatePartyResponse, CantonError> { ... }

    pub async fn list_parties(
        &self, filter: Option<&str>,
    ) -> Result<Vec<PartyDetails>, CantonError> { ... }

    // ─── Command Submission ───
    pub async fn submit_command(
        &self, req: &SubmitCommandRequest,
    ) -> Result<SubmitCommandResponse, CantonError> { ... }

    pub async fn simulate_command(
        &self, req: &SimulateCommandRequest,
    ) -> Result<SimulateCommandResponse, CantonError> { ... }

    // ─── Queries ───
    pub async fn get_active_contracts(
        &self, template_id: &str, parties: &[String],
    ) -> Result<Vec<ActiveContract>, CantonError> { ... }

    pub async fn get_completions(
        &self, offset: &str, parties: &[String],
    ) -> Result<Vec<Completion>, CantonError> { ... }

    // ─── State ───
    pub async fn get_connected_synchronizers(
        &self,
    ) -> Result<Vec<ConnectedSynchronizer>, CantonError> { ... }

    pub async fn health_check(&self) -> Result<bool, CantonError> { ... }
}
```

## API Endpoints

### POST /v2/parties/external/generate-topology

```json
// Request
{ "publicKey": "MCowBQYDK2VwAyEA...", "synchronizer": "canton::sync-id" }

// Response
{
  "partyId": "agent-treasury::1220abcd",
  "transactions": ["base64-encoded-topology-tx-1", "base64-encoded-topology-tx-2"]
}
```

### POST /v2/parties/external/allocate

```json
// Request
{
  "synchronizer": "canton::sync-id",
  "onboardingTransactions": ["base64-tx-1", "base64-tx-2"],
  "multiHashSignatures": [
    {
      "format": "SIGNATURE_FORMAT_CONCAT",
      "signature": "base64-signature",
      "signedBy": "1220abcdef...",
      "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
    }
  ]
}

// Response
{ "partyId": "agent-treasury::1220abcd" }
```

### GET /v2/parties

```
GET /v2/parties?filter-party=agent-treasury

Response:
{
  "partyDetails": [
    {
      "party": "agent-treasury::1220abcd",
      "isLocal": false,
      "participantPermissions": [...]
    }
  ]
}
```

### POST /v2/commands/submit

```json
// Request (simplified — exact format per Canton docs)
{
  "commands": {
    "actAs": ["agent-treasury::1220abcd"],
    "readAs": [],
    "commandId": "uuid-v4",
    "commands": [
      {
        "ExerciseCommand": {
          "templateId": "Daml.Finance.Holding.Fungible:Fungible",
          "contractId": "00a1b2c3d4...",
          "choice": "Transfer",
          "choiceArgument": { "newOwner": "recipient::1220dead" }
        }
      }
    ]
  },
  "multiHashSignatures": [
    {
      "format": "SIGNATURE_FORMAT_CONCAT",
      "signature": "base64-sig",
      "signedBy": "1220abcd...",
      "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
    }
  ]
}
```

### POST /v2/commands/simulate

Same request body as submit, but no signature required. Returns simulation result without committing.

### GET /v2/state/connected-synchronizers

```json
{
  "connectedSynchronizers": [
    { "synchronizerId": "canton::12207a2f...", "alias": "global" }
  ]
}
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum LedgerApiError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request timeout after {0}ms")]
    Timeout(u64),

    #[error("Authentication required (401)")]
    Unauthorized,

    #[error("Forbidden (403): {0}")]
    Forbidden(String),

    #[error("Not found (404): {0}")]
    NotFound(String),

    #[error("Conflict (409): {0}")]
    Conflict(String),

    #[error("Server error ({status}): {body}")]
    ServerError { status: u16, body: String },

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}
```

## Authentication

If `auth_token` is provided, include it in every request:
```
Authorization: Bearer <token>
```

The token can be a JWT or a Canton admin bearer token, depending on the participant configuration.

## Retry Policy

- Connection errors: retry up to 3 times with exponential backoff (1s, 2s, 4s)
- 5xx errors: retry up to 2 times with 1s delay
- 4xx errors: no retry (client error)
- Timeout: no retry (caller decides)

## Unit Tests Required (with wiremock)

```
test_health_check_ok              → mock 200 → true
test_health_check_fail            → mock 503 → false
test_generate_topology_success    → mock 200 with party_id
test_generate_topology_error      → mock 400 → appropriate error
test_allocate_party_success       → mock 200
test_allocate_party_conflict      → mock 409 → Conflict error
test_list_parties                 → mock 200 with party list
test_submit_command_success       → mock 200 with completion
test_simulate_command_success     → mock 200 with simulation result
test_auth_header_included         → verify Authorization header when token set
test_auth_header_absent           → verify no header when no token
test_timeout                      → mock delay > timeout → Timeout error
test_retry_on_5xx                 → mock 500 then 200 → succeeds on retry
```
