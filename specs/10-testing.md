# Spec 10 — Testing Strategy

## Test Levels

| Level | Location | Canton Required | CI |
|-------|----------|-----------------|-----|
| Unit tests | `tests/unit/` | No | Every push |
| Integration tests | `tests/integration/` | Yes (Sandbox Docker) | Feature-gated |
| E2E tests | `tests/e2e/` | Yes (Devnet) | Nightly/manual |

## Unit Test Coverage Requirements

Every public function MUST have at least one test. Crypto functions MUST have deterministic vector tests.

### Test Fixtures

Store in `tests/fixtures/`:

**sample_wallet.json** — A valid Canton wallet file with known mnemonic for deterministic tests:
```json
{
  "ows_version": 2,
  "id": "test-0000-0000-0000-000000000001",
  "name": "test-wallet",
  "chain_type": "canton",
  "accounts": [{
    "account_id": "canton:sandbox:test-wallet::1220aabbccdd",
    "address": "test-wallet::1220aabbccdd",
    "chain_id": "canton:sandbox",
    "derivation_path": "m/44'/9999'/0'/0/0",
    "canton": {
      "party_id": "test-wallet::1220aabbccdd",
      "key_fingerprint": "1220aabbccddeeff00112233445566778899",
      "key_format": "DER",
      "signing_algorithm": "SIGNING_ALGORITHM_SPEC_ED25519",
      "party_type": "external",
      "topology_registered": true,
      "participant_host": "http://localhost:7575",
      "synchronizer_id": null
    }
  }],
  "crypto": { "cipher": "aes-256-gcm", "..." : "..." },
  "key_type": "mnemonic"
}
```

**test_mnemonic** — Use this fixed mnemonic for deterministic key derivation tests:
```
abandon abandon abandon abandon abandon abandon abandon abandon
abandon abandon abandon about
```

**sample_policy.json** — A test policy with all rule types.

**sample_api_key.json** — A test API key file.

### Mock Server

Use `wiremock` for Ledger API mocking in unit tests:

```rust
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

async fn setup_mock_participant() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v2/state/connected-synchronizers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "connectedSynchronizers": [{
                "synchronizerId": "canton::test-sync",
                "alias": "sandbox"
            }]
        })))
        .mount(&server)
        .await;

    server
}
```

## Integration Test Setup

### Canton Sandbox Docker

```yaml
# tests/docker-compose.yml
services:
  canton:
    image: digitalasset/canton-open-source:latest
    ports:
      - "7575:7575"   # Ledger API
      - "7576:7576"   # Admin API
    volumes:
      - ./fixtures/canton_sandbox.conf:/canton/config.conf
    command: ["--config", "/canton/config.conf"]
```

### Integration Test Pattern

```rust
#[cfg(feature = "integration-tests")]
mod integration {
    use ows_canton::*;

    #[tokio::test]
    async fn test_full_wallet_lifecycle() {
        // 1. Create wallet (registers External Party on sandbox)
        let wallet = canton_create_wallet("int-test-wallet", "testpassphrase1", ...).await.unwrap();

        // 2. Verify party registered
        let client = LedgerApiClient::new("http://localhost:7575", None);
        let parties = client.list_parties(Some("int-test-wallet")).await.unwrap();
        assert!(!parties.is_empty());

        // 3. Submit a create command (requires a DAML template on sandbox)
        // ... test with a simple template

        // 4. Query active contracts
        // ... verify contract created

        // 5. Clean up
        std::fs::remove_file(wallet_path(&wallet.id)).ok();
    }
}
```

## Critical Test Scenarios

```
IDENTIFIERS:
  - Parse valid/invalid CAIP-2 strings
  - Parse valid/invalid CAIP-10 strings
  - Roundtrip: parse → format → parse

KEY MANAGEMENT:
  - Deterministic derivation (same mnemonic → same key)
  - Different derivation index → different key
  - DER encoding correctness (check known test vector)
  - Fingerprint computation (deterministic)
  - Sign/verify roundtrip
  - Zeroize implementation exists

WALLET:
  - Create/load/decrypt roundtrip
  - Wrong passphrase → DecryptionFailed
  - List filters by chain_type
  - File permissions on Unix
  - JSON schema validation

SIGNING:
  - Ed25519 sign → verify
  - Command serialization
  - MultiHashSignature structure

POLICY:
  - Each rule type: allow and deny cases
  - AND semantics: one fail → deny
  - Empty policy → allow
  - NeedsSimulation flag
  - Owner mode skips policy

ONBOARDING:
  - Full flow with mock participant
  - Offline mode (no participant)
  - Register pending wallet
  - Party already exists error

LEDGER API:
  - Each endpoint with mock (success + error)
  - Auth token inclusion
  - Retry on 5xx
  - Timeout handling

CLI:
  - Each command with mock (verify output format)
  - Invalid arguments → proper error message

MCP:
  - Each tool with mock
  - Invalid tool name → error
```
