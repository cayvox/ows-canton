//! Integration tests against a live Canton Sandbox.
//!
//! These tests require a Canton participant node with the HTTP JSON Ledger API v2
//! (Canton 3.4+) running at `http://localhost:6864`.
//!
//! The Canton sandbox exposes:
//! - HTTP JSON API (Ledger API v2) on port 6864
//! - gRPC Ledger API on port 6865
//!
//! Start the sandbox with:
//! ```bash
//! ./scripts/run-sandbox-tests.sh
//! ```
//!
//! Or manually:
//! ```bash
//! java -jar ~/.daml/sdk/3.4.10/canton/canton.jar sandbox --no-tty
//! ```
//!
//! Then run tests:
//! ```bash
//! cargo test -p ows-canton --features integration-tests -- --test-threads=1
//! ```

#![cfg(feature = "integration-tests")]

use std::time::Duration;

use ows_canton::keygen::{generate_canton_keypair, CantonSigningAlgorithm};
use ows_canton::ledger_api::client::LedgerApiClient;

/// Canton sandbox HTTP JSON API endpoint.
const SANDBOX_URL: &str = "http://localhost:6864";

/// Test mnemonic for deterministic keypair generation.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Get a LedgerApiClient pointed at the sandbox.
fn sandbox_client() -> LedgerApiClient {
    LedgerApiClient::new(SANDBOX_URL, None).with_timeout(Duration::from_secs(15))
}

/// Derive a deterministic keypair from the test mnemonic at a given index.
fn test_keypair_at_index(index: u32) -> ows_canton::keygen::CantonKeyPair {
    let mnemonic = bip39::Mnemonic::parse(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let path = format!("m/44'/9999'/0'/0/{index}");
    generate_canton_keypair(&seed, &path, CantonSigningAlgorithm::Ed25519).unwrap()
}

/// Skip the test if the sandbox is not reachable.
async fn require_sandbox(client: &LedgerApiClient) {
    let healthy = client.health_check().await.unwrap_or(false);
    if !healthy {
        eprintln!("SKIP: Canton Sandbox not available at {SANDBOX_URL}");
        eprintln!("      Start it with: ./scripts/run-sandbox-tests.sh");
        panic!("Canton Sandbox not available — skipping integration test");
    }
}

// ── Test: Version ───────────────────────────────────────────────────

#[tokio::test]
async fn test_sandbox_version() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // The health_check calls GET /v2/version — verify it succeeds.
    let healthy = client.health_check().await.unwrap();
    assert!(healthy, "sandbox should respond to /v2/version");
    eprintln!("Canton sandbox is live at {SANDBOX_URL}");
}

// ── Test: Connected Synchronizers ──────────────────────────────────

#[tokio::test]
async fn test_sandbox_connected_synchronizers() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    let syncs = client.get_connected_synchronizers().await.unwrap();
    assert!(
        !syncs.is_empty(),
        "sandbox should have at least one connected synchronizer"
    );

    eprintln!("Connected synchronizers:");
    for s in &syncs {
        eprintln!(
            "  {} (alias: {}, permission: {})",
            s.synchronizer_id, s.synchronizer_alias, s.permission
        );
    }

    // Verify field names match the real API format.
    let first = &syncs[0];
    assert!(
        !first.synchronizer_id.is_empty(),
        "synchronizerId should be non-empty"
    );
    assert!(
        !first.synchronizer_alias.is_empty(),
        "synchronizerAlias should be non-empty"
    );
}

// ── Test: List Parties ──────────────────────────────────────────────

#[tokio::test]
async fn test_sandbox_list_parties() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    let parties = client.list_parties(None).await.unwrap();
    assert!(
        !parties.is_empty(),
        "sandbox should have at least one party (the default sandbox party)"
    );

    eprintln!("Parties on sandbox:");
    for p in &parties {
        eprintln!("  {} (local: {})", p.party, p.is_local);
    }

    // The default sandbox party has the name "sandbox".
    let has_sandbox_party = parties.iter().any(|p| p.party.starts_with("sandbox::"));
    assert!(
        has_sandbox_party,
        "expected a 'sandbox::...' party on the Canton sandbox"
    );
}

// ── Test: Allocate Party ────────────────────────────────────────────

#[tokio::test]
async fn test_sandbox_allocate_party() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // Use a timestamp-based name to avoid collisions.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let party_hint = format!("testalloc{ts}");

    let party = client
        .allocate_party(&party_hint, "Integration Test Party")
        .await
        .unwrap();

    eprintln!("Allocated party: {}", party.party);
    assert!(
        party.party.starts_with(&party_hint),
        "allocated party '{}' should start with hint '{}'",
        party.party,
        party_hint
    );
    assert!(party.is_local, "newly allocated party should be local");

    // Verify it appears in the party list.
    let parties = client.list_parties(None).await.unwrap();
    let found = parties.iter().any(|p| p.party == party.party);
    assert!(
        found,
        "allocated party '{}' should appear in party list",
        party.party
    );
    eprintln!("Party verified in party list");
}

// ── Test: Keypair and Fingerprint ───────────────────────────────────

#[tokio::test]
async fn test_sandbox_keypair_derivation() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // Verify deterministic keypair derivation works.
    let kp1 = test_keypair_at_index(0);
    let kp2 = test_keypair_at_index(0);
    let kp3 = test_keypair_at_index(1);

    assert_eq!(
        kp1.fingerprint, kp2.fingerprint,
        "same index should give same fingerprint"
    );
    assert_ne!(
        kp1.fingerprint, kp3.fingerprint,
        "different index should give different fingerprint"
    );

    eprintln!("Keypair index 0 fingerprint: {}", kp1.fingerprint);
    eprintln!("Keypair index 1 fingerprint: {}", kp3.fingerprint);

    // Verify fingerprint format: "1220" + hex
    assert!(
        kp1.fingerprint.starts_with("1220"),
        "fingerprint should start with '1220'"
    );
    assert_eq!(
        kp1.fingerprint.len(),
        40,
        "fingerprint should be 40 hex chars (1220 + 36)"
    );
}

// ── Test: Get Completions ───────────────────────────────────────────

#[tokio::test]
async fn test_sandbox_get_completions() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    let parties = client.list_parties(None).await.unwrap();
    assert!(!parties.is_empty());

    let party_ids: Vec<String> = parties.iter().map(|p| p.party.clone()).collect();

    // Get completions from offset 0 — should include an OffsetCheckpoint event.
    // Use "participant_admin" as userId (required by Canton, even without auth).
    let completions = client
        .get_completions(0, &party_ids, "participant_admin")
        .await
        .unwrap();
    assert!(
        !completions.is_empty(),
        "completions from offset 0 should include at least one OffsetCheckpoint"
    );

    eprintln!("Got {} completion events from offset 0", completions.len());
}
