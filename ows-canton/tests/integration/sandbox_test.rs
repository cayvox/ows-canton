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

use base64::Engine;
use ows_canton::keygen::{generate_canton_keypair, CantonSigningAlgorithm};
use ows_canton::ledger_api::client::LedgerApiClient;
use ows_canton::ledger_api::types::{
    AllocatePartyRequest, MultiHashSignatureRequest, SignedTopologyTransaction,
};

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

// ── Test: External Party — Generate Topology ──────────────────────

#[tokio::test]
async fn test_sandbox_generate_topology() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // Get synchronizer ID.
    let syncs = client.get_connected_synchronizers().await.unwrap();
    let sync_id = &syncs[0].synchronizer_id;

    // Derive an Ed25519 keypair.
    let kp = test_keypair_at_index(100);
    let pubkey_raw_b64 = base64::engine::general_purpose::STANDARD.encode(&kp.public_key);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let party_hint = format!("owstopo{ts}");

    // Call generate-topology.
    let resp = client
        .generate_external_topology(
            &pubkey_raw_b64,
            "SIGNING_KEY_SPEC_EC_CURVE25519",
            sync_id,
            &party_hint,
        )
        .await
        .unwrap();

    eprintln!("Generated topology for party: {}", resp.party_id);
    eprintln!("Public key fingerprint: {}", resp.public_key_fingerprint);
    eprintln!(
        "Topology transactions: {} items",
        resp.topology_transactions.len()
    );

    // Verify response fields.
    assert!(
        resp.party_id.starts_with(&party_hint),
        "party_id '{}' should start with hint '{}'",
        resp.party_id,
        party_hint
    );
    assert!(
        !resp.public_key_fingerprint.is_empty(),
        "publicKeyFingerprint should be non-empty"
    );
    assert!(
        resp.public_key_fingerprint.starts_with("1220"),
        "publicKeyFingerprint should start with '1220'"
    );
    assert!(
        !resp.topology_transactions.is_empty(),
        "topologyTransactions should have at least one entry"
    );
}

// ── Test: External Party — Full Allocate Flow ─────────────────────

#[tokio::test]
async fn test_sandbox_external_party_allocate() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // Get synchronizer ID.
    let syncs = client.get_connected_synchronizers().await.unwrap();
    let sync_id = &syncs[0].synchronizer_id;

    // Use a unique index + timestamp for each test run.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let party_hint = format!("owsalloc{ts}");

    let kp = test_keypair_at_index(200);
    let pubkey_raw_b64 = base64::engine::general_purpose::STANDARD.encode(&kp.public_key);

    // 1. Generate topology.
    let topo = client
        .generate_external_topology(
            &pubkey_raw_b64,
            "SIGNING_KEY_SPEC_EC_CURVE25519",
            sync_id,
            &party_hint,
        )
        .await
        .unwrap();

    eprintln!("Topology generated for: {}", topo.party_id);

    // 2. Sign the multiHash from the generate-topology response.
    //    The multiHash is a commitment covering all topology transactions.
    //    Canton expects Ed25519 signature over the raw multiHash bytes.
    use ows_canton::keygen::ed25519_sign;

    let multi_hash_bytes = base64::engine::general_purpose::STANDARD
        .decode(&topo.multi_hash)
        .unwrap();
    let sig_bytes = ed25519_sign(&kp.private_key, &multi_hash_bytes).unwrap();

    eprintln!(
        "multiHash (hex): {}, sig len: {}",
        hex::encode(&multi_hash_bytes),
        sig_bytes.len()
    );

    // Wrap transactions with empty per-transaction signatures.
    let signed_txs: Vec<SignedTopologyTransaction> = topo
        .topology_transactions
        .iter()
        .map(|tx| SignedTopologyTransaction {
            transaction: tx.clone(),
            signatures: vec![],
        })
        .collect();

    // 3. Allocate the external party with top-level multiHashSignatures.
    let alloc_req = AllocatePartyRequest {
        synchronizer: sync_id.to_string(),
        onboarding_transactions: signed_txs,
        multi_hash_signatures: vec![MultiHashSignatureRequest {
            format: "SIGNATURE_FORMAT_CONCAT".to_string(),
            signature: base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
            signed_by: topo.public_key_fingerprint.clone(),
            signing_algorithm_spec: "SIGNING_ALGORITHM_SPEC_ED25519".to_string(),
        }],
    };
    let alloc_resp = client.allocate_external_party(&alloc_req).await.unwrap();

    eprintln!("Allocated external party: {}", alloc_resp.party_id);
    assert!(
        alloc_resp.party_id.starts_with(&party_hint),
        "allocated party_id '{}' should start with hint '{}'",
        alloc_resp.party_id,
        party_hint
    );
    assert_eq!(
        alloc_resp.party_id, topo.party_id,
        "allocate response party_id should match generate-topology party_id"
    );
}

// ── Test: External Party — Allocate Without Signatures (Sandbox) ──

#[tokio::test]
async fn test_sandbox_external_party_allocate_no_sig() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    let syncs = client.get_connected_synchronizers().await.unwrap();
    let sync_id = &syncs[0].synchronizer_id;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let party_hint = format!("owsnosig{ts}");

    let kp = test_keypair_at_index(300);
    let pubkey_raw_b64 = base64::engine::general_purpose::STANDARD.encode(&kp.public_key);

    // Generate topology.
    let topo = client
        .generate_external_topology(
            &pubkey_raw_b64,
            "SIGNING_KEY_SPEC_EC_CURVE25519",
            sync_id,
            &party_hint,
        )
        .await
        .unwrap();

    // Allocate with empty signatures (sandbox allows this).
    let signed_txs: Vec<SignedTopologyTransaction> = topo
        .topology_transactions
        .iter()
        .map(|tx| SignedTopologyTransaction {
            transaction: tx.clone(),
            signatures: vec![],
        })
        .collect();

    let alloc_req = AllocatePartyRequest {
        synchronizer: sync_id.to_string(),
        onboarding_transactions: signed_txs,
        multi_hash_signatures: vec![],
    };
    let alloc_resp = client.allocate_external_party(&alloc_req).await.unwrap();

    eprintln!("Allocated external party (no sig): {}", alloc_resp.party_id);
    assert_eq!(alloc_resp.party_id, topo.party_id);
}
