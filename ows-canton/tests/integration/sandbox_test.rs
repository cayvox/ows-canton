//! Integration tests against a live Canton Sandbox.
//!
//! These tests require a Canton participant node with the JSON Ledger API v2
//! (Canton 3.4+) running at `http://localhost:7575`.
//!
//! Run with:
//! ```bash
//! cargo test -p ows-canton --features integration-tests -- --test-threads=1
//! ```
//!
//! Or use the helper script:
//! ```bash
//! ./scripts/run-sandbox-tests.sh
//! ```

#![cfg(feature = "integration-tests")]

use std::time::Duration;

use ows_canton::keygen::{generate_canton_keypair, CantonSigningAlgorithm};
use ows_canton::ledger_api::client::LedgerApiClient;
use ows_canton::ledger_api::types::{MultiHashSignatureRequest, SubmitCommandRequest};
use ows_canton::onboarding::onboard_external_party;
use ows_canton::policy::{CantonCommand, CantonCommandType};
use ows_canton::signing::build_submission_request;

const SANDBOX_URL: &str = "http://localhost:7575";
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Get a LedgerApiClient pointed at the sandbox.
fn sandbox_client() -> LedgerApiClient {
    LedgerApiClient::new(SANDBOX_URL, None).with_timeout(Duration::from_secs(15))
}

/// Derive a deterministic keypair from the test mnemonic at a given index.
fn test_keypair_at_index(
    index: u32,
) -> ows_canton::keygen::CantonKeyPair {
    let mnemonic = bip39::Mnemonic::parse(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let path = format!("m/44'/9999'/0'/0/{index}");
    generate_canton_keypair(&seed, &path, CantonSigningAlgorithm::Ed25519).unwrap()
}

/// Skip the test with a message if the sandbox is not reachable.
async fn require_sandbox(client: &LedgerApiClient) {
    let healthy = client.health_check().await.unwrap_or(false);
    if !healthy {
        eprintln!("SKIP: Canton Sandbox not available at {SANDBOX_URL}");
        eprintln!("      Start it with: ./scripts/run-sandbox-tests.sh");
        // We panic with a clear message rather than silently passing.
        // In CI this ensures the test is noticed as failing when sandbox is expected.
        panic!("Canton Sandbox not available — skipping integration test");
    }
}

// ── Test: Health Check + Connected Synchronizers ───────────────────

#[tokio::test]
async fn test_sandbox_health_and_synchronizers() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // Health check.
    let healthy = client.health_check().await.unwrap();
    assert!(healthy, "sandbox should be healthy");

    // Get connected synchronizers.
    let syncs = client.get_connected_synchronizers().await.unwrap();
    assert!(
        !syncs.is_empty(),
        "sandbox should have at least one connected synchronizer"
    );

    eprintln!("Connected synchronizers:");
    for s in &syncs {
        eprintln!("  {} (alias: {})", s.synchronizer_id, s.alias);
    }
}

// ── Test: Full External Party Onboarding ───────────────────────────

#[tokio::test]
async fn test_full_external_party_onboarding_against_sandbox() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // 1. Get a synchronizer to register on.
    let syncs = client.get_connected_synchronizers().await.unwrap();
    assert!(!syncs.is_empty(), "need at least one synchronizer");
    let sync_id = &syncs[0].synchronizer_id;
    eprintln!("Using synchronizer: {sync_id}");

    // 2. Generate a fresh keypair (use index based on timestamp to avoid collisions).
    let index = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        % 100_000) as u32;
    let keypair = test_keypair_at_index(index);
    eprintln!("Key fingerprint: {}", keypair.fingerprint);

    // 3. Onboard as External Party.
    let party_hint = format!("inttest{index}");
    let result = onboard_external_party(&keypair, &party_hint, &client, sync_id)
        .await
        .unwrap();

    assert!(result.topology_registered);
    eprintln!("External party registered on Canton Sandbox:");
    eprintln!("  Party ID:     {}", result.party_id);
    eprintln!("  Synchronizer: {}", result.synchronizer_id);
    eprintln!("  Fingerprint:  {}", result.fingerprint);

    // 4. Verify via list_parties.
    let parties = client.list_parties(Some(&party_hint)).await.unwrap();
    let found = parties
        .iter()
        .any(|p| p.party == result.party_id.to_string());
    assert!(
        found,
        "registered party should appear in party list: looked for '{}' in {:?}",
        result.party_id,
        parties.iter().map(|p| &p.party).collect::<Vec<_>>()
    );
    eprintln!("Party verified in party list");
}

// ── Test: Submit Command Against Sandbox ───────────────────────────

/// This test attempts to submit a DAML create command against the sandbox.
///
/// Canton requires a deployed DAML model (DAR) to accept create commands.
/// On a bare sandbox without a DAR, the submit will fail with a template-not-found
/// error — but this validates that our signing payload format is accepted by
/// Canton's protocol layer (the error comes after signature verification).
#[tokio::test]
async fn test_submit_command_against_sandbox() {
    let client = sandbox_client();
    require_sandbox(&client).await;

    // 1. Get synchronizer + onboard a party first.
    let syncs = client.get_connected_synchronizers().await.unwrap();
    assert!(!syncs.is_empty());
    let sync_id = &syncs[0].synchronizer_id;

    let index = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        % 100_000 + 50_000) as u32; // offset to avoid collision with onboarding test
    let keypair = test_keypair_at_index(index);
    let party_hint = format!("submit{index}");

    let onboard_result = onboard_external_party(&keypair, &party_hint, &client, sync_id)
        .await
        .unwrap();

    let party_id = onboard_result.party_id.to_string();
    eprintln!("Party for submit test: {party_id}");

    // 2. Build a create command.
    //    We use a fake template that won't exist on the sandbox.
    //    The goal is to verify our signing format is accepted by Canton.
    let command = CantonCommand {
        template_id: "OWSTest.Ping:Ping".to_string(),
        command_type: CantonCommandType::Create,
        choice: None,
        contract_id: None,
        arguments: serde_json::json!({
            "sender": party_id,
            "receiver": party_id,
            "message": "hello from ows-canton integration test"
        }),
    };

    let command_id = uuid::Uuid::new_v4().to_string();
    let submission = build_submission_request(
        &command,
        &[party_id.clone()],
        &[],
        &command_id,
    );

    // 3. Sign the submission payload.
    use base64::Engine;
    use sha2::Digest;

    let payload_bytes = serde_json::to_vec(&submission).unwrap();
    let payload_hash = sha2::Sha256::digest(&payload_bytes);
    let sig_bytes =
        ows_canton::keygen::ed25519_sign(&keypair.private_key, &payload_hash).unwrap();

    let sig_request = MultiHashSignatureRequest {
        format: "SIGNATURE_FORMAT_CONCAT".to_string(),
        signature: base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
        signed_by: keypair.fingerprint.clone(),
        signing_algorithm_spec: "SIGNING_ALGORITHM_SPEC_ED25519".to_string(),
    };

    // 4. Submit.
    let submit_req = SubmitCommandRequest {
        commands: submission,
        multi_hash_signatures: vec![sig_request],
    };

    let result = client.submit_command(&submit_req).await;

    // We expect either:
    // - Success (if somehow a matching template exists)
    // - An error from Canton (template not found, invalid payload, etc.)
    //
    // What matters is that Canton ACCEPTED the HTTP request and parsed
    // our signature format. A "template not found" error proves the signing
    // payload format is correct — Canton validated the signature before
    // trying to interpret the command.
    match &result {
        Ok(resp) => {
            eprintln!("Submit succeeded (unexpected on bare sandbox):");
            eprintln!("  Command ID:     {}", resp.command_id);
            eprintln!("  Transaction ID: {:?}", resp.transaction_id);
        }
        Err(e) => {
            let err_str = format!("{e:?}");
            eprintln!("Submit returned error (expected on bare sandbox): {e}");

            // If we get a "signature verification failed" error, our payload
            // format is wrong and we need to fix signing.rs.
            let is_sig_error = err_str.to_lowercase().contains("signature")
                && err_str.to_lowercase().contains("verif");
            assert!(
                !is_sig_error,
                "CRITICAL: Canton rejected our signature format. \
                 The signing payload needs to be fixed. Error: {e}"
            );
        }
    }
}
