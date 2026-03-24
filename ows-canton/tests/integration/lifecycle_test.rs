//! Integration tests for the Canton wallet lifecycle.
//!
//! These tests require a running Canton Sandbox (Docker).
//! Run with: `cargo test -p ows-canton --features integration-tests`

#![cfg(feature = "integration-tests")]

use ows_canton::identifier::CantonChainId;
use ows_canton::keygen::CantonSigningAlgorithm;
use ows_canton::policy::*;
use ows_canton::wallet::*;

const TEST_PASSPHRASE: &str = "integration-test-passphrase-ok";

#[test]
fn test_full_wallet_lifecycle() {
    let tmpdir = tempfile::tempdir().unwrap();
    let chain_id = CantonChainId::parse(CantonChainId::SANDBOX).unwrap();

    // 1. Create wallet (offline mode).
    let wallet = create_canton_wallet_in(
        tmpdir.path(),
        "lifecycle-test",
        TEST_PASSPHRASE,
        &chain_id,
        "http://localhost:7575",
        CantonSigningAlgorithm::Ed25519,
    )
    .unwrap();

    assert_eq!(wallet.ows_version, 2);
    assert_eq!(wallet.chain_type, "canton");
    assert!(!wallet.accounts[0].canton.topology_registered);

    // 2. Load by ID.
    let loaded = load_canton_wallet_in(tmpdir.path(), &wallet.id).unwrap();
    assert_eq!(loaded.id, wallet.id);
    assert_eq!(loaded.name, "lifecycle-test");

    // 3. Decrypt and verify mnemonic.
    let entropy = decrypt_canton_wallet(&loaded, TEST_PASSPHRASE).unwrap();
    assert_eq!(entropy.len(), 32); // 24-word mnemonic = 256 bits
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
    assert_eq!(mnemonic.word_count(), 24);

    // 4. List wallets.
    let wallets = list_canton_wallets_in(tmpdir.path()).unwrap();
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].name, "lifecycle-test");
}

#[test]
fn test_policy_evaluation_flow() {
    // Load the sample policy.
    let policy_json = include_str!("../fixtures/sample_policy.json");
    let policy: CantonPolicy = serde_json::from_str(policy_json).unwrap();
    assert_eq!(policy.rules.len(), 6);

    // Create a context that matches the policy.
    let ctx = CantonPolicyContext {
        command: CantonCommand {
            template_id: "TIFA.Receivable:Receivable".to_string(),
            command_type: CantonCommandType::Exercise,
            choice: Some("Settle".to_string()),
            contract_id: Some("cid-1".to_string()),
            arguments: serde_json::json!({}),
        },
        chain_id: "canton:global".to_string(),
        wallet_id: "test-wallet".to_string(),
        wallet_name: "test-wallet".to_string(),
        act_as: vec!["tifa-agent::1220abcdef0011223344".to_string()],
        read_as: vec![],
        timestamp: "2026-03-23T00:00:00Z".to_string(),
        api_key_id: "key-1".to_string(),
        api_key_name: "test-key".to_string(),
        simulation_result: Some(SimulationResult {
            success: true,
            error_message: None,
        }),
    };

    // Should need no denial — template allowed, choice allowed, party in scope,
    // simulation provided and passed, synchronizer allowed, command type allowed.
    let result = evaluate_canton_policy(&policy, &ctx);
    assert!(result.is_allow(), "expected Allow, got: {result:?}");

    // Now test denial: use a template NOT in the allowlist.
    let denied_ctx = CantonPolicyContext {
        command: CantonCommand {
            template_id: "Evil.Template:Steal".to_string(),
            command_type: CantonCommandType::Create,
            choice: None,
            contract_id: None,
            arguments: serde_json::json!({}),
        },
        ..ctx
    };
    let denied_result = evaluate_canton_policy(&policy, &denied_ctx);
    assert!(
        denied_result.is_deny(),
        "expected Deny, got: {denied_result:?}"
    );
}
