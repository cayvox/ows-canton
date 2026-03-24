//! External Party registration flow for Canton Network.
//!
//! Handles the onboarding of new External Parties by generating topology
//! transactions, signing them locally, and registering them with the Canton
//! participant node. Supports offline mode for deferred registration.
//! See `specs/06-onboarding.md` for the full specification.

use base64::Engine;

use crate::identifier::CantonPartyId;
use crate::keygen::{ed25519_sign, generate_canton_keypair, CantonKeyPair, CantonSigningAlgorithm};
use crate::ledger_api::client::LedgerApiClient;
use crate::ledger_api::topology::build_allocate_request;
use crate::signing::CantonSignature;
use crate::wallet::{decrypt_canton_wallet, save_wallet_in, CantonWalletFile};
use crate::CantonError;

/// Result of an External Party onboarding operation.
#[derive(Debug, Clone)]
pub struct OnboardingResult {
    /// Registered Canton party identifier.
    pub party_id: CantonPartyId,
    /// Synchronizer where the party was registered.
    pub synchronizer_id: String,
    /// Key fingerprint.
    pub fingerprint: String,
    /// Whether the party was successfully registered on-chain.
    pub topology_registered: bool,
}

/// Register a key pair as an External Party on a Canton synchronizer.
///
/// # Steps
///
/// 1. Base64-encode the DER public key
/// 2. Call `generate-topology` to get topology transactions
/// 3. Sign each topology transaction (SHA-256 hash → Ed25519 sign)
/// 4. Call `allocate` with signed transactions
/// 5. Verify registration via `list_parties`
pub async fn onboard_external_party(
    keypair: &CantonKeyPair,
    party_hint: &str,
    client: &LedgerApiClient,
    synchronizer_id: &str,
) -> Result<OnboardingResult, CantonError> {
    // 1. Encode raw public key as base64 (Canton wants raw bytes, not SPKI-DER).
    let pubkey_raw_b64 = base64::engine::general_purpose::STANDARD.encode(&keypair.public_key);

    // Determine key spec from signing algorithm.
    let key_spec = match keypair.signing_algorithm {
        CantonSigningAlgorithm::Ed25519 => "SIGNING_KEY_SPEC_EC_CURVE25519",
        CantonSigningAlgorithm::EcDsaSha256 => "SIGNING_KEY_SPEC_EC_SECP256K1",
    };

    // 2. Generate topology transactions.
    let topo_resp = client
        .generate_external_topology(&pubkey_raw_b64, key_spec, synchronizer_id, party_hint)
        .await?;

    let party_id_str = topo_resp.party_id.clone();

    // 3. Sign the multiHash (commitment to all topology transactions).
    //    Canton provides a multiHash in the generate-topology response that
    //    covers all transactions. We sign it directly with Ed25519.
    let multi_hash_bytes = base64::engine::general_purpose::STANDARD
        .decode(&topo_resp.multi_hash)
        .map_err(|e| CantonError::OnboardingFailed {
            reason: format!("invalid base64 multiHash: {e}"),
        })?;

    let sig_bytes = ed25519_sign(&keypair.private_key, &multi_hash_bytes)?;

    // Use Canton's publicKeyFingerprint (not our locally-computed one) as signedBy.
    let signed_by = topo_resp.public_key_fingerprint.clone();

    let signatures = vec![CantonSignature {
        signature: base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
        signed_by,
        format: "SIGNATURE_FORMAT_CONCAT".to_string(),
        algorithm: keypair.signing_algorithm.to_string(),
    }];

    // 4. Allocate party with signed transactions.
    let alloc_req = build_allocate_request(
        synchronizer_id,
        &topo_resp.topology_transactions,
        &signatures,
    );
    client.allocate_external_party(&alloc_req).await?;

    // 5. Verify registration.
    let parties = client.list_parties(Some(party_hint)).await?;
    let found = parties.iter().any(|p| p.party == party_id_str);
    if !found {
        tracing::warn!(
            "party '{}' not found in party list after allocation — may be propagating",
            party_id_str
        );
    }

    // Parse the party ID.
    let party_id =
        CantonPartyId::parse(&party_id_str).map_err(|e| CantonError::OnboardingFailed {
            reason: format!("invalid party id from participant: {e}"),
        })?;

    Ok(OnboardingResult {
        party_id,
        synchronizer_id: synchronizer_id.to_string(),
        fingerprint: keypair.fingerprint.clone(),
        topology_registered: true,
    })
}

/// Register a previously-created offline wallet on a Canton synchronizer.
///
/// The wallet must have `topology_registered == false`. Decrypts the wallet
/// to derive the key pair, onboards the party, then updates the wallet file.
pub async fn register_pending_wallet(
    wallet: &mut CantonWalletFile,
    passphrase: &str,
    client: &LedgerApiClient,
    synchronizer_id: &str,
    ows_home: &std::path::Path,
) -> Result<OnboardingResult, CantonError> {
    let account = wallet
        .accounts
        .first()
        .ok_or_else(|| CantonError::InvalidWalletFile {
            reason: "wallet has no accounts".to_string(),
        })?;

    if account.canton.topology_registered {
        return Err(CantonError::OnboardingFailed {
            reason: "wallet is already registered".to_string(),
        });
    }

    let party_hint = &wallet.name;
    let derivation_path = account.derivation_path.clone();
    let algorithm: CantonSigningAlgorithm = serde_json::from_value(serde_json::Value::String(
        account.canton.signing_algorithm.clone(),
    ))
    .map_err(|_| CantonError::UnsupportedAlgorithm {
        algorithm: account.canton.signing_algorithm.clone(),
    })?;

    // Decrypt wallet → derive keypair.
    let entropy = decrypt_canton_wallet(wallet, passphrase)?;
    let mnemonic =
        bip39::Mnemonic::from_entropy(&entropy).map_err(|e| CantonError::InvalidMnemonic {
            reason: e.to_string(),
        })?;
    let seed = mnemonic.to_seed("");
    let keypair = generate_canton_keypair(&seed, &derivation_path, algorithm)?;

    // Onboard.
    let result = onboard_external_party(&keypair, party_hint, client, synchronizer_id).await?;

    // Update wallet metadata.
    if let Some(account) = wallet.accounts.first_mut() {
        account.canton.topology_registered = true;
        account.canton.synchronizer_id = Some(result.synchronizer_id.clone());
        account.canton.party_id = result.party_id.to_string();
        account.address = result.party_id.to_string();
        account.account_id = format!("{}:{}", account.chain_id, result.party_id);
    }

    // Rewrite wallet file.
    save_wallet_in(ows_home, wallet)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::CantonChainId;
    use crate::wallet::create_canton_wallet_in;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PASSPHRASE: &str = "test-passphrase-long-enough";

    /// Set up wiremock mocks for a successful onboarding flow.
    async fn setup_onboarding_mocks(mock: &MockServer) {
        // generate-topology
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/generate-topology"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyId": "test-wallet::1220aabbccdd",
                "publicKeyFingerprint": "1220aabbccdd",
                "topologyTransactions": ["dHgx", "dHgy"],
                "multiHash": "EiAAAA=="
            })))
            .mount(mock)
            .await;

        // allocate
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/allocate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyId": "test-wallet::1220aabbccdd"
            })))
            .mount(mock)
            .await;

        // list parties (verification)
        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyDetails": [
                    { "party": "test-wallet::1220aabbccdd", "isLocal": false, "identityProviderId": "" }
                ],
                "nextPageToken": ""
            })))
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn test_onboard_success() {
        let mock = MockServer::start().await;
        setup_onboarding_mocks(&mock).await;

        let client = LedgerApiClient::new(&mock.uri(), None);

        // Generate a keypair for testing.
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let keypair =
            generate_canton_keypair(&seed, "m/44'/9999'/0'/0/0", CantonSigningAlgorithm::Ed25519)
                .unwrap();

        let result = onboard_external_party(&keypair, "test-wallet", &client, "canton::sync1")
            .await
            .unwrap();

        assert!(result.topology_registered);
        assert_eq!(result.synchronizer_id, "canton::sync1");
        assert_eq!(result.party_id.hint, "test-wallet");
    }

    #[tokio::test]
    async fn test_onboard_offline_mode() {
        // No client → wallet created with topology_registered=false.
        let tmpdir = tempfile::tempdir().unwrap();
        let chain_id = CantonChainId::parse(CantonChainId::SANDBOX).unwrap();

        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "offline-wallet",
            PASSPHRASE,
            &chain_id,
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        assert!(!wallet.accounts[0].canton.topology_registered);
        assert!(wallet.accounts[0].canton.synchronizer_id.is_none());
    }

    #[tokio::test]
    async fn test_register_pending() {
        let mock = MockServer::start().await;
        setup_onboarding_mocks(&mock).await;

        let tmpdir = tempfile::tempdir().unwrap();
        let chain_id = CantonChainId::parse(CantonChainId::SANDBOX).unwrap();

        // Create offline wallet.
        let mut wallet = create_canton_wallet_in(
            tmpdir.path(),
            "test-wallet",
            PASSPHRASE,
            &chain_id,
            &mock.uri(),
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        assert!(!wallet.accounts[0].canton.topology_registered);

        let client = LedgerApiClient::new(&mock.uri(), None);
        let result = register_pending_wallet(
            &mut wallet,
            PASSPHRASE,
            &client,
            "canton::sync1",
            tmpdir.path(),
        )
        .await
        .unwrap();

        assert!(result.topology_registered);
        assert!(wallet.accounts[0].canton.topology_registered);
        assert_eq!(
            wallet.accounts[0].canton.synchronizer_id.as_deref(),
            Some("canton::sync1")
        );

        // Verify the file was rewritten.
        let loaded = crate::wallet::load_canton_wallet_in(tmpdir.path(), &wallet.id).unwrap();
        assert!(loaded.accounts[0].canton.topology_registered);
    }

    #[tokio::test]
    async fn test_onboard_party_exists() {
        let mock = MockServer::start().await;

        // generate-topology succeeds
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/generate-topology"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyId": "dup::1220aabbccdd",
                "publicKeyFingerprint": "1220aabbccdd",
                "topologyTransactions": ["dHgx"],
                "multiHash": "EiAAAA=="
            })))
            .mount(&mock)
            .await;

        // allocate returns 409 Conflict
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/allocate"))
            .respond_with(ResponseTemplate::new(409).set_body_string("party already exists"))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let keypair =
            generate_canton_keypair(&seed, "m/44'/9999'/0'/0/0", CantonSigningAlgorithm::Ed25519)
                .unwrap();

        let err = onboard_external_party(&keypair, "dup", &client, "canton::sync1")
            .await
            .unwrap_err();

        assert!(matches!(err, CantonError::OnboardingFailed { .. }));
    }

    #[tokio::test]
    async fn test_register_already_registered() {
        let mock = MockServer::start().await;
        let tmpdir = tempfile::tempdir().unwrap();
        let chain_id = CantonChainId::parse(CantonChainId::SANDBOX).unwrap();

        let mut wallet = create_canton_wallet_in(
            tmpdir.path(),
            "already-reg",
            PASSPHRASE,
            &chain_id,
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        // Manually set as registered.
        wallet.accounts[0].canton.topology_registered = true;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let err = register_pending_wallet(
            &mut wallet,
            PASSPHRASE,
            &client,
            "canton::sync1",
            tmpdir.path(),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, CantonError::OnboardingFailed { .. }));
    }

    #[tokio::test]
    async fn test_onboard_unreachable() {
        // Client points to a non-existent server.
        let client = LedgerApiClient::new("http://127.0.0.1:1", None)
            .with_timeout(Duration::from_millis(200));

        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let keypair =
            generate_canton_keypair(&seed, "m/44'/9999'/0'/0/0", CantonSigningAlgorithm::Ed25519)
                .unwrap();

        let err = onboard_external_party(&keypair, "test", &client, "canton::sync1")
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                CantonError::ConnectionFailed { .. } | CantonError::RequestTimeout { .. }
            ),
            "expected connection error, got: {err:?}"
        );
    }
}
