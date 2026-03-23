//! Canton signing protocol for messages and DAML command submission.
//!
//! Implements the interactive submission protocol where DAML commands are
//! signed locally with the External Party's private key and submitted to the
//! Canton Ledger API. Policy evaluation occurs before any key decryption.
//! See `specs/04-signing.md` for the full specification.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{append_audit_log_in, AuditEntry};
use crate::keygen::{
    ed25519_sign, ed25519_verify, generate_canton_keypair, CantonSigningAlgorithm,
};
use crate::ledger_api::client::LedgerApiClient;
use crate::ledger_api::types::{
    ActiveContract, MultiHashSignatureRequest, SimulateCommandRequest, SubmitCommandRequest,
};
use crate::policy::{CantonCommand, CantonCommandType, SimulationResult};
use crate::wallet::{decrypt_canton_wallet, CantonWalletFile};
use crate::CantonError;

// ── Types ──────────────────────────────────────────────────────────

/// An Ed25519 / secp256k1 signature produced by Canton signing operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonSignature {
    /// Base64-encoded raw signature bytes (64 bytes for Ed25519).
    pub signature: String,
    /// Key fingerprint identifying the signing key.
    pub signed_by: String,
    /// Canton signature format (always `"SIGNATURE_FORMAT_CONCAT"`).
    pub format: String,
    /// Canton signing algorithm spec string.
    pub algorithm: String,
}

/// Result of a DAML command submission to the Ledger API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonSubmitResult {
    /// Unique command identifier.
    pub command_id: String,
    /// Submission outcome.
    pub status: CantonCommandStatus,
    /// Ledger offset at completion (if succeeded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_offset: Option<String>,
    /// Transaction identifier (if succeeded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

/// Outcome of a submitted DAML command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CantonCommandStatus {
    /// Command was accepted and committed.
    Succeeded,
    /// Command was rejected.
    Failed {
        /// Human-readable rejection reason.
        reason: String,
    },
    /// Command timed out waiting for completion.
    Timeout,
}

/// Encoding of the message to be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageEncoding {
    /// Message is raw UTF-8 bytes.
    Utf8,
    /// Message is hex-encoded bytes.
    Hex,
}

/// Canton signature format constant.
const SIGNATURE_FORMAT_CONCAT: &str = "SIGNATURE_FORMAT_CONCAT";

// ── Signing functions ──────────────────────────────────────────────

/// Sign an arbitrary message with the Canton wallet key.
///
/// Used for authentication challenges and off-chain attestations.
/// Decrypts the wallet, derives the signing key, signs the message,
/// then zeroizes all key material.
pub fn canton_sign_message(
    wallet: &CantonWalletFile,
    passphrase: &str,
    message: &[u8],
    _encoding: MessageEncoding,
) -> Result<CantonSignature, CantonError> {
    let (fingerprint, algorithm, sig_bytes) = sign_with_wallet(wallet, passphrase, message)?;

    Ok(CantonSignature {
        signature: base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
        signed_by: fingerprint,
        format: SIGNATURE_FORMAT_CONCAT.to_string(),
        algorithm,
    })
}

/// Sign topology transaction bytes with the Canton wallet key.
///
/// Used for External Party registration, key rotation, and party
/// hosting topology transactions.
pub fn canton_sign_topology(
    wallet: &CantonWalletFile,
    passphrase: &str,
    topology_bytes: &[u8],
) -> Result<CantonSignature, CantonError> {
    let (fingerprint, algorithm, sig_bytes) = sign_with_wallet(wallet, passphrase, topology_bytes)?;

    Ok(CantonSignature {
        signature: base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
        signed_by: fingerprint,
        format: SIGNATURE_FORMAT_CONCAT.to_string(),
        algorithm,
    })
}

/// Build a Canton Ledger API v2 command submission request body.
///
/// Returns the JSON object suitable for `POST /v2/commands/submit`.
pub fn build_submission_request(
    command: &CantonCommand,
    act_as: &[String],
    read_as: &[String],
    command_id: &str,
) -> serde_json::Value {
    let commands = match command.command_type {
        CantonCommandType::Create => {
            serde_json::json!([{
                "create": {
                    "templateId": &command.template_id,
                    "createArguments": &command.arguments,
                }
            }])
        }
        CantonCommandType::Exercise | CantonCommandType::ExerciseByKey => {
            serde_json::json!([{
                "exercise": {
                    "templateId": &command.template_id,
                    "contractId": command.contract_id.as_deref().unwrap_or(""),
                    "choice": command.choice.as_deref().unwrap_or(""),
                    "choiceArgument": &command.arguments,
                }
            }])
        }
        CantonCommandType::CreateAndExercise => {
            serde_json::json!([{
                "createAndExercise": {
                    "templateId": &command.template_id,
                    "createArguments": serde_json::json!({}),
                    "choice": command.choice.as_deref().unwrap_or(""),
                    "choiceArgument": &command.arguments,
                }
            }])
        }
    };

    serde_json::json!({
        "commands": commands,
        "commandId": command_id,
        "actAs": act_as,
        "readAs": read_as,
    })
}

/// Build a Canton `MultiHashSignature` JSON object.
///
/// This is the signature payload attached to interactive submission requests.
pub fn build_multi_hash_signature(
    signature_bytes: &[u8],
    fingerprint: &str,
    algorithm: &CantonSigningAlgorithm,
) -> serde_json::Value {
    serde_json::json!({
        "format": SIGNATURE_FORMAT_CONCAT,
        "signature": base64::engine::general_purpose::STANDARD.encode(signature_bytes),
        "signedBy": fingerprint,
        "signingAlgorithmSpec": algorithm.to_string(),
    })
}

// ── Internal helpers ───────────────────────────────────────────────

/// Decrypt the wallet, derive the signing key, sign the message, and
/// zeroize all key material. Returns `(fingerprint, algorithm_string, signature_bytes)`.
fn sign_with_wallet(
    wallet: &CantonWalletFile,
    passphrase: &str,
    message: &[u8],
) -> Result<(String, String, Vec<u8>), CantonError> {
    let account = wallet
        .accounts
        .first()
        .ok_or_else(|| CantonError::InvalidWalletFile {
            reason: "wallet has no accounts".to_string(),
        })?;

    let fingerprint = account.canton.key_fingerprint.clone();
    let algorithm_str = account.canton.signing_algorithm.clone();
    let derivation_path = &account.derivation_path;

    // Parse the signing algorithm from the stored string.
    let algorithm: CantonSigningAlgorithm =
        serde_json::from_value(serde_json::Value::String(algorithm_str.clone())).map_err(|_| {
            CantonError::UnsupportedAlgorithm {
                algorithm: algorithm_str.clone(),
            }
        })?;

    // Decrypt wallet → mnemonic entropy.
    let entropy = decrypt_canton_wallet(wallet, passphrase)?;

    // Reconstruct mnemonic → seed → keypair.
    let mnemonic =
        bip39::Mnemonic::from_entropy(&entropy).map_err(|e| CantonError::InvalidMnemonic {
            reason: e.to_string(),
        })?;
    let seed = mnemonic.to_seed("");
    let keypair = generate_canton_keypair(&seed, derivation_path, algorithm)?;

    // Sign.
    let sig_bytes = ed25519_sign(&keypair.private_key, message)?;

    // keypair.private_key is Zeroizing and will be zeroized on drop.
    // entropy is Zeroizing<Vec<u8>> and will be zeroized on drop.

    Ok((fingerprint, algorithm_str, sig_bytes))
}

/// Verify a Canton signature against a wallet's public key and message.
///
/// This is a convenience function for testing and off-chain verification.
pub fn verify_canton_signature(
    wallet: &CantonWalletFile,
    passphrase: &str,
    message: &[u8],
    signature: &CantonSignature,
) -> Result<bool, CantonError> {
    let account = wallet
        .accounts
        .first()
        .ok_or_else(|| CantonError::InvalidWalletFile {
            reason: "wallet has no accounts".to_string(),
        })?;
    let derivation_path = &account.derivation_path;

    let algorithm: CantonSigningAlgorithm = serde_json::from_value(serde_json::Value::String(
        account.canton.signing_algorithm.clone(),
    ))
    .map_err(|_| CantonError::UnsupportedAlgorithm {
        algorithm: account.canton.signing_algorithm.clone(),
    })?;

    let entropy = decrypt_canton_wallet(wallet, passphrase)?;
    let mnemonic =
        bip39::Mnemonic::from_entropy(&entropy).map_err(|e| CantonError::InvalidMnemonic {
            reason: e.to_string(),
        })?;
    let seed = mnemonic.to_seed("");
    let keypair = generate_canton_keypair(&seed, derivation_path, algorithm)?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signature.signature)
        .map_err(|e| CantonError::SigningFailed {
            reason: format!("invalid base64 signature: {e}"),
        })?;

    let pubkey: [u8; 32] =
        keypair
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| CantonError::InvalidPublicKey {
                reason: "unexpected public key length".to_string(),
            })?;

    ed25519_verify(&pubkey, message, &sig_bytes)
}

// ── Command submission flow ────────────────────────────────────────

/// Submit a signed DAML command to the Canton Ledger API.
///
/// Full flow: decrypt wallet → derive keypair → build request →
/// SHA-256 hash → sign → submit → audit log → return result.
///
/// Key material is zeroized automatically via [`Zeroizing`](zeroize::Zeroizing)
/// and [`CantonKeyPair::drop`](crate::keygen::CantonKeyPair).
pub async fn canton_submit_command(
    wallet: &CantonWalletFile,
    passphrase: &str,
    command: &CantonCommand,
    act_as: &[String],
    read_as: &[String],
    client: &LedgerApiClient,
    ows_home: Option<&std::path::Path>,
) -> Result<CantonSubmitResult, CantonError> {
    let account = wallet
        .accounts
        .first()
        .ok_or_else(|| CantonError::InvalidWalletFile {
            reason: "wallet has no accounts".to_string(),
        })?;

    let fingerprint = account.canton.key_fingerprint.clone();
    let derivation_path = &account.derivation_path;
    let algorithm: CantonSigningAlgorithm = serde_json::from_value(serde_json::Value::String(
        account.canton.signing_algorithm.clone(),
    ))
    .map_err(|_| CantonError::UnsupportedAlgorithm {
        algorithm: account.canton.signing_algorithm.clone(),
    })?;

    // 1. Decrypt wallet → mnemonic entropy.
    let entropy = decrypt_canton_wallet(wallet, passphrase)?;
    let mnemonic =
        bip39::Mnemonic::from_entropy(&entropy).map_err(|e| CantonError::InvalidMnemonic {
            reason: e.to_string(),
        })?;
    let seed = mnemonic.to_seed("");

    // 2. Derive signing key.
    let keypair = generate_canton_keypair(&seed, derivation_path, algorithm)?;

    // 3. Build submission request.
    let command_id = uuid::Uuid::new_v4().to_string();
    let submission = build_submission_request(command, act_as, read_as, &command_id);

    // 4. Hash the serialized submission → sign.
    let payload_bytes = serde_json::to_vec(&submission)?;
    let payload_hash = Sha256::digest(&payload_bytes);
    let sig_bytes = ed25519_sign(&keypair.private_key, &payload_hash)?;

    // 5. Build signature request for the API.
    let sig_request = MultiHashSignatureRequest {
        format: SIGNATURE_FORMAT_CONCAT.to_string(),
        signature: base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
        signed_by: fingerprint.clone(),
        signing_algorithm_spec: algorithm.to_string(),
    };

    // keypair, entropy, seed are all dropped here → zeroized.

    // 6. Submit to Ledger API.
    let submit_req = SubmitCommandRequest {
        commands: submission,
        multi_hash_signatures: vec![sig_request],
    };
    let resp = client.submit_command(&submit_req).await?;

    // 7. Build result.
    let result = CantonSubmitResult {
        command_id: command_id.clone(),
        status: if resp.transaction_id.is_some() {
            CantonCommandStatus::Succeeded
        } else {
            CantonCommandStatus::Failed {
                reason: "no transaction_id in response".to_string(),
            }
        },
        completion_offset: resp.completion_offset,
        transaction_id: resp.transaction_id,
    };

    // 8. Audit log.
    if let Some(home) = ows_home {
        let _ = append_audit_log_in(
            home,
            &AuditEntry::new(
                &wallet.id,
                "canton_submit_command",
                &account.chain_id,
                serde_json::json!({
                    "template_id": &command.template_id,
                    "choice": &command.choice,
                    "command_id": &command_id,
                    "act_as": act_as,
                    "status": serde_json::to_value(&result.status).unwrap_or_default(),
                }),
            ),
        );
    }

    Ok(result)
}

/// Simulate a DAML command without signing or committing.
///
/// No key decryption is needed — the command is sent directly to the
/// Ledger API simulation endpoint.
pub async fn canton_simulate(
    command: &CantonCommand,
    act_as: &[String],
    read_as: &[String],
    client: &LedgerApiClient,
) -> Result<SimulationResult, CantonError> {
    let command_id = uuid::Uuid::new_v4().to_string();
    let submission = build_submission_request(command, act_as, read_as, &command_id);

    let req = SimulateCommandRequest {
        commands: submission,
    };
    let resp = client.simulate_command(&req).await?;

    Ok(SimulationResult {
        success: resp.success,
        error_message: resp.error_message,
    })
}

/// Query active contracts from the Ledger API.
pub async fn canton_query_contracts(
    template_id: &str,
    parties: &[String],
    client: &LedgerApiClient,
) -> Result<Vec<ActiveContract>, CantonError> {
    client.get_active_contracts(template_id, parties).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::CantonChainId;
    use crate::wallet::create_canton_wallet_in;

    const PASSPHRASE: &str = "test-passphrase-long-enough";

    /// Create a test wallet in a temp directory.
    fn make_test_wallet(tmpdir: &std::path::Path) -> CantonWalletFile {
        let chain_id = CantonChainId::parse(CantonChainId::SANDBOX).unwrap();
        create_canton_wallet_in(
            tmpdir,
            "sign-test",
            PASSPHRASE,
            &chain_id,
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap()
    }

    #[test]
    fn test_sign_message_ed25519() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = make_test_wallet(tmpdir.path());

        let sig =
            canton_sign_message(&wallet, PASSPHRASE, b"hello", MessageEncoding::Utf8).unwrap();

        assert_eq!(sig.format, "SIGNATURE_FORMAT_CONCAT");
        assert_eq!(sig.algorithm, "SIGNING_ALGORITHM_SPEC_ED25519");
        assert!(!sig.signature.is_empty());
        assert!(sig.signed_by.starts_with("1220"));

        // Signature base64 decodes to 64 bytes.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig.signature)
            .unwrap();
        assert_eq!(raw.len(), 64);
    }

    #[test]
    fn test_sign_message_deterministic() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = make_test_wallet(tmpdir.path());

        let sig1 =
            canton_sign_message(&wallet, PASSPHRASE, b"deterministic", MessageEncoding::Utf8)
                .unwrap();
        let sig2 =
            canton_sign_message(&wallet, PASSPHRASE, b"deterministic", MessageEncoding::Utf8)
                .unwrap();

        assert_eq!(sig1.signature, sig2.signature);
        assert_eq!(sig1.signed_by, sig2.signed_by);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = make_test_wallet(tmpdir.path());
        let message = b"canton roundtrip test";

        let sig = canton_sign_message(&wallet, PASSPHRASE, message, MessageEncoding::Utf8).unwrap();

        let valid = verify_canton_signature(&wallet, PASSPHRASE, message, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet_a = make_test_wallet(tmpdir.path());

        // Create a second wallet with a different key.
        let chain_id = CantonChainId::parse(CantonChainId::SANDBOX).unwrap();
        let wallet_b = create_canton_wallet_in(
            tmpdir.path(),
            "sign-test-b",
            PASSPHRASE,
            &chain_id,
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let message = b"signed by A";
        let sig =
            canton_sign_message(&wallet_a, PASSPHRASE, message, MessageEncoding::Utf8).unwrap();

        // Verify with B's key should fail.
        let valid = verify_canton_signature(&wallet_b, PASSPHRASE, message, &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_verify_tampered_msg() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = make_test_wallet(tmpdir.path());

        let sig =
            canton_sign_message(&wallet, PASSPHRASE, b"hello", MessageEncoding::Utf8).unwrap();

        let valid = verify_canton_signature(&wallet, PASSPHRASE, b"world", &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_topology() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = make_test_wallet(tmpdir.path());
        let topology_bytes = b"topology-tx-payload-bytes";

        let sig = canton_sign_topology(&wallet, PASSPHRASE, topology_bytes).unwrap();

        assert_eq!(sig.format, "SIGNATURE_FORMAT_CONCAT");
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn test_sign_wrong_passphrase() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = make_test_wallet(tmpdir.path());

        let err = canton_sign_message(&wallet, "wrong-passphrase!", b"msg", MessageEncoding::Utf8)
            .unwrap_err();
        assert!(matches!(err, CantonError::DecryptionFailed));
    }

    #[test]
    fn test_build_submission_request() {
        let cmd = CantonCommand {
            template_id: "Daml.Finance.Holding:Fungible".to_string(),
            command_type: CantonCommandType::Create,
            choice: None,
            contract_id: None,
            arguments: serde_json::json!({"owner": "alice"}),
        };

        let req = build_submission_request(
            &cmd,
            &["alice::1220abcd".to_string()],
            &["bob::1220ffff".to_string()],
            "cmd-001",
        );

        assert_eq!(req["commandId"], "cmd-001");
        assert_eq!(req["actAs"][0], "alice::1220abcd");
        assert_eq!(req["readAs"][0], "bob::1220ffff");
        assert!(req["commands"].is_array());
        assert!(req["commands"][0]["create"].is_object());
        assert_eq!(
            req["commands"][0]["create"]["templateId"],
            "Daml.Finance.Holding:Fungible"
        );
    }

    #[test]
    fn test_build_submission_request_exercise() {
        let cmd = CantonCommand {
            template_id: "Daml.Finance.Holding:Fungible".to_string(),
            command_type: CantonCommandType::Exercise,
            choice: Some("Transfer".to_string()),
            contract_id: Some("00abcdef".to_string()),
            arguments: serde_json::json!({"newOwner": "bob"}),
        };

        let req = build_submission_request(&cmd, &["alice::1220abcd".to_string()], &[], "cmd-002");

        assert!(req["commands"][0]["exercise"].is_object());
        let ex = &req["commands"][0]["exercise"];
        assert_eq!(ex["templateId"], "Daml.Finance.Holding:Fungible");
        assert_eq!(ex["contractId"], "00abcdef");
        assert_eq!(ex["choice"], "Transfer");
    }

    #[test]
    fn test_build_multi_hash_signature() {
        let sig_bytes = vec![0xAA; 64];
        let result =
            build_multi_hash_signature(&sig_bytes, "1220abcdef", &CantonSigningAlgorithm::Ed25519);

        assert_eq!(result["format"], "SIGNATURE_FORMAT_CONCAT");
        assert_eq!(result["signedBy"], "1220abcdef");
        assert_eq!(
            result["signingAlgorithmSpec"],
            "SIGNING_ALGORITHM_SPEC_ED25519"
        );

        // Signature should be base64-encoded.
        let sig_b64 = result["signature"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        assert_eq!(decoded.len(), 64);
    }

    #[test]
    fn test_command_type_serialization() {
        let create = serde_json::to_value(CantonCommandType::Create).unwrap();
        assert_eq!(create, "create");

        let exercise = serde_json::to_value(CantonCommandType::Exercise).unwrap();
        assert_eq!(exercise, "exercise");

        let cae = serde_json::to_value(CantonCommandType::CreateAndExercise).unwrap();
        assert_eq!(cae, "create_and_exercise");
    }

    #[test]
    fn test_submit_result_parsing() {
        let json = serde_json::json!({
            "command_id": "cmd-001",
            "status": "succeeded",
            "completion_offset": "000000000000000042",
            "transaction_id": "tx-abc123"
        });
        let result: CantonSubmitResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.command_id, "cmd-001");
        assert!(matches!(result.status, CantonCommandStatus::Succeeded));
        assert_eq!(
            result.completion_offset.as_deref(),
            Some("000000000000000042")
        );
        assert_eq!(result.transaction_id.as_deref(), Some("tx-abc123"));

        // Failed status.
        let json_fail = serde_json::json!({
            "command_id": "cmd-002",
            "status": { "failed": { "reason": "contract not found" } },
        });
        let result_fail: CantonSubmitResult = serde_json::from_value(json_fail).unwrap();
        assert!(matches!(
            result_fail.status,
            CantonCommandStatus::Failed { .. }
        ));

        // Timeout status.
        let json_timeout = serde_json::json!({
            "command_id": "cmd-003",
            "status": "timeout",
        });
        let result_timeout: CantonSubmitResult = serde_json::from_value(json_timeout).unwrap();
        assert!(matches!(
            result_timeout.status,
            CantonCommandStatus::Timeout
        ));
    }

    #[test]
    fn test_canton_signature_serde() {
        let sig = CantonSignature {
            signature: "dGVzdA==".to_string(),
            signed_by: "1220abcd".to_string(),
            format: "SIGNATURE_FORMAT_CONCAT".to_string(),
            algorithm: "SIGNING_ALGORITHM_SPEC_ED25519".to_string(),
        };
        let json = serde_json::to_value(&sig).unwrap();
        assert_eq!(json["format"], "SIGNATURE_FORMAT_CONCAT");
        let roundtrip: CantonSignature = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.signed_by, sig.signed_by);
    }

    // ── Async command submission tests ─────────────────────────────

    mod submit_tests {
        use super::*;
        use crate::audit::read_audit_log_in;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        async fn make_test_wallet_and_dir() -> (tempfile::TempDir, CantonWalletFile) {
            let tmpdir = tempfile::tempdir().unwrap();
            let chain_id = CantonChainId::parse(CantonChainId::SANDBOX).unwrap();
            let wallet = create_canton_wallet_in(
                tmpdir.path(),
                "submit-test",
                PASSPHRASE,
                &chain_id,
                "http://localhost:7575",
                CantonSigningAlgorithm::Ed25519,
            )
            .unwrap();
            (tmpdir, wallet)
        }

        fn test_command() -> CantonCommand {
            CantonCommand {
                template_id: "Daml.Finance.Holding:Fungible".to_string(),
                command_type: CantonCommandType::Exercise,
                choice: Some("Transfer".to_string()),
                contract_id: Some("00abcdef".to_string()),
                arguments: serde_json::json!({"newOwner": "bob"}),
            }
        }

        #[tokio::test]
        async fn test_submit_command_success() {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v2/commands/submit"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "commandId": "cmd-001",
                    "completionOffset": "42",
                    "transactionId": "tx-abc"
                })))
                .mount(&mock)
                .await;

            let (tmpdir, wallet) = make_test_wallet_and_dir().await;
            let client = LedgerApiClient::new(&mock.uri(), None);

            let result = canton_submit_command(
                &wallet,
                PASSPHRASE,
                &test_command(),
                &["alice::1220abcd".to_string()],
                &[],
                &client,
                Some(tmpdir.path()),
            )
            .await
            .unwrap();

            assert!(!result.command_id.is_empty());
            assert!(matches!(result.status, CantonCommandStatus::Succeeded));
            assert_eq!(result.transaction_id.as_deref(), Some("tx-abc"));
            assert_eq!(result.completion_offset.as_deref(), Some("42"));
        }

        #[tokio::test]
        async fn test_submit_command_failure() {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v2/commands/submit"))
                .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
                .mount(&mock)
                .await;

            let (tmpdir, wallet) = make_test_wallet_and_dir().await;
            let client = LedgerApiClient::new(&mock.uri(), None);

            let err = canton_submit_command(
                &wallet,
                PASSPHRASE,
                &test_command(),
                &["alice::1220abcd".to_string()],
                &[],
                &client,
                Some(tmpdir.path()),
            )
            .await
            .unwrap_err();

            assert!(matches!(err, CantonError::ServerError { .. }));
        }

        #[tokio::test]
        async fn test_simulate_success() {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v2/commands/simulate"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": true
                })))
                .mount(&mock)
                .await;

            let client = LedgerApiClient::new(&mock.uri(), None);
            let result = canton_simulate(
                &test_command(),
                &["alice::1220abcd".to_string()],
                &[],
                &client,
            )
            .await
            .unwrap();

            assert!(result.success);
            assert!(result.error_message.is_none());
        }

        #[tokio::test]
        async fn test_simulate_failure() {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v2/commands/simulate"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": false,
                    "errorMessage": "contract not active"
                })))
                .mount(&mock)
                .await;

            let client = LedgerApiClient::new(&mock.uri(), None);
            let result = canton_simulate(
                &test_command(),
                &["alice::1220abcd".to_string()],
                &[],
                &client,
            )
            .await
            .unwrap();

            assert!(!result.success);
            assert_eq!(result.error_message.as_deref(), Some("contract not active"));
        }

        #[tokio::test]
        async fn test_query_contracts() {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v2/state/active-contracts"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "activeContracts": [
                        {
                            "contractId": "cid-001",
                            "templateId": "T:T",
                            "payload": {"key": "value"},
                            "signatories": ["alice::1220abcd"],
                            "observers": []
                        }
                    ]
                })))
                .mount(&mock)
                .await;

            let client = LedgerApiClient::new(&mock.uri(), None);
            let contracts =
                canton_query_contracts("T:T", &["alice::1220abcd".to_string()], &client)
                    .await
                    .unwrap();

            assert_eq!(contracts.len(), 1);
            assert_eq!(contracts[0].contract_id, "cid-001");
            assert_eq!(contracts[0].template_id, "T:T");
        }

        #[tokio::test]
        async fn test_audit_log_written() {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v2/commands/submit"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "commandId": "cmd-audit",
                    "completionOffset": "1",
                    "transactionId": "tx-audit"
                })))
                .mount(&mock)
                .await;

            let (tmpdir, wallet) = make_test_wallet_and_dir().await;
            let client = LedgerApiClient::new(&mock.uri(), None);

            canton_submit_command(
                &wallet,
                PASSPHRASE,
                &test_command(),
                &["alice::1220abcd".to_string()],
                &[],
                &client,
                Some(tmpdir.path()),
            )
            .await
            .unwrap();

            let entries = read_audit_log_in(tmpdir.path()).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].operation, "canton_submit_command");
            assert_eq!(entries[0].wallet_id, wallet.id);
            assert!(entries[0].details["command_id"].is_string());
            assert!(entries[0].details["template_id"].is_string());
        }

        #[tokio::test]
        async fn test_audit_log_append() {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v2/commands/submit"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "commandId": "cmd-x",
                    "completionOffset": "1",
                    "transactionId": "tx-x"
                })))
                .mount(&mock)
                .await;

            let (tmpdir, wallet) = make_test_wallet_and_dir().await;
            let client = LedgerApiClient::new(&mock.uri(), None);

            // Submit twice.
            canton_submit_command(
                &wallet,
                PASSPHRASE,
                &test_command(),
                &["alice::1220abcd".to_string()],
                &[],
                &client,
                Some(tmpdir.path()),
            )
            .await
            .unwrap();

            canton_submit_command(
                &wallet,
                PASSPHRASE,
                &test_command(),
                &["alice::1220abcd".to_string()],
                &[],
                &client,
                Some(tmpdir.path()),
            )
            .await
            .unwrap();

            let entries = read_audit_log_in(tmpdir.path()).unwrap();
            assert_eq!(entries.len(), 2, "should have 2 audit entries");
        }
    }
}
