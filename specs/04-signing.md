# Spec 04 — Signing Interface

## Overview

Canton signing differs from raw-transaction-based chains. There is no `tx_hex` to sign. Instead, Canton uses an interactive submission protocol where the External Party signs specific protocol messages.

## Signing Modes

### Mode 1: DAML Command Submission (Primary)

The agent submits a structured DAML command. OWS signs the submission payload and sends it to the Ledger API.

```rust
pub async fn canton_submit_command(
    wallet: &CantonWalletFile,
    credential: &str,            // passphrase or ows_key_...
    command: &CantonCommand,
    act_as: &[String],
    read_as: &[String],
    client: &LedgerApiClient,
) -> Result<CantonSubmitResult, CantonError>
```

### Mode 2: Message Signing

Sign an arbitrary message with the Canton key. Used for authentication challenges, off-chain attestations.

```rust
pub fn canton_sign_message(
    wallet: &CantonWalletFile,
    credential: &str,
    message: &[u8],
    encoding: MessageEncoding,
) -> Result<CantonSignature, CantonError>
```

### Mode 3: Topology Transaction Signing

Sign topology transactions for key rotation, party hosting changes.

```rust
pub fn canton_sign_topology(
    wallet: &CantonWalletFile,
    credential: &str,
    topology_tx_bytes: &[u8],
) -> Result<CantonSignature, CantonError>
```

## Core Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonCommand {
    pub command_type: CantonCommandType,
    pub template_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CantonCommandType {
    Create,
    Exercise,
    CreateAndExercise,
}

#[derive(Debug, Clone)]
pub struct CantonSignature {
    /// Base64-encoded signature bytes
    pub signature: String,
    /// Key fingerprint (identifies the signing key)
    pub signed_by: String,
    /// Signature format for Canton API
    pub format: String,  // "SIGNATURE_FORMAT_CONCAT"
    /// Signing algorithm spec
    pub algorithm: String, // "SIGNING_ALGORITHM_SPEC_ED25519"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonSubmitResult {
    pub command_id: String,
    pub status: CantonCommandStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CantonCommandStatus {
    Succeeded,
    Failed { reason: String },
    Timeout,
}
```

## Signing Flow (Detailed)

### Step-by-Step for Command Submission

```
fn canton_submit_command_inner(
    wallet, credential, command, act_as, read_as, client
) -> Result<CantonSubmitResult>:

    // 1. Authenticate
    let access = authenticate(credential, wallet)?;
    // access is either OwnerAccess(passphrase) or AgentAccess(api_key)

    // 2. Policy check (agent mode only)
    if let AgentAccess(api_key) = &access {
        let context = build_canton_policy_context(command, wallet, act_as, &api_key);
        evaluate_policies(&api_key.policy_ids, &context)?;
        // Returns Err(PolicyDenied) if any policy denies
    }

    // 3. Simulate (if required by policy or flag)
    if should_simulate(command, &access) {
        let sim_result = client.simulate(command, act_as).await?;
        if !sim_result.success {
            return Err(CantonError::SimulationFailed(sim_result.error));
        }
    }

    // 4. Decrypt key material
    let mnemonic = match access {
        OwnerAccess(passphrase) => decrypt_wallet(wallet, passphrase)?,
        AgentAccess(api_key) => decrypt_api_key_secret(api_key, wallet.id)?,
    };

    // 5. Derive signing key
    let keypair = derive_canton_key(&mnemonic, &wallet.accounts[0].derivation_path)?;
    mnemonic.zeroize();

    // 6. Build submission request
    let command_id = uuid::Uuid::new_v4().to_string();
    let submission = build_submission_request(command, act_as, read_as, &command_id);

    // 7. Sign the submission
    //    Canton's interactive submission requires signing the hash of the
    //    serialized submission payload
    let payload_hash = sha256(serde_json::to_vec(&submission)?);
    let signature = ed25519_sign(&keypair.private_key, &payload_hash)?;
    keypair.private_key.zeroize();

    // 8. Construct MultiHashSignature
    let multi_sig = CantonSignature {
        signature: base64_encode(&signature),
        signed_by: keypair.fingerprint.clone(),
        format: "SIGNATURE_FORMAT_CONCAT".to_string(),
        algorithm: "SIGNING_ALGORITHM_SPEC_ED25519".to_string(),
    };

    // 9. Submit to Ledger API
    let result = client.submit_command(&submission, &multi_sig).await?;

    // 10. Write audit log
    audit_log(AuditEntry::CantonSubmit {
        wallet_id: wallet.id.clone(),
        chain_id: wallet.accounts[0].chain_id.clone(),
        command_id: command_id.clone(),
        template_id: command.template_id.clone(),
        choice: command.choice.clone(),
        status: result.status.clone(),
    })?;

    Ok(result)
```

### Ed25519 Signing

```rust
use ed25519_dalek::{SigningKey, Signer};

pub fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, CantonError> {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<bool, CantonError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)?;
    let sig = ed25519_dalek::Signature::from_slice(signature)?;
    Ok(verifying_key.verify_strict(message, &sig).is_ok())
}
```

## Important Notes

### Canton Interactive Submission Protocol

The exact signing format depends on Canton's protocol version. For Canton 3.4+:

1. The client serializes the DAML command as a JSON body for the `/v2/commands/submit` endpoint
2. The External Party signs a hash of the serialized command payload
3. The signature is attached as a `multiHashSignatures` field in the request

**CRITICAL:** The exact bytes that need to be signed (the "signing payload") are determined by Canton's protocol. The implementation MUST be tested against a running Canton Sandbox to verify the correct signing format. The hash computation and signature format described above are based on Canton 3.4 documentation — verify against actual sandbox behavior during integration testing.

### Signature Format

Canton expects signatures in the `SIGNATURE_FORMAT_CONCAT` format, which means the raw signature bytes concatenated (no DER wrapping for Ed25519).

For Ed25519: 64 bytes (R || S)
For secp256k1: implementation-dependent (likely DER-encoded ECDSA signature)

## Unit Tests Required

```
test_sign_message_ed25519          → sign "hello", verify signature
test_sign_message_deterministic    → same key + message → same signature
test_sign_verify_roundtrip         → sign → verify → true
test_sign_verify_wrong_key         → sign with A, verify with B → false
test_sign_verify_tampered_msg      → sign "hello", verify "world" → false
test_build_submission_request      → correct JSON structure
test_build_multi_hash_signature    → correct format/algorithm fields
test_command_type_serialization    → Create/Exercise serialize correctly
test_submit_result_parsing         → parse success/failure responses
```
