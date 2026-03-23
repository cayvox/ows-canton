# Spec 03 — Wallet File Format

## Overview

Canton wallets use the standard OWS wallet file format (Spec 01 — Storage Format) with Canton-specific extensions in the `accounts` array and a `canton_config` top-level field.

## Wallet File Structure

File location: `~/.ows/wallets/<uuid>.json`
Permissions: `0600` (owner read/write only)

```json
{
  "ows_version": 2,
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "name": "agent-treasury",
  "created_at": "2026-03-23T10:30:00Z",
  "chain_type": "canton",
  "accounts": [
    {
      "account_id": "canton:global:agent-treasury::1220a1b2c3d4e5f6a7b8",
      "address": "agent-treasury::1220a1b2c3d4e5f6a7b8",
      "chain_id": "canton:global",
      "derivation_path": "m/44'/9999'/0'/0/0",
      "canton": {
        "party_id": "agent-treasury::1220a1b2c3d4e5f6a7b8",
        "key_fingerprint": "1220a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
        "key_format": "DER",
        "signing_algorithm": "SIGNING_ALGORITHM_SPEC_ED25519",
        "party_type": "external",
        "topology_registered": true,
        "participant_host": "https://participant.canton.network:443",
        "synchronizer_id": "canton::global-synchronizer-id"
      }
    }
  ],
  "crypto": {
    "cipher": "aes-256-gcm",
    "cipherparams": {
      "iv": "6087dab2f9fdbbfaddc31a90"
    },
    "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
    "auth_tag": "3c5d8c2f1a4b6e9d0f2a5c8b",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 65536,
      "r": 8,
      "p": 1,
      "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
    }
  },
  "key_type": "mnemonic",
  "canton_config": {
    "default_synchronizer": "canton:global",
    "participant_url": "https://participant.canton.network:443",
    "auth_token_path": null,
    "simulation_required": true
  },
  "metadata": {}
}
```

## Rust Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonWalletFile {
    pub ows_version: u32,  // Always 2
    pub id: String,        // UUID v4
    pub name: String,
    pub created_at: String, // ISO 8601
    pub chain_type: String, // "canton"
    pub accounts: Vec<CantonAccountEntry>,
    pub crypto: CryptoEnvelope,
    pub key_type: KeyType,  // "mnemonic" or "private_key"
    #[serde(default)]
    pub canton_config: Option<CantonConfig>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonAccountEntry {
    pub account_id: String,       // CAIP-10
    pub address: String,          // Canton party ID
    pub chain_id: String,         // CAIP-2
    pub derivation_path: String,  // BIP-44 path
    pub canton: CantonAccountMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonAccountMetadata {
    pub party_id: String,
    pub key_fingerprint: String,
    pub key_format: String,  // Always "DER"
    pub signing_algorithm: String,
    pub party_type: CantonPartyType,
    pub topology_registered: bool,
    pub participant_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synchronizer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CantonPartyType {
    External,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonConfig {
    pub default_synchronizer: String,
    pub participant_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token_path: Option<String>,
    #[serde(default)]
    pub simulation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEnvelope {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub auth_tag: String,
    pub kdf: String,
    pub kdfparams: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Mnemonic,
    PrivateKey,
}
```

## Wallet Operations

### Create

```rust
pub fn create_canton_wallet(
    name: &str,
    passphrase: &str,
    chain_id: &CantonChainId,
    participant_url: &str,
    signing_algorithm: CantonSigningAlgorithm,
) -> Result<CantonWalletFile, CantonError>
```

1. Generate UUID v4 for wallet ID
2. Generate BIP-39 mnemonic (256-bit entropy)
3. Derive key pair via SLIP-0010
4. Build CantonAccountEntry with metadata
5. Encrypt mnemonic with AES-256-GCM(scrypt(passphrase))
6. Construct wallet file JSON
7. Write to `~/.ows/wallets/{id}.json`
8. Set file permissions to 0600

### Read

```rust
pub fn load_canton_wallet(
    wallet_id_or_name: &str,
) -> Result<CantonWalletFile, CantonError>
```

1. If input is UUID, load `~/.ows/wallets/{id}.json`
2. If input is name, scan all wallet files, find by `name` field
3. Parse JSON into CantonWalletFile
4. Validate ows_version == 2
5. Validate chain_type == "canton"

### Decrypt

```rust
pub fn decrypt_canton_wallet(
    wallet: &CantonWalletFile,
    passphrase: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CantonError>
```

1. Derive key from passphrase using wallet's KDF params
2. Decrypt ciphertext with AES-256-GCM
3. Return mnemonic entropy (zeroize wrapper)

### List

```rust
pub fn list_canton_wallets() -> Result<Vec<CantonWalletFile>, CantonError>
```

1. Read all `.json` files in `~/.ows/wallets/`
2. Filter by `chain_type == "canton"`
3. Return list (without decrypting)

## Encryption Parameters

### Passphrase Requirements
- Minimum 12 characters
- Enforced at wallet creation time
- Not stored anywhere

### scrypt Parameters
- `n`: 65536 (2^16) — MINIMUM. Implementations MAY use higher.
- `r`: 8
- `p`: 1
- `dklen`: 32 bytes
- `salt`: 32 random bytes, hex-encoded

### AES-256-GCM Parameters
- Key: 32 bytes (from scrypt)
- IV: 12 random bytes, hex-encoded
- Auth tag: 16 bytes, hex-encoded

## Unit Tests Required

```
test_create_wallet_valid          → creates file, verify JSON structure
test_create_wallet_short_pass     → passphrase < 12 chars → Err
test_load_wallet_by_id            → load by UUID
test_load_wallet_by_name          → load by wallet name
test_load_wallet_not_found        → non-existent → Err
test_decrypt_wallet_correct_pass  → decrypt → mnemonic matches original
test_decrypt_wallet_wrong_pass    → wrong passphrase → Err(DecryptionFailed)
test_wallet_roundtrip             → create → load → decrypt → same mnemonic
test_wallet_json_schema           → serialized JSON has all required fields
test_wallet_file_permissions      → file permissions are 0600 (Unix only)
test_list_canton_wallets          → create 2 canton + 1 evm → list returns 2
test_canton_metadata_complete     → all CantonAccountMetadata fields present
```
