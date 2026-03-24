//! Canton wallet file format (create, read, write, encrypt, decrypt).
//!
//! Manages Canton wallet files stored in `~/.ows/wallets/`, including
//! AES-256-GCM encryption of mnemonic material with scrypt-derived keys.
//! See `specs/03-wallet-format.md` for the full specification.

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::identifier::CantonChainId;
use crate::keygen::{generate_canton_keypair, CantonSigningAlgorithm, CANTON_DERIVATION_PATH};
use crate::CantonError;

/// Minimum passphrase length in characters.
const MIN_PASSPHRASE_LEN: usize = 12;

/// scrypt log₂(N) parameter — N = 65536.
const SCRYPT_LOG_N: u8 = 16;

/// scrypt block size parameter.
const SCRYPT_R: u32 = 8;

/// scrypt parallelism parameter.
const SCRYPT_P: u32 = 1;

/// Derived key length in bytes.
const SCRYPT_DKLEN: usize = 32;

/// AES-GCM nonce (IV) length in bytes.
const AES_NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes.
const AES_TAG_LEN: usize = 16;

/// scrypt salt length in bytes.
const SALT_LEN: usize = 32;

// ── Types ──────────────────────────────────────────────────────────

/// Top-level Canton wallet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonWalletFile {
    /// OWS format version. Always `2`.
    pub ows_version: u32,
    /// Wallet UUID v4.
    pub id: String,
    /// Human-readable wallet name.
    pub name: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Chain type discriminator. Always `"canton"`.
    pub chain_type: String,
    /// Accounts contained in this wallet.
    pub accounts: Vec<CantonAccountEntry>,
    /// Encrypted mnemonic envelope.
    pub crypto: CryptoEnvelope,
    /// Type of key material stored.
    pub key_type: KeyType,
    /// Canton-specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canton_config: Option<CantonConfig>,
    /// Arbitrary metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// A single account entry within the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonAccountEntry {
    /// CAIP-10 account identifier.
    pub account_id: String,
    /// Canton party ID (address).
    pub address: String,
    /// CAIP-2 chain identifier.
    pub chain_id: String,
    /// BIP-44 HD derivation path.
    pub derivation_path: String,
    /// Canton-specific account metadata.
    pub canton: CantonAccountMetadata,
}

/// Canton-specific metadata for an account entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonAccountMetadata {
    /// Canton party ID.
    pub party_id: String,
    /// Hex-encoded key fingerprint.
    pub key_fingerprint: String,
    /// Key encoding format (always `"DER"`).
    pub key_format: String,
    /// Canton signing algorithm spec string.
    pub signing_algorithm: String,
    /// Party type (external or local).
    pub party_type: CantonPartyType,
    /// Whether the party has been registered via topology transaction.
    pub topology_registered: bool,
    /// Canton participant node URL.
    pub participant_host: String,
    /// Synchronizer identifier (set after onboarding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synchronizer_id: Option<String>,
}

/// Canton party type discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CantonPartyType {
    /// External party — key held by OWS vault.
    External,
    /// Local party — key held by participant node.
    Local,
}

/// Canton-specific wallet configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonConfig {
    /// Default synchronizer for this wallet.
    pub default_synchronizer: String,
    /// Canton participant node URL.
    pub participant_url: String,
    /// Path to JWT auth token file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token_path: Option<String>,
    /// Whether command simulation is required before submission.
    #[serde(default)]
    pub simulation_required: bool,
}

/// Encrypted key material envelope (AES-256-GCM + scrypt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEnvelope {
    /// Cipher algorithm identifier.
    pub cipher: String,
    /// Cipher parameters (IV).
    pub cipherparams: CipherParams,
    /// Hex-encoded ciphertext.
    pub ciphertext: String,
    /// Hex-encoded AES-GCM authentication tag.
    pub auth_tag: String,
    /// Key derivation function identifier.
    pub kdf: String,
    /// KDF parameters.
    pub kdfparams: serde_json::Value,
}

/// AES-GCM cipher parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// Hex-encoded 12-byte nonce (IV).
    pub iv: String,
}

/// Type of key material stored in the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// BIP-39 mnemonic entropy.
    Mnemonic,
    /// Raw private key bytes.
    PrivateKey,
}

/// scrypt KDF parameters for JSON serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScryptKdfParams {
    dklen: u32,
    n: u32,
    r: u32,
    p: u32,
    salt: String,
}

// ── Public API ─────────────────────────────────────────────────────

/// Create a new Canton wallet, encrypt it, and write to disk.
///
/// Generates a 24-word BIP-39 mnemonic, derives an Ed25519 key pair,
/// encrypts the mnemonic entropy with AES-256-GCM + scrypt, and writes
/// the wallet file to `$OWS_HOME/wallets/<uuid>.json`.
///
/// # Errors
///
/// Returns [`CantonError::PassphraseTooShort`] if `passphrase` is shorter
/// than 12 characters.
pub fn create_canton_wallet(
    name: &str,
    passphrase: &str,
    chain_id: &CantonChainId,
    participant_url: &str,
    algorithm: CantonSigningAlgorithm,
) -> Result<CantonWalletFile, CantonError> {
    let ows_home = get_ows_home()?;
    create_canton_wallet_in(
        &ows_home,
        name,
        passphrase,
        chain_id,
        participant_url,
        algorithm,
    )
}

/// Load a Canton wallet by UUID or name.
///
/// Searches `$OWS_HOME/wallets/` for a matching wallet file. If the input
/// looks like a UUID, loads the file directly; otherwise scans all wallet
/// files for a matching `name` field.
pub fn load_canton_wallet(wallet_id_or_name: &str) -> Result<CantonWalletFile, CantonError> {
    let ows_home = get_ows_home()?;
    load_canton_wallet_in(&ows_home, wallet_id_or_name)
}

/// Decrypt the mnemonic entropy from an encrypted wallet.
///
/// Derives the decryption key from `passphrase` using the wallet's scrypt
/// parameters, then decrypts the AES-256-GCM ciphertext. The returned
/// bytes are the raw BIP-39 mnemonic entropy wrapped in [`Zeroizing`].
pub fn decrypt_canton_wallet(
    wallet: &CantonWalletFile,
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, CantonError> {
    decrypt_wallet_crypto(&wallet.crypto, passphrase)
}

/// List all Canton wallets in `$OWS_HOME/wallets/`.
pub fn list_canton_wallets() -> Result<Vec<CantonWalletFile>, CantonError> {
    let ows_home = get_ows_home()?;
    list_canton_wallets_in(&ows_home)
}

// ── Internal API (pub(crate) for testing) ──────────────────────────

/// Create a wallet in the given base directory.
pub fn create_canton_wallet_in(
    ows_home: &Path,
    name: &str,
    passphrase: &str,
    chain_id: &CantonChainId,
    participant_url: &str,
    algorithm: CantonSigningAlgorithm,
) -> Result<CantonWalletFile, CantonError> {
    validate_passphrase(passphrase)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Generate mnemonic (24 words = 256-bit entropy).
    let mut rng_entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rng_entropy);
    let mnemonic =
        bip39::Mnemonic::from_entropy(&rng_entropy).map_err(|e| CantonError::InvalidMnemonic {
            reason: e.to_string(),
        })?;
    let entropy = mnemonic.to_entropy();
    let seed = mnemonic.to_seed("");

    // Derive key pair.
    let keypair = generate_canton_keypair(&seed, CANTON_DERIVATION_PATH, algorithm)?;

    // Build party ID from name and fingerprint.
    let party_id = format!("{}::{}", name, keypair.fingerprint);
    let chain_id_str = chain_id.to_caip2();
    let account_id = format!("{chain_id_str}:{party_id}");

    let account = CantonAccountEntry {
        account_id,
        address: party_id.clone(),
        chain_id: chain_id_str.clone(),
        derivation_path: CANTON_DERIVATION_PATH.to_string(),
        canton: CantonAccountMetadata {
            party_id,
            key_fingerprint: keypair.fingerprint.clone(),
            key_format: "DER".to_string(),
            signing_algorithm: keypair.signing_algorithm.to_string(),
            party_type: CantonPartyType::External,
            topology_registered: false,
            participant_host: participant_url.to_string(),
            synchronizer_id: None,
        },
    };

    // Encrypt mnemonic entropy.
    let crypto = encrypt_entropy(&entropy, passphrase)?;

    let wallet = CantonWalletFile {
        ows_version: 2,
        id: wallet_id,
        name: name.to_string(),
        created_at: now,
        chain_type: "canton".to_string(),
        accounts: vec![account],
        crypto,
        key_type: KeyType::Mnemonic,
        canton_config: Some(CantonConfig {
            default_synchronizer: chain_id_str,
            participant_url: participant_url.to_string(),
            auth_token_path: None,
            simulation_required: true,
        }),
        metadata: serde_json::Value::Object(serde_json::Map::new()),
    };

    // Write to disk.
    let wallets_dir = ows_home.join("wallets");
    fs::create_dir_all(&wallets_dir)?;

    let wallet_path = wallets_dir.join(format!("{}.json", wallet.id));
    let json = serde_json::to_string_pretty(&wallet)?;
    fs::write(&wallet_path, &json)?;

    // Set file permissions to 0600 (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&wallet_path, perms)?;
    }

    Ok(wallet)
}

/// Load a wallet from the given base directory.
pub fn load_canton_wallet_in(
    ows_home: &Path,
    wallet_id_or_name: &str,
) -> Result<CantonWalletFile, CantonError> {
    let wallets_dir = ows_home.join("wallets");

    // Try loading by UUID first.
    let by_id = wallets_dir.join(format!("{wallet_id_or_name}.json"));
    if by_id.exists() {
        let json = fs::read_to_string(&by_id)?;
        let wallet: CantonWalletFile = serde_json::from_str(&json)?;
        validate_wallet_file(&wallet)?;
        return Ok(wallet);
    }

    // Scan by name.
    if wallets_dir.is_dir() {
        for entry in fs::read_dir(&wallets_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let json = fs::read_to_string(&path)?;
                if let Ok(wallet) = serde_json::from_str::<CantonWalletFile>(&json) {
                    if wallet.name == wallet_id_or_name {
                        validate_wallet_file(&wallet)?;
                        return Ok(wallet);
                    }
                }
            }
        }
    }

    Err(CantonError::WalletNotFound {
        wallet_id: wallet_id_or_name.to_string(),
    })
}

/// List Canton wallets from the given base directory.
pub fn list_canton_wallets_in(
    ows_home: &Path,
) -> Result<Vec<CantonWalletFile>, CantonError> {
    let wallets_dir = ows_home.join("wallets");
    if !wallets_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut wallets = Vec::new();
    for entry in fs::read_dir(&wallets_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let json = fs::read_to_string(&path)?;
            if let Ok(wallet) = serde_json::from_str::<CantonWalletFile>(&json) {
                if wallet.chain_type == "canton" {
                    wallets.push(wallet);
                }
            }
        }
    }
    Ok(wallets)
}

// ── Encryption / Decryption ────────────────────────────────────────

/// Encrypt mnemonic entropy bytes with AES-256-GCM + scrypt.
fn encrypt_entropy(entropy: &[u8], passphrase: &str) -> Result<CryptoEnvelope, CantonError> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut iv = [0u8; AES_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut iv);

    // Derive encryption key with scrypt.
    let derived_key = derive_key_scrypt(passphrase.as_bytes(), &salt)?;

    // Encrypt with AES-256-GCM.
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|e| CantonError::EncryptionFailed {
            reason: e.to_string(),
        })?;
    let nonce = Nonce::from_slice(&iv);
    let encrypted = cipher
        .encrypt(nonce, entropy)
        .map_err(|e| CantonError::EncryptionFailed {
            reason: e.to_string(),
        })?;

    // Split ciphertext and auth tag.
    let tag_start = encrypted.len() - AES_TAG_LEN;
    let ciphertext = &encrypted[..tag_start];
    let auth_tag = &encrypted[tag_start..];

    let kdfparams = ScryptKdfParams {
        dklen: SCRYPT_DKLEN as u32,
        n: 1 << SCRYPT_LOG_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: hex::encode(salt),
    };

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm".to_string(),
        cipherparams: CipherParams {
            iv: hex::encode(iv),
        },
        ciphertext: hex::encode(ciphertext),
        auth_tag: hex::encode(auth_tag),
        kdf: "scrypt".to_string(),
        kdfparams: serde_json::to_value(kdfparams)?,
    })
}

/// Decrypt mnemonic entropy from a CryptoEnvelope.
fn decrypt_wallet_crypto(
    crypto: &CryptoEnvelope,
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, CantonError> {
    let kdfparams: ScryptKdfParams =
        serde_json::from_value(crypto.kdfparams.clone()).map_err(|e| {
            CantonError::InvalidWalletFile {
                reason: format!("invalid kdfparams: {e}"),
            }
        })?;

    let salt = hex::decode(&kdfparams.salt).map_err(|e| CantonError::InvalidWalletFile {
        reason: format!("invalid salt hex: {e}"),
    })?;
    let iv = hex::decode(&crypto.cipherparams.iv).map_err(|e| CantonError::InvalidWalletFile {
        reason: format!("invalid iv hex: {e}"),
    })?;
    let ciphertext =
        hex::decode(&crypto.ciphertext).map_err(|e| CantonError::InvalidWalletFile {
            reason: format!("invalid ciphertext hex: {e}"),
        })?;
    let auth_tag = hex::decode(&crypto.auth_tag).map_err(|e| CantonError::InvalidWalletFile {
        reason: format!("invalid auth_tag hex: {e}"),
    })?;

    // Derive key with scrypt.
    let derived_key = derive_key_scrypt(passphrase.as_bytes(), &salt)?;

    // Reassemble ciphertext + tag for AES-GCM.
    let mut payload = Vec::with_capacity(ciphertext.len() + auth_tag.len());
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&auth_tag);

    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CantonError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&iv);
    let decrypted = cipher
        .decrypt(nonce, payload.as_ref())
        .map_err(|_| CantonError::DecryptionFailed)?;

    Ok(Zeroizing::new(decrypted))
}

/// Derive a 32-byte key using scrypt.
fn derive_key_scrypt(password: &[u8], salt: &[u8]) -> Result<[u8; 32], CantonError> {
    let params =
        scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN).map_err(|e| {
            CantonError::EncryptionFailed {
                reason: format!("invalid scrypt params: {e}"),
            }
        })?;
    let mut dk = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut dk).map_err(|e| {
        CantonError::EncryptionFailed {
            reason: format!("scrypt failed: {e}"),
        }
    })?;
    Ok(dk)
}

/// Rewrite a wallet file to disk (used after metadata updates like onboarding).
pub(crate) fn save_wallet_in(
    ows_home: &Path,
    wallet: &CantonWalletFile,
) -> Result<(), CantonError> {
    let wallets_dir = ows_home.join("wallets");
    fs::create_dir_all(&wallets_dir)?;

    let wallet_path = wallets_dir.join(format!("{}.json", wallet.id));
    let json = serde_json::to_string_pretty(wallet)?;
    fs::write(&wallet_path, &json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&wallet_path, perms)?;
    }

    Ok(())
}

// ── Validation helpers ─────────────────────────────────────────────

/// Validate passphrase meets minimum length requirement.
fn validate_passphrase(passphrase: &str) -> Result<(), CantonError> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(CantonError::PassphraseTooShort);
    }
    Ok(())
}

/// Validate wallet file structure.
fn validate_wallet_file(wallet: &CantonWalletFile) -> Result<(), CantonError> {
    if wallet.ows_version != 2 {
        return Err(CantonError::InvalidWalletFile {
            reason: format!("unsupported ows_version: {}", wallet.ows_version),
        });
    }
    if wallet.chain_type != "canton" {
        return Err(CantonError::InvalidWalletFile {
            reason: format!(
                "expected chain_type \"canton\", got \"{}\"",
                wallet.chain_type
            ),
        });
    }
    Ok(())
}

/// Resolve the OWS home directory from environment or default.
fn get_ows_home() -> Result<PathBuf, CantonError> {
    if let Ok(home) = std::env::var("OWS_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = std::env::var("HOME").map_err(|_| CantonError::IoError {
        reason: "HOME environment variable not set".to_string(),
    })?;
    Ok(PathBuf::from(home).join(".ows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain_id() -> CantonChainId {
        CantonChainId::parse(CantonChainId::SANDBOX).unwrap()
    }

    const GOOD_PASSPHRASE: &str = "super-secret-passphrase-12345";
    const SHORT_PASSPHRASE: &str = "short";

    #[test]
    fn test_create_wallet_valid() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "test-wallet",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        assert_eq!(wallet.ows_version, 2);
        assert_eq!(wallet.chain_type, "canton");
        assert_eq!(wallet.name, "test-wallet");
        assert_eq!(wallet.key_type, KeyType::Mnemonic);
        assert!(!wallet.accounts.is_empty());

        // Verify file exists on disk.
        let file_path = tmpdir
            .path()
            .join("wallets")
            .join(format!("{}.json", wallet.id));
        assert!(file_path.exists());

        // Verify JSON is valid.
        let json = fs::read_to_string(&file_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ows_version"], 2);
        assert_eq!(parsed["chain_type"], "canton");
    }

    #[test]
    fn test_create_wallet_short_pass() {
        let tmpdir = tempfile::tempdir().unwrap();
        let err = create_canton_wallet_in(
            tmpdir.path(),
            "test-wallet",
            SHORT_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap_err();

        assert!(matches!(err, CantonError::PassphraseTooShort));
    }

    #[test]
    fn test_load_wallet_by_id() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "by-id-wallet",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let loaded = load_canton_wallet_in(tmpdir.path(), &wallet.id).unwrap();
        assert_eq!(loaded.id, wallet.id);
        assert_eq!(loaded.name, wallet.name);
    }

    #[test]
    fn test_load_wallet_by_name() {
        let tmpdir = tempfile::tempdir().unwrap();
        create_canton_wallet_in(
            tmpdir.path(),
            "named-wallet",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let loaded = load_canton_wallet_in(tmpdir.path(), "named-wallet").unwrap();
        assert_eq!(loaded.name, "named-wallet");
    }

    #[test]
    fn test_load_wallet_not_found() {
        let tmpdir = tempfile::tempdir().unwrap();
        let err = load_canton_wallet_in(tmpdir.path(), "nonexistent").unwrap_err();
        assert!(matches!(err, CantonError::WalletNotFound { .. }));
    }

    #[test]
    fn test_decrypt_wallet_correct_pass() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "decrypt-test",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let entropy = decrypt_canton_wallet(&wallet, GOOD_PASSPHRASE).unwrap();
        // 24-word mnemonic = 256-bit = 32-byte entropy.
        assert_eq!(entropy.len(), 32);
        // Should reconstruct a valid mnemonic.
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn test_decrypt_wallet_wrong_pass() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "wrong-pass-test",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let err = decrypt_canton_wallet(&wallet, "wrong-passphrase!").unwrap_err();
        assert!(matches!(err, CantonError::DecryptionFailed));
    }

    #[test]
    fn test_wallet_roundtrip() {
        let tmpdir = tempfile::tempdir().unwrap();

        // Create.
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "roundtrip-test",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        // Load.
        let loaded = load_canton_wallet_in(tmpdir.path(), &wallet.id).unwrap();
        assert_eq!(loaded.id, wallet.id);

        // Decrypt and reconstruct mnemonic.
        let entropy = decrypt_canton_wallet(&loaded, GOOD_PASSPHRASE).unwrap();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();

        // Derive key pair from recovered mnemonic.
        let seed = mnemonic.to_seed("");
        let keypair = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        // Fingerprint must match what was stored.
        assert_eq!(
            keypair.fingerprint,
            loaded.accounts[0].canton.key_fingerprint
        );
    }

    #[test]
    fn test_wallet_json_schema() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "schema-test",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let json: serde_json::Value = serde_json::to_value(&wallet).unwrap();
        assert_eq!(json["ows_version"], 2);
        assert_eq!(json["chain_type"], "canton");
        assert_eq!(json["key_type"], "mnemonic");
        assert!(json["id"].is_string());
        assert!(json["created_at"].is_string());
        assert!(json["accounts"].is_array());
        assert!(json["crypto"].is_object());
        assert_eq!(json["crypto"]["cipher"], "aes-256-gcm");
        assert_eq!(json["crypto"]["kdf"], "scrypt");
        assert!(json["crypto"]["cipherparams"]["iv"].is_string());
        assert!(json["crypto"]["ciphertext"].is_string());
        assert!(json["crypto"]["auth_tag"].is_string());
        assert!(json["canton_config"].is_object());
    }

    #[cfg(unix)]
    #[test]
    fn test_wallet_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "perms-test",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let file_path = tmpdir
            .path()
            .join("wallets")
            .join(format!("{}.json", wallet.id));
        let metadata = fs::metadata(&file_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "wallet file must have 0600 permissions");
    }

    #[test]
    fn test_list_canton_wallets() {
        let tmpdir = tempfile::tempdir().unwrap();

        // Create 2 Canton wallets.
        create_canton_wallet_in(
            tmpdir.path(),
            "list-wallet-1",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();
        create_canton_wallet_in(
            tmpdir.path(),
            "list-wallet-2",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        // Write a non-Canton wallet file.
        let wallets_dir = tmpdir.path().join("wallets");
        let evm_wallet = serde_json::json!({
            "ows_version": 2,
            "id": "evm-wallet-id",
            "name": "evm-wallet",
            "created_at": "2026-01-01T00:00:00Z",
            "chain_type": "evm",
            "accounts": [],
            "crypto": {},
            "key_type": "mnemonic",
            "metadata": {}
        });
        fs::write(
            wallets_dir.join("evm-wallet-id.json"),
            serde_json::to_string_pretty(&evm_wallet).unwrap(),
        )
        .unwrap();

        let wallets = list_canton_wallets_in(tmpdir.path()).unwrap();
        assert_eq!(wallets.len(), 2, "should only return Canton wallets");
    }

    #[test]
    fn test_canton_metadata_complete() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallet = create_canton_wallet_in(
            tmpdir.path(),
            "meta-test",
            GOOD_PASSPHRASE,
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let account = &wallet.accounts[0];
        let meta = &account.canton;

        assert!(!meta.party_id.is_empty());
        assert!(meta.key_fingerprint.starts_with("1220"));
        assert_eq!(meta.key_format, "DER");
        assert_eq!(meta.signing_algorithm, "SIGNING_ALGORITHM_SPEC_ED25519");
        assert_eq!(meta.party_type, CantonPartyType::External);
        assert!(!meta.topology_registered);
        assert_eq!(meta.participant_host, "http://localhost:7575");

        // Account ID should be a valid CAIP-10.
        assert!(account.account_id.starts_with("canton:sandbox:"));
        assert_eq!(account.chain_id, "canton:sandbox");
        assert_eq!(account.derivation_path, CANTON_DERIVATION_PATH);
    }

    #[test]
    fn test_list_empty_dir() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wallets = list_canton_wallets_in(tmpdir.path()).unwrap();
        assert!(wallets.is_empty());
    }

    #[test]
    fn test_passphrase_exactly_12() {
        let tmpdir = tempfile::tempdir().unwrap();
        // Exactly 12 chars should be accepted.
        let result = create_canton_wallet_in(
            tmpdir.path(),
            "min-pass",
            "123456789012",
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_passphrase_11_chars() {
        let tmpdir = tempfile::tempdir().unwrap();
        let err = create_canton_wallet_in(
            tmpdir.path(),
            "short-pass",
            "12345678901",
            &test_chain_id(),
            "http://localhost:7575",
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(err, CantonError::PassphraseTooShort));
    }
}
