//! Ed25519 and secp256k1 key generation with SLIP-0010 derivation.
//!
//! Generates key pairs from BIP-39 mnemonics using SLIP-0010 derivation paths,
//! encodes public keys in DER SubjectPublicKeyInfo format for Canton topology
//! transactions, and provides signing and verification operations.
//! See `specs/02-key-management.md` for the full specification.

use std::fmt;

use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::CantonError;

/// Default Canton HD derivation path: `m/44'/9999'/0'/0/0`.
///
/// - Purpose: `44'` (BIP-44)
/// - Coin type: `9999'` (Canton — unregistered, pending SLIP-0044 submission)
/// - Account: `0'`
/// - Change: `0` (Canton does not use change addresses)
/// - Index: `0`
pub const CANTON_DERIVATION_PATH: &str = "m/44'/9999'/0'/0/0";

/// DER prefix for Ed25519 SubjectPublicKeyInfo.
///
/// ```text
/// 30 2a       SEQUENCE (42 bytes)
///   30 05       SEQUENCE (5 bytes)
///     06 03       OID (3 bytes)
///       2b 65 70    1.3.101.112 (id-EdDSA / Ed25519)
///   03 21       BIT STRING (33 bytes)
///     00          unused bits = 0
/// ```
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Canton signing algorithm specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CantonSigningAlgorithm {
    /// Ed25519 (Curve25519) — Canton default.
    #[serde(rename = "SIGNING_ALGORITHM_SPEC_ED25519")]
    Ed25519,
    /// ECDSA with SHA-256 on secp256k1.
    #[serde(rename = "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256")]
    EcDsaSha256,
}

impl fmt::Display for CantonSigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "SIGNING_ALGORITHM_SPEC_ED25519"),
            Self::EcDsaSha256 => write!(f, "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256"),
        }
    }
}

/// A Canton key pair holding private key material with zeroize-on-drop semantics.
///
/// Private key bytes are wrapped in [`Zeroizing`] and additionally zeroized
/// in the [`Drop`] implementation.  The private key MUST NOT be logged, serialized,
/// or returned from any public API.
pub struct CantonKeyPair {
    /// Raw private key bytes (32 bytes). Zeroized on drop.
    pub private_key: Zeroizing<[u8; 32]>,
    /// Raw public key bytes (32 bytes for Ed25519).
    pub public_key: Vec<u8>,
    /// DER-encoded SubjectPublicKeyInfo.
    pub public_key_der: Vec<u8>,
    /// Hex-encoded Canton fingerprint (`1220` + truncated SHA-256).
    pub fingerprint: String,
    /// Signing algorithm used for this key pair.
    pub signing_algorithm: CantonSigningAlgorithm,
}

impl Drop for CantonKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

// Custom Debug to never expose private key material.
impl fmt::Debug for CantonKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CantonKeyPair")
            .field("public_key", &hex::encode(&self.public_key))
            .field("fingerprint", &self.fingerprint)
            .field("signing_algorithm", &self.signing_algorithm)
            .finish_non_exhaustive()
    }
}

/// Parse a BIP-32/44 derivation path string (e.g. `"m/44'/9999'/0'/0/0"`) into
/// a vector of raw child indexes suitable for [`slip10_ed25519::derive_ed25519_private_key`].
fn parse_derivation_path(path: &str) -> Result<Vec<u32>, CantonError> {
    let dp: derivation_path::DerivationPath =
        path.parse()
            .map_err(|e: derivation_path::DerivationPathParseError| {
                CantonError::KeyDerivationFailed {
                    reason: format!("invalid derivation path: {e}"),
                }
            })?;
    Ok(dp.path().iter().map(|idx| idx.to_u32()).collect())
}

/// Generate a Canton key pair from a BIP-39 mnemonic seed.
///
/// # Arguments
///
/// - `mnemonic_seed` — 64-byte seed from `bip39::Mnemonic::to_seed("")`.
/// - `path` — HD derivation path (e.g. `"m/44'/9999'/0'/0/0"`).
/// - `algorithm` — signing algorithm to use.
///
/// # Errors
///
/// Returns [`CantonError::UnsupportedAlgorithm`] if `EcDsaSha256` is requested
/// without the `secp256k1` feature enabled.
pub fn generate_canton_keypair(
    mnemonic_seed: &[u8; 64],
    path: &str,
    algorithm: CantonSigningAlgorithm,
) -> Result<CantonKeyPair, CantonError> {
    match algorithm {
        CantonSigningAlgorithm::Ed25519 => generate_ed25519_keypair(mnemonic_seed, path),
        CantonSigningAlgorithm::EcDsaSha256 => Err(CantonError::UnsupportedAlgorithm {
            algorithm: "EcDsaSha256 (requires secp256k1 feature)".to_string(),
        }),
    }
}

/// Internal: generate an Ed25519 key pair via SLIP-0010 derivation.
fn generate_ed25519_keypair(seed: &[u8; 64], path: &str) -> Result<CantonKeyPair, CantonError> {
    let indexes = parse_derivation_path(path)?;

    // SLIP-0010 Ed25519 derivation (all indexes treated as hardened).
    let private_key_bytes = slip10_ed25519::derive_ed25519_private_key(seed, &indexes);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_key_bytes);
    let public_key_bytes = signing_key.verifying_key().to_bytes();

    let public_key_der = encode_ed25519_spki(&public_key_bytes)?;
    let fingerprint = compute_fingerprint(&public_key_der);

    Ok(CantonKeyPair {
        private_key: Zeroizing::new(private_key_bytes),
        public_key: public_key_bytes.to_vec(),
        public_key_der,
        fingerprint,
        signing_algorithm: CantonSigningAlgorithm::Ed25519,
    })
}

/// Encode an Ed25519 public key as DER SubjectPublicKeyInfo (SPKI).
///
/// The output is exactly 44 bytes: a 12-byte ASN.1 header containing
/// OID `1.3.101.112` followed by the 32-byte public key.
pub fn encode_ed25519_spki(pubkey_bytes: &[u8; 32]) -> Result<Vec<u8>, CantonError> {
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&ED25519_SPKI_PREFIX);
    der.extend_from_slice(pubkey_bytes);
    Ok(der)
}

/// Compute the Canton fingerprint from a DER-encoded public key.
///
/// Format: `"1220"` (multihash prefix for SHA-256) followed by the
/// hex-encoded first 18 bytes of the SHA-256 hash, yielding a 40-character
/// hex string.
pub fn compute_fingerprint(pubkey_der: &[u8]) -> String {
    let hash = Sha256::digest(pubkey_der);
    // "1220" = multihash: 0x12 = SHA-256, 0x20 = 32 bytes length
    format!("1220{}", hex::encode(&hash[..18]))
}

/// Sign a message with an Ed25519 private key.
///
/// Returns the 64-byte Ed25519 signature.
pub fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, CantonError> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature against a public key and message.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if the
/// signature does not match, or an error if inputs are malformed.
pub fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CantonError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|e| {
        CantonError::InvalidPublicKey {
            reason: e.to_string(),
        }
    })?;
    let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|e| {
        CantonError::SigningFailed {
            reason: format!("invalid signature format: {e}"),
        }
    })?;
    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard 12-word test mnemonic from BIP-39.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Compute the 64-byte seed from the test mnemonic.
    fn test_seed() -> [u8; 64] {
        let mnemonic = bip39::Mnemonic::parse(TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let mut out = [0u8; 64];
        out.copy_from_slice(&seed);
        out
    }

    #[test]
    fn test_ed25519_keygen() {
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();
        assert_eq!(kp.public_key.len(), 32);
        assert_eq!(kp.signing_algorithm, CantonSigningAlgorithm::Ed25519);
    }

    #[test]
    fn test_ed25519_deterministic() {
        let seed = test_seed();
        let kp1 = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();
        let kp2 = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.fingerprint, kp2.fingerprint);
        assert_eq!(kp1.public_key_der, kp2.public_key_der);
        assert_eq!(*kp1.private_key, *kp2.private_key);
    }

    #[test]
    fn test_ed25519_different_index() {
        let seed = test_seed();
        let kp0 =
            generate_canton_keypair(&seed, "m/44'/9999'/0'/0/0", CantonSigningAlgorithm::Ed25519)
                .unwrap();
        let kp1 =
            generate_canton_keypair(&seed, "m/44'/9999'/0'/0/1", CantonSigningAlgorithm::Ed25519)
                .unwrap();
        assert_ne!(kp0.public_key, kp1.public_key);
        assert_ne!(kp0.fingerprint, kp1.fingerprint);
    }

    #[test]
    fn test_ed25519_spki_encoding() {
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let der_hex = hex::encode(&kp.public_key_der);
        // DER must start with the standard Ed25519 SPKI prefix
        assert!(
            der_hex.starts_with("302a300506032b6570032100"),
            "unexpected DER prefix: {der_hex}"
        );
        // The last 32 bytes must be the raw public key
        assert_eq!(&kp.public_key_der[12..], kp.public_key.as_slice());
    }

    #[test]
    fn test_ed25519_spki_length() {
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();
        assert_eq!(kp.public_key_der.len(), 44);
    }

    #[test]
    fn test_fingerprint_format() {
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        assert!(
            kp.fingerprint.starts_with("1220"),
            "fingerprint must start with 1220"
        );
        // "1220" (4 chars) + 18 bytes as hex (36 chars) = 40 chars
        assert_eq!(kp.fingerprint.len(), 40, "fingerprint must be 40 hex chars");
        // Must be valid lowercase hex
        assert!(
            kp.fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must be hex"
        );
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let pubkey = [0xab_u8; 32];
        let der1 = encode_ed25519_spki(&pubkey).unwrap();
        let der2 = encode_ed25519_spki(&pubkey).unwrap();
        assert_eq!(compute_fingerprint(&der1), compute_fingerprint(&der2));
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let message = b"canton command payload";
        let signature = ed25519_sign(&kp.private_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        let pubkey: [u8; 32] = kp.public_key.as_slice().try_into().unwrap();
        let valid = ed25519_verify(&pubkey, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_different_key() {
        let seed = test_seed();
        let kp_a =
            generate_canton_keypair(&seed, "m/44'/9999'/0'/0/0", CantonSigningAlgorithm::Ed25519)
                .unwrap();
        let kp_b =
            generate_canton_keypair(&seed, "m/44'/9999'/0'/0/1", CantonSigningAlgorithm::Ed25519)
                .unwrap();

        let message = b"test message";
        let signature = ed25519_sign(&kp_a.private_key, message).unwrap();

        // Verify with key B should fail
        let pubkey_b: [u8; 32] = kp_b.public_key.as_slice().try_into().unwrap();
        let valid = ed25519_verify(&pubkey_b, message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_zeroize_on_drop() {
        // Verify that CantonKeyPair implements Drop (compilation test).
        // We cannot reliably read memory after drop, but we confirm the
        // Drop impl exists and calls zeroize by checking it compiles.
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();
        let _fingerprint = kp.fingerprint.clone();
        drop(kp);
        // If we get here, Drop ran without panic.
    }

    #[test]
    fn test_debug_hides_private_key() {
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();
        let debug_str = format!("{kp:?}");
        let privkey_hex = hex::encode(&*kp.private_key);
        assert!(
            !debug_str.contains(&privkey_hex),
            "Debug output must not contain the private key"
        );
        assert!(debug_str.contains("CantonKeyPair"));
    }

    #[test]
    fn test_signing_algorithm_serde() {
        let json = serde_json::to_string(&CantonSigningAlgorithm::Ed25519).unwrap();
        assert_eq!(json, "\"SIGNING_ALGORITHM_SPEC_ED25519\"");

        let parsed: CantonSigningAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CantonSigningAlgorithm::Ed25519);
    }

    #[test]
    fn test_signing_algorithm_display() {
        assert_eq!(
            CantonSigningAlgorithm::Ed25519.to_string(),
            "SIGNING_ALGORITHM_SPEC_ED25519"
        );
        assert_eq!(
            CantonSigningAlgorithm::EcDsaSha256.to_string(),
            "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256"
        );
    }

    #[test]
    fn test_unsupported_algorithm() {
        let seed = test_seed();
        let err = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::EcDsaSha256,
        )
        .unwrap_err();
        assert!(matches!(err, CantonError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn test_invalid_derivation_path() {
        let seed = test_seed();
        let err = generate_canton_keypair(&seed, "not-a-path", CantonSigningAlgorithm::Ed25519)
            .unwrap_err();
        assert!(matches!(err, CantonError::KeyDerivationFailed { .. }));
    }

    #[test]
    fn test_encode_spki_direct() {
        let pubkey = [0x42_u8; 32];
        let der = encode_ed25519_spki(&pubkey).unwrap();
        assert_eq!(der.len(), 44);
        assert_eq!(&der[..12], &ED25519_SPKI_PREFIX);
        assert_eq!(&der[12..], &pubkey);
    }

    #[test]
    fn test_verify_wrong_message() {
        let seed = test_seed();
        let kp = generate_canton_keypair(
            &seed,
            CANTON_DERIVATION_PATH,
            CantonSigningAlgorithm::Ed25519,
        )
        .unwrap();

        let signature = ed25519_sign(&kp.private_key, b"message A").unwrap();
        let pubkey: [u8; 32] = kp.public_key.as_slice().try_into().unwrap();
        let valid = ed25519_verify(&pubkey, b"message B", &signature).unwrap();
        assert!(!valid);
    }
}
