# Spec 02 — Key Management

## Supported Schemes

| Scheme | Curve | Key Size | OWS Status | Canton Default | Feature Flag |
|--------|-------|----------|------------|----------------|--------------|
| Ed25519 | Curve25519 | 32 bytes | Reuse from Solana/TON | Yes (default) | `ed25519` (default) |
| ECDSA secp256k1 | secp256k1 | 32 bytes | Reuse from EVM/BTC | Supported | `secp256k1` (optional) |

## HD Derivation Path

```
m / 44' / 9999' / account' / change / index

Purpose:    44' (BIP-44)
Coin type:  9999' (Canton — unregistered, pending SLIP-0044 submission)
Account:    0' (default, increment for multi-account)
Change:     0 (Canton doesn't use change addresses)
Index:      0 (increment for sub-keys)
```

### SLIP-0010 for Ed25519

Ed25519 keys CANNOT use standard BIP-32 derivation. Use SLIP-0010 (Ed25519 variant):

```rust
use slip10_ed25519::derive_ed25519_private_key;

pub fn derive_canton_ed25519(mnemonic_seed: &[u8; 64], index: u32) -> Result<[u8; 32], CantonError> {
    let path = format!("m/44'/9999'/0'/0/{}", index);
    let private_key = derive_ed25519_private_key(mnemonic_seed, &path);
    Ok(private_key)
}
```

### secp256k1 Derivation (Optional)

For secp256k1, use standard BIP-32 derivation with the same path. This is the same mechanism used by EVM chains.

## Key Generation Flow

```rust
pub struct CantonKeyPair {
    /// Raw private key bytes (32 bytes). MUST be zeroized after use.
    pub private_key: zeroize::Zeroizing<[u8; 32]>,
    /// Raw public key bytes (32 bytes for Ed25519, 33 bytes compressed for secp256k1)
    pub public_key: Vec<u8>,
    /// DER-encoded SubjectPublicKeyInfo
    pub public_key_der: Vec<u8>,
    /// Hex-encoded fingerprint: SHA-256(public_key_der)[0..20]
    pub fingerprint: String,
    /// Signing algorithm spec string for Canton API
    pub signing_algorithm: CantonSigningAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CantonSigningAlgorithm {
    #[serde(rename = "SIGNING_ALGORITHM_SPEC_ED25519")]
    Ed25519,
    #[serde(rename = "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256")]
    EcDsaSha256,
}
```

### Generation Steps

```
1. Input: mnemonic_entropy (from BIP-39 generation or existing wallet)

2. Derive seed:
   seed = bip39::mnemonic_to_seed(mnemonic, "") // empty passphrase

3. Derive private key:
   IF Ed25519:
     privkey = slip10_ed25519::derive(seed, "m/44'/9999'/0'/0/0")
     pubkey = ed25519_dalek::SigningKey::from_bytes(&privkey).verifying_key()
   IF secp256k1:
     privkey = bip32::derive(seed, "m/44'/9999'/0'/0/0")
     pubkey = k256::SecretKey::from_bytes(&privkey).public_key()

4. Encode public key as DER:
   pubkey_der = spki::encode_public_key(pubkey, algorithm_oid)
   // For Ed25519: OID 1.3.101.112
   // For secp256k1: OID 1.2.840.10045.2.1 with curve OID 1.3.132.0.10

5. Compute fingerprint:
   fingerprint = hex::encode(sha256(pubkey_der))[0..40]
   // 20 bytes = 40 hex chars, matching Canton's convention

6. Return CantonKeyPair { privkey, pubkey, pubkey_der, fingerprint, algorithm }
```

## DER Encoding

Canton expects public keys in X.509 SubjectPublicKeyInfo (SPKI) format:

```
SubjectPublicKeyInfo ::= SEQUENCE {
  algorithm AlgorithmIdentifier,
  subjectPublicKey BIT STRING
}
```

### Ed25519 SPKI

```
SEQUENCE {
  SEQUENCE {
    OID 1.3.101.112  (id-EdDSA / Ed25519)
  }
  BIT STRING (contains 32-byte Ed25519 public key)
}
```

Hex prefix for Ed25519 SPKI: `302a300506032b6570032100` + 32 bytes pubkey

### Rust Implementation

```rust
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use der::Encode;

pub fn encode_ed25519_spki(pubkey_bytes: &[u8; 32]) -> Result<Vec<u8>, CantonError> {
    // Ed25519 OID: 1.3.101.112
    let algorithm = AlgorithmIdentifierRef {
        oid: const_oid::db::rfc8410::ID_ED_25519,
        parameters: None,
    };
    let spki = SubjectPublicKeyInfoRef {
        algorithm,
        subject_public_key: BitStringRef::new(0, pubkey_bytes)?,
    };
    Ok(spki.to_der()?)
}
```

## Fingerprint Computation

Canton identifies keys by their fingerprint, which is a truncated SHA-256 hash of the DER-encoded public key.

```rust
pub fn compute_fingerprint(pubkey_der: &[u8]) -> String {
    let hash = sha2::Sha256::digest(pubkey_der);
    // Canton uses "1220" prefix (multihash: 0x12 = SHA-256, 0x20 = 32 bytes)
    // followed by truncated hash
    format!("1220{}", hex::encode(&hash[..18]))
}
```

**Note:** The exact fingerprint format depends on the Canton version. Check the actual fingerprint returned by `/v2/parties/external/generate-topology` and match that format. The `1220` prefix is the multihash identifier for SHA-256.

## Memory Safety

```rust
use zeroize::Zeroize;

// All private key material MUST use Zeroizing wrapper
let private_key: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(derived_key);

// After signing, explicitly zeroize
let mut seed = mnemonic_to_seed(&mnemonic);
// ... use seed to derive key ...
seed.zeroize();

// CantonKeyPair implements Drop with zeroize
impl Drop for CantonKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
```

## Unit Tests Required

```
test_ed25519_keygen                → generate key pair, verify pubkey length == 32
test_ed25519_deterministic         → same mnemonic + path → same keypair
test_ed25519_different_index       → index 0 ≠ index 1
test_ed25519_spki_encoding         → DER output starts with 302a300506032b6570032100
test_ed25519_spki_length           → DER output is exactly 44 bytes
test_fingerprint_format            → starts with "1220", is hex, expected length
test_fingerprint_deterministic     → same pubkey → same fingerprint
test_sign_verify_roundtrip         → sign message, verify with pubkey → true
test_sign_different_key            → sign with key A, verify with key B → false
test_zeroize_on_drop               → after drop, memory should be zeroed (hard to test, but verify Drop impl exists)
test_secp256k1_keygen              → (feature-gated) generate secp256k1 keypair
test_secp256k1_spki_encoding       → (feature-gated) valid DER encoding
```
