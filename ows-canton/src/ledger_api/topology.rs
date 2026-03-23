//! Topology transaction API helpers for Canton participant nodes.
//!
//! Handles generation and submission of topology transactions required for
//! External Party registration, including namespace delegation and party-to-key
//! mapping transactions.

use base64::Engine;

use crate::keygen::CantonSigningAlgorithm;
use crate::signing::CantonSignature;

use super::types::{AllocatePartyRequest, MultiHashSignatureRequest};

/// Build an [`AllocatePartyRequest`] from topology transactions and signatures.
pub fn build_allocate_request(
    synchronizer: &str,
    transactions: &[String],
    signatures: &[CantonSignature],
) -> AllocatePartyRequest {
    let multi_hash_signatures = signatures
        .iter()
        .map(|sig| MultiHashSignatureRequest {
            format: sig.format.clone(),
            signature: sig.signature.clone(),
            signed_by: sig.signed_by.clone(),
            signing_algorithm_spec: sig.algorithm.clone(),
        })
        .collect();

    AllocatePartyRequest {
        synchronizer: synchronizer.to_string(),
        onboarding_transactions: transactions.to_vec(),
        multi_hash_signatures,
    }
}

/// Decode a base64-encoded topology transaction for signing.
pub fn decode_topology_transaction(base64_tx: &str) -> Result<Vec<u8>, crate::CantonError> {
    base64::engine::general_purpose::STANDARD
        .decode(base64_tx)
        .map_err(|e| crate::CantonError::OnboardingFailed {
            reason: format!("invalid base64 topology transaction: {e}"),
        })
}

/// Build a [`MultiHashSignatureRequest`] from raw signature bytes.
pub fn build_signature_request(
    signature_bytes: &[u8],
    fingerprint: &str,
    algorithm: &CantonSigningAlgorithm,
) -> MultiHashSignatureRequest {
    MultiHashSignatureRequest {
        format: "SIGNATURE_FORMAT_CONCAT".to_string(),
        signature: base64::engine::general_purpose::STANDARD.encode(signature_bytes),
        signed_by: fingerprint.to_string(),
        signing_algorithm_spec: algorithm.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_allocate_request() {
        let sig = CantonSignature {
            signature: "c2ln".to_string(),
            signed_by: "1220abcd".to_string(),
            format: "SIGNATURE_FORMAT_CONCAT".to_string(),
            algorithm: "SIGNING_ALGORITHM_SPEC_ED25519".to_string(),
        };

        let req = build_allocate_request(
            "canton::sync1",
            &["dHgx".to_string(), "dHgy".to_string()],
            &[sig],
        );

        assert_eq!(req.synchronizer, "canton::sync1");
        assert_eq!(req.onboarding_transactions.len(), 2);
        assert_eq!(req.multi_hash_signatures.len(), 1);
        assert_eq!(req.multi_hash_signatures[0].signed_by, "1220abcd");
    }

    #[test]
    fn test_decode_topology_transaction() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"hello topology");
        let decoded = decode_topology_transaction(&b64).unwrap();
        assert_eq!(decoded, b"hello topology");
    }

    #[test]
    fn test_decode_invalid_base64() {
        let err = decode_topology_transaction("not-valid-base64!!!").unwrap_err();
        assert!(matches!(err, crate::CantonError::OnboardingFailed { .. }));
    }

    #[test]
    fn test_build_signature_request() {
        let sig =
            build_signature_request(&[0xAA; 64], "1220abcdef", &CantonSigningAlgorithm::Ed25519);

        assert_eq!(sig.format, "SIGNATURE_FORMAT_CONCAT");
        assert_eq!(sig.signed_by, "1220abcdef");
        assert_eq!(sig.signing_algorithm_spec, "SIGNING_ALGORITHM_SPEC_ED25519");
        assert!(!sig.signature.is_empty());
    }
}
