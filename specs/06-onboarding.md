# Spec 06 — External Party Onboarding

## Overview

When a user creates a Canton wallet via OWS, the plugin registers the generated key as an External Party on the target synchronizer. This is a multi-step process involving topology transaction generation, signing, and submission via the Canton Ledger API v2.

## Onboarding Flow

```
ows wallet create --name agent-treasury --chain canton

Step 1: GENERATE KEY PAIR
   → See specs/02-key-management.md
   → Output: CantonKeyPair { private_key, public_key, public_key_der, fingerprint }

Step 2: GENERATE TOPOLOGY TRANSACTIONS
   POST {participant_url}/v2/parties/external/generate-topology
   Content-Type: application/json
   Body: {
     "publicKey": "<base64(public_key_der)>",
     "synchronizer": "<synchronizer_id>"
   }
   Response: {
     "partyId": "agent-treasury::1220a1b2c3d4",
     "transactions": [<serialized topology transactions>]
   }

Step 3: SIGN TOPOLOGY TRANSACTIONS
   For each topology transaction in the response:
     hash = SHA-256(transaction_bytes)
     signature = Ed25519.sign(private_key, hash)

Step 4: ALLOCATE PARTY
   POST {participant_url}/v2/parties/external/allocate
   Content-Type: application/json
   Body: {
     "synchronizer": "<synchronizer_id>",
     "onboardingTransactions": [<transactions from step 2>],
     "multiHashSignatures": [
       {
         "format": "SIGNATURE_FORMAT_CONCAT",
         "signature": "<base64(signature)>",
         "signedBy": "<public_key_fingerprint>",
         "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
       }
     ]
   }

Step 5: VERIFY REGISTRATION
   GET {participant_url}/v2/parties?filter-party={party_id}
   Expect: party appears in response

Step 6: STORE WALLET
   → Build CantonWalletFile with topology_registered: true
   → Encrypt and write to ~/.ows/wallets/
```

## Rust Interface

```rust
pub struct OnboardingResult {
    pub party_id: CantonPartyId,
    pub synchronizer_id: String,
    pub fingerprint: String,
    pub topology_registered: bool,
}

pub async fn onboard_external_party(
    keypair: &CantonKeyPair,
    party_hint: &str,
    participant_url: &str,
    synchronizer_id: &str,
    auth_token: Option<&str>,
) -> Result<OnboardingResult, CantonError>
```

## Offline Mode

If the participant node is unreachable during wallet creation:

1. Generate and encrypt the key pair normally
2. Set `topology_registered: false` in wallet metadata
3. Display warning: "Wallet created but not registered on Canton. Run `ows canton register --wallet <name>` when participant is available."

Later registration:

```rust
pub async fn register_pending_wallet(
    wallet: &mut CantonWalletFile,
    passphrase: &str,
    client: &LedgerApiClient,
) -> Result<OnboardingResult, CantonError>
```

## Error Handling

| Error | Cause | Recovery |
|-------|-------|----------|
| `ParticipantUnreachable` | Can't connect to Ledger API | Create wallet offline, register later |
| `SynchronizerNotConnected` | Participant has no synchronizer | Wait for synchronizer connection |
| `TopologyRejected` | Synchronizer rejected topology TX | Check domain policy (permissioned vs open) |
| `PartyAlreadyExists` | Party hint + namespace collision | Use different party hint or wallet name |
| `InvalidPublicKey` | DER encoding error | Bug in keygen — should not happen |

## Unit Tests Required

```
test_onboard_success                → mock API returns party_id
test_onboard_offline_mode           → unreachable API → wallet created, registered=false
test_onboard_already_exists         → 409 response → appropriate error
test_register_pending_wallet        → offline wallet → register → registered=true
test_generate_topology_request      → correct JSON body structure
test_allocate_request               → correct signature format
test_verify_party_registered        → mock party list → found
```
