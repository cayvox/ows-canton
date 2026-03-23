# ARCHITECTURE.md — System Architecture

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Consumer Layer                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ CLI      │  │ MCP      │  │ REST API │  │ SDK (lib)    │   │
│  │ (clap)   │  │ Server   │  │ (future) │  │ (Rust/Node/  │   │
│  │          │  │ (stdin/  │  │          │  │  Python)     │   │
│  │          │  │  stdout) │  │          │  │              │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
│       │              │              │               │           │
│       └──────────────┴──────┬───────┴───────────────┘           │
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ows-canton Public API                        │
│                                                                  │
│  canton_create_wallet()     canton_submit_command()               │
│  canton_sign_message()      canton_sign_topology()               │
│  canton_query_contracts()   canton_list_parties()                 │
│  canton_simulate()          canton_get_balance()                  │
│  canton_register_party()    canton_rotate_key()                   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
┌──────────────────┐ ┌─────────────────┐ ┌────────────────────┐
│  Key Management  │ │  Policy Engine  │ │  Ledger API Client │
│                  │ │                 │ │                    │
│  keygen.rs       │ │  policy.rs      │ │  ledger_api/       │
│  - Ed25519 gen   │ │  - Template     │ │  - client.rs       │
│  - secp256k1 gen │ │    allowlist    │ │  - types.rs        │
│  - DER encoding  │ │  - Choice       │ │  - commands.rs     │
│  - SLIP-0010 HD  │ │    restriction  │ │  - topology.rs     │
│  - Fingerprint   │ │  - Party scope  │ │                    │
│                  │ │  - Simulation   │ │  HTTP JSON → Canton│
│  wallet.rs       │ │    requirement  │ │  Participant Node  │
│  - Read/write    │ │  - Synchronizer │ │                    │
│  - Encrypt/      │ │    restriction  │ └─────────┬──────────┘
│    decrypt       │ │  - Spending     │           │
│  - Canton        │ │    limit        │           │
│    metadata      │ │                 │           │
└────────┬─────────┘ └────────┬────────┘           │
         │                    │                    │
         │         ┌──────────┴──────────┐         │
         │         │   Signing Enclave   │         │
         │         │                     │         │
         └────────►│   signing.rs        │◄────────┘
                   │                     │
                   │ 1. Receive request  │
                   │ 2. Decrypt key      │
                   │ 3. Sign payload     │
                   │ 4. Zeroize key      │
                   │ 5. Return signature │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │     OWS Vault        │
                   │   ~/.ows/            │
                   │                      │
                   │  wallets/*.json      │
                   │  keys/*.json         │
                   │  policies/*.json     │
                   │  logs/audit.jsonl    │
                   │  config.json         │
                   └──────────────────────┘
```

## Data Flow: Agent Submits DAML Command

This is the primary flow. An AI agent (via MCP) or developer tool (via CLI/SDK) submits a DAML command to Canton through OWS.

```
Step 1: REQUEST
───────────────
Agent calls ows_canton_submit via MCP/CLI/SDK with:
  - wallet_id or wallet_name
  - command: { type: "exercise", template_id, choice, contract_id, arguments }
  - act_as: ["agent-treasury::1220abcd"]
  - credential: "ows_key_a1b2c3..." (API key token)

Step 2: AUTHENTICATION
──────────────────────
identify_caller(credential):
  IF credential starts with "ows_key_" → Agent mode
    - SHA256(token) → look up key file in ~/.ows/keys/
    - Verify key exists, not expired
    - Verify wallet_id is in key's wallet_ids scope
    - Load policy_ids from key file
    → Proceed to Step 3
  ELSE (passphrase) → Owner mode
    - No policy evaluation
    → Skip to Step 4

Step 3: POLICY EVALUATION
─────────────────────────
for each policy_id in api_key.policy_ids:
  load policy from ~/.ows/policies/{policy_id}.json
  build CantonPolicyContext:
    - command (template_id, choice, arguments)
    - chain_id
    - wallet descriptor
    - act_as / read_as
    - timestamp
    - api_key_id
  evaluate(policy, context):
    - canton_template_allowlist: is template_id in allowlist?
    - canton_choice_restriction: is choice allowed for this template?
    - canton_party_scope: is act_as party in allowed list?
    - canton_synchronizer_restriction: is target synchronizer allowed?
    - canton_simulation_required: need to simulate first?
    - spending_limit: estimate value, check cumulative daily spend
  IF any policy returns deny → return Err(PolicyDenied { reason })
  IF simulation_required and not yet simulated:
    → call ledger_api.simulate(command)
    → if simulation fails, return Err(SimulationFailed { details })

Step 4: KEY DECRYPTION
──────────────────────
IF agent mode:
  derived_key = HKDF-SHA256(api_key.salt, token, "ows-api-key-v1", 32)
  mnemonic = AES-256-GCM-decrypt(derived_key, api_key.wallet_secrets[wallet_id])
ELSE (owner mode):
  derived_key = scrypt(passphrase, wallet.crypto.kdfparams)
  mnemonic = AES-256-GCM-decrypt(derived_key, wallet.crypto.ciphertext)

Step 5: KEY DERIVATION
──────────────────────
seed = bip39::mnemonic_to_seed(mnemonic)
(private_key, public_key) = slip10_ed25519::derive(seed, "m/44'/9999'/0'/0/0")
// Now private_key is in memory — minimize time to signing

Step 6: SIGNING
───────────────
Build Canton submission payload:
  - Serialize DAML command per Ledger API v2 format
  - Compute hash of submission payload
  - Sign hash with Ed25519(private_key)
  - Construct MultiHashSignature { format: CONCAT, signature, signedBy: fingerprint, algorithm: ED25519 }

Step 7: ZEROIZE
───────────────
zeroize(mnemonic)
zeroize(seed)
zeroize(private_key)
zeroize(derived_key)
// Only signature and public data remain in memory

Step 8: SUBMIT TO LEDGER API
─────────────────────────────
POST {participant_url}/v2/commands/submit
  Body: {
    commands: [serialized_command],
    actAs: act_as,
    readAs: read_as,
    commandId: uuid_v4(),
    signatures: [multi_hash_signature]
  }
Wait for completion:
  GET {participant_url}/v2/completions?offset={offset}&parties={act_as}
  Check status: SUCCEEDED | FAILED | TIMEOUT

Step 9: AUDIT LOG
─────────────────
Append to ~/.ows/logs/audit.jsonl:
{
  "timestamp": "2026-03-23T10:35:22Z",
  "wallet_id": "3198bc9c-...",
  "operation": "canton_submit_command",
  "chain_id": "canton:global",
  "details": {
    "template_id": "...",
    "choice": "Transfer",
    "act_as": [...],
    "command_id": "...",
    "status": "SUCCEEDED",
    "completion_offset": "...",
    "api_key_id": "7a2f1b3c-..." // null for owner mode
  }
}

Step 10: RETURN
───────────────
Return CantonSubmitResult {
  command_id,
  status: Succeeded,
  completion_offset,
  transaction_id (if available),
}
```

## Data Flow: Create Canton Wallet

```
Step 1: Generate mnemonic (BIP-39, 256-bit entropy)
Step 2: Derive Ed25519 key at m/44'/9999'/0'/0/0 via SLIP-0010
Step 3: Encode public key as DER (X.509 SubjectPublicKeyInfo)
Step 4: Compute fingerprint = hex(SHA-256(pubkey_der))[0..40]
Step 5: IF participant is reachable:
          POST /v2/parties/external/generate-topology { publicKey: base64(pubkey_der), synchronizer }
          Sign topology transactions with private key
          POST /v2/parties/external/allocate { signatures, transactions }
          Verify party appears: GET /v2/parties?filter-party={party_id}
          Set topology_registered = true
        ELSE:
          Set topology_registered = false (register later)
Step 6: Encrypt mnemonic with AES-256-GCM(scrypt(passphrase))
Step 7: Build wallet JSON with Canton metadata
Step 8: Write to ~/.ows/wallets/{uuid}.json with permissions 600
Step 9: Append audit log: create_wallet
Step 10: Display wallet info (party_id, addresses, key fingerprint)
```

## Module Dependency Graph

```
lib.rs
  ├── error.rs (no deps)
  ├── identifier.rs (depends on: error)
  ├── keygen.rs (depends on: error, identifier)
  ├── wallet.rs (depends on: error, identifier, keygen)
  ├── policy.rs (depends on: error, identifier, wallet)
  ├── signing.rs (depends on: error, keygen, wallet)
  ├── onboarding.rs (depends on: error, keygen, wallet, ledger_api, signing)
  ├── audit.rs (depends on: error, identifier)
  ├── ledger_api/
  │   ├── types.rs (depends on: error, identifier)
  │   ├── client.rs (depends on: error, types)
  │   ├── commands.rs (depends on: error, types, client)
  │   └── topology.rs (depends on: error, types, client)
  ├── mcp/
  │   └── tools.rs (depends on: everything above)
  └── cli/
      └── commands.rs (depends on: everything above)
```

## Concurrency Model

- **Signing operations** are synchronous (CPU-bound, no I/O). They run on the calling thread.
- **Ledger API calls** are async (I/O-bound). They use `tokio::runtime` and `reqwest`.
- **Vault file access** uses advisory file locking (`flock`) to prevent concurrent writes from multiple OWS processes.
- **Audit log** appends are atomic (write + fsync per entry).

## Configuration Hierarchy

Configuration is resolved in this order (later overrides earlier):

1. **Defaults** — hardcoded in code (localhost:7575, Ed25519, etc.)
2. **~/.ows/config.json** — global OWS config, Canton section
3. **Wallet file canton_config** — per-wallet overrides
4. **Environment variables** — OWS_CANTON_PARTICIPANT_URL, etc.
5. **CLI flags** — --participant-url, --chain, etc.
6. **MCP tool parameters** — per-request overrides

### config.json Canton Section

```json
{
  "canton": {
    "default_synchronizer": "canton:global",
    "participant_url": "https://participant.canton.network:443",
    "auth_token_path": null,
    "signing_algorithm": "ed25519",
    "simulation_required": false,
    "connection_timeout_ms": 5000,
    "request_timeout_ms": 30000
  }
}
```
