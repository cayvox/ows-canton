# ows-canton

**Canton Network chain family plugin for the [Open Wallet Standard](https://openwallet.sh).**

[![crates.io](https://img.shields.io/crates/v/ows-canton.svg)](https://crates.io/crates/ows-canton)
[![CI](https://github.com/cayvox/ows-canton/actions/workflows/ci.yml/badge.svg)](https://github.com/cayvox/ows-canton/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Canton](https://img.shields.io/badge/canton-3.4%2B-green.svg)](https://www.canton.network)

---

## Why

AI agents need secure, programmable access to blockchain wallets. Every agent framework reinvents key management, and none of them support Canton Network. `ows-canton` solves this by bringing Canton to the Open Wallet Standard: one encrypted vault, one signing interface, policy-gated access for agents, and private keys that never leave the enclave.

## Features

- **Ed25519 key generation** with SLIP-0010 HD derivation and DER-encoded SPKI public keys
- **AES-256-GCM + scrypt encrypted vault** compatible with the OWS wallet format
- **Canton External Party onboarding** via topology transaction signing and party allocation
- **DAML command signing** through Canton's interactive submission protocol
- **Pre-signing policy engine** with 6 rule types: template allowlist, choice restriction, party scope, simulation required, synchronizer restriction, command type restriction
- **MCP server tools** for AI agents (Claude, GPT, LangChain) -- 8 Canton-specific tools
- **CLI** with 8 subcommands under `ows canton`
- **Ledger API v2 client** with exponential backoff retry, auth token injection, and error mapping
- **CAIP-2 identifiers** using the `canton:` namespace (`canton:global`, `canton:devnet`, `canton:sandbox`)
- **Append-only audit trail** in JSONL format for every signing operation

## Quick Start

### Install

```bash
cargo install ows-canton
```

### Create a Canton Wallet

```bash
ows canton create --name agent-treasury --synchronizer canton:devnet
```

```
Created wallet: agent-treasury
  Wallet ID:    3198bc9c-6672-5ab3-d995-4942343ae5b6
  Party ID:     agent-treasury::1220a1b2c3d4e5f6
  Chain ID:     canton:devnet
  Fingerprint:  1220a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  Algorithm:    Ed25519
  Registered:   true
  Derivation:   m/44'/9999'/0'/0/0
```

### Sign and Submit a DAML Command

```bash
ows canton submit --wallet agent-treasury --type exercise \
  --template "Daml.Finance.Holding.Fungible:Fungible" \
  --choice "Transfer" \
  --contract-id "00a1b2c3d4..." \
  --arguments '{"newOwner": "recipient::1220deadbeef"}' \
  --act-as "agent-treasury::1220a1b2c3d4e5f6"
```

### Use from Rust

```rust
use ows_canton::wallet::create_canton_wallet_in;
use ows_canton::identifier::CantonChainId;
use ows_canton::keygen::CantonSigningAlgorithm;

let chain_id = CantonChainId::parse("canton:devnet")?;
let wallet = create_canton_wallet_in(
    &ows_home,
    "agent-treasury",
    "my-secure-passphrase",
    &chain_id,
    "http://localhost:7575",
    CantonSigningAlgorithm::Ed25519,
)?;

println!("Party ID: {}", wallet.accounts[0].canton.party_id);
```

## AI Agent Integration (MCP)

Add to your Claude Code or Claude Desktop configuration:

```json
{
  "mcpServers": {
    "ows-canton": {
      "command": "ows",
      "args": ["serve", "--mcp", "--chain", "canton"]
    }
  }
}
```

| Tool | Description |
|------|-------------|
| `ows_canton_create_wallet` | Create wallet and register External Party |
| `ows_canton_submit` | Submit a signed DAML command (create, exercise) |
| `ows_canton_query` | Query active contracts on the ledger |
| `ows_canton_simulate` | Simulate a command without committing |
| `ows_canton_list_wallets` | List Canton wallets in the vault |
| `ows_canton_list_parties` | List parties on the synchronizer |
| `ows_canton_register` | Register a pending offline wallet |
| `ows_canton_get_balance` | Get token balances for a party |

## Architecture

```
Agent (Claude / GPT / CLI / SDK)
          |
          v
  OWS Canton Interface
   (MCP - CLI - SDK)
          |
    +-----+-----+
    |     |     |
    v     v     v
 Policy  Sign  Ledger API
 Engine  Enclave  Client
    |     |     |
    +-----+-----+
          |
          v
    Encrypted Vault
    ~/.ows/wallets/
```

Keys never leave the vault unencrypted. The policy engine evaluates every request before any key material is decrypted. Canton's External Party model enforces key isolation at the protocol level -- the participant node physically cannot sign on behalf of the party.

## Policy Engine

Every agent request passes through the policy engine before keys are touched. Policies use AND semantics -- all rules must allow for the operation to proceed.

| Rule Type | Description |
|-----------|-------------|
| `canton_template_allowlist` | Restrict which DAML templates agents can use |
| `canton_choice_restriction` | Restrict which choices can be exercised per template |
| `canton_party_scope` | Restrict which parties agents can act as |
| `canton_simulation_required` | Require simulation before signing |
| `canton_synchronizer_restriction` | Restrict target synchronizers |
| `canton_command_type_restriction` | Restrict command types (create / exercise) |

## Supported Chains

| Chain ID | Network | Description |
|----------|---------|-------------|
| `canton:global` | Global Synchronizer | Canton mainnet |
| `canton:devnet` | Canton Devnet | Development network |
| `canton:sandbox` | Local Sandbox | Docker-based local development |

## Cryptography

| Component | Implementation |
|-----------|---------------|
| Signing | Ed25519 (default), secp256k1 (optional) |
| Key Derivation | SLIP-0010, path `m/44'/9999'/0'/0/0` |
| Encryption | AES-256-GCM |
| KDF | scrypt (N=65536, r=8, p=1) |
| Key Encoding | DER (X.509 SubjectPublicKeyInfo) |
| Identifiers | CAIP-2 / CAIP-10 |

## Canton Compatibility

This plugin uses Canton's External Party model, where the signing key lives exclusively in the OWS vault and is never shared with the participant node. The participant generates topology transactions, the plugin signs them locally, and the signed transactions are submitted back to register the party. Requires Canton 3.4+ with External Party support. Tested against Canton Sandbox.

## Development

```bash
# Build
cargo build -p ows-canton

# Test (166 tests)
cargo test -p ows-canton

# Lint
cargo clippy -p ows-canton -- -D warnings

# Format
cargo fmt -p ows-canton

# Docs
cargo doc -p ows-canton --no-deps --open
```

## Project Structure

```
src/
├── lib.rs              # Crate root
├── error.rs            # Error types (CantonError)
├── identifier.rs       # CAIP-2/CAIP-10 Canton identifiers
├── keygen.rs           # Key generation + DER encoding
├── wallet.rs           # Wallet file format + encryption
├── signing.rs          # Signing interface + command submission
├── policy.rs           # Policy engine (6 rule types)
├── onboarding.rs       # External Party registration
├── audit.rs            # Audit logging (JSONL)
├── ledger_api/         # Canton Ledger API v2 client
│   ├── client.rs       # HTTP client with retry
│   ├── types.rs        # Request/response types
│   ├── commands.rs     # DAML command builders
│   └── topology.rs     # Topology transaction helpers
├── mcp/                # MCP server tools
│   └── tools.rs        # 8 tool definitions + handlers
└── cli/                # CLI subcommands
    └── commands.rs     # 8 subcommands (clap)
```

## Contributing

Contributions welcome. Please open an issue first to discuss significant changes.

```bash
git clone https://github.com/cayvox/ows-canton.git
cd ows-canton
cargo build
cargo test
```

## Related

- [Open Wallet Standard](https://openwallet.sh) -- The parent standard
- [Canton Network](https://www.canton.network) -- The blockchain network
- [DAML Documentation](https://docs.daml.com) -- Smart contract language
- [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) -- Chain identifier standard

## License

MIT -- see [LICENSE](LICENSE)

## About

Built by [Cayvox Labs](https://github.com/cayvox) -- blockchain infrastructure for Canton Network.
