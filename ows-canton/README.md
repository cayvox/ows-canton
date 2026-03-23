# OWS Canton Plugin

Canton Network chain family plugin for the [Open Wallet Standard](https://github.com/open-wallet-standard/core).

## Overview

`ows-canton` enables AI agents and developer tools to securely create, manage, and use Canton Network wallets. It generates Ed25519 keys, registers them as Canton External Parties, signs DAML commands through the interactive submission protocol, and enforces pre-signing policies — all while keeping private keys encrypted at rest and zeroized after use.

### Features

- **Key Management** — Ed25519 key generation with SLIP-0010 HD derivation, DER-encoded SPKI public keys
- **Encrypted Vault** — AES-256-GCM + scrypt wallet encryption with 0600 file permissions
- **External Party Registration** — Topology transaction signing and party allocation on Canton synchronizers
- **DAML Command Submission** — Sign and submit create/exercise commands via Ledger API v2
- **Policy Engine** — Template allowlists, choice restrictions, party scope, simulation requirements
- **MCP Tools** — 8 Canton-specific tools for AI agent integration (Claude, GPT, LangChain)
- **CLI** — Full command-line interface for wallet creation, signing, querying, and management
- **Audit Logging** — Append-only JSONL audit trail for all signing operations

## Quick Start

```bash
# Build
cargo build -p ows-canton

# Run tests
cargo test -p ows-canton

# Check lints
cargo clippy -p ows-canton -- -D warnings
```

### Create a Wallet

```bash
ows canton create --name agent-treasury --synchronizer canton:devnet --passphrase "your-passphrase"
```

### Submit a DAML Command

```bash
ows canton submit --wallet agent-treasury --type exercise \
  --template "Daml.Finance.Holding.Fungible:Fungible" \
  --choice "Transfer" --contract-id "00abc..." \
  --arguments '{"newOwner": "bob::1220..."}' \
  --act-as "agent-treasury::1220..." \
  --passphrase "your-passphrase"
```

### Query Active Contracts

```bash
ows canton query --wallet agent-treasury \
  --template "Daml.Finance.Holding.Fungible:Fungible"
```

## MCP Integration (Claude Code)

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

Available MCP tools: `ows_canton_create_wallet`, `ows_canton_list_wallets`, `ows_canton_submit`, `ows_canton_query`, `ows_canton_simulate`, `ows_canton_get_balance`, `ows_canton_list_parties`, `ows_canton_register`.

## Architecture

The plugin follows a layered architecture: consumer interfaces (CLI, MCP, SDK) call the public API, which coordinates key management, policy evaluation, and Ledger API communication through a signing enclave that minimizes private key exposure time.

| Component | Module | Purpose |
|-----------|--------|---------|
| Identifiers | `identifier.rs` | CAIP-2/CAIP-10 Canton ID parsing |
| Key Management | `keygen.rs` | Ed25519 generation, DER encoding, SLIP-0010 |
| Wallet | `wallet.rs` | Encrypted wallet files, AES-256-GCM + scrypt |
| Policy Engine | `policy.rs` | 6 rule types, AND semantics evaluation |
| Signing | `signing.rs` | Message/topology/command signing with zeroize |
| Ledger API | `ledger_api/` | HTTP client with retry, auth, error mapping |
| Onboarding | `onboarding.rs` | External Party registration flow |
| Audit | `audit.rs` | Append-only JSONL audit log |
| MCP | `mcp/` | AI agent tool definitions and handlers |
| CLI | `cli/` | clap-based command-line interface |

### Supported Chain IDs

| CAIP-2 ID | Network | Usage |
|-----------|---------|-------|
| `canton:global` | Canton Global Synchronizer | Production |
| `canton:devnet` | Canton Devnet | Development |
| `canton:sandbox` | Local Sandbox | Local testing |

## Security

- **Key Isolation** — Private keys only exist in memory during signing, then zeroized via `Zeroizing` + `Drop`
- **Policy Before Decryption** — All policies evaluated before any key material is decrypted
- **Encrypted at Rest** — AES-256-GCM with scrypt (N=65536) key derivation
- **File Permissions** — Wallet files created with 0600 permissions
- **External Party Model** — Canton participant node never has access to private keys
- **Audit Trail** — Every signing operation logged to append-only JSONL

See [specs/11-security.md](specs/11-security.md) for the full threat model.

## License

MIT
