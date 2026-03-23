# PROJECT.md — Repository Structure & Tech Stack

## Repository Layout

This crate is designed to be added to the OWS monorepo at `ows/ows-chains/ows-canton/`. For standalone development, the following structure applies:

```
ows-canton/
├── Cargo.toml
├── src/
│   ├── lib.rs                    # Crate root — module declarations, re-exports
│   ├── error.rs                  # CantonError enum (thiserror)
│   ├── identifier.rs             # CAIP-2/CAIP-10 parsing and validation
│   ├── keygen.rs                 # Ed25519/secp256k1 key generation + DER encoding
│   ├── wallet.rs                 # Canton wallet file format (read/write/extend)
│   ├── signing.rs                # Canton signing protocol (message signing, command signing)
│   ├── policy.rs                 # Canton-specific policy rule types + evaluation
│   ├── onboarding.rs             # External Party registration flow
│   ├── ledger_api/
│   │   ├── mod.rs                # Ledger API client module root
│   │   ├── client.rs             # HTTP JSON API client (reqwest)
│   │   ├── types.rs              # Request/response types for Ledger API v2
│   │   ├── commands.rs           # DAML command builder (create, exercise, etc.)
│   │   └── topology.rs           # Topology transaction API helpers
│   ├── mcp/
│   │   ├── mod.rs                # MCP module root
│   │   └── tools.rs              # MCP tool definitions and handlers
│   ├── cli/
│   │   ├── mod.rs                # CLI module root
│   │   └── commands.rs           # Canton-specific CLI subcommands
│   └── audit.rs                  # Canton-specific audit log entries
├── tests/
│   ├── unit/
│   │   ├── identifier_test.rs
│   │   ├── keygen_test.rs
│   │   ├── wallet_test.rs
│   │   ├── signing_test.rs
│   │   └── policy_test.rs
│   ├── integration/
│   │   ├── onboarding_test.rs    # Requires Canton Sandbox
│   │   ├── submit_test.rs        # Requires Canton Sandbox
│   │   └── mcp_test.rs           # MCP tool integration tests
│   └── fixtures/
│       ├── sample_wallet.json
│       ├── sample_api_key.json
│       ├── sample_policy.json
│       └── canton_sandbox.conf
└── README.md
```

## Cargo.toml

```toml
[package]
name = "ows-canton"
version = "0.1.0"
edition = "2021"
authors = ["Cayvox Labs <contact@cayvox.com>"]
license = "MIT"
description = "Canton Network chain family plugin for Open Wallet Standard"
repository = "https://github.com/open-wallet-standard/core"
keywords = ["canton", "wallet", "daml", "blockchain", "ows"]
categories = ["cryptography", "authentication"]

[dependencies]
# Cryptography
ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }
k256 = { version = "0.13", features = ["ecdsa", "sha256"], optional = true }
rand = "0.8"
sha2 = "0.10"
hkdf = "0.12"
aes-gcm = "0.10"
scrypt = "0.11"
zeroize = { version = "1", features = ["derive"] }
bip39 = "2"
derivation-path = "0.2"
slip10_ed25519 = "0.1"

# Key encoding
pkcs8 = { version = "0.10", features = ["std"] }
spki = "0.7"
der = "0.7"
base64 = "0.22"
hex = "0.4"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }

# Async + HTTP
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

# Error handling
thiserror = "2"
anyhow = "1"

# Logging
tracing = "0.1"

# CLI (optional, for binary)
clap = { version = "4", features = ["derive"], optional = true }

[dev-dependencies]
tokio-test = "0.4"
tempfile = "3"
wiremock = "0.6"
assert_matches = "1"
test-log = "0.2"

[features]
default = ["ed25519", "cli"]
ed25519 = []
secp256k1 = ["k256"]
cli = ["clap"]
integration-tests = []
```

## Tech Stack Summary

| Component | Technology | Purpose |
|-----------|------------|---------|
| Core language | Rust 2021 edition | Memory safety, performance, zeroize support |
| Signing (default) | ed25519-dalek 2.x | Ed25519 key generation and signing |
| Signing (optional) | k256 0.13 | secp256k1 ECDSA support |
| Key encoding | pkcs8 + spki + der | DER-encoded SubjectPublicKeyInfo for Canton |
| Encryption | aes-gcm + scrypt | AES-256-GCM vault encryption (OWS standard) |
| Mnemonic | bip39 2.x | BIP-39 seed phrase generation and parsing |
| Key derivation | slip10_ed25519 | SLIP-0010 Ed25519 HD derivation |
| HTTP client | reqwest 0.12 | Canton Ledger API v2 (JSON over HTTP) |
| Async runtime | tokio 1.x | Async I/O for Ledger API communication |
| Serialization | serde + serde_json | JSON wallet files, API payloads, audit logs |
| CLI | clap 4.x (optional) | Canton-specific CLI subcommands |
| Error handling | thiserror 2.x | Typed error enums |
| Memory safety | zeroize 1.x | Secure memory wiping for key material |
| Testing | wiremock 0.6 | HTTP mock server for Ledger API tests |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OWS_HOME` | No | `~/.ows` | Vault directory path |
| `OWS_PASSPHRASE` | No | (prompt) | Vault passphrase (insecure — prefer stdin) |
| `OWS_CANTON_PARTICIPANT_URL` | No | `http://localhost:7575` | Default Ledger API URL |
| `OWS_CANTON_AUTH_TOKEN` | No | (none) | JWT token for Ledger API auth |
| `OWS_LOG_LEVEL` | No | `info` | Tracing log level |
| `RUST_LOG` | No | (none) | Fine-grained log control |

## Minimum Supported Rust Version

MSRV: **1.75.0** (edition 2021, async fn in trait stabilization)

## External Dependencies (Runtime)

1. **Canton Participant Node** — running and accessible at the configured URL. The Ledger API v2 must be exposed (HTTP JSON API).
2. **Canton Synchronizer** — the participant must be connected to at least one synchronizer for topology registration.
3. **File system** — read/write access to `~/.ows/` for vault storage.
