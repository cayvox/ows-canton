# CLAUDE.md — OWS Canton Plugin

## Project Identity

- **Name:** ows-canton — Canton Network chain family plugin for Open Wallet Standard
- **Repo:** A new Rust crate (`ows-canton`) designed to integrate into the [open-wallet-standard/core](https://github.com/open-wallet-standard/core) monorepo
- **Language:** Rust (core), with Node.js (NAPI-RS) and Python (PyO3) bindings
- **License:** MIT
- **Canton Version Target:** 3.4+ (External Party support required)
- **OWS Version Target:** 1.0.0

## What This Project Does

This plugin enables AI agents and developer tools to securely create, manage, and use Canton Network wallets through the Open Wallet Standard. It:

1. Generates Ed25519/secp256k1 keys and encrypts them in the OWS vault
2. Registers keys as Canton External Parties via topology transactions
3. Signs DAML commands through Canton's interactive submission protocol
4. Enforces pre-signing policies (template allowlists, spending limits, party scope)
5. Exposes Canton-specific MCP tools for AI agent access (Claude, GPT, LangChain)
6. Provides CLI commands for wallet creation, signing, and management

## Documentation Map

Read these files in order before writing any code:

```
CLAUDE.md                    ← You are here. Start here always.
PROJECT.md                   ← Repo structure, tech stack, build commands
ARCHITECTURE.md              ← System architecture, data flow, component interactions
TASKS.md                     ← Ordered implementation tasks with acceptance criteria

specs/
├── 01-identifiers.md        ← CAIP-2/CAIP-10 Canton identifier scheme
├── 02-key-management.md     ← Key generation, derivation paths, DER encoding
├── 03-wallet-format.md      ← Wallet file format extensions for Canton
├── 04-signing.md            ← Signing interface and interactive submission protocol
├── 05-policy-engine.md      ← Canton-specific policy rules
├── 06-onboarding.md         ← External Party registration flow
├── 07-ledger-api.md         ← Canton Ledger API v2 client
├── 08-mcp-tools.md          ← MCP server tool definitions and schemas
├── 09-cli-commands.md       ← CLI command specifications
├── 10-testing.md            ← Test strategy, fixtures, scenarios
└── 11-security.md           ← Threat model, security invariants
```

## Critical Rules

### 1. Never Expose Private Keys
Private keys MUST only exist in memory during the signing operation inside the signing enclave function. After signing, call `zeroize()` on all key material. Keys MUST NOT appear in logs, error messages, debug output, or function return values.

### 2. Canton ≠ EVM
Canton does NOT use raw transaction hex signing. Do NOT model the signing interface after EVM's `sign_transaction(tx_bytes)` pattern. Canton uses structured DAML commands submitted through the Ledger API with the interactive submission protocol. See `specs/04-signing.md`.

### 3. External Party Model
The primary signing mode is External Party submission. The OWS vault holds the party's private key. The Canton participant node NEVER has access to the private key. The party signs commands locally, and the signed command is submitted to the Ledger API. See `specs/06-onboarding.md`.

### 4. Policy Before Key Material
The policy engine MUST evaluate all attached policies BEFORE any key material is decrypted. If any policy denies the request, return `POLICY_DENIED` error immediately. Key decryption only happens after all policies pass. See `specs/05-policy-engine.md`.

### 5. CAIP Identifiers Everywhere
All chain references use CAIP-2 format (`canton:global`, `canton:devnet`). All account references use CAIP-10 format (`canton:global:alice::1220abcd`). Never use shorthand or internal-only identifiers in public APIs, wallet files, or audit logs. See `specs/01-identifiers.md`.

### 6. Error Handling
Use `thiserror` for error types. Every public function returns `Result<T, CantonError>`. Never `unwrap()` or `expect()` in library code. Panics are bugs. Propagate errors with `?` and add context with `.context()` (anyhow) or custom error variants.

### 7. Testing
Every public function has at least one unit test. Integration tests use Canton Sandbox (Docker). No test should require a live network. Mock the Ledger API client for unit tests. See `specs/10-testing.md`.

## Build & Test Commands

```bash
# Build the crate
cargo build -p ows-canton

# Run unit tests
cargo test -p ows-canton

# Run unit tests with output
cargo test -p ows-canton -- --nocapture

# Run specific test
cargo test -p ows-canton test_caip2_parsing

# Check formatting
cargo fmt -p ows-canton -- --check

# Run clippy
cargo clippy -p ows-canton -- -D warnings

# Run integration tests (requires Docker)
cargo test -p ows-canton --features integration-tests
```

## Code Style

- **Formatting:** `rustfmt` default configuration
- **Linting:** `clippy` with `-D warnings` (all warnings are errors)
- **Naming:** snake_case for functions/variables, PascalCase for types, SCREAMING_SNAKE_CASE for constants
- **Documentation:** Every public item has a `///` doc comment. Every module has a `//!` module-level doc comment.
- **Imports:** Group by std → external crates → internal modules, separated by blank lines
- **Error types:** One `CantonError` enum per crate with `#[derive(Debug, thiserror::Error)]`
- **Serialization:** `serde` with `#[serde(rename_all = "snake_case")]` on all public structs
- **Async:** Use `tokio` runtime for async operations (Ledger API calls). Non-async for pure crypto operations.
