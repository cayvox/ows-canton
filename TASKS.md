# TASKS.md — Implementation Task List

Execute these tasks in order. Each task builds on the previous one. Do NOT skip ahead.

---

## Phase 1: Foundation

### Task 1: Project Scaffolding
**Create the crate structure and Cargo.toml**

- [ ] Create `ows-canton/Cargo.toml` with all dependencies from PROJECT.md
- [ ] Create `src/lib.rs` with module declarations (empty modules)
- [ ] Create `src/error.rs` with `CantonError` enum
- [ ] Create all empty module files listed in PROJECT.md
- [ ] Verify: `cargo build -p ows-canton` succeeds with no errors
- [ ] Verify: `cargo clippy -p ows-canton -- -D warnings` passes

**Acceptance:** Crate compiles. All modules exist. Error type is defined.

### Task 2: Identifier Types
**Implement CAIP-2 and CAIP-10 Canton identifiers**

Spec: `specs/01-identifiers.md`

- [ ] Implement `CantonChainId` (parse, validate, display, serialize/deserialize)
- [ ] Implement `CantonPartyId` (parse, validate, display, serialize/deserialize)
- [ ] Implement `CantonAccountId` (parse, validate, display, serialize/deserialize)
- [ ] Add constants: `GLOBAL`, `DEVNET`, `SANDBOX`
- [ ] Write all unit tests from spec
- [ ] Verify: `cargo test -p ows-canton identifier` — all pass

**Acceptance:** All identifier types parse, validate, roundtrip. All tests pass.

### Task 3: Key Generation
**Implement Ed25519 key generation with SLIP-0010 derivation and DER encoding**

Spec: `specs/02-key-management.md`

- [ ] Implement `CantonKeyPair` struct with `Zeroize` derive
- [ ] Implement `CantonSigningAlgorithm` enum
- [ ] Implement `generate_canton_keypair(mnemonic_seed, derivation_path, algorithm)` → `CantonKeyPair`
- [ ] Implement `encode_ed25519_spki(pubkey_bytes)` → DER bytes
- [ ] Implement `compute_fingerprint(pubkey_der)` → hex string
- [ ] Implement `ed25519_sign(private_key, message)` → signature bytes
- [ ] Implement `ed25519_verify(public_key, message, signature)` → bool
- [ ] Implement `Drop` for `CantonKeyPair` with zeroize
- [ ] Write all unit tests from spec (use test mnemonic from fixtures)
- [ ] Verify: deterministic test — known mnemonic produces known public key

**Acceptance:** Key generation is deterministic. DER encoding is valid. Sign/verify works. Zeroize on drop.

### Task 4: Wallet File Format
**Implement Canton wallet creation, reading, and encryption**

Spec: `specs/03-wallet-format.md`

- [ ] Implement all wallet types: `CantonWalletFile`, `CantonAccountEntry`, `CantonAccountMetadata`, `CantonConfig`, `CryptoEnvelope`, etc.
- [ ] Implement `create_canton_wallet(name, passphrase, chain_id, participant_url, algorithm)` → `CantonWalletFile`
  - Generate mnemonic
  - Derive key
  - Build account entry with Canton metadata
  - Encrypt mnemonic with AES-256-GCM + scrypt
  - Write to `~/.ows/wallets/{id}.json`
  - Set file permissions 0600
- [ ] Implement `load_canton_wallet(id_or_name)` → `CantonWalletFile`
- [ ] Implement `decrypt_canton_wallet(wallet, passphrase)` → mnemonic bytes (Zeroizing)
- [ ] Implement `list_canton_wallets()` → Vec<CantonWalletFile>
- [ ] Implement passphrase validation (minimum 12 chars)
- [ ] Write all unit tests from spec (use tempdir for file operations)
- [ ] Verify: create → load → decrypt roundtrip produces same mnemonic

**Acceptance:** Wallet files are valid JSON. Encryption/decryption works. File permissions enforced.

---

## Phase 2: Policy & Signing

### Task 5: Policy Engine
**Implement Canton-specific policy rules and evaluation**

Spec: `specs/05-policy-engine.md`

- [ ] Implement `CantonPolicyContext` struct
- [ ] Implement `CantonPolicy` and `CantonPolicyRule` types (serde tagged enum)
- [ ] Implement `PolicyResult` enum (Allow, Deny, NeedsSimulation)
- [ ] Implement evaluators for each rule type:
  - `evaluate_template_allowlist`
  - `evaluate_choice_restriction`
  - `evaluate_party_scope`
  - `evaluate_simulation_required`
  - `evaluate_synchronizer_restriction`
  - `evaluate_command_type_restriction`
- [ ] Implement `evaluate_canton_policy(policy, context)` — AND semantics
- [ ] Implement policy file read/write (`~/.ows/policies/`)
- [ ] Write all unit tests from spec
- [ ] Verify: each rule type has allow + deny test case

**Acceptance:** All 6 rule types evaluate correctly. AND semantics work. Policy files serialize/deserialize.

### Task 6: Signing Interface
**Implement the Canton signing protocol**

Spec: `specs/04-signing.md`

- [ ] Implement `CantonCommand` type with `CantonCommandType`
- [ ] Implement `CantonSignature` type (signature, signed_by, format, algorithm)
- [ ] Implement `CantonSubmitResult` type
- [ ] Implement `canton_sign_message(wallet, credential, message)` → `CantonSignature`
  - Authenticate (passphrase vs API key)
  - Policy check (agent mode)
  - Decrypt key
  - Sign message
  - Zeroize key
  - Return signature
- [ ] Implement `canton_sign_topology(wallet, credential, topology_bytes)` → `CantonSignature`
- [ ] Implement `build_submission_request(command, act_as, read_as, command_id)` → JSON
- [ ] Implement `build_multi_hash_signature(signature, fingerprint, algorithm)` → JSON
- [ ] Write all unit tests from spec
- [ ] Verify: sign/verify roundtrip. Policy denial prevents signing.

**Acceptance:** Signing works for messages and topology transactions. Policy evaluation happens before decryption.

---

## Phase 3: Ledger API & Onboarding

### Task 7: Ledger API Client
**Implement the HTTP JSON API client for Canton Participant Node**

Spec: `specs/07-ledger-api.md`

- [ ] Implement `LedgerApiClient` struct (reqwest-based)
- [ ] Implement all endpoint methods:
  - `health_check()`
  - `get_connected_synchronizers()`
  - `generate_external_topology(pubkey_b64, synchronizer)`
  - `allocate_external_party(req)`
  - `list_parties(filter)`
  - `submit_command(req, signature)`
  - `simulate_command(req)`
  - `get_active_contracts(template_id, parties)`
  - `get_completions(offset, parties)`
- [ ] Implement request/response types in `ledger_api/types.rs`
- [ ] Implement auth token header injection
- [ ] Implement retry logic (3x on connection error, 2x on 5xx)
- [ ] Implement error mapping (HTTP status → LedgerApiError)
- [ ] Write all unit tests with wiremock
- [ ] Verify: each endpoint tested with mock success + error cases

**Acceptance:** All Ledger API endpoints implemented. Auth header works. Retry logic works. Mock tests pass.

### Task 8: External Party Onboarding
**Implement the wallet creation + External Party registration flow**

Spec: `specs/06-onboarding.md`

- [ ] Implement `onboard_external_party(keypair, hint, url, sync_id, token)` → `OnboardingResult`
  - Call generate-topology
  - Sign topology transactions
  - Call allocate
  - Verify registration
- [ ] Implement offline mode (skip registration, set topology_registered=false)
- [ ] Implement `register_pending_wallet(wallet, passphrase, client)` for later registration
- [ ] Wire onboarding into `create_canton_wallet` (if participant reachable: register, else: offline)
- [ ] Write tests with wiremock (mock the full onboarding flow)
- [ ] Verify: full create → register → verify flow works with mocks

**Acceptance:** Wallet creation with registration works. Offline mode works. Pending registration works.

### Task 9: Command Submission
**Implement the full DAML command submission flow**

Spec: `specs/04-signing.md` (full flow section)

- [ ] Implement `canton_submit_command(wallet, credential, command, act_as, read_as, client)` → `CantonSubmitResult`
  - Full flow: authenticate → policy → simulate → decrypt → derive → sign → submit → audit
- [ ] Implement `canton_simulate(wallet, command, act_as, client)` → SimulationResult
- [ ] Implement `canton_query_contracts(wallet, template_id, client)` → Vec<ActiveContract>
- [ ] Implement audit logging for all operations
- [ ] Write tests with wiremock (mock submit + completion)
- [ ] Verify: full submit flow works end-to-end with mocks

**Acceptance:** Complete submit flow including policy check, simulation, signing, and audit logging.

---

## Phase 4: User Interfaces

### Task 10: CLI Commands
**Implement Canton-specific CLI subcommands**

Spec: `specs/09-cli-commands.md`

- [ ] Implement `CantonCli` and all subcommand structs with clap derive
- [ ] Implement handlers for each command:
  - `create` — calls create_canton_wallet + displays result
  - `list` — calls list_canton_wallets + formatted table output
  - `info` — calls load_canton_wallet + displays details
  - `register` — calls register_pending_wallet
  - `submit` — calls canton_submit_command + displays result
  - `query` — calls canton_query_contracts + JSON output
  - `simulate` — calls canton_simulate + displays result
  - `parties` — calls list_parties + formatted table
- [ ] Implement passphrase prompting (stdin, or --passphrase flag)
- [ ] Implement proper exit codes per spec
- [ ] Write tests for argument parsing
- [ ] Verify: each command produces expected output format

**Acceptance:** All CLI commands work. Output matches spec format. Exit codes correct.

### Task 11: MCP Tools
**Implement MCP server tool definitions and handlers**

Spec: `specs/08-mcp-tools.md`

- [ ] Implement tool definitions (JSON schema for each tool)
- [ ] Implement `handle_mcp_tool(name, arguments, credential)` dispatcher
- [ ] Implement handlers for each tool:
  - `ows_canton_create_wallet`
  - `ows_canton_list_wallets`
  - `ows_canton_submit`
  - `ows_canton_query`
  - `ows_canton_simulate`
  - `ows_canton_list_parties`
  - `ows_canton_register`
  - `ows_canton_get_balance`
- [ ] Implement MCP stdin/stdout protocol handling
- [ ] Write tests for each tool handler with mocks
- [ ] Verify: tool definitions match JSON schemas in spec

**Acceptance:** All MCP tools defined and handle requests correctly. Claude Code config works.

---

## Phase 5: Polish & Integration

### Task 12: Integration Tests
**Write integration tests against Canton Sandbox**

Spec: `specs/10-testing.md`

- [ ] Create `tests/docker-compose.yml` for Canton Sandbox
- [ ] Create `tests/fixtures/canton_sandbox.conf`
- [ ] Write integration test: full wallet lifecycle (create → submit → query)
- [ ] Write integration test: policy denial flow
- [ ] Write integration test: offline → register flow
- [ ] Feature-gate all integration tests behind `integration-tests` flag
- [ ] Verify: `cargo test -p ows-canton --features integration-tests` passes against running sandbox

**Acceptance:** Integration tests pass against Canton Sandbox Docker container.

### Task 13: Documentation
**Write crate documentation and README**

- [ ] Write `//!` module-level docs for every module
- [ ] Write `///` docs for every public item
- [ ] Write `README.md` with quickstart, examples, architecture overview
- [ ] Write `CONTRIBUTING.md` with development setup instructions
- [ ] Verify: `cargo doc -p ows-canton --no-deps` generates without warnings
- [ ] Verify: README examples compile (doc tests)

**Acceptance:** All public items documented. README has working examples. `cargo doc` clean.

### Task 14: CI Configuration
**Set up GitHub Actions CI pipeline**

- [ ] Create `.github/workflows/ci.yml`:
  - `cargo fmt -- --check`
  - `cargo clippy -- -D warnings`
  - `cargo test`
  - `cargo doc --no-deps`
- [ ] Create `.github/workflows/integration.yml`:
  - Start Canton Sandbox Docker
  - `cargo test --features integration-tests`
- [ ] Verify: CI passes on push to main

**Acceptance:** CI pipeline runs fmt, clippy, tests, docs. All green.

---

## Task Dependency Graph

```
Task 1 (Scaffolding)
  └→ Task 2 (Identifiers)
       └→ Task 3 (Key Generation)
            └→ Task 4 (Wallet Format)
                 ├→ Task 5 (Policy Engine)
                 │    └→ Task 6 (Signing)
                 │         └→ Task 9 (Command Submission)
                 │              ├→ Task 10 (CLI)
                 │              └→ Task 11 (MCP Tools)
                 └→ Task 7 (Ledger API Client)
                      └→ Task 8 (Onboarding)
                           └→ Task 9 (Command Submission)

Task 12 (Integration Tests) requires Tasks 1-11
Task 13 (Documentation) requires Tasks 1-11
Task 14 (CI) requires Task 1
```
