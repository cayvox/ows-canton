# Spec 09 — CLI Commands

## Overview

Canton-specific commands are added as subcommands under `ows canton`. They follow the existing OWS CLI patterns.

## Command Tree

```
ows canton
├── create          Create a new Canton wallet + External Party
├── list            List Canton wallets in the vault
├── info            Show wallet details (party ID, fingerprint, registration)
├── register        Register a pending wallet on a synchronizer
├── submit          Submit a DAML command
├── query           Query active contracts
├── simulate        Simulate a DAML command
├── parties         List parties on the synchronizer
├── rotate-key      Rotate the signing key for a Canton wallet
└── export          Export wallet public info (party ID, public key DER)
```

## Command Specifications

### ows canton create

```
ows canton create --name <NAME> [OPTIONS]

OPTIONS:
  --name <NAME>              Wallet name (used as Canton party hint) [required]
  --synchronizer <SYNC>      Target synchronizer [default: from config]
  --participant-url <URL>    Ledger API URL [default: from config]
  --algorithm <ALG>          Signing algorithm: ed25519 | secp256k1 [default: ed25519]
  --offline                  Create key without registering on Canton
  --passphrase <PASS>        Vault passphrase (prompt if not provided)

OUTPUT (success):
  Created wallet: agent-treasury
    Wallet ID:    3198bc9c-6672-5ab3-d995-4942343ae5b6
    Party ID:     agent-treasury::1220a1b2c3d4e5f6
    Chain ID:     canton:global
    Fingerprint:  1220a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
    Algorithm:    Ed25519
    Registered:   true
    Derivation:   m/44'/9999'/0'/0/0

EXIT CODES:
  0   Success
  1   General error
  2   Passphrase too short
  3   Participant unreachable (with --offline: still 0)
  4   Party already exists
```

### ows canton submit

```
ows canton submit --wallet <WALLET> --template <TEMPLATE> --act-as <PARTY> [OPTIONS]

OPTIONS:
  --wallet <WALLET>          Wallet name or ID [required]
  --type <TYPE>              Command type: create | exercise [required]
  --template <TEMPLATE>      Fully qualified DAML template ID [required]
  --choice <CHOICE>          Choice name (for exercise) [required for exercise]
  --contract-id <ID>         Contract ID (for exercise) [required for exercise]
  --arguments <JSON>         Command arguments as JSON string [required]
  --act-as <PARTY>           Party to act as [required, repeatable]
  --read-as <PARTY>          Party to read as [optional, repeatable]
  --no-simulate              Skip pre-submission simulation
  --api-key <TOKEN>          Use API key instead of passphrase

OUTPUT (success):
  Command submitted successfully
    Command ID:    a1b2c3d4-e5f6-7890-abcd-ef1234567890
    Status:        SUCCEEDED
    Offset:        00000000000012a4
    Transaction:   tx-1220abcdef...

EXIT CODES:
  0   Success
  1   General error
  5   Policy denied
  6   Simulation failed
  7   Submission failed
```

### ows canton list

```
ows canton list

OUTPUT:
  Canton Wallets (3 found):

  NAME              PARTY ID                            CHAIN           REGISTERED
  agent-treasury    agent-treasury::1220a1b2c3d4       canton:global   ✓
  test-wallet       test-wallet::1220deadbeef          canton:devnet   ✓
  offline-wallet    offline-wallet::1220cafe1234       canton:global   ✗ (pending)
```

### ows canton info

```
ows canton info --wallet <WALLET>

OUTPUT:
  Wallet: agent-treasury
    ID:               3198bc9c-6672-5ab3-d995-4942343ae5b6
    Party ID:         agent-treasury::1220a1b2c3d4e5f6
    Account ID:       canton:global:agent-treasury::1220a1b2c3d4e5f6
    Chain ID:         canton:global
    Fingerprint:      1220a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
    Algorithm:        Ed25519
    Key Format:       DER
    Party Type:       external
    Registered:       true
    Participant:      https://participant.canton.network:443
    Synchronizer:     canton::global-synchronizer-id
    Derivation:       m/44'/9999'/0'/0/0
    Created:          2026-03-23T10:30:00Z
```

### ows canton register

```
ows canton register --wallet <WALLET>

Registers a wallet that was created with --offline.
```

### ows canton query

```
ows canton query --wallet <WALLET> --template <TEMPLATE>

OUTPUT (JSON):
  [
    {
      "contractId": "00a1b2c3...",
      "templateId": "Module:Template",
      "payload": { ... },
      "signatories": ["alice::1220..."],
      "observers": []
    }
  ]
```

### ows canton simulate

```
ows canton simulate --wallet <WALLET> --type exercise --template <TEMPLATE> \
  --choice Transfer --contract-id <ID> --arguments '{"newOwner": "bob::1220..."}' \
  --act-as agent-treasury::1220a1b2c3d4

OUTPUT:
  Simulation result: SUCCESS
  Created contracts: 1
  Archived contracts: 1
  Events: [...]
```

### ows canton parties

```
ows canton parties --wallet <WALLET> [--filter <STRING>]

OUTPUT:
  Parties on canton:global:

  PARTY ID                              LOCAL   PERMISSIONS
  alice::1220a1b2c3d4                   true    submission, confirmation
  agent-treasury::1220dead1234          false   submission (external)
  bob::1220cafe5678                     true    confirmation
```

## Clap Derive Structure

```rust
#[derive(Parser)]
pub struct CantonCli {
    #[command(subcommand)]
    pub command: CantonCommand,
}

#[derive(Subcommand)]
pub enum CantonCommand {
    Create(CreateArgs),
    List(ListArgs),
    Info(InfoArgs),
    Register(RegisterArgs),
    Submit(SubmitArgs),
    Query(QueryArgs),
    Simulate(SimulateArgs),
    Parties(PartiesArgs),
    RotateKey(RotateKeyArgs),
    Export(ExportArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long, default_value = "canton:global")]
    pub synchronizer: String,
    #[arg(long)]
    pub participant_url: Option<String>,
    #[arg(long, default_value = "ed25519")]
    pub algorithm: String,
    #[arg(long)]
    pub offline: bool,
    #[arg(long)]
    pub passphrase: Option<String>,
}

// ... similar for other commands
```
