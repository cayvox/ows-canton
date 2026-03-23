# Spec 08 — MCP Server Tools

## Overview

OWS exposes Canton operations as MCP (Model Context Protocol) tools via `ows serve --mcp`. AI agents (Claude, GPT, LangChain) call these tools to interact with Canton wallets.

## Tool Registry

| Tool | Description | Requires Ledger API |
|------|-------------|---------------------|
| `ows_canton_create_wallet` | Create a new Canton wallet + register External Party | Yes (unless offline) |
| `ows_canton_list_wallets` | List all Canton wallets in the vault | No |
| `ows_canton_submit` | Submit a DAML command (create, exercise) | Yes |
| `ows_canton_query` | Query active contracts on the ledger | Yes |
| `ows_canton_simulate` | Simulate a DAML command without committing | Yes |
| `ows_canton_get_balance` | Get token balances for a Canton party | Yes |
| `ows_canton_list_parties` | List Canton parties on the connected synchronizer | Yes |
| `ows_canton_register` | Register a pending wallet as External Party | Yes |

## Tool Definitions

### ows_canton_create_wallet

```json
{
  "name": "ows_canton_create_wallet",
  "description": "Create a new Canton Network wallet. Generates an Ed25519 key pair, encrypts it in the OWS vault, and registers the key as an External Party on the specified synchronizer. Returns the party ID and wallet details.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {
        "type": "string",
        "description": "Human-readable wallet name (used as Canton party hint)"
      },
      "synchronizer": {
        "type": "string",
        "description": "Target synchronizer (e.g., 'canton:global', 'canton:devnet'). Defaults to config default.",
        "default": "canton:global"
      },
      "signing_algorithm": {
        "type": "string",
        "enum": ["ed25519", "secp256k1"],
        "default": "ed25519"
      }
    },
    "required": ["name"]
  }
}
```

### ows_canton_submit

```json
{
  "name": "ows_canton_submit",
  "description": "Submit a DAML command to Canton Network. Signs the command using the wallet's External Party key (policy checks enforced for agent keys) and submits via the Ledger API. Supports create, exercise, and createAndExercise commands.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "wallet": {
        "type": "string",
        "description": "Wallet name or UUID"
      },
      "command_type": {
        "type": "string",
        "enum": ["create", "exercise", "createAndExercise"],
        "description": "DAML command type"
      },
      "template_id": {
        "type": "string",
        "description": "Fully qualified DAML template ID (e.g., 'Module:Template')"
      },
      "arguments": {
        "type": "object",
        "description": "Command arguments (create payload or exercise choice argument)"
      },
      "choice": {
        "type": "string",
        "description": "Choice name (required for exercise and createAndExercise)"
      },
      "contract_id": {
        "type": "string",
        "description": "Contract ID (required for exercise)"
      },
      "act_as": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Party IDs to act as"
      },
      "read_as": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Party IDs to read as (optional)"
      },
      "simulate_first": {
        "type": "boolean",
        "default": true,
        "description": "Simulate command before submitting"
      }
    },
    "required": ["wallet", "command_type", "template_id", "arguments", "act_as"]
  }
}
```

### ows_canton_query

```json
{
  "name": "ows_canton_query",
  "description": "Query active contracts on the Canton ledger. Returns matching contracts visible to the specified parties.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "wallet": {
        "type": "string",
        "description": "Wallet name or UUID (determines participant connection)"
      },
      "template_id": {
        "type": "string",
        "description": "DAML template ID to filter by"
      },
      "party": {
        "type": "string",
        "description": "Party ID to query as (defaults to wallet's party)"
      }
    },
    "required": ["wallet", "template_id"]
  }
}
```

### ows_canton_simulate

```json
{
  "name": "ows_canton_simulate",
  "description": "Simulate a DAML command without signing or committing. Returns the expected result of executing the command, useful for validating commands before submission.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "wallet": { "type": "string" },
      "command_type": { "type": "string", "enum": ["create", "exercise", "createAndExercise"] },
      "template_id": { "type": "string" },
      "arguments": { "type": "object" },
      "choice": { "type": "string" },
      "contract_id": { "type": "string" },
      "act_as": { "type": "array", "items": { "type": "string" } }
    },
    "required": ["wallet", "command_type", "template_id", "arguments", "act_as"]
  }
}
```

### ows_canton_list_wallets

```json
{
  "name": "ows_canton_list_wallets",
  "description": "List all Canton wallets stored in the OWS vault. Shows wallet name, party ID, synchronizer, and registration status.",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

### ows_canton_list_parties

```json
{
  "name": "ows_canton_list_parties",
  "description": "List all parties on the connected Canton synchronizer, showing party IDs and hosting information.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "wallet": { "type": "string", "description": "Wallet name (for participant connection)" },
      "filter": { "type": "string", "description": "Filter party list by substring" }
    },
    "required": ["wallet"]
  }
}
```

## MCP Tool Handler Pattern

```rust
pub async fn handle_mcp_tool(
    tool_name: &str,
    arguments: serde_json::Value,
    credential: &str,
) -> Result<serde_json::Value, CantonError> {
    match tool_name {
        "ows_canton_create_wallet" => {
            let args: CreateWalletArgs = serde_json::from_value(arguments)?;
            let result = canton_create_wallet(&args, credential).await?;
            Ok(serde_json::to_value(result)?)
        }
        "ows_canton_submit" => {
            let args: SubmitArgs = serde_json::from_value(arguments)?;
            let result = canton_submit_command(&args, credential).await?;
            Ok(serde_json::to_value(result)?)
        }
        // ... other tools
        _ => Err(CantonError::UnknownTool(tool_name.to_string())),
    }
}
```

## Claude Code Configuration

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
