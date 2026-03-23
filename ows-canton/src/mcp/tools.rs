//! MCP tool definitions and request handlers.
//!
//! Defines the JSON schemas for each MCP tool and implements the dispatch
//! logic that routes incoming tool calls to the appropriate Canton operations.

use serde::Deserialize;

use crate::identifier::CantonChainId;
use crate::keygen::CantonSigningAlgorithm;
use crate::ledger_api::client::LedgerApiClient;
use crate::onboarding::register_pending_wallet;
use crate::policy::{CantonCommand, CantonCommandType};
use crate::signing::{canton_query_contracts, canton_simulate, canton_submit_command};
use crate::wallet::{create_canton_wallet_in, list_canton_wallets, load_canton_wallet};
use crate::CantonError;

// ── Tool argument structs ──────────────────────────────────────────

/// Arguments for `ows_canton_create_wallet`.
#[derive(Debug, Deserialize)]
pub struct CreateWalletArgs {
    /// Wallet name (party hint).
    pub name: String,
    /// Target synchronizer (default: "canton:global").
    pub synchronizer: Option<String>,
    /// Signing algorithm (default: "ed25519").
    pub signing_algorithm: Option<String>,
}

/// Arguments for `ows_canton_list_wallets`.
#[derive(Debug, Deserialize)]
pub struct ListWalletsArgs {}

/// Arguments for `ows_canton_submit`.
#[derive(Debug, Deserialize)]
pub struct SubmitArgs {
    /// Wallet name or UUID.
    pub wallet: String,
    /// Command type: create, exercise, createAndExercise.
    pub command_type: String,
    /// DAML template ID.
    pub template_id: String,
    /// Command arguments.
    pub arguments: serde_json::Value,
    /// Parties to act as.
    pub act_as: Vec<String>,
    /// Choice name (for exercise).
    pub choice: Option<String>,
    /// Contract ID (for exercise).
    pub contract_id: Option<String>,
    /// Parties to read as.
    pub read_as: Option<Vec<String>>,
    /// Whether to simulate before submitting.
    pub simulate_first: Option<bool>,
}

/// Arguments for `ows_canton_query`.
#[derive(Debug, Deserialize)]
pub struct QueryArgs {
    /// Wallet name or UUID.
    pub wallet: String,
    /// DAML template ID.
    pub template_id: String,
    /// Party to query as.
    pub party: Option<String>,
}

/// Arguments for `ows_canton_simulate`.
#[derive(Debug, Deserialize)]
pub struct SimulateArgs {
    /// Wallet name or UUID.
    pub wallet: String,
    /// Command type.
    pub command_type: String,
    /// DAML template ID.
    pub template_id: String,
    /// Command arguments.
    pub arguments: serde_json::Value,
    /// Parties to act as.
    pub act_as: Vec<String>,
    /// Choice name.
    pub choice: Option<String>,
    /// Contract ID.
    pub contract_id: Option<String>,
}

/// Arguments for `ows_canton_get_balance`.
#[derive(Debug, Deserialize)]
pub struct GetBalanceArgs {
    /// Wallet name or UUID.
    pub wallet: String,
    /// Instrument identifier to filter by.
    pub instrument_id: Option<String>,
}

/// Arguments for `ows_canton_list_parties`.
#[derive(Debug, Deserialize)]
pub struct ListPartiesArgs {
    /// Wallet name or UUID.
    pub wallet: String,
    /// Filter string.
    pub filter: Option<String>,
}

/// Arguments for `ows_canton_register`.
#[derive(Debug, Deserialize)]
pub struct RegisterArgs {
    /// Wallet name or UUID.
    pub wallet: String,
}

// ── Tool definitions ───────────────────────────────────────────────

/// Return MCP tool definitions for all Canton tools.
pub fn get_canton_tool_definitions() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
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
        }),
        serde_json::json!({
            "name": "ows_canton_list_wallets",
            "description": "List all Canton wallets stored in the OWS vault. Shows wallet name, party ID, synchronizer, and registration status.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "ows_canton_submit",
            "description": "Submit a DAML command to Canton Network. Signs the command using the wallet's External Party key (policy checks enforced for agent keys) and submits via the Ledger API. Supports create, exercise, and createAndExercise commands.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet": { "type": "string", "description": "Wallet name or UUID" },
                    "command_type": { "type": "string", "enum": ["create", "exercise", "createAndExercise"], "description": "DAML command type" },
                    "template_id": { "type": "string", "description": "Fully qualified DAML template ID (e.g., 'Module:Template')" },
                    "arguments": { "type": "object", "description": "Command arguments (create payload or exercise choice argument)" },
                    "choice": { "type": "string", "description": "Choice name (required for exercise and createAndExercise)" },
                    "contract_id": { "type": "string", "description": "Contract ID (required for exercise)" },
                    "act_as": { "type": "array", "items": { "type": "string" }, "description": "Party IDs to act as" },
                    "read_as": { "type": "array", "items": { "type": "string" }, "description": "Party IDs to read as (optional)" },
                    "simulate_first": { "type": "boolean", "default": true, "description": "Simulate command before submitting" }
                },
                "required": ["wallet", "command_type", "template_id", "arguments", "act_as"]
            }
        }),
        serde_json::json!({
            "name": "ows_canton_query",
            "description": "Query active contracts on the Canton ledger. Returns matching contracts visible to the specified parties.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet": { "type": "string", "description": "Wallet name or UUID (determines participant connection)" },
                    "template_id": { "type": "string", "description": "DAML template ID to filter by" },
                    "party": { "type": "string", "description": "Party ID to query as (defaults to wallet's party)" }
                },
                "required": ["wallet", "template_id"]
            }
        }),
        serde_json::json!({
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
        }),
        serde_json::json!({
            "name": "ows_canton_get_balance",
            "description": "Get token balances for a Canton party. Queries Daml.Finance holdings visible to the wallet's party.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet": { "type": "string", "description": "Wallet name or UUID" },
                    "instrument_id": { "type": "string", "description": "Filter by instrument identifier" }
                },
                "required": ["wallet"]
            }
        }),
        serde_json::json!({
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
        }),
        serde_json::json!({
            "name": "ows_canton_register",
            "description": "Register a pending Canton wallet as an External Party on the synchronizer. Use this after creating a wallet in offline mode.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet": { "type": "string", "description": "Wallet name or UUID to register" }
                },
                "required": ["wallet"]
            }
        }),
    ]
}

// ── Tool dispatcher ────────────────────────────────────────────────

/// Dispatch an MCP tool call to the appropriate handler.
pub async fn handle_mcp_tool(
    tool_name: &str,
    arguments: serde_json::Value,
    passphrase: &str,
) -> Result<serde_json::Value, CantonError> {
    match tool_name {
        "ows_canton_create_wallet" => {
            let args: CreateWalletArgs = serde_json::from_value(arguments)?;
            handle_create_wallet(args, passphrase).await
        }
        "ows_canton_list_wallets" => handle_list_wallets().await,
        "ows_canton_submit" => {
            let args: SubmitArgs = serde_json::from_value(arguments)?;
            handle_submit(args, passphrase).await
        }
        "ows_canton_query" => {
            let args: QueryArgs = serde_json::from_value(arguments)?;
            handle_query(args).await
        }
        "ows_canton_simulate" => {
            let args: SimulateArgs = serde_json::from_value(arguments)?;
            handle_simulate_tool(args).await
        }
        "ows_canton_get_balance" => {
            let args: GetBalanceArgs = serde_json::from_value(arguments)?;
            handle_get_balance(args).await
        }
        "ows_canton_list_parties" => {
            let args: ListPartiesArgs = serde_json::from_value(arguments)?;
            handle_list_parties(args).await
        }
        "ows_canton_register" => {
            let args: RegisterArgs = serde_json::from_value(arguments)?;
            handle_register(args, passphrase).await
        }
        _ => Err(CantonError::UnknownTool {
            tool_name: tool_name.to_string(),
        }),
    }
}

// ── Handlers ───────────────────────────────────────────────────────

async fn handle_create_wallet(
    args: CreateWalletArgs,
    passphrase: &str,
) -> Result<serde_json::Value, CantonError> {
    let sync = args.synchronizer.as_deref().unwrap_or("canton:global");
    let chain_id = CantonChainId::parse(sync)?;
    let algorithm = parse_algorithm(args.signing_algorithm.as_deref().unwrap_or("ed25519"))?;

    let ows_home = get_ows_home()?;
    let wallet = create_canton_wallet_in(
        &ows_home,
        &args.name,
        passphrase,
        &chain_id,
        "http://localhost:7575",
        algorithm,
    )?;

    let account = &wallet.accounts[0];
    Ok(serde_json::json!({
        "wallet_id": wallet.id,
        "name": wallet.name,
        "party_id": account.canton.party_id,
        "chain_id": account.chain_id,
        "fingerprint": account.canton.key_fingerprint,
        "algorithm": account.canton.signing_algorithm,
        "registered": account.canton.topology_registered,
    }))
}

async fn handle_list_wallets() -> Result<serde_json::Value, CantonError> {
    let wallets = list_canton_wallets()?;
    let list: Vec<serde_json::Value> = wallets
        .iter()
        .filter_map(|w| {
            let a = w.accounts.first()?;
            Some(serde_json::json!({
                "name": w.name,
                "wallet_id": w.id,
                "party_id": a.canton.party_id,
                "chain_id": a.chain_id,
                "registered": a.canton.topology_registered,
            }))
        })
        .collect();
    Ok(serde_json::Value::Array(list))
}

async fn handle_submit(
    args: SubmitArgs,
    passphrase: &str,
) -> Result<serde_json::Value, CantonError> {
    let wallet = load_canton_wallet(&args.wallet)?;
    let command = build_command_from_mcp_args(
        &args.command_type,
        &args.template_id,
        args.arguments,
        args.choice,
        args.contract_id,
    )?;

    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.as_str())
        .unwrap_or("http://localhost:7575");
    let client = LedgerApiClient::new(participant_url, None);
    let read_as = args.read_as.unwrap_or_default();

    let result = canton_submit_command(
        &wallet,
        passphrase,
        &command,
        &args.act_as,
        &read_as,
        &client,
        None,
    )
    .await?;

    Ok(serde_json::to_value(&result)?)
}

async fn handle_query(args: QueryArgs) -> Result<serde_json::Value, CantonError> {
    let wallet = load_canton_wallet(&args.wallet)?;
    let parties = if let Some(party) = &args.party {
        vec![party.clone()]
    } else if let Some(account) = wallet.accounts.first() {
        vec![account.canton.party_id.clone()]
    } else {
        vec![]
    };

    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.as_str())
        .unwrap_or("http://localhost:7575");
    let client = LedgerApiClient::new(participant_url, None);
    let contracts = canton_query_contracts(&args.template_id, &parties, &client).await?;
    Ok(serde_json::to_value(&contracts)?)
}

async fn handle_simulate_tool(args: SimulateArgs) -> Result<serde_json::Value, CantonError> {
    let wallet = load_canton_wallet(&args.wallet)?;
    let command = build_command_from_mcp_args(
        &args.command_type,
        &args.template_id,
        args.arguments,
        args.choice,
        args.contract_id,
    )?;

    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.as_str())
        .unwrap_or("http://localhost:7575");
    let client = LedgerApiClient::new(participant_url, None);
    let result = canton_simulate(&command, &args.act_as, &[], &client).await?;
    Ok(serde_json::to_value(&result)?)
}

async fn handle_get_balance(args: GetBalanceArgs) -> Result<serde_json::Value, CantonError> {
    // Stub — balance query requires Daml.Finance template knowledge.
    let _wallet = load_canton_wallet(&args.wallet)?;
    Ok(serde_json::json!({
        "status": "not_implemented",
        "message": "Balance query is not yet implemented. Use ows_canton_query with Daml.Finance.Holding templates.",
        "wallet": args.wallet,
        "instrument_id": args.instrument_id,
    }))
}

async fn handle_list_parties(args: ListPartiesArgs) -> Result<serde_json::Value, CantonError> {
    let wallet = load_canton_wallet(&args.wallet)?;
    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.as_str())
        .unwrap_or("http://localhost:7575");
    let client = LedgerApiClient::new(participant_url, None);
    let parties = client.list_parties(args.filter.as_deref()).await?;
    Ok(serde_json::to_value(&parties)?)
}

async fn handle_register(
    args: RegisterArgs,
    passphrase: &str,
) -> Result<serde_json::Value, CantonError> {
    let mut wallet = load_canton_wallet(&args.wallet)?;
    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.clone())
        .unwrap_or_else(|| "http://localhost:7575".to_string());
    let sync_id = wallet
        .canton_config
        .as_ref()
        .map(|c| c.default_synchronizer.clone())
        .unwrap_or_else(|| "canton:global".to_string());

    let client = LedgerApiClient::new(&participant_url, None);
    let ows_home = get_ows_home()?;
    let result =
        register_pending_wallet(&mut wallet, passphrase, &client, &sync_id, &ows_home).await?;

    Ok(serde_json::json!({
        "party_id": result.party_id.to_string(),
        "synchronizer_id": result.synchronizer_id,
        "fingerprint": result.fingerprint,
        "registered": result.topology_registered,
    }))
}

// ── Helpers ────────────────────────────────────────────────────────

/// Build a [`CantonCommand`] from MCP tool arguments.
pub fn build_command_from_mcp_args(
    command_type: &str,
    template_id: &str,
    arguments: serde_json::Value,
    choice: Option<String>,
    contract_id: Option<String>,
) -> Result<CantonCommand, CantonError> {
    let cmd_type = match command_type.to_lowercase().as_str() {
        "create" => CantonCommandType::Create,
        "exercise" => CantonCommandType::Exercise,
        "createandexercise" | "create_and_exercise" => CantonCommandType::CreateAndExercise,
        "exercisebykey" | "exercise_by_key" => CantonCommandType::ExerciseByKey,
        other => {
            return Err(CantonError::ToolArgumentError {
                reason: format!("unknown command type: {other}"),
            })
        }
    };

    Ok(CantonCommand {
        template_id: template_id.to_string(),
        command_type: cmd_type,
        choice,
        contract_id,
        arguments,
    })
}

fn parse_algorithm(s: &str) -> Result<CantonSigningAlgorithm, CantonError> {
    match s.to_lowercase().as_str() {
        "ed25519" => Ok(CantonSigningAlgorithm::Ed25519),
        "secp256k1" | "ecdsa" => Ok(CantonSigningAlgorithm::EcDsaSha256),
        _ => Err(CantonError::UnsupportedAlgorithm {
            algorithm: s.to_string(),
        }),
    }
}

fn get_ows_home() -> Result<std::path::PathBuf, CantonError> {
    if let Ok(home) = std::env::var("OWS_HOME") {
        return Ok(std::path::PathBuf::from(home));
    }
    let home = std::env::var("HOME").map_err(|_| CantonError::IoError {
        reason: "HOME environment variable not set".to_string(),
    })?;
    Ok(std::path::PathBuf::from(home).join(".ows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definitions_count() {
        let defs = get_canton_tool_definitions();
        assert_eq!(defs.len(), 8);
    }

    #[test]
    fn test_tool_definitions_valid() {
        for def in get_canton_tool_definitions() {
            assert!(def["name"].is_string(), "tool missing name");
            assert!(def["description"].is_string(), "tool missing description");
            assert!(def["inputSchema"].is_object(), "tool missing inputSchema");
            assert_eq!(def["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn test_tool_definitions_required_fields() {
        let defs = get_canton_tool_definitions();
        let submit = defs
            .iter()
            .find(|d| d["name"] == "ows_canton_submit")
            .unwrap();
        let required = submit["inputSchema"]["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"wallet"));
        assert!(required_strs.contains(&"command_type"));
        assert!(required_strs.contains(&"template_id"));
        assert!(required_strs.contains(&"arguments"));
        assert!(required_strs.contains(&"act_as"));
    }

    #[tokio::test]
    async fn test_handle_unknown_tool() {
        let err = handle_mcp_tool("nonexistent_tool", serde_json::json!({}), "pass")
            .await
            .unwrap_err();
        assert!(matches!(err, CantonError::UnknownTool { .. }));
        if let CantonError::UnknownTool { tool_name } = err {
            assert_eq!(tool_name, "nonexistent_tool");
        }
    }

    #[test]
    fn test_handle_list_wallets_empty() {
        // list_canton_wallets reads from $OWS_HOME; with a temp dir it's empty.
        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("OWS_HOME", tmpdir.path());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt
            .block_on(handle_mcp_tool(
                "ows_canton_list_wallets",
                serde_json::json!({}),
                "",
            ))
            .unwrap();
        assert!(result.is_array());
        assert!(result.as_array().unwrap().is_empty());
        std::env::remove_var("OWS_HOME");
    }

    #[test]
    fn test_create_wallet_args_deserialize() {
        let json = serde_json::json!({
            "name": "my-wallet",
            "synchronizer": "canton:devnet",
            "signing_algorithm": "ed25519"
        });
        let args: CreateWalletArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.name, "my-wallet");
        assert_eq!(args.synchronizer.as_deref(), Some("canton:devnet"));
        assert_eq!(args.signing_algorithm.as_deref(), Some("ed25519"));
    }

    #[test]
    fn test_submit_args_deserialize() {
        let json = serde_json::json!({
            "wallet": "my-wallet",
            "command_type": "exercise",
            "template_id": "Daml.Finance:Token",
            "arguments": {"to": "bob"},
            "act_as": ["alice::1220abcd"],
            "choice": "Transfer",
            "contract_id": "cid-1",
            "read_as": ["bob::1220ffff"],
            "simulate_first": true
        });
        let args: SubmitArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.wallet, "my-wallet");
        assert_eq!(args.command_type, "exercise");
        assert_eq!(args.template_id, "Daml.Finance:Token");
        assert_eq!(args.choice.as_deref(), Some("Transfer"));
        assert_eq!(args.contract_id.as_deref(), Some("cid-1"));
        assert_eq!(args.act_as, vec!["alice::1220abcd"]);
        assert_eq!(
            args.read_as.as_deref(),
            Some(vec!["bob::1220ffff".to_string()].as_slice())
        );
        assert_eq!(args.simulate_first, Some(true));
    }

    #[test]
    fn test_build_command_from_mcp_args() {
        let cmd = build_command_from_mcp_args(
            "exercise",
            "Daml.Finance:Token",
            serde_json::json!({"to": "bob"}),
            Some("Transfer".to_string()),
            Some("cid-1".to_string()),
        )
        .unwrap();

        assert_eq!(cmd.command_type, CantonCommandType::Exercise);
        assert_eq!(cmd.template_id, "Daml.Finance:Token");
        assert_eq!(cmd.choice.as_deref(), Some("Transfer"));
        assert_eq!(cmd.contract_id.as_deref(), Some("cid-1"));
    }

    #[test]
    fn test_build_command_invalid_type() {
        let err = build_command_from_mcp_args("invalid", "T:T", serde_json::json!({}), None, None)
            .unwrap_err();
        assert!(matches!(err, CantonError::ToolArgumentError { .. }));
    }

    #[test]
    fn test_tool_names_unique() {
        let defs = get_canton_tool_definitions();
        let names: Vec<&str> = defs.iter().map(|d| d["name"].as_str().unwrap()).collect();
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len(), "tool names must be unique");
    }
}
