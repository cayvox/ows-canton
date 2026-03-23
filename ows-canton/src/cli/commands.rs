//! Canton-specific CLI subcommand definitions and handlers.
//!
//! Implements the `create`, `list`, `info`, `register`, `submit`, `query`,
//! `simulate`, and `parties` subcommands with proper argument parsing,
//! passphrase prompting, and formatted output.

use clap::{Args, Parser, Subcommand};

use crate::identifier::CantonChainId;
use crate::keygen::CantonSigningAlgorithm;
use crate::ledger_api::client::LedgerApiClient;
use crate::onboarding::register_pending_wallet;
use crate::policy::{CantonCommand, CantonCommandType};
use crate::signing::{canton_query_contracts, canton_simulate, canton_submit_command};
use crate::wallet::{
    create_canton_wallet_in, list_canton_wallets, load_canton_wallet, CantonWalletFile,
};
use crate::CantonError;

/// Default participant URL.
const DEFAULT_PARTICIPANT_URL: &str = "http://localhost:7575";

// ── CLI structure ──────────────────────────────────────────────────

/// Canton Network wallet operations.
#[derive(Parser)]
#[command(name = "canton", about = "Canton Network wallet operations")]
pub struct CantonCli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: CantonSubcommand,
}

/// Available Canton subcommands.
#[derive(Subcommand)]
pub enum CantonSubcommand {
    /// Create a new Canton wallet and External Party.
    Create(CreateArgs),
    /// List Canton wallets in the vault.
    List(ListArgs),
    /// Show wallet details.
    Info(InfoArgs),
    /// Register a pending wallet on a synchronizer.
    Register(RegisterArgs),
    /// Submit a signed DAML command.
    Submit(SubmitArgs),
    /// Query active contracts.
    Query(QueryArgs),
    /// Simulate a DAML command without committing.
    Simulate(SimulateArgs),
    /// List parties on the synchronizer.
    Parties(PartiesArgs),
}

/// Arguments for `canton create`.
#[derive(Args)]
pub struct CreateArgs {
    /// Wallet name (used as Canton party hint).
    #[arg(long)]
    pub name: String,
    /// Target synchronizer.
    #[arg(long, default_value = "canton:global")]
    pub synchronizer: String,
    /// Ledger API URL.
    #[arg(long)]
    pub participant_url: Option<String>,
    /// Signing algorithm: ed25519 | secp256k1.
    #[arg(long, default_value = "ed25519")]
    pub algorithm: String,
    /// Create key without registering on Canton.
    #[arg(long)]
    pub offline: bool,
    /// Vault passphrase (prompts if not provided).
    #[arg(long)]
    pub passphrase: Option<String>,
}

/// Arguments for `canton list`.
#[derive(Args)]
pub struct ListArgs {}

/// Arguments for `canton info`.
#[derive(Args)]
pub struct InfoArgs {
    /// Wallet name or ID.
    #[arg(long)]
    pub wallet: String,
}

/// Arguments for `canton register`.
#[derive(Args)]
pub struct RegisterArgs {
    /// Wallet name or ID.
    #[arg(long)]
    pub wallet: String,
    /// Vault passphrase (prompts if not provided).
    #[arg(long)]
    pub passphrase: Option<String>,
}

/// Arguments for `canton submit`.
#[derive(Args)]
pub struct SubmitArgs {
    /// Wallet name or ID.
    #[arg(long)]
    pub wallet: String,
    /// Command type: create | exercise.
    #[arg(long, rename_all = "snake_case")]
    pub r#type: String,
    /// Fully qualified DAML template ID.
    #[arg(long)]
    pub template: String,
    /// Choice name (for exercise commands).
    #[arg(long)]
    pub choice: Option<String>,
    /// Contract ID (for exercise commands).
    #[arg(long)]
    pub contract_id: Option<String>,
    /// Command arguments as JSON string.
    #[arg(long)]
    pub arguments: String,
    /// Party to act as (repeatable).
    #[arg(long)]
    pub act_as: Vec<String>,
    /// Party to read as (repeatable).
    #[arg(long)]
    pub read_as: Vec<String>,
    /// Skip pre-submission simulation.
    #[arg(long)]
    pub no_simulate: bool,
    /// Vault passphrase (prompts if not provided).
    #[arg(long)]
    pub passphrase: Option<String>,
}

/// Arguments for `canton query`.
#[derive(Args)]
pub struct QueryArgs {
    /// Wallet name or ID.
    #[arg(long)]
    pub wallet: String,
    /// DAML template ID to filter by.
    #[arg(long)]
    pub template: String,
    /// Party to query as (uses wallet party if not specified).
    #[arg(long)]
    pub party: Option<String>,
}

/// Arguments for `canton simulate`.
#[derive(Args)]
pub struct SimulateArgs {
    /// Wallet name or ID.
    #[arg(long)]
    pub wallet: String,
    /// Command type: create | exercise.
    #[arg(long)]
    pub r#type: String,
    /// Fully qualified DAML template ID.
    #[arg(long)]
    pub template: String,
    /// Choice name (for exercise commands).
    #[arg(long)]
    pub choice: Option<String>,
    /// Contract ID (for exercise commands).
    #[arg(long)]
    pub contract_id: Option<String>,
    /// Command arguments as JSON string.
    #[arg(long)]
    pub arguments: String,
    /// Party to act as (repeatable).
    #[arg(long)]
    pub act_as: Vec<String>,
}

/// Arguments for `canton parties`.
#[derive(Args)]
pub struct PartiesArgs {
    /// Wallet name or ID.
    #[arg(long)]
    pub wallet: String,
    /// Filter parties by string.
    #[arg(long)]
    pub filter: Option<String>,
}

// ── Executor ───────────────────────────────────────────────────────

/// Execute a Canton CLI subcommand.
pub async fn execute_canton_command(cmd: CantonSubcommand) -> Result<(), CantonError> {
    match cmd {
        CantonSubcommand::Create(args) => handle_create(args).await,
        CantonSubcommand::List(_) => handle_list().await,
        CantonSubcommand::Info(args) => handle_info(args).await,
        CantonSubcommand::Register(args) => handle_register(args).await,
        CantonSubcommand::Submit(args) => handle_submit(args).await,
        CantonSubcommand::Query(args) => handle_query(args).await,
        CantonSubcommand::Simulate(args) => handle_simulate(args).await,
        CantonSubcommand::Parties(args) => handle_parties(args).await,
    }
}

// ── Handlers ───────────────────────────────────────────────────────

async fn handle_create(args: CreateArgs) -> Result<(), CantonError> {
    let passphrase = get_passphrase(&args.passphrase)?;
    let chain_id = CantonChainId::parse(&args.synchronizer)?;
    let algorithm = parse_algorithm(&args.algorithm)?;
    let participant_url = args
        .participant_url
        .as_deref()
        .unwrap_or(DEFAULT_PARTICIPANT_URL);

    let ows_home = get_ows_home()?;
    let wallet = create_canton_wallet_in(
        &ows_home,
        &args.name,
        &passphrase,
        &chain_id,
        participant_url,
        algorithm,
    )?;

    // Try onboarding if not offline.
    let registered = if !args.offline {
        let client = LedgerApiClient::new(participant_url, None);
        match try_onboard(&wallet, &passphrase, &client, &ows_home).await {
            Ok(_) => true,
            Err(e) => {
                println!("Warning: Could not register on Canton: {e}");
                println!(
                    "Run `canton register --wallet {}` when participant is available.",
                    args.name
                );
                false
            }
        }
    } else {
        false
    };

    let account = &wallet.accounts[0];
    println!("Created wallet: {}", wallet.name);
    println!("  Wallet ID:    {}", wallet.id);
    println!("  Party ID:     {}", account.canton.party_id);
    println!("  Chain ID:     {}", account.chain_id);
    println!("  Fingerprint:  {}", account.canton.key_fingerprint);
    println!("  Algorithm:    {}", account.canton.signing_algorithm);
    println!("  Registered:   {registered}");
    println!("  Derivation:   {}", account.derivation_path);
    Ok(())
}

async fn handle_list() -> Result<(), CantonError> {
    let wallets = list_canton_wallets()?;

    if wallets.is_empty() {
        println!("No Canton wallets found.");
        return Ok(());
    }

    println!("Canton Wallets ({} found):\n", wallets.len());
    println!(
        "  {:<20} {:<40} {:<16} REGISTERED",
        "NAME", "PARTY ID", "CHAIN"
    );
    for w in &wallets {
        if let Some(account) = w.accounts.first() {
            let reg = if account.canton.topology_registered {
                "yes"
            } else {
                "pending"
            };
            println!(
                "  {:<20} {:<40} {:<16} {}",
                w.name, account.canton.party_id, account.chain_id, reg
            );
        }
    }
    Ok(())
}

async fn handle_info(args: InfoArgs) -> Result<(), CantonError> {
    let wallet = load_canton_wallet(&args.wallet)?;
    let account = wallet
        .accounts
        .first()
        .ok_or_else(|| CantonError::InvalidWalletFile {
            reason: "wallet has no accounts".to_string(),
        })?;

    println!("Wallet: {}", wallet.name);
    println!("  ID:               {}", wallet.id);
    println!("  Party ID:         {}", account.canton.party_id);
    println!("  Account ID:       {}", account.account_id);
    println!("  Chain ID:         {}", account.chain_id);
    println!("  Fingerprint:      {}", account.canton.key_fingerprint);
    println!("  Algorithm:        {}", account.canton.signing_algorithm);
    println!("  Key Format:       {}", account.canton.key_format);
    println!("  Party Type:       {:?}", account.canton.party_type);
    println!("  Registered:       {}", account.canton.topology_registered);
    println!("  Participant:      {}", account.canton.participant_host);
    println!(
        "  Synchronizer:     {}",
        account
            .canton
            .synchronizer_id
            .as_deref()
            .unwrap_or("(none)")
    );
    println!("  Derivation:       {}", account.derivation_path);
    println!("  Created:          {}", wallet.created_at);
    Ok(())
}

async fn handle_register(args: RegisterArgs) -> Result<(), CantonError> {
    let passphrase = get_passphrase(&args.passphrase)?;
    let mut wallet = load_canton_wallet(&args.wallet)?;

    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.clone())
        .unwrap_or_else(|| DEFAULT_PARTICIPANT_URL.to_string());

    let sync_id = wallet
        .canton_config
        .as_ref()
        .map(|c| c.default_synchronizer.clone())
        .unwrap_or_else(|| "canton:global".to_string());

    let client = LedgerApiClient::new(&participant_url, None);
    let ows_home = get_ows_home()?;

    let result =
        register_pending_wallet(&mut wallet, &passphrase, &client, &sync_id, &ows_home).await?;

    println!("Wallet registered successfully");
    println!("  Party ID:     {}", result.party_id);
    println!("  Synchronizer: {}", result.synchronizer_id);
    println!("  Fingerprint:  {}", result.fingerprint);
    Ok(())
}

async fn handle_submit(args: SubmitArgs) -> Result<(), CantonError> {
    let passphrase = get_passphrase(&args.passphrase)?;
    let wallet = load_canton_wallet(&args.wallet)?;

    let command = build_command_from_args(
        &args.r#type,
        &args.template,
        args.choice.as_deref(),
        args.contract_id.as_deref(),
        &args.arguments,
    )?;

    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.clone())
        .unwrap_or_else(|| DEFAULT_PARTICIPANT_URL.to_string());

    let client = LedgerApiClient::new(&participant_url, None);
    let ows_home = get_ows_home()?;

    let result = canton_submit_command(
        &wallet,
        &passphrase,
        &command,
        &args.act_as,
        &args.read_as,
        &client,
        Some(&ows_home),
    )
    .await?;

    println!("Command submitted successfully");
    println!("  Command ID:    {}", result.command_id);
    println!("  Status:        {}", format_status(&result.status));
    if let Some(offset) = &result.completion_offset {
        println!("  Offset:        {offset}");
    }
    if let Some(tx_id) = &result.transaction_id {
        println!("  Transaction:   {tx_id}");
    }
    Ok(())
}

async fn handle_query(args: QueryArgs) -> Result<(), CantonError> {
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
        .map(|c| c.participant_url.clone())
        .unwrap_or_else(|| DEFAULT_PARTICIPANT_URL.to_string());

    let client = LedgerApiClient::new(&participant_url, None);
    let contracts = canton_query_contracts(&args.template, &parties, &client).await?;

    let json = serde_json::to_string_pretty(&contracts)?;
    println!("{json}");
    Ok(())
}

async fn handle_simulate(args: SimulateArgs) -> Result<(), CantonError> {
    let command = build_command_from_args(
        &args.r#type,
        &args.template,
        args.choice.as_deref(),
        args.contract_id.as_deref(),
        &args.arguments,
    )?;

    let wallet = load_canton_wallet(&args.wallet)?;
    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.clone())
        .unwrap_or_else(|| DEFAULT_PARTICIPANT_URL.to_string());

    let client = LedgerApiClient::new(&participant_url, None);
    let result = canton_simulate(&command, &args.act_as, &[], &client).await?;

    if result.success {
        println!("Simulation result: SUCCESS");
    } else {
        println!(
            "Simulation result: FAILED — {}",
            result.error_message.as_deref().unwrap_or("unknown error")
        );
    }
    Ok(())
}

async fn handle_parties(args: PartiesArgs) -> Result<(), CantonError> {
    let wallet = load_canton_wallet(&args.wallet)?;
    let participant_url = wallet
        .canton_config
        .as_ref()
        .map(|c| c.participant_url.clone())
        .unwrap_or_else(|| DEFAULT_PARTICIPANT_URL.to_string());

    let client = LedgerApiClient::new(&participant_url, None);
    let parties = client.list_parties(args.filter.as_deref()).await?;

    let chain_id = wallet
        .accounts
        .first()
        .map(|a| a.chain_id.as_str())
        .unwrap_or("canton:global");

    println!("Parties on {chain_id}:\n");
    println!("  {:<40} {:<8} PERMISSIONS", "PARTY ID", "LOCAL");
    for p in &parties {
        println!(
            "  {:<40} {:<8} {:?}",
            p.party, p.is_local, p.participant_permissions
        );
    }
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────

/// Get passphrase from CLI argument or interactive prompt.
pub fn get_passphrase(passphrase_arg: &Option<String>) -> Result<String, CantonError> {
    if let Some(p) = passphrase_arg {
        return Ok(p.clone());
    }
    rpassword::read_password_from_tty(Some("Enter vault passphrase: ")).map_err(|e| {
        CantonError::IoError {
            reason: format!("failed to read passphrase: {e}"),
        }
    })
}

/// Parse a signing algorithm string.
fn parse_algorithm(s: &str) -> Result<CantonSigningAlgorithm, CantonError> {
    match s.to_lowercase().as_str() {
        "ed25519" => Ok(CantonSigningAlgorithm::Ed25519),
        "secp256k1" | "ecdsa" => Ok(CantonSigningAlgorithm::EcDsaSha256),
        _ => Err(CantonError::UnsupportedAlgorithm {
            algorithm: s.to_string(),
        }),
    }
}

/// Build a `CantonCommand` from CLI arguments.
fn build_command_from_args(
    cmd_type: &str,
    template: &str,
    choice: Option<&str>,
    contract_id: Option<&str>,
    arguments_json: &str,
) -> Result<CantonCommand, CantonError> {
    let command_type = match cmd_type.to_lowercase().as_str() {
        "create" => CantonCommandType::Create,
        "exercise" => CantonCommandType::Exercise,
        "create_and_exercise" | "createandexercise" => CantonCommandType::CreateAndExercise,
        "exercise_by_key" | "exercisebykey" => CantonCommandType::ExerciseByKey,
        _ => {
            return Err(CantonError::InvalidWalletFile {
                reason: format!("unknown command type: {cmd_type}"),
            });
        }
    };

    let arguments: serde_json::Value =
        serde_json::from_str(arguments_json).map_err(|e| CantonError::SerializationError {
            reason: format!("invalid JSON arguments: {e}"),
        })?;

    Ok(CantonCommand {
        template_id: template.to_string(),
        command_type,
        choice: choice.map(String::from),
        contract_id: contract_id.map(String::from),
        arguments,
    })
}

/// Format a command status for display.
fn format_status(status: &crate::signing::CantonCommandStatus) -> String {
    match status {
        crate::signing::CantonCommandStatus::Succeeded => "SUCCEEDED".to_string(),
        crate::signing::CantonCommandStatus::Failed { reason } => {
            format!("FAILED: {reason}")
        }
        crate::signing::CantonCommandStatus::Timeout => "TIMEOUT".to_string(),
    }
}

/// Try to onboard a wallet, returning whether it succeeded.
async fn try_onboard(
    wallet: &CantonWalletFile,
    passphrase: &str,
    client: &LedgerApiClient,
    ows_home: &std::path::Path,
) -> Result<(), CantonError> {
    let mut wallet_mut = wallet.clone();
    let sync_id = wallet
        .canton_config
        .as_ref()
        .map(|c| c.default_synchronizer.clone())
        .unwrap_or_else(|| "canton:global".to_string());

    register_pending_wallet(&mut wallet_mut, passphrase, client, &sync_id, ows_home).await?;
    Ok(())
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
    fn test_create_args_parsing() {
        let cli = CantonCli::try_parse_from([
            "canton",
            "create",
            "--name",
            "my-wallet",
            "--synchronizer",
            "canton:devnet",
            "--algorithm",
            "ed25519",
            "--offline",
        ])
        .unwrap();

        match cli.command {
            CantonSubcommand::Create(args) => {
                assert_eq!(args.name, "my-wallet");
                assert_eq!(args.synchronizer, "canton:devnet");
                assert_eq!(args.algorithm, "ed25519");
                assert!(args.offline);
                assert!(args.passphrase.is_none());
                assert!(args.participant_url.is_none());
            }
            _ => panic!("expected Create subcommand"),
        }
    }

    #[test]
    fn test_submit_args_parsing() {
        let cli = CantonCli::try_parse_from([
            "canton",
            "submit",
            "--wallet",
            "my-wallet",
            "--type",
            "exercise",
            "--template",
            "Daml.Finance:Token",
            "--choice",
            "Transfer",
            "--contract-id",
            "00abc",
            "--arguments",
            r#"{"newOwner": "bob"}"#,
            "--act-as",
            "alice::1220abcd",
            "--read-as",
            "bob::1220ffff",
            "--no-simulate",
        ])
        .unwrap();

        match cli.command {
            CantonSubcommand::Submit(args) => {
                assert_eq!(args.wallet, "my-wallet");
                assert_eq!(args.r#type, "exercise");
                assert_eq!(args.template, "Daml.Finance:Token");
                assert_eq!(args.choice.as_deref(), Some("Transfer"));
                assert_eq!(args.contract_id.as_deref(), Some("00abc"));
                assert_eq!(args.arguments, r#"{"newOwner": "bob"}"#);
                assert_eq!(args.act_as, vec!["alice::1220abcd"]);
                assert_eq!(args.read_as, vec!["bob::1220ffff"]);
                assert!(args.no_simulate);
            }
            _ => panic!("expected Submit subcommand"),
        }
    }

    #[test]
    fn test_get_passphrase_from_arg() {
        let result = get_passphrase(&Some("my-long-passphrase".to_string())).unwrap();
        assert_eq!(result, "my-long-passphrase");
    }

    #[test]
    fn test_parse_algorithm_ed25519() {
        let algo = parse_algorithm("ed25519").unwrap();
        assert_eq!(algo, CantonSigningAlgorithm::Ed25519);
    }

    #[test]
    fn test_parse_algorithm_unknown() {
        let err = parse_algorithm("rsa").unwrap_err();
        assert!(matches!(err, CantonError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn test_build_command_create() {
        let cmd = build_command_from_args(
            "create",
            "Daml.Finance:Token",
            None,
            None,
            r#"{"name": "test"}"#,
        )
        .unwrap();

        assert_eq!(cmd.command_type, CantonCommandType::Create);
        assert_eq!(cmd.template_id, "Daml.Finance:Token");
        assert!(cmd.choice.is_none());
    }

    #[test]
    fn test_build_command_exercise() {
        let cmd = build_command_from_args(
            "exercise",
            "Daml.Finance:Token",
            Some("Transfer"),
            Some("cid-001"),
            r#"{"to": "bob"}"#,
        )
        .unwrap();

        assert_eq!(cmd.command_type, CantonCommandType::Exercise);
        assert_eq!(cmd.choice.as_deref(), Some("Transfer"));
        assert_eq!(cmd.contract_id.as_deref(), Some("cid-001"));
    }

    #[test]
    fn test_build_command_invalid_json() {
        let err = build_command_from_args("create", "T:T", None, None, "not-json").unwrap_err();
        assert!(matches!(err, CantonError::SerializationError { .. }));
    }

    #[test]
    fn test_list_args_parsing() {
        let cli = CantonCli::try_parse_from(["canton", "list"]).unwrap();
        assert!(matches!(cli.command, CantonSubcommand::List(_)));
    }

    #[test]
    fn test_info_args_parsing() {
        let cli = CantonCli::try_parse_from(["canton", "info", "--wallet", "my-wallet"]).unwrap();
        match cli.command {
            CantonSubcommand::Info(args) => assert_eq!(args.wallet, "my-wallet"),
            _ => panic!("expected Info subcommand"),
        }
    }

    #[test]
    fn test_parties_args_parsing() {
        let cli = CantonCli::try_parse_from([
            "canton",
            "parties",
            "--wallet",
            "my-wallet",
            "--filter",
            "alice",
        ])
        .unwrap();
        match cli.command {
            CantonSubcommand::Parties(args) => {
                assert_eq!(args.wallet, "my-wallet");
                assert_eq!(args.filter.as_deref(), Some("alice"));
            }
            _ => panic!("expected Parties subcommand"),
        }
    }

    #[test]
    fn test_format_status() {
        assert_eq!(
            format_status(&crate::signing::CantonCommandStatus::Succeeded),
            "SUCCEEDED"
        );
        assert_eq!(
            format_status(&crate::signing::CantonCommandStatus::Timeout),
            "TIMEOUT"
        );
        assert!(format_status(&crate::signing::CantonCommandStatus::Failed {
            reason: "oops".to_string()
        })
        .contains("FAILED"));
    }
}
