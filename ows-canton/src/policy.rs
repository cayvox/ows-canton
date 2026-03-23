//! Canton-specific policy rule types and evaluation engine.
//!
//! Enforces pre-signing policies including template allowlists, choice restrictions,
//! party scope limits, simulation requirements, and synchronizer restrictions.
//! All policies are evaluated before any key material is decrypted.
//! See `specs/05-policy-engine.md` for the full specification.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::CantonError;

// ── Command & Simulation types (shared with signing module) ────────

/// Canton DAML command description used for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonCommand {
    /// Fully qualified DAML template identifier (e.g. `"Daml.Finance.Holding.Fungible:Fungible"`).
    pub template_id: String,
    /// Command type.
    pub command_type: CantonCommandType,
    /// Choice name (only present for exercise / createAndExercise commands).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice: Option<String>,
    /// Contract ID (only present for exercise commands).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    /// Command arguments (opaque JSON).
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// Canton command type discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CantonCommandType {
    /// Create a new contract.
    Create,
    /// Exercise a choice on an existing contract.
    Exercise,
    /// Create a contract and immediately exercise a choice on it.
    CreateAndExercise,
    /// Exercise a choice by contract key.
    ExerciseByKey,
}

impl std::fmt::Display for CantonCommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Exercise => write!(f, "exercise"),
            Self::CreateAndExercise => write!(f, "create_and_exercise"),
            Self::ExerciseByKey => write!(f, "exercise_by_key"),
        }
    }
}

/// Result of a DAML command simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Whether the simulation succeeded.
    pub success: bool,
    /// Error message if the simulation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

// ── Policy Context ─────────────────────────────────────────────────

/// Context provided to every policy rule evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct CantonPolicyContext {
    /// The command being evaluated.
    pub command: CantonCommand,
    /// CAIP-2 chain identifier.
    pub chain_id: String,
    /// Wallet UUID.
    pub wallet_id: String,
    /// Wallet human-readable name.
    pub wallet_name: String,
    /// Parties the agent wants to act as.
    pub act_as: Vec<String>,
    /// Parties the agent wants to read as.
    pub read_as: Vec<String>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// API key identifier.
    pub api_key_id: String,
    /// API key human-readable name.
    pub api_key_name: String,
    /// Simulation result (if simulation has been run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_result: Option<SimulationResult>,
}

// ── Policy Result ──────────────────────────────────────────────────

/// Outcome of a policy rule evaluation.
#[derive(Debug, Clone)]
pub enum PolicyResult {
    /// The rule allows the operation.
    Allow,
    /// The rule denies the operation.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
    },
    /// The rule requires simulation before a decision can be made.
    NeedsSimulation,
}

impl PolicyResult {
    /// Returns `true` if this result is [`PolicyResult::Allow`].
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyResult::Allow)
    }

    /// Returns `true` if this result is [`PolicyResult::Deny`].
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyResult::Deny { .. })
    }
}

// ── Policy & Rule types ────────────────────────────────────────────

/// A Canton policy consisting of one or more rules evaluated with AND semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonPolicy {
    /// Unique policy identifier.
    pub id: String,
    /// Human-readable policy name.
    pub name: String,
    /// Policy schema version.
    pub version: u32,
    /// Ordered list of rules. All must allow for the policy to allow.
    pub rules: Vec<CantonPolicyRule>,
}

/// Tagged union of all Canton policy rule types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CantonPolicyRule {
    /// Restrict which DAML templates the agent can interact with.
    CantonTemplateAllowlist(TemplateAllowlistRule),
    /// Restrict which choices can be exercised on specific templates.
    CantonChoiceRestriction(ChoiceRestrictionRule),
    /// Restrict which parties the agent can act as or read as.
    CantonPartyScope(PartyScopeRule),
    /// Require command simulation before signing.
    CantonSimulationRequired(SimulationRequiredRule),
    /// Restrict which synchronizers the agent can target.
    CantonSynchronizerRestriction(SynchronizerRestrictionRule),
    /// Restrict which command types the agent can use.
    CantonCommandTypeRestriction(CommandTypeRestrictionRule),
}

/// Template allowlist rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateAllowlistRule {
    /// List of allowed DAML template identifiers (exact match).
    pub templates: Vec<String>,
}

/// Choice restriction rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChoiceRestrictionRule {
    /// Per-template choice restrictions.
    pub rules: Vec<ChoiceRule>,
}

/// A single template-specific choice restriction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChoiceRule {
    /// Template ID or `"*"` for wildcard.
    pub template: String,
    /// Choices explicitly allowed (empty = no restriction via this list).
    pub allowed_choices: Vec<String>,
    /// Choices explicitly denied (checked before allowed).
    pub denied_choices: Vec<String>,
}

/// Party scope rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyScopeRule {
    /// Parties allowed to act as. `["*"]` = any.
    pub allowed_act_as: Vec<String>,
    /// Parties explicitly denied from acting as (checked first).
    pub denied_act_as: Vec<String>,
    /// Parties allowed to read as. `["*"]` = any.
    pub allowed_read_as: Vec<String>,
    /// Parties explicitly denied from reading as (checked first).
    pub denied_read_as: Vec<String>,
}

/// Simulation requirement rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationRequiredRule {
    /// Whether simulation is required.
    pub require_simulation: bool,
    /// Whether to deny if simulation fails.
    #[serde(default = "default_true")]
    pub fail_on_simulation_error: bool,
    /// Maximum allowed simulation latency in milliseconds.
    #[serde(default)]
    pub max_simulation_latency_ms: u64,
}

/// Synchronizer restriction rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizerRestrictionRule {
    /// Synchronizers explicitly allowed.
    #[serde(default)]
    pub allowed_synchronizers: Vec<String>,
    /// Synchronizers explicitly denied (checked first).
    #[serde(default)]
    pub denied_synchronizers: Vec<String>,
}

/// Command type restriction rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTypeRestrictionRule {
    /// Command types explicitly allowed.
    #[serde(default)]
    pub allowed_types: Vec<String>,
    /// Command types explicitly denied (checked first).
    #[serde(default)]
    pub denied_types: Vec<String>,
}

fn default_true() -> bool {
    true
}

// ── Evaluation ─────────────────────────────────────────────────────

/// Evaluate all rules in a policy with AND semantics.
///
/// Returns [`PolicyResult::Allow`] only if every rule allows.
/// Short-circuits on the first [`PolicyResult::Deny`] or
/// [`PolicyResult::NeedsSimulation`].
pub fn evaluate_canton_policy(
    policy: &CantonPolicy,
    context: &CantonPolicyContext,
) -> PolicyResult {
    for rule in &policy.rules {
        match evaluate_rule(rule, context) {
            PolicyResult::Allow => continue,
            deny_or_sim => return deny_or_sim,
        }
    }
    PolicyResult::Allow
}

/// Dispatch a single rule to its evaluator.
fn evaluate_rule(rule: &CantonPolicyRule, ctx: &CantonPolicyContext) -> PolicyResult {
    match rule {
        CantonPolicyRule::CantonTemplateAllowlist(r) => evaluate_template_allowlist(r, ctx),
        CantonPolicyRule::CantonChoiceRestriction(r) => evaluate_choice_restriction(r, ctx),
        CantonPolicyRule::CantonPartyScope(r) => evaluate_party_scope(r, ctx),
        CantonPolicyRule::CantonSimulationRequired(r) => evaluate_simulation_required(r, ctx),
        CantonPolicyRule::CantonSynchronizerRestriction(r) => {
            evaluate_synchronizer_restriction(r, ctx)
        }
        CantonPolicyRule::CantonCommandTypeRestriction(r) => {
            evaluate_command_type_restriction(r, ctx)
        }
    }
}

/// Evaluate a template allowlist rule.
pub fn evaluate_template_allowlist(
    rule: &TemplateAllowlistRule,
    ctx: &CantonPolicyContext,
) -> PolicyResult {
    if rule.templates.contains(&ctx.command.template_id) {
        PolicyResult::Allow
    } else {
        PolicyResult::Deny {
            reason: format!(
                "template '{}' is not in the allowlist",
                ctx.command.template_id
            ),
        }
    }
}

/// Evaluate a choice restriction rule.
///
/// Only applies to `exercise` and `createAndExercise` commands.
/// For `create` commands, returns [`PolicyResult::Allow`].
pub fn evaluate_choice_restriction(
    rule: &ChoiceRestrictionRule,
    ctx: &CantonPolicyContext,
) -> PolicyResult {
    // Only applies to exercise-type commands.
    if ctx.command.command_type != CantonCommandType::Exercise
        && ctx.command.command_type != CantonCommandType::CreateAndExercise
        && ctx.command.command_type != CantonCommandType::ExerciseByKey
    {
        return PolicyResult::Allow;
    }

    let choice = match &ctx.command.choice {
        Some(c) => c,
        None => return PolicyResult::Allow,
    };

    // Find matching rule: exact template first, then wildcard "*".
    let matching_rule = rule
        .rules
        .iter()
        .find(|r| r.template == ctx.command.template_id)
        .or_else(|| rule.rules.iter().find(|r| r.template == "*"));

    let choice_rule = match matching_rule {
        Some(r) => r,
        None => return PolicyResult::Allow,
    };

    // Denied choices checked first.
    if !choice_rule.denied_choices.is_empty() && choice_rule.denied_choices.contains(choice) {
        return PolicyResult::Deny {
            reason: format!(
                "choice '{choice}' is denied on template '{}'",
                ctx.command.template_id
            ),
        };
    }

    // If allowed_choices is non-empty, the choice must be in it.
    if !choice_rule.allowed_choices.is_empty() && !choice_rule.allowed_choices.contains(choice) {
        return PolicyResult::Deny {
            reason: format!(
                "choice '{choice}' is not in the allowed list for template '{}'",
                ctx.command.template_id
            ),
        };
    }

    PolicyResult::Allow
}

/// Evaluate a party scope rule.
///
/// Denied lists are checked before allowed lists. `"*"` in an allowed
/// list permits any party.
pub fn evaluate_party_scope(rule: &PartyScopeRule, ctx: &CantonPolicyContext) -> PolicyResult {
    // Check act_as parties.
    for party in &ctx.act_as {
        if rule.denied_act_as.contains(party) {
            return PolicyResult::Deny {
                reason: format!("party '{party}' is in the denied act_as list"),
            };
        }
        if !rule.allowed_act_as.contains(&"*".to_string()) && !rule.allowed_act_as.contains(party) {
            return PolicyResult::Deny {
                reason: format!("party '{party}' is not in the allowed act_as list"),
            };
        }
    }

    // Check read_as parties.
    for party in &ctx.read_as {
        if rule.denied_read_as.contains(party) {
            return PolicyResult::Deny {
                reason: format!("party '{party}' is in the denied read_as list"),
            };
        }
        if !rule.allowed_read_as.contains(&"*".to_string()) && !rule.allowed_read_as.contains(party)
        {
            return PolicyResult::Deny {
                reason: format!("party '{party}' is not in the allowed read_as list"),
            };
        }
    }

    PolicyResult::Allow
}

/// Evaluate a simulation requirement rule.
///
/// Returns [`PolicyResult::NeedsSimulation`] if simulation is required
/// but no result is present.
pub fn evaluate_simulation_required(
    rule: &SimulationRequiredRule,
    ctx: &CantonPolicyContext,
) -> PolicyResult {
    if !rule.require_simulation {
        return PolicyResult::Allow;
    }

    match &ctx.simulation_result {
        None => PolicyResult::NeedsSimulation,
        Some(result) => {
            if result.success {
                PolicyResult::Allow
            } else if rule.fail_on_simulation_error {
                PolicyResult::Deny {
                    reason: format!(
                        "simulation failed: {}",
                        result.error_message.as_deref().unwrap_or("unknown error")
                    ),
                }
            } else {
                PolicyResult::Allow
            }
        }
    }
}

/// Evaluate a synchronizer restriction rule.
pub fn evaluate_synchronizer_restriction(
    rule: &SynchronizerRestrictionRule,
    ctx: &CantonPolicyContext,
) -> PolicyResult {
    // Denied checked first.
    if rule.denied_synchronizers.contains(&ctx.chain_id) {
        return PolicyResult::Deny {
            reason: format!("synchronizer '{}' is denied", ctx.chain_id),
        };
    }

    if !rule.allowed_synchronizers.is_empty() && !rule.allowed_synchronizers.contains(&ctx.chain_id)
    {
        return PolicyResult::Deny {
            reason: format!("synchronizer '{}' is not in the allowed list", ctx.chain_id),
        };
    }

    PolicyResult::Allow
}

/// Evaluate a command type restriction rule.
pub fn evaluate_command_type_restriction(
    rule: &CommandTypeRestrictionRule,
    ctx: &CantonPolicyContext,
) -> PolicyResult {
    let cmd_type = ctx.command.command_type.to_string();

    // Denied checked first.
    if rule.denied_types.contains(&cmd_type) {
        return PolicyResult::Deny {
            reason: format!("command type '{cmd_type}' is denied"),
        };
    }

    if !rule.allowed_types.is_empty() && !rule.allowed_types.contains(&cmd_type) {
        return PolicyResult::Deny {
            reason: format!("command type '{cmd_type}' is not in the allowed list"),
        };
    }

    PolicyResult::Allow
}

// ── Policy file I/O ────────────────────────────────────────────────

/// Save a policy to `$OWS_HOME/policies/<id>.json`.
pub fn save_canton_policy(policy: &CantonPolicy) -> Result<(), CantonError> {
    let ows_home = get_ows_home()?;
    save_canton_policy_in(&ows_home, policy)
}

/// Load a policy from `$OWS_HOME/policies/<id>.json`.
pub fn load_canton_policy(policy_id: &str) -> Result<CantonPolicy, CantonError> {
    let ows_home = get_ows_home()?;
    load_canton_policy_in(&ows_home, policy_id)
}

pub(crate) fn save_canton_policy_in(
    ows_home: &Path,
    policy: &CantonPolicy,
) -> Result<(), CantonError> {
    let policies_dir = ows_home.join("policies");
    fs::create_dir_all(&policies_dir)?;
    let path = policies_dir.join(format!("{}.json", policy.id));
    let json = serde_json::to_string_pretty(policy)?;
    fs::write(path, json)?;
    Ok(())
}

pub(crate) fn load_canton_policy_in(
    ows_home: &Path,
    policy_id: &str,
) -> Result<CantonPolicy, CantonError> {
    let path = ows_home.join("policies").join(format!("{policy_id}.json"));
    if !path.exists() {
        return Err(CantonError::InvalidPolicy {
            reason: format!("policy file not found: {policy_id}"),
        });
    }
    let json = fs::read_to_string(path)?;
    let policy: CantonPolicy = serde_json::from_str(&json)?;
    Ok(policy)
}

fn get_ows_home() -> Result<PathBuf, CantonError> {
    if let Ok(home) = std::env::var("OWS_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = std::env::var("HOME").map_err(|_| CantonError::IoError {
        reason: "HOME environment variable not set".to_string(),
    })?;
    Ok(PathBuf::from(home).join(".ows"))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a minimal context for testing.
    fn make_ctx(
        template_id: &str,
        cmd_type: CantonCommandType,
        choice: Option<&str>,
        chain_id: &str,
        act_as: Vec<&str>,
        read_as: Vec<&str>,
    ) -> CantonPolicyContext {
        CantonPolicyContext {
            command: CantonCommand {
                template_id: template_id.to_string(),
                command_type: cmd_type,
                choice: choice.map(String::from),
                contract_id: None,
                arguments: serde_json::Value::Null,
            },
            chain_id: chain_id.to_string(),
            wallet_id: "test-wallet-id".to_string(),
            wallet_name: "test-wallet".to_string(),
            act_as: act_as.into_iter().map(String::from).collect(),
            read_as: read_as.into_iter().map(String::from).collect(),
            timestamp: "2026-03-23T00:00:00Z".to_string(),
            api_key_id: "key-1".to_string(),
            api_key_name: "test-key".to_string(),
            simulation_result: None,
        }
    }

    // ── Template allowlist ─────────────────────────────────────────

    #[test]
    fn test_template_allowlist_allowed() {
        let rule = TemplateAllowlistRule {
            templates: vec![
                "Daml.Finance.Holding.Fungible:Fungible".to_string(),
                "Daml.Finance.Instrument.Token:Instrument".to_string(),
            ],
        };
        let ctx = make_ctx(
            "Daml.Finance.Holding.Fungible:Fungible",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec!["alice::1220abcd"],
            vec![],
        );
        assert!(evaluate_template_allowlist(&rule, &ctx).is_allow());
    }

    #[test]
    fn test_template_allowlist_denied() {
        let rule = TemplateAllowlistRule {
            templates: vec!["Daml.Finance.Holding.Fungible:Fungible".to_string()],
        };
        let ctx = make_ctx(
            "Evil.Template:Steal",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec!["alice::1220abcd"],
            vec![],
        );
        assert!(evaluate_template_allowlist(&rule, &ctx).is_deny());
    }

    // ── Choice restriction ─────────────────────────────────────────

    #[test]
    fn test_choice_restriction_allowed() {
        let rule = ChoiceRestrictionRule {
            rules: vec![ChoiceRule {
                template: "Daml.Finance.Holding.Fungible:Fungible".to_string(),
                allowed_choices: vec!["Transfer".to_string(), "Split".to_string()],
                denied_choices: vec![],
            }],
        };
        let ctx = make_ctx(
            "Daml.Finance.Holding.Fungible:Fungible",
            CantonCommandType::Exercise,
            Some("Transfer"),
            "canton:global",
            vec!["alice::1220abcd"],
            vec![],
        );
        assert!(evaluate_choice_restriction(&rule, &ctx).is_allow());
    }

    #[test]
    fn test_choice_restriction_denied() {
        let rule = ChoiceRestrictionRule {
            rules: vec![ChoiceRule {
                template: "Daml.Finance.Holding.Fungible:Fungible".to_string(),
                allowed_choices: vec!["Transfer".to_string()],
                denied_choices: vec!["Archive".to_string()],
            }],
        };
        let ctx = make_ctx(
            "Daml.Finance.Holding.Fungible:Fungible",
            CantonCommandType::Exercise,
            Some("Archive"),
            "canton:global",
            vec!["alice::1220abcd"],
            vec![],
        );
        assert!(evaluate_choice_restriction(&rule, &ctx).is_deny());
    }

    #[test]
    fn test_choice_restriction_wildcard() {
        let rule = ChoiceRestrictionRule {
            rules: vec![ChoiceRule {
                template: "*".to_string(),
                allowed_choices: vec![],
                denied_choices: vec!["Archive".to_string()],
            }],
        };
        // Denied via wildcard.
        let ctx = make_ctx(
            "Any.Template:Any",
            CantonCommandType::Exercise,
            Some("Archive"),
            "canton:global",
            vec!["alice::1220abcd"],
            vec![],
        );
        assert!(evaluate_choice_restriction(&rule, &ctx).is_deny());

        // Allowed via wildcard (not in denied list).
        let ctx2 = make_ctx(
            "Any.Template:Any",
            CantonCommandType::Exercise,
            Some("Transfer"),
            "canton:global",
            vec!["alice::1220abcd"],
            vec![],
        );
        assert!(evaluate_choice_restriction(&rule, &ctx2).is_allow());
    }

    #[test]
    fn test_choice_restriction_create_cmd() {
        let rule = ChoiceRestrictionRule {
            rules: vec![ChoiceRule {
                template: "*".to_string(),
                allowed_choices: vec![],
                denied_choices: vec!["Archive".to_string()],
            }],
        };
        // Create commands have no choice → rule does not apply.
        let ctx = make_ctx(
            "Daml.Finance.Holding.Fungible:Fungible",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec!["alice::1220abcd"],
            vec![],
        );
        assert!(evaluate_choice_restriction(&rule, &ctx).is_allow());
    }

    // ── Party scope ────────────────────────────────────────────────

    #[test]
    fn test_party_scope_allowed() {
        let rule = PartyScopeRule {
            allowed_act_as: vec!["alice::1220abcd".to_string()],
            denied_act_as: vec![],
            allowed_read_as: vec!["*".to_string()],
            denied_read_as: vec![],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec!["alice::1220abcd"],
            vec!["bob::1220ffff"],
        );
        assert!(evaluate_party_scope(&rule, &ctx).is_allow());
    }

    #[test]
    fn test_party_scope_denied() {
        let rule = PartyScopeRule {
            allowed_act_as: vec!["alice::1220abcd".to_string()],
            denied_act_as: vec![],
            allowed_read_as: vec!["*".to_string()],
            denied_read_as: vec![],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec!["eve::1220eeee"],
            vec![],
        );
        assert!(evaluate_party_scope(&rule, &ctx).is_deny());
    }

    #[test]
    fn test_party_scope_wildcard() {
        let rule = PartyScopeRule {
            allowed_act_as: vec!["*".to_string()],
            denied_act_as: vec![],
            allowed_read_as: vec!["*".to_string()],
            denied_read_as: vec![],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec!["anyone::1220aaaa"],
            vec!["anyone-else::1220bbbb"],
        );
        assert!(evaluate_party_scope(&rule, &ctx).is_allow());
    }

    #[test]
    fn test_party_scope_denied_overrides() {
        let rule = PartyScopeRule {
            allowed_act_as: vec!["*".to_string()],
            denied_act_as: vec!["evil::1220dead".to_string()],
            allowed_read_as: vec!["*".to_string()],
            denied_read_as: vec![],
        };
        // Even though "*" allows all, denied_act_as is checked first.
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec!["evil::1220dead"],
            vec![],
        );
        assert!(evaluate_party_scope(&rule, &ctx).is_deny());
    }

    // ── Simulation required ────────────────────────────────────────

    #[test]
    fn test_simulation_required_missing() {
        let rule = SimulationRequiredRule {
            require_simulation: true,
            fail_on_simulation_error: true,
            max_simulation_latency_ms: 5000,
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        assert!(matches!(
            evaluate_simulation_required(&rule, &ctx),
            PolicyResult::NeedsSimulation
        ));
    }

    #[test]
    fn test_simulation_required_success() {
        let rule = SimulationRequiredRule {
            require_simulation: true,
            fail_on_simulation_error: true,
            max_simulation_latency_ms: 5000,
        };
        let mut ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        ctx.simulation_result = Some(SimulationResult {
            success: true,
            error_message: None,
        });
        assert!(evaluate_simulation_required(&rule, &ctx).is_allow());
    }

    #[test]
    fn test_simulation_required_failure() {
        let rule = SimulationRequiredRule {
            require_simulation: true,
            fail_on_simulation_error: true,
            max_simulation_latency_ms: 5000,
        };
        let mut ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        ctx.simulation_result = Some(SimulationResult {
            success: false,
            error_message: Some("contract not active".to_string()),
        });
        assert!(evaluate_simulation_required(&rule, &ctx).is_deny());
    }

    // ── Synchronizer restriction ───────────────────────────────────

    #[test]
    fn test_synchronizer_allowed() {
        let rule = SynchronizerRestrictionRule {
            allowed_synchronizers: vec!["canton:global".to_string(), "canton:devnet".to_string()],
            denied_synchronizers: vec![],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        assert!(evaluate_synchronizer_restriction(&rule, &ctx).is_allow());
    }

    #[test]
    fn test_synchronizer_denied() {
        let rule = SynchronizerRestrictionRule {
            allowed_synchronizers: vec!["canton:global".to_string()],
            denied_synchronizers: vec![],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:sandbox",
            vec![],
            vec![],
        );
        assert!(evaluate_synchronizer_restriction(&rule, &ctx).is_deny());
    }

    // ── Command type restriction ───────────────────────────────────

    #[test]
    fn test_command_type_allowed() {
        let rule = CommandTypeRestrictionRule {
            allowed_types: vec!["exercise".to_string()],
            denied_types: vec![],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Exercise,
            Some("Transfer"),
            "canton:global",
            vec![],
            vec![],
        );
        assert!(evaluate_command_type_restriction(&rule, &ctx).is_allow());
    }

    #[test]
    fn test_command_type_denied() {
        let rule = CommandTypeRestrictionRule {
            allowed_types: vec![],
            denied_types: vec!["create".to_string()],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        assert!(evaluate_command_type_restriction(&rule, &ctx).is_deny());
    }

    // ── Multi-rule policy evaluation ───────────────────────────────

    #[test]
    fn test_multi_rule_all_pass() {
        let policy = CantonPolicy {
            id: "test".to_string(),
            name: "Test Policy".to_string(),
            version: 1,
            rules: vec![
                CantonPolicyRule::CantonTemplateAllowlist(TemplateAllowlistRule {
                    templates: vec!["T:T".to_string()],
                }),
                CantonPolicyRule::CantonCommandTypeRestriction(CommandTypeRestrictionRule {
                    allowed_types: vec!["create".to_string()],
                    denied_types: vec![],
                }),
            ],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        assert!(evaluate_canton_policy(&policy, &ctx).is_allow());
    }

    #[test]
    fn test_multi_rule_one_fails() {
        let policy = CantonPolicy {
            id: "test".to_string(),
            name: "Test Policy".to_string(),
            version: 1,
            rules: vec![
                CantonPolicyRule::CantonTemplateAllowlist(TemplateAllowlistRule {
                    templates: vec!["T:T".to_string()],
                }),
                CantonPolicyRule::CantonCommandTypeRestriction(CommandTypeRestrictionRule {
                    allowed_types: vec!["exercise".to_string()],
                    denied_types: vec![],
                }),
            ],
        };
        // Template passes but command type fails (create not in allowed).
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        assert!(evaluate_canton_policy(&policy, &ctx).is_deny());
    }

    #[test]
    fn test_empty_policy() {
        let policy = CantonPolicy {
            id: "empty".to_string(),
            name: "Empty".to_string(),
            version: 1,
            rules: vec![],
        };
        let ctx = make_ctx(
            "T:T",
            CantonCommandType::Create,
            None,
            "canton:global",
            vec![],
            vec![],
        );
        // No rules → vacuously true.
        assert!(evaluate_canton_policy(&policy, &ctx).is_allow());
    }

    // ── Serialization / file roundtrip ─────────────────────────────

    #[test]
    fn test_policy_file_roundtrip() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy = CantonPolicy {
            id: "roundtrip-test".to_string(),
            name: "Roundtrip Policy".to_string(),
            version: 1,
            rules: vec![
                CantonPolicyRule::CantonTemplateAllowlist(TemplateAllowlistRule {
                    templates: vec!["TIFA.Receivable:Receivable".to_string()],
                }),
                CantonPolicyRule::CantonChoiceRestriction(ChoiceRestrictionRule {
                    rules: vec![ChoiceRule {
                        template: "TIFA.Receivable:Receivable".to_string(),
                        allowed_choices: vec!["Settle".to_string()],
                        denied_choices: vec!["Archive".to_string()],
                    }],
                }),
                CantonPolicyRule::CantonPartyScope(PartyScopeRule {
                    allowed_act_as: vec!["tifa-agent::1220abcd".to_string()],
                    denied_act_as: vec![],
                    allowed_read_as: vec!["*".to_string()],
                    denied_read_as: vec![],
                }),
                CantonPolicyRule::CantonSimulationRequired(SimulationRequiredRule {
                    require_simulation: true,
                    fail_on_simulation_error: true,
                    max_simulation_latency_ms: 5000,
                }),
                CantonPolicyRule::CantonSynchronizerRestriction(SynchronizerRestrictionRule {
                    allowed_synchronizers: vec!["canton:global".to_string()],
                    denied_synchronizers: vec![],
                }),
                CantonPolicyRule::CantonCommandTypeRestriction(CommandTypeRestrictionRule {
                    allowed_types: vec!["exercise".to_string()],
                    denied_types: vec![],
                }),
            ],
        };

        save_canton_policy_in(tmpdir.path(), &policy).unwrap();
        let loaded = load_canton_policy_in(tmpdir.path(), "roundtrip-test").unwrap();

        assert_eq!(loaded.id, policy.id);
        assert_eq!(loaded.name, policy.name);
        assert_eq!(loaded.version, policy.version);
        assert_eq!(loaded.rules.len(), 6);

        // Verify JSON serde tags are correct.
        let json = serde_json::to_string_pretty(&policy).unwrap();
        assert!(json.contains("canton_template_allowlist"));
        assert!(json.contains("canton_choice_restriction"));
        assert!(json.contains("canton_party_scope"));
        assert!(json.contains("canton_simulation_required"));
        assert!(json.contains("canton_synchronizer_restriction"));
        assert!(json.contains("canton_command_type_restriction"));
    }
}
