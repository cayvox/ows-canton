# Spec 05 — Canton Policy Engine

## Access Model

| Caller | Credential | Policy Evaluation |
|--------|-----------|-------------------|
| Owner | Passphrase | NONE — full sudo access to all wallets |
| Agent | `ows_key_...` token | ALL policies in api_key.policy_ids evaluated. AND semantics — all must allow. |

## Canton Policy Context

Every Canton-specific policy receives this context for evaluation:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct CantonPolicyContext {
    pub command: CantonCommand,
    pub chain_id: String,
    pub wallet_id: String,
    pub wallet_name: String,
    pub act_as: Vec<String>,
    pub read_as: Vec<String>,
    pub timestamp: String,
    pub api_key_id: String,
    pub api_key_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_result: Option<SimulationResult>,
}
```

## Policy Rule Types

### 1. canton_template_allowlist

Restrict which DAML templates the agent can interact with.

```json
{
  "type": "canton_template_allowlist",
  "templates": [
    "Daml.Finance.Holding.Fungible:Fungible",
    "Daml.Finance.Holding.NonFungible:NonFungible",
    "Daml.Finance.Instrument.Token:Instrument"
  ],
  "action": "deny"
}
```

**Evaluation:** If `command.template_id` is NOT in `templates` list → DENY.
**Note:** Template matching is exact string match. Wildcard support (`Daml.Finance.*`) is a future enhancement.

```rust
pub fn evaluate_template_allowlist(
    rule: &TemplateAllowlistRule,
    ctx: &CantonPolicyContext,
) -> PolicyResult {
    if rule.templates.contains(&ctx.command.template_id) {
        PolicyResult::Allow
    } else {
        PolicyResult::Deny {
            reason: format!(
                "Template '{}' is not in the allowlist",
                ctx.command.template_id
            ),
        }
    }
}
```

### 2. canton_choice_restriction

Restrict which choices can be exercised on specific templates.

```json
{
  "type": "canton_choice_restriction",
  "rules": [
    {
      "template": "Daml.Finance.Holding.Fungible:Fungible",
      "allowed_choices": ["Transfer", "Split", "Merge"],
      "denied_choices": []
    },
    {
      "template": "*",
      "allowed_choices": [],
      "denied_choices": ["Archive"]
    }
  ]
}
```

**Evaluation logic:**
1. Find matching template rule (exact match first, then `*` wildcard)
2. If `denied_choices` is non-empty and choice is in it → DENY
3. If `allowed_choices` is non-empty and choice is NOT in it → DENY
4. Otherwise → ALLOW
5. Only applies to `exercise` and `createAndExercise` commands

### 3. canton_party_scope

Restrict which parties the agent can act as or read as.

```json
{
  "type": "canton_party_scope",
  "allowed_act_as": ["agent-treasury::1220a1b2c3d4"],
  "denied_act_as": [],
  "allowed_read_as": ["*"],
  "denied_read_as": []
}
```

**Evaluation:** Check each party in `act_as` and `read_as` against the lists.
- `"*"` in allowed list = allow any party
- Empty allowed list = allow none (deny all)
- Denied list checked before allowed list

### 4. canton_simulation_required

Require successful DAML command simulation before signing.

```json
{
  "type": "canton_simulation_required",
  "require_simulation": true,
  "fail_on_simulation_error": true,
  "max_simulation_latency_ms": 5000
}
```

**Evaluation:** This is a pre-condition policy. If `require_simulation` is true and `ctx.simulation_result` is None → return `PolicyResult::NeedsSimulation`. The calling code must run simulation before re-evaluating.

### 5. canton_synchronizer_restriction

Restrict which synchronizers the agent can target.

```json
{
  "type": "canton_synchronizer_restriction",
  "allowed_synchronizers": ["canton:global", "canton:devnet"],
  "denied_synchronizers": []
}
```

### 6. canton_command_type_restriction

Restrict which command types the agent can use.

```json
{
  "type": "canton_command_type_restriction",
  "allowed_types": ["exercise"],
  "denied_types": ["create"]
}
```

## Policy File Format

Stored in `~/.ows/policies/<policy-id>.json`:

```json
{
  "id": "tifa-agent-policy",
  "name": "TIFA Finance Agent Restrictions",
  "version": 1,
  "rules": [
    {
      "type": "canton_template_allowlist",
      "templates": ["TIFA.Receivable:Receivable", "TIFA.Payment:Payment"]
    },
    {
      "type": "canton_choice_restriction",
      "rules": [
        {
          "template": "TIFA.Receivable:Receivable",
          "allowed_choices": ["Settle", "Query"],
          "denied_choices": ["Archive", "Cancel"]
        }
      ]
    },
    {
      "type": "canton_party_scope",
      "allowed_act_as": ["tifa-agent::1220abcd"],
      "denied_act_as": [],
      "allowed_read_as": ["*"],
      "denied_read_as": []
    },
    {
      "type": "canton_simulation_required",
      "require_simulation": true,
      "fail_on_simulation_error": true,
      "max_simulation_latency_ms": 5000
    }
  ]
}
```

## Rust Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonPolicy {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub rules: Vec<CantonPolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CantonPolicyRule {
    CantonTemplateAllowlist(TemplateAllowlistRule),
    CantonChoiceRestriction(ChoiceRestrictionRule),
    CantonPartyScope(PartyScopeRule),
    CantonSimulationRequired(SimulationRequiredRule),
    CantonSynchronizerRestriction(SynchronizerRestrictionRule),
    CantonCommandTypeRestriction(CommandTypeRestrictionRule),
}

#[derive(Debug, Clone)]
pub enum PolicyResult {
    Allow,
    Deny { reason: String },
    NeedsSimulation,
}

/// Evaluate all rules in a policy. AND semantics — all must allow.
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
```

## Unit Tests Required

```
test_template_allowlist_allowed       → template in list → Allow
test_template_allowlist_denied        → template not in list → Deny
test_choice_restriction_allowed       → allowed choice → Allow
test_choice_restriction_denied        → denied choice → Deny
test_choice_restriction_wildcard      → "*" template matches all
test_choice_restriction_create_cmd    → create command → Allow (no choice to check)
test_party_scope_allowed              → act_as in allowed list → Allow
test_party_scope_denied               → act_as not in allowed list → Deny
test_party_scope_wildcard             → "*" allows any party
test_party_scope_denied_overrides     → denied list checked first
test_simulation_required_missing      → no simulation result → NeedsSimulation
test_simulation_required_success      → simulation passed → Allow
test_simulation_required_failure      → simulation failed → Deny
test_synchronizer_allowed             → chain_id in allowed list → Allow
test_synchronizer_denied              → chain_id not in allowed list → Deny
test_command_type_allowed             → exercise allowed → Allow
test_command_type_denied              → create denied → Deny
test_multi_rule_all_pass              → all rules pass → Allow
test_multi_rule_one_fails             → one rule fails → Deny (first failure)
test_policy_file_roundtrip            → serialize → deserialize → same policy
test_empty_policy                     → no rules → Allow (vacuously true)
```
