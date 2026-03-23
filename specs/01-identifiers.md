# Spec 01 — Canton Identifier Scheme

## CAIP-2 Chain Identifier

### Namespace: `canton`

Canton Network does not have a registered CAIP-2 namespace. We define the `canton` namespace.

```
Format:    canton:<reference>
Regex:     ^canton:[-_a-zA-Z0-9]{1,32}$
```

### Canonical Chain IDs

| CAIP-2 ID | Network | Usage |
|-----------|---------|-------|
| `canton:global` | Canton Global Synchronizer | Production mainnet |
| `canton:devnet` | Canton Devnet | Shared dev environment |
| `canton:sandbox` | Local Sandbox | Local development (Docker) |
| `canton:<sync_alias>` | Custom Synchronizer | Any synchronizer by alias |

### Resolution Method

To resolve a `canton:<reference>` identifier, query the participant node:

```
GET {participant_url}/v2/state/connected-synchronizers

Response:
{
  "connectedSynchronizers": [
    {
      "synchronizerId": "canton::12207a2f1b3c4d5e6f7a8b9c",
      "alias": "global"
    }
  ]
}
```

The `alias` field maps to the CAIP-2 reference. If no alias matches, fall back to matching the synchronizerId directly.

### Rust Types

```rust
/// CAIP-2 Canton chain identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CantonChainId {
    /// Always "canton"
    pub namespace: String,
    /// Synchronizer reference (e.g., "global", "devnet", "sandbox")
    pub reference: String,
}

impl CantonChainId {
    pub const GLOBAL: &'static str = "canton:global";
    pub const DEVNET: &'static str = "canton:devnet";
    pub const SANDBOX: &'static str = "canton:sandbox";

    /// Parse from CAIP-2 string
    pub fn parse(s: &str) -> Result<Self, CantonError> { ... }

    /// Format as CAIP-2 string
    pub fn to_caip2(&self) -> String {
        format!("{}:{}", self.namespace, self.reference)
    }
}

impl FromStr for CantonChainId { ... }
impl Display for CantonChainId { ... }
```

### Validation Rules

1. Namespace MUST be exactly `"canton"`
2. Reference MUST match `[-_a-zA-Z0-9]{1,32}`
3. Reference MUST NOT be empty
4. The string `"canton:"` alone is invalid

## CAIP-10 Account Identifier

### Format

```
Format:    canton:<reference>:<party_id>
Example:   canton:global:alice::1220a1b2c3d4e5f6
```

Canton party IDs have the format `<hint>::<namespace_fingerprint>`. The `::` separator is part of the party ID, not the CAIP-10 structure.

### Rust Types

```rust
/// CAIP-10 Canton account identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CantonAccountId {
    pub chain_id: CantonChainId,
    /// Full Canton party ID (e.g., "alice::1220a1b2c3d4e5f6")
    pub party_id: CantonPartyId,
}

/// Canton party identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CantonPartyId {
    /// Human-readable hint (e.g., "alice", "agent-treasury")
    pub hint: String,
    /// Namespace fingerprint — hex-encoded SHA-256 prefix of public key
    pub fingerprint: String,
}

impl CantonAccountId {
    /// Parse from CAIP-10 string
    pub fn parse(s: &str) -> Result<Self, CantonError> { ... }

    /// Format as CAIP-10 string
    pub fn to_caip10(&self) -> String {
        format!("{}:{}", self.chain_id.to_caip2(), self.party_id)
    }
}

impl CantonPartyId {
    /// Parse from Canton party ID string (e.g., "alice::1220abcd")
    pub fn parse(s: &str) -> Result<Self, CantonError> { ... }

    /// Format as Canton party ID
    pub fn to_string(&self) -> String {
        format!("{}::{}", self.hint, self.fingerprint)
    }
}
```

### Validation Rules

1. Chain ID portion MUST be a valid CantonChainId
2. Party ID MUST contain exactly one `::` separator
3. Hint (before `::`) MUST match `[a-zA-Z0-9_-]{1,64}`
4. Fingerprint (after `::`) MUST be lowercase hex, 8-64 characters
5. Empty hint or empty fingerprint is invalid

## Unit Tests Required

```
test_caip2_parse_global           → CantonChainId::parse("canton:global") == Ok
test_caip2_parse_devnet           → CantonChainId::parse("canton:devnet") == Ok
test_caip2_parse_custom           → CantonChainId::parse("canton:my-sync") == Ok
test_caip2_parse_invalid_ns       → CantonChainId::parse("eip155:1") == Err
test_caip2_parse_empty_ref        → CantonChainId::parse("canton:") == Err
test_caip2_parse_too_long         → CantonChainId::parse("canton:a{33}") == Err
test_caip2_parse_invalid_chars    → CantonChainId::parse("canton:foo bar") == Err
test_caip2_roundtrip              → parse(id.to_caip2()) == id

test_caip10_parse_full            → CantonAccountId::parse("canton:global:alice::1220abcd") == Ok
test_caip10_parse_long_hint       → CantonAccountId::parse("canton:devnet:agent-treasury::1220abcd") == Ok
test_caip10_parse_missing_party   → CantonAccountId::parse("canton:global:") == Err
test_caip10_parse_no_separator    → CantonAccountId::parse("canton:global:alice1220abcd") == Err
test_caip10_roundtrip             → parse(id.to_caip10()) == id

test_party_id_parse_valid         → CantonPartyId::parse("alice::1220abcd") == Ok
test_party_id_parse_no_hint       → CantonPartyId::parse("::1220abcd") == Err
test_party_id_parse_no_fp         → CantonPartyId::parse("alice::") == Err
```
