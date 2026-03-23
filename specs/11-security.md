# Spec 11 — Security Model

## Security Invariants

These invariants MUST hold at all times. Any violation is a critical bug.

### INV-1: Key Isolation
Private key bytes MUST NOT exist outside the signing function scope. After signing, all key material (mnemonic, seed, private key, derived key) MUST be zeroized.

### INV-2: Policy Before Decryption
In agent mode, ALL policies MUST be evaluated BEFORE any key material is decrypted. If any policy denies, the function MUST return error without touching key material.

### INV-3: Encrypted at Rest
All private key material in `~/.ows/wallets/` and `~/.ows/keys/` MUST be encrypted with AES-256-GCM. Plaintext private keys MUST NEVER be written to disk.

### INV-4: File Permissions
Wallet files: 0600. Key files: 0600. Wallet directory: 0700. Keys directory: 0700. Implementations MUST verify permissions on startup and refuse to operate if world-readable.

### INV-5: No Key Logging
Private keys, mnemonics, seeds, and derived encryption keys MUST NOT appear in log output, error messages, debug format output, or audit logs at any log level.

### INV-6: Audit Completeness
Every signing operation MUST be recorded in the audit log BEFORE the result is returned to the caller.

## Threat Model

| # | Threat | Attacker | Mitigation | Severity |
|---|--------|----------|------------|----------|
| T1 | Agent extracts private key from MCP response | Malicious AI agent | Key never exposed to agent. MCP tools return signatures only. | CRITICAL |
| T2 | LLM prompt injection triggers unauthorized signing | Prompt injection via agent | Policy engine evaluates before key decryption. Template allowlist restricts operations. | HIGH |
| T3 | Malicious DAML command drains wallet | Compromised agent | Template allowlist + choice restriction + spending limit policies | HIGH |
| T4 | Agent impersonates another party | Compromised agent | Party scope policy restricts act_as permissions | HIGH |
| T5 | API key stolen, attacker signs from another machine | Network attacker | API key file has encrypted mnemonic — need both token AND file access. Without file, token is useless. | MEDIUM |
| T6 | Local file read — attacker reads vault | Same-user process | AES-256-GCM + scrypt(N=65536). Encrypted at rest. | MEDIUM |
| T7 | Token + disk access | Privileged attacker | Can decrypt, but must bypass OWS process. Spending limits still apply if API key has policies. | MEDIUM |
| T8 | Replay of signed Canton command | Network attacker | Canton protocol includes nonces and sequencer authentication. OWS doesn't need to handle this — Canton handles it. | LOW |
| T9 | Memory dump reveals key material | Root attacker | Zeroize after use. Future: mlock() support. | LOW |
| T10 | Audit log tampering | Local attacker | Append-only log. File permissions 0600. Future: signed log entries. | LOW |

## Passphrase Security

- Minimum 12 characters, enforced at creation
- `OWS_PASSPHRASE` env var: read and clear immediately. Warn that env vars are less secure.
- Prefer: stdin prompt or file descriptor
- NEVER store passphrase to disk
- NEVER log passphrase

## API Key Security

- Token format: `ows_key_<64 hex chars>` (256-bit random)
- Token stored as SHA-256 hash only — raw token shown once
- Mnemonic re-encrypted under HKDF-SHA256(token) — token is decryption capability
- Revocation: delete key file — encrypted copy destroyed, token decrypts nothing
- Multiple API keys: independent copies — revoking one doesn't affect others

## Canton-Specific Security

### External Party Advantage
Canton's External Party model provides protocol-level key isolation. The participant node physically cannot sign commands on behalf of the party — it doesn't have the key. This is stronger than EVM where key isolation is purely a client-side convention.

### Topology Registration
Party keys are registered via topology transactions that are cryptographically signed and distributed to all synchronizer members. Key rotation requires a new topology transaction — there's no way to silently change which key is associated with a party.

### Threshold Signatures
Canton supports multi-key thresholds. OWS can register multiple keys per party and require m-of-n signatures. This is a future enhancement.

## Recommendations for Deployment

1. Use a dedicated user account for the OWS vault
2. Enable full-disk encryption on the machine running OWS
3. Use file descriptor passing instead of env vars for passphrases
4. Configure spending limits and template allowlists for all agent API keys
5. Enable simulation_required policy for production agents
6. Monitor audit log for unusual patterns
7. Rotate API keys regularly (revoke + create new)
8. Use separate API keys for separate agents (never share tokens)
