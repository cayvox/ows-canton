//! Canton-specific audit log entries.
//!
//! Records all wallet operations (creation, signing, submission, policy evaluations)
//! to an append-only audit log for compliance and debugging purposes.
//! Audit entries never contain private key material.
//!
//! Log format: JSONL (one JSON object per line) at `~/.ows/logs/audit.jsonl`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::CantonError;

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Wallet UUID.
    pub wallet_id: String,
    /// Operation name (e.g. `"canton_submit_command"`).
    pub operation: String,
    /// CAIP-2 chain identifier.
    pub chain_id: String,
    /// Operation-specific details (never contains key material).
    pub details: serde_json::Value,
}

impl AuditEntry {
    /// Create a new audit entry with the current timestamp.
    pub fn new(
        wallet_id: &str,
        operation: &str,
        chain_id: &str,
        details: serde_json::Value,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            wallet_id: wallet_id.to_string(),
            operation: operation.to_string(),
            chain_id: chain_id.to_string(),
            details,
        }
    }
}

/// Append an audit entry to `$OWS_HOME/logs/audit.jsonl`.
pub fn append_audit_log(entry: &AuditEntry) -> Result<(), CantonError> {
    let ows_home = get_ows_home()?;
    append_audit_log_in(&ows_home, entry)
}

/// Append an audit entry to the given base directory.
pub(crate) fn append_audit_log_in(ows_home: &Path, entry: &AuditEntry) -> Result<(), CantonError> {
    let logs_dir = ows_home.join("logs");
    fs::create_dir_all(&logs_dir)?;

    let log_path = logs_dir.join("audit.jsonl");
    let mut line = serde_json::to_string(entry).map_err(|e| CantonError::AuditLogWriteFailed {
        reason: e.to_string(),
    })?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| CantonError::AuditLogWriteFailed {
            reason: e.to_string(),
        })?;

    file.write_all(line.as_bytes())
        .map_err(|e| CantonError::AuditLogWriteFailed {
            reason: e.to_string(),
        })?;

    file.flush().map_err(|e| CantonError::AuditLogWriteFailed {
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Read all audit entries from the log file.
pub fn read_audit_log_in(ows_home: &Path) -> Result<Vec<AuditEntry>, CantonError> {
    let log_path = ows_home.join("logs").join("audit.jsonl");
    if !log_path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&log_path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        if !line.trim().is_empty() {
            let entry: AuditEntry =
                serde_json::from_str(line).map_err(|e| CantonError::AuditLogWriteFailed {
                    reason: format!("corrupt audit entry: {e}"),
                })?;
            entries.push(entry);
        }
    }
    Ok(entries)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_serde() {
        let entry = AuditEntry::new(
            "wallet-1",
            "canton_submit_command",
            "canton:global",
            serde_json::json!({"command_id": "cmd-1"}),
        );
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.wallet_id, "wallet-1");
        assert_eq!(parsed.operation, "canton_submit_command");
    }

    #[test]
    fn test_append_and_read_audit_log() {
        let tmpdir = tempfile::tempdir().unwrap();
        let entry1 = AuditEntry::new(
            "w1",
            "canton_submit_command",
            "canton:global",
            serde_json::json!({"status": "succeeded"}),
        );
        let entry2 = AuditEntry::new(
            "w1",
            "canton_simulate",
            "canton:global",
            serde_json::json!({"result": "ok"}),
        );

        append_audit_log_in(tmpdir.path(), &entry1).unwrap();
        append_audit_log_in(tmpdir.path(), &entry2).unwrap();

        let entries = read_audit_log_in(tmpdir.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].operation, "canton_submit_command");
        assert_eq!(entries[1].operation, "canton_simulate");
    }

    #[test]
    fn test_audit_log_creates_directory() {
        let tmpdir = tempfile::tempdir().unwrap();
        let entry = AuditEntry::new("w1", "test_op", "canton:sandbox", serde_json::json!({}));

        append_audit_log_in(tmpdir.path(), &entry).unwrap();

        let log_path = tmpdir.path().join("logs").join("audit.jsonl");
        assert!(log_path.exists());
    }

    #[test]
    fn test_audit_log_jsonl_format() {
        let tmpdir = tempfile::tempdir().unwrap();
        let entry = AuditEntry::new("w1", "op1", "canton:global", serde_json::json!({"k": "v"}));
        append_audit_log_in(tmpdir.path(), &entry).unwrap();

        let content = fs::read_to_string(tmpdir.path().join("logs").join("audit.jsonl")).unwrap();
        // Each line is valid JSON, ends with newline.
        assert!(content.ends_with('\n'));
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        serde_json::from_str::<AuditEntry>(lines[0]).unwrap();
    }

    #[test]
    fn test_read_empty_audit_log() {
        let tmpdir = tempfile::tempdir().unwrap();
        let entries = read_audit_log_in(tmpdir.path()).unwrap();
        assert!(entries.is_empty());
    }
}
