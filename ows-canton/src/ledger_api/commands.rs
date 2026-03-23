//! DAML command builder for create, exercise, and other command types.
//!
//! Provides helper functions for constructing Canton Ledger API v2
//! command request bodies from [`CantonCommand`](crate::policy::CantonCommand).

use crate::policy::{CantonCommand, CantonCommandType};

use super::types::{MultiHashSignatureRequest, SimulateCommandRequest, SubmitCommandRequest};

/// Build a [`SubmitCommandRequest`] from a command, parties, and signatures.
pub fn build_submit_request(
    command: &CantonCommand,
    act_as: &[String],
    read_as: &[String],
    command_id: &str,
    signatures: Vec<MultiHashSignatureRequest>,
) -> SubmitCommandRequest {
    let commands_payload =
        crate::signing::build_submission_request(command, act_as, read_as, command_id);

    SubmitCommandRequest {
        commands: commands_payload,
        multi_hash_signatures: signatures,
    }
}

/// Build a [`SimulateCommandRequest`] from a command and parties.
pub fn build_simulate_request(
    command: &CantonCommand,
    act_as: &[String],
    read_as: &[String],
    command_id: &str,
) -> SimulateCommandRequest {
    let commands_payload =
        crate::signing::build_submission_request(command, act_as, read_as, command_id);

    SimulateCommandRequest {
        commands: commands_payload,
    }
}

/// Format a command type as the Canton API string representation.
pub fn command_type_api_name(cmd_type: &CantonCommandType) -> &'static str {
    match cmd_type {
        CantonCommandType::Create => "CreateCommand",
        CantonCommandType::Exercise => "ExerciseCommand",
        CantonCommandType::CreateAndExercise => "CreateAndExerciseCommand",
        CantonCommandType::ExerciseByKey => "ExerciseByKeyCommand",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_submit_request() {
        let cmd = CantonCommand {
            template_id: "T:T".to_string(),
            command_type: CantonCommandType::Create,
            choice: None,
            contract_id: None,
            arguments: serde_json::json!({"key": "value"}),
        };

        let req =
            build_submit_request(&cmd, &["alice::1220abcd".to_string()], &[], "cmd-1", vec![]);

        assert_eq!(req.commands["commandId"], "cmd-1");
        assert!(req.multi_hash_signatures.is_empty());
    }

    #[test]
    fn test_build_simulate_request() {
        let cmd = CantonCommand {
            template_id: "T:T".to_string(),
            command_type: CantonCommandType::Exercise,
            choice: Some("Go".to_string()),
            contract_id: Some("cid-1".to_string()),
            arguments: serde_json::json!({}),
        };

        let req = build_simulate_request(&cmd, &["a::12345678".to_string()], &[], "sim-1");
        assert_eq!(req.commands["commandId"], "sim-1");
    }

    #[test]
    fn test_command_type_api_name() {
        assert_eq!(
            command_type_api_name(&CantonCommandType::Create),
            "CreateCommand"
        );
        assert_eq!(
            command_type_api_name(&CantonCommandType::Exercise),
            "ExerciseCommand"
        );
    }
}
