//! Checkpoint file preflight; paths are relative to the invocation cwd.
use std::path::Path;

use enigma_core::CheckpointRecord;

pub(super) struct CheckpointFile<'a> {
    pub(super) label: &'a str,
    pub(super) record: Option<CheckpointRecord>,
}

impl<'a> CheckpointFile<'a> {
    /// Run before reading the request, so failed preflight cannot start work.
    pub(super) fn prepare(
        cwd: &Path,
        checkpoint: Option<&'a str>,
        resume: Option<&'a str>,
    ) -> Result<Option<Self>, String> {
        match (checkpoint, resume) {
            (Some(_), Some(_)) => Err("--checkpoint and --resume cannot be combined".into()),
            (Some(label), None) => {
                match std::fs::symlink_metadata(cwd.join(label)) {
                    Ok(_) => {
                        return Err(format!(
                        "--checkpoint file already exists, use --resume to continue it: {label:?}"
                    ))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("cannot inspect checkpoint {label:?}: {error}"))
                    }
                }
                Ok(Some(Self {
                    label,
                    record: None,
                }))
            }
            (None, Some(label)) => {
                let text = std::fs::read_to_string(cwd.join(label))
                    .map_err(|error| Self::invalid(label, error))?;
                let record = CheckpointRecord::parse_json(&text)
                    .map_err(|error| Self::invalid(label, error))?;
                Ok(Some(Self {
                    label,
                    record: Some(record),
                }))
            }
            (None, None) => Ok(None),
        }
    }

    pub(super) fn invalid(label: &str, reason: impl std::fmt::Display) -> String {
        format!("invalid checkpoint {label:?}: {reason}")
    }
}
