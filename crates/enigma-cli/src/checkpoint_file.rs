//! Checkpoint file preflight; paths are relative to the invocation cwd.
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use enigma_core::{
    CheckpointIdentity, CheckpointReason, CheckpointRecord, CheckpointSnapshot, Event,
};

pub(super) struct CheckpointFile<'a> {
    pub(super) label: &'a str,
    pub(super) record: Option<CheckpointRecord>,
    path: PathBuf,
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
                    path: cwd.join(label),
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
                    path: cwd.join(label),
                }))
            }
            (None, None) => Ok(None),
        }
    }

    pub(super) fn invalid(label: &str, reason: impl std::fmt::Display) -> String {
        format!("invalid checkpoint {label:?}: {reason}")
    }
}

/// Calling-thread persistence state. Failed writes never move the cadence origin.
pub(super) struct CheckpointWriter<'a> {
    file: &'a CheckpointFile<'a>,
    identity: CheckpointIdentity,
    interval: Duration,
    pub(super) last_write: Duration,
    pub(super) failed: bool,
}

impl<'a> CheckpointWriter<'a> {
    pub(super) fn new(file: &'a CheckpointFile<'a>, identity: CheckpointIdentity) -> Self {
        let interval = Duration::from_secs(300);
        // Debug builds only: integration tests can force block writes without waiting.
        // This is not a public CLI setting and release builds always use 300 seconds.
        #[cfg(debug_assertions)]
        let interval = std::env::var("ENIGMA_TEST_CHECKPOINT_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(interval);
        Self {
            file,
            identity,
            interval,
            last_write: Duration::ZERO,
            failed: false,
        }
    }

    pub(super) fn due(&self, reason: CheckpointReason, now: Duration) -> bool {
        reason != CheckpointReason::BlockCommitted
            || now.saturating_sub(self.last_write) >= self.interval
    }

    pub(super) fn write(
        &mut self,
        snapshot: CheckpointSnapshot<'_>,
        elapsed: u128,
    ) -> Option<Event> {
        let result = snapshot
            .record(self.identity, elapsed)
            .map_err(io::Error::other)
            .and_then(|mut record| {
                let bytes = record.seal_json().map_err(io::Error::other)?;
                atomic_write(&self.file.path, bytes.as_bytes())?;
                Ok(Event::checkpoint(&record))
            });
        match result {
            Ok(event) => Some(event),
            Err(error) => {
                self.failed = true;
                eprintln!(
                    "error: cannot write checkpoint {:?}: {error}",
                    self.file.label
                );
                None
            }
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let temporary = PathBuf::from(name);
    // Replace a partial temporary file left by an interrupted checkpoint write.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        // Clean up the temporary file opened by this attempt.
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_is_monotonic_and_mandatory_offers_bypass_it() {
        let file = CheckpointFile {
            label: "unused",
            record: None,
            path: PathBuf::from("unused"),
        };
        let identity = enigma_core::checkpoint_identity("{}", &Default::default()).unwrap();
        let mut writer = CheckpointWriter::new(&file, identity);
        writer.interval = Duration::from_secs(300);
        for last in [0, 300, 700] {
            writer.last_write = Duration::from_secs(last);
            let boundary = Duration::from_secs(last + 300);
            assert!(!writer.due(
                CheckpointReason::BlockCommitted,
                boundary - Duration::from_millis(1)
            ));
            assert!(writer.due(CheckpointReason::BlockCommitted, boundary));
            for reason in [CheckpointReason::OuterFinished, CheckpointReason::Cancelled] {
                assert!(writer.due(reason, writer.last_write));
            }
        }
    }

    #[test]
    fn rename_failure_preserves_destination_and_cleans_owned_temporary() {
        let dir = crate::cancel_file::test_support::tempdir().unwrap();
        let target = dir.path().join("destination");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), "unchanged").unwrap();
        assert!(atomic_write(&target, b"new checkpoint").is_err());
        assert_eq!(
            std::fs::read_to_string(target.join("sentinel")).unwrap(),
            "unchanged"
        );
        assert!(!dir.path().join("destination.tmp").exists());
    }
}
