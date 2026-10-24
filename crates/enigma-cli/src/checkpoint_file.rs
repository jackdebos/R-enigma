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
    expected: Option<Vec<u8>>,
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
                    expected: None,
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
                    expected: Some(text.into_bytes()),
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
    expected: Option<Vec<u8>>,
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
            expected: file.expected.clone(),
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
                atomic_write(&self.file.path, bytes.as_bytes(), &mut self.expected)?;
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

fn atomic_write(path: &Path, bytes: &[u8], expected: &mut Option<Vec<u8>>) -> io::Result<()> {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let temporary = PathBuf::from(name);
    // Unlink stale names, never truncate through a symlink or a hard link.
    match std::fs::symlink_metadata(&temporary) {
        Ok(_) => std::fs::remove_file(&temporary)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        let unchanged = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => match expected.as_deref() {
                Some(previous) => std::fs::read(path)? == previous,
                None => false,
            },
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => expected.is_none(),
            Err(error) => return Err(error),
        };
        if !unchanged {
            return Err(io::Error::other(
                "destination changed since the last checkpoint",
            ));
        }
        // A small check-then-rename race remains: std has no portable conditional rename.
        std::fs::rename(&temporary, path)?;
        *expected = Some(bytes.to_vec());
        Ok(())
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
            expected: None,
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

    #[cfg(unix)]
    #[test]
    fn stale_temporary_links_do_not_modify_foreign_files() {
        for hardlink in [false, true] {
            let dir = crate::cancel_file::test_support::tempdir().unwrap();
            let target = dir.path().join("save");
            let temporary = dir.path().join("save.tmp");
            let foreign = dir.path().join("foreign");
            std::fs::write(&foreign, b"valuable foreign data").unwrap();
            if hardlink {
                std::fs::hard_link(&foreign, &temporary).unwrap();
            } else {
                std::os::unix::fs::symlink(&foreign, &temporary).unwrap();
            }
            atomic_write(&target, b"new checkpoint", &mut None).unwrap();
            assert_eq!(std::fs::read(&foreign).unwrap(), b"valuable foreign data");
            assert_eq!(std::fs::read(&target).unwrap(), b"new checkpoint");
            assert!(!temporary.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn temporary_link_to_checkpoint_does_not_destroy_destination() {
        let dir = crate::cancel_file::test_support::tempdir().unwrap();
        let target = dir.path().join("save");
        let temporary = dir.path().join("save.tmp");
        std::fs::write(&target, b"previous checkpoint").unwrap();
        std::os::unix::fs::symlink(&target, &temporary).unwrap();
        atomic_write(
            &target,
            b"new checkpoint",
            &mut Some(b"previous checkpoint".to_vec()),
        )
        .unwrap();
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"new checkpoint");
    }

    #[test]
    fn foreign_destination_appearing_after_prepare_is_preserved_on_every_attempt() {
        let dir = crate::cancel_file::test_support::tempdir().unwrap();
        let file = CheckpointFile::prepare(dir.path(), Some("save"), None)
            .unwrap()
            .unwrap();
        std::fs::write(&file.path, b"foreign data").unwrap();
        let mut expected = file.expected.clone();
        for _ in 0..2 {
            let error = atomic_write(&file.path, b"new checkpoint", &mut expected).unwrap_err();
            assert_eq!(expected, None);
            assert_eq!(
                error.to_string(),
                "destination changed since the last checkpoint"
            );
            assert_eq!(std::fs::read(&file.path).unwrap(), b"foreign data");
            assert!(!dir.path().join("save.tmp").exists());
        }
    }

    #[test]
    fn changed_or_missing_destination_after_success_is_not_replaced() {
        let dir = crate::cancel_file::test_support::tempdir().unwrap();
        let target = dir.path().join("save");
        let mut expected = None;
        atomic_write(&target, b"previous checkpoint", &mut expected).unwrap();
        assert_eq!(expected.as_deref(), Some(b"previous checkpoint".as_slice()));
        std::fs::write(&target, b"foreign data").unwrap();
        assert!(atomic_write(&target, b"new checkpoint", &mut expected).is_err());
        assert_eq!(expected.as_deref(), Some(b"previous checkpoint".as_slice()));
        assert_eq!(std::fs::read(&target).unwrap(), b"foreign data");
        assert!(!dir.path().join("save.tmp").exists());
        std::fs::remove_file(&target).unwrap();
        assert!(atomic_write(&target, b"new checkpoint", &mut expected).is_err());
        assert!(!target.exists());
        assert!(!dir.path().join("save.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn destination_symlink_is_never_followed_or_replaced() {
        let dir = crate::cancel_file::test_support::tempdir().unwrap();
        let target = dir.path().join("save");
        let foreign = dir.path().join("foreign");
        std::fs::write(&foreign, b"previous checkpoint").unwrap();
        std::os::unix::fs::symlink(&foreign, &target).unwrap();
        assert!(atomic_write(
            &target,
            b"new checkpoint",
            &mut Some(b"previous checkpoint".to_vec())
        )
        .is_err());
        assert!(std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"previous checkpoint");
        assert!(!dir.path().join("save.tmp").exists());
    }

    #[test]
    fn temporary_directory_failure_preserves_previous_checkpoint() {
        let dir = crate::cancel_file::test_support::tempdir().unwrap();
        let target = dir.path().join("save");
        std::fs::write(&target, b"previous checkpoint").unwrap();
        std::fs::create_dir(dir.path().join("save.tmp")).unwrap();
        assert!(atomic_write(
            &target,
            b"new checkpoint",
            &mut Some(b"previous checkpoint".to_vec())
        )
        .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"previous checkpoint");
        assert!(dir.path().join("save.tmp").is_dir());
    }

    #[test]
    fn rename_failure_preserves_destination_and_cleans_owned_temporary() {
        let dir = crate::cancel_file::test_support::tempdir().unwrap();
        let target = dir.path().join("destination");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), "unchanged").unwrap();
        assert!(atomic_write(&target, b"new checkpoint", &mut None).is_err());
        assert_eq!(
            std::fs::read_to_string(target.join("sentinel")).unwrap(),
            "unchanged"
        );
        assert!(!dir.path().join("destination.tmp").exists());
    }
}
