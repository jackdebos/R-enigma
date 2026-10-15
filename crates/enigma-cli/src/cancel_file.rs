//! Existence-only cancellation marker; no clock or marker ownership.

use std::io;
use std::path::PathBuf;

pub(crate) struct CancelFile {
    path: PathBuf,
    stopped: bool,
    runtime_error: Option<io::Error>,
}

impl CancelFile {
    /// Call after request/resource preflight, before emitting started.
    /// Relative paths retain the caller's cwd semantics; no resolution occurs here.
    pub(crate) fn new(path: PathBuf) -> io::Result<Self> {
        let stopped = Self::inspect(&path)?;
        Ok(Self {
            path,
            stopped,
            runtime_error: None,
        })
    }

    fn inspect(path: &std::path::Path) -> io::Result<bool> {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cancel marker must resolve to a regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Suitable for the adapter's bool callback, independently of progress cadence.
    pub(crate) fn poll(&mut self) -> bool {
        if !self.stopped {
            match Self::inspect(&self.path) {
                Ok(present) => self.stopped = present,
                Err(error) => {
                    self.runtime_error = Some(error);
                    self.stopped = true;
                }
            }
        }
        self.stopped
    }

    /// Inspect after the adapter returns, even if it stopped polling early.
    /// Report alongside, never instead of, any adapter/Core failure.
    pub(crate) fn runtime_error(&self) -> Option<&io::Error> {
        self.runtime_error.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestDir(PathBuf);

    impl TestDir {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn tempdir() -> io::Result<TestDir> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "enigma-cancel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(TestDir(path))
    }

    #[test]
    fn absent_then_created_and_removed_is_sticky() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("marker");
        let mut marker = CancelFile::new(path.clone()).unwrap();
        assert!(!marker.poll());
        fs::write(&path, b"ignored contents").unwrap();
        assert!(marker.poll());
        assert_eq!(fs::read(&path).unwrap(), b"ignored contents");
        fs::remove_file(&path).unwrap();
        assert!(marker.poll());
        assert!(!path.exists());
        assert!(marker.runtime_error().is_none());
    }

    #[test]
    fn existing_marker_is_observed_at_setup_and_not_consumed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("marker");
        fs::write(&path, [0xff, 0, 0xfe]).unwrap();
        let mut marker = CancelFile::new(path.clone()).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(marker.poll());
        fs::write(&path, b"still owned by caller").unwrap();
        let mut next_run = CancelFile::new(path.clone()).unwrap();
        assert!(next_run.poll());
        assert_eq!(fs::read(path).unwrap(), b"still owned by caller");
    }

    #[test]
    fn missing_parent_is_normal_and_never_created() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing/marker");
        let mut marker = CancelFile::new(path.clone()).unwrap();
        assert!(!marker.poll());
        assert!(!path.parent().unwrap().exists());
        assert!(marker.runtime_error().is_none());
    }

    #[test]
    fn initial_directory_is_an_error() {
        let dir = tempdir().unwrap();
        assert!(CancelFile::new(dir.path().to_owned()).is_err());
        assert!(dir.path().is_dir());
    }

    #[test]
    fn runtime_type_error_is_retained_after_path_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("marker");
        let mut marker = CancelFile::new(path.clone()).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(marker.poll());
        let first = marker.runtime_error().unwrap() as *const io::Error;
        fs::remove_dir(&path).unwrap();
        assert!(marker.poll());
        assert_eq!(marker.runtime_error().unwrap() as *const io::Error, first);
        fs::write(&path, b"new marker").unwrap();
        assert!(marker.poll());
        assert_eq!(marker.runtime_error().unwrap() as *const io::Error, first);
        assert_eq!(fs::read(path).unwrap(), b"new marker");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_follow_regular_targets_and_allow_dangling_targets() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        let mut marker = CancelFile::new(link.clone()).unwrap();
        assert!(!marker.poll());
        fs::write(&target, b"ignored").unwrap();
        assert!(marker.poll());
        assert!(CancelFile::new(link.clone()).unwrap().poll());
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(target).unwrap(), b"ignored");
        let directory_link = dir.path().join("directory-link");
        symlink(dir.path(), &directory_link).unwrap();
        assert!(CancelFile::new(directory_link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn metadata_errors_fail_setup_and_request_runtime_safe_stop() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let path = dir.path().join("loop");
        let mut marker = CancelFile::new(path.clone()).unwrap();
        symlink(&path, &path).unwrap();
        assert!(CancelFile::new(path.clone()).is_err());
        assert!(marker.poll());
        assert!(marker.runtime_error().is_some());
        fs::remove_file(&path).unwrap();
        assert!(marker.poll());
        assert!(marker.runtime_error().is_some());
    }
}
