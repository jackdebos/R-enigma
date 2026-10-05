//! Caller-side lexical path loading. No sandbox or confinement is implied.
use enigma_core::{
    ResourceReference, MAX_RESOURCE_BYTES, MAX_RESOURCE_REFERENCES, MAX_RESOURCE_TOTAL_BYTES,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(crate) struct LoadError {
    pub code: &'static str,
    pub message: String,
    pub location: String,
}

#[derive(Debug)]
enum ReadError {
    Io(io::Error),
    Limit,
}

/// Never request more than the remaining allowance plus one detection byte.
/// Once that byte is observed, return without probing the reader again.
fn read_resource(mut reader: impl Read, allowance: usize) -> Result<Vec<u8>, ReadError> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let size = chunk.len().min(allowance - bytes.len() + 1);
        let read = match reader.read(&mut chunk[..size]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadError::Io(error)),
            Ok(read) => read,
        };
        if read == 0 {
            return Ok(bytes);
        }
        if read > allowance - bytes.len() {
            return Err(ReadError::Limit);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

struct Budget {
    per_reference: usize,
    remaining: usize,
    references: usize,
}
impl Budget {
    fn allowance(&self, index: usize) -> Result<usize, ReadError> {
        if index >= self.references {
            return Err(ReadError::Limit);
        }
        Ok(self.per_reference.min(self.remaining))
    }
    fn consume(&mut self, bytes: usize) {
        // The bounded reader has already checked this subtraction.
        self.remaining -= bytes;
    }
}

pub(crate) fn load(
    references: &[ResourceReference],
    origin: &Path,
) -> Result<BTreeMap<String, String>, LoadError> {
    let mut budget = Budget {
        per_reference: MAX_RESOURCE_BYTES,
        remaining: MAX_RESOURCE_TOTAL_BYTES,
        references: MAX_RESOURCE_REFERENCES,
    };
    let mut contents = BTreeMap::new();
    // Parsed references are in deterministic ID order, not selected-measure order.
    // Each reference is read independently even when path spellings are identical.
    for (index, reference) in references.iter().enumerate() {
        let id = reference.measure().id();
        let fail = |code, message: String| LoadError {
            code,
            message: format!(
                "measure {id:?}, selected file {:?}: {message}",
                reference.path()
            ),
            location: format!(
                "/job/resources/{}/path",
                id.replace('~', "~0").replace('/', "~1")
            ),
        };
        let allowance = budget.allowance(index).map_err(|_| {
            fail(
                "resource_limit",
                "request exceeds resource reference limit".to_owned(),
            )
        })?;
        let path = origin.join(reference.path()); // Absolute paths replace the origin.
                                                  // Reject known non-files before opening (for example, a FIFO may block on
                                                  // open). Recheck the opened handle too; this is not race-proof confinement.
        let selected = std::fs::metadata(&path).map_err(|error| {
            fail(
                "unsupported_resource",
                format!("failed to inspect resource: {error}"),
            )
        })?;
        if !selected.is_file() {
            return Err(fail(
                "unsupported_resource",
                "resource must be a regular file".to_owned(),
            ));
        }
        let file = File::open(&path).map_err(|error| {
            fail(
                "unsupported_resource",
                format!("failed to open resource: {error}"),
            )
        })?;
        let metadata = file.metadata().map_err(|error| {
            fail(
                "unsupported_resource",
                format!("failed to inspect resource: {error}"),
            )
        })?;
        if !metadata.is_file() {
            return Err(fail(
                "unsupported_resource",
                "resource must be a regular file".to_owned(),
            ));
        }
        let bytes = read_resource(file, allowance).map_err(|error| match error {
            ReadError::Io(error) => fail("unsupported_resource", format!("failed to read resource: {error}")),
            ReadError::Limit => fail("resource_limit", format!("resource exceeds {MAX_RESOURCE_BYTES}-byte per-reference or {MAX_RESOURCE_TOTAL_BYTES}-byte aggregate limit")),
        })?;
        budget.consume(bytes.len());
        let text = String::from_utf8(bytes).map_err(|error| {
            fail(
                "unsupported_resource",
                format!("resource is not valid UTF-8: {error}"),
            )
        })?;
        contents.insert(id.to_owned(), text);
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Scripted {
        bytes: usize,
        calls: usize,
        fail_after: bool,
    }
    impl Read for Scripted {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.bytes == 0 {
                if self.fail_after {
                    return Err(io::Error::other("injected read failure"));
                }
                return Ok(0);
            }
            let count = self.bytes.min(buffer.len());
            buffer[..count].fill(b' ');
            self.bytes -= count;
            Ok(count)
        }
    }
    #[test]
    fn eof_and_exact_allowance_are_accepted() {
        for size in [0, 3, 4] {
            assert_eq!(
                read_resource(Cursor::new(vec![b' '; size]), 4)
                    .unwrap()
                    .len(),
                size
            );
        }
    }
    #[test]
    fn first_excess_byte_stops_before_next_read_even_if_it_would_fail() {
        let mut reader = Scripted {
            bytes: 5,
            calls: 0,
            fail_after: true,
        };
        assert!(matches!(
            read_resource(&mut reader, 4),
            Err(ReadError::Limit)
        ));
        assert_eq!(reader.calls, 1);
        assert_eq!(reader.bytes, 0);
        let mut zero = Scripted {
            bytes: 1,
            calls: 0,
            fail_after: true,
        };
        assert!(matches!(read_resource(&mut zero, 0), Err(ReadError::Limit)));
        assert_eq!(zero.calls, 1);
    }
    #[test]
    fn read_failure_before_detection_proof_remains_io() {
        let mut reader = Scripted {
            bytes: 4,
            calls: 0,
            fail_after: true,
        };
        assert!(matches!(
            read_resource(&mut reader, 4),
            Err(ReadError::Io(_))
        ));
        assert_eq!(reader.calls, 2);
    }
    #[test]
    fn aggregate_and_reference_guards_use_remaining_allowance() {
        let mut budget = Budget {
            per_reference: 4,
            remaining: 6,
            references: 16,
        };
        assert_eq!(budget.allowance(0).unwrap(), 4);
        budget.consume(4);
        assert_eq!(budget.allowance(1).unwrap(), 2);
        assert!(matches!(
            read_resource(Cursor::new(b"abc"), budget.allowance(1).unwrap()),
            Err(ReadError::Limit)
        ));
        budget.consume(2);
        assert_eq!(budget.allowance(15).unwrap(), 0);
        assert!(matches!(budget.allowance(16), Err(ReadError::Limit)));
        // Only seven dependent IDs exist: this is helper, not public-request coverage.
    }
}
