//! Command-line client.
//!
//! Stage 1 speaks the protocol over `stdin`/`stdout` (see `docs/protocol.md` §2). This
//! binary is a thin shell: it must contain no cryptanalytic logic, so that the same
//! engine can be driven by the TUI (Stage 2), the local web client (Stage 2) and the
//! test harness without divergence. Parsing, validation and computation live in
//! `enigma-core`; this module only moves bytes and emits protocol events.

mod resource_loader;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use enigma_core::{
    encode, rfc3339_utc, DoneReason, Event, ParsedRequest, ParsedSearchRequest, TransformRequest,
    MAX_REQUEST_BYTES,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            eprintln!("error: failed to capture current directory: {error}");
            return ExitCode::from(2);
        }
    };
    match resolve_input(&args, &cwd) {
        Ok((bytes, origin)) => run(bytes, &origin),
        Err(InputError::Usage) => {
            print_usage();
            ExitCode::from(2)
        }
        Err(InputError::Io(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
        Err(InputError::ResourceLimit) => {
            let message =
                format!("request JSON exceeds the {MAX_REQUEST_BYTES}-byte resource limit");
            if let Err(write_error) = emit_error_line("resource_limit", &message, "", 1) {
                eprintln!("error: failed to write protocol event: {write_error}");
            }
            eprintln!("resource_limit: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Why a request could not be read from the command line.
enum InputError {
    /// The argument shape is not one of the accepted forms.
    Usage,
    /// The selected input source could not be read.
    Io(String),
    /// The request exceeds `MAX_REQUEST_BYTES` and was rejected before parsing.
    ResourceLimit,
}

/// Resolves the accepted argument shapes into raw request bytes.
///
/// Accepted: no argument is a usage error; one positional non-flag argument is a file
/// path; `--request -` reads stdin; `--request <path>` reads that file. Anything else
/// is a usage error.
fn resolve_input(args: &[String], cwd: &Path) -> Result<(Vec<u8>, PathBuf), InputError> {
    let path = match args {
        [path] if !path.starts_with("--") => path,
        [flag, value] if flag == "--request" => {
            if value == "-" {
                return read_stdin().map(|bytes| (bytes, cwd.to_owned()));
            }
            value
        }
        _ => return Err(InputError::Usage),
    };
    // Lexical filename origin, deliberately not the canonical symlink target.
    let filename = cwd.join(path);
    let origin = filename.parent().unwrap_or(cwd).to_owned();
    read_file(&filename, path).map(|bytes| (bytes, origin))
}

fn read_stdin() -> Result<Vec<u8>, InputError> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    read_bounded(&mut lock, "stdin")
}

fn read_file(filename: &Path, path: &str) -> Result<Vec<u8>, InputError> {
    let file = fs::File::open(filename)
        .map_err(|error| InputError::Io(format!("failed to open {path:?}: {error}")))?;
    read_bounded(file, path)
}

/// Reads a request capped at `MAX_REQUEST_BYTES` bytes plus one.
///
/// The cap is applied while reading so an oversized input fails as a pre-validation
/// `resource_limit` instead of being buffered whole. One byte past the limit detects
/// oversize without silently truncating the request.
fn read_bounded(reader: impl Read, source: &str) -> Result<Vec<u8>, InputError> {
    let mut buffer = Vec::new();
    let mut bounded = reader.take(MAX_REQUEST_BYTES as u64 + 1);
    bounded
        .read_to_end(&mut buffer)
        .map_err(|error| InputError::Io(format!("failed to read {source}: {error}")))?;
    if buffer.len() > MAX_REQUEST_BYTES {
        return Err(InputError::ResourceLimit);
    }
    Ok(buffer)
}

fn print_usage() {
    eprintln!("enigma {}", env!("CARGO_PKG_VERSION"));
    eprintln!("protocol version {}", enigma_core::PROTOCOL_VERSION);
    eprintln!();
    eprintln!("Usage: enigma <request.json>");
    eprintln!("       enigma --request -        read the request from stdin");
    eprintln!("       enigma --request <path>   read the request from a file");
    eprintln!();
    eprintln!("One JSON event is written per line to stdout; diagnostics go to stderr.");
    eprintln!("See docs/protocol.md for the contract and odd/tasks/enigma-engine.md for the plan.");
}

/// Decodes input as UTF-8, parses and validates the request, and runs the transport.
fn run(bytes: Vec<u8>, origin: &Path) -> ExitCode {
    let json = match String::from_utf8(bytes) {
        Ok(json) => json,
        Err(error) => {
            let message = format!("input is not valid UTF-8: {error}");
            if let Err(write_error) = emit_error_line("invalid_json", &message, "", 1) {
                eprintln!("error: failed to write protocol event: {write_error}");
            }
            eprintln!("invalid_json: {message}");
            return ExitCode::FAILURE;
        }
    };

    match ParsedRequest::parse_json(&json) {
        Ok(ParsedRequest::Transform(request)) => run_transform(request),
        Ok(ParsedRequest::Search(request)) => run_search(request, origin),
        Err(diagnostics) => {
            // Pre-validation failure: exactly one `error` at seq 1, no `started`.
            let first = &diagnostics[0];
            if let Err(write_error) =
                emit_error_line(first.code(), first.message(), first.location(), 1)
            {
                eprintln!("error: failed to write protocol event: {write_error}");
            }
            for diagnostic in &diagnostics {
                eprintln!("{diagnostic}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Load owned UTF-8 once, then borrow it into the pure core binding boundary.
/// Successful binding is not execution: never enumerate candidates or emit work.
fn run_search(request: ParsedSearchRequest, origin: &Path) -> ExitCode {
    let contents = match resource_loader::load(&request, origin) {
        Ok(contents) => contents,
        Err(error) => return search_error(error.code, &error.message, &error.location),
    };
    let supplied: BTreeMap<String, &str> = contents
        .iter()
        .map(|(id, text)| (id.clone(), text.as_str()))
        .collect();
    match request.bind_resources(&supplied) {
        Ok(_validated) => search_error(
            "unsupported_job",
            "search execution is not implemented",
            "/job/kind",
        ),
        Err(diagnostics) => {
            let first = &diagnostics[0];
            for diagnostic in &diagnostics {
                eprintln!("{diagnostic}");
            }
            search_error(first.code(), first.message(), first.location())
        }
    }
}

fn search_error(code: &str, message: &str, location: &str) -> ExitCode {
    if let Err(error) = emit_error_line(code, message, location, 1) {
        eprintln!("error: failed to write protocol event: {error}");
    }
    eprintln!("{code}: {message}");
    ExitCode::FAILURE
}

/// Emits the successful lifecycle: `started`, one `output`, then terminal `done`.
fn run_transform(request: TransformRequest) -> ExitCode {
    let ts = now_ts();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    if let Err(error) = emit(&mut out, &Event::Started, 1, &ts) {
        eprintln!("error: failed to write protocol event: {error}");
        return ExitCode::FAILURE;
    }

    match request.transform() {
        Ok(output) => {
            if let Err(error) = emit(&mut out, &Event::Output { output }, 2, &ts) {
                eprintln!("error: failed to write protocol event: {error}");
                return ExitCode::FAILURE;
            }
            if let Err(error) = emit(
                &mut out,
                &Event::Done {
                    reason: DoneReason::Completed,
                },
                3,
                &ts,
            ) {
                eprintln!("error: failed to write protocol event: {error}");
                return ExitCode::FAILURE;
            }
            if let Err(error) = out.flush() {
                eprintln!("error: failed to flush stdout: {error}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        // Validation runs before `started`, so this branch is not expected; if the
        // engine ever fails, surface it as a terminal `error` with no `done`.
        Err(error) => {
            let message = error.to_string();
            // `started` already used `seq: 1`, so the terminal error must continue the
            // stream monotonically instead of repeating the sequence number.
            if let Err(write_error) = emit_error_line("internal_error", &message, "", 2) {
                eprintln!("error: failed to write protocol event: {write_error}");
            }
            eprintln!("internal_error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Writes one terminal `error` event at the caller-supplied `seq` to stdout.
fn emit_error_line(code: &str, message: &str, location: &str, seq: u64) -> io::Result<()> {
    let event = Event::Error {
        code: code.to_owned(),
        message: message.to_owned(),
        location: location.to_owned(),
        expected: None,
        hint: None,
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    emit(&mut out, &event, seq, &now_ts())?;
    out.flush()
}

/// Encodes one event and writes it as a single stdout line.
fn emit(writer: &mut impl Write, event: &Event, seq: u64, ts: &str) -> io::Result<()> {
    let line = encode(event, seq, ts)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writeln!(writer, "{line}")
}

/// The current time as RFC 3339 UTC. A clock before the epoch maps to the epoch.
fn now_ts() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => rfc3339_utc(elapsed.as_secs() as i64),
        Err(_) => rfc3339_utc(0),
    }
}
