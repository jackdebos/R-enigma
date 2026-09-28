//! Command-line client.
//!
//! Stage 1 speaks the protocol over `stdin`/`stdout` (see `docs/protocol.md` §2). This
//! binary is a thin shell: it must contain no cryptanalytic logic, so that the same
//! engine can be driven by the TUI (Stage 2), the local web client (Stage 2) and the
//! test harness without divergence. Parsing, validation and computation live in
//! `enigma-core`; this module only moves bytes and emits protocol events.

use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use enigma_core::{encode, rfc3339_utc, DoneReason, Event, TransformRequest, MAX_REQUEST_BYTES};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match resolve_input(&args) {
        Ok(bytes) => run(bytes),
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
fn resolve_input(args: &[String]) -> Result<Vec<u8>, InputError> {
    match args {
        [] => Err(InputError::Usage),
        [path] if !path.starts_with("--") => read_file(path),
        [flag, value] if flag == "--request" => {
            if value == "-" {
                read_stdin()
            } else {
                read_file(value)
            }
        }
        _ => Err(InputError::Usage),
    }
}

fn read_stdin() -> Result<Vec<u8>, InputError> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    read_bounded(&mut lock, "stdin")
}

fn read_file(path: &str) -> Result<Vec<u8>, InputError> {
    let file = fs::File::open(path)
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
fn run(bytes: Vec<u8>) -> ExitCode {
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

    match TransformRequest::parse_json(&json) {
        Ok(request) => run_transform(request),
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
