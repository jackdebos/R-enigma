//! Command-line client.
//!
//! Stage 1 speaks the protocol over `stdin`/`stdout` (see `docs/protocol.md` §2). This
//! binary is a thin shell: it must contain no cryptanalytic logic, so that the same
//! engine can be driven by the TUI (Stage 2), the local web client (Stage 2) and the
//! test harness without divergence. Parsing, validation and computation live in
//! `enigma-core`; this module only moves bytes and emits protocol events.

mod attack_transport;
mod cancel_file;
mod resource_loader;
mod signals;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cancel_file::CancelFile;
use enigma_core::{
    encode, rfc3339_utc, DoneReason, Event, ParsedAttackRequest, ParsedRequest,
    ParsedSearchRequest, TransformRequest, MAX_REQUEST_BYTES,
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
    let resolved = split_cancel_file(&args).and_then(|(input, cancel_file)| {
        let cancel_file = cancel_file.map(|path| cwd.join(path));
        resolve_input(input, &cwd).map(|(bytes, origin)| (bytes, origin, cancel_file))
    });
    match resolved {
        Ok((bytes, origin, cancel_file)) => run(bytes, &origin, cancel_file.as_deref()),
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

/// Splits one optional `--cancel-file <path>` pair from before or after the input form.
///
/// A duplicate pair, a missing value or a `--`-prefixed value is a usage error. The
/// path is returned unresolved; the caller joins it to the invocation cwd.
fn split_cancel_file(args: &[String]) -> Result<(&[String], Option<&str>), InputError> {
    let (input, value) = match args {
        [flag, value, input @ ..] | [input @ .., flag, value] if flag == "--cancel-file" => {
            (input, value)
        }
        _ => return Ok((args, None)),
    };
    if value.starts_with("--") || input.iter().any(|arg| arg == "--cancel-file") {
        return Err(InputError::Usage);
    }
    Ok((input, Some(value)))
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
    eprintln!("Options (before or after the request form):");
    eprintln!("  --cancel-file <path>   cancel a hill_climb/partial_exhaustion attack");
    eprintln!("                         once <path> exists as a regular file");
    eprintln!();
    eprintln!("One JSON event is written per line to stdout; diagnostics go to stderr.");
    eprintln!("See docs/protocol.md for the contract and odd/tasks/enigma-engine.md for the plan.");
}

/// Rejection message for `--cancel-file` on jobs without a cancellation contract.
const CANCEL_FILE_UNSUPPORTED: &str =
    "--cancel-file is supported only for hill_climb and partial_exhaustion attacks";

/// Decodes input as UTF-8, parses and validates the request, and runs the transport.
fn run(bytes: Vec<u8>, origin: &Path, cancel_file: Option<&Path>) -> ExitCode {
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
        Ok(ParsedRequest::Transform(_)) if cancel_file.is_some() => {
            search_error("unsupported_job", CANCEL_FILE_UNSUPPORTED, "/job/kind")
        }
        Ok(ParsedRequest::Transform(request)) => run_transform(request),
        Ok(ParsedRequest::Search(request)) => run_search(request, origin, cancel_file.is_some()),
        Ok(ParsedRequest::Attack(request)) => run_attack(
            request,
            origin,
            cancel_file,
            signals::install,
            &mut io::stdout().lock(),
        ),
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
fn run_search(request: ParsedSearchRequest, origin: &Path, cancel_file: bool) -> ExitCode {
    let contents = match resource_loader::load(request.resources(), origin) {
        Ok(contents) => contents,
        Err(error) => return search_error(error.code, &error.message, &error.location),
    };
    let supplied: BTreeMap<String, &str> = contents
        .iter()
        .map(|(id, text)| (id.clone(), text.as_str()))
        .collect();
    match request.bind_resources(&supplied) {
        Ok(_validated) => {
            let message = if cancel_file {
                CANCEL_FILE_UNSUPPORTED
            } else {
                "search execution is not implemented"
            };
            search_error("unsupported_job", message, "/job/kind")
        }
        Err(diagnostics) => {
            let first = &diagnostics[0];
            for diagnostic in &diagnostics {
                eprintln!("{diagnostic}");
            }
            search_error(first.code(), first.message(), first.location())
        }
    }
}

/// Binding finalizes eligibility, so no second gate check or resource read is needed.
/// The cancel marker is first inspected only after load and bind succeed; the signal
/// handler is installed only after that, still before `started`.
fn run_attack<'s>(
    request: ParsedAttackRequest,
    origin: &Path,
    cancel_file: Option<&Path>,
    install_signals: impl FnOnce() -> Result<&'s AtomicBool, String>,
    out: &mut impl Write,
) -> ExitCode {
    let failure = |out: &mut _, code: &str, message: &str, location: &str| {
        if let Err(error) = write_error_line(out, code, message, location, 1) {
            eprintln!("error: failed to write protocol event: {error}");
        }
        eprintln!("{code}: {message}");
        ExitCode::FAILURE
    };
    let contents = match resource_loader::load(request.resources(), origin) {
        Ok(contents) => contents,
        Err(error) => return failure(out, error.code, &error.message, &error.location),
    };
    let supplied: BTreeMap<String, &str> = contents
        .iter()
        .map(|(id, text)| (id.clone(), text.as_str()))
        .collect();
    match request.bind_resources(&supplied) {
        Ok(validated) => {
            let marker = cancel_file.map(|path| CancelFile::new(path.to_owned()));
            let mut marker = match marker.transpose() {
                Ok(marker) => marker,
                Err(error) => {
                    eprintln!("error: failed to inspect cancel file: {error}");
                    return ExitCode::from(2);
                }
            };
            let signal = match install_signals() {
                Ok(signal) => signal,
                Err(error) => {
                    eprintln!("error: failed to install signal handler: {error}");
                    return ExitCode::from(2);
                }
            };
            let entry = Instant::now();
            let status = match attack_transport::run(
                &validated,
                out,
                || entry.elapsed(),
                now_ts,
                // Poll the marker first so a raised signal never masks its runtime error.
                || marker.as_mut().is_some_and(CancelFile::poll) || signal.load(Ordering::Relaxed),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    if let Some(runtime) = error.runtime {
                        eprintln!("{runtime}");
                    }
                    if let Some(projection) = error.projection {
                        eprintln!("error: failed to project attack result: {projection}");
                    }
                    if let Some(transport) = error.transport {
                        eprintln!("error: failed to write protocol event: {transport}");
                    }
                    ExitCode::FAILURE
                }
            };
            // The adapter stops polling once stopped, so check the latch afterwards.
            match marker.as_ref().and_then(CancelFile::runtime_error) {
                Some(error) => {
                    eprintln!("error: failed to inspect cancel file: {error}");
                    ExitCode::FAILURE
                }
                None => status,
            }
        }
        Err(diagnostics) => {
            for diagnostic in &diagnostics {
                eprintln!("{diagnostic}");
            }
            let first = &diagnostics[0];
            failure(out, first.code(), first.message(), first.location())
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
    let stdout = io::stdout();
    write_error_line(&mut stdout.lock(), code, message, location, seq)
}

fn write_error_line(
    out: &mut impl Write,
    code: &str,
    message: &str,
    location: &str,
    seq: u64,
) -> io::Result<()> {
    let event = Event::Error {
        code: code.to_owned(),
        message: message.to_owned(),
        location: location.to_owned(),
        expected: None,
        hint: None,
        context: None,
    };
    emit(out, &event, seq, &now_ts())?;
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

#[cfg(test)]
mod attack_tests {
    use super::*;
    use serde_json::{json, Value};

    /// A signal flag that is never raised; no real handler is installed in tests.
    static IDLE: AtomicBool = AtomicBool::new(false);

    fn request() -> Value {
        json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
            "alphabet":["A","B"],"wheels":[{"name":"r","wiring":["B","A"],"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],"stepping":{"rules":[]}}}},
            "job":{"kind":"search","configuration":{"slots":[{"id":"r","ring":"A"}],"plugboard":[]},
            "space":{"slots":[{"id":"r","positions":["A","B"]}],
                "plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":1}},
            "text":"AA","passes":["hill_climb"],"measures":["ic"],"resources":{},
            "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":1,"backtrack_pairs":0,"start":[]}}})
    }

    fn check(value: &Value, origin: &Path, code: &str, location: &str) -> Value {
        let parsed = ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            run_attack(parsed, origin, None, || Ok(&IDLE), &mut output),
            ExitCode::FAILURE
        );
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 1, "no work events: {text}");
        let event: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(event["event"], "error");
        assert_eq!(event["seq"], 1);
        assert_eq!(event["code"], code, "{event}");
        assert_eq!(event["location"], location, "{event}");
        event
    }

    fn partial(selection: &str) -> Value {
        let mut value = request();
        value["job"]["passes"] = json!(["partial_exhaustion"]);
        let attack = value["job"]["attack"].as_object_mut().unwrap();
        attack.remove("start");
        attack.insert("kind".into(), json!("partial_exhaustion"));
        attack.insert(
            "seeds".into(),
            json!({"kind":"empty_single","selection":selection}),
        );
        if selection == "touching" {
            value["job"]["attack"]["seeds"]["symbols"] = json!(["A"]);
        }
        value
    }

    fn outer(slots: usize) -> Value {
        let alphabet: Vec<String> = (0..256)
            .map(|i| char::from_u32(0x100 + i).unwrap().to_string())
            .collect();
        let mut value = request();
        value["machine"]["definition"]["value"] = json!({
            "alphabet":alphabet,"wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
            "slots":(0..slots).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"})).collect::<Vec<_>>(),
            "stepping":{"rules":[]}});
        value["job"]["configuration"]["slots"] = json!([]);
        value["job"]["text"] = json!(alphabet[0].repeat(2));
        value["job"]["space"] = json!({"limit":1,
            "slots":(0..slots).map(|i| json!({"id":format!("r{i}"),"positions":alphabet,"rings":alphabet})).collect::<Vec<_>>(),
            "plugboard":{"kind":"attack","symbols":&alphabet[..2],"max_pairs":1}});
        value
    }

    fn success(value: &Value, origin: &Path) {
        let parsed = ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            run_attack(parsed, origin, None, || Ok(&IDLE), &mut output),
            ExitCode::SUCCESS
        );
        let events: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events[0]["event"], "started");
        assert!(events[1..events.len() - 2]
            .iter()
            .all(|event| event["event"] == "progress"));
        assert_eq!(events[events.len() - 2]["event"], "result");
        assert_eq!(events.last().unwrap()["event"], "done");
    }

    #[test]
    fn validated_attack_executes() {
        for value in [request(), partial("all"), partial("touching"), outer(5)] {
            success(&value, Path::new("."));
        }
        check(&outer(8), Path::new("."), "resource_limit", "/job/space");
    }

    #[test]
    fn structural_diagnostics_are_parser_not_handler_failures() {
        for (passes, code, location) in [
            (
                json!(["partial_exhaustion"]),
                "invalid_request",
                "/job/attack/kind",
            ),
            (
                json!(["hill_climb", "partial_exhaustion"]),
                "unsupported_pass",
                "/job/passes",
            ),
            (json!(["reswapping"]), "unsupported_pass", "/job/passes"),
            (
                json!(["hill_climb", "measure", "measure"]),
                "invalid_request",
                "/job/passes/2",
            ),
            (
                json!(["measure", "hill_climb"]),
                "unsupported_pass",
                "/job/passes",
            ),
        ] {
            let mut value = request();
            value["job"]["passes"] = passes;
            parse_error(&value, code, location);
        }
        for (pointer, replacement, code, location) in [
            (
                "/job/attack/initial_measure",
                json!("entropy"),
                "invalid_request",
                "/job/attack/initial_measure",
            ),
            (
                "/job/attack/final_measure",
                json!("entropy"),
                "invalid_request",
                "/job/attack/final_measure",
            ),
            (
                "/job/attack/start",
                json!([["A", "A"]]),
                "invalid_search_space",
                "/job/attack/start/0",
            ),
            (
                "/job/attack/switch_pairs",
                json!(2),
                "invalid_search_space",
                "/job/attack/switch_pairs",
            ),
            ("/job/text", json!("A"), "invalid_text", "/job/text"),
        ] {
            let mut value = request();
            *value.pointer_mut(pointer).unwrap() = replacement;
            parse_error(&value, code, location);
        }
        let mut value = request();
        value["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
        parse_error(&value, "invalid_request", "/job/attack/seeds");
        let mut value = partial("all");
        value["job"]["attack"]["start"] = json!([]);
        parse_error(&value, "invalid_request", "/job/attack/start");
        let mut value = partial("touching");
        value["job"]["attack"]["seeds"]["symbols"] = json!([]);
        parse_error(&value, "invalid_search_space", "/job/attack/seeds/symbols");
        // Every declared measure imposes its minimum, even a non-objective.
        for (measure, text) in [
            ("ic", "A"),
            ("entropy", ""),
            ("trie", ""),
            ("sinkov_bigram", "A"),
        ] {
            let mut value = request();
            value["job"]["measures"] = json!(["entropy", measure]);
            value["job"]["attack"]["initial_measure"] = json!("entropy");
            value["job"]["attack"]["final_measure"] = json!("entropy");
            if measure == "entropy" {
                value["job"]["measures"] = json!(["entropy"]);
            }
            value["job"]["text"] = json!(text);
            if !["ic", "entropy"].contains(&measure) {
                value["job"]["resources"][measure] = json!({"path":"never-loaded.json"});
            }
            parse_error(&value, "invalid_text", "/job/text");
        }
    }

    fn parse_error(value: &Value, code: &str, location: &str) {
        let errors = ParsedAttackRequest::parse_json(&value.to_string()).unwrap_err();
        assert_eq!((errors[0].code(), errors[0].location()), (code, location));
    }

    #[test]
    fn resources_load_then_bind_then_finalize_eligibility() {
        // A unique lexical origin also lets missing paths include escaped diagnostics.
        let origin = std::env::temp_dir().join(format!("enigma-attack-{}", std::process::id()));
        fs::create_dir_all(&origin).unwrap();
        let filename = "model\"\\.json";
        let mut model = json!({"resource_version":1,"kind":"ngram","alphabet":["A","B"],
            "order":2,"entries":[{"gram":["A","A"],"count":1}]});
        let backed = |mut value: Value| {
            value["job"]["measures"] = json!(["ic", "sinkov_bigram"]);
            value["job"]["resources"] = json!({"sinkov_bigram":{"path":filename}});
            value
        };
        let overflow = backed(outer(8));
        let event = check(
            &overflow,
            &origin,
            "unsupported_resource",
            "/job/resources/sinkov_bigram/path",
        );
        assert!(event["message"].as_str().unwrap().contains("model"));
        // A directory is a deterministically unreadable resource, even as root.
        let mut directory = backed(request());
        directory["job"]["resources"]["sinkov_bigram"]["path"] = json!(".");
        check(
            &directory,
            &origin,
            "unsupported_resource",
            "/job/resources/sinkov_bigram/path",
        );
        let path = origin.join(filename);
        fs::write(&path, "{").unwrap();
        check(&overflow, &origin, "invalid_json", "");
        for (content, code, location) in [
            ("{".to_owned(), "invalid_json", ""),
            (
                {
                    let mut m = model.clone();
                    m["order"] = json!(1);
                    m["entries"][0]["gram"] = json!(["A"]);
                    m.to_string()
                },
                "unsupported_resource",
                "/order",
            ),
            (
                {
                    let mut m = model.clone();
                    m["alphabet"] = json!(["B", "A"]);
                    m.to_string()
                },
                "unsupported_resource",
                "/alphabet",
            ),
        ] {
            fs::write(&path, content).unwrap();
            check(&backed(request()), &origin, code, location);
        }
        fs::write(&path, model.to_string()).unwrap();
        success(&backed(request()), &origin);
        model["alphabet"] = outer(8)["machine"]["definition"]["value"]["alphabet"].clone();
        model["entries"][0]["gram"] = json!(["Ā", "Ā"]);
        fs::write(&path, model.to_string()).unwrap();
        check(&overflow, &origin, "resource_limit", "/job/space");
        fs::remove_dir_all(origin).unwrap();
    }

    #[test]
    fn error_output_flushes_and_writer_failures_are_not_delivery_guarantees() {
        struct Writer {
            bytes: Vec<u8>,
            flushes: usize,
            fail_write: bool,
            fail_flush: bool,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.fail_write {
                    return Err(io::Error::other("injected write failure"));
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                if self.fail_flush {
                    Err(io::Error::other("injected flush failure"))
                } else {
                    Ok(())
                }
            }
        }
        for (fail_write, fail_flush) in [(false, false), (true, false), (false, true)] {
            let mut out = Writer {
                bytes: vec![],
                flushes: 0,
                fail_write,
                fail_flush,
            };
            // Valid structure, deterministic eligibility failure before any work events.
            let parsed = ParsedAttackRequest::parse_json(&outer(8).to_string()).unwrap();
            assert_eq!(
                run_attack(parsed, Path::new("."), None, || Ok(&IDLE), &mut out),
                ExitCode::FAILURE
            );
            assert_eq!(out.flushes, usize::from(!fail_write));
            if !fail_write {
                let event: Value = serde_json::from_slice(&out.bytes).unwrap();
                assert_eq!(event["event"], "error");
                assert_eq!(event["seq"], 1);
            }
        }
    }

    /// Runs an action on the first write, i.e. right after `started`.
    struct Writer<F: FnMut()>(Option<F>, Vec<u8>);
    impl<F: FnMut()> Write for Writer<F> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(mut action) = self.0.take() {
                action();
            }
            self.1.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn assert_cancelled(bytes: Vec<u8>) {
        let events: Vec<Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events[0]["event"], "started");
        assert_eq!(events[events.len() - 2]["event"], "result");
        assert_eq!(events.last().unwrap()["event"], "done");
        assert_eq!(events.last().unwrap()["reason"], "cancelled");
    }

    #[test]
    fn cancel_marker_is_polled_after_started() {
        let dir = cancel_file::test_support::tempdir().unwrap();
        for (index, value) in [request(), partial("all")].into_iter().enumerate() {
            for (kind, exit) in [("file", ExitCode::SUCCESS), ("dir", ExitCode::FAILURE)] {
                let path = dir.path().join(format!("{kind}-{index}"));
                let mut out = Writer(
                    Some(|| match kind {
                        "file" => fs::write(&path, b"").unwrap(),
                        _ => fs::create_dir(&path).unwrap(),
                    }),
                    vec![],
                );
                let parsed = ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
                assert_eq!(
                    run_attack(parsed, Path::new("."), Some(&path), || Ok(&IDLE), &mut out),
                    exit
                );
                assert_cancelled(out.1);
            }
        }
    }

    #[test]
    fn signal_flag_requests_the_same_safe_stop() {
        let dir = cancel_file::test_support::tempdir().unwrap();
        for (index, value) in [request(), partial("all")].into_iter().enumerate() {
            // (flag pre-set, marker turned into a directory on first write, exit)
            for (preset, marker, exit) in [
                (false, false, ExitCode::SUCCESS),
                (true, false, ExitCode::SUCCESS),
                (false, true, ExitCode::FAILURE),
            ] {
                let path = dir.path().join(format!("dir-{index}"));
                let flag = AtomicBool::new(preset);
                let mut out = Writer(
                    Some(|| {
                        flag.store(true, Ordering::Relaxed);
                        if marker {
                            fs::create_dir(&path).unwrap();
                        }
                    }),
                    vec![],
                );
                let parsed = ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
                let cancel_file = marker.then_some(path.as_path());
                assert_eq!(
                    run_attack(parsed, Path::new("."), cancel_file, || Ok(&flag), &mut out),
                    exit,
                    "preset {preset}, marker {marker}"
                );
                assert_cancelled(out.1);
            }
        }
    }
}
