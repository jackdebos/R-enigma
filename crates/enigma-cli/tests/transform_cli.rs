//! End-to-end tests for the `transform` stdio transport (`docs/protocol.md` §2–§4).
//!
//! These drive the real `enigma` binary, pipe a protocol request through the transport,
//! and assert the emitted JSONL event stream. They never call the engine directly.

mod support;

use support::successful_events;

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

use enigma_core::MAX_REQUEST_BYTES;

/// The protocol §3 `enigma-i` example: four explicit slots, empty plugboard, `AAAA`.
fn valid_request() -> Value {
    json!({
        "protocol_version": 1,
        "machine": {"definition": {"kind": "bundled", "id": "enigma-i"}},
        "job": {
            "kind": "transform",
            "configuration": {
                "slots": [
                    {"id": "reflector", "wheel": "B", "position": "A", "ring": "A"},
                    {"id": "left", "wheel": "I", "position": "A", "ring": "A"},
                    {"id": "middle", "wheel": "II", "position": "A", "ring": "A"},
                    {"id": "right", "wheel": "III", "position": "A", "ring": "A"}
                ],
                "plugboard": []
            },
            "text": "AAAA",
            "direction": "encrypt"
        }
    })
}

fn run_with_stdin(request: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--request", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the enigma binary");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(request.to_string().as_bytes())
        .expect("failed to write the request to stdin");
    child.wait_with_output().expect("failed to collect output")
}

/// Runs the binary with `--request -`, writing raw (possibly non-UTF-8) bytes to stdin.
fn run_with_raw_stdin(bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--request", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the enigma binary");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(bytes)
        .expect("failed to write the request to stdin");
    child.wait_with_output().expect("failed to collect output")
}

fn json_lines(stdout: &[u8]) -> Vec<Value> {
    let text = std::str::from_utf8(stdout).expect("stdout is valid UTF-8");
    assert!(
        text.ends_with('\n'),
        "stdout must end with a newline: {text:?}"
    );
    text.lines()
        .map(|line| serde_json::from_str(line).expect("each stdout line is one JSON object"))
        .collect()
}

fn unique_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0)
}

#[test]
fn valid_transform_emits_started_output_done() {
    let output = run_with_stdin(&valid_request());
    let events = successful_events(&output);
    assert_eq!(events.len(), 3, "events: {events:?}");
    assert_eq!(events[0]["event"], json!("started"));
    assert_eq!(events[1]["event"], json!("output"));
    assert_eq!(events[2]["event"], json!("done"));

    assert_eq!(events[2]["reason"], json!("completed"));

    // Independently assert the known transform and prove it by round-tripping the
    // emitted ciphertext back with `direction: "decrypt"`.
    let transformed = events[1]["output"].as_str().expect("output is a string");
    assert_eq!(transformed, "BDZG");

    let mut decrypt = valid_request();
    decrypt["job"]["text"] = json!(transformed);
    decrypt["job"]["direction"] = json!("decrypt");
    let round_trip = run_with_stdin(&decrypt);
    let round_events = successful_events(&round_trip);
    assert_eq!(round_events[1]["output"], json!("AAAA"));
}

#[test]
fn invalid_direction_emits_one_error_before_started() {
    let mut request = valid_request();
    request["job"]["direction"] = json!("sideways");
    let output = run_with_stdin(&request);
    assert!(
        !output.status.success(),
        "an invalid request must exit nonzero"
    );

    let events = json_lines(&output.stdout);
    assert_eq!(events.len(), 1, "events: {events:?}");
    assert_eq!(events[0]["event"], json!("error"));
    assert_eq!(events[0]["seq"], json!(1));
    assert_eq!(events[0]["protocol_version"], json!(1));
    assert_eq!(events[0]["code"], json!("invalid_request"));
    assert_eq!(events[0]["location"], json!("/job/direction"));
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("started"),
        "a pre-validation failure must not emit `started`"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid_request"), "stderr: {stderr}");
    assert!(stderr.contains("/job/direction"), "stderr: {stderr}");
}

#[test]
fn positional_file_path_emits_the_same_stream() {
    let request = valid_request();
    let path = std::env::temp_dir().join(format!(
        "enigma-transform-{}-{}.json",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::write(&path, request.to_string()).expect("failed to write the request file");

    let output = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run enigma with a file path");
    let _ = std::fs::remove_file(&path);

    let events = successful_events(&output);
    assert_eq!(events.len(), 3, "events: {events:?}");
    assert_eq!(events[0]["event"], json!("started"));
    assert_eq!(events[1]["event"], json!("output"));
    assert_eq!(events[2]["event"], json!("done"));
    assert_eq!(events[2]["reason"], json!("completed"));
}

#[test]
fn no_arguments_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run enigma without arguments");

    assert_eq!(
        output.status.code(),
        Some(2),
        "exit status: {:?}",
        output.status
    );
    assert!(
        output.stdout.is_empty(),
        "a usage error must not emit JSON events: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"), "stderr: {stderr}");
}

#[test]
fn unknown_argument_shape_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .arg("--bogus")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run enigma with an unknown argument");

    assert_eq!(
        output.status.code(),
        Some(2),
        "exit status: {:?}",
        output.status
    );
    assert!(
        output.stdout.is_empty(),
        "a usage error must not emit JSON events: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"), "stderr: {stderr}");
}

#[test]
fn invalid_utf8_stdin_emits_one_error_without_started() {
    let output = run_with_raw_stdin(&[0xFF, 0xFE]);

    assert!(!output.status.success(), "exit status: {:?}", output.status);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the process must terminate with a signal-free failure code: {:?}",
        output.status
    );

    let events = json_lines(&output.stdout);
    assert_eq!(events.len(), 1, "events: {events:?}");
    assert_eq!(events[0]["event"], json!("error"));
    assert_eq!(events[0]["seq"], json!(1));
    assert_eq!(events[0]["code"], json!("invalid_json"));
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("started"),
        "a pre-validation failure must not emit `started`"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid_json"), "stderr: {stderr}");
}

#[test]
fn oversized_stdin_is_rejected_before_started() {
    // One byte past the limit is enough to prove the read is bounded: the process must
    // reject the input without buffering it whole and without emitting `started`.
    let oversized = vec![b' '; MAX_REQUEST_BYTES + 1];
    let output = run_with_raw_stdin(&oversized);

    assert!(!output.status.success(), "exit status: {:?}", output.status);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the process must terminate with a signal-free failure code: {:?}",
        output.status
    );

    let events = json_lines(&output.stdout);
    assert_eq!(events.len(), 1, "events: {events:?}");
    assert_eq!(events[0]["event"], json!("error"));
    assert_eq!(events[0]["seq"], json!(1));
    assert_eq!(events[0]["protocol_version"], json!(1));
    assert_eq!(events[0]["code"], json!("resource_limit"));
    assert_eq!(events[0]["location"], json!(""));
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("started"),
        "an oversized input must fail before `started`"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("resource_limit"), "stderr: {stderr}");
}
