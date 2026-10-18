//! Differential parity against observations captured from the pinned bomm reference.
//!
//! Each case directory under `e2e/bomm/` holds the bomm `query.json` that was run once at
//! capture time and a `case.json` with the same key in this engine's schema plus bomm's
//! observed preview and IC score (see `e2e/bomm/README.md`). These tests never run bomm:
//! they decrypt the query's ciphertext through the real `enigma` binary and compare the
//! first 64 letters exactly and the full-message IC within bomm's printed precision.

mod support;

use support::successful_events;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use enigma_core::{index_of_coincidence, Alphabet, SCALE};

const BOMM_COMMIT: &str = "aeb2f2bf00dfdee68e972f90ae7e83b387b188e9";
const CASES: &[&str] = &[
    "enigma-i-double-step",
    "enigma-m3-two-notch",
    "enigma-m4-thin-c-gamma",
    "m4-u264-first-break",
    "repetitive-high-ic",
];
/// bomm prints the score as `%+10.10f` cut to nine characters: six decimals, truncated.
const SCORE_TOLERANCE: f64 = 1.1e-6;
const PREVIEW_LETTERS: usize = 64;

fn bomm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../e2e/bomm")
}

fn load(case: &str, file: &str) -> Value {
    let path = bomm_dir().join(case).join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("invalid JSON in {}: {error}", path.display()))
}

/// Decrypts `ciphertext` through the CLI with the case's own-schema configuration.
fn decrypt(engine: &Value, ciphertext: &str) -> String {
    let plugboard: Vec<Value> = engine["plugboard"]
        .as_array()
        .expect("plugboard is an array of pairs")
        .iter()
        .map(|pair| {
            let pair = pair.as_str().expect("each pair is a two-letter string");
            json!([&pair[0..1], &pair[1..2]])
        })
        .collect();
    let request = json!({
        "protocol_version": 1,
        "machine": {"definition": {"kind": "bundled", "id": engine["machine"]}},
        "job": {
            "kind": "transform",
            "configuration": {"slots": engine["slots"], "plugboard": plugboard},
            "text": ciphertext,
            "direction": "decrypt"
        }
    });

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
    let output = child.wait_with_output().expect("failed to collect output");
    let events = successful_events(&output);
    assert_eq!(events.len(), 3, "events: {events:?}");
    assert_eq!(events[1]["event"], json!("output"), "events: {events:?}");
    events[1]["output"]
        .as_str()
        .expect("output is a string")
        .to_string()
}

/// bomm's IC: alphabet size times coincident pairs over n(n-1), on the full message.
fn ic(text: &str) -> f64 {
    let alphabet = Alphabet::new(('A'..='Z').collect()).expect("A-Z is a valid alphabet");
    let units = index_of_coincidence(&alphabet, text)
        .expect("plaintext is measurable")
        .measured()
        .units();
    units as f64 / SCALE as f64
}

/// Whether a case's full plaintext comes from a historical source or from its construction.
enum Kind {
    Historical,
    Constructed,
}

fn check(case: &str, kind: Kind) {
    let query = load(case, "query.json");
    let record = load(case, "case.json");

    // The test, not the fixture, decides which full-plaintext check applies.
    let (label, expected) = match kind {
        Kind::Historical => ("historical", &record["plaintext"]),
        Kind::Constructed => ("constructed", &record["provenance"]["plaintext"]),
    };
    assert_eq!(record["kind"], json!(label), "{case}: kind");
    let expected = expected
        .as_str()
        .unwrap_or_else(|| panic!("{case}: {label} plaintext is a string"));

    let capture = &record["capture"];
    assert_eq!(capture["bomm_commit"], json!(BOMM_COMMIT), "{case}");
    assert_eq!(capture["exit_code"], json!(0), "{case}");
    assert_eq!(capture["units"], json!(1), "{case}: exactly one key");

    // bomm reads lowercase only; this engine's alphabet is uppercase.
    let ciphertext = query["ciphertext"]
        .as_str()
        .expect("query ciphertext is a string")
        .to_ascii_uppercase();
    let plaintext = decrypt(&record["engine"], &ciphertext);
    assert_eq!(plaintext.len(), ciphertext.len(), "{case}");

    let observed = &record["observed"];
    let preview = observed["preview"]
        .as_str()
        .expect("observed preview is a string")
        .to_ascii_uppercase();
    assert_eq!(preview.len(), PREVIEW_LETTERS, "{case}");
    assert_eq!(&plaintext[..PREVIEW_LETTERS], preview, "{case}: preview");

    let score_text = observed["score"]
        .as_str()
        .expect("observed score is a string");
    let score: f64 = score_text.parse().expect("observed score is a decimal");
    let ours = ic(&plaintext);
    assert!(
        (ours - score).abs() <= SCORE_TOLERANCE,
        "{case}: IC {ours:.10} vs bomm {score_text}"
    );

    // bomm only shows 64 letters; the rest is checked against the known plaintext.
    assert_eq!(plaintext, expected, "{case}: full {label} plaintext");
}

#[test]
fn every_case_directory_is_checked() {
    let mut found: Vec<String> = std::fs::read_dir(bomm_dir())
        .expect("e2e/bomm is readable")
        .map(|entry| entry.expect("directory entry"))
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(found, CASES);
}

#[test]
fn historical_m4_u264_first_break() {
    check("m4-u264-first-break", Kind::Historical);
}

#[test]
fn enigma_i_double_step() {
    check("enigma-i-double-step", Kind::Constructed);
}

#[test]
fn enigma_m3_two_notch() {
    check("enigma-m3-two-notch", Kind::Constructed);
}

#[test]
fn enigma_m4_thin_c_gamma() {
    check("enigma-m4-thin-c-gamma", Kind::Constructed);
}

#[test]
fn repetitive_high_ic() {
    check("repetitive-high-ic", Kind::Constructed);
}
