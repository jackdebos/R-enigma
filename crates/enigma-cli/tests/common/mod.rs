//! Design-A (`e2e/bomm/m4-u264-attack-board`) fixture shared by the parity and timing tests.
//!
//! Test crates that use this module also declare `mod support;`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::{json, Value};

use enigma_core::parse_ngram_json;

use crate::support::successful_events;

pub const BOMM_COMMIT: &str = "aeb2f2bf00dfdee68e972f90ae7e83b387b188e9";
pub const ATTACK_CASE: &str = "m4-u264-attack-board";
pub const HISTORICAL_PAIRS: &[&str] = &["AT", "BL", "DF", "GJ", "HM", "NW", "OP", "QY", "RZ", "VX"];

pub fn bomm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../e2e/bomm")
}

pub fn load(case: &str, file: &str) -> Value {
    let path = bomm_dir().join(case).join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("invalid JSON in {}: {error}", path.display()))
}

/// Strict test-only txt -> JSON v1 adapter. No production parser or model bypass.
pub fn converted_resource(text: &str, order: usize, source: &str) -> (Value, usize) {
    let fields: Vec<_> = text.split_whitespace().collect();
    assert_eq!(
        fields.len() % 2,
        0,
        "{source}: incomplete gram/count record"
    );
    let mut seen = HashSet::new();
    let entries: Vec<_> = fields
        .chunks_exact(2)
        .enumerate()
        .map(|(index, fields)| {
            let context = format!("{source}: record {} ({:?})", index + 1, fields);
            let gram = fields[0];
            assert!(
                gram.len() == order && gram.bytes().all(|b| b.is_ascii_lowercase()),
                "{context}: expected exactly {order} lowercase ASCII letters"
            );
            assert!(seen.insert(gram), "{context}: duplicate gram");
            assert!(
                fields[1].bytes().all(|b| b.is_ascii_digit()),
                "{context}: count must contain decimal digits only"
            );
            let count: u64 = fields[1]
                .parse()
                .unwrap_or_else(|error| panic!("{context}: invalid count: {error}"));
            assert!(count > 0, "{context}: count must be positive");
            let symbols: Vec<_> = gram
                .to_ascii_uppercase()
                .chars()
                .map(|c| c.to_string())
                .collect();
            json!({"gram": symbols, "count": count})
        })
        .collect();
    let count = entries.len();
    let alphabet: Vec<_> = ('A'..='Z').map(|c| c.to_string()).collect();
    let resource = json!({
        "resource_version": 1, "kind": "ngram", "alphabet": alphabet,
        "order": order, "entries": entries
    });
    (resource, count)
}

pub fn attack_fixture() -> (Value, Value) {
    let query = load(ATTACK_CASE, "query.json");
    let record = load(ATTACK_CASE, "case.json");
    let historical = load("m4-u264-sinkov-trigram-correct", "case.json");
    assert_eq!(record["kind"], json!("historical-attack"));
    assert_eq!(record["historical_pairs"], json!(HISTORICAL_PAIRS));
    assert_eq!(record["observed"]["plugboard"], json!(HISTORICAL_PAIRS));
    assert_eq!(historical["engine"]["plugboard"], json!(HISTORICAL_PAIRS));
    assert_eq!(record["plaintext"], historical["plaintext"]);
    assert_eq!(record["plaintext"].as_str().unwrap().len(), 232);
    assert_eq!(record["capture"]["bomm_commit"], json!(BOMM_COMMIT));
    assert_eq!(record["capture"]["exit_code"], json!(0));
    assert_eq!(
        record["engine"]["job"]["configuration"]["plugboard"],
        json!([])
    );
    assert_eq!(record["engine"]["job"]["attack"]["start"], json!([]));
    assert_eq!(query["space"]["plugboard"], json!(""));
    assert_eq!(
        query["ciphertext"],
        load("m4-u264-sinkov-trigram-correct", "query.json")["ciphertext"]
    );
    assert_eq!(
        record["resource"]["source"],
        json!("frequencies/enigma1941-trigram.txt")
    );
    assert_eq!(record["resource"]["order"], json!(3));
    assert_eq!(record["resource"]["measure"], json!("sinkov_trigram"));
    (query, record)
}

/// Per-process temporary directory holding generated attack inputs.
/// Best-effort cleanup also covers subprocess errors and assertion panics.
pub struct AttackInputs(PathBuf);

impl AttackInputs {
    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write(&self, name: &str, value: &Value) {
        std::fs::write(self.0.join(name), value.to_string()).unwrap();
    }
}

impl Drop for AttackInputs {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove {}: {error}", self.0.display());
        }
    }
}

/// Writes `trigram.json` and the design-A `request.json` (no converted JSON in Git).
/// Returns the inputs, the case record and the written request.
pub fn prepare_attack_inputs(prefix: &str) -> (AttackInputs, Value, Value) {
    let (query, record) = attack_fixture();
    let source = record["resource"]["source"].as_str().unwrap();
    let text = std::fs::read_to_string(bomm_dir().join(source)).unwrap();
    let (resource, _) = converted_resource(&text, 3, source);
    parse_ngram_json(&resource.to_string()).expect("converted table passes the public parser");

    let directory = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let inputs = AttackInputs(directory);
    inputs.write("trigram.json", &resource);
    let mut request = record["engine"].clone();
    request["job"]["text"] = json!(query["ciphertext"].as_str().unwrap().to_ascii_uppercase());
    request["job"]["resources"] = json!({"sinkov_trigram": {"path": "trigram.json"}});
    inputs.write("request.json", &request);
    (inputs, record, request)
}

pub fn verify_attack_output(output: &Output, record: &Value) {
    let events = successful_events(output);
    let results: Vec<_> = events
        .iter()
        .filter(|event| event["event"] == "result")
        .collect();
    assert_eq!(results.len(), 1, "events: {events:?}");
    let best = &results[0]["best"];
    let mut pairs: Vec<String> = best["configuration"]["plugboard"]
        .as_array()
        .expect("result board is an array")
        .iter()
        .map(|pair| {
            let mut letters: Vec<_> = pair
                .as_array()
                .unwrap()
                .iter()
                .map(|letter| letter.as_str().unwrap())
                .collect();
            assert_eq!(letters.len(), 2);
            letters.sort_unstable();
            letters.concat()
        })
        .collect();
    pairs.sort_unstable();
    assert_eq!(pairs, HISTORICAL_PAIRS);
    assert_eq!(
        best["plaintext"], record["plaintext"],
        "full sourced plaintext"
    );
}
