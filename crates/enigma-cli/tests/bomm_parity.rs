//! Differential parity against observations captured from the pinned bomm reference.
//!
//! Each case directory under `e2e/bomm/` holds the bomm `query.json` that was run once at
//! capture time and a `case.json` with the same key in this engine's schema plus bomm's
//! observed preview and score (see `e2e/bomm/README.md`). These tests never run bomm:
//! they decrypt through the real `enigma` binary, compare the first 64 letters exactly,
//! and compare full-message IC or Sinkov scores within justified numeric bounds.
//! The opt-in release attack case compares recovered board/plaintext outcomes only.

mod support;

use support::successful_events;

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use enigma_core::{index_of_coincidence, parse_ngram_json, Alphabet, NgramModel, SCALE};

const BOMM_COMMIT: &str = "aeb2f2bf00dfdee68e972f90ae7e83b387b188e9";
const CASES: &[&str] = &[
    "enigma-i-double-step",
    "enigma-m3-two-notch",
    "enigma-m4-thin-c-gamma",
    "m4-u264-attack-board",
    "m4-u264-first-break",
    "m4-u264-sinkov-bigram-correct",
    "m4-u264-sinkov-bigram-wrong",
    "m4-u264-sinkov-trigram-correct",
    "m4-u264-sinkov-trigram-wrong",
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

/// Strict test-only txt -> JSON v1 adapter. No production parser or model bypass.
fn converted_resource(text: &str, order: usize, source: &str) -> (Value, usize) {
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

fn convert_table(text: &str, order: usize, source: &str) -> (NgramModel, usize) {
    let (resource, count) = converted_resource(text, order, source);
    let model = parse_ngram_json(&resource.to_string()).unwrap_or_else(|errors| {
        panic!("{source}: public resource parser rejected table: {errors:?}")
    });
    (model, count)
}

fn table(order: usize) -> (NgramModel, usize) {
    let name = match order {
        2 => "enigma1941-bigram.txt",
        3 => "enigma1941-trigram.txt",
        _ => panic!("unsupported fixture order {order}"),
    };
    let path = bomm_dir().join("frequencies").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    convert_table(&text, order, name)
}

/// Printed truncation plus half an f32 ULP below |weight|=16 and a conservative
/// 1e-9 for Q32 log/mean floors, Q48 approximation and binary64 log/accumulation.
/// The table test below guards the count and weight bounds behind this allowance.
fn sinkov_tolerance(printed: &str) -> f64 {
    let (_, fraction) = printed.split_once('.').expect("printed decimal score");
    assert!(!fraction.is_empty() && fraction.bytes().all(|b| b.is_ascii_digit()));
    10_f64.powi(-(fraction.len() as i32)) + 2_f64.powi(-21) + 1e-9
}

/// Whether full plaintext is sourced, constructed, or intentionally unavailable.
enum Kind {
    Historical,
    Constructed,
    HistoricalWrongKey,
}

fn check(case: &str, kind: Kind) -> (f64, f64) {
    let query = load(case, "query.json");
    let record = load(case, "case.json");

    // The test, not the fixture, decides which full-plaintext check applies.
    let (label, expected) = match kind {
        Kind::Historical => ("historical", &record["plaintext"]),
        Kind::Constructed => ("constructed", &record["provenance"]["plaintext"]),
        Kind::HistoricalWrongKey => ("historical-wrong-key", &Value::Null),
    };
    assert_eq!(record["kind"], json!(label), "{case}: kind");
    let expected = if matches!(kind, Kind::HistoricalWrongKey) {
        assert!(
            record.get("plaintext").is_none(),
            "{case}: no sourced wrong-key plaintext"
        );
        None
    } else {
        Some(
            expected
                .as_str()
                .unwrap_or_else(|| panic!("{case}: {label} plaintext is a string")),
        )
    };

    let capture = &record["capture"];
    assert_eq!(capture["bomm_commit"], json!(BOMM_COMMIT), "{case}");
    assert_eq!(capture["exit_code"], json!(0), "{case}");
    assert_eq!(capture["units"], json!(1), "{case}: exactly one key");
    assert_eq!(
        capture["decrypts"],
        json!(1),
        "{case}: exactly one decryption"
    );

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
    let measure = query["passes"][0]["measure"]
        .as_str()
        .expect("measure name");
    let ours = match measure {
        "ic" => {
            let ours = ic(&plaintext);
            assert!(
                (ours - score).abs() <= SCORE_TOLERANCE,
                "{case}: IC {ours:.10} vs bomm {score_text}"
            );
            ours
        }
        "sinkov_bigram" | "sinkov_trigram" => {
            let order = if measure == "sinkov_bigram" { 2 } else { 3 };
            let (model, _) = table(order);
            let ours = model
                .score(&plaintext)
                .expect("measurable plaintext")
                .measured()
                .units() as f64
                / SCALE as f64;
            let difference = (ours - score).abs();
            let tolerance = sinkov_tolerance(score_text);
            eprintln!("{case}: ours={ours:.12}, bomm={score_text}, difference={difference:.12}, tolerance={tolerance:.12}");
            assert!(difference <= tolerance,
                "{case}: Sinkov {ours:.12} vs bomm {score_text}; difference {difference} exceeds {tolerance}");
            ours
        }
        other => panic!("{case}: unexpected measure {other}"),
    };

    // bomm only shows 64 letters; check the rest when known plaintext exists.
    if let Some(expected) = expected {
        assert_eq!(plaintext, expected, "{case}: full {label} plaintext");
    }
    (ours, score)
}

const HISTORICAL_PAIRS: &[&str] = &["AT", "BL", "DF", "GJ", "HM", "NW", "OP", "QY", "RZ", "VX"];

fn attack_fixture() -> (Value, Value) {
    let query = load("m4-u264-attack-board", "query.json");
    let record = load("m4-u264-attack-board", "case.json");
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

fn case_a_runs(option: Option<&OsStr>) -> Result<usize, &'static str> {
    match option {
        None => Ok(1),
        Some(value) if value == "1" => Ok(3),
        Some(_) => Err("ENIGMA_CASE_A_TIMING must be absent or exactly 1"),
    }
}

fn case_a_timing_summary(samples: [Duration; 3]) -> Value {
    let mut sorted = samples;
    sorted.sort_unstable();
    json!({
        "case": "m4-u264-attack-board",
        "unit": "seconds",
        "samples": samples.map(|sample| sample.as_secs_f64()),
        "min": sorted[0].as_secs_f64(),
        "median": sorted[1].as_secs_f64(),
        "max": sorted[2].as_secs_f64(),
        "verified_pairs": 10,
        "verified_plaintext_letters": 232
    })
}

// Best-effort cleanup also covers subprocess errors and assertion panics.
struct AttackInputs(PathBuf);

impl Drop for AttackInputs {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove {}: {error}", self.0.display());
        }
    }
}

#[test]
fn case_a_timing_option_is_explicit() {
    assert_eq!(case_a_runs(None), Ok(1));
    assert_eq!(case_a_runs(Some(OsStr::new("1"))), Ok(3));
    for value in ["", "0", "2", "true", " 1"] {
        assert_eq!(
            case_a_runs(Some(OsStr::new(value))),
            Err("ENIGMA_CASE_A_TIMING must be absent or exactly 1")
        );
    }
}

#[test]
fn case_a_timing_summary_preserves_order_and_sorts_statistics() {
    let samples = [30, 10, 20].map(Duration::from_secs);
    assert_eq!(
        case_a_timing_summary(samples),
        json!({
            "case": "m4-u264-attack-board",
            "unit": "seconds",
            "samples": [30.0, 10.0, 20.0],
            "min": 10.0, "median": 20.0, "max": 30.0,
            "verified_pairs": 10, "verified_plaintext_letters": 232
        })
    );
    let equal = case_a_timing_summary([Duration::from_millis(250); 3]);
    assert_eq!(equal["samples"], json!([0.25, 0.25, 0.25]));
    for field in ["min", "median", "max"] {
        assert_eq!(equal[field], json!(0.25));
    }
}

#[test]
fn historical_attack_fixture_is_consistent() {
    attack_fixture();
}

#[test]
#[ignore = "~15 s release attack; run with cargo test --release -p enigma-cli --test bomm_parity -- --ignored"]
fn historical_m4_u264_attack_board() {
    let runs = case_a_runs(std::env::var_os("ENIGMA_CASE_A_TIMING").as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    let (query, record) = attack_fixture();
    let source = record["resource"]["source"].as_str().unwrap();
    let text = std::fs::read_to_string(bomm_dir().join(source)).unwrap();
    let (resource, _) = converted_resource(&text, 3, source);
    parse_ngram_json(&resource.to_string()).expect("converted table passes the public parser");

    // Generated inputs live in a per-process temporary directory (no converted JSON in Git).
    let directory = std::env::temp_dir().join(format!("enigma-bomm-attack-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let inputs = AttackInputs(directory.clone());
    std::fs::write(directory.join("trigram.json"), resource.to_string()).unwrap();
    let mut request = record["engine"].clone();
    request["job"]["text"] = json!(query["ciphertext"].as_str().unwrap().to_ascii_uppercase());
    request["job"]["resources"] = json!({"sinkov_trigram": {"path": "trigram.json"}});
    std::fs::write(directory.join("request.json"), request.to_string()).unwrap();
    let mut samples = [Duration::ZERO; 3];
    for sample in samples.iter_mut().take(runs) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_enigma"));
        command.current_dir(&directory).arg("request.json");
        let start = Instant::now();
        let output = command.output();
        *sample = start.elapsed();
        let output = output.expect("failed to run the attack through the real CLI");
        verify_attack_output(&output, &record);
    }
    drop(inputs);
    if runs == 3 {
        println!("ENIGMA_CASE_A_TIMING {}", case_a_timing_summary(samples));
    }
}

fn verify_attack_output(output: &std::process::Output, record: &Value) {
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

#[test]
fn every_case_directory_is_checked() {
    let mut found: Vec<String> = std::fs::read_dir(bomm_dir())
        .expect("e2e/bomm is readable")
        .map(|entry| entry.expect("directory entry"))
        .filter(|entry| entry.path().is_dir() && entry.file_name() != "frequencies")
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(found, CASES);
}

#[test]
fn frequency_tables_parse_without_losing_records() {
    // No SHA dependency is available: byte hashes are recorded/verified at capture time.
    for order in [2, 3] {
        let (model, records) = table(order);
        assert!(records > 0);
        assert_eq!(model.entry_count(), records);
        assert_eq!(model.order(), order);
        assert_eq!(
            model.alphabet(),
            &Alphabet::new(('A'..='Z').collect()).unwrap()
        );
        // Every source count is then exactly representable in bomm's f32 map;
        // total is exact in f64. The unseen floor bounds all log magnitudes.
        assert!(model.total_count() <= (1 << 24));
        let max_weight = (2.0 * model.total_count() as f64 / model.minimum_count() as f64).ln();
        assert!(max_weight < 16.0);
        // Exercise the deterministic Q32 approximation against binary64 ln on
        // every listed gram and an unseen gram (the tables are sparse).
        let name = if order == 2 { "bigram" } else { "trigram" };
        let text =
            std::fs::read_to_string(bomm_dir().join(format!("frequencies/enigma1941-{name}.txt")))
                .unwrap();
        let fields: Vec<_> = text.split_whitespace().collect();
        let mut listed = HashSet::new();
        for fields in fields.chunks_exact(2) {
            let gram = fields[0].to_ascii_uppercase();
            listed.insert(gram.clone());
            let count: f64 = fields[1].parse().unwrap();
            let expected = (count / model.total_count() as f64).ln();
            let actual = model.score(&gram).unwrap().measured().units() as f64 / SCALE as f64;
            assert!((actual - expected).abs() < 1e-9, "{name}: {gram}");
        }
        let unseen = ('A'..='Z')
            .flat_map(|a| {
                ('A'..='Z').flat_map(move |b| {
                    ('A'..='Z').map(move |c| {
                        if order == 2 {
                            format!("{a}{b}")
                        } else {
                            format!("{a}{b}{c}")
                        }
                    })
                })
            })
            .find(|gram| !listed.contains(gram))
            .expect("sparse fixture has an unseen gram");
        let actual = model.score(&unseen).unwrap().measured().units() as f64 / SCALE as f64;
        assert!((actual + max_weight).abs() < 1e-9);
    }
}

#[test]
fn sinkov_display_precision_is_derived_per_value() {
    let arithmetic = 2_f64.powi(-21) + 1e-9;
    assert!((sinkov_tolerance("-6.038888") - (1e-6 + arithmetic)).abs() < 1e-15);
    assert!((sinkov_tolerance("-10.19315") - (1e-5 + arithmetic)).abs() < 1e-15);
}

#[test]
fn converter_rejects_malformed_records_without_repair() {
    for text in [
        "ab",
        "ab 0",
        "ab -1",
        "ab 1.5",
        "ab 18446744073709551616",
        "AB 1",
        "aé 1",
        "a 1",
        "abc 1",
        "ab 1 ab 2",
        "",
    ] {
        assert!(
            std::panic::catch_unwind(|| convert_table(text, 2, "negative control")).is_err(),
            "accepted malformed table: {text:?}"
        );
    }
}

#[test]
fn historical_m4_u264_sinkov_bigram() {
    let (correct, bomm_correct) = check("m4-u264-sinkov-bigram-correct", Kind::Historical);
    let (wrong, bomm_wrong) = check("m4-u264-sinkov-bigram-wrong", Kind::HistoricalWrongKey);
    assert!(
        correct - wrong > 1.0,
        "correct key must clearly outrank wrong key"
    );
    assert!(bomm_correct - bomm_wrong > 1.0);
}

#[test]
fn historical_m4_u264_sinkov_trigram() {
    let (correct, bomm_correct) = check("m4-u264-sinkov-trigram-correct", Kind::Historical);
    let (wrong, bomm_wrong) = check("m4-u264-sinkov-trigram-wrong", Kind::HistoricalWrongKey);
    assert!(
        correct - wrong > 1.0,
        "correct key must clearly outrank wrong key"
    );
    assert!(bomm_correct - bomm_wrong > 1.0);
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
