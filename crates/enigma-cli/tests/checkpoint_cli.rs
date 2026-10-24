//! Checkpoint startup is preflight: rejected files must never be changed.
use enigma_core::{checkpoint_identity, AttackRequest, CheckpointRecord, ExecutionOptions};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "enigma-checkpoint-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.0.join(name), text).unwrap();
    }
    fn unchanged(&self, name: &str, text: &str) {
        assert_eq!(std::fs::read_to_string(self.0.join(name)).unwrap(), text);
    }
    fn run(&self, args: &[&str], input: &Value) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
            .current_dir(&self.0)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let write = child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes());
        if let Err(error) = write {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        child.wait_with_output().unwrap()
    }
    fn reject(&self, args: &[&str], input: &Value, message: &str) {
        let output = self.run(args, input);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, b"");
        assert_eq!(output.stderr, format!("error: {message}\n").as_bytes());
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn request() -> Value {
    json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B"],"wheels":[{"name":"r","wiring":["B","A"],"turnovers":[]}],
        "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],"stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":[{"id":"r","ring":"A"}],"plugboard":[]},
        "space":{"slots":[{"id":"r","positions":["A","B"]}],"plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":1}},
        "text":"AA","passes":["hill_climb"],"measures":["ic"],"resources":{},
        "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":1,"backtrack_pairs":0,"start":[]}}})
}
fn normalize(mut value: Value) -> Value {
    for field in ["ts", "elapsed_ms", "seq"] {
        value.as_object_mut().unwrap().remove(field);
    }
    value
}
fn events(output: &Output) -> Vec<Value> {
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| normalize(serde_json::from_str(line).unwrap()))
        .collect()
}
fn record(value: &Value, resources: &BTreeMap<String, String>) -> String {
    let text = value.to_string();
    let supplied = resources
        .iter()
        .map(|(id, t)| (id.clone(), t.as_str()))
        .collect();
    let attack = enigma_core::ParsedAttackRequest::parse_json(&text)
        .unwrap()
        .bind_resources(&supplied)
        .unwrap();
    capture(&attack, value, resources)
}
fn capture(
    attack: &AttackRequest,
    identity_request: &Value,
    res: &BTreeMap<String, String>,
) -> String {
    let identity = checkpoint_identity(&identity_request.to_string(), res).unwrap();
    let mut saved = String::new();
    attack
        .run_with_checkpoints(
            ExecutionOptions::serial(),
            |_| {},
            || false,
            |s| saved = s.record(identity, 1234).unwrap().seal_json().unwrap(),
        )
        .unwrap();
    saved
}
#[test]
fn startup_conflicts_precede_request_read_and_preserve_files() {
    let dir = Scratch::new();
    dir.write("save", "foreign");
    dir.reject(
        &["--checkpoint", "save", "missing.json"],
        &request(),
        "--checkpoint file already exists, use --resume to continue it: \"save\"",
    );
    dir.reject(
        &["--checkpoint", "save", "missing.json", "--resume", "save"],
        &request(),
        "--checkpoint and --resume cannot be combined",
    );
    dir.unchanged("save", "foreign");
}
#[test]
fn option_shapes_and_help() {
    let dir = Scratch::new();
    let help = dir.run(&["--help"], &request());
    assert_eq!(help.status.code(), Some(2));
    assert!(help.stdout.is_empty());
    let usage = String::from_utf8(help.stderr.clone()).unwrap();
    assert!(usage.contains("  --checkpoint <path>  save HC/PE checkpoints to a new file\n"));
    let resume_help = "  --resume <path>      resume HC/PE and keep saving to the same file\n";
    assert!(usage.contains(resume_help));
    for option in ["--checkpoint", "--resume"] {
        for args in [
            vec![option],
            vec!["--request", "-", option],
            vec![option, "--bad", "--request", "-"],
            vec![option, "save", "--request", "-", option, "other"],
        ] {
            let output = dir.run(&args, &request());
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert_eq!(output.stderr, help.stderr);
        }
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}
#[test]
fn unsupported_jobs_and_option_precedence() {
    let dir = Scratch::new();
    let mut transform = request();
    transform["job"] = json!({"kind":"transform","configuration":{"slots":[{"id":"r","wheel":"r","position":"A","ring":"A"}],"plugboard":[]},"text":"AA","direction":"encrypt"});
    let mut legacy = request();
    legacy["job"].as_object_mut().unwrap().remove("attack");
    legacy["job"]["space"] = json!({"slots":[{"id":"r","positions":["A","B"]}]});
    let saved = record(&request(), &BTreeMap::new());
    dir.write("resume", &saved);
    for value in [transform, legacy] {
        for option in ["--checkpoint", "--resume"] {
            for (extra, message) in [
                (vec![], "--checkpoint and --resume are supported only for hill_climb and partial_exhaustion attacks"),
                (vec!["--threads", "1"], "--threads is supported only for hill_climb and partial_exhaustion attacks"),
                (vec!["--threads", "1", "--cancel-file", "marker"], "--cancel-file is supported only for hill_climb and partial_exhaustion attacks")
            ] {
                let path = if option == "--resume" { "resume" } else { "new" };
                let mut args = vec![option, path, "--request", "-"];
                args.extend(extra);
                let output = dir.run(&args, &value);
                assert_eq!(output.status.code(), Some(1));
                assert_eq!(output.stderr, format!("unsupported_job: {message}\n").as_bytes());
                assert_eq!(events(&output), vec![json!({"event":"error","protocol_version":1,"code":"unsupported_job","message":message,"location":"/job/kind"})]);
                let event: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(event["seq"], 1);
            }
        }
    }
    dir.unchanged("resume", &saved);
    assert!(!dir.0.join("new").exists());
}
#[test]
fn invalid_records_are_checked_before_request_and_never_modified() {
    let dir = Scratch::new();
    let saved = record(&request(), &BTreeMap::new());
    let mut tampered: Value = serde_json::from_str(&saved).unwrap();
    tampered["elapsed_ms"] = json!("999");
    let mut version: Value = serde_json::from_str(&saved).unwrap();
    version["checkpoint_version"] = json!(2);
    for bytes in [
        "foreign".to_owned(),
        "{".to_owned(),
        saved[..saved.len() / 2].to_owned(),
        tampered.to_string(),
        version.to_string(),
    ] {
        dir.write("save", &bytes);
        let reason = CheckpointRecord::parse_json(&bytes).unwrap_err();
        dir.reject(
            &["missing.json", "--resume", "save"],
            &request(),
            &format!("invalid checkpoint \"save\": {reason}"),
        );
        dir.unchanged("save", &bytes);
    }
    let reason = std::fs::read_to_string(dir.0.join("absent")).unwrap_err();
    dir.reject(
        &["--resume", "absent", "missing.json"],
        &request(),
        &format!("invalid checkpoint \"absent\": {reason}"),
    );
}
#[test]
fn identity_drift_and_checked_restore_fail_before_started() {
    let dir = Scratch::new();
    let original = request();
    let mut changed = original.clone();
    changed["job"]["text"] = json!("AB");
    let saved = record(&original, &BTreeMap::new());
    dir.write("save", &saved);
    dir.reject(
        &["--resume", "save", "--request", "-"],
        &changed,
        "checkpoint \"save\" belongs to a different search",
    );
    dir.unchanged("save", &saved);
    // Codec-valid and identity-matching input still needs Core re-scoring.
    let attack = AttackRequest::parse_json(&changed.to_string()).unwrap();
    let bad = capture(&attack, &original, &BTreeMap::new());
    let parsed = CheckpointRecord::parse_json(&bad).unwrap();
    let bound = AttackRequest::parse_json(&original.to_string()).unwrap();
    let reason = bound.resume(&parsed).err().unwrap();
    dir.write("save", &bad);
    dir.reject(
        &["--request", "-", "--resume", "save"],
        &original,
        &format!("invalid checkpoint \"save\": {reason}"),
    );
    dir.unchanged("save", &bad);
    let mut backed = original;
    backed["job"]["measures"] = json!(["ic", "sinkov_bigram"]);
    backed["job"]["resources"] = json!({"sinkov_bigram":{"path":"model.json"}});
    let model = json!({"resource_version":1,"kind":"ngram","alphabet":["A","B"],"order":2,"entries":[{"gram":["A","A"],"count":1}]}).to_string();
    let resources = BTreeMap::from([("sinkov_bigram".into(), model.clone())]);
    let saved = record(&backed, &resources);
    dir.write("save", &saved);
    dir.write("model.json", &format!("{model}\n"));
    dir.reject(
        &["--resume", "save", "--request", "-"],
        &backed,
        "checkpoint \"save\" belongs to a different search",
    );
    dir.unchanged("save", &saved);
    dir.unchanged("model.json", &format!("{model}\n"));
}
#[test]
fn valid_resume_and_checkpoint_preserve_normal_results() {
    let dir = Scratch::new();
    let value = request();
    let baseline = dir.run(&["--request", "-", "--threads", "1"], &value);
    assert_eq!(baseline.status.code(), Some(0));
    assert!(baseline.stderr.is_empty());
    let attack = AttackRequest::parse_json(&value.to_string()).unwrap();
    let mut expected = vec![enigma_core::Event::Started];
    let result = attack
        .run(
            |p| expected.push(enigma_core::Event::progress(p, 0)),
            || false,
        )
        .unwrap();
    expected.extend([
        enigma_core::Event::result(&result, 0),
        enigma_core::Event::Done {
            reason: result.termination().into(),
        },
    ]);
    let expected: Vec<Value> = expected
        .iter()
        .map(|e| {
            normalize(serde_json::from_str(&enigma_core::encode(e, 1, "UTC").unwrap()).unwrap())
        })
        .collect();
    assert_eq!(events(&baseline), expected);
    let fresh = dir.run(&["--checkpoint", "new", "--request", "-"], &value);
    assert_eq!(fresh.status.code(), Some(0));
    assert!(fresh.stderr.is_empty());
    assert_eq!(events(&fresh), expected);
    let saved = record(&value, &BTreeMap::new());
    dir.write("save", &saved);
    let args = ["--request", "-", "--resume", "save", "--threads", "2"];
    let resumed = dir.run(&args, &value);
    assert_eq!(resumed.status.code(), Some(0));
    assert!(resumed.stderr.is_empty());
    let mut restored_expected = expected;
    restored_expected[1] = restored_expected[2].clone();
    assert_eq!(events(&resumed), restored_expected);
    for line in std::str::from_utf8(&resumed.stdout).unwrap().lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        if let Some(elapsed) = event["elapsed_ms"].as_str() {
            assert!(elapsed.parse::<u128>().unwrap() >= 1234);
        }
    }
    dir.unchanged("save", &saved);
}
