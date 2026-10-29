//! Distinct wheels: public CLI evidence for the constraint, its counts, results and errors.
mod support;

use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use support::successful_events;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "enigma-distinct-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str], input: &Value) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
            .current_dir(&self.0)
            .env_remove("ENIGMA_TEST_CHECKPOINT_INTERVAL_MS")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Err(error) = child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
        {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        child.wait_with_output().unwrap()
    }
    fn events(&self, args: &[&str], input: &Value) -> Vec<Value> {
        successful_events(&self.run(
            &[&["--events", "-", "--request", "-"][..], args].concat(),
            input,
        ))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn request(constrained: bool) -> Value {
    // Five wheel identities over a tiny alphabet; identical wirings make every IC
    // score equal, exposing the complete enumeration/tie order through the hold.
    let wheels: Vec<_> = (0..5).map(|i| format!("w{i}")).collect();
    let slots = ["left", "middle", "right"];
    let mut value = json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B"],
        "wheels":wheels.iter().map(|w| json!({"name":w,"wiring":["B","A"],"turnovers":[]})).collect::<Vec<_>>(),
        "slots":slots.iter().map(|id| json!({"id":id,"role":"rotor","movement":"fixed","allowed_wheels":wheels})).collect::<Vec<_>>(),
        "stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":slots.iter().map(|id| json!({"id":id,"ring":"A"})).collect::<Vec<_>>(),"plugboard":[]},
        "space":{"slots":slots.iter().map(|id| json!({"id":id,"wheels":wheels,"positions":["A","B"]})).collect::<Vec<_>>(),
        "plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":0}},
        "text":"AA","passes":["hill_climb"],"measures":["ic"],"resources":{},
        "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,"start":[],"hold":1000}}});
    if constrained {
        value["job"]["space"]["constraints"] = json!({"distinct_wheels":slots});
    }
    value
}

fn terminal(events: &[Value]) -> Vec<Value> {
    events
        .iter()
        .filter(|e| e["event"] == "result" || e["event"] == "done")
        .cloned()
        .map(|mut e| {
            for field in [
                "ts",
                "elapsed_ms",
                "seq",
                "threads",
                "started_at",
                "finished_at",
            ] {
                e.as_object_mut().unwrap().remove(field);
            }
            e
        })
        .collect()
}

fn oracle(constrained: bool) -> Vec<Value> {
    let mut keys = Vec::new();
    for left in 0..5 {
        for lp in ["A", "B"] {
            for middle in 0..5 {
                for mp in ["A", "B"] {
                    for right in 0..5 {
                        for rp in ["A", "B"] {
                            if constrained && (left == middle || left == right || middle == right) {
                                continue;
                            }
                            keys.push(json!([
                                {"id":"left","wheel":format!("w{left}"),"position":lp,"ring":"A"},
                                {"id":"middle","wheel":format!("w{middle}"),"position":mp,"ring":"A"},
                                {"id":"right","wheel":format!("w{right}"),"position":rp,"ring":"A"}
                            ]));
                        }
                    }
                }
            }
        }
    }
    keys
}

fn check_keys(events: &[Value], expected: &[Value], offset: usize) {
    assert_eq!(events.first().unwrap()["event"], "started");
    assert_eq!(events[0]["outers_selected"], expected.len().to_string());
    let end = terminal(events);
    assert_eq!(end.len(), 2);
    assert_eq!(
        end[1],
        json!({"event":"done","protocol_version":1,"reason":"completed"})
    );
    let result = &end[0];
    assert_eq!(
        result["counters"]["outers_completed"],
        expected.len().to_string()
    );
    let hold = result["hold"].as_array().unwrap();
    assert_eq!(hold.len(), expected.len());
    for (i, entry) in hold.iter().enumerate() {
        assert_eq!(entry["configuration"]["slots"], expected[i]);
        assert_eq!(entry["outer_index"], (offset + i).to_string());
    }
    assert_eq!(result["best"]["configuration"]["slots"], expected[0]);
    assert_eq!(result["best"]["outer_index"], offset.to_string());
}

#[test]
fn version_030_keeps_protocol_1() {
    let output = Scratch::new().run(&["--version"], &json!(null));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    assert_eq!(output.stdout, b"enigma 0.3.0\nprotocol version 1\n");
}

#[test]
fn constrained_attack_count_keys_and_filtered_slice() {
    let dir = Scratch::new();
    let expected = oracle(true);
    // 5 * 4 * 3 distinct wheel orders, times 2^3 positions = 480.
    assert_eq!(expected.len(), 60 * 8);
    let mut input = request(true);
    check_keys(&dir.events(&["--threads", "1"], &input), &expected, 0);
    // Cross both a wheel-order and a 128-key block boundary in filtered order.
    input["job"]["space"]["offset"] = json!(117);
    input["job"]["space"]["limit"] = json!(137);
    check_keys(
        &dir.events(&["--threads", "1"], &input),
        &expected[117..254],
        117,
    );
    input["job"]["space"]["offset"] = json!(477);
    check_keys(&dir.events(&[], &input), &expected[477..], 477);
}

#[test]
fn constrained_human_report_matches_filtered_count_and_keys() {
    let dir = Scratch::new();
    let output = dir.run(
        &["--request", "-", "--no-report", "--threads", "1"],
        &request(true),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Outer keys:   480 of 480\n"));
    let wheels: Vec<_> = report
        .lines()
        .filter_map(|line| line.strip_prefix("    Wheels:     "))
        .collect();
    assert_eq!(wheels.len(), 480);
    for line in wheels {
        let names: Vec<_> = line.split_whitespace().collect();
        assert_eq!(names.len(), 3);
        assert!(names[0] != names[1] && names[0] != names[2] && names[1] != names[2]);
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn unconstrained_attack_preserves_product_order_and_repeated_wheels() {
    let expected = oracle(false);
    // No implicit rule: 5^3 wheel orders times 2^3 positions = 1000.
    assert_eq!(expected.len(), 125 * 8);
    check_keys(
        &Scratch::new().events(&["--threads", "1"], &request(false)),
        &expected,
        0,
    );
}

#[test]
fn constrained_threads_one_and_four_have_identical_results() {
    let dir = Scratch::new();
    let input = request(true);
    let serial = dir.events(&["--threads", "1"], &input);
    let parallel = dir.events(&["--threads", "4"], &input);
    assert_eq!(
        serial.iter().find(|e| e["event"] == "result").unwrap()["threads"],
        "1"
    );
    assert_eq!(
        parallel.iter().find(|e| e["event"] == "result").unwrap()["threads"],
        "4"
    );
    assert_eq!(terminal(&serial), terminal(&parallel));
}

#[test]
fn constrained_cancel_checkpoint_resume_matches_uninterrupted() {
    let dir = Scratch::new();
    let input = request(true);
    std::fs::write(dir.0.join("marker"), b"cancel").unwrap();
    let cancelled = dir.events(
        &[
            "--checkpoint",
            "save",
            "--cancel-file",
            "marker",
            "--threads",
            "1",
        ],
        &input,
    );
    let end = terminal(&cancelled);
    assert_eq!(end[1]["reason"], "cancelled");
    assert_eq!(end[0]["best"], Value::Null);
    assert_eq!(end[0]["hold"], json!([]));
    for counter in end[0]["counters"].as_object().unwrap().values() {
        assert_eq!(counter, "0");
    }
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.0.join("save")).unwrap()).unwrap();
    assert_eq!(saved["phase"], "outer");
    assert_eq!(saved["next_outer"], "0");
    assert!(cancelled.iter().any(|e| e["event"] == "checkpoint"));
    let normal = dir.events(&["--threads", "1"], &input);
    let resumed = dir.events(&["--resume", "save", "--threads", "4"], &input);
    assert_eq!(terminal(&resumed), terminal(&normal));
    assert_eq!(std::fs::read(dir.0.join("marker")).unwrap(), b"cancel");
    assert!(!dir.0.join("save.tmp").exists());
}

#[test]
fn checkpoint_identity_rejects_both_constraint_mode_changes_without_writes() {
    let dir = Scratch::new();
    for constrained in [true, false] {
        let name = if constrained {
            "constrained"
        } else {
            "unconstrained"
        };
        dir.events(
            &["--checkpoint", name, "--threads", "1"],
            &request(constrained),
        );
        let before = std::fs::read(dir.0.join(name)).unwrap();
        let output = dir.run(
            &["--events", "-", "--request", "-", "--resume", name],
            &request(!constrained),
        );
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, b"");
        assert_eq!(
            output.stderr,
            format!("error: checkpoint \"{name}\" belongs to a different search\n").as_bytes()
        );
        assert_eq!(std::fs::read(dir.0.join(name)).unwrap(), before);
        assert!(!dir.0.join(format!("{name}.tmp")).exists());
    }
}

#[test]
fn impossible_and_legacy_constraints_are_exact_preflight_errors() {
    let dir = Scratch::new();
    let mut impossible = request(true);
    for i in [0, 1] {
        impossible["job"]["configuration"]["slots"][i]["wheel"] = json!("w0");
        impossible["job"]["space"]["slots"][i]
            .as_object_mut()
            .unwrap()
            .remove("wheels");
    }
    let mut legacy = request(true);
    legacy["job"].as_object_mut().unwrap().remove("attack");
    legacy["job"]["space"]
        .as_object_mut()
        .unwrap()
        .remove("plugboard");
    for (input, path, message) in [
        (
            impossible,
            "/job/space/constraints/distinct_wheels",
            "no assignment of the slots named by distinct_wheels uses distinct wheels",
        ),
        (
            legacy,
            "/job/space/constraints",
            "constraints are allowed only on the attack branch (space.plugboard.kind = \"attack\")",
        ),
    ] {
        let output = dir.run(&["--events", "-", "--request", "-"], &input);
        assert_eq!(output.status.code(), Some(1));
        let mut diagnostic = format!("invalid_search_space at {path}: {message}\n");
        if path.ends_with("/distinct_wheels") {
            // Binding failures include both the detailed diagnostic and summary.
            diagnostic.push_str(&format!("invalid_search_space: {message}\n"));
        }
        assert_eq!(output.stderr, diagnostic.as_bytes());
        let mut event: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(event["seq"], 1);
        assert!(event["ts"].is_string());
        event.as_object_mut().unwrap().remove("ts");
        assert_eq!(
            event,
            json!({"event":"error","protocol_version":1,"seq":1,"code":"invalid_search_space","message":message,"location":path})
        );
        assert!(output.stdout.ends_with(b"\n"));
        let human = dir.run(&["--request", "-", "--no-report"], &input);
        assert_eq!(human.status.code(), Some(1));
        assert_eq!(human.stdout, b"");
        assert_eq!(human.stderr, output.stderr);
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
    }
}
