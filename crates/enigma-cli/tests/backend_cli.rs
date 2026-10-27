//! L38: backend selection is host configuration, never silent CPU fallback.
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.scratch/t6")
            .join(format!(
                "enigma-backend-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str], input: &Value) -> Output {
        let stored = || {
            let mut files: Vec<_> = std::fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let contents = std::fs::read(&path).unwrap();
                    (path, contents)
                })
                .collect();
            files.sort();
            files
        };
        let before = stored();
        let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
            .current_dir(&self.0)
            .env_remove("ENIGMA_TEST_CHECKPOINT_INTERVAL_MS")
            .args(["--events", "-", "--request", "-"])
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
        let output = child.wait_with_output().unwrap();
        // Report-free invocations must leave resources unchanged and no new state.
        assert_eq!(stored(), before);
        output
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn transform() -> Value {
    json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B"],"wheels":[{"name":"r","wiring":["B","A"],"turnovers":[]}],
        "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],"stepping":{"rules":[]}}}},
        "job":{"kind":"transform","configuration":{"slots":[{"id":"r","wheel":"r","position":"A","ring":"A"}],"plugboard":[]},"text":"AA","direction":"encrypt"}})
}
fn attack() -> Value {
    let mut value = transform();
    value["job"] = json!({"kind":"search","configuration":{"slots":[{"id":"r","ring":"A"}],"plugboard":[]},
        "space":{"slots":[{"id":"r","positions":["A","B"]}],"plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":1}},
        "text":"AA","passes":["hill_climb"],"measures":["ic"],"resources":{},
        "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":1,"backtrack_pairs":0,"start":[]}});
    value
}
fn events(output: &Output) -> Vec<Value> {
    assert!(output.stdout.ends_with(b"\n"));
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let mut value: Value = serde_json::from_str(line).unwrap();
            assert!(value["ts"].is_string());
            for key in ["ts", "elapsed_ms", "threads", "started_at", "finished_at"] {
                value.as_object_mut().unwrap().remove(key);
            }
            value
        })
        .collect()
}
fn usage(output: Output, message: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(output.stderr, format!("error: {message}\n").as_bytes());
}
fn rejection(output: &Output, code: &str, message: &str, location: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stderr, format!("{code}: {message}\n").as_bytes());
    assert_eq!(
        events(output),
        vec![
            json!({"event":"error","protocol_version":1,"seq":1,"code":code,"message":message,"location":location})
        ]
    );
}
#[test]
fn invalid_backend_is_rejected_before_input() {
    usage(
        Scratch::new().run(&["--backend", "other"], &json!(null)),
        "--backend expects cpu or gpu, got \"other\"",
    );
}
#[test]
fn invalid_gpu_usage_is_rejected_before_input() {
    for value in ["0", "101", "x", "", "+1", "-1", "１", "1.0"] {
        usage(
            Scratch::new().run(&["--backend", "gpu", "--gpu-usage", value], &json!(null)),
            &format!("--gpu-usage expects an integer from 1 to 100, got {value:?}"),
        );
    }
}
#[test]
fn gpu_usage_requires_explicit_gpu_backend() {
    for args in [
        vec!["--gpu-usage", "20"],
        vec!["--gpu-usage", "20", "--backend", "cpu"],
    ] {
        usage(
            Scratch::new().run(&args, &json!(null)),
            "--gpu-usage requires --backend gpu",
        );
    }
}
#[test]
fn duplicate_backend_and_gpu_usage_are_usage_errors() {
    let dir = Scratch::new();
    let help = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert_eq!(help.stderr, b"");
    for args in [
        vec!["--backend", "cpu", "--backend", "gpu"],
        vec!["--backend", "gpu", "--gpu-usage", "20", "--gpu-usage", "30"],
        vec!["--backend"],
        vec!["--gpu-usage"],
    ] {
        let output = dir.run(&args, &json!(null));
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, b"");
        assert_eq!(output.stderr, help.stdout);
    }
}
#[test]
fn non_attack_jobs_reject_backend_after_existing_option_precedence() {
    let dir = Scratch::new();
    let mut search = attack();
    search["job"].as_object_mut().unwrap().remove("attack");
    search["job"]["space"]
        .as_object_mut()
        .unwrap()
        .remove("plugboard");
    for input in [transform(), search] {
        for args in [
            vec!["--backend", "cpu"],
            vec!["--backend", "gpu", "--gpu-usage", "20"],
        ] {
            rejection(
                &dir.run(&args, &input),
                "unsupported_job",
                "--backend is supported only for hill_climb and partial_exhaustion attacks",
                "/job/kind",
            );
        }
        for (args, option) in [
            (vec!["--backend", "gpu", "--threads", "1"], "--threads"),
            (
                vec![
                    "--backend",
                    "gpu",
                    "--threads",
                    "1",
                    "--cancel-file",
                    "marker",
                ],
                "--cancel-file",
            ),
        ] {
            rejection(
                &dir.run(&args, &input),
                "unsupported_job",
                &format!(
                    "{option} is supported only for hill_climb and partial_exhaustion attacks"
                ),
                "/job/kind",
            );
        }
    }
}
#[test]
fn explicit_cpu_preserves_default_attack_events() {
    let dir = Scratch::new();
    let default = dir.run(&[], &attack());
    let cpu = dir.run(&["--backend", "cpu"], &attack());
    assert_eq!(default.status.code(), Some(0));
    assert_eq!(cpu.status.code(), Some(0));
    assert_eq!(default.stderr, b"");
    assert_eq!(cpu.stderr, b"");
    assert_eq!(events(&default), events(&cpu));
    assert_eq!(events(&cpu).last().unwrap()["reason"], "completed");
}
#[test]
fn gpu_row_limit_is_rejected_before_started() {
    let dir = Scratch::new();
    let mut input = attack();
    input["job"]["text"] = json!("A".repeat(262145));
    rejection(
        &dir.run(&["--backend", "gpu"], &input),
        "unsupported_job",
        "--backend gpu does not support this attack: text exceeds accelerator row data limit",
        "/job/attack",
    );
}
#[test]
fn gpu_trie_matches_cpu_or_reports_unavailability() {
    let dir = Scratch::new();
    std::fs::write(
        dir.0.join("words.json"),
        json!({"resource_version":1,"kind":"dictionary",
        "alphabet":["A","B"],"entries":[{"word":["A"],"weight":1}]})
        .to_string(),
    )
    .unwrap();
    let mut input = attack();
    input["job"]["measures"] = json!(["trie"]);
    input["job"]["resources"] = json!({"trie":{"path":"words.json"}});
    input["job"]["attack"]["initial_measure"] = json!("trie");
    input["job"]["attack"]["final_measure"] = json!("trie");
    gpu_matches_cpu_in(&dir, &input);
}
#[test]
fn gpu_partial_exhaustion_matches_cpu_or_reports_unavailability() {
    let mut input = attack();
    input["job"]["passes"] = json!(["partial_exhaustion"]);
    input["job"]["attack"]
        .as_object_mut()
        .unwrap()
        .remove("start");
    input["job"]["attack"]["kind"] = json!("partial_exhaustion");
    input["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
    input["job"]["attack"]["hold"] = json!(3);
    gpu_matches_cpu(&input);
}

#[test]
fn gpu_at_low_usage_matches_cpu_or_reports_unavailability() {
    gpu_matches_cpu(&attack());
}

fn gpu_matches_cpu(input: &Value) {
    gpu_matches_cpu_in(&Scratch::new(), input);
}

fn gpu_matches_cpu_in(dir: &Scratch, input: &Value) {
    let gpu = dir.run(
        &["--backend", "gpu", "--gpu-usage", "20", "--threads", "1"],
        input,
    );
    let observed = events(&gpu);
    if observed[0]["code"] == "backend_unavailable" {
        let message = observed[0]["message"].as_str().unwrap();
        assert!(message.starts_with("GPU backend unavailable: "));
        rejection(&gpu, "backend_unavailable", message, "");
        eprintln!("SKIP GPU CLI equivalence: {message}");
        return;
    }
    assert_eq!(
        gpu.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&gpu.stderr)
    );
    assert_eq!(gpu.stderr, b"");
    let cpu = dir.run(&["--backend", "cpu", "--threads", "1"], input);
    assert_eq!(cpu.status.code(), Some(0));
    assert_eq!(cpu.stderr, b"");
    assert_eq!(observed, events(&cpu));
}
