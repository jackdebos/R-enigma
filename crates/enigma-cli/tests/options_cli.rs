//! Public command-line contract, pinned to protocol §2.1.
use enigma_core::{checkpoint_identity, AttackRequest, ExecutionOptions};
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
            "enigma-options-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
            .current_dir(&self.0)
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
            .write_all(transform().to_string().as_bytes())
        {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        child.wait_with_output().unwrap()
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
fn help() -> String {
    let doc = include_str!("../../../docs/protocol.md");
    doc.split("The help text is exactly")
        .nth(1)
        .unwrap()
        .split("```text\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap()
        .replace("<version>", env!("CARGO_PKG_VERSION"))
        .replace(
            "protocol version 1",
            &format!("protocol version {}", enigma_core::PROTOCOL_VERSION),
        )
}
fn check(output: Output, code: i32, stdout: &str, stderr: &str) {
    assert_eq!(output.status.code(), Some(code));
    assert_eq!(output.stdout, stdout.as_bytes());
    assert_eq!(output.stderr, stderr.as_bytes());
}
#[test]
fn help_and_version_are_exact_and_win_before_input_or_validation() {
    let dir = Scratch::new();
    for args in [
        vec!["-h"],
        vec!["--help"],
        vec!["--threads", "x", "-h"],
        vec!["--bogus", "--help"],
        vec!["-V", "missing", "-h"],
        vec!["--report", "existing", "--no-report", "--help"],
    ] {
        check(dir.run(&args), 0, &help(), "");
    }
    let version = format!(
        "enigma {}\nprotocol version {}\n",
        env!("CARGO_PKG_VERSION"),
        enigma_core::PROTOCOL_VERSION
    );
    for args in [
        vec!["-V"],
        vec!["--version"],
        vec!["--bogus", "-V"],
        vec!["--threads", "x", "--version"],
    ] {
        check(dir.run(&args), 0, &version, "");
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}
#[test]
fn malformed_shapes_are_exact_usage_errors_without_side_effects() {
    let dir = Scratch::new();
    let mut cases = vec![
        vec![],
        vec!["-tc"],
        vec!["-t", "-c"],
        vec!["-z"],
        vec!["-q"],
        vec!["a", "b"],
        vec!["a", "-i", "-"],
        vec!["--request=-"],
        vec!["-i", "--bogus"],
        vec!["--no-report", "--no-report", "-i", "-"],
    ];
    for (short, long) in [
        ("-i", "--request"),
        ("-e", "--events"),
        ("-o", "--report"),
        ("-t", "--threads"),
        ("-c", "--checkpoint"),
        ("-r", "--resume"),
        ("-x", "--cancel-file"),
    ] {
        cases.push(vec![short]);
        cases.push(vec![long]);
        cases.push(vec![short, "2", long, "3", "-i", "-"]);
        cases.push(vec![long, "2", short, "3", "-i", "-"]);
        for reserved in ["-i", "-e", "-o", "-t", "-c", "-r", "-x", "--bogus"] {
            cases.push(vec![short, reserved]);
        }
    }
    for args in cases {
        check(dir.run(&args), 2, "", &help());
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}
#[test]
fn report_preflight_preserves_existing_files_and_dangling_links() {
    let dir = Scratch::new();
    std::fs::write(dir.0.join("existing"), "foreign").unwrap();
    std::fs::create_dir(dir.0.join("directory")).unwrap();
    let mut names = vec!["existing", "directory"];
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("absent", dir.0.join("dangling")).unwrap();
        names.push("dangling");
    }
    for flag in ["--report", "-o"] {
        check(
            dir.run(&[flag, "existing", "--no-report", "missing"]),
            2,
            "",
            "error: --report and --no-report cannot be combined\n",
        );
        check(
            dir.run(&[flag, "new", "--no-report"]),
            2,
            "",
            "error: --report and --no-report cannot be combined\n",
        );
        for name in &names {
            for args in [vec!["missing", flag, name], vec![flag, name]] {
                check(
                    dir.run(&args),
                    2,
                    "",
                    &format!("error: --report file already exists: {name:?}\n"),
                );
            }
        }
        check(dir.run(&[flag, "new", "-i", "-"]), 0, "BB\n", "");
        assert!(!dir.0.join("new").exists()); // Saving is T5, not parser work.
    }
    check(dir.run(&["--no-report", "-i", "-"]), 0, "BB\n", "");
    assert_eq!(std::fs::read(dir.0.join("existing")).unwrap(), b"foreign");
    #[cfg(unix)]
    assert_eq!(
        std::fs::read_link(dir.0.join("dangling")).unwrap(),
        PathBuf::from("absent")
    );
}
#[test]
fn short_forms_preserve_long_form_execution_and_diagnostics() {
    let dir = Scratch::new();
    let mut attack = transform();
    attack["job"] = json!({"kind":"search","configuration":{"slots":[{"id":"r","ring":"A"}],"plugboard":[]},"space":{"slots":[{"id":"r","positions":["A","B"]}],"plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":1}},"text":"AA","passes":["hill_climb"],"measures":["ic"],"resources":{},"attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":1,"backtrack_pairs":0,"start":[]}});
    let identity = checkpoint_identity(&attack.to_string(), &BTreeMap::new()).unwrap();
    let mut saved = String::new();
    AttackRequest::parse_json(&attack.to_string())
        .unwrap()
        .run_with_checkpoints(
            ExecutionOptions::serial(),
            |_| {},
            || false,
            |s| saved = s.record(identity, 0).unwrap().seal_json().unwrap(),
        )
        .unwrap();
    std::fs::write(dir.0.join("resume"), &saved).unwrap();
    for (short,long,value,message) in [
        ("-t","--threads","2","--threads is supported only for hill_climb and partial_exhaustion attacks"),
        ("-x","--cancel-file","marker","--cancel-file is supported only for hill_climb and partial_exhaustion attacks"),
        ("-c","--checkpoint","new","--checkpoint and --resume are supported only for hill_climb and partial_exhaustion attacks"),
        ("-r","--resume","resume","--checkpoint and --resume are supported only for hill_climb and partial_exhaustion attacks")
    ] {
        for flag in [short,long] { check(dir.run(&["-i","-",flag,value]),1,"", &format!("unsupported_job: {message}\n")); }
    }
    for flag in ["-t", "--threads"] {
        check(
            dir.run(&[flag, "x", "-i", "-"]),
            2,
            "",
            "error: --threads expects an integer from 1 to 256, got \"x\"\n",
        );
    }
    for flag in ["-c", "--checkpoint"] {
        for args in [vec![flag, "resume", "missing"], vec![flag, "resume"]] {
            check(
                dir.run(&args),
                2,
                "",
                "error: --checkpoint file already exists, use --resume to continue it: \"resume\"\n",
            );
        }
    }
    for flag in ["-i", "--request"] {
        check(dir.run(&[flag, "-"]), 0, "BB\n", "");
    }
    std::fs::write(dir.0.join("request"), transform().to_string()).unwrap();
    for args in [
        vec!["request", "--no-report"],
        vec!["--no-report", "request"],
        vec!["-i", "request", "--no-report"],
    ] {
        check(dir.run(&args), 0, "BB\n", "");
    }
    let expected: Vec<Value> = [
        json!({"event":"started","protocol_version":1,"seq":1}),
        json!({"event":"output","protocol_version":1,"seq":2,"output":"BB"}),
        json!({"event":"done","protocol_version":1,"seq":3,"reason":"completed"}),
    ]
    .into();
    for (flag, name) in [("-e", "short"), ("--events", "long")] {
        let out = dir.run(&[flag, "-", "-i", "-"]);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(out.stderr, b"");
        let normalize = |bytes: &[u8]| -> Vec<Value> {
            std::str::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(|line| {
                    let mut v: Value = serde_json::from_str(line).unwrap();
                    v.as_object_mut().unwrap().remove("ts");
                    v
                })
                .collect()
        };
        assert_eq!(normalize(&out.stdout), expected);
        check(dir.run(&["--request", "-", flag, name]), 0, "BB\n", "");
        assert_eq!(
            normalize(&std::fs::read(dir.0.join(name)).unwrap()),
            expected
        );
    }
    assert_eq!(
        std::fs::read_to_string(dir.0.join("resume")).unwrap(),
        saved
    );
    assert!(!dir.0.join("new").exists());
}
