//! Human mode is the default and `--events <path|->` selects the JSONL destination
//! (`docs/protocol.md` §2.2, §2.3).
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "enigma-events-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
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
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn transform() -> Value {
    json!({"protocol_version":1,"machine":{"definition":{"kind":"bundled","id":"enigma-i"}},
        "job":{"kind":"transform","configuration":{"slots":[
            {"id":"reflector","wheel":"B","position":"A","ring":"A"},
            {"id":"left","wheel":"I","position":"A","ring":"A"},
            {"id":"middle","wheel":"II","position":"A","ring":"A"},
            {"id":"right","wheel":"III","position":"A","ring":"A"}],"plugboard":[]},
            "text":"AAAA","direction":"encrypt"}})
}

fn attack() -> Value {
    json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B"],"wheels":[{"name":"r","wiring":["B","A"],"turnovers":[]}],
        "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],"stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":[{"id":"r","ring":"A"}],"plugboard":[]},
        "space":{"slots":[{"id":"r","positions":["A","B"]}],"plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":1}},
        "text":"AA","passes":["hill_climb"],"measures":["ic"],"resources":{},
        "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":1,"backtrack_pairs":0,"start":[]}}})
}

fn events(jsonl: &[u8]) -> Vec<Value> {
    let text = std::str::from_utf8(jsonl).unwrap();
    assert!(text.ends_with('\n'), "{text:?}");
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn names(events: &[Value]) -> Vec<&str> {
    events
        .iter()
        .map(|event| event["event"].as_str().unwrap())
        .collect()
}

#[test]
fn events_dash_writes_the_jsonl_stream_to_stdout() {
    let dir = Scratch::new();
    for args in [
        &["--events", "-", "--request", "-"][..],
        &["--request", "-", "--events", "-"][..],
    ] {
        let output = dir.run(args, &transform());
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        assert_eq!(output.stderr, b"", "{args:?}");
        let events = events(&output.stdout);
        assert_eq!(names(&events), ["started", "output", "done"], "{args:?}");
        assert_eq!(events[1]["output"], json!("BDZG"));
    }
    let output = dir.run(&["--events", "-", "--request", "-"], &attack());
    assert_eq!(output.status.code(), Some(0));
    let events = events(&output.stdout);
    assert_eq!(names(&events)[0], "started");
    assert_eq!(names(&events)[events.len() - 2..], ["result", "done"]);
}

#[test]
fn human_mode_prints_transform_text_and_no_events() {
    let dir = Scratch::new();
    let output = dir.run(&["--request", "-"], &transform());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"BDZG\n");
    assert_eq!(output.stderr, b"");
}

#[test]
fn human_mode_attack_writes_no_jsonl_to_stdout() {
    let dir = Scratch::new();
    let output = dir.run(&["--request", "-"], &attack());
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("\"event\""),
        "stdout must carry no JSONL event in human mode"
    );
    // stderr is not a terminal here, so no progress bar is drawn.
    assert_eq!(output.stderr, b"");
}

#[test]
fn events_file_receives_the_same_stream_as_events_dash() {
    let dir = Scratch::new();
    let piped = dir.run(&["--events", "-", "--request", "-"], &attack());
    let output = dir.run(&["--request", "-", "--events", "run.jsonl"], &attack());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    let strip = |events: Vec<Value>| -> Vec<Value> {
        events
            .into_iter()
            .map(|mut event| {
                let object = event.as_object_mut().unwrap();
                object.remove("ts");
                object.remove("elapsed_ms");
                event
            })
            .collect()
    };
    let saved = std::fs::read(dir.path("run.jsonl")).unwrap();
    assert_eq!(strip(events(&saved)), strip(events(&piped.stdout)));

    let transformed = dir.run(&["--events", "t.jsonl", "--request", "-"], &transform());
    assert_eq!(transformed.status.code(), Some(0));
    assert_eq!(transformed.stdout, b"BDZG\n");
    let saved = std::fs::read(dir.path("t.jsonl")).unwrap();
    assert_eq!(names(&events(&saved)), ["started", "output", "done"]);
}

#[test]
fn an_existing_events_file_is_never_overwritten() {
    let dir = Scratch::new();
    std::fs::write(dir.path("run.jsonl"), "foreign").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("missing-target", dir.path("dangling")).unwrap();
    let mut names = vec!["run.jsonl"];
    if cfg!(unix) {
        names.push("dangling");
    }
    for name in names {
        let output = dir.run(&["--events", name, "--request", "-"], &transform());
        assert_eq!(output.status.code(), Some(2), "{name}");
        assert_eq!(output.stdout, b"", "{name}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("error: --events file already exists: {name:?}\n")
        );
    }
    assert_eq!(
        std::fs::read_to_string(dir.path("run.jsonl")).unwrap(),
        "foreign"
    );
    assert!(!dir.path("missing-target").exists());
}

#[test]
fn validation_errors_keep_stdout_empty_in_human_mode() {
    let dir = Scratch::new();
    let mut invalid = transform();
    invalid["job"]["text"] = json!("A1");
    let piped = dir.run(&["--events", "-", "--request", "-"], &invalid);
    assert_eq!(piped.status.code(), Some(1));
    let error = &events(&piped.stdout)[0];
    assert_eq!(error["event"], json!("error"));

    let human = dir.run(&["--request", "-", "--events", "err.jsonl"], &invalid);
    assert_eq!(human.status.code(), Some(1));
    assert_eq!(human.stdout, b"");
    assert_eq!(human.stderr, piped.stderr);
    let saved = events(&std::fs::read(dir.path("err.jsonl")).unwrap());
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["code"], error["code"]);
    assert_eq!(saved[0]["location"], error["location"]);
}

#[test]
fn malformed_events_arguments_are_usage_errors() {
    let dir = Scratch::new();
    for args in [
        &["--request", "-", "--events"][..],
        &["--events", "--request", "-"][..],
        &["--events", "-", "--events", "x", "--request", "-"][..],
        &["--events", "-", "--request", "-", "--events", "x"][..],
    ] {
        let output = dir.run(args, &transform());
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(output.stdout, b"", "{args:?}");
        assert!(String::from_utf8(output.stderr).unwrap().contains("Usage:"));
    }
    assert!(!dir.path("x").exists());
}
