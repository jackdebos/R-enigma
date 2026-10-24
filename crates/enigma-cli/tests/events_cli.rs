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

#[test]
fn reports_saved_and_event_mode_opt_in() {
    let dir = Scratch::new();
    for option in ["--report", "-o"] {
        let name = format!("report{option}.txt");
        let output = dir.run(&["--request", "-", option, &name], &attack());
        assert_eq!(output.status.code(), Some(0));
        assert!(output
            .stdout
            .starts_with(b"Enigma attack report\nStatus:       completed\nRequest:      stdin\n"));
        assert_eq!(std::fs::read(dir.path(&name)).unwrap(), output.stdout);
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!(
                "Report {name:?} saved successfully in {}\n",
                dir.0.canonicalize().unwrap().display()
            )
        );
    }
    let output = dir.run(
        &[
            "--events",
            "-",
            "--request",
            "-",
            "--report",
            "transform.txt",
        ],
        &transform(),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        names(&events(&output.stdout)),
        ["started", "output", "done"]
    );
    let text = std::fs::read_to_string(dir.path("transform.txt")).unwrap();
    assert!(text.starts_with("Enigma transform report\nRequest:      stdin\n"));
    assert!(text.contains("Direction:    encrypt\n"));
    assert!(text.contains("Plugboard:  none\n"));
    assert!(text.ends_with("Input:      AAAA\nOutput:     BDZG\n"));
}

#[test]
fn default_reports_collision_and_cancel() {
    let dir = Scratch::new();
    std::fs::write(dir.path("request.json"), attack().to_string()).unwrap();
    std::fs::write(dir.path("request.report.txt"), b"foreign").unwrap();
    for _ in 0..3 {
        let output = dir.run(&["request.json", "--threads", "1"], &attack());
        assert_eq!(output.status.code(), Some(0));
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("Report \"request."));
    }
    assert_eq!(
        std::fs::read(dir.path("request.report.txt")).unwrap(),
        b"foreign"
    );
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 5);
    std::fs::write(dir.path("stop"), b"").unwrap();
    let output = dir.run(
        &[
            "request.json",
            "--cancel-file",
            "stop",
            "--checkpoint",
            "check point",
            "--no-report",
        ],
        &attack(),
    );
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Status:       CANCELLED\n"));
    assert!(text.ends_with("--resume 'check point' --no-report\n"));
    assert_eq!(output.stderr, b"");
    let output = dir.run(
        &[
            "request.json",
            "--cancel-file",
            "stop",
            "--report",
            "cancelled.txt",
        ],
        &attack(),
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.ends_with(
        b"Resume:       not available (run with --checkpoint to make a search resumable)\n"
    ));
    assert_eq!(
        std::fs::read(dir.path("cancelled.txt")).unwrap(),
        output.stdout
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "Report \"cancelled.txt\" saved successfully in {}\n",
            dir.0.canonicalize().unwrap().display()
        )
    );
}

#[test]
fn stdin_default_and_dangling_collision() {
    let dir = Scratch::new();
    let output = dir.run(&["--request", "-"], &transform());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"BDZG\n");
    let entries: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].starts_with("enigma-"));
    assert!(entries[0].ends_with("Z.report.txt"));
    #[cfg(unix)]
    {
        std::fs::write(dir.path("file.json"), transform().to_string()).unwrap();
        std::os::unix::fs::symlink("absent", dir.path("file.report.txt")).unwrap();
        let output = dir.run(&["file.json"], &transform());
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"BDZG\n");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.starts_with("Report \"file."));
        assert!(stderr.ends_with(&format!(
            "Z.report.txt\" saved successfully in {}\n",
            dir.0.canonicalize().unwrap().display()
        )));
        assert_eq!(
            std::fs::read_link(dir.path("file.report.txt")).unwrap(),
            PathBuf::from("absent")
        );
        assert!(!dir.path("absent").exists());
    }
}

#[test]
fn save_failure_preserves_printed_output() {
    let dir = Scratch::new();
    let output = dir.run(
        &["--request", "-", "--report", "missing/report.txt"],
        &transform(),
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"BDZG\n");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "error: failed to save report \"missing/report.txt\": {}\n",
            std::fs::File::open(dir.path("missing/report.txt")).unwrap_err()
        )
    );
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn report_race_never_overwrites_explicit_target() {
    let dir = Scratch::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .current_dir(&dir.0)
        .args([
            "--request",
            "-",
            "--events",
            "events.jsonl",
            "--report",
            "race.txt",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    while !dir.path("events.jsonl").exists() {
        assert!(start.elapsed().as_secs() < 10);
        std::thread::yield_now();
    }
    std::fs::write(dir.path("race.txt"), b"foreign").unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(transform().to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"BDZG\n");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "error: failed to save report \"race.txt\": {}\n",
            std::io::Error::from_raw_os_error(17)
        )
    );
    assert_eq!(std::fs::read(dir.path("race.txt")).unwrap(), b"foreign");
}

#[cfg(unix)]
#[test]
fn unwritable_directory_reports_failure() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let permissions = std::fs::metadata(&dir.0).unwrap().permissions();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o555)).unwrap();
    let output = dir.run(&["--request", "-", "--report", "out.txt"], &transform());
    std::fs::set_permissions(&dir.0, permissions).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"BDZG\n");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "error: failed to save report \"out.txt\": {}\n",
            std::io::Error::from_raw_os_error(13)
        )
    );
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn timestamp_collisions_increment_without_following_links() {
    let dir = Scratch::new();
    std::fs::write(dir.path("request.json"), transform().to_string()).unwrap();
    std::fs::write(dir.path("request.report.txt"), b"original").unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut originals = Vec::new();
    for second in now..now + 30 {
        let stamp = enigma_core::rfc3339_utc(second).replace(['-', ':'], "");
        let name = format!("request.{stamp}.report.txt");
        std::fs::write(dir.path(&name), b"timestamped").unwrap();
        originals.push(name);
    }
    let output = dir.run(&["request.json"], &transform());
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("-2.report.txt\" saved successfully"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(dir.path("request.report.txt")).unwrap(),
        b"original"
    );
    for name in originals {
        assert_eq!(std::fs::read(dir.path(&name)).unwrap(), b"timestamped");
    }
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
    assert_eq!(output.stderr, b"");
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
    let events = events(&output.stdout);
    assert_eq!(names(&events)[0], "started");
    assert_eq!(names(&events)[events.len() - 2..], ["result", "done"]);
}

#[test]
fn attack_additive_execution_data() {
    let dir = Scratch::new();
    for pe in [false, true] {
        for threads in ["1", "2"] {
            for sliced in [false, true] {
                let mut request = attack();
                if pe {
                    request["job"]["passes"] = json!(["partial_exhaustion"]);
                    let settings = request["job"]["attack"].as_object_mut().unwrap();
                    settings.insert("kind".into(), json!("partial_exhaustion"));
                    settings.remove("start");
                    settings.insert(
                        "seeds".into(),
                        json!({"kind":"empty_single","selection":"all"}),
                    );
                }
                if sliced {
                    request["job"]["space"]["offset"] = json!(1);
                    request["job"]["space"]["limit"] = json!(1);
                }
                let output = dir.run(
                    &["--events", "-", "--threads", threads, "--request", "-"],
                    &request,
                );
                assert_eq!(output.status.code(), Some(0));
                assert_eq!(output.stderr, b"");
                let wire = events(&output.stdout);
                assert_eq!(wire[0]["outers_selected"], if sliced { "1" } else { "2" });
                let result = &wire[wire.len() - 2];
                assert_eq!(result["threads"], threads);
                let start = result["started_at"].as_str().unwrap();
                let finish = result["finished_at"].as_str().unwrap();
                for timestamp in [start, finish] {
                    assert_eq!(timestamp.len(), 20);
                    for (index, byte) in timestamp.bytes().enumerate() {
                        match index {
                            4 | 7 => assert_eq!(byte, b'-'),
                            10 => assert_eq!(byte, b'T'),
                            13 | 16 => assert_eq!(byte, b':'),
                            19 => assert_eq!(byte, b'Z'),
                            _ => assert!(byte.is_ascii_digit()),
                        }
                    }
                }
                assert!(start <= finish);
                for candidate in
                    std::iter::once(&result["best"]).chain(result["hold"].as_array().unwrap())
                {
                    for field in ["measured", "ranking"] {
                        assert_eq!(candidate["score"][format!("{field}_q32")], "8589934592");
                        assert_eq!(candidate["score"][field], "2.000000");
                    }
                }
            }
        }
    }
}

#[test]
fn human_mode_prints_transform_text_and_no_events() {
    let dir = Scratch::new();
    let output = dir.run(&["--request", "-", "--no-report"], &transform());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"BDZG\n");
    assert_eq!(output.stderr, b"");
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn human_mode_attack_writes_no_jsonl_to_stdout() {
    let dir = Scratch::new();
    let output = dir.run(&["--request", "-", "--no-report"], &attack());
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
fn piped_human_attack_stderr_is_empty_for_hc_and_pe() {
    let dir = Scratch::new();
    let mut request = attack();
    for pe in [false, true] {
        if pe {
            request["job"]["passes"] = json!(["partial_exhaustion"]);
            let settings = request["job"]["attack"].as_object_mut().unwrap();
            settings.insert("kind".into(), json!("partial_exhaustion"));
            settings.remove("start");
            settings.insert(
                "seeds".into(),
                json!({"kind":"empty_single","selection":"all"}),
            );
        }
        let output = dir.run(&["--request", "-", "--no-report"], &request);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.starts_with(b"Enigma attack report\n"));
        assert_eq!(output.stderr, b"");
    }
}

#[test]
fn events_file_receives_the_same_stream_as_events_dash() {
    let dir = Scratch::new();
    let piped = dir.run(&["--events", "-", "--request", "-"], &attack());
    let output = dir.run(
        &["--request", "-", "--events", "run.jsonl", "--no-report"],
        &attack(),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    let strip = |events: Vec<Value>| -> Vec<Value> {
        events
            .into_iter()
            .map(|mut event| {
                let object = event.as_object_mut().unwrap();
                object.remove("ts");
                object.remove("elapsed_ms");
                for field in ["threads", "started_at", "finished_at"] {
                    object.remove(field);
                }
                event
            })
            .collect()
    };
    let saved = std::fs::read(dir.path("run.jsonl")).unwrap();
    assert_eq!(strip(events(&saved)), strip(events(&piped.stdout)));

    let transformed = dir.run(
        &["--events", "t.jsonl", "--request", "-", "--no-report"],
        &transform(),
    );
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

// S6/S7: save messages identify the actual file and containing directory.
#[test]
fn nested_and_absolute_report_messages_identify_saved_location() {
    for absolute in [false, true] {
        let dir = Scratch::new();
        std::fs::create_dir(dir.path("subdir")).unwrap();
        let target = dir.path("subdir/custom.txt");
        let name = if absolute {
            target.to_string_lossy().into_owned()
        } else {
            "subdir/custom.txt".to_owned()
        };
        let output = dir.run(&["--request", "-", "--report", &name], &transform());
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"BDZG\n");
        assert!(std::fs::read(&target)
            .unwrap()
            .starts_with(b"Enigma transform report\n"));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!(
                "Report \"custom.txt\" saved successfully in {}\n",
                dir.path("subdir").canonicalize().unwrap().display()
            )
        );
    }
}

// S6/S7: default collisions and explicit preflight never follow live links
// or replace directories.
#[cfg(unix)]
#[test]
fn report_collisions_preserve_live_links_and_directories() {
    for directory in [false, true] {
        let dir = Scratch::new();
        std::fs::write(dir.path("r.json"), transform().to_string()).unwrap();
        std::fs::write(dir.path("valuable"), b"valuable original").unwrap();
        let destination = dir.path("r.report.txt");
        if directory {
            std::fs::create_dir(&destination).unwrap();
            std::fs::write(destination.join("child"), b"child original").unwrap();
        } else {
            std::os::unix::fs::symlink("valuable", &destination).unwrap();
        }
        let output = dir.run(&["r.json"], &transform());
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"BDZG\n");
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("Report \"r."));
        let rejected = dir.run(&["missing.json", "--report", "r.report.txt"], &transform());
        assert_eq!(rejected.status.code(), Some(2));
        assert_eq!(rejected.stdout, b"");
        assert_eq!(
            rejected.stderr,
            b"error: --report file already exists: \"r.report.txt\"\n"
        );
        assert_eq!(
            std::fs::read(dir.path("valuable")).unwrap(),
            b"valuable original"
        );
        if directory {
            assert_eq!(
                std::fs::read(destination.join("child")).unwrap(),
                b"child original"
            );
        } else {
            assert_eq!(
                std::fs::read_link(destination).unwrap(),
                PathBuf::from("valuable")
            );
        }
    }
}

// D6: an execution-time checkpoint failure must not save a report.
#[test]
fn checkpoint_failure_does_not_deliver_human_report() {
    let dir = Scratch::new();
    let output = dir.run(
        &[
            "--request",
            "-",
            "--threads",
            "1",
            "--checkpoint",
            "missing/check",
            "--report",
            "bad.txt",
            "--events",
            "events.jsonl",
        ],
        &attack(),
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "error: cannot write checkpoint \"missing/check\": No such file or directory (os error 2)\n"
    );
    assert!(!dir.path("bad.txt").exists());
}
