//! UKW-D search contract: synthetic inputs, not historical reference vectors.
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

fn run(value: &Value, args: &[&str]) -> Output {
    run_raw(&value.to_string(), args)
}
fn run_raw(text: &str, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--events", "-", "--request", "-"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
fn events(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn success(output: &Output) -> Vec<Value> {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, b"");
    let events = events(output);
    assert_eq!(events[0]["event"], "started");
    assert_eq!(events.last().unwrap()["reason"], "completed");
    events
}
fn result(events: &[Value]) -> &Value {
    events.iter().find(|e| e["event"] == "result").unwrap()
}
fn pairs() -> Value {
    json!([
        ["A", "C"],
        ["D", "E"],
        ["F", "G"],
        ["H", "I"],
        ["J", "K"],
        ["L", "M"],
        ["N", "P"],
        ["Q", "R"],
        ["S", "T"],
        ["U", "V"],
        ["W", "X"],
        ["Y", "Z"]
    ])
}
fn request(searched: bool) -> Value {
    let mut value = json!({"protocol_version":1,"machine":{"definition":{"kind":"bundled","id":"enigma-i-ukwd"}},
        "job":{"kind":"search","configuration":{"slots":[
            {"id":"reflector","wheel":"D","position":"A","ring":"A","pairs":pairs()},
            {"id":"left","wheel":"I","position":"A","ring":"A"},
            {"id":"middle","wheel":"II","position":"A","ring":"A"},
            {"id":"right","wheel":"III","position":"A","ring":"A"}],"plugboard":[]},
        "text":"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "space":{"plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":0}},
        "passes":["hill_climb"],"measures":["ic"],"attack":{"kind":"hill_climb","initial_measure":"ic",
            "final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,"start":[],"hold":2}}});
    if searched {
        value["job"]["configuration"]["slots"][0]
            .as_object_mut()
            .unwrap()
            .remove("pairs");
        value["job"]["space"]["slots"] = json!([{"id":"reflector","pairs":{"kind":"attack"}}]);
        value["job"]["attack"]["reflector_starts"] = json!(2);
    }
    value
}
fn reject(value: &Value, code: &str, path: &str) {
    reject_raw(&value.to_string(), code, path);
}
fn reject_raw(value: &str, code: &str, path: &str) {
    let output = run_raw(value, &[]);
    assert_eq!(output.status.code(), Some(1));
    let events = events(&output);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "error");
    assert_eq!(events[0]["seq"], 1);
    assert_eq!(events[0]["code"], code);
    assert_eq!(events[0]["location"], path);
    assert_eq!(
        output.stderr,
        format!(
            "{code} at {path}: {}\n",
            events[0]["message"].as_str().unwrap()
        )
        .as_bytes()
    );
}
#[test]
fn known_wiring_hc_pe_stages_and_gpu() {
    for pass in ["hill_climb", "partial_exhaustion"] {
        let mut value = request(false);
        value["job"]["passes"] = json!([pass, "measure"]);
        value["job"]["attack"]["kind"] = json!(pass);
        if pass == "partial_exhaustion" {
            value["job"]["attack"]
                .as_object_mut()
                .unwrap()
                .remove("start");
            value["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
        }
        let cpu = success(&run(&value, &["--threads", "1"]));
        let cpu = result(&cpu);
        assert_eq!(cpu["best"]["configuration"], value["job"]["configuration"]);
        assert_eq!(
            cpu["hold"][0]["configuration"],
            value["job"]["configuration"]
        );
        assert_eq!(cpu["counters"]["evaluations_completed"], "2");
        assert_eq!(cpu["stages"][0]["completed"], true);
        let output = run(&value, &["--backend", "gpu", "--threads", "1"]);
        let gpu = events(&output);
        if gpu[0]["code"] == "backend_unavailable" {
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(gpu.len(), 1);
            eprintln!("GPU unavailable: {}", gpu[0]["message"]);
        } else {
            let gpu = success(&output);
            for field in ["best", "hold", "counters", "stages"] {
                assert_eq!(result(&gpu)[field], cpu[field], "CPU/GPU {pass} {field}");
            }
            eprintln!("known UKW-D {pass}: GPU equals CPU");
        }
    }
}
#[test]
fn ordinary_i_m3_hc_pe_fixed_keys_are_preserved() {
    for machine in ["enigma-i", "enigma-m3"] {
        for pass in ["hill_climb", "partial_exhaustion"] {
            let mut value = request(false);
            value["machine"]["definition"]["id"] = json!(machine);
            value["job"]["configuration"]["slots"][0]["wheel"] = json!("B");
            value["job"]["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("pairs");
            value["job"]["passes"] = json!([pass]);
            value["job"]["attack"]["kind"] = json!(pass);
            if pass == "partial_exhaustion" {
                value["job"]["attack"]
                    .as_object_mut()
                    .unwrap()
                    .remove("start");
                value["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
            }
            let mut transform = value.clone();
            transform["job"] = json!({"kind":"transform","configuration":value["job"]["configuration"],
                "text":value["job"]["text"],"direction":"decrypt"});
            let plaintext = success(&run(&transform, &[]))[1]["output"].clone();
            let observed = success(&run(&value, &["--backend", "cpu", "--threads", "1"]));
            let observed = result(&observed);
            assert_eq!(observed["best"]["plaintext"], plaintext);
            assert_eq!(
                observed["best"]["configuration"],
                value["job"]["configuration"]
            );
            for field in [
                "evaluations_admitted",
                "evaluations_completed",
                "climbs_started",
                "climbs_completed",
                "outers_completed",
            ] {
                assert_eq!(observed["counters"][field], "1");
            }
        }
    }
}
#[test]
fn wiring_coverage_and_domains() {
    let mut value = request(true);
    value["job"]["configuration"]["slots"][0]["pairs"] = pairs();
    reject(&value, "invalid_search_space", "/job/space/slots/0/pairs");
    let mut value = request(true);
    value["job"]["space"]
        .as_object_mut()
        .unwrap()
        .remove("slots");
    reject(&value, "invalid_search_space", "/job/space/slots");
    let mut value = request(true);
    value["machine"]["definition"]["id"] = json!("enigma-i");
    value["job"]["configuration"]["slots"][0]["wheel"] = json!("B");
    reject(&value, "unknown_field", "/job/space/slots/0/pairs");
    let mut value = request(true);
    value["job"].as_object_mut().unwrap().remove("attack");
    value["job"]["space"]["plugboard"] = json!({"candidates":[["A","B"]],"size":1});
    reject(&value, "invalid_search_space", "/job/space/slots/0/pairs");
    for bad in [json!(null), json!([]), json!({}), json!({"kind":"other"})] {
        let mut value = request(true);
        value["job"]["space"]["slots"][0]["pairs"] = bad;
        reject(&value, "invalid_search_space", "/job/space/slots/0/pairs");
    }
    let mut value = request(true);
    value["job"]["space"]["slots"][0]["pairs"]["extra"] = json!(0);
    reject(&value, "unknown_field", "/job/space/slots/0/pairs/extra");
}
#[test]
fn reflector_starts_validation() {
    let mut value = request(false);
    value["job"]["attack"]["reflector_starts"] = json!(1);
    reject(&value, "invalid_request", "/job/attack/reflector_starts");
    let mut value = request(true);
    value["job"]["attack"]
        .as_object_mut()
        .unwrap()
        .remove("reflector_starts");
    reject(&value, "invalid_request", "/job/attack/reflector_starts");
    for literal in [
        "0",
        "-0",
        "-1",
        "1.0",
        "1e0",
        "null",
        "true",
        "\"1\"",
        "[]",
        "{}",
        "1000001",
        "18446744073709551616",
    ] {
        let value = request(true).to_string().replace(
            "\"reflector_starts\":2",
            &format!("\"reflector_starts\":{literal}"),
        );
        reject_raw(&value, "invalid_request", "/job/attack/reflector_starts");
    }
    let mut value = request(true);
    value["job"]["attack"]["reflector_starts"] = json!(0);
    value["job"]["attack"]["unexpected"] = json!(true);
    reject(&value, "unknown_field", "/job/attack/unexpected");
    // Upper bound acceptance without executing a million starts.
    let mut value = request(true);
    value["job"]["attack"]["reflector_starts"] = json!(1000000);
    value["job"]["space"]["offset"] = json!(1);
    let output = run(&value, &[]);
    assert_eq!(output.status.code(), Some(0), "{:?}", events(&output));
    assert_eq!(events(&output).last().unwrap()["reason"], "outer_slice_end");
}
#[test]
fn searched_wiring_pass_and_gpu_rejections() {
    for pass in ["partial_exhaustion", "bombe"] {
        let mut value = request(true);
        value["job"]["passes"] = json!([pass]);
        value["job"]["attack"]["kind"] = json!(pass);
        value["job"]["attack"]
            .as_object_mut()
            .unwrap()
            .remove("start");
        if pass == "bombe" {
            value["job"]["attack"]["crib"] = json!({"text":"AB"});
        } else {
            value["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
        }
        reject(&value, "unsupported_pass", "/job/passes");
    }
    let output = run(&request(true), &["--backend", "gpu"]);
    assert_eq!(output.status.code(), Some(1));
    let ev = events(&output);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["seq"], 1);
    assert_eq!(ev[0]["code"], "backend_unavailable");
    assert_eq!(ev[0]["location"], "/job/attack");
    assert_eq!(
        ev[0]["message"],
        "GPU backend unavailable: the UKW-D wiring search runs on the CPU only"
    );
    assert_eq!(output.stderr,b"backend_unavailable: GPU backend unavailable: the UKW-D wiring search runs on the CPU only\n");
}
#[test]
fn human_report_shows_each_winning_reflector_wiring() {
    let value = request(true);
    let observed = success(&run(&value, &["--threads", "1"]));
    let held = result(&observed)["hold"].as_array().unwrap();
    assert_eq!(held.len(), 2);
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--request", "-", "--no-report", "--threads", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    let report = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = report
        .lines()
        .filter(|line| line.starts_with("    Wheels:"))
        .collect();
    let expected: Vec<_> = held
        .iter()
        .map(|candidate| {
            let pairs = candidate["configuration"]["slots"][0]["pairs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| format!("{}{}", pair[0].as_str().unwrap(), pair[1].as_str().unwrap()))
                .collect::<Vec<_>>()
                .join(" ");
            format!("    Wheels:     D (pairs: {pairs}) I II III")
        })
        .collect();
    assert_eq!(lines, expected);
    assert!(!report.contains("\"event\""));
}

#[test]
fn recovery_of_known_ukwd_wiring() {
    let source: Value = serde_json::from_str(include_str!(
        "../../../e2e/bomm/m4-u264-attack-positions/case.json"
    ))
    .unwrap();
    let plaintext = &source["plaintext"].as_str().unwrap()[..220];
    let mut transform = request(false);
    transform["job"] = json!({"kind":"transform","configuration":transform["job"]["configuration"],"text":plaintext,"direction":"encrypt"});
    let encrypted = success(&run(&transform, &[]));
    let mut search = request(true);
    search["job"]["text"] = encrypted[1]["output"].clone();
    search["job"]["attack"]["reflector_starts"] = json!(8);
    // Existing independently sourced German military trigram model, not trained
    // on this synthetic ciphertext or on its key.
    search["job"]["measures"] = json!(["ic", "sinkov_trigram"]);
    search["job"]["resources"] = json!({"sinkov_trigram":{"path":concat!(env!("CARGO_MANIFEST_DIR"),"/../../web/internal/tables/enigma1941-trigram.json")}});
    search["job"]["attack"]["initial_measure"] = json!("sinkov_trigram");
    search["job"]["attack"]["final_measure"] = json!("sinkov_trigram");
    search["job"]["passes"] = json!(["hill_climb", "measure"]);
    let start = Instant::now();
    let output = success(&run(&search, &["--threads", "1"]));
    eprintln!("UKW-D recovery: {:.3}s", start.elapsed().as_secs_f64());
    let result = result(&output);
    assert_eq!(result["best"]["plaintext"], plaintext);
    assert_eq!(
        result["best"]["configuration"],
        transform["job"]["configuration"]
    );
    assert_eq!(result["counters"]["climbs_started"], "8");
    assert_eq!(result["counters"]["climbs_completed"], "8");
    assert_eq!(result["counters"]["outers_completed"], "1");
    for held in result["hold"].as_array().unwrap() {
        assert_eq!(
            held["configuration"]["slots"][0]["pairs"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
        let mut replay = transform.clone();
        replay["job"]["configuration"] = held["configuration"].clone();
        replay["job"]["text"] = search["job"]["text"].clone();
        assert_eq!(success(&run(&replay, &[]))[1]["output"], held["plaintext"]);
    }
}
