//! Public CLI no-plugboard recovery; also exercises the ETW and the G carries.
//! Synthetic ciphertext, NOT a historical attack/reference vector. German text
//! comes from the tracked e2e/bomm U-264 fixture (its provenance remains there).
//! Search-passes §§3–5: slots are enumerated, never climbed. With max_pairs=0
//! both HC's empty start and PE's only admissible seed cost one score per key.
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

const KEYS: u64 = 6 * 2 * 2 * 2 * 2 * 2 * 2;

fn run(request: &Value, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .env_remove("ENIGMA_TEST_CHECKPOINT_INTERVAL_MS")
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
        .write_all(request.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn events(output: &Output) -> Vec<Value> {
    assert!(output.stdout.ends_with(b"\n"));
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
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
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event["seq"], i + 1);
        assert_eq!(event["protocol_version"], 1);
        assert!(event["ts"].is_string());
        assert_ne!(event["event"], "error");
    }
    assert_eq!(events.first().unwrap()["event"], "started");
    assert_eq!(events.last().unwrap()["event"], "done");
    assert_eq!(events.last().unwrap()["reason"], "completed");
    events
}

fn configuration(machine: &str) -> Value {
    // G starts at a full carry (I=A, II=S, III=U): reflector moves on
    // the first keypress. Railway crosses turnovers within the 200 letters.
    let positions = if machine == "enigma-g312" {
        ["U", "S", "A"]
    } else {
        ["K", "D", "M"]
    };
    json!({"slots":[
        {"id":"reflector","wheel":"UKW","position":"J","ring":"D"},
        {"id":"left","wheel":"III","position":positions[0],"ring":"F"},
        {"id":"middle","wheel":"II","position":positions[1],"ring":"C"},
        {"id":"right","wheel":"I","position":positions[2],"ring":"P"},
        {"id":"etw","wheel":"ETW","position":"A","ring":"A"}],"plugboard":[]})
}

fn plaintext() -> String {
    let source: Value = serde_json::from_str(include_str!(
        "../../../e2e/bomm/m4-u264-attack-positions/case.json"
    ))
    .unwrap();
    // A fresh 200-letter synthetic message from an existing normalized corpus;
    // no downloads, private recovery corpus or source ciphertext required.
    let text = &source["plaintext"].as_str().unwrap()[..200];
    assert!(text.bytes().all(|b| b.is_ascii_uppercase()));
    assert!(text.contains('X'));
    text.to_owned()
}

fn request(machine: &str, job: Value) -> Value {
    json!({"protocol_version":1,"machine":{"definition":{"kind":"bundled","id":machine}},"job":job})
}

fn setup(machine: &str, pass: &str) -> (String, Value, Value) {
    let plaintext = plaintext();
    let key = configuration(machine);
    let encrypted = success(&run(
        &request(
            machine,
            json!({"kind":"transform",
        "configuration":key,"text":plaintext,"direction":"encrypt"}),
        ),
        &[],
    ));
    assert_eq!(
        encrypted
            .iter()
            .map(|e| e["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["started", "output", "done"]
    );
    let ciphertext = encrypted[1]["output"].as_str().unwrap();
    assert_eq!(ciphertext.len(), plaintext.len());
    assert_ne!(ciphertext, plaintext);
    let mut fixed = key.clone();
    let mut domains = Vec::new();
    for slot in fixed["slots"].as_array_mut().unwrap().iter_mut().take(4) {
        let id = slot["id"].as_str().unwrap().to_owned();
        let position = slot.as_object_mut().unwrap().remove("position").unwrap();
        let mut domain = json!({"id":id,"positions":["B",position]});
        if id != "reflector" {
            slot.as_object_mut().unwrap().remove("wheel");
            domain["wheels"] = json!(["I", "II", "III"]);
        }
        if id == "right" || id == "reflector" {
            let ring = slot.as_object_mut().unwrap().remove("ring").unwrap();
            domain["rings"] = json!(["A", ring]);
        }
        domains.push(domain);
    }
    let mut attack = json!({"kind":pass,"initial_measure":"ic","final_measure":"ic",
        "switch_pairs":0,"backtrack_pairs":0,"hold":1});
    if pass == "hill_climb" {
        attack["start"] = json!([]);
    } else {
        attack["seeds"] = json!({"kind":"empty_single","selection":"all"});
    }
    let input = request(
        machine,
        json!({"kind":"search","configuration":fixed,"text":ciphertext,
        "space":{"slots":domains,"constraints":{"distinct_wheels":["left","middle","right"]},
            "plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":0}},
        "passes":[pass],"measures":["ic"],"attack":attack}),
    );
    (plaintext, key, input)
}

fn check(events: &[Value], plaintext: &str, key: &Value) -> Value {
    assert_eq!(events[0]["outers_selected"], KEYS.to_string());
    let results: Vec<_> = events.iter().filter(|e| e["event"] == "result").collect();
    assert_eq!(results.len(), 1);
    let result = results[0];
    for name in [
        "evaluations_admitted",
        "evaluations_completed",
        "climbs_started",
        "climbs_completed",
        "outers_completed",
    ] {
        assert_eq!(result["counters"][name], KEYS.to_string(), "{name}");
    }
    let best = &result["best"];
    assert_eq!(best["plaintext"], plaintext);
    // Reflector ring/position have equivalent simultaneous shifts: electrical
    // offset is p-r, and reflector position is never a stepping predicate.
    // This bounded domain excludes those ties, so the exact initial key wins.
    assert_eq!(best["configuration"], *key);
    assert_eq!(best["mutable_plugboard"], json!([]));
    assert_eq!(best["start_index"], "0");
    assert_eq!(best["incomplete"], false);
    assert_eq!(best["neighborhood_exhausted"], true);
    assert_eq!(best["score"]["measure"], "ic");
    let hold = result["hold"].as_array().unwrap();
    assert_eq!(hold.len(), 1);
    let mut top = hold[0].clone();
    assert_eq!(
        top.as_object_mut().unwrap().remove("stages"),
        Some(json!([]))
    );
    assert_eq!(top, *best);
    result.clone()
}

fn recover(machine: &str, pass: &str, gpu: bool) {
    let (plaintext, key, input) = setup(machine, pass);
    let start = Instant::now();
    let cpu = success(&run(&input, &["--backend", "cpu", "--threads", "1"]));
    let elapsed = start.elapsed().as_secs_f64();
    let result = check(&cpu, &plaintext, &key);
    eprintln!(
        "{machine} {pass}: {KEYS} keys, {elapsed:.3}s wall, {:.1} keys/s; engine {}ms; key {key}",
        KEYS as f64 / elapsed,
        result["elapsed_ms"]
    );
    // Historical dimensions: 6 orders * 26^4 positions * 26^4 rings;
    // ETW stays A/A. Raw count includes electrically equivalent keys.
    let full = 6_u64 * 26_u64.pow(8);
    eprintln!("full raw space: {full} keys, {:.1} years at this debug/host rate (linear estimate, not a benchmark guarantee)",
        full as f64 / (KEYS as f64 / elapsed) / (365.25 * 86400.0));
    if gpu {
        let output = run(&input, &["--backend", "gpu", "--threads", "1"]);
        let observed = events(&output);
        if observed[0]["code"] == "backend_unavailable" {
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0]["seq"], 1);
            let message = observed[0]["message"].as_str().unwrap();
            assert!(message.starts_with("GPU backend unavailable: "));
            assert_eq!(
                output.stderr,
                format!("backend_unavailable: {message}\n").as_bytes()
            );
            eprintln!("GPU unavailable: {message}");
        } else {
            let gpu = check(&success(&output), &plaintext, &key);
            for field in ["best", "hold", "counters", "stages"] {
                assert_eq!(gpu[field], result[field], "CPU/GPU {field}");
            }
            eprintln!("GPU matches CPU best, hold, scores and counters");
        }
    }
}

#[test]
fn railway_hc() {
    recover("enigma-railway", "hill_climb", false);
}
#[test]
fn railway_pe() {
    recover("enigma-railway", "partial_exhaustion", false);
}
#[test]
fn g312_hc() {
    recover("enigma-g312", "hill_climb", false);
}
#[test]
fn g312_pe_and_gpu_if_available() {
    recover("enigma-g312", "partial_exhaustion", true);
}
