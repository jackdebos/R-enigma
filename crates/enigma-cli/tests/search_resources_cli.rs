//! Real transport tests for legacy validation and executable HC/PE attacks.
mod support;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "enigma-resources-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
    fn stdin(&self, request: &Value) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
            .current_dir(&self.0)
            .args(["--request", "-"])
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
    fn file(&self, path: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_enigma"))
            .current_dir(&self.0)
            .arg(path)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn request(ids: &[&str]) -> Value {
    let resources: serde_json::Map<String, Value> = ids
        .iter()
        .filter(|id| !["ic", "entropy"].contains(id))
        .map(|id| (id.to_string(), json!({"path": format!("{id}.json")})))
        .collect();
    json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B"],"wheels":[{"name":"r","wiring":["B","A"],"turnovers":[]}],
        "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],"stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":[{"id":"r","ring":"A"}],"plugboard":[]},
        "space":{"slots":[{"id":"r","positions":["A","B"]}]},"text":"AAAAAA","passes":["hill_climb"],"measures":ids,"resources":resources}})
}
fn model(order: usize) -> Value {
    json!({"resource_version":1,"kind":"ngram","alphabet":["A","B"],"order":order,"entries":[{"gram":vec!["A";order],"count":1}]})
}
fn dictionary() -> Value {
    json!({"resource_version":1,"kind":"dictionary","alphabet":["A","B"],"entries":[{"word":["A"],"weight":1}]})
}
fn error(output: Output, code: &str, location: &str) -> Value {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "no work events: {stdout}");
    let event: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event["event"], "error");
    assert_eq!(event["seq"], 1);
    assert_eq!(event["code"], code, "{event}");
    assert_eq!(event["location"], location, "{event}");
    event
}
#[test]
fn missing_resource_is_loaded_before_unsupported_job() {
    let f = Fixture::new();
    let event = error(
        f.stdin(&request(&["trie"])),
        "unsupported_resource",
        "/job/resources/trie/path",
    );
    assert!(event["message"].as_str().unwrap().contains("trie.json"));
}
#[test]
fn valid_free_and_bound_search_only_emit_unsupported_job() {
    let f = Fixture::new();
    error(
        f.stdin(&request(&["ic", "entropy"])),
        "unsupported_job",
        "/job/kind",
    );
    f.write("sinkov_bigram.json", model(2).to_string());
    f.write("trie.json", dictionary().to_string());
    error(
        f.stdin(&request(&["trie", "sinkov_bigram"])),
        "unsupported_job",
        "/job/kind",
    );
}
#[test]
fn structural_validation_precedes_file_access() {
    let f = Fixture::new();
    let mut r = request(&["trie"]);
    r["job"]["extra"] = json!(true);
    error(f.stdin(&r), "unknown_field", "/job/extra");
}
#[test]
fn directories_and_invalid_utf8_are_loading_errors() {
    let f = Fixture::new();
    fs::create_dir(f.0.join("trie.json")).unwrap();
    error(
        f.stdin(&request(&["trie"])),
        "unsupported_resource",
        "/job/resources/trie/path",
    );
    f.write("sinkov_bigram.json", [255]);
    error(
        f.stdin(&request(&["sinkov_bigram"])),
        "unsupported_resource",
        "/job/resources/sinkov_bigram/path",
    );
}
#[test]
fn binding_diagnostics_precede_unsupported_job() {
    let f = Fixture::new();
    for (text, code, location) in [
        ("{".to_owned(), "invalid_json", ""),
        (
            {
                let mut m = model(2);
                m["extra"] = json!(true);
                m.to_string()
            },
            "unknown_field",
            "/extra",
        ),
        (
            {
                let mut m = model(2);
                m["kind"] = json!("dictionary");
                m.to_string()
            },
            "unsupported_resource",
            "/kind",
        ),
        (model(1).to_string(), "unsupported_resource", "/order"),
        (
            {
                let mut m = model(2);
                m["alphabet"] = json!(["B", "A"]);
                m.to_string()
            },
            "unsupported_resource",
            "/alphabet",
        ),
    ] {
        f.write("sinkov_bigram.json", text);
        let event = error(f.stdin(&request(&["sinkov_bigram"])), code, location);
        assert!(event["message"]
            .as_str()
            .unwrap()
            .contains("sinkov_bigram.json"));
    }
}
#[test]
fn reference_id_order_not_measure_or_filename_order_wins() {
    let f = Fixture::new();
    let mut r = request(&["trie", "sinkov_bigram"]);
    r["job"]["resources"]["trie"]["path"] = json!("a-missing");
    r["job"]["resources"]["sinkov_bigram"]["path"] = json!("z-missing");
    error(
        f.stdin(&r),
        "unsupported_resource",
        "/job/resources/sinkov_bigram/path",
    );
}
#[test]
fn file_origin_stdin_origin_and_absolute_resources() {
    let f = Fixture::new();
    f.write("nested/trie.json", dictionary().to_string());
    f.write("nested/request.json", request(&["trie"]).to_string());
    f.write("trie.json", b"invalid");
    error(
        f.file("nested/request.json"),
        "unsupported_job",
        "/job/kind",
    );
    error(f.stdin(&request(&["trie"])), "invalid_json", "");
    let mut r = request(&["trie"]);
    r["job"]["resources"]["trie"]["path"] = json!(f.0.join("nested/trie.json"));
    error(f.stdin(&r), "unsupported_job", "/job/kind");
}
#[cfg(unix)]
#[test]
fn symlink_request_retains_filename_origin_not_target_origin() {
    let f = Fixture::new();
    f.write("target/request.json", request(&["trie"]).to_string());
    f.write("target/trie.json", b"invalid target fixture");
    f.write("link/trie.json", dictionary().to_string());
    std::os::unix::fs::symlink(
        f.0.join("target/request.json"),
        f.0.join("link/request.json"),
    )
    .unwrap();
    error(f.file("link/request.json"), "unsupported_job", "/job/kind");
}
#[test]
fn actual_per_reference_boundary_and_detection_byte() {
    let f = Fixture::new();
    let mut bytes = dictionary().to_string().into_bytes();
    bytes.resize(enigma_core::MAX_RESOURCE_BYTES, b' ');
    f.write("trie.json", &bytes);
    error(f.stdin(&request(&["trie"])), "unsupported_job", "/job/kind");
    bytes.push(b' ');
    f.write("trie.json", &bytes);
    error(
        f.stdin(&request(&["trie"])),
        "resource_limit",
        "/job/resources/trie/path",
    );
}
#[test]
fn aggregate_counts_repeated_paths_before_semantic_parsing() {
    let f = Fixture::new();
    let ids = [
        "sinkov_trigram",
        "sinkov_quadgram",
        "sinkov_pentagram",
        "sinkov_monogram",
        "sinkov_hexagram",
    ];
    let mut r = request(&ids);
    for id in ids {
        r["job"]["resources"][id]["path"] = json!("same.json");
    }
    // Four exact 16 MiB references reach parsing, despite identical paths.
    f.write("same.json", vec![b' '; enigma_core::MAX_RESOURCE_BYTES]);
    let mut four = r.clone();
    four["job"]["measures"] = json!(&ids[..4]);
    four["job"]["resources"]
        .as_object_mut()
        .unwrap()
        .remove(ids[4]);
    error(f.stdin(&four), "invalid_json", "");
    error(
        f.stdin(&r),
        "resource_limit",
        "/job/resources/sinkov_trigram/path",
    );
}
#[test]
fn complete_attack_routes_before_resource_loading() {
    let f = Fixture::new();
    let mut r = request(&["ic", "trie"]);
    r["job"]["space"]["plugboard"] = json!({"kind":"attack","symbols":["A","B"],"max_pairs":1});
    r["job"]["attack"] = json!({"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
        "switch_pairs":1,"backtrack_pairs":0,"evaluation_budget":1,"start":[]});
    enigma_core::ParsedAttackRequest::parse_json(&r.to_string()).unwrap();
    error(
        f.stdin(&r),
        "unsupported_resource",
        "/job/resources/trie/path",
    );
    r["job"]["passes"] = json!(["partial_exhaustion"]);
    r["job"]["attack"].as_object_mut().unwrap().remove("start");
    r["job"]["attack"]["kind"] = json!("partial_exhaustion");
    r["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
    enigma_core::ParsedAttackRequest::parse_json(&r.to_string()).unwrap();
    f.write("request.json", r.to_string());
    error(
        f.file("request.json"),
        "unsupported_resource",
        "/job/resources/trie/path",
    );
}

fn attack(pass: &str, selection: &str, ids: &[&str]) -> Value {
    let mut r = request(ids);
    r["job"]["passes"] = json!([pass]);
    r["job"]["space"]["plugboard"] = json!({"kind":"attack","symbols":["A","B"],"max_pairs":1});
    r["job"]["attack"] = json!({"kind":pass,"initial_measure":ids[0],"final_measure":ids[0],
        "switch_pairs":1,"backtrack_pairs":0,"evaluation_budget":1});
    if pass == "hill_climb" {
        r["job"]["attack"]["start"] = json!([]);
    } else {
        r["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":selection});
        if selection == "touching" {
            r["job"]["attack"]["seeds"]["symbols"] = json!(["A"]);
        }
    }
    r
}

#[test]
fn public_attack_free_and_bound_execution() {
    let f = Fixture::new();
    f.write("sinkov_bigram.json", model(2).to_string());
    for (pass, selection) in [
        ("hill_climb", "all"),
        ("partial_exhaustion", "all"),
        ("partial_exhaustion", "touching"),
    ] {
        for ids in [&["ic"][..], &["sinkov_bigram"][..]] {
            let request = attack(pass, selection, ids);
            let events = attack_events(&f.stdin(&request));
            let parsed =
                enigma_core::ParsedAttackRequest::parse_json(&request.to_string()).unwrap();
            let text = model(2).to_string();
            let supplied = if ids == ["ic"] {
                std::collections::BTreeMap::new()
            } else {
                std::collections::BTreeMap::from([("sinkov_bigram".into(), text.as_str())])
            };
            let bound = parsed.bind_resources(&supplied).unwrap();
            let expected = bound.run(|_| {}, || false).unwrap();
            let actual = &events[events.len() - 2];
            let projected = serde_json::to_value(enigma_core::Event::result(&expected, 0)).unwrap();
            for field in ["best", "counters"] {
                assert_eq!(
                    actual[field], projected[field],
                    "{pass}/{selection}/{ids:?}"
                );
            }
            assert!(!actual["best"].is_null());
            let terminal = serde_json::to_value(enigma_core::Event::Done {
                reason: expected.termination().into(),
            })
            .unwrap();
            assert_eq!(events.last().unwrap()["reason"], terminal["reason"]);
        }
    }
}

fn attack_events(output: &Output) -> Vec<Value> {
    let events = support::successful_events(output);
    assert_eq!(events.first().unwrap()["event"], "started");
    assert_eq!(events.last().unwrap()["event"], "done");
    assert_eq!(events[events.len() - 2]["event"], "result");
    let mut elapsed = 0;
    for event in &events[1..events.len() - 1] {
        assert!(matches!(
            event["event"].as_str(),
            Some("progress" | "result")
        ));
        let decimal = |value: &Value| {
            let text = value.as_str().unwrap();
            let number = text.parse::<u128>().unwrap();
            assert_eq!(text, number.to_string());
            number
        };
        let next = decimal(&event["elapsed_ms"]);
        assert!(next >= elapsed);
        elapsed = next;
        for value in event["counters"].as_object().unwrap().values() {
            decimal(value);
        }
    }
    assert!(events[1..events.len() - 2]
        .iter()
        .all(|event| event["event"] == "progress"));
    assert_eq!(
        events[events.len() - 3]["counters"],
        events[events.len() - 2]["counters"]
    );
    assert_eq!(
        events[events.len() - 3]["elapsed_ms"],
        events[events.len() - 2]["elapsed_ms"]
    );
    events
}

#[test]
fn public_attack_structural_diagnostics_precede_loading() {
    let f = Fixture::new();
    for (pass, selection, pointer, replacement) in [
        (
            "hill_climb",
            "all",
            "/job/attack/start",
            json!([["A", "A"]]),
        ),
        ("hill_climb", "all", "/job/attack/seeds", json!({})),
        ("hill_climb", "all", "/job/attack/extra", json!(true)),
        (
            "hill_climb",
            "all",
            "/job/attack/evaluation_budget",
            json!(0),
        ),
        ("hill_climb", "all", "/job/text", json!("Z")),
        (
            "hill_climb",
            "all",
            "/job/passes",
            json!(["partial_exhaustion"]),
        ),
        (
            "hill_climb",
            "all",
            "/job/space/plugboard/candidates",
            json!([]),
        ),
        ("partial_exhaustion", "all", "/job/attack/start", json!([])),
        (
            "partial_exhaustion",
            "all",
            "/job/attack/seeds/selection",
            json!("unknown"),
        ),
        (
            "partial_exhaustion",
            "touching",
            "/job/attack/seeds/symbols",
            json!(["A", "A"]),
        ),
    ] {
        let mut r = attack(pass, selection, &["sinkov_bigram"]);
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        r.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), replacement);
        let expected = enigma_core::ParsedAttackRequest::parse_json(&r.to_string()).unwrap_err();
        let event = error(f.stdin(&r), expected[0].code(), expected[0].location());
        assert_eq!(event["message"], expected[0].message(), "{pointer}");
    }
    let mut r = attack("hill_climb", "all", &["sinkov_bigram"]);
    r["job"].as_object_mut().unwrap().remove("attack");
    error(f.stdin(&r), "invalid_request", "/job/attack");
}

fn outer_attack(slots: usize, bound: bool) -> Value {
    let alphabet: Vec<String> = (0..256)
        .map(|i| char::from_u32(0x100 + i).unwrap().to_string())
        .collect();
    let mut r = attack(
        "hill_climb",
        "all",
        if bound { &["sinkov_bigram"] } else { &["ic"] },
    );
    r["machine"]["definition"]["value"] = json!({
        "alphabet":alphabet,"wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
        "slots":(0..slots).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"})).collect::<Vec<_>>(),
        "stepping":{"rules":[]}});
    r["job"]["configuration"]["slots"] = json!([]);
    r["job"]["text"] = json!(alphabet[0].repeat(2));
    r["job"]["space"] = json!({"limit":1,
        "slots":(0..slots).map(|i| json!({"id":format!("r{i}"),"positions":alphabet,"rings":alphabet})).collect::<Vec<_>>(),
        "plugboard":{"kind":"attack","symbols":&alphabet[..2],"max_pairs":1}});
    r
}

#[test]
fn public_attack_load_bind_gate_precedence_and_full_cardinality() {
    let f = Fixture::new();
    attack_events(&f.stdin(&outer_attack(5, false)));
    error(
        f.stdin(&outer_attack(8, false)),
        "resource_limit",
        "/job/space",
    );
    let overflow = outer_attack(8, true);
    error(
        f.stdin(&overflow),
        "unsupported_resource",
        "/job/resources/sinkov_bigram/path",
    );
    let ordinary = attack("hill_climb", "all", &["sinkov_bigram"]);
    for (contents, code, location) in [
        ("{".to_owned(), "invalid_json", ""),
        (model(1).to_string(), "unsupported_resource", "/order"),
        (
            {
                let mut m = model(2);
                m["alphabet"] = json!(["B", "A"]);
                m.to_string()
            },
            "unsupported_resource",
            "/alphabet",
        ),
    ] {
        f.write("sinkov_bigram.json", contents);
        error(f.stdin(&ordinary), code, location);
    }
    f.write("sinkov_bigram.json", "{");
    error(f.stdin(&overflow), "invalid_json", "");
    let alphabet = overflow["machine"]["definition"]["value"]["alphabet"].clone();
    f.write(
        "sinkov_bigram.json",
        json!({"resource_version":1,"kind":"ngram",
        "alphabet":alphabet,"order":2,"entries":[{"gram":[alphabet[0],alphabet[0]],"count":1}]})
        .to_string(),
    );
    error(f.stdin(&overflow), "resource_limit", "/job/space");
    attack_events(&f.stdin(&outer_attack(5, true)));
}

#[test]
fn missing_request_stays_stderr_only_exit_two() {
    let f = Fixture::new();
    let out = f.file("missing.json");
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
