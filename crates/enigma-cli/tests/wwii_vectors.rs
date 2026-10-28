//! Independent WWII vectors: Palloks for G, Palloks and Toledo for Railway/KD/UKW-D.
//! See docs/historical-catalog.md for conventions and the retained G disagreement.
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

fn transform(vector: &Value, text: &str, direction: &str) -> String {
    let mut slots = vec![json!({"id":"reflector", "wheel":"UKW",
        "position":vector["positions"]["ukw"], "ring":vector["rings"]["ukw"]})];
    if let Some(pairs) = vector.get("reflector_pairs") {
        slots[0]["wheel"] = json!("D");
        slots[0]["pairs"] = json!(pairs
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p
                .as_str()
                .unwrap()
                .chars()
                .map(|c| c.to_string())
                .collect::<Vec<_>>())
            .collect::<Vec<_>>());
    }
    for (i, id) in ["left", "middle", "right"].iter().enumerate() {
        let wheel = match vector["rotor_order"][i].as_str().unwrap() {
            "1" => "I",
            "2" => "II",
            "3" => "III",
            "4" => "IV",
            "5" => "V",
            "6" => "VI",
            "7" => "VII",
            "8" => "VIII",
            other => panic!("unknown wheel {other}"),
        };
        slots.push(json!({"id":id, "wheel":wheel,
            "position":vector["positions"]["rotors"][i], "ring":vector["rings"]["rotors"][i]}));
    }
    if let Some(etw) = vector.get("etw") {
        slots.push(
            json!({"id":"etw", "wheel":"ETW", "position":etw["position"], "ring":etw["ring"]}),
        );
    }
    let plugboard: Vec<Vec<String>> = vector
        .get("plugboard")
        .and_then(Value::as_array)
        .map(|pairs| {
            pairs
                .iter()
                .map(|p| p.as_str().unwrap().chars().map(|c| c.to_string()).collect())
                .collect()
        })
        .unwrap_or_default();
    let request = json!({"protocol_version":1,
        "machine":{"definition":{"kind":"bundled","id":vector["machine"]}},
        "job":{"kind":"transform", "configuration":{"slots":slots,"plugboard":plugboard},
            "text":text,"direction":direction}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--events", "-", "--request", "-"])
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
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}: {}",
        vector["id"],
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, b"");
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(!events.iter().any(|event| event["event"] == "error"));
    let outputs: Vec<_> = events
        .iter()
        .filter(|event| event["event"] == "output")
        .collect();
    assert_eq!(outputs.len(), 1);
    outputs[0]["output"].as_str().unwrap().to_owned()
}

fn check(machine: &str) {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/wwii_reference_vectors.json")).unwrap();
    let vector = vectors.iter().find(|v| v["machine"] == machine).unwrap();
    let plaintext = vector["plaintext"].as_str().unwrap();
    let ciphertext = transform(vector, plaintext, "encrypt");
    assert_eq!(
        ciphertext, vector["ciphertext"],
        "{machine}: Palloks reference"
    );
    if vector["agreement"] == true {
        assert_eq!(ciphertext, vector["toledo_ciphertext"], "Toledo reference");
    }
    assert_eq!(transform(vector, &ciphertext, "decrypt"), plaintext);
}

#[test]
fn railway_reference_and_round_trip() {
    check("enigma-railway");
}
#[test]
fn g312_reference_and_round_trip() {
    check("enigma-g312");
}
#[test]
fn g260_reference_and_round_trip() {
    check("enigma-g260");
}

#[test]
fn kd_reference_and_round_trip() {
    check("enigma-kd");
}
#[test]
fn i_ukwd_reference_and_round_trip() {
    check("enigma-i-ukwd");
}
#[test]
fn m3_ukwd_reference_and_round_trip() {
    check("enigma-m3-ukwd");
}
