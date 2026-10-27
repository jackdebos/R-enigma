//! Rewirable UKW-D reflector (protocol §3.1-3.2, search-passes §11): transform only.
//! The KD vector is an independent Palloks/Toledo reference with a UKW-D wiring.
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn run(request: &Value) -> (Option<i32>, Vec<Value>, String) {
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
    let events = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (
        output.status.code(),
        events,
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn output_text(request: &Value) -> String {
    let (code, events, stderr) = run(request);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr, "");
    let outputs: Vec<_> = events.iter().filter(|e| e["event"] == "output").collect();
    assert_eq!(outputs.len(), 1, "events: {events:?}");
    outputs[0]["output"].as_str().unwrap().to_owned()
}

fn single_error(request: &Value) -> Value {
    let (code, events, stderr) = run(request);
    assert_eq!(code, Some(1), "events: {events:?}");
    assert_eq!(events.len(), 1, "events: {events:?}");
    assert_eq!(events[0]["event"], json!("error"));
    assert_eq!(events[0]["seq"], json!(1));
    let error = events[0].clone();
    assert_eq!(
        stderr,
        format!(
            "{} at {}: {}\n",
            error["code"].as_str().unwrap(),
            error["location"].as_str().unwrap(),
            error["message"].as_str().unwrap()
        )
    );
    error
}

/// Splits a 26-letter involution into its pairs, without the fixed `BO` pair.
fn free_pairs(wiring: &str) -> Vec<Value> {
    let symbols: Vec<char> = ALPHABET.chars().collect();
    let mapped: Vec<char> = wiring.chars().collect();
    let mut pairs = Vec::new();
    for (i, &a) in symbols.iter().enumerate() {
        let b = mapped[i];
        assert_eq!(mapped[symbols.iter().position(|&s| s == b).unwrap()], a);
        if a < b && !(a == 'B' && b == 'O') {
            pairs.push(json!([a.to_string(), b.to_string()]));
        }
    }
    pairs
}

fn letters(text: &str) -> Vec<String> {
    text.chars().map(|c| c.to_string()).collect()
}

fn wheel(name: &str, wiring: &str, turnovers: &str) -> Value {
    json!({"name": name, "wiring": letters(wiring), "turnovers": letters(turnovers)})
}

fn ukwd() -> Value {
    json!({"name": "D", "rewirable": {"fixed_pairs": [["B", "O"]]}, "turnovers": []})
}

fn transform(definition: Value, slots: Value, text: &str, direction: &str) -> Value {
    json!({"protocol_version": 1, "machine": {"definition": definition},
        "job": {"kind": "transform", "configuration": {"slots": slots, "plugboard": []},
            "text": text, "direction": direction}})
}

fn kd_vector() -> Value {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/wwii_reference_vectors.json")).unwrap();
    vectors
        .into_iter()
        .find(|v| v["machine"] == "enigma-kd")
        .unwrap()
}

/// KD as a custom definition: FRA rotors, inverse-QWERTZ ETW, standard stepping, UKW-D.
fn kd_request(text: &str, direction: &str, ukw_pairs: Value) -> Value {
    let vector = kd_vector();
    let rotors = vector["custom_rotors"].as_array().unwrap();
    let turnovers = vector["turnovers"].as_array().unwrap();
    let mut wheels: Vec<Value> = ["I", "II", "III"]
        .iter()
        .enumerate()
        .map(|(i, name)| {
            wheel(
                name,
                rotors[i].as_str().unwrap(),
                turnovers[i].as_str().unwrap(),
            )
        })
        .collect();
    wheels.push(wheel("ETW", "JWULCMNOHPQZYXIRADKEGVBTSF", ""));
    wheels.push(ukwd());
    let rotor_slot = |id: &str| {
        json!({"id": id, "role": "rotor", "movement": "movable",
        "allowed_wheels": ["I", "II", "III"]})
    };
    let definition = json!({"kind": "custom", "value": {
        "alphabet": letters(ALPHABET),
        "wheels": wheels,
        "slots": [
            {"id": "reflector", "role": "reflector", "movement": "fixed", "wheel": "D"},
            rotor_slot("left"), rotor_slot("middle"), rotor_slot("right"),
            {"id": "etw", "role": "rotor", "movement": "fixed", "wheel": "ETW"}],
        "stepping": {"rules": [
            {"when": {"always": true}, "advance": ["right"]},
            {"when": {"at_turnover": "right"}, "advance": ["middle"]},
            {"when": {"at_turnover": "middle"}, "advance": ["middle", "left"]}]}}});
    let mut slots = vec![json!({"id": "reflector", "wheel": "D",
        "position": vector["positions"]["ukw"], "ring": vector["rings"]["ukw"], "pairs": ukw_pairs})];
    for (i, id) in ["left", "middle", "right"].iter().enumerate() {
        let name = match vector["rotor_order"][i].as_str().unwrap() {
            "1" => "I",
            "2" => "II",
            "3" => "III",
            other => panic!("unknown wheel {other}"),
        };
        slots.push(json!({"id": id, "wheel": name,
            "position": vector["positions"]["rotors"][i], "ring": vector["rings"]["rotors"][i]}));
    }
    slots.push(json!({"id": "etw", "wheel": "ETW", "position": "A", "ring": "A"}));
    transform(definition, json!(slots), text, direction)
}

fn kd_pairs() -> Value {
    json!(free_pairs(
        kd_vector()["reflector_wiring"].as_str().unwrap()
    ))
}

#[test]
fn kd_ukwd_wiring_matches_the_independent_reference_and_round_trips() {
    let vector = kd_vector();
    let plaintext = vector["plaintext"].as_str().unwrap();
    let ciphertext = output_text(&kd_request(plaintext, "encrypt", kd_pairs()));
    assert_eq!(ciphertext, vector["ciphertext"], "Palloks reference");
    assert_eq!(ciphertext, vector["toledo_ciphertext"], "Toledo reference");
    assert_eq!(
        output_text(&kd_request(&ciphertext, "decrypt", kd_pairs())),
        plaintext
    );
}

/// A UKW-D key equals the same machine with that involution as a fixed reflector.
fn bundled_slots(reflector: Value, rotors: [&str; 3]) -> Value {
    let mut slots = vec![reflector];
    for (id, wheel) in ["left", "middle", "right"].iter().zip(rotors) {
        slots.push(json!({"id": id, "wheel": wheel, "position": "Q", "ring": "F"}));
    }
    json!(slots)
}

fn equivalent_fixed_reflector(catalog: &str, wiring: &str, rotors: [&str; 3]) -> Value {
    let mut value: Value = serde_json::from_str(catalog).unwrap();
    value["wheels"]
        .as_array_mut()
        .unwrap()
        .push(wheel("KEY", wiring, ""));
    value["slots"][0] =
        json!({"id": "reflector", "role": "reflector", "movement": "fixed", "wheel": "KEY"});
    let reflector = json!({"id": "reflector", "wheel": "KEY", "position": "A", "ring": "A"});
    transform(
        json!({"kind": "custom", "value": value}),
        bundled_slots(reflector, rotors),
        "DIESXISTXEINXTESTXDERXUMKEHRWALZEXDORA",
        "encrypt",
    )
}

fn bundled_ukwd(id: &str, rotors: [&str; 3], pairs: Value) -> Value {
    let reflector =
        json!({"id": "reflector", "wheel": "D", "position": "A", "ring": "A", "pairs": pairs});
    transform(
        json!({"kind": "bundled", "id": id}),
        bundled_slots(reflector, rotors),
        "DIESXISTXEINXTESTXDERXUMKEHRWALZEXDORA",
        "encrypt",
    )
}

#[test]
fn bundled_ukwd_machines_equal_their_fixed_reflector_equivalent() {
    let wiring = kd_vector()["reflector_wiring"].as_str().unwrap().to_owned();
    for (id, catalog, rotors) in [
        (
            "enigma-i-ukwd",
            include_str!("../../enigma-core/catalog/enigma-i.json"),
            ["II", "IV", "V"],
        ),
        (
            "enigma-m3-ukwd",
            include_str!("../../enigma-core/catalog/enigma-m3.json"),
            ["VI", "VIII", "I"],
        ),
    ] {
        let expected = output_text(&equivalent_fixed_reflector(catalog, &wiring, rotors));
        assert_eq!(
            output_text(&bundled_ukwd(id, rotors, kd_pairs())),
            expected,
            "{id}"
        );
    }
}

#[test]
fn ordinary_i_and_m3_transforms_keep_their_known_output() {
    for id in ["enigma-i", "enigma-m3"] {
        let slots = json!([
            {"id":"reflector","wheel":"B","position":"A","ring":"A"},
            {"id":"left","wheel":"I","position":"A","ring":"A"},
            {"id":"middle","wheel":"II","position":"A","ring":"A"},
            {"id":"right","wheel":"III","position":"A","ring":"A"}
        ]);
        let request = transform(json!({"kind":"bundled","id":id}), slots, "AAAAA", "encrypt");
        assert_eq!(output_text(&request), "BDZGO");
    }
}

#[test]
fn ukwd_search_fails_closed_without_a_wiring_key() {
    for id in ["enigma-i-ukwd", "enigma-m3-ukwd"] {
        for attack in [false, true] {
            let mut request = bundled_ukwd(id, ["I", "II", "III"], kd_pairs());
            request["job"]["configuration"]["slots"][0]
                .as_object_mut()
                .unwrap()
                .remove("pairs");
            let job = request["job"].as_object_mut().unwrap();
            job.remove("direction");
            job.insert("kind".into(), json!("search"));
            job.insert("space".into(), json!({}));
            job.insert("measures".into(), json!(["ic"]));
            job.insert("passes".into(), json!(["measure"]));
            if attack {
                job.insert("space".into(), json!({"plugboard":{"kind":"attack","symbols":letters(ALPHABET),"max_pairs":10}}));
                job.insert("passes".into(), json!(["hill_climb"]));
                job.insert("attack".into(), json!({"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":1,"backtrack_pairs":0,"start":[]}));
            }
            let error = single_error(&request);
            assert_eq!(error["code"], "invalid_slot");
            assert_eq!(error["location"], "/job/configuration/slots/0/pairs");
            assert_eq!(
                error["message"],
                "slot \"reflector\" uses rewirable wheel \"D\" and requires `pairs`"
            );
        }
    }
}

#[test]
fn pairs_order_and_orientation_do_not_change_the_key() {
    let mut reversed: Vec<Value> = kd_pairs().as_array().unwrap().clone();
    reversed.reverse();
    for pair in &mut reversed {
        pair.as_array_mut().unwrap().reverse();
    }
    let rotors = ["I", "II", "III"];
    assert_eq!(
        output_text(&bundled_ukwd("enigma-i-ukwd", rotors, json!(reversed))),
        output_text(&bundled_ukwd("enigma-i-ukwd", rotors, kd_pairs()))
    );
}

fn pairs_error(pairs: Value) -> Value {
    single_error(&bundled_ukwd("enigma-i-ukwd", ["I", "II", "III"], pairs))
}

fn replace_pair(index: usize, pair: Value) -> Value {
    let mut pairs = kd_pairs().as_array().unwrap().clone();
    pairs[index] = pair;
    json!(pairs)
}

#[test]
fn missing_pairs_on_a_rewirable_slot_is_rejected() {
    let reflector = json!({"id": "reflector", "wheel": "D", "position": "A", "ring": "A"});
    let error = single_error(&transform(
        json!({"kind": "bundled", "id": "enigma-i-ukwd"}),
        bundled_slots(reflector, ["I", "II", "III"]),
        "AAAA",
        "encrypt",
    ));
    assert_eq!(error["code"], json!("invalid_slot"));
    assert_eq!(error["location"], json!("/job/configuration/slots/0/pairs"));
    assert_eq!(
        error["message"],
        json!("slot \"reflector\" uses rewirable wheel \"D\" and requires `pairs`")
    );
}

#[test]
fn pairs_on_a_fixed_wiring_slot_is_an_unknown_field() {
    let reflector = json!({"id": "reflector", "wheel": "B", "position": "A", "ring": "A",
        "pairs": kd_pairs()});
    let error = single_error(&transform(
        json!({"kind": "bundled", "id": "enigma-i"}),
        bundled_slots(reflector, ["I", "II", "III"]),
        "AAAA",
        "encrypt",
    ));
    assert_eq!(error["code"], json!("unknown_field"));
    assert_eq!(error["location"], json!("/job/configuration/slots/0/pairs"));
    assert_eq!(
        error["message"],
        json!("`pairs` is allowed only on a slot whose wheel is rewirable; wheel \"B\" is not")
    );
}

#[test]
fn incomplete_and_inadmissible_pairs_are_rejected() {
    let mut eleven = kd_pairs().as_array().unwrap().clone();
    eleven.pop();
    let error = pairs_error(json!(eleven));
    assert_eq!(error["code"], json!("invalid_slot"));
    assert_eq!(error["location"], json!("/job/configuration/slots/0/pairs"));
    assert_eq!(
        error["message"],
        json!("rewirable wheel \"D\" needs exactly 12 pairs; got 11")
    );

    // KD pair 0 is A-K; every replacement keeps the count at 12.
    for (pair, code, message) in [
        (
            json!(["A", "O"]),
            "invalid_slot",
            "pair endpoint \"O\" is wired permanently by wheel \"D\"",
        ),
        (
            json!(["A", "A"]),
            "invalid_plugboard",
            "a pair must join two distinct symbols; got \"A\" twice",
        ),
        (
            json!(["A", "a"]),
            "invalid_symbol",
            "pair symbol \"a\" is not in the machine alphabet",
        ),
        (
            json!(["A", "C"]),
            "invalid_plugboard",
            "pair endpoint \"C\" is already used by another pair",
        ),
    ] {
        let error = pairs_error(replace_pair(0, pair.clone()));
        assert_eq!(error["code"], json!(code), "{pair}");
        assert_eq!(error["message"], json!(message), "{pair}");
        assert!(
            error["location"]
                .as_str()
                .unwrap()
                .starts_with("/job/configuration/slots/0/pairs/"),
            "{error}"
        );
    }
}

#[test]
fn malformed_pairs_shape_is_rejected_before_resolution() {
    for (pairs, location) in [
        (json!("AB"), "/job/configuration/slots/0/pairs"),
        (json!([["A"]]), "/job/configuration/slots/0/pairs/0"),
        (json!([["A", "BC"]]), "/job/configuration/slots/0/pairs/0/1"),
    ] {
        let error = pairs_error(pairs.clone());
        assert_eq!(error["location"], json!(location), "{pairs}");
    }
}

fn custom_ukwd_definition(rewirable: Value, slot: Value) -> Value {
    json!({"kind": "custom", "value": {
        "alphabet": ["A", "B", "C", "D"],
        "wheels": [
            {"name": "R", "wiring": ["B", "C", "D", "A"], "turnovers": []},
            {"name": "D", "rewirable": rewirable, "turnovers": []}],
        "slots": [slot, {"id": "fast", "role": "rotor", "movement": "movable", "wheel": "R"}],
        "stepping": {"rules": [{"when": {"always": true}, "advance": ["fast"]}]}}})
}

#[test]
fn invalid_rewirable_definitions_are_rejected() {
    let reflector = json!({"id": "ukw", "role": "reflector", "movement": "fixed", "wheel": "D"});
    for (rewirable, slot, location, message) in [
        (
            json!({"fixed_pairs": [["A", "B"], ["C", "D"]]}),
            reflector.clone(),
            "/machine/definition/value/wheels/1/rewirable/fixed_pairs",
            "a rewirable wheel needs an even, nonzero number of free symbols; got 0",
        ),
        (
            json!({"fixed_pairs": [["A", "B"], ["B", "C"]]}),
            reflector.clone(),
            "/machine/definition/value/wheels/1/rewirable/fixed_pairs/1/0",
            "fixed pair endpoint \"B\" is repeated",
        ),
        (
            json!({"fixed_pairs": [], "other": 1}),
            reflector.clone(),
            "/machine/definition/value/wheels/1/rewirable/other",
            "field \"other\" is not allowed here",
        ),
        (
            json!({"fixed_pairs": []}),
            json!({"id": "ukw", "role": "rotor", "movement": "fixed", "wheel": "D"}),
            "/machine/definition/value/slots/0/wheel",
            "rewirable wheel \"D\" is allowed only in a reflector slot",
        ),
        (
            json!({"fixed_pairs": []}),
            json!({"id": "ukw", "role": "reflector", "movement": "fixed",
                "allowed_wheels": ["D", "R"]}),
            "/machine/definition/value/slots/0/allowed_wheels/0",
            "a slot admitting rewirable wheel \"D\" must admit no other wheel",
        ),
    ] {
        let request = transform(
            custom_ukwd_definition(rewirable.clone(), slot),
            json!([]),
            "A",
            "encrypt",
        );
        let error = single_error(&request);
        assert_eq!(error["location"], json!(location), "{rewirable}");
        assert_eq!(error["message"], json!(message), "{rewirable}");
    }
}

#[test]
fn a_custom_rewirable_wheel_without_fixed_pairs_transforms() {
    let definition = custom_ukwd_definition(
        json!({"fixed_pairs": []}),
        json!({"id": "ukw", "role": "reflector", "movement": "fixed", "wheel": "D"}),
    );
    let slots = |pairs: Value| {
        json!([{"id": "ukw", "wheel": "D", "position": "A", "ring": "A", "pairs": pairs},
            {"id": "fast", "wheel": "R", "position": "A", "ring": "A"}])
    };
    let encrypted = output_text(&transform(
        definition.clone(),
        slots(json!([["A", "C"], ["B", "D"]])),
        "ABCD",
        "encrypt",
    ));
    let other = output_text(&transform(
        definition.clone(),
        slots(json!([["A", "B"], ["C", "D"]])),
        "ABCD",
        "encrypt",
    ));
    assert_ne!(encrypted, other, "the wiring is key material");
    assert_eq!(
        output_text(&transform(
            definition,
            slots(json!([["A", "C"], ["B", "D"]])),
            &encrypted,
            "decrypt"
        )),
        "ABCD"
    );
}
