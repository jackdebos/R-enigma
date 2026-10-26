use enigma_core::{AttackRequest, Event, ExecutionOptions};
use serde_json::{json, Value};

fn fixture() -> Value {
    json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B","C","D"],
        "wheels":[{"name":"u","wiring":["B","A","D","C"],"turnovers":[]},
                  {"name":"r","wiring":["A","B","C","D"],"turnovers":[]}],
        "slots":[{"id":"u","role":"reflector","movement":"fixed","wheel":"u"},
                 {"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
        "stepping":{"rules":[]}}}},"job":{"kind":"search",
        "configuration":{"slots":[{"id":"u","position":"A","ring":"A"},
            {"id":"r","position":"A","ring":"A"}],"plugboard":[]},
        "text":"BBBB","passes":["bombe"],"measures":["ic"],
        "space":{"plugboard":{"kind":"attack","symbols":["A","B","C","D"],"max_pairs":0}},
        "attack":{"kind":"bombe","crib":{"text":"AA"},"initial_measure":"ic",
            "final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,"hold":10}}})
}

fn rejected(value: &Value, code: &str, pointer: &str) {
    // Parsing/admission is pure: no run or observer can be entered on rejection.
    let errors = AttackRequest::parse_json(&value.to_string()).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(
        (errors[0].code(), errors[0].location()),
        (code, pointer),
        "{errors:?}"
    );
}

#[test]
fn bombe_validation_table() {
    const CRIB: &str = "/job/attack/crib";
    const TEXT: &str = "/job/attack/crib/text";
    const POSITION: &str = "/job/attack/crib/position";
    for (crib, code, pointer) in [
        (Value::Null, "invalid_request", CRIB),
        (json!([]), "invalid_request", CRIB),
        (json!({}), "invalid_request", TEXT),
        (json!({"text":1}), "invalid_request", TEXT),
        (json!({"text":""}), "invalid_search_space", TEXT),
        (json!({"text":"a"}), "invalid_search_space", TEXT),
        (json!({"text":"A A"}), "invalid_search_space", TEXT),
        (json!({"text":"AAAAA"}), "invalid_search_space", TEXT),
        (json!({"text":"B"}), "invalid_search_space", CRIB),
        (
            json!({"text":"AB","position":1}),
            "invalid_search_space",
            POSITION,
        ),
    ] {
        let mut value = fixture();
        value["job"]["attack"]["crib"] = crib;
        rejected(&value, code, pointer);
    }
    for position in [
        json!(-1),
        json!(1.0),
        json!("0"),
        Value::Null,
        json!(3),
        json!(u64::MAX),
    ] {
        let mut value = fixture();
        value["job"]["attack"]["crib"]["position"] = position;
        rejected(&value, "invalid_search_space", POSITION);
    }
    let mut value = fixture();
    value["job"]["attack"]["crib"]["extra"] = json!(0);
    rejected(&value, "unknown_field", "/job/attack/crib/extra");
    value["job"]["attack"]
        .as_object_mut()
        .unwrap()
        .remove("crib");
    rejected(&value, "invalid_request", CRIB);
    for member in ["start", "seeds"] {
        let mut value = fixture();
        value["job"]["attack"][member] = json!([]);
        rejected(&value, "invalid_request", &format!("/job/attack/{member}"));
    }
    let mut value = fixture();
    value["job"]["attack"]["crib"] = json!({"text":"AB","position":1});
    let errors = AttackRequest::parse_json(&value.to_string()).unwrap_err();
    assert!(
        errors[0].message().contains('2'),
        "first crashing absolute index: {errors:?}"
    );
    for wiring in [json!(["A", "B", "C", "D"]), json!(["A", "C", "B", "D"])] {
        let mut value = fixture();
        value["machine"]["definition"]["value"]["wheels"][0]["wiring"] = wiring;
        rejected(&value, "unsupported_topology", "/machine");
    }
    let mut value = fixture();
    value["machine"]["definition"]["value"]["slots"][0]["role"] = json!("rotor");
    rejected(&value, "unsupported_topology", "/machine");
}

fn run(value: &Value, threads: usize) -> Value {
    let request = AttackRequest::parse_json(&value.to_string()).unwrap();
    let result = request
        .run_with(
            ExecutionOptions::with_threads(threads).unwrap(),
            |_| {},
            || false,
        )
        .unwrap();
    serde_json::to_value(Event::result(&result, 0)).unwrap()
}

#[test]
fn bombe_positions_counters_and_duplicate_rule() {
    let value = fixture();
    let request = AttackRequest::parse_json(&value.to_string()).unwrap();
    assert_eq!(request.gate().bombe_settings(), Some(3));
    let mut snapshots = Vec::new();
    let completed = request.run(|p| snapshots.push(p), || false).unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].bombe_settings(), 0);
    assert_eq!(snapshots[1].bombe_settings(), 3);
    let result = serde_json::to_value(Event::result(&completed, 0)).unwrap();
    assert_eq!(
        result["crib"],
        json!({"text":"AA","positions":["0","1","2"],"settings":"3","stops":"3"})
    );
    assert_eq!(result["counters"]["bombe_settings"], "3");
    assert_eq!(result["counters"]["bombe_stops"], "3");
    assert_eq!(result["counters"]["climbs_started"], "3");
    assert_eq!(result["best"]["plaintext"], "AAAA");
    assert_eq!(result["best"]["crib_position"], "0");
    assert_eq!(result["hold"].as_array().unwrap().len(), 1);
    let mut fixed = value;
    fixed["job"]["attack"]["crib"]["position"] = json!(2);
    let result = run(&fixed, 1);
    assert_eq!(result["crib"]["positions"], json!(["2"]));
    assert_eq!(result["crib"]["settings"], "1");
    assert_eq!(result["best"]["crib_position"], "2");
    assert_eq!(result["best"]["start_index"], "0");
    let identity = |value: &Value| {
        enigma_core::checkpoint_identity(&value.to_string(), &Default::default()).unwrap()
    };
    let original = identity(&fixed);
    fixed["job"]["attack"]["crib"]["position"] = json!(1);
    assert_ne!(identity(&fixed), original);
    fixed["job"]["attack"]["crib"]["position"] = json!(2);
    fixed["job"]["attack"]["crib"]["text"] = json!("AC");
    assert_ne!(identity(&fixed), original);
}

#[test]
fn bombe_rejections_have_no_stops_and_gpu_has_no_work() {
    let mut value = fixture();
    value["job"]["attack"]["crib"]["text"] = json!("AC");
    let result = run(&value, 1);
    assert_eq!(result["crib"]["settings"], "3");
    assert_eq!(result["crib"]["stops"], "0");
    assert_eq!(result["best"], Value::Null);
    assert_eq!(result["counters"]["evaluations_completed"], "0");
    let request = AttackRequest::parse_json(&value.to_string()).unwrap();
    let mut snapshots = Vec::new();
    let error = request
        .run_with(
            ExecutionOptions::serial().with_accelerator(&enigma_core::ReferenceClimbAccelerator),
            |p| snapshots.push(p),
            || false,
        )
        .unwrap_err();
    assert!(snapshots.is_empty());
    assert_eq!(error.evaluations_used(), 0);
    assert_eq!(
        error.run_source().unsupported_accelerator(),
        Some(&enigma_core::ClimbUnsupported::Bombe)
    );
}

fn recovery_fixture(m4: bool) -> (Value, String, enigma_core::TransformConfiguration) {
    use enigma_core::{DefinitionSource, Direction, SlotConfiguration, TransformConfiguration};
    let machine = if m4 { "enigma-m4" } else { "enigma-i" };
    let definition = DefinitionSource::Bundled { id: machine.into() }
        .resolve()
        .unwrap();
    let slots = if m4 {
        vec![
            ("reflector", "Thin-B", 'A', 'A'),
            ("greek", "Beta", 'B', 'A'),
            ("left", "II", 'A', 'A'),
            ("middle", "IV", 'I', 'A'),
            ("right", "I", 'P', 'C'),
        ]
    } else {
        vec![
            ("reflector", "B", 'A', 'A'),
            ("left", "I", 'A', 'A'),
            ("middle", "II", 'D', 'A'),
            ("right", "III", 'U', 'C'),
        ]
    };
    // The first few keypresses cross the fast turnover and the middle double step.
    let configuration = TransformConfiguration::new(
        slots
            .iter()
            .map(|&(id, wheel, position, ring)| SlotConfiguration::new(id, wheel, position, ring))
            .collect(),
        vec![('A', 'B'), ('C', 'D')],
    );
    let plaintext = "EEEEEEEEEEABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(5);
    let ciphertext = configuration
        .resolve(&definition)
        .unwrap()
        .into_engine()
        .unwrap()
        .transform(&plaintext, Direction::Encrypt)
        .unwrap();
    let mut fixed = slots.iter().map(|&(id, wheel, position, ring)| json!({"id":id,"wheel":wheel,"position":position.to_string(),"ring":ring.to_string()})).collect::<Vec<_>>();
    fixed
        .last_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("ring");
    let value = json!({"protocol_version":1,"machine":{"definition":{"kind":"bundled","id":machine}},
        "job":{"kind":"search","configuration":{"slots":fixed,"plugboard":[["A","B"]]},
        "text":ciphertext,"passes":["bombe","reswapping","measure"],"measures":["ic"],
        "space":{"slots":[{"id":"right","rings":["A","B","C"]}],
            "plugboard":{"kind":"attack","symbols":["C","D","E","F","G","H"],"max_pairs":3}},
        "attack":{"kind":"bombe","crib":{"text":plaintext,"position":0},
            "initial_measure":"ic","final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,
            "hold":10,"reswapping":{"measure":"ic"},"measure":{"measure":"ic"}}}});
    (value, plaintext, configuration)
}

#[test]
fn bombe_recovers_enigma_i_and_m4_rings_and_locks_deductions_through_stages() {
    for m4 in [false, true] {
        let (value, plaintext, configuration) = recovery_fixture(m4);
        let request = AttackRequest::parse_json(&value.to_string()).unwrap();
        let mut snapshots = Vec::new();
        let result = request.run(|p| snapshots.push(p), || false).unwrap();
        let best = result.best().unwrap();
        assert_eq!(best.configuration(), &configuration);
        assert_eq!(best.plaintext(), plaintext);
        assert_eq!(best.crib_position(), Some(0));
        // CD was unknown in the request but uniquely deduced; all other mutable
        // symbols were deduced self-connected, leaving nothing for HC/reswapping.
        assert!(best.mutable_plugboard().is_empty());
        assert_eq!(result.stages().len(), 2);
        assert_eq!(result.counters().bombe_settings(), 3);
        assert_eq!(result.counters().bombe_stops(), 1);
        assert_eq!(snapshots.first().unwrap().bombe_settings(), 0);
        assert_eq!(snapshots.last(), Some(&result.counters()));
        for snapshot in snapshots {
            let wire = serde_json::to_value(Event::progress(snapshot, 0)).unwrap();
            assert_eq!(
                wire["counters"]["bombe_settings"],
                snapshot.bombe_settings().to_string()
            );
            assert_eq!(
                wire["counters"]["bombe_stops"],
                snapshot.bombe_stops().to_string()
            );
        }
        let identity =
            enigma_core::checkpoint_identity(&value.to_string(), &Default::default()).unwrap();
        let mut saved = None;
        request
            .run_with_checkpoints(
                ExecutionOptions::serial(),
                |_| {},
                || false,
                |snapshot| saved = Some(snapshot.record(identity, 0).unwrap()),
            )
            .unwrap();
        let resumed = request
            .resume(&saved.unwrap())
            .unwrap()
            .run_with(ExecutionOptions::serial(), |_| {}, || false)
            .unwrap();
        assert_eq!(
            serde_json::to_value(Event::result(&resumed, 0)).unwrap(),
            serde_json::to_value(Event::result(&result, 0)).unwrap()
        );
    }
}

#[test]
fn bombe_dragging_recovers_the_true_placement_on_both_machines() {
    for m4 in [false, true] {
        let (mut value, plaintext, configuration) = recovery_fixture(m4);
        value["job"]["attack"]["crib"] = json!({"text":"ABCDEFGHIJKLMNOPQRSTUVWXYZ"});
        let request = AttackRequest::parse_json(&value.to_string()).unwrap();
        let result = request.run(|_| {}, || false).unwrap();
        let best = result.best().unwrap();
        assert_eq!(best.plaintext(), plaintext);
        assert_eq!(best.configuration(), &configuration);
        assert_eq!(best.crib_position(), Some(10));
        value["job"]["attack"]["crib"]["position"] = json!(46);
        let fixed = run(&value, 1);
        assert_eq!(fixed["best"]["plaintext"], plaintext);
        assert_eq!(fixed["best"]["crib_position"], "46");
        assert_eq!(fixed["best"]["start_index"], "0");
    }
}

#[test]
fn detached_bombe_gate_rechecks_crib_alphabet() {
    let original = AttackRequest::parse_json(&fixture().to_string()).unwrap();
    let mut value = fixture();
    value["job"].as_object_mut().unwrap().remove("attack");
    value["job"]["space"] = json!({});
    value["job"]["text"] = json!("XXXX");
    value["machine"]["definition"]["value"]["alphabet"] = json!(["W", "X", "Y", "Z"]);
    value["machine"]["definition"]["value"]["wheels"][0]["wiring"] = json!(["X", "W", "Z", "Y"]);
    value["machine"]["definition"]["value"]["wheels"][1]["wiring"] = json!(["W", "X", "Y", "Z"]);
    for slot in value["job"]["configuration"]["slots"]
        .as_array_mut()
        .unwrap()
    {
        slot["position"] = json!("W");
        slot["ring"] = json!("W");
    }
    let carrier = enigma_core::SearchRequest::parse_json(&value.to_string()).unwrap();
    let domain = enigma_core::AttackPlugboardDomain::parse_json(
        carrier.definition().alphabet(),
        &[],
        r#"{"kind":"attack","symbols":["W","X","Y","Z"],"max_pairs":0}"#,
    )
    .unwrap();
    let errors =
        enigma_core::AttackGate::check(&carrier, &domain, original.settings()).unwrap_err();
    assert_eq!(
        (errors[0].code(), errors[0].location()),
        ("invalid_search_space", "/job/attack/crib/text")
    );
}

#[test]
fn bombe_parallel_and_checkpoint_resume() {
    let mut value = fixture();
    // Four variable rotor dimensions give 256 keys, spanning two logical blocks.
    let definition = &mut value["machine"]["definition"]["value"];
    for i in 1..4 {
        definition["slots"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"}));
    }
    value["job"]["configuration"]["slots"] = json!([{"id":"u","position":"A","ring":"A"}]);
    value["job"]["space"]["slots"] = json!((0..4).map(|i| json!({"id":if i == 0 {"r".into()} else {format!("r{i}")},"positions":["A","B","C","D"],"rings":["A"]})).collect::<Vec<_>>());
    let expected = run(&value, 1);
    assert_eq!(run(&value, 3), expected);
    let request = AttackRequest::parse_json(&value.to_string()).unwrap();
    let identity =
        enigma_core::checkpoint_identity(&value.to_string(), &Default::default()).unwrap();
    let mut saved = None;
    let polls = std::cell::Cell::new(0);
    let cancelled = request
        .run_with_checkpoints(
            ExecutionOptions::serial(),
            |_| {},
            || {
                polls.set(polls.get() + 1);
                polls.get() > 1
            },
            |snapshot| {
                saved = Some(snapshot.record(identity, 0).unwrap());
            },
        )
        .unwrap();
    assert_eq!(
        cancelled.termination(),
        enigma_core::AttackTermination::Cancelled
    );
    let mut record = saved.unwrap();
    let encoded = record.seal_json().unwrap();
    let record = enigma_core::CheckpointRecord::parse_json(&encoded).unwrap();
    let resumed = request
        .resume(&record)
        .unwrap()
        .run_with(ExecutionOptions::with_threads(3).unwrap(), |_| {}, || false)
        .unwrap();
    assert_eq!(
        serde_json::to_value(Event::result(&resumed, 0)).unwrap(),
        expected
    );
}

#[test] // S2/S3/S4/S6: public execution vs an independent exhaustive-board witness.
fn verifier_stop_counts_across_outer_positions_rings_and_capacities() {
    use enigma_core::{DefinitionSource, Direction, SlotConfiguration, TransformConfiguration};
    // Enumerate all four-symbol functions, retain involutions (10 complete boards).
    let boards: Vec<Vec<usize>> = (0..256usize)
        .filter_map(|mut code| {
            let b: Vec<_> = (0..4)
                .map(|_| {
                    let x = code % 4;
                    code /= 4;
                    x
                })
                .collect();
            (0..4).all(|x| b[b[x]] == x).then_some(b)
        })
        .collect();
    assert_eq!(boards.len(), 10);
    let mut v = fixture();
    v["machine"]["definition"]["value"]["wheels"][1]["wiring"] = json!(["B", "C", "A", "D"]);
    v["job"]["configuration"]["slots"] = json!([{"id":"u","position":"A","ring":"A"}]);
    v["job"]["space"]["slots"] = json!([{"id":"r","positions":["D","B","A"],"rings":["C","A"]}]);
    v["job"]["text"] = json!("BBBC");
    v["job"]["attack"]["crib"] = json!({"text":"AA"});
    let definition = DefinitionSource::parse_json(&v["machine"]["definition"].to_string())
        .unwrap()
        .resolve()
        .unwrap();
    let mut totals = Vec::new();
    for cap in 0..=2 {
        v["job"]["space"]["plugboard"]["max_pairs"] = json!(cap);
        let mut stops = 0;
        for position in ['D', 'B', 'A'] {
            for ring in ['C', 'A'] {
                let outputs: Vec<String> = boards
                    .iter()
                    .filter(|b| b.iter().enumerate().filter(|&(x, &y)| x < y).count() <= cap)
                    .map(|b| {
                        let pairs = (0..4)
                            .filter(|&x| x < b[x])
                            .map(|x| ((b'A' + x as u8) as char, (b'A' + b[x] as u8) as char))
                            .collect();
                        TransformConfiguration::new(
                            vec![
                                SlotConfiguration::new("u", "u", 'A', 'A'),
                                SlotConfiguration::new("r", "r", position, ring),
                            ],
                            pairs,
                        )
                        .resolve(&definition)
                        .unwrap()
                        .into_engine()
                        .unwrap()
                        .transform("BBBC", Direction::Decrypt)
                        .unwrap()
                    })
                    .collect();
                for p in 0..3 {
                    stops += usize::from(outputs.iter().any(|text| &text[p..p + 2] == "AA"));
                }
            }
        }
        let result = run(&v, 1);
        assert_eq!(result["crib"]["positions"], json!(["0", "1", "2"]));
        assert_eq!(result["crib"]["settings"], "18");
        assert_eq!(result["crib"]["stops"], stops.to_string(), "capacity={cap}");
        assert_eq!(result["counters"]["climbs_started"], stops.to_string());
        assert_eq!(result["counters"]["climbs_completed"], stops.to_string());
        let mut keys = Vec::new();
        for entry in result["hold"].as_array().unwrap() {
            let outer: usize = entry["outer_index"].as_str().unwrap().parse().unwrap();
            let rank: usize = entry["start_index"].as_str().unwrap().parse().unwrap();
            assert_eq!(entry["crib_position"], rank.to_string());
            let slot = &entry["configuration"]["slots"][1];
            assert_eq!(slot["position"], ["D", "B", "A"][outer / 2]);
            assert_eq!(slot["ring"], ["C", "A"][outer % 2]);
            let key = entry["configuration"].to_string();
            assert!(!keys.contains(&key), "duplicate complete key");
            keys.push(key);
        }
        totals.push(stops);
    }
    assert!(
        totals[0] < totals[2],
        "the oracle must exercise both rejection and acceptance: {totals:?}"
    );
}

#[test] // S3/S9: inclusive last placement, one-symbol crib, scalar rather than byte offsets.
fn verifier_last_position_and_unicode_symbols() {
    let mut v = fixture();
    v["machine"]["definition"]["value"]["alphabet"] = json!(["é", "🦀", "C", "D"]);
    v["machine"]["definition"]["value"]["wheels"][0]["wiring"] = json!(["🦀", "é", "D", "C"]);
    v["machine"]["definition"]["value"]["wheels"][1]["wiring"] = json!(["é", "🦀", "C", "D"]);
    for slot in v["job"]["configuration"]["slots"].as_array_mut().unwrap() {
        slot["position"] = json!("é");
        slot["ring"] = json!("é");
    }
    v["job"]["space"]["plugboard"]["symbols"] = json!(["é", "🦀", "C", "D"]);
    v["job"]["text"] = json!("ééé🦀");
    v["job"]["attack"]["crib"] = json!({"text":"é"});
    let result = run(&v, 1);
    assert_eq!(
        result["crib"],
        json!({"text":"é","positions":["3"],"settings":"1","stops":"1"})
    );
    assert_eq!(result["best"]["crib_position"], "3");
    assert_eq!(result["best"]["start_index"], "0");
    assert_eq!(result["best"]["plaintext"], "🦀🦀🦀é");
    v["job"]["attack"]["crib"]["position"] = json!(3);
    assert_eq!(run(&v, 1), result);
}

#[test] // S2/S4/S6: M3, filtered wheel order, position/ring order, finishing/stage facts.
fn verifier_m3_outer_order_and_deduced_facts() {
    let (mut v, plaintext, configuration) = recovery_fixture(false);
    v["machine"]["definition"]["id"] = json!("enigma-m3");
    v["job"]["configuration"]["slots"][1]
        .as_object_mut()
        .unwrap()
        .remove("wheel");
    v["job"]["configuration"]["slots"][3]
        .as_object_mut()
        .unwrap()
        .remove("wheel");
    v["job"]["configuration"]["slots"][3]
        .as_object_mut()
        .unwrap()
        .remove("position");
    v["job"]["space"]["slots"] = json!([
        {"id":"left","wheels":["III","I"]},
        {"id":"right","wheels":["I","III"],"positions":["V","U"],"rings":["A","B","C"]}]);
    v["job"]["space"]["constraints"] = json!({"distinct_wheels":["left","right"]});
    let request = AttackRequest::parse_json(&v.to_string()).unwrap();
    let result = request.run(|_| {}, || false).unwrap();
    assert_eq!(result.counters().bombe_settings(), 12);
    let best = result.best().unwrap();
    assert_eq!(best.configuration(), &configuration);
    assert_eq!(best.plaintext(), plaintext);
    assert!(best.mutable_plugboard().is_empty());
    let wire = serde_json::to_value(Event::result(&result, 0)).unwrap();
    assert_eq!(wire["best"]["outer_index"], "11");
    assert_eq!(wire["best"]["start_index"], "0");
    assert_eq!(wire["best"]["crib_position"], "0");
}
