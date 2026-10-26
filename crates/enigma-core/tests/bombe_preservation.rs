//! Public-interface goldens for the ciphertext-only paths shared with Bombe.
use enigma_core::{AttackRequest, Event, ExecutionOptions};
use serde_json::{json, Value};

fn request(pe: bool) -> Value {
    let kind = if pe {
        "partial_exhaustion"
    } else {
        "hill_climb"
    };
    let mut value = json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B","C","D"],
        "wheels":[{"name":"r","wiring":["A","B","C","D"],"turnovers":[]}],
        "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
        "stepping":{"rules":[]}}}},"job":{"kind":"search",
        "configuration":{"slots":[{"id":"r","position":"A","ring":"A"}],"plugboard":[["A","B"]]},
        "text":"AAAA","passes":[kind],"measures":["ic"],
        "space":{"plugboard":{"kind":"attack","symbols":["C","D"],"max_pairs":2}},
        "attack":{"kind":kind,"initial_measure":"ic","final_measure":"ic",
            "switch_pairs":0,"backtrack_pairs":0,"hold":1}}});
    value["job"]["attack"][if pe { "seeds" } else { "start" }] = if pe {
        json!({"kind":"empty_single","selection":"all"})
    } else {
        json!([["C", "D"]])
    };
    value
}

fn expected(pe: bool) -> Value {
    let count = if pe { "4" } else { "2" };
    let climbs = if pe { "2" } else { "1" };
    let best = json!({"configuration":{"slots":[{"id":"r","wheel":"r","position":"A","ring":"A"}],
        "plugboard":if pe {json!([["A","B"]])} else {json!([["A","B"],["C","D"]])}},
        "mutable_plugboard":if pe {json!([])} else {json!([["C","D"]])},"plaintext":"AAAA",
        "score":{"measure":"ic","measured_q32":"17179869184","ranking_q32":"17179869184",
            "measured":"4.000000","ranking":"4.000000"},
        "outer_index":"0","start_index":"0","incomplete":false,
        "final_objective_ascent":true,"neighborhood_exhausted":true});
    let mut entry = best.clone();
    entry["stages"] = json!([]);
    json!({"event":"result","best":best,"hold":[entry],"stages":[],"elapsed_ms":"0",
        "counters":{"evaluations_admitted":count,"evaluations_completed":count,
            "climbs_started":climbs,"climbs_completed":climbs,"outers_completed":"1"}})
}

fn assert_previous_result(pe: bool) {
    let value = request(pe);
    let owner = AttackRequest::parse_json(&value.to_string()).unwrap();
    let result = owner.run(|_| {}, || false).unwrap();
    let wire = serde_json::to_value(Event::result(&result, 0)).unwrap();
    assert_eq!(wire, expected(pe));
    println!("DIFFERENTIAL result {pe}: {wire}");
    // A new field must not leak into either sibling's admission grammar, even
    // when another invalid value would otherwise be diagnosed first.
    for malformed in [false, true] {
        let mut invalid = value.clone();
        invalid["job"]["attack"]["crib"] = json!({"text":"A"});
        if malformed {
            invalid["job"]["attack"]["kind"] = json!("wrong");
        }
        let errors = AttackRequest::parse_json(&invalid.to_string()).unwrap_err();
        assert_eq!(
            (errors[0].code(), errors[0].location()),
            ("unknown_field", "/job/attack/crib")
        );
        println!(
            "DIFFERENTIAL error {pe} {malformed}: {} {} {}",
            errors[0].code(),
            errors[0].location(),
            errors[0].message()
        );
    }
}

#[test]
fn hc_result_is_unchanged() {
    assert_previous_result(false);
}

#[test]
fn pe_result_is_unchanged() {
    assert_previous_result(true);
}

#[test]
fn checkpoint_record_is_unchanged() {
    for pe in [false, true] {
        let value = request(pe);
        let identity =
            enigma_core::checkpoint_identity(&value.to_string(), &Default::default()).unwrap();
        let owner = AttackRequest::parse_json(&value.to_string()).unwrap();
        let mut saved = None;
        owner
            .run_with_checkpoints(
                ExecutionOptions::serial(),
                |_| {},
                || false,
                |snapshot| saved = Some(snapshot.record(identity, 0).unwrap()),
            )
            .unwrap();
        let mut record = saved.unwrap();
        let encoded = record.seal_json().unwrap();
        let parsed: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 12);
        assert_eq!(parsed["counters"], expected(pe)["counters"]);
        assert!(parsed["best"].get("crib_position").is_none());
        assert_eq!(parsed["best"].as_object().unwrap().len(), 9);
        assert_eq!(parsed["phase"], "stages");
        assert_eq!(parsed["next_outer"], "1");
        let record = enigma_core::CheckpointRecord::parse_json(&encoded).unwrap();
        let resumed = owner
            .resume(&record)
            .unwrap()
            .run_with(ExecutionOptions::serial(), |_| {}, || false)
            .unwrap();
        assert_eq!(
            serde_json::to_value(Event::result(&resumed, 0)).unwrap(),
            expected(pe)
        );
        println!("DIFFERENTIAL checkpoint {pe}: {encoded}");
    }
}
