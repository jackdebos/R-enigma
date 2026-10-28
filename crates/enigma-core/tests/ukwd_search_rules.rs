use enigma_core::{AttackRequest, Event, ExecutionOptions};
use serde_json::{json, Value};
use std::collections::BTreeMap;
fn tiny(starts: u64) -> Value {
    json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":["A","B","C","D"],"wheels":[
            {"name":"D","rewirable":{"fixed_pairs":[]},"turnovers":[]},
            {"name":"I","wiring":["A","B","C","D"],"turnovers":[]}],
        "slots":[{"id":"ukw","role":"reflector","movement":"fixed","wheel":"D"},
            {"id":"r","role":"rotor","movement":"fixed","wheel":"I"}],"stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":[{"id":"ukw","position":"A","ring":"A"},
            {"id":"r","position":"A","ring":"A"}],"plugboard":[]},"text":"AAAA",
        "space":{"slots":[{"id":"ukw","pairs":{"kind":"attack"}}],"plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":0}},
        "passes":["hill_climb"],"measures":["ic","entropy"],"attack":{"kind":"hill_climb","initial_measure":"ic",
        "final_measure":"entropy","switch_pairs":1,"backtrack_pairs":0,"start":[],"reflector_starts":starts,"hold":10}}})
}
#[test]
fn wiring_plateau_accounting_and_independent_starts() {
    let request = AttackRequest::parse_json(&tiny(2).to_string()).unwrap();
    let result = request.run(|_| {}, || false).unwrap();
    // Per start: initial + two equal-score wiring trials + one final rescore.
    assert_eq!(result.counters().evaluations_completed(), 8);
    assert_eq!(result.counters().climbs_started(), 2);
    assert_eq!(result.counters().climbs_completed(), 2);
    let best = result.best().unwrap();
    assert_eq!(best.start_index(), 0);
    assert!(!best.final_objective_ascent());
    assert!(best.neighborhood_exhausted());
    assert_eq!(
        best.configuration().slots()[0].pairs(),
        Some(&[('A', 'D'), ('B', 'C')][..])
    );
    // Same objectives must reuse the final score rather than charge a rescore.
    let mut value = tiny(2);
    value["job"]["attack"]["final_measure"] = json!("ic");
    let identical = AttackRequest::parse_json(&value.to_string())
        .unwrap()
        .run(|_| {}, || false)
        .unwrap();
    assert_eq!(identical.counters().evaluations_completed(), 6);
}
#[test]
fn strict_best_earliest_wiring_tie_and_stage_rows() {
    let mut value = tiny(2);
    value["job"]["measures"] = json!(["sinkov_monogram", "ic"]);
    value["job"]["resources"] = json!({"sinkov_monogram":{"path":"unused.json"}});
    value["job"]["attack"]["initial_measure"] = json!("sinkov_monogram");
    value["job"]["attack"]["final_measure"] = json!("sinkov_monogram");
    value["job"]["passes"] = json!(["hill_climb", "measure"]);
    value["job"]["attack"]["measure"] = json!({"measure":"sinkov_monogram"});
    let model = json!({"resource_version":1,"kind":"ngram","alphabet":["A","B","C","D"],"order":1,
        "entries":[{"gram":["A"],"count":1},{"gram":["B"],"count":10},
            {"gram":["C"],"count":10},{"gram":["D"],"count":1}]})
    .to_string();
    let supplied = BTreeMap::from([("sinkov_monogram".to_owned(), model.as_str())]);
    let request = enigma_core::ParsedAttackRequest::parse_json(&value.to_string())
        .unwrap()
        .bind_resources(&supplied)
        .unwrap();
    let result = request.run(|_| {}, || false).unwrap();
    // Start 0 is AD BC. AB CD then AC BD tie as strict improvements;
    // retain the earliest (AB CD), never a plateau transition to AC BD.
    let best = result.best().unwrap();
    assert_eq!(
        best.configuration().slots()[0].pairs(),
        Some(&[('A', 'B'), ('C', 'D')][..])
    );
    assert_eq!(best.plaintext(), "BBBB");
    assert_eq!(best.start_index(), 0);
    assert_eq!(result.hold().count(), 2); // Different equal-score wirings remain distinct.
    for entry in result.hold() {
        assert_eq!(entry.best().score(), best.score());
        assert_eq!(entry.stages().len(), 1);
    }
}
#[test]
fn board_commit_switches_the_single_shared_phase_before_wiring_trials() {
    let mut value = tiny(1);
    value["job"]["space"]["plugboard"]["max_pairs"] = json!(1);
    value["job"]["measures"] = json!(["sinkov_monogram", "entropy"]);
    value["job"]["resources"] = json!({"sinkov_monogram":{"path":"unused.json"}});
    value["job"]["attack"]["initial_measure"] = json!("sinkov_monogram");
    let model = json!({"resource_version":1,"kind":"ngram","alphabet":["A","B","C","D"],"order":1,
        "entries":[{"gram":["A"],"count":1},{"gram":["B"],"count":1},
            {"gram":["C"],"count":10},{"gram":["D"],"count":1}]})
    .to_string();
    let supplied = BTreeMap::from([("sinkov_monogram".to_owned(), model.as_str())]);
    let request = enigma_core::ParsedAttackRequest::parse_json(&value.to_string())
        .unwrap()
        .bind_resources(&supplied)
        .unwrap();
    let result = request.run(|_| {}, || false).unwrap();
    // Initial + add AB + objective switch + remove AB trial + two wiring trials.
    // No per-phase or per-subclimb final rescoring is permitted.
    assert_eq!(result.counters().evaluations_completed(), 6);
    let best = result.best().unwrap();
    assert_eq!(best.mutable_plugboard(), &[('A', 'B')]);
    assert_eq!(best.plaintext(), "CCCC");
    assert!(best.final_objective_ascent());
    assert_eq!(
        best.configuration().slots()[0].pairs(),
        Some(&[('A', 'D'), ('B', 'C')][..])
    );
}
#[test]
fn checkpoint_roundtrip_reverifies_stored_wiring_before_stages() {
    for capacity in [1, 10] {
        let mut value = tiny(2);
        value["job"]["attack"]["hold"] = json!(capacity);
        value["job"]["passes"] = json!(["hill_climb", "measure"]);
        let text = value.to_string();
        let request = AttackRequest::parse_json(&text).unwrap();
        let identity = enigma_core::checkpoint_identity(&text, &BTreeMap::new()).unwrap();
        let mut record = None;
        let expected = request
            .run_with_checkpoints(
                ExecutionOptions::serial(),
                |_| {},
                || false,
                |snapshot| {
                    if snapshot.reason() == enigma_core::CheckpointReason::OuterFinished {
                        let mut captured = snapshot.record(identity, 0).unwrap();
                        record = Some(captured.seal_json().unwrap());
                    }
                },
            )
            .unwrap();
        let record = enigma_core::CheckpointRecord::parse_json(&record.unwrap()).unwrap();
        let actual = request
            .resume(&record)
            .unwrap()
            .run_with(ExecutionOptions::serial(), |_| {}, || false)
            .unwrap();
        assert_eq!(
            serde_json::to_value(Event::result(&actual, 0)).unwrap(),
            serde_json::to_value(Event::result(&expected, 0)).unwrap()
        );
    }
}
