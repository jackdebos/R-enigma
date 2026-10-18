use enigma_core::{
    AttackBest, AttackCounterOverflow, AttackProgress, AttackResult, AttackRunCategory,
    AttackRunError, AttackRunSource, AttackTermination,
};

#[test]
fn hc_pe_runs_have_empty_public_and_wire_stage_histories() {
    for pe in [false, true] {
        for (budget, offset, cancelled) in [
            (100, 0, false),
            (1, 0, false),
            (1, 1, false),
            (100, 0, true),
        ] {
            let result = fixture(budget, offset, pe)
                .run(|_| {}, || cancelled)
                .unwrap();
            assert!(result.stages().is_empty());
            let wire = serde_json::to_value(enigma_core::Event::result(&result, 0)).unwrap();
            assert_eq!(wire["stages"], serde_json::json!([]));
            assert_eq!(wire.as_object().unwrap().len(), 6);
            assert_eq!(
                wire["hold"].as_array().unwrap().len(),
                result.hold().count()
            );
            assert_eq!(result.hold().next().is_none(), result.best().is_none());
        }
    }
    use enigma_core::{AttackStageResult, MeasureId, MeasuredScore};
    let _: fn(&AttackResult) -> &[AttackStageResult] = AttackResult::stages;
    let _: fn(&AttackRunError) -> &[AttackStageResult] = AttackRunError::stages;
    let _: fn(&AttackStageResult) -> &str = AttackStageResult::pass;
    let _: fn(&AttackStageResult) -> MeasureId = AttackStageResult::measure;
    let _: fn(&AttackStageResult) -> Option<MeasureId> = AttackStageResult::base_measure;
    let _: fn(&AttackStageResult) -> Option<MeasuredScore> = AttackStageResult::score;
    let _: fn(&AttackStageResult) -> u64 = AttackStageResult::evaluations_used;
    let _: fn(&AttackStageResult) -> bool = AttackStageResult::completed;
}

#[test]
fn success_hold_is_borrowed_ordered_and_keeps_entry_histories() {
    fn client<'a>(entry: enigma_core::AttackHoldEntry<'a>) -> &'a AttackBest {
        entry.best()
    }
    for capacity in [1, 100] {
        let mut value = fixture_value(100, 0, true);
        value["job"]["attack"]["hold"] = serde_json::json!(capacity);
        let before = enigma_core::AttackRequest::parse_json(&value.to_string())
            .unwrap()
            .run(|_| {}, || false)
            .unwrap();
        value["job"]["passes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("measure"));
        value["job"]["attack"]["measure"] = serde_json::json!({"measure": "ic"});
        value["job"]["attack"]["evaluation_budget"] =
            serde_json::json!(before.evaluations_used() + 1);
        let result = enigma_core::AttackRequest::parse_json(&value.to_string())
            .unwrap()
            .run(|_| {}, || false)
            .unwrap();
        let entries: Vec<_> = result.hold().collect();
        assert_eq!(entries.len(), if capacity == 1 { 1 } else { 2 });
        assert!(std::ptr::eq(client(entries[0]), result.best().unwrap()));
        assert!(std::ptr::eq(entries[0].stages(), result.stages()));
        assert_eq!(entries[0].stages().len(), 1);
        if capacity > 1 {
            assert!(entries[1].stages().is_empty());
        }
        let wire = serde_json::to_value(enigma_core::Event::result(&result, 0)).unwrap();
        for (entry, projected) in entries.iter().zip(wire["hold"].as_array().unwrap()) {
            assert_eq!(
                projected["start_index"],
                entry.best().start_index().to_string()
            );
            assert_eq!(
                projected["stages"].as_array().unwrap().len(),
                entry.stages().len()
            );
        }
        assert_eq!(wire["hold"][0]["stages"], wire["stages"]);
    }
}

#[test]
fn public_run_error_is_pointer_sized() {
    assert_eq!(
        std::mem::size_of::<AttackRunError>(),
        std::mem::size_of::<usize>(),
        "the opaque error owns its complete factual envelope indirectly"
    );
}

#[test]
fn borrowed_projection_error_supports_client_downcast() {
    // Qualify this synthetic downcast separately from public runtime coverage.
    fn client(error: &AttackRunError) -> Option<&enigma_core::ModelError> {
        let projection = error.best().err()?;
        projection.downcast_ref::<enigma_core::ModelError>()
    }
    let _: fn(&AttackRunError) -> Option<&enigma_core::ModelError> = client;
    let owned = enigma_core::ModelError::UnknownSymbol('Z');
    let borrowed: &(dyn std::error::Error + Send + Sync + 'static) = &owned;
    assert_eq!(
        borrowed.downcast_ref::<enigma_core::ModelError>(),
        Some(&owned)
    );
}

fn fixture_value(budget: u64, offset: u64, pe: bool) -> serde_json::Value {
    let alphabet = ["🦀", "é", "Ω", "中"];
    let mut value = serde_json::json!({
        "protocol_version": 1, "machine": {"definition": {"kind": "custom", "value": {
            "alphabet": alphabet, "wheels": [{"name": "r", "wiring": alphabet, "turnovers": []}],
            "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
            "stepping": {"rules": []}
        }}}, "job": {
            "kind": "search", "configuration": {"slots": [{"id": "r", "position": "é", "ring": "Ω"}],
                "plugboard": [["中", "é"]]}, "text": "🦀🦀", "measures": ["ic"], "passes": ["hill_climb"],
            "space": {"offset": offset, "plugboard": {"kind": "attack", "symbols": ["🦀", "Ω"], "max_pairs": 2}},
            "attack": {"kind": "hill_climb", "initial_measure": "ic", "final_measure": "ic",
                "switch_pairs": 2, "backtrack_pairs": 2, "evaluation_budget": budget, "start": [["Ω", "🦀"]]}
        }
    });
    if pe {
        value["job"]["passes"] = serde_json::json!(["partial_exhaustion"]);
        let attack = value["job"]["attack"].as_object_mut().unwrap();
        attack.insert("kind".into(), serde_json::json!("partial_exhaustion"));
        attack.remove("start");
        attack.insert(
            "seeds".into(),
            serde_json::json!({"kind": "empty_single", "selection": "all"}),
        );
    }
    value
}

fn measure_fixture(budget: u64, offset: u64, pe: bool) -> enigma_core::AttackRequest {
    let mut value = fixture_value(budget, offset, pe);
    value["job"]["passes"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("measure"));
    value["job"]["measures"] = serde_json::json!(["ic", "entropy"]);
    value["job"]["attack"]["measure"] = serde_json::json!({"measure": "entropy"});
    value["job"]["attack"]["hold"] = serde_json::json!(1); // Task 13 single winner.
    enigma_core::AttackRequest::parse_json(&value.to_string()).unwrap()
}

#[test]
fn measure_rescores_the_same_hc_and_pe_winner_once() {
    for pe in [false, true] {
        let before = fixture(100, 0, pe).run(|_| {}, || false).unwrap();
        let mut last = None;
        let after = measure_fixture(before.evaluations_used() + 1, 0, pe)
            .run(|p| last = Some(p), || false)
            .unwrap();
        assert_eq!(after.termination(), AttackTermination::Completed);
        assert_eq!(last, Some(after.counters()));
        let (a, c, started, finished, outers) = counts(before.counters());
        assert_eq!(
            counts(after.counters()),
            (a + 1, c + 1, started, finished, outers)
        );
        assert_eq!(after.evaluations_used(), before.evaluations_used() + 1);
        let old = before.best().unwrap();
        let best = after.best().unwrap();
        assert_eq!(best.configuration(), old.configuration());
        assert_eq!(best.mutable_plugboard(), old.mutable_plugboard());
        assert_eq!(best.plaintext(), old.plaintext());
        assert_eq!(best.outer_index(), old.outer_index());
        assert_eq!(best.start_index(), old.start_index());
        assert_eq!(best.incomplete(), old.incomplete());
        assert_eq!(best.final_objective_ascent(), old.final_objective_ascent());
        assert_eq!(best.neighborhood_exhausted(), old.neighborhood_exhausted());
        let expected = enigma_core::shannon_entropy(
            &enigma_core::Alphabet::new("🦀éΩ中".chars().collect()).unwrap(),
            best.plaintext(),
        )
        .unwrap();
        assert_eq!(best.score(), expected);
        assert_eq!(best.measure(), enigma_core::MeasureId::Entropy);
        let stage = &after.stages()[0];
        assert_eq!(after.stages().len(), 1);
        assert_eq!(
            (stage.pass(), stage.measure(), stage.base_measure()),
            ("measure", enigma_core::MeasureId::Entropy, None)
        );
        assert_eq!(
            (stage.score(), stage.evaluations_used(), stage.completed()),
            (Some(expected), 1, true)
        );
        let wire = serde_json::to_value(enigma_core::Event::result(&after, 0)).unwrap();
        assert_eq!(wire["stages"][0]["evaluations_used"], "1");
    }
}

#[test]
fn measure_starts_only_after_first_admission() {
    use std::cell::Cell;
    for pe in [false, true] {
        let complete = fixture(100, 0, pe).run(|_| {}, || false).unwrap();
        let used = complete.evaluations_used();
        for (budget, offset, cancel, termination) in [
            (1, 0, false, AttackTermination::EvaluationBudget),
            (used, 0, false, AttackTermination::EvaluationBudget),
            (used, 0, true, AttackTermination::Cancelled),
            (used + 1, 0, true, AttackTermination::Cancelled),
            (used + 1, 1, true, AttackTermination::OuterSliceEnd),
        ] {
            let completed = Cell::new(0);
            let mut last = None;
            let result = measure_fixture(budget, offset, pe)
                .run(
                    |p| {
                        completed.set(p.outers_completed());
                        last = Some(p);
                    },
                    || cancel && completed.get() == 1,
                )
                .unwrap();
            assert_eq!(result.termination(), termination);
            assert!(result.stages().is_empty());
            assert_eq!(last, Some(result.counters()));
            assert!(result.evaluations_used() <= used);
            if offset == 1 {
                assert!(result.best().is_none());
            }
            if budget >= used && offset == 0 {
                assert_eq!(
                    result.best().unwrap().score(),
                    complete.best().unwrap().score()
                );
            }
        }
        // Completion must not add a speculative cancellation poll after the final score.
        let completed = Cell::new(0);
        let result = measure_fixture(used + 1, 0, pe)
            .run(
                |p| completed.set(p.evaluations_completed()),
                || completed.get() > used,
            )
            .unwrap();
        assert_eq!(result.termination(), AttackTermination::Completed);
    }
}

fn trie_fixture(
    budget: u64,
    pe: bool,
    order: &[&str],
    base: Option<&str>,
    weight: i64,
) -> enigma_core::AttackRequest {
    let mut value = fixture_value(budget, 0, pe);
    value["job"]["text"] = serde_json::json!("🦀éΩ🦀");
    value["job"]["measures"] = serde_json::json!(["ic", "entropy", "trie"]);
    value["job"]["attack"]["initial_measure"] = serde_json::json!("entropy");
    value["job"]["attack"]["final_measure"] = serde_json::json!("entropy");
    value["job"]["attack"]["hold"] = serde_json::json!(1); // Task 13 single winner.
    value["job"]["passes"]
        .as_array_mut()
        .unwrap()
        .extend(order.iter().map(|stage| serde_json::json!(stage)));
    if order.contains(&"trie") {
        value["job"]["attack"]["trie"] = base.map_or_else(
            || serde_json::json!({}),
            |base| serde_json::json!({"base_measure": base}),
        );
    }
    value["job"]["resources"] = serde_json::json!({"trie": {"path": "words.json"}});
    let dictionary = serde_json::json!({"resource_version": 1, "kind": "dictionary",
        "alphabet": ["🦀", "é", "Ω", "中"],
        "entries": [{"word": ["🦀"], "weight": weight}]})
    .to_string();
    enigma_core::ParsedAttackRequest::parse_json(&value.to_string())
        .unwrap()
        .bind_resources(&std::collections::BTreeMap::from([(
            "trie".to_owned(),
            dictionary.as_str(),
        )]))
        .unwrap()
}

#[test]
fn trie_composes_rankings_once_on_the_same_hc_and_pe_plaintext() {
    use enigma_core::{index_of_coincidence, shannon_entropy, Alphabet, MeasureId, SCALE};
    let alphabet = Alphabet::new("🦀éΩ中".chars().collect()).unwrap();
    for pe in [false, true] {
        let before = trie_fixture(100, pe, &[], None, 3)
            .run(|_| {}, || false)
            .unwrap();
        let used = before.evaluations_used();
        for base in [None, Some("ic"), Some("entropy"), Some("trie")] {
            for weight in [-3, 3] {
                let after = trie_fixture(used + 1, pe, &["trie"], base, weight)
                    .run(|_| {}, || false)
                    .unwrap();
                assert_eq!(after.termination(), AttackTermination::Completed);
                let old = before.best().unwrap();
                let best = after.best().unwrap();
                assert_eq!(best.configuration(), old.configuration());
                assert_eq!(best.mutable_plugboard(), old.mutable_plugboard());
                assert_eq!(best.plaintext(), old.plaintext());
                assert_eq!(best.outer_index(), old.outer_index());
                assert_eq!(best.start_index(), old.start_index());
                assert_eq!(best.incomplete(), old.incomplete());
                assert_eq!(best.final_objective_ascent(), old.final_objective_ascent());
                assert_eq!(best.neighborhood_exhausted(), old.neighborhood_exhausted());
                let trie = best.plaintext().chars().filter(|&c| c == '🦀').count() as i128
                    * i128::from(weight)
                    * SCALE;
                assert_ne!(trie, 0);
                assert_ne!(old.score().measured(), old.score().ranking());
                let base_units = match base {
                    Some("ic") => index_of_coincidence(&alphabet, best.plaintext())
                        .unwrap()
                        .ranking()
                        .units(),
                    Some("entropy") => shannon_entropy(&alphabet, best.plaintext())
                        .unwrap()
                        .ranking()
                        .units(),
                    Some("trie") => trie,
                    _ => old.score().ranking().units(),
                };
                assert_eq!(best.measure(), MeasureId::Trie);
                assert_eq!(best.score().measured().units(), trie);
                assert_eq!(best.score().ranking().units(), base_units + trie);
                let (a, c, s, f, o) = counts(before.counters());
                assert_eq!(counts(after.counters()), (a + 1, c + 1, s, f, o));
                let wire = serde_json::to_value(enigma_core::Event::result(&after, 0)).unwrap();
                assert_eq!(
                    wire["stages"][0],
                    serde_json::json!({"pass": "trie", "measure": "trie",
                    "base_measure": base, "score": wire["best"]["score"],
                    "evaluations_used": "1", "completed": true})
                );
            }
        }
    }
}

#[test]
fn supported_stage_orders_share_allowance_and_cancellation_boundaries() {
    use std::cell::Cell;
    for pe in [false, true] {
        let before = trie_fixture(100, pe, &[], None, 3)
            .run(|_| {}, || false)
            .unwrap();
        let used = before.evaluations_used();
        let outers = Cell::new(0);
        let cancelled = trie_fixture(used + 1, pe, &["trie"], None, 3)
            .run(|p| outers.set(p.outers_completed()), || outers.get() > 0)
            .unwrap();
        assert_eq!(cancelled.termination(), AttackTermination::Cancelled);
        assert!(cancelled.stages().is_empty());
        assert_eq!(cancelled.evaluations_used(), used);
        for order in [["measure", "trie"], ["trie", "measure"]] {
            let completed = Cell::new(0);
            for extra in 0..=2 {
                for cancel in [false, true] {
                    completed.set(0);
                    let mut last = None;
                    let result = trie_fixture(used + extra, pe, &order, None, 3)
                        .run(
                            |p| {
                                completed.set(p.evaluations_completed());
                                last = Some(p);
                            },
                            || cancel && completed.get() > used,
                        )
                        .unwrap();
                    let stages = if cancel { extra.min(1) } else { extra };
                    assert_eq!(result.stages().len() as u64, stages);
                    assert_eq!(result.evaluations_used(), used + stages);
                    assert_eq!(last, Some(result.counters()));
                    assert_eq!(
                        result.termination(),
                        if cancel && extra > 0 {
                            AttackTermination::Cancelled
                        } else if extra < 2 {
                            AttackTermination::EvaluationBudget
                        } else {
                            AttackTermination::Completed
                        }
                    );
                    for (stage, pass) in result.stages().iter().zip(order) {
                        assert_eq!(stage.pass(), pass);
                        assert_eq!(stage.evaluations_used(), 1);
                        assert!(stage.completed());
                    }
                    let best = result.best().unwrap();
                    let ic = enigma_core::index_of_coincidence(
                        &enigma_core::Alphabet::new("🦀éΩ中".chars().collect()).unwrap(),
                        best.plaintext(),
                    )
                    .unwrap();
                    if stages == 2 {
                        if order[1] == "measure" {
                            assert_eq!(best.score(), ic);
                        } else {
                            assert_eq!(
                                best.score().ranking().units(),
                                ic.ranking().units() + best.score().measured().units()
                            );
                        }
                    }
                }
            }
            // A pending cancellation after the final evaluation cannot undo completion.
            completed.set(0);
            let result = trie_fixture(used + 2, pe, &order, None, 3)
                .run(
                    |p| completed.set(p.evaluations_completed()),
                    || completed.get() == used + 2,
                )
                .unwrap();
            assert_eq!(result.termination(), AttackTermination::Completed);
        }
    }
}

fn reswapping_fixture(budget: u64, pe: bool, order: &[&str]) -> enigma_core::AttackRequest {
    let mut value = fixture_value(budget, 0, pe);
    let passes = value["job"]["passes"].as_array_mut().unwrap();
    passes.extend(order.iter().map(|stage| serde_json::json!(stage)));
    value["job"]["measures"] = serde_json::json!(["ic", "entropy"]);
    if order.contains(&"measure") {
        value["job"]["attack"]["measure"] = serde_json::json!({"measure": "ic"});
    }
    value["job"]["attack"]["reswapping"] = serde_json::json!({"measure": "entropy"});
    value["job"]["attack"]["hold"] = serde_json::json!(1); // Task 13 single winner.
    enigma_core::AttackRequest::parse_json(&value.to_string()).unwrap()
}

#[test]
fn reswapping_climbs_the_hc_and_pe_winner_under_shared_accounting() {
    use enigma_core::MeasureId::Entropy;
    let alphabet = enigma_core::Alphabet::new("🦀éΩ中".chars().collect()).unwrap();
    for pe in [false, true] {
        let before = fixture(100, 0, pe).run(|_| {}, || false).unwrap();
        let (used, old) = (before.evaluations_used(), before.best().unwrap());
        for order in [&["reswapping"][..], &["measure", "reswapping"]] {
            let mut last = None;
            let after = reswapping_fixture(used + 20, pe, order)
                .run(|p| last = Some(p), || false)
                .unwrap();
            assert_eq!(after.termination(), AttackTermination::Completed);
            assert_eq!(last, Some(after.counters()));
            let best = after.best().unwrap();
            let stage = after.stages().last().unwrap();
            let spent = after.evaluations_used() - used - (order.len() as u64 - 1);
            assert_eq!(after.stages().len(), order.len());
            assert_eq!((stage.pass(), stage.measure()), ("reswapping", Entropy));
            assert_eq!(stage.base_measure(), None);
            assert_eq!(
                (stage.score(), stage.evaluations_used(), stage.completed()),
                (Some(best.score()), spent, true)
            );
            // HC keeps one pair (initial plus four trials); PE keeps the empty board.
            assert_eq!(spent, if pe { 1 } else { 5 });
            let (a, c, s, f, o) = counts(before.counters());
            let extra = after.evaluations_used() - used;
            assert_eq!(counts(after.counters()), (a + extra, c + extra, s, f, o));
            let entropy = |text| enigma_core::shannon_entropy(&alphabet, text).unwrap();
            assert_eq!(best.measure(), Entropy);
            assert_eq!(best.score(), entropy(best.plaintext()));
            assert!(best.score().ranking().units() >= entropy(old.plaintext()).ranking().units());
            assert_eq!(best.outer_index(), old.outer_index());
            assert_eq!(best.start_index(), old.start_index());
            assert!(best.configuration().plugboard().contains(&('é', '中')));
            let wire = serde_json::to_value(enigma_core::Event::result(&after, 0)).unwrap();
            assert_eq!(
                wire["stages"][order.len() - 1],
                serde_json::json!({"pass": "reswapping", "measure": "entropy",
                    "base_measure": null, "score": wire["best"]["score"],
                    "evaluations_used": spent.to_string(), "completed": true})
            );
        }
    }
}

#[test]
fn reswapping_stops_mid_stage_or_before_start_on_budget_and_cancellation() {
    use std::cell::Cell;
    use AttackTermination::{Cancelled, Completed, EvaluationBudget};
    for pe in [false, true] {
        let before = fixture(100, 0, pe).run(|_| {}, || false).unwrap();
        let used = before.evaluations_used();
        let full = reswapping_fixture(used + 20, pe, &["reswapping"])
            .run(|_| {}, || false)
            .unwrap();
        let spent = full.stages()[0].evaluations_used();
        let completed = Cell::new(0);
        for extra in 0..=spent {
            for cancel in [false, true] {
                completed.set(0);
                let budget = if cancel { used + 20 } else { used + extra };
                let result = reswapping_fixture(budget, pe, &["reswapping"])
                    .run(
                        |p| completed.set(p.evaluations_completed()),
                        || cancel && completed.get() >= used + extra,
                    )
                    .unwrap();
                assert_eq!(result.evaluations_used(), used + extra);
                if extra == 0 {
                    // Neither stop admits a first evaluation, so the stage never starts.
                    assert!(result.stages().is_empty());
                    let stop = [EvaluationBudget, Cancelled][usize::from(cancel)];
                    assert_eq!(result.termination(), stop);
                    let score = |run: &AttackResult| run.best().unwrap().score();
                    assert_eq!(score(&result), score(&before));
                    continue;
                }
                let stage = &result.stages()[0];
                assert_eq!(stage.evaluations_used(), extra);
                assert_eq!(stage.score(), Some(result.best().unwrap().score()));
                // A pending cancellation after the final scan does not undo completion.
                let termination = match (extra == spent, cancel) {
                    (true, _) => Completed,
                    (_, true) => Cancelled,
                    (_, false) => EvaluationBudget,
                };
                assert_eq!(result.termination(), termination);
                assert_eq!(stage.completed(), termination == Completed);
            }
        }
    }
}

#[test]
fn reswapping_commits_a_strict_trie_improvement_over_the_hc_winner() {
    // A non-identity wheel makes plaintext board-dependent; IC ties keep the HC start.
    let mut value = fixture_value(20, 0, false);
    value["machine"]["definition"]["value"]["wheels"][0]["wiring"] =
        serde_json::json!(["é", "🦀", "中", "Ω"]);
    value["job"]["measures"] = serde_json::json!(["ic", "trie"]);
    value["job"]["resources"] = serde_json::json!({"trie": {"path": "words.json"}});
    let dictionary = serde_json::json!({"resource_version": 1, "kind": "dictionary",
        "alphabet": ["🦀", "é", "Ω", "中"], "entries": [{"word": ["é"], "weight": 3}]})
    .to_string();
    let supplied = std::collections::BTreeMap::from([("trie".to_owned(), dictionary.as_str())]);
    let run = |value: &serde_json::Value| {
        let parsed = enigma_core::ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
        let request = parsed.bind_resources(&supplied).unwrap();
        request.run(|_| {}, || false).unwrap()
    };
    let before = run(&value);
    value["job"]["passes"] = serde_json::json!(["hill_climb", "reswapping"]);
    value["job"]["attack"]["reswapping"] = serde_json::json!({"measure": "trie"});
    let after = run(&value);
    let (old, best) = (before.best().unwrap(), after.best().unwrap());
    assert_eq!(old.mutable_plugboard(), [('🦀', 'Ω')]);
    assert_eq!((old.plaintext(), best.plaintext()), ("中中", "éé"));
    // The winning pure removal shrinks the board; the empty rescan has no trials.
    assert!(best.mutable_plugboard().is_empty());
    assert_eq!(best.configuration().plugboard(), [('é', '中')]);
    assert_eq!(best.score().ranking().units(), 6 * enigma_core::SCALE);
    assert_eq!(best.measure(), enigma_core::MeasureId::Trie);
    let stage = &after.stages()[0];
    let history = (stage.score(), stage.evaluations_used(), stage.completed());
    assert_eq!(history, (Some(best.score()), 5, true));
    assert_eq!(after.termination(), AttackTermination::Completed);
}

fn fixture(budget: u64, offset: u64, pe: bool) -> enigma_core::AttackRequest {
    enigma_core::AttackRequest::parse_json(&fixture_value(budget, offset, pe).to_string()).unwrap()
}

#[test]
fn public_run_preserves_absolute_selected_outer_index() {
    let mut value = fixture_value(100, 1, false);
    value["job"]["configuration"]["slots"] = serde_json::json!([]);
    value["job"]["space"]["slots"] = serde_json::json!([
        {"id": "r", "positions": ["🦀", "é"], "rings": ["Ω"]}
    ]);
    let request = enigma_core::AttackRequest::parse_json(&value.to_string()).unwrap();
    let result = request.run(|_| {}, || false).unwrap();
    assert_eq!(result.termination(), AttackTermination::Completed);
    let best = result.best().unwrap();
    assert_eq!((best.outer_index(), best.start_index()), (1, 0));
    assert_eq!(
        best.configuration().slots(),
        &[enigma_core::SlotConfiguration::new("r", "r", 'é', 'Ω')]
    );
    assert_eq!(counts(result.counters()), (2, 2, 1, 1, 1));
}

fn counts(progress: AttackProgress) -> (u64, u64, u128, u128, u128) {
    (
        progress.evaluations_admitted(),
        progress.evaluations_completed(),
        progress.climbs_started(),
        progress.climbs_completed(),
        progress.outers_completed(),
    )
}

#[test]
fn public_run_projects_real_winner_and_terminal_observation() {
    let request = fixture(100, 0, false);
    let mut snapshots = Vec::new();
    let result = request
        .run(|snapshot| snapshots.push(snapshot), || false)
        .unwrap();
    assert_eq!(result.termination(), AttackTermination::Completed);
    assert_eq!(snapshots.last(), Some(&result.counters()));
    assert_eq!(counts(result.counters()), (2, 2, 1, 1, 1));
    assert_eq!(result.evaluations_used(), 2);
    let best = result.best().unwrap();
    assert_eq!(
        best.configuration().plugboard(),
        &[('🦀', 'Ω'), ('é', '中')]
    );
    assert_eq!(
        best.configuration().slots(),
        &[enigma_core::SlotConfiguration::new("r", "r", 'é', 'Ω')]
    );
    assert_eq!(best.mutable_plugboard(), &[('🦀', 'Ω')]);
    assert_eq!(best.plaintext(), "🦀🦀");
    assert_eq!(best.measure(), enigma_core::MeasureId::Ic);
    assert_eq!(
        best.score(),
        enigma_core::index_of_coincidence(
            &enigma_core::Alphabet::new("🦀éΩ中".chars().collect()).unwrap(),
            "🦀🦀"
        )
        .unwrap()
    );
    assert_eq!((best.outer_index(), best.start_index()), (0, 0));
    assert!(!best.incomplete());
    assert!(best.final_objective_ascent());
    assert!(best.neighborhood_exhausted());
}

#[test]
fn public_run_restarts_after_cancel_and_after_completion() {
    let request = fixture(100, 0, false);
    let mut last = None;
    let cancelled = request.run(|p| last = Some(p), || true).unwrap();
    assert_eq!(cancelled.termination(), AttackTermination::Cancelled);
    assert_eq!(counts(cancelled.counters()), (0, 0, 0, 0, 0));
    assert_eq!(cancelled.evaluations_used(), 0);
    assert!(cancelled.best().is_none());
    assert_eq!(last, Some(cancelled.counters()));
    for _ in 0..2 {
        let complete = request.run(|_| {}, || false).unwrap();
        assert_eq!(complete.termination(), AttackTermination::Completed);
        assert_eq!(counts(complete.counters()), (2, 2, 1, 1, 1));
        assert_eq!(complete.evaluations_used(), 2);
        assert!(complete.best().is_some());
    }
}

#[test]
fn public_run_empty_slice_beats_cancellation() {
    let mut last = None;
    let result = fixture(1, 1, false)
        .run(|p| last = Some(p), || true)
        .unwrap();
    assert_eq!(result.termination(), AttackTermination::OuterSliceEnd);
    assert_eq!(counts(result.counters()), (0, 0, 0, 0, 0));
    assert_eq!(result.evaluations_used(), 0);
    assert!(result.best().is_none());
    assert_eq!(last, Some(result.counters()));
}

#[test]
fn public_run_budget_stop_and_exact_budget_completion() {
    for (budget, termination, expected) in [
        (1, AttackTermination::EvaluationBudget, (1, 1, 1, 0, 0)),
        (2, AttackTermination::Completed, (2, 2, 1, 1, 1)),
    ] {
        let mut last = None;
        let result = fixture(budget, 0, false)
            .run(|p| last = Some(p), || false)
            .unwrap();
        assert_eq!(result.termination(), termination);
        assert_eq!(counts(result.counters()), expected);
        assert_eq!(result.evaluations_used(), budget);
        assert_eq!(last, Some(result.counters()));
        assert_eq!(result.best().unwrap().incomplete(), budget == 1);
    }
}

#[test]
fn public_pe_projects_unicode_mutable_winner() {
    let mut last = None;
    let mut value = fixture_value(100, 0, true);
    value["machine"]["definition"]["value"]["wheels"][0]["wiring"] =
        serde_json::json!(["é", "🦀", "Ω", "中"]);
    value["job"]["measures"] = serde_json::json!(["trie"]);
    value["job"]["attack"]["initial_measure"] = serde_json::json!("trie");
    value["job"]["attack"]["final_measure"] = serde_json::json!("trie");
    value["job"]["resources"] = serde_json::json!({"trie": {"path": "dictionary.json"}});
    let dictionary = serde_json::json!({"resource_version":1,"kind":"dictionary","alphabet":["🦀","é","Ω","中"],"entries":[{"word":["中","中"],"weight":1}]}).to_string();
    let supplied = std::collections::BTreeMap::from([("trie".to_owned(), dictionary.as_str())]);
    let request = enigma_core::ParsedAttackRequest::parse_json(&value.to_string())
        .unwrap()
        .bind_resources(&supplied)
        .unwrap();
    let result = request
        .run(|p| last = Some(p), || false)
        .expect("public PE executes");
    assert_eq!(result.termination(), AttackTermination::Completed);
    assert_eq!(last, Some(result.counters()));
    assert_eq!(counts(result.counters()), (5, 5, 2, 2, 1));
    assert_eq!(result.evaluations_used(), 5);
    let best = result.best().unwrap();
    assert_eq!(
        best.configuration().plugboard(),
        &[('🦀', 'Ω'), ('é', '中')]
    );
    assert_eq!(best.mutable_plugboard(), &[('🦀', 'Ω')]);
    assert_eq!(
        best.configuration().slots(),
        &[enigma_core::SlotConfiguration::new("r", "r", 'é', 'Ω')]
    );
    assert_eq!(best.plaintext(), "中中");
    assert_eq!(best.measure(), enigma_core::MeasureId::Trie);
    assert_eq!(best.score().ranking().units(), 1 << 32);
    assert_eq!((best.outer_index(), best.start_index()), (0, 0));
    assert!(!best.incomplete());
    assert!(best.final_objective_ascent());
    assert!(best.neighborhood_exhausted());
}

#[test]
fn public_root_getter_signatures_are_accessible() {
    let _: fn(&AttackRunError) -> &AttackRunSource = AttackRunError::run_source;
    let _: fn(&AttackRunError) -> Option<u128> = AttackRunError::outer_index;
    let _: fn(&AttackRunError) -> Option<u128> = AttackRunError::start_index;
    let _: fn(&AttackRunError) -> u64 = AttackRunError::evaluations_used;
    let _: fn(&AttackRunError) -> AttackProgress = AttackRunError::counters;
    let _: fn(
        &AttackRunError,
    ) -> Result<Option<&AttackBest>, &(dyn std::error::Error + Send + Sync)> = AttackRunError::best;
    let _: fn(&AttackRunSource) -> AttackRunCategory = AttackRunSource::category;
    let _: fn(&AttackRunSource) -> Option<&[enigma_core::SearchDiagnostic]> =
        AttackRunSource::diagnostics;
    let _: fn(&AttackRunSource) -> Option<AttackCounterOverflow> = AttackRunSource::overflow;
    fn assert_error<T: std::error::Error + Send + Sync + 'static>() {}
    assert_error::<AttackRunError>();
    assert_error::<AttackRunSource>();
    let _ = AttackRunCategory::UnsupportedExecution;
    let _: fn(&AttackResult) -> AttackTermination = AttackResult::termination;
    let _: fn(&AttackResult) -> AttackProgress = AttackResult::counters;
    let _: fn(&AttackResult) -> u64 = AttackResult::evaluations_used;
    let _: fn(&AttackResult) -> Option<&AttackBest> = AttackResult::best;
    let _: fn(&AttackProgress) -> u64 = AttackProgress::evaluations_admitted;
    let _: fn(&AttackProgress) -> u64 = AttackProgress::evaluations_completed;
    let _: fn(&AttackProgress) -> u128 = AttackProgress::climbs_started;
    let _: fn(&AttackProgress) -> u128 = AttackProgress::climbs_completed;
    let _: fn(&AttackProgress) -> u128 = AttackProgress::outers_completed;
    let _: fn(&AttackBest) -> &enigma_core::TransformConfiguration = AttackBest::configuration;
    let _: fn(&AttackBest) -> &[(char, char)] = AttackBest::mutable_plugboard;
    let _: fn(&AttackBest) -> &str = AttackBest::plaintext;
    let _: fn(&AttackBest) -> enigma_core::MeasuredScore = AttackBest::score;
    let _: fn(&AttackBest) -> enigma_core::MeasureId = AttackBest::measure;
    let _: fn(&AttackBest) -> u128 = AttackBest::outer_index;
    let _: fn(&AttackBest) -> u128 = AttackBest::start_index;
    let _: fn(&AttackBest) -> bool = AttackBest::incomplete;
    let _: fn(&AttackBest) -> bool = AttackBest::final_objective_ascent;
    let _: fn(&AttackBest) -> bool = AttackBest::neighborhood_exhausted;
}
