use enigma_core::{
    AttackBest, AttackCounterOverflow, AttackProgress, AttackResult, AttackRunCategory,
    AttackRunError, AttackRunSource, AttackTermination,
};

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
fn public_run_rejects_valid_pe_without_callbacks() {
    use std::error::Error;
    let error = fixture(100, 0, true)
        .run(
            |_| panic!("unsupported execution must not observe"),
            || panic!("unsupported execution must not poll cancellation"),
        )
        .unwrap_err();
    assert_eq!(
        error.run_source().category(),
        AttackRunCategory::UnsupportedExecution
    );
    assert!(error
        .source()
        .unwrap()
        .downcast_ref::<AttackRunSource>()
        .is_some());
    assert!(!error.run_source().to_string().is_empty());
    assert!(error.run_source().diagnostics().is_none());
    assert!(error.run_source().overflow().is_none());
    assert_eq!((error.outer_index(), error.start_index()), (None, None));
    assert_eq!(error.evaluations_used(), 0);
    assert_eq!(counts(error.counters()), (0, 0, 0, 0, 0));
    assert!(error.best().unwrap().is_none());
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
