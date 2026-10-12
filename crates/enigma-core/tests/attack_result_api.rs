use enigma_core::{
    AttackBest, AttackCounterOverflow, AttackProgress, AttackResult, AttackRunCategory,
    AttackRunError, AttackRunSource, AttackTermination,
};

#[test]
fn borrowed_projection_error_supports_client_downcast() {
    // No public runner or constructor exists yet; type-check the real client body.
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
