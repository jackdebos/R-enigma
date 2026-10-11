use enigma_core::{AttackBest, AttackProgress, AttackResult, AttackTermination};

#[test]
fn public_root_getter_signatures_are_accessible() {
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
