//! Private bounded canonical finalists shared by attack schedulers.

use std::cmp::Ordering;

use crate::AttackBest;

/// Owns final-scored candidates from one owner and one comparable objective.
///
/// Inputs must have canonical complete configurations: definition-ordered slots,
/// alphabet-ordered pair endpoints and pairs, including fixed plus mutable pairs.
/// Configuration equality is structural; this type does not normalize raw keys.
#[derive(Debug)]
pub(crate) struct AttackHold {
    capacity: usize,
    entries: Vec<AttackBest>,
}

impl AttackHold {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "attack hold capacity must be positive");
        Self {
            capacity,
            entries: Vec::new(),
        }
    }

    /// Reject duplicate complete keys before considering rank or eviction.
    /// Existing payloads survive even inconsistent duplicate scores or indices;
    /// production offers arrive in ascending enumeration order.
    pub(crate) fn offer(&mut self, candidate: AttackBest) {
        if self
            .entries
            .iter()
            .any(|entry| entry.configuration == candidate.configuration)
        {
            return;
        }
        let position = self
            .entries
            .iter()
            .position(|entry| rank_order(&candidate, entry) == Ordering::Less);
        let position = position.unwrap_or(self.entries.len());
        if position < self.capacity {
            self.entries.insert(position, candidate);
            self.entries.truncate(self.capacity);
        }
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[AttackBest] {
        &self.entries
    }

    /// Move the ranked head and unpolished tail into the run envelope.
    pub(crate) fn into_head_tail(self) -> (Option<AttackBest>, Vec<AttackBest>) {
        let mut entries = self.into_entries().into_iter();
        (entries.next(), entries.collect())
    }

    pub(crate) fn into_entries(self) -> Vec<AttackBest> {
        self.entries
    }
}

/// Hold order: ranking descending, then absolute `(outer, start)` ascending.
fn rank_order(left: &AttackBest, right: &AttackBest) -> Ordering {
    let ranking = |entry: &AttackBest| entry.score.ranking().units();
    let index = |entry: &AttackBest| (entry.outer_index, entry.start_index);
    ranking(right)
        .cmp(&ranking(left))
        .then_with(|| index(left).cmp(&index(right)))
}

/// Final post-stage order: ranked polished entries, the partial entry, then
/// unpolished entries as given. Later duplicate complete keys are dropped
/// without refilling, so polished duplicates keep the smaller index.
#[allow(dead_code)] // Wired when 14.3b runs stages over the hold.
pub(crate) fn rerank_after_stages(
    mut polished: Vec<AttackBest>,
    partial: Option<AttackBest>,
    unpolished: Vec<AttackBest>,
) -> Vec<AttackBest> {
    polished.sort_by(rank_order);
    let mut ranked: Vec<AttackBest> = Vec::with_capacity(polished.len() + unpolished.len() + 1);
    for entry in polished.into_iter().chain(partial).chain(unpolished) {
        if !ranked
            .iter()
            .any(|kept| kept.configuration == entry.configuration)
        {
            ranked.push(entry);
        }
    }
    ranked
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{FixedScore, MeasureId, MeasuredScore, SlotConfiguration, TransformConfiguration};

    fn candidate(key: &str, ranking: i128, outer_index: u128, start_index: u128) -> AttackBest {
        AttackBest {
            configuration: TransformConfiguration::new(
                vec![SlotConfiguration::new("rotor", key, 'A', 'A')],
                vec![('A', 'B'), ('C', 'D')],
            ),
            mutable_plugboard: vec![('C', 'D')],
            plaintext: key.into(),
            score: MeasuredScore::higher_is_better(FixedScore::from_units(ranking)),
            measure: MeasureId::Ic,
            outer_index,
            start_index,
            incomplete: false,
            final_objective_ascent: true,
            neighborhood_exhausted: true,
            stages: Vec::new(),
        }
    }

    /// Compare every payload field and the plaintext allocation without cloning it.
    pub(crate) fn snapshot(entries: &[AttackBest]) -> Vec<(String, usize)> {
        entries
            .iter()
            .map(|entry| (format!("{entry:?}"), entry.plaintext.as_ptr() as usize))
            .collect()
    }

    pub(crate) fn tail_fixture() -> Vec<AttackBest> {
        let mut last = candidate("tail-last", -9, 7, 8);
        last.incomplete = true;
        last.final_objective_ascent = false;
        last.neighborhood_exhausted = false;
        vec![candidate("tail-first", -2, 4, 5), last]
    }

    #[test]
    fn hold_ownership_consumption_preserves_rank_payload_and_allocations() {
        for size in 0..=3 {
            let mut hold = AttackHold::new(3);
            for index in 0..size {
                hold.offer(candidate(&format!("key-{index}"), index, index as u128, 2));
            }
            let expected = snapshot(hold.entries());
            let (head, tail) = hold.into_head_tail();
            assert_eq!(head.is_some(), size > 0);
            assert_eq!(tail.len(), (size as usize).saturating_sub(1));
            let actual: Vec<_> = head.into_iter().chain(tail).collect();
            assert_eq!(snapshot(&actual), expected);
        }
    }

    #[test]
    fn empty_capacity_and_eviction() {
        let mut hold = AttackHold::new(2);
        assert!(hold.entries().is_empty());
        hold.offer(candidate("low", 1, 0, 0));
        assert_eq!(hold.entries().len(), 1);
        hold.offer(candidate("high", 3, 1, 0));
        assert_eq!(keys(&hold), ["high", "low"]);
        hold.offer(candidate("middle", 2, 2, 0));
        assert_eq!(keys(&hold), ["high", "middle"]);
        hold.offer(candidate("rejected", 0, 3, 0));
        assert_eq!(keys(&hold), ["high", "middle"]);
        let owned = hold.into_entries();
        assert_eq!(owned.len(), 2);
        assert_eq!(owned[0].plaintext(), "high");
        assert_eq!(owned[1].plaintext(), "middle");
    }

    fn keys(hold: &AttackHold) -> Vec<&str> {
        hold.entries().iter().map(AttackBest::plaintext).collect()
    }

    #[test]
    fn capacity_one_matches_strict_greater_earliest_winner() {
        let mut hold = AttackHold::new(1);
        hold.offer(candidate("first", 4, 0, 0));
        hold.offer(candidate("equal", 4, 0, 1));
        hold.offer(candidate("worse", 3, 1, 0));
        assert_eq!(keys(&hold), ["first"]);
        hold.offer(candidate("better", 5, 2, 0));
        hold.offer(candidate("later_equal", 5, 3, 0));
        assert_eq!(keys(&hold), ["better"]);
    }

    #[test]
    fn distinct_equal_scores_use_absolute_lexicographic_indices_not_arrival() {
        let mut hold = AttackHold::new(3);
        hold.offer(candidate("last", 7, u128::MAX, u128::MAX));
        hold.offer(candidate("middle", 7, 1, 0));
        hold.offer(candidate("first", 7, 0, u128::MAX));
        assert_eq!(keys(&hold), ["first", "middle", "last"]);
        hold.offer(candidate("earliest", 7, 0, 0));
        assert_eq!(keys(&hold), ["earliest", "first", "middle"]);
        hold.offer(candidate("too_late", 7, u128::MAX, 0));
        assert_eq!(keys(&hold), ["earliest", "first", "middle"]);
    }

    #[test]
    fn duplicate_keeps_entire_original_payload_without_eviction() {
        let mut hold = AttackHold::new(2);
        hold.offer(candidate("original", 5, 10, 20));
        hold.offer(candidate("other", 1, 11, 0));
        for ranking in [5, i128::MAX] {
            let mut duplicate = candidate("original", ranking, 0, 0);
            duplicate.plaintext = "replacement".into();
            duplicate.incomplete = true;
            duplicate.final_objective_ascent = false;
            duplicate.neighborhood_exhausted = false;
            // Identity comes from the complete configuration, not this metadata.
            duplicate.mutable_plugboard.clear();
            duplicate.measure = MeasureId::Entropy;
            hold.offer(duplicate);
        }
        assert_eq!(keys(&hold), ["original", "other"]);
        let kept = &hold.entries()[0];
        assert_eq!(kept.score().ranking().units(), 5);
        assert_eq!(kept.measure(), MeasureId::Ic);
        assert_eq!((kept.outer_index(), kept.start_index()), (10, 20));
        assert_eq!(kept.mutable_plugboard(), [('C', 'D')]);
        assert!(!kept.incomplete());
        assert!(kept.final_objective_ascent());
        assert!(kept.neighborhood_exhausted());
    }

    #[test]
    fn complete_key_distinguishes_every_slot_field_and_both_board_parts() {
        let mut hold = AttackHold::new(8);
        hold.offer(candidate("base", 0, 0, 0));
        let variants = [
            ("rotor", "other", 'A', 'A'),
            ("rotor", "base", 'B', 'A'),
            ("rotor", "base", 'A', 'B'),
            ("other_slot", "base", 'A', 'A'),
        ];
        for (index, (id, wheel, position, ring)) in variants.into_iter().enumerate() {
            let mut entry = candidate("base", 0, 1, index as u128);
            entry.configuration = TransformConfiguration::new(
                vec![SlotConfiguration::new(id, wheel, position, ring)],
                entry.configuration.plugboard().to_vec(),
            );
            hold.offer(entry);
        }
        for (index, board) in [
            vec![('A', 'E'), ('C', 'D')], // fixed pair differs
            vec![('A', 'B'), ('C', 'E')], // mutable pair differs
            vec![('A', 'B')],             // mutable pair absent
        ]
        .into_iter()
        .enumerate()
        {
            let mut entry = candidate("base", 0, 2, index as u128);
            entry.mutable_plugboard = board.iter().copied().skip(1).collect();
            entry.configuration =
                TransformConfiguration::new(entry.configuration.slots().to_vec(), board);
            hold.offer(entry);
        }
        assert_eq!(hold.entries().len(), 8);
        // Every canonical key is different, regardless of equal score/plaintext.
        for (index, entry) in hold.entries().iter().enumerate() {
            for earlier in &hold.entries()[..index] {
                assert_ne!(entry.configuration(), earlier.configuration());
            }
        }
    }

    #[test]
    fn ranking_not_measurement_controls_order() {
        let mut hold = AttackHold::new(2);
        let mut lower = candidate("large_measurement", 100, 0, 0);
        lower.score = lower
            .score
            .with_ranking_base(FixedScore::from_units(-200))
            .unwrap();
        let higher = candidate("small_measurement", 1, 1, 0);
        assert!(lower.score.measured().units() > higher.score.measured().units());
        hold.offer(lower);
        hold.offer(higher);
        assert_eq!(keys(&hold), ["small_measurement", "large_measurement"]);
    }

    #[test]
    fn signed_extremes_are_compared_without_negation_or_subtraction() {
        let mut hold = AttackHold::new(3);
        hold.offer(candidate("minimum", i128::MIN, 0, 0));
        hold.offer(candidate("maximum", i128::MAX, 1, 0));
        hold.offer(candidate("zero", 0, 2, 0));
        assert_eq!(keys(&hold), ["maximum", "zero", "minimum"]);
        hold.offer(candidate("negative", -1, 3, 0));
        assert_eq!(keys(&hold), ["maximum", "zero", "negative"]);
    }

    #[test]
    #[should_panic(expected = "attack hold capacity must be positive")]
    fn zero_capacity_violates_internal_precondition() {
        AttackHold::new(0);
    }

    fn rerank_keys(entries: &[AttackBest]) -> Vec<&str> {
        entries.iter().map(AttackBest::plaintext).collect()
    }

    #[test]
    fn hold_rerank_tiers_precede_numeric_score_and_measure() {
        let polished = candidate("polished", -50, 9, 9);
        let mut partial = candidate("partial", 40, 0, 0);
        partial.measure = MeasureId::Entropy;
        let unpolished = candidate("unpolished", 90, 0, 1);
        let ranked = rerank_after_stages(vec![polished], Some(partial), vec![unpolished]);
        assert_eq!(rerank_keys(&ranked), ["polished", "partial", "unpolished"]);
    }

    #[test]
    fn hold_rerank_polished_by_ranking_then_indices_unpolished_kept() {
        let polished = vec![
            candidate("low", 1, 0, 0),
            candidate("tie_late", 5, 2, 0),
            candidate("tie_early", 5, 1, 7),
            candidate("high", 8, 3, 0),
        ];
        let unpolished = vec![candidate("u_low", 1, 4, 0), candidate("u_high", 9, 5, 0)];
        let ranked = rerank_after_stages(polished, None, unpolished);
        assert_eq!(
            rerank_keys(&ranked),
            ["high", "tie_early", "tie_late", "low", "u_low", "u_high"]
        );
    }

    #[test]
    fn hold_rerank_without_stages_keeps_pre_stage_order() {
        let mut hold = AttackHold::new(4);
        for (index, ranking) in [3, 7, 7, 1].into_iter().enumerate() {
            hold.offer(candidate(
                &format!("key-{index}"),
                ranking,
                index as u128,
                0,
            ));
        }
        let expected = snapshot(hold.entries());
        let ranked = rerank_after_stages(hold.into_entries(), None, Vec::new());
        assert_eq!(snapshot(&ranked), expected);
    }

    #[test]
    fn hold_rerank_drops_later_duplicates_without_refill() {
        let polished = vec![candidate("dup", 4, 3, 0), candidate("dup", 4, 1, 0)];
        let mut partial = candidate("partial_dup", 0, 0, 0);
        partial.configuration = polished[0].configuration.clone();
        let unpolished = vec![
            candidate("other", 2, 5, 0),
            candidate("dup", 9, 0, 0),
            candidate("other", 1, 6, 0),
        ];
        let ranked = rerank_after_stages(polished, Some(partial), unpolished);
        assert_eq!(rerank_keys(&ranked), ["dup", "other"]);
        assert_eq!((ranked[0].outer_index, ranked[1].outer_index), (1, 5));
    }

    #[test]
    fn hold_rerank_empty_inputs() {
        assert!(rerank_after_stages(Vec::new(), None, Vec::new()).is_empty());
        let only_partial =
            rerank_after_stages(Vec::new(), Some(candidate("p", 0, 0, 0)), Vec::new());
        assert_eq!(rerank_keys(&only_partial), ["p"]);
    }

    #[test]
    fn hold_rerank_preserves_entry_stage_history() {
        let stage = |pass| crate::AttackStageResult {
            pass,
            measure: MeasureId::Ic,
            base_measure: None,
            score: None,
            evaluations_used: 3,
            completed: pass == "done",
        };
        let mut low = candidate("low", 1, 0, 0);
        low.stages = vec![stage("done")];
        let mut high = candidate("high", 2, 1, 0);
        high.stages = vec![stage("done"), stage("done")];
        let mut partial = candidate("partial", 0, 2, 0);
        partial.stages = vec![stage("cut")];
        let ranked = rerank_after_stages(vec![low, high], Some(partial), Vec::new());
        let history: Vec<Vec<_>> = ranked
            .iter()
            .map(|entry| entry.stages.iter().map(|s| (s.pass, s.completed)).collect())
            .collect();
        assert_eq!(
            history,
            [
                vec![("done", true), ("done", true)],
                vec![("done", true)],
                vec![("cut", false)],
            ]
        );
    }
}
