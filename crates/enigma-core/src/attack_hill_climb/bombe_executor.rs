//! Deductive outer-block execution. Only stops allocate finishing-climb state.

use super::*;
use crate::bombe::Scratch;

impl crate::AttackRequest {
    pub(super) fn bombe_summary(
        &self,
        counters: crate::AttackProgress,
    ) -> Option<crate::AttackCribResult> {
        self.gate()
            .bombe
            .as_ref()
            .map(|plan| crate::AttackCribResult {
                text: self.settings().crib().expect("bombe crib").0.to_owned(),
                positions: plan.positions.clone(),
                settings: counters.bombe_settings(),
                stops: counters.bombe_stops(),
            })
    }

    fn bombe_initial(
        &self,
        initial: &ResolvedConfiguration,
        domain: &AttackPlugboardDomain,
    ) -> Result<ResolvedConfiguration, TrialEvaluationError> {
        let slots = initial
            .topology()
            .slots()
            .iter()
            .map(|slot| {
                crate::SlotConfiguration::new(slot.id(), slot.wheel(), slot.position(), slot.ring())
            })
            .collect();
        crate::TransformConfiguration::new(slots, domain.fixed_pairs().to_vec())
            .resolve(self.definition())
            .map_err(|_| TrialEvaluationError::Invariant("deduced fixed key failed to resolve"))
    }

    /// Reconstruct the stop's domain for checkpoint validation and chained stages.
    /// The entry's position/index must refer to the same admitted menu.
    pub(super) fn bombe_context(
        &self,
        initial: &ResolvedConfiguration,
        position: usize,
        start_index: u128,
    ) -> Result<(ResolvedConfiguration, AttackPlugboardDomain), TrialEvaluationError> {
        let plan = self
            .gate()
            .bombe
            .as_ref()
            .ok_or(TrialEvaluationError::Invariant("missing bombe plan"))?;
        let rank = usize::try_from(start_index)
            .map_err(|_| TrialEvaluationError::Invariant("invalid crib index"))?;
        if plan.positions.get(rank) != Some(&position) {
            return Err(TrialEvaluationError::Invariant(
                "crib position does not match start index",
            ));
        }
        let mut rows = Vec::new();
        initial
            .clone()
            .into_engine()
            .map_err(TrialEvaluationError::Model)?
            .scrambler_rows(plan.row_length, Direction::Decrypt, &mut rows)
            .map_err(TrialEvaluationError::Model)?;
        let mut scratch = Scratch::default();
        let width = self.definition().alphabet().len();
        let menu = &plan.menus[rank];
        let window = &rows[position * width..(position + menu.edges.len()) * width];
        if !scratch.test(menu, window, &plan.facts) {
            return Err(TrialEvaluationError::Invariant(
                "saved crib setting is not a stop",
            ));
        }
        let domain = self
            .domain()
            .with_deductions(&scratch.deduced_pairs, &scratch.deduced_self);
        Ok((self.bombe_initial(initial, &domain)?, domain))
    }

    pub(super) fn run_bombe_block(
        &self,
        preparation: &RunPreparation<'_>,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        block: OuterBlock,
    ) -> BlockOutcome<Vec<crate::AttackBest>, DirectRunError> {
        let bombe = self.gate().bombe.as_ref().expect("admitted bombe");
        let mut outcome = BlockOutcome {
            outers: Vec::new(),
            error: None,
            accounting: BlockAccounting::default(),
        };
        outcome.accounting.control.enable_bombe();
        let mut workspace = preparation.bombe.borrow_mut();
        let (scratch, rows) = &mut *workspace;
        for (index, initial) in plan.keys(block) {
            let mut held = crate::attack_hold::AttackHold::new(self.settings().hold_capacity());
            let mut start_index = None;
            let run = (|| {
                let initial = initial.map_err(DirectRunError::Resolution)?;
                rows.clear();
                initial
                    .clone()
                    .into_engine()
                    .map_err(TrialEvaluationError::Model)?
                    .scrambler_rows(bombe.row_length, Direction::Decrypt, rows)
                    .map_err(TrialEvaluationError::Model)?;
                let width = self.definition().alphabet().len();
                for (rank, (&position, menu)) in
                    bombe.positions.iter().zip(&bombe.menus).enumerate()
                {
                    start_index = Some(rank as u128);
                    outcome
                        .accounting
                        .transition(AttackControl::record_bombe_setting)?;
                    let window = &rows[position * width..(position + menu.edges.len()) * width];
                    if !scratch.test(menu, window, &bombe.facts) {
                        continue;
                    }
                    outcome
                        .accounting
                        .transition(AttackControl::record_bombe_stop)?;
                    let domain = self
                        .domain()
                        .with_deductions(&scratch.deduced_pairs, &scratch.deduced_self);
                    let fixed_initial = self.bombe_initial(&initial, &domain)?;
                    let first = self.settings().initial_measure();
                    let last = self.settings().final_measure();
                    let scoring = BoundClimbScoring::new(
                        &fixed_initial,
                        &domain,
                        self.text(),
                        (first, self.bound_resource(first)),
                        (last, self.bound_resource(last)),
                        self.settings().switch_pairs(),
                    )
                    .with_preparation(preparation, index);
                    let climb = scoring.climb_accounted(
                        Vec::new(),
                        self.settings().backtrack_pairs(),
                        &mut outcome.accounting,
                    )?;
                    let raw = DirectOuterOutcome {
                        initial: fixed_initial,
                        outer_index: index,
                        start_index: rank as u128,
                        climb,
                    };
                    let mut best = raw
                        .project(&domain, last)
                        .map_err(DirectRunError::Projection)?;
                    best.crib_position = Some(position);
                    held.offer(best);
                }
                start_index = None;
                Ok::<_, DirectRunError>(())
            })();
            let run = run.and_then(|()| {
                outcome
                    .accounting
                    .transition(AttackControl::record_outer_completed)
                    .map_err(DirectRunError::from)
            });
            // On evaluation failure retain earlier eligible stops; on outer-completion
            // overflow none of that outer's offers may be accepted.
            let outer_overflow = matches!(
                &run,
                Err(DirectRunError::Counter(CounterOverflow::OutersCompleted))
            );
            if !outer_overflow {
                outcome.outers.push(held.into_entries());
            }
            if let Err(error) = run {
                outcome.error = Some((
                    index,
                    BlockFailure::Climb(DirectRunError::Bombe {
                        start_index,
                        source: Box::new(error),
                    }),
                ));
                break;
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use crate::{AttackRequest, Event};
    use serde_json::json;

    #[test]
    fn rows_cover_only_the_admitted_prefix_once_and_finishing_rows_are_shared() {
        let mut value = json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
            "alphabet":["A","B","C","D"],
            "wheels":[{"name":"u","wiring":["B","A","D","C"],"turnovers":[]},
                      {"name":"r","wiring":["A","B","C","D"],"turnovers":[]}],
            "slots":[{"id":"u","role":"reflector","movement":"fixed","wheel":"u"},
                     {"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}}}},"job":{"kind":"search",
            "configuration":{"slots":[{"id":"u","position":"A","ring":"A"},
                {"id":"r","position":"A","ring":"A"}],"plugboard":[]},
            "text":"BBBAAA","passes":["bombe"],"measures":["ic"],
            "space":{"plugboard":{"kind":"attack","symbols":["A","B","C","D"],"max_pairs":0}},
            "attack":{"kind":"bombe","crib":{"text":"AA"},"initial_measure":"ic",
                "final_measure":"ic","switch_pairs":0,"backtrack_pairs":0}}});
        for (crib, expected_lengths, stops) in [("AA", vec![3, 6], 2), ("AC", vec![4], 0)] {
            value["job"]["attack"]["crib"]["text"] = json!(crib);
            crate::engine::ROW_LENGTHS.with(|lengths| *lengths.borrow_mut() = Some(Vec::new()));
            let request = AttackRequest::parse_json(&value.to_string()).unwrap();
            let result = request.run(|_| {}, || false).unwrap();
            let lengths = crate::engine::ROW_LENGTHS.with(|lengths| lengths.borrow_mut().take());
            assert_eq!(lengths.unwrap(), expected_lengths);
            assert_eq!(result.counters().bombe_stops(), stops);
            let wire = serde_json::to_value(Event::result(&result, 0)).unwrap();
            assert_eq!(wire["crib"]["stops"], stops.to_string());
        }
    }
}
