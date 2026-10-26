//! Deductive outer-block execution. Only stops allocate finishing-climb state.

use super::*;
use crate::bombe::Scratch;

/// Test-only runtime faults injected at one outer of `run_bombe_block`.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    /// The finishing climb of this crib rank fails with an evaluation error.
    Climb { outer: u128, rank: usize },
    /// Counting this outer as completed overflows.
    OuterCompleted { outer: u128 },
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
}

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
        let menu = plan.menu(rank);
        let window = &rows[position * width..(position + menu.edges.len()) * width];
        if !scratch.test(&menu, window, &plan.facts) {
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
                for (rank, &position) in bombe.positions.iter().enumerate() {
                    start_index = Some(rank as u128);
                    outcome
                        .accounting
                        .transition(AttackControl::record_bombe_setting)?;
                    // Over the admission budget this builds the menu for this use only.
                    let menu = bombe.menu(rank);
                    let window = &rows[position * width..(position + menu.edges.len()) * width];
                    if !scratch.test(&menu, window, &bombe.facts) {
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
                    #[cfg(test)]
                    if FAULT.get() == Some(Fault::Climb { outer: index, rank }) {
                        return Err(TrialEvaluationError::MissingResource(last).into());
                    }
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
                #[cfg(test)]
                if FAULT.get() == Some(Fault::OuterCompleted { outer: index }) {
                    return Err(DirectRunError::Counter(CounterOverflow::OutersCompleted));
                }
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
    use super::{Fault, FAULT};
    use crate::bombe::{shared_menu_bytes, Menus, MENU_BUDGET};
    use crate::{AttackCounterOverflow, AttackRequest, AttackRunCategory, Event};
    use serde_json::json;

    /// Admits `value` with the shared-menu budget overridden on this thread.
    fn admit(value: &serde_json::Value, budget: Option<usize>) -> AttackRequest {
        MENU_BUDGET.with(|cell| cell.set(budget));
        let request = AttackRequest::parse_json(&value.to_string());
        MENU_BUDGET.with(|cell| cell.set(None));
        request.unwrap()
    }

    fn shared_menus(request: &AttackRequest) -> Option<usize> {
        match &request.gate().bombe.as_ref().unwrap().menus {
            Menus::Shared(menus) => Some(menus.len()),
            Menus::OnDemand { .. } => None,
        }
    }

    #[test]
    fn admission_shares_menus_within_the_budget_and_defers_them_beyond_it() {
        let value = two_stop_request();
        // Two admitted positions, a two-letter crib, a four-symbol alphabet.
        let bytes = shared_menu_bytes(2, 2, 4).unwrap();
        assert_eq!(shared_menus(&admit(&value, None)), Some(2));
        assert_eq!(shared_menus(&admit(&value, Some(bytes))), Some(2));
        assert_eq!(shared_menus(&admit(&value, Some(bytes - 1))), None);
        assert_eq!(shared_menus(&admit(&value, Some(0))), None);
        // Long text and long crib: well past the default budget; overflow defers too.
        assert!(
            shared_menu_bytes(10_000, 2_000, 26).unwrap() > crate::bombe::MAX_SHARED_MENU_BYTES
        );
        assert_eq!(shared_menu_bytes(usize::MAX, 2, 4), None);
        // Admission diagnostics do not depend on the menu storage.
        let mut crash = value.clone();
        crash["job"]["attack"]["crib"]["position"] = json!(2);
        for budget in [None, Some(0)] {
            MENU_BUDGET.with(|cell| cell.set(budget));
            let errors = AttackRequest::parse_json(&crash.to_string()).unwrap_err();
            MENU_BUDGET.with(|cell| cell.set(None));
            assert_eq!(
                (errors[0].code(), errors[0].location(), errors[0].message()),
                (
                    "invalid_search_space",
                    "/job/attack/crib/position",
                    "crib crashes at text index 3"
                )
            );
        }
    }

    #[test]
    fn on_demand_menus_give_identical_results_checkpoints_and_stages() {
        let mut value = two_stop_request();
        // Four variable rotor dimensions give 256 keys over two blocks, and a stage
        // re-derives each stop's deductions through `bombe_context`.
        let definition = &mut value["machine"]["definition"]["value"];
        for i in 1..4 {
            definition["slots"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"}));
        }
        let job = &mut value["job"];
        job["configuration"]["slots"] = json!([{"id":"u","position":"A","ring":"A"}]);
        job["space"]["slots"] = json!(["r", "r1", "r2", "r3"]
            .map(|id| json!({"id":id,"positions":["A","B","C","D"],"rings":["A"]})));
        // Admitted positions 0, 1 and 2 carry different letter pairs, so menus differ.
        job["text"] = json!("BBDDAA");
        job["passes"] = json!(["bombe", "measure"]);
        job["attack"]["hold"] = json!(10);
        job["attack"]["measure"] = json!({"measure":"ic"});
        let shared = admit(&value, None);
        let deferred = admit(&value, Some(0));
        assert_eq!(shared_menus(&shared), Some(3));
        assert_eq!(shared_menus(&deferred), None);
        let wire = |request: &AttackRequest, threads| {
            let options = crate::ExecutionOptions::with_threads(threads).unwrap();
            let result = request.run_with(options, |_| {}, || false).unwrap();
            serde_json::to_value(Event::result(&result, 0)).unwrap()
        };
        let expected = wire(&shared, 1);
        assert!(
            expected["crib"]["stops"]
                .as_str()
                .unwrap()
                .parse::<u32>()
                .unwrap()
                > 1
        );
        assert_eq!(expected["crib"]["settings"], "768");
        assert_eq!(expected["hold"].as_array().unwrap().len(), 10);
        for threads in [1, 3] {
            assert_eq!(wire(&shared, threads), expected);
            assert_eq!(wire(&deferred, threads), expected);
        }
        let identity = crate::checkpoint_identity(&value.to_string(), &Default::default()).unwrap();
        let mut saved = None;
        let polls = std::cell::Cell::new(0);
        deferred
            .run_with_checkpoints(
                crate::ExecutionOptions::serial(),
                |_| {},
                || {
                    polls.set(polls.get() + 1);
                    polls.get() > 1
                },
                |snapshot| saved = Some(snapshot.record(identity, 0).unwrap()),
            )
            .unwrap();
        let mut record = saved.unwrap();
        let record = crate::CheckpointRecord::parse_json(&record.seal_json().unwrap()).unwrap();
        let resumed = deferred
            .resume(&record)
            .unwrap()
            .run_with(crate::ExecutionOptions::serial(), |_| {}, || false)
            .unwrap();
        assert_eq!(
            serde_json::to_value(Event::result(&resumed, 0)).unwrap(),
            expected
        );
    }

    /// One outer whose crib "AA" stops at both admitted positions 0 and 1.
    fn two_stop_request() -> serde_json::Value {
        json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
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
                "final_measure":"ic","switch_pairs":0,"backtrack_pairs":0}}})
    }

    fn run_with_fault(fault: Fault) -> (crate::AttackRunError, usize) {
        let request = AttackRequest::parse_json(&two_stop_request().to_string()).unwrap();
        let mut checkpoints = 0;
        FAULT.with(|cell| cell.set(Some(fault)));
        let run = request.run_with_checkpoints(
            crate::ExecutionOptions::serial(),
            |_| {},
            || false,
            |_| checkpoints += 1,
        );
        FAULT.with(|cell| cell.set(None));
        (run.unwrap_err(), checkpoints)
    }

    #[test]
    fn runtime_error_keeps_the_failing_outers_earlier_stops_without_a_checkpoint() {
        let request = AttackRequest::parse_json(&two_stop_request().to_string()).unwrap();
        let clean = request.run(|_| {}, || false).unwrap();
        let first = clean
            .hold()
            .map(|entry| entry.best())
            .find(|best| best.crib_position() == Some(0))
            .expect("stop at position 0");

        let (error, checkpoints) = run_with_fault(Fault::Climb { outer: 0, rank: 1 });
        assert_eq!(error.run_source().category(), AttackRunCategory::Evaluation);
        assert_eq!(
            (error.outer_index(), error.start_index()),
            (Some(0), Some(1))
        );
        let held: Vec<_> = error.hold().unwrap().map(|entry| entry.best()).collect();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].crib_position(), Some(0));
        assert_eq!(held[0].start_index(), 0);
        assert_eq!(held[0].plaintext(), first.plaintext());
        assert_eq!(held[0].configuration(), first.configuration());
        let counters = error.counters();
        assert_eq!((counters.bombe_settings(), counters.bombe_stops()), (2, 2));
        assert_eq!(
            (counters.climbs_started(), counters.outers_completed()),
            (1, 0)
        );
        let crib = error.crib().unwrap();
        assert_eq!((crib.settings(), crib.stops()), (2, 2));
        assert_eq!(checkpoints, 0);
    }

    #[test]
    fn outer_completion_overflow_discards_that_outers_stops() {
        let (error, checkpoints) = run_with_fault(Fault::OuterCompleted { outer: 0 });
        assert_eq!(
            error.run_source().overflow(),
            Some(AttackCounterOverflow::OutersCompleted)
        );
        assert_eq!((error.outer_index(), error.start_index()), (Some(0), None));
        assert!(error.best().unwrap().is_none());
        assert_eq!(error.hold().unwrap().count(), 0);
        let counters = error.counters();
        assert_eq!((counters.bombe_settings(), counters.bombe_stops()), (2, 2));
        assert_eq!(
            (counters.climbs_started(), counters.outers_completed()),
            (2, 0)
        );
        assert_eq!(checkpoints, 0);
    }

    #[test]
    fn rows_cover_only_the_admitted_prefix_once_and_finishing_rows_are_shared() {
        let mut value = two_stop_request();
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
