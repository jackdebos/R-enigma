//! UKW-D: independent wiring starts inside each outer, sharing ordinary HC accounting.
use super::*;

impl crate::AttackRequest {
    fn wiring_key(
        &self,
        initial: &ResolvedConfiguration,
        pairs: Vec<(char, char)>,
    ) -> Result<ResolvedConfiguration, TrialEvaluationError> {
        let slots = initial
            .key_slots()
            .iter()
            .map(|slot| {
                if slot.pairs().is_some() {
                    slot.clone().with_pairs(pairs.clone())
                } else {
                    slot.clone()
                }
            })
            .collect();
        crate::TransformConfiguration::new(slots, self.domain().fixed_pairs().to_vec())
            .resolve(self.definition())
            .map_err(|_| TrialEvaluationError::Invariant("wiring trial failed to resolve"))
    }

    pub(super) fn run_reflector_block(
        &self,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        block: OuterBlock,
        starts: u64,
    ) -> BlockOutcome<Vec<crate::AttackBest>, DirectRunError> {
        let mut outcome = BlockOutcome {
            outers: Vec::new(),
            error: None,
            accounting: BlockAccounting::default(),
        };
        for (index, initial) in plan.keys(block) {
            let initial = match initial {
                Ok(initial) => initial,
                Err(error) => {
                    outcome.error = Some((index, BlockFailure::Resolution(error)));
                    break;
                }
            };
            // Bound memory by the ordinary hold capacity, not reflector_starts.
            // Offer every eligible start through the existing canonical insertion.
            let mut hold = crate::attack_hold::AttackHold::new(self.settings().hold_capacity());
            let result = (0..starts).try_for_each(|start| {
                self.reflector_start(&initial, index, start, &mut outcome.accounting)
                    .map_err(DirectRunError::from)
                    .and_then(|candidate| {
                        candidate
                            .project(self.domain(), self.settings().final_measure())
                            .map_err(DirectRunError::Projection)
                    })
                    .map(|candidate| hold.offer(candidate))
                    .map_err(|source| DirectRunError::Reflector {
                        start_index: u128::from(start),
                        source: Box::new(source),
                    })
            });
            if let Err(source) = result {
                outcome.outers.push(hold.into_entries());
                outcome.error = Some((index, BlockFailure::Climb(source)));
                break;
            }
            if let Err(error) = outcome
                .accounting
                .transition(AttackControl::record_outer_completed)
            {
                // An unaccepted outer must not leak offers on completion overflow.
                outcome.error = Some((index, BlockFailure::Counter(error)));
                break;
            }
            outcome.outers.push(hold.into_entries());
        }
        outcome
    }

    fn reflector_start(
        &self,
        outer: &ResolvedConfiguration,
        index: u128,
        start: u64,
        accounting: &mut BlockAccounting,
    ) -> Result<DirectOuterOutcome, ObservedClimbError> {
        let slot = outer
            .key_slots()
            .iter()
            .find(|s| s.pairs().is_some())
            .expect("rewirable slot");
        let fixed = self
            .definition()
            .rewirable_fixed_pairs(slot.wheel())
            .expect("rewirable wheel");
        let mut initial = self.wiring_key(
            outer,
            crate::rewirable::start(self.definition().alphabet(), fixed, start),
        )?;
        let mut saved = None;
        let mut final_ascent = false;
        loop {
            // Deliberately no RunPreparation: its outer-index cache cannot identify
            // wiring changes. Each committed wiring gets new board-phase rows.
            let (scoring, board) = self
                .direct_scoring(&initial)
                .map_err(|_| TrialEvaluationError::Invariant("missing direct wiring start"))?;
            let state = match saved.take() {
                None => {
                    let state = scoring.start(board, accounting)?;
                    accounting.transition(AttackControl::record_climb_started)?;
                    state
                }
                Some((current, final_phase, known_final)) => ScoringState {
                    context: &scoring,
                    current,
                    final_phase,
                    known_final,
                },
            };
            let (state, exhausted, ascent) =
                scoring.ascend_board(state, self.settings().backtrack_pairs(), accounting)?;
            debug_assert!(exhausted, "outer blocks never poll cancellation");
            final_ascent |= ascent;
            let final_phase = state.final_phase;
            let known_final = state.known_final;
            let mut current = state.current;
            let identical = scoring.identical;
            let objective = if final_phase {
                self.settings().final_measure()
            } else {
                self.settings().initial_measure()
            };
            let mut moved = false;
            loop {
                let pairs = initial
                    .key_slots()
                    .iter()
                    .find_map(|s| s.pairs())
                    .expect("wiring key");
                let mut best = None;
                let mut ranking = current.score.ranking();
                for pairs in crate::rewirable::trials(pairs) {
                    let trial = self.wiring_key(&initial, pairs)?;
                    let evaluator = TrialEvaluator::new(
                        &trial,
                        self.domain(),
                        self.text(),
                        Direction::Decrypt,
                        objective,
                        self.bound_resource(objective),
                    );
                    accounting.admit()?;
                    let (plaintext, score) = evaluator.evaluate_fresh(&current.board)?;
                    accounting.complete()?;
                    if score.ranking().units() > ranking.units() {
                        ranking = score.ranking();
                        best = Some((trial, plaintext, score));
                    }
                }
                final_ascent |= final_phase || identical;
                match best {
                    Some((key, plaintext, score)) => {
                        initial = key;
                        current.plaintext = plaintext;
                        current.score = score;
                        moved = true;
                    }
                    None => break,
                }
            }
            if moved {
                saved = Some((current, final_phase, known_final));
            } else {
                if !known_final {
                    let objective = self.settings().final_measure();
                    let evaluator = TrialEvaluator::new(
                        &initial,
                        self.domain(),
                        self.text(),
                        Direction::Decrypt,
                        objective,
                        self.bound_resource(objective),
                    );
                    accounting.admit()?;
                    let (plaintext, score) = evaluator.evaluate_fresh(&current.board)?;
                    accounting.complete()?;
                    current.plaintext = plaintext;
                    current.score = score;
                }
                accounting.transition(AttackControl::record_climb_completed)?;
                return Ok(DirectOuterOutcome {
                    initial,
                    outer_index: index,
                    start_index: u128::from(start),
                    climb: ClimbOutcome {
                        current: Some(current),
                        incomplete: false,
                        cancelled: false,
                        final_objective_ascent: final_ascent,
                        neighborhood_exhausted: true,
                    },
                });
            }
        }
    }
}
