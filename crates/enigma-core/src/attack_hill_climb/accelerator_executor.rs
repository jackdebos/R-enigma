//! Accelerator scheduling; the parent module's coordinator is the only committer.
use super::*;
use crate::{AcceleratedClimb, AcceleratorError, ClimbAccelerator, ClimbJob};

struct PreparedOuter {
    index: u128,
    initial: Result<ResolvedConfiguration, Vec<crate::SearchDiagnostic>>,
    rows: Result<Vec<u8>, TrialEvaluationError>,
}

struct PreparedDispatch {
    blocks: Vec<OuterBlock>,
    keys: Vec<PreparedOuter>,
}

impl crate::AttackRequest {
    fn prepare_dispatch(
        &self,
        workers: usize,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        blocks: Vec<OuterBlock>,
    ) -> PreparedDispatch {
        let first = blocks.first().expect("nonempty dispatch");
        let len = blocks.iter().map(|b| b.len).sum();
        let mut keys: Vec<_> = plan
            .keys(OuterBlock {
                index: first.index,
                start: first.start,
                len,
            })
            .map(|(index, initial)| PreparedOuter {
                index,
                initial,
                rows: Ok(Vec::new()),
            })
            .collect();
        let chunk = keys.len().div_ceil(workers).max(1);
        std::thread::scope(|scope| {
            for keys in keys.chunks_mut(chunk) {
                scope.spawn(move || {
                    for key in keys {
                        if let Ok(initial) = &key.initial {
                            let evaluator = TrialEvaluator::new(
                                initial,
                                self.domain(),
                                self.text(),
                                Direction::Decrypt,
                                self.settings().final_measure(),
                                self.bound_resource(self.settings().final_measure()),
                            );
                            key.rows =
                                evaluator.byte_rows(self.settings().start().expect("direct start"));
                        }
                    }
                });
            }
        });
        PreparedDispatch { blocks, keys }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn drive_accelerated(
        &self,
        workers: usize,
        accelerator: &dyn ClimbAccelerator,
        plan: &crate::attack_blocks::OuterPlan<'_>,
        next_outer: u128,
        control: &mut AttackControl,
        requested: &mut impl FnMut() -> bool,
        commit: &mut impl FnMut(
            &mut AttackControl,
            OuterBlock,
            PhaseBlock,
        ) -> Result<(), crate::AttackRunError>,
    ) -> Result<DirectRunTermination, crate::AttackRunError> {
        // Like the serial driver, an exhausted range wins over cancellation.
        if next_outer == plan.selected_range().1 {
            return Ok(if plan.block_count() == 0 {
                DirectRunTermination::OuterSliceEnd
            } else {
                DirectRunTermination::Completed
            });
        }
        if control.poll_cancellation(requested()) {
            return Ok(DirectRunTermination::Cancelled);
        }
        let job = self.climb_job().expect("preflight checked");
        let block_keys = crate::attack_blocks::OUTER_BLOCK_KEYS as usize;
        let batch_blocks = (accelerator.preferred_max_keys() / block_keys).max(1);
        // A rendezvous channel bounds preparation to exactly one dispatch ahead.
        // The producer never calls user hooks or touches coordinator accounting.
        let (sender, receiver) = std::sync::mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let mut blocks = plan.blocks_from(next_outer);
                loop {
                    let batch: Vec<_> = blocks.by_ref().take(batch_blocks).collect();
                    if batch.is_empty() {
                        break;
                    }
                    if sender
                        .send(self.prepare_dispatch(workers, plan, batch))
                        .is_err()
                    {
                        break;
                    }
                }
            });
            // Drop the receiver before joining the producer, including on error,
            // cancellation or callback panic, so a waiting send cannot deadlock.
            let receiver = receiver;
            let mut termination = if plan.block_count() == 0 {
                DirectRunTermination::OuterSliceEnd
            } else {
                DirectRunTermination::Completed
            };
            for prepared in &receiver {
                if control.poll_cancellation(requested()) {
                    return Ok(DirectRunTermination::Cancelled);
                }
                let first = prepared.blocks[0];
                let mut rows = Vec::new();
                let mut count = 0;
                for key in &prepared.keys {
                    if key.initial.is_err() {
                        break;
                    }
                    let Ok(key_rows) = &key.rows else {
                        break;
                    };
                    rows.extend_from_slice(key_rows);
                    count += 1;
                }
                let results = if count == 0 {
                    Ok(Vec::new())
                } else {
                    accelerator.climb(&job, first.start, &rows)
                };
                let results = results.and_then(|results| {
                    if results.len() == count {
                        Ok(results)
                    } else {
                        Err(AcceleratorError(format!(
                            "result count mismatch: expected {count}, got {}",
                            results.len()
                        )))
                    }
                });
                let results = match results {
                    Ok(results) => results,
                    Err(error) => {
                        commit(
                            control,
                            first,
                            PhaseBlock::Direct(BlockOutcome {
                                outers: Vec::new(),
                                accounting: BlockAccounting::default(),
                                error: Some((
                                    first.start,
                                    BlockFailure::Climb(DirectRunError::Accelerator(error)),
                                )),
                            }),
                        )?;
                        unreachable!("failed block commit returns an error");
                    }
                };
                let mut results = results.into_iter();
                let mut keys = prepared.keys.into_iter();
                for block in prepared.blocks {
                    if block.start != first.start && control.poll_cancellation(requested()) {
                        return Ok(DirectRunTermination::Cancelled);
                    }
                    let block_keys: Vec<_> = keys.by_ref().take(block.len as usize).collect();
                    let mut payloads = std::collections::VecDeque::new();
                    let initials: Vec<_> = block_keys
                        .into_iter()
                        .map(|key| {
                            payloads.push_back(key.rows);
                            (key.index, key.initial)
                        })
                        .collect();
                    let outcome =
                        run_worker_block(initials.into_iter(), |initial, index, accounting| {
                            let rows = payloads.pop_front().expect("one payload per key").map_err(
                                |e| DirectRunError::Climb(DirectClimbError::Evaluation(e)),
                            )?;
                            let result = results.next().expect("one result per prepared key");
                            let climb = self
                                .rebuild_accelerated(&job, &initial, &rows, result, accounting)?;
                            Ok(DirectOuterOutcome {
                                initial,
                                outer_index: index,
                                start_index: 0,
                                climb,
                            })
                        });
                    let failed = outcome.error.is_some();
                    commit(control, block, PhaseBlock::Direct(outcome))?;
                    debug_assert!(!failed, "failed commit returns an error");
                    termination = DirectRunTermination::Completed;
                }
            }
            Ok(termination)
        })
    }

    fn rebuild_accelerated(
        &self,
        job: &ClimbJob<'_>,
        initial: &ResolvedConfiguration,
        rows: &[u8],
        result: AcceleratedClimb,
        accounting: &mut BlockAccounting,
    ) -> Result<ClimbOutcome, DirectRunError> {
        let symbols = &initial.topology().alphabet().symbols;
        let board: Vec<_> = result
            .board
            .iter()
            .map(|&(a, b)| {
                symbols
                    .get(a as usize)
                    .zip(symbols.get(b as usize))
                    .map(|(&a, &b)| (a, b))
                    .ok_or_else(|| {
                        DirectRunError::Accelerator(AcceleratorError(
                            "terminal board index outside alphabet".into(),
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        let evaluator = TrialEvaluator::new(
            initial,
            self.domain(),
            self.text(),
            Direction::Decrypt,
            self.settings().final_measure(),
            self.bound_resource(self.settings().final_measure()),
        )
        .with_byte_rows(&job.input, rows);
        let (plaintext, score) = evaluator.evaluate(&board).map_err(|error| {
            DirectRunError::Accelerator(AcceleratorError(format!(
                "terminal board re-scoring failed: {error}"
            )))
        })?;
        if score.ranking().units() != result.score_units {
            return Err(DirectRunError::Accelerator(AcceleratorError(format!(
                "terminal score mismatch: accelerator {}, CPU {}",
                result.score_units,
                score.ranking().units()
            ))));
        }
        accounting.used =
            accounting
                .used
                .checked_add(result.evaluations)
                .ok_or(DirectRunError::Counter(
                    CounterOverflow::EvaluationsAdmitted,
                ))?;
        accounting
            .control
            .merge_block(crate::attack_control::CounterSnapshot {
                evaluations_admitted: result.evaluations,
                evaluations_completed: result.evaluations,
                climbs_started: 1,
                climbs_completed: 1,
                outers_completed: 0,
            })
            .map_err(DirectRunError::Counter)?;
        Ok(ClimbOutcome {
            current: Some(ScoredBoard {
                board,
                plaintext,
                score,
            }),
            incomplete: false,
            cancelled: false,
            final_objective_ascent: result.final_objective_ascent,
            neighborhood_exhausted: true,
        })
    }

    pub(crate) fn reference_climbs(
        &self,
        job: &ClimbJob<'_>,
        first: u128,
        rows: &[u8],
    ) -> Result<Vec<AcceleratedClimb>, AcceleratorError> {
        let stride = job.text_length * job.alphabet_size;
        if stride == 0 || !rows.len().is_multiple_of(stride) {
            return Err(AcceleratorError("invalid reference row length".into()));
        }
        let plan = self.outer_plan();
        let block = OuterBlock {
            index: 0,
            start: first,
            len: (rows.len() / stride) as u128,
        };
        plan.keys(block)
            .zip(rows.chunks_exact(stride))
            .map(|((_, initial), rows)| {
                let initial = initial.map_err(|e| AcceleratorError(format!("{e:?}")))?;
                let (mut scoring, start) = self
                    .direct_scoring(&initial)
                    .map_err(|e| AcceleratorError(format!("{e:?}")))?;
                scoring.initial_evaluator =
                    scoring.initial_evaluator.with_byte_rows(&job.input, rows);
                scoring.final_evaluator = scoring.final_evaluator.with_byte_rows(&job.input, rows);
                let mut accounting = BlockAccounting::default();
                let climb = scoring
                    .climb_accounted(start, job.backtrack_pairs, &mut accounting)
                    .map_err(|e| AcceleratorError(format!("{e:?}")))?;
                let current = climb.current.expect("completed climb");
                let alphabet = initial.topology().alphabet();
                Ok(AcceleratedClimb {
                    board: current
                        .board
                        .iter()
                        .map(|&(a, b)| {
                            (
                                alphabet.index_of(a).unwrap() as u8,
                                alphabet.index_of(b).unwrap() as u8,
                            )
                        })
                        .collect(),
                    score_units: current.score.ranking().units(),
                    evaluations: accounting.used,
                    final_objective_ascent: climb.final_objective_ascent,
                })
            })
            .collect()
    }
}
