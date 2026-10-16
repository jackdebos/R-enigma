//! Private constrained steepest-ascent reswapping stage (search-passes §9.3, §9.5).
// The runner wiring arrives in Task 13.3b; until then only unit tests reach it.
#![cfg_attr(not(test), allow(dead_code))]

use crate::attack_control::{AttackControl, CounterObserver};
use crate::attack_hill_climb::{
    EvaluationAccounting, ObservedAccounting, ObservedClimbError, ScoredBoard,
};
use crate::attack_result::{AttackRunErrorData, RunPayload};
use crate::{Alphabet, AttackPlugboardDomain, AttackTermination, MeasureId, MeasuredScore};

impl From<ObservedClimbError> for RunPayload {
    fn from(error: ObservedClimbError) -> Self {
        match error {
            ObservedClimbError::Counter(source) => Self::Counter(source),
            ObservedClimbError::Evaluation(source) => Self::Evaluation(source),
        }
    }
}

fn order(alphabet: &Alphabet, symbol: char) -> usize {
    alphabet.index_of(symbol).expect("validated symbol")
}

/// Orient pairs and sort them by alphabet index, as best projection does.
fn normalize(alphabet: &Alphabet, board: &mut [(char, char)]) {
    for (left, right) in board.iter_mut() {
        if order(alphabet, *left) > order(alphabet, *right) {
            std::mem::swap(left, right);
        }
    }
    board.sort_by_key(|&(a, b)| (order(alphabet, a), order(alphabet, b)));
}

struct Reswapper<'s, 'a, O, C, E> {
    alphabet: &'s Alphabet,
    domain: &'s AttackPlugboardDomain,
    accounting: &'s mut ObservedAccounting<'a, O>,
    cancel_requested: C,
    evaluate: E,
}

impl<O, C, E> Reswapper<'_, '_, O, C, E>
where
    O: CounterObserver,
    C: FnMut() -> bool,
    E: FnMut(&[(char, char)]) -> Result<(String, MeasuredScore), RunPayload>,
{
    fn cancelled(&mut self) -> bool {
        let requested = (self.cancel_requested)();
        self.accounting.control.poll_cancellation(requested)
    }

    /// Poll, admit one shared unit, evaluate and record completion.
    fn trial(
        &mut self,
        board: &[(char, char)],
    ) -> Result<Result<ScoredBoard, AttackTermination>, RunPayload> {
        if self.cancelled() {
            return Ok(Err(AttackTermination::Cancelled));
        }
        if !self.accounting.admit(0)? {
            return Ok(Err(AttackTermination::EvaluationBudget));
        }
        let (plaintext, score) = (self.evaluate)(board)?;
        let record = AttackControl::record_evaluation_completed;
        self.accounting.transition(record)?;
        let board = board.to_vec();
        Ok(Ok(ScoredBoard {
            board,
            plaintext,
            score,
        }))
    }

    /// `Ok(None)` is completion; an interrupted scan discards its provisional winner.
    fn run(
        &mut self,
        start: &[(char, char)],
        committed: &mut Option<ScoredBoard>,
    ) -> Result<Option<AttackTermination>, RunPayload> {
        let mut current = match self.trial(start)? {
            Ok(initial) => initial,
            Err(stop) => return Ok(Some(stop)),
        };
        loop {
            normalize(self.alphabet, &mut current.board);
            let (pairs, mut bar) = (current.board.clone(), current.score);
            *committed = Some(current);
            let mut winner = None;
            for (index, &(i, k)) in pairs.iter().enumerate() {
                let mut rest = pairs.clone();
                rest.remove(index);
                // Fixed endpoints are never domain symbols; free means unpaired.
                let mut free: Vec<char> = (self.domain.symbols().iter().copied())
                    .filter(|&x| rest.iter().all(|&(a, b)| a != x && b != x))
                    .collect();
                free.sort_by_key(|&x| order(self.alphabet, x));
                for x in free {
                    for end in [i, k] {
                        let mut board = rest.clone();
                        if x != end {
                            board.push((end, x));
                        }
                        let trial = match self.trial(&board)? {
                            Ok(trial) => trial,
                            Err(stop) => return Ok(Some(stop)),
                        };
                        if trial.score.ranking().units() > bar.ranking().units() {
                            bar = trial.score;
                            winner = Some(trial);
                        }
                    }
                }
            }
            let Some(winner) = winner else {
                return Ok(None);
            };
            if self.cancelled() {
                return Ok(Some(AttackTermination::Cancelled));
            }
            current = winner;
        }
    }
}

/// Runs one reswapping stage on the committed best; history follows first admission.
pub(crate) fn reswapping_stage(
    mut result: crate::AttackResult,
    measure: MeasureId,
    alphabet: &Alphabet,
    domain: &AttackPlugboardDomain,
    accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
    cancel_requested: impl FnMut() -> bool,
    evaluate: impl FnMut(&[(char, char)]) -> Result<(String, MeasuredScore), RunPayload>,
) -> Result<crate::AttackResult, crate::AttackRunError> {
    let before = accounting.allowance.used;
    let best = result.best.as_mut().expect("completed run has best");
    let mut committed = None;
    let outcome = Reswapper {
        alphabet,
        domain,
        accounting: &mut *accounting,
        cancel_requested,
        evaluate,
    }
    .run(&best.mutable_plugboard.clone(), &mut committed);
    if accounting.allowance.used == before {
        result.termination = outcome.ok().flatten().expect("unadmitted stage stopped");
        return Ok(result);
    }
    if let Some(key) = &committed {
        let mut pairs = [domain.fixed_pairs(), &key.board].concat();
        normalize(alphabet, &mut pairs);
        let slots = best.configuration.slots().to_vec();
        best.configuration = crate::TransformConfiguration::new(slots, pairs);
        best.mutable_plugboard.clone_from(&key.board);
        best.plaintext.clone_from(&key.plaintext);
        (best.score, best.measure) = (key.score, measure);
    }
    result.evaluations_used = accounting.allowance.used;
    result.counters = crate::AttackProgress(accounting.control.snapshot());
    result.stages.push(crate::AttackStageResult {
        pass: "reswapping",
        measure,
        base_measure: None,
        score: committed.map(|key| key.score),
        evaluations_used: accounting.allowance.used - before,
        completed: matches!(outcome, Ok(None)),
    });
    match outcome {
        Ok(stop) => {
            result.termination = stop.unwrap_or(result.termination);
            Ok(result)
        }
        Err(source) => {
            accounting.control.notify(accounting.observer);
            Err(crate::AttackRunError::new(AttackRunErrorData {
                outer_index: result.best.as_ref().map(|best| best.outer_index),
                start_index: result.best.as_ref().map(|best| best.start_index),
                source: crate::AttackRunSource(source),
                stages: result.stages,
                evaluations_used: result.evaluations_used,
                counters: result.counters,
                best: Ok(result.best),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_control::CounterSnapshot;
    use crate::attack_hill_climb::EvaluationAllowance;
    use crate::{AttackBest, AttackResult, FixedScore};
    use std::cell::{Cell, RefCell};
    use AttackTermination::{Cancelled, Completed, EvaluationBudget};

    struct Recorder;
    impl CounterObserver for Recorder {
        fn observe(&mut self, _: CounterSnapshot) {}
    }

    const N: usize = usize::MAX;
    const AB: &[(char, char)] = &[('A', 'B')];
    const AB_CD: &[(char, char)] = &[('A', 'B'), ('C', 'D')];
    const CD: &[(char, char)] = &[('C', 'D')];
    type Run = (Result<AttackResult, crate::AttackRunError>, Vec<String>);
    type Pairs<'a> = &'a [(char, char)];

    fn score(units: i128) -> MeasuredScore {
        MeasuredScore::higher_is_better(FixedScore::from_units(units))
    }

    /// Alphabet A–F, fixed F–E, symbols D,A,C,B in source order; prior use 5, prior
    /// score -100. `stop` is [budget, cancel after, fail at]; boards are logged raw
    /// and scored by their sorted symbols (default 0).
    fn run(start: &[(char, char)], scores: &[(&str, i128)], stop: [usize; 3]) -> Run {
        let alphabet = Alphabet::new("ABCDEF".chars().collect()).unwrap();
        let json = r#"{"kind":"attack","symbols":["D","A","C","B"],"max_pairs":3}"#;
        let domain = AttackPlugboardDomain::parse_json(&alphabet, &[('F', 'E')], json).unwrap();
        let pairs = [start, &[('E', 'F')]].concat();
        let result = AttackResult {
            termination: Completed,
            counters: crate::AttackProgress(CounterSnapshot::default()),
            evaluations_used: 5,
            best: Some(AttackBest {
                configuration: crate::TransformConfiguration::new(Vec::new(), pairs),
                mutable_plugboard: start.to_vec(),
                plaintext: "old".into(),
                score: score(-100),
                measure: MeasureId::Ic,
                outer_index: 1,
                start_index: 2,
                incomplete: false,
                final_objective_ascent: false,
                neighborhood_exhausted: false,
            }),
            stages: Vec::new(),
        };
        let (count, log) = (Cell::new(0), RefCell::new(Vec::new()));
        // Capped so a non-terminating scan fails fast instead of exhausting memory.
        let limit = (stop[0] as u64).min(10_000).saturating_add(5);
        let mut allowance = EvaluationAllowance { used: 5, limit };
        let mut control = AttackControl::default();
        let accounting = &mut ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut Recorder,
        };
        let cancel = || count.get() >= stop[1];
        let evaluate = |board: &[(char, char)]| {
            count.set(count.get() + 1);
            let raw: String = board.iter().flat_map(|&(a, b)| [a, b]).collect();
            let mut key: Vec<char> = raw.chars().collect();
            log.borrow_mut().push(raw);
            if count.get() == stop[2] {
                return Err(RunPayload::Invariant("synthetic trial failure"));
            }
            key.sort_unstable();
            let key: String = key.into_iter().collect();
            let units = scores.iter().find(|(k, _)| *k == key).map_or(0, |e| e.1);
            Ok((format!("p{key}"), score(units)))
        };
        let measure = MeasureId::SinkovTrigram;
        let outcome = reswapping_stage(
            result, measure, &alphabet, &domain, accounting, cancel, evaluate,
        );
        (outcome, log.into_inner())
    }

    fn ok(run: Run) -> (AttackResult, Vec<String>) {
        (run.0.unwrap(), run.1)
    }

    /// Termination and the single history entry as (score, evaluations, completed).
    fn summary(result: &AttackResult) -> (AttackTermination, Option<i128>, u64, bool) {
        let (t, s) = (result.termination, &result.stages[0]);
        assert_eq!(
            (s.pass(), s.measure()),
            ("reswapping", MeasureId::SinkovTrigram)
        );
        let units = s.score().map(|s| s.ranking().units());
        (t, units, s.evaluations_used(), s.completed())
    }

    /// Committed (mutable board, ranking, plaintext, complete configuration board).
    fn best(b: &AttackBest) -> (Pairs<'_>, i128, &str, Pairs<'_>) {
        let (board, units) = (&b.mutable_plugboard, b.score.ranking().units());
        (board, units, &b.plaintext, b.configuration.plugboard())
    }

    #[test]
    fn scan_visits_free_symbols_in_alphabet_order_and_counts_every_trial() {
        let (result, log) = ok(run(&[('B', 'A')], &[], [N, N, N]));
        assert_eq!(log, ["BA", "", "BA", "AB", "", "AC", "BC", "AD", "BD"]);
        assert_eq!(summary(&result), (Completed, Some(0), 9, true));
        assert_eq!(result.evaluations_used, 14);
        assert_eq!(result.counters.evaluations_completed(), 9);
        let expected = (AB, 0, "pAB", &[('A', 'B'), ('E', 'F')][..]);
        assert_eq!(best(result.best.as_ref().unwrap()), expected);
        assert_eq!(result.best.unwrap().measure, MeasureId::SinkovTrigram);
    }

    #[test]
    fn first_strict_winner_commits_and_restoring_it_never_wins() {
        let (result, log) = ok(run(AB, &[("AC", 5), ("BC", 5)], [N, N, N]));
        assert_eq!(log[9..], ["", "CA", "AB", "CB", "AC", "", "AD", "CD"]);
        assert_eq!(summary(&result), (Completed, Some(5), 17, true));
        assert_eq!(best(result.best.as_ref().unwrap()).0, [('A', 'C')]);
    }

    #[test]
    fn pure_removal_win_shrinks_the_board_and_rescans() {
        let (result, log) = ok(run(AB_CD, &[("CD", 3)], [N, N, N]));
        assert_eq!(log[1..5], ["CD", "CDBA", "CDAB", "CD"]);
        assert_eq!(summary(&result), (Completed, Some(3), 17, true));
        let expected = (CD, 3, "pCD", &[('C', 'D'), ('E', 'F')][..]);
        assert_eq!(best(result.best.as_ref().unwrap()), expected);
    }

    #[test]
    fn zero_pairs_cost_one_evaluation_and_complete() {
        let (result, log) = ok(run(&[], &[], [N, 1, N]));
        assert_eq!(log, [""]);
        assert_eq!(summary(&result), (Completed, Some(0), 1, true));
    }

    #[test]
    fn refused_initial_admission_or_cancellation_leaves_no_history() {
        for (stop, expected) in [([0, N, N], EvaluationBudget), ([N, 0, N], Cancelled)] {
            let (result, log) = ok(run(AB, &[], stop));
            assert!(log.is_empty() && result.stages.is_empty());
            assert_eq!((result.termination, result.evaluations_used), (expected, 5));
            assert_eq!(best(result.best.as_ref().unwrap()).1, -100);
        }
    }

    #[test]
    fn budget_discards_provisional_winner_and_keeps_earlier_commit() {
        let (result, log) = ok(run(AB_CD, &[("CD", 3), ("AC", 9)], [12, N, N]));
        assert_eq!(log[9..], ["CA", "DA", "CB"]);
        assert_eq!(summary(&result), (EvaluationBudget, Some(3), 12, false));
        assert_eq!(best(result.best.as_ref().unwrap()).0, CD);
    }

    #[test]
    fn cancellation_is_polled_before_commit_but_not_after_final_scan() {
        let (result, log) = ok(run(AB_CD, &[("CD", 3)], [N, 9, N]));
        assert_eq!(log.len(), 9);
        assert_eq!(summary(&result), (Cancelled, Some(0), 9, false));
        assert_eq!(best(result.best.as_ref().unwrap()).0, AB_CD);
        let (result, _) = ok(run(AB, &[], [N, 9, N]));
        assert_eq!(summary(&result), (Completed, Some(0), 9, true));
    }

    #[test]
    fn mid_scan_error_reports_committed_best_and_score() {
        let error = run(AB_CD, &[("CD", 3)], [N, N, 12]).0.unwrap_err();
        let expected = (CD, 3, "pCD", &[('C', 'D'), ('E', 'F')][..]);
        assert_eq!(best(error.best().unwrap().unwrap()), expected);
        let s = &error.stages()[0];
        let history = (s.score(), s.evaluations_used(), s.completed());
        assert_eq!(history, (Some(score(3)), 12, false));
        assert_eq!(error.evaluations_used(), 17);
        assert_eq!(error.counters().evaluations_admitted(), 12);
        assert_eq!(error.counters().evaluations_completed(), 11);
        assert_eq!(error.outer_index().zip(error.start_index()), Some((1, 2)));
    }

    #[test]
    fn initial_error_keeps_prior_best_and_null_score() {
        let error = run(AB, &[], [N, N, 1]).0.unwrap_err();
        let prior = error.best().unwrap().unwrap();
        assert_eq!((best(prior).2, prior.measure), ("old", MeasureId::Ic));
        assert_eq!(prior.score, score(-100));
        let s = &error.stages()[0];
        assert_eq!((s.score(), s.evaluations_used()), (None, 1));
    }
}
