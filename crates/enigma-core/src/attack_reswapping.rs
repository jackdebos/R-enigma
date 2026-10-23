//! Private constrained steepest-ascent reswapping stage (search-passes §9.3, §9.5).

#[cfg(test)]
use crate::attack_control::AttackControl;
use crate::attack_control::CounterObserver;
use crate::attack_hill_climb::{EvaluationAccounting, ObservedAccounting};
use crate::attack_result::{AttackRunErrorData, RunPayload};
use crate::{Alphabet, AttackPlugboardDomain, AttackTermination, MeasureId, MeasuredScore};

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

/// A scored trial board; plaintext only when a materializing fallback carried it.
struct Trial {
    board: Vec<(char, char)>,
    plaintext: Option<String>,
    score: MeasuredScore,
}

/// Scored trial result: plaintext only when a materializing fallback carried it.
type Scored = (Option<String>, MeasuredScore);

/// One neighbor of the baseline in alphabet indices: sever the pair (i, k), then
/// link `end` to the free symbol `x` unless they coincide (a pure removal).
#[derive(Clone, Copy)]
struct Move {
    i: usize,
    k: usize,
    x: usize,
    end: usize,
}

struct Reswapper<'s, 'a, O, C, E, M> {
    alphabet: &'s Alphabet,
    accounting: &'s mut ObservedAccounting<'a, O>,
    cancel_requested: C,
    evaluate: E,
    evaluate_mapped: M,
    /// Domain symbols by ascending alphabet index; never fixed endpoints.
    domain: Vec<usize>,
    fixed: Vec<bool>,
    /// Full fixed and mutable involution of the committed board, plus any applied move.
    map: Vec<usize>,
}

impl<O, C, E, M> Reswapper<'_, '_, O, C, E, M>
where
    O: CounterObserver,
    C: FnMut() -> bool,
    E: FnMut(&[(char, char)]) -> Result<Scored, RunPayload>,
    M: FnMut(&[usize]) -> Result<Scored, RunPayload>,
{
    fn cancelled(&mut self) -> bool {
        let requested = (self.cancel_requested)();
        self.accounting.control.poll_cancellation(requested)
    }

    /// Poll, admit one shared unit, evaluate and record completion.
    fn admitted(
        &mut self,
        evaluate: impl FnOnce(&mut Self) -> Result<Scored, RunPayload>,
    ) -> Result<Result<Scored, AttackTermination>, RunPayload> {
        if self.cancelled() {
            return Ok(Err(AttackTermination::Cancelled));
        }
        if !self.accounting.admit(0)? {
            return Ok(Err(AttackTermination::EvaluationBudget));
        }
        let scored = evaluate(self)?;
        self.accounting.complete()?;
        Ok(Ok(scored))
    }

    /// Rewrites the baseline in place; [`Self::restore`] undoes it.
    fn apply(&mut self, m: Move) {
        (self.map[m.i], self.map[m.k]) = (m.i, m.k);
        if m.x != m.end {
            (self.map[m.end], self.map[m.x]) = (m.x, m.end);
        }
    }

    /// `x` was free in the baseline, or is i or k, which the pair rewrites.
    fn restore(&mut self, m: Move) {
        self.map[m.x] = m.x;
        (self.map[m.i], self.map[m.k]) = (m.k, m.i);
    }

    /// Canonical mutable board: pairs by ascending lower alphabet index, fixed omitted.
    fn board(&self) -> Vec<(char, char)> {
        let symbols = &self.alphabet.symbols;
        (0..self.map.len())
            .filter(|&i| i < self.map[i] && !self.fixed[i])
            .map(|i| (symbols[i], symbols[self.map[i]]))
            .collect()
    }

    /// `Ok(None)` is completion; an interrupted scan discards its provisional winner.
    fn run(
        &mut self,
        start: &[(char, char)],
        committed: &mut Option<Trial>,
    ) -> Result<Option<AttackTermination>, RunPayload> {
        // The initial trial validates the start board; neighbors stay within it.
        let (plaintext, score) = match self.admitted(|this| (this.evaluate)(start))? {
            Ok(initial) => initial,
            Err(stop) => return Ok(Some(stop)),
        };
        for &(x, y) in start {
            let (x, y) = (order(self.alphabet, x), order(self.alphabet, y));
            (self.map[x], self.map[y]) = (y, x);
        }
        let mut current = Trial {
            board: self.board(),
            plaintext,
            score,
        };
        loop {
            let mut bar = current.score;
            *committed = Some(current);
            let mut winner = None;
            // Same order as the board: pairs, free symbols, then endpoints i, k.
            for i in 0..self.map.len() {
                let k = self.map[i];
                if k <= i || self.fixed[i] {
                    continue;
                }
                for d in 0..self.domain.len() {
                    let x = self.domain[d];
                    if self.map[x] != x && x != i && x != k {
                        continue;
                    }
                    for end in [i, k] {
                        let m = Move { i, k, x, end };
                        let scored = self.admitted(|this| {
                            this.apply(m);
                            let scored = (this.evaluate_mapped)(&this.map);
                            this.restore(m);
                            scored
                        })?;
                        let (plaintext, score) = match scored {
                            Ok(scored) => scored,
                            Err(stop) => return Ok(Some(stop)),
                        };
                        // Strictly greater: a tie (e.g. restoring the pair) would
                        // otherwise win and rescan forever.
                        if score.ranking().units() > bar.ranking().units() {
                            bar = score;
                            winner = Some((m, plaintext, score));
                        }
                    }
                }
            }
            let Some((m, plaintext, score)) = winner else {
                return Ok(None);
            };
            if self.cancelled() {
                return Ok(Some(AttackTermination::Cancelled));
            }
            self.apply(m);
            current = Trial {
                board: self.board(),
                plaintext,
                score,
            };
        }
    }
}

/// Runs one reswapping stage on the committed best; history follows first admission.
/// Trials are score-only; only the final commit's plaintext is replayed, once and
/// outside accounting, unless a materializing fallback already carried it.
pub(crate) fn reswapping_stage(
    mut result: crate::AttackResult,
    measure: MeasureId,
    alphabet: &Alphabet,
    domain: &AttackPlugboardDomain,
    accounting: &mut ObservedAccounting<'_, impl CounterObserver>,
    cancel_requested: impl FnMut() -> bool,
    (evaluate, evaluate_mapped, replay): (
        impl FnMut(&[(char, char)]) -> Result<Scored, RunPayload>,
        impl FnMut(&[usize]) -> Result<Scored, RunPayload>,
        impl FnOnce(&[(char, char)]) -> Result<String, RunPayload>,
    ),
) -> Result<crate::AttackResult, crate::AttackRunError> {
    let before = accounting.allowance.used;
    let best = result.best.as_mut().expect("completed run has best");
    let mut committed = None;
    let mut map: Vec<usize> = (0..alphabet.symbols.len()).collect();
    let mut fixed = vec![false; map.len()];
    for &(x, y) in domain.fixed_pairs() {
        let (x, y) = (order(alphabet, x), order(alphabet, y));
        (map[x], map[y], fixed[x], fixed[y]) = (y, x, true, true);
    }
    let mut symbols: Vec<usize> = (domain.symbols().iter())
        .map(|&x| order(alphabet, x))
        .collect();
    symbols.sort_unstable();
    let outcome = Reswapper {
        alphabet,
        accounting: &mut *accounting,
        cancel_requested,
        evaluate,
        evaluate_mapped,
        domain: symbols,
        fixed,
        map,
    }
    .run(&best.mutable_plugboard.clone(), &mut committed);
    let score = committed.as_ref().map(|key| key.score);
    // A replay failure is an invariant; any earlier trial error keeps precedence.
    let (committed, outcome) = match committed {
        Some(Trial {
            board,
            plaintext: None,
            score,
        }) => match replay(&board) {
            Ok(plaintext) => (Some((board, plaintext, score)), outcome),
            Err(source) => (None, outcome.and(Err(source))),
        },
        Some(Trial {
            board,
            plaintext: Some(plaintext),
            score,
        }) => (Some((board, plaintext, score)), outcome),
        None => (None, outcome),
    };
    // Admission charges the allowance first; an unchanged count means not started.
    if accounting.allowance.used != before {
        if let Some((board, plaintext, score)) = committed {
            let mut pairs = [domain.fixed_pairs(), &board].concat();
            normalize(alphabet, &mut pairs);
            let slots = best.configuration.slots().to_vec();
            best.configuration = crate::TransformConfiguration::new(slots, pairs);
            best.mutable_plugboard = board;
            best.plaintext = plaintext;
            (best.score, best.measure) = (score, measure);
        }
        result.evaluations_used = accounting.allowance.used;
        result.counters = crate::AttackProgress(accounting.control.snapshot());
        result.stages.push(crate::AttackStageResult {
            pass: "reswapping",
            measure,
            base_measure: None,
            score,
            evaluations_used: accounting.allowance.used - before,
            completed: matches!(outcome, Ok(None)),
        });
    }
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
                held_tail: result.held_tail,
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
    /// score -100. `stop` is [budget, cancel after, fail at]; the initial board is
    /// logged raw, neighbors as canonical boards, all scored by their sorted
    /// symbols (default 0).
    fn run(start: &[(char, char)], scores: &[(&str, i128)], stop: [usize; 3]) -> Run {
        run_with(AttackControl::default(), start, scores, stop, Mode::Stream)
    }

    /// How synthetic trials deliver plaintext: streamed and replayed on commit,
    /// carried from a materializing fallback, or streamed with a failing replay.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Stream,
        Carry,
        ReplayFails,
    }

    thread_local! {
        static REPLAYS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    /// Raw boards replayed since the last call.
    fn replays() -> Vec<String> {
        REPLAYS.with(|replays| replays.take())
    }

    fn run_with(
        mut control: AttackControl,
        start: &[(char, char)],
        scores: &[(&str, i128)],
        stop: [usize; 3],
        mode: Mode,
    ) -> Run {
        let alphabet = Alphabet::new("ABCDEF".chars().collect()).unwrap();
        let json = r#"{"kind":"attack","symbols":["D","A","C","B"],"max_pairs":3}"#;
        let domain = AttackPlugboardDomain::parse_json(&alphabet, &[('F', 'E')], json).unwrap();
        let pairs = [start, &[('E', 'F')]].concat();
        let result = AttackResult {
            held_tail: crate::attack_hold::tests::tail_fixture(),
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
                stages: Vec::new(),
            }),
            stages: Vec::new(),
        };
        let tail = crate::attack_hold::tests::snapshot(&result.held_tail);
        let (count, log) = (Cell::new(0), RefCell::new(Vec::new()));
        // Capped so a non-terminating scan fails fast instead of exhausting memory.
        let limit = (stop[0] as u64).min(10_000).saturating_add(5);
        let mut allowance = EvaluationAllowance { used: 5, limit };
        let accounting = &mut ObservedAccounting {
            allowance: &mut allowance,
            control: &mut control,
            observer: &mut Recorder,
        };
        let cancel = || count.get() >= stop[1];
        let raw = |board: &[(char, char)]| -> String {
            board.iter().flat_map(|&(a, b)| [a, b]).collect()
        };
        let key = |raw: &str| {
            let mut key: Vec<char> = raw.chars().collect();
            key.sort_unstable();
            key.into_iter().collect::<String>()
        };
        let score_raw = |raw: String| -> Result<Scored, RunPayload> {
            count.set(count.get() + 1);
            let key = key(&raw);
            log.borrow_mut().push(raw);
            if count.get() == stop[2] {
                return Err(RunPayload::Invariant("synthetic trial failure"));
            }
            let units = scores.iter().find(|(k, _)| *k == key).map_or(0, |e| e.1);
            let carried = (mode == Mode::Carry).then(|| format!("p{key}"));
            Ok((carried, score(units)))
        };
        let evaluate = |board: &[(char, char)]| score_raw(raw(board));
        // Neighbor mappings log their canonical mutable board; E–F is fixed.
        let evaluate_mapped = |map: &[usize]| {
            let symbols = &alphabet.symbols;
            let board: Vec<(char, char)> = (0..4)
                .filter(|&i| i < map[i])
                .map(|i| (symbols[i], symbols[map[i]]))
                .collect();
            score_raw(raw(&board))
        };
        let replay = |board: &[(char, char)]| {
            let raw = raw(board);
            let plaintext = format!("p{}", key(&raw));
            REPLAYS.with(|replays| replays.borrow_mut().push(raw));
            match mode {
                Mode::ReplayFails => Err(RunPayload::Invariant("synthetic replay failure")),
                _ => Ok(plaintext),
            }
        };
        let measure = MeasureId::SinkovTrigram;
        replays();
        let outcome = reswapping_stage(
            result,
            measure,
            &alphabet,
            &domain,
            accounting,
            cancel,
            (evaluate, evaluate_mapped, replay),
        );
        let retained = match &outcome {
            Ok(result) => &result.held_tail[..],
            Err(error) => crate::attack_result::tests::held_tail(error),
        };
        assert_eq!(crate::attack_hold::tests::snapshot(retained), tail);
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
        assert_eq!(log, ["BA", "", "AB", "AB", "", "AC", "BC", "AD", "BD"]);
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
        assert_eq!(log[9..], ["", "AC", "AB", "BC", "AC", "", "AD", "CD"]);
        assert_eq!(summary(&result), (Completed, Some(5), 17, true));
        assert_eq!(best(result.best.as_ref().unwrap()).0, [('A', 'C')]);
    }

    #[test]
    fn pure_removal_win_shrinks_the_board_and_rescans() {
        let (result, log) = ok(run(AB_CD, &[("CD", 3)], [N, N, N]));
        assert_eq!(log[1..5], ["CD", "ABCD", "ABCD", "CD"]);
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
        assert_eq!(log[9..], ["AC", "AD", "BC"]);
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
    fn hold_ownership_reswapping_error_retains_tail_and_committed_best() {
        let error = run(AB_CD, &[("CD", 3)], [N, N, 12]).0.unwrap_err();
        let expected = (CD, 3, "pCD", &[('C', 'D'), ('E', 'F')][..]);
        assert_eq!(best(error.best().unwrap().unwrap()), expected);
        assert!(matches!(
            error.run_source().0,
            RunPayload::Invariant("synthetic trial failure")
        ));
        assert_eq!(error.counters().climbs_started(), 0);
        assert_eq!(error.counters().climbs_completed(), 0);
        assert_eq!(error.counters().outers_completed(), 0);
        let s = &error.stages()[0];
        let history = (s.score(), s.evaluations_used(), s.completed());
        assert_eq!(history, (Some(score(3)), 12, false));
        assert_eq!(error.evaluations_used(), 17);
        assert_eq!(error.counters().evaluations_admitted(), 12);
        assert_eq!(error.counters().evaluations_completed(), 11);
        assert_eq!(error.outer_index().zip(error.start_index()), Some((1, 2)));
    }

    #[test]
    fn first_admission_counter_overflow_is_returned_with_history() {
        let counters = CounterSnapshot {
            evaluations_admitted: u64::MAX,
            ..CounterSnapshot::default()
        };
        let control = AttackControl::with_counters(counters);
        let error = run_with(control, AB, &[], [N, N, N], Mode::Stream)
            .0
            .unwrap_err();
        let overflow = crate::AttackCounterOverflow::EvaluationsAdmitted;
        assert_eq!(error.run_source().overflow(), Some(overflow));
        let s = &error.stages()[0];
        let history = (s.score(), s.evaluations_used(), s.completed());
        assert_eq!(history, (None, 1, false));
        assert_eq!(error.best().unwrap().unwrap().score, score(-100));
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

    #[test]
    fn only_the_committed_board_is_replayed_once() {
        ok(run(&[('B', 'A')], &[], [N, N, N]));
        assert_eq!(replays(), ["AB"]);
        ok(run(AB, &[("AC", 5), ("BC", 5)], [N, N, N]));
        assert_eq!(replays(), ["AC"]);
        // Interruptions discard the provisional winner; only the commit replays.
        let (result, _) = ok(run(AB_CD, &[("CD", 3), ("AC", 9)], [12, N, N]));
        assert_eq!(replays(), ["CD"]);
        assert_eq!(best(result.best.as_ref().unwrap()).2, "pCD");
        ok(run(AB_CD, &[("CD", 3)], [N, 9, N]));
        assert_eq!(replays(), ["ABCD"]);
        for stop in [[0, N, N], [N, 0, N], [N, N, 1]] {
            let _ = run(AB, &[], stop);
            assert!(replays().is_empty());
        }
        run(AB_CD, &[("CD", 3)], [N, N, 12]).0.unwrap_err();
        assert_eq!(replays(), ["CD"]);
    }

    #[test]
    fn carried_plaintext_is_never_replayed_and_matches_streamed_runs() {
        type Scores<'a> = &'a [(&'a str, i128)];
        let cases: [(Pairs, Scores, [usize; 3]); 6] = [
            (&[('B', 'A')], &[], [N, N, N]),
            (AB, &[("AC", 5), ("BC", 5)], [N, N, N]),
            (AB_CD, &[("CD", 3), ("AC", 9)], [12, N, N]),
            (AB_CD, &[("CD", 3)], [N, 9, N]),
            (AB_CD, &[("CD", 3)], [N, N, 12]),
            (AB, &[], [N, N, 1]),
        ];
        for (start, scores, stop) in cases {
            let control = AttackControl::default;
            let streamed = run_with(control(), start, scores, stop, Mode::Stream);
            let carried = run_with(control(), start, scores, stop, Mode::Carry);
            assert!(replays().is_empty());
            assert_eq!(format!("{carried:?}"), format!("{streamed:?}"));
        }
    }

    #[test]
    fn replay_failure_is_an_invariant_after_any_trial_error() {
        let control = AttackControl::default;
        let failed = |stop| run_with(control(), AB_CD, &[("CD", 3)], stop, Mode::ReplayFails);
        let error = failed([N, N, N]).0.unwrap_err();
        assert!(matches!(
            error.run_source().0,
            RunPayload::Invariant("synthetic replay failure")
        ));
        // The unreplayable commit never reaches best; history still records it.
        assert_eq!(best(error.best().unwrap().unwrap()).2, "old");
        let s = &error.stages()[0];
        let history = (s.score(), s.evaluations_used(), s.completed());
        assert_eq!(history, (Some(score(3)), 17, false));
        assert_eq!(error.evaluations_used(), 22);
        assert_eq!(error.counters().evaluations_completed(), 17);
        let error = failed([N, N, 12]).0.unwrap_err();
        assert!(matches!(
            error.run_source().0,
            RunPayload::Invariant("synthetic trial failure")
        ));
    }

    /// The materializing stage before score-only trials, kept as an oracle.
    mod reference {
        use super::super::{normalize, order};
        use crate::attack_control::CounterObserver;
        use crate::attack_hill_climb::{EvaluationAccounting, ObservedAccounting, ScoredBoard};
        use crate::attack_result::{AttackRunErrorData, RunPayload};
        use crate::MeasuredScore;
        use crate::{Alphabet, AttackPlugboardDomain, AttackTermination, MeasureId};

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
                self.accounting.complete()?;
                let board = board.to_vec();
                Ok(Ok(ScoredBoard {
                    board,
                    plaintext,
                    score,
                }))
            }

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

        pub(super) fn reswapping_stage(
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
            if accounting.allowance.used != before {
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
            }
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
                        held_tail: result.held_tail,
                        stages: result.stages,
                        evaluations_used: result.evaluations_used,
                        counters: result.counters,
                        best: Ok(result.best),
                    }))
                }
            }
        }
    }

    #[derive(Default)]
    struct Snapshots(Vec<CounterSnapshot>);
    impl CounterObserver for Snapshots {
        fn observe(&mut self, snapshot: CounterSnapshot) {
            self.0.push(snapshot);
        }
    }

    #[test]
    fn score_only_reswapping_matches_materializing_reference() {
        use crate::attack_evaluator::{TrialEvaluator, BOARD_FILLS, PLAINTEXT_BUILDS};
        use crate::{BoundResource, SlotConfiguration, TransformConfiguration};
        use MeasureId::{Entropy, Ic, SinkovBigram, SinkovQuadgram, Trie};
        let builds = || PLAINTEXT_BUILDS.with(|count| count.replace(0));
        let fills = || BOARD_FILLS.with(|count| count.replace(0));
        let mut improved = 0;
        for symbols in ["ABCDEF", "界éHβAGλ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"] {
            let s: Vec<char> = symbols.chars().collect();
            let wiring: Vec<char> = s.iter().cycle().skip(3).take(s.len()).copied().collect();
            let source = serde_json::json!({"kind": "custom", "value": {
                "alphabet": s, "wheels": [{"name": "r", "wiring": wiring, "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "movable", "wheel": "r"}],
                "stepping": {"rules": [{"when": {"always": true}, "advance": ["r"]}]}
            }});
            let definition = crate::DefinitionSource::parse_json(&source.to_string())
                .unwrap()
                .resolve()
                .unwrap();
            let slots = vec![SlotConfiguration::new("r", "r", s[0], 'A')];
            let initial = TransformConfiguration::new(slots.clone(), vec![])
                .resolve(&definition)
                .unwrap();
            let alphabet = initial.topology().alphabet();
            let json = serde_json::json!({"kind": "attack", "symbols": s, "max_pairs": 3});
            let domain =
                AttackPlugboardDomain::parse_json(alphabet, &[], &json.to_string()).unwrap();
            let ngram = |order| {
                let entries = vec![(s[..order].to_vec(), 5), (vec![s[1]; order], 2)];
                BoundResource::Ngram(
                    crate::NgramModel::new(alphabet.clone(), order, entries).unwrap(),
                )
            };
            let entries = vec![(vec![s[0], s[2]], 3), (vec![s[1]], -1), (vec![s[4]], 2)];
            let trie =
                BoundResource::Trie(crate::TrieModel::new(alphabet.clone(), entries).unwrap());
            let (bigram, quadgram) = (ngram(2), ngram(4));
            let input: String = (0..40).map(|i| s[(i * 7 + i / 3) % s.len()]).collect();
            let start = [(s[0], s[1]), (s[2], s[3])];
            for (measure, resource) in [
                (Ic, None),
                (Entropy, None),
                (SinkovBigram, Some(&bigram)),
                (SinkovQuadgram, Some(&quadgram)),
                (Trie, Some(&trie)),
            ] {
                // Quadgrams over 26 symbols have no dense table and score sparsely.
                let streamable = measure != Trie && (measure != SinkovQuadgram || s.len() < 26);
                for deny in [false, true] {
                    for (limit, cancel_at) in [
                        (N, N),
                        (0, N),
                        (1, N),
                        (7, N),
                        (30, N),
                        (N, 0),
                        (N, 1),
                        (N, 10),
                        (N, 40),
                    ] {
                        let run = |old: bool| {
                            let evaluator = TrialEvaluator::new(
                                &initial,
                                &domain,
                                &input,
                                crate::Direction::Decrypt,
                                measure,
                                resource,
                            );
                            let evaluator = if deny {
                                evaluator.with_reservation_denied()
                            } else {
                                evaluator
                            };
                            let configuration =
                                TransformConfiguration::new(slots.clone(), start.to_vec());
                            let result = AttackResult {
                                held_tail: Vec::new(),
                                termination: Completed,
                                counters: crate::AttackProgress(CounterSnapshot::default()),
                                evaluations_used: 5,
                                best: Some(AttackBest {
                                    configuration,
                                    mutable_plugboard: start.to_vec(),
                                    plaintext: "old".into(),
                                    score: score(-100),
                                    measure: MeasureId::Ic,
                                    outer_index: 1,
                                    start_index: 2,
                                    incomplete: false,
                                    final_objective_ascent: false,
                                    neighborhood_exhausted: false,
                                    stages: Vec::new(),
                                }),
                                stages: Vec::new(),
                            };
                            let mut control = AttackControl::default();
                            let mut observer = Snapshots::default();
                            let limit = (limit as u64).saturating_add(5);
                            let mut allowance = EvaluationAllowance { used: 5, limit };
                            let accounting = &mut ObservedAccounting {
                                allowance: &mut allowance,
                                control: &mut control,
                                observer: &mut observer,
                            };
                            let polls = Cell::new(0);
                            let cancel = || {
                                polls.set(polls.get() + 1);
                                polls.get() > cancel_at
                            };
                            builds();
                            fills();
                            let outcome = if old {
                                let evaluate = |board: &[(char, char)]| {
                                    evaluator.evaluate(board).map_err(RunPayload::Evaluation)
                                };
                                reference::reswapping_stage(
                                    result, measure, alphabet, &domain, accounting, cancel,
                                    evaluate,
                                )
                            } else {
                                let evaluate = |board: &[(char, char)]| {
                                    evaluator
                                        .evaluate_score(board)
                                        .map_err(RunPayload::Evaluation)
                                };
                                let evaluate_mapped = |mapping: &[usize]| {
                                    evaluator
                                        .evaluate_score_mapped(mapping)
                                        .map_err(RunPayload::Evaluation)
                                };
                                let replay = |board: &[(char, char)]| {
                                    evaluator.replay_plaintext(board).map_err(RunPayload::from)
                                };
                                reswapping_stage(
                                    result,
                                    measure,
                                    alphabet,
                                    &domain,
                                    accounting,
                                    cancel,
                                    (evaluate, evaluate_mapped, replay),
                                )
                            };
                            let (builds, fills) = (builds(), fills());
                            let used = allowance.used;
                            (
                                format!("{outcome:?}"),
                                outcome,
                                used,
                                control.snapshot(),
                                observer.0,
                                builds,
                                fills,
                            )
                        };
                        let label = format!("{symbols} {measure:?} {deny} {limit} {cancel_at}");
                        let (old, new) = (run(true), run(false));
                        assert_eq!(
                            (&new.0, new.2, new.3, &new.4),
                            (&old.0, old.2, old.3, &old.4),
                            "{label}"
                        );
                        let result = new.1.unwrap();
                        let stage = result.stages.first();
                        let committed = stage.is_some_and(|stage| stage.score().is_some());
                        let expected = if streamable && !deny {
                            usize::from(committed)
                        } else {
                            old.5
                        };
                        assert_eq!(new.5, expected, "{label}");
                        // Only the initial trial and the commit replay build a board;
                        // neighbor trials score the in-place index mapping.
                        assert!(new.6 <= 2, "{label}: {} board fills", new.6);
                        assert_eq!(old.5, usize::try_from(old.2 - 5).unwrap(), "{label}");
                        let board = &result.best.as_ref().unwrap().mutable_plugboard;
                        improved += usize::from(committed && board[..] != start[..]);
                    }
                }
            }
        }
        assert!(improved > 0);
    }
}
