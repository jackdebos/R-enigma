//! Private counters and cancellation integrated with HC and PE runtimes; public control is deferred.
//!
//! Accounting records facts; successful completions own the global progress grid.
//! Callers own transition eligibility, stop precedence and reserved final rescoring.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CounterSnapshot {
    pub(super) evaluations_admitted: u64,
    pub(super) evaluations_completed: u64,
    pub(super) climbs_started: u128,
    pub(super) climbs_completed: u128,
    pub(super) outers_completed: u128,
    pub(super) bombe: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CounterOverflow {
    EvaluationsAdmitted,
    EvaluationsCompleted,
    ClimbsStarted,
    ClimbsCompleted,
    OutersCompleted,
    BombeSettings,
    BombeStops,
}

impl std::fmt::Display for CounterOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "attack counter overflow: {self:?}")
    }
}

impl std::error::Error for CounterOverflow {}

/// A synchronous, infallible notification carrying counters, never candidates.
pub(super) trait CounterObserver {
    fn observe(&mut self, snapshot: CounterSnapshot);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AttackControl {
    counters: CounterSnapshot,
    cancelled: bool,
    progress_every: u64,
    next: Option<u64>,
    last_emitted: u64,
}

impl Default for AttackControl {
    fn default() -> Self {
        Self::with_progress_every(100_000)
    }
}

impl AttackControl {
    pub(super) fn with_progress_every(progress_every: u64) -> Self {
        assert!(progress_every > 0);
        Self {
            counters: CounterSnapshot::default(),
            cancelled: false,
            progress_every,
            next: Some(progress_every),
            last_emitted: 0,
        }
    }

    // T4 consumes these at the coordinator's checkpoint boundary, not in workers.
    #[allow(dead_code)]
    pub(crate) fn checkpoint_progress(&self) -> u64 {
        self.last_emitted
    }

    #[allow(dead_code)]
    pub(crate) fn progress_every(&self) -> u64 {
        self.progress_every
    }

    #[allow(dead_code)]
    pub(crate) fn from_checkpoint(
        counters: CounterSnapshot,
        last_emitted: u64,
        progress_every: u64,
    ) -> Self {
        let mut control = Self::with_progress_every(progress_every);
        // Reuse block merging's global-grid reconstruction and checked accounting.
        control
            .merge_block(counters)
            .expect("zero plus checkpoint counters");
        control.last_emitted = last_emitted;
        control
    }

    /// Only successful evaluations advance the global public cadence.
    pub(super) fn complete(
        &mut self,
        observer: &mut impl CounterObserver,
    ) -> Result<(), CounterOverflow> {
        self.record_evaluation_completed()?;
        if self.next == Some(self.counters.evaluations_completed) {
            self.next = self
                .counters
                .evaluations_completed
                .checked_add(self.progress_every);
            self.last_emitted = self.counters.evaluations_completed;
            self.notify(observer);
        }
        Ok(())
    }

    /// Merge a finished worker block without observing intermediate evaluations.
    pub(super) fn merge_block(&mut self, local: CounterSnapshot) -> Result<(), CounterOverflow> {
        let mut merged = self.counters;
        macro_rules! add {
            ($field:ident, $error:ident) => {
                merged.$field = merged
                    .$field
                    .checked_add(local.$field)
                    .ok_or(CounterOverflow::$error)?;
            };
        }
        add!(evaluations_admitted, EvaluationsAdmitted);
        add!(evaluations_completed, EvaluationsCompleted);
        add!(climbs_started, ClimbsStarted);
        add!(climbs_completed, ClimbsCompleted);
        add!(outers_completed, OutersCompleted);
        if let Some((settings, stops)) = local.bombe {
            let (prior_settings, prior_stops) = merged.bombe.unwrap_or_default();
            merged.bombe = Some((
                prior_settings
                    .checked_add(settings)
                    .ok_or(CounterOverflow::BombeSettings)?,
                prior_stops
                    .checked_add(stops)
                    .ok_or(CounterOverflow::BombeStops)?,
            ));
        }
        self.counters = merged;
        let completed = merged.evaluations_completed;
        // Skip the grid points inside this block. Stages retain their original
        // global multiples, rather than rebasing their cadence onto a block edge.
        self.next = completed.checked_add(self.progress_every - completed % self.progress_every);
        Ok(())
    }

    /// One outer-phase notification at most, measured from the previous emission.
    pub(super) fn block_progress(&mut self, observer: &mut impl CounterObserver) {
        let completed = self.counters.evaluations_completed;
        if completed - self.last_emitted >= self.progress_every {
            self.last_emitted = completed;
            self.notify(observer);
        }
    }

    #[cfg(test)]
    pub(super) fn with_counters(counters: CounterSnapshot) -> Self {
        Self {
            counters,
            ..Self::default()
        }
    }

    pub(super) fn snapshot(&self) -> CounterSnapshot {
        self.counters
    }

    /// Explicit notification only; neither accounting nor polling invokes it.
    pub(super) fn notify(&self, observer: &mut impl CounterObserver) {
        observer.observe(self.snapshot());
    }

    /// Latch an observed request without imposing an observer cadence.
    pub(super) fn poll_cancellation(&mut self, requested: bool) -> bool {
        self.cancelled |= requested;
        self.cancelled
    }

    pub(super) fn enable_bombe(&mut self) {
        self.counters.bombe.get_or_insert((0, 0));
    }

    pub(super) fn record_bombe_setting(&mut self) -> Result<(), CounterOverflow> {
        let counters = self.counters.bombe.get_or_insert((0, 0));
        counters.0 = counters
            .0
            .checked_add(1)
            .ok_or(CounterOverflow::BombeSettings)?;
        Ok(())
    }

    pub(super) fn record_bombe_stop(&mut self) -> Result<(), CounterOverflow> {
        let counters = self.counters.bombe.get_or_insert((0, 0));
        counters.1 = counters
            .1
            .checked_add(1)
            .ok_or(CounterOverflow::BombeStops)?;
        Ok(())
    }

    pub(super) fn record_evaluation_admitted(&mut self) -> Result<(), CounterOverflow> {
        self.counters.evaluations_admitted = self
            .counters
            .evaluations_admitted
            .checked_add(1)
            .ok_or(CounterOverflow::EvaluationsAdmitted)?;
        Ok(())
    }

    pub(super) fn record_evaluation_completed(&mut self) -> Result<(), CounterOverflow> {
        self.counters.evaluations_completed = self
            .counters
            .evaluations_completed
            .checked_add(1)
            .ok_or(CounterOverflow::EvaluationsCompleted)?;
        Ok(())
    }

    pub(super) fn record_climb_started(&mut self) -> Result<(), CounterOverflow> {
        self.counters.climbs_started = self
            .counters
            .climbs_started
            .checked_add(1)
            .ok_or(CounterOverflow::ClimbsStarted)?;
        Ok(())
    }

    pub(super) fn record_climb_completed(&mut self) -> Result<(), CounterOverflow> {
        self.counters.climbs_completed = self
            .counters
            .climbs_completed
            .checked_add(1)
            .ok_or(CounterOverflow::ClimbsCompleted)?;
        Ok(())
    }

    pub(super) fn record_outer_completed(&mut self) -> Result<(), CounterOverflow> {
        self.counters.outers_completed = self
            .counters
            .outers_completed
            .checked_add(1)
            .ok_or(CounterOverflow::OutersCompleted)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Vec<CounterSnapshot>);

    impl CounterObserver for Recorder {
        fn observe(&mut self, snapshot: CounterSnapshot) {
            self.0.push(snapshot);
        }
    }

    #[test]
    fn block_progress_uses_last_emission_and_stages_keep_the_global_grid() {
        let mut control = AttackControl::with_progress_every(3);
        let mut observer = Recorder::default();
        for count in [2, 2, 2, 1] {
            control
                .merge_block(CounterSnapshot {
                    evaluations_admitted: count,
                    evaluations_completed: count,
                    ..Default::default()
                })
                .unwrap();
            control.block_progress(&mut observer);
        }
        assert_eq!(
            observer
                .0
                .iter()
                .map(|s| s.evaluations_completed)
                .collect::<Vec<_>>(),
            [4, 7]
        );
        control.complete(&mut observer).unwrap(); // 8: not a stage grid point.
        control.complete(&mut observer).unwrap(); // 9: original stage cadence.
        assert_eq!(
            observer
                .0
                .iter()
                .map(|s| s.evaluations_completed)
                .collect::<Vec<_>>(),
            [4, 7, 9]
        );
    }

    #[test]
    fn checkpoint_progress_rebuilds_grid_and_clears_cancel_latch() {
        for count in [0, 2, 3, 7, u64::MAX] {
            let mut original = AttackControl::with_progress_every(3);
            original
                .merge_block(CounterSnapshot {
                    evaluations_completed: count,
                    ..Default::default()
                })
                .unwrap();
            original.block_progress(&mut Recorder::default());
            let restored = AttackControl::from_checkpoint(
                original.snapshot(),
                original.checkpoint_progress(),
                3,
            );
            assert_eq!(restored, original);
            original.poll_cancellation(true);
            assert!(!restored.cancelled);
        }
    }

    #[test]
    fn block_merge_overflow_is_transactional() {
        let counters = CounterSnapshot {
            evaluations_admitted: u64::MAX,
            ..Default::default()
        };
        let mut control = AttackControl::with_counters(counters);
        assert_eq!(
            control.merge_block(CounterSnapshot {
                evaluations_admitted: 1,
                evaluations_completed: 1,
                ..Default::default()
            }),
            Err(CounterOverflow::EvaluationsAdmitted)
        );
        assert_eq!(control.snapshot(), counters);
    }

    #[test]
    fn completion_cadence_is_global_and_checked() {
        let mut control = AttackControl::with_progress_every(3);
        let mut observer = Recorder::default();
        for count in 1..=7 {
            control.record_evaluation_admitted().unwrap();
            control.record_climb_started().unwrap();
            control.record_climb_completed().unwrap();
            control.record_outer_completed().unwrap();
            control.complete(&mut observer).unwrap();
            assert_eq!(control.snapshot().evaluations_completed, count);
        }
        assert_eq!(
            observer
                .0
                .iter()
                .map(|s| s.evaluations_completed)
                .collect::<Vec<_>>(),
            [3, 6]
        );
        control.notify(&mut observer);
        assert_eq!(observer.0.last().unwrap().evaluations_completed, 7);

        let mut control = AttackControl::with_progress_every(u64::MAX - 1);
        control.counters.evaluations_completed = u64::MAX - 2;
        let mut observer = Recorder::default();
        control.complete(&mut observer).unwrap();
        control.complete(&mut observer).unwrap();
        assert_eq!(observer.0.len(), 1);
        assert_eq!(control.next, None);
        assert_eq!(
            control.complete(&mut observer),
            Err(CounterOverflow::EvaluationsCompleted)
        );
        assert_eq!(observer.0.len(), 1);
    }

    #[test]
    fn cancellation_is_sticky() {
        let mut control = AttackControl::default();
        assert!(!control.poll_cancellation(false));
        assert!(control.poll_cancellation(true));
        assert!(control.poll_cancellation(false));
    }

    #[test]
    fn bombe_counters_are_checked_and_block_merges_are_transactional() {
        let mut control = AttackControl::with_counters(CounterSnapshot {
            bombe: Some((u64::MAX, u64::MAX)),
            ..Default::default()
        });
        let before = control.snapshot();
        assert_eq!(
            control.record_bombe_setting(),
            Err(CounterOverflow::BombeSettings)
        );
        assert_eq!(
            control.record_bombe_stop(),
            Err(CounterOverflow::BombeStops)
        );
        assert_eq!(control.snapshot(), before);
        for (counts, expected) in [
            ((1, 0), CounterOverflow::BombeSettings),
            ((0, 1), CounterOverflow::BombeStops),
        ] {
            assert_eq!(
                control.merge_block(CounterSnapshot {
                    evaluations_completed: 1,
                    bombe: Some(counts),
                    ..Default::default()
                }),
                Err(expected)
            );
            assert_eq!(control.snapshot(), before);
        }
    }

    #[test]
    fn zero_snapshot_is_a_retained_copy() {
        let mut control = AttackControl::default();
        let retained = control.snapshot();
        assert_eq!(retained, CounterSnapshot::default());
        control.record_evaluation_admitted().unwrap();
        assert_eq!(retained.evaluations_admitted, 0);
        assert_eq!(control.snapshot().evaluations_admitted, 1);
    }

    #[test]
    fn polling_and_accounting_do_not_notify() {
        let mut control = AttackControl::default();
        let mut observer = Recorder::default();
        control.notify(&mut observer);
        assert!(control.poll_cancellation(true));
        control.record_evaluation_admitted().unwrap();
        assert!(control.poll_cancellation(false));
        assert_eq!(observer.0, vec![CounterSnapshot::default()]);
        assert_eq!(control.snapshot().evaluations_admitted, 1);
    }

    #[test]
    fn failed_evaluation_retains_admission_without_completion() {
        let mut control = AttackControl::default();
        control.record_evaluation_admitted().unwrap();
        let evaluation: Result<(), &str> = Err("scoring failed");
        if evaluation.is_ok() {
            control.record_evaluation_completed().unwrap();
        }
        let mut observer = Recorder::default();
        control.notify(&mut observer); // Error boundary is explicit.
        control.notify(&mut observer); // Duplicate terminal snapshots are allowed.
        let charged = CounterSnapshot {
            evaluations_admitted: 1,
            ..CounterSnapshot::default()
        };
        assert_eq!(evaluation, Err("scoring failed"));
        assert_eq!(observer.0, vec![charged, charged]);
        assert_eq!(control.snapshot(), charged);
    }

    #[test]
    fn successful_completion_and_climb_outer_transitions_are_separate() {
        let mut control = AttackControl::default();
        control.record_evaluation_admitted().unwrap();
        assert_eq!(control.snapshot().evaluations_completed, 0);
        control.record_evaluation_completed().unwrap();
        assert_eq!(control.snapshot().climbs_started, 0);
        control.record_climb_started().unwrap();
        assert_eq!(control.snapshot().climbs_completed, 0);
        control.record_climb_completed().unwrap();
        assert_eq!(control.snapshot().outers_completed, 0);
        control.record_outer_completed().unwrap();
        let completed = CounterSnapshot {
            evaluations_admitted: 1,
            evaluations_completed: 1,
            climbs_started: 1,
            climbs_completed: 1,
            outers_completed: 1,
            bombe: None,
        };
        let mut observer = Recorder::default();
        control.notify(&mut observer);
        control.notify(&mut observer);
        assert_eq!(observer.0, vec![completed, completed]);
        assert_eq!(control.snapshot(), completed);
    }

    #[test]
    fn every_counter_overflow_is_explicit_and_leaves_snapshot_unchanged() {
        type Transition = fn(&mut AttackControl) -> Result<(), CounterOverflow>;
        let cases: [(Transition, CounterOverflow); 5] = [
            (
                AttackControl::record_evaluation_admitted,
                CounterOverflow::EvaluationsAdmitted,
            ),
            (
                AttackControl::record_evaluation_completed,
                CounterOverflow::EvaluationsCompleted,
            ),
            (
                AttackControl::record_climb_started,
                CounterOverflow::ClimbsStarted,
            ),
            (
                AttackControl::record_climb_completed,
                CounterOverflow::ClimbsCompleted,
            ),
            (
                AttackControl::record_outer_completed,
                CounterOverflow::OutersCompleted,
            ),
        ];
        for (transition, expected) in cases {
            let mut control = AttackControl {
                counters: CounterSnapshot {
                    evaluations_admitted: u64::MAX,
                    evaluations_completed: u64::MAX,
                    climbs_started: u128::MAX,
                    climbs_completed: u128::MAX,
                    outers_completed: u128::MAX,
                    bombe: None,
                },
                ..AttackControl::default()
            };
            let retained = control.snapshot();
            assert_eq!(transition(&mut control), Err(expected));
            assert_eq!(control.snapshot(), retained);
        }
    }
}
