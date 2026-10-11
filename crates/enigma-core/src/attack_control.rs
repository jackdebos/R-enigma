//! Private counters and cancellation integrated with HC and PE runtimes; public control is deferred.
//!
//! Accounting records facts only. Callers own transition eligibility, stop
//! precedence, observer cadence and any reserved final-objective rescore.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CounterSnapshot {
    pub(super) evaluations_admitted: u64,
    pub(super) evaluations_completed: u64,
    pub(super) climbs_started: u128,
    pub(super) climbs_completed: u128,
    pub(super) outers_completed: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CounterOverflow {
    EvaluationsAdmitted,
    EvaluationsCompleted,
    ClimbsStarted,
    ClimbsCompleted,
    OutersCompleted,
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

#[derive(Default)]
pub(super) struct AttackControl {
    counters: CounterSnapshot,
    cancelled: bool,
}

impl AttackControl {
    #[cfg(test)]
    pub(super) fn with_counters(counters: CounterSnapshot) -> Self {
        Self {
            counters,
            cancelled: false,
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
    fn cancellation_is_sticky() {
        let mut control = AttackControl::default();
        assert!(!control.poll_cancellation(false));
        assert!(control.poll_cancellation(true));
        assert!(control.poll_cancellation(false));
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
                },
                cancelled: false,
            };
            let retained = control.snapshot();
            assert_eq!(transition(&mut control), Err(expected));
            assert_eq!(control.snapshot(), retained);
        }
    }
}
