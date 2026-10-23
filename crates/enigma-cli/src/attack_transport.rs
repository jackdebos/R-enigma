//! Private synchronous JSONL adapter for validated HC/PE execution.

use std::cell::{Cell, RefCell};
use std::io::{self, Write};
use std::time::Duration;

use enigma_core::{encode, AttackProgress, AttackRequest, Event};

/// No clock or I/O enters Core. Both clocks are supplied by the CLI boundary.
struct Transport<W, M, U> {
    writer: W,
    monotonic: M,
    utc: U,
    entry: Duration,
    seq: u64,
    failure: Option<io::Error>,
}

/// Original runtime failure remains primary; projection and delivery are separate.
#[derive(Debug)]
pub(super) struct Failure {
    pub(super) runtime: Option<Box<dyn std::error::Error + Send + Sync>>,
    pub(super) projection: Option<String>,
    pub(super) transport: Option<io::Error>,
}

impl<W: Write, M: FnMut() -> Duration, U: FnMut() -> String> Transport<W, M, U> {
    fn new(writer: W, mut monotonic: M, utc: U) -> Self {
        let entry = monotonic();
        Self {
            writer,
            monotonic,
            utc,
            entry,
            seq: 1,
            failure: None,
        }
    }

    fn elapsed(&mut self) -> u128 {
        (self.monotonic)().saturating_sub(self.entry).as_millis()
    }

    fn emit(&mut self, event: Event) {
        if self.failure.is_some() {
            return;
        }
        let result = encode(&event, self.seq, &(self.utc)())
            .map_err(io::Error::other)
            .and_then(|mut line| {
                line.push('\n');
                self.writer.write_all(line.as_bytes())?;
                self.writer.flush()
            });
        match result {
            Ok(()) => self.seq += 1,
            Err(error) => self.failure = Some(error),
        }
    }

    fn observe(&mut self, progress: AttackProgress) {
        if self.failure.is_none() {
            let elapsed = self.elapsed();
            self.emit(Event::progress(progress, elapsed));
        }
    }

    /// A fallible projection is resolved before either terminal line is emitted.
    fn terminal(&mut self, projected: Result<(Event, Event), String>) -> Option<String> {
        match projected {
            Ok((result, terminal)) => {
                self.emit(result);
                self.emit(terminal);
                None
            }
            Err(error) => Some(error),
        }
    }

    fn finish(
        mut self,
        projected: Result<(Event, Event), String>,
        runtime: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Result<(), Failure> {
        let projection = self.terminal(projected);
        let failure = Failure {
            runtime,
            projection,
            transport: self.failure,
        };
        if failure.runtime.is_some() || failure.projection.is_some() || failure.transport.is_some()
        {
            Err(failure)
        } else {
            Ok(())
        }
    }
}

/// Called only after parsing, binding and all Core eligibility preflight.
/// External cancellation is independently polled and sticky, as is delivery failure.
pub(super) fn run(
    request: &AttackRequest,
    writer: impl Write,
    monotonic: impl FnMut() -> Duration,
    utc: impl FnMut() -> String,
    mut cancel_requested: impl FnMut() -> bool,
) -> Result<(), Failure> {
    let transport = RefCell::new(Transport::new(writer, monotonic, utc));
    let cancelled = Cell::new(false);
    transport.borrow_mut().emit(Event::Started);
    let result = request.run(
        |progress| transport.borrow_mut().observe(progress),
        || {
            cancelled
                .set(cancelled.get() || transport.borrow().failure.is_some() || cancel_requested());
            cancelled.get()
        },
    );
    let mut transport = transport.into_inner();
    // Measure after run: Core's required final rescore is included.
    let elapsed = transport.elapsed();
    match result {
        Ok(result) => transport.finish(
            Ok((
                Event::result(&result, elapsed),
                Event::Done {
                    reason: result.termination().into(),
                },
            )),
            None,
        ),
        Err(error) => {
            let projected = Event::runtime_error(&error, elapsed)
                .map_err(|projection| projection.best_projection().to_string());
            transport.finish(projected, Some(Box::new(error)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn request(pe: bool) -> AttackRequest {
        request_with_objectives(pe, false)
    }

    fn request_with_objectives(pe: bool, rescore: bool) -> AttackRequest {
        request_with_progress(pe, rescore, 100_000)
    }

    fn request_with_progress(pe: bool, rescore: bool, progress_every: u64) -> AttackRequest {
        let mut value = json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "custom", "value": {
                "alphabet": ["A", "B", "C", "D"],
                "wheels": [{"name": "r", "wiring": ["A", "B", "C", "D"], "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
                "stepping": {"rules": []}
            }}},
            "job": {
                "kind": "search", "text": "AA", "measures": ["ic"], "passes": ["hill_climb"],
                "configuration": {"slots": [{"id": "r", "position": "A", "ring": "A"}], "plugboard": []},
                "space": {"plugboard": {"kind": "attack", "symbols": ["A", "B"], "max_pairs": 1}},
                "attack": {"kind": "hill_climb", "initial_measure": "ic", "final_measure": "ic",
                    "switch_pairs": 1, "backtrack_pairs": 1, "progress_every": progress_every, "start": []}
            }
        });
        if pe {
            value["job"]["passes"] = json!(["partial_exhaustion"]);
            let attack = value["job"]["attack"].as_object_mut().unwrap();
            attack.insert("kind".into(), json!("partial_exhaustion"));
            attack.remove("start");
            attack.insert(
                "seeds".into(),
                json!({"kind": "empty_single", "selection": "all"}),
            );
        }
        if rescore {
            value["job"]["measures"] = json!(["ic", "entropy"]);
            value["job"]["attack"]["final_measure"] = json!("entropy");
        }
        AttackRequest::parse_json(&value.to_string()).unwrap()
    }

    fn snapshot() -> AttackProgress {
        request(false).run(|_| {}, || false).unwrap().counters()
    }

    fn lines(bytes: &[u8]) -> Vec<Value> {
        std::str::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// Faults are injected only at the writer boundary, not into Core.
    #[derive(Default)]
    struct Writer {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
        fail_event: Option<&'static str>,
        fail_occurrence: usize,
        matches: usize,
        flush_failure: bool,
        partial: bool,
        pending_failure: bool,
        failed: bool,
        attempts_after_failure: usize,
    }

    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.failed {
                self.attempts_after_failure += 1;
                return Err(io::Error::other("later write"));
            }
            if self.pending_failure {
                self.failed = true;
                return Err(io::Error::other("injected partial write failure"));
            }
            let event: Value = serde_json::from_slice(bytes).unwrap();
            let matched = self.fail_event.is_some_and(|name| event["event"] == name);
            let hit = matched && self.matches == self.fail_occurrence;
            self.matches += usize::from(matched);
            if hit && !self.flush_failure {
                if self.partial {
                    let length = bytes.len() / 2;
                    self.bytes.extend_from_slice(&bytes[..length]);
                    self.pending_failure = true;
                    return Ok(length);
                }
                self.failed = true;
                return Err(io::Error::other("injected write failure"));
            }
            self.bytes.extend_from_slice(bytes);
            self.pending_failure = hit;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.failed {
                self.attempts_after_failure += 1;
            }
            if self.pending_failure {
                self.failed = true;
                return Err(io::Error::other("injected flush failure"));
            }
            Ok(())
        }
    }

    #[test]
    fn real_hc_pe_lifecycle_and_wall_clock_independence() {
        for pe in [false, true] {
            let request = request(pe);
            let expected = request.run(|_| {}, || false).unwrap();
            let mut writer = Writer::default();
            let wall = Cell::new(0);
            run(
                &request,
                &mut writer,
                || Duration::from_secs(50),
                || {
                    wall.set(wall.get() + 1);
                    // Deliberately goes backwards; cadence never uses UTC.
                    format!("UTC-{}", 100 - wall.get())
                },
                || false,
            )
            .unwrap();
            let events = lines(&writer.bytes);
            assert_eq!(
                events
                    .iter()
                    .map(|event| event["event"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["started", "progress", "progress", "result", "done"]
            );
            assert_eq!(writer.flushes, events.len());
            for (index, event) in events.iter().enumerate() {
                assert_eq!(event["seq"], index + 1);
                assert_eq!(event["ts"], format!("UTC-{}", 99 - index));
            }
            assert_eq!(events[3]["elapsed_ms"], "0");
            assert_eq!(
                events[3]["counters"],
                serde_json::to_value(enigma_core::ProgressCounters::from(expected.counters()))
                    .unwrap()
            );
            assert_eq!(
                events[3],
                serde_json::from_str::<Value>(
                    &encode(&Event::result(&expected, 0), 4, "UTC-96").unwrap()
                )
                .unwrap()
            );
            assert_eq!(events[4]["reason"], "completed");
        }
    }

    #[test]
    fn core_grid_is_forwarded_exactly_with_one_clock_read_per_progress() {
        for pe in [false, true] {
            for every in [1, 3, 6, 100] {
                let request = request_with_progress(pe, false, every);
                let mut core = Vec::new();
                let expected = request.run(|p| core.push(p), || false).unwrap();
                let clock_calls = Cell::new(0u64);
                let mut output = Vec::new();
                run(
                    &request,
                    &mut output,
                    || {
                        clock_calls.set(clock_calls.get() + 1);
                        Duration::ZERO
                    },
                    || "UTC".into(),
                    || false,
                )
                .unwrap();
                let events = lines(&output);
                let progress: Vec<_> = events
                    .iter()
                    .filter(|event| event["event"] == "progress")
                    .collect();
                assert_eq!(progress.len(), core.len());
                for (wire, snapshot) in progress.iter().zip(&core) {
                    assert_eq!(
                        wire["counters"],
                        serde_json::to_value(enigma_core::ProgressCounters::from(*snapshot))
                            .unwrap()
                    );
                }
                assert_eq!(clock_calls.get(), core.len() as u64 + 2); // entry + result
                assert_eq!(events.first().unwrap()["event"], "started");
                assert_eq!(events[events.len() - 2]["event"], "result");
                assert_eq!(events.last().unwrap()["event"], "done");
                assert_eq!(
                    progress.last().unwrap()["counters"],
                    events[events.len() - 2]["counters"]
                );
                assert_eq!(core.last(), Some(&expected.counters()));
                if expected
                    .counters()
                    .evaluations_completed()
                    .is_multiple_of(every)
                {
                    assert_eq!(
                        core[core.len() - 2].evaluations_completed(),
                        core.last().unwrap().evaluations_completed()
                    );
                }
            }
        }
    }

    #[test]
    fn terminal_elapsed_is_measured_after_final_rescore() {
        let clock = Cell::new(0);
        let request = request_with_objectives(false, true);
        let polls = Cell::new(0);
        let mut output = Vec::new();
        run(
            &request,
            &mut output,
            || {
                let now = clock.get();
                clock.set(now + 17);
                Duration::from_millis(now)
            },
            || "UTC".into(),
            || {
                polls.set(polls.get() + 1);
                polls.get() == 3
            },
        )
        .unwrap();
        let events = lines(&output);
        let result = events
            .iter()
            .find(|event| event["event"] == "result")
            .unwrap();
        assert_eq!(result["elapsed_ms"], (clock.get() - 17).to_string());
        assert_eq!(events[events.len() - 3]["elapsed_ms"], "34");
        assert_eq!(clock.get(), 68); // entry, initial, terminal, result: no per-trial reads
        assert_eq!(result["counters"]["evaluations_completed"], "2");
        assert_eq!(result["best"]["score"]["measure"], "entropy");
        assert_eq!(events.last().unwrap()["reason"], "cancelled");
    }

    #[test]
    fn write_and_flush_failures_at_every_lifecycle_stage_latch() {
        // With the default Core cadence this small job emits initial and terminal
        // progress only; occurrence 1 faults terminal delivery separately.
        for (event, fail_occurrence) in [
            ("started", 0),
            ("progress", 0),
            ("progress", 1),
            ("result", 0),
            ("done", 0),
        ] {
            for flush_failure in [false, true] {
                let mut writer = Writer {
                    fail_event: Some(event),
                    fail_occurrence,
                    flush_failure,
                    ..Writer::default()
                };
                let failure = run(
                    &request(false),
                    &mut writer,
                    || Duration::ZERO,
                    || "UTC".into(),
                    || false,
                )
                .unwrap_err();
                assert!(
                    failure.transport.is_some(),
                    "{event}, flush={flush_failure}"
                );
                assert!(failure.runtime.is_none());
                assert!(failure.projection.is_none());
                assert_eq!(writer.attempts_after_failure, 0);
                let calls = writer.writes;
                assert!(calls > 0);
                if event == "started" || event == "progress" {
                    assert!(
                        !String::from_utf8_lossy(&writer.bytes).contains("\"event\":\"result\"")
                    );
                }
            }
        }
    }

    #[test]
    fn external_cancellation_after_entry_does_not_wait_for_cadence() {
        let mut output = Vec::new();
        let polls = Cell::new(0);
        run(
            &request(false),
            &mut output,
            || Duration::ZERO,
            || "UTC".into(),
            || {
                polls.set(polls.get() + 1);
                polls.get() == 2 // a one-poll pulse, not a persistent external flag
            },
        )
        .unwrap();
        let events = lines(&output);
        assert_eq!(events.last().unwrap()["reason"], "cancelled");
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"] == "progress")
                .count(),
            2
        );
        assert!(events
            .iter()
            .filter(|event| event["event"] == "progress")
            .all(|event| event["elapsed_ms"] == "0"));
    }

    #[test]
    fn partial_line_is_not_replayed_or_followed_by_more_attempts() {
        let mut writer = Writer {
            fail_event: Some("progress"),
            partial: true,
            ..Writer::default()
        };
        let failure = run(
            &request(true),
            &mut writer,
            || Duration::ZERO,
            || "UTC".into(),
            || false,
        )
        .unwrap_err();
        assert!(failure.transport.is_some());
        assert_eq!(writer.writes, 3); // started, partial progress, remaining bytes failure
        assert_eq!(writer.flushes, 1);
        assert_eq!(writer.attempts_after_failure, 0);
        assert!(!writer.bytes.ends_with(b"\n"));
    }

    #[test]
    fn cancellation_is_independent_of_cadence_and_retains_absent_best() {
        for pe in [false, true] {
            let mut output = Vec::new();
            let polls = Cell::new(0);
            run(
                &request(pe),
                &mut output,
                || Duration::ZERO,
                || "UTC".into(),
                || {
                    polls.set(polls.get() + 1);
                    true
                },
            )
            .unwrap();
            assert!(polls.get() > 0);
            let events = lines(&output);
            let result = events
                .iter()
                .find(|event| event["event"] == "result")
                .unwrap();
            assert!(result["best"].is_null());
            assert_eq!(result["counters"]["evaluations_admitted"], "0");
            assert_eq!(events.last().unwrap()["reason"], "cancelled");
        }
    }

    #[test]
    fn latched_transport_cancellation_permits_required_final_rescore() {
        // Fail the first completed-evaluation cadence delivery (X = 1).
        // Required finalization must still finish after cancellation is latched.
        struct FailAfterAdmission {
            last: Cell<u64>,
            writes: Cell<usize>,
        }
        impl Write for &FailAfterAdmission {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes.set(self.writes.get() + 1);
                let event: Value = serde_json::from_slice(bytes).unwrap();
                if event["counters"]["evaluations_admitted"] == "1" {
                    self.last.set(1);
                    return Err(io::Error::other("injected admitted-progress failure"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let writer = FailAfterAdmission {
            last: Cell::new(0),
            writes: Cell::new(0),
        };
        let clock = Cell::new(0);
        let failure = run(
            &request_with_progress(false, true, 1),
            &writer,
            || {
                let now = clock.get();
                clock.set(now + 250);
                Duration::from_millis(now)
            },
            || "UTC".into(),
            || false,
        )
        .unwrap_err();
        assert!(failure.transport.is_some());
        assert_eq!(writer.last.get(), 1);
        // No further progress clock reads or writes after delivery failure.
        assert_eq!(clock.get() / 250, 4); // entry, initial, failed cadence, result
        assert_eq!(writer.writes.get(), 3);

        // Real Core evidence: cancellation after completion still completes the required
        // initial/final evaluation and retains the committed winner, never a trial.
        let admitted = Cell::new(false);
        let result = request_with_progress(false, true, 1)
            .run(
                |progress| admitted.set(progress.evaluations_admitted() > 0),
                || admitted.get(),
            )
            .unwrap();
        assert_eq!(
            result.termination(),
            enigma_core::AttackTermination::Cancelled
        );
        assert_eq!(result.counters().evaluations_completed(), 2);
        assert!(result.best().is_some());
    }

    #[test]
    fn injected_runtime_terminal_preserves_primary_and_never_emits_done() {
        // The public owner has no constructor for synthetic Core failures. Inject the
        // already projected terminal pair at this private delivery seam, not into Core.
        for fail_event in [None, Some("result"), Some("error")] {
            for flush_failure in [false, true] {
                let mut writer = Writer {
                    fail_event,
                    flush_failure,
                    ..Writer::default()
                };
                let mut transport = Transport::new(&mut writer, || Duration::ZERO, || "UTC".into());
                transport.emit(Event::Started);
                let mut initial = None;
                let expected = request(false)
                    .run(
                        |p| {
                            initial.get_or_insert(p);
                        },
                        || false,
                    )
                    .unwrap();
                transport.observe(initial.unwrap());
                transport.observe(expected.counters()); // injected cadence snapshot
                transport.observe(expected.counters()); // terminal is not deduplicated
                let projected = Ok((
                    Event::result(&expected, 9),
                    Event::Error {
                        code: "internal_error".into(),
                        message: "injected runtime cause".into(),
                        location: "/job".into(),
                        expected: None,
                        hint: None,
                        context: None,
                    },
                ));
                let failure = transport
                    .finish(
                        projected,
                        Some(Box::new(io::Error::other("injected runtime cause"))),
                    )
                    .unwrap_err();
                assert_eq!(
                    failure.runtime.unwrap().to_string(),
                    "injected runtime cause"
                );
                assert_eq!(failure.transport.is_some(), fail_event.is_some());
                assert!(failure.projection.is_none());
                assert_eq!(writer.attempts_after_failure, 0);
                let events = lines(&writer.bytes);
                assert!(!events.iter().any(|event| event["event"] == "done"));
                if fail_event.is_none() {
                    assert_eq!(
                        events
                            .iter()
                            .map(|event| event["event"].as_str().unwrap())
                            .collect::<Vec<_>>(),
                        ["started", "progress", "progress", "progress", "result", "error"]
                    );
                    assert_eq!(events[2]["counters"], events[3]["counters"]);
                    assert_eq!(events[3]["counters"], events[4]["counters"]);
                }
            }
        }
    }

    #[test]
    fn injected_malformed_best_fails_closed_without_fabricated_null() {
        for fail_started in [false, true] {
            let mut writer = Writer {
                fail_event: fail_started.then_some("started"),
                ..Writer::default()
            };
            let mut transport = Transport::new(&mut writer, || Duration::ZERO, || "UTC".into());
            transport.emit(Event::Started);
            // Explicit injection of the fallible Core projection's Err arm.
            let failure = transport
                .finish(
                    Err("injected malformed best".into()),
                    Some(Box::new(io::Error::other("injected original cause"))),
                )
                .unwrap_err();
            assert_eq!(
                failure.runtime.unwrap().to_string(),
                "injected original cause"
            );
            assert_eq!(
                failure.projection.as_deref(),
                Some("injected malformed best")
            );
            assert_eq!(failure.transport.is_some(), fail_started);
            assert_eq!(writer.writes, 1);
            assert_eq!(writer.attempts_after_failure, 0);
            assert!(!String::from_utf8_lossy(&writer.bytes).contains("result"));
        }
    }

    #[test]
    fn forwarding_ignores_elapsed_gaps_and_keeps_duplicate_snapshots() {
        let clock = Cell::new(1000);
        let mut transport = Transport::new(
            Vec::new(),
            || Duration::from_millis(clock.get()),
            || "independent UTC".into(),
        );
        let progress = snapshot();
        for time in [1000, 1249, 1250, 1250, 1501] {
            clock.set(time);
            transport.observe(progress);
        }
        let events = lines(&transport.writer);
        assert_eq!(events.len(), 5);
        assert_eq!(
            events
                .iter()
                .map(|event| event["elapsed_ms"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["0", "249", "250", "250", "501"]
        );
    }
}
