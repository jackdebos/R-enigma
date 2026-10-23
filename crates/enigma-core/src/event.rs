//! Protocol event stream types (`docs/protocol.md` §4).
//!
//! This module is pure data plus pure helpers: it serializes the protocol events
//! and converts Unix timestamps to RFC 3339 UTC. It performs no I/O and reads no clock;
//! the transport supplies the timestamp. `protocol_version`, `seq`, and `ts` are added
//! to every encoded event so callers only choose the event payload and its position.

use serde::Serialize;
use serde_json::Value;

use crate::{
    AttackBest, AttackProgress, AttackResult, AttackRunCategory, AttackRunError, AttackTermination,
    PROTOCOL_VERSION,
};

/// Wire-only runtime failure facts; elapsed time belongs to the paired result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeContext {
    outer_index: Option<String>,
    start_index: Option<String>,
    evaluations_used: String,
    counters: ProgressCounters,
    source: RuntimeSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RuntimeSource {
    kind: &'static str,
    message: String,
    diagnostics: Vec<RuntimeDiagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RuntimeDiagnostic {
    code: &'static str,
    message: String,
    location: String,
}

/// Non-wire failure to project a retained best, preserving both independent causes.
#[derive(Debug)]
pub struct RuntimeProjectionError<'a> {
    original: &'a AttackRunError,
    best_projection: &'a (dyn std::error::Error + Send + Sync + 'static),
}

impl<'a> RuntimeProjectionError<'a> {
    /// Original runtime envelope, never replaced by a best-projection failure.
    pub fn original(&self) -> &'a AttackRunError {
        self.original
    }

    /// Separate retained-best projection cause, with its original identity.
    pub fn best_projection(&self) -> &'a (dyn std::error::Error + Send + Sync + 'static) {
        self.best_projection
    }
}

impl std::fmt::Display for RuntimeProjectionError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; retained best projection: {}",
            self.original, self.best_projection
        )
    }
}

impl std::error::Error for RuntimeProjectionError<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original)
    }
}

/// Wire-only factual counters, encoded as canonical unsigned decimal strings.
///
/// Constructed from an immutable runtime snapshot, without serializing runtime types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProgressCounters {
    evaluations_admitted: String,
    evaluations_completed: String,
    climbs_started: String,
    climbs_completed: String,
    outers_completed: String,
}

impl From<AttackProgress> for ProgressCounters {
    fn from(progress: AttackProgress) -> Self {
        Self {
            evaluations_admitted: progress.evaluations_admitted().to_string(),
            evaluations_completed: progress.evaluations_completed().to_string(),
            climbs_started: progress.climbs_started().to_string(),
            climbs_completed: progress.climbs_completed().to_string(),
            outers_completed: progress.outers_completed().to_string(),
        }
    }
}

/// Wire-only committed winner, projected without changing runtime ordering or scores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BestResult {
    configuration: WinningConfiguration,
    mutable_plugboard: Vec<(char, char)>,
    plaintext: String,
    score: WinningScore,
    outer_index: String,
    start_index: String,
    incomplete: bool,
    final_objective_ascent: bool,
    neighborhood_exhausted: bool,
}

/// Wire-only finalist with the same nine winner fields and its own history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HoldResult {
    #[serde(flatten)]
    best: BestResult,
    stages: Vec<StageResult>,
}

impl From<crate::AttackHoldEntry<'_>> for HoldResult {
    fn from(entry: crate::AttackHoldEntry<'_>) -> Self {
        Self {
            best: BestResult::from(entry.best()),
            stages: entry.stages().iter().map(StageResult::from).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct WinningConfiguration {
    slots: Vec<WinningSlot>,
    plugboard: Vec<(char, char)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct WinningSlot {
    id: String,
    wheel: String,
    position: char,
    ring: char,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct WinningScore {
    measure: String,
    measured_q32: String,
    ranking_q32: String,
}

/// Wire-only history entry for one admitted chained stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StageResult {
    pass: &'static str,
    measure: &'static str,
    base_measure: Option<&'static str>,
    score: Option<WinningScore>,
    evaluations_used: String,
    completed: bool,
}

impl From<&crate::AttackStageResult> for StageResult {
    fn from(stage: &crate::AttackStageResult) -> Self {
        Self {
            pass: stage.pass(),
            measure: stage.measure().id(),
            base_measure: stage.base_measure().map(crate::MeasureId::id),
            score: stage.score().map(|score| WinningScore {
                measure: stage.measure().id().to_owned(),
                measured_q32: score.measured().units().to_string(),
                ranking_q32: score.ranking().units().to_string(),
            }),
            evaluations_used: stage.evaluations_used().to_string(),
            completed: stage.completed(),
        }
    }
}

impl From<&AttackBest> for BestResult {
    fn from(best: &AttackBest) -> Self {
        let configuration = best.configuration();
        Self {
            configuration: WinningConfiguration {
                slots: configuration
                    .slots()
                    .iter()
                    .map(|slot| WinningSlot {
                        id: slot.id().to_owned(),
                        wheel: slot.wheel().to_owned(),
                        position: slot.position(),
                        ring: slot.ring(),
                    })
                    .collect(),
                plugboard: configuration.plugboard().to_vec(),
            },
            mutable_plugboard: best.mutable_plugboard().to_vec(),
            plaintext: best.plaintext().to_owned(),
            score: WinningScore {
                measure: best.measure().id().to_owned(),
                measured_q32: best.score().measured().units().to_string(),
                ranking_q32: best.score().ranking().units().to_string(),
            },
            outer_index: best.outer_index().to_string(),
            start_index: best.start_index().to_string(),
            incomplete: best.incomplete(),
            final_objective_ascent: best.final_objective_ascent(),
            neighborhood_exhausted: best.neighborhood_exhausted(),
        }
    }
}

/// A single protocol event, tagged in JSON by `event` in `snake_case`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Emitted once, first, after validation succeeded and before any work.
    Started,
    /// Emitted after `started` carrying the transformed text for a `transform` job.
    Output {
        /// The transformed text.
        output: String,
    },
    /// A factual search snapshot with caller-supplied elapsed milliseconds.
    Progress {
        /// All five factual counters, distinct from charged allowance usage.
        counters: ProgressCounters,
        /// Canonical unsigned decimal milliseconds; no clock is read here.
        elapsed_ms: String,
    },
    /// Final committed search winner and factual whole-run snapshot.
    Result {
        /// Final ordered finalists; empty only when no winner is retained.
        hold: Vec<HoldResult>,
        /// Started stages in pipeline order, including on runtime failure.
        stages: Vec<StageResult>,
        /// Null only when the runtime result genuinely has no winner.
        best: Option<Box<BestResult>>,
        /// All five factual counters, not charged allowance usage.
        counters: ProgressCounters,
        /// Caller-supplied canonical unsigned decimal milliseconds.
        elapsed_ms: String,
    },
    /// The single terminal lifecycle event of a successful job.
    Done {
        /// Why the job stopped.
        reason: DoneReason,
    },
    /// A terminal failure. `expected` and `hint` are omitted when `None`.
    Error {
        /// Stable machine-readable diagnostic code.
        code: String,
        /// Actionable explanation of the failure.
        message: String,
        /// Request-relative JSON Pointer to the invalid value.
        location: String,
        /// Optional description of what was expected instead.
        #[serde(skip_serializing_if = "Option::is_none")]
        expected: Option<String>,
        /// Optional actionable remediation hint.
        #[serde(skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
        /// Optional runtime facts, omitted for legacy validation/transport errors.
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<Box<RuntimeContext>>,
    },
}

/// Why a job emitted its terminal `done` event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoneReason {
    /// The job ran to completion.
    Completed,
    /// The requested outer slice was empty.
    OuterSliceEnd,
    /// Cooperative cancellation stopped remaining work.
    Cancelled,
}

impl From<AttackTermination> for DoneReason {
    fn from(termination: AttackTermination) -> Self {
        match termination {
            AttackTermination::Completed => Self::Completed,
            AttackTermination::OuterSliceEnd => Self::OuterSliceEnd,
            AttackTermination::Cancelled => Self::Cancelled,
        }
    }
}

impl Event {
    /// Projects an owned runtime result without clocks, I/O or execution orchestration.
    pub fn result(result: &AttackResult, elapsed_ms: u128) -> Self {
        Self::result_snapshot(
            result.best(),
            result.counters(),
            result.stages(),
            result.hold().map(HoldResult::from).collect(),
            elapsed_ms,
        )
    }

    fn result_snapshot(
        best: Option<&AttackBest>,
        counters: AttackProgress,
        stages: &[crate::AttackStageResult],
        hold: Vec<HoldResult>,
        elapsed_ms: u128,
    ) -> Self {
        Self::Result {
            hold,
            stages: stages.iter().map(StageResult::from).collect(),
            best: best.map(|best| Box::new(BestResult::from(best))),
            counters: counters.into(),
            elapsed_ms: elapsed_ms.to_string(),
        }
    }

    /// Projects a borrowed runtime failure as `(result, terminal error)`.
    ///
    /// A malformed retained best fails closed; only genuine absence becomes null.
    /// Delivery and elapsed measurement remain the caller's responsibility.
    pub fn runtime_error(
        error: &AttackRunError,
        elapsed_ms: u128,
    ) -> Result<(Self, Self), RuntimeProjectionError<'_>> {
        let hold: Vec<_> = error
            .hold()
            .map_err(|best_projection| RuntimeProjectionError {
                original: error,
                best_projection,
            })?
            .map(HoldResult::from)
            .collect();
        let best = error.best().expect("hold validated best projection");
        let source = error.run_source();
        let diagnostics: Vec<_> = source
            .diagnostics()
            .unwrap_or_default()
            .iter()
            .map(|diagnostic| RuntimeDiagnostic {
                code: diagnostic.code(),
                message: diagnostic.message().to_owned(),
                location: diagnostic.location().to_owned(),
            })
            .collect();
        let location = diagnostics
            .first()
            .map_or("/job", |diagnostic| diagnostic.location.as_str())
            .to_owned();
        let message = source.to_string();
        let context = RuntimeContext {
            outer_index: error.outer_index().map(|index| index.to_string()),
            start_index: error.start_index().map(|index| index.to_string()),
            evaluations_used: error.evaluations_used().to_string(),
            counters: error.counters().into(),
            source: RuntimeSource {
                kind: match source.category() {
                    AttackRunCategory::Resolution => "resolution",
                    AttackRunCategory::Evaluation => "evaluation",
                    AttackRunCategory::Counter => "counter",
                    AttackRunCategory::Invariant | AttackRunCategory::UnsupportedExecution => {
                        "invariant"
                    }
                },
                message: message.clone(),
                diagnostics,
            },
        };
        Ok((
            Self::result_snapshot(best, error.counters(), error.stages(), hold, elapsed_ms),
            Self::Error {
                code: "internal_error".to_owned(),
                message,
                location,
                expected: None,
                hint: None,
                context: Some(Box::new(context)),
            },
        ))
    }

    /// Projects a runtime snapshot and elapsed whole milliseconds into wire data.
    ///
    /// The caller measures elapsed time; this helper reads no clock, schedules no
    /// work, and does not infer timing from the envelope timestamp.
    pub fn progress(progress: AttackProgress, elapsed_ms: u128) -> Self {
        Self::Progress {
            counters: progress.into(),
            elapsed_ms: elapsed_ms.to_string(),
        }
    }
}

/// Serializes `event` as one JSON object with `protocol_version`, `seq`, and `ts`.
///
/// JSON member order is not significant. The caller supplies the timestamp so this
/// function stays pure and free of clock side effects.
pub fn encode(event: &Event, seq: u64, ts: &str) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(event)?;
    let object = value
        .as_object_mut()
        .expect("a protocol event always serializes to a JSON object");
    object.insert("protocol_version".to_owned(), Value::from(PROTOCOL_VERSION));
    object.insert("seq".to_owned(), Value::from(seq));
    object.insert("ts".to_owned(), Value::from(ts));
    serde_json::to_string(&value)
}

/// Converts a Unix timestamp in seconds to `YYYY-MM-DDTHH:MM:SSZ` (RFC 3339 UTC).
///
/// Uses the proleptic Gregorian calendar with no external dependency. Handles the epoch,
/// pre-epoch values, and dates far in the future.
pub fn rfc3339_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts a count of days since 1970-01-01 to a civil `(year, month, day)`.
///
/// This is Howard Hinnant's `civil_from_days` algorithm, valid for the proleptic
/// Gregorian calendar. Integer division here truncates toward zero, which the era
/// correction accounts for, so pre-epoch days convert correctly.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146_096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::{encode, rfc3339_utc, DoneReason, Event};
    use serde_json::{json, Value};

    use crate::attack_control::CounterSnapshot;
    use crate::{AttackProgress, AttackTermination};

    const TS: &str = "2023-11-14T22:13:20Z";

    fn encoded(event: &Event) -> Value {
        serde_json::from_str(&encode(event, 7, TS).expect("encode succeeds"))
            .expect("encode emits valid JSON")
    }

    fn result_fixture_value(pe: bool, offset: u64) -> Value {
        let alphabet = ["🦀", "é", "Ω", "中"];
        let mut value = json!({
            "protocol_version": 1, "machine": {"definition": {"kind": "custom", "value": {
                "alphabet": alphabet, "wheels": [{"name": "r", "wiring": alphabet, "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
                "stepping": {"rules": []}
            }}}, "job": {
                "kind": "search", "configuration": {"slots": [{"id": "r", "position": "é", "ring": "Ω"}],
                    "plugboard": [["中", "é"]]}, "text": "🦀🦀", "measures": ["ic"], "passes": ["hill_climb"],
                "space": {"offset": offset, "plugboard": {"kind": "attack", "symbols": ["🦀", "Ω"], "max_pairs": 2}},
                "attack": {"kind": "hill_climb", "initial_measure": "ic", "final_measure": "ic",
                    "switch_pairs": 2, "backtrack_pairs": 2, "start": [["Ω", "🦀"]]}
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
        value
    }

    fn result_fixture(pe: bool, offset: u64) -> crate::AttackResult {
        crate::AttackRequest::parse_json(&result_fixture_value(pe, offset).to_string())
            .unwrap()
            .run(|_| {}, || false)
            .unwrap()
    }

    // Public winners below are real runs; their failure envelopes are injected,
    // not evidence that validated public requests naturally fail.
    fn assert_runtime_winner_projection(result: crate::AttackResult) {
        use crate::attack_result::{AttackRunErrorData, AttackRunSource, RunPayload};
        let expected = encoded(&Event::result(&result, u128::MAX));
        let error = crate::AttackRunError::new(AttackRunErrorData {
            held_tail: result.held_tail,
            stages: result.stages,
            source: AttackRunSource(RunPayload::Invariant("injected after accepted winner")),
            outer_index: Some(u128::MAX),
            start_index: None,
            evaluations_used: result.evaluations_used,
            counters: result.counters,
            best: Ok(result.best),
        });
        let (projected, terminal) = Event::runtime_error(&error, u128::MAX).unwrap();
        assert_eq!(encoded(&projected), expected);
        assert_eq!(encoded(&terminal)["context"]["source"]["kind"], "invariant");
    }

    #[test]
    fn error_hold_borrows_and_projects_all_retained_histories() {
        use crate::attack_result::{AttackRunErrorData, AttackRunSource, RunPayload};
        // Inject a post-rerank error envelope; this is not a naturally failing request.
        let mut result = result_fixture(false, 0);
        for (index, completed) in [(7, true), (3, false)] {
            let mut entry = result_fixture(false, 0).best.take().unwrap();
            entry.outer_index = index;
            entry.start_index = index + 1;
            entry.stages.push(crate::AttackStageResult {
                pass: "measure",
                measure: crate::MeasureId::Ic,
                base_measure: None,
                score: Some(entry.score()),
                evaluations_used: index as u64,
                completed,
            });
            result.held_tail.push(entry);
        }
        result.stages = result.held_tail[0].stages.clone();
        result.stages[0].evaluations_used = 1;
        let expected = encoded(&Event::result(&result, 29));
        let error = crate::AttackRunError::new(AttackRunErrorData {
            held_tail: result.held_tail,
            stages: result.stages,
            source: AttackRunSource(RunPayload::Invariant("injected stage failure")),
            outer_index: Some(3),
            start_index: Some(4),
            evaluations_used: 11,
            counters: result.counters,
            best: Ok(result.best),
        });
        let entries: Vec<_> = error.hold().unwrap().collect();
        assert_eq!(entries.len(), 3);
        assert!(std::ptr::eq(
            entries[0].best(),
            error.best().unwrap().unwrap()
        ));
        assert!(std::ptr::eq(entries[0].stages(), error.stages()));
        for (view, owned) in entries[1..].iter().zip(error.held_tail()) {
            assert!(std::ptr::eq(view.best(), owned));
            assert!(std::ptr::eq(
                view.best().plaintext().as_ptr(),
                owned.plaintext().as_ptr()
            ));
            assert!(std::ptr::eq(view.stages(), owned.stages.as_slice()));
        }
        let (projected, terminal) = Event::runtime_error(&error, 29).unwrap();
        let wire = encoded(&projected);
        assert_eq!(wire, expected);
        assert_eq!(wire["hold"][0]["stages"], wire["stages"]);
        assert_ne!(wire["hold"][0]["stages"], wire["hold"][1]["stages"]);
        assert_ne!(wire["hold"][1]["stages"], wire["hold"][2]["stages"]);
        for entry in wire["hold"].as_array().unwrap() {
            assert_eq!(entry.as_object().unwrap().len(), 10);
        }
        let mut head = wire["hold"][0].clone();
        head.as_object_mut().unwrap().remove("stages");
        assert_eq!(head, wire["best"]);
        let context = encoded(&terminal)["context"].clone();
        assert_eq!(context["outer_index"], "3");
        assert_eq!(context["start_index"], "4");
        assert_ne!(context["outer_index"], wire["best"]["outer_index"]);
        assert_eq!(context["evaluations_used"], "11");
        assert_eq!(context["counters"], wire["counters"]);
        assert_eq!(context["source"]["message"], "injected stage failure");
    }

    #[test]
    fn success_hold_projects_every_entry_and_its_own_history() {
        let mut result = result_fixture(false, 0);
        let mut tail = result_fixture(false, 0).best.take().unwrap();
        tail.outer_index = 7;
        tail.stages.push(crate::AttackStageResult {
            pass: "measure",
            measure: crate::MeasureId::Ic,
            base_measure: None,
            score: Some(tail.score()),
            evaluations_used: 3,
            completed: false,
        });
        result.held_tail.push(tail);
        let wire = encoded(&Event::result(&result, 0));
        let hold = wire["hold"].as_array().expect("success hold array");
        assert_eq!(hold.len(), 2);
        for (entry, best) in hold
            .iter()
            .zip(result.best.iter().chain(result.held_tail.iter()))
        {
            let mut expected = serde_json::to_value(super::BestResult::from(best)).unwrap();
            expected["stages"] = if best.outer_index() == 7 {
                json!([super::StageResult::from(&best.stages[0])])
            } else {
                wire["stages"].clone()
            };
            assert_eq!(entry, &expected);
            assert_eq!(entry.as_object().unwrap().len(), 10);
        }
        assert_eq!(hold[0]["stages"], json!([]));
        assert_eq!(hold[1]["stages"][0]["evaluations_used"], "3");
        assert_eq!(hold[1]["stages"][0]["completed"], false);
        let mut head = hold[0].clone();
        head.as_object_mut().unwrap().remove("stages");
        assert_eq!(head, wire["best"]);
    }

    #[test]
    fn result_public_pe_nonempty_unicode_winner() {
        let mut value = result_fixture_value(true, 0);
        value["machine"]["definition"]["value"]["wheels"][0]["wiring"] =
            json!(["é", "🦀", "Ω", "中"]);
        value["job"]["measures"] = json!(["ic", "trie"]);
        value["job"]["attack"]["final_measure"] = json!("trie");
        value["job"]["resources"] = json!({"trie": {"path": "dictionary.json"}});
        let dictionary = json!({"resource_version": 1, "kind": "dictionary",
            "alphabet": ["🦀", "é", "Ω", "中"],
            "entries": [{"word": ["中", "中"], "weight": 1}]})
        .to_string();
        let supplied = std::collections::BTreeMap::from([("trie".to_owned(), dictionary.as_str())]);
        let result = crate::ParsedAttackRequest::parse_json(&value.to_string())
            .unwrap()
            .bind_resources(&supplied)
            .unwrap()
            .run(|_| {}, || false)
            .unwrap();
        let wire = encoded(&Event::result(&result, 0));
        let best = result.best().unwrap();
        assert_eq!(best.mutable_plugboard(), &[('🦀', 'Ω')]);
        assert_eq!(
            wire["best"]["configuration"]["plugboard"],
            json!([["🦀", "Ω"], ["é", "中"]])
        );
        assert_eq!(wire["best"]["mutable_plugboard"], json!([["🦀", "Ω"]]));
        assert_eq!(wire["best"]["plaintext"], "中中");
        assert_eq!(
            wire["best"]["score"],
            json!({"measure": "trie",
            "measured_q32": "4294967296", "ranking_q32": "4294967296"})
        );
        assert_eq!(wire["best"]["start_index"], best.start_index().to_string());
        assert_eq!(
            wire["best"]["score"]["ranking_q32"],
            best.score().ranking().units().to_string()
        );
        assert_runtime_winner_projection(result);
    }

    #[test]
    fn result_public_entropy_keeps_initial_moving_slots_in_definition_order() {
        let mut value = result_fixture_value(false, 0);
        value["machine"]["definition"]["value"]["slots"] = json!([
            {"id": "z", "role": "rotor", "movement": "movable", "wheel": "r"},
            {"id": "a", "role": "rotor", "movement": "fixed", "wheel": "r"}
        ]);
        value["machine"]["definition"]["value"]["stepping"] =
            json!({"rules": [{"when": {"always": true}, "advance": ["z"]}]});
        let slots = json!([
            {"id": "z", "wheel": "r", "position": "é", "ring": "Ω"},
            {"id": "a", "wheel": "r", "position": "中", "ring": "🦀"}
        ]);
        value["job"]["configuration"]["slots"] = slots.clone();
        value["job"]["text"] = json!("🦀é");
        value["job"]["measures"] = json!(["ic", "entropy"]);
        value["job"]["attack"]["final_measure"] = json!("entropy");
        let result = crate::AttackRequest::parse_json(&value.to_string())
            .unwrap()
            .run(|_| {}, || false)
            .unwrap();
        let wire = encoded(&Event::result(&result, 0));
        let best = result.best().unwrap();
        assert_eq!(wire["best"]["configuration"]["slots"], slots);
        assert_eq!(wire["best"]["plaintext"], "🦀é");
        assert_eq!(
            wire["best"]["score"],
            json!({"measure": "entropy",
            "measured_q32": "4294967296", "ranking_q32": "-4294967296"})
        );
        assert_eq!(
            wire["best"]["score"]["measured_q32"],
            best.score().measured().units().to_string()
        );
        assert_eq!(
            wire["best"]["score"]["ranking_q32"],
            best.score().ranking().units().to_string()
        );
        // Two pre-keypress advances leave z at 中, not its initial é; identity wiring
        // keeps plaintext stable but cannot hide a stepped-position projection bug.
        assert_ne!(wire["best"]["configuration"]["slots"][0]["position"], "中");
        assert_runtime_winner_projection(result);
    }

    #[test]
    fn result_preserves_winning_key() {
        for pe in [false, true] {
            let result = result_fixture(pe, 0);
            let best = result.best().unwrap();
            let slots: Vec<Value> = best
                .configuration()
                .slots()
                .iter()
                .map(|slot| {
                    json!({"id": slot.id(), "wheel": slot.wheel(),
                    "position": slot.position(), "ring": slot.ring()})
                })
                .collect();
            assert_eq!(
                encoded(&Event::result(&result, 23)),
                json!({
                    "event": "result", "stages": [],
                    "hold": result.hold().map(super::HoldResult::from).collect::<Vec<_>>(),
                    "best": {
                        "configuration": {"slots": slots, "plugboard": best.configuration().plugboard()},
                        "mutable_plugboard": best.mutable_plugboard(), "plaintext": best.plaintext(),
                        "score": {"measure": best.measure().id(),
                            "measured_q32": best.score().measured().units().to_string(),
                            "ranking_q32": best.score().ranking().units().to_string()},
                        "outer_index": best.outer_index().to_string(), "start_index": best.start_index().to_string(),
                        "incomplete": best.incomplete(), "final_objective_ascent": best.final_objective_ascent(),
                        "neighborhood_exhausted": best.neighborhood_exhausted()
                    }, "counters": super::ProgressCounters::from(result.counters()),
                    "elapsed_ms": "23", "protocol_version": 1, "seq": 7, "ts": TS
                })
            );
            assert_eq!(
                slots,
                json!([{"id": "r", "wheel": "r", "position": "é", "ring": "Ω"}])
                    .as_array()
                    .unwrap()
                    .clone()
            );
            assert_eq!(
                best.configuration().plugboard()[0],
                if pe { ('é', '中') } else { ('🦀', 'Ω') }
            );
        }
    }

    #[test]
    fn result_empty_slice_is_genuine_null() {
        for pe in [false, true] {
            let result = result_fixture(pe, 1);
            assert_eq!(result.termination(), AttackTermination::OuterSliceEnd);
            assert!(result.best().is_none());
            let value = encoded(&Event::result(&result, 0));
            assert_eq!(value["best"], Value::Null);
            assert_eq!(value["elapsed_ms"], "0");
            assert_eq!(
                value["counters"],
                encoded(&Event::progress(result.counters(), 0))["counters"]
            );
            assert_eq!(value["stages"], json!([]));
            assert_eq!(value["hold"], json!([]));
            assert_eq!(value.as_object().unwrap().len(), 9);
        }
    }

    #[test]
    fn stage_history_projects_exact_fields_on_success_and_runtime_error() {
        // Synthetic history proves the future carrier, not stage execution support.
        use crate::attack_result::{AttackRunErrorData, AttackRunSource, RunPayload};
        let mut result = result_fixture(false, 0);
        result.stages.push(crate::AttackStageResult {
            pass: "trie",
            measure: crate::MeasureId::Trie,
            base_measure: Some(crate::MeasureId::Entropy),
            score: Some(result.best().unwrap().score()),
            evaluations_used: u64::MAX,
            completed: true,
        });
        result.stages.push(crate::AttackStageResult {
            pass: "measure",
            measure: crate::MeasureId::Ic,
            base_measure: None,
            score: None,
            evaluations_used: 1,
            completed: false,
        });
        let score = result.best().unwrap().score();
        let expected = json!([
            {"pass":"trie","measure":"trie","base_measure":"entropy",
             "score":{"measure":"trie","measured_q32":score.measured().units().to_string(),
                      "ranking_q32":score.ranking().units().to_string()},
             "evaluations_used":u64::MAX.to_string(),"completed":true},
            {"pass":"measure","measure":"ic","base_measure":null,"score":null,
             "evaluations_used":"1","completed":false}
        ]);
        assert_eq!(encoded(&Event::result(&result, 0))["stages"], expected);
        let error = crate::AttackRunError::new(AttackRunErrorData {
            held_tail: Vec::new(),
            stages: result.stages,
            source: AttackRunSource(RunPayload::Invariant("injected")),
            outer_index: None,
            start_index: None,
            evaluations_used: 1,
            counters: result.counters,
            best: Ok(result.best),
        });
        assert_eq!(error.stages().len(), 2);
        let (projected, _) = Event::runtime_error(&error, 0).unwrap();
        assert_eq!(encoded(&projected)["stages"], expected);
        assert_eq!(encoded(&projected)["hold"][0]["stages"], expected);
    }

    #[test]
    fn result_synthetic_scores_indices_and_independent_flags() {
        // Owned synthetic carriers prove schema, not runtime reachability of extrema or flags.
        let mut result = result_fixture(false, 0);
        for units in [i128::MIN, -1, 0, i128::MAX] {
            result.best.as_mut().unwrap().score =
                crate::MeasuredScore::higher_is_better(crate::FixedScore::from_units(units));
            let value = encoded(&Event::result(&result, 0));
            assert_eq!(value["best"]["score"]["measured_q32"], units.to_string());
            assert_eq!(value["best"]["score"]["ranking_q32"], units.to_string());
        }
        let alphabet = crate::Alphabet::new("🦀éΩ中".chars().collect()).unwrap();
        let entropy = crate::shannon_entropy(&alphabet, "🦀é").unwrap();
        assert_ne!(entropy.measured(), entropy.ranking());
        for mask in 0..8 {
            let best = result.best.as_mut().unwrap();
            best.score = entropy;
            best.measure = crate::MeasureId::Entropy;
            best.outer_index = u128::MAX;
            best.start_index = u128::MAX;
            best.incomplete = mask & 1 != 0;
            best.final_objective_ascent = mask & 2 != 0;
            best.neighborhood_exhausted = mask & 4 != 0;
            let value = encoded(&Event::result(&result, u128::MAX));
            let best = result.best().unwrap();
            assert_eq!(value["elapsed_ms"], u128::MAX.to_string());
            let wire = &value["best"];
            assert_eq!(wire["outer_index"], u128::MAX.to_string());
            assert_eq!(wire["start_index"], u128::MAX.to_string());
            assert_eq!(
                wire["score"],
                json!({"measure": best.measure().id(),
                "measured_q32": entropy.measured().units().to_string(),
                "ranking_q32": entropy.ranking().units().to_string()})
            );
            assert_eq!(wire["incomplete"], mask & 1 != 0);
            assert_eq!(wire["final_objective_ascent"], mask & 2 != 0);
            assert_eq!(wire["neighborhood_exhausted"], mask & 4 != 0);
        }
    }

    #[test]
    fn progress_uses_decimal_strings() {
        // Synthetic snapshot: schema evidence, not a full-width runtime execution.
        let progress = AttackProgress(CounterSnapshot {
            evaluations_admitted: 17,
            evaluations_completed: 13,
            climbs_started: 11,
            climbs_completed: 7,
            outers_completed: 3,
        });
        assert_eq!(
            encoded(&Event::progress(progress, 23)),
            json!({
                "event": "progress",
                "counters": {
                    "evaluations_admitted": "17",
                    "evaluations_completed": "13",
                    "climbs_started": "11",
                    "climbs_completed": "7",
                    "outers_completed": "3"
                },
                "elapsed_ms": "23",
                "protocol_version": 1,
                "seq": 7,
                "ts": TS
            })
        );
        assert_eq!(progress.evaluations_completed(), 13);
    }

    #[test]
    fn progress_preserves_zero_and_full_width_values() {
        for (evaluations, climbs, elapsed) in [(0, 0, 0), (u64::MAX, u128::MAX, u128::MAX)] {
            let progress = AttackProgress(CounterSnapshot {
                evaluations_admitted: evaluations,
                evaluations_completed: evaluations,
                climbs_started: climbs,
                climbs_completed: climbs,
                outers_completed: climbs,
            });
            let event = Event::progress(progress, elapsed);
            let timestamp = "caller timestamp unchanged";
            let value: Value =
                serde_json::from_str(&encode(&event, u64::MAX, timestamp).unwrap()).unwrap();
            assert_eq!(value["protocol_version"], json!(1));
            assert_eq!(value["seq"], json!(u64::MAX));
            assert_eq!(value["ts"], timestamp);
            assert_eq!(value["elapsed_ms"], elapsed.to_string());
            let counters = value["counters"].as_object().unwrap();
            assert_eq!(counters.len(), 5);
            for field in ["evaluations_admitted", "evaluations_completed"] {
                assert_eq!(counters[field], evaluations.to_string());
            }
            for field in ["climbs_started", "climbs_completed", "outers_completed"] {
                assert_eq!(counters[field], climbs.to_string());
            }
            assert_eq!(value.as_object().unwrap().len(), 6);
        }
    }

    #[test]
    fn all_attack_terminations_map_to_exact_done_reasons() {
        for (termination, reason, wire) in [
            (
                AttackTermination::Completed,
                DoneReason::Completed,
                "completed",
            ),
            (
                AttackTermination::OuterSliceEnd,
                DoneReason::OuterSliceEnd,
                "outer_slice_end",
            ),
            (
                AttackTermination::Cancelled,
                DoneReason::Cancelled,
                "cancelled",
            ),
        ] {
            let mapped = DoneReason::from(termination);
            assert_eq!(mapped, reason);
            assert_eq!(
                encoded(&Event::Done { reason: mapped }),
                json!({
                    "event": "done",
                    "reason": wire,
                    "protocol_version": 1,
                    "seq": 7,
                    "ts": TS
                })
            );
        }
    }

    #[test]
    fn encodes_started_with_envelope() {
        assert_eq!(
            encoded(&Event::Started),
            json!({
                "event": "started",
                "protocol_version": 1,
                "seq": 7,
                "ts": TS
            })
        );
    }

    #[test]
    fn encodes_output() {
        assert_eq!(
            encoded(&Event::Output {
                output: "BDZG".to_owned()
            }),
            json!({
                "event": "output",
                "output": "BDZG",
                "protocol_version": 1,
                "seq": 7,
                "ts": TS
            })
        );
    }

    #[test]
    fn encodes_done_completed() {
        assert_eq!(
            encoded(&Event::Done {
                reason: DoneReason::Completed
            }),
            json!({
                "event": "done",
                "reason": "completed",
                "protocol_version": 1,
                "seq": 7,
                "ts": TS
            })
        );
    }

    #[test]
    fn encodes_error_without_optional_fields() {
        let value = encoded(&Event::Error {
            code: "invalid_request".to_owned(),
            message: "direction is not supported".to_owned(),
            location: "/job/direction".to_owned(),
            expected: None,
            hint: None,
            context: None,
        });
        assert_eq!(
            value,
            json!({
                "event": "error",
                "code": "invalid_request",
                "message": "direction is not supported",
                "location": "/job/direction",
                "protocol_version": 1,
                "seq": 7,
                "ts": TS
            })
        );
        assert!(value.get("expected").is_none());
        assert!(value.get("hint").is_none());
    }

    #[test]
    fn encodes_error_with_optional_fields() {
        assert_eq!(
            encoded(&Event::Error {
                code: "invalid_request".to_owned(),
                message: "direction is not supported".to_owned(),
                location: "/job/direction".to_owned(),
                expected: Some("encrypt or decrypt".to_owned()),
                hint: Some("pick a direction".to_owned()),
                context: None,
            }),
            json!({
                "event": "error",
                "code": "invalid_request",
                "message": "direction is not supported",
                "location": "/job/direction",
                "expected": "encrypt or decrypt",
                "hint": "pick a direction",
                "protocol_version": 1,
                "seq": 7,
                "ts": TS
            })
        );
    }

    fn runtime_causes() -> Vec<crate::attack_result::RunPayload> {
        use crate::attack_control::CounterOverflow::*;
        use crate::attack_evaluator::{TrialBoardError, TrialEvaluationError as Trial};
        use crate::attack_result::RunPayload::*;
        use crate::{MeasureError, ModelError, ScoreError, SearchDiagnostic};
        vec![
            Resolution(vec![]),
            Resolution(vec![SearchDiagnostic::new(
                "original_code",
                "original message",
                "/job/space/slots/0",
            )]),
            Evaluation(Trial::Board(TrialBoardError::Model(
                ModelError::UnknownSymbol('Ω'),
            ))),
            Evaluation(Trial::Model(ModelError::EmptyAlphabet)),
            Evaluation(Trial::Measure(MeasureError::Arithmetic(
                ScoreError::Overflow,
            ))),
            Invariant("original invariant"),
            Counter(EvaluationsAdmitted),
            Counter(EvaluationsCompleted),
            Counter(ClimbsStarted),
            Counter(ClimbsCompleted),
            Counter(OutersCompleted),
        ]
    }

    #[test]
    fn error_hold_projection_preserves_original_and_best_errors() {
        use crate::attack_control::CounterOverflow as PrivateCounter;
        use crate::attack_evaluator::{TrialBoardError, TrialEvaluationError};
        use crate::attack_result::{AttackRunErrorData, AttackRunSource, RunPayload};
        use crate::{MeasureError, ModelError, ScoreError};
        use std::error::Error;
        // Injected causes exercise projection, not naturally failing public runs.
        for malformed in [false, true] {
            for payload in runtime_causes() {
                let expected_counter = match &payload {
                    RunPayload::Counter(counter) => Some(*counter),
                    _ => None,
                };
                let (kind, location) = match &payload {
                    RunPayload::Resolution(d) if !d.is_empty() => {
                        ("resolution", "/job/space/slots/0")
                    }
                    RunPayload::Resolution(_) => ("resolution", "/job"),
                    RunPayload::Evaluation(_) => ("evaluation", "/job"),
                    RunPayload::Counter(_) => ("counter", "/job"),
                    RunPayload::Invariant(_) => ("invariant", "/job"),
                };
                let error = crate::AttackRunError::new(AttackRunErrorData {
                    held_tail: Vec::new(),
                    stages: Vec::new(),
                    source: AttackRunSource(payload),
                    outer_index: None,
                    start_index: None,
                    evaluations_used: 0,
                    counters: AttackProgress(CounterSnapshot::default()),
                    best: if malformed {
                        Err(Box::new(ModelError::EmptyAlphabet))
                    } else {
                        Ok(None)
                    },
                });
                if !malformed {
                    assert_eq!(error.hold().unwrap().count(), 0);
                    let (result, terminal) = Event::runtime_error(&error, 0).unwrap();
                    let diagnostics: Vec<_> = error
                        .run_source()
                        .diagnostics()
                        .unwrap_or_default()
                        .iter()
                        .map(|d| {
                            json!({"code": d.code(), "message": d.message(),
                                "location": d.location()})
                        })
                        .collect();
                    assert_eq!(
                        encoded(&terminal),
                        json!({
                            "event": "error", "code": "internal_error", "message": error.to_string(),
                            "location": location, "context": {
                                "outer_index": null, "start_index": null, "evaluations_used": "0",
                                "counters": {"evaluations_admitted": "0", "evaluations_completed": "0",
                                    "climbs_started": "0", "climbs_completed": "0", "outers_completed": "0"},
                                "source": {"kind": kind, "message": error.to_string(), "diagnostics": diagnostics}
                            }, "protocol_version": 1, "seq": 7, "ts": TS
                        })
                    );
                    assert_eq!(
                        encoded(&result),
                        json!({
                            "event": "result", "stages": [], "hold": [], "best": null, "counters": super::ProgressCounters::from(error.counters()),
                            "elapsed_ms": "0", "protocol_version": 1, "seq": 7, "ts": TS
                        })
                    );
                    continue;
                }
                let hold_failure = error
                    .hold()
                    .err()
                    .expect("projection must not become empty");
                assert!(std::ptr::eq(hold_failure, error.best().unwrap_err()));
                let failure = Event::runtime_error(&error, 0).unwrap_err();
                assert!(std::ptr::eq(failure.original(), &error));
                assert!(std::ptr::eq(
                    failure.best_projection(),
                    error.best().unwrap_err()
                ));
                let original = failure
                    .source()
                    .unwrap()
                    .downcast_ref::<crate::AttackRunError>()
                    .unwrap();
                assert!(std::ptr::eq(original, &error));
                let cause = original
                    .source()
                    .unwrap()
                    .downcast_ref::<AttackRunSource>()
                    .unwrap();
                assert!(std::ptr::eq(cause, error.run_source()));
                if let Some(counter) = expected_counter {
                    use crate::AttackCounterOverflow as PublicCounter;
                    assert_eq!(
                        cause.source().unwrap().downcast_ref::<PrivateCounter>(),
                        Some(&counter)
                    );
                    let expected = match counter {
                        PrivateCounter::EvaluationsAdmitted => PublicCounter::EvaluationsAdmitted,
                        PrivateCounter::EvaluationsCompleted => PublicCounter::EvaluationsCompleted,
                        PrivateCounter::ClimbsStarted => PublicCounter::ClimbsStarted,
                        PrivateCounter::ClimbsCompleted => PublicCounter::ClimbsCompleted,
                        PrivateCounter::OutersCompleted => PublicCounter::OutersCompleted,
                    };
                    assert_eq!(cause.overflow(), Some(expected));
                }
                assert_eq!(
                    failure.best_projection().downcast_ref::<ModelError>(),
                    Some(&ModelError::EmptyAlphabet)
                );
                if let Some(trial) = cause
                    .source()
                    .and_then(|s| s.downcast_ref::<TrialEvaluationError>())
                {
                    let nested = trial.source().unwrap();
                    match trial {
                        TrialEvaluationError::Board(_) => {
                            let board = nested.downcast_ref::<TrialBoardError>().unwrap();
                            assert_eq!(
                                board.source().unwrap().downcast_ref::<ModelError>(),
                                Some(&ModelError::UnknownSymbol('Ω'))
                            );
                        }
                        TrialEvaluationError::Model(_) => assert_eq!(
                            nested.downcast_ref::<ModelError>(),
                            Some(&ModelError::EmptyAlphabet)
                        ),
                        TrialEvaluationError::Measure(_) => {
                            let measure = nested.downcast_ref::<MeasureError>().unwrap();
                            assert_eq!(
                                measure.source().unwrap().downcast_ref::<ScoreError>(),
                                Some(&ScoreError::Overflow)
                            );
                        }
                        _ => unreachable!("only three injected evaluation chains"),
                    }
                }
            }
        }
    }

    #[test]
    fn runtime_context_preserves_independent_indices_usage_and_counters() {
        use crate::attack_result::{AttackRunErrorData, AttackRunSource, RunPayload};
        for outer_index in [None, Some(0), Some(u128::MAX)] {
            for start_index in [None, Some(0), Some(u128::MAX)] {
                let error = crate::AttackRunError::new(AttackRunErrorData {
                    held_tail: Vec::new(),
                    stages: Vec::new(),
                    source: AttackRunSource(RunPayload::Invariant("full width")),
                    outer_index,
                    start_index,
                    evaluations_used: u64::MAX,
                    counters: AttackProgress(CounterSnapshot {
                        evaluations_admitted: u64::MAX - 1,
                        evaluations_completed: u64::MAX - 2,
                        climbs_started: u128::MAX,
                        climbs_completed: u128::MAX - 1,
                        outers_completed: u128::MAX - 2,
                    }),
                    best: Ok(None),
                });
                let (result, terminal) = Event::runtime_error(&error, u128::MAX).unwrap();
                let context = encoded(&terminal)["context"].clone();
                assert_eq!(
                    context["outer_index"],
                    json!(outer_index.map(|i| i.to_string()))
                );
                assert_eq!(
                    context["start_index"],
                    json!(start_index.map(|i| i.to_string()))
                );
                assert_eq!(context["evaluations_used"], u64::MAX.to_string());
                assert_eq!(
                    context["counters"],
                    json!({
                        "evaluations_admitted": (u64::MAX - 1).to_string(),
                        "evaluations_completed": (u64::MAX - 2).to_string(),
                        "climbs_started": u128::MAX.to_string(),
                        "climbs_completed": (u128::MAX - 1).to_string(),
                        "outers_completed": (u128::MAX - 2).to_string()
                    })
                );
                assert_eq!(encoded(&result)["elapsed_ms"], u128::MAX.to_string());
                assert_eq!(encoded(&result)["counters"], context["counters"]);
                assert!(context.get("elapsed_ms").is_none());
            }
        }
    }

    #[test]
    fn rfc3339_utc_converts_known_timestamps() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(-1), "1969-12-31T23:59:59Z");
        assert_eq!(rfc3339_utc(-62_135_596_800), "0001-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(253_402_300_799), "9999-12-31T23:59:59Z");
    }
}
