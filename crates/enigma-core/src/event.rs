//! Protocol event stream types (`docs/protocol.md` §4).
//!
//! This module is pure data plus pure helpers: it serializes the protocol events
//! and converts Unix timestamps to RFC 3339 UTC. It performs no I/O and reads no clock;
//! the transport supplies the timestamp. `protocol_version`, `seq`, and `ts` are added
//! to every encoded event so callers only choose the event payload and its position.

use serde::Serialize;
use serde_json::Value;

use crate::{AttackProgress, AttackTermination, PROTOCOL_VERSION};

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
    /// Evaluation allowance prevented remaining work.
    EvaluationBudget,
    /// Cooperative cancellation stopped remaining work.
    Cancelled,
}

impl From<AttackTermination> for DoneReason {
    fn from(termination: AttackTermination) -> Self {
        match termination {
            AttackTermination::Completed => Self::Completed,
            AttackTermination::OuterSliceEnd => Self::OuterSliceEnd,
            AttackTermination::EvaluationBudget => Self::EvaluationBudget,
            AttackTermination::Cancelled => Self::Cancelled,
        }
    }
}

impl Event {
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
                AttackTermination::EvaluationBudget,
                DoneReason::EvaluationBudget,
                "evaluation_budget",
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
