//! Shared assertions for successful real-CLI JSONL process envelopes.

use std::process::Output;

use serde_json::{json, Value};

/// Validate the transport envelope, leaving event lifecycle and payload checks local.
pub fn successful_events(output: &Output) -> Vec<Value> {
    assert!(output.status.success(), "exit status: {:?}", output.status);
    assert!(
        output.stderr.is_empty(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::str::from_utf8(&output.stdout).expect("stdout is valid UTF-8");
    assert!(
        text.ends_with('\n'),
        "stdout must end with a newline: {text:?}"
    );
    let events: Vec<Value> = text
        .lines()
        .map(|line| {
            let event: Value = serde_json::from_str(line).expect("each stdout line is valid JSON");
            assert!(event.is_object(), "each stdout line must be a JSON object");
            event
        })
        .collect();

    for (index, event) in events.iter().enumerate() {
        assert_eq!(
            event["protocol_version"],
            json!(1),
            "event {index}: {event:?}"
        );
        assert_eq!(
            event["seq"],
            json!(index as u64 + 1),
            "event {index}: {event:?}"
        );
        let ts = event["ts"].as_str().expect("ts is a string");
        // The CLI emits whole-second RFC 3339 UTC: YYYY-MM-DDTHH:MM:SSZ.
        // Check shape only, not calendar validity or wall-clock ordering.
        assert_eq!(ts.len(), 20, "event {index} timestamp: {ts:?}");
        for (position, byte) in ts.bytes().enumerate() {
            let valid = match position {
                4 | 7 => byte == b'-',
                10 => byte == b'T',
                13 | 16 => byte == b':',
                19 => byte == b'Z',
                _ => byte.is_ascii_digit(),
            };
            assert!(valid, "event {index} timestamp: {ts:?}");
        }
    }
    events
}
