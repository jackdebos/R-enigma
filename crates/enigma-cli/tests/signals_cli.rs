//! Real Unix signals against a running HC attack: the single timing-dependent test.
#![cfg(unix)]
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Kills a child that outlives this bound, so a broken handler fails instead of hanging.
const WATCHDOG: Duration = Duration::from_secs(30);

/// An HC attack over 26^6 outers with an effectively unlimited budget: uninterrupted,
/// it runs far longer than the watchdog bound.
fn long_attack() -> Value {
    let alphabet: Vec<String> = ('A'..='Z').map(String::from).collect();
    let mut wiring = alphabet.clone();
    wiring.rotate_left(1);
    let ids: Vec<String> = (0..3).map(|i| format!("r{i}")).collect();
    json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
        "alphabet":alphabet,"wheels":[{"name":"r","wiring":wiring,"turnovers":[]}],
        "slots":ids.iter().map(|id| json!({"id":id,"role":"rotor","movement":"fixed","wheel":"r"})).collect::<Vec<_>>(),
        "stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":[],"plugboard":[]},
        "space":{"slots":ids.iter().map(|id| json!({"id":id,"positions":alphabet,"rings":alphabet})).collect::<Vec<_>>(),
            "plugboard":{"kind":"attack","symbols":alphabet,"max_pairs":10}},
        "text":"QWERTYUIOPASDFGHJKLZXCVBNM".repeat(8),"passes":["hill_climb"],"measures":["ic"],"resources":{},
        "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":10,
            "backtrack_pairs":0,"start":[]}}})
}

/// Sends `signal` once `started` is read, then checks the cancelled lifecycle and exit 0.
fn assert_signal_cancels(signal: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--request", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(long_attack().to_string().as_bytes())
        .unwrap();
    drop(stdin);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();

    let (exited, wait) = mpsc::channel::<()>();
    let killer = pid.clone();
    let watchdog = thread::spawn(move || {
        let fired = wait.recv_timeout(WATCHDOG).is_err();
        if fired {
            Command::new("kill")
                .args(["-KILL", &killer])
                .status()
                .unwrap();
        }
        fired
    });

    let mut first = String::new();
    stdout.read_line(&mut first).unwrap();
    let started: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(started["event"], "started", "{signal}");
    assert!(Command::new("kill")
        .args([signal, &pid])
        .status()
        .unwrap()
        .success());
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let status = child.wait().unwrap();
    let _ = exited.send(());
    assert!(
        !watchdog.join().unwrap(),
        "{signal}: watchdog killed the child"
    );
    let mut diagnostics = String::new();
    stderr.read_to_string(&mut diagnostics).unwrap();

    assert_eq!(status.code(), Some(0), "{signal}: {status:?} {diagnostics}");
    assert!(diagnostics.is_empty(), "{signal}: {diagnostics}");
    assert!(rest.ends_with('\n'), "{signal}: {rest:?}");
    let events: Vec<Value> = rest
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let [.., result, done] = &events[..] else {
        panic!("{signal}: missing terminal events: {rest:?}");
    };
    assert_eq!(result["event"], "result", "{signal}");
    assert_eq!(done["event"], "done", "{signal}");
    assert_eq!(done["reason"], "cancelled", "{signal}");
}

#[test]
fn sigint_requests_safe_stop() {
    assert_signal_cancels("-INT");
}

#[test]
fn sigterm_requests_safe_stop() {
    assert_signal_cancels("-TERM");
}
