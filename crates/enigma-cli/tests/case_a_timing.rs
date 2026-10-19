//! Symmetric end-to-end timing harnesses for design A (`e2e/bomm/m4-u264-attack-board`).
//!
//! Both ignored tests time real subprocesses with the same clock: `Instant` around
//! `Command::output()` only. Each runs one unrecorded warm-up of each kind, then per
//! iteration a startup probe (startup plus exactly one evaluation) followed by the full
//! attack, strictly sequentially, asserting every output. Launch them through
//! `e2e/enigma_rust_timing/run.sh` and `e2e/bomm_timing/run.sh`, which supply metadata and
//! the results path. Without `ENIGMA_TIMING_OUTPUT` the report is only printed.

mod common;
mod support;

use common::{
    attack_fixture, bomm_dir, prepare_attack_inputs, verify_attack_output, ATTACK_CASE,
    BOMM_COMMIT, HISTORICAL_PAIRS,
};
use support::successful_events;

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

const DEFAULT_RUNS: usize = 100;
/// Evaluations of the full design-A attack (bomm's `Number of decrypts`).
const EVALUATIONS: u32 = 8456;
const BOMM_QUERY: &str = "e2e/bomm/m4-u264-attack-board/query.json";
const BOMM_STARTUP_QUERY: &str = "e2e/bomm_timing/startup-query.json";

/// `ENIGMA_TIMING_RUNS`: absent means 100; otherwise a positive decimal integer.
fn timing_runs(value: Option<&OsStr>) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_RUNS);
    };
    let text = value.to_str().unwrap_or("");
    match text.parse::<usize>() {
        Ok(runs) if runs > 0 && text.bytes().all(|b| b.is_ascii_digit()) => Ok(runs),
        _ => Err(format!(
            "ENIGMA_TIMING_RUNS must be a positive integer, got {value:?}"
        )),
    }
}

/// Nearest-rank percentile of ascending `sorted`: the sample at 1-based rank
/// `ceil(percent * N / 100)`, at least 1. Always an observed sample, never interpolated.
fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    let rank = (percent * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

/// Execution-order samples plus nearest-rank statistics; median is p50.
fn statistics(samples: &[Duration]) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    json!({
        "samples_seconds": samples.iter().map(Duration::as_secs_f64).collect::<Vec<_>>(),
        "min": sorted[0].as_secs_f64(),
        "p10": percentile(&sorted, 10).as_secs_f64(),
        "median": percentile(&sorted, 50).as_secs_f64(),
        "p90": percentile(&sorted, 90).as_secs_f64(),
        "max": sorted[sorted.len() - 1].as_secs_f64(),
    })
}

/// `(search seconds, per-evaluation microseconds)` from the two medians, unclamped.
fn search_metrics(startup_median: Duration, full_median: Duration) -> (f64, f64) {
    let search = full_median.as_secs_f64() - startup_median.as_secs_f64();
    (search, search * 1e6 / f64::from(EVALUATIONS))
}

fn median(samples: &[Duration]) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    percentile(&sorted, 50)
}

/// Creates `path`, failing instead of overwriting an existing file.
fn write_new(path: &Path, text: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(text.as_bytes())
}

fn cpu_model() -> Value {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(key, _)| key.trim() == "model name")
                .map(|(_, model)| json!(model.trim()))
        })
        .unwrap_or(Value::Null)
}

/// Launcher-supplied settings, read and validated before any measurement.
struct Settings {
    runs: usize,
    output: Option<PathBuf>,
    metadata: Map<String, Value>,
}

impl Settings {
    fn from_env(program: &str) -> Self {
        let runs = timing_runs(std::env::var_os("ENIGMA_TIMING_RUNS").as_deref())
            .unwrap_or_else(|error| panic!("{error}"));
        let output = std::env::var_os("ENIGMA_TIMING_OUTPUT").map(PathBuf::from);
        if let Some(path) = &output {
            assert!(!path.exists(), "{} already exists", path.display());
        }
        let mut metadata = Map::new();
        metadata.insert("program".into(), json!(program));
        metadata.insert("case".into(), json!(ATTACK_CASE));
        metadata.insert("cpu_model".into(), cpu_model());
        for (key, variable) in [
            ("git_commit", "ENIGMA_TIMING_GIT_COMMIT"),
            ("binary_sha256", "ENIGMA_TIMING_BINARY_SHA256"),
            ("timestamp_utc", "ENIGMA_TIMING_TIMESTAMP"),
        ] {
            let value = std::env::var(variable).ok();
            assert!(
                value.is_some() || output.is_none(),
                "{variable} is required with ENIGMA_TIMING_OUTPUT; use the run.sh launcher"
            );
            metadata.insert(key.into(), json!(value));
        }
        Settings {
            runs,
            output,
            metadata,
        }
    }

    fn finish(self, startup: &[Duration], full: &[Duration]) {
        let (search, per_evaluation) = search_metrics(median(startup), median(full));
        let mut report = self.metadata;
        report.insert("runs".into(), json!(self.runs));
        report.insert("evaluations".into(), json!(EVALUATIONS));
        report.insert("startup".into(), statistics(startup));
        report.insert("full".into(), statistics(full));
        report.insert("search_seconds_median".into(), json!(search));
        report.insert("per_evaluation_microseconds".into(), json!(per_evaluation));
        let text = serde_json::to_string_pretty(&report).unwrap() + "\n";
        match &self.output {
            Some(path) => {
                write_new(path, &text)
                    .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
                println!("ENIGMA_TIMING wrote {}", path.display());
            }
            None => print!("ENIGMA_TIMING {text}"),
        }
        println!("ENIGMA_TIMING search_seconds_median={search} per_evaluation_microseconds={per_evaluation}");
    }
}

/// Times only `Command::output()`; the command is fully built before the clock starts.
fn timed(mut command: Command) -> (Duration, Output) {
    let start = Instant::now();
    let output = command.output();
    let elapsed = start.elapsed();
    (
        elapsed,
        output.expect("failed to run the measured subprocess"),
    )
}

/// One unrecorded warm-up of each kind, then `runs` (startup, full) pairs, all checked.
fn measure(
    runs: usize,
    startup: impl Fn() -> Command,
    check_startup: impl Fn(&Output),
    full: impl Fn() -> Command,
    check_full: impl Fn(&Output),
) -> (Vec<Duration>, Vec<Duration>) {
    check_startup(&timed(startup()).1);
    check_full(&timed(full()).1);
    let mut startup_samples = Vec::with_capacity(runs);
    let mut full_samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let (elapsed, output) = timed(startup());
        check_startup(&output);
        startup_samples.push(elapsed);
        let (elapsed, output) = timed(full());
        check_full(&output);
        full_samples.push(elapsed);
    }
    (startup_samples, full_samples)
}

fn verify_startup_output(output: &Output) {
    let events = successful_events(output);
    let last = events.last().expect("at least one event");
    assert_eq!(last["event"], json!("done"), "events: {events:?}");
    assert_eq!(
        last["reason"],
        json!("evaluation_budget"),
        "events: {events:?}"
    );
}

#[test]
#[ignore = "release timing harness; run e2e/enigma_rust_timing/run.sh"]
fn enigma_rust_case_a_timing() {
    let settings = Settings::from_env("enigma-rust");
    let binary = env!("CARGO_BIN_EXE_enigma");
    if let Some(hashed) = std::env::var_os("ENIGMA_TIMING_BINARY") {
        assert_eq!(
            std::fs::canonicalize(binary).unwrap(),
            std::fs::canonicalize(&hashed).unwrap(),
            "the measured CLI must be the binary hashed by run.sh"
        );
    }
    let (inputs, record, mut request) = prepare_attack_inputs("enigma-rust-timing");
    // Budget 0 is rejected; 1 keeps startup, binding, row build and one evaluation.
    request["job"]["attack"]["evaluation_budget"] = json!(1);
    inputs.write("startup-request.json", &request);
    let command = |file: &str| {
        let mut command = Command::new(binary);
        command.current_dir(inputs.path()).arg(file);
        command
    };
    let (startup, full) = measure(
        settings.runs,
        || command("startup-request.json"),
        verify_startup_output,
        || command("request.json"),
        |output| verify_attack_output(output, &record),
    );
    drop(inputs);
    settings.finish(&startup, &full);
}

/// bomm options recorded in the capture command, between the binary and the query path.
fn bomm_flags(record: &Value) -> Vec<String> {
    let command = record["capture"]["command"]
        .as_str()
        .expect("capture command");
    let tokens: Vec<_> = command.split_whitespace().collect();
    let binary = tokens
        .iter()
        .position(|token| token.ends_with("/bomm"))
        .expect("capture command names the bomm binary");
    assert_eq!(tokens.last(), Some(&BOMM_QUERY), "capture query path");
    let flags: Vec<String> = tokens[binary + 1..tokens.len() - 1]
        .iter()
        .map(|token| token.to_string())
        .collect();
    assert!(
        flags.windows(2).any(|pair| pair == ["-t", "1"]),
        "{flags:?}"
    );
    flags
}

/// `Number of decrypts` when printed, and the pairs of the first key line whose leading
/// wheels/rings/positions fields equal `key_prefix`, normalized to sorted uppercase.
fn bomm_report(stdout: &str, key_prefix: &str) -> (Option<u64>, Vec<String>) {
    let decrypts = stdout.lines().find_map(|line| {
        line.strip_prefix("Number of decrypts:")
            .map(|count| count.trim().parse().expect("decrypt count"))
    });
    let fields = key_prefix.split_whitespace().count();
    let key = stdout
        .lines()
        .map(|line| line.trim_matches(|c: char| c == '│' || c.is_whitespace()))
        .find(|line| {
            line.split_whitespace()
                .take(fields)
                .eq(key_prefix.split_whitespace())
        })
        .unwrap_or_else(|| panic!("no key line starting {key_prefix:?}: {stdout}"));
    let mut pairs: Vec<String> = key
        .split_whitespace()
        .skip(fields)
        .map(|pair| {
            let mut letters: Vec<char> = pair.to_ascii_uppercase().chars().collect();
            letters.sort_unstable();
            letters.into_iter().collect()
        })
        .collect();
    pairs.sort_unstable();
    (decrypts, pairs)
}

fn bomm_stdout(output: &Output) -> &str {
    assert!(
        output.status.success(),
        "bomm exit status: {:?}",
        output.status
    );
    std::str::from_utf8(&output.stdout).expect("bomm stdout is UTF-8")
}

#[test]
#[ignore = "bomm timing harness; run e2e/bomm_timing/run.sh with BOMM_BIN"]
fn bomm_case_a_timing() {
    let mut settings = Settings::from_env("bomm");
    let binary = PathBuf::from(
        std::env::var_os("BOMM_BIN").expect("BOMM_BIN must name the pinned bomm binary"),
    );
    assert!(
        binary.is_file(),
        "BOMM_BIN {} is not a file",
        binary.display()
    );
    let (_, record) = attack_fixture();
    if let Some(Value::String(hash)) = settings.metadata.get("binary_sha256") {
        assert_eq!(
            record["capture"]["bomm_sha256"],
            json!(hash),
            "BOMM_BIN is not the pinned capture binary"
        );
    }
    settings
        .metadata
        .insert("bomm_commit".into(), json!(BOMM_COMMIT));
    let flags = bomm_flags(&record);
    let observed_key = record["observed"]["key"].as_str().unwrap();
    let key_prefix: Vec<_> = observed_key.split_whitespace().take(3).collect();
    let key_prefix = key_prefix.join(" ");
    // bomm opens frequency tables relative to its working directory.
    let root = std::fs::canonicalize(bomm_dir().join("../..")).unwrap();
    let command = |query: &str| {
        let mut command = Command::new(&binary);
        command.current_dir(&root).args(&flags).arg(query);
        command
    };
    let (startup, full) = measure(
        settings.runs,
        || command(BOMM_STARTUP_QUERY),
        |output| {
            let (decrypts, pairs) = bomm_report(bomm_stdout(output), &key_prefix);
            assert!(matches!(decrypts, None | Some(1)), "{decrypts:?}");
            assert!(pairs.is_empty(), "startup board must be empty: {pairs:?}");
        },
        || command(BOMM_QUERY),
        |output| {
            let (decrypts, pairs) = bomm_report(bomm_stdout(output), &key_prefix);
            assert!(
                decrypts.is_none_or(|n| n == u64::from(EVALUATIONS)),
                "{decrypts:?}"
            );
            assert_eq!(pairs, HISTORICAL_PAIRS);
            assert_eq!(record["observed"]["plugboard"], json!(pairs));
        },
    );
    settings.finish(&startup, &full);
}

#[test]
fn timing_runs_default_to_one_hundred_and_reject_non_positive_integers() {
    assert_eq!(timing_runs(None), Ok(DEFAULT_RUNS));
    assert_eq!(timing_runs(Some(OsStr::new("1"))), Ok(1));
    assert_eq!(timing_runs(Some(OsStr::new("2"))), Ok(2));
    assert_eq!(timing_runs(Some(OsStr::new("250"))), Ok(250));
    for value in [
        "",
        "0",
        "00",
        "-1",
        "+3",
        " 3",
        "3 ",
        "1.5",
        "ten",
        "99999999999999999999999",
    ] {
        assert!(
            timing_runs(Some(OsStr::new(value))).is_err(),
            "accepted {value:?}"
        );
    }
}

#[test]
fn nearest_rank_percentiles_cover_odd_even_and_ties() {
    let odd = [1, 2, 3, 4, 5].map(Duration::from_secs);
    assert_eq!(percentile(&odd, 10), Duration::from_secs(1));
    assert_eq!(percentile(&odd, 50), Duration::from_secs(3));
    assert_eq!(percentile(&odd, 90), Duration::from_secs(5));
    // Nearest rank on even N picks the lower middle sample, never an average.
    let even = [1, 2, 3, 4].map(Duration::from_secs);
    assert_eq!(percentile(&even, 50), Duration::from_secs(2));
    assert_eq!(percentile(&even, 10), Duration::from_secs(1));
    assert_eq!(percentile(&even, 90), Duration::from_secs(4));
    let hundred: Vec<_> = (1..=100).map(Duration::from_millis).collect();
    assert_eq!(percentile(&hundred, 10), Duration::from_millis(10));
    assert_eq!(percentile(&hundred, 50), Duration::from_millis(50));
    assert_eq!(percentile(&hundred, 90), Duration::from_millis(90));
    let single = [Duration::from_secs(7)];
    for percent in [10, 50, 90, 100] {
        assert_eq!(percentile(&single, percent), Duration::from_secs(7));
    }
}

#[test]
fn statistics_keep_execution_order_and_sort_only_for_percentiles() {
    let samples = [3, 1, 2, 2].map(Duration::from_secs);
    assert_eq!(
        statistics(&samples),
        json!({
            "samples_seconds": [3.0, 1.0, 2.0, 2.0],
            "min": 1.0, "p10": 1.0, "median": 2.0, "p90": 3.0, "max": 3.0
        })
    );
    let tied = statistics(&[Duration::from_millis(250); 3]);
    assert_eq!(tied["samples_seconds"], json!([0.25, 0.25, 0.25]));
    for field in ["min", "p10", "median", "p90", "max"] {
        assert_eq!(tied[field], json!(0.25));
    }
}

#[test]
fn search_metrics_subtract_startup_median_and_divide_by_evaluations() {
    let (search, per_evaluation) =
        search_metrics(Duration::from_millis(100), Duration::from_millis(946));
    assert!((search - 0.846).abs() < 1e-12);
    assert!((per_evaluation - 0.846e6 / f64::from(EVALUATIONS)).abs() < 1e-9);
    // Noise may make startup exceed the full run; report it rather than clamp.
    let (search, per_evaluation) =
        search_metrics(Duration::from_millis(30), Duration::from_millis(20));
    assert!((search + 0.010).abs() < 1e-12);
    assert!(per_evaluation < 0.0);
}

#[test]
fn results_are_never_overwritten() {
    let directory =
        std::env::temp_dir().join(format!("enigma-timing-write-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("result.json");
    let first = write_new(&path, "first\n");
    let second = write_new(&path, "second\n");
    let content = std::fs::read_to_string(&path);
    std::fs::remove_dir_all(&directory).unwrap();
    first.unwrap();
    assert_eq!(
        second.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(content.unwrap(), "first\n");
}

#[test]
fn bomm_flags_and_board_come_from_the_recorded_capture() {
    let (_, record) = attack_fixture();
    assert_eq!(bomm_flags(&record), ["-q", "-t", "1", "-n", "5"]);
    let stdout = "Final query results:\n\
        │ \u{1b}[32mvonvon\u{1b}[37m   -8.333018 │\n\
        │ UKW-B-thin,beta,II,IV,I aaaav avjna vx at bl df gj hm nw op qy zr            │\n\
        │ UKW-B-thin,beta,II,IV,I aaaav avjna ab            │\n\
        Number of units: 1\nNumber of decrypts: 8456\n";
    let (decrypts, pairs) = bomm_report(stdout, "UKW-B-thin,beta,II,IV,I aaaav avjna");
    assert_eq!(decrypts, Some(8456));
    assert_eq!(pairs, HISTORICAL_PAIRS);
    let (decrypts, pairs) = bomm_report(
        "│ UKW-B-thin,beta,II,IV,I aaaav avjna              │\n",
        "UKW-B-thin,beta,II,IV,I aaaav avjna",
    );
    assert_eq!(decrypts, None);
    assert!(pairs.is_empty());
}
