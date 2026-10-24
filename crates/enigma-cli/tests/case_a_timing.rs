//! End-to-end timing harnesses for U-264 designs A, A2, B and C.
//! `ENIGMA_TIMING_CASE=a|positions|b|c` selects the workload; A remains the default.
//!
//! Our CLI measures startup from the live `started` event within each full run.
//! bomm retains a separate one-decrypt startup probe. Both use `Instant`, run an
//! unrecorded warm-up, and check every output, strictly sequentially. Launch through
//! `e2e/enigma_rust_timing/run.sh` and `e2e/bomm_timing/run.sh`, which supply metadata and
//! the results path. Without `ENIGMA_TIMING_OUTPUT` the report is only printed.

mod common;
mod support;

use common::{
    attack_fixture, bomm_dir, prepare_attack_inputs, verify_attack_output, ATTACK_CASE,
    BOMM_COMMIT, HISTORICAL_PAIRS,
};
use support::successful_events;

use std::cell::Cell;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

const DEFAULT_RUNS: usize = 100;
/// Evaluations of the full design-A attack (bomm's `Number of decrypts`).
const EVALUATIONS: u32 = 8456;
const BOMM_QUERY: &str = "e2e/bomm/m4-u264-attack-board/query.json";
const BOMM_STARTUP_QUERY: &str = "e2e/bomm_timing/startup-query.json";
const POSITIONS_CASE: &str = "m4-u264-attack-positions";
const DESIGN_B_CASE: &str = "m4-u264-attack-design-b";
const DESIGN_C_CASE: &str = "m4-u264-attack-design-c";

fn timing_case(value: Option<&OsStr>) -> Result<&'static str, String> {
    match value {
        None => Ok(ATTACK_CASE),
        Some(value) if value == "a" => Ok(ATTACK_CASE),
        Some(value) if value == "positions" => Ok(POSITIONS_CASE),
        Some(value) if value == "b" => Ok(DESIGN_B_CASE),
        Some(value) if value == "c" => Ok(DESIGN_C_CASE),
        Some(value) => Err(format!(
            "ENIGMA_TIMING_CASE must be a, positions, b or c, got {value:?}"
        )),
    }
}

fn selected_fixture(case: &str) -> (Value, Value) {
    if case == ATTACK_CASE {
        attack_fixture()
    } else {
        (
            common::load(case, "query.json"),
            common::load(case, "case.json"),
        )
    }
}

fn evaluation_metrics(startup: Duration, full: Duration, count: Option<u64>) -> Option<f64> {
    count.map(|count| (full.as_secs_f64() - startup.as_secs_f64()) * 1e6 / count as f64)
}

/// Reject inconsistent counts rather than silently divide timing by a different run's work.
fn record_evaluations(observed: &Cell<Option<u64>>, count: Option<u64>) {
    if let Some(previous) = observed.get() {
        assert_eq!(
            count,
            Some(previous),
            "evaluation count changed between runs"
        );
    }
    observed.set(count);
}

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

/// Harness default stays monothread, independently of the application's default.
fn timing_threads(value: Option<&OsStr>) -> Result<usize, String> {
    let Some(value) = value else { return Ok(1) };
    let text = value.to_str().unwrap_or("");
    match text.parse::<usize>() {
        Ok(threads) if (1..=256).contains(&threads) && text.bytes().all(|b| b.is_ascii_digit()) => {
            Ok(threads)
        }
        _ => Err(format!(
            "ENIGMA_TIMING_THREADS must be an integer from 1 to 256, got {value:?}"
        )),
    }
}

fn enigma_command(binary: &str, directory: &Path, threads: usize) -> Command {
    let mut command = Command::new(binary);
    command
        .current_dir(directory)
        .args(["--threads", &threads.to_string(), "request.json"]);
    command
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
    case: &'static str,
    runs: usize,
    threads: usize,
    output: Option<PathBuf>,
    metadata: Map<String, Value>,
}

impl Settings {
    fn from_env(program: &str) -> Self {
        let threads = timing_threads(std::env::var_os("ENIGMA_TIMING_THREADS").as_deref())
            .unwrap_or_else(|error| panic!("{error}"));
        let runs = timing_runs(std::env::var_os("ENIGMA_TIMING_RUNS").as_deref())
            .unwrap_or_else(|error| panic!("{error}"));
        let case = timing_case(std::env::var_os("ENIGMA_TIMING_CASE").as_deref())
            .unwrap_or_else(|error| panic!("{error}"));
        let output = std::env::var_os("ENIGMA_TIMING_OUTPUT").map(PathBuf::from);
        if let Some(path) = &output {
            assert!(!path.exists(), "{} already exists", path.display());
        }
        let mut metadata = Map::new();
        metadata.insert("program".into(), json!(program));
        metadata.insert("case".into(), json!(case));
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
            case,
            runs,
            threads,
            output,
            metadata,
        }
    }

    fn finish(
        self,
        startup: &[Duration],
        full: &[Duration],
        evaluations: Option<u64>,
        paired: Option<&[Duration]>,
    ) {
        let search = paired.map_or_else(
            || median(full).as_secs_f64() - median(startup).as_secs_f64(),
            |samples| median(samples).as_secs_f64(),
        );
        let per_evaluation = if paired.is_some() {
            evaluations.map(|count| search * 1e6 / count as f64)
        } else if self.case == ATTACK_CASE {
            Some(search_metrics(median(startup), median(full)).1)
        } else {
            evaluation_metrics(median(startup), median(full), evaluations)
        };
        let mut report = self.metadata;
        report.insert("runs".into(), json!(self.runs));
        report.insert("threads".into(), json!(self.threads));
        if let Some(count) = evaluations {
            report.insert("evaluations".into(), json!(count));
        }
        report.insert("startup".into(), statistics(startup));
        report.insert("full".into(), statistics(full));
        if let Some(samples) = paired {
            report.insert("search".into(), statistics(samples));
            report.insert("startup_measurement".into(), json!("in_run_started_event"));
        }
        report.insert("search_seconds_median".into(), json!(search));
        if let Some(metric) = per_evaluation {
            report.insert("per_evaluation_microseconds".into(), json!(metric));
        }
        let text = serde_json::to_string_pretty(&report).unwrap() + "\n";
        match &self.output {
            Some(path) => {
                write_new(path, &text)
                    .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
                println!("ENIGMA_TIMING wrote {}", path.display());
            }
            None => print!("ENIGMA_TIMING {text}"),
        }
        if let Some(metric) = per_evaluation {
            println!(
                "ENIGMA_TIMING search_seconds_median={search} per_evaluation_microseconds={metric}"
            );
        } else {
            println!("ENIGMA_TIMING search_seconds_median={search}");
        }
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

/// Capture stdout unchanged, timestamping `started` before reading the next line.
fn read_started_stdout(
    reader: &mut impl BufRead,
    elapsed: impl Fn() -> Duration,
) -> (Duration, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut startup = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader
            .read_until(b'\n', &mut line)
            .expect("read CLI stdout")
            == 0
        {
            break;
        }
        let event: Value = serde_json::from_slice(&line).expect("CLI event JSON");
        if event["event"] == "started" {
            assert!(startup.is_none(), "duplicate started event");
            startup = Some(elapsed());
        }
        stdout.extend_from_slice(&line);
    }
    (startup.expect("missing started event"), stdout)
}

fn paired_search(startup: &[Duration], full: &[Duration]) -> Vec<Duration> {
    assert_eq!(startup.len(), full.len());
    full.iter().zip(startup).map(|(f, s)| *f - *s).collect()
}

/// Drain stderr concurrently so a full pipe cannot block the measured process.
fn timed_enigma(mut command: Command) -> (Duration, Duration, Output) {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = command.spawn().expect("spawn measured CLI");
    let mut stderr = child.stderr.take().unwrap();
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).expect("read CLI stderr");
        bytes
    });
    let (startup, stdout) =
        read_started_stdout(&mut BufReader::new(child.stdout.take().unwrap()), || {
            start.elapsed()
        });
    let status = child.wait().expect("wait for measured CLI");
    let full = start.elapsed();
    let stderr = stderr_reader.join().expect("stderr reader");
    (
        startup,
        full,
        Output {
            status,
            stdout,
            stderr,
        },
    )
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
    let (inputs, mut record, mut request) = prepare_attack_inputs("enigma-rust-timing");
    if settings.case != ATTACK_CASE {
        let (query, selected) = selected_fixture(settings.case);
        record = selected;
        let resources = request["job"]["resources"].clone();
        request = record["engine"].clone();
        request["job"]["text"] = json!(query["ciphertext"].as_str().unwrap().to_ascii_uppercase());
        request["job"]["resources"] = resources;
        inputs.write("request.json", &request);
    }
    let evaluations = Cell::new(Some(u64::from(EVALUATIONS)));
    if settings.case != ATTACK_CASE {
        evaluations.set(None);
    }
    let command = || enigma_command(binary, inputs.path(), settings.threads);
    let check = |output: &Output| {
        verify_attack_output(output, &record);
        if settings.case != ATTACK_CASE {
            let events = successful_events(output);
            let result = events
                .iter()
                .find(|event| event["event"] == "result")
                .unwrap();
            let positions: &[(&str, &str)] = if settings.case == POSITIONS_CASE {
                &[("middle", "N"), ("right", "A")]
            } else {
                &[("left", "J"), ("middle", "N"), ("right", "A")]
            };
            let slot = |id: &str| {
                result["best"]["configuration"]["slots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|slot| slot["id"] == id)
                    .unwrap()
            };
            for &(id, position) in positions {
                assert_eq!(slot(id)["position"], position);
            }
            if settings.case == DESIGN_C_CASE {
                assert_eq!(slot("right")["ring"], "V");
            }
            let outers = match settings.case {
                POSITIONS_CASE => "676",
                DESIGN_B_CASE => "17576",
                DESIGN_C_CASE => "456976",
                _ => unreachable!(),
            };
            assert_eq!(result["counters"]["outers_completed"], outers);
        }
        let events = successful_events(output);
        let result = events
            .iter()
            .find(|event| event["event"] == "result")
            .unwrap();
        let expected = match settings.case {
            ATTACK_CASE => u64::from(EVALUATIONS),
            POSITIONS_CASE => 5_372_197,
            DESIGN_B_CASE => 139_628_857,
            DESIGN_C_CASE => 3_636_321_119,
            _ => unreachable!(),
        };
        let count = result["counters"]["evaluations_completed"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(count, expected);
        record_evaluations(&evaluations, Some(count));
        let done = events.last().unwrap();
        assert_eq!(done["event"], "done");
        assert_eq!(done["reason"], "completed");
    };
    check(&timed_enigma(command()).2);
    let mut startup = Vec::with_capacity(settings.runs);
    let mut full = Vec::with_capacity(settings.runs);
    for _ in 0..settings.runs {
        let (started, elapsed, output) = timed_enigma(command());
        check(&output);
        startup.push(started);
        full.push(elapsed);
    }
    let search = paired_search(&startup, &full);
    drop(inputs);
    settings.finish(&startup, &full, evaluations.get(), Some(&search));
}

/// bomm options recorded in the capture command, between the binary and the query path.
fn bomm_flags(record: &Value, threads: usize) -> Vec<String> {
    let command = record["capture"]["command"]
        .as_str()
        .expect("capture command");
    let tokens: Vec<_> = command.split_whitespace().collect();
    let binary = tokens
        .iter()
        .position(|token| token.ends_with("/bomm"))
        .expect("capture command names the bomm binary");
    let query = tokens.last().expect("capture query path");
    assert!(
        [
            BOMM_QUERY,
            "e2e/bomm/m4-u264-attack-positions/query.json",
            "e2e/bomm/m4-u264-attack-design-b/query.json",
            "e2e/bomm/m4-u264-attack-design-c/query.json",
        ]
        .contains(query),
        "capture query path: {query}"
    );
    let mut flags: Vec<String> = tokens[binary + 1..tokens.len() - 1]
        .iter()
        .map(|token| token.to_string())
        .collect();
    let thread_value = flags
        .windows(2)
        .position(|pair| pair[0] == "-t")
        .unwrap_or_else(|| panic!("capture must contain -t <threads>: {flags:?}"))
        + 1;
    flags[thread_value] = threads.to_string();
    flags
}

/// `Number of decrypts` when printed and the top key's sorted uppercase pairs.
/// Rejects a nonhistorical top key even if the historical key appears lower down.
fn bomm_report(stdout: &str, key_prefix: &str) -> (Option<u64>, Vec<String>) {
    let decrypts = stdout.lines().find_map(|line| {
        line.strip_prefix("Number of decrypts:")
            .map(|count| count.trim().parse().expect("decrypt count"))
    });
    let fields = key_prefix.split_whitespace().count();
    let key = stdout
        .lines()
        .map(|line| line.trim_matches(|c: char| c == '│' || c.is_whitespace()))
        .find(|line| line.starts_with("UKW-"))
        .unwrap_or_else(|| panic!("no top key line: {stdout}"));
    assert!(
        key.split_whitespace()
            .take(fields)
            .eq(key_prefix.split_whitespace()),
        "top key does not start with {key_prefix:?}: {key}"
    );
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
    let (_, record) = selected_fixture(settings.case);
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
    let flags = bomm_flags(&record, settings.threads);
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
    let query = format!("e2e/bomm/{}/query.json", settings.case);
    let evaluations = Cell::new(None);
    let (startup, full) = measure(
        settings.runs,
        || command(BOMM_STARTUP_QUERY),
        |output| {
            let (decrypts, pairs) = bomm_report(bomm_stdout(output), &key_prefix);
            assert!(matches!(decrypts, None | Some(1)), "{decrypts:?}");
            assert!(pairs.is_empty(), "startup board must be empty: {pairs:?}");
        },
        || command(&query),
        |output| {
            let (decrypts, pairs) = bomm_report(bomm_stdout(output), &key_prefix);
            if settings.case == ATTACK_CASE {
                assert!(
                    decrypts.is_none_or(|n| n == u64::from(EVALUATIONS)),
                    "{decrypts:?}"
                );
                record_evaluations(&evaluations, Some(u64::from(EVALUATIONS)));
            } else {
                // This pinned binary prints a total; if unavailable, omit count-based metrics.
                assert!(decrypts.is_none_or(|count| count > 0));
                record_evaluations(&evaluations, decrypts);
            }
            assert_eq!(pairs, HISTORICAL_PAIRS);
            assert_eq!(record["observed"]["plugboard"], json!(pairs));
        },
    );
    settings.finish(&startup, &full, evaluations.get(), None);
}

#[test]
fn thread_boundaries_and_exact_engine_arguments_preserve_capture_flags() {
    assert_eq!(timing_threads(None), Ok(1));
    for (text, threads) in [("1", 1), ("006", 6), ("256", 256)] {
        assert_eq!(timing_threads(Some(OsStr::new(text))), Ok(threads));
        let command = enigma_command("enigma", Path::new("inputs"), threads);
        assert_eq!(command.get_current_dir(), Some(Path::new("inputs")));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["--threads", &threads.to_string(), "request.json"].map(OsStr::new)
        );
        for case in [ATTACK_CASE, POSITIONS_CASE, DESIGN_B_CASE, DESIGN_C_CASE] {
            let (_, record) = selected_fixture(case);
            let original = record["capture"]["command"].clone();
            assert_eq!(
                bomm_flags(&record, threads),
                ["-q", "-t", text.trim_start_matches('0'), "-n", "5"]
            );
            assert_eq!(record["capture"]["command"], original);
        }
    }
}

#[test]
fn case_a_public_harness_records_default_and_explicit_threads() {
    for threads in [None, Some("1"), Some("6")] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "enigma_rust_case_a_timing",
                "--ignored",
                "--exact",
                "--nocapture",
            ])
            .env_remove("ENIGMA_TIMING_OUTPUT")
            .env_remove("ENIGMA_TIMING_BINARY")
            .env_remove("ENIGMA_TIMING_THREADS")
            .env("ENIGMA_TIMING_CASE", "a")
            .env("ENIGMA_TIMING_RUNS", "1");
        if let Some(value) = threads {
            command.env("ENIGMA_TIMING_THREADS", value);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let report = stdout.split_once("ENIGMA_TIMING {").unwrap().1;
        let report = format!("{{{report}");
        let report: Value = serde_json::Deserializer::from_str(&report)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            report["threads"],
            threads.unwrap_or("1").parse::<usize>().unwrap()
        );
        assert_eq!(report["runs"], 1);
        assert_eq!(report["evaluations"], EVALUATIONS);
        assert_eq!(report["startup_measurement"], "in_run_started_event");
        for field in ["startup", "search", "full"] {
            assert_eq!(
                report[field]["samples_seconds"].as_array().unwrap().len(),
                1
            );
        }
    }
}

#[test]
fn launchers_reject_invalid_threads_before_building_or_writing_results() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for launcher in ["e2e/enigma_rust_timing/run.sh", "e2e/bomm_timing/run.sh"] {
        for value in [
            "",
            "0",
            "00",
            "257",
            "-1",
            "+3",
            " 3",
            "3 ",
            "1.5",
            "ten",
            "99999999999999999999999",
        ] {
            let output = Command::new("sh")
                .arg(root.join(launcher))
                .env("ENIGMA_TIMING_THREADS", value)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert_eq!(
                output.stderr,
                b"run.sh: ENIGMA_TIMING_THREADS must be an integer from 1 to 256\n"
            );
        }
        let script = std::fs::read_to_string(root.join(launcher)).unwrap();
        assert!(script.contains("$case_suffix-t$threads.json"));
        assert!(script.contains("threads=${ENIGMA_TIMING_THREADS-1}"));
    }
}

#[test]
fn thread_validation_precedes_measurement_in_both_public_harnesses() {
    for harness in ["enigma_rust_case_a_timing", "bomm_case_a_timing"] {
        for value in [
            "",
            "0",
            "00",
            "257",
            "-1",
            "+3",
            " 3",
            "3 ",
            "1.5",
            "ten",
            "99999999999999999999999",
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([harness, "--ignored", "--exact", "--nocapture"])
                .env_remove("ENIGMA_TIMING_OUTPUT")
                .env("ENIGMA_TIMING_THREADS", value)
                .env("ENIGMA_TIMING_RUNS", "invalid-sentinel")
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(101));
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                stderr.contains(&format!(
                    "ENIGMA_TIMING_THREADS must be an integer from 1 to 256, got {value:?}"
                )),
                "{harness}: {stderr}"
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("ENIGMA_TIMING {"));
        }
    }
}

#[test]
fn positions_capture_uses_the_same_flags_and_its_own_decrypt_count() {
    let (_, record) = selected_fixture(POSITIONS_CASE);
    assert_eq!(bomm_flags(&record, 1), ["-q", "-t", "1", "-n", "5"]);
    let (count, pairs) = bomm_report(
        "│ UKW-B-thin,beta,II,IV,I aaaav avjna at bl df gj hm nw op qy rz vx │\nNumber of decrypts: 5492071\n",
        "UKW-B-thin,beta,II,IV,I aaaav avjna",
    );
    assert_eq!(count, Some(5_492_071));
    assert_eq!(pairs, HISTORICAL_PAIRS);
}

#[test]
fn design_b_capture_uses_the_same_flags_and_its_own_decrypt_count() {
    let (_, record) = selected_fixture(DESIGN_B_CASE);
    assert_eq!(bomm_flags(&record, 1), ["-q", "-t", "1", "-n", "5"]);
    let (count, pairs) = bomm_report(
        "│ UKW-B-thin,beta,II,IV,I aaaav avjna at bl df gj hm nw op qy rz vx │\nNumber of decrypts: 142788085\n",
        "UKW-B-thin,beta,II,IV,I aaaav avjna",
    );
    assert_eq!(count, Some(142_788_085));
    assert_eq!(pairs, HISTORICAL_PAIRS);
}

#[test]
fn design_c_capture_uses_the_same_flags_and_its_own_decrypt_count() {
    let (_, record) = selected_fixture(DESIGN_C_CASE);
    assert_eq!(bomm_flags(&record, 6), ["-q", "-t", "6", "-n", "5"]);
    assert_eq!(bomm_flags(&record, 1), ["-q", "-t", "1", "-n", "5"]);
    let (count, pairs) = bomm_report(
        "│ UKW-B-thin,beta,II,IV,I aaaav avjna at bl df gj hm nw op qy rz vx │\nNumber of decrypts: 3718611649\n",
        "UKW-B-thin,beta,II,IV,I aaaav avjna",
    );
    assert_eq!(count, Some(3_718_611_649));
    assert_eq!(pairs, HISTORICAL_PAIRS);
}

#[test]
#[should_panic(expected = "capture must contain -t <threads>")]
fn bomm_flags_require_a_thread_flag_in_the_capture() {
    bomm_flags(
        &json!({"capture": {"command": "../bomm-reference/build/bomm -q -n 5 e2e/bomm/m4-u264-attack-design-c/query.json"}}),
        6,
    );
}

#[test]
#[should_panic(expected = "top key does not start")]
fn bomm_rejects_historical_key_below_a_wrong_top_key() {
    bomm_report(
        "│ UKW-B-thin,beta,II,IV,I aaaav avjnb ab │\n│ UKW-B-thin,beta,II,IV,I aaaav avjna at bl df gj hm nw op qy rz vx │\n",
        "UKW-B-thin,beta,II,IV,I aaaav avjna",
    );
}

#[test]
fn optional_evaluation_metrics_use_the_selected_engines_count() {
    let startup = Duration::from_millis(100);
    let full = Duration::from_millis(946);
    assert_eq!(evaluation_metrics(startup, full, None), None);
    for count in [8456, 5_372_197, 5_492_071] {
        let metric = evaluation_metrics(startup, full, Some(count)).unwrap();
        assert!((metric - 0.846e6 / count as f64).abs() < 1e-9);
    }
}

#[test]
fn timing_case_defaults_accepts_known_cases_and_rejects_invalid_values() {
    assert_eq!(timing_case(None), Ok(ATTACK_CASE));
    assert_eq!(timing_case(Some(OsStr::new("a"))), Ok(ATTACK_CASE));
    assert_eq!(
        timing_case(Some(OsStr::new("positions"))),
        Ok(POSITIONS_CASE)
    );
    assert_eq!(
        timing_case(Some(OsStr::new("b"))),
        Ok("m4-u264-attack-design-b")
    );
    assert_eq!(
        timing_case(Some(OsStr::new("c"))),
        Ok("m4-u264-attack-design-c")
    );
    for value in [
        "",
        "A",
        " positions",
        "positions ",
        "B",
        " b",
        "b ",
        "C",
        " c",
        "c ",
        "unknown",
    ] {
        assert_eq!(
            timing_case(Some(OsStr::new(value))),
            Err(format!(
                "ENIGMA_TIMING_CASE must be a, positions, b or c, got {:?}",
                OsStr::new(value)
            ))
        );
    }
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
fn started_is_timestamped_while_reading_and_stdout_is_preserved() {
    let stdout = b"{\"event\":\"progress\"}\n{\"event\":\"started\"}\n{\"event\":\"done\"}\n";
    struct LiveReader<'a> {
        inner: std::io::Cursor<&'a [u8]>,
        timestamped: &'a Cell<bool>,
    }
    impl Read for LiveReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }
    impl BufRead for LiveReader<'_> {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.inner.position() >= 41 {
                assert!(
                    self.timestamped.get(),
                    "timestamp must precede reading done"
                );
            }
            self.inner.fill_buf()
        }
        fn consume(&mut self, amount: usize) {
            self.inner.consume(amount);
        }
    }
    let timestamped = Cell::new(false);
    let mut reader = LiveReader {
        inner: std::io::Cursor::new(stdout.as_slice()),
        timestamped: &timestamped,
    };
    let (startup, captured) = read_started_stdout(&mut reader, || {
        assert!(!timestamped.replace(true));
        Duration::from_millis(25)
    });
    assert!(timestamped.get());
    assert_eq!(startup, Duration::from_millis(25));
    assert_eq!(captured, stdout);
}

#[test]
#[should_panic(expected = "missing started event")]
fn startup_requires_a_started_event() {
    read_started_stdout(&mut std::io::Cursor::new(b"{\"event\":\"done\"}\n"), || {
        Duration::ZERO
    });
}

#[test]
fn search_statistics_subtract_each_runs_startup_before_taking_medians() {
    let startup = [1, 9, 2].map(Duration::from_secs);
    let full = [6, 10, 5].map(Duration::from_secs);
    let search = paired_search(&startup, &full);
    assert_eq!(
        statistics(&search),
        json!({
            "samples_seconds": [5.0, 1.0, 3.0],
            "min": 1.0, "p10": 1.0, "median": 3.0, "p90": 5.0, "max": 5.0
        })
    );
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
    assert_eq!(bomm_flags(&record, 1), ["-q", "-t", "1", "-n", "5"]);
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
