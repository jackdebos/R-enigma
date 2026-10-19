# Design A timing: our release CLI

Measures our `enigma` CLI on design A (`e2e/bomm/m4-u264-attack-board/`) and writes
one new JSON file per invocation. The bomm counterpart is `e2e/bomm_timing/`, which
uses the same clock and statistics.

## Quick path

```sh
e2e/enigma_rust_timing/run.sh                       # 100 runs (default)
ENIGMA_TIMING_RUNS=5 e2e/enigma_rust_timing/run.sh  # a short check
ls e2e/enigma_rust_timing/results/ | tail -n 1      # newest result
```

Works from any directory. The script builds `target/release/enigma`, hashes it,
and then runs the ignored test `enigma_rust_case_a_timing` in
`crates/enigma-cli/tests/case_a_timing.rs`, which uses that same binary.

## What is measured

| Probe | Request | Checked on every run |
| --- | --- | --- |
| startup | design-A request with `evaluation_budget: 1` | success, final `done` reason `evaluation_budget` |
| full | design-A request unchanged (8,456 evaluations) | ten historical pairs and the full 232-letter plaintext |

- **Startup** = process start, request and trigram resource parsing, binding, scrambler
  row build, one evaluation and output. Budget 0 is rejected, so 1 is the minimum.
- **Order**: one unrecorded warm-up of each probe, then N iterations of startup then
  full. Runs never overlap. Do not run the bomm harness at the same time.
- **Clock**: `Instant` around `Command::output()` only. Compilation, input conversion
  into a temporary directory, assertions and result writing are excluded.

## Reading a result

Files are `results/<UTC yyyymmddTHHMMSSZ>-<short commit>.json`; name order is time
order, and an existing file is never overwritten. Results are untracked
(`results/` is git-ignored); copy summaries to the task tracker.

| Field | Meaning |
| --- | --- |
| `startup`, `full` | `samples_seconds` in execution order, plus `min`, `p10`, `median`, `p90`, `max` |
| `search_seconds_median` | `full.median - startup.median` |
| `per_evaluation_microseconds` | search seconds / `evaluations` (8,456), in µs |
| `git_commit`, `binary_sha256`, `cpu_model`, `timestamp_utc`, `runs` | provenance |

Percentiles use nearest rank: the sample at rank `ceil(p·N/100)`, so `median` is the
lower middle sample for even N. Values can be negative when noise dominates; they
are reported, not clamped. There are no timing thresholds.
