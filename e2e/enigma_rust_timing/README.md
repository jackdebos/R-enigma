# U-264 timing: our release CLI

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

## Select the longer positions case

```sh
ENIGMA_TIMING_CASE=positions ENIGMA_TIMING_RUNS=20 e2e/enigma_rust_timing/run.sh
```

`ENIGMA_TIMING_CASE` accepts `a` (default, unchanged), `positions` or `b`; all other
values are rejected. The latter uses `e2e/bomm/m4-u264-attack-positions/`: design
A2, identical to A except middle/right positions sweep A–Z (676 outer keys).
Every full run checks the historical ten pairs, positions N/A and all 232
plaintext letters, plus completion of all 676 keys. Startup uses the selected
request with budget 1. Recommend 20 runs rather than 100: a manual single run
took 2.795 s (not a performance guarantee).

This is an **outcome-level comparison**, not identical search work. bomm runs
every pass on every outer key; our engine runs reswapping/measure only on the
hold-5 finalists. Observed totals were 5,492,071 bomm decrypts versus 5,372,197
our evaluations. Our total is parsed from the result's `evaluations_completed`
counter (stage `evaluations_used` alone is not the total), checked for stability
on every run and recorded as `evaluations`. `per_evaluation_microseconds` uses
our own count, never A's 8,456 or bomm's count.

A2 results use `results/<UTC>-<short commit>-positions.json`, with
`case: "m4-u264-attack-positions"`; A filenames and JSON fields remain unchanged.
Never run the two harnesses concurrently.

## Select design B: all three rotating positions

```sh
# Run only after the bomm harness has finished:
ENIGMA_TIMING_CASE=b ENIGMA_TIMING_RUNS=3 e2e/enigma_rust_timing/run.sh
```

Design B uses `e2e/bomm/m4-u264-attack-design-b/`: left/II, middle/IV and
right/I positions sweep A–Z, giving 26³ = 17,576 outer keys. Wheels, rings,
greek position V, reflector and other attack settings remain fixed as in A2.
B alone uses a 200,000,000 evaluation budget; A/A2 retain 100,000,000.
The old budget recovered the key but stopped after 12,579 outer keys.
Every full run must recover J/N/A, the ten historical pairs and all 232
plaintext letters, and complete all 17,576 keys. Startup uses this request
with budget 1. Use a small count such as 3; a full warm-up is also run.

This is outcome-level timing: bomm applies every pass inline to every key;
ours polishes only the hold-5 finalists with reswapping/measure. Each harness
reports its own observed evaluation count and uses it for per-evaluation time.
Results use `results/<UTC>-<short commit>-b.json` and
`case: "m4-u264-attack-design-b"`. A and A2 behavior remains unchanged.
Never run the harnesses concurrently.

## What is measured (default A)

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
