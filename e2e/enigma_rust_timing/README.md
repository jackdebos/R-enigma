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
`crates/enigma-cli/tests/case_a_timing.rs`, which uses that same binary with
`enigma --events - --threads N request.json`. The opt-in JSONL stream keeps the
live `started` measurement unchanged; no human report or progress bar is emitted.

## Select threads

`ENIGMA_TIMING_THREADS` is a decimal integer from 1 to 256; absent means **1**.
Invalid values fail before measurement. The launcher passes explicit `--threads N`;
this does not change the application's half-logical-CPU default. Reports include
numeric `threads`, and every filename ends in `-tN.json`, including default `-t1`.
Other flags, fixtures, correctness checks and statistics stay unchanged.

## Select the longer positions case

```sh
ENIGMA_TIMING_CASE=positions ENIGMA_TIMING_RUNS=20 e2e/enigma_rust_timing/run.sh
```

`ENIGMA_TIMING_CASE` accepts `a` (default, unchanged), `positions`, `b` or `c`; all
other values are rejected. `positions` uses `e2e/bomm/m4-u264-attack-positions/`: design
A2, identical to A except middle/right positions sweep A–Z (676 outer keys).
Every full run checks the historical ten pairs, positions N/A and all 232
plaintext letters, plus completion of all 676 keys. Startup is measured inside
each full run at `started`. Recommend 20 runs rather than 100: a manual single run
took 2.795 s (not a performance guarantee).

This is an **outcome-level comparison**, not identical search work. bomm runs
every pass on every outer key; our engine runs reswapping/measure only on the
hold-5 finalists. Observed totals were 5,492,071 bomm decrypts versus 5,372,197
our evaluations. Our total is parsed from the result's `evaluations_completed`
counter (stage `evaluations_used` alone is not the total), checked for stability
on every run and recorded as `evaluations`. `per_evaluation_microseconds` uses
our own count, never A's 8,456 or bomm's count.

A2 results use `results/<UTC>-<short commit>-positions-tN.json`, with
`case: "m4-u264-attack-positions"`.
Never run the two harnesses concurrently.

## Select design B: all three rotating positions

```sh
# Run each invocation only after the previous harness has finished:
ENIGMA_TIMING_CASE=b ENIGMA_TIMING_THREADS=1 ENIGMA_TIMING_RUNS=3 e2e/enigma_rust_timing/run.sh
ENIGMA_TIMING_CASE=b ENIGMA_TIMING_THREADS=6 ENIGMA_TIMING_RUNS=3 e2e/enigma_rust_timing/run.sh
```

Design B uses `e2e/bomm/m4-u264-attack-design-b/`: left/II, middle/IV and
right/I positions sweep A–Z, giving 26³ = 17,576 outer keys. Wheels, rings,
greek position V, reflector and other attack settings remain fixed as in A2.
The evaluation cap has been removed; B no longer needs a raised cap to finish
its finite space.
Every full run must recover J/N/A, the ten historical pairs and all 232
plaintext letters, and complete all 17,576 keys. Startup is measured inside
each full run at `started`. Use a small count such as 3; a full warm-up is also run.

This is outcome-level timing: bomm applies every pass inline to every key;
ours polishes only the hold-5 finalists with reswapping/measure. Each harness
reports its own observed evaluation count and uses it for per-evaluation time.
Results use `results/<UTC>-<short commit>-b-tN.json` and
`case: "m4-u264-attack-design-b"`. A and A2 behavior remains unchanged.
Never run the harnesses concurrently. Initial comparison uses explicit 1 and 6
threads for both engines, each with one unrecorded warm-up and 3 recorded runs.
Compare **full-time medians** primarily: equal threads do not imply equal evaluation
work or equal startup boundaries. The 1/2/4/8 scaling sweep is deferred.

## Select design C: positions and the right ring

```sh
# Run only after the bomm harness has finished:
ENIGMA_TIMING_CASE=c ENIGMA_TIMING_THREADS=6 ENIGMA_TIMING_RUNS=1 e2e/enigma_rust_timing/run.sh
```

Design C uses `e2e/bomm/m4-u264-attack-design-c/`: design B plus an A–Z `rings`
domain on the right wheel, giving 26 × 26³ = 456,976 outer keys. Everything else
remains fixed as in B. Every full run must recover ring V, positions J/N/A, the
ten historical pairs and all 232 plaintext letters, and complete all 456,976 keys
(3,636,321,119 evaluations). The reference run took 404.0 s at 6 threads; the
hold-5 runners-up are near-equivalent right ring/position shifts, as in bomm.

Use `ENIGMA_TIMING_THREADS=6 ENIGMA_TIMING_RUNS=1`: a full warm-up is also run.
Results use `results/<UTC>-<short commit>-c-tN.json` and
`case: "m4-u264-attack-design-c"`. A, A2 and B behavior remains unchanged.
Never run the harnesses concurrently.

## What is measured (default A)

Every full run uses the unchanged design-A request (8,456 evaluations) and checks
the ten historical pairs and the full 232-letter plaintext. No separate startup
request or process is used.

- **Startup** = wall time from just before process spawn until the live stdout
  reader receives the `started` event. This is an in-run event boundary, not the
  former one-evaluation probe and **not comparable to bomm's startup probe**.
- **Full** = wall time from the same spawn boundary until process exit is observed.
  **Search** = full minus startup, computed separately for each run before statistics.
  Full-time medians are the primary cross-engine comparison; startup equivalence
  and identical evaluation work are not claimed.
- **Order**: one unrecorded full warm-up, then N full runs, strictly sequentially.
  Do not run the bomm harness at the same time.
- **Clock**: `Instant`, with stdout read as events arrive (not parsed after exit).
  Compilation, input conversion into a temporary directory, assertions and result
  writing are excluded.

## Reading a result

Files for A are `results/<UTC yyyymmddTHHMMSSZ>-<short commit>-tN.json`; name order is time
order, and an existing file is never overwritten. Results are untracked
(`results/` is git-ignored); copy summaries to the task tracker.

| Field | Meaning |
| --- | --- |
| `startup`, `search`, `full` | per-run `samples_seconds` in execution order, plus `min`, `p10`, `median`, `p90`, `max` |
| `startup_measurement` | `in_run_started_event`; distinguishes this method from older separate-probe reports |
| `search_seconds_median` | `search.median` (median of paired differences, not difference of medians) |
| `evaluations` | completed evaluations per full run, checked for stability |
| `per_evaluation_microseconds` | `search.median * 1e6 / evaluations` (8,456 for A) |
| `threads` | explicit engine thread count (default 1) |
| `git_commit`, `binary_sha256`, `cpu_model`, `timestamp_utc`, `runs` | provenance |

Percentiles use nearest rank: the sample at rank `ceil(p·N/100)`, so `median` is the
lower middle sample for even N. In-run startup cannot exceed its full run, so
paired search samples are nonnegative. There are no timing thresholds. Older
separate-probe results use a different startup boundary and search statistic;
do not mix them with these reports.
