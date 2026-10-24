# U-264 timing: pinned bomm reference

Measures the pinned bomm binary (commit `aeb2f2bf00dfdee68e972f90ae7e83b387b188e9`) on
design A (`e2e/bomm/m4-u264-attack-board/`) and writes one new JSON file per
invocation. It shares the clock and percentile conventions with
`e2e/enigma_rust_timing/`, but retains its separate startup probe.

## Quick path

```sh
BOMM_BIN=/path/to/bomm-reference/build/bomm e2e/bomm_timing/run.sh  # 100 runs
e2e/bomm_timing/run.sh /path/to/bomm                                # same, by argument
ls e2e/bomm_timing/results/ | tail -n 1                             # newest result
```

Works from any directory; bomm runs with the repository root as its working
directory because it opens frequency tables relative to it. The script fails if
no binary is given, and the test fails unless its SHA-256 equals the hash recorded
in the design-A `case.json`.

## Select threads

`ENIGMA_TIMING_THREADS` is a decimal integer from 1 to 256; absent means **1**.
Invalid values fail before measurement. Both probes use explicit `-t N`, replacing
only the captured `-t 1` value; all other capture flags and fixtures are unchanged.
Reports include numeric `threads`, and every filename ends in `-tN.json`, including
default `-t1`. Correctness checks and statistics stay unchanged.

## Select the longer positions case

```sh
ENIGMA_TIMING_CASE=positions ENIGMA_TIMING_RUNS=20 \
  BOMM_BIN=../bomm-reference/build/bomm e2e/bomm_timing/run.sh
```

`ENIGMA_TIMING_CASE` accepts `a` (default, unchanged), `positions`, `b` or `c`; all
other values are rejected. `positions` uses `e2e/bomm/m4-u264-attack-positions/`: design
A2, identical to A except middle/right positions are unknown (`*`, 26 × 26 = 676
outer keys). It verifies the top historical key VJNA and all ten pairs every run.
Startup remains the fixed design-A one-decrypt probe. Recommend 20 runs rather
than 100: a manual single run took 5.764 s (not a performance guarantee).

This is an **outcome-level comparison**, not identical search work. bomm runs
every pass on every outer key; our engine runs reswapping/measure only on the
hold-5 finalists. Observed totals were 5,492,071 bomm decrypts versus 5,372,197
our evaluations. The harness parses each run's actual total and checks stability;
it never uses A's 8,456 for A2 or B. If bomm omits its count, both `evaluations` and
`per_evaluation_microseconds` are omitted. Otherwise the latter divides the
median search time by bomm's own count, in microseconds.

A2 results use `results/<UTC>-<short commit>-positions-tN.json`, with
`case: "m4-u264-attack-positions"`.
Never run the two harnesses concurrently.

## Select design B: all three rotating positions

```sh
ENIGMA_TIMING_CASE=b ENIGMA_TIMING_THREADS=1 ENIGMA_TIMING_RUNS=3 \
  BOMM_BIN=../bomm-reference/build/bomm e2e/bomm_timing/run.sh
# Wait for completion, then:
ENIGMA_TIMING_CASE=b ENIGMA_TIMING_THREADS=6 ENIGMA_TIMING_RUNS=3 \
  BOMM_BIN=../bomm-reference/build/bomm e2e/bomm_timing/run.sh
```

Design B uses `e2e/bomm/m4-u264-attack-design-b/`: left/II, middle/IV and
right/I positions are unknown (`*`), giving 26³ = 17,576 outer keys. Wheels,
rings, greek position V, reflector and attack passes remain fixed as in A2.
Our counterpart's evaluation cap has been removed; B needs no raised cap to
complete the entire finite space, just as bomm has no such cap.
Every full run verifies historical VJNA and all ten pairs. Startup remains
the fixed design-A one-decrypt probe. The single capture reported 17,576 units
and 142,788,085 decrypts; this is not a required cross-engine workload count.
bomm runs all passes inline on every key, unlike our finalist-only polishing.

Use a small count such as 3: each invocation also runs a full warm-up.
Results use `results/<UTC>-<short commit>-b-tN.json` and
`case: "m4-u264-attack-design-b"`, with bomm's own observed count for timing.
Wait for this harness to finish before running ours. A and A2 checks are unchanged.
Initial comparison uses explicit 1 and 6 threads for both engines, each with one
unrecorded warm-up per probe and 3 recorded runs. Compare **full-time medians**
primarily: equal threads do not imply equal evaluation work or startup boundaries.
The 1/2/4/8 scaling sweep is deferred.

## Select design C: positions and the right ring

```sh
ENIGMA_TIMING_CASE=c ENIGMA_TIMING_THREADS=6 ENIGMA_TIMING_RUNS=1 \
  BOMM_BIN=../bomm-reference/build/bomm e2e/bomm_timing/run.sh
```

Design C uses `e2e/bomm/m4-u264-attack-design-c/`: design B plus the right-wheel
ring unknown (`"rings": "*"`), giving 26 × 26³ = 456,976 outer keys. Everything
else remains fixed as in B. Every full run verifies the historical top key
(ring V, positions VJNA) and all ten pairs. The single capture at `-t 6` took
693.9 s wall and reported 456,976 units and 3,718,611,649 decrypts; this is not a
required cross-engine workload count. The capture's `-t 6` is replaced by the
selected thread count like the other cases' `-t 1`.

Use `ENIGMA_TIMING_THREADS=6 ENIGMA_TIMING_RUNS=1`: each invocation also runs a
full warm-up, so one recorded run already takes over 20 minutes. Results use
`results/<UTC>-<short commit>-c-tN.json` and `case: "m4-u264-attack-design-c"`.
Never run this harness concurrently with ours. A, A2 and B checks are unchanged.

## One-time reference

The 100-run bomm capture is a **one-time reference**. Do not regenerate it unless
the comparison case changes. Never run it at the same time as our harness.

## What is measured (default A)

Both probes use the captured flags, replacing only the thread value
(`-q -t N -n 5`, default N=1).

| Probe | Query | Checked on every run |
| --- | --- | --- |
| startup | `startup-query.json`: design-A slots, empty plugboard, one trigram `measure` pass | success, empty board, 1 decrypt if printed |
| full | `e2e/bomm/m4-u264-attack-board/query.json` | ten historical pairs on the top key line, 8,456 decrypts if printed |

- **Startup** = process start, query parsing, trigram table load and one decrypt.
- **Order and clock**: one unrecorded warm-up per probe, then N
  iterations of startup then full, timed by `Instant` around `Command::output()`.
  bomm's own `Elapsed` display is not used.

## Reading a result

Files for A are `results/<UTC yyyymmddTHHMMSSZ>-<short commit>-tN.json` (repository commit);
name order is time order and files are never overwritten. Results are untracked;
copy summaries to the task tracker. `startup` and `full` contain execution-order
samples and nearest-rank statistics, with `bomm_commit` recording provenance
and numeric `threads` recording the explicit thread count.
`search_seconds_median = full.median - startup.median` and
`per_evaluation_microseconds = search_seconds_median * 1e6 / evaluations`.
Our harness instead measures startup inside each full run at `started` and reports
paired search samples (see `e2e/enigma_rust_timing/README.md`). Startup times are
not comparable; full-time medians are the primary cross-engine metric, not
claims of identical hot-loop work.
