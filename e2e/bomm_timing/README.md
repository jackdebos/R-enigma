# U-264 timing: pinned bomm reference

Measures the pinned bomm binary (commit `aeb2f2bf00dfdee68e972f90ae7e83b387b188e9`) on
design A (`e2e/bomm/m4-u264-attack-board/`) and writes one new JSON file per
invocation. It mirrors `e2e/enigma_rust_timing/`: same clock, order and statistics.

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

## Select the longer positions case

```sh
ENIGMA_TIMING_CASE=positions ENIGMA_TIMING_RUNS=20 \
  BOMM_BIN=../bomm-reference/build/bomm e2e/bomm_timing/run.sh
```

`ENIGMA_TIMING_CASE` accepts `a` (default, unchanged), `positions` or `b`; all other
values are rejected. The latter uses `e2e/bomm/m4-u264-attack-positions/`: design
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

A2 results use `results/<UTC>-<short commit>-positions.json`, with
`case: "m4-u264-attack-positions"`; A filenames and JSON fields remain unchanged.
Never run the two harnesses concurrently.

## Select design B: all three rotating positions

```sh
ENIGMA_TIMING_CASE=b ENIGMA_TIMING_RUNS=3 \
  BOMM_BIN=../bomm-reference/build/bomm e2e/bomm_timing/run.sh
```

Design B uses `e2e/bomm/m4-u264-attack-design-b/`: left/II, middle/IV and
right/I positions are unknown (`*`), giving 26³ = 17,576 outer keys. Wheels,
rings, greek position V, reflector and attack passes remain fixed as in A2.
Our counterpart uses a 200,000,000 evaluation budget for B only, rather than
A/A2's 100,000,000, to complete the entire space. bomm has no such budget flag.
Every full run verifies historical VJNA and all ten pairs. Startup remains
the fixed design-A one-decrypt probe. The single capture reported 17,576 units
and 142,788,085 decrypts; this is not a required cross-engine workload count.
bomm runs all passes inline on every key, unlike our finalist-only polishing.

Use a small count such as 3: each invocation also runs a full warm-up.
Results use `results/<UTC>-<short commit>-b.json` and
`case: "m4-u264-attack-design-b"`, with bomm's own observed count for timing.
Wait for this harness to finish before running ours. A and A2 are unchanged.

## One-time reference

The 100-run bomm capture is a **one-time reference**. Do not regenerate it unless
the comparison case changes. Never run it at the same time as our harness.

## What is measured (default A)

Both probes use the flags recorded in the case capture (`-q -t 1 -n 5`).

| Probe | Query | Checked on every run |
| --- | --- | --- |
| startup | `startup-query.json`: design-A slots, empty plugboard, one trigram `measure` pass | success, empty board, 1 decrypt if printed |
| full | `e2e/bomm/m4-u264-attack-board/query.json` | ten historical pairs on the top key line, 8,456 decrypts if printed |

- **Startup** = process start, query parsing, trigram table load and one decrypt.
- **Order and clock**: as in our harness; one unrecorded warm-up per probe, then N
  iterations of startup then full, timed by `Instant` around `Command::output()`.
  bomm's own `Elapsed` display is not used.

## Reading a result

Files are `results/<UTC yyyymmddTHHMMSSZ>-<short commit>.json` (repository commit);
name order is time order and files are never overwritten. Results are untracked;
copy summaries to the task tracker. Fields match our harness
(see `e2e/enigma_rust_timing/README.md`) plus `bomm_commit`:
`per_evaluation_microseconds = (full.median - startup.median) / 8456`, with
nearest-rank percentiles.
