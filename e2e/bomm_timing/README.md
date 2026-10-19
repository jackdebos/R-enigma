# Design A timing: pinned bomm reference

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

## One-time reference

The 100-run bomm capture is a **one-time reference**. Do not regenerate it unless
the comparison case changes. Never run it at the same time as our harness.

## What is measured

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
