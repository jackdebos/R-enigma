# bomm differential cases

Known-key decrypt/IC/Sinkov and opt-in plugboard-attack cases observed from the unmodified bomm CLI
([ffraenz/bomm](https://github.com/ffraenz/bomm) at `aeb2f2bf00dfdee68e972f90ae7e83b387b188e9`)
and compared with this engine (attack opt-in, other cases on every test run) by
`crates/enigma-cli/tests/bomm_parity.rs`. This is not JSON compatibility. Each engine is
driven in its own schema. The tests need neither network nor the bomm binary.

## Layout

One directory per case:

- `query.json`: the exact bomm input that was run. The ciphertext here is the single source used by both engines.
- `case.json`: `kind` (`historical`, `historical-wrong-key`, `historical-attack` or `constructed`), `provenance` (constructed cases carry their full source `plaintext` here), `engine` (the same key in this engine's schema), `plaintext` (correct-key historical cases only, as sourced), `capture` (commit, binary SHA-256, date, command, exit code, units and decrypts) and `observed` (bomm's preview, score and key line, verbatim).
- `frequencies/`: the two verbatim source tables described below; not a case directory.

The historical case is `m4-u264-first-break`: the first M4 Project break (U-264 message), whose plaintext is confirmed by the war diary. Its source URL and the copied values are listed in its `provenance`. The constructed ciphertexts were produced by this engine's CLI (`transform`, `encrypt`) from the plaintext given in `provenance`. bomm decrypts them independently.

The four `m4-u264-sinkov-{bigram,trigram}-{correct,wrong}` cases reuse that
historical ciphertext, with one fixed key per query. Correct cases reuse VJNA;
wrong cases change only the rightmost message-key position A to B (VJNB), keeping
wheels, rings and plugboard unchanged. This one-step offset produces non-German
output as a negative control. Wrong-key cases have no sourced plaintext: only
the preview is compared exactly. Both engines must score the correct key more
than 1 natural-log unit above the wrong key for each order.

## Opt-in design A plugboard attack

`m4-u264-attack-board` fixes the U-264 wheels, rings and positions but starts
with an empty, unknown plugboard. Both engines run IC hill climb → Sinkov trigram
(switch at 7 pairs, backtrack at 5), trigram reswapping, then trigram measure,
with hold 5. Our config uses `max_pairs: 13` and budget 100,000,000. Its
`historical-attack` case stores the search request under `engine`; the test
supplies ciphertext from the query and resources via the existing strict table
converter, writing JSON v1 and the request into a per-process directory under
the system temporary directory, removed after the CLI run.

Run the real CLI attack explicitly in release:

```sh
cargo test --release -p enigma-cli --test bomm_parity -- --ignored
```

The default suite checks fixture consistency and accounts for this directory,
but never runs the attack. Debug builds are too slow; revisit the opt-in choice
after the planned engine-optimization work. The successful measurement probe
was **0.028 s bomm (`-t 1`) versus 14.7 s ours (release)**, sequential single
runs, not a benchmark or stable performance guarantee. Both reported 8,456
evaluations/decrypts; that agreement is observational, not asserted.

The permanent query was separately captured exactly once from the repository
root using `timeout 120 $R/build/bomm -q -t 1 -n 5
e2e/bomm/m4-u264-attack-board/query.json`. It recovered
`AT BL DF GJ HM NW OP QY RZ VX`, preview
`vonvonjlooksjhffttteinseinsdreizwoyyqnnsneuninhaltxxbeiangriffun`, score
`-8.333018`, one unit and 8,456 decrypts (exit 0). Provenance, binary hash and
command are in `case.json`. This case compares **outcomes only**: stored bomm
pairs and our top board equal the ten historical pairs, and our full plaintext
equals the sourced 232 letters. bomm itself prints only a 64-letter preview.
There is no trajectory, score or evaluation-count assertion for the attack.

### Verify and time case A

The ignored test above runs the CLI exactly once and prints no timing. Timing
lives in two symmetric harnesses that read this directory's design-A inputs:

| Harness | Program | Guide |
| --- | --- | --- |
| `e2e/enigma_rust_timing/run.sh` | our release CLI | `e2e/enigma_rust_timing/README.md` |
| `e2e/bomm_timing/run.sh` | pinned bomm (`BOMM_BIN`) | `e2e/bomm_timing/README.md` |

Each runs `ENIGMA_TIMING_RUNS` (default 100) sequential pairs of a startup probe
and the full attack, checks every output, and writes a new untracked JSON file
under its `results/`. Per-evaluation search time is
`(median full - median startup) / 8456`. There are no timing thresholds.

### Design A2: unknown middle/right positions

A2 is a step between design A (1 key) and the planned design B (all three
rotating positions unknown, 17,576 keys; Task 17.7).


`m4-u264-attack-positions` is A with only middle/right positions unknown:
`*` in bomm, A–Z domains in our request, for 676 outer keys. All wheels, rings,
other positions, passes, measures, hold 5, budget and max_pairs remain unchanged.
A cheap non-ignored parity test verifies those exact fixture differences; the
attack itself remains opt-in through the timing harnesses:

```sh
ENIGMA_TIMING_CASE=positions ENIGMA_TIMING_RUNS=20 e2e/enigma_rust_timing/run.sh
# Run only after the first harness finishes:
ENIGMA_TIMING_CASE=positions ENIGMA_TIMING_RUNS=20 \
  BOMM_BIN=../bomm-reference/build/bomm e2e/bomm_timing/run.sh
```

Both recovered historical VJNA and `AT BL DF GJ HM NW OP QY RZ VX` in manual
single runs: 2.795 s ours, 5.764 s bomm. These are observations, not guarantees.
This is outcome-level timing: bomm runs every pass on every outer key, whereas
our engine runs reswapping/measure only on the hold-5 finalists. The resulting
counts differ (5,492,071 decrypts versus 5,372,197 completed evaluations).
Each harness reports its own actual count and divides by that count for
per-evaluation timing; no cross-engine count equality is asserted. Each full
run verifies the historical result; ours also checks N/A and full plaintext.
B filenames end in `-positions.json`; default A reports remain unchanged.

## Frequency tables

`frequencies/enigma1941-bigram.txt` and `enigma1941-trigram.txt` are byte-for-byte
copies of `data/frequencies/` in the pinned bomm commit above. Its README credits
raw 1941 Enigma message decrypt tables published by Frode Weierud,
[CryptoCellar](https://cryptocellar.org/bgac/keyofE.html). No separate data licence
is stated. No English tables are included.

| File | Records | SHA-256 |
| --- | ---: | --- |
| `enigma1941-bigram.txt` | 568 | `749fd92249944326fa6ae1b29ebcebc197ac2a745cfc88e2b2bc496fc74e5e08` |
| `enigma1941-trigram.txt` | 3514 | `e5e6e2ec7522e1e921393177fdc6acd86fe669984c4ffb9de3d7440ecc49f345` |

Both totals are 17694, with minimum count 1 (maxima 453 and 194). Hashes were
verified against the reference copies at capture time. No hash crate is an
available CLI dev-dependency, so tests do not assert SHA-256 and add no dependency.
The test-only adapter strictly validates lowercase ASCII grams and positive
integer counts, rejects duplicates/malformed records, uppercases grams and emits
JSON resource v1 in memory with ordered A–Z. The real public
`enigma_core::parse_ngram_json` parser loads it; no converted JSON is versioned.
Tests verify entry counts and rejection of malformed input.

## Capture

With `$R` the reference checkout (build details: `odd/tasks/enigma-engine-bomm-oracle.md`),
binary `$R/build/bomm` SHA-256 `58f236fc648638a21d7c1be7e4a355c0a9aeca7edcbbfc2743ebd8cdb81895b5`,
run from the repository root:

    $R/build/bomm -q -t 1 -n 1 e2e/bomm/<case>/query.json

Use short options only (the long options are declared without arguments). Each known-key query fixes one wheel per slot, single-letter `rings`/`positions` masks and a fixed `plugboard`, and has one `measure` pass (`ic`, `sinkov_bigram` or `sinkov_trigram`). That means no search. Every known-key capture printed `Number of units: 1` and `Number of decrypts: 1`. bomm silently drops non-lowercase letters, so query text is lowercase. The preview is the first 64 letters of the hold entry, and the score is `%+10.10f` cut to nine characters. Both are stored verbatim. Raw terminal output, logs and binaries are per-run artifacts and are not versioned.

N-gram queries supply `frequencies.bigram` or `frequencies.trigram` as
`e2e/bomm/frequencies/enigma1941-<order>.txt`. bomm opens these relative to the
**process working directory**, not the query directory: capture from this
repository root. Each of the four n-gram queries was run once on 2026-10-18,
exit 0, one unit and one decrypt. Reference HEAD, clean status and binary hash
were checked before and after capture and were unchanged.

## Schema mapping

| bomm `query.json` | this engine `case.json` |
| --- | --- |
| slots left to right: reflector, (greek), left, middle, right | slot ids `reflector`, (`greek`), `left`, `middle`, `right` |
| `UKW-B`, `UKW-C` | `B`, `C` |
| `UKW-B-thin`, `UKW-C-thin` | `Thin-B`, `Thin-C` |
| `beta`, `gamma` (non-rotating slot) | `Beta`, `Gamma` (fixed `greek` slot) |
| `I` … `VIII` with `"rotating": true` | `I` … `VIII` |
| `rings` / `positions` letter, `a` = 0 | `ring` / `position` letter, `A` = first |
| `plugboard` `"at bl …"` | `plugboard` `["AT", "BL", …]` |
| lowercase ciphertext | same text uppercased |

No ETW slot is given to bomm: without one it maps letters identically, as our machines do. UKW-A is not used.

## Comparison policy

- Text: our full decryption's first 64 letters must equal the uppercased preview exactly. Letters beyond the preview are not observed from bomm, so correct-key full decryptions must also equal the known plaintext: the sourced one for historical cases, the construction input for constructed ones. `historical-wrong-key` explicitly checks only the preview; its remaining output has no independent plaintext oracle. Each test declares its case's kind; a mismatching `kind` field fails instead of skipping a check.
- IC: bomm's measure pass scores `26 * sum f(f-1) / (n(n-1))` over the whole decrypted message (`src/measure.h` `bomm_measure_frequency_ic` via `bomm_measure_scrambler`), the same text and formula as `enigma_core::index_of_coincidence`. Our Q32 units are divided by `2^32`, and `|ours - printed| <= 1.1e-6` must hold. The printed value has six decimals, truncated, and our Q32 floor adds at most `2^-32`.
- Sinkov: both engines take the mean natural-log probability over every overlapping window of the full decryption: listed `ln(count/F)`, unseen `ln(m/(2F))`. bomm stores weights as binary32 and accumulates in binary64 (`src/measure.c:107–130`, `src/measure.h`); ours uses deterministic Q32 weights and a floored Q32 mean (see `docs/scoring-resources.md` §4–5). For **each printed score**, derive decimal count `d` from its string and use `10^-d + 2^-21 + 1e-9`. The first term covers display truncation (including the final decimal rounding before cutting); the second is half a binary32 ULP for weights with magnitude below 16. Both tables' largest magnitude is the unseen weight, `ln(35388) ≈ 10.474128`; all counts are exactly representable in binary32 and their totals in binary64. Tests guard these bounds. The conservative `1e-9` covers two Q32 floors (less than `2/2^32`), the Q48 log approximation and binary64 log/accumulation on 230–231 windows. Tests additionally compare every listed Q32 weight and an unseen weight with binary64 ln within `1e-9`. The tolerance is about `1.477837e-6` for six decimals or `1.047784e-5` for five, not fitted to the observed differences below.
- A mismatch is reported as a discrepancy. Observed values are never edited to match.

Measured before setting the Sinkov tolerance (Q32 units divided by `2^32`):

| Order/key | bomm printed | Ours | Absolute difference |
| --- | ---: | ---: | ---: |
| bigram/correct | -6.038888 | -6.038888248848 | 2.48848e-7 |
| bigram/wrong | -7.848161 | -7.848161784234 | 7.84234e-7 |
| trigram/correct | -8.333018 | -8.333018734353 | 7.34353e-7 |
| trigram/wrong | -10.19315 | -10.193157256581 | 7.256581e-6 |

## Coverage and remaining work

Covered: known-key decryption and resource-free IC on Enigma I, M3 (two-notch VI–VIII) and M4 (thin reflectors, Beta/Gamma), with nonzero rings, plugboards and middle-wheel double steps inside the preview, plus one historical message and German Enigma1941 bigram/trigram Sinkov scoring on its correct and wrong keys. The opt-in design A case adds unknown-plugboard hill-climb/reswapping outcome coverage with fixed outer settings. Not covered: text beyond 64 letters against bomm itself, scores beyond display precision, other n-gram orders/tables, general search/plugboard exploration, stage trajectories, hold-list ordering and outer ordering. Those are separate Task17 slices; attack comparisons must use real German text with a known plaintext. A source-linked helper calling bomm's functions directly would lift the 64-letter and six-decimal limits if needed.
