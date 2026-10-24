# Recovery benchmark: correct-key success rate

Measures how often the engine recovers the correct key on synthetic,
historical-style messages, not just how fast it searches. The internal tools build scoring tables, fetch
verified source texts and generate reproducible synthetic cases.
The builder is standalone Python 3 (standard library only), not an engine command.

## Quick path

From the repository root, with your own UTF-8 corpus already in `data/`:

```sh
python3 e2e/recovery/ngrams.py build e2e/recovery/data/corpus.txt --order 3 \
  --bomm-out e2e/recovery/data/trigram.txt --json-out e2e/recovery/data/trigram.json
python3 e2e/recovery/ngrams.py build e2e/recovery/data/corpus.txt --order 2 \
  --bomm-out e2e/recovery/data/bigram.txt --json-out e2e/recovery/data/bigram.json
python3 e2e/recovery/ngrams.py convert e2e/bomm/frequencies/enigma1941-trigram.txt \
  --order 3 --json-out e2e/recovery/data/enigma1941-trigram.json
python3 -m unittest discover -s e2e/recovery -v
```

Create `data/` locally before writing there. No input files means stdin; `-` also
means stdin. Use `--print-text` to inspect the militarized stream or `--text-out`
to save it. Output directories must exist. Existing files require `--force`;
inputs cannot be overwritten. See `build --help` and `convert --help` for options.

## Text and table conventions

Uppercase A-Z, umlauts AE/OE/UE and ß SS; other decomposable diacritics fold to
base letters. Words run together, as 1941 operators wrote them: spaces and tabs
are dropped. Each run of punctuation, symbols, line boundaries and file
boundaries becomes one X, without boundary Xs at the start or end. A number is
spelled digit by digit as one block (0 NULL, 1 EINS, 2 ZWO, 3 DREI, 4 VIER,
5 FUENF, 6 SECHS, 7 SIEBEN, 8 ACHT, 9 NEUN) with an X on either side. For
example, `An Panz. Gruppe 4` becomes `ANPANZXGRUPPEXVIER` and
`Größe 12, Übung.` becomes `GROESSEXEINSZWOXUEBUNG`. On the Leipzig news corpus
about 10% of trigrams contain X, against 21% in the enigma1941 table (an X
between every word would give 44%).

Orders 1–6 count overlapping grams across the complete stream, including Xs.
Built bomm tables use lowercase grams, two spaces plus right-aligned counts,
sorted by descending count then gram; JSON uses the engine's v1 resource shape.
Conversion preserves source table order and validates lowercase grams, unique
entries and positive u64 counts (one gram/count pair per nonblank line).

## Leipzig tables

`e2e/recovery/fetch_leipzig.sh [CORPUS]` (default `deu_news_2010_1M`, a 254 MB
download of 1,000,000 German news sentences) writes the archive, its sentences
and `leipzig-{bigram,trigram}.{txt,json}` to `data/leipzig/`, in about two
minutes. Reruns reuse the archive and sentences and refuse to replace existing
tables; delete them by hand to rebuild. The Leipzig Corpora Collection is
"made available free of charge for private and scientific use under the
Creative Commons licence CC BY-NC" (wortschatz.uni-leipzig.de/en/usage):
publishing a derived table needs attribution and stays non-commercial.

## Weierud texts

Run `python3 -B e2e/recovery/weierud.py`. Requires Python 3, `/usr/bin/pdftotext`
and the release Enigma CLI; the script builds the CLI if missing. Existing
downloads are reused. It decrypts the July 1941 Heeresgruppe Nord messages and
the messages of the 2017 article with their published keys.

Downloads, extracted text, `plaintexts.json` and `audit.json` stay in git-ignored
`data/weierud/`. Never commit source keys, ciphertexts or plaintexts.

HTML decryptions are compared with the published raw plaintext. PDF decryptions
check the published Stop positions (display-notch stepping, including the double
step), the header's cipher length and German trigram coverage; any disagreement
fails the message. Incomplete messages are skipped explicitly.
Verification failures are reported individually and the script exits 1; only
entries whose `verification.passed` is true may be used as benchmark input. On
2026-10-24: 53 decrypted, 48 verified (4,916 letters, lengths 18-214), 5 failed
on source inconsistencies, 16 skipped.

## Generate synthetic cases

After fetching the source texts and building the release CLI:

```sh
python3 -B e2e/recovery/cases.py
```

Writes `data/cases/manifest.json` (answers, source IDs and digest, engine digest,
seed and stream offsets) plus our requests and bomm queries for both tables and
both levels. The output directory must be new and inside `data/`; nothing is
replaced. Use `--out`, `--plaintexts`, `--engine` or `--seed` to override inputs;
`--help` lists their defaults. No source text is committed.

Only records with `verification.passed: true` contribute. Join their plaintexts
in recorded order with X, then consume non-overlapping segments: eight each of
50, 75, 100, 150 and 200 letters (40 cases, 4,600 stream letters). Seed 20261024
selects three distinct wheels I–V, independent rings and initial positions, B
reflector and ten disjoint plugboard pairs. The CLI encrypts every segment.

N1 searches all 17,576 positions with known wheels and rings; N2 also searches
the right ring (456,976 outer keys). Both attack an unknown board (capacity 13),
using HC (IC then Sinkov trigram), reswapping and final measure, with hold 100.
This freezes the current default explicitly. Cases/keys are identical across
levels and tables. Our resource paths are relative to each request; bomm paths
are relative to the repository root. Generate tables before running attacks;
case generation only transforms texts and does not load scoring resources.

## Run and summarize recovery

After generating cases and tables, run the base configuration from the repository root:

```sh
python3 -B e2e/recovery/run.py
# Only after that finishes, and after granting access to your bomm executable:
python3 -B e2e/recovery/run.py --configuration bomm --bomm PATH_TO_CONSENTED_BINARY
```

Defaults are ours, N1, both tables and six threads (allowed range 1–8).
`--level N2` selects the right-ring search; `--table enigma1941` or `--table leipzig`
selects one table. `--manifest` and `--engine` override the generated case manifest
and built Enigma CLI. Each selected case/table runs once, sequentially; never launch
runner invocations concurrently. This command does not schedule later stages or
create variants. Prepare a separate manifest/request set for a different attack.

Every invocation creates a unique ignored `results/` directory. `--out` can name a
new directory beneath it; existing output is never replaced. `summary.json` and
`summary.md` group successes, misses, errors, success rate and wall seconds by
length, table and configuration (`ours/N1`, for example). Rates include errors
in the denominator; misses exclude errors. Numbered artifacts retain each search's
exact stdout/stderr bytes, exit code, command, working directory and error, if any.
Provenance includes manifest, binary, request and scoring-resource SHA-256 digests,
seed, hold and threads. Wall time includes process startup and bomm-key replay.

Our successful exit must also contain a completed terminal done event and a result;
its best plaintext must match the **entire** original segment exactly. A completed
nonmatch is a miss, while cancellation, malformed output and nonzero exits are
errors. Bomm's preview is ignored: the first boxed UKW-B key is parsed (wheel order,
rings, positions and board), then replayed through the Enigma transform CLI against
the full ciphertext. Unsupported/missing keys or failed replay are errors. This
format is documented by the tracked Enigma I bomm fixtures; live validation still
requires consent to access the external binary.

Exit codes: 0 means all searches completed (possibly with misses), 1 means at least
one run error, and 2 means invalid input/setup. Setup failures create no output.
`--help` lists all options. Tests use invented messages and in-project fake tools;
they do not execute a real recovery benchmark.

## Layout and source policy

- `ngrams.py`, `test_ngrams.py`: builder/converter and CLI tests.
- `fetch_leipzig.sh`: Leipzig download and neutral tables.
- `weierud.py`, `test_weierud.py`: 1941 plaintext extraction and its tests
  (synthetic snippets only).
- `cases.py`, `test_cases.py`: seeded cases and N1/N2 requests; tests use invented
  texts and the built release CLI, including full encrypt/decrypt round trips.
- `run.py`, `test_run.py`: sequential search runner, full-text checks and summaries.
- `sources.md`: source URLs and attribution; no copied historical texts.
- `data/` (**git-ignored**): downloaded corpora, ciphertexts, keys, decrypted
  plaintexts and generated tables. Weierud-derived material is never committed;
  Leipzig-derived tables are not committed for now, pending a publication decision.
- `results/` (**git-ignored**): generated run reports, not source fixtures.

See [sources.md](sources.md) for provenance.
