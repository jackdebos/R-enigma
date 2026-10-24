# Recovery benchmark: correct-key success rate

Measures how often the engine recovers the correct key on synthetic,
historical-style messages, not just how fast it searches. This scaffold provides
an internal n-gram builder; fetching corpora and running recovery cases come later.
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
base letters. Remaining non-letters become separators. Each punctuation/space
run, line boundary and file boundary becomes one X, without boundary Xs at the
start or end. ASCII digits expand individually: 0 NULL, 1 EINS, 2 ZWO, 3 DREI,
4 VIER, 5 FUENF, 6 SECHS, 7 SIEBEN, 8 ACHT, 9 NEUN, each separated from its
neighbours by X. For example, `Größe 12, Übung.` becomes
`GROESSEXEINSXZWOXUEBUNG`.

Orders 1–6 count overlapping grams across the complete stream, including Xs.
Built bomm tables use lowercase grams, two spaces plus right-aligned counts,
sorted by descending count then gram; JSON uses the engine's v1 resource shape.
Conversion preserves source table order and validates lowercase grams, unique
entries and positive u64 counts (one gram/count pair per nonblank line).

## Layout and source policy

- `ngrams.py`, `test_ngrams.py`: builder/converter and CLI tests.
- `sources.md`: source URLs and attribution; no copied historical texts.
- `data/` (**git-ignored**): downloaded corpora, ciphertexts, keys, decrypted
  plaintexts and generated tables. Weierud-derived material is never committed;
  Leipzig-derived tables are not committed for now, pending a publication decision.
- `results/` (**git-ignored**): generated run reports, not source fixtures.

See [sources.md](sources.md) for provenance. Leipzig licensing must be confirmed
in T2 before corpus acquisition/use; this scaffold downloads nothing.
