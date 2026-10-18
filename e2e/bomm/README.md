# bomm differential cases

Known-key decrypt/IC cases observed once from the unmodified bomm CLI
([ffraenz/bomm](https://github.com/ffraenz/bomm) at `aeb2f2bf00dfdee68e972f90ae7e83b387b188e9`)
and compared with this engine on every test run by
`crates/enigma-cli/tests/bomm_parity.rs`. This is not JSON compatibility. Each engine is
driven in its own schema. The tests need neither network nor the bomm binary.

## Layout

One directory per case:

- `query.json`: the exact bomm input that was run. The ciphertext here is the single source used by both engines.
- `case.json`: `kind` (`historical` or `constructed`), `provenance` (constructed cases carry their full source `plaintext` here), `engine` (the same key in this engine's schema), `plaintext` (historical cases only, as sourced), `capture` (commit, binary SHA-256, date, command, exit code, keys evaluated) and `observed` (bomm's preview, score and key line, verbatim).

The historical case is `m4-u264-first-break`: the first M4 Project break (U-264 message), whose plaintext is confirmed by the war diary. Its source URL and the copied values are listed in its `provenance`. The constructed ciphertexts were produced by this engine's CLI (`transform`, `encrypt`) from the plaintext given in `provenance`. bomm decrypts them independently.

## Capture

With `$R` the reference checkout (build details: `odd/tasks/enigma-engine-bomm-oracle.md`),
binary `$R/build/bomm` SHA-256 `58f236fc648638a21d7c1be7e4a355c0a9aeca7edcbbfc2743ebd8cdb81895b5`,
run from the repository root:

    $R/build/bomm -q -t 1 -n 1 e2e/bomm/<case>/query.json

Use short options only (the long options are declared without arguments). Each query fixes one wheel per slot, single-letter `rings`/`positions` masks and a fixed `plugboard`, and has one `{"type": "measure", "measure": "ic"}` pass. That means no search. Every capture printed `Number of units: 1` and `Number of decrypts: 1`. bomm silently drops non-lowercase letters, so query text is lowercase. The preview is the first 64 letters of the hold entry, and the score is `%+10.10f` cut to nine characters. Both are stored verbatim. Raw terminal output, logs and binaries are per-run artifacts and are not versioned.

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

- Text: our full decryption's first 64 letters must equal the uppercased preview exactly. Letters beyond the preview are not observed from bomm, so the full decryption must also equal the known plaintext: the sourced one for historical cases, the construction input for constructed ones. Each test declares its case's kind; a mismatching `kind` field fails instead of skipping a check.
- IC: bomm's measure pass scores `26 * sum f(f-1) / (n(n-1))` over the whole decrypted message (`src/measure.h` `bomm_measure_frequency_ic` via `bomm_measure_scrambler`), the same text and formula as `enigma_core::index_of_coincidence`. Our Q32 units are divided by `2^32`, and `|ours - printed| <= 1.1e-6` must hold. The printed value has six decimals, truncated, and our Q32 floor adds at most `2^-32`.
- A mismatch is reported as a discrepancy. Observed values are never edited to match.

## Coverage and remaining work

Covered: known-key decryption and resource-free IC on Enigma I, M3 (two-notch VI–VIII) and M4 (thin reflectors, Beta/Gamma), with nonzero rings, plugboards and middle-wheel double steps inside the preview, plus one historical message. Not covered: text beyond 64 letters against bomm itself, IC beyond six decimals, n-gram scoring, and every search (hill climbing, plugboard exploration, stages, hold list, outer ordering). Those are separate Task17 slices; attack comparisons must use real German text with a known plaintext. A source-linked helper calling bomm's functions directly would lift the 64-letter and six-decimal limits if needed.
