# Scoring and external resources

Status: **Normative unpublished protocol v1 contract; implementation is partial.**
The core implements checked fixed-point arithmetic, monogram IC, and positive
Shannon entropy with explicit ranking orientation. Typed sparse n-gram models and
Sinkov scoring and strict standalone n-gram JSON parsing (`parse_ngram_json`) are
also implemented in the core. Typed immutable weighted dictionaries (`TrieModel`)
and exact overlapping trie scoring are implemented. Strict standalone dictionary
JSON parsing (`parse_dictionary_json`) returns a validated `TrieModel`.
Resource binding and CLI resource loading remain unimplemented. Slice 10.1 froze this
contract before those implementation slices; the formulas below remain normative.
The current CLI cannot execute search, including structurally valid search requests.
See [Engine Protocol](protocol.md) for the surrounding request and event contract.

## 1. Quick path and measure selection

1. Select a nonempty array of unique measure IDs in `job.measures`.
2. For each Sinkov or trie measure, save a reusable external JSON resource and
   reference its path under that exact measure ID in `job.resources`.
3. Have the caller load bounded UTF-8 text and bind validated resource contents
   before candidate enumeration. Core parsers never open files.

| Measure ID | Required resource | Minimum text length | Ranking orientation |
| --- | --- | --- | --- |
| `ic` | None | 2 scalars | Higher measured value |
| `entropy` | None | 1 scalar | Negative of positive measured entropy |
| `sinkov_monogram` | N-gram, order 1 | 1 scalar | Higher measured value |
| `sinkov_bigram` | N-gram, order 2 | 2 scalars | Higher measured value |
| `sinkov_trigram` | N-gram, order 3 | 3 scalars | Higher measured value |
| `sinkov_quadgram` | N-gram, order 4 | 4 scalars | Higher measured value |
| `sinkov_pentagram` | N-gram, order 5 | 5 scalars | Higher measured value |
| `sinkov_hexagram` | N-gram, order 6 | 6 scalars | Higher measured value |
| `trie` | Dictionary | 1 scalar | Higher measured value |

These are the initial supported names; unsupported names fail. IC and entropy
initially operate on monograms only. IDs have no aliases. Every selected
resource-dependent measure has exactly one reference; resource-free measures have
none. Measures are independently ordered: selecting several does not define a
combined score, implicit sum, or combined ranking.

### Request fragment

This is a search-job fragment, not a complete executable request. The enclosing
request must supply the definition, configuration, space, passes, and text required
by [protocol §3.3](protocol.md#33-search-job-boundary-task-9-grammar).

```json
{
  "measures": ["ic", "entropy", "sinkov_bigram", "trie"],
  "resources": {
    "sinkov_bigram": {"path": "models/two-symbol-bigrams.json"},
    "trie": {"path": "dictionaries/two-symbol-words.json"}
  }
}
```

`job.resources` is an optional object keyed only by selected measure IDs. Each
reference object has exactly one field, `path`, a nonempty string. Missing required
references, unused references (including references for `ic` or `entropy`), duplicate
IDs, inline contents, unknown fields, and empty paths fail. An omitted resources
object or `{}` is valid only when all selected measures are resource-free.
Existing resource-free `ic` requests remain valid when they have sufficient samples.

## 2. External JSON schemas

Resources are external files only; no embedded models or dictionaries are accepted.
Every object below has exactly the listed fields. Duplicate JSON keys are invalid
at every depth, even when their values agree; unknown fields are invalid too.
Versions other than integer `resource_version: 1` fail.

Every resource declares `alphabet`: a nonempty ordered array of unique strings,
each containing exactly one Unicode scalar. It must equal the resolved machine
alphabet, including order. Grams and words use the same single-scalar string arrays;
every symbol must belong to that alphabet. No trimming, case folding, normalization,
padding, or conversion is performed. A combining sequence contains multiple scalars.
Entry order is not significant; alphabet order is significant.

### 2.1 Sparse n-gram model

An n-gram resource has exactly `resource_version`, `kind`, `alphabet`, `order`,
and `entries`. `kind` is `"ngram"`; `order` is an integer from 1 through 6 and must
match the selected Sinkov measure. `entries` is nonempty. Each entry has exactly
`gram` and `count`; the gram has exactly `order` scalars and is unique in the model.
`count` is a positive unsigned 64-bit integer, not a probability or floating value.
Counts are totaled with checked unsigned 128-bit arithmetic; total overflow fails.

```json
{
  "resource_version": 1,
  "kind": "ngram",
  "alphabet": ["A", "B"],
  "order": 2,
  "entries": [
    {"gram": ["A", "A"], "count": 2},
    {"gram": ["A", "B"], "count": 1},
    {"gram": ["B", "A"], "count": 1}
  ]
}
```

Sparse means unlisted grams are permitted and receive the floor in §5.3. Do not
expand a sparse model into the complete alphabet power. There is no smoothing,
renormalization, or implicit conversion beyond that explicitly defined unseen floor.

### 2.2 Weighted dictionary

A dictionary has exactly `resource_version`, `kind`, `alphabet`, and `entries`.
`kind` is `"dictionary"`; `entries` is nonempty. Each entry has exactly `word` and
`weight`. A word is a nonempty array of at most 256 scalars and is unique in the
dictionary. `weight` is a signed 32-bit integer. Negative weights are deliberate
penalties; zero is permitted. Matching uses an exact weighted trie, not garbles,
fuzzy matches, or an automatically added base score.

```json
{
  "resource_version": 1,
  "kind": "dictionary",
  "alphabet": ["A", "B"],
  "entries": [
    {"word": ["A"], "weight": 1},
    {"word": ["A", "B"], "weight": 3},
    {"word": ["B", "A"], "weight": -2}
  ]
}
```

Empty models/dictionaries, repeated grams/words, wrong resource kinds or orders,
and mismatched alphabets fail rather than being repaired or silently ignored.

## 3. Bounded parsing and loading

These are engineering defaults, not historical language-model constraints.
Existing request, definition, alphabet, and text limits remain in force.

| Limit | Maximum |
| --- | --- |
| Encoded UTF-8 text per resource file | 16 MiB (16 × 2^20 bytes) |
| Aggregate resource text per request | 64 MiB (64 × 2^20 bytes) |
| References per request | 16 |
| Entries per resource | 250,000 |
| N-gram order | 1–6 |
| Dictionary word length | 256 Unicode scalars |
| Trie nodes, including root, per dictionary | 1,000,000 |

The current measure set naturally permits fewer than 16 references. Aggregate
accounting counts supplied text for each reference, even if paths coincide.
Enforce byte sizes, reference/entry counts, and trie-node growth before large
allocations or expansions; return diagnostics, never panics. A bounded reader may
read at most one extra byte to detect a file-size violation. Check the aggregate
budget while loading, not after collecting arbitrarily large files. Core parsers
also validate supplied-text sizes and semantic limits; caller bounds do not replace
core validation. Do not allocate an alphabet-to-the-order dense table.

### 3.1 Path resolution belongs to the caller

| Request source | Base for relative resource paths |
| --- | --- |
| Positional file or `--request <path>` | Directory of the request filename |
| `--request -` (stdin) | Working directory captured once for that request |

Absolute resource paths are allowed. There is no tilde or environment-variable
expansion, URL fetching, or automatic symlink canonicalization. Resolve relative
request filenames against the captured working directory, then use their containing
directory as the base; do not switch to a symlink target's directory. Ordinary
filesystem symlink behavior is not a sandbox. User-selected files may be anywhere
the caller can read; no repository confinement is imposed.

The caller/CLI performs bounded reads and UTF-8 validation before `started`.
Unreadable files and invalid UTF-8 are pre-start errors. Retain loaded contents once
for binding and scoring, rather than rereading files for each candidate. A path is
not itself validated resource content.

### 3.2 Two-stage core boundary

`ParsedSearchRequest` denotes a structurally parsed request: exact fields, measure
IDs, references, machine/text validation, coverage, and applicable compatibility
checks have passed. It **cannot enumerate candidates** while resource contents are
unbound. `bind_resources` receives resource text keyed by measure ID, never paths
to open, and validates schemas, kinds, orders, alphabets, totals, and all limits.
Missing or extra supplied content fails. Only successful binding produces a fully
validated `SearchRequest` carrying scoring resources and eligible for enumeration.

Exact Rust names may vary; the invariant must not: no partially validated request
can enumerate. `SearchRequest::parse_json` remains a convenience for resource-free
requests and fails when external binding is needed. Pure resource parsers accept
supplied text and never perform filesystem I/O.

Shared strict job dispatch must distinguish transform and search without weakening
duplicate-key detection or interpreting invalid search JSON as a transform. Transform
never loads scoring resources. After the loader integration slice, the CLI validates
and binds search resources, then emits exactly one `unsupported_job` error: no
`started`, `output`, `done`, or candidate enumeration. Resource validation errors
precede that unsupported-search result. This is a future integration requirement,
not a claim that the current CLI already loads resources or runs search.

## 4. Score representation and reproducible logarithms

All core measured scores use checked signed 128-bit integers in Q32 units:
`SCALE = 2^32 = 4294967296`. The represented value is `score / SCALE`.
Integer products, accumulations, conversion, and ranking negation are checked.
Under applicable sample/resource limits, a failed check is an explicit score-overflow
diagnostic, never wrapping arithmetic, a panic, NaN, or a competitive sentinel.

The mathematical formulas in §5 explain meaning. Their deterministic approximation
is frozen below; it is neither the exact floor of every real-valued formula nor a
promise of bitwise compatibility with `bomm` floating-point scores. Platform `libm`
is not the scoring contract.

### 4.1 Integer log2 helper

For a positive unsigned 128-bit integer `v`, define `B(v)` in Q48:

1. Let `k = floor(log2(v))`, found from the highest set bit, not floating point.
2. Normalize to a Q63 mantissa `m` in `[2^63, 2^64)`: left shift `v` by `63-k`
   when `k <= 63`, otherwise floor-right-shift by `k-63`.
3. Initialize `fraction = 0`. For fractional bit indices `i = 1..48`:
   square `m` in unsigned 128-bit arithmetic and set `m = (m*m) >> 63`.
   If `m >= 2^64`, set `m = m >> 1` and set bit `48-i` in `fraction`.
4. Return `B(v) = k * 2^48 + fraction`.

Every discarded intermediate bit truncates downward. The pre-square mantissa is
always less than `2^64`, so its square fits u128; the post-square value before
halving is held in u128, not u64. Zero is outside the helper's domain.
A rational log2 is defined as the signed difference `B(num) - B(denom)`, not as
`B` of a rounded integer quotient.

### 4.2 Natural logs and division

Freeze `C = floor(ln(2) * 2^48) = 195103586505167`.
For positive integer numerator and denominator, define:

```text
lnQ32(num / denom) = floor((B(num) - B(denom)) * C / 2^64)
```

All signed floor divisions round toward negative infinity, **not** Rust integer
truncation toward zero. This distinction affects negative Sinkov weights and sums.
There is no platform-dependent transcendental call in the runtime definition.

## 5. Measure semantics

Let `A` be alphabet size, `L` the number of input Unicode scalars, and `c` a symbol's
observed count. Text must belong to the resolved alphabet. No measure adds padding.
Reject insufficient input before scoring; empty text is invalid for every measure.

### 5.1 Alphabet-scaled index of coincidence

```text
IC = A * sum_c(c * (c - 1)) / (L * (L - 1)),  L >= 2
ICQ32 = floor(SCALE * A * sum_c(c * (c - 1)) / (L * (L - 1)))
```

Absent symbols contribute zero (do not subtract one from an unsigned zero count).
The integer rational is truncated downward. Higher values rank better.
For alphabet `["A", "B"]` and text `"AA"`, IC is 2, represented as `2 * SCALE`.

### 5.2 Positive Shannon entropy

```text
H = -sum_{c > 0} (c / L) * log2(c / L),  L >= 1
HQ32 = floor(sum_{c > 0} c * (B(L) - B(c)) / (L * 2^16))
```

The measured value is nonnegative entropy in bits. Ranking uses `-HQ32`, derived
only after quantizing the positive value. Do not expose negative entropy as the
measured value or silently sum it with other measures.
Balanced text `"AB"` over `["A", "B"]` has exactly 1 bit under this helper:
`HQ32 = SCALE`, ranking orientation `-SCALE`. Constant text has entropy zero.

### 5.3 Sinkov mean log probability

For order `n`, inspect every overlapping contiguous n-gram window, without padding.
There are `W = L - n + 1` windows; require `W > 0`. Let `F` be the checked sum of
listed counts and `m` their minimum positive count. For each window:

```text
q = count / F          if the gram is listed
q = m / (2 * F)        otherwise
mathematical score = sum_windows ln(q) / W
weightQ32 = lnQ32(count / F) or lnQ32(m / (2 * F))
SinkovQ32 = floor(sum_windows weightQ32 / W)
```

Compute and quantize each log weight first, then floor the integer mean. Higher
scores rank better. The missing-gram floor is not renormalized into a probability
distribution. Unique grams with positive counts remove ambiguity from duplicate or nonpositive
source-loader inputs. All totals, `2 * F`, and score accumulations are checked.
For the example bigram model, `"ABA"` has windows `AB` and `BA`, each with `q=1/4`;
`"BB"` uses the unseen floor `1/8`. No decimal log golden is implied here.

### 5.4 Exact weighted trie

For every scalar start position, follow the trie and sum the weights of **all**
complete words encountered. Overlapping occurrences and independently weighted
prefix words all count. There are no word boundaries, length normalization, or
implicit monogram/base score. Require nonempty text even if it contains no matches.

```text
raw = sum of weights of all complete matches at every start
TrieQ32 = raw * SCALE
```

Higher scores rank better; explicit penalty weights can make the result negative.
Using the example dictionary, `"ABA"` matches `A` twice, `AB` once, and `BA` once:
`raw = 1 + 1 + 3 - 2 = 3`, so `TrieQ32 = 3 * SCALE`. This demonstrates overlaps
and the weighted prefix `A` independently of the longer word `AB`.

## 6. Diagnostics and evidence boundary

Validation errors use the protocol's actionable pre-start error envelope and JSON
Pointer location. Reference/read failures point to `/job/resources/<measure>/path`;
resource errors identify the measure, selected file, and resource-relative pointer
(such as `/entries/0/count`) in their diagnostic context. The standalone n-gram and dictionary
parsers expose `ResourceDiagnostic` code, message, and resource-relative location;
file and measure context must be attached by a future caller. It rejects text over
16 MiB before decoding and entries beyond 250,000 before decoding the excess
entry. Other local collections are capped at 256 elements or members, with the
standard JSON decoder recursion guard retained. Both standalone parsers
allow at most 64 nested containers (objects or arrays): a root container is level
1, each child container adds one level, and scalar values add no level. The visitor
rejects entry into level 65 before decoding its contents, well below the decoder's
recursion guard, with `resource_limit` at that container's resource-relative pointer
and a message requesting flatter nesting. Depth is numeric and independent of
member spelling, pointer escaping, or UTF-8 length. Containers through level 64
are decoded normally and then checked against the schema; malformed syntax still
uses `invalid_json`. Limit errors use `resource_limit`; trie-node exhaustion points
to the entry whose insertion would exceed the root-inclusive node cap. Dictionary
schema errors use `unsupported_resource`, duplicate words point to their `word`
array, and invalid weights point to `weight`. Integer weights accept the full signed
i32 range, including the integer lexeme `-0` as zero, but reject decimal and
exponent lexical forms (including `-0.0` and `-0e0`). Word membership and scalar
errors point to the offending array element. Limit errors use `resource_limit`.
Duplicate keys and syntax
errors identify the closest available containing location. Limits and score overflow
are diagnostics, not `internal_error` substitutes or silently dropped candidates.

Reject unknown measures, bad reference shape, missing/unused content, wrong
kind/order/alphabet, malformed scalars, duplicate entries, invalid numeric ranges,
empty resources, insufficient samples, and exceeded limits before enumeration.
Use the protocol's `unsupported_measure` and `unsupported_resource` categories for
unsupported selections/compatibility, with actionable messages for concrete resource
validation failures; `invalid_json`, `unknown_field`, and `invalid_text` retain their
existing meanings. No new event grammar is defined by this document.

The semantic source is canonical `ffraenz/bomm`, pinned at
`aeb2f2bf00dfdee68e972f90ae7e83b387b188e9`:

- [measure.c lines 95–130](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/measure.c#L95-L130): Sinkov model probabilities and unseen floor.
- [measure.h lines 132–186](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/measure.h#L132-L186): overlapping Sinkov windows and mean scoring.
- [measure.h lines 243–295](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/measure.h#L243-L295): IC and entropy semantics.
- [trie.h lines 52–72](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/trie.h#L52-L72): weighted complete matches.

Strict external JSON, Unicode handling, limits, checked fixed-point arithmetic,
orientation, and safe sample rejection are this project's contract decisions.
The article/thesis was not fetched; article confirmation and executable parity are
not claimed. Search execution and differential validation remain later tasks.
