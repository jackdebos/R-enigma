# Engine Protocol

Status: **Protocol v1 is unpublished; transform and validated HC/PE execution ship
in Rust. Legacy search and deferred controls remain unimplemented.** It replaces the former superset-of-`bomm` proposal. It makes no promise to
accept `bomm` query files unchanged; `bomm` remains a differential oracle. See
`odd/tasks/enigma-engine.md` for task status. The engine has no UI; the Stage 2 web
client is a separate program that drives this CLI (§8).

## 1. Normative boundary

A request has three layers: `machine.definition` declares machine structure,
admissible components, and slot constraints; `job.configuration` fixes known key choices
for both job kinds; `job.space` describes the remaining variable key choices for search.
The definition is not a key. A known machine never implies a known key. Every required
key choice must be covered explicitly: fixed by configuration, variable in space, or
structurally non-configurable in the definition. Omission is not a default. Bundled
historical definitions and custom embedded definitions use the same schema and
validation.

This document marks protocol requirements as normative. Search-space grammar is
specified in §3.3 and §7; [Scoring and external resources](scoring-resources.md)
specifies the normative Task 10 measure/resource contract. Pass execution fields
remain deferred to their implementation tasks; the checkpoint record is specified in §6.
[Core HC API](search-passes.md#62-public-core-hc-api--task-128) freezes the
first public HC/PE adapter contract; §4.1 specifies its shipped JSONL lifecycle.
[Task 11 plugboard attacks](search-passes.md) freezes the planned additive attack
branch and pass settings; strict attack parsing, CLI validation and HC/PE execution
are supported. Illustrative
search concepts below are not executable request examples. Representability does not imply catalog availability or
search support.

## 2. Transport

| Mode | Use | Enabled by | Stage |
| --- | --- | --- | --- |
| `stdio` (default) | scripts, tests, the web client (§8) | — | 1 |

**Status:** §2.1-§2.4 and the additive §4.1 fields ship in the CLI
(`odd/tasks/enigma-human-output.md`).

Stage 1 is one command-line process (§2.1). By default it runs in **human mode**
(§2.2): a progress bar on stderr, a readable report at the end and a saved report
file, with no JSON on stdout. The JSONL event stream (§4), one JSON object per line
without embedded newlines, is written only when `--events` selects a destination
(§2.3). Diagnostics always go to `stderr`. The engine opens no network listener; the
Stage 2 web client (§8) reads the same event stream from a child process.

### 2.1 Command line

```text
enigma [options] <request.json>
enigma [options] --request <path|->
```

Every option has a long form; all but `--no-report` also have a one-letter short
form that behaves exactly like it:

| Long | Short | Value | Contract |
| --- | --- | --- | --- |
| `--help` | `-h` | — | §2.1 below |
| `--version` | `-V` | — | §2.1 below |
| `--request` | `-i` | `<path\|->` | request file, or stdin with `-` |
| `--events` | `-e` | `<path\|->` | §2.3 |
| `--report` | `-o` | `<name>` | §2.4 |
| `--no-report` | — | — | §2.4 |
| `--threads` | `-t` | `<n>` | §5 |
| `--checkpoint` | `-c` | `<path>` | §6.1 |
| `--resume` | `-r` | `<path>` | §6.1 |
| `--cancel-file` | `-x` | `<path>` | §5 |

Rules, applied before the request is read:

- Options may precede or follow the input form, in any order. An option that takes a
  value is always followed by that value as the next argument; `--name=value` is not
  accepted.
- Short forms are single letters and are never grouped: `-tc` is not `-t -c`.
- Each option may appear once. Giving it twice, in either form (`-t 2 --threads 3`),
  a missing value, or a value that starts with `--` or equals a short form is a
  usage error.
- The positional request path must not start with `-`; use `-i ./-name.json` for such a
  file. Any other argument shape, including an unknown option, is a usage error.
- A usage error writes the help text to stderr and exits 2 with empty stdout.
- When any argument is exactly `-h` or `--help`, the help text is written to stdout
  and the process exits 0 without reading the request; this wins over every other
  argument and error. Otherwise, when any argument is exactly `-V` or `--version`, the
  two version lines (the first two help lines) are written to stdout with exit 0.

The help text is exactly (`<version>` is the crate version):

```text
enigma <version>
protocol version 1

Usage: enigma [options] <request.json>
       enigma [options] --request <path|->

Input:
  -i, --request <path|->    read the request from a file, or from stdin with -

Output:
  -e, --events <path|->     write the JSONL event stream to a new file, or to
                            stdout with - (no progress bar, no terminal report)
  -o, --report <name>       save the report to <name>, a new file
      --no-report           do not save a report file

Attacks (hill_climb and partial_exhaustion):
  -t, --threads <n>         worker threads, 1 to 256 (default: half the logical
                            CPUs); completed runs give the same result for any <n>
  -c, --checkpoint <path>   save checkpoints to a new file
  -r, --resume <path>       resume from a checkpoint and keep saving to it
  -x, --cancel-file <path>  stop safely once <path> exists as a regular file

Other:
  -h, --help                print this help
  -V, --version             print the version

By default progress is drawn on stderr when it is a terminal, and the result is
printed on stdout and saved as a report in the working directory.
See docs/protocol.md for the contract.
```

Relative paths in every option value use the invocation working directory.
Diagnostics name options by their long form, whichever form was given.

### 2.2 Human mode (default)

Without `--events -` the process runs in human mode:

- **Attacks** (HC/PE): while the search runs, the progress bar (below) is drawn on
  stderr. At the end stdout receives the report text (§2.4), and the report is saved
  to a file unless `--no-report` is given.
- **Transform**: stdout receives the transformed text followed by one newline; no bar is
  drawn; the transform report (§2.4) is saved to a file unless `--no-report` is given.
- **Errors**: stdout stays empty; stderr carries the same diagnostics as in event mode
  and the exit codes are unchanged. No report file is written when the job ends in an
  error.

With `--events <path>` (a file) human mode still applies; the event stream goes to
that file in addition.

**Progress bar.** Drawn only when stderr is a terminal; otherwise nothing is drawn and
stderr carries diagnostics only. The bar is one line rewritten in place (carriage
return, then the line, then clear to end of line), redrawn at Core progress snapshots
(§4.1) and at most 10 times per second; the initial and terminal snapshots are always
drawn. No timer thread is added. During the outer phase the line is

```text
[#########...............]  37.5% | 6591/17576 outer keys | 1.23M eval/s | 00:01:05 elapsed | ETA 00:01:48
```

- the bar has 24 cells, filled by `outers_completed / outers_selected`, rounded down;
  the percent has one decimal;
- the rate is evaluations completed by this process divided by its own running time,
  with `K`/`M`/`G` suffixes and two decimals (`850.00 eval/s`, `1.23M eval/s`);
- `elapsed` is the `elapsed_ms` of the snapshot, which on resume includes the time
  before the stop (§6.5); so after `--resume` the bar starts at the restored share;
- the ETA extrapolates the outer keys completed by this process to the remaining ones,
  and shows `--:--:--` until this process completed one;
- durations are `HH:MM:SS` (hours grow past 99 when needed).

During chained stages the total is unknown and the line is

```text
chained stages | 1523000 evaluations | 1.23M eval/s | 00:02:10 elapsed
```

The line is cleared before the report is printed or a diagnostic is written.

### 2.3 Event mode (`--events`)

- `--events -` writes the complete JSONL stream (§4) to stdout. No bar is drawn and no
  report text is printed; no report file is saved unless `--report` is given. Machine
  consumers (web client, tests, timing harnesses) use this form. Stdout is then
  exactly what the CLI wrote to stdout before human mode existed, apart from the
  additive fields of §4.1.
- `--events <path>` writes the same stream to a new file. If `<path>` already exists,
  including as a dangling symlink, the CLI writes
  `error: --events file already exists: "<path>"` to stderr and exits 2 with empty
  stdout, before reading the request; a file is never overwritten. The file is
  created before the request is read, and an error event is written to it like to
  stdout in event mode.
- Transport failures on either destination follow §4.1 (latched, stderr, nonzero exit).

### 2.4 Reports

An attack report is plain UTF-8 text, the same on stdout and in the file:

```text
Enigma attack report
Status:       completed
Request:      request-b.json
Started:      2026-10-24T12:00:00Z
Finished:     2026-10-24T12:01:10Z
Duration:     00:01:10
Outer keys:   17576 of 17576
Evaluations:  142788085
Threads:      6
Measure:      ngram

#1  score -8.333021  (gap to #2: 1.085312)
    Wheels:     B I II III
    Rings:      AAAV
    Positions:  AVJN
    Plugboard:  AB CD EF GH IJ KL MN OP QR ST
    Plaintext:  VONVO NHEIN ...

#2  score -9.418333  (gap to #3: 0.120000)
...
```

- `Status` is `completed`, `empty slice` (`outer_slice_end`) or `CANCELLED`.
  `Request` is the request path as given, or `stdin`. `Started`/`Finished` are this
  process's RFC 3339 UTC start and end; `Duration` is the result `elapsed_ms` (it
  includes restored time after a resume). `Outer keys` is `outers_completed of
  outers_selected`; `Evaluations` is `evaluations_completed`; `Measure` is the final
  measure ID.
- Candidates follow `result.hold` in rank order (`#1` is `best`). The score is the
  decimal measured score (§4.1); the gap is the absolute ranking difference to the
  next candidate, omitted for the last one. With no candidate the block is the single
  line `No candidates.`
- The key uses the configuration slots in definition order: `Wheels` lists each
  slot's wheel ID separated by spaces, `Rings` and `Positions` concatenate each slot's
  symbol, and `Plugboard` lists the complete pairs (`none` when empty).
- The plaintext is split into groups of five symbols separated by one space, ten
  groups per line; continuation lines are indented to the first group.
- A `CANCELLED` report ends with a `Resume:` line. When the run used `--checkpoint`
  or `--resume`, it holds the command to continue: the invoked program name and
  arguments with `--checkpoint`/`-c <path>` replaced by `--resume <path>` and without
  the `--events <path>`/`-e <path>` (a file; `-` stays) and `--report`/`-o <name>`
  pairs, whose files this run already created, each
  argument quoted for a POSIX shell when it contains other than letters, digits or
  `-_./=:`. Otherwise it reads
  `Resume:       not available (run with --checkpoint to make a search resumable)`.

A transform report has the header `Enigma transform report`, the `Request`,
`Started`, `Finished` and `Direction` (`encrypt`/`decrypt`) lines, the key lines
above for the request configuration, and `Input:` and `Output:` texts grouped like
the plaintext.

**File.** The report is saved, at the end of the job, to a new file in the working
directory:

- default name: the request file name with its last extension replaced by
  `.report.txt` (`data/request-b.json` -> `request-b.report.txt`), or
  `enigma-<UTC YYYYMMDDTHHMMSSZ>.report.txt` for stdin;
- if the default name already exists (any file type, including a dangling symlink),
  the UTC timestamp is inserted before `.report.txt` (`request-b.20261024T120110Z.report.txt`),
  then `-2`, `-3`, ... after the timestamp until a free name is found; an existing
  file is never overwritten or followed;
- `--report <name>` uses `<name>` exactly, relative to the working directory. If it
  already exists the CLI writes `error: --report file already exists: "<name>"` to
  stderr and exits 2 with empty stdout, before reading the request. The file is still
  created exclusively at the end; if it appeared meanwhile, saving fails as below;
- `--no-report` saves nothing; combined with `--report` the CLI writes
  `error: --report and --no-report cannot be combined` to stderr and exits 2.

After saving, stderr receives
`Report "<file name>" saved successfully in <absolute directory>`.
If saving fails, stderr receives `error: failed to save report "<path>": <reason>`
and the exit code is 1; the report text was already printed on stdout.

## 3. Request

A request is exactly `protocol_version`, `machine`, and `job`. Unknown fields and
versions fail before work. JSON member order has no meaning.

```json
{
  "protocol_version": 1,
  "machine": {
    "definition": {"kind": "bundled", "id": "enigma-i"}
  },
  "job": {
    "kind": "transform",
    "configuration": {
      "slots": [
        {"id": "reflector", "wheel": "B", "position": "A", "ring": "A"},
        {"id": "left", "wheel": "I", "position": "A", "ring": "A"},
        {"id": "middle", "wheel": "II", "position": "A", "ring": "A"},
        {"id": "right", "wheel": "III", "position": "A", "ring": "A"}
      ],
      "plugboard": []
    },
    "text": "AAAA",
    "direction": "encrypt"
  }
}
```

This illustrates the reference-and-configuration shape only: `enigma-i` is resolved
from the historically sourced bundled catalog, and this example is not a test vector.
The conventional slot IDs and wheel names shown are catalog identifiers; the selected
positions, rings, and empty plugboard are explicit illustrative key values, not
catalog defaults. Historical wiring is supplied only by the sourced bundle, never
reproduced or guessed in this example.

A custom definition is embedded under `machine.definition.value` and passes the same
definition schema and validation as a bundled definition. This deliberately small,
arbitrary example has complete values and is not a historical machine:

```json
{
  "protocol_version": 1,
  "machine": {
    "definition": {
      "kind": "custom",
      "value": {
        "alphabet": ["A", "B", "C", "D"],
        "wheels": [
          {"name": "rotor", "wiring": ["B", "A", "D", "C"], "turnovers": ["B"]},
          {"name": "reflector", "wiring": ["B", "A", "D", "C"], "turnovers": []}
        ],
        "slots": [
          {"id": "ukw", "role": "reflector", "movement": "fixed", "wheel": "reflector"},
          {"id": "fast", "role": "rotor", "movement": "movable", "allowed_wheels": ["rotor"]}
        ],
        "stepping": {"rules": [{"when": {"always": true}, "advance": ["fast"]}]}
      }
    }
  },
  "job": {
    "kind": "transform",
    "configuration": {
      "slots": [
        {"id": "ukw", "wheel": "reflector", "position": "A", "ring": "A"},
        {"id": "fast", "wheel": "rotor", "position": "B", "ring": "A"}
      ],
      "plugboard": []
    },
    "text": "ABCD",
    "direction": "encrypt"
  }
}
```

### 3.1 Machine definition

`machine.definition` is a strict tagged union: bundled form has exactly `kind` and
`id`; custom form has exactly `kind` and `value` (a complete definition object). Their
conceptual shapes are:

```text
bundled := {"kind":"bundled", "id": BUNDLED_ID}
custom  := {"kind":"custom", "value": DEFINITION_OBJECT}
```

The bundled `id` resolves to an immutable catalog entry shipped with the engine. The
catalog is limited in Stage 1 to historically sourced Enigma I, M3, and M4 definitions.
Each bundled definition is JSON conforming to the same `DEFINITION_OBJECT` schema as a
custom definition. Catalog authors must document authoritative historical sources for
all included alphabet, wheel wiring/turnover, reflector, slot, and stepping facts, and
validate cross-references and structural constraints. Where sources do not establish
a fact sufficiently, do not invent or silently normalize it; resolve the evidence
before adding that catalog data. A bundled alias is not itself machine content and
must not be used as checkpoint identity.

A definition fixes non-key structure and admissibility, never the active key. It has
exactly `alphabet`, `wheels`, `slots`, and `stepping`:

- `alphabet`: non-empty ordered array of unique single Unicode scalar values. No trim,
  case-fold, normalization, or rewriting. Combining sequences are multiple scalars.
  Implementations document and enforce a maximum size.
- `wheels`: non-empty array of named wheel objects with exactly `name`, `wiring`, and
  `turnovers`. Names are unique non-empty strings. `wiring` is a bijection with one
  alphabet symbol for each input symbol; the inverse is derived. `turnovers` contains
  distinct alphabet symbols and refers to displayed pre-step positions, not ring-adjusted
  positions. A wheel used in a reflector slot must be involutive.
- `slots`: non-empty array in physical left-to-right order. Each slot has exactly `id`,
  `role`, `movement`, and exactly one of `wheel` or `allowed_wheels`. IDs are unique,
  stable, non-empty strings. `role` is `rotor` or `reflector`; `movement` is `fixed` or
  `movable`, independent of role. `wheel` fixes the structural wheel. `allowed_wheels`
  is a non-empty unique list of declared wheels admissible for a variable wheel choice.
  At most one reflector is allowed and it is leftmost. A fixed entry wheel is a rotor,
  not a third role. The model supports one or more rotor slots and at least six as a
  capacity requirement; this is not a minimum configuration size or maximum. Any
  documented resource limit is checked before work.
- `stepping`: exactly `{"rules":[...]}`. Rules are non-key structure. Each is
  `{"when": CONDITION, "advance":[SLOT_ID,...]}`. Conditions are `{"always":true}`, `{"at_turnover":SLOT_ID}`, `{"at_position":{"slot":SLOT_ID,"symbol":SYMBOL}}`, `{"all":[CONDITION,...]}`, `{"any":[CONDITION,...]}`, or `{"not":CONDITION}`. Each condition has one operator; groups are non-empty; `always` is literal true. Limits are 64 rules, 256 total condition nodes, depth 16, and 64 distinct advance targets. Every target must refer to a movable slot. All rules inspect the same pre-keypress state; targets are unioned and advanced once simultaneously. An empty rules array means no movement.

The M4 Greek wheel is fixed, but is not the stationary entry wheel. The entry wheel,
when represented, is the rightmost fixed `role: "rotor"` slot; the reflector is leftmost
when present. Movement is explicit. Do not model the Greek wheel as the entry wheel,
imply that a reflector moves by role, or infer key values from an M4 definition.

Definition validation checks exact fields, Unicode scalar constraints, unique names/IDs,
all wheel permutations and turnover symbols, slot/wheel references, reflector placement
and involution, stepping grammar/limits, and movement compatibility. It performs no
implicit normalization. The same validation applies to custom values and resolved
bundled content.

### 3.2 Configuration and transform

`job.configuration` is required for **both** job kinds. For `kind: "transform"`, it has
exactly `slots` and `plugboard`: `slots` has exactly one entry per definition slot in
definition order, each with exactly `id`, `wheel`, `position`, and `ring`. The ID must
match its structural slot; wheel must equal a structurally fixed `wheel` or belong to
`allowed_wheels`; `position` and `ring` are each one alphabet symbol. `plugboard` is
required, including when empty, and is an array of disjoint two-symbol pairs.
Self-pairs, duplicate endpoints, and symbols outside the alphabet are invalid. No
required value is omitted or defaulted; even structurally fixed wheels are explicitly
repeated here and checked against their definition. A transform has no `space`.

For `kind: "search"`, `configuration` has exactly `slots` and `plugboard` and expresses
only the **known fixed choices**. Fixed and variable assignments are reconciled by the
§3.3 coverage rules; omission from the fixed portion is neither a default nor automatic
enumeration.

`configuration.slots` is an array of partial slot facts. Each entry is an object with
exactly `id` plus any subset of `wheel`, `position`, and `ring`; `id` is required, must
name a definition slot, and every entry must name a distinct slot (array order is
insignificant). A present member is a fixed key fact and is checked for admissibility
exactly as in a transform. Position and ring are key dimensions for every slot. A wheel
is a key dimension only for a slot whose definition declares `allowed_wheels`; a
structurally fixed wheel may be repeated here for checking or omitted, and is never a
variable dimension. Any dimension that is neither structurally fixed nor fixed here
must be covered by `space`.

`configuration.plugboard` is an array of fixed disjoint pairs, validated exactly as in
a transform and including the empty array. When `space.plugboard` is present these
pairs are the known facts and the remainder is searched; when it is absent the fixed
pair set is complete. A present-but-empty `configuration.plugboard` therefore means "no
fixed pairs", and the ambiguity this section forbids is resolved by the presence or
absence of `space.plugboard`, never by `[]` alone.

The definition contains no position, ring, active wheel selection, or plugboard key.
Configuration resolution combines definition structure and explicit configuration into
a concrete topology, stepping rules, and plugboard. `Engine::new` consumes that resolved
combination; this protocol redesign does not change Task 4's model boundary.

For each symbol, step once before electrical traversal, independent of direction. Let
`N` be alphabet length, `p` position index, `r` ring index, and `o=(p-r) mod N`. A wheel
maps `forward(x)=(wiring[(x+o) mod N]-o) mod N`; reverse substitutes inverse wiring.
With reflector: input plugboard, forward through rotor slots right-to-left, reflector
once using its own position/ring, reverse through rotors left-to-right, output
plugboard. The reflector must be involutive. Encrypt and decrypt use this reciprocal
traversal and produce the same transform. Without reflector, encrypt traverses forward
right-to-left and decrypt reverse left-to-right, with plugboard at both ends. No
universal involution or no-self-encryption claim is made.

### 3.3 Search job boundary (Task 9 grammar)

A search job has `kind: "search"` and exactly `configuration`, `text`, `space`,
`passes`, `measures`, and optional `resources`. `configuration` carries the fixed
known choices (§3.2), `space` carries the explicit variable domains and bounds,
`passes` and `measures` select behavior, and `resources` parameterizes it. This
section is normative for the §3.2/§3.3 structure only; execution is specified by
the pass contracts (HC/PE attacks and the Task 13 chained stages of
[search-passes §9](search-passes.md#9-chained-stages--task-13) execute; §4.1).

`space` is an object allowing exactly `slots`, `plugboard`, `offset`, `limit`, and
`constraints`; all five are optional, so an empty object means the fixed choices are
already complete.
`slots` and `plugboard` are present only when that dimension is variable:

- `slots`: array of slot domains. Each entry is an object with exactly `id` plus any
  subset of `wheels`, `positions`, and `rings`; `id` is required, names a definition
  slot, and is unique. `wheels` is allowed only for a slot with `allowed_wheels` and is
  a non-empty unique subset of that slot's admissible wheels; `positions` and `rings`
  are non-empty unique arrays of alphabet symbols. At least one of the three members
  must be present.
- `plugboard`: the retained Task 9 subset branch is an object with exactly `candidates` and `size`. `candidates` is a non-empty
  unique array of disjoint two-symbol pairs drawn from the alphabet; `size` is a
  positive integer no greater than `candidates.len()`, the number of additional pairs
  to draw from that pool. Known pairs in `configuration.plugboard` must be disjoint
  from every candidate pair.
- `offset`: optional non-negative integer, default `0`, addressing the deterministic
  enumeration order of §7.
- `limit`: optional positive integer bounding the number of enumerated candidates;
  omission means no explicit request bound (documented resource limits still apply).
- `constraints`: optional object restricting which candidates exist, allowed only with
  the attack branch (`space.plugboard.kind = "attack"`); on any other request it is
  `invalid_search_space`. It has exactly one member, `distinct_wheels`, required: an
  array of at least two unique slot IDs, each naming a definition slot with
  `allowed_wheels`. It removes every outer candidate in which two of the named slots hold
  the same wheel name, as on the real machine, where each wheel exists once. Named slots
  may have a known wheel (`configuration`) or a variable one (`space.slots`); a known
  wheel therefore excludes itself from the other named slots. Slots not named are not
  restricted. The constraint applies only when requested: no catalog definition implies
  it, and transform still accepts repeated wheels. Unknown members are `unknown_field`.
  Example: `"constraints": {"distinct_wheels": ["left", "middle", "right"]}`.
  Counting is exact; a constraint needing more than 100,000 counting states fails
  with `resource_limit` at `/job/space/constraints/distinct_wheels`.

The separately discriminated
[`kind: "attack"` branch](search-passes.md#1-two-domain-branches-no-implicit-unknown-key)
supports strict parsing and public validation, adding mutable endpoints without
altering this subset grammar or fixed-pair meaning.
Its strict `job.attack` field is an additive exception to the inventory above,
only for that branch; see [settings](search-passes.md#2-one-executable-pass-and-explicit-settings).

Coverage and conflict are checked before enumeration:

- Every required key dimension has exactly one path: structurally fixed by the
  definition, fixed in `configuration`, or declared in `space`.
- Position and ring are required dimensions for every slot. A slot whose definition
  fixes `wheel` has no wheel dimension; a slot with `allowed_wheels` requires the wheel
  dimension to be fixed or declared.
- A dimension covered twice (fixed and declared, or declared twice, or declared for a
  structurally fixed wheel) is `invalid_search_space`; a required dimension covered by
  no path is `invalid_search_space` with an actionable message. Unknown members remain
  `unknown_field`. No value is defaulted or inferred.
- A `distinct_wheels` constraint that leaves no outer candidate (for example two named
  slots with the same known wheel, or more named slots than wheels available to them) is
  `invalid_search_space` at `/job/space/constraints/distinct_wheels`, reported before
  any work.
- The candidate resolver enforces definition restrictions, disjoint plugboard pairs,
  and unique complete candidates; concrete candidates bind anew to their final
  topology and stepping rules. Incompatible slot/wheel combinations and unsupported
  topology/pass/measure/resource combinations fail preflight with
  `unsupported_topology`, `unsupported_pass`, `unsupported_measure`, or
  `unsupported_resource` before enumeration. Search never silently skips unsupported
  work.

`passes` is a non-empty unique array of pass identifiers. `measures` is a non-empty
unique array of measure identifiers: initially `ic`, `entropy`, `sinkov_monogram`,
`sinkov_bigram`, `sinkov_trigram`, `sinkov_quadgram`, `sinkov_pentagram`,
`sinkov_hexagram`, and `trie`. Unsupported names fail; there are no aliases or
implicit combinations. IC and entropy are initially resource-free monogram measures.
Each selected Sinkov/trie measure requires exactly one `resources` entry keyed by
that measure ID, whose value is exactly `{"path":"..."}` with a nonempty path.
Missing or unused references, duplicate keys, inline contents, and unknown fields
fail. All request JSON remains duplicate-key-strict at every depth.

The standalone [scoring/resource contract](scoring-resources.md) is normative for
external JSON schemas, compatibility, bounds, Unicode semantics, formulas,
orientation, and checked deterministic Q32 arithmetic. Resources must match the
resolved ordered alphabet and selected kind/order. Measures are independently
ordered; no combined ranking is promised. There is no global reflector requirement.

Structural parsing does not authorize enumeration with unbound resources. The
caller supplies bounded UTF-8 contents keyed by measure ID to a binding stage;
only fully validated requests may enumerate. Core parsers never read files.
Resource-free `SearchRequest::parse_json` remains a convenience; it fails when
binding is required. File-request resource paths are relative to the request
filename's directory; stdin paths are relative to the working directory captured
once. Absolute paths are allowed; no expansion, URL loading, automatic symlink
canonicalization, or sandbox restriction is introduced.

**Implementation status:** Current execution availability is summarized in §4.1.
Engine 0.2.0 implements `space.constraints` (`distinct_wheels`);
older engines reject it as `unknown_field`.
Task 9 implements the structural boundary and capability
framework. Task 10 implements deterministic IC, Shannon entropy, Sinkov n-gram and
weighted trie scoring, strict external resource parsers, typed measure/resource
selection, pure content binding, and bounded CLI loading. The CLI uses shared strict
dispatch to validate and bind search resources before execution. Legacy search still
returns one `unsupported_job` error without work events; resource errors precede
that result. Validated HC/PE attacks execute through the shared adapter. Transform
never loads resources; its grammar and events are unchanged.

[Task 11](search-passes.md) adds strict attack dispatch when
`job.space.plugboard.kind` is `"attack"`, still with `job.kind = "search"`.
The CLI loads and binds resources and checks eligibility and counts before
execution. Structural, loading, model-binding and eligibility failures emit only a
seq1 `error`, without work events. Missing or other discriminators retain legacy
search validation and unsupported execution. HC/PE evaluation, seed exhaustion and
ordered outer scheduling use Core `AttackRequest::run` through the shared synchronous
adapter, with counter-only observation and independently polled cancellation.

Stage 1 plans `hill_climb`, `partial_exhaustion` with backtracking, `reswapping`, `trie`,
and `measure`; measures include index of coincidence, Sinkov n-gram statistics,
Shannon entropy, and trie scoring. This plan does not assert parser or search support.
The chained `reswapping`/`trie`/`measure` stages are specified and implemented in
[search-passes §9](search-passes.md#9-chained-stages--task-13).
Representability by the definition schema does not imply algorithm support for arbitrary
alphabet, wheel count, stepping rule, or topology.

## 4. Events and validation errors

Each event line (written to the `--events` destination, §2.3) is a JSON event with
`event`, `protocol_version`, monotonic `seq` starting at 1, and RFC 3339 UTC `ts`. Unknown event names/fields may be ignored by
clients. A successful validated job emits one `started` first, then applicable events,
then exactly one terminal `done`; runtime failure emits terminal `error`. Search may
emit `progress`, `candidate`, `checkpoint`, and `hold` according to job lifecycle.
The first HC/PE release instead uses only `progress` and final `result` (§4.1);
`candidate` and `hold` remain eventual Stage 1 requirements, not part
of that release; `checkpoint` is specified in §6.5 (Task 16). Task 14 implements the hold delivered once, as the
final `result.hold` array ([search-passes §10](search-passes.md#10-hold-list--task-14));
no live `hold` event. Transform emits no candidate, hold, or checkpoint event. A validated `transform` job
emits `started`, then exactly one `output` whose `output` member is the transformed
text, then exactly one terminal `done` with `reason: "completed"`. `done` remains
solely a lifecycle/reason event shared by transform and future search; it never carries
the transformed text. Pre-validation failure emits one `error` at `seq: 1`, with no
`started` or work events. Errors contain stable `code`,
actionable `message`, and JSON Pointer `location`; `expected` and `hint` may be added.
Exit nonzero and write diagnostics to stderr on invalid input.

Validate syntax, exact root and nested fields, version, definition (including bundled
content), complete configuration or search-space coverage, all symbols and references,
job kind/direction, topology compatibility, text alphabet membership, and applicable
search pass/measure/resource constraints before `started`. Unknown and omitted fields
are distinct: unknown is an error; omission of a required value is an error, never a
default. Example location: `/job/configuration/slots/1/position`. Error codes include
`invalid_json`, `invalid_request`, `unsupported_version`, `unknown_field`,
`invalid_definition`, `invalid_symbol`, `invalid_wiring`, `invalid_reflector`,
`invalid_plugboard`, `invalid_slot`, `invalid_rule`, `invalid_search_space`,
`unsupported_job`,
`unsupported_pass`, `unsupported_measure`, `unsupported_resource`, `invalid_text`,
`unsupported_topology`, `resource_limit` (including pre-execution count/resource bounds),
and `internal_error`. `internal_error` is reserved for an
internal runtime failure after `started` (including evaluation, resolution or counter
invariants); it is never a request-validation failure.
Syntax errors point to the closest available containing path.

### 4.1 Planned HC/PE search events — Task 12.7

**Current availability (Task12.11):** Transform and validated HC/PE attacks execute
in the production CLI. HC/PE share the synchronous JSONL adapter and fallible Core
projections. Legacy search still returns seq1 `unsupported_job` after preflight,
without work events. All preflight failures remain seq1-only errors.
`AttackResult::hold()` exposes ordered borrowed entry views; `AttackRunError::hold()`
is independently fallible, preserving projection errors rather than returning an
empty hold. Each view borrows its best payload and entry-specific stage history.

Core provides pure progress and result
wire projections from `AttackProgress`/`AttackResult` and caller-supplied elapsed
milliseconds, decimal-string counters, indices, Q32 units and elapsed time, and all
three `DoneReason` mappings. Result preserves the complete initial winning key,
mutable remainder, final score and independent flags; genuine absence is null.
`Event::runtime_error` projects a borrowed failure into a result/error pair with
optional boxed context. Malformed retained best fails with `RuntimeProjectionError`,
which retains the original runtime cause and separate best-projection cause;
only genuine absence becomes null. These projection helpers read no clocks and
perform no I/O or orchestration; the private adapter supplies that boundary.
One leading attack pass, `hill_climb` or `partial_exhaustion`, is eligible, optionally
followed by the executable [Task 13 chained stages](search-passes.md#9-chained-stages--task-13)
`measure`, `trie` and `reswapping`; recognition of other passes is not support, and
mixed/deferred/legacy rejection is unchanged. `result.stages` is live: it lists the
started stages in pipeline order (§9.6 there), empty when none started.

After all parsing, resource loading/binding, eligibility and count validation,
emit `started`, initial/cadence/terminal `progress`, one `result`, then exactly one terminal
`done` or runtime `error`. Preflight failures retain the existing seq1 `error` only.
Task12.8 exposes Core HC; Task12.9c adds Core PE through the same synchronous API.
The lifecycle below is implemented by the shared production HC/PE adapter;
legacy search remains unsupported.
On runtime error, `result` retains the earlier eligible committed finalists in
`hold`, with their aggregate `best` or null; do not invent a result for the failing
climb. Stage errors retain the failing finalist's last committed key per
[search-passes §10.5](search-passes.md#105-stages-over-the-hold).
No `done` follows error. `result` is final, not a stream of provisional trials;
its `hold` array is the implemented Task 14 hold ([search-passes §10.7](search-passes.md#107-result-and-wire-projection)).

Payloads below supplement the existing event envelope; `done` stays reason-only:

| Event | Required payload |
| --- | --- |
| `started` | `outers_selected` (HC/PE only; transform `started` is unchanged) |
| `progress` | `counters`, `elapsed_ms` |
| `result` | `stages`, `best` (object or null), `hold` (Task 14 array), `counters`, `elapsed_ms`, `threads`, `started_at`, `finished_at` |
| `done` | `reason`: `completed`, `outer_slice_end`, or `cancelled` |
| Runtime `error` | Existing `code`, `message`, `location`; additionally `context` |

`counters` has exactly `evaluations_admitted`, `evaluations_completed`,
`climbs_started`, `climbs_completed`, `outers_completed` with the factual meanings
in [accounting](search-passes.md#accounting-and-completion). `evaluations_used` in
Core records charged allowance, not completed work. Charge precedes the checked
admitted-counter increment: rare overflow may leave used > admitted; preserve both
factual values, never refund usage or fabricate counters. No percentage, estimated remaining
work, total mathematical-board count, rate or backend scheduling cursor is promised.

`best` has exactly `configuration`, `mutable_plugboard`, `plaintext`, `score`,
`outer_index`, `start_index`, `incomplete`, `final_objective_ascent`, and
`neighborhood_exhausted`. `configuration` uses the complete transform key shape
(§3.2): resolved initial slots in definition order and the **winning complete**
plugboard, fixed pairs union committed mutable pairs. It is not the stepped key.
`mutable_plugboard` separately contains just the winning mutable remainder. Pairs
are oriented and sorted by ordered alphabet indices. `start_index` is 0 for direct
HC and the dense seed index for PE; `outer_index` is absolute, unsliced.
`score` has exactly `measure` (the requested final measure ID), `measured_q32`,
`ranking_q32`, `measured` and `ranking`; the same shape is used in every hold entry. Ranking is higher-is-better; do not negate measured entropy.
The three boolean winner flags are independent of each other and of run termination;
`incomplete` means that winning climb was interrupted. Ties retain earliest
(outer index, start index). No best means JSON null, never a sentinel key or score.

All new search count/index/elapsed fields are canonical unsigned decimal **strings**
(`0` or a nonzero digit followed by digits), including u64 counts; Q32 fields are
canonical signed decimal strings of raw i128 units (optional minus, no `+`, leading
zeros or `-0`). The scale is exactly 2^32 and the Q32 fields are authoritative.
`measured` and `ranking` are informative decimal strings of the Q32 value divided
by 2^32, rounded half away from zero to exactly six fraction digits (`-8.333021`,
`0.000000`; optional minus, never `-0.000000`, no exponent); no float is sent.

`outers_selected` is the number of outer keys in the requested slice (after `offset`
and `limit`), the total that `outers_completed` reaches on exhaustion. `threads` is
the worker count used by this process (§5). `started_at` and `finished_at` are this
process's RFC 3339 UTC wall-clock times at execution entry and when `result` is
built; after a resume they describe the resumed process only, while `elapsed_ms`
includes restored time. u128 indices/counters retain their full range. Existing request
integer grammar and transform envelope numbers (`protocol_version`, `seq`) do not
change; strings are used consistently even inside the safe JSON integer range.

Elapsed time is monotonic whole milliseconds since execution entry after preflight,
not RFC3339 wall-clock subtraction; terminal values include final rescoring.
Core owns the snapshot stream: one initial snapshot, block-boundary snapshots during
the outer phase, cadence snapshots during chained stages, and one terminal snapshot
on success, cooperative cancellation or returned error. Optional
`job.attack.progress_every` sets X (default
**100000**); it must be a positive JSON `u64` integer. Zero, negative values
(including `-0`), decimal/exponent forms, wrong types, null and overflow are
`invalid_request` at `/job/attack/progress_every`; unknown-member validation retains
precedence. HC and Partial Exhaustion (PE) share this grammar.
The outer phase runs selected outer keys in fixed blocks of 128 consecutive keys in
key order ([search-passes §6.1](search-passes.md#61-private-progress-and-cancellation--task-12)).
After a block's work is committed, Core emits one snapshot if at least X evaluations
completed since the previously emitted snapshot (the initial one counts as 0), even
when the block crossed several multiples of X; nothing is emitted inside a block.
Chained stages keep the global grid: one snapshot at each completed count that is a
multiple of X. Failed evaluations and winner plaintext replay do not advance
completed counts. Admissions and internal boundaries do not notify. Initial and terminal observations
are retained even when equal to each other or to a cadence snapshot.
The CLI forwards Core snapshots without a second gate, using monotonic elapsed
and UTC event clocks only at the transport boundary. Delivery is synchronous
at safe callbacks, with no timer threads, mid-evaluation callbacks or hard wall-clock
delivery/cancellation bound. Timestamp `ts` remains supplied UTC wall time.
No clock or I/O enters the private evaluator.

Map established exhaustion of a nonempty requested slice to `completed`; an empty
slice to `outer_slice_end`, not legacy `offset_end`/`limit_reached`. When work remains,
map safe cancellation to `cancelled`. Precedence is errors > exhaustion >
cancellation. Required final rescoring, when the final score is absent, must succeed
before an interrupted current board is eligible; failed rescoring is error, never a
provisional best or cancellation.

During the outer phase, cancellation is polled only at block boundaries: before the
first block, then before each later block on one thread, or after each finished block
with several worker threads (§5). A stop lets every block already started finish,
including every climb's final scoring, and commits them; no further block is started
and the run ends `cancelled` with the hold, winner and counters of committed blocks,
always a key-order prefix. If those blocks complete the slice, established exhaustion
wins (`completed`). A stop requested before the first block yields no outer work. An
evaluation error stops its block at the failing evaluation; work before it is
committed, and later blocks are neither started nor committed. Chained stages keep
their per-trial polling.

Runtime `context` has exactly `outer_index`, `start_index` (nullable when unavailable),
`evaluations_used`, `counters`, and `source`. `source` has `kind`, `message`, and
`diagnostics` (array, empty unless resolution diagnostics exist). Kinds distinguish
`resolution`, `evaluation`, `counter`, and `invariant`; each resolution diagnostic
retains its original code/message/location. Runtime failures use `internal_error`
and `/job` unless an original diagnostic supplies a more precise location. Preserve
the original nested Core source in the API error, not a cancellation replacement;
wire messages describe that source without pretending private Rust Debug names are
stable codes. Charged failed calls remain admitted, never completed or refunded.

An infallible observer cannot return a write/flush error through the evaluator.
The adapter latches the first transport failure, stops further writes and requests
cooperative cancellation independently of progress cadence; Core observes it at the
next block boundary or stage poll. It still permits required final rescoring and retains any runtime error and charged usage. Report transport
failure on stderr and exit nonzero; retain runtime failure as primary when both occur.
Never retry a partially written JSONL line or promise `result`/terminal delivery on
failed transport. On a healthy stream flush each emitted line; exactly-one-terminal
ordering applies only while delivery succeeds, including final result write/flush.

## 5. Control

| Action | Mechanism | Result |
| --- | --- | --- |
| Cancel (first HC/PE release) | `--cancel-file <path>` marker or a platform signal (`SIGINT`/`SIGTERM`/`SIGHUP`, Windows Ctrl+C/Break); both shipped | Cooperative safe-stop, final `result`, then `done` with `reason: "cancelled"`; retained `result.hold` per Task 14; with `--checkpoint`/`--resume`, a checkpoint is written first (§6.2) |
| Parallel HC/PE outer keys | `--threads <n>`, default half the logical CPUs; outer-key blocks run on that many worker threads | Same public output as one thread for completed runs; see the `--threads` contract below |
| Pause/resume live job | Not in Stage 1 | Future extension |
| Save and resume HC/PE | `--checkpoint <path>`, `--resume <path>` (Task 16) | Periodic, end-of-outer-phase and cancellation checkpoints; resume with any `--threads`; see §6 |
| Bound HC/PE search | `space.offset`/`space.limit` and cancellation | §4.1 slice/exhaustion/cancellation reasons; slices bound outer keys only; no new `--max-keys` attack control |
| Other future bounded search | Planned `--max-keys` | Legacy planned `limit_reached`/`offset_end`, not HC/PE mappings |

Transform has no search progress, cancellation, hold, or checkpoint contract in v1.

[Task 12 private integration](search-passes.md#61-private-progress-and-cancellation--task-12)
implements shared accounting, counter-only snapshots and cooperative cancellation
for private HC climbs/outer scheduling and PE seeds/resolved owners/outer scheduling.
Admitted evaluations are nonpreemptive; errors > established exhaustion > cancellation.
Stops retain committed results and required final rescoring when the final score is
absent; original errors and charged usage are preserved, not masked by cancellation.
Searches are finite (strict ascent, finite neighborhoods, seeds and outer keys), but
not necessarily short. Use offset/limit to bound outer keys or cancellation to stop
remaining work.
Core runtime, fallible JSONL projections and the synchronous HC/PE adapter ship in the
production CLI (§4.1), including the final retained hold. Live hold events remain
unimplemented; checkpoint cadence is specified in §6.2 (Task 16).
Task12.12 ships `--cancel-file` and Task12.13 platform signals as the external
cancellation sources, per the contracts below; they combine by OR, both sticky.
Without either, cancellation stays false. Signal handlers only feed a sticky
cancellation request, never perform evaluation or JSONL writes.

### `--cancel-file <path>` contract

The option applies to validated HC/PE attacks. Transform and unsupported search
jobs reject it with a seq 1 `unsupported_job` error at `/job/kind` and exit 1;
request parse, resource load and bind errors take precedence. Relative paths use
the invocation working directory, not the request-file directory.

The marker is existence-only: accept a regular file or a symlink resolving to one,
without reading contents. Missing paths, missing parents and dangling symlinks mean
no cancellation request. Other file types and metadata errors are failures. The CLI
never creates, consumes or deletes the marker; an existing marker applies to each
new run. Once observed, cancellation stays set even if the marker disappears.

Validate the request and resources before initial marker inspection and before
`started`; initial inspection errors prevent execution, writing only a stderr
diagnostic with exit 2 and empty stdout. During execution, inspect
at every Core cancellation callback (at outer block boundaries, then at stage polls,
§4.1), independently of progress cadence, until
cancellation or error is latched. No clock, timer thread or hard latency guarantee
is introduced. A runtime inspection error latches the first error and requests safe
stop; it remains inspectable even after the adapter stops polling. Report it on
stderr after any adapter, transport or Core diagnostics, never instead of them,
and exit 1.

Normal cancellation retains eligible results, emits `result` then `done` with
`reason: "cancelled"`, and exits zero on healthy delivery. Established exhaustion
and runtime-error precedence remain authoritative (§4.1); observing a marker does
not override them. No hold, cleanup or marker ownership is added by this contract;
checkpoints on cancellation follow §6.2. Core remains clock- and I/O-free.

### Signal contract

`SIGINT`, `SIGTERM` and `SIGHUP` on Unix, and Ctrl+C/Break on Windows, request the
same safe stop as an observed marker: `result` then `done` with
`reason: "cancelled"`, exit zero on healthy delivery, with the precedence and exit
codes above unchanged. The handler applies only to HC/PE attacks; it is installed
after request/resource binding and initial marker inspection, before `started`.
Earlier phases, transform and search jobs keep the default signal behavior. If
installation fails, the CLI writes a stderr diagnostic and exits 2 with empty
stdout, before `started`.

The first signal only raises the sticky flag. A second signal exits immediately with
code 130, without a terminal-event guarantee; a JSONL line may be cut. The handler
replaces inherited ignored dispositions: under `nohup`, a terminal hangup requests a
safe stop. Use `setsid`, `tmux` or `screen` to outlive the terminal. Windows and
macOS behavior relies on the `ctrlc` crate and is not verified by tests here.
Live hold events remain deferred, not removed from eventual Stage 1 goals; cancellation
retains the final `result.hold` (search-passes §10.6). With `--checkpoint` or
`--resume`, the first signal also writes a checkpoint before `result` (§6.2).

### `--threads <n>` contract

The option applies to validated HC/PE attacks and is host configuration, never a
request field (§11). `<n>` is ASCII decimal digits naming an integer from 1 to 256;
any other value fails before the request is read, writing only
`error: --threads expects an integer from 1 to 256, got "<value>"` to stderr with
exit 2 and empty stdout. Transform and unsupported search jobs reject the option
like `--cancel-file`, with a seq 1 `unsupported_job` error at `/job/kind`, the message
`--threads is supported only for hill_climb and partial_exhaustion attacks` and exit 1;
when both options are present the `--cancel-file` message is reported. Without the
option an attack uses half the logical CPUs reported by the platform, at least one.

Outer keys are split into fixed blocks of 128 keys in key order. Up to `<n>` worker
threads (never more than there are blocks) take the next block as they become free,
at most twice the worker count ahead of the oldest unmerged block; each worker keeps
its own scoring preparation. With `<n>` = 1 or a single block the attack runs on the
calling thread. Progress, cancellation inspection and all output stay on the calling
thread, which merges finished blocks. Block outcomes are merged in key order, so hold ranking, duplicate
payloads, winners, errors and counters match a one-thread run; chained stages then
run on one thread. A completed run therefore writes the same events, exit code and
stderr for every thread count, apart from `ts`, `elapsed_ms`, `threads`,
`started_at` and `finished_at` (and, in human mode, the report lines derived from them
and the progress bar). Progress is emitted
only at block boundaries in key order, so its positions depend on the block layout,
never on the thread count.

A stop request (marker or first signal) is observed at block boundaries: every worker
finishes the block it holds, finished blocks are merged, then the run delivers `result`
and `done` with `reason: "cancelled"` as above. Blocks are sized to last about a
second or less in typical searches, so stopping may take that long; a second signal
still exits immediately with code 130. Which blocks finish before a stop depends on
timing, so cancelled runs are not promised to match across thread counts.

## 6. Checkpoint and resume (Task 16)

**Status:** shipped for validated HC/PE attacks (`odd/tasks/enigma-checkpoints.md`).

Only a resumable search may write checkpoints. A transform has no Stage 1 checkpoint.
Checkpoint identity binds a canonical digest of the resolved definition **content**
(not the bundled alias), the complete fixed portion of `job.configuration` **and** the
complete `job.space` including constraints and ordering, the remaining search job
(including passes/measures), relevant resource content, and protocol version. A bundled catalog
update that changes resolved content therefore rejects an old checkpoint. Resource
identity must capture relevant content, not merely a mutable path. Resume rejects any
drift in those inputs before work. The record contains a deterministic structured
candidate cursor, state digest, completed work units, elapsed time, hold, and RNG state
when relevant; cursor is not a loop counter. Search ordering is deterministic and
resume restores the same next candidate. The rules below apply to the HC/PE attacks;
they use no randomness (seeds are enumerated, not drawn), so the record has no RNG state.

### 6.1 Options

- `--checkpoint <path>` saves checkpoints of this run to `<path>`. If `<path>`
  already exists the CLI writes
  `error: --checkpoint file already exists, use --resume to continue it: "<path>"`
  to stderr and exits 2 with empty stdout, before reading the request, so a foreign
  file is never overwritten.
- `--resume <path>` loads the checkpoint at `<path>`, checks it against the request
  (§6.4), continues the search from it and keeps saving checkpoints to the same `<path>`.
- Both options take one path value with the placement, duplicate and missing-value
  rules of §2.1, and combine with `--cancel-file` and `--threads`. Giving
  both writes `error: --checkpoint and --resume cannot be combined` to stderr, exit 2,
  empty stdout. Relative paths use the invocation working directory.
- Transform and unsupported search jobs reject either option with the seq 1
  `unsupported_job` error at `/job/kind`, the message
  `--checkpoint and --resume are supported only for hill_climb and partial_exhaustion attacks`
  and exit 1; a `--cancel-file` or `--threads` message takes precedence.
- `--threads` is host configuration, not identity: a run may resume with any thread count.

### 6.2 When a checkpoint is written

Only on the calling thread, at a committed outer-block boundary (§5 `--threads`),
never inside a block or from a worker:

1. **Periodic:** at the first committed block boundary at least 300 seconds
   (monotonic clock) after the start of this process's execution or the previous
   successful write.
2. **End of the outer phase:** once, after the last block is merged and before
   chained stages start (`phase: "stages"`).
3. **Cancellation:** after a stop request is observed and in-flight blocks are
   drained (or, during stages, at the stage poll that observes it), before `result`.

Each write saves the state of every block merged so far. Blocks that were still running
are not in it; a resume runs them again. A stop during chained stages saves the
pre-stage state of item 2: resume reruns all stages, and the counters of the discarded
stage work are dropped. A second signal (exit 130), a kill or a power loss keeps only
the last successful write. Runtime errors write no new checkpoint; the previous one
stays. After a completed run the last checkpoint (`phase: "stages"`) stays on disk;
resuming it reruns only the stages and gives the same result.

A write goes to `<path>.tmp` in the same directory, is flushed, then renamed over
`<path>`, so a failed or interrupted write never damages the previous checkpoint.
An existing `<path>.tmp` left by an interrupted write is removed first (a link is removed, never followed), and a new one is created. Before replacing `<path>`, the CLI checks that it still holds this run's last checkpoint (or the one loaded by `--resume`); if another program created or changed it, the write fails as above and `<path>` is left untouched.
After each successful write the CLI emits one `checkpoint` event (§6.5). A failed write
writes `error: cannot write checkpoint "<path>": <reason>` to stderr, the search
continues (later writes are still attempted), and the process exits 1 at the end
even when the search completes; runtime-error and transport-failure precedence (§4.1)
is unchanged.

### 6.3 Record (`checkpoint_version` 1)

One strict JSON object (unknown or duplicate members rejected), UTF-8, written compact.
Counts, indices and elapsed time use the canonical decimal strings of §4.1.

| Member | Content |
| --- | --- |
| `checkpoint_version` | JSON integer `1` |
| `protocol_version` | JSON integer `1` |
| `identity` | 64 lowercase hex digits: SHA-256 identity digest (§6.4) |
| `state_digest` | 64 lowercase hex digits: SHA-256 of the canonical record without this member |
| `phase` | `"outer"` (outer blocks remain) or `"stages"` (outer phase finished) |
| `next_outer` | absolute outer index of the first key not yet merged; in `"stages"` the end of the selected range |
| `counters` | the five §4.1 counters after the merged blocks |
| `evaluations_used` | charged allowance (§4.1) |
| `progress_last_emitted` | `evaluations_completed` of the last emitted progress snapshot |
| `elapsed_ms` | execution time accumulated over every run of this search |
| `best` | the §4.1 `best` object of the merged blocks, or null |
| `hold` | the retained hold before stages, in hold order, as §4.1 `best` objects |

`next_outer` addresses the flat outer order of §7 inside the range selected by
`space.offset`/`space.limit`; it lies on a 128-key block boundary of that range or at
its end. Merged blocks always form a prefix in key order, so this one index is the whole
cursor. `best` and `hold` entries carry no stage history, because stages always rerun.
The canonical record used by `state_digest` is the record with keys sorted and no
whitespace.

### 6.4 Identity and resume checks

`identity` is the SHA-256 (FIPS 180-4) of this byte sequence: the ASCII line
`enigma-checkpoint-identity/1\n`; the canonical request (the parsed request JSON
with object keys sorted, no whitespace, array order kept) followed by `\n`; when the
definition is bundled, the exact catalog JSON of that alias followed by `\n`; then for
each loaded resource in ascending measure-ID order, its ID, `\n`, its byte length in
decimal, `\n` and its exact bytes. The request already carries `protocol_version`, the
whole job, text and settings; changing any of them, the catalog content or a
resource byte changes the identity. Reformatting the request does not. Adding or
removing `space.constraints` changes the identity, so a checkpoint never resumes a run
with different constraints; reordering the IDs inside `distinct_wheels` changes it too,
although it selects the same keys.

Resume reads and parses the record before the request. An unreadable file, invalid
JSON, an unknown member, an unsupported `checkpoint_version` or `protocol_version`,
a malformed field or a `state_digest` mismatch writes
`error: invalid checkpoint "<path>": <reason>` to stderr and exits 2 with empty stdout.
After the request and resources are bound, a different `identity` writes
`error: checkpoint "<path>" belongs to a different search` and exits 2 with empty
stdout. Before `started`, every `best`/`hold` entry is decrypted and scored again with
the bound measure (not counted in `counters`); a key, plaintext or score that does not match, a `next_outer`
outside the selected range or off a block boundary, or entries that break hold order
or capacity also fail as an invalid checkpoint (exit 2). The checkpoint file is never
modified by a failed check.

### 6.5 Events and equivalence

A resumed run emits `started`, an initial `progress` with the restored counters, then
continues the normal lifecycle (§4.1). `checkpoint` events carry `phase`, `next_outer`
and `counters` (same encodings as the record) and are emitted only after a successful
write. `elapsed_ms` in `progress` and `result` adds the restored `elapsed_ms` to this
run's monotonic time.

For completed runs, the `result` and `done` events of a search that was stopped and
resumed (any number of times, with any thread counts) are equal to those of an
uninterrupted run, apart from `ts`, `elapsed_ms`, `seq`, `threads`, `started_at` and
`finished_at`. `progress` and `checkpoint`
events depend on where the stops happened and are not part of that promise.

## 7. Determinism

Enumeration order is completely defined by the resolved search space; offset/limit
address that order. The Task 9 base order is a flat lexicographic order over the
assignment tuple: dimensions are visited in definition slot order (left to right), and
within a slot in the order `wheel`, `position`, `ring`; the plugboard remainder is the
last dimension. Later dimensions vary fastest (odometer), so the rightmost slot and
then the plugboard remainder change fastest. A dimension that is structurally fixed or
has a single-value domain contributes one value and does not vary. The plugboard
remainder enumerates the `size`-element combinations of `candidates` in increasing
candidate-index order, lexicographically. `offset` skips that many candidates and
`limit` caps how many are produced, both counted in this one flat order. Multi-variant
search (several machine definitions in one request) is not planned: to try another
machine, run a separate request with that machine's definition.
Scoring uses integer/fixed-point arithmetic where floating point
could vary, otherwise results are bit-identical. Unordered reductions do not affect
scores; each candidate is scored independently. Stochastic passes record seed and RNG
state. Holds order by `(score desc, enumeration index asc)`; for attacks the index is
(outer, start) and stages re-rank per
[search-passes §10](search-passes.md#10-hold-list--task-14). These obligations apply
only to implemented search jobs. The planned Task 11 attack branch retains the
per-slot order but slices outer scramblers only; seed/action indices are separate,
as specified in [attack order](search-passes.md#3-pre-execution-gates-and-outer-order).
With `space.constraints.distinct_wheels`, the outer order is that same order with every
candidate that repeats a wheel among the named slots removed; outer indices, `offset`,
`limit`, `outers_selected`, blocks and checkpoint `next_outer` all count in that
filtered order. Without constraints the order and counts are exactly as before.
This does not change legacy subset enumeration or define cross-pass holds.

## 8. Web client (Stage 2)

The web client is a separate program, `enigma-web` (Go, `web/`), released apart from
the engine. There is no TUI and the engine binary has no listener. `enigma-web` uses
only this CLI's public surface: it runs `enigma` as a child process with
`--events - --request -`, writes the request to stdin and reads the JSONL events of §4
from stdout; cancellation uses the cancel file (§5), and checkpoints use the §6 options.
It never links the engine library. For attacks, `enigma-web` runs a child with
`--events - --request request.json`, `--checkpoint`/`--resume` and a per-run cancel
file, retaining each run's events and report in its attack directory.

Compatibility: `enigma-web` keeps an explicit list of supported engine versions, as
printed by `--version` (`enigma <version>` and `protocol version <n>`). It refuses any
other engine, older or newer, until `enigma-web` itself is updated; an engine change
that the web client must follow therefore ships with a matching `enigma-web` release.

The listener binds `127.0.0.1` only and never `0.0.0.0`, requires a per-run random
token that is part of the URL opened in the browser, and rejects requests whose `Host`
or `Origin` is not its own loopback address. Its HTTP routes belong to `enigma-web`
and are documented in `web/README.md`; they are not part of this protocol.

## 9. `bomm` parity

No compatibility with `bomm` query JSON is required. Each differential case expresses
equivalent machine, key, input, pass, and score configuration in each tool's own format.
Compare resulting key/plaintext and compare scores only when measure, resources, and
passes are equivalent. Shared acceptance of one JSON file is not evidence of parity.
Task 17 is the differential-oracle validation task.

## 10. Version and status

Engine 0.2.0 adds the optional `space.constraints` member under protocol version 1,
an additive extension like `hold` and chained stages.

`protocol_version: 1` denotes this unpublished contract. Unknown
versions and fields fail before work. Incompatible changes to field meaning,
validation, traversal, or event ordering after v1 ships require a version bump. Detailed
pass execution fields other than the [Task 11 contract](search-passes.md)
(whose HC/PE attacks and [Task 13 chained stages](search-passes.md#9-chained-stages--task-13)
execute) remain deferred; the checkpoint record is specified in §6.3. They must be specified
before their implementation, not presumed executable or imported from `bomm`.
Search-space and [measure/resource schemas](scoring-resources.md) are specified as
normative design; that does not assert implemented scoring or search execution.
The engine has no UI; the Stage 2 web client is the separate program of §8.

## 11. GPU constraints (Stage 4)

Progress uses completed work units. A cursor identifies a resumable position without a
CPU loop counter. Scores are independent per candidate. Thread counts, workgroup sizes,
and dispatch geometry are not protocol fields; backend metadata is informational only.
