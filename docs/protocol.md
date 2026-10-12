# Engine Protocol

Status: **Protocol v1 is unpublished pre-implementation design; Rust implementation is
pending.** It replaces the former superset-of-`bomm` proposal. It makes no promise to
accept `bomm` query files unchanged; `bomm` remains a differential oracle. See
`odd/tasks/enigma-engine.md` for task status. No UI is in Stage 1; UI begins in Stage 2.

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
specifies the normative Task 10 measure/resource contract. Pass execution fields and
checkpoint record layout remain deferred to their implementation tasks.
[Core HC API](search-passes.md#62-public-core-hc-api--task-128) freezes the
first public HC/PE adapter contract; §4.1 freezes its JSONL projection, not execution.
[Task 11 plugboard attacks](search-passes.md) freezes the planned additive attack
branch and pass settings; strict attack parsing and CLI validation are supported,
but execution is not. Illustrative
search concepts below are not executable request examples. Representability does not imply catalog availability or
search support.

## 2. Transport

| Mode | Use | Enabled by | Stage |
| --- | --- | --- | --- |
| `stdio` (default) | TUI, scripts, tests | — | 1 |
| local listener | web client | `--listen 127.0.0.1:<port>` | 2 (planned) |

`stdout` contains one JSON object per line (JSONL), without embedded newlines.
Diagnostics go to `stderr`. Stage 1 accepts a positional request file path,
`--request <path>` for a file, or `--request -` for stdin. A future Stage 2 listener
carries the same messages. No UI is part of Stage 1.

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
section is normative for the §3.2/§3.3 structure; it does not claim that any search
pass executes (Tasks 11–13 implement the passes).

`space` is an object allowing exactly `slots`, `plugboard`, `offset`, and `limit`; all
four are optional, so an empty object means the fixed choices are already complete.
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

**Implementation status:** Task 9 implements the structural boundary and capability
framework. Task 10 implements deterministic IC, Shannon entropy, Sinkov n-gram and
weighted trie scoring, strict external resource parsers, typed measure/resource
selection, pure content binding, and bounded CLI loading. The CLI uses shared strict
dispatch to validate and bind search resources before returning one `unsupported_job`
error, with no `started`, `output`, `done`, or enumeration; resource errors precede
that result. Valid search is still not executable in the current CLI. Transform
never loads resources. This status does not change transform grammar or events.

[Task 11](search-passes.md) adds strict attack dispatch when
`job.space.plugboard.kind` is `"attack"`, still with `job.kind = "search"`.
The CLI loads and binds resources, checks eligibility, then emits one seq1
`unsupported_job` at `/job/kind`: `attack execution is not implemented`.
Structural, loading, model-binding and eligibility errors precede that result.
Missing or other discriminators retain legacy search validation. Private HC/PE
evaluation, seed exhaustion and ordered outer scheduling are implemented.
Core `AttackRequest::run` supports synchronous HC with counter-only observation
and independently polled cancellation; public PE and CLI execution remain unsupported.

Stage 1 plans `hill_climb`, `partial_exhaustion` with backtracking, `reswapping`, `trie`,
and `measure`; measures include index of coincidence, Sinkov n-gram statistics,
Shannon entropy, and trie scoring. This plan does not assert parser or search support.
Representability by the definition schema does not imply algorithm support for arbitrary
alphabet, wheel count, stepping rule, or topology.

## 4. Events and validation errors

Each stdout line is a JSON event with `event`, `protocol_version`, monotonic `seq`
starting at 1, and RFC 3339 UTC `ts`. Unknown event names/fields may be ignored by
clients. A successful validated job emits one `started` first, then applicable events,
then exactly one terminal `done`; runtime failure emits terminal `error`. Search may
emit `progress`, `candidate`, `checkpoint`, and `hold` according to job lifecycle.
The first HC/PE release instead uses only `progress` and final `result` (§4.1);
`candidate`, `checkpoint` and `hold` remain eventual Stage 1 requirements, not part
of that release. Transform emits no candidate, hold, or checkpoint event. A validated `transform` job
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
`unsupported_topology`, `resource_limit` (including pre-execution count/budget bounds),
and `internal_error`. `internal_error` is reserved for an
internal runtime failure after `started` (including evaluation, resolution or counter
invariants); it is never a request-validation failure.
Syntax errors point to the closest available containing path.

### 4.1 Planned HC/PE search events — Task 12.7

**Frozen design, not implemented:** existing `Event`/`DoneReason` and CLI still
support transform only; validated attacks still return `unsupported_job` before
`started`. No new request fields or execution permission follow from this section.
Only one attack pass, `hill_climb` or `partial_exhaustion`, is eligible; recognition
of other passes is not support. Mixed/deferred/legacy rejection remains unchanged.

After all parsing, resource loading/binding, eligibility and count/budget validation,
emit `started`, zero or more `progress`, one `result`, then exactly one terminal
`done` or runtime `error`. Preflight failures retain the existing seq1 `error` only.
Task12.8 stages Core HC availability only; valid PE remains unsupported until12.9.
Its Core unsupported-execution availability error is not a runtime error: wire
validation/preflight still emits seq1 `unsupported_job` before `started`, with no
`result` or work events. This staging does not authorize CLI changes or wire execution.
On runtime error, `result` contains only the earlier successfully committed aggregate
best, or null; do not invent a result for the failing climb. No `done` follows error.
`result` is final, not a stream of provisional trials or a hold list.

Payloads below supplement the existing event envelope; `done` stays reason-only:

| Event | Required payload |
| --- | --- |
| `progress` | `counters`, `elapsed_ms` |
| `result` | `best` (object or null), `counters`, `elapsed_ms` |
| `done` | `reason`: `completed`, `outer_slice_end`, `evaluation_budget`, or `cancelled` |
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
and `ranking_q32`. Ranking is higher-is-better; do not negate measured entropy.
The three boolean winner flags are independent of each other and of run termination;
`incomplete` means that winning climb was interrupted. Ties retain earliest
(outer index, start index). No best means JSON null, never a sentinel key or score.

All new search count/index/elapsed fields are canonical unsigned decimal **strings**
(`0` or a nonzero digit followed by digits), including u64 counts; Q32 fields are
canonical signed decimal strings of raw i128 units (optional minus, no `+`, leading
zeros or `-0`). The scale is exactly 2^32; no float, exponent or rounded decimal
score is sent. u128 indices/counters retain their full range. Existing request
integer grammar and transform envelope numbers (`protocol_version`, `seq`) do not
change; strings are used consistently even inside the safe JSON integer range.

Elapsed time is monotonic whole milliseconds since execution entry after preflight,
not RFC3339 wall-clock subtraction; terminal values include final rescoring. The
transport coalesces immutable private snapshots at safe callback boundaries using
an explicitly supplied positive adapter progress interval, independent of cancel
polling. Entry and final snapshots are available without waiting for the interval;
the final counters always travel in `result`. Duplicate snapshots are allowed.
There is no numeric default or request cadence field frozen here, nor a timer-thread,
mid-evaluation callback or hard wall-clock delivery/cancellation bound. Timestamp
`ts` remains supplied UTC wall time. No clock or I/O enters the private evaluator.

Map established exhaustion of a nonempty requested slice to `completed`; an empty
slice to `outer_slice_end`, not legacy `offset_end`/`limit_reached`. When work remains,
map safe cancellation to `cancelled`, otherwise allowance stop to
`evaluation_budget`. Errors dominate cancellation; exhaustion > cancellation >
budget. Required reserved final rescoring must succeed before an interrupted current
board is eligible; failed rescoring is error, never a provisional best or cancellation.

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
cooperative cancellation independently of progress cadence. It still permits required
final rescoring and retains any runtime error and charged usage. Report transport
failure on stderr and exit nonzero; retain runtime failure as primary when both occur.
Never retry a partially written JSONL line or promise `result`/terminal delivery on
failed transport. On a healthy stream flush each emitted line; exactly-one-terminal
ordering applies only while delivery succeeds, including final result write/flush.

## 5. Control

| Action | Mechanism | Result |
| --- | --- | --- |
| Cancel (first HC/PE release) | Future `--cancel-file <path>` adapter; POSIX `SIGINT`/`SIGTERM` and Windows Ctrl+C integration separately pending | Cooperative safe-stop, final `result`, then `done` with `reason: "cancelled"`; no hold/checkpoint promise |
| Pause/resume live job | Not in Stage 1 | Future extension |
| Resume dead job | `--resume <checkpoint>` | Search only; see §6 |
| Bound HC/PE search | `space.offset`/`space.limit`, `attack.evaluation_budget` | §4.1 slice/exhaustion/budget reasons; no new `--max-keys` attack control |
| Other future bounded search | Planned `--max-keys` | Legacy planned `limit_reached`/`offset_end`, not HC/PE mappings |

Transform has no search progress, cancellation, hold, or checkpoint contract in v1.

[Task 12 private integration](search-passes.md#61-private-progress-and-cancellation--task-12)
implements shared accounting, counter-only snapshots and cooperative cancellation
for private HC climbs/outer scheduling and PE seeds/resolved owners/outer scheduling.
Admitted evaluations are nonpreemptive; established exhaustion wins over cancellation,
which wins over budget. Stops retain committed results and required reserved final
rescoring; original errors and charged usage are preserved, not masked by cancellation.
This is not public timed progress or search execution: public runtime, JSONL events,
platform signals/control files, hold and checkpoint cadence remain unimplemented.
The first-release obligations in §4.1 remain design requirements, not shipped
behavior. Cancel-file integration (Task12.12) and POSIX/Windows signals (Task12.13)
are provisional/unstarted: they may only feed a sticky cancellation request, never
perform evaluation or JSONL writes in a signal handler. File contents/polling and
platform setup/failure details must be specified before those adapters implement.
Hold remains deferred, not removed from eventual Stage 1 goals; cancellation in the
first release writes no hold or checkpoint. Checkpoint/resume remains Task 16 under §6.

## 6. Checkpoint and resume (record schema deferred)

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
resume restores the same next candidate. Detailed record fields are deferred to task
16 and must be finalized before implementation.

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
`limit` caps how many are produced, both counted in this one flat order. Task 14 may
nest deterministic variant selection outside this base order; it does not change the
order within a variant. Scoring uses integer/fixed-point arithmetic where floating point
could vary, otherwise results are bit-identical. Unordered reductions do not affect
scores; each candidate is scored independently. Stochastic passes record seed and RNG
state. Holds order by `(score desc, enumeration index asc)`. These obligations apply
only to implemented search jobs. The planned Task 11 attack branch retains the
per-slot order but slices outer scramblers only; seed/action indices and evaluation
budgets are separate, as specified in [attack order](search-passes.md#3-pre-execution-gates-and-outer-order).
This does not change legacy subset enumeration or define cross-pass holds.

## 8. Local listener (Stage 2)

Not Stage 1. A future listener binds `127.0.0.1` only, forbids `0.0.0.0`, uses a
per-run bearer token printed once to stderr, validates `Origin` against an allow-list,
and mirrors the protocol through `POST /jobs`, `GET /jobs/{id}/events`, and
`POST /jobs/{id}/cancel`.

## 9. `bomm` parity

No compatibility with `bomm` query JSON is required. Each differential case expresses
equivalent machine, key, input, pass, and score configuration in each tool's own format.
Compare resulting key/plaintext and compare scores only when measure, resources, and
passes are equivalent. Shared acceptance of one JSON file is not evidence of parity.
Task 17 is the differential-oracle validation task.

## 10. Version and status

`protocol_version: 1` denotes this unpublished, pre-implementation design. Unknown
versions and fields fail before work. Incompatible changes to field meaning,
validation, traversal, or event ordering after v1 ships require a version bump. Detailed
pass execution fields other than the [planned Task 11 contract](search-passes.md)
and checkpoint schemas remain deferred; they must be specified
before their implementation, not presumed executable or imported from `bomm`.
Search-space and [measure/resource schemas](scoring-resources.md) are specified as
normative design; that does not assert implemented scoring or search execution.
There is no Stage 1 UI; clients belong to Stage 2.

## 11. GPU constraints (Stage 4)

Progress uses completed work units. A cursor identifies a resumable position without a
CPU loop counter. Scores are independent per candidate. Thread counts, workgroup sizes,
and dispatch geometry are not protocol fields; backend metadata is informational only.
