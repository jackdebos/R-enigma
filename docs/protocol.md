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

This document marks protocol requirements as normative. Exact search-space grammar,
pass fields, scoring/resource schemas, and checkpoint record layout are deferred to
tasks 9, 10, and 16, respectively. Illustrative search concepts below are not
executable request examples. Representability does not imply catalog availability or
search support.

## 2. Transport

| Mode | Use | Enabled by | Stage |
| --- | --- | --- | --- |
| `stdio` (default) | TUI, scripts, tests | — | 1 |
| local listener | web client | `--listen 127.0.0.1:<port>` | 2 (planned) |

`stdout` contains one JSON object per line (JSONL), without embedded newlines.
Diagnostics go to `stderr`. Stage 1 accepts a request file path or `--request -` for
stdin. A future Stage 2 listener carries the same messages. No UI is part of Stage 1.

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

For `kind: "search"`, `configuration` expresses only the **known fixed choices**, and
`space` expressly covers every remaining required choice (§3.3). Omission from the
fixed portion alone means neither default nor automatic enumeration: if the same
choice has no explicit variable domain in `space`, the request is invalid. For a
partially known plugboard, the future search grammar must distinguish a fully fixed
pair set (including the empty set) from known pairs plus an explicitly searched
remainder; it must not reuse `[]` ambiguously for both. Exact partial-configuration
syntax is finalized with `space` in task 9, before search parsing. No search object
is claimed executable until this grammar is specified.

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

### 3.3 Search job boundary (schema deferred)

A search job has `kind: "search"`, required `configuration`, `text`, `space`,
`passes`, `measures`, and optional `resources`. `configuration` contains fixed known
choices, while `space` contains explicit variable domains over definition slots and
bounds such as `offset` and `limit`; `passes`, `measures`, and `resources` select and
parameterize search behavior. This inventory is normative about the job boundary,
not an executable schema. Do not treat a schematic search object as valid v1 JSON.

For every required key dimension (including wheel choice where configurable,
position, ring, and plugboard state), validation must prove exactly one coverage path:
fully fixed by `configuration`, or variable in `space`, possibly constrained by
explicit fixed partial facts such as known plugboard pairs. The variable remainder
must be explicitly identified; fixed and variable assignments cannot conflict or
leave an unbounded omission. The candidate resolver enforces definition restrictions,
disjoint plugboard pairs, and unique complete candidates. Task 9 must define the exact
partial-slot/plugboard syntax, search domains, bounds, variants, coverage checks, and
unknown-versus-omitted errors before any search parser is implemented; task 10 defines
resource and measure syntax. Concrete candidates are bound anew to their final
topology and stepping rules; incompatible slot/wheel combinations or unsupported
topology/pass/measure/resource combinations fail preflight before enumeration. Search
never silently skips unsupported work.

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
Transform emits no candidate, hold, or checkpoint event. Pre-validation failure emits
one `error` at `seq: 1`, with no `started` or work events. Errors contain stable `code`,
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
`invalid_plugboard`, `invalid_slot`, `invalid_rule`, `unsupported_job`,
`unsupported_pass`, `unsupported_measure`, `unsupported_resource`, `invalid_text`, and
`unsupported_topology`. Syntax errors point to the closest available containing path.

## 5. Control

| Action | Mechanism | Result |
| --- | --- | --- |
| Cancel | POSIX `SIGINT`/`SIGTERM`, Windows Ctrl+C, or `--cancel-file <path>` | Started search observes cancellation within a progress interval, emits hold and configured final checkpoint, then `done` with `reason: "cancelled"` |
| Pause/resume live job | Not in Stage 1 | Future extension |
| Resume dead job | `--resume <checkpoint>` | Search only; see §6 |
| Bound search | `space` offset/limit or `--max-keys` | `done` with `limit_reached` or `offset_end` |

Transform has no search progress, cancellation, hold, or checkpoint contract in v1.

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
address that order. Scoring uses integer/fixed-point arithmetic where floating point
could vary, otherwise results are bit-identical. Unordered reductions do not affect
scores; each candidate is scored independently. Stochastic passes record seed and RNG
state. Holds order by `(score desc, enumeration index asc)`. These obligations apply
only to implemented search jobs.

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
search-space, pass, measure/resource, and checkpoint schemas remain deferred; they must
be specified before their implementation, not presumed executable or imported from
`bomm`. There is no Stage 1 UI; clients belong to Stage 2.

## 11. GPU constraints (Stage 4)

Progress uses completed work units. A cursor identifies a resumable position without a
CPU loop counter. Scores are independent per candidate. Thread counts, workgroup sizes,
and dispatch geometry are not protocol fields; backend metadata is informational only.
