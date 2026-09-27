# Engine Protocol

Status: **Protocol v1 is a revised pre-implementation design; Rust implementation is
pending.** It is not a shipped interface. This explicitly agreed redesign replaces the
previous frozen superset-of-`bomm` request promise. Backwards compatibility with `bomm`
query files is not a requirement; parity remains a test obligation using equivalent
configurations expressed in each tool's own format (see §9).

This document specifies the target contract between the cryptanalysis engine and its
clients. It is independent of transport and implementation. Stage 1 uses `stdin` and
`stdout`; a later local listener can carry the same messages. Examples and guarantees
describe intended behavior, not current Rust capabilities. See
`odd/tasks/enigma-engine.md` for implementation status and work units.

## 1. Design principles

1. **Transport-agnostic.** The protocol defines messages, not transport.
2. **Strict requests, tolerant event consumers.** Unknown request fields, versions,
   enum values, or unsupported DSL forms fail closed. Clients may ignore unknown event
   names and event fields.
3. **Declarative machine model.** Alphabet, wheels, slots, stepping, and jobs are
   represented as data. The protocol does not imply that every representable topology
   has a preset or is supported by every search pass.
4. **Deterministic and reproducible.** A request fully determines enumeration order and
   scores; backend differences must not change results.
5. **Checkpoint-first.** Progress, cancellation, and resume are protocol features.

## 2. Transport

| Mode | Use | Enabled by | Stage |
| --- | --- | --- | --- |
| `stdio` (default) | TUI, scripts, tests | — | 1 |
| local listener | web client | `--listen 127.0.0.1:<port>` | 2 (planned) |

`stdout` contains only one JSON object per line (JSONL), without embedded newlines.
Diagnostics, warnings, and logs go to `stderr`. A request is supplied by path argument,
`--request -` (read from `stdin`), or as an HTTP POST body in listener mode.

## 3. Request (input)

A request is one JSON object with exactly three root fields: `protocol_version`,
`machine`, and `job`. Version 1 requires all three; unknown fields are errors. JSON
object member order has no meaning. The schema below is the v1 target, not an assertion
that a parser or any listed job already exists.

```json
{
  "protocol_version": 1,
  "machine": {
    "alphabet": ["A", "B", "C", "D"],
    "wheels": [
      {"name": "entry", "wiring": ["A", "B", "C", "D"], "turnovers": []},
      {"name": "rotor", "wiring": ["B", "A", "D", "C"], "turnovers": ["B"]},
      {"name": "reflector", "wiring": ["B", "A", "D", "C"], "turnovers": []}
    ],
    "slots": [
      {"id": "ukw", "wheel": "reflector", "role": "reflector", "movement": "fixed", "position": "A", "ring": "A"},
      {"id": "slow", "wheel": "rotor", "role": "rotor", "movement": "movable", "position": "A", "ring": "A"},
      {"id": "entry", "wheel": "entry", "role": "rotor", "movement": "fixed", "position": "A", "ring": "A"}
    ],
    "plugboard": [["A", "B"]],
    "stepping": {"rules": [
      {"when": {"at_turnover": "slow"}, "advance": ["slow"]},
      {"when": {"always": true}, "advance": ["slow"]}
    ]}
  },
  "job": {"kind": "transform", "text": "ABCD", "direction": "encrypt"}
}
```

This four-symbol illustration is valid JSON and a valid transform configuration. Its
small arbitrary wiring is a protocol-shape example, not a historical Enigma preset.

### 3.1 Machine

#### Alphabet and symbols

`machine.alphabet` is a non-empty ordered array of unique single Unicode scalar values.
The order defines symbol indices and is semantically significant. ASCII letters and
digits are permitted. A symbol is exactly one scalar value: combining sequences count
as multiple scalars and are rejected. The engine does not trim, case-fold, normalize,
or otherwise rewrite symbols or text. Implementations must reject invalid Unicode
scalar encodings, duplicate symbols, and an alphabet too large for the supported
implementation before execution; the supported maximum size must be documented by the
implementation and reported as a validation error when exceeded.

Every symbol in wiring arrays, turnover arrays, positions, rings, plug pairs, and job
text must be a member of this alphabet. Arrays preserve order except where explicitly
specified as sets.

#### Wheels

`machine.wheels` is a non-empty array of named wheel definitions:

- `name`: non-empty unique string.
- `wiring`: array with exactly one alphabet symbol per alphabet symbol. At input index
  `i`, the symbol at `wiring[i]` is the output. It must be a bijection; its inverse is
  derived by the engine.
- `turnovers`: array of distinct alphabet symbols. These are displayed pre-step
  symbols at which this wheel's slot satisfies `at_turnover`; they are not adjusted for
  the ring setting.

A reflector-role slot's referenced wheel must additionally be involutive (`wiring` is
its own inverse). Other wheels may be any bijection.

#### Slots and topology

`machine` has exactly `alphabet`, `wheels`, `slots`, `stepping`, and optional
`plugboard`; omitted `plugboard` means the identity mapping. A machine may have any
number of `role: "rotor"` slots starting at one, plus an optional `role: "reflector"`
slot. The engine must support configurations with at least six rotor slots (plus an
optional reflector); six is a capacity requirement, not a minimum configuration size
or a maximum. Implementations may impose a documented upper resource limit and must
reject requests over it before work starts.

`machine.slots` is a non-empty array in physical left-to-right order. Each slot has
exactly `id`, `wheel`, `role`, `movement`, `position`, and `ring`:

- `id`: non-empty unique stable slot identifier.
- `wheel`: reference to one declared wheel.
- `role`: `rotor` or `reflector`. A stationary entry wheel is represented as a `rotor`
  slot with `movement: "fixed"`; no third role is implied.
- `movement`: `fixed` or `movable`. Movement is explicit and independent of role, so a
  reflector can move only when configured as movable.
- `position` and `ring`: one alphabet symbol each.

At most one reflector slot is permitted, and if present it must be the leftmost slot.
A reflector is optional. Every slot without reflector role is traversed as a rotor
(whether fixed or movable). A step rule may target only movable slots; attempting to
advance a fixed slot is invalid configuration, never silently ignored. This supports a
stationary historical entry wheel and a movable reflector when explicitly configured,
without promising exotic preset/mechanism paths.

`machine.plugboard` is an array of two-symbol arrays. Each symbol occurs in at most
one pair; pairs therefore define a disjoint involution, and unpaired symbols map to
themselves. The empty array means identity. A symbol paired with itself is invalid.
Plugboard transformation is applied at both ends of every traversal.

#### Declarative stepping rules

`machine.stepping` has exactly one field, `rules`, an ordered array of rules. A rule is
`{"when": CONDITION, "advance": [SLOT_ID, ...]}`. The following is grammar notation,
not one JSON document; quoted values such as `"slot-id"` and `"A"` stand for ordinary
JSON strings containing a declared slot ID and alphabet symbol respectively:

```text
condition := {"always": true}
           | {"at_turnover": slot_id}
           | {"at_position": {"slot": slot_id, "symbol": symbol}}
           | {"all": [condition, ...]}
           | {"any": [condition, ...]}
           | {"not": condition}

slot_id   := JSON string naming a declared slot
symbol    := JSON string containing one alphabet symbol
```

Each condition object has exactly one operator. `all` and `any` require non-empty
arrays; `not` contains one condition. `always` must be literal `true`. Conditions refer
to declared slot IDs; `at_turnover` is true when that slot's wheel turnover set contains
the slot's displayed pre-keypress position. `at_position` compares that same displayed
position with its symbol. Ring setting affects electrical offset only; it does not
subtract from the turnover position.

All conditions for every rule are evaluated against the same state before the
keypress. The target slot IDs from all matching rules are unioned, then each target is
advanced exactly once, simultaneously, before electrical traversal. Rule order does
not change the result. An empty `rules` array means no slots move. Empty `advance`
arrays are permitted and have no effect. Unknown slot references, unknown operators,
invalid symbols, duplicate/unknown fields, non-movable targets, and malformed
conditions are validation errors; no DSL element is ignored and arbitrary executable
code is not permitted.

Implementations must enforce grammar limits before starting: at most 64 rules, at most
256 condition nodes total, maximum nesting depth 16, and at most 64 distinct advance
targets across the rules. Exceeding a bound is an actionable validation error. These
limits constrain parsing/evaluation resources, not machine size.

### 3.2 Jobs

All work-specific fields live under `job`; `job.kind` selects a defined job. Unknown or
unsupported kinds fail validation before work starts. Version 1 defines these shapes:

- **Transform:** `{"kind":"transform","text":"...","direction":"encrypt"}`;
  `direction` is `encrypt` or `decrypt`. Before processing each symbol, apply the
  configured stepping rules once, independent of direction. Let `N` be the alphabet
  length, and encode alphabet symbols as zero-based indices. For each rotor slot let
  `p` be its current displayed position index and `r` its ring index; define the modular
  offset `o = (p - r) mod N`. Interpret every wheel wiring entry as an alphabet index.
  Its forward electrical mapping is
  `forward(x) = (wiring[(x + o) mod N] - o) mod N`; its reverse mapping substitutes
  the inverse wiring for `wiring` in that formula. Thus reverse is the mathematical
  inverse of forward at the same position and ring.

  With a reflector, begin with the input plugboard mapping, traverse rotor slots from
  rightmost toward leftmost using forward mappings, apply the reflector exactly once
  using its own `p`, `r`, and offset-adjusted forward mapping, then traverse rotor slots
  left-to-right using reverse mappings, and apply the output plugboard mapping. The
  reflector must be involutive as validated in §3.1. Encrypt and decrypt use this same
  reciprocal traversal and therefore produce the same transform.

  Without a reflector, encrypt applies the input plugboard, traverses all rotor slots
  rightmost-to-leftmost using forward mappings, then applies the output plugboard.
  Decrypt applies the input plugboard, traverses slots leftmost-to-rightmost using
  reverse mappings, then applies the output plugboard. It uses the same stepping
  schedule as encrypt; only the electrical traversal reverses. No general involution or
  no-self-encryption guarantee is made.
- **Search (Stage 1 planned):** fields are `kind: "search"`, `text` (ciphertext),
  `space`, `passes`, `measures`, and optional `resources`. These stay nested in `job`,
  not at the request root. `space` describes the key enumeration using the machine's
  slots and includes `offset`, `limit`, and optional `variants`; each variant supplies
  an alternate slot configuration over declared wheels. `passes` is an ordered array
  using the pass definitions in §3.3; `measures` names/configures scoring measures;
  `resources` declares external scoring inputs such as frequency maps or trie data.
  Search must reject a topology, pass, measure, or resource unsupported by that release
  before enumeration. This schema reserves no implicit access to files: resource paths
  and their readability/content must be validated before work starts. Exact per-pass,
  key-space, scoring-resource, and checkpoint compatibility fields require definition
  before their implementation; they must not be inferred from old `bomm` root fields.

The search field inventory above locates the established concepts consistently; it is
not a claim that their detailed v1 sub-schemas or parser exist. Any field needing a
separate incompatible evolution must be introduced by a protocol version change, not
silently added to v1 after it ships.

A topology's representability does not guarantee presets or search support for it.
Stage 1 targets Enigma I, M3, and M4 presets plus the explicitly listed search work;
search support for arbitrary runtime alphabets, wheel counts, or stepping rules must be
stated and validated by implementation rather than inferred from this declarative
schema.

### 3.3 Search pass and measure plan

Search targets the four `bomm` pass concepts—`hill_climb`, `reswapping`, `trie`, and
`measure`—plus `partial_exhaustion` in Stage 1. Measures target index of coincidence,
Sinkov n-gram statistics, Shannon entropy, and trie scoring. Their detailed request
fields and resource formats must be specified before those implementations; this list
is a plan, not parser support. A pass or measure unavailable in a release must be
rejected, never skipped. Stage 3 crib attacks and Stage 5 simulated annealing, genetic
search, exotic presets, and `cog` are not implied by v1 implementation support.

## 4. Event stream (output)

Every line is a JSON object with `event`, `protocol_version`, `seq`, and `ts`. `seq` is
monotonic from 1; `ts` is RFC 3339 UTC. Field order is illustrative. Events retain the
existing envelopes and ordering guarantees while job-specific fields (for example,
search totals and candidate topology) are adapted to variable alphabet size, topology,
and `job` nesting. No event may fabricate a value for a field that is not meaningful
for that job.

### 4.1 Events and ordering

- `started`: exactly once and first for a run that passed validation. It identifies the
  job and reports applicable run metadata.
- `progress`: zero or more rate-limited progress reports, expressed in completed work
  units.
- `candidate`: zero or more search results, emitted when the hold changes, not per
  evaluation. It is not emitted for transform jobs.
- `checkpoint`: zero or more durable checkpoint notifications.
- `hold`: for started search jobs, emitted once on completion, cancellation, or
  shutdown. It is not fabricated for transform jobs.
- `done`: exactly once and last on normal completion/cancellation/bounded completion.
- `error`: terminal and always last; pre-validation errors are described below.

Exactly one `started` is first except for a pre-validation error, which has no
`started`. Exactly one terminal event (`done` or `error`) is last. `seq` strictly
increases; candidates occur only after `started` and before terminal. Existing
cancellation, hold, checkpoint, and deterministic-order guarantees continue to apply
to jobs for which they are meaningful.

### 4.2 Validation errors

Before any work starts, validate JSON syntax; exact fields and version; alphabet and
symbol constraints; wheel wiring permutations and inverses; reflector involution;
plugboard pairs; slot topology and named references; stepping grammar, limits and
movement compatibility; job kind/direction and topology compatibility; text alphabet
membership; and, for search, key-space, pass, scoring measure, and resource constraints.
No work starts until all validation succeeds.

On invalid input, emit exactly one terminal JSONL `error` with `seq: 1`, this engine's
`protocol_version`, a stable `code`, human-actionable `message`, and JSON Pointer
`location` identifying the offending value (or the closest containing value for a
syntax error). `expected` and `hint` may additionally be supplied. Write a diagnostic
to `stderr`, exit nonzero, and emit no `started`, progress, candidate, hold, or done.
Unknown protocol versions are rejected the same way; the emitted version is the
engine's supported version. Validation error codes include `invalid_json`,
`invalid_request`, `unsupported_version`, `unknown_field`, `invalid_alphabet`,
`invalid_symbol`, `invalid_wiring`, `invalid_reflector`, `invalid_plugboard`,
`invalid_slot`, `invalid_rule`, `unsupported_job`, `unsupported_pass`,
`unsupported_measure`, `unsupported_resource`, `invalid_text`, and
`unsupported_topology`. Implementations may define further stable codes. Runtime
failures after `started` use terminal `error` and preserve the event ordering contract.

A representative error (all fields are JSON values):

```json
{"event":"error","protocol_version":1,"seq":1,"ts":"2026-01-01T00:00:00Z",
 "code":"invalid_symbol","message":"position is not a member of machine.alphabet",
 "location":"/machine/slots/1/position","expected":"one alphabet symbol"}
```

## 5. Control

| Action | Mechanism | Result |
| --- | --- | --- |
| Cancel | POSIX `SIGINT`/`SIGTERM`, Windows console Ctrl+C, or `--cancel-file <path>` | A started search emits `hold`, writes a final checkpoint when configured, emits `done` with `reason: "cancelled"`, exits 0 |
| Pause / resume a live job | Not in Stage 1 | Future extension |
| Resume a dead job | `--resume <checkpoint>` | §6 |
| Bound a search | Search key-space offset/limit or `--max-keys` | `done` with `limit_reached` or `offset_end` |

Cancellation is cooperative and bounded: observe it within one progress interval and
never lose the hold. Windows handles console Ctrl+C; `--cancel-file` is the portable
control for scripts and tests.

## 6. Checkpoint and resume

A started resumable search may write checkpoints at `--checkpoint-interval` (default
300 s), and writes a final checkpoint on normal terminal completion when configured.
A pre-validation error never writes one. Checkpoints include `protocol_version`, a
canonical request digest, state digest, completed work units, elapsed time, structured
cursor, hold, and RNG state when a stochastic pass is used. Resume requires an exact
request digest match; a checkpoint cannot be applied to a different job or machine.
Cursor representation must not depend on a CPU loop counter and must account for
variable topology. A stochastic resume without reproducible RNG state is rejected.
A resumed run reports `resumed_from` in `started`.

The concrete checkpoint schema must track the finalized search-job schema before
implementation; this section does not claim a parser or checkpoint implementation.

## 7. Determinism rules

1. Search enumeration order is fully determined by machine, job, and search-space
   definitions; offset and limit address that order.
2. Scoring uses integer or fixed-point arithmetic where floating point could vary
   between backends. Otherwise results are bit-identical.
3. Unordered reductions may not affect scores; each candidate is scored independently.
4. Stochastic passes record their seed in `started` and checkpoints.
5. Search holds are totally ordered by `(score desc, enumeration index asc)`.

These obligations apply only to implemented jobs and measures.

## 8. Local listener (web client) — Stage 2 planned

Not part of Stage 1. It binds `127.0.0.1` only; binding `0.0.0.0` is forbidden. It
requires a per-run bearer token printed once to `stderr`, validates `Origin` against an
allow-list, and mirrors the protocol through `POST /jobs`,
`GET /jobs/{id}/events`, and `POST /jobs/{id}/cancel`.

## 9. Compatibility and parity with `bomm`

`bomm` query JSON compatibility is not a requirement: this v1 redesign replaces the
previous superset promise, and old query files need not parse unchanged. `bomm` remains a
differential test oracle. Each parity test expresses equivalent machine, key, input
text, and scoring configuration in the protocol's own request format and in `bomm`'s
format. Compare resulting key, plaintext, and score. Compare scores only when measure,
resources, and passes are equivalent. Tests must not claim equivalence merely because
both tools accepted the same JSON file, and no unchanged-query obligation remains.

## 10. Versioning and status

`protocol_version` versions the request contract. Version 1 is the redesigned,
pre-implementation contract in this document. Unknown versions and fields are rejected
before work. This is an explicit redesign, not a silent extension of the former
frozen interface; historical task and commit evidence about the earlier alignment
remains historically accurate (see `odd/tasks/enigma-engine.md`).

Once v1 ships, incompatible changes to field meaning, validation, traversal, or event
ordering require a version bump. New request fields or enum values require an explicit
versioned evolution; event consumers may ignore unknown event names/fields. Detailed
search fields and any resource formats not yet specified here must be defined before
implementation or via such a versioned evolution, never presumed to exist.

## 11. GPU constraints (Stage 4)

1. Progress is expressed in completed work units, not loop iterations.
2. A cursor identifies a resumable position without depending on a CPU loop counter.
3. Scores are computed per candidate independently.
4. Thread counts, workgroup sizes, and dispatch geometry are not protocol fields;
   backend metadata is informational only.
