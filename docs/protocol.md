# Engine Protocol

Status: **Stage 1 protocol design frozen; Rust implementation pending.** "Frozen"
refers to the intended interface, not to shipped engine functionality. Versioning
of future changes follows §10.

This document specifies the target contract between the cryptanalysis engine and
any client; examples and guarantees below describe intended behavior, not current
Rust capabilities. It is deliberately independent of both the transport and the
implementation. It exists so that the TUI, the local web client (§8, Stage 2), the
test harness, and the future GPU backend (Stage 4) can all be built and replaced
without touching each other.

The stage vocabulary below (`Stage N`, "planned", "future", "unscheduled") names the
release intended to deliver a feature. It never implies shipped support: in this
repository the engine itself is still being built (see `odd/tasks/enigma-engine.md`).

---

## 1. Design principles

1. **Transport-agnostic.** The protocol defines *messages*, not a transport. Stage 1
   uses `stdin`/`stdout`. A local listener (§8, Stage 2) carries the same messages over
   HTTP. The TUI and the web client therefore share one protocol and differ only in
   plumbing.
2. **Superset of `bomm`.** Any query file that `bomm` accepts must be accepted here,
   unchanged, with the same meaning. Extension fields are version-gated (§10): request
   extensions require the protocol version that defines them, output extensions stay
   ignorable.
3. **Strict input, lenient output.** An unrecognised field in a *request* is a hard
   error (fail closed): silently ignoring a requested feature produces plausible but
   wrong cryptanalytic results, which is the worst possible failure. An unrecognised
   *event* or field in an event is ignored by clients, so new events and new event
   fields can be added without breaking older clients. This asymmetry is exactly why
   request and output versioning differ (§10).
4. **Deterministic and reproducible.** A run is fully described by its request. Two
   runs of the same request must produce the same enumeration order and the same
   scores, on any backend.
5. **Checkpoint-first.** Attacks take tens of hours. Progress, cancellation and resume
   are protocol features, not client features.

---

## 2. Transport

| Mode | Use | Enabled by | Stage |
| --- | --- | --- | --- |
| `stdio` (default) | TUI, scripts, tests | — | 1 |
| local listener | web client | `--listen 127.0.0.1:<port>` | 2 (planned) |

Rules:

- **`stdout` carries only the event stream**, one JSON object per line (JSONL), with no
  embedded newlines. Every diagnostic, warning and log message goes to `stderr`.
- The request is supplied as a file path argument, as `--request -` (read from `stdin`),
  or as the body of an HTTP POST in listener mode.

---

## 3. Job request (input)

The request is a single JSON object. Fields below marked **[bomm]** are exactly
`bomm`'s; fields marked **[+]** are additive extensions.

### Root

| Field | Type | Req | Notes |
| --- | --- | --- | --- |
| `ciphertext` | string | yes | **[bomm]** Letters of the alphabet only; spaces are stripped |
| `space` | object | yes | **[bomm]** §3.1 |
| `alphabet` | string | no | **[bomm]** Expected alphabet. **Changed:** validated against the *runtime* alphabet, not a compile-time constant |
| `passes` | array | no | **[bomm]** §3.2 |
| `wheels` | array | no | **[bomm]** Custom wheels: `{name, wiring, turnovers?}` |
| `measures` | object | no | **[bomm]** `{trie: {baseMeasure, trie}}` |
| `frequencies` | object | no | **[bomm]** File paths for `monogram`..`hexagram` Sinkov maps |
| `protocol_version` | integer | no | **[+]** Defaults to `1`. Only fields defined by the requested version are accepted; an unknown version is rejected (§10) |
| `job` | object | no | **[+]** Free-form metadata for client display: `{label?, notes?, source?}` |

### 3.1 `space`

| Field | Type | Notes |
| --- | --- | --- |
| `slots` | array | **required.** Physical order, **left to right**, including the reflector at index `0` and the entry wheel (if any) at the last index |
| `slots[].wheels` | string[] | required. Wheel names resolved from the built-in library or root `wheels` |
| `slots[].rotating` | bool | default `false` |
| `slots[].rings` | lettermask | default `"a"`. `"*"` selects the whole alphabet |
| `slots[].positions` | lettermask | default `"a"`. `"*"` selects the whole alphabet |
| `mechanism` | enum | **[bomm]** `stepping` \| `odometer` \| `none`; **[+]** `cog` (Stage 5, planned) |
| `plugboard` | string | **[bomm]** Fixed plug pairs, e.g. `"aberbfch"` |
| `plugs` | lettermask | **[bomm]** Which letters may be plugged |
| `offset` | integer | **[bomm]** Keys to skip at the start of the enumeration |
| `limit` | integer | **[bomm]** Maximum keys to enumerate (excluding `offset`) |
| `variants` | array | **[+]** §3.1.1; Stage 1 planned extension over the search space |

A *lettermask* is a set of letters drawn from the alphabet, or `"*"` for all of them.

#### 3.1.1 `variants` — multi-variant search **[+], Stage 1 planned extension**

For uncertain-machine cases (`bomm` requires running the query once per hypothesis —
see its `kr-blitz-*.json` set). `variants` is an array of alternative `slots`
definitions searched in a single run and ranked in one shared hold. It extends the
Stage 1 goal of describing the search space as data; it does not add a search
technique. Enumeration stays fully determined (§7.1), ordered variant-major, and every
`candidate` event carries the `variant` index that produced it:

```json
"space": {
  "variants": [
    { "slots": [ { "wheels": ["UKW-B"] }, { "wheels": ["I","II","III"], "rotating": true, "positions": "*" } ] },
    { "slots": [ { "wheels": ["B207-UKW"] }, { "wheels": ["B207-I","B207-II","B207-III"], "rotating": true, "positions": "*" } ] }
  ]
}
```

`space.slots` and `space.variants` are mutually exclusive. The second entry above is an
**illustrative Stage 5 exotic wheel set** (B207-style), shown only to fix the shape of
the field; it is not a claim of Stage 1 support for those wheels.

### 3.2 `passes`

The four **[bomm]** passes below exist in `bomm` and are targets for the Rust port.
**[+]** passes are additions to that baseline. None of these passes is implemented
in this Rust project yet; the stage labels describe the plan, not current support.
Stage 1 must cover all four `[bomm]` passes plus `partial_exhaustion`; the remaining
`[+]` passes belong to Stages 3 and 5.

| `type` | Fields | Baseline / Rust target |
| --- | --- | --- |
| `hill_climb` | **[bomm]** `measure`, `finalMeasure`, `finalMeasureMinNumPlugs`, `backtrackingMinNumPlugs` | `bomm` exists; Rust Stage 1 planned |
| `reswapping` | **[bomm]** `measure` | `bomm` exists; Rust Stage 1 planned |
| `trie` | **[bomm]** `baseMeasure`, `trie` | `bomm` exists; Rust Stage 1 planned |
| `measure` | **[bomm]** `measure` | `bomm` exists; Rust Stage 1 planned |
| `partial_exhaustion` | **[+]** `exhaustMeasure`, `exhaustDepth`, then `hill_climb` parameters | Rust Stage 1 planned |
| `simulated_annealing` | **[+]** `measure`, `temperature`, `cooling`, `seed` | Rust Stage 5 planned |
| `genetic` | **[+]** `measure`, `population`, `generations`, `seed` | Rust Stage 5 planned |
| `crib_attack` | **[+]** `crib`, `cribOffset`, `maxFalsestops` | Rust Stage 3 planned |

Once request handling is available, a pass unsupported by that release must be
**rejected** with `error.code = "unsupported_pass"`, never silently skipped. A pass
listed for a future stage is recognized by this design but unsupported until that stage
is activated; it is not an unknown request field.

### 3.3 `measure` enum

**[bomm]** `entropy`, `ic`, `sinkov_*` each in `monogram`..`hexagram`, plus `trie`.

**[+]** `chi_squared`, `chi_squared_bigram`, `chi_squared_trigram`,
`chi_squared_quadgram` — additive but **unscheduled**: they are not Stage 1 targets and
no stage is currently assigned to them.

---

## 4. Event stream (output)

Every line is one JSON object. Every event, without exception, carries these four
fields:

| Field | Type | Notes |
| --- | --- | --- |
| `event` | string | Event name |
| `protocol_version` | integer | Version of the stream. Present on every event, including a pre-validation `error` (§4.4) |
| `seq` | integer | Monotonic, starting at `1`. Clients can detect gaps and drops |
| `ts` | string | RFC 3339 UTC timestamp |

Field order inside an example is illustrative; JSON objects are unordered. The examples
below form one coherent happy-path run, followed by a rejected request.

### 4.1 Event catalogue

**`started`** — exactly once, and always first, unless the run never starts (§4.4).

```json
{"event":"started","seq":1,"ts":"2026-01-01T00:00:00Z","protocol_version":1,
 "job_id":"kr-blitz","alphabet":"abcdefghijklmnopqrstuvwxyz",
 "total_keys":27418560,"variants":1,"seed":null,
 "backend":{"kind":"cpu"},
 "resumed_from":null}
```

`variants` is the size of `space.variants` (`1` when `space.slots` is used). `seed` is
`null` unless a stochastic pass is used (§7.4). `backend` is informational only and
never carries thread counts, workgroup sizes or dispatch geometry (§11).

**`progress`** — rate-limited (default: at most one every 500 ms, `--progress-interval`).
It is never emitted per key, and the rate limit is part of the contract.

```json
{"event":"progress","seq":2,"ts":"2026-01-01T00:03:44Z","protocol_version":1,
 "keys_done":62500,"total_keys":27418560,
 "elapsed_ms":224100,"eta_ms":97800000,"rate_keys_per_s":278.9}
```

**`candidate`** — a key that entered the hold, emitted on *change* of the hold, never
per evaluation. The universal envelope is inlined with the candidate object's fields
(§4.2).

```json
{"event":"candidate","seq":3,"ts":"2026-01-01T00:04:00Z","protocol_version":1,
 "rank":1,"score":-8.702661,"variant":0,
 "settings":"UKW-B,III,IV,V aaaa aber bf ch dt in kv or ps qz wy",
 "wheels":["UKW-B","III","IV","V"],"positions":"aaaa","rings":"aaaa",
 "plugboard":"aberbfchdtinkvorpsqz",
 "plaintext":"tgenpjnrjdqubenahrbefohsamtjnenexsiesgalieldninsnptcqssenidfqxan"}
```

**`checkpoint`** — emitted when durable state is written (§6).

```json
{"event":"checkpoint","seq":4,"ts":"2026-01-01T00:59:50Z","protocol_version":1,
 "path":"kr-blitz.ckpt.json","keys_done":1048576,"state_digest":"sha256:…"}
```

**`hold`** — the full hold, emitted once on completion, cancellation and shutdown of a
run that emitted `started`. A pre-validation error has no hold (§4.4).

```json
{"event":"hold","seq":5,"ts":"2026-01-02T02:01:12Z","protocol_version":1,
 "entries":[ /* candidate objects, §4.2, best first */ ]}
```

**`done`** — exactly once, and always last, unless replaced by `error`.

```json
{"event":"done","seq":6,"ts":"2026-01-02T02:01:12Z","protocol_version":1,
 "reason":"completed","stats":{"keys_done":27418560,
 "elapsed_ms":93672000,"rate_keys_per_s":292.7},"best":{ /* candidate object, §4.2 */ }}
```

`reason` is one of `completed`, `cancelled`, `limit_reached`, `offset_end`.

**`error`** — terminal, and always last.

```json
{"event":"error","seq":1,"ts":"2026-01-01T00:00:00Z","protocol_version":1,
 "code":"unsupported_pass","message":"pass 'genetic' is declared but not implemented before Stage 5"}
```

`code` values: `invalid_request`, `unsupported_pass`, `unsupported_measure`,
`unsupported_mechanism`, `unknown_wheel`, `alphabet_mismatch`, `ciphertext_not_in_alphabet`,
`checkpoint_mismatch`, `internal`. Which of them may appear before `started` is defined
in §4.4.

### 4.2 Candidate object

A **candidate object** is the payload of a `candidate` event, an element of
`hold.entries`, or the `done.best` value. It carries the resolved key and has **no
universal envelope**: no `event`, `seq`, `ts` or `protocol_version`. In a `candidate`
event its fields are inlined next to the envelope, not nested.

| Field | Type | Notes |
| --- | --- | --- |
| `rank` | integer | 1-based within the hold |
| `score` | number | Final score under the pass `measure` |
| `variant` | integer | Index into `space.variants`; `0` when `space.slots` is used |
| `settings` | string | Human-readable rendering of the whole key |
| `wheels` | string[] | Wheel names, left to right |
| `positions` | string | Rotor positions, left to right |
| `rings` | string | Ring settings, left to right |
| `plugboard` | string | Plug pairs, canonicalised |
| `plaintext` | string | Text decrypted under this key |

### 4.3 Ordering guarantees

1. Exactly one `started`, first — except for a request rejected before computation
   (§4.4), which emits no `started` at all.
2. Exactly one terminal event (`done` or `error`), last.
3. `seq` strictly increases.
4. `candidate` events never appear before `started` or after the terminal event.
5. Zero or more `progress` and `checkpoint` events in between.

### 4.4 Pre-validation errors

An `error` may terminate a run before `started` exists. That happens exactly when the
request is rejected during validation, before any key is enumerated:

`invalid_request`, `alphabet_mismatch`, `ciphertext_not_in_alphabet`,
`unsupported_pass`, `unsupported_measure`, `unsupported_mechanism`, `unknown_wheel`,
`checkpoint_mismatch`.

Such an `error` is the whole stream: `seq` is `1`, no `started` precedes it, and it
carries the engine's own `protocol_version` (§4, §10) because the requested version may
be unknown. Every other failure is reported as `internal` after `started`.

---

## 5. Control

| Action | Mechanism | Result |
| --- | --- | --- |
| Cancel | POSIX `SIGINT`/`SIGTERM`, Windows console Ctrl+C, or `--cancel-file <path>` | For a started run, emit `hold`, write a final checkpoint, emit `done` with `reason: "cancelled"`, exit `0` |
| Pause / resume a live job | not in Stage 1 | future extension |
| Resume a dead job | `--resume <checkpoint>` | §6 |
| Bound a run | `space.offset`, `space.limit`, `--max-keys` | Terminal `done` with `reason: "limit_reached"` or `"offset_end"` |

Cancellation is **cooperative and bounded**: the engine must observe it within one
progress interval and must never lose the hold. The three mechanisms below are
equivalent and always produce the same terminal sequence.

- **POSIX** (`SIGINT`, `SIGTERM`): delivered by the OS.
- **Windows**: Windows has no `SIGTERM`. Stage 1 handles console `Ctrl+C` (the Windows
  `SIGINT`); there is no SIGTERM equivalent on that platform.
- **`--cancel-file <path>`** — portable control for every platform, including scripts
  and tests: the engine polls for the file once per `--progress-interval` and cancels
  when it appears. Use it when no console signal is available; it is the only control
  that behaves identically on Linux, macOS and Windows.

---

## 6. Checkpoint and resume

A started run writes checkpoints to `--checkpoint <path>` at
`--checkpoint-interval` (default 300 s) and writes a final checkpoint on a normal
terminal `done` (including completion, cancellation, and bounded-run endings). On an
`internal` error after `started`, writing a final checkpoint is best-effort and only
applies when the current state and cursor can be serialized meaningfully. A
pre-validation error before `started` never writes a checkpoint: no run state or cursor
exists.

```json
{
  "protocol_version": 1,
  "request_digest": "sha256:…",
  "state_digest": "sha256:…",
  "keys_done": 1048576,
  "elapsed_ms": 3590000,
  "cursor": { "variant": 0, "slot_indices": [0, 3, 1, 7], "plugboard": "aberbf" },
  "hold": [ /* candidate objects, best first */ ],
  "rng": { "seed": 12345, "state": "…" }
}
```

Resume semantics:

- `request_digest` is the SHA-256 of the canonicalised request. A resume whose digest
  does not match the current request is rejected with `checkpoint_mismatch`. **A
  checkpoint may never be applied to a different job.**
- The engine resumes from `cursor`, not by re-deriving progress, so `keys_done` is exact
  and the hold is preserved.
- `rng` is present only when a stochastic pass is used; without it, resume is not
  reproducible and must be rejected.
- A resumed run emits `started` with `resumed_from` set to the checkpoint path.

---

## 7. Determinism rules

These are contract obligations, not implementation advice. The GPU backend (Stage 4)
must satisfy them identically to the CPU backend.

1. **Enumeration order is fully determined** by the `space` definition. `offset` and
   `limit` address that order.
2. **Scoring uses integer or fixed-point arithmetic** wherever a float would introduce
   backend-dependent rounding. Where floating point is unavoidable, the result must be
   bit-identical across backends; otherwise the measure is not admissible.
3. **No unordered reductions** may affect a score. Atomic accumulation into a shared
   score is forbidden; per-candidate scores are computed independently.
4. **Every stochastic pass records its seed** in `started` and in the checkpoint
   (`started.seed` is `null` when no stochastic pass is used).
5. **The hold is totally ordered** by `(score desc, enumeration index asc)`, so ties are
   broken deterministically.

Any deviation is a bug, not a variation.

---

## 8. Local listener (web client) — Stage 2 (planned)

Not part of Stage 1. Required so the browser client never needs compute privileges of
its own.

- Binds **`127.0.0.1` only.** Binding `0.0.0.0` is forbidden: the engine has no
  authentication beyond the token below and must never be reachable from the network.
- Requires a bearer token, generated per run and printed once to `stderr`.
- Validates the `Origin` header against an allow-list. A page on the open internet must
  not be able to drive a local engine.
- Endpoints mirror the protocol exactly: `POST /jobs` (request → `202` + `job_id`),
  `GET /jobs/{id}/events` (the event stream as JSONL, or as SSE), `POST /jobs/{id}/cancel`.

---

## 9. Compatibility with `bomm`

Every row is a **target** for Stage 1, not shipped behavior; the table compares intended
contracts only.

| `bomm` behaviour | This protocol (target) |
| --- | --- |
| Query JSON file as the only argument | Identical, plus `--request -`; the listener (§8) is Stage 2 |
| ANSI TUI on `stdout`, live-updating | Replaced by the JSONL event stream on `stdout` |
| Full hold printed on completion and on `SIGINT`/`SIGTERM` | Preserved, as the `hold` event; cancellation accepts POSIX `SIGINT`/`SIGTERM`, Windows Ctrl+C, and `--cancel-file` everywhere (§5) |
| Alphabet fixed at compile time | Runtime `alphabet` field |
| `mechanism`: `stepping`, `odometer`, `none` | Preserved; `cog` is a Stage 5 addition |
| `passes`: `hill_climb`, `reswapping`, `trie`, `measure` | Preserved; `partial_exhaustion` in Stage 1, further passes later (§3.2) |
| Measures: `entropy`, `ic`, `sinkov_*`, `trie` | Preserved; `chi_squared_*` is additive but unscheduled (§3.3) |
| 29-wheel library, custom wheels by JSON | Preserved; exotic wheel sets (e.g. B207-style) are Stage 5 |
| No resume | `--resume` |
| Single hypothesis per run | `space.variants` (Stage 1 planned extension, §3.1.1) |

**Verification obligation:** `bomm`'s own `data/queries/*.json` must parse and run
unchanged, producing the same key, the same plaintext and the same score. This is
task 12 and it is the primary correctness gate for the whole port.

---

## 10. Versioning

`protocol_version` is an integer, currently `1`. It versions the **request** contract;
event output is versioned only in the sense that older clients ignore what they do not
know.

1. **Design status.** "Frozen" means the interface in this document is agreed; it does
   not mean shipped. Implementation status lives in `odd/tasks/enigma-engine.md`.
2. **Version 1 activates Stage 1 request features only.** Fields and enum members marked
   for later stages in §3 are reserved in this design, not accepted as active v1
   features. A known but inactive future-stage pass is rejected with
   `unsupported_pass`; the corresponding mechanism or measure is rejected with
   `unsupported_mechanism` or `unsupported_measure`. Truly unrecognized request fields
   remain hard errors (§1.3).
3. **Output-compatible additions do not bump the version.** New event types and new
   event fields are ignored by clients (§1.3), so they may ship without negotiation.
4. **Activating future request features after v1 ships requires version negotiation or
   a version bump.** Adding a request field or a new member to a request enum
   (`passes[].type`, `mechanism`, `measure`) is compatible only for clients that request
   a version defining it, unless it is explicitly negotiated. This applies to the
   Stage 3/5 pass entries and the Stage 5 `cog` mechanism in §3; `chi_squared*` measures
   follow the same rule if they are scheduled and activated. `space.variants` is a
   Stage 1 feature and is part of the v1 request design.
5. **Breaking changes bump the version:** removing or changing the meaning of an
   existing field, changing ordering guarantees, or changing the determinism rules.
6. A client requesting an unsupported `protocol_version` receives `invalid_request`
   before any computation begins, i.e. with no `started` (§4.4).

---

## 11. Constraints inherited from the GPU backend (Stage 4)

Recorded now so the protocol does not have to be rewritten later:

1. `progress` must be expressible in terms of **completed work units**, not loop
   iterations, because a GPU evaluates candidates in batched dispatches.
2. `cursor` must identify a resumable position **without depending on a CPU loop
   counter** — hence the structured `cursor` object rather than a single integer.
3. Scores must be computed **per candidate independently** (§7.3), because a GPU cannot
   maintain a global running score without non-determinism.
4. The contract does not expose thread counts, workgroup sizes or dispatch geometry.
   `backend` is **informational only**; clients must not branch on it.
