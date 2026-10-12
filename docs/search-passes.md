# Plugboard attack contract — Task 11

Status: **Core HC execution and Core/CLI attack validation are supported; public PE and CLI execution remain deferred.**
Task 11.2a provides only `AttackPlugboardDomain::parse_json`: strict typed fragment
validation with immutable known fixed pairs. It is separate from legacy search
spaces and grants neither complete request acceptance nor candidate enumeration.
Task 11.2b adds isolated `AttackSettings::parse_json` validation for common
settings, exact declared objectives and direct hill-climb starts, bound to the
domain's ordered alphabet, plus typed partial-exhaustion `empty_single` all/touching
seed policies. Task 11.2c adds `AttackGate::check` over a borrowed resource-bound
`SearchRequest` and explicit typed domain/settings. It rechecks compatibility and
returns privately constructed full/sliced outer and per-outer start counts, not an
executable request or evaluation reservation. Counts do not truncate to the budget.
Task 11.2d.5 exposes `ParsedAttackRequest::parse_json` and supplied-content binding,
plus resource-free `AttackRequest::parse_json`. Both promotion routes check eligibility
before returning privately owned inputs, retained models and counts. Owned result
carriers and the HC facade are exposed; raw candidate APIs remain private. Public root dispatch selects this owner only when
`job.space.plugboard.kind` is `"attack"`, with wire kind still `"search"`.
The CLI loads resources once, binds and checks eligibility, then emits one seq1
`unsupported_job` error at `/job/kind` (`attack execution is not implemented`),
without work events. CLI execution remains unsupported; Core HC uses §6.2.
Task 11.4a adds private budget-aware complete-neighborhood best-improvement selection only.
Task 11.4b.1 adds a private bound scoring lifecycle: start-phase selection, shared final-score
reservation, committed-board objective switching and once-only finalization, without an ascent loop.
Task 11.4b.2 adds a private single-climb driver repeating complete strict-improvement scans,
with final-scored committed outcomes on completion or budget interruption. Interrupted scans
never commit provisional winners; final rescoring alone does not count as final-objective ascent.
Task 11.5a adds private lazy empty/single mutable seed generation with dense local indices.
Task 11.5b adds private ordered independent known-scrambler seed climbs with one shared
allowance and stable final-score selection, including interrupted committed boards.
Task 11.6a adds private lazy outer-candidate projection with absolute `u128` indices,
resolved slot assignments and fixed plugboard facts, preserving indexed resolution errors.
Task 11.6b.1 binds one internally supplied resolved outer/index to the owner's direct-HC
settings and retained resources, returning owned initial facts, committed outcome and shared
usage, or an indexed original evaluation error. Partial exhaustion is rejected before work.
Task 11.6b.2 privately schedules same-owner ordered direct-HC outers with one allowance,
checked counters, stable final-score best ownership and independent aggregate termination.
Original indexed resolution/evaluation errors retain cumulative usage; PE remains rejected.
Task 11.6c.1 binds one internally supplied resolved outer/index to retained PE settings and
resources, preserving independent seed outcomes, winner flags, run counts and cumulative
usage or the indexed original evaluator error. Task 11.6c.2 privately schedules ordered
same-owner PE outers with one allowance, checked aggregate counts and stable committed
final-score best ownership. Whole seed-run completion stays independent of winner flags;
original indexed resolution/evaluation errors retain cumulative usage.
Private HC/PE aggregates and the public Core HC facade are implemented;
public PE, full wire results and CLI execution remain deferred.

For this settings fragment, malformed raw JSON (including duplicate keys, trailing
input and nonobjects), missing fields and invalid kind/objectives/budget use
`invalid_request`; unknown fields use `unknown_field` with escaped JSON Pointers.
Known branch-forbidden members and malformed policy shape/kind/selection use
`invalid_request`; malformed touching masks use `invalid_search_space` at the
field or offending index, including duplicates. Missing touching masks use
`invalid_request`. Unknown members are checked against both branch keys before
kind/conditional checks.
Malformed thresholds/starts use `invalid_search_space` at the offending field or
index. The 4 MiB raw-byte ceiling and incompatible ordered alphabets use
`invalid_request` at `/job/attack`. Raw validation precedes alphabet compatibility,
then exact-field and required/type checks. These fragment-local choices do not
change existing root/domain diagnostic policies.
Task 11 first validates a known scrambler with unknown plugboard, then nests the
same attack inside outer scrambler enumeration. Current CLI search only validates,
loads and binds resources, then returns `unsupported_job`. Private HC/PE drivers
and outer schedulers are implemented; Core HC is public, but CLI execution is unsupported.
[Protocol](protocol.md) and [scoring/resources](scoring-resources.md) remain normative.
This document specifies `hill_climb` and `partial_exhaustion`, plus the future private
control contract in §6.1 and public HC adapter in §6.2;
[protocol §4.1](protocol.md#41-planned-hcpe-search-events--task-127) defines first-release
lifecycle/results/progress. That wire contract does not enable CLI execution. Checkpoints, other
passes and variants remain separate work.

## 1. Two domain branches, no implicit unknown key

Retain the existing `space.plugboard = {candidates, size}` branch exactly:
a pre-disjoint pool, positive fixed subset size, published combination order and
coverage rules. It is structurally valid legacy search, **not a Task 11 attack
domain**. Task 11 execution rejects that branch with `unsupported_pass`; it never
reinterprets pool pairs as overlapping seeds or changes their enumeration.

The additive Task 11 branch is exactly:

```text
space.plugboard := {"kind":"attack", "symbols":[SYMBOL,...], "max_pairs":INTEGER}
```

| Field | Strict requirement |
| --- | --- |
| `kind` | Literal `"attack"`; required discriminator |
| `symbols` | Nonempty unique array of single runtime-alphabet scalars |
| `max_pairs` | Required nonnegative integer; maximum **total** board pairs |

All objects reject unknown and duplicate keys at every depth. The two branches
are exclusive: `candidates`/`size` cannot coexist with attack fields. No aliases,
normalization, wildcard, omitted unknown domain, or inferred key defaults exist.
Integer fields reject fractional values, negatives and values outside their stated
bounds; budget is unsigned 64-bit, outer offsets/limits retain existing types.

`configuration.plugboard` remains required fixed knowledge. Its disjoint pairs
are immutable throughout every climb, not mutable initial guesses. `symbols`
is the complete mutable endpoint universe: both endpoints of every mutable pair
must belong to it. It must exclude every fixed-pair endpoint. Alphabet symbols
outside fixed endpoints and `symbols` are explicitly self-connected, not unknown.
Unpaired symbols inside `symbols` are mutable free endpoints. Pair capacity is
`C = floor(alphabet_length / 2)`; require fixed_pair_count <= max_pairs <= C.
Also require max_pairs <= fixed_pair_count + floor(symbols.len() / 2).
Zero is valid only with no fixed pairs; it explicitly permits only the empty board.

An absent `space.plugboard` still means a complete fixed board, including fixed
empty `[]`, never an unconstrained unknown board. Task 11 requires the attack
branch even when its only permissible remainder is empty. Fixed configuration,
seed and every trial board must satisfy the existing definition/resolver
plugboard admissibility (currently alphabet membership and disjoint symmetry).
No new definition fields or historical ten-pair constraint are introduced.
All slot coverage and fixed/variable conflicts retain protocol §3.2–3.3 rules.

## 2. One executable pass and explicit settings

`job.passes` retains its array of unique identifier strings. Task 11 execution
requires exactly one identifier, `hill_climb` or `partial_exhaustion`. Add required
`job.attack` **only for this attack branch**, with the following strict fields:

| Field | Type and meaning |
| --- | --- |
| `kind` | String exactly equal to the sole selected pass |
| `initial_measure` | Declared `job.measures` identifier |
| `final_measure` | Declared `job.measures` identifier |
| `switch_pairs` | Integer in [0, C], total board cardinality threshold |
| `backtrack_pairs` | Integer in [0, C], total board cardinality threshold |
| `evaluation_budget` | Positive unsigned 64-bit integer, whole request run |
| `start` | Required only for direct `hill_climb`; array of mutable pairs |
| `seeds` | Required only for `partial_exhaustion`; strict object below |

All listed common fields are mandatory. No heuristic defaults: reference
floor(N × .3)/floor(N × .2) gives 7/5 for 26 symbols, but users choose thresholds
explicitly. Thresholds may exceed `max_pairs`: switching then may never occur;
backtracking then may remain unavailable. No ordering relation between thresholds
is required. Equal initial/final measures are valid (no objective change needed).
`start` and `seeds` are mutually exclusive, including empty/unused members.

`start` uses existing two-symbol pair syntax, but contains guesses, not facts.
It must be disjoint internally and from known endpoints, use only mutable symbols,
and fit `max_pairs` after union with fixed pairs. Repeating a fixed pair is a
conflict, not deduplication. `start: []` explicitly starts with known pairs only.
Malformed starts/domains/thresholds use `invalid_search_space` at the offending
path; unknown keys use `unknown_field`. Missing/mismatched attack settings are
`invalid_request`. Recognized but deferred `reswapping`, `trie`, and `measure`
remain structurally recognized, but are `unsupported_pass` for Task 11 execution.
Mixed passes likewise fail before work; no cross-pass hold/objective state exists.
Legacy structural requests without `attack` keep their existing parsing meaning.

Both objectives use already declared and retained Task 10 scorers. All selected
measures, including those not used as objectives, must satisfy existing minimum
text lengths and resource binding rules before execution. No model rereads, score
sum, implicit trie base score, or new smoothing is introduced. Compare checked
Q32 **ranking** values, maximizing them; entropy uses negative measured entropy.
Initial and final raw scores are not directly compared across different measures.
Unused *resource references* remain invalid; non-objective declared measures are
allowed, but Task 11 need not evaluate them for its internal result.

## 3. Pre-execution gates and outer order

Before the first evaluation, validate strict syntax, full coverage, starts/seeds,
all topology and scoring/resource compatibility, integer/count bounds and budget.
Task 11 supports decrypting any topology already resolvable by the universal
engine under its existing resource limits: one or more rotors, optional leftmost
reflector, fixed/movable slots and validated declarative stepping. There is **no
global reflector requirement**. Unsupported concrete combinations fail early,
never get silently skipped. Search always decrypts `job.text`; no search
`direction` field is added. No-reflector decrypt uses the engine's inverse path.

If a supported existing domain reports `candidate_count() == None`, return
`resource_limit` before execution, even with a small offset/limit. Never execute
`candidate.rs`'s overflow placeholder radix as if it were a real subset. Task 11
does not repair unrelated >u128 enumeration. Attack outer products must likewise
have checked representable u128 counts; seed and evaluation counters are checked.

For the attack branch, the outer tuple contains only slot dimensions. Retain
**definition slot order; wheel, position, ring within each slot; later dimensions
fastest**, with domain-array order preserved. Do not adopt bomm's global nesting.
All fixed slot choices yield one outer candidate (index 0). `space.offset` and
`space.limit` slice outer candidates, not seeds, neighbors, score calls or climbs.
Outer indices are absolute unsliced indices. Each selected outer candidate runs
all seeds in order before advancing the outer tuple, unless budget ends the run.
Legacy subset indices/order remain unchanged in their own branch.

An empty outer slice returns no best candidate with termination `outer_slice_end`.
Otherwise normal exhaustion of the requested slice is `completed`; completion is
only of that slice, never a claim of all mathematical plugboards being exhausted.
Execution is sequential in this contract; parallelism must preserve identical
budget allocation and result order if separately introduced.

## 4. Empty and single-pair seed exhaustion

`seeds` is exactly one of these strict objects:

```text
{"kind":"empty_single", "selection":"all"}
{"kind":"empty_single", "selection":"touching", "symbols":[SYMBOL,...]}
```

`all` forbids `symbols`. `touching` requires a nonempty unique subset of attack
mutable symbols. This explicit mask can select any runtime symbol; “E-Stecker”
means a user-selected singleton mask, never a hardcoded Latin E assumption.

Seed 0 is always the empty mutable remainder, merged with fixed pairs. Subsequent
seeds are every unordered free-symbol pair `(a,b)` with alphabet_index(a) <
alphabet_index(b), lexicographically by those indices. For `touching`, retain
pairs with at least one endpoint in the mask. Each pair appears once even when
both endpoints are masked. Occupied fixed endpoints are excluded by the domain
validation; seeds exceeding `max_pairs` are filtered before assigning indices.
Thus if fixed pairs already reach the cap, only seed 0 exists. Indices are dense
and local to each outer candidate. No duet, quartet, recursive generation, or DFS.

Each seed invokes exactly the same hill routine independently. Restore fixed
knowledge, selected seed, initial objective phase and initial machine positions;
never carry a previous climb's board or stepped state into the next seed. Two
seeds may converge to the same result; do not deduplicate climbs or redistribute
budget. Direct hill climb instead uses its explicit `start`, with start index 0.

## 5. Deterministic constrained neighborhood

Let P be the **current committed** board. Enumerate unordered alphabet pairs
`(a,b)` in increasing alphabet-index lexicographic order. For each pair use the
following action order, with c=P(a), d=P(b) where relevant. Other connections stay
unchanged. Removed endpoints become free unless paired again in that action.

| Current case | Ordered resulting replacements |
| --- | --- |
| Both free | Add (a,b) |
| Paired to each other | Remove (a,b) |
| One free f, other x paired to y | Remove (x,y); add (f,x), then separately add (f,y) |
| Distinct pairs (a,c), (b,d) | Remove both; add (a,b); add (a,b)+(c,d); add (a,d); add (a,d)+(c,b) |

The one-free orientation always uses f as the free letter, independent of which
of a/b it is. The last row describes four independent trials, not incremental
commits. This is the reference's four-case action order. Trials that reproduce
another pair/action's board are evaluated again in order (no undocumented pruning).

Filter an action if any removed/added endpoint touches a fixed known pair, if
any added pair leaves the mutable domain, if the resulting board violates
admissibility/capacity, or if it is unchanged. Below `backtrack_pairs` allow only
the both-free add case; at/above it allow all four cases subject to constraints.
This gate is recomputed from actual current cardinality at each iteration.

Evaluate every legal action from the same P and scrambler initial state. Restore
P and machine state after **each** trial, including failures. Select the greatest
strict ranking improvement over the current objective score; equal winners retain
the first pair/action. Apply one winner only after the entire legal neighborhood
has been evaluated. No plateau move, random restart, worsening move, first
improvement, recursive depth or undocumented pruning is permitted.

## 6. Adaptive hill routine and bounded evaluations

At climb start, actual pair count includes fixed plus seed/start pairs. Use final
objective immediately if count >= `switch_pairs`; otherwise use initial objective.
After each committed move reaching the threshold, switch permanently to final
objective and remeasure the **current** board before the next neighborhood.
Do not switch back if later removals reduce count. Backtracking availability,
unlike the objective phase, continues to track actual current count.

If a complete neighborhood has no strict improvement, finish the ascent. When
it ends before switching, score its current board under `final_measure`, but do
not restart ascent or claim final-objective local optimality. With identical
objectives the existing current score suffices; no redundant switch measurement.
With threshold 0 final optimization begins at start. A neighborhood with no legal
moves is complete without evaluations.

One evaluation is one fresh full-message decryption plus **one** objective score.
Count initial scores, every legal trial (including repeated boards), objective
remeasurements and final rescoring. Cached plaintext/score must not evade counts.
Filtering invalid actions, resolving candidates and comparing scores cost zero
budget evaluations. All calls share the one request budget; no per-seed reset.
Fresh engine state means initial outer positions, before the first keypress;
precomputation is permitted only if equivalent to this decrypt-and-score result.

Reserve one evaluation for final rescoring whenever the current committed board
has no known final score and objectives differ. Before starting a climb require
its initial score plus that reserve; otherwise stop without starting that climb.
Before each trial or objective switch, require its cost plus any still-needed
reserve. Switching consumes the reserve to establish the final score. At budget
stop, use the reserved call to final-score the committed board; never report an
unscored board as a competitive winner. If a final score already exists, no
reserve is needed. Counts include the reserved call when actually performed.

If budget prevents finishing a neighborhood, discard its provisional winner,
leave P committed unchanged, and terminate the run as `evaluation_budget`.
Trial scores from that incomplete neighborhood are not eligible result boards.
Never apply a partial best-neighborhood winner as “best improvement”. If a
complete neighborhood can commit its winner but the next required operation
cannot fit, retain that committed board and terminate with its final score.
A zero-cost completion takes precedence over budget termination when there is
no remaining work (including an empty legal neighborhood). No evaluation beyond
the budget or timeout heuristic is specified; cancellation is governed by §6.1 and
planned public events by [protocol §4.1](protocol.md#41-planned-hcpe-search-events--task-127).

### 6.1 Private progress and cancellation — Task 12

**Private HC and PE control integration is implemented through Task 12.5.**
Single climbs, HC outer scheduling, PE seeds/resolved owners and PE outer scheduling
share checked accounting, counter snapshots and cooperative cancellation.
Budget-only callers retain Task 11 behavior; §6.2 exposes only the controlled HC path.
Public PE execution, JSONL events, timed progress, platform signals and
control files, hold and checkpoint cadence remain unimplemented. Checkpoint/resume
belongs to Task 16; Task 12 remains in progress at private documentary acceptance.

#### Accounting and completion

Private immutable snapshots carry checked counters for the shared whole run:

| Counter | Type | Increment condition |
| --- | --- | --- |
| `evaluations_admitted` | `u64` | Admission consumes allowance before evaluation |
| `evaluations_completed` | `u64` | Full decryption and objective scoring both succeed |
| `climbs_started` | `u128` | Initial evaluation succeeds |
| `climbs_completed` | `u128` | Normal neighborhood exhaustion and required final score succeed |
| `outers_completed` | `u128` | All climbs for that outer complete |

Existing `evaluations_used` records charged allowance, not completed work.
Allowance is charged before the checked `evaluations_admitted` increment; on rare
counter overflow, used may exceed admitted. Preserve both factual values, without
refunds or fabricated increments.
Initial, trial, objective-switch and final evaluations all follow these rules.
Failed evaluations remain admitted but not completed; there are no refunds.
Reservations protect required final scoring; only an actually admitted call is charged.
Cancelled or budget-interrupted climbs and their unfinished outers are not completed.
Before initial success there is no current climb result; retain any earlier aggregate.

#### Sticky safe-stop and committed results

Cancellation observation is sticky. Poll before the next climb or outer, before
trial admission, and after evaluation before the next trial or scan-winner commit.
Once observed, abandon any unfinished scan and its provisional winner; preserve
only the previously committed board. No optimization follows observation: no new
trial, winner commit, objective-switch ascent or next climb/outer may begin.

The sole evaluation exception is one already-required, reserved, charged final-
objective rescore of that committed board, only if its final score is absent.
If a final score already exists, reuse it without evaluation. This exception retains
an eligible valid result, never promotes a provisional winner or resumes ascent.
Failure of this final rescore remains an error, not a cancelled result.

Each admitted full-message decryption plus score is cooperative and nonpreemptible;
it may finish before cancellation is observed. There is no immediate-interruption,
wall-clock bound or compliance claim for the public progress interval.

#### Stop precedence and determinism

An encountered evaluation, resolution or invariant error remains an error;
cancellation must not mask it or erase charged usage. Already-established zero-cost
or natural exhaustion remains complete (an empty outer slice is `outer_slice_end`).
When work remains, cancellation precedes budget termination. Do not perform an extra
evaluation to probe exhaustion, and do not cancel retroactively after completion.

Preserve deterministic pair/action and outer/seed tie order, immutable fixed pairs,
and final-score eligibility. Winning-result flags (final-objective ascent and fully
exhausted neighborhood) remain distinct from the whole-run stop reason; neither
final rescoring nor an earlier completed winner makes a cancelled run complete.

#### Counter-only observation boundary

The implemented private observer is synchronous and infallible and receives immutable
counters only: at entry, after successful evaluations, at accounting transitions,
and at terminal success, cancellation or error. Duplicate snapshots are allowed.
No callback runs mid-evaluation; cancellation polling is independent of observer
cadence. Error snapshots retain admitted usage and only successful completions.

This boundary decides no clock, rate, I/O, hold capacity or candidate payload.
Future public-adapter coalescing is separate work, not an observer cadence promise.
[Protocol control](protocol.md#5-control) retains its public obligations; Task 16
still owns checkpoint/resume design and implementation.

### 6.2 Public Core HC API — Task 12.8

**`AttackRequest::run` executes HC on an already validated, resource-bound owner.**
Owned `AttackProgress`, `AttackResult`, `AttackBest`, `AttackTermination` and
`AttackRunError`/`AttackRunSource` expose factual counters, committed winners and
original causes. Malformed accepted best projections return explicit errors,
never silently become null; success-projection failures retain terminal counters
and usage with an invariant cause and the concrete failure through `best()`.
CLI and public PE execution remain deferred. The synchronous facade is:

```rust,ignore
fn run(&self, observe: impl FnMut(AttackProgress),
       cancel_requested: impl FnMut() -> bool)
    -> Result<AttackResult, AttackRunError>;
```

Each invocation creates fresh whole-run control/allowance and reuses the controlled
same-owner lazy HC scheduler with absolute outer indices. It never rereads resources
or accepts caller-supplied raw outer candidates. Valid PE rejects before enumeration,
evaluation, observation or cancellation polling: `UnsupportedExecution`, no indices,
zero charged usage and all counters zero, with best `Ok(None)`.
Callbacks are synchronous; observation is infallible and counter-only, cancellation
is polled separately and latched. Repeated runs start fresh. No public exports of
private schedulers, allowances, seed cursors or evaluator/control types are needed.
CLI/resource preflight still completes before `started`; Core parsing stays pure.

| Public type | Owned projection / boundary |
| --- | --- |
| `AttackProgress` | Five typed factual counters from §6.1; u64 evaluation counts, u128 climb/outer counts; no clock or candidate |
| `AttackResult` | `AttackTermination`, final `AttackProgress`, optional `AttackBest` |
| `AttackBest` | Complete initial winning key plus separate mutable remainder, plaintext, final `MeasuredScore` and `MeasureId`, u128 outer/start indices, three independent boolean flags |
| `AttackRunError` | Original owned source, optional outer/start indices, cumulative charged usage, final progress, fallible optional earlier aggregate best |

`AttackBest` projects direct `DirectOuterOutcome` without retaining trial boards;
PE `SeedBest` projection remains future work. Its key combines resolved slot facts with fixed plus winning mutable
pairs; never report the owner's initial fixed-only board as the winning complete key.
Flags are `incomplete`, `final_objective_ascent`, `neighborhood_exhausted`; direct
HC interruption derives from its cancellation/budget flags, PE from its seed winner.
No ascent is implied merely by final scoring. Tie order and eligibility remain §3–6.
The controlled-direct private error already owns the earlier accepted aggregate best,
source, outer index, charged usage and terminal snapshot. Its public projection keeps
those facts; resolution and missing-outer failures have no start index, while known
direct-climb failures use start0, never the earlier winner's index. Failed-outer
provisional boards are not eligible. `AttackRunError::best()` returns `Ok(None)` for
absence or an owned projection error by reference for malformed retained best. This
separate fallible channel preserves the original runtime cause and all accounting
instead of silently dropping a malformed winner or replacing the runtime failure.
Original evaluation/counter/resolution sources are wrapped in an owned
`AttackRunSource`; raw scheduler error types stay private. The HC-only facade
returns `UnsupportedExecution` for valid PE until12.9: an API availability error,
not an evaluation/invariant failure. Rejection precedes enumeration, evaluation,
cancellation polling and observation, with absent indices, zero usage/counters
and best `Ok(None)`.
Reconcile this temporary category with the eventual HC/PE source taxonomy at12.9.
Preserve nested source access and diagnostics,
not just a formatted string or sentinel result. Result/best/progress/error fields use
the wire names in protocol §4.1; Core replaces `elapsed_ms` with transport ownership,
Q32 strings with `FixedScore` values and null with `Option`. `AttackTermination`
variants are `Completed`, `OuterSliceEnd`, `EvaluationBudget`, `Cancelled`.

`completed`, `outer_slice_end`, `evaluation_budget`, `cancelled` have exactly the
[wire stop meanings](protocol.md#41-planned-hcpe-search-events--task-127). The public
HC facade uses the controlled HC path; public PE execution remains deferred.
No current-climb result exists before initial success; a failed final rescore cannot
make that board eligible. Errors dominate cancellation and preserve charged usage.
The transport adds clock/coalescing and exact decimal-string encoding; Core keeps
u64/u128/i128 values and Q32 units. Transport failures latch cancellation without
turning the infallible observer into a fallible evaluator or hiding a runtime error.

First-release JSONL is `started`, optional `progress`, final `result`, then `done`
or runtime `error`; validation errors remain seq1-only. Holds remain an eventual
Stage 1 requirement, deferred from this release; no candidate/hold/checkpoint event
is promised. Task16 owns checkpoint/resume. File and POSIX/Windows adapters are
separately unstarted under [protocol control](protocol.md#5-control); none is shipped.

## 7. Minimal core result, examples and limits

The budget-only internal run result contains termination (`completed`, `outer_slice_end`,
or `evaluation_budget`); controlled HC/PE also supports `cancelled`. It carries
evaluations used, outer candidates completed, climbs started
and completed, and an optional best committed board with resolved initial slot
key, plaintext, final measured/ranking score, absolute outer index and seed/start
index. A climb interrupted by budget is not completed. An outer candidate is
completed only after all its climbs finish. Eligible final-scored committed boards
include the interrupted climb's board, marked incomplete; ties select lowest
(outer index, seed/start index). No hold capacity is defined; the planned public
projection is §6.2 and protocol §4.1.
Per-climb outcome records whether final-objective ascent occurred and whether its
legal neighborhood was fully exhausted; final rescoring alone is not optimization.
Runtime scoring/invariant errors fail explicitly, not as a termination or sentinel.

These are **valid planned search-job fragments**, completed by protocol root
`protocol_version: 1` and bundled `machine.definition` for `enigma-i`. They are
not known-answer vectors. Direct Core attack parsing, binding and eligibility checks
validate them. Safe public root Core/CLI validation and private execution are
implemented; public HC runs in Core only, while public PE and CLI execution remain deferred.

```json
{
  "kind": "search",
  "configuration": {"slots": [
    {"id":"reflector","wheel":"B","position":"A","ring":"A"},
    {"id":"left","wheel":"I","position":"A","ring":"A"},
    {"id":"middle","wheel":"II","position":"A","ring":"A"},
    {"id":"right","wheel":"III","position":"A","ring":"A"}
  ], "plugboard": [["A","B"]]},
  "text": "ABCDABCD", "measures": ["ic","entropy"],
  "space": {"plugboard": {"kind":"attack","symbols":["C","D","E","F"],"max_pairs":3}},
  "passes": ["partial_exhaustion"],
  "attack": {"kind":"partial_exhaustion","initial_measure":"ic","final_measure":"entropy",
    "switch_pairs":2,"backtrack_pairs":1,"evaluation_budget":1000,
    "seeds":{"kind":"empty_single","selection":"touching","symbols":["E"]}}
}
```

The seeds are `[]`, CE, DE, EF; AB stays fixed. For direct hill climb, replace
`passes` with `["hill_climb"]`, set `attack.kind` to `"hill_climb"`, and replace
`seeds` with `"start":[["C","E"]]`; all other fields are unchanged and valid.
For outer search, remove the right slot's fixed `position` and add
`space.slots: [{"id":"right","positions":["A","B"]}]`: indices 0/1 select A/B,
with the same local seed sequence for each, subject to the shared budget.

## 8. Reference basis and deliberate departures

- Friederes, *Breaking Enigma Ciphertext in 2023*, [published PDF](https://cdn.ciphereditor.com/archive/2023/breaking-enigma-ciphertext-in-2023.pdf):
  §4.3 printed pp22–23 = PDF pp24–25 (four neighborhoods); §4.4 printed pp24–26
  = PDF pp26–28 (outer scrambler, best improvement, seeds and adaptive scoring).
  Printed body page numbers are PDF page numbers minus two, not interchangeable.
- Pinned bomm [hill_climb.c, lines 36–103](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/passes/hill_climb.c#L36-L103)
  and [lines 143–224](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/passes/hill_climb.c#L143-L224): neighborhood and adaptive climb.
- Pinned bomm [key.h, lines 327–373](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/key.h#L327-L373):
  empty/single-pair seeds touching an explicit mask, avoiding occupied endpoints.

Adaptations are intentional: protect true fixed pairs (reference does not), use
actual board cardinality rather than reference `num_plugs=0` net-change counter,
retain our per-slot outer order, explicit domains/starts/objectives/thresholds,
checked Q32 scoring, no-reflector decrypt support and deterministic shared budget.
No floating-point score/trajectory parity or guaranteed key recovery is promised.
Duet/quartet, DFS, mutable fixed facts and additional attacks remain out of scope.
Public lifecycle/result transport is frozen above but implementation remains later
Task12 work; differential oracle remains Task17.
