# Plugboard attack contract — Task 11

Status: **Core HC/PE execution and the shared production CLI JSONL adapter ship.**
[Current availability](protocol.md#41-planned-hcpe-search-events--task-127) describes
validated HC/PE execution, legacy unsupported search and Core evaluation-count progress.
Task 11.2a provides only `AttackPlugboardDomain::parse_json`: strict typed fragment
validation with immutable known fixed pairs. It is separate from legacy search
spaces and grants neither complete request acceptance nor candidate enumeration.
Task 11.2b adds isolated `AttackSettings::parse_json` validation for common
settings, exact declared objectives and direct hill-climb starts, bound to the
domain's ordered alphabet, plus typed partial-exhaustion `empty_single` all/touching
seed policies. Task 11.2c adds `AttackGate::check` over a borrowed resource-bound
`SearchRequest` and explicit typed domain/settings. It rechecks compatibility and
returns privately constructed full/sliced outer and per-outer start counts, not an
executable request. Counts describe the full selected work.
Task 11.2d.5 exposes `ParsedAttackRequest::parse_json` and supplied-content binding,
plus resource-free `AttackRequest::parse_json`. Both promotion routes check eligibility
before returning privately owned inputs, retained models and counts. Owned result
carriers and the HC facade are exposed; raw candidate APIs remain private. Public root dispatch selects this owner only when
`job.space.plugboard.kind` is `"attack"`, with wire kind still `"search"`.
The CLI loads resources once, binds and checks eligibility/counts before
HC/PE execution through §6.2; failures remain seq1-only errors.
Task 11.4a adds private complete-neighborhood best-improvement selection only.
Task 11.4b.1 adds a private bound scoring lifecycle: start-phase selection,
committed-board objective switching and once-only finalization, without an ascent loop.
Task 11.4b.2 adds a private single-climb driver repeating complete strict-improvement scans,
with final-scored committed outcomes on completion or cancellation. Interrupted scans
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
Private HC/PE aggregates, the public Core HC/PE facade and fallible wire result
projections are implemented and used by the production CLI adapter.
Task 12.9a privately retains the best earlier successful, final-scored seed when a
later seed fails. Its error envelope owns the original resolved initial key separately
from the committed mutable board, preserving the failure source/index and charged usage.
Failed climbs, provisional scan winners and failed final rescoring never supply that best.
Task 12.9b privately retains earlier accepted outers and eligible earlier seeds in
failing outers, selecting strictly better final scores and preserving earliest ties.
Outer-completion accounting precedes acceptance: overflow retains only the prior aggregate.
Private owned PE projections preserve terminal usage/counters, nullable failure indices,
original causes and separate malformed-best errors. Public HC is unchanged;
Task 12.9c exposes these PE projections through the same public run facade.

For this settings fragment, malformed raw JSON (including duplicate keys, trailing
input and nonobjects), missing fields and invalid kind/objectives use
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
same attack inside outer scrambler enumeration. Current CLI availability is
summarized above; private HC/PE drivers and outer schedulers are implemented.
[Protocol](protocol.md) and [scoring/resources](scoring-resources.md) remain normative.
This document specifies `hill_climb` and `partial_exhaustion`, plus the implemented private
control contract in §6.1 and public Core HC/PE facade in §6.2;
[protocol §4.1](protocol.md#41-planned-hcpe-search-events--task-127) defines first-release
lifecycle/results/progress, now delivered by the CLI for HC/PE. Chained stages are
specified in [§9](#9-chained-stages--task-13) and the hold list in [§10](#10-hold-list--task-14);
checkpoints remain separate work; multi-variant search is not planned.
The Stage 3 `bombe` pass, which reuses this attack branch with a crib and a
finishing climb, is specified in [crib-attack.md](crib-attack.md).

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
bounds; outer offsets/limits retain existing types.

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
| `progress_every` | Optional positive `u64` integer, default 100000; global completed-evaluation interval |
| `start` | Required only for direct `hill_climb`; array of mutable pairs |
| `seeds` | Required only for `partial_exhaustion`; strict object below |

`job.attack.evaluation_budget` is rejected as `unknown_field` at
`/job/attack/evaluation_budget`; it is not silently ignored.

All listed common fields except `progress_every` are mandatory. No heuristic defaults: reference
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
(Task 13 supersedes this for chained stages after the sole HC/PE pass: §9; Task 14
hold: §10.)
Legacy structural requests without `attack` keep their existing parsing meaning.

Both objectives use already declared and retained Task 10 scorers. All selected
measures, including those not used as objectives, must satisfy existing minimum
text lengths and resource binding rules before execution. No model rereads, score
sum, implicit trie base score, or new smoothing is introduced (sole trie-stage
exception: §9.4). Compare checked
Q32 **ranking** values, maximizing them; entropy uses negative measured entropy.
Initial and final raw scores are not directly compared across different measures.
Unused *resource references* remain invalid; non-objective declared measures are
allowed, but Task 11 need not evaluate them for its internal result.

## 3. Pre-execution gates and outer order

Before the first evaluation, validate strict syntax, full coverage, starts/seeds,
all topology and scoring/resource compatibility, and integer/count bounds.
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
all seeds in order before advancing the outer tuple, unless cancellation stops the run.
Legacy subset indices/order remain unchanged in their own branch.

`space.constraints.distinct_wheels` (protocol §3.3) filters this order: every outer
tuple in which two named slots hold the same wheel name is removed, and the remaining
tuples keep their relative order. Index 0 is the first remaining tuple; "absolute
unsliced" means unsliced by `offset`/`limit` within the filtered order. Validity depends
only on the wheel coordinates, so the count and the n-th tuple are computed directly
from per-slot wheel counts, without enumerating earlier tuples; the result is the same
as filtering the full order one tuple at a time. Example: Enigma I with `left`,
`middle` and `right` wheels unknown (5 wheels each), positions unknown and rings known
has 5 x 5 x 5 x 26^3 = 2,197,000 outer keys; naming those three slots leaves
5 x 4 x 3 x 26^3 = 1,054,560. For M4 name `left`, `middle` and `right`: the `greek`
slot has its own wheels (`Beta`, `Gamma`), so naming it removes nothing.

An empty outer slice returns no best candidate with termination `outer_slice_end`.
Otherwise normal exhaustion of the requested slice is `completed`; completion is
only of that slice, never a claim of all mathematical plugboards being exhausted.
Selected outer keys run in fixed blocks of 128 consecutive keys (§6.1), committed
in key order; parallel execution must preserve that deterministic result order.

Searches are finite: strict ascent over finite boards and neighborhoods, finite
seed sets and finite outer keys. Finite does not mean short. Use offset/limit to
bound outer keys only, or cancellation to stop remaining work.

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
seeds may converge to the same result; do not deduplicate climbs.
Direct hill climb instead uses its explicit `start`, with start index 0.

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

## 6. Adaptive hill routine and evaluation accounting

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
evaluations. All calls share whole-request checked accounting; no per-seed reset.
Fresh engine state means initial outer positions, before the first keypress;
precomputation is permitted only if equivalent to this decrypt-and-score result.

Final rescoring is required whenever the committed board has no known final score,
including after cancellation. Reuse an existing final score without evaluation;
otherwise count the fresh final-objective call normally. Never report an unscored
board as a competitive winner; failed final rescoring remains an error.
Cancellation discards an unfinished neighborhood's provisional winner and retains
only the committed board (§6.1). Public events are specified by
[protocol §4.1](protocol.md#41-planned-hcpe-search-events--task-127).

### 6.1 Private progress and cancellation — Task 12

**Core HC and PE execution is publicly available through `AttackRequest::run` (§6.2).**
Single climbs, HC outer scheduling, PE seeds/resolved owners and PE outer scheduling
share checked accounting, counter snapshots and cooperative cancellation.
Both controlled paths use fresh per-invocation control and evaluation accounting.
Fallible JSONL projections and the shared synchronous HC/PE adapter ship in the CLI.
The CLI `--cancel-file` marker (Task12.12) and platform signals (Task12.13) are
the external cancellation sources; checkpoint cadence remains deferred.
Checkpoint/resume belongs to Task 16 and the hold list to Task 14 (§10); Task 12 is done.

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
Only an actually admitted call is charged, including required final rescoring.
Cancelled climbs and their unfinished outers are not completed.
Before initial success there is no current climb result; retain any earlier aggregate.

The outer phase runs blocks of `OUTER_BLOCK_KEYS` = 128 consecutive selected outer
keys. A block runner shares only the immutable request, bound resources and outer
plan; it owns its scrambler preparation and local counters, and calls no observer
or cancellation callback. It returns its per-outer outcomes in key order, its local
counters and its first error, with the work before that error. The coordinator adds
each block's counters to the run totals in key order (checked; an overflow discards
that block and reports its first key as `outer_index`), then offers its outcomes to
the hold and strict winner in key order. The first error in key order stops the run.

With `ExecutionOptions` above one thread and more than one block, `run_with` runs
block runners on up to that many scoped worker threads, each with its own
preparation. Workers take the next block in key order, at most twice the worker
count ahead of the next block to commit; the coordinator (the calling thread)
buffers finished blocks, commits them in key order and alone calls the observer and
the cancellation callback. Results of completed runs are therefore independent of
the thread count. Stages run afterwards on the calling thread; they use the run's
preparation only as a cache, so its contents never change their results.

#### Sticky safe-stop and committed results

Cancellation observation is sticky. In the outer phase it is polled only at block
boundaries (before each block on one thread; before the first block and after each
finished block with workers); nothing inside a block polls, so a stop requested
mid-block lets every started block finish (all climbs, seeds and final scores) and
be committed, and no later block starts. A stop before the first block yields no
outer work. Chained stages
poll before trial admission and after evaluation before the next trial or
scan-winner commit. Once a stage observes a stop, it abandons any unfinished scan and
its provisional winner and preserves only the previously committed board. No
optimization follows observation: no new trial, winner commit or later stage begins.

The sole evaluation exception is one already-required final-objective rescore of
that committed board, only if its final score is absent; it is admitted and charged
normally.
If a final score already exists, reuse it without evaluation. This exception retains
an eligible valid result, never promotes a provisional winner or resumes ascent.
Failure of this final rescore remains an error, not a cancelled result.

Each admitted full-message decryption plus score is cooperative and nonpreemptible;
an outer block runs to its end before cancellation is observed. Blocks are sized to
last about a second or less in typical searches, but there is no
immediate-interruption, wall-clock bound or compliance claim for the public progress
interval.

#### Stop precedence and determinism

An encountered evaluation, resolution or invariant error remains an error;
cancellation must not mask it or erase charged usage. Already-established zero-cost
or natural exhaustion remains complete (an empty outer slice is `outer_slice_end`).
When work remains, safe cancellation stops it. Precedence is errors > exhaustion >
cancellation: a stop observed after the last block cannot turn the slice into
`cancelled`. Do not perform an extra evaluation to probe exhaustion, and do not
cancel retroactively after completion.

Preserve deterministic pair/action and outer/seed tie order, immutable fixed pairs,
and final-score eligibility. Winning-result flags (final-objective ascent and fully
exhausted neighborhood) remain distinct from the whole-run stop reason; neither
final rescoring nor an earlier completed winner makes a cancelled run complete.

#### Counter-only observation boundary

The Core observer is synchronous and infallible and receives immutable counters
only: once initially, after committed outer blocks, at stage cadence points, and
once on terminal success, cooperative cancellation or returned error. X is the
positive `job.attack.progress_every` (default **100000**), shared across the entire
HC or Partial Exhaustion (PE) attack. After each committed block, one snapshot is
emitted if at least X evaluations completed since the previous emitted snapshot,
however many multiples of X the block crossed. Chained stages and held finalists
keep the global grid: one snapshot at each completed count X, 2X, ... reached during
the stages. Admission and internal boundaries update counters without notifying.
Failed evaluations retain admission but do not advance cadence; winner plaintext
replay is not an evaluation. Threshold overflow ends cadence without wrapping or
repeating; existing checked counter overflow remains an error.

Keep terminal observations even when equal to an initial or cadence snapshot.
No callback runs mid-evaluation or inside an outer block; cancellation polling is
independent of observer cadence. The CLI forwards every Core snapshot directly, reads the progress elapsed
clock only for delivery, flushes each line and latches output failures into
independently polled cancellation. Broken output or hard process exit can prevent
terminal delivery. No timer thread or wall-clock delivery bound is promised.
External cancellation uses the optional `--cancel-file` marker and platform signals
([protocol §5](protocol.md#5-control)).
[Protocol control](protocol.md#5-control) retains its public obligations; Task 16
still owns checkpoint/resume design and implementation.

### 6.2 Public Core HC API — Task 12.8

**`AttackRequest::run` executes HC or PE on an already validated, resource-bound owner.**
Owned `AttackProgress`, `AttackResult`, `AttackBest`, `AttackTermination` and
`AttackRunError`/`AttackRunSource` expose factual counters, committed winners and
original causes. Malformed accepted best projections return explicit errors,
never silently become null; success-projection failures retain terminal counters
and usage with an invariant cause and the concrete failure through `best()`.
The CLI uses this same synchronous facade for HC and PE:

```rust,ignore
fn run(&self, observe: impl FnMut(AttackProgress),
       cancel_requested: impl FnMut() -> bool)
    -> Result<AttackResult, AttackRunError>;
```

Each invocation creates fresh whole-run control/allowance and runs the same-owner
HC or PE block runner over the lazy outer plan (§6.1) with absolute outer indices
and dense PE seed indices. It never rereads resources or accepts caller-supplied raw outer candidates.
PE cancellation retains eligible final-scored seed winners; winner
incompleteness is independent of whole-run termination.
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
PE `SeedBest` projection reuses that owned key validation. Its key combines resolved slot facts with fixed plus winning mutable
pairs; never report the owner's initial fixed-only board as the winning complete key.
Flags are `incomplete`, `final_objective_ascent`, `neighborhood_exhausted`; direct
HC interruption derives from its cancellation/incomplete flags, PE from its seed winner.
PE seed incompleteness is independent of whole-run termination; failure indices never
replace the retained winner's outer/seed indices. No ascent is implied merely by final
scoring. Tie order and eligibility remain §3–6.
The controlled-direct private error already owns the earlier accepted aggregate best,
source, outer index, charged usage and terminal snapshot. Its public projection keeps
those facts; resolution and missing-outer failures have no start index, while known
direct-climb failures use start0, never the earlier winner's index. Failed-outer
provisional boards are not eligible. `AttackRunError::best()` returns `Ok(None)` for
absence or an owned projection error by reference for malformed retained best. This
separate fallible channel preserves the original runtime cause and all accounting
instead of silently dropping a malformed winner or replacing the runtime failure.
Original evaluation/counter/resolution sources are wrapped in an owned
`AttackRunSource`; raw scheduler error types stay private. PE errors preserve the
original failure indices, earlier eligible seed/outer winner and terminal accounting
through the same owned envelope. The public `UnsupportedExecution` category remains
available for compatibility, but valid HC/PE runs no longer produce that rejection.
Preserve nested source access and diagnostics,
not just a formatted string or sentinel result. Result/best/progress/error fields use
the wire names in protocol §4.1; Core replaces `elapsed_ms` with transport ownership,
Q32 strings with `FixedScore` values and null with `Option`. `AttackTermination`
variants are `Completed`, `OuterSliceEnd`, `Cancelled`.

`completed`, `outer_slice_end`, `cancelled` have exactly the
[wire stop meanings](protocol.md#41-planned-hcpe-search-events--task-127). The public
facade and production CLI use the corresponding controlled HC/PE path.
No current-climb result exists before initial success; a failed final rescore cannot
make that board eligible. Errors dominate cancellation and preserve charged usage.
The transport adds elapsed clocks and exact decimal-string encoding; Core keeps
u64/u128/i128 values and Q32 units. Transport failures latch cancellation without
turning the infallible observer into a fallible evaluator or hiding a runtime error.

First-release JSONL is `started`, initial/cadence/terminal `progress`, final `result`, then `done`
or runtime `error`; validation errors remain seq1-only. Task 14 specifies the hold,
delivered once as the final `result.hold` array (§10); no candidate/hold/checkpoint event
is promised. Task16 owns checkpoint/resume. File and POSIX/Windows adapters are
separately unstarted under [protocol control](protocol.md#5-control); none is shipped.

## 7. Minimal core result, examples and limits

The HC/PE run result contains termination (`completed`, `outer_slice_end`,
or `cancelled`). It carries
evaluations used, outer candidates completed, climbs started
and completed, and an optional best committed board with resolved initial slot
key, plaintext, final measured/ranking score, absolute outer index and seed/start
index. A cancelled climb is not completed. An outer candidate is
completed only after all its climbs finish. Eligible final-scored committed boards
include the interrupted climb's board, marked incomplete; ties select lowest
(outer index, seed/start index). §10 generalizes this best to a top-N hold; the public
Core projection is §6.2 and wire projection is protocol §4.1.
Per-climb outcome records whether final-objective ascent occurred and whether its
legal neighborhood was fully exhausted; final rescoring alone is not optimization.
Runtime scoring/invariant errors fail explicitly, not as a termination or sentinel.

These are **valid planned search-job fragments**, completed by protocol root
`protocol_version: 1` and bundled `machine.definition` for `enigma-i`. They are
not known-answer vectors. Direct Core attack parsing, binding and eligibility checks
validate them. Safe public root Core/CLI validation and private execution are
implemented; public HC/PE runs through Core and the production CLI adapter.

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
    "switch_pairs":2,"backtrack_pairs":1,
    "seeds":{"kind":"empty_single","selection":"touching","symbols":["E"]}}
}
```

The seeds are `[]`, CE, DE, EF; AB stays fixed. For direct hill climb, replace
`passes` with `["hill_climb"]`, set `attack.kind` to `"hill_climb"`, and replace
`seeds` with `"start":[["C","E"]]`; all other fields are unchanged and valid.
For outer search, remove the right slot's fixed `position` and add
`space.slots: [{"id":"right","positions":["A","B"]}]`: indices 0/1 select A/B,
with the same local seed sequence for each, subject to cancellation.

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
checked Q32 scoring, no-reflector decrypt support and checked shared accounting.
No floating-point score/trajectory parity or guaranteed key recovery is promised.
Duet/quartet, DFS, mutable fixed facts and additional attacks remain out of scope.
Public lifecycle/result transport is frozen above and implemented in the production
HC/PE adapter; the hold is §10 (Task 14) and checkpoint controls remain Task16 work.
Differential oracle remains Task17.

## 9. Chained stages — Task 13

Status: **reswapping, measure and trie implemented** after HC/PE, in listed order.
Task 13 supersedes, for this
branch only, the §2 sentences rejecting `reswapping`, `trie`, `measure` and mixed
passes; §1–§8 otherwise stay normative. Pinned bomm basis:
[attack.c, lines 81–91](https://github.com/ffraenz/bomm/blob/aeb2f2bf00dfdee68e972f90ae7e83b387b188e9/src/attack.c#L81-L91),
`src/passes/reswapping.c`, `trie.c` and `measure.c` at the same commit.

### 9.1 Request shape and admission

`job.passes` stays a unique identifier array. Its first element must be `hill_climb`
or `partial_exhaustion` (the sole HC/PE pass), followed by zero or more distinct
stages from `reswapping`, `trie`, `measure` in any order. `job.attack.kind` equals
that first element. A stage listed first, a stages-only list, a second HC/PE pass
or any other identifier is `unsupported_pass` at `/job/passes`. Uniqueness means
each stage runs at most once (bomm allows repeats; we do not).

`job.attack` gains three optional members, allowed only when the same-named stage
is listed; each is a strict object whose members are all optional:

| Member | Fields | Omitted default |
| --- | --- | --- |
| `reswapping` | `measure` | `sinkov_trigram` |
| `trie` | `base_measure` | none: carry the previous score (§9.4) |
| `measure` | `measure` | `ic` |

An omitted object equals `{}`. Unknown members use `unknown_field`; a settings
object for an unlisted stage, a nonobject, or a non-string/`null` field value is
`invalid_request` at that member. Every explicit or defaulted measure must be an
exact `job.measures` identifier, else `invalid_request` before work: at the
explicit field, or at `/job/passes/<index>` for an undeclared default. A listed
`trie` stage likewise requires `trie` (with its dictionary resource) to be declared.
`base_measure` may name any declared measure, including `trie`. Because every
stage measure is declared, §2's minimum-length and resource-binding preflight
already covers them; all such failures stay seq1-only errors.

```json
"passes": ["hill_climb", "reswapping", "trie", "measure"],
"attack": {"kind": "hill_climb", "...": "§2 fields unchanged",
  "reswapping": {"measure": "sinkov_bigram"}, "trie": {"base_measure": "ic"}}
```

Here `measure` uses default `ic`, so `job.measures` must declare `ic`,
`sinkov_bigram`, `trie` and both §2 objectives.

### 9.2 Chaining

Stages run sequentially in `job.passes` order on **one** key: the HC/PE run's
committed best (§7), only when that run terminated `completed` with a best. Each
stage receives the previous stage's committed key and score and hands on its own.
Task 14 repeats this pipeline per hold entry (§10.5); there is no checkpoint
(Task 16), RNG or parallelism; the pipeline is fully deterministic. Every evaluation is a fresh full-message decrypt of
`job.text` from the key's initial positions; slot choices never change, and the
winner's `outer_index`/`start_index` and HC/PE flags are retained unchanged.

### 9.3 `reswapping` — constrained steepest ascent

Let K be the committed key and S its ranking under the stage measure. The first
evaluation scores K (stage start). Each scan then visits every committed **mutable**
pair (i,k), alphabet-index(i) < index(k), in increasing order of i. For each, remove
it, then for every free mutable symbol x in alphabet order, including i and k
themselves, evaluate (i,x) then (k,x), one evaluation each, restoring the board after
every trial. A trial with x equal to its own endpoint ((i,i) or (k,k)) is the board
with (i,k) removed; (k,i) at x = i and (i,k) at x = k restore K. Track the best strict
ranking improvement over S; the first found wins ties, so restoring K never wins.
After the full scan apply only that winner (remove (i,k), then add the chosen pair
unless it is a pure removal), set S, and rescan; stop when a complete scan has no
strict improvement (completed, even with no trials).

Constrained departures: fixed pairs are never removed or reswapped; x comes from
the §1 `symbols` universe and is unpaired; the pair count never grows, so `max_pairs`
holds (a winning pure removal shrinks it by one); the §5 backtrack/switch thresholds
do not apply. Like pinned bomm, the identity and pure-removal trials are evaluated
and counted.

Decision (Task 13.3b): a started reswapping stage that stops early (cancellation
or evaluation error) reports the committed S as its history `score`;
the score is `null` only when its initial evaluation fails, and best then stays as
before the stage.

### 9.4 `trie` and `measure`

`measure` costs one evaluation: score K with its measure; K is unchanged and the
new score replaces the carried one. `trie` costs one evaluation: decrypt K once,
compute `TrieQ32` (scoring §5.4), and, if configured, the `base_measure` ranking on
that same plaintext; otherwise use the carried `ranking_q32`. The stage score is
`measure: "trie"`, `measured_q32 = TrieQ32`, `ranking_q32 = checked(base + TrieQ32)`.
This explicit Q32 ranking sum is the **only** exception to §2's "no score sum, no
implicit trie base score", scoped to this stage; overflow is a runtime evaluation
error. Explicit `base_measure: "trie"` doubles the trie ranking, still within one
evaluation. Signed dictionary weights retain their signs. The carried base may
come from a different measure; the sum is defined but
not comparable across measures. Otherwise scores of different measures remain
incomparable, including across stages.

### 9.5 Safe stop, termination and errors

Stages share the §6.1 checked counters; each evaluation above is admitted, charged
and completed exactly as there. Stage scores are always known for the committed
key, so no final rescore is needed. A reswapping scan interrupted by cancellation
discards its provisional winner; earlier applied reswaps remain committed.
Climb and outer counters never change during stages.

Cancellation is polled before each stage, before each admission and after each
evaluation before a reswap commit; once observed no further stage evaluation runs.
A cancellation pending after the final no-improvement scan therefore leaves the
reswapping stage `completed`: no commit, hence no poll, follows that scan.
Run termination: the HC/PE termination if not `completed` (stages never start);
otherwise `completed` only when every listed stage completed, else `cancelled`
with §6.1 precedence (errors > exhaustion > cancellation).
A stage error is a runtime `error` whose result best is the last committed
key and score, with HC/PE indices and `source.kind` `evaluation`.

### 9.6 Result projection

`best.configuration`, `best.mutable_plugboard`, `best.plaintext` and `best.score`
describe the final committed key and the score of the last stage that established
it: the last completed stage, or an interrupted `reswapping` stage after its first
evaluation. `result` gains an additive `stages` array (empty for HC/PE-only runs)
with one entry per started stage, in order, each exactly `pass`, `measure`,
`base_measure` (trie only, else `null`), `score` (§4.1 score object or `null`),
`evaluations_used` (decimal string) and `completed` (boolean). Unstarted stages have
no entry: a stage starts at its first evaluation admission, so cancellation
preventing that admission leaves no history entry. Core mirrors this on `AttackResult`.

## 10. Hold list — Task 14

Status: **implemented in Core and the CLI.** A run keeps the top-N committed
candidates instead of one best, polishes them with the §9 stages and delivers them
once, in the final `result`. §1–§9 stay normative except where this section extends
them. Scope is the hold list only: multi-variant search is not planned (one request
per machine definition); live `hold` events and parallelism are out of scope (§10.8).
Pinned bomm basis: `src/hold.c` (`bomm_hold_add`), `src/attack.c` and `src/query.c`
(`--num-hold`, default 100) at commit `aeb2f2bf`.

### 10.1 Request field and admission

`job.attack` gains one optional common member, valid for both `hill_climb` and
`partial_exhaustion`:

| Member | Type and meaning | Omitted default |
| --- | --- | --- |
| `hold` | Integer in [1, 1000]: hold capacity N | 100 |

A present value that is not an integer, is fractional, or lies outside [1, 1000]
is `invalid_request` at `/job/attack/hold`; `null` is not omission.
`hold` is parsed in the §2 settings fragment at its exact-field/type step
(after raw validation, unknown-member and alphabet checks), so it fails before the
§3 gate counts, resource binding and `started`, as a seq1-only `error`.
The upper bound caps retained memory and the final `result` line: each entry owns a
full plaintext of `job.text`, so output grows as N × text length. 1000 is ten times
the bomm default. A capacity above the number of climbs is valid; the hold is then
simply shorter. The hold never changes HC/PE enumeration or accounting rules.

### 10.2 Entry rule

The HC/PE schedulers offer the hold exactly the candidates they compare against the
single best today (§7, §6.2): once per climb (direct start or PE seed), at its end,
the climb's committed board with its required final score, in enumeration order.
This includes cancellation-interrupted climbs (flag `incomplete`), whose required
final score was established successfully. Provisional scan winners, failed climbs, failed
final rescores and climbs that never obtained an initial score offer nothing; a
§6.1 safe stop offers no further climb. On a runtime error the hold keeps exactly
the earlier offers that the Task 12.9a/b retention rules keep for the single best
(earlier outers and eligible earlier seeds of a failing outer); when outer-completion
accounting overflows, offers of that outer are discarded with it. Stages (§10.5) do
not offer new entries; they replace existing ones.

### 10.3 Order, ties, duplicates and capacity

Entries are ordered by `(ranking_q32 desc, enumeration index asc)`, the protocol
[determinism](protocol.md#7-determinism) hold order. The enumeration index of an
attack candidate is the pair (absolute unsliced `outer_index`, `start_index`) of §3
and §4, compared lexicographically; it is unique per climb. Before stages, every
entry carries its HC/PE `final_measure` score, so all are comparable.

A duplicate is an offer whose complete key equals a held entry's: every resolved
slot (wheel, position, ring, and wiring `pairs` when rewirable) and the complete
plugboard (fixed plus mutable pairs).
Deterministic scoring gives duplicates equal scores, so the held entry has the
smaller index; the offer is rejected without evicting anything. Otherwise, while
fewer than N entries are held, the offer is inserted at its ordered position (after
equal scores, since it is later). When full, it is inserted only if it orders before
the last entry, which is then evicted; else it is rejected. Rejected and evicted
candidates are never reconsidered. The flags and indices of a kept entry are its own.

### 10.4 Compatibility invariant

With N = 1 the run reproduces Task 13 exactly: the same `best`, `stages`,
termination, counters, usage and runtime-error context. Without listed stages,
`best` is the first entry for every N and equals today's strict-`>` earliest best.

### 10.5 Stages over the hold

Stages run only when the HC/PE run terminated `completed` with a nonempty hold (§9.2).
Finalists are processed one at a time, best-first by their pre-stage order; each runs
the complete §9 pipeline in `job.passes` order from its own committed key and score,
exactly as §9.2–§9.4 define for one key, keeping its own indices and HC/PE flags.
All finalists share the §6.1 checked counters and cancellation (§9.5).
Cancellation is also polled before each finalist. After a stop no further stage evaluation runs for any finalist.

Each entry ends in one state:

| State | Meaning | Score |
| --- | --- | --- |
| polished | every listed stage completed | last stage's score |
| partial | some stage started, not all completed (at most one entry, the finalist at stop or error) | §9.6 rule |
| unpolished | no stage started | HC/PE final score |

Final order: polished entries by `(ranking_q32 desc, enumeration index asc)`, then the
partial entry, then unpolished entries in pre-stage order. Scores of different
measures are not comparable (§2, §9.4), so ranking never compares across states;
polished entries share one final measure and are comparable. Because best-first
processing reaches the strongest pre-stage candidates first, a stop leaves them
polished and ahead. After re-ranking, an entry whose complete key equals an earlier
entry's is removed (polished duplicates have equal scores, so the smaller index
stays); removed slots are not refilled. With no listed stages every entry is
trivially polished and the pre-stage order stands.

Termination: the HC/PE termination if not `completed`; otherwise `completed` only
when every finalist is polished, else `cancelled` with §9.5
precedence. A stage error is a runtime `error` (§9.5): its finalist keeps its last
committed key and score as the partial entry; the hold is retained.

### 10.6 Cancellation and errors

A stop or error never discards held entries: cancellation returns the retained hold
(§10.2 during HC/PE, §10.5 states during stages) in the final `result`; a runtime
error returns it in the error's `result`. Precedence is errors > exhaustion >
cancellation (§6.1). Stage cost grows with N; `hold: 1` keeps the Task 13 cost.

### 10.7 Result and wire projection

`result` gains an additive `hold` array, in final order (§10.5); it is empty exactly
when `best` is null. Each entry has exactly the nine `best` fields of
[protocol §4.1](protocol.md#41-planned-hcpe-search-events--task-127) plus `stages`,
the entry's own stage history in the §9.6 shape (empty when unpolished or without
stages). The array position is the rank; no separate rank field exists. `best`
equals the first entry without `stages`, and top-level `result.stages` equals the
first entry's `stages`, so both keep their Task 13 meaning for N = 1. Entries may
carry different `score.measure` values; clients must not compare scores across
measures. Runtime `error` context keeps the §4.1 shape; for a stage error its
`outer_index`/`start_index` are the failing finalist's. Core mirrors this on
`AttackResult` with an ordered entry list. A checkpoint records the pre-stage hold
([protocol §6.3](protocol.md#63-record-checkpoint_version-1)).

### 10.8 Non-goals and departures from bomm

Not in Task 14: multi-variant search (not planned; run one request per machine),
live or periodic `hold` events, threads or a shared concurrent hold, and
checkpointing (Task 16).

Deliberate departures from pinned bomm:

- Offers: one final-scored committed board per climb, not every pass result of
  every key; stages replace an entry in place rather than adding offers, because
  stage measures differ and §9 polishes one key per pipeline.
- Stages run on the hold after HC/PE, best-first, not inline per key.
- Ties order by enumeration index, not thread arrival; duplicates are any equal
  complete key, not only an equal-score neighbour (equivalent under deterministic
  scoring), and are re-checked after stages.
- Capacity is bounded by 1000; re-ranking is tiered by polish state because scores
  from different measures are not comparable.

## 11. Rewirable reflector (UKW-D) — Stage 5

Status: **Core transform and CPU wiring search implemented**, including complete
result/hold keys, stages and checkpoint re-verification (plan
`odd/tasks/enigma-wwii-machines.md`, T9–T11). Human-report wiring display and web
controls remain T11/T13 work. Protocol [§3.1](protocol.md#31-machine-definition) and
[§3.2](protocol.md#32-configuration-and-transform) define the rewirable wheel
and its `pairs` key; this section defines how an attack searches that key.

### 11.1 Notation and machines

Pairs use the engine's contact notation, the same one used by every other
wheel wiring in the catalog: Bletchley Park (BP) notation, contacts
`ABCDEFGHIJKLMNOPQRSTUVWXYZ` clockwise, with BP `BO` wired permanently.
German key sheets label the same contacts `A-ZXWVUTSRQPON-MLKIHGFEDCB`
(hyphens are the fixed contacts); converting a German sheet is a client
concern, documented in [historical catalog](historical-catalog.md), never an
engine alias. UKW-D is offered by separate bundled machines (`enigma-i-ukwd`,
`enigma-m3-ukwd`, and `enigma-kd` in T12), so the `enigma-i`/`enigma-m3`
catalog bytes and their checkpoints do not change. The M4 replaced UKW-B and
the Greek wheel with UKW-D, which is structurally `enigma-m3-ukwd`. The
historical setting of the UKW-D slot is position `A`, ring `A`; other values
are representable but non-historical, as for the ETW.

### 11.2 Request

A searched wiring is declared in the attack branch only, on the slot domain:

```text
space.slots[] := {"id": SLOT_ID, "pairs": {"kind":"attack"}, ...}
job.attack.reflector_starts := INTEGER   (1 to 1000000)
```

`pairs` is allowed only for a slot whose wheel is rewirable (protocol §3.1),
exactly once per such slot, and conflicts with a fixed `pairs` in
`configuration` (`invalid_search_space`, as for any double coverage, at
`/job/space/slots/<index>/pairs`). An uncovered wiring uses the existing missing
dimension diagnostic, `invalid_search_space` at `/job/space/slots`. A `pairs`
domain on a non-rewirable slot is `unknown_field` at that domain's `pairs`;
malformed domain shape or kind is `invalid_search_space` there. Unknown members
inside the domain remain `unknown_field` at the member, checked before kind.
A known wiring is given in `configuration` and needs no new attack setting.
`reflector_starts` is required when a wiring is searched and forbidden
otherwise (`invalid_request` at `/job/attack/reflector_starts`). Like
`progress_every`, a supplied value that is not a JSON integer in 1..=1000000
(zero, negative, fractional, exponent form, wrong type, null, overflow) is also
`invalid_request` at `/job/attack/reflector_starts`; unknown-member validation
retains precedence. Partially known
wirings are not supported in this stage: the wiring is either fully fixed or
fully searched. The legacy subset branch rejects `pairs` domains with
`invalid_search_space`.

Supported passes: `hill_climb` only, followed by optional chained stages (§9)
and hold (§10). `partial_exhaustion` and `bombe` with a searched wiring fail
before work with `unsupported_pass` at `/job/passes`. Chained stages keep the
winning wiring fixed and polish the plugboard only.

### 11.3 Starts

Per outer key, start `s` (0-based, `s < reflector_starts`) builds its initial
wiring deterministically, with no RNG state: list the free symbols (alphabet
minus fixed pairs) in alphabet order; shuffle with Fisher–Yates from the last
index `i` down to 1, swapping `i` with `j = next() mod (i + 1)`; pair elements
`(0,1)`, `(2,3)`, … . `next()` is SplitMix64 seeded with `s`: `state +=
0x9E3779B97F4A7C15; z = state; z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
z = (z ^ (z >> 27)) * 0x94D049BB133111EB; return z ^ (z >> 31)` (wrapping u64
arithmetic). The modulo bias is accepted and fixed by this definition.
`best.start_index` is the reflector start `s`. Each start restores the direct
`start` board, the initial objective phase and the initial positions; nothing
carries over between starts.

### 11.4 Wiring neighborhood

Let W be the committed wiring's free pairs, each oriented `(a,b)` with
`alphabet_index(a) < alphabet_index(b)` and sorted by `a`. For every two pairs
`(a,b)` before `(c,d)` in that order, evaluate two trials, in this order:
`(a,c)+(b,d)`, then `(a,d)+(b,c)`. With 12 free pairs this is 132 trials.
Selection follows §5: every trial from the same committed state, greatest
strict ranking improvement wins, ties keep the first trial, no plateau or
worsening moves. Each trial is one evaluation (§6).

### 11.5 Alternating climb

For one start: (1) climb the plugboard (§5, §6) with W fixed; (2) climb W
(§11.4) with the board fixed, using the objective of the current phase; if
step 2 committed at least one move, repeat from step 1, otherwise stop. The
objective phase is the single §6 phase driven by board cardinality, shared by
both steps. Final rescoring (§6) happens once, after the alternation stops.
Termination: every committed move strictly improves the score of the current
phase over a finite space. A board with no legal moves (for example
`max_pairs: 0`, as on KD) makes step 1 a no-op, so the climb is the wiring
climb alone.

### 11.6 Results, checkpoint and backend

`best.configuration` and every hold entry carry the winning `pairs` in the
UKW-D slot entry, oriented and sorted like plugboard pairs; it is a complete
transform key. `mutable_plugboard` is unchanged. The human report prints the
wiring next to the reflector slot. Checkpoints need no new member or version:
`best`/`hold` already carry the complete key, resume re-decrypts it (protocol
§6.4), and identity already binds the request and the catalog content.

Searching the wiring is CPU-only. `--backend gpu` with a searched wiring emits
one seq 1 `backend_unavailable` at `/job/attack`, message
`GPU backend unavailable: the UKW-D wiring search runs on the CPU only`, exit 1,
before device initialization. With a **known** wiring the GPU plugboard attack
is supported unchanged, because the CPU prepares rows from the resolved
reflector. Deferred options (L13): a hybrid where the CPU climbs W and the GPU
climbs the board on rows prepared per wiring, or a GPU kernel that climbs W.
