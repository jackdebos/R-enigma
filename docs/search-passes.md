# Plugboard attack contract — Task 11

Status: **Normative contract; Core and CLI attack validation are supported, execution is not.**
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
before returning privately owned inputs, retained models and counts. No carrier or
candidate APIs are exposed. Public root dispatch selects this owner only when
`job.space.plugboard.kind` is `"attack"`, with wire kind still `"search"`.
The CLI loads resources once, binds and checks eligibility, then emits one seq1
`unsupported_job` error at `/job/kind` (`attack execution is not implemented`),
without work events. CLI execution and public runtime attacks remain unsupported.
Task 11.4a adds private budget-aware complete-neighborhood best-improvement selection only.
Task 11.4b.1 adds a private bound scoring lifecycle: start-phase selection, shared final-score
reservation, committed-board objective switching and once-only finalization, without an ascent loop.
Task 11.4b.2 adds a private single-climb driver repeating complete strict-improvement scans,
with final-scored committed outcomes on completion or budget interruption. Interrupted scans
never commit provisional winners; final rescoring alone does not count as final-objective ascent.
Task 11.5a adds private lazy empty/single mutable seed generation with dense local indices.
Task 11.5b adds private ordered independent known-scrambler seed climbs with one shared
allowance and stable final-score selection, including interrupted committed boards.
Outer scheduling, public runtime APIs and CLI execution remain unimplemented.

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
loads and binds resources, then returns `unsupported_job`; core attacks do not run.
[Protocol](protocol.md) and [scoring/resources](scoring-resources.md) remain normative.
This document specifies only `hill_climb` and `partial_exhaustion`, not lifecycle,
wire results, progress, cancellation, checkpoints, other passes or variants.

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
the budget, timeout heuristic, cancellation or new wire event is specified.

## 7. Minimal core result, examples and limits

The internal run result contains termination (`completed`, `outer_slice_end`, or
`evaluation_budget`), evaluations used, outer candidates completed, climbs started
and completed, and an optional best committed board with resolved initial slot
key, plaintext, final measured/ranking score, absolute outer index and seed/start
index. A climb interrupted by budget is not completed. An outer candidate is
completed only after all its climbs finish. Eligible final-scored committed boards
include the interrupted climb's board, marked incomplete; ties select lowest
(outer index, seed/start index). No hold capacity or JSONL payload is defined.
Per-climb outcome records whether final-objective ascent occurred and whether its
legal neighborhood was fully exhausted; final rescoring alone is not optimization.
Runtime scoring/invariant errors fail explicitly, not as a termination or sentinel.

These are **valid planned search-job fragments**, completed by protocol root
`protocol_version: 1` and bundled `machine.definition` for `enigma-i`. They are
not known-answer vectors. Direct Core attack parsing, binding and eligibility checks
validate them; public root dispatch and CLI/runtime execution remain unsupported.

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
Duet/quartet, DFS, mutable fixed facts, additional attacks and CLI execution remain
out of scope; lifecycle/result transport and differential oracle remain later tasks.
