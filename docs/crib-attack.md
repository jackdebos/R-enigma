# Crib attack contract — Stage 3

Status: **Core, CLI and web implemented.** This document specifies the `bombe` attack:
the user supplies a crib (a plaintext fragment believed to be in the message); the
engine drags it along the ciphertext, runs a deductive Turing-Welchman bombe on every
declared outer key and admissible crib position, and finishes every stop with the
existing hill climb, the stop's deduced plugboard facts fixed.
[Protocol](protocol.md), [search passes](search-passes.md) and
[scoring/resources](scoring-resources.md) stay normative except where this document
extends them.

Basis: the crib pipeline of current Enigma projects (crib dragging with the crash
rule, menu, bombe with the diagonal board, stops, finishing climb with the deduced
pairs locked and the right ring tried) and Ostwald & Weierud, *Modern breaking of
Enigma ciphertexts*, Cryptologia 41(5), 2017. Ciphertext-only attacks are unchanged.

## 1. Request

The crib attack is a new pass on the attack branch of
[search passes §1](search-passes.md#1-two-domain-branches-no-implicit-unknown-key):
`job.space.plugboard.kind` is `"attack"` and the wire kind stays `"search"`.

```json
"passes": ["bombe"],
"attack": {
  "kind": "bombe",
  "crib": {"text": "WETTERVORHERSAGE", "position": 0},
  "initial_measure": "ic",
  "final_measure": "sinkov_trigram",
  "switch_pairs": 7,
  "backtrack_pairs": 5,
  "hold": 20
}
```

- `job.passes` starts with exactly one `bombe`, optionally followed by the chained
  stages of [search passes §9](search-passes.md#9-chained-stages); the §9.1
  shape gains `bombe` as a third leading pass. Hold, stages, `progress_every` and
  their defaults keep their [§2](search-passes.md#2-one-executable-pass-and-explicit-settings)
  and [§10](search-passes.md#10-hold-list) meaning.
- `job.attack.kind` equals `"bombe"`. `initial_measure`, `final_measure`,
  `switch_pairs` and `backtrack_pairs` configure the finishing climb (§5) exactly as
  for `hill_climb`. `start` and `seeds` are forbidden members (`invalid_request`):
  every finishing climb starts from the stop's facts (§5).
- `crib` is required, an object with exactly `text` and optional `position`:
  - `text`: nonempty string of runtime-alphabet symbols, one crib per request.
    The engine does not normalize: no case folding, no space removal. The web
    does not either: like the message, the crib is sent as typed and the user
    converts it with an uppercase button.
  - `position`: optional nonnegative integer, the 0-based index in `job.text` of the
    crib's first symbol. Omitted means every admissible position (§2).
- Any crib length is accepted. Short cribs produce many false stops and long runs;
  the result reports the stop count (§7) and clients may warn.

Validation, before `started`, as seq1-only `error` events:

| Condition | Code | Pointer |
| --- | --- | --- |
| `crib` missing, not an object, `text` missing or not a string | `invalid_request` | `/job/attack/crib` (or member) |
| `start` or `seeds` present with `kind: "bombe"` | `invalid_request` | the member |
| Unknown member of `crib` | `unknown_field` | the member |
| `text` empty or a symbol outside the alphabet | `invalid_search_space` | `/job/attack/crib/text` |
| `text` longer than `job.text` | `invalid_search_space` | `/job/attack/crib/text` |
| `position` not a nonnegative integer, or `position + len(crib) > len(text)` | `invalid_search_space` | `/job/attack/crib/position` |
| `position` crashes (§2) | `invalid_search_space` | `/job/attack/crib/position`, message names the first crashing index |
| No admissible position | `invalid_search_space` | `/job/attack/crib` |
| A candidate machine without a reflector, or with a reflector that maps a symbol to itself | `unsupported_topology` | `/machine` |

The last rule keeps the crash rule (§2) sound. Enigma I, M3 and M4 qualify.

## 2. Crib dragging

Let `T` be `job.text` (the ciphertext, length `n`) and `K` the crib (length `m`).
Position `p` (0 <= p <= n - m) is **admissible** when no crib symbol equals the
ciphertext symbol under it: `K[j] != T[p + j]` for every `j`. A reflector machine
without reflector fixed points never encrypts a symbol to itself, so an inadmissible
position cannot be the true one. With `position` set, the run tests that position
only. Otherwise it tests every admissible position in ascending order. The positions
are computed once, before `started`.

## 3. Menu

At position `p` the crib gives `m` edges `(K[j], T[p + j])`, each labeled with its
text index `i = p + j`. The **menu** is the undirected multigraph of these edges over
the symbols. It splits into connected components. In each component the **test
symbol** is the symbol with the most edges, ties going to the earliest alphabet
symbol.

Menus depend only on the position, so Core builds them once, before `started`, and
shares them across settings, as long as all of them together are estimated to fit in
64 MiB. A longer text with a long crib can admit more menus than that. Then Core
keeps none and rebuilds each position's menu where it is used. The menus, stops,
counters, order and checkpoints are the same either way; only the speed differs.

## 4. Bombe test on one setting

A **setting** is one resolved outer key of the declared space (every slot's wheel,
position and ring, as in [search passes §3](search-passes.md#3-pre-execution-gates-and-outer-order))
plus one admissible crib position. `S_i` is the board-free scrambler permutation at
text index `i` for that outer key (the involution the machine applies between the two
plugboard passes, with the real stepping, including the middle-rotor double step).
The machine encrypts `x` as `P(S_i(P(x)))`, where `P` is the plugboard involution, so
every edge `(k, c)` at index `i` requires `S_i(P(k)) = P(c)`.

**Facts.** The known pairs `configuration.plugboard` are fixed. A symbol that is
neither a fixed endpoint nor in `space.plugboard.symbols` is self-connected (search
passes §1). Pairs among the mutable symbols are unknown, and the total board size is
at most `max_pairs`.

**Stop (declarative, normative).** A setting is a **stop** exactly when some complete
admissible board `B` (all facts held, at most `max_pairs` pairs) makes the machine
encrypt the crib at `p` into `T[p .. p+m]`. This is the exactness contract: the true
key at the true position is always a stop, and implementations must return exactly
the stops this definition gives. Shared work, deduplication or ordering shortcuts
must not change the stop set.

**Algorithm (informative).** For each component and each candidate partner `y` of
its test symbol (only the known partner when facts fix it), set `P(test) = y` and
propagate through the component's edges: a known `P(k)` forces `P(c) = S_i(P(k))`,
and a known `P(c)` forces `P(k) = S_i(P(c))`. Every assignment is kept symmetric
(`x -> y` implies `y -> x`), which is the effect of Welchman's diagonal board. A
symbol forced to two different partners, a broken fact or an overfull board
contradicts `y`. Because the component is connected, a consistent `y` determines `P`
on every symbol of the component. The setting is a stop when one consistent closure
per component can be chosen with the chosen closures mutually consistent and within
`max_pairs`; symbols outside every closure may stay self-connected.

**Deduced facts of a stop.** These are the assignments of every component that has
exactly one consistent closure. Each such assignment holds in every board that
satisfies the stop, so fixing it never excludes a solution. A deduced pair `x-y` is
added to the fixed pairs; a deduced self-connection `x-x` removes `x` from the mutable
symbols. Components with several consistent closures deduce nothing; the finishing
climb resolves them.

## 5. Finishing climb

Every stop runs one finishing climb on its outer key. The climb domain is the request
domain plus the deduced facts (§4): the deduced pairs are fixed and the deduced
self-connections leave the mutable symbols. `max_pairs` is unchanged. The climb is
exactly the `hill_climb` of search passes §5–§6 with `start: []`, the request's
measures and thresholds, on the full `job.text`. It offers its committed board to the
hold (§10.2) like any climb. The deduced facts stay fixed: the climb never removes
them. Chained stages then run on the hold as in §9 and §10.5, and reswapping keeps
the fixed pairs fixed.

Several right rings (and positions) give the same scrambler over the crib window and
differ only where the middle rotor steps. Each is its own outer key, so each stop is
climbed and scored on the full text. This is how the ring is found: the true ring
scores best because its stepping decrypts the whole message.

## 6. Order, counting and determinism

Settings are enumerated by outer index ascending (the existing outer order, after
`distinct_wheels`), then by admissible position ascending. The enumeration index of a
finishing climb is the pair (`outer_index`, `start_index`), with `start_index` the
rank of its crib position among the admissible positions. The hold order, ties and
duplicate rules of §10.3 apply unchanged. Results are identical for every thread
count and for interrupted-and-resumed runs.

Counters (checked `u64`, additive to the §6.1 counters): `bombe_settings` (settings
tested) and `bombe_stops` (stops found). Finishing-climb evaluations count as HC
evaluations do today.

## 7. Progress, result, report

- Progress events keep their shape and add `bombe_settings` and `bombe_stops`.
- `result` adds a `crib` object: `text`, `positions` (the admissible positions
  tested, ascending), `settings` and `stops`. Each `best`/`hold` entry adds
  `crib_position`, the position its stop came from. Other fields keep their meaning.
- The human report shows the crib, how many positions were tested (listing the
  0-based positions when there are at most 10), settings and stops, then the
  finalists as today, each with its `Crib position`. See
  [protocol §2.4](protocol.md#24-reports) for the layout.

## 8. Control

Cancellation, signals, `--threads` and the cancel file behave as for HC
([protocol §5](protocol.md#5-control)). Checkpoints use the outer-block cursor of
[protocol §6](protocol.md#6-checkpoint-and-resume). The crib is part of the job,
so it is part of the checkpoint identity; the counters of §6 are saved and restored.
On a runtime error the hold keeps the stops of earlier outers and the earlier stops of
the failing outer, and the counters include the failing outer's partial work; when
outer-completion accounting overflows, that outer's offers are discarded with it. No
checkpoint is written for the failing block ([search passes §10.2](search-passes.md#102-entry-rule),
[protocol §4.1](protocol.md#41-hcpe-search-events)).
`--backend gpu` with a `bombe` job fails before work with `backend_unavailable`,
at `/job/attack`, with message `GPU backend unavailable: the crib attack runs on the CPU only`
and exit 1; there is no silent CPU fallback. A GPU bombe is later work.

## 9. Web

The attack page method choice gains the crib attack. Choosing it shows:

- a crib field with the message's exact-text rule: nothing is converted
  automatically, an uppercase button is offered, and symbols outside the alphabet
  (spaces included) are an error shown before launch;
- an optional position field;
- a warning when the crib has fewer than 14 letters;
- a default ring domain with the right ring unknown and the other rings at A,
  editable in the advanced settings.

The GPU backend option is unavailable for the crib attack. Results show the crib
summary (positions, settings, stops) and each finalist's crib position. Texts are in
Spanish and English.

## 10. Non-goals

- Several cribs per request (run one request per crib).
- The corpus crib finder (later task).
- A GPU bombe (later, with GPU parity).
- Partial exhaustion as the finishing search (the finishing climb is `hill_climb`).
- Machines without a fixed-point-free reflector.
