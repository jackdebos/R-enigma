# Exact GPU outer climbing

`enigma-gpu` implements core's `ClimbAccelerator` with wgpu 29. Core retains
CPU row preparation, ordered commits, progress, checkpoints and finalist stages.
There is no approximate scoring or silent CPU fallback.

## Use

```rust,no_run
use enigma_core::ExecutionOptions;
use enigma_gpu::GpuClimbAccelerator;

// Usage percentage 1-100; scan-slice budget 1-4. Tests use low percentages.
let gpu = GpuClimbAccelerator::new(25, 1)?;
let options = ExecutionOptions::with_threads(6).ok_or("invalid threads")?.with_accelerator(&gpu);
// request.run_with_checkpoints(options, observe, cancel, checkpoint)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Construction distinguishes unavailable adapters, missing `SHADER_INT64`, invalid
options and device failures. `supports_job` returns a typed unsupported reason.
Core invokes `check_job` before row preparation or progress. Runtime failures
become `AcceleratorError`, stopping the attack without switching backends.
CLI/web wiring remains separate. The `timing` example exercises the real core
executor, and `ClimbJob::climb_from_projection` is a hidden device-free oracle
that consumes job fields and rows without following the private request owner.

## Exactness and limits

- Alphabets contain 1-256 symbols. Text is bounded by device buffer limits, the
  core 512-KiB-per-key row policy, and a conservative 1,000,000-symbol ceiling.
- Objectives are IC or dense i64 n-grams of any representable order. Tables must
  fit a storage binding and u32 indexing; every window sum must fit i64.
  IC uses exact Q32 long division, avoiding an overflowing shifted numerator;
  n-gram division floors negative scores instead of truncating.
- Fixed pairs, mutable masks, pair capacity, backtracking, one-way switching and
  nonempty starts are honored. Every emitted trial counts, including duplicates.
  Strict improvement and earliest-ordinal ties follow the CPU walker.
- An untouched start retains its supplied pair order and orientation. A committed
  winner uses the walker's canonical alphabet-index order, with fixed pairs omitted.
- Core calls and hardware batches contain up to 512 keys (one 128-thread
  workgroup each), exposing enough key-level parallelism for all 36 RX 580 CUs.
  Core's 64-MiB row cap and device limits can reduce that; tails may be smaller.
  Uploads contain only the active batch. Four workgroups in Stage A were a
  conservative safety setting, not four keys per compute unit.

## Resumption and display sharing

Each 128-lane workgroup owns one key. A dispatch processes at most `scan_budget`
scan slices per key. The base slice is `clamp(8192 / text_length, 1, 128)`
lexicographic symbol pairs; the effective slice is `max(base / scan_budget, 1)`.
Each pair emits at most four trials, distributed across lanes by action ordinal.
Increasing the slice count therefore does not create a long-dispatch mode.
Even an unfinished neighborhood can yield; no provisional winner commits early.
U-264 uses 512 keys, budget 1 and 35 pairs per slice.

The persistent state has a 64-byte header, an alphabet-wide u32 mapping, and an
alphabet-wide ordered-pair array (one packed pair per word). Its header retains
current/best i64 scores, u64 evaluations, pair count, phase, ascent flag,
initialization/done flags, scan cursor, best ordinal and ordered-board length.
The `(score, ordinal)` reduction retains only metadata; the winning action is
replayed once. This avoids an alphabet-wide board per reduction lane in LDS.

Rows use an LDS cache only when they fit the device's workgroup storage allowance
and a 16-KiB cache ceiling; otherwise decoding reads packed global storage.
Weights always remain in global storage. Alphabets up to 32 symbols use scalar,
byte-packed private mappings; wider alphabets keep array mappings. Histograms
also pack only when text length is <=255, where byte counts cannot overflow.
Pipelines specialize these storage choices, not objectives or climb decisions.
Already-finished keys return before loading their rows again.

After **every** dispatch, including the last, the host sleeps for
`elapsed * (100 - usage) / usage`. `elapsed` measures submit through completion,
readback and error checks, not hardware timestamps. It includes host/driver
scheduling, so the resulting percentage is a conservative wall-time proxy, not a
hardware-utilization promise. `dispatch_stats` exposes work, idle and maximum
dispatch wall times. Pipeline creation is outside these measurements. Optional
`with_dispatch_observer` instrumentation receives individual durations and geometry;
the timing tool owns its sample collection, so ordinary runs retain no sample log.

The bounded work is intended to keep dispatches to a few milliseconds, but is not
a real-time guarantee for arbitrary devices/jobs. Any measured speed cost must
be considered before another execution mode; this crate provides no unlimited mode.

## Verification

`cargo test --workspace` runs small GPU differential cases at 25% and 20% usage,
with budgets 1 and 2, when a suitable adapter exists. Otherwise it writes a visible
skip notice directly to stderr. Other initialization/runtime failures fail tests.
The matrix checks every key's ordered board, score, evaluations and ascent flag,
then full CPU/GPU results, progress and checkpoints, plus cross-backend resume and
an injected host score fault. It covers 4/26/34-symbol alphabets, orders 1-6,
switching, backtracking, fixed pairs, masks, capacity, starts, plateaus, global rows
and a 773-key range with a tail. Device-free tests check configuration/job limits
and compare the projection-only oracle with CPU results, progress and checkpoints.
The latter deliberately supplies an unrelated request owner to catch accidental
private-link use; it reuses the validated production neighborhood walker.

## Full timing (not a test)

```sh
cargo run --release -p enigma-gpu --example timing -- --tune
cargo run --release -p enigma-gpu --example timing
```

`--tune` checks 512 keys at 25% usage with budgets 1, 2 and 4. The default runs
all 17,576 design-B keys through `AttackRequest::run_with`, with six CPU/preparation
threads: CPU once, GPU at 100% once and GPU at 50% once, budget 1. All hold/finalist
stages are included. Parsing, device setup and 128-key warmups are excluded.
Every `AttackResult` field is compared via its derived Debug representation
(the type does not implement `PartialEq`). It reports wall time, dispatch count,
maximum and median host dispatch duration, and the historical L25 references.
The example converts the checked-in trigram table in memory, like the spike;
it writes no converted resource or scratch files.

### RX 580 measurement (Stage B)

Single release sample per configuration, all 17,576 keys; whole-result equality
passed at both usage percentages. CPU-6 wall time was **15.395346209 s**.

| Usage | GPU wall | Dispatches | Maximum dispatch | Median dispatch |
| --- | ---: | ---: | ---: | ---: |
| 100% | 16.722646321 s | 7340 | 7.492814 ms | 2.260000 ms |
| 50% | 32.025874485 s | 7340 | 8.106128 ms | 2.237662 ms |

Chosen geometry: **512 keys, budget 1, 35 pairs/slice**, with a smaller final
batch. The maximum includes readback and host scheduling; the 50% sample is
slightly above 8 ms, so this is an approximately-8-ms target, not a hard deadline.
An earlier 512-key/budget-2/35-pair setting was exact but rejected for latency:
100% wall 15.300024796 s, max 9.493541 ms; 50% wall 29.091004084 s, max 9.621174 ms.

The selected 100% run is **3.457x the L25 spike's 4.837 s**, and slower than the
current six-thread CPU (0.921x speedup). At 50% it is 6.621x the spike. This is
an observed end-to-end cost, not an isolated short-dispatch penalty: the product
also has generalized scoring/state, core guards/commits and finalist stages;
the spike omitted the latter stages. The historical CLI reference was 14.888 s.
The speed trade-off needs the user's decision before any unlimited mode is added.
