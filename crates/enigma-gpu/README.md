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
The CLI includes this backend unconditionally: select `--backend gpu` and optionally
`--gpu-usage N` (1-100, default 100); CPU is the default. Web wiring remains separate.
The `timing` example exercises the real core
executor, and `ClimbJob::climb_from_projection` is a hidden device-free oracle
that consumes job fields and rows without following the private request owner.

## Exactness and limits

- Alphabets contain 1-256 symbols. Text is bounded by device buffer limits, the
  core 512-KiB-per-key row policy, and a conservative 1,000,000-symbol ceiling.
- Objectives are IC, entropy or dense i64 n-grams of any representable order. Tables must
  fit a storage binding and u32 indexing; every window sum must fit i64.
  IC uses exact Q32 long division, avoiding an overflowing shifted numerator;
  n-gram division floors negative scores instead of truncating.
- Entropy needs no logarithm on the device: the host tabulates core's exact term
  `c * (B(N) - B(c))` for every count `c` (`entropy_terms`), split into a high word
  and a 16-bit low word. The kernel sums both from the symbol histogram and uses
  `floor((highs + (lows >> 16)) / N)`, equal to the CPU's `floor(sum / (N * 2^16))`.
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
scan slices per key. The base slice is `32 * clamp(1024 / text_length, 1, 4)`
lexicographic symbol pairs (about 1024 decoded letters per lane and slice); the
effective slice is `base / scan_budget`, rounded down to a multiple of 32 when it
is at least 32, and never below 1. A full 128-pair slice gives each lane one whole
pair and its up to four actions, so add-only scans (only action 0 is legal) do not
idle three of four lanes. Smaller slices give each lane one action slot, so 32
pairs fill a 128-lane round. Either way a lane evaluates about four trials per
slice, so a larger slice count does not create a long-dispatch mode. Ordinals and
the reduction are unchanged by the lane layout.
Even an unfinished neighborhood can yield; no provisional winner commits early.
U-264 uses 512 keys, budget 1 and 128 whole-pair lanes per slice.

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
Pipelines are also specialized per immutable job shape and cached for the
accelerator's lifetime: text length, initial/final objective orders (so radix,
window count and the phase branch fold), identical objectives, slice size and lane
layout, and whether any symbol is fixed or immutable (otherwise mask reads are
skipped). Scores, thresholds and climb decisions are computed exactly as before;
a new job shape costs one pipeline compilation outside dispatch timing.
Already-finished keys return before loading their rows again.

Climb state stays in GPU memory for the whole batch. After each dispatch the host
reads back only a 4-byte count of finished keys, which each workgroup increments
once when its climb stops; full terminal states are read once, after the batch
finishes. A batch is the whole core call when it fits (512 keys for U-264).

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
maximum, p99 and median host dispatch duration, and the historical L25 references.
The example converts the checked-in trigram table in memory, like the spike;
it writes no converted resource or scratch files.

### RX 580 measurement (after L34 optimization)

Single release sample per configuration, all 17,576 keys; whole-result equality
passed at both usage percentages. CPU-6 wall time in the same invocation was
**17.130141836 s** (CPU-6 samples range 14.9-17.1 s across invocations on this machine).

| Usage | GPU wall | Dispatches | Maximum dispatch | p99 dispatch | Median dispatch |
| --- | ---: | ---: | ---: | ---: | ---: |
| 100% | 4.240908921 s | 2202 | 5.486316 ms | 3.733956 ms | 0.997150 ms |
| 50% | 7.800849360 s | 2202 | 6.305153 ms | 3.152401 ms | 1.174326 ms |

Chosen geometry: **512 keys, budget 1, 128 whole-pair lanes per slice**, with a
smaller final batch. `--tune` (512 keys, 25%) was exact with budgets 1, 2 and 4
(maximum 3.2-3.7 ms). Maximums include readback and host scheduling; this is an
approximately-8-ms target, not a hard deadline. Interleaved repeat samples and
rejected settings are in `DIAGNOSIS.md`.

At 100% the GPU run is about 3.5-4.0x the six-thread CPU and 0.88x the L25 spike's
4.837 s, while including finalist stages and core commits that the spike omitted.
The earlier Stage B setting (512 keys, 35-pair action-slot slices, no job
specialization, full-state readback per dispatch) took 16.722646321 s at 100%
(7340 dispatches, maximum 7.492814 ms) and 32.025874485 s at 50%.
No asynchronous or unlimited mode exists; see `DIAGNOSIS.md` for why it was not added.
