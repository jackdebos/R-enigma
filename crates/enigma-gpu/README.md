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
let options = ExecutionOptions::with_threads(6)?.with_accelerator(&gpu);
// request.run_with_checkpoints(options, observe, cancel, checkpoint)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Construction distinguishes unavailable adapters, missing `SHADER_INT64`, invalid
options and device failures. `supports_job` returns a typed unsupported reason.
Core invokes `check_job` before row preparation or progress. Runtime failures
become `AcceleratorError`, stopping the attack without switching backends.
CLI/web wiring, the full design-B timing tool and R3's device-free job-only oracle
are deliberately outside this Stage A implementation.

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
- Core calls contain at most 128 keys; hardware batches contain at most four.
  Small devices can reduce that further. Uploads contain only the active batch.

## Resumption and display sharing

Each 128-lane workgroup owns one key. A dispatch processes at most `scan_budget`
scan slices per key. A slice visits at most `clamp(8192 / text_length, 1, 128)`
lexicographic symbol pairs, each emitting at most four trials. Thus even an
unfinished neighborhood can yield; no provisional winner is committed early.

The persistent state has a 64-byte header, an alphabet-wide u32 mapping, and an
alphabet-wide ordered-pair array (one packed pair per word). Its header retains
current/best i64 scores, u64 evaluations, pair count, phase, ascent flag,
initialization/done flags, scan cursor, best ordinal and ordered-board length.
The `(score, ordinal)` reduction retains only metadata; the winning action is
replayed once. This avoids an alphabet-wide board per reduction lane in LDS.

Rows use an LDS cache only when they fit the device's workgroup storage allowance
and a 16-KiB cache ceiling; otherwise decoding reads packed global storage.
Weights always remain in global storage. Pipelines specialize only alphabet width
and row-cache geometry, not objectives or climb decisions.

After **every** dispatch, including the last, the host sleeps for
`elapsed * (100 - usage) / usage`. `elapsed` measures submit through completion,
readback and error checks, not hardware timestamps. It includes host/driver
scheduling, so the resulting percentage is a conservative wall-time proxy, not a
hardware-utilization promise. `dispatch_stats` exposes work, idle and maximum
dispatch wall times. Pipeline creation is outside these measurements.

The bounded work is intended to keep dispatches to a few milliseconds, but is not
a real-time guarantee for arbitrary devices/jobs. Stage B must measure full
U-264 performance and any short-dispatch speed cost before considering another
execution mode; this crate provides no unlimited mode.

## Verification

`cargo test --workspace` runs small GPU differential cases at 25% and 20% usage,
with budgets 1 and 2, when a suitable adapter exists. Otherwise it writes a visible
skip notice directly to stderr. Other initialization/runtime failures fail tests.
The matrix checks every key's ordered board, score, evaluations and ascent flag,
then full CPU/GPU results, progress and checkpoints, plus cross-backend resume and
an injected host score fault. It covers 4/26-symbol alphabets, orders 1-6, switching,
backtracking, fixed pairs, masks, capacity, starts, plateaus, global rows and a
261-key range with a tail. Device-free tests check configuration and job limits.
