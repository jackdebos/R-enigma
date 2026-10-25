# U-264 GPU slowdown diagnosis at `766a5ab`

**Most of the regression is GPU work caused by small scan tiles, not CPU row
preparation or finalists.** Host synchronization is a significant second cost.
The measurements below this first section describe `766a5ab`; all temporary
instrumentation was removed after them. The first section records the L34
follow-up ("Optimizar con pantalla fluida"), which implemented options 1, 3 and 4.

## L34 follow-up: short-dispatch optimizations

Same machine and tool (`cargo run --release -p enigma-gpu --example timing`), usage
100%, all 17,576 keys. Every row matched the CPU's whole `AttackResult`. Sweeps
used a temporary geometry override and a 100%-only switch, both removed. Where two
binaries are compared, runs were interleaved because samples drift by about 5%
(CPU-6 ranged 14.9-17.1 s). The kept rows are cumulative.

| Step | Wall | Dispatches | Maximum | p99 | Median | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline `b4cc751` (512 keys x 35-pair action slots) | 16.646 s | 7340 | 7.44 ms | 4.33 ms | 2.26 ms | reference |
| 1a action slots, 256 x 64 / 256 x 128 / 128 x 128 | 11.77 / 10.74 / 12.36 s | 8466 / 4233 / 8133 | 7.08 / 7.18 / 5.97 ms | 2.57 / 4.29 / 2.83 ms | 1.35 / 2.47 / 1.33 ms | superseded by 1b |
| 1a action slots, 256 x 70 / 384 x 48 / 512 x 32 / 256 x 96 | 13.51 / 14.38 / 11.76 / 11.14 s | 7055 / 9751 / 8074 / 5644 | 6.81 / 7.36 / 8.22 / 8.48 ms | 3.67 / 3.52 / 3.47 / 3.78 ms | 1.87 / 0.96 / 1.46 / 1.90 ms | rejected |
| 1a action slots, 512 x 64 | 10.45 s | 4404 | 11.39 ms | 4.20 ms | 2.42 ms | rejected: latency |
| 1b whole-pair lanes, 256 x 128 | 9.545 s (A/B 9.12-9.65 s) | 4233 | 7.41 ms | 4.06 ms | 1.68 ms | **kept** |
| 1b whole-pair lanes, 512 x 128 (before step 3) | 8.18 s | 2202 | 9.93 ms | 7.25 ms | 2.38 ms | rejected: latency |
| 1b whole-pair lanes, 320 / 384 x 128; 256 x 192 | 9.41 / 9.45 / 10.88 s | 4212 / 4179 / 2822 | 8.21 / 8.90 / 9.88 ms | 4.80 / 5.46 / 7.40 ms | 1.68 / 1.52 / 3.02 ms | rejected |
| 2a call-resident state + 4-byte atomic count, 256 keys | 9.98-10.06 s vs 9.49-9.63 s | 4233 | 7.40-8.24 ms | 4.26-4.32 ms | 1.74-1.76 ms | rejected: slower |
| 2b call-resident state + per-key done words, 256 keys | 9.69-10.00 s vs 9.12-9.50 s | 4233 | 7.45-9.08 ms | 4.54-4.60 ms | 1.70-1.76 ms | rejected: slower |
| 3 immutable-job pipeline specialization, 256 x 128 | 5.561 / 5.639 s vs 9.624 / 9.651 s | 4233 | 6.03 / 5.25 ms | 2.88 / 2.85 ms | 0.88 / 0.89 ms | **kept** |
| 3 + geometry 512 x 128 | 4.104 s | 2202 | 5.93 ms | 3.71 ms | 0.99 ms | **kept** |
| 3 + geometry 512 x 256 / 384 x 128 / 256 x 256 | 3.94 / 5.21 / 5.18 s | 1468 / 4179 / 2822 | 6.73 / 5.85 / 9.81 ms | 5.34 / 3.07 / 3.96 ms | 1.60 / 0.80 / 1.36 ms | rejected: p99/latency or slower |
| 2c per-batch 4-byte atomic count, 512 x 128 (4 interleaved pairs) | mean 4.080 s vs 4.129 s | 2202 | 5.53-7.28 ms | 3.54-3.79 ms | 0.94-0.96 ms | **kept** (dispatch work 3.23 s vs 3.32 s, lower in 4/4) |
| Final, default tool run | **4.241 s** (50%: 7.801 s) | 2202 | 5.49 ms (50%: 6.31 ms) | 3.73 ms | 1.00 ms | result |

- Whole-pair lanes (1b) are the main tiling gain. In the climb's add-only scans
  (fewer than `backtrack_pairs` pairs), only action 0 is legal, so action-slot
  lanes are mostly idle. Lane-per-pair is used only for full 128-pair slices;
  smaller slices (long texts, budgets above 1) keep action slots, so a lane still
  evaluates about four trials per slice.
- Specialization (step 3) halved GPU time at unchanged geometry. It made 512-key
  dispatches short enough for the target; `keys_per_dispatch` is now the whole
  512-key core call. Core caps calls at 512 keys (R4), so larger dispatches were
  not tried.
- Minimal readback did not help while a call spanned two 256-key batches with a
  call-resident state buffer (both 2a and 2b were about 0.5 s slower; the cause was
  not isolated). With one batch per call, the per-batch 4-byte count variant
  measured slightly faster and was kept.
- Option 2 (bounded asynchronous submission) was **not implemented**. Single
  dispatches already peak at 5.5-7.3 ms, so two in flight could form bursts of
  about 11-15 ms, above the ~8-ms target. The remaining host gap is at most
  wall minus dispatch work, about 0.9 s, much of it core executor work.
- Fault checks: forcing `MASKED` false, or dropping action 3 in whole-pair lanes,
  fails the device differential test.


## Measurements

RX 580 / RADV POLARIS10, release build, all 17,576 U-264 design-B keys, six
CPU/preparation threads, usage 100%. Each row is one sample. Every run matched
the CPU's whole `AttackResult` through its derived Debug representation.

| Geometry, up to 512 keys/batch | Wall | Dispatches | GPU compute timestamps | Host dispatch/readback sum | Maximum dispatch | Median dispatch |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Current: 35 pairs, budget 1 | 16.921465771 s | 7340 | 12.951961920 s | 15.953298515 s | 7.852479 ms | 2.296817 ms |
| Diagnostic: 35 pairs, budget 10001 | 12.447400643 s | 35 | 11.342924160 s | 11.366916424 s | 353.692611 ms | 329.264614 ms |
| Diagnostic: 325 pairs, budget 10000 | 8.060681105 s | 35 | 6.565474880 s | 6.593364932 s | 208.486587 ms | 190.943719 ms |

The large budgets are upper bounds: every workgroup stopped when its key finished.
The 35-dispatch runs completed each batch's climbs in one dispatch. The 35-pair
variant retains the current internal scan slicing; the 325-pair variant performs
one full neighborhood scan per loop, like the spike. The CPU-6 references were
14.492813870 s for the first/third rows and 14.367871661 s for the second row.

Historical L25: spike total 4.837 s, resident climb 4.688 s; CLI 14.888 s.
Even without external slicing, the generic full-scan kernel's compute is about
1.40x that historical resident-climb time. Its 8.061-s executor wall is 1.67x the
spike's total, not the 3.50x of the instrumented short-dispatch run.

### Where the difference goes

- Removing external dispatch boundaries, **without changing 35-pair internal
  slices**, saves 1.609037760 s of GPU compute and about 2.977 s of additional
  host/copy/scheduling gap. Wall improves by 4.474065128 s.
- Changing the internal slices from 35 to 325 pairs, with the same 35 external
  dispatches, saves another **4.777449280 s of GPU compute**.
- Current dispatch wall minus GPU compute is 3.001336595 s, about 408.9 us per
  dispatch on average. This is not all CPU execution: it includes transfers,
  queue scheduling, mapping and idle gaps. CPU phase clocks and GPU timestamps
  overlap; do not add the GPU duration to the wait duration below.

## Host dispatch and state traffic

A minimal 512-workgroup no-op pass used the same submit/poll/map/CPU-copy path and
error scopes, with ten warmups and 200 measured iterations per size. It idled for
three times the elapsed duration after each iteration to avoid hammering the GPU.

| Readback per iteration | Mean | Median | Maximum |
| --- | ---: | ---: | ---: |
| 4 bytes | 127.170 us | 82.823 us | 908.551 us |
| 139,264 bytes | 162.573 us | 111.799 us | 1.088887 ms |

The minimal full-state mean extrapolates to about 1.19 s over 7340 dispatches;
this is an estimate/lower-load baseline, not an exact additive decomposition of
the busy run. The payload-size difference extrapolates to only about 0.26 s.

In the busy sliced run, host phase sums were: encoding 232.917215 ms, submission
560.203419 ms, wait/map 15.015986753 s (including GPU execution), and CPU state
copy/timestamp decoding/unmapping 124.693423 ms. The remaining roughly 19.5 ms
inside dispatch timing covers scopes, health checks and other small overhead.

State is `(16 + 2*26)*4 = 272` bytes/key: **139,264 bytes (136 KiB)** for 512 keys,
or 45,696 bytes for the final 168-key batch. Current slicing read back exactly
**1,004,419,840 bytes**; the 35-dispatch variants read back 4,780,672 bytes.
Diagnostics additionally read 16 timestamp bytes per dispatch, excluded from
those state-byte counts. A per-key done-only read would be 2048 bytes for a full
batch; one aggregated flag would be four bytes. Smaller payloads alone cannot
recover the multi-second GPU compute loss.

## Executor outside the accelerator

Temporary timers surrounded receiver waits, row concatenation, accelerator calls,
terminal rebuild/rescore, block commits and finalist stages.

| Component | Current short dispatches | Whole climb / full scan |
| --- | ---: | ---: |
| Sum inside `ClimbAccelerator::climb` | 16.089073933 s | 6.781214422 s |
| Wall outside those calls | 0.832391838 s | 1.279466683 s |
| Waiting for prepared rows | 50.701765 ms | 48.825927 ms |
| Row concatenation | 32.759310 ms | 87.158253 ms |
| Terminal rebuild, rescore guard and accounting | 451.157393 ms | 658.598971 ms |
| Ordered block commit callbacks | 151.219749 ms | 266.520525 ms |
| All five finalists' stages | 2.419006 ms | 3.289023 ms |
| Producer preparation batch wall sum, overlapped | 1.661406437 s | 1.588378556 s |

Preparation overlaps accelerator execution; its sum must **not** be added to the
wall breakdown. Unclassified outer-driver bookkeeping/allocation/scheduling is
about 144 ms / 215 ms respectively. Clock/load variation is visible between
runs. Neither row waits nor finalists explain the regression. The S29 rescore
guard remains required; removing it is not a proposed shortcut.

## Kernel differences and likely causes

Compared with `spikes/gpu-scoring/src/climb.wgsl`:

- **LDS rows already work.** Both kernels cache U-264's 6032-byte rows. Both keep
  the 140,608-byte trigram weights in global storage; that table exceeds RX 580's
  64-KiB LDS capacity. Adding LDS rows is not a missing optimization.
- Both use scalar-packed private mappings and byte histograms for this job.
  Product mappings have eight packed words versus the spike's seven. Product
  persistent/shared state also stores alphabet-wide map and ordered-board arrays;
  each slice reconstructs a private mapping with `load_board`.
- Product slices run a seven-stage reduction and synchronization for each tile,
  reload rows on each new dispatch for unfinished keys, and save/restore state.
  The spike caches once and retains its climb state for the entire climb.
- **Action-slot packing is inefficient at 35 pairs.** A scan has 1300 potential
  action slots. Nine 35-pair tiles plus a 10-pair tail require 19 rounds of 128
  lanes: 53.45% slot occupancy. A full scan requires 11 rounds: 92.33%. These are
  structural slot counts, not measured hardware utilization; illegal actions and
  divergence further affect active lanes. The spike instead strides pairs and
  emits their valid actions, so its early add-only scans avoid many invalid slots.
- Product objective order, rolling modulus/radix, switching/backtracking thresholds,
  masks and fixed flags remain runtime job data. The spike hard-codes trigram
  order, modulus 676, capacities and empty fixed/start boards. Runtime integer
  division/branches and repeated trial validation are plausible per-work costs.
- Product's reduction records are smaller (about 3 KiB declared candidate LDS versus
  the spike's 12 KiB array), so greater candidate LDS demand does not explain its
  slowdown. No hardware VGPR/spill/occupancy counters or display FPS were collected;
  register-pressure explanations remain hypotheses, not established measurements.

## Ranked options — proposals only

Gain ranges below are hypotheses bounded by these measurements, not promised or
additive speedups. Preserve exact integers, trial ordinals, evaluation counts and
ordered commits; rerun full differentials for any implementation.

| Rank | Option and estimated gain | Display effect | Exactness / implementation risk |
| --- | --- | --- | --- |
| 1 | Align tiles with action-lane capacity; try **256 keys x 64 pairs** instead of 512 x 35. Roughly similar aggregate pairs/dispatch, with 92.33% structural slot occupancy over a scan and six reductions rather than ten. Potentially recover 2-4 s of the measured 4.777-s internal-geometry loss. | Target stays a few ms by reducing keys rather than merely lengthening work; 256 groups still expose substantial CU parallelism. Must measure worst-case dispatches. | Low-medium: geometry should not change decisions, but uneven cursors/tails and reduction accounting require tests. |
| 2 | Keep a small, bounded number of short dispatches in flight; poll a done flag occasionally and read full state only at completion. Potentially recover 1-2.5 s of the roughly 2.98-s dispatch-boundary host gap. It will not remove the small-tile compute inefficiency. | Cap queued GPU time, not just command count. Two-four queued dispatches can form a longer burst; unbounded queueing could starve display work. Duty-cycle idling and cancellation/error latency need redesign. | Medium synchronization/lifecycle risk; no arithmetic approximation needed. Never commit before completion and CPU score verification. |
| 3 | Specialize immutable job constants (objective order/radix, length, empty fixed mask and thresholds), retaining the generic path. Tentatively 1-3 s on the sliced run; the full-scan generic-versus-historical-spike compute gap is about 1.88 s. Profile before predicting more. | Same or shorter dispatches at unchanged geometry. | Low-medium: high gain is plausible but unproven; specialization must preserve floor division, switches and all general cases. |
| 4 | Read only done flags each dispatch, without asynchronous submission. Estimated 0.1-0.3 s; easy first telemetry/memory reduction, not a cure for 16.9 s. | About unchanged or slightly shorter dispatches. | Low-medium buffer/synchronization risk; terminal full-state read remains mandatory. |
| 5 | Reduce allocation/duplication in terminal rebuild and commits, without removing the guard. Maybe 0.2-0.5 s; much lower priority than kernel geometry. | GPU dispatch lengths unchanged. | Medium if overlapped with later GPU work: preserve ordered events, checkpoint boundaries and error handling. |

Simply accepting longer GPU bursts trades away smoothness: the earlier 70-pair
budget-2 setting peaked near 9.6 ms, while these whole-climb experiments reached
208-354 ms (roughly 12-21 60-Hz frame intervals if nonpreemptive). Neither is a
new product mode. The user must decide before any such unlimited/long mode.

## Method and restoration

Commands were `cargo run --release -p enigma-gpu --example timing` twice, under
temporary instrumentation. The first invocation compared current slices with
whole/full scans and ran the minimal-pass benchmark; the second retained internal
35-pair slices inside a whole-climb dispatch. Compute-pass begin/end queries used
wgpu `TIMESTAMP_QUERY` and the queue timestamp period. The diagnostic feature,
large-budget exceptions, extra readbacks and executor timers were then removed.

Parsing, device/pipeline construction and 128-key warmups were outside timing,
matching the tool's normal boundary. Timestamp instrumentation adds query resolve,
a second 16-byte mapping and host clocks; the 16.921-s baseline is close to the
prior uninstrumented 16.723 s, but samples are not perfectly interchangeable.
The measurements are not GPU FPS traces or an isolated instruction profiler.
