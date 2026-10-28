//! Exact GPU outer climbing with bounded, resumable dispatches.
//!
//! `GpuClimbAccelerator::new` probes a device, requiring `SHADER_INT64`.
//! Core still owns preparation, ordered commits, checkpoints and final stages.
//! There is no CPU fallback. See the crate README for limits and timing semantics.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use enigma_core::{AcceleratedClimb, AcceleratorError, ClimbAccelerator, ClimbJob, ClimbObjective};
use wgpu::util::DeviceExt;

/// A missing capability, distinct from a device failure during execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GpuUnsupported {
    NoAdapter(String),
    MissingInt64(String),
    Job(String),
}

impl std::fmt::Display for GpuUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAdapter(reason) => write!(f, "no GPU adapter: {reason}"),
            Self::MissingInt64(name) => write!(f, "adapter {name} lacks SHADER_INT64"),
            Self::Job(reason) => write!(f, "unsupported GPU climb job: {reason}"),
        }
    }
}
impl std::error::Error for GpuUnsupported {}

/// Initialization, configuration, capability or runtime failure; never a fallback.
#[derive(Debug)]
pub enum GpuError {
    Unsupported(GpuUnsupported),
    InvalidUsage(u8),
    InvalidScanBudget(u32),
    Device(String),
}
impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(reason) => reason.fmt(f),
            Self::InvalidUsage(value) => write!(f, "GPU usage must be 1-100, got {value}"),
            Self::InvalidScanBudget(value) => {
                write!(f, "GPU scan budget must be 1-4, got {value}")
            }
            Self::Device(reason) => write!(f, "GPU device failure: {reason}"),
        }
    }
}
impl std::error::Error for GpuError {}
impl From<GpuError> for AcceleratorError {
    fn from(error: GpuError) -> Self {
        Self(error.to_string())
    }
}

/// Host submit through completion/readback durations, not GPU timestamp queries.
#[derive(Clone, Copy, Debug, Default)]
pub struct DispatchStats {
    pub dispatches: u64,
    pub work_time: Duration,
    pub idle_time: Duration,
    pub max_dispatch: Duration,
    /// Awaited host-to-device copies of at most 4 MiB (rows, tables), timed apart
    /// from dispatches but included in `work_time` and the duty cycle. The last
    /// queued chunk (also at most 4 MiB) instead travels with the next dispatch.
    pub uploads: u64,
    pub max_upload: Duration,
    /// Complete objective tables built and uploaded, excluding cache hits.
    pub objective_uploads: u64,
    pub table_build_time: Duration,
    /// Host table upload wall time, including chunk waits and duty-cycle rests.
    pub table_upload_time: Duration,
}

/// One dispatch's host timing and bounded work geometry, for opt-in instrumentation.
#[derive(Clone, Copy, Debug)]
pub struct DispatchSample {
    pub duration: Duration,
    pub keys: usize,
    pub scan_budget: u32,
    pub pair_slice: usize,
}

#[derive(Default)]
struct Session {
    pipelines: HashMap<Specialization, wgpu::ComputePipeline>,
    /// Only the active job's objectives remain resident; host sparse tables are dropped.
    weights: HashMap<WeightKey, ResidentWeights>,
    stats: DispatchStats,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum WeightKey {
    Ic,
    Dense(usize, Vec<i64>),
    Sparse(usize),
    Entropy(usize),
    Trie(usize),
}

impl WeightKey {
    fn of(objective: ClimbObjective<'_>) -> Self {
        match objective {
            ClimbObjective::Ic { .. } => Self::Ic,
            ClimbObjective::DenseNgram { order, weights, .. } => {
                Self::Dense(order, weights.to_vec())
            }
            ClimbObjective::SparseNgram { model, .. } => {
                Self::Sparse(Arc::as_ptr(&model.table_identity()) as usize)
            }
            ClimbObjective::Entropy { length } => Self::Entropy(length),
            ClimbObjective::Trie { model } => {
                Self::Trie(Arc::as_ptr(&model.table_identity()) as usize)
            }
        }
    }
}

struct ResidentWeights {
    buffer: wgpu::Buffer,
    // Keeps allocation identity unique even if the request/model is dropped.
    _identity: Option<Arc<()>>,
}

/// Kernel order code of the entropy objective; n-gram orders are 1-6, IC is 0.
const ENTROPY_ORDER: usize = 7;
const TRIE_ORDER: usize = 8;

// One buffer per objective reuses the existing bindings: [depth, edges_base],
// [edge_start, edge_count, signed terminal-or-zero] per node, [symbol, child] per edge.
fn trie_table(model: &enigma_core::TrieModel) -> Result<Vec<i64>, GpuError> {
    let flat = model
        .flatten()
        .map_err(|e| GpuError::Device(format!("flatten trie: {e}")))?;
    let mut table = Vec::with_capacity(model.flattened_bytes() as usize / 8);
    table.extend([flat.max_depth as i64, (2 + 3 * flat.nodes.len()) as i64]);
    for node in flat.nodes {
        table.extend([
            i64::from(node.edge_start),
            i64::from(node.edge_count),
            i64::from(node.terminal.unwrap_or(0)),
        ]);
    }
    for edge in flat.edges {
        table.extend([i64::from(edge.symbol), i64::from(edge.child)]);
    }
    Ok(table)
}

/// Per count `c` in `0..=length`, the exact entropy term split as `[high, low]`
/// with `term = high * 2^16 + low` and `0 <= low < 2^16`. Summing highs and lows
/// apart keeps i64 sums, and `floor(total / (N * 2^16)) = floor((highs + (lows >> 16)) / N)`.
fn entropy_table(length: usize) -> Result<Vec<i64>, GpuError> {
    let invalid = |_| GpuError::Device("entropy terms exceed the exact i64 split".into());
    let terms = enigma_core::entropy_terms(length)
        .map_err(|e| GpuError::Device(format!("entropy terms: {e:?}")))?;
    let mut table = Vec::with_capacity(2 * terms.len());
    for term in terms {
        table.push(i64::try_from(term >> 16).map_err(invalid)?);
        table.push((term & 0xffff) as i64);
    }
    Ok(table)
}

/// One serialized GPU execution stream. Usage is the dispatch wall-time duty cycle.
/// `scan_budget` (1-4) bounds scan slices per dispatch, not climb iterations.
/// Slices preserve the unfinished scan winner, ordinal and evaluation count.
pub struct GpuClimbAccelerator {
    device: wgpu::Device,
    queue: wgpu::Queue,
    limits: wgpu::Limits,
    name: String,
    usage: u8,
    scan_budget: u32,
    failure: Arc<Mutex<Option<String>>>,
    session: Mutex<Session>,
    observer: Option<Box<dyn Fn(DispatchSample) + Send + Sync>>,
    cooperative: Cooperative,
    dispatch_limit: u64,
}

/// Texts longer than `from` letters share each evaluation across the workgroup:
/// `letters` positions per lane and round, `rounds * scan_budget` rounds per
/// dispatch with `letters / scan_budget` positions (at least one) per lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cooperative {
    from: usize,
    letters: usize,
    rounds: usize,
}

const COOPERATIVE: Cooperative = Cooperative {
    from: 1024,
    letters: 16,
    rounds: 8,
};

/// Sliced lanes decode whole trials, so keys per dispatch shrink inversely with
/// text length above 256 letters (512 keys at <=256, 128 at 1024), in multiples of 32.
fn sliced_keys(length: usize) -> usize {
    let keys = (512 * 256 / length.max(256)).max(1);
    if keys >= 32 {
        keys / 32 * 32
    } else {
        keys
    }
}

/// Host-to-device bytes that may be queued ahead of one dispatch or one timed wait.
const UPLOAD_CHUNK: usize = 4 << 20;

/// Header words before the alphabet-wide mapping, board and partial counts.
const STATE_HEADER: usize = 24;

fn state_words(width: usize) -> usize {
    STATE_HEADER + 2 * width + width.next_multiple_of(2)
}

/// Immutable job facts compiled into a pipeline; one cache entry per distinct job shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Specialization {
    width: usize,
    length: usize,
    cache_words: usize,
    packed_counts: bool,
    initial_order: usize,
    final_order: usize,
    identical: bool,
    pair_slice: usize,
    masked: bool,
    cooperative: Option<(usize, usize)>,
}

struct JobLayout {
    row_words: usize,
    cache_words: usize,
    keys_per_dispatch: usize,
    pair_slice: usize,
    initial_order: usize,
    final_order: usize,
    identical: bool,
    /// Letters per lane and round, and rounds per dispatch, for long texts.
    cooperative: Option<(usize, usize)>,
}

fn bounded_pair_slice(base: usize, budget: u32) -> usize {
    let slice = (base / budget as usize).max(1);
    // 32 pairs fill one 128-lane round of action slots.
    if slice >= 32 {
        slice / 32 * 32
    } else {
        slice
    }
}

/// Whole-pair lanes for full 128-pair slices, else one action slot per lane.
/// Both bound a lane to about four evaluations per slice.
fn lane_actions(pair_slice: usize) -> u32 {
    if pair_slice >= 128 {
        4
    } else {
        1
    }
}

fn unsupported(reason: impl Into<String>) -> GpuUnsupported {
    GpuUnsupported::Job(reason.into())
}

fn objective(
    objective: ClimbObjective<'_>,
    width: usize,
    length: usize,
    max_buffer: u64,
) -> Result<usize, GpuUnsupported> {
    match objective {
        ClimbObjective::Ic { scale, denominator } => {
            if length < 2 || scale != 1u128 << 32 || denominator != (length * (length - 1)) as u128
            {
                return Err(unsupported(
                    "IC requires a Q32 scale and the text's nonzero denominator",
                ));
            }
            Ok(0)
        }
        ClimbObjective::DenseNgram {
            order,
            weights,
            max_abs,
        } => {
            if order == 0 || order > length || order > u32::MAX as usize {
                return Err(unsupported("invalid n-gram order or insufficient text"));
            }
            let entries = width
                .checked_pow(order as u32)
                .filter(|&entries| entries <= u32::MAX as usize)
                .ok_or_else(|| unsupported("n-gram table index exceeds u32"))?;
            if entries != weights.len() || entries as u64 * 8 > max_buffer {
                return Err(unsupported(
                    "dense n-gram table exceeds the storage buffer limit or has wrong dimensions",
                ));
            }
            if (length - order + 1) as u128 * max_abs as u128 > i64::MAX as u128
                || weights.iter().any(|w| w.unsigned_abs() > max_abs)
            {
                return Err(unsupported("n-gram window sums do not fit i64"));
            }
            Ok(order)
        }
        ClimbObjective::SparseNgram {
            model,
            order,
            max_abs,
        } => {
            if order == 0
                || order > length
                || order != model.order()
                || width != model.alphabet().len()
            {
                return Err(unsupported(
                    "invalid sparse n-gram dimensions or insufficient text",
                ));
            }
            let entries = (width as u64)
                .checked_pow(order as u32)
                .ok_or_else(|| unsupported("n-gram table size overflows u64"))?;
            let bytes = entries
                .checked_mul(8)
                .ok_or_else(|| unsupported("n-gram table byte size overflows u64"))?;
            if entries > u64::from(u32::MAX) {
                return Err(unsupported(format!(
                    "n-gram table size {bytes} bytes exceeds u32 indexing"
                )));
            }
            if bytes > max_buffer {
                return Err(unsupported(format!("n-gram table size {bytes} bytes exceeds device storage buffer limit {max_buffer} bytes")));
            }
            if (length - order + 1) as u128 * u128::from(max_abs) > i64::MAX as u128
                || model.i64_max_abs().is_none_or(|max| max > max_abs)
            {
                return Err(unsupported("n-gram window sums do not fit i64"));
            }
            Ok(order)
        }
        ClimbObjective::Trie { model } => {
            if model.alphabet().len() != width
                || length == 0
                || model.flattened_bytes() > max_buffer
            {
                return Err(unsupported(
                    "trie dimensions or flattened table exceed device storage buffer limit",
                ));
            }
            Ok(TRIE_ORDER)
        }
        ClimbObjective::Entropy { length: total } => {
            // Two i64 words per count 0..=length; highs sum below 2^63 for 1e6 letters.
            if total != length || length == 0 || (length as u64 + 1) * 16 > max_buffer {
                return Err(unsupported(
                    "entropy requires the text length and a storable count table",
                ));
            }
            Ok(ENTROPY_ORDER)
        }
    }
}

fn same_objectives(a: ClimbObjective<'_>, b: ClimbObjective<'_>) -> bool {
    match (a, b) {
        (ClimbObjective::Ic { .. }, ClimbObjective::Ic { .. }) => true,
        (
            ClimbObjective::DenseNgram {
                order: a,
                weights: x,
                ..
            },
            ClimbObjective::DenseNgram {
                order: b,
                weights: y,
                ..
            },
        ) => a == b && x == y,
        (
            ClimbObjective::SparseNgram { model: a, .. },
            ClimbObjective::SparseNgram { model: b, .. },
        ) => std::ptr::eq(a, b),
        (ClimbObjective::Trie { model: a }, ClimbObjective::Trie { model: b }) => {
            std::ptr::eq(a, b)
        }
        (ClimbObjective::Entropy { .. }, ClimbObjective::Entropy { .. }) => true,
        _ => false,
    }
}

/// Debug object names stay off unless `WGPU_DEBUG` asks for them: the Vulkan
/// loader's `vkSetDebugUtilsObjectNameEXT` segfaults while another thread creates
/// an instance, so concurrent accelerators crashed in debug builds.
fn instance_descriptor() -> wgpu::InstanceDescriptor {
    let mut descriptor = wgpu::InstanceDescriptor::new_without_display_handle();
    descriptor.flags.remove(wgpu::InstanceFlags::DEBUG);
    descriptor.with_env()
}

impl GpuClimbAccelerator {
    /// Probe the adapter. Invalid options are rejected before touching the device.
    /// No-adapter and missing-int64 outcomes are typed unsupported errors.
    pub fn new(usage: u8, scan_budget: u32) -> Result<Self, GpuError> {
        if !(1..=100).contains(&usage) {
            return Err(GpuError::InvalidUsage(usage));
        }
        if !(1..=4).contains(&scan_budget) {
            return Err(GpuError::InvalidScanBudget(scan_budget));
        }
        let instance = wgpu::Instance::new(instance_descriptor());
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            ..Default::default()
        }))
        .map_err(|e| GpuError::Unsupported(GpuUnsupported::NoAdapter(e.to_string())))?;
        let name = adapter.get_info().name;
        if !adapter.features().contains(wgpu::Features::SHADER_INT64) {
            return Err(GpuError::Unsupported(GpuUnsupported::MissingInt64(name)));
        }
        let limits = adapter.limits();
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            required_features: wgpu::Features::SHADER_INT64,
            required_limits: limits.clone(),
            ..Default::default()
        }))
        .map_err(|e| GpuError::Device(e.to_string()))?;
        let failure = Arc::new(Mutex::new(None));
        let uncaptured = Arc::clone(&failure);
        device.on_uncaptured_error(Arc::new(move |error: wgpu::Error| {
            *uncaptured.lock().unwrap() = Some(error.to_string());
        }));
        let lost = Arc::clone(&failure);
        device.set_device_lost_callback(move |reason, message| {
            *lost.lock().unwrap() = Some(format!("device lost ({reason:?}): {message}"));
        });
        Ok(Self {
            device,
            queue,
            limits,
            name,
            usage,
            scan_budget,
            failure,
            session: Mutex::new(Session::default()),
            observer: None,
            cooperative: COOPERATIVE,
            dispatch_limit: u64::MAX,
        })
    }

    /// Test hook: cooperative long-text geometry for texts longer than `from`.
    #[doc(hidden)]
    pub fn with_cooperative_geometry(mut self, from: usize, letters: usize, rounds: usize) -> Self {
        assert!(letters > 0 && rounds > 0);
        self.cooperative = Cooperative {
            from,
            letters,
            rounds,
        };
        self
    }

    /// Test hook: lower the per-batch dispatch bound to exercise the watchdog.
    #[doc(hidden)]
    pub fn with_dispatch_limit(mut self, limit: u64) -> Self {
        self.dispatch_limit = limit;
        self
    }

    /// Opt in to dispatch samples. Callback work is excluded from dispatch timing;
    /// it must be short and must not re-enter this serialized accelerator.
    pub fn with_dispatch_observer(
        mut self,
        observer: impl Fn(DispatchSample) + Send + Sync + 'static,
    ) -> Self {
        self.observer = Some(Box::new(observer));
        self
    }

    pub fn adapter_name(&self) -> &str {
        &self.name
    }

    pub fn dispatch_stats(&self) -> DispatchStats {
        self.session.lock().unwrap().stats
    }

    /// Validate a projected job without row preparation or GPU work.
    pub fn supports_job(&self, job: &ClimbJob<'_>) -> Result<(), GpuUnsupported> {
        self.layout(job).map(|_| ())
    }

    fn layout(&self, job: &ClimbJob<'_>) -> Result<JobLayout, GpuUnsupported> {
        Self::bounded_layout(job, &self.limits, self.scan_budget, self.cooperative)
    }

    /// Device layout plus the per-dispatch work bounds for this scan budget.
    fn bounded_layout(
        job: &ClimbJob<'_>,
        limits: &wgpu::Limits,
        budget: u32,
        geometry: Cooperative,
    ) -> Result<JobLayout, GpuUnsupported> {
        let mut layout = Self::layout_for(job, limits)?;
        // Larger requested slice counts must not become a long-dispatch mode.
        layout.pair_slice = bounded_pair_slice(layout.pair_slice, budget);
        layout.cooperative = (job.text_length > geometry.from).then(|| {
            let budget = budget as usize;
            ((geometry.letters / budget).max(1), geometry.rounds * budget)
        });
        // Keep short trie trials in independent lanes: cooperation serializes
        // their action search. Depth still bounds slices and concurrent keys.
        // Exceptionally deep trials need cooperation even in short texts, so
        // a single lane's worst-case walk cannot monopolize the display.
        let depth = [job.initial_objective, job.final_objective]
            .into_iter()
            .map(|o| match o {
                ClimbObjective::Trie { model } => model.max_depth().min(job.text_length),
                _ => 1,
            })
            .max()
            .unwrap_or(1);
        let work_length = job.text_length.saturating_mul(depth);
        if depth > 1 && (layout.cooperative.is_some() || work_length > 16_384) {
            layout.cooperative = Some((
                (geometry.letters / budget as usize / depth).max(1),
                (geometry.rounds * budget as usize / depth).max(1),
            ));
        }
        layout.keys_per_dispatch = layout.keys_per_dispatch.min((512 / depth).max(1));
        if layout.cooperative.is_none() {
            layout.keys_per_dispatch = layout.keys_per_dispatch.min(sliced_keys(work_length));
            layout.pair_slice = bounded_pair_slice(32 * (1024 / work_length).clamp(1, 4), budget);
        }
        Ok(layout)
    }

    /// Provable upper bound on dispatches until every (key, seed) of a batch finishes.
    /// Seeds advance concurrently, each with its own state; their count does not
    /// multiply this bound. Host batches cap workgroups exactly as for single starts.
    /// Each committed winner strictly raises the phase objective's score, so a
    /// climb has at most `distinct(initial) + distinct(final) + 2` scans. Every
    /// unfinished key consumes `scan_budget` slices (sliced) or a fixed number of
    /// rounds (cooperative) per dispatch. The bound is a liveness backstop against
    /// a kernel that never finishes, not an expected duration.
    fn dispatch_bound(job: &ClimbJob<'_>, layout: &JobLayout, budget: u32) -> u64 {
        let distinct = |objective| match objective {
            ClimbObjective::Ic { denominator, .. } => denominator.saturating_add(1),
            ClimbObjective::Trie { model } => {
                let bound = job.text_length as u128 * model.max_depth() as u128 * (1u128 << 31);
                2 * bound + 2
            }
            ClimbObjective::DenseNgram { max_abs, .. }
            | ClimbObjective::SparseNgram { max_abs, .. } => u128::from(max_abs) * 2 + 2,
            // Ranking is -measured with 0 <= measured <= B(length) >> 16.
            ClimbObjective::Entropy { length } => enigma_core::integer_log2_q48(length as u128)
                .map_or(u128::MAX, |log| (log >> 16) as u128 + 2),
        };
        let scans = distinct(job.initial_objective)
            .saturating_add(distinct(job.final_objective))
            .saturating_add(2);
        let width = job.alphabet_size as u128;
        let pairs = width * width.saturating_sub(1) / 2;
        let dispatches = match layout.cooperative {
            None => scans
                .saturating_mul(pairs.div_ceil(layout.pair_slice as u128).max(1))
                .div_ceil(u128::from(budget)),
            Some((letters, rounds)) => {
                let evaluation = (job.text_length as u128).div_ceil(128 * letters as u128);
                let actions = 4 * pairs;
                let per_scan = (actions + 1)
                    .saturating_mul(evaluation + 1)
                    .saturating_add(actions.div_ceil(128) + 1);
                scans
                    .saturating_mul(per_scan)
                    .saturating_add(evaluation)
                    .div_ceil(rounds as u128)
            }
        };
        u64::try_from(dispatches.saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn layout_for(job: &ClimbJob<'_>, limits: &wgpu::Limits) -> Result<JobLayout, GpuUnsupported> {
        let width = job.alphabet_size;
        let length = job.text_length;
        if !(1..=256).contains(&width) || length == 0 || length > 1_000_000 {
            return Err(unsupported(
                "alphabet must be 1-256 symbols and text 1-1000000 symbols",
            ));
        }
        if job.input.len() != length
            || job.input.iter().any(|&s| s as usize >= width)
            || job.mutable_mask.len() != width
        {
            return Err(unsupported("input or mutable mask dimensions are invalid"));
        }
        if job.max_pairs > width / 2
            || job.backtrack_pairs > u32::MAX as usize
            || job.switch_pairs > u32::MAX as usize
            || job.starts.is_empty()
            || job
                .starts
                .iter()
                .any(|start| job.fixed_pairs.len() + start.len() > job.max_pairs)
        {
            return Err(unsupported("pair counts or thresholds exceed job limits"));
        }
        for start in &job.starts {
            let mut seen = vec![false; width];
            for (fixed, pairs) in [(true, &job.fixed_pairs), (false, start)] {
                for &(a, b) in pairs {
                    let (a, b) = (a as usize, b as usize);
                    if a >= width
                        || b >= width
                        || a == b
                        || seen[a]
                        || seen[b]
                        || (!fixed && (!job.mutable_mask[a] || !job.mutable_mask[b]))
                    {
                        return Err(unsupported(
                            "fixed/start board is not a disjoint legal involution",
                        ));
                    }
                    seen[a] = true;
                    seen[b] = true;
                }
            }
        }
        let max_buffer = limits
            .max_storage_buffer_binding_size
            .min(limits.max_buffer_size);
        let stride = length
            .checked_mul(width)
            .ok_or_else(|| unsupported("row size overflow"))?;
        let row_words = stride.div_ceil(4);
        if stride > 512 * 1024
            || row_words as u64 * 4 > max_buffer
            || length as u64 * 4 > max_buffer
            || (2 * width + job.starts.len() * (2 * width + 1)) as u64 * 4 > max_buffer
        {
            return Err(unsupported(
                "text rows exceed the device/core storage buffer limit",
            ));
        }
        let initial_order = objective(job.initial_objective, width, length, max_buffer)?;
        let final_order = objective(job.final_objective, width, length, max_buffer)?;
        // 128 reduction records (24 bytes), two State copies conservatively,
        // and optional row cache. A one-word placeholder keeps WGSL arrays legal.
        // Plus the cooperative histogram and next-trial word.
        let shared = 128 * 24 + 2 * state_words(width) * 4 + width * 4 + 4;
        let available = limits.max_compute_workgroup_storage_size as usize;
        if limits.max_compute_invocations_per_workgroup < 128
            || limits.max_compute_workgroup_size_x < 128
            || limits.max_storage_buffers_per_shader_stage < 7
            || limits.max_uniform_buffer_binding_size < 64
            || shared + 4 > available
            || state_words(width) as u64 * 4 > max_buffer
        {
            return Err(unsupported(
                "device lacks workgroup or storage resources for the exact kernel",
            ));
        }
        let cache_words = if row_words * 4 + shared <= available && row_words <= 4096 {
            row_words
        } else {
            0
        };
        let keys_per_dispatch = 512usize
            .min(limits.max_compute_workgroups_per_dimension as usize)
            .min((max_buffer / (row_words * 4) as u64) as usize)
            .min((max_buffer / (state_words(width) * 4) as u64) as usize);
        if keys_per_dispatch == 0 {
            return Err(unsupported("device cannot dispatch one key"));
        }
        Ok(JobLayout {
            row_words,
            cache_words,
            keys_per_dispatch,
            // About 1024 decoded letters per lane and slice: 128 pairs below
            // 257 letters, then 96/64/32-pair action-slot rounds.
            pair_slice: 32 * (1024 / length).clamp(1, 4),
            initial_order,
            final_order,
            identical: same_objectives(job.initial_objective, job.final_objective),
            cooperative: None,
        })
    }

    fn health(&self) -> Result<(), GpuError> {
        match self.failure.lock().unwrap().as_ref() {
            Some(reason) => Err(GpuError::Device(reason.clone())),
            None => Ok(()),
        }
    }

    fn checked<T>(&self, work: impl FnOnce() -> Result<T, GpuError>) -> Result<T, GpuError> {
        self.health()?;
        let scopes = [
            wgpu::ErrorFilter::OutOfMemory,
            wgpu::ErrorFilter::Internal,
            wgpu::ErrorFilter::Validation,
        ]
        .map(|filter| self.device.push_error_scope(filter));
        let result = work();
        for scope in scopes.into_iter().rev() {
            if let Some(error) = pollster::block_on(scope.pop()) {
                return Err(GpuError::Device(error.to_string()));
            }
        }
        self.health()?;
        result
    }

    fn buffer(&self, label: &str, bytes: &[u8], usage: wgpu::BufferUsages) -> wgpu::Buffer {
        self.device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some(label),
                contents: bytes,
                usage,
            })
    }

    /// Duty-cycle idling after measured GPU work.
    fn rest(&self, elapsed: Duration, stats: &mut DispatchStats) {
        let idle = Instant::now();
        std::thread::sleep(elapsed.mul_f64(f64::from(100 - self.usage) / f64::from(self.usage)));
        stats.idle_time += idle.elapsed();
    }

    /// Queue `bytes` into a new storage buffer. Before queued writes would exceed
    /// `UPLOAD_CHUNK`, they are submitted and awaited as one timed upload, so at most
    /// one chunk precedes the next dispatch on the queue (`pending` tracks it).
    fn upload(
        &self,
        label: &str,
        bytes: &[u8],
        pending: &mut usize,
        stats: &mut DispatchStats,
    ) -> Result<wgpu::Buffer, GpuError> {
        let buffer = self.checked(|| {
            Ok(self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(label),
                size: bytes.len().next_multiple_of(4).max(4) as u64,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            }))
        })?;
        for (index, chunk) in bytes.chunks(UPLOAD_CHUNK).enumerate() {
            if *pending > 0 && *pending + chunk.len() > UPLOAD_CHUNK {
                let start = Instant::now();
                self.checked(|| {
                    self.queue.submit([]);
                    self.device
                        .poll(wgpu::PollType::wait_indefinitely())
                        .map_err(|e| GpuError::Device(e.to_string()))?;
                    Ok(())
                })?;
                let elapsed = start.elapsed();
                *pending = 0;
                stats.uploads += 1;
                stats.work_time += elapsed;
                stats.max_upload = stats.max_upload.max(elapsed);
                self.rest(elapsed, stats);
            }
            self.checked(|| {
                self.queue
                    .write_buffer(&buffer, (index * UPLOAD_CHUNK) as u64, chunk);
                Ok(())
            })?;
            *pending += chunk.len();
        }
        Ok(buffer)
    }

    fn read_words(&self, buffer: &wgpu::Buffer) -> Result<Vec<u32>, GpuError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        buffer.map_async(wgpu::MapMode::Read, .., move |result| {
            let _ = sender.send(result);
        });
        self.device
            .poll(wgpu::PollType::wait_indefinitely())
            .map_err(|e| GpuError::Device(e.to_string()))?;
        receiver
            .recv()
            .map_err(|e| GpuError::Device(e.to_string()))?
            .map_err(|e| GpuError::Device(e.to_string()))?;
        let words = bytemuck::cast_slice::<u8, u32>(&buffer.get_mapped_range(..)).to_vec();
        buffer.unmap();
        Ok(words)
    }

    fn specialization(job: &ClimbJob<'_>, layout: &JobLayout) -> Specialization {
        Specialization {
            width: job.alphabet_size,
            length: job.text_length,
            cache_words: layout.cache_words,
            packed_counts: job.alphabet_size <= 32 && job.text_length <= 255,
            initial_order: layout.initial_order,
            final_order: layout.final_order,
            identical: layout.identical,
            pair_slice: layout.pair_slice,
            masked: !job.fixed_pairs.is_empty() || job.mutable_mask.iter().any(|&m| !m),
            cooperative: layout.cooperative,
        }
    }

    fn pipeline(&self, spec: &Specialization) -> Result<wgpu::ComputePipeline, GpuError> {
        let packed = spec.width <= 32;
        let source = include_str!("climb.wgsl")
            .replace("{{MAPPING_TYPE}}", if packed { "PackedBoard" } else { "array<u32, WIDTH>" })
            .replace("{{MAPPING_FUNCTIONS}}", if packed {
                include_str!("packed.wgsl")
            } else {
                "fn lookup(board: Mapping, index: u32) -> u32 { return board[index]; }\n\
                 fn put(board: ptr<function, Mapping>, index: u32, value: u32) { (*board)[index] = value; }"
            })
            .replace("{{PACKED_COUNTS}}", &spec.packed_counts.to_string())
            .replace("{{WIDTH}}", &spec.width.to_string())
            .replace("{{LENGTH}}", &spec.length.to_string())
            .replace("{{INITIAL_ORDER}}", &spec.initial_order.to_string())
            .replace("{{FINAL_ORDER}}", &spec.final_order.to_string())
            .replace("{{IDENTICAL}}", &spec.identical.to_string())
            .replace("{{PAIR_SLICE}}", &spec.pair_slice.to_string())
            .replace("{{LANE_ACTIONS}}", &lane_actions(spec.pair_slice).to_string())
            .replace("{{MASKED}}", &spec.masked.to_string())
            .replace("{{COOPERATIVE}}", &spec.cooperative.is_some().to_string())
            .replace(
                "{{CLIMB}}",
                if spec.cooperative.is_some() {
                    "cooperative"
                } else {
                    "sliced"
                },
            )
            .replace("{{COOP_LETTERS}}", &spec.cooperative.map_or(1, |c| c.0).to_string())
            .replace("{{COOP_ROUNDS}}", &spec.cooperative.map_or(1, |c| c.1).to_string())
            .replace("{{COUNT_WORDS}}", &spec.width.next_multiple_of(2).to_string())
            .replace("{{CACHE_WORDS}}", &spec.cache_words.max(1).to_string())
            .replace("{{CACHE_ROWS}}", &(spec.cache_words != 0).to_string());
        self.checked(|| {
            let module = self
                .device
                .create_shader_module(wgpu::ShaderModuleDescriptor {
                    label: Some("exact resumable climb"),
                    source: wgpu::ShaderSource::Wgsl(source.into()),
                });
            Ok(self
                .device
                .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                    label: Some("exact resumable climb"),
                    layout: None,
                    module: &module,
                    entry_point: Some("main"),
                    compilation_options: Default::default(),
                    cache: None,
                }))
        })
    }

    fn resident_weights(
        &self,
        objective: ClimbObjective<'_>,
        key: WeightKey,
        session: &mut Session,
        pending: &mut usize,
        stats: &mut DispatchStats,
    ) -> Result<wgpu::Buffer, GpuError> {
        if let Some(resident) = session.weights.get(&key) {
            return Ok(resident.buffer.clone());
        }
        let start = Instant::now();
        let owned;
        let weights = match objective {
            ClimbObjective::Ic { .. } => &[0i64][..],
            ClimbObjective::DenseNgram { weights, .. } => weights,
            ClimbObjective::SparseNgram { model, .. } => {
                owned = model
                    .complete_i64_table()
                    .map_err(|e| GpuError::Device(format!("complete n-gram table: {e:?}")))?;
                &owned
            }
            ClimbObjective::Trie { model } => {
                owned = trie_table(model)?;
                &owned
            }
            ClimbObjective::Entropy { length } => {
                owned = entropy_table(length)?;
                &owned
            }
        };
        stats.table_build_time += start.elapsed();
        let start = Instant::now();
        let buffer = self.upload(
            "objective weights",
            bytemuck::cast_slice(weights),
            pending,
            stats,
        )?;
        stats.table_upload_time += start.elapsed();
        stats.objective_uploads += 1;
        let identity = match objective {
            ClimbObjective::SparseNgram { model, .. } => Some(model.table_identity()),
            ClimbObjective::Trie { model } => Some(model.table_identity()),
            _ => None,
        };
        session.weights.insert(
            key,
            ResidentWeights {
                buffer: buffer.clone(),
                _identity: identity,
            },
        );
        // `owned` is released here, not retained for the accelerator's lifetime.
        Ok(buffer)
    }

    fn run(&self, job: &ClimbJob<'_>, rows: &[u8]) -> Result<Vec<AcceleratedClimb>, GpuError> {
        let layout = self.layout(job).map_err(GpuError::Unsupported)?;
        let width = job.alphabet_size;
        let stride = width * job.text_length;
        if rows.is_empty()
            || !rows.len().is_multiple_of(stride)
            || rows.len() / stride > 512
            || rows.iter().any(|&s| s as usize >= width)
        {
            return Err(GpuError::Unsupported(unsupported(
                "rows must contain 1-512 complete, valid keys",
            )));
        }
        let mut session = self.session.lock().unwrap();
        let initial_key = WeightKey::of(job.initial_objective);
        let final_key = WeightKey::of(job.final_objective);
        session
            .weights
            .retain(|key, _| *key == initial_key || *key == final_key);
        let mut stats = session.stats;
        let mut pending = 0;
        let initial = self.resident_weights(
            job.initial_objective,
            initial_key,
            &mut session,
            &mut pending,
            &mut stats,
        )?;
        let final_weights = self.resident_weights(
            job.final_objective,
            final_key,
            &mut session,
            &mut pending,
            &mut stats,
        )?;
        let cache_key = Self::specialization(job, &layout);
        if let std::collections::hash_map::Entry::Vacant(entry) = session.pipelines.entry(cache_key)
        {
            entry.insert(self.pipeline(&cache_key)?);
        }
        let pipeline = &session.pipelines[&cache_key];
        let input: Vec<u32> = job.input.iter().map(|&s| u32::from(s)).collect();
        // Shared masks, then one [length, mapping, ordered board] record per seed.
        let seed_words = 2 * width + 1;
        let mut data = vec![0u32; 2 * width + job.starts.len() * seed_words];
        for i in 0..width {
            data[width + i] = u32::from(job.mutable_mask[i]);
        }
        for &(a, b) in &job.fixed_pairs {
            data[a as usize] = 1;
            data[b as usize] = 1;
        }
        for (seed, start) in job.starts.iter().enumerate() {
            let base = 2 * width + seed * seed_words;
            data[base] = start.len() as u32;
            for i in 0..width {
                data[base + 1 + i] = i as u32;
            }
            for &(a, b) in job.fixed_pairs.iter().chain(start) {
                data[base + 1 + a as usize] = u32::from(b);
                data[base + 1 + b as usize] = u32::from(a);
            }
            for (i, &(a, b)) in start.iter().enumerate() {
                data[base + 1 + width + i] = u32::from(a) | (u32::from(b) << 8);
            }
        }
        let input = self.upload(
            "input",
            bytemuck::cast_slice(&input),
            &mut pending,
            &mut stats,
        )?;
        let data = self.upload("job", bytemuck::cast_slice(&data), &mut pending, &mut stats)?;
        let total = rows.len() / stride * job.starts.len();
        let mut results = Vec::with_capacity(total);
        // Bound workgroups, not outer keys: even one outer may have >512 seeds.
        // Each batch uploads the distinct keys it uses; seeds share their key's rows.
        for first in (0..total).step_by(layout.keys_per_dispatch) {
            let keys = (total - first).min(layout.keys_per_dispatch);
            let first_outer = first / job.starts.len();
            let last_outer = (first + keys - 1) / job.starts.len();
            let batch = &rows[first_outer * stride..(last_outer + 1) * stride];
            let mut packed = vec![0u8; (last_outer - first_outer + 1) * layout.row_words * 4];
            for (key, bytes) in batch.chunks_exact(stride).enumerate() {
                packed[key * layout.row_words * 4..key * layout.row_words * 4 + stride]
                    .copy_from_slice(bytes);
            }
            let params = [
                keys as u32,
                job.text_length as u32,
                width as u32,
                layout.row_words as u32,
                job.max_pairs as u32,
                job.backtrack_pairs as u32,
                job.switch_pairs as u32,
                job.fixed_pairs.len() as u32,
                job.starts.len() as u32,
                u32::from(layout.identical),
                layout.initial_order as u32,
                layout.final_order as u32,
                self.scan_budget,
                layout.pair_slice as u32,
                lane_actions(layout.pair_slice),
                (first % job.starts.len()) as u32,
            ];
            let state_words = state_words(width);
            let size = (keys * state_words * 4) as u64;
            let rows = self.upload("rows", &packed, &mut pending, &mut stats)?;
            let (states, read, finished, finished_read, bindings) = self.checked(|| {
                let storage = wgpu::BufferUsages::STORAGE;
                let params = self.buffer(
                    "params",
                    bytemuck::cast_slice(&params),
                    wgpu::BufferUsages::UNIFORM,
                );
                let states = self.device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("persistent climbs"),
                    size,
                    usage: storage | wgpu::BufferUsages::COPY_SRC,
                    mapped_at_creation: false,
                });
                let read = self.device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("climb readback"),
                    size,
                    usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                });
                let finished = self.device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("finished keys"),
                    size: 4,
                    usage: storage | wgpu::BufferUsages::COPY_SRC,
                    mapped_at_creation: false,
                });
                let finished_read = self.device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("finished readback"),
                    size: 4,
                    usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                });
                let bindings = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("climb"),
                    layout: &pipeline.get_bind_group_layout(0),
                    entries: [
                        &params,
                        &input,
                        &rows,
                        &initial,
                        &final_weights,
                        &data,
                        &states,
                        &finished,
                    ]
                    .iter()
                    .enumerate()
                    .map(|(binding, buffer)| wgpu::BindGroupEntry {
                        binding: binding as u32,
                        resource: buffer.as_entire_binding(),
                    })
                    .collect::<Vec<_>>()
                    .as_slice(),
                });
                Ok((states, read, finished, finished_read, bindings))
            })?;
            let bound =
                Self::dispatch_bound(job, &layout, self.scan_budget).min(self.dispatch_limit);
            let mut batch_dispatches = 0u64;
            loop {
                let start = Instant::now();
                let records = self.checked(|| {
                    let mut encoder = self.device.create_command_encoder(&Default::default());
                    {
                        let mut pass = encoder.begin_compute_pass(&Default::default());
                        pass.set_pipeline(pipeline);
                        pass.set_bind_group(0, &bindings, &[]);
                        pass.dispatch_workgroups(keys as u32, 1, 1);
                    }
                    encoder.copy_buffer_to_buffer(&finished, 0, &finished_read, 0, 4);
                    self.queue.submit([encoder.finish()]);
                    if self.read_words(&finished_read)?[0] as usize != keys {
                        return Ok(None);
                    }
                    // Whole terminal states only once the batch has finished.
                    let mut encoder = self.device.create_command_encoder(&Default::default());
                    encoder.copy_buffer_to_buffer(&states, 0, &read, 0, size);
                    self.queue.submit([encoder.finish()]);
                    self.read_words(&read).map(Some)
                })?;
                // The submission also flushed any queued upload chunk.
                pending = 0;
                let elapsed = start.elapsed();
                stats.dispatches += 1;
                stats.work_time += elapsed;
                stats.max_dispatch = stats.max_dispatch.max(elapsed);
                if let Some(observer) = &self.observer {
                    observer(DispatchSample {
                        duration: elapsed,
                        keys,
                        scan_budget: self.scan_budget,
                        pair_slice: layout.pair_slice,
                    });
                }
                // Idle after EVERY completed dispatch, including the terminal one.
                self.rest(elapsed, &mut stats);
                if let Some(records) = records {
                    for record in records.chunks_exact(state_words) {
                        let signed = |at| {
                            i64::from_le_bytes(
                                bytemuck::cast_slice(&record[at..at + 2])
                                    .try_into()
                                    .unwrap(),
                            )
                        };
                        let evaluations = u64::from_le_bytes(
                            bytemuck::cast_slice(&record[2..4]).try_into().unwrap(),
                        );
                        let len = record[14] as usize;
                        let board = STATE_HEADER + width;
                        if record[10] == 0 || len > width / 2 {
                            return Err(GpuError::Device("invalid terminal board length".into()));
                        }
                        results.push(AcceleratedClimb {
                            board: record[board..board + len]
                                .iter()
                                .map(|&pair| ((pair & 255) as u8, (pair >> 8) as u8))
                                .collect(),
                            evaluations,
                            final_objective_ascent: record[8] != 0,
                            // Trie climbs compare raw i64 sums, never Q32-scaled
                            // i64 (which can overflow). Positive scaling preserves
                            // all strict comparisons and ties. Phases never compare
                            // unlike units: a switch rescore replaces current.score.
                            score_units: i128::from(signed(0))
                                * if layout.final_order == TRIE_ORDER {
                                    1i128 << 32
                                } else {
                                    1
                                },
                        });
                    }
                    break;
                }
                batch_dispatches += 1;
                if batch_dispatches >= bound {
                    session.stats = stats;
                    return Err(GpuError::Device(format!(
                        "climb batch did not finish within its provable bound of {bound} dispatches"
                    )));
                }
            }
        }
        session.stats = stats;
        Ok(results)
    }
}

impl ClimbAccelerator for GpuClimbAccelerator {
    fn preferred_max_keys(&self) -> usize {
        512
    }

    fn check_job(&self, job: &ClimbJob<'_>) -> Result<(), AcceleratorError> {
        self.supports_job(job)
            .map_err(|e| AcceleratorError(e.to_string()))
    }

    fn climb(
        &self,
        job: &ClimbJob<'_>,
        _first_outer: u128,
        rows: &[u8],
    ) -> Result<Vec<AcceleratedClimb>, AcceleratorError> {
        self.run(job, rows).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
