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
    pipelines: HashMap<(usize, usize, bool), wgpu::ComputePipeline>,
    stats: DispatchStats,
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
}

struct JobLayout {
    row_words: usize,
    cache_words: usize,
    keys_per_dispatch: usize,
    pair_slice: usize,
    initial_order: usize,
    final_order: usize,
    identical: bool,
}

fn bounded_pair_slice(base: usize, budget: u32) -> usize {
    (base / budget as usize).max(1)
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
        _ => false,
    }
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
        let instance =
            wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle_from_env());
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
        })
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
        let mut layout = Self::layout_for(job, &self.limits)?;
        // Larger requested slice counts must not become a long-dispatch mode.
        layout.pair_slice = bounded_pair_slice(layout.pair_slice, self.scan_budget);
        Ok(layout)
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
            || job.fixed_pairs.len() + job.start_board.len() > job.max_pairs
        {
            return Err(unsupported("pair counts or thresholds exceed job limits"));
        }
        let mut seen = vec![false; width];
        for (fixed, pairs) in [(true, &job.fixed_pairs), (false, &job.start_board)] {
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
            || width as u64 * 16 > max_buffer
        {
            return Err(unsupported(
                "text rows exceed the device/core storage buffer limit",
            ));
        }
        let initial_order = objective(job.initial_objective, width, length, max_buffer)?;
        let final_order = objective(job.final_objective, width, length, max_buffer)?;
        // 128 reduction records (24 bytes), two State copies conservatively,
        // and optional row cache. A one-word placeholder keeps WGSL arrays legal.
        let shared = 128 * 24 + 2 * (16 + 2 * width) * 4;
        let available = limits.max_compute_workgroup_storage_size as usize;
        if limits.max_compute_invocations_per_workgroup < 128
            || limits.max_compute_workgroup_size_x < 128
            || limits.max_storage_buffers_per_shader_stage < 6
            || limits.max_uniform_buffer_binding_size < 64
            || shared + 4 > available
            || (16 + 2 * width) as u64 * 4 > max_buffer
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
            .min((max_buffer / ((16 + 2 * width) * 4) as u64) as usize);
        if keys_per_dispatch == 0 {
            return Err(unsupported("device cannot dispatch one key"));
        }
        Ok(JobLayout {
            row_words,
            cache_words,
            keys_per_dispatch,
            pair_slice: (8192 / length).clamp(1, 128),
            initial_order,
            final_order,
            identical: same_objectives(job.initial_objective, job.final_objective),
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

    fn pipeline(
        &self,
        job: &ClimbJob<'_>,
        layout: &JobLayout,
    ) -> Result<wgpu::ComputePipeline, GpuError> {
        let packed = job.alphabet_size <= 32;
        let source = include_str!("climb.wgsl")
            .replace("{{MAPPING_TYPE}}", if packed { "PackedBoard" } else { "array<u32, WIDTH>" })
            .replace("{{MAPPING_FUNCTIONS}}", if packed {
                include_str!("packed.wgsl")
            } else {
                "fn lookup(board: Mapping, index: u32) -> u32 { return board[index]; }\n\
                 fn put(board: ptr<function, Mapping>, index: u32, value: u32) { (*board)[index] = value; }"
            })
            .replace("{{PACKED_COUNTS}}", if packed && job.text_length <= 255 { "true" } else { "false" })
            .replace("{{WIDTH}}", &job.alphabet_size.to_string())
            .replace("{{CACHE_WORDS}}", &layout.cache_words.max(1).to_string())
            .replace(
                "{{CACHE_ROWS}}",
                if layout.cache_words != 0 {
                    "true"
                } else {
                    "false"
                },
            );
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
        let cache_key = (
            width,
            layout.cache_words,
            width <= 32 && job.text_length <= 255,
        );
        if let std::collections::hash_map::Entry::Vacant(entry) = session.pipelines.entry(cache_key)
        {
            entry.insert(self.pipeline(job, &layout)?);
        }
        let pipeline = &session.pipelines[&cache_key];
        let input: Vec<u32> = job.input.iter().map(|&s| u32::from(s)).collect();
        let mut data = vec![0u32; width * 4];
        for i in 0..width {
            data[width + i] = u32::from(job.mutable_mask[i]);
            data[2 * width + i] = i as u32;
        }
        for &(a, b) in &job.fixed_pairs {
            data[a as usize] = 1;
            data[b as usize] = 1;
        }
        for &(a, b) in job.fixed_pairs.iter().chain(&job.start_board) {
            data[2 * width + a as usize] = u32::from(b);
            data[2 * width + b as usize] = u32::from(a);
        }
        for (i, &(a, b)) in job.start_board.iter().enumerate() {
            data[3 * width + i] = u32::from(a) | (u32::from(b) << 8);
        }
        let weights = |objective| match objective {
            ClimbObjective::Ic { .. } => &[0i64][..],
            ClimbObjective::DenseNgram { weights, .. } => weights,
        };
        let (input, data, initial, final_weights) = self.checked(|| {
            let storage = wgpu::BufferUsages::STORAGE;
            Ok((
                self.buffer("input", bytemuck::cast_slice(&input), storage),
                self.buffer("job", bytemuck::cast_slice(&data), storage),
                self.buffer(
                    "initial weights",
                    bytemuck::cast_slice(weights(job.initial_objective)),
                    storage,
                ),
                self.buffer(
                    "final weights",
                    bytemuck::cast_slice(weights(job.final_objective)),
                    storage,
                ),
            ))
        })?;
        let mut results = Vec::with_capacity(rows.len() / stride);
        let mut stats = session.stats;
        for batch in rows.chunks(stride * layout.keys_per_dispatch) {
            let keys = batch.len() / stride;
            let mut packed = vec![0u8; keys * layout.row_words * 4];
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
                job.start_board.len() as u32,
                u32::from(layout.identical),
                layout.initial_order as u32,
                layout.final_order as u32,
                self.scan_budget,
                layout.pair_slice as u32,
                0,
                0,
            ];
            let state_words = 16 + 2 * width;
            let size = (keys * state_words * 4) as u64;
            let (states, read, bindings) = self.checked(|| {
                let storage = wgpu::BufferUsages::STORAGE;
                let rows = self.buffer("rows", &packed, storage);
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
                Ok((states, read, bindings))
            })?;
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
                    encoder.copy_buffer_to_buffer(&states, 0, &read, 0, size);
                    self.queue.submit([encoder.finish()]);
                    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
                    read.map_async(wgpu::MapMode::Read, .., move |result| {
                        let _ = sender.send(result);
                    });
                    self.device
                        .poll(wgpu::PollType::wait_indefinitely())
                        .map_err(|e| GpuError::Device(e.to_string()))?;
                    receiver
                        .recv()
                        .map_err(|e| GpuError::Device(e.to_string()))?
                        .map_err(|e| GpuError::Device(e.to_string()))?;
                    let records =
                        bytemuck::cast_slice::<u8, u32>(&read.get_mapped_range(..)).to_vec();
                    read.unmap();
                    Ok(records)
                })?;
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
                let idle = Instant::now();
                std::thread::sleep(
                    elapsed.mul_f64(f64::from(100 - self.usage) / f64::from(self.usage)),
                );
                stats.idle_time += idle.elapsed();
                if records.chunks_exact(state_words).all(|r| r[10] != 0) {
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
                        if len > width / 2 {
                            return Err(GpuError::Device("invalid terminal board length".into()));
                        }
                        results.push(AcceleratedClimb {
                            board: record[16 + width..16 + width + len]
                                .iter()
                                .map(|&pair| ((pair & 255) as u8, (pair >> 8) as u8))
                                .collect(),
                            evaluations,
                            final_objective_ascent: record[8] != 0,
                            score_units: i128::from(signed(0)),
                        });
                    }
                    break;
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
