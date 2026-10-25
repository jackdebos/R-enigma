//! Full real-executor U-264 timing; never invoked by the test suite.
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use enigma_core::{AttackRequest, ExecutionOptions, ParsedAttackRequest};
use enigma_gpu::{DispatchSample, GpuClimbAccelerator};
use serde_json::{json, Value};

fn request(limit: Option<usize>) -> Result<AttackRequest, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |path: &str| std::fs::read_to_string(root.join(path));
    let case: Value = serde_json::from_str(&read("e2e/bomm/m4-u264-attack-design-b/case.json")?)?;
    let query: Value = serde_json::from_str(&read("e2e/bomm/m4-u264-attack-design-b/query.json")?)?;
    let mut request = case["engine"].clone();
    request["job"]["text"] = json!(query["ciphertext"]
        .as_str()
        .ok_or("missing ciphertext")?
        .to_ascii_uppercase());
    request["job"]["resources"] = json!({"sinkov_trigram":{"path":"trigram.json"}});
    if let Some(limit) = limit {
        request["job"]["space"]["limit"] = json!(limit);
    }
    // Same pure JSON conversion as the spike oracle; no converted files written.
    let text = read("e2e/bomm/frequencies/enigma1941-trigram.txt")?;
    let fields: Vec<_> = text.split_whitespace().collect();
    if !fields.len().is_multiple_of(2) {
        return Err("invalid trigram fixture".into());
    }
    let entries = fields
        .chunks_exact(2)
        .map(|f| {
            let gram: Vec<_> = f[0]
                .to_ascii_uppercase()
                .chars()
                .map(|c| c.to_string())
                .collect();
            Ok(json!({"gram":gram,"count":f[1].parse::<u64>()?}))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let model = json!({"resource_version":1,"kind":"ngram",
        "alphabet":('A'..='Z').map(|c| c.to_string()).collect::<Vec<_>>(),
        "order":3,"entries":entries})
    .to_string();
    Ok(ParsedAttackRequest::parse_json(&request.to_string())
        .map_err(|e| format!("fixture: {e:?}"))?
        .bind_resources(&std::collections::BTreeMap::from([(
            "sinkov_trigram".to_owned(),
            model.as_str(),
        )]))
        .map_err(|e| format!("fixture binding: {e:?}"))?)
}

fn report(samples: &[DispatchSample]) {
    let mut durations: Vec<_> = samples.iter().map(|s| s.duration).collect();
    durations.sort_unstable();
    let median = if durations.len().is_multiple_of(2) {
        (durations[durations.len() / 2 - 1] + durations[durations.len() / 2]) / 2
    } else {
        durations[durations.len() / 2]
    };
    let max = durations.last().copied().unwrap_or(Duration::ZERO);
    let p99 = durations[(durations.len() * 99).div_ceil(100) - 1];
    let max_keys = samples.iter().map(|s| s.keys).max().unwrap_or(0);
    let max_pairs = samples.iter().map(|s| s.pair_slice).max().unwrap_or(0);
    println!("dispatches={} max={max:?} p99={p99:?} median={median:?}; keys/dispatch<={max_keys}, pair_slice<={max_pairs}", samples.len());
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "cargo run --release -p enigma-gpu --example timing [-- --tune]\n\
            Default: full U-264 design B, CPU six threads once, GPU 100% and 50% once each, budget 1.\n\
            --tune: 512 keys, CPU six threads once, GPU 25% with budgets 1, 2 and 4.\n\
            Includes real core row preparation, upload/readback, hold and finalist stages.\n\
            Parsing, device/pipeline setup and 128-key warmups are outside timing.\n\
            Compares every AttackResult field through its derived Debug representation.\n\
            Dispatch durations are host submit/readback times, not GPU timestamps."
        );
        return Ok(());
    }
    let tune = args == ["--tune"];
    if !args.is_empty() && !tune {
        return Err("expected --tune or --help".into());
    }
    let request = request(tune.then_some(512))?;
    let warm = self::request(Some(128))?;
    let cpu = ExecutionOptions::with_threads(6).ok_or("invalid CPU thread count")?;
    warm.run_with(cpu, |_| {}, || false)?;
    println!(
        "U-264 design B: {}; six CPU/preparation threads; all finalist stages included",
        if tune {
            "512-key tuning subset"
        } else {
            "17576 keys"
        }
    );
    let start = Instant::now();
    let expected = request.run_with(cpu, |_| {}, || false)?;
    let cpu_time = start.elapsed();
    let expected = format!("{expected:?}");
    println!("CPU-6 wall: {cpu_time:?}");
    let configurations = if tune {
        vec![(25, 1), (25, 2), (25, 4)]
    } else {
        vec![(100, 1), (50, 1)]
    };
    for (usage, budget) in configurations {
        let samples = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&samples);
        let gpu = GpuClimbAccelerator::new(usage, budget)?
            .with_dispatch_observer(move |sample| recorded.lock().unwrap().push(sample));
        println!(
            "GPU: {} usage={usage}% scan_budget={budget}",
            gpu.adapter_name()
        );
        let accelerated = cpu.with_accelerator(&gpu);
        warm.run_with(accelerated, |_| {}, || false)?;
        samples.lock().unwrap().clear();
        let before = gpu.dispatch_stats();
        let start = Instant::now();
        let actual = request.run_with(accelerated, |_| {}, || false)?;
        let wall = start.elapsed();
        let exact = format!("{actual:?}") == expected;
        let after = gpu.dispatch_stats();
        println!(
            "whole AttackResult equal: {exact}; GPU wall: {wall:?}; CPU-6 speedup: {:.3}x",
            cpu_time.as_secs_f64() / wall.as_secs_f64()
        );
        println!(
            "dispatch work={:?} idle={:?}",
            after.work_time - before.work_time,
            after.idle_time - before.idle_time
        );
        report(&samples.lock().unwrap());
        if !tune {
            println!("Historical references (different timing boundary): L25 long-dispatch GPU 4.837 s (no finalist stages/setup); CLI 14.888 s. GPU wall / L25: {:.3}x", wall.as_secs_f64() / 4.837);
        }
        if !exact {
            return Err("GPU AttackResult differs from CPU".into());
        }
    }
    Ok(())
}
