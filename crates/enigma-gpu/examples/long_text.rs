//! Manual long-text dispatch timing (verifier scenario); never invoked by the test suite.
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use enigma_core::{AttackRequest, ExecutionOptions};
use enigma_gpu::GpuClimbAccelerator;
use serde_json::json;

/// 512 outer keys over 26 symbols, IC only, a pseudo-random text of `length` letters.
fn request(length: usize, max_pairs: usize) -> Result<AttackRequest, Box<dyn Error>> {
    let alphabet: Vec<String> = ('A'..='Z').map(|c| c.to_string()).collect();
    let wiring: Vec<_> = (0..26)
        .map(|i| alphabet[(i * 7 + 3) % 26].clone())
        .collect();
    let mut x = 12345u64;
    let text: String = (0..length)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            alphabet[((x >> 33) % 26) as usize].clone()
        })
        .collect();
    let slots: Vec<_> = (0..3)
        .map(|i| json!({"id":format!("r{i}"),"positions":&alphabet[..8],"rings":["A"]}))
        .collect();
    let value = json!({"protocol_version":1,
        "machine":{"definition":{"kind":"custom","value":{
            "alphabet":alphabet,
            "wheels":[{"name":"r","wiring":wiring,"turnovers":[]}],
            "slots":(0..3).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"movable","wheel":"r"})).collect::<Vec<_>>(),
            "stepping":{"rules":[{"when":{"always":true},"advance":["r2"]}]}}}},
        "job":{"kind":"search","configuration":{"slots":[],"plugboard":[]},
            "text":text,"passes":["hill_climb"],"measures":["ic"],
            "space":{"slots":slots,
                "plugboard":{"kind":"attack","symbols":alphabet,"max_pairs":max_pairs}},
            "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":7,"backtrack_pairs":5,"hold":3,"start":[]}}});
    Ok(AttackRequest::parse_json(&value.to_string()).map_err(|e| format!("{e:?}"))?)
}

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args().nth(1).as_deref() == Some("--help") {
        println!(
            "cargo run --release -p enigma-gpu --example long_text\n\
            512 keys, 26 symbols, IC; GPU at 10% usage, budget 1, versus CPU four threads.\n\
            13 pairs at 232, 512, 1024 (sliced lanes, keys per dispatch shrinking with\n\
            length) and 1025 (first cooperative length); one pair at 2000, 4000, 20000\n\
            and 20164 (the 512-KiB per-key row maximum for 26 symbols). Reports\n\
            per-length exactness, maximum/p99/median dispatch and maximum upload chunk."
        );
        return Ok(());
    }
    let cpu = ExecutionOptions::with_threads(4).ok_or("invalid threads")?;
    let mut exact = true;
    for (length, pairs) in [
        (232, 13),
        (512, 13),
        (1024, 13),
        (1025, 13),
        (2000, 1),
        (4000, 1),
        (20000, 1),
        (20164, 1),
    ] {
        // One accelerator per length, so maxima and upload statistics are per length.
        let samples = Arc::new(Mutex::new(Vec::<Duration>::new()));
        let recorded = Arc::clone(&samples);
        let gpu = GpuClimbAccelerator::new(10, 1)?
            .with_dispatch_observer(move |s| recorded.lock().unwrap().push(s.duration));
        let request = request(length, pairs)?;
        let expected = format!("{:?}", request.run_with(cpu, |_| {}, || false)?);
        samples.lock().unwrap().clear();
        let start = Instant::now();
        let actual = format!(
            "{:?}",
            request.run_with(cpu.with_accelerator(&gpu), |_| {}, || false)?
        );
        let wall = start.elapsed();
        let stats = gpu.dispatch_stats();
        let mut durations = std::mem::take(&mut *samples.lock().unwrap());
        durations.sort_unstable();
        let at = |q: usize| durations[(durations.len() * q).div_ceil(100).max(1) - 1];
        exact &= actual == expected;
        println!(
            "length={length} max_pairs={pairs} exact={} dispatches={} max={:?} p99={:?} median={:?} uploads={} max_upload={:?} gpu10%_wall={wall:?}",
            actual == expected,
            durations.len(),
            durations.last().copied().unwrap_or_default(),
            at(99),
            at(50),
            stats.uploads,
            stats.max_upload,
        );
    }
    if !exact {
        return Err("GPU AttackResult differs from CPU".into());
    }
    Ok(())
}
