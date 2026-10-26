//! Opt-in synthetic hexagram table measurement; never run by CI tests.
use std::error::Error;
use std::time::Instant;

use enigma_core::{ExecutionOptions, ParsedAttackRequest};
use enigma_gpu::GpuClimbAccelerator;
use serde_json::json;

fn main() -> Result<(), Box<dyn Error>> {
    let alphabet: Vec<_> = ('A'..='Z').map(|c| c.to_string()).collect();
    let model = json!({"resource_version":1,"kind":"ngram","alphabet":alphabet,
        "order":6,"entries":[{"gram":["A","A","A","A","A","A"],"count":31},
        {"gram":["A","B","C","D","E","F"],"count":7}]})
    .to_string();
    let request = json!({"protocol_version":1,
        "machine":{"definition":{"kind":"custom","value":{
            "alphabet":alphabet,
            "wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":[],"plugboard":[]},
            "text":"AAAAAAABCDEFZZZZZZAAAAAA","passes":["hill_climb"],
            "measures":["sinkov_hexagram"],"resources":{"sinkov_hexagram":{"path":"synthetic.json"}},
            "space":{"slots":[{"id":"r","positions":["A"],"rings":["A"]}],
                "plugboard":{"kind":"attack","symbols":alphabet,"max_pairs":0}},
            "attack":{"kind":"hill_climb","initial_measure":"sinkov_hexagram","final_measure":"sinkov_hexagram",
                "switch_pairs":0,"backtrack_pairs":0,"hold":1,"start":[]}}});
    let request = ParsedAttackRequest::parse_json(&request.to_string())
        .map_err(|e| format!("parse: {e:?}"))?
        .bind_resources(&std::collections::BTreeMap::from([(
            "sinkov_hexagram".to_owned(),
            model.as_str(),
        )]))
        .map_err(|e| format!("bind: {e:?}"))?;
    let cpu = ExecutionOptions::with_threads(6).ok_or("invalid threads")?;
    let expected = request.run_with(cpu, |_| {}, || false)?;
    let gpu = GpuClimbAccelerator::new(25, 1)?;
    let job = request.climb_job()?;
    if let Err(reason) = gpu.supports_job(&job) {
        println!(
            "{}: hexagram device preflight: {reason}",
            gpu.adapter_name()
        );
        let enigma_core::ClimbObjective::SparseNgram { model, .. } = job.final_objective else {
            return Err("expected CPU-sparse hexagram model".into());
        };
        let start = Instant::now();
        let table = model
            .complete_i64_table()
            .map_err(|e| format!("table: {e:?}"))?;
        println!("host build={:?}; entries={}; bytes={}; upload and GPU run unavailable at this device limit",
            start.elapsed(), table.len(), table.len() * 8);
        std::hint::black_box(&table);
        drop(table);
        report_memory();
        return Ok(());
    }
    println!(
        "{}: synthetic 26^6 complete table, 2471326208 bytes, usage 25%",
        gpu.adapter_name()
    );
    let start = Instant::now();
    let actual = request.run_with(cpu.with_accelerator(&gpu), |_| {}, || false)?;
    let first_wall = start.elapsed();
    if format!("{actual:?}") != format!("{expected:?}") {
        return Err("hexagram CPU/GPU result mismatch".into());
    }
    let before = gpu.dispatch_stats();
    println!(
        "first wall={first_wall:?}; host build={:?}; chunked upload wall={:?}; stats={before:?}",
        before.table_build_time, before.table_upload_time
    );
    let start = Instant::now();
    let cached = request.run_with(cpu.with_accelerator(&gpu), |_| {}, || false)?;
    let after = gpu.dispatch_stats();
    if format!("{cached:?}") != format!("{expected:?}")
        || before.objective_uploads != after.objective_uploads
    {
        return Err("cached hexagram result or upload count mismatch".into());
    }
    println!(
        "cached wall={:?}; objective uploads={}; whole results identical",
        start.elapsed(),
        after.objective_uploads
    );
    report_memory();
    Ok(())
}

fn report_memory() {
    // Fallback evidence on hosts without /usr/bin/time: Linux process high-water RSS.
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status
            .lines()
            .filter(|s| s.starts_with("VmHWM:") || s.starts_with("VmRSS:"))
        {
            println!("{line}");
        }
    }
}
