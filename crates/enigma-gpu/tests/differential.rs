use enigma_core::{AttackRequest, ClimbAccelerator, ExecutionOptions, ParsedAttackRequest};
use enigma_gpu::{GpuClimbAccelerator, GpuError, GpuUnsupported};
use serde_json::json;

fn request(width: usize, variant: usize) -> AttackRequest {
    let alphabet: Vec<_> = ('A'..).take(width).map(|s| s.to_string()).collect();
    let wiring: Vec<_> = (0..width)
        .map(|i| alphabet[(i * 3 + 1) % width].clone())
        .collect();
    let order = match variant {
        8 => 1,
        9 => 4,
        10 => 5,
        11 => 6,
        _ if variant.is_multiple_of(2) => 2,
        _ => 3,
    };
    let id = match order {
        1 => "sinkov_monogram",
        2 => "sinkov_bigram",
        3 => "sinkov_trigram",
        4 => "sinkov_quadgram",
        5 => "sinkov_pentagram",
        _ => "sinkov_hexagram",
    };
    let final_id = if variant == 0 || variant == 12 || variant == 13 {
        "ic"
    } else {
        id
    };
    let initial_id = if variant == 3 { id } else { "ic" };
    let mut value = json!({"protocol_version":1,
        "machine":{"definition":{"kind":"custom","value":{
            "alphabet":alphabet,
            "wheels":[{"name":"r","wiring":wiring,"turnovers":[]}],
            "slots":(0..3).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"movable","wheel":"r"})).collect::<Vec<_>>(),
            "stepping":{"rules":[{"when":{"always":true},"advance":["r2"]}]}}}},
        "job":{"kind":"search","configuration":{"slots":[],"plugboard":[]},
            "text":"AAABACADBBABCDABAAA","passes":["hill_climb"],
            "measures":if initial_id == final_id { vec![final_id] } else { vec![initial_id,final_id] },
            "space":{"offset":3,"limit":if variant == 0 { 773 } else { 3 },
                "slots":(0..3).map(|i| json!({"id":format!("r{i}"),"positions":&alphabet[..4],"rings":&alphabet[..4]})).collect::<Vec<_>>(),
                "plugboard":{"kind":"attack","symbols":alphabet,"max_pairs":width / 2}},
            "attack":{"kind":"hill_climb","initial_measure":initial_id,"final_measure":final_id,
                "switch_pairs":variant % 3,"backtrack_pairs":variant % 3,"hold":3,"start":[],"progress_every":137}}});
    if variant == 4 {
        value["job"]["attack"]["start"] = json!([["D", "C"]]);
        value["job"]["attack"]["switch_pairs"] = json!(width / 2);
        value["job"]["space"]["plugboard"]["max_pairs"] = json!(1);
    }
    if variant == 5 {
        value["job"]["configuration"]["plugboard"] = json!([["B", "A"]]);
        value["job"]["space"]["plugboard"]["symbols"] = json!(&alphabet[2..]);
    }
    if variant == 6 {
        value["job"]["space"]["plugboard"]["symbols"] = json!(["A", "C", "D"]);
        value["job"]["space"]["plugboard"]["max_pairs"] = json!(1);
    }
    if variant == 7 {
        // >255 counters and >16 KiB rows: use the global-memory kernel path.
        value["job"]["text"] = json!("AAABACADBBABCDABAAA".repeat(256));
        value["job"]["space"]["plugboard"]["max_pairs"] = json!(0);
        value["job"]["space"]["limit"] = json!(1);
    }
    if variant == 12 {
        // Identity rows give an exact plateau: no winner may canonicalize start.
        value["machine"]["definition"]["value"]["wheels"][0]["wiring"] = json!(alphabet);
        value["job"]["attack"]["start"] = json!([["D", "C"], ["B", "A"]]);
        value["job"]["space"]["limit"] = json!(1);
    }
    if variant == 13 {
        // IC-only, 779 letters with pairs: with the third accelerator's geometry every
        // evaluation takes 7 rounds against 6 per dispatch, so its partial counts
        // always cross a dispatch boundary, starting with the initial score.
        value["job"]["text"] = json!("AAABACADBBABCDABAAA".repeat(41));
        value["job"]["space"]["limit"] = json!(64);
    }
    if final_id == "ic" {
        return AttackRequest::parse_json(&value.to_string()).unwrap();
    }
    value["job"]["resources"] = json!({id:{"path":"model.json"}});
    let model = json!({"resource_version":1,"kind":"ngram","alphabet":alphabet,"order":order,
        "entries":[{"gram":vec!["A";order],"count":31},{"gram":vec!["B";order],"count":7}]})
    .to_string();
    ParsedAttackRequest::parse_json(&value.to_string())
        .unwrap()
        .bind_resources(&std::collections::BTreeMap::from([(
            id.to_owned(),
            model.as_str(),
        )]))
        .unwrap()
}

fn gpu(usage: u8, budget: u32) -> Option<GpuClimbAccelerator> {
    match GpuClimbAccelerator::new(usage, budget) {
        Ok(gpu) => Some(gpu),
        Err(GpuError::Unsupported(
            reason @ (GpuUnsupported::NoAdapter(_) | GpuUnsupported::MissingInt64(_)),
        )) => {
            // Write directly: cargo's default test capture must not hide device skips.
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "SKIP enigma-gpu device differential: {reason}"
            );
            None
        }
        Err(error) => panic!("GPU initialization failed: {error}"),
    }
}

// Check every key, including outcomes not retained by hold, against production.
struct Audited<'a>(&'a GpuClimbAccelerator);
impl ClimbAccelerator for Audited<'_> {
    fn preferred_max_keys(&self) -> usize {
        self.0.preferred_max_keys()
    }

    fn check_job(
        &self,
        job: &enigma_core::ClimbJob<'_>,
    ) -> Result<(), enigma_core::AcceleratorError> {
        self.0.check_job(job)
    }

    fn climb(
        &self,
        job: &enigma_core::ClimbJob<'_>,
        first: u128,
        rows: &[u8],
    ) -> Result<Vec<enigma_core::AcceleratedClimb>, enigma_core::AcceleratorError> {
        let actual = self.0.climb(job, first, rows)?;
        let expected = enigma_core::ReferenceClimbAccelerator.climb(job, first, rows)?;
        assert_eq!(actual, expected, "per-key terminal facts at outer {first}");
        assert_eq!(actual, job.climb_from_projection(rows)?);
        Ok(actual)
    }
}

#[test]
fn invalid_options_are_rejected_without_a_device() {
    for usage in [0, 101, 255] {
        assert!(matches!(
            GpuClimbAccelerator::new(usage, 1),
            Err(GpuError::InvalidUsage(_))
        ));
    }
    for budget in [0, 5, u32::MAX] {
        assert!(matches!(
            GpuClimbAccelerator::new(25, budget),
            Err(GpuError::InvalidScanBudget(_))
        ));
    }
}

#[test]
fn device_matches_cpu_results_progress_checkpoints_and_geometry() {
    let Some(first) = gpu(25, 1) else { return };
    let Some(second) = gpu(20, 2) else { return };
    // Every text cooperative, one letter per lane and six rounds per dispatch, so
    // evaluations of texts over 128 letters span rounds and dispatches.
    let Some(third) = gpu(20, 3).map(|gpu| gpu.with_cooperative_geometry(1, 1, 2)) else {
        return;
    };
    let identity = enigma_core::checkpoint_identity("{}", &Default::default()).unwrap();
    for width in [4, 26, 34] {
        for variant in 0..14 {
            // Keep long/multiblock and high-order cases on the small alphabet.
            if (width == 26 && (variant == 0 || variant >= 7)) || (width == 34 && variant != 1) {
                continue;
            }
            let request = request(width, variant);
            let run = |accelerator: Option<&dyn ClimbAccelerator>| {
                let cpu = ExecutionOptions::with_threads(3).unwrap();
                let options = accelerator.map_or(cpu, |a| cpu.with_accelerator(a));
                let mut progress = Vec::new();
                let mut checkpoints = Vec::new();
                let result = request
                    .run_with_checkpoints(
                        options,
                        |p| progress.push(p),
                        || false,
                        |s| checkpoints.push(s.record(identity, 0).unwrap()),
                    )
                    .unwrap();
                (format!("{result:?}"), progress, checkpoints)
            };
            let expected = run(None);
            let actual = run(Some(&Audited(&first)));
            assert_eq!(actual, expected, "width={width} variant={variant} budget=1");
            assert_eq!(
                run(Some(&Audited(&second))),
                expected,
                "width={width} variant={variant} budget=2"
            );
            assert_eq!(
                run(Some(&Audited(&third))),
                expected,
                "width={width} variant={variant} cooperative"
            );
            if variant == 0 {
                // CPU checkpoint -> GPU, and GPU checkpoint -> CPU.
                for (record, options) in [
                    (
                        &expected.2[0],
                        ExecutionOptions::serial().with_accelerator(&first),
                    ),
                    (&actual.2[0], ExecutionOptions::serial()),
                ] {
                    let resumed = request
                        .resume(record)
                        .unwrap()
                        .run_with(options, |_| {}, || false)
                        .unwrap();
                    assert_eq!(format!("{resumed:?}"), expected.0);
                }
            }
        }
    }
    // Exercise the production rescore guard with an actual GPU result, not a stub.
    struct Corrupt<'a>(&'a GpuClimbAccelerator);
    impl ClimbAccelerator for Corrupt<'_> {
        fn climb(
            &self,
            job: &enigma_core::ClimbJob<'_>,
            first: u128,
            rows: &[u8],
        ) -> Result<Vec<enigma_core::AcceleratedClimb>, enigma_core::AcceleratorError> {
            let mut result = self.0.climb(job, first, rows)?;
            result[0].score_units += 1;
            Ok(result)
        }
    }
    let mut checkpoints = 0;
    let error = request(4, 1)
        .run_with_checkpoints(
            ExecutionOptions::serial().with_accelerator(&Corrupt(&first)),
            |_| {},
            || false,
            |_| checkpoints += 1,
        )
        .unwrap_err();
    assert!(error.to_string().contains("terminal score mismatch"));
    assert_eq!(error.evaluations_used(), 0);
    assert_eq!(error.counters().outers_completed(), 0);
    assert_eq!(checkpoints, 0);
    // Watchdog: a batch that outlives its dispatch bound stops with an error.
    let Some(limited) = gpu(25, 1).map(|gpu| gpu.with_dispatch_limit(1)) else {
        return;
    };
    let error = request(4, 1)
        .run_with(
            ExecutionOptions::serial().with_accelerator(&limited),
            |_| {},
            || false,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("provable bound of 1 dispatches"),
        "{error}"
    );
    assert_eq!(error.counters().outers_completed(), 0);
    for (gpu, idle_factor) in [(&first, 3.0), (&second, 4.0), (&third, 4.0)] {
        let stats = gpu.dispatch_stats();
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "enigma-gpu {} dispatches={} max={:?} total={:?} (host submit/readback; includes scheduling)", gpu.adapter_name(), stats.dispatches, stats.max_dispatch, stats.work_time);
        assert!(stats.dispatches > 1);
        assert!(
            stats.idle_time + std::time::Duration::from_micros(1)
                >= stats.work_time.mul_f64(idle_factor)
        );
    }
}
