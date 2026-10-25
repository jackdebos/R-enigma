use super::*;

fn request(length: usize) -> enigma_core::AttackRequest {
    let value = serde_json::json!({"protocol_version":1,
        "machine":{"definition":{"kind":"custom","value":{
            "alphabet":["A","B","C","D"],
            "wheels":[{"name":"r","wiring":["B","D","A","C"],"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}}}},
        "job":{"kind":"search","configuration":{"slots":[],"plugboard":[]},
            "text":"ABCD".repeat(length.div_ceil(4)).chars().take(length).collect::<String>(),
            "passes":["hill_climb"],"measures":["ic"],
            "space":{"slots":[{"id":"r","positions":["A"],"rings":["A"]}],
                "plugboard":{"kind":"attack","symbols":["A","B","C","D"],"max_pairs":2}},
            "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":1,"backtrack_pairs":0,"start":[]}}});
    enigma_core::AttackRequest::parse_json(&value.to_string()).unwrap()
}

#[test]
fn job_limits_and_global_row_fallback_are_device_free() {
    let request = request(19);
    let job = request.climb_job().unwrap();
    let limits = wgpu::Limits::default();
    let layout = GpuClimbAccelerator::layout_for(&job, &limits).unwrap();
    assert_eq!(layout.row_words, 19);
    assert_eq!(layout.cache_words, 19);
    assert_eq!(layout.keys_per_dispatch, 512);
    assert_eq!(layout.pair_slice, 128);
    assert!(layout.identical);
    for limits in [
        wgpu::Limits {
            max_storage_buffer_binding_size: 64,
            ..limits.clone()
        },
        wgpu::Limits {
            max_compute_invocations_per_workgroup: 64,
            ..limits.clone()
        },
        wgpu::Limits {
            max_compute_workgroup_storage_size: 1,
            ..limits.clone()
        },
        wgpu::Limits {
            max_compute_workgroups_per_dimension: 0,
            ..limits.clone()
        },
    ] {
        assert!(matches!(
            GpuClimbAccelerator::layout_for(&job, &limits),
            Err(GpuUnsupported::Job(_))
        ));
    }
    let long = self::request(4864);
    let layout = GpuClimbAccelerator::layout_for(&long.climb_job().unwrap(), &limits).unwrap();
    assert_eq!(layout.cache_words, 0);
    assert_eq!(layout.row_words, 4864);
    assert_eq!(layout.pair_slice, 32);
    assert_eq!(lane_actions(layout.pair_slice), 1);
    let layout =
        GpuClimbAccelerator::layout_for(&self::request(232).climb_job().unwrap(), &limits).unwrap();
    assert_eq!((layout.keys_per_dispatch, layout.pair_slice), (512, 128));
    assert_eq!(lane_actions(layout.pair_slice), 4);
    let layout =
        GpuClimbAccelerator::layout_for(&self::request(257).climb_job().unwrap(), &limits).unwrap();
    assert_eq!(layout.pair_slice, 96);
}

#[test]
fn increasing_scan_budget_still_bounds_dispatch_work() {
    assert_eq!(
        [1, 2, 3, 4].map(|budget| bounded_pair_slice(128, budget)),
        [128, 64, 32, 32]
    );
    // Only full slices take whole-pair lanes; smaller ones keep action slots.
    assert_eq!([128, 96, 64, 32, 1].map(lane_actions), [4, 1, 1, 1, 1]);
    for base in 1..=128 {
        for budget in 1..=4 {
            assert!((1..=base).contains(&bounded_pair_slice(base, budget)));
        }
    }
}

#[test]
fn malformed_projection_is_rejected_with_typed_reasons() {
    let request = request(19);
    let limits = wgpu::Limits::default();
    for variant in 0..7 {
        let mut job = request.climb_job().unwrap();
        match variant {
            0 => job.alphabet_size = 257,
            1 => job.input[0] = 255,
            2 => job.mutable_mask.clear(),
            3 => job.start_board = vec![(0, 1), (1, 2)],
            4 => job.max_pairs = 3,
            5 => {
                job.initial_objective = ClimbObjective::Ic {
                    scale: 1,
                    denominator: 342,
                }
            }
            _ => job.text_length = 1_000_001,
        }
        assert!(matches!(
            GpuClimbAccelerator::layout_for(&job, &limits),
            Err(GpuUnsupported::Job(_))
        ));
    }
}

#[test]
fn dense_objectives_require_exact_dimensions_bounds_and_device_storage() {
    let weights = [-8; 16];
    let dense = |max_abs| ClimbObjective::DenseNgram {
        order: 2,
        weights: &weights,
        max_abs,
    };
    assert_eq!(objective(dense(8), 4, 5, 128), Ok(2));
    for result in [
        objective(dense(8), 4, 5, 127),
        objective(dense(8), 5, 5, 128),
        objective(dense(7), 4, 5, 128),
        objective(dense(u64::MAX), 4, 5, 128),
        objective(dense(8), 4, 1, 128),
    ] {
        assert!(matches!(result, Err(GpuUnsupported::Job(_))));
    }
}

#[test]
fn dispatch_work_is_bounded_for_any_text_length() {
    let limits = wgpu::Limits::default();
    assert_eq!(
        [1, 232, 256, 257, 341, 512, 1024, 1025, 4864].map(sliced_keys),
        [512, 512, 512, 480, 384, 256, 128, 96, 26]
    );
    for (length, cooperative) in [
        (19, None),
        (1024, None),
        (1025, Some((16, 8))),
        (4864, Some((16, 8))),
    ] {
        let request = request(length);
        let job = request.climb_job().unwrap();
        let layout = GpuClimbAccelerator::bounded_layout(&job, &limits, 1, COOPERATIVE).unwrap();
        assert_eq!(layout.cooperative, cooperative, "length={length}");
        if cooperative.is_none() {
            assert!(layout.keys_per_dispatch <= sliced_keys(length));
        }
    }
    // Larger budgets split cooperative work into finer rounds, not longer dispatches.
    let request = request(4864);
    let job = request.climb_job().unwrap();
    assert_eq!(
        [1, 2, 3, 4].map(|budget| {
            GpuClimbAccelerator::bounded_layout(&job, &limits, budget, COOPERATIVE)
                .unwrap()
                .cooperative
        }),
        [Some((16, 8)), Some((8, 16)), Some((5, 24)), Some((4, 32))]
    );
}

#[test]
fn dispatch_bound_follows_distinct_scores_slices_and_rounds() {
    let limits = wgpu::Limits::default();
    let short = request(19);
    let job = short.climb_job().unwrap();
    let bound = |budget| {
        let layout =
            GpuClimbAccelerator::bounded_layout(&job, &limits, budget, COOPERATIVE).unwrap();
        GpuClimbAccelerator::dispatch_bound(&job, &layout, budget)
    };
    // IC has 19 * 18 + 1 distinct scores per objective: 688 scans of one slice.
    assert_eq!([bound(1), bound(2)], [689, 345]);
    let long = request(4864);
    let job = long.climb_job().unwrap();
    let layout = GpuClimbAccelerator::bounded_layout(&job, &limits, 1, COOPERATIVE).unwrap();
    // 47,307,268 scans of at most 102 rounds, plus the initial evaluation, 8 per dispatch.
    assert_eq!(
        GpuClimbAccelerator::dispatch_bound(&job, &layout, 1),
        603_167_669
    );
}
