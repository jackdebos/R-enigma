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
    assert_eq!(layout.keys_per_dispatch, 4);
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
    assert_eq!(layout.pair_slice, 1);
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
