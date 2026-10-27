//! Randomized GPU-versus-CPU differential over small attacks (verifier probe).
use enigma_core::{
    AcceleratedClimb, AcceleratorError, AttackRequest, ClimbAccelerator, ClimbJob,
    ExecutionOptions, ParsedAttackRequest,
};
use enigma_gpu::{GpuClimbAccelerator, GpuError, GpuUnsupported};
use serde_json::json;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) % n as u64) as usize
    }
}

fn order(id: &str) -> usize {
    match id {
        "sinkov_bigram" => 2,
        "sinkov_trigram" => 3,
        _ => 0,
    }
}

/// None when the generated combination is not a valid request.
fn request(seed: u64) -> Option<AttackRequest> {
    let mut r = Lcg(seed);
    let width = [3, 4, 5, 6, 8, 34][r.next(6)];
    let alphabet: Vec<String> = (0..width)
        .map(|i| char::from_u32(0x41 + i as u32).unwrap().to_string())
        .collect();
    let mut wiring: Vec<usize> = (0..width).collect();
    for i in (1..width).rev() {
        wiring.swap(i, r.next(i + 1));
    }
    let wiring: Vec<_> = wiring.iter().map(|&i| alphabet[i].clone()).collect();
    let length = if r.next(6) == 0 {
        256 + r.next(40)
    } else {
        6 + r.next(30)
    };
    let text: String = (0..length)
        .map(|_| alphabet[r.next(width)].as_str())
        .collect();
    let measures = ["ic", "sinkov_bigram", "sinkov_trigram", "entropy"];
    let initial = [measures[0], measures[1], measures[3]][r.next(3)];
    let last = measures[r.next(4)];
    let mut symbols: Vec<usize> = (0..width).collect();
    let mut fixed = Vec::new();
    if width >= 4 && r.next(3) == 0 {
        fixed.push(json!([alphabet[0], alphabet[1]]));
        symbols.retain(|&s| s > 1);
    }
    if r.next(4) == 0 && symbols.len() > 2 {
        symbols.remove(r.next(symbols.len()));
    }
    let capacity = (fixed.len() + symbols.len() / 2).min(width / 2);
    let max_pairs = fixed.len() + r.next(capacity - fixed.len() + 1);
    let mut start = Vec::new();
    if r.next(3) == 0 && max_pairs > fixed.len() && symbols.len() >= 2 {
        start.push(json!([alphabet[symbols[1]], alphabet[symbols[0]]]));
    }
    let names: Vec<_> = if initial == last {
        vec![last]
    } else {
        vec![initial, last]
    };
    let mut value = json!({"protocol_version":1,
        "machine":{"definition":{"kind":"custom","value":{
            "alphabet":alphabet,
            "wheels":[{"name":"r","wiring":wiring,"turnovers":[]}],
            "slots":(0..2).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"movable","wheel":"r"})).collect::<Vec<_>>(),
            "stepping":{"rules":[{"when":{"always":true},"advance":["r1"]}]}}}},
        "job":{"kind":"search","configuration":{"slots":[],"plugboard":fixed},
            "text":text,"passes":["hill_climb"],"measures":names,
            "space":{"limit":5,
                "slots":(0..2).map(|i| json!({"id":format!("r{i}"),"positions":&alphabet[..3],"rings":&alphabet[..1]})).collect::<Vec<_>>(),
                "plugboard":{"kind":"attack","symbols":symbols.iter().map(|&s| alphabet[s].clone()).collect::<Vec<_>>(),"max_pairs":max_pairs}},
            "attack":{"kind":"hill_climb","initial_measure":initial,"final_measure":last,
                "switch_pairs":r.next(4),"backtrack_pairs":r.next(3),"hold":3,"start":start}}});
    if width <= 8 && r.next(3) == 0 {
        value["job"]["passes"] = json!(["partial_exhaustion"]);
        value["job"]["attack"]["kind"] = json!("partial_exhaustion");
        value["job"]["attack"]
            .as_object_mut()
            .unwrap()
            .remove("start");
        value["job"]["attack"]["seeds"] = if r.next(2) == 0 {
            json!({"kind":"empty_single","selection":"all"})
        } else {
            json!({"kind":"empty_single","selection":"touching","symbols":[alphabet[symbols[0]]]})
        };
    }
    let mut resources = std::collections::BTreeMap::new();
    let mut models = Vec::new();
    for id in names.iter().filter(|id| order(id) > 0) {
        let n = order(id);
        let entries: Vec<_> = (0..4)
            .map(|_| {
                let gram: Vec<_> = (0..n)
                    .map(|_| alphabet[r.next(width.min(5))].clone())
                    .collect();
                json!({"gram":gram,"count":1 + r.next(40)})
            })
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|e| seen.insert(e["gram"].to_string()))
            .collect();
        value["job"]["resources"][*id] = json!({"path":format!("{id}.json")});
        models.push((id.to_string(), json!({"resource_version":1,"kind":"ngram","alphabet":alphabet,"order":n,"entries":entries}).to_string()));
    }
    for (id, model) in &models {
        resources.insert(id.clone(), model.as_str());
    }
    let parsed = ParsedAttackRequest::parse_json(&value.to_string()).ok()?;
    parsed.bind_resources(&resources).ok()
}

struct Audited<'a>(&'a GpuClimbAccelerator);
impl ClimbAccelerator for Audited<'_> {
    fn preferred_max_keys(&self) -> usize {
        self.0.preferred_max_keys()
    }
    fn check_job(&self, job: &ClimbJob<'_>) -> Result<(), AcceleratorError> {
        self.0.check_job(job)
    }
    fn climb(
        &self,
        job: &ClimbJob<'_>,
        first: u128,
        rows: &[u8],
    ) -> Result<Vec<AcceleratedClimb>, AcceleratorError> {
        let actual = self.0.climb(job, first, rows)?;
        let expected = enigma_core::ReferenceClimbAccelerator.climb(job, first, rows)?;
        assert_eq!(actual, expected, "per-key terminal facts at outer {first}");
        Ok(actual)
    }
}

#[test]
fn randomized_small_attacks_match_cpu() {
    let gpu = match GpuClimbAccelerator::new(20, 1) {
        Ok(gpu) => gpu,
        Err(GpuError::Unsupported(
            reason @ (GpuUnsupported::NoAdapter(_) | GpuUnsupported::MissingInt64(_)),
        )) => {
            eprintln!("SKIP verifier probe: {reason}");
            return;
        }
        Err(error) => panic!("{error}"),
    };
    let budget2 = GpuClimbAccelerator::new(20, 2).unwrap();
    let mut checked = 0;
    for seed in 0..300u64 {
        let Some(request) = request(seed) else {
            continue;
        };
        if request.climb_job().is_err() {
            continue;
        }
        let run = |accelerator: Option<&dyn ClimbAccelerator>| {
            let cpu = ExecutionOptions::with_threads(2).unwrap();
            let options = accelerator.map_or(cpu, |a| cpu.with_accelerator(a));
            let mut progress = Vec::new();
            let result = request
                .run_with(options, |p| progress.push(p), || false)
                .unwrap();
            (format!("{result:?}"), progress)
        };
        let expected = run(None);
        assert_eq!(run(Some(&Audited(&gpu))), expected, "seed {seed} budget 1");
        assert_eq!(
            run(Some(&Audited(&budget2))),
            expected,
            "seed {seed} budget 2"
        );
        checked += 1;
    }
    eprintln!("verifier probe checked {checked} requests");
    assert!(checked >= 150, "only {checked} valid requests");
}
