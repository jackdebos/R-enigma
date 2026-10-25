//! Indexed outer-key projection for the dynamic worker pool.

use crate::candidate::CandidatePlan;
use crate::{AttackGate, ResolvedConfiguration, SearchDiagnostic, SearchRequest};

/// Fixed dispatch geometry, independent of worker count and machine CPU count.
///
/// Design B takes ~72 s for 17,576 outer keys (~4.1 ms/key), so 128 keys
/// target ~0.52 s/block, leaving headroom below the typical one-second stop
/// latency target. Small A/A2 spaces simply use a partial block. This is not a
/// time guarantee for expensive keys; T6/T7 can tune this single policy constant.
pub(crate) const OUTER_BLOCK_KEYS: u128 = 128;

/// A selected-range-relative block number and an absolute flat key range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OuterBlock {
    pub(crate) index: u128,
    pub(crate) start: u128,
    pub(crate) len: u128,
}

/// Lazy splitter: stores no per-block list, even for near-u128::MAX counts.
pub(crate) struct OuterBlocks {
    index: u128,
    next: u128,
    remaining: u128,
}

impl OuterBlocks {
    fn new(start: u128, len: u128) -> Self {
        assert!(len <= u128::MAX - start, "outer range end exceeds u128");
        Self {
            index: 0,
            next: start,
            remaining: len,
        }
    }
}

impl Iterator for OuterBlocks {
    type Item = OuterBlock;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let len = self.remaining.min(OUTER_BLOCK_KEYS);
        let block = OuterBlock {
            index: self.index,
            start: self.next,
            len,
        };
        self.remaining -= len;
        self.next += len;
        self.index += 1;
        Some(block)
    }
}

/// One immutable candidate plan shared by all block iterators of a checked attack.
pub(crate) struct OuterPlan<'a> {
    candidates: CandidatePlan<'a>,
    start: u128,
    len: u128,
}

impl<'a> OuterPlan<'a> {
    pub(crate) fn new(request: &'a SearchRequest, gate: &AttackGate) -> Self {
        Self {
            candidates: CandidatePlan::build(request),
            start: u128::from(request.space().offset()).min(gate.outer_total()),
            len: gate.outer_selected(),
        }
    }

    pub(crate) fn selected_range(&self) -> (u128, u128) {
        (self.start, self.start + self.len)
    }

    pub(crate) fn blocks(&self) -> OuterBlocks {
        OuterBlocks::new(self.start, self.len)
    }

    /// Resume without changing the original selected-range block indices.
    pub(crate) fn blocks_from(&self, next: u128) -> OuterBlocks {
        let mut blocks = self.blocks();
        blocks.next = next;
        blocks.remaining = self.start + self.len - next;
        blocks.index = (next - self.start).div_ceil(OUTER_BLOCK_KEYS);
        blocks
    }

    pub(crate) fn block_count(&self) -> u128 {
        self.len.div_ceil(OUTER_BLOCK_KEYS)
    }

    /// Resolves a block lazily with the precomputed plan, preserving resolution errors.
    /// Only descriptors within this projection's selected range are accepted.
    pub(crate) fn keys(
        &self,
        block: OuterBlock,
    ) -> impl Iterator<Item = (u128, Result<ResolvedConfiguration, Vec<SearchDiagnostic>>)> + '_
    {
        assert!(block.start >= self.start);
        let relative = block.start - self.start;
        assert!(relative <= self.len && block.len <= self.len - relative);
        (block.start..block.start + block.len).map(|index| (index, self.candidates.resolve(index)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttackRequest;
    use serde_json::{json, Value};

    #[test]
    fn block_coverage_is_contiguous_and_ordered() {
        for len in [
            0,
            1,
            OUTER_BLOCK_KEYS,
            2 * OUTER_BLOCK_KEYS,
            2 * OUTER_BLOCK_KEYS + 1,
        ] {
            let blocks: Vec<_> = OuterBlocks::new(7, len).collect();
            let mut next = 7;
            for (index, block) in blocks.iter().enumerate() {
                assert_eq!(block.index, index as u128);
                assert_eq!(block.start, next);
                assert_eq!(block.len, OUTER_BLOCK_KEYS.min(7 + len - next));
                next += block.len;
            }
            assert_eq!(next, 7 + len);
            assert_eq!(blocks.len() as u128, len.div_ceil(OUTER_BLOCK_KEYS));
        }
    }

    #[test]
    fn huge_ranges_are_lazy_and_do_not_overflow() {
        let mut blocks = OuterBlocks::new(0, u128::MAX);
        assert_eq!(
            blocks.next().unwrap(),
            OuterBlock {
                index: 0,
                start: 0,
                len: OUTER_BLOCK_KEYS
            }
        );
        assert_eq!(blocks.next().unwrap().start, OUTER_BLOCK_KEYS);
        let mut tail = OuterBlocks::new(u128::MAX - OUTER_BLOCK_KEYS - 1, OUTER_BLOCK_KEYS + 1);
        assert_eq!(tail.next().unwrap().len, OUTER_BLOCK_KEYS);
        assert_eq!(
            tail.next().unwrap(),
            OuterBlock {
                index: 1,
                start: u128::MAX - 1,
                len: 1
            }
        );
        assert!(tail.next().is_none());
        assert!(tail.next().is_none());
    }

    fn request(offset: u64, limit: Option<u64>) -> AttackRequest {
        let mut value = json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
            "alphabet":["A","B","C","D"],
            "wheels":[{"name":"r","wiring":["B","C","D","A"],"turnovers":[]}],
            "slots":(0..4).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"})).collect::<Vec<_>>(),
            "stepping":{"rules":[]}}}},"job":{"kind":"search",
            "configuration":{"slots":[],"plugboard":[["A","B"]]},
            "text":"ABCD","passes":["hill_climb"],"measures":["ic"],
            "space":{"offset":offset,"slots":(0..4).map(|i| json!({"id":format!("r{i}"),"positions":["D","B","A","C"],"rings":["C","A"]})).collect::<Vec<_>>(),
                "plugboard":{"kind":"attack","symbols":["C","D"],"max_pairs":2}},
            "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":0,"backtrack_pairs":0,"start":[]}}});
        if let Some(limit) = limit {
            value["job"]["space"]["limit"] = json!(limit);
        }
        AttackRequest::parse_json(&value.to_string()).unwrap()
    }

    /// Rotor slots `a`, `b`, `c` share three admissible wheels; `f` fixes its wheel.
    /// `space` is the whole `job.space` object; `configuration_slots` fill the rest.
    fn wheel_request(
        space: Value,
        configuration_slots: Value,
    ) -> Result<AttackRequest, Vec<crate::RequestDiagnostic>> {
        let rotor = |id: &str| json!({"id":id,"role":"rotor","movement":"fixed","allowed_wheels":["w0","w1","w2"]});
        let value = json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
            "alphabet":["A","B","C","D"],
            "wheels":[
                {"name":"w0","wiring":["B","C","D","A"],"turnovers":[]},
                {"name":"w1","wiring":["C","D","B","A"],"turnovers":[]},
                {"name":"w2","wiring":["D","A","C","B"],"turnovers":[]}],
            "slots":[rotor("a"), rotor("b"), rotor("c"),
                {"id":"f","role":"rotor","movement":"fixed","wheel":"w0"}],
            "stepping":{"rules":[]}}}},"job":{"kind":"search",
            "configuration":{"slots":configuration_slots,"plugboard":[]},
            "text":"ABCD","passes":["hill_climb"],"measures":["ic"],
            "space":space,
            "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":0,"backtrack_pairs":0,"start":[]}}});
        AttackRequest::parse_json(&value.to_string())
    }

    fn wheel_space(known_a: bool) -> (Value, Value) {
        let mut a = json!({"id":"a","positions":["A","B"]});
        let mut fixed_a = json!({"id":"a","ring":"A"});
        if known_a {
            fixed_a["wheel"] = json!("w1");
        } else {
            a["wheels"] = json!(["w0", "w1", "w2"]);
        }
        let space = json!({"slots":[a,
                {"id":"b","wheels":["w2","w0","w1"],"rings":["A","C"]},
                {"id":"c","wheels":["w1","w2"]}],
            "plugboard":{"kind":"attack","symbols":["C","D"],"max_pairs":1}});
        let configuration = json!([fixed_a, {"id":"b","position":"A"},
            {"id":"c","position":"B","ring":"A"}, {"id":"f","position":"A","ring":"A"}]);
        (space, configuration)
    }

    /// Independent oracle: filter the unconstrained flat order (protocol §7) by
    /// decomposing each base index with the domain sizes this test declares.
    fn filtered_base_keys(
        known_a: bool,
        named: &[&str],
    ) -> Vec<Result<ResolvedConfiguration, Vec<SearchDiagnostic>>> {
        let (space, configuration) = wheel_space(known_a);
        let base = wheel_request(space, configuration).unwrap();
        let wheels: [&[&str]; 3] = [
            if known_a {
                &["w1"]
            } else {
                &["w0", "w1", "w2"]
            },
            &["w2", "w0", "w1"],
            &["w1", "w2"],
        ];
        // Per slot a, b, c, f: wheel, position, ring radices.
        let radices = [wheels[0].len() as u128, 2, 1, 3, 1, 2, 2, 1, 1, 1, 1, 1];
        base.outer_candidates()
            .filter(|(index, _)| {
                let mut rest = *index;
                let mut digits = [0u128; 12];
                for position in (0..12).rev() {
                    digits[position] = rest % radices[position];
                    rest /= radices[position];
                }
                let chosen: Vec<&str> = ["a", "b", "c"]
                    .iter()
                    .enumerate()
                    .filter(|(_, id)| named.contains(id))
                    .map(|(slot, _)| wheels[slot][digits[slot * 3] as usize])
                    .collect();
                let unique: std::collections::HashSet<_> = chosen.iter().collect();
                unique.len() == chosen.len()
            })
            .map(|(_, key)| key)
            .collect()
    }

    fn constrained(
        known_a: bool,
        named: &[&str],
        offset: u64,
        limit: Option<u64>,
    ) -> AttackRequest {
        let (mut space, configuration) = wheel_space(known_a);
        space["constraints"] = json!({"distinct_wheels": named});
        space["offset"] = json!(offset);
        if let Some(limit) = limit {
            space["limit"] = json!(limit);
        }
        wheel_request(space, configuration).unwrap()
    }

    fn planned_keys(
        request: &AttackRequest,
    ) -> Vec<(u128, Result<ResolvedConfiguration, Vec<SearchDiagnostic>>)> {
        let plan = request.outer_plan();
        plan.blocks()
            .flat_map(|block| plan.keys(block).collect::<Vec<_>>())
            .collect()
    }

    #[test]
    fn distinct_wheels_order_is_the_filtered_base_order() {
        for (known_a, named, count) in [
            (false, &["a", "b", "c"][..], 16),
            (false, &["c", "a"][..], 48),
            // Known a=w1 forces c=w2 and b=w0: 1 assignment * 2 positions * 2 rings.
            (true, &["a", "b", "c"][..], 4),
            (false, &["a", "b"][..], 48),
        ] {
            let expected = filtered_base_keys(known_a, named);
            assert_eq!(expected.len() as u128, count, "oracle {named:?}");
            let request = constrained(known_a, named, 0, None);
            assert_eq!(request.gate().outer_total(), count);
            assert_eq!(request.gate().outer_selected(), count);
            let actual = planned_keys(&request);
            let indices: Vec<u128> = actual.iter().map(|(index, _)| *index).collect();
            assert_eq!(indices, (0..count).collect::<Vec<_>>());
            let keys: Vec<_> = actual.into_iter().map(|(_, key)| key).collect();
            assert_eq!(keys, expected, "order for {named:?}, known a {known_a}");
            let serial: Vec<_> = request.outer_candidates().map(|(_, key)| key).collect();
            assert_eq!(serial, expected);
        }
    }

    #[test]
    fn distinct_wheels_offset_and_limit_slice_the_filtered_order() {
        let expected = filtered_base_keys(false, &["a", "b", "c"]);
        for (offset, limit) in [
            (0, Some(1)),
            (3, Some(5)),
            (15, None),
            (16, None),
            (40, Some(2)),
        ] {
            let request = constrained(false, &["a", "b", "c"], offset, limit);
            let start = (offset as usize).min(expected.len());
            let end = limit.map_or(expected.len(), |limit| {
                (start + limit as usize).min(expected.len())
            });
            assert_eq!(request.gate().outer_total(), 16);
            assert_eq!(request.gate().outer_selected(), (end - start) as u128);
            let actual = planned_keys(&request);
            let indices: Vec<u128> = actual.iter().map(|(index, _)| *index).collect();
            assert_eq!(indices, (start as u128..end as u128).collect::<Vec<_>>());
            let keys: Vec<_> = actual.into_iter().map(|(_, key)| key).collect();
            assert_eq!(keys, expected[start..end]);
        }
    }

    fn constraint_error(
        constraints: Value,
        configuration_a: Option<Value>,
    ) -> (String, String, String) {
        let (mut space, mut configuration) = wheel_space(false);
        space["constraints"] = constraints;
        if let Some(entry) = configuration_a {
            configuration[0] = entry;
            space["slots"][0] = json!({"id":"a","positions":["A","B"]});
        }
        let error = wheel_request(space, configuration).unwrap_err().remove(0);
        (
            error.code().to_owned(),
            error.location().to_owned(),
            error.message().to_owned(),
        )
    }

    #[test]
    fn distinct_wheels_rejects_malformed_and_impossible_constraints() {
        let path = "/job/space/constraints/distinct_wheels";
        for (constraints, code, location) in [
            (
                json!({"distinct_wheels":["a","b"],"x":1}),
                "unknown_field",
                "/job/space/constraints/x".to_owned(),
            ),
            (json!({}), "invalid_request", path.to_owned()),
            (
                json!([]),
                "invalid_request",
                "/job/space/constraints".to_owned(),
            ),
            (
                json!({"distinct_wheels":["a"]}),
                "invalid_search_space",
                path.to_owned(),
            ),
            (
                json!({"distinct_wheels":[]}),
                "invalid_search_space",
                path.to_owned(),
            ),
            (
                json!({"distinct_wheels":["a","a"]}),
                "invalid_search_space",
                path.to_owned(),
            ),
            (
                json!({"distinct_wheels":["a","z"]}),
                "invalid_search_space",
                format!("{path}/1"),
            ),
            (
                json!({"distinct_wheels":["a","f"]}),
                "invalid_search_space",
                format!("{path}/1"),
            ),
            (
                json!({"distinct_wheels":["a",2]}),
                "invalid_request",
                format!("{path}/1"),
            ),
        ] {
            let (actual_code, actual_location, message) =
                constraint_error(constraints.clone(), None);
            assert_eq!(
                (actual_code.as_str(), actual_location.as_str()),
                (code, location.as_str()),
                "{constraints}: {message}"
            );
        }
        // Two named slots with the same known wheel leave no outer candidate.
        let (mut space, mut configuration) = wheel_space(true);
        space["slots"][2] = json!({"id":"c"});
        configuration[2] = json!({"id":"c","wheel":"w1","position":"B","ring":"A"});
        space["slots"].as_array_mut().unwrap().remove(2);
        space["constraints"] = json!({"distinct_wheels":["a","c"]});
        let error = wheel_request(space, configuration).unwrap_err().remove(0);
        assert_eq!(
            (error.code(), error.location()),
            ("invalid_search_space", path)
        );
        assert!(error.message().contains("distinct"), "{}", error.message());
    }

    #[test]
    fn distinct_wheels_is_rejected_outside_the_attack_branch() {
        let value = json!({"protocol_version":1,"machine":{"definition":{"kind":"bundled","id":"enigma-i"}},
            "job":{"kind":"search","configuration":{"slots":[
                {"id":"reflector","wheel":"B","position":"A","ring":"A"},
                {"id":"left","position":"A","ring":"A"},
                {"id":"middle","wheel":"II","position":"A","ring":"A"},
                {"id":"right","wheel":"III","position":"A","ring":"A"}],"plugboard":[]},
                "text":"ABCDEFGHIJ","passes":["hill_climb"],"measures":["ic"],
                "space":{"slots":[{"id":"left","wheels":["I","IV"]}],
                    "constraints":{"distinct_wheels":["left","middle"]}}}});
        let error = crate::SearchRequest::parse_json(&value.to_string())
            .unwrap_err()
            .remove(0);
        assert_eq!(
            (error.code(), error.location()),
            ("invalid_search_space", "/job/space/constraints")
        );
    }

    #[test]
    fn distinct_wheels_too_many_combinations_is_a_resource_limit() {
        // 20 named slots over 40 wheels: exact counting would visit too many states.
        let symbols: Vec<String> = (0..6).map(|i| ((b'A' + i) as char).to_string()).collect();
        let mut wirings = Vec::new();
        let mut current: Vec<usize> = (0..6).collect();
        while wirings.len() < 40 {
            wirings.push(
                current
                    .iter()
                    .map(|&i| symbols[i].clone())
                    .collect::<Vec<_>>(),
            );
            // Next lexicographic permutation.
            let mut i = 4;
            while current[i] > current[i + 1] {
                i -= 1;
            }
            let mut j = 5;
            while current[j] < current[i] {
                j -= 1;
            }
            current.swap(i, j);
            current[i + 1..].reverse();
        }
        let names: Vec<String> = (0..40).map(|i| format!("w{i}")).collect();
        let ids: Vec<String> = (0..20).map(|i| format!("s{i}")).collect();
        let value = json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
            "alphabet":symbols,
            "wheels":names.iter().zip(&wirings).map(|(name, wiring)| json!({"name":name,"wiring":wiring,"turnovers":[]})).collect::<Vec<_>>(),
            "slots":ids.iter().map(|id| json!({"id":id,"role":"rotor","movement":"fixed","allowed_wheels":names})).collect::<Vec<_>>(),
            "stepping":{"rules":[]}}}},"job":{"kind":"search",
            "configuration":{"slots":ids.iter().map(|id| json!({"id":id,"position":"A","ring":"A"})).collect::<Vec<_>>(),"plugboard":[]},
            "text":"ABCDEF","passes":["hill_climb"],"measures":["ic"],
            "space":{"slots":ids.iter().map(|id| json!({"id":id,"wheels":names})).collect::<Vec<_>>(),
                "plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":1},
                "constraints":{"distinct_wheels":ids}},
            "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
                "switch_pairs":0,"backtrack_pairs":0,"start":[]}}});
        let error = AttackRequest::parse_json(&value.to_string())
            .unwrap_err()
            .remove(0);
        assert_eq!(
            (error.code(), error.location()),
            ("resource_limit", "/job/space/constraints/distinct_wheels")
        );
    }

    #[test]
    fn blocks_match_serial_keys_and_absolute_slice_indices() {
        for (offset, limit) in [
            (0, None),
            (3, Some(260)),
            (4095, Some(20)),
            (4096, None),
            (9000, Some(1)),
        ] {
            let request = request(offset, limit);
            let projection = request.outer_plan();
            let serial: Vec<_> = request.outer_candidates().collect();
            let blocks: Vec<_> = projection.blocks().collect();
            let mut actual = Vec::new();
            for block in blocks {
                let keys: Vec<_> = projection.keys(block).collect();
                assert_eq!(keys.len() as u128, block.len);
                assert_eq!(keys.first().unwrap().0, block.start);
                assert_eq!(keys, serial[actual.len()..actual.len() + keys.len()]);
                actual.extend(keys);
            }
            assert_eq!(actual, serial);
            assert_eq!(actual.len() as u128, request.gate().outer_selected());
            assert_eq!(
                projection.block_count(),
                projection.blocks().count() as u128
            );
        }
    }
}
