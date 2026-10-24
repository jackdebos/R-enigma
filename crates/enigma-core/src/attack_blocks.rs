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
    use serde_json::json;

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
