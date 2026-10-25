//! Hidden seam for the GPU spikes (`odd/tasks/enigma-gpu.md` T3/T6).
//!
//! Not a supported API: it exists only with the off-by-default `gpu-spike` feature
//! and may change or disappear. It hands the spike the same board-independent rows,
//! dense weights and scoring code the trial evaluator uses, so the CPU side of the
//! comparison is the engine itself, not a copy.

use crate::attack_evaluator::{spike_dense_units, spike_ic_units};
use crate::{Alphabet, MeasureError, ModelError, NgramModel, TransformRequest};

/// One outer key's prepared rows in the trial evaluator's byte layout:
/// `rows[p * width + s]` is the scrambler output for input index `s` at offset `p`.
pub struct ByteRows {
    pub alphabet: Alphabet,
    pub input: Vec<u8>,
    pub rows: Vec<u8>,
}

impl ByteRows {
    /// Builds the rows a trial evaluator prepares for the request's outer key,
    /// text and direction; its plugboard is ignored, like a trial's.
    pub fn from_request(request: TransformRequest) -> Result<Self, ModelError> {
        let (engine, text, direction) = request.into_parts();
        Self::from_engine(engine, &text, direction)
    }

    fn from_engine(
        mut engine: crate::Engine,
        text: &str,
        direction: crate::Direction,
    ) -> Result<Self, ModelError> {
        let alphabet = engine.alphabet().clone();
        let input = text
            .chars()
            .map(|symbol| {
                alphabet
                    .index_of(symbol)
                    .and_then(|index| u8::try_from(index).ok())
                    .ok_or(ModelError::UnknownSymbol(symbol))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut rows = Vec::with_capacity(input.len() * alphabet.len());
        engine.scrambler_byte_rows(input.len(), direction, &mut rows)?;
        Ok(Self {
            alphabet,
            input,
            rows,
        })
    }

    /// The evaluator's IC ranking of a full board mapping, in Q32 units.
    pub fn ic_units(&self, mapping: &[usize]) -> Result<i128, MeasureError> {
        spike_ic_units(&self.input, &self.rows, mapping)
    }

    /// The evaluator's dense n-gram ranking of a full board mapping, in Q32 units;
    /// None when the model has no dense table.
    pub fn dense_units(
        &self,
        model: &NgramModel,
        mapping: &[usize],
    ) -> Option<Result<i128, MeasureError>> {
        spike_dense_units(model, &self.input, &self.rows, mapping)
    }
}

/// Terminal production-climb facts, compared without score narrowing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClimbResult {
    pub mapping: Vec<u32>,
    pub score: i128,
    pub evaluations: u64,
}

/// A resource-bound attack, using the actual filtered outer-key projection.
/// Construct the request and resource JSON exactly as for the CLI; no I/O here.
pub struct ClimbOracle {
    request: crate::AttackRequest,
}

pub(crate) fn resolve_outer(
    request: &crate::AttackRequest,
    index: u128,
) -> Result<crate::ResolvedConfiguration, String> {
    let plan = request.outer_plan();
    let (start, end) = plan.selected_range();
    if !(start..end).contains(&index) {
        return Err(format!("outer index {index} outside {start}..{end}"));
    }
    let result = plan
        .keys(crate::attack_blocks::OuterBlock {
            index: 0,
            start: index,
            len: 1,
        })
        .next()
        .expect("one outer")
        .1;
    result.map_err(|e| format!("{e:?}"))
}

impl ClimbOracle {
    /// Parses the attack and binds its supplied JSON v1 trigram resource, without I/O.
    pub fn from_json(request: &str, trigram_resource: &str) -> Result<Self, String> {
        let parsed =
            crate::ParsedAttackRequest::parse_json(request).map_err(|e| format!("{e:?}"))?;
        let supplied =
            std::collections::BTreeMap::from([("sinkov_trigram".to_owned(), trigram_resource)]);
        let request = parsed
            .bind_resources(&supplied)
            .map_err(|e| format!("{e:?}"))?;
        Ok(Self { request })
    }

    /// Climbs one absolute outer index through the production accounted path.
    pub fn climb(&self, index: u128) -> Result<ClimbResult, String> {
        self.request.spike_climb(index)
    }

    /// Slot IDs and displayed positions in physical topology order, before stepping.
    pub fn positions(&self, index: u128) -> Result<Vec<(String, char)>, String> {
        let initial = resolve_outer(&self.request, index)?;
        Ok(initial
            .topology()
            .slots()
            .iter()
            .map(|s| (s.id().to_owned(), s.position()))
            .collect())
    }

    /// Prepares the exact same absolute outer key and ciphertext as `climb`.
    pub fn rows(&self, index: u128) -> Result<ByteRows, String> {
        let engine = resolve_outer(&self.request, index)?
            .into_engine()
            .map_err(|e| format!("{e:?}"))?;
        ByteRows::from_engine(engine, self.request.text(), crate::Direction::Decrypt)
            .map_err(|e| format!("{e:?}"))
    }

    /// Appends the rows of `count` consecutive outer keys from `first` to `out`,
    /// byte-identical to calling `rows` per key, but builds the candidate plan once.
    pub fn rows_into(&self, first: u128, count: usize, out: &mut Vec<u8>) -> Result<(), String> {
        let plan = self.request.outer_plan();
        let (start, end) = plan.selected_range();
        let last = first + count as u128;
        if first < start || last > end {
            return Err(format!(
                "outer range {first}..{last} outside {start}..{end}"
            ));
        }
        let block = crate::attack_blocks::OuterBlock {
            index: 0,
            start: first,
            len: count as u128,
        };
        for (_, resolved) in plan.keys(block) {
            let mut engine = resolved
                .map_err(|e| format!("{e:?}"))?
                .into_engine()
                .map_err(|e| format!("{e:?}"))?;
            engine
                .scrambler_byte_rows(
                    self.request.text().chars().count(),
                    crate::Direction::Decrypt,
                    out,
                )
                .map_err(|e| format!("{e:?}"))?;
        }
        Ok(())
    }

    /// Borrows the bound production trigram table, without rebuilding its model.
    pub fn dense_weights(&self) -> Option<(&[i64], u64)> {
        match self
            .request
            .bound_resource(crate::MeasureId::SinkovTrigram)?
        {
            crate::BoundResource::Ngram(model) => dense_weights(model),
            _ => None,
        }
    }
}

/// A model's dense weights in radix-width window order (`(a*w+b)*w+c` for
/// trigrams) and their largest magnitude; None without a dense table.
pub fn dense_weights(model: &NgramModel) -> Option<(&[i64], u64)> {
    model.dense_parts()
}
