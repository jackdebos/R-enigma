//! Hidden seam for the GPU scoring spike (`odd/tasks/enigma-gpu.md` T3).
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
        let (mut engine, text, direction) = request.into_parts();
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

/// A model's dense weights in radix-width window order (`(a*w+b)*w+c` for
/// trigrams) and their largest magnitude; None without a dense table.
pub fn dense_weights(model: &NgramModel) -> Option<(&[i64], u64)> {
    model.dense_parts()
}
