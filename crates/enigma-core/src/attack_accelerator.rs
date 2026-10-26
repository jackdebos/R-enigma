//! Hardware-independent, exact outer-climb acceleration.
//!
//! Core prepares rows, checks terminal scores and owns ordered commits, progress,
//! checkpoints and finalist stages. An accelerator must not approximate decisions
//! or silently fall back. See `ClimbAccelerator` for the dispatch contract.

use crate::{AttackKind, AttackRequest, BoundResource, MeasureId};

// Bounds apply to each prepared dispatch, including the one prepared ahead.
// During execution core also holds a concatenated copy of the active rows.
const MAX_DISPATCH_KEYS: usize = 512;
const MAX_DISPATCH_ROW_BYTES: usize = 64 * 1024 * 1024;

/// Preserve logical blocks while bounding both key count and row payload size.
/// None means even one logical block would exceed the row data policy.
pub(crate) fn dispatch_key_limit(stride: usize, preferred: usize) -> Option<usize> {
    let block = crate::attack_blocks::OUTER_BLOCK_KEYS as usize;
    if stride == 0 {
        return None;
    }
    let keys = (MAX_DISPATCH_ROW_BYTES / stride)
        .min(MAX_DISPATCH_KEYS)
        .min(preferred.max(block));
    let keys = keys / block * block;
    (keys >= block).then_some(keys)
}

/// An objective's exact integer data; all scores are higher-is-better Q32 units.
#[derive(Clone, Copy, Debug)]
pub enum ClimbObjective<'a> {
    /// `floor(sum(c*(c-1)) * alphabet_size * scale / denominator)` in u128.
    Ic {
        /// Q32 scale (2^32).
        scale: u128,
        /// `text_length * (text_length - 1)`.
        denominator: u128,
    },
    /// Radix-alphabet-size weights, summed in i64, then floor-divided by windows.
    DenseNgram {
        /// Symbols per window.
        order: usize,
        /// Production weights, including unseen-window weights.
        weights: &'a [i64],
        /// Largest absolute weight, bounding every partial sum.
        max_abs: u64,
    },
}

/// A bound, machine-independent description shared by every outer in a run.
/// Pair endpoints are alphabet indices. Fixed and start pair ordering is retained.
/// The private owner link is used only by the production CPU reference oracle.
#[derive(Clone)]
pub struct ClimbJob<'a> {
    /// Ordered alphabet width, at most 256.
    pub alphabet_size: usize,
    /// Number of input symbols (not UTF-8 bytes).
    pub text_length: usize,
    /// Input alphabet indices.
    pub input: Vec<u8>,
    /// Immutable known links.
    pub fixed_pairs: Vec<(u8, u8)>,
    /// One entry per alphabet symbol, true where mutable links may end.
    pub mutable_mask: Vec<bool>,
    /// Maximum total fixed plus mutable pairs.
    pub max_pairs: usize,
    /// Below this total pair count, consider only add-only trials.
    pub backtrack_pairs: usize,
    /// Switch permanently to the final objective at this total pair count.
    pub switch_pairs: usize,
    /// Ordered mutable starting pairs (fixed pairs excluded).
    pub start_board: Vec<(u8, u8)>,
    /// Objective before the switch.
    pub initial_objective: ClimbObjective<'a>,
    /// Objective after the switch and for terminal scoring.
    pub final_objective: ClimbObjective<'a>,
    pub(crate) owner: &'a AttackRequest,
}

/// Exact terminal facts for one outer key, in dispatch order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceleratedClimb {
    /// Mutable pairs in the exact order/orientation committed by the CPU walker.
    pub board: Vec<(u8, u8)>,
    /// All evaluations, including initial, switching and terminal rescoring.
    pub evaluations: u64,
    /// Whether a complete scan used the final objective (or identical objectives).
    pub final_objective_ascent: bool,
    /// Final higher-is-better Q32 ranking units, checked by core without accounting.
    pub score_units: i128,
}

/// Fatal accelerator failure. Core never silently switches to CPU execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceleratorError(pub String);

impl std::fmt::Display for AcceleratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "accelerator: {}", self.0)
    }
}
impl std::error::Error for AcceleratorError {}

/// Typed reason an exact climb job cannot be expressed by this interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClimbUnsupported {
    /// Deductive crib testing is CPU-only.
    Bombe,
    /// Only direct hill climbing is supported.
    PartialExhaustion,
    /// Byte rows require at most 256 symbols.
    AlphabetTooLarge,
    /// Byte rows or one logical block exceed the bounded row data policy.
    RowDataLimit,
    /// Entropy, trie or another nonrepresentable objective.
    Objective(MeasureId),
    /// No dense integer weight table exists.
    SparseNgram(MeasureId),
    /// Window sums require the production i128 path.
    WideNgram(MeasureId),
}
impl std::fmt::Display for ClimbUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bombe => f.write_str("bombe is CPU-only"),
            Self::PartialExhaustion => f.write_str("partial exhaustion"),
            Self::AlphabetTooLarge => f.write_str("alphabet exceeds 256 symbols"),
            Self::RowDataLimit => f.write_str("text exceeds accelerator row data limit"),
            Self::Objective(id) => write!(f, "unsupported objective {}", id.id()),
            Self::SparseNgram(id) => write!(f, "sparse n-gram objective {}", id.id()),
            Self::WideNgram(id) => write!(f, "i128 n-gram objective {}", id.id()),
        }
    }
}
impl std::error::Error for ClimbUnsupported {}

/// Whole-climb accelerator. Implementations must preserve production neighborhood
/// order, strict improvement, pair order, integer arithmetic and evaluation counts.
/// `rows` concatenates consecutive keys starting at absolute `first_outer`;
/// each key has `text_length * alphabet_size` bytes, position-major:
/// `rows[key * stride + position * alphabet_size + symbol]`.
/// Return exactly one result per key, or a fatal error. Cancellation is owned by
/// core and polled between bounded dispatches, not inside this synchronous call.
pub trait ClimbAccelerator: Sync {
    /// Preferred maximum keys per call (not necessarily one hardware dispatch).
    /// Core clamps to 512 keys and 64 MiB of byte rows, then rounds down to whole
    /// 128-key blocks (minimum one block). A final block may be short. Jobs whose
    /// full logical block cannot fit the row limit are rejected before work.
    /// Implementations must further split calls into bounded hardware dispatches.
    fn preferred_max_keys(&self) -> usize {
        128
    }
    /// Device-specific capability checks, before any preparation or progress.
    /// A failure stops the run; core never selects another accelerator implicitly.
    fn check_job(&self, _job: &ClimbJob<'_>) -> Result<(), AcceleratorError> {
        Ok(())
    }
    /// Climb a run of consecutive prepared outer keys, without host side effects.
    fn climb(
        &self,
        job: &ClimbJob<'_>,
        first_outer: u128,
        rows: &[u8],
    ) -> Result<Vec<AcceleratedClimb>, AcceleratorError>;
}

/// Production CPU climb behind the accelerator contract, for device-free tests.
#[doc(hidden)]
pub struct ReferenceClimbAccelerator;
impl ClimbAccelerator for ReferenceClimbAccelerator {
    fn climb(
        &self,
        job: &ClimbJob<'_>,
        first: u128,
        rows: &[u8],
    ) -> Result<Vec<AcceleratedClimb>, AcceleratorError> {
        job.owner.reference_climbs(job, first, rows)
    }
}

impl ClimbJob<'_> {
    /// Device-free projection oracle. Uses only public job fields and supplied rows,
    /// never the private request owner. The production walker retains its board
    /// validation, neighborhood ordering and winner canonicalization invariants.
    #[doc(hidden)]
    pub fn climb_from_projection(
        &self,
        rows: &[u8],
    ) -> Result<Vec<AcceleratedClimb>, AcceleratorError> {
        use crate::attack_neighborhood::NeighborhoodWalker;
        let fail = |message: &str| AcceleratorError(format!("projected reference: {message}"));
        let width = self.alphabet_size;
        let stride = self.text_length.checked_mul(width).unwrap_or(0);
        if !(1..=256).contains(&width)
            || stride == 0
            || !rows.len().is_multiple_of(stride)
            || self.input.len() != self.text_length
            || self.mutable_mask.len() != width
            || self.input.iter().chain(rows).any(|&s| s as usize >= width)
        {
            return Err(fail("invalid job or row dimensions"));
        }
        // Only the generic walker's validated board context needs a topology.
        // Its identity wiring is never evaluated; all decoding uses supplied rows.
        let symbols: Vec<_> = (0..width)
            .map(|i| char::from_u32(0xe000 + i as u32).unwrap())
            .collect();
        let pairs = |pairs: &[(u8, u8)]| {
            pairs
                .iter()
                .map(|&(a, b)| {
                    symbols
                        .get(a as usize)
                        .zip(symbols.get(b as usize))
                        .map(|(&a, &b)| (a, b))
                        .ok_or_else(|| fail("invalid pair index"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let fixed = pairs(&self.fixed_pairs)?;
        let start = pairs(&self.start_board)?;
        let source = serde_json::json!({"kind":"custom","value":{
            "alphabet":symbols,
            "wheels":[{"name":"r","wiring":symbols,"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}}});
        let definition = crate::DefinitionSource::parse_json(&source.to_string())
            .and_then(|source| source.resolve())
            .map_err(|e| AcceleratorError(format!("projected reference: {e:?}")))?;
        let initial = crate::TransformConfiguration::new(
            vec![crate::SlotConfiguration::new(
                "r", "r", symbols[0], symbols[0],
            )],
            fixed.clone(),
        )
        .resolve(&definition)
        .map_err(|e| AcceleratorError(format!("projected reference: {e:?}")))?;
        let mask: Vec<_> = symbols
            .iter()
            .zip(&self.mutable_mask)
            .filter_map(|(&s, &mutable)| mutable.then_some(s))
            .collect();
        let domain = crate::AttackPlugboardDomain::parse_json(
            definition.alphabet(),
            &fixed,
            &serde_json::json!({"kind":"attack","symbols":mask,"max_pairs":self.max_pairs})
                .to_string(),
        )
        .map_err(|e| AcceleratorError(format!("projected reference: {e:?}")))?;
        let identical = match (self.initial_objective, self.final_objective) {
            (
                ClimbObjective::Ic {
                    scale: a,
                    denominator: x,
                },
                ClimbObjective::Ic {
                    scale: b,
                    denominator: y,
                },
            ) => a == b && x == y,
            (
                ClimbObjective::DenseNgram {
                    order: a,
                    weights: x,
                    ..
                },
                ClimbObjective::DenseNgram {
                    order: b,
                    weights: y,
                    ..
                },
            ) => a == b && x == y,
            _ => false,
        };
        rows.chunks_exact(stride)
            .map(|rows| {
                let evaluate = |mapping: &[usize], objective| -> Result<i128, AcceleratorError> {
                    let plain: Vec<_> = self
                        .input
                        .iter()
                        .zip(rows.chunks_exact(width))
                        .map(|(&s, row)| mapping[row[mapping[s as usize]] as usize])
                        .collect();
                    match objective {
                        ClimbObjective::Ic { scale, denominator } => {
                            let mut counts = vec![0u128; width];
                            for s in plain {
                                counts[s] += 1;
                            }
                            let pairs: u128 = counts.iter().map(|&c| c * c.saturating_sub(1)).sum();
                            let units = pairs
                                .checked_mul(width as u128)
                                .and_then(|v| v.checked_mul(scale))
                                .and_then(|v| v.checked_div(denominator))
                                .ok_or_else(|| fail("invalid IC arithmetic"))?;
                            i128::try_from(units).map_err(|_| fail("IC score exceeds i128"))
                        }
                        ClimbObjective::DenseNgram { order, weights, .. } => {
                            if order == 0 || plain.len() < order {
                                return Err(fail("invalid n-gram order"));
                            }
                            let mut sum = 0i64;
                            for window in plain.windows(order) {
                                let index = window
                                    .iter()
                                    .try_fold(0usize, |index, &s| {
                                        index.checked_mul(width).and_then(|v| v.checked_add(s))
                                    })
                                    .ok_or_else(|| fail("n-gram index overflow"))?;
                                let weight = weights
                                    .get(index)
                                    .ok_or_else(|| fail("missing dense weight"))?;
                                sum = sum
                                    .checked_add(*weight)
                                    .ok_or_else(|| fail("n-gram sum overflow"))?;
                            }
                            crate::floor_div(i128::from(sum), (plain.len() - order + 1) as i128)
                                .map_err(|_| fail("invalid n-gram divisor"))
                        }
                    }
                };
                let mut board = start.clone();
                let mut phase = fixed.len() + board.len() >= self.switch_pairs;
                let mut walker =
                    NeighborhoodWalker::validated(&initial, &domain, &board, self.backtrack_pairs)
                        .map_err(|e| AcceleratorError(format!("projected reference: {e:?}")))?;
                let mut score = evaluate(
                    walker.mapping(),
                    if phase {
                        self.final_objective
                    } else {
                        self.initial_objective
                    },
                )?;
                let mut evaluations = 1;
                let mut ascent = false;
                loop {
                    let mut best = score;
                    let mut winner = None;
                    while let Some(action) = walker.next_action() {
                        walker.apply(action);
                        let trial = evaluate(
                            walker.mapping(),
                            if phase {
                                self.final_objective
                            } else {
                                self.initial_objective
                            },
                        )?;
                        walker.restore();
                        evaluations += 1;
                        if trial > best {
                            best = trial;
                            winner = Some(walker.selected(action));
                        }
                    }
                    ascent |= phase || identical;
                    let Some(winner) = winner else { break };
                    board = walker.winner_board(&winner, &symbols);
                    walker = NeighborhoodWalker::validated(
                        &initial,
                        &domain,
                        &board,
                        self.backtrack_pairs,
                    )
                    .map_err(|e| AcceleratorError(format!("projected reference: {e:?}")))?;
                    score = best;
                    if !phase && fixed.len() + board.len() >= self.switch_pairs {
                        phase = true;
                        if !identical {
                            score = evaluate(walker.mapping(), self.final_objective)?;
                            evaluations += 1;
                        }
                    }
                }
                if !phase && !identical {
                    score = evaluate(walker.mapping(), self.final_objective)?;
                    evaluations += 1;
                }
                Ok(AcceleratedClimb {
                    board: board
                        .iter()
                        .map(|&(a, b)| {
                            (
                                symbols.iter().position(|&s| s == a).unwrap() as u8,
                                symbols.iter().position(|&s| s == b).unwrap() as u8,
                            )
                        })
                        .collect(),
                    evaluations,
                    final_objective_ascent: ascent,
                    score_units: score,
                })
            })
            .collect()
    }
}

impl AttackRequest {
    /// Check eligibility without evaluations, progress events or outer-key work.
    /// Finalist stages are CPU-owned and do not restrict the outer objectives.
    pub fn climb_job(&self) -> Result<ClimbJob<'_>, ClimbUnsupported> {
        if self.settings().kind() == AttackKind::Bombe {
            return Err(ClimbUnsupported::Bombe);
        }
        if self.settings().kind() != AttackKind::HillClimb {
            return Err(ClimbUnsupported::PartialExhaustion);
        }
        let alphabet = self.definition().alphabet();
        let width = alphabet.len();
        if width > 256 {
            return Err(ClimbUnsupported::AlphabetTooLarge);
        }
        let input: Vec<_> = self
            .text()
            .chars()
            .map(|c| alphabet.index_of(c).expect("bound input") as u8)
            .collect();
        let length = input.len();
        if !crate::attack_evaluator::byte_rows_fit(length, width)
            || length
                .checked_mul(width)
                .and_then(|stride| dispatch_key_limit(stride, MAX_DISPATCH_KEYS))
                .is_none()
        {
            return Err(ClimbUnsupported::RowDataLimit);
        }
        let objective = |id: MeasureId| {
            if id == MeasureId::Ic {
                return Ok(ClimbObjective::Ic {
                    scale: crate::SCALE as u128,
                    denominator: length as u128 * length.saturating_sub(1) as u128,
                });
            }
            if let Some(BoundResource::Ngram(model)) = self.bound_resource(id) {
                let (weights, max_abs) = model
                    .dense_parts()
                    .ok_or(ClimbUnsupported::SparseNgram(id))?;
                let order = model.order();
                let windows = length.saturating_sub(order - 1);
                if !crate::ngram::fits_i64(windows as u128, max_abs) {
                    return Err(ClimbUnsupported::WideNgram(id));
                }
                return Ok(ClimbObjective::DenseNgram {
                    order,
                    weights,
                    max_abs,
                });
            }
            Err(ClimbUnsupported::Objective(id))
        };
        let pairs = |pairs: &[(char, char)]| {
            pairs
                .iter()
                .map(|&(a, b)| {
                    (
                        alphabet.index_of(a).unwrap() as u8,
                        alphabet.index_of(b).unwrap() as u8,
                    )
                })
                .collect()
        };
        Ok(ClimbJob {
            alphabet_size: width,
            text_length: length,
            input,
            fixed_pairs: pairs(self.domain().fixed_pairs()),
            mutable_mask: alphabet
                .symbols
                .iter()
                .map(|c| self.domain().symbols().contains(c))
                .collect(),
            max_pairs: self.domain().max_pairs(),
            backtrack_pairs: self.settings().backtrack_pairs(),
            switch_pairs: self.settings().switch_pairs(),
            start_board: pairs(self.settings().start().expect("direct start")),
            initial_objective: objective(self.settings().initial_measure())?,
            final_objective: objective(self.settings().final_measure())?,
            owner: self,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_limits_bound_rows_keys_and_round_only_whole_blocks() {
        for (stride, preferred, expected) in [
            (1, 0, Some(128)),
            (1, 127, Some(128)),
            (1, 255, Some(128)),
            (1, 384, Some(384)),
            (1, usize::MAX, Some(512)),
            (MAX_DISPATCH_ROW_BYTES / 384, usize::MAX, Some(384)),
            (MAX_DISPATCH_ROW_BYTES / 128, usize::MAX, Some(128)),
            (MAX_DISPATCH_ROW_BYTES / 128 + 1, usize::MAX, None),
            (usize::MAX, usize::MAX, None),
            (0, usize::MAX, None),
        ] {
            assert_eq!(dispatch_key_limit(stride, preferred), expected);
            if let Some(keys) = expected {
                assert!(keys * stride <= MAX_DISPATCH_ROW_BYTES);
                assert!(keys <= MAX_DISPATCH_KEYS);
                assert_eq!(keys % 128, 0);
            }
        }
    }
}
