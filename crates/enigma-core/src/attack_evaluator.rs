//! Private fresh-state trial evaluation with retained, caller-borrowed scoring models.

use std::cell::{OnceCell, RefCell};

use crate::measure::{
    index_coincidence, index_coincidence_iter, index_entropy, index_entropy_iter,
};
use crate::{
    index_of_coincidence, shannon_entropy, AttackPlugboardDomain, BoundResource, Direction, Engine,
    MeasureError, MeasureId, MeasuredScore, ModelError, NgramModel, Plugboard,
    ResolvedConfiguration,
};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum TrialEvaluationError {
    Board(TrialBoardError),
    Model(ModelError),
    MissingResource(MeasureId),
    IncompatibleResource(MeasureId),
    Measure(MeasureError),
    /// An internal guarantee failed after successful scoring; never a user input error.
    Invariant(&'static str),
}

impl std::fmt::Display for TrialEvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Board(error) => write!(f, "trial board: {error}"),
            Self::Model(error) => write!(f, "trial model: {error}"),
            Self::Measure(error) => write!(f, "trial measure: {error}"),
            Self::MissingResource(id) => write!(f, "missing trial resource: {id:?}"),
            Self::IncompatibleResource(id) => write!(f, "incompatible trial resource: {id:?}"),
            Self::Invariant(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for TrialEvaluationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Board(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::Measure(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) struct TrialEvaluator<'a> {
    initial: &'a ResolvedConfiguration,
    domain: &'a AttackPlugboardDomain,
    input: &'a str,
    direction: Direction,
    objective: MeasureId,
    resource: Option<&'a BoundResource>,
    // Only successful checks of the immutable, borrowed binding are retained.
    binding: OnceCell<()>,
    // None in the cell remembers an allocation-policy fallback, not an unbuilt cache.
    prepared: OnceCell<Option<Prepared>>,
    shared: Option<(&'a RunPreparation<'a>, u128)>,
    engine_validated: OnceCell<()>,
    scratch: RefCell<TrialScratch>,
    #[cfg(test)]
    deny_reservation: bool,
    #[cfg(test)]
    force_wide: bool,
}

#[derive(Default)]
struct TrialScratch {
    mapping: Vec<usize>,
    indices: Vec<u32>,
}

/// Board-independent alphabet indices: the input, then one scrambler row per offset.
/// Alphabets of at most 256 symbols use compact byte rows (one byte per entry, one
/// alphabet-wide row per offset, no padding) when they fit the data limit; larger
/// alphabets or inputs keep `u32` rows under their own limit.
#[derive(Debug)]
enum Prepared {
    Bytes { input: Vec<u8>, rows: Vec<u8> },
    Wide { input: Vec<u32>, rows: Vec<u32> },
}

/// Index kernels a prepared trial can stream into without materializing output.
#[derive(Clone, Copy)]
enum StreamKind<'a> {
    Ic,
    Entropy,
    Dense(&'a NgramModel),
}

/// Runs `$body` with `$decoded` bound to the prepared table's concrete decoder, so
/// each kernel is compiled once per table kind with no per-symbol dispatch.
macro_rules! with_decoded {
    ($prepared:expr, $mapping:expr, |$decoded:ident| $body:expr) => {
        match $prepared {
            Prepared::Bytes { input, rows } => {
                let $decoded = ByteDecoded::new(input, rows, $mapping);
                $body
            }
            Prepared::Wide { input, rows } => {
                let $decoded = WideDecoded::new(input, rows, $mapping);
                $body
            }
        }
    };
}

/// Decrypted output indices of a byte table, computed on demand.
struct ByteDecoded<'p> {
    steps: std::iter::Zip<std::slice::Iter<'p, u8>, std::slice::ChunksExact<'p, u8>>,
    mapping: [u8; 256],
}

impl<'p> ByteDecoded<'p> {
    fn new(input: &'p [u8], rows: &'p [u8], mapping: &[usize]) -> Self {
        // Byte tables exist only for alphabets of at most 256 symbols, so every
        // mapping value fits a byte; entries past the alphabet are never read.
        // A 256-entry copy keeps byte-indexed mapping lookups in bounds by type,
        // while row lookups stay checked against the alphabet width.
        let mut bytes = [0; 256];
        for (byte, &index) in bytes.iter_mut().zip(mapping) {
            debug_assert!(index < 256);
            *byte = index as u8;
        }
        Self {
            steps: input.iter().zip(rows.chunks_exact(mapping.len())),
            mapping: bytes,
        }
    }
}

impl Iterator for ByteDecoded<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let (&symbol, row) = self.steps.next()?;
        let signal = self.mapping[usize::from(symbol)];
        Some(u32::from(
            self.mapping[usize::from(row[usize::from(signal)])],
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.steps.size_hint()
    }
}

impl ExactSizeIterator for ByteDecoded<'_> {}

/// Decrypted output indices of a `u32` table, computed on demand.
struct WideDecoded<'p> {
    steps: std::iter::Zip<std::slice::Iter<'p, u32>, std::slice::ChunksExact<'p, u32>>,
    mapping: &'p [usize],
}

impl<'p> WideDecoded<'p> {
    fn new(input: &'p [u32], rows: &'p [u32], mapping: &'p [usize]) -> Self {
        // The trial board is bound to this alphabet, so its mapping is indexed by
        // the same alphabet indices as the rows, and every row is one mapping wide.
        // Alphabets are never empty, so the width is positive.
        Self {
            steps: input.iter().zip(rows.chunks_exact(mapping.len())),
            mapping,
        }
    }
}

impl Iterator for WideDecoded<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let (&symbol, row) = self.steps.next()?;
        let signal = self.mapping[symbol as usize];
        Some(self.mapping[row[signal] as usize] as u32)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.steps.size_hint()
    }
}

impl ExactSizeIterator for WideDecoded<'_> {}

/// The streamed IC ranking of a prepared byte-table trial, exactly as
/// [`TrialEvaluator`] scores it, in Q32 units.
#[cfg(feature = "gpu-spike")]
pub(crate) fn spike_ic_units(
    input: &[u8],
    rows: &[u8],
    mapping: &[usize],
) -> Result<i128, MeasureError> {
    let decoded = ByteDecoded::new(input, rows, mapping);
    index_coincidence_iter(mapping.len(), decoded).map(|score| score.ranking().units())
}

/// The streamed dense n-gram ranking of a prepared byte-table trial, exactly as
/// [`TrialEvaluator`] scores it, in Q32 units; None without a dense table.
#[cfg(feature = "gpu-spike")]
pub(crate) fn spike_dense_units(
    model: &NgramModel,
    input: &[u8],
    rows: &[u8],
    mapping: &[usize],
) -> Option<Result<i128, MeasureError>> {
    let decoded = ByteDecoded::new(input, rows, mapping);
    model
        .score_index_iter(decoded)
        .map(|score| score.map(|score| score.ranking().units()))
}

/// A single run's input/domain/direction and most recently evaluated outer.
/// The scheduler supplies absolute outer indices from this same request only.
/// No row reference escapes a trial, so eviction drops the old payload before building.
pub(super) struct RunPreparation<'a> {
    owner: &'a crate::AttackRequest,
    pub(super) bombe: RefCell<(crate::bombe::Scratch, Vec<u32>)>,
    latest: RefCell<Option<(u128, OnceCell<Option<Prepared>>)>>,
}

impl<'a> RunPreparation<'a> {
    pub(super) fn new(owner: &'a crate::AttackRequest) -> Self {
        Self {
            owner,
            bombe: RefCell::new((crate::bombe::Scratch::default(), Vec::new())),
            latest: RefCell::new(None),
        }
    }

    pub(super) fn evaluator(
        &'a self,
        initial: &'a ResolvedConfiguration,
        outer_index: u128,
        objective: MeasureId,
    ) -> TrialEvaluator<'a> {
        self.evaluator_in_domain(initial, self.owner.domain(), outer_index, objective)
    }

    /// Keep the board-free row cache while binding a stop-specific fixed/mutable domain.
    pub(super) fn evaluator_in_domain(
        &'a self,
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        outer_index: u128,
        objective: MeasureId,
    ) -> TrialEvaluator<'a> {
        let mut evaluator = TrialEvaluator::new(
            initial,
            domain,
            self.owner.text(),
            Direction::Decrypt,
            objective,
            self.owner.bound_resource(objective),
        );
        evaluator.shared = Some((self, outer_index));
        evaluator
    }
}

impl<'a> TrialEvaluator<'a> {
    pub(super) fn new(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        input: &'a str,
        direction: Direction,
        objective: MeasureId,
        resource: Option<&'a BoundResource>,
    ) -> Self {
        Self {
            initial,
            domain,
            input,
            direction,
            objective,
            resource,
            binding: OnceCell::new(),
            prepared: OnceCell::new(),
            shared: None,
            engine_validated: OnceCell::new(),
            scratch: RefCell::new(TrialScratch::default()),
            #[cfg(test)]
            deny_reservation: false,
            #[cfg(test)]
            force_wide: false,
        }
    }

    /// Prepare through the same validation, allocation policy and Engine as trials.
    pub(super) fn byte_rows(
        &self,
        start: &[(char, char)],
    ) -> Result<Vec<u8>, TrialEvaluationError> {
        self.with_trial(start, |_, _, prepared, _| match prepared {
            Some(Prepared::Bytes { rows, .. }) => Ok(rows.clone()),
            _ => Err(TrialEvaluationError::Invariant(
                "accelerator byte-row preparation failed",
            )),
        })
    }

    /// Retain host-prepared rows for reference climbs and uncharged terminal checks.
    pub(super) fn with_byte_rows(self, input: &[u8], rows: &[u8]) -> Self {
        self.prepared
            .set(Some(Prepared::Bytes {
                input: input.to_vec(),
                rows: rows.to_vec(),
            }))
            .expect("fresh evaluator");
        self
    }

    pub(super) fn objective(&self) -> MeasureId {
        self.objective
    }

    pub(super) fn evaluate(
        &self,
        mutable: &[(char, char)],
    ) -> Result<(String, MeasuredScore), TrialEvaluationError> {
        self.with_trial(mutable, |mapping, indices, prepared, engine| {
            self.materialize(mapping, indices, prepared, engine)
        })
    }

    /// [`Self::evaluate`]'s score, with identical errors and precedence. Streamable
    /// prepared trials build no plaintext (None); others carry their materialized one.
    pub(super) fn evaluate_score(
        &self,
        mutable: &[(char, char)],
    ) -> Result<(Option<String>, MeasuredScore), TrialEvaluationError> {
        self.with_trial(mutable, |mapping, indices, prepared, engine| {
            self.score(mapping, indices, prepared, engine)
        })
    }

    /// [`Self::evaluate_score`] for a full alphabet-index involution that already
    /// holds the fixed pairs and a mutable board within mask and capacity. Callers
    /// own that invariant, so no board is built or limit checked; binding,
    /// preparation and scoring errors keep their order.
    pub(super) fn evaluate_score_mapped(
        &self,
        mapping: &[usize],
    ) -> Result<(Option<String>, MeasuredScore), TrialEvaluationError> {
        debug_assert_eq!(mapping.len(), self.initial.topology().alphabet().len());
        self.check_binding()?;
        let mut scratch = self.scratch.borrow_mut();
        self.with_mapping(
            mapping,
            &mut scratch.indices,
            |mapping, indices, prepared, engine| self.score(mapping, indices, prepared, engine),
        )
    }

    fn score(
        &self,
        mapping: &[usize],
        indices: &mut Vec<u32>,
        prepared: Option<&Prepared>,
        engine: Option<&mut Engine>,
    ) -> Result<(Option<String>, MeasuredScore), TrialEvaluationError> {
        if let (Some(prepared), Some(kind)) = (prepared, self.stream_kind()) {
            let width = self.initial.topology().alphabet().len();
            let score = with_decoded!(prepared, mapping, |decoded| match kind {
                StreamKind::Ic => Some(index_coincidence_iter(width, decoded)),
                StreamKind::Entropy => Some(index_entropy_iter(width, decoded)),
                StreamKind::Dense(model) => model.score_index_iter(decoded),
            });
            // A model without a dense table keeps its sparse text scoring.
            if let Some(score) = score {
                return Ok((None, score.map_err(TrialEvaluationError::Measure)?));
            }
        }
        let (plaintext, score) = self.materialize(mapping, indices, prepared, engine)?;
        Ok((Some(plaintext), score))
    }

    /// Rebuild a streamed winner's plaintext without scoring or accounting. Only
    /// prepared boards that already succeeded reach here; anything else is an invariant.
    pub(super) fn replay_plaintext(
        &self,
        mutable: &[(char, char)],
    ) -> Result<String, TrialEvaluationError> {
        const FAILED: TrialEvaluationError =
            TrialEvaluationError::Invariant("winner plaintext replay failed");
        self.with_trial(mutable, |mapping, _, prepared, _| {
            let symbols = &self.initial.topology().alphabet().symbols;
            let rows = prepared.ok_or(FAILED)?;
            #[cfg(test)]
            PLAINTEXT_BUILDS.with(|count| count.set(count.get() + 1));
            Ok(with_decoded!(rows, mapping, |decoded| decoded
                .map(|output| symbols[output as usize])
                .collect()))
        })
        .map_err(|_| FAILED)
    }

    /// Only a successful check of the immutable, borrowed binding is cached.
    fn check_binding(&self) -> Result<(), TrialEvaluationError> {
        if self.binding.get().is_none() {
            validate_binding(self.initial, self.domain).map_err(TrialEvaluationError::Board)?;
            // Retain success even if mutable, input or scoring validation below fails.
            self.binding.set(()).expect("single-threaded binding check");
        }
        Ok(())
    }

    /// Shared board prefix: binding, board model and mutable limits, then
    /// [`Self::with_mapping`] over the filled scratch mapping.
    fn with_trial<T>(
        &self,
        mutable: &[(char, char)],
        run: impl FnOnce(
            &[usize],
            &mut Vec<u32>,
            Option<&Prepared>,
            Option<&mut Engine>,
        ) -> Result<T, TrialEvaluationError>,
    ) -> Result<T, TrialEvaluationError> {
        self.check_binding()?;
        let mut scratch = self.scratch.borrow_mut();
        let TrialScratch { mapping, indices } = &mut *scratch;
        #[cfg(test)]
        BOARD_FILLS.with(|count| count.set(count.get() + 1));
        Plugboard::fill_mapping(
            self.initial.topology().alphabet(),
            self.domain.fixed_pairs().iter().chain(mutable).copied(),
            mapping,
        )
        .map_err(|error| TrialEvaluationError::Board(TrialBoardError::Model(error)))?;
        check_mutable_limits(self.domain, mutable).map_err(TrialEvaluationError::Board)?;
        self.with_mapping(mapping, indices, run)
    }

    /// Selects the outer's preparation for a bound, valid mapping; `run` receives
    /// the mapping, index scratch, rows and a borrow of any leftover fresh Engine.
    fn with_mapping<T>(
        &self,
        mapping: &[usize],
        indices: &mut Vec<u32>,
        run: impl FnOnce(
            &[usize],
            &mut Vec<u32>,
            Option<&Prepared>,
            Option<&mut Engine>,
        ) -> Result<T, TrialEvaluationError>,
    ) -> Result<T, TrialEvaluationError> {
        let latest;
        let prepared = if let Some((run_preparation, outer)) = self.shared {
            let mut slot = run_preparation.latest.borrow_mut();
            if slot.as_ref().map(|(key, _)| *key) != Some(outer) {
                // Explicitly drop the previous table before any new allocation.
                *slot = None;
                *slot = Some((outer, OnceCell::new()));
            }
            latest = slot;
            &latest.as_ref().expect("selected outer").1
        } else {
            &self.prepared
        };
        // A new evaluator must validate its constructor even when rows are shared.
        // An initialized None is also warm: retain the remembered fallback policy.
        if self.engine_validated.get().is_some() {
            if let Some(prepared) = prepared.get() {
                return run(mapping, indices, prepared.as_ref(), None);
            }
        }
        let mut engine = self.prepare(mapping, prepared)?;
        run(
            mapping,
            indices,
            prepared.get().expect("prepared above").as_ref(),
            engine.as_mut(),
        )
    }

    /// Validates the Engine constructor and lazily builds rows; returns an Engine
    /// that the fallback path may reuse.
    fn prepare(
        &self,
        mapping: &[usize],
        prepared: &OnceCell<Option<Prepared>>,
    ) -> Result<Option<Engine>, TrialEvaluationError> {
        let mut engine = None;
        // Shared rows never certify a new evaluator's Engine constructor. Cache
        // only its successful immutable validation, after this trial's board check.
        if self.engine_validated.get().is_none() || prepared.get().is_none() {
            engine = Some(self.fresh_engine(Plugboard::from_validated_mapping(
                self.initial.topology().alphabet(),
                mapping,
            ))?);
            self.engine_validated.set(()).ok();
        }
        if prepared.get().is_none() {
            // Preserve constructor-before-full-input validation, even on fallback.
            let mut fresh = engine.take().expect("cold preparation has fresh engine");
            let alphabet = self.initial.topology().alphabet();
            let mut input = Vec::with_capacity(self.input.len());
            for symbol in self.input.chars() {
                let index = alphabet
                    .index_of(symbol)
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or(TrialEvaluationError::Model(ModelError::UnknownSymbol(
                        symbol,
                    )))?;
                input.push(index);
            }
            let length = input.len();
            let width = alphabet.symbols.len();
            let table = if self.reserve_denied() {
                None
            } else if let Some(mut rows) = (byte_rows_fit(length, width) && !self.wide_forced())
                .then(|| reserved_byte_rows(length, width))
                .flatten()
            {
                fresh
                    .scrambler_byte_rows(length, self.direction, &mut rows)
                    .map_err(TrialEvaluationError::Model)?;
                // Indices below a width of at most 256 fit a byte.
                let input = input.iter().map(|&index| index as u8).collect();
                Some(Prepared::Bytes { input, rows })
            } else if let Some(mut rows) = reserved_rows(length, width, false) {
                fresh
                    .scrambler_rows(length, self.direction, &mut rows)
                    .map_err(TrialEvaluationError::Model)?;
                Some(Prepared::Wide { input, rows })
            } else {
                None
            };
            if table.is_none() {
                engine = Some(fresh);
            }
            // Failed model/input validation never initializes the cell.
            prepared
                .set(table)
                .expect("single-threaded lazy preparation");
        }
        Ok(engine)
    }

    fn materialize(
        &self,
        mapping: &[usize],
        indices: &mut Vec<u32>,
        prepared: Option<&Prepared>,
        engine: Option<&mut Engine>,
    ) -> Result<(String, MeasuredScore), TrialEvaluationError> {
        #[cfg(test)]
        PLAINTEXT_BUILDS.with(|count| count.set(count.get() + 1));
        match prepared {
            Some(prepared) => {
                let symbols = &self.initial.topology().alphabet().symbols;
                let mut plaintext = String::with_capacity(self.input.len());
                indices.clear();
                with_decoded!(prepared, mapping, |decoded| {
                    for output in decoded {
                        plaintext.push(symbols[output as usize]);
                        indices.push(output);
                    }
                });
                let score = self.measure_with(&plaintext, Some(indices))?;
                Ok((plaintext, score))
            }
            None => {
                let mut fresh;
                let engine = match engine {
                    Some(engine) => engine,
                    None => {
                        fresh = self.fresh_engine(Plugboard::from_validated_mapping(
                            self.initial.topology().alphabet(),
                            mapping,
                        ))?;
                        &mut fresh
                    }
                };
                let plaintext = engine
                    .transform(self.input, self.direction)
                    .map_err(TrialEvaluationError::Model)?;
                let score = self.measure(&plaintext)?;
                Ok((plaintext, score))
            }
        }
    }

    /// The index kernel [`Self::measure_with`] would select, under the same guards.
    /// None keeps every other path (errors, trie) on materializing scoring.
    fn stream_kind(&self) -> Option<StreamKind<'a>> {
        let alphabet = self.initial.topology().alphabet();
        match (self.objective, self.resource) {
            (MeasureId::Ic, None) => Some(StreamKind::Ic),
            (MeasureId::Entropy, None) => Some(StreamKind::Entropy),
            (objective, Some(BoundResource::Ngram(model)))
                if objective.order() == Some(model.order()) && model.alphabet() == alphabet =>
            {
                Some(StreamKind::Dense(model))
            }
            _ => None,
        }
    }

    fn fresh_engine(&self, board: Plugboard) -> Result<Engine, TrialEvaluationError> {
        #[cfg(test)]
        ENGINE_CHECKS.with(|count| count.set(count.get() + 1));
        Engine::new(
            self.initial.topology().clone(),
            self.initial.stepping().clone(),
            board,
        )
        .map_err(TrialEvaluationError::Model)
    }

    #[cfg(test)]
    pub(super) fn with_reservation_denied(mut self) -> Self {
        self.deny_reservation = true;
        self
    }

    fn wide_forced(&self) -> bool {
        #[cfg(test)]
        {
            self.force_wide
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    fn reserve_denied(&self) -> bool {
        #[cfg(test)]
        {
            self.deny_reservation
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// One decryption; optional base scoring reuses that exact plaintext.
    pub(super) fn evaluate_trie(
        &self,
        mutable: &[(char, char)],
        base: Option<&Self>,
        carried: crate::FixedScore,
    ) -> Result<(String, MeasuredScore), TrialEvaluationError> {
        let (plaintext, trie) = self.evaluate(mutable)?;
        let ranking = match base {
            Some(base) => base.measure(&plaintext)?.ranking(),
            None => carried,
        };
        let score = trie
            .with_ranking_base(ranking)
            .map_err(TrialEvaluationError::Measure)?;
        Ok((plaintext, score))
    }

    fn measure(&self, plaintext: &str) -> Result<MeasuredScore, TrialEvaluationError> {
        self.measure_with(plaintext, None)
    }

    /// Prepared trials pass the plaintext's alphabet indices, already known valid, so
    /// IC, entropy and n-gram scoring skip per-symbol membership lookups. The resource
    /// guards and their order are shared with the character path.
    fn measure_with(
        &self,
        plaintext: &str,
        indices: Option<&[u32]>,
    ) -> Result<MeasuredScore, TrialEvaluationError> {
        let alphabet = self.initial.topology().alphabet();
        let incompatible = || TrialEvaluationError::IncompatibleResource(self.objective);
        let score = match (self.objective, self.resource) {
            (MeasureId::Ic, None) => match indices {
                Some(indices) => index_coincidence(alphabet.len(), indices),
                None => index_of_coincidence(alphabet, plaintext),
            },
            (MeasureId::Entropy, None) => match indices {
                Some(indices) => index_entropy(alphabet.len(), indices),
                None => shannon_entropy(alphabet, plaintext),
            },
            (objective, None) if objective.requires_resource() => {
                return Err(TrialEvaluationError::MissingResource(objective));
            }
            (objective, Some(BoundResource::Ngram(model)))
                if objective.order() == Some(model.order()) && model.alphabet() == alphabet =>
            {
                match indices {
                    Some(indices) => model.score_indices(plaintext, indices),
                    None => model.score(plaintext),
                }
            }
            (MeasureId::Trie, Some(BoundResource::Trie(model))) if model.alphabet() == alphabet => {
                model.score(plaintext)
            }
            _ => return Err(incompatible()),
        };
        score.map_err(TrialEvaluationError::Measure)
    }
}

const TABLE_DATA_LIMIT: usize = 1024 * 1024;

fn table_entries(length: usize, width: usize) -> Option<usize> {
    let entries = length.checked_mul(width)?;
    (entries.checked_mul(std::mem::size_of::<u32>())? <= TABLE_DATA_LIMIT).then_some(entries)
}

/// Compact byte rows cost `width` bytes per input symbol under the same data limit.
pub(crate) fn byte_rows_fit(length: usize, width: usize) -> bool {
    width <= 256 && byte_row_entries(length, width).is_some()
}

fn byte_row_entries(length: usize, width: usize) -> Option<usize> {
    length
        .checked_mul(width)
        .filter(|&bytes| bytes <= TABLE_DATA_LIMIT)
}

fn reserved_byte_rows(length: usize, width: usize) -> Option<Vec<u8>> {
    let entries = byte_row_entries(length, width)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(entries).ok()?;
    Some(rows)
}

fn reserved_rows(length: usize, width: usize, deny: bool) -> Option<Vec<u32>> {
    let entries = table_entries(length, width)?;
    let mut rows = Vec::new();
    if deny || rows.try_reserve_exact(entries).is_err() {
        return None;
    }
    Some(rows)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TrialBoardError {
    AlphabetBinding,
    FixedFactsBinding,
    OutsideMutable(char),
    TotalCapacity,
    Model(ModelError),
}

impl std::fmt::Display for TrialBoardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Model(error) => write!(f, "trial board model: {error}"),
            Self::AlphabetBinding => f.write_str("trial board alphabet binding mismatch"),
            Self::FixedFactsBinding => f.write_str("trial board fixed facts mismatch"),
            Self::OutsideMutable(symbol) => write!(f, "symbol outside mutable board: {symbol}"),
            Self::TotalCapacity => f.write_str("trial board capacity exceeded"),
        }
    }
}

impl std::error::Error for TrialBoardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
thread_local! {
    pub(super) static BINDING_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static ENGINE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static PLAINTEXT_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static BOARD_FILLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Accept only mutable guesses, bound to the selected initial scrambler.
/// Fixed facts are compared by mapping; their stored order and orientation stay untouched.
pub(crate) fn validated_trial_board(
    initial: &ResolvedConfiguration,
    domain: &AttackPlugboardDomain,
    mutable: &[(char, char)],
) -> Result<Plugboard, TrialBoardError> {
    validate_binding(initial, domain)?;
    checked_mutable_board(initial, domain, mutable)
}

fn validate_binding(
    initial: &ResolvedConfiguration,
    domain: &AttackPlugboardDomain,
) -> Result<(), TrialBoardError> {
    #[cfg(test)]
    BINDING_CHECKS.with(|count| count.set(count.get() + 1));
    let alphabet = initial.topology().alphabet();
    if !domain.matches_alphabet(alphabet) {
        return Err(TrialBoardError::AlphabetBinding);
    }
    // Compare electrical facts, not pair order or orientation. Never normalize inputs.
    let fixed = Plugboard::new(alphabet, domain.fixed_pairs()).map_err(TrialBoardError::Model)?;
    if &fixed != initial.plugboard() {
        return Err(TrialBoardError::FixedFactsBinding);
    }
    Ok(())
}

fn checked_mutable_board(
    initial: &ResolvedConfiguration,
    domain: &AttackPlugboardDomain,
    mutable: &[(char, char)],
) -> Result<Plugboard, TrialBoardError> {
    let alphabet = initial.topology().alphabet();
    let mut pairs = domain.fixed_pairs().to_vec();
    pairs.extend_from_slice(mutable);
    // Existing model validation reports self-pairs, foreign and reused endpoints.
    let board = Plugboard::new(alphabet, &pairs).map_err(TrialBoardError::Model)?;
    check_mutable_limits(domain, mutable)?;
    Ok(board)
}

fn check_mutable_limits(
    domain: &AttackPlugboardDomain,
    mutable: &[(char, char)],
) -> Result<(), TrialBoardError> {
    for &(a, b) in mutable {
        for symbol in [a, b] {
            if !domain.symbols().contains(&symbol) {
                return Err(TrialBoardError::OutsideMutable(symbol));
            }
        }
    }
    if domain.fixed_pairs().len() + mutable.len() > domain.max_pairs() {
        return Err(TrialBoardError::TotalCapacity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Alphabet, DefinitionSource, SlotConfiguration, TransformConfiguration};

    #[test]
    fn warm_trials_build_no_plugboard() {
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let trial = evaluator(&initial, &domain, "AA");
        let expected = trial.evaluate(&[]).unwrap();
        crate::PLUGBOARD_BUILDS.with(|c| c.set(0));
        BINDING_CHECKS.with(|c| c.set(0));
        assert_eq!(trial.evaluate(&[]).unwrap(), expected);
        assert_eq!(crate::PLUGBOARD_BUILDS.with(|c| c.get()), 0);
        assert_eq!(BINDING_CHECKS.with(|c| c.get()), 0);
    }

    #[test]
    fn cold_and_fallback_trials_still_build_plugboards() {
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        for deny in [false, true] {
            let mut trial = evaluator(&initial, &domain, "AA");
            trial.deny_reservation = deny;
            crate::PLUGBOARD_BUILDS.with(|c| c.set(0));
            let expected = trial.evaluate(&[]).unwrap();
            assert_eq!(crate::PLUGBOARD_BUILDS.with(|c| c.get()), 2);
            crate::PLUGBOARD_BUILDS.with(|c| c.set(0));
            assert_eq!(trial.evaluate(&[]).unwrap(), expected);
            assert_eq!(crate::PLUGBOARD_BUILDS.with(|c| c.get()), usize::from(deny));
        }
    }

    #[test]
    fn scratch_trials_match_standalone_boards_and_reset_after_errors() {
        for symbols in ["ABCDEFGH", "界éHβAGλ中"] {
            let alphabet = Alphabet::new(symbols.chars().collect()).unwrap();
            let s = &alphabet.symbols;
            let fixed = [(s[0], s[1])];
            let initial = initial(&alphabet, &fixed);
            let mutable_symbols: String = s[2..6].iter().collect();
            let domain = domain(&alphabet, &fixed, &mutable_symbols, 2);
            let trial = evaluator(&initial, &domain, symbols);
            let valid = [(s[2], s[3])];
            let expected_valid = trial.evaluate(&valid).unwrap();
            let endpoints: Vec<_> = s.iter().copied().chain(['?']).collect();
            let mut cases = vec![vec![], valid.to_vec()];
            for &left in &endpoints {
                for &right in &endpoints {
                    let pair = (left, right);
                    cases.push(vec![pair]);
                    for second in [
                        (s[2], s[3]),
                        (s[4], s[5]),
                        (s[6], s[7]),
                        (s[4], s[4]),
                        (s[4], '?'),
                    ] {
                        cases.push(vec![pair, second]);
                    }
                }
            }
            for board in cases {
                let expected = validated_trial_board(&initial, &domain, &board)
                    .map_err(TrialEvaluationError::Board)
                    .and_then(|board| {
                        let mut engine = trial.fresh_engine(board)?;
                        let plaintext = engine
                            .transform(symbols, Direction::Decrypt)
                            .map_err(TrialEvaluationError::Model)?;
                        let score = trial.measure(&plaintext)?;
                        Ok((plaintext, score))
                    });
                assert_eq!(trial.evaluate(&board), expected, "{symbols}: {board:?}");
                assert_eq!(trial.evaluate(&valid).unwrap(), expected_valid);
                assert_eq!(trial.evaluate(&[]).unwrap().0, symbols);
            }
        }
    }

    #[test]
    fn successful_binding_survives_later_failures_but_failed_binding_retries() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let valid = domain(&alphabet, &[('B', 'A')], "CDEF", 2);
        for (input, objective) in [
            ("AACD", MeasureId::Ic),
            ("AAZ", MeasureId::Ic),
            ("A", MeasureId::Ic),
            ("AACD", MeasureId::SinkovBigram),
        ] {
            BINDING_CHECKS.with(|c| c.set(0));
            let trial =
                TrialEvaluator::new(&initial, &valid, input, Direction::Decrypt, objective, None);
            assert_eq!(BINDING_CHECKS.with(|c| c.get()), 0);
            assert!(matches!(
                trial.evaluate(&[('C', 'C')]),
                Err(TrialEvaluationError::Board(TrialBoardError::Model(
                    ModelError::PlugboardSelfPair('C')
                )))
            ));
            assert_eq!(BINDING_CHECKS.with(|c| c.get()), 1);
            BINDING_CHECKS.with(|c| c.set(0));
            let first = trial.evaluate(&[]);
            assert!(trial.evaluate(&[('C', 'C')]).is_err());
            assert_eq!(trial.evaluate(&[]), first);
            assert_eq!(BINDING_CHECKS.with(|c| c.get()), 0, "{input}");
        }
        let reversed = Alphabet::new("HGFEDCBA".chars().collect()).unwrap();
        for (invalid, error, builds) in [
            (
                domain(&reversed, &[], "CD", 1),
                TrialBoardError::AlphabetBinding,
                0,
            ),
            (
                domain(&alphabet, &[], "CD", 1),
                TrialBoardError::FixedFactsBinding,
                1,
            ),
        ] {
            let trial = evaluator(&initial, &invalid, "Z");
            BINDING_CHECKS.with(|c| c.set(0));
            crate::PLUGBOARD_BUILDS.with(|c| c.set(0));
            let expected = TrialEvaluationError::Board(error);
            for count in 1..=2 {
                assert_eq!(trial.evaluate(&[('C', 'C')]).unwrap_err(), expected);
                assert_eq!(BINDING_CHECKS.with(|c| c.get()), count);
                assert_eq!(crate::PLUGBOARD_BUILDS.with(|c| c.get()), builds * count);
            }
        }
    }

    #[test]
    fn validation_precedence_matrix_cold_and_warm() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let domain = domain(&alphabet, &[('A', 'B')], "CDEF", 2);
        let cases = [
            (
                vec![('G', 'H'), ('C', 'C')],
                TrialBoardError::Model(ModelError::PlugboardSelfPair('C')),
            ),
            (
                vec![('C', 'D'), ('E', 'Z')],
                TrialBoardError::Model(ModelError::UnknownSymbol('Z')),
            ),
            (
                vec![('C', 'D'), ('E', 'G')],
                TrialBoardError::OutsideMutable('G'),
            ),
            (vec![('H', 'G')], TrialBoardError::OutsideMutable('H')),
            (vec![('C', 'D'), ('E', 'F')], TrialBoardError::TotalCapacity),
        ];
        for warm in [false, true] {
            for input in ["AACD", "Z"] {
                let trial = TrialEvaluator::new(
                    &initial,
                    &domain,
                    input,
                    Direction::Decrypt,
                    MeasureId::SinkovBigram,
                    None,
                );
                if warm {
                    let expected = if input == "Z" {
                        TrialEvaluationError::Model(ModelError::UnknownSymbol('Z'))
                    } else {
                        TrialEvaluationError::MissingResource(MeasureId::SinkovBigram)
                    };
                    assert_eq!(trial.evaluate(&[]).unwrap_err(), expected);
                }
                for (board, expected) in &cases {
                    assert_eq!(
                        validated_trial_board(&initial, &domain, board).unwrap_err(),
                        *expected
                    );
                    assert_eq!(
                        trial.evaluate(board).unwrap_err(),
                        TrialEvaluationError::Board(
                            validated_trial_board(&initial, &domain, board).unwrap_err()
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn lazy_rows_are_built_once_across_boards_and_rejected_trials() {
        crate::engine::ROW_BUILDS.with(|count| count.set(0));
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let trial = evaluator(&initial, &domain, "AA");
        crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), 0));
        assert!(trial.evaluate(&[('A', 'A')]).is_err());
        crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), 0));
        let a = trial.evaluate(&[]).unwrap();
        trial.evaluate(&[('A', 'B')]).unwrap();
        assert!(trial.evaluate(&[('A', 'A')]).is_err());
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), 1));
    }

    #[test]
    fn prepared_trials_decrypt_and_score_without_symbol_lookups() {
        let initial = machine("ABC", "BAC", "A", true);
        let alphabet = initial.topology().alphabet();
        let domain = domain(alphabet, &[], "ABC", 1);
        let resource = ngram(alphabet, 2);
        for (objective, resource) in [
            (MeasureId::Ic, None),
            (MeasureId::Entropy, None),
            (MeasureId::SinkovBigram, Some(&resource)),
        ] {
            let input = "ABCAB".repeat(4);
            let trial = TrialEvaluator::new(
                &initial,
                &domain,
                &input,
                Direction::Decrypt,
                objective,
                resource,
            );
            let first = trial.evaluate(&[]).unwrap();
            crate::INDEX_LOOKUPS.with(|count| count.set(0));
            assert_eq!(trial.evaluate(&[]).unwrap(), first);
            crate::INDEX_LOOKUPS.with(|count| assert_eq!(count.get(), 0, "{objective:?}"));
        }
    }

    #[test]
    fn prepared_trigram_trials_bypass_sparse_lookups() {
        let alphabet = Alphabet::new("ABC".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "ABC", 1);
        let resource = ngram(&alphabet, 3);
        let input = "ABCAAABBBABC";
        let trial = TrialEvaluator::new(
            &initial,
            &domain,
            input,
            Direction::Decrypt,
            MeasureId::SinkovTrigram,
            Some(&resource),
        );
        let first = trial.evaluate(&[]).unwrap();
        assert_eq!(first.0, input);
        crate::ngram::SPARSE_LOOKUPS.with(|count| count.set(0));
        assert_eq!(trial.measure(input), Ok(first.1));
        crate::ngram::SPARSE_LOOKUPS.with(|count| assert_eq!(count.get(), input.len() - 2));
        crate::ngram::SPARSE_LOOKUPS.with(|count| count.set(0));
        assert_eq!(trial.evaluate(&[]).unwrap(), first);
        crate::ngram::SPARSE_LOOKUPS.with(|count| assert_eq!(count.get(), 0));
    }

    #[test]
    fn prepared_trials_keep_sparse_fallback_for_oversized_models() {
        let symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let alphabet = Alphabet::new(symbols.chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], symbols, 13);
        let input = "AAAABAAABBBBB";
        for (order, objective) in (4..=6).zip(SINKOV.into_iter().skip(3)) {
            let resource = ngram(&alphabet, order);
            let trial = TrialEvaluator::new(
                &initial,
                &domain,
                input,
                Direction::Decrypt,
                objective,
                Some(&resource),
            );
            let first = trial.evaluate(&[]).unwrap();
            assert_eq!(first.0, input);
            assert_eq!(trial.measure(input), Ok(first.1));
            crate::ngram::SPARSE_LOOKUPS.with(|count| count.set(0));
            assert_eq!(trial.evaluate(&[]).unwrap(), first);
            crate::ngram::SPARSE_LOOKUPS
                .with(|count| assert_eq!(count.get(), input.len() - order + 1));
        }
    }

    fn turnover_machine(symbols: &str, reflector: bool) -> ResolvedConfiguration {
        let s: Vec<_> = symbols.chars().collect();
        let mut slots = Vec::new();
        if reflector {
            slots.push(
                serde_json::json!({"id":"ukw","role":"reflector","movement":"fixed","wheel":"ukw"}),
            );
        }
        for id in ["slow", "middle", "fast"] {
            slots
                .push(serde_json::json!({"id":id,"role":"rotor","movement":"movable","wheel":"r"}));
        }
        let source = serde_json::json!({"kind":"custom","value":{
        "alphabet":s,
        "wheels":[{"name":"r","wiring":[s[1],s[3],s[2],s[0]],"turnovers":[s[3]]},
                  {"name":"ukw","wiring":[s[1],s[0],s[3],s[2]],"turnovers":[]}],
        "slots":slots,"stepping":{"rules":[
            {"when":{"always":true},"advance":["fast"]},
            {"when":{"at_turnover":"fast"},"advance":["middle","fast"]},
            {"when":{"at_turnover":"middle"},"advance":["slow","middle"]},
            {"when":{"at_turnover":"middle"},"advance":["middle"]}
        ]}}});
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        let mut config = Vec::new();
        if reflector {
            config.push(SlotConfiguration::new("ukw", "ukw", s[2], s[1]));
        }
        config.extend([
            SlotConfiguration::new("slow", "r", s[1], s[2]),
            SlotConfiguration::new("middle", "r", s[2], s[1]),
            SlotConfiguration::new("fast", "r", s[3], s[2]),
        ]);
        TransformConfiguration::new(config, vec![(s[0], s[1])])
            .resolve(&definition)
            .unwrap()
    }

    #[test]
    fn cached_and_denied_tables_match_fresh_engine_across_contexts() {
        for symbols in ["ABCD", "界Aéλ"] {
            let s: Vec<_> = symbols.chars().collect();
            for reflector in [false, true] {
                let initial = turnover_machine(symbols, reflector);
                let domain = domain(
                    initial.topology().alphabet(),
                    &[(s[0], s[1])],
                    &symbols.chars().skip(2).collect::<String>(),
                    2,
                );
                // Fast turnover advances middle onto its own notch, then middle
                // advances again on the next keypress (the real double-step).
                let mut probe = initial.clone().into_engine().unwrap();
                probe
                    .transform(&s[0].to_string(), Direction::Encrypt)
                    .unwrap();
                let start = usize::from(reflector);
                assert_eq!(&probe.positions()[start..], &[s[1], s[3], s[0]]);
                probe
                    .transform(&s[0].to_string(), Direction::Encrypt)
                    .unwrap();
                assert_eq!(&probe.positions()[start..], &[s[2], s[0], s[1]]);
                let alphabet = initial.topology().alphabet();
                let resources: Vec<_> = (1..=6)
                    .map(|order| {
                        let mixed = s.iter().cycle().skip(2).take(order).copied().collect();
                        let entries = vec![(vec![s[0]; order], 3), (vec![s[1]; order], 1)];
                        let entries = entries.into_iter().chain([(mixed, 2)]).collect();
                        let model = crate::NgramModel::new(alphabet.clone(), order, entries);
                        BoundResource::Ngram(model.unwrap())
                    })
                    .collect();
                let objectives = [(MeasureId::Ic, None), (MeasureId::Entropy, None)]
                    .into_iter()
                    .chain(SINKOV.into_iter().zip(resources.iter().map(Some)));
                for (objective, resource) in objectives {
                    for direction in [Direction::Encrypt, Direction::Decrypt] {
                        for input in [symbols.to_owned(), symbols.repeat(9)] {
                            for (deny, wide) in [(false, false), (false, true), (true, false)] {
                                let mut trial = TrialEvaluator::new(
                                    &initial, &domain, &input, direction, objective, resource,
                                );
                                trial.deny_reservation = deny;
                                trial.force_wide = wide;
                                for pairs in [vec![], vec![(s[2], s[3])], vec![]] {
                                    let board =
                                        validated_trial_board(&initial, &domain, &pairs).unwrap();
                                    let mut fresh = Engine::new(
                                        initial.topology().clone(),
                                        initial.stepping().clone(),
                                        board,
                                    )
                                    .unwrap();
                                    let plaintext = fresh.transform(&input, direction).unwrap();
                                    let score = match resource {
                                        Some(BoundResource::Ngram(model)) => {
                                            model.score(&plaintext)
                                        }
                                        _ if objective == MeasureId::Ic => {
                                            index_of_coincidence(alphabet, &plaintext)
                                        }
                                        _ => shannon_entropy(alphabet, &plaintext),
                                    };
                                    let expected = score
                                        .map(|score| (plaintext, score))
                                        .map_err(TrialEvaluationError::Measure);
                                    assert_eq!(trial.evaluate(&pairs), expected, "{objective:?}");
                                    let prepared = trial.prepared.get().unwrap();
                                    assert_eq!(prepared.is_none(), deny);
                                    if let Some(prepared) = prepared {
                                        let is_wide = matches!(prepared, Prepared::Wide { .. });
                                        assert_eq!(is_wide, wide);
                                    }
                                    assert!(matches!(
                                        trial.evaluate(&[(s[2], s[2])]),
                                        Err(TrialEvaluationError::Board(_))
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn decoded_reads_one_row_per_input_symbol_through_the_mapping() {
        // Width 3, input of 4 symbols, rows laid out offset-major.
        let input = [0_u32, 2, 1, 2];
        let rows = [1_u32, 0, 2, 2, 1, 0, 0, 2, 1, 1, 2, 0];
        let mapping = [2, 1, 0];
        let naive: Vec<u32> = input
            .iter()
            .enumerate()
            .map(|(offset, &symbol)| {
                let signal = mapping[symbol as usize];
                mapping[rows[offset * 3 + signal] as usize] as u32
            })
            .collect();
        let decoded = WideDecoded::new(&input, &rows, &mapping);
        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded.collect::<Vec<_>>(), naive);
        assert_eq!(naive, vec![0, 0, 0, 1]);
        let single = WideDecoded::new(&[0; 3], &[0; 3], &[0]);
        assert_eq!(single.collect::<Vec<_>>(), vec![0; 3]);
    }

    #[test]
    fn byte_decoded_matches_wide_decoded_over_compact_rows() {
        let input = [0_u32, 2, 1, 2];
        let rows = [1_u32, 0, 2, 2, 1, 0, 0, 2, 1, 1, 2, 0];
        let mapping = [2, 1, 0];
        let byte_input: Vec<u8> = input.iter().map(|&s| s as u8).collect();
        let byte_rows: Vec<u8> = rows.iter().map(|&output| output as u8).collect();
        let bytes = ByteDecoded::new(&byte_input, &byte_rows, &mapping);
        assert_eq!(bytes.len(), 4);
        let wide: Vec<_> = WideDecoded::new(&input, &rows, &mapping).collect();
        assert_eq!(bytes.collect::<Vec<_>>(), wide);
        let single = ByteDecoded::new(&[0; 3], &[0; 3], &[0]);
        assert_eq!(single.collect::<Vec<_>>(), vec![0; 3]);
    }

    #[test]
    fn byte_rows_cover_alphabets_through_256_within_the_data_limit() {
        // Compact byte rows cost `width` bytes per input symbol.
        assert!(byte_rows_fit(40_329, 26));
        assert!(!byte_rows_fit(40_330, 26));
        assert!(byte_rows_fit(349_525, 3));
        assert!(!byte_rows_fit(349_526, 3));
        assert!(byte_rows_fit(4096, 256));
        assert!(!byte_rows_fit(4097, 256));
        assert!(!byte_rows_fit(1, 257));
        assert!(byte_rows_fit(0, 1));
        assert!(!byte_rows_fit(usize::MAX, 2));
        // Width 256 (the definition limit) admits 4,096 byte-row letters but only
        // 1,024 `u32` ones, so past 4,096 there is no table.
        for (length, bytes) in [(1025, Some(true)), (4096, Some(true)), (4097, None)] {
            let width = 256;
            // The test machine's ring is 'A', so it leads the alphabet.
            let symbols: String = std::iter::once('A')
                .chain((1..width).map(|i| char::from_u32(0x100 + i).unwrap()))
                .collect();
            let wiring: String = symbols
                .chars()
                .cycle()
                .skip(1)
                .take(width as usize)
                .collect();
            let first = symbols.chars().next().unwrap().to_string();
            let initial = machine(&symbols, &wiring, &first, true);
            let pool: String = symbols.chars().take(4).collect();
            let domain = domain(initial.topology().alphabet(), &[], &pool, 1);
            let input: String = symbols.chars().cycle().take(length).collect();
            let trial = evaluator(&initial, &domain, &input);
            let expected = initial
                .clone()
                .into_engine()
                .unwrap()
                .transform(&input, Direction::Decrypt)
                .unwrap();
            assert_eq!(trial.evaluate(&[]).unwrap().0, expected);
            let prepared = trial.prepared.get().unwrap().as_ref();
            let kind = prepared.map(|prepared| matches!(prepared, Prepared::Bytes { .. }));
            assert_eq!(kind, bytes, "{width} x {length}");
        }
    }

    #[test]
    fn table_allocation_policy_checks_overflow_boundary_and_denial() {
        let entries = TABLE_DATA_LIMIT / std::mem::size_of::<u32>();
        assert_eq!(table_entries(entries, 1), Some(entries));
        assert_eq!(table_entries(entries + 1, 1), None);
        assert_eq!(table_entries(usize::MAX, 2), None);
        assert_eq!(table_entries(usize::MAX / 2, 1), None);
        assert!(reserved_rows(2, 4, true).is_none());
        assert_eq!(reserved_rows(0, 4, false), Some(Vec::new()));
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let input = "ABC".repeat(entries / 9 + 1);
        // Byte rows would admit this input; the `u32` limit is under test.
        let mut trial = evaluator(&initial, &domain, &input);
        trial.force_wide = true;
        assert_eq!(table_entries(input.chars().count(), 3), None);
        let expected = initial
            .clone()
            .into_engine()
            .unwrap()
            .transform(&input, Direction::Decrypt)
            .unwrap();
        assert_eq!(trial.evaluate(&[]).unwrap().0, expected);
        assert!(matches!(trial.prepared.get(), Some(None)));
        assert_eq!(trial.evaluate(&[]).unwrap().0, expected);
    }

    #[test]
    fn validation_precedence_and_failed_first_trials_do_not_prepare() {
        let initial = machine("ABC", "BAC", "A", true);
        let alphabet = initial.topology().alphabet();
        let domain = domain(alphabet, &[], "ABC", 1);
        for deny in [false, true] {
            let mut invalid = evaluator(&initial, &domain, "AZ");
            invalid.deny_reservation = deny;
            assert!(matches!(
                invalid.evaluate(&[('A', 'A')]),
                Err(TrialEvaluationError::Board(_))
            ));
            assert_eq!(
                invalid.evaluate(&[]),
                Err(TrialEvaluationError::Model(ModelError::UnknownSymbol('Z')))
            );
            assert!(invalid.prepared.get().is_none());
            let wrong_fixed = super::tests::domain(alphabet, &[('A', 'B')], "C", 1);
            let invalid = evaluator(&initial, &wrong_fixed, "AZ");
            assert_eq!(
                invalid.evaluate(&[]),
                Err(TrialEvaluationError::Board(
                    TrialBoardError::FixedFactsBinding
                ))
            );
            assert!(invalid.prepared.get().is_none());
            for input in ["", "A"] {
                let mut trial = evaluator(&initial, &domain, input);
                trial.deny_reservation = deny;
                assert!(matches!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::Measure(
                        MeasureError::InsufficientSamples { .. }
                    ))
                ));
                assert!(trial.prepared.get().is_some());
                assert!(matches!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::Measure(
                        MeasureError::InsufficientSamples { .. }
                    ))
                ));
            }
        }
    }

    #[test]
    fn owned_trial_errors_preserve_causal_sources() {
        use std::error::Error;
        let model =
            TrialEvaluationError::Board(TrialBoardError::Model(ModelError::UnknownSymbol('Z')));
        let board = model
            .source()
            .unwrap()
            .downcast_ref::<TrialBoardError>()
            .unwrap();
        assert_eq!(
            board.source().unwrap().downcast_ref::<ModelError>(),
            Some(&ModelError::UnknownSymbol('Z'))
        );
        let direct = TrialEvaluationError::Model(ModelError::EmptyAlphabet);
        assert_eq!(
            direct.source().unwrap().downcast_ref::<ModelError>(),
            Some(&ModelError::EmptyAlphabet)
        );
        let cause = MeasureError::InsufficientSamples {
            required: 2,
            actual: 1,
        };
        let measure = TrialEvaluationError::Measure(cause.clone());
        assert_eq!(
            measure.source().unwrap().downcast_ref::<MeasureError>(),
            Some(&cause)
        );
        assert!(TrialEvaluationError::MissingResource(MeasureId::Trie)
            .source()
            .is_none());
        assert!(TrialBoardError::TotalCapacity.source().is_none());
        assert!(!model.to_string().is_empty());
        assert!(!measure.to_string().is_empty());
    }

    fn plaintext_builds() -> usize {
        PLAINTEXT_BUILDS.with(|count| count.replace(0))
    }

    #[test]
    fn score_only_trials_match_full_evaluation() {
        let mut seed = 0x9e37_79b9_u32;
        let mut next = |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as usize % bound
        };
        for symbols in ["ABCDEFGH", "界éHβAGλ中", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"] {
            let s: Vec<_> = symbols.chars().collect();
            let wiring: String = s.iter().cycle().skip(3).take(s.len()).collect();
            let initial = machine(symbols, &wiring, "AA", true);
            let alphabet = initial.topology().alphabet();
            let domain = domain(alphabet, &[], symbols, 3);
            let other = Alphabet::new("AB".chars().collect()).unwrap();
            let tries = vec![(vec![s[0]], 2), (vec![s[0], s[1]], -1), (vec![s[1]], 1)];
            let model = |order| {
                let entries = vec![(vec![s[0]; order], 3), (vec![s[1]; order], 1)];
                BoundResource::Ngram(
                    crate::NgramModel::new(alphabet.clone(), order, entries).unwrap(),
                )
            };
            let mut cases = vec![
                (MeasureId::Ic, None, true),
                (MeasureId::Entropy, None, true),
                (MeasureId::SinkovBigram, None, false),
                (MeasureId::Ic, Some(model(1)), false),
                (MeasureId::SinkovBigram, Some(ngram(&other, 2)), false),
                (
                    MeasureId::Trie,
                    Some(BoundResource::Trie(
                        crate::TrieModel::new(alphabet.clone(), tries).unwrap(),
                    )),
                    false,
                ),
            ];
            for (order, objective) in (1..=6).zip(SINKOV) {
                let dense = s.len() < 26 || order < 4;
                cases.push((objective, Some(model(order)), dense));
            }
            let random: String = (0..17).map(|_| s[next(s.len())]).collect();
            let inputs = [
                String::new(),
                s[..1].iter().collect(),
                s[..2].iter().collect(),
                s[..5].iter().collect(),
                symbols.repeat(3),
                random,
                format!("{}?{}", s[0], s[1]),
            ];
            for (objective, resource, streamable) in &cases {
                for input in &inputs {
                    for deny in [false, true] {
                        let new = || {
                            let mut trial = TrialEvaluator::new(
                                &initial,
                                &domain,
                                input,
                                Direction::Decrypt,
                                *objective,
                                resource.as_ref(),
                            );
                            trial.deny_reservation = deny;
                            trial
                        };
                        let (full, fast) = (new(), new());
                        for _ in 0..12 {
                            let board: Vec<_> = (0..next(5))
                                .map(|_| {
                                    let mut end = || match next(12) {
                                        0 => '?',
                                        _ => s[next(s.len())],
                                    };
                                    (end(), end())
                                })
                                .collect();
                            let expected = full.evaluate(&board);
                            plaintext_builds();
                            let actual = fast.evaluate_score(&board);
                            let builds = plaintext_builds();
                            let label = format!("{symbols} {objective:?} {input} {deny} {board:?}");
                            match (expected, actual) {
                                (Ok((plaintext, score)), Ok((carried, streamed))) => {
                                    assert_eq!(streamed, score, "{label}");
                                    let streams = *streamable && !deny;
                                    assert_eq!(carried.is_none(), streams, "{label}");
                                    assert_eq!(builds, usize::from(!streams), "{label}");
                                    if let Some(carried) = carried {
                                        assert_eq!(carried, plaintext, "{label}");
                                    } else {
                                        assert_eq!(fast.replay_plaintext(&board), Ok(plaintext));
                                    }
                                }
                                (Err(expected), Err(actual)) => {
                                    assert_eq!(actual, expected, "{label}")
                                }
                                (expected, actual) => {
                                    panic!("{label}: {expected:?} != {actual:?}")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn shared_score_only_trials_match_full_evaluation() {
        let owner = run_owner();
        let run = RunPreparation::new(&owner);
        let initial = machine("ABC", "BAC", "A", true);
        for outer in [0, 1, 0] {
            let full = run.evaluator(&initial, outer, MeasureId::Ic);
            let fast = run.evaluator(&initial, outer, MeasureId::Ic);
            for board in [vec![], vec![('A', 'B')], vec![('A', 'A')]] {
                let expected = full.evaluate(&board);
                let actual = fast.evaluate_score(&board);
                assert_eq!(
                    actual.map(|(carried, score)| (carried.is_none(), score)),
                    expected.map(|(_, score)| (true, score))
                );
            }
        }
    }

    fn trial_counters() -> [usize; 5] {
        [
            BINDING_CHECKS.with(|count| count.replace(0)),
            crate::PLUGBOARD_BUILDS.with(|count| count.replace(0)),
            PLAINTEXT_BUILDS.with(|count| count.replace(0)),
            ENGINE_CHECKS.with(|count| count.replace(0)),
            crate::engine::ROW_BUILDS.with(|count| count.replace(0)),
        ]
    }

    fn board_fills() -> usize {
        BOARD_FILLS.with(|count| count.replace(0))
    }

    #[test]
    fn mapped_score_equals_board_score() {
        let mut seed = 0x2545_f491_u32;
        let mut next = |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as usize % bound
        };
        let mut compared = 0;
        for symbols in ["ABCDEFGH", "界éHβAGλ中", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"] {
            let s: Vec<_> = symbols.chars().collect();
            let wiring: String = s.iter().cycle().skip(3).take(s.len()).collect();
            let initial = machine(symbols, &wiring, "AA", true);
            let alphabet = initial.topology().alphabet();
            let domain = domain(alphabet, &[], symbols, 3);
            let other = Alphabet::new("AB".chars().collect()).unwrap();
            let tries = vec![(vec![s[0]], 2), (vec![s[0], s[1]], -1), (vec![s[1]], 1)];
            let model = |order| {
                let entries = vec![(vec![s[0]; order], 3), (vec![s[1]; order], 1)];
                BoundResource::Ngram(
                    crate::NgramModel::new(alphabet.clone(), order, entries).unwrap(),
                )
            };
            let mut cases = vec![
                (MeasureId::Ic, None),
                (MeasureId::Entropy, None),
                (MeasureId::SinkovBigram, None),
                (MeasureId::Ic, Some(model(1))),
                (MeasureId::SinkovBigram, Some(ngram(&other, 2))),
                (
                    MeasureId::Trie,
                    Some(BoundResource::Trie(
                        crate::TrieModel::new(alphabet.clone(), tries).unwrap(),
                    )),
                ),
            ];
            for (order, objective) in (1..=6).zip(SINKOV) {
                cases.push((objective, Some(model(order))));
            }
            let inputs = [
                String::new(),
                s[..1].iter().collect(),
                s[..5].iter().collect(),
                symbols.repeat(3),
                format!("{}?{}", s[0], s[1]),
            ];
            for (objective, resource) in &cases {
                for input in &inputs {
                    for deny in [false, true] {
                        let new = || {
                            let mut trial = TrialEvaluator::new(
                                &initial,
                                &domain,
                                input,
                                Direction::Decrypt,
                                *objective,
                                resource.as_ref(),
                            );
                            trial.deny_reservation = deny;
                            trial
                        };
                        let (by_board, by_mapping) = (new(), new());
                        for _ in 0..12 {
                            let board: Vec<_> = (0..next(4))
                                .map(|_| (s[next(s.len())], s[next(s.len())]))
                                .collect();
                            // Only valid boards have a mapping; derive it independently.
                            let Ok(plugboard) = validated_trial_board(&initial, &domain, &board)
                            else {
                                continue;
                            };
                            let mapping: Vec<_> = s
                                .iter()
                                .map(|&c| alphabet.index_of(plugboard.map(c).unwrap()).unwrap())
                                .collect();
                            let label = format!("{symbols} {objective:?} {input} {deny} {board:?}");
                            // Cold pairs first, then the long-lived warm pair.
                            for (board_trial, mapped_trial) in
                                [(&new(), &new()), (&by_board, &by_mapping)]
                            {
                                trial_counters();
                                board_fills();
                                let expected = board_trial.evaluate_score(&board);
                                let counts = trial_counters();
                                assert_eq!(board_fills(), 1, "{label}");
                                let actual = mapped_trial.evaluate_score_mapped(&mapping);
                                assert_eq!(actual, expected, "{label}");
                                // Binding, plugboard, plaintext, engine and row work all
                                // match; only the board-to-mapping fill is skipped.
                                assert_eq!(trial_counters(), counts, "{label}");
                                assert_eq!(board_fills(), 0, "{label}");
                                compared += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(compared > 1000, "{compared}");
        // Binding errors keep precedence on cold evaluators for either entry point.
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let mapping = [1, 0, 2, 3, 4, 5, 6, 7];
        let reversed = Alphabet::new("HGFEDCBA".chars().collect()).unwrap();
        for (invalid, error) in [
            (
                domain(&reversed, &[], "CD", 1),
                TrialEvaluationError::Board(TrialBoardError::AlphabetBinding),
            ),
            (
                domain(&alphabet, &[], "CD", 1),
                TrialEvaluationError::Board(TrialBoardError::FixedFactsBinding),
            ),
        ] {
            let (board_trial, mapped_trial) = (
                evaluator(&initial, &invalid, "Z"),
                evaluator(&initial, &invalid, "Z"),
            );
            for _ in 0..2 {
                trial_counters();
                let expected = board_trial.evaluate_score(&[]);
                assert_eq!(expected.as_ref().err(), Some(&error));
                let counts = trial_counters();
                assert_eq!(mapped_trial.evaluate_score_mapped(&mapping), expected);
                assert_eq!(trial_counters(), counts);
            }
        }
    }

    #[test]
    fn replay_rebuilds_streamed_plaintext_outside_any_engine() {
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let trial = evaluator(&initial, &domain, "ABCAB");
        for board in [vec![], vec![('A', 'B')]] {
            let (expected, score) = trial.evaluate(&board).unwrap();
            assert_eq!(trial.evaluate_score(&board), Ok((None, score)));
            plaintext_builds();
            ENGINE_CHECKS.with(|count| count.set(0));
            assert_eq!(trial.replay_plaintext(&board), Ok(expected));
            assert_eq!(plaintext_builds(), 1);
            assert_eq!(ENGINE_CHECKS.with(|count| count.get()), 0);
        }
        // Replay is only reached for streamed winners; anything else is an invariant.
        assert!(matches!(
            trial.replay_plaintext(&[('A', 'A')]),
            Err(TrialEvaluationError::Invariant(_))
        ));
        let mut denied = evaluator(&initial, &domain, "ABCAB");
        denied.deny_reservation = true;
        assert!(denied.evaluate_score(&[]).unwrap().0.is_some());
        assert!(matches!(
            denied.replay_plaintext(&[]),
            Err(TrialEvaluationError::Invariant(_))
        ));
        let error = TrialEvaluationError::Invariant("replay");
        assert!(std::error::Error::source(&error).is_none());
        assert!(!error.to_string().is_empty());
    }

    fn initial(alphabet: &Alphabet, fixed: &[(char, char)]) -> ResolvedConfiguration {
        let symbols = &alphabet.symbols;
        let source = serde_json::json!({
            "kind": "custom", "value": {
                "alphabet": symbols,
                "wheels": [{"name": "r", "wiring": symbols, "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
                "stepping": {"rules": []}
            }
        });
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        TransformConfiguration::new(
            vec![SlotConfiguration::new("r", "r", symbols[0], symbols[0])],
            fixed.to_vec(),
        )
        .resolve(&definition)
        .unwrap()
    }

    fn alphabet() -> Alphabet {
        Alphabet::new("ABCDEFGH".chars().collect()).unwrap()
    }

    fn domain(
        alphabet: &Alphabet,
        fixed: &[(char, char)],
        symbols: &str,
        cap: usize,
    ) -> AttackPlugboardDomain {
        let source = serde_json::json!({
            "kind": "attack", "symbols": symbols.chars().collect::<Vec<_>>(),
            "max_pairs": cap
        });
        AttackPlugboardDomain::parse_json(alphabet, fixed, &source.to_string()).unwrap()
    }

    fn assert_mapping(board: &Plugboard, expected: &str) {
        let actual: String = "ABCDEFGH".chars().map(|c| board.map(c).unwrap()).collect();
        assert_eq!(actual, expected);
    }

    fn machine(
        symbols: &str,
        wiring: &str,
        positions: &str,
        stepped: bool,
    ) -> ResolvedConfiguration {
        let slots: Vec<_> = positions.chars().enumerate().map(|(i, _)| {
            serde_json::json!({"id": format!("r{i}"), "role": "rotor", "movement": "movable", "wheel": "r"})
        }).collect();
        let rules = if stepped {
            serde_json::json!([{"when": {"always": true}, "advance": ["r0"]}])
        } else {
            serde_json::json!([])
        };
        let source = serde_json::json!({"kind": "custom", "value": {
            "alphabet": symbols.chars().collect::<Vec<_>>(),
            "wheels": [{"name": "r", "wiring": wiring.chars().collect::<Vec<_>>(), "turnovers": []}],
            "slots": slots, "stepping": {"rules": rules}
        }});
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        TransformConfiguration::new(
            positions
                .chars()
                .enumerate()
                .map(|(i, p)| SlotConfiguration::new(format!("r{i}"), "r", p, 'A'))
                .collect(),
            vec![],
        )
        .resolve(&definition)
        .unwrap()
    }

    fn evaluator<'a>(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        input: &'a str,
    ) -> TrialEvaluator<'a> {
        TrialEvaluator::new(
            initial,
            domain,
            input,
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        )
    }

    const SINKOV: [MeasureId; 6] = [
        MeasureId::SinkovMonogram,
        MeasureId::SinkovBigram,
        MeasureId::SinkovTrigram,
        MeasureId::SinkovQuadgram,
        MeasureId::SinkovPentagram,
        MeasureId::SinkovHexagram,
    ];

    fn ngram(alphabet: &Alphabet, order: usize) -> BoundResource {
        BoundResource::Ngram(
            crate::NgramModel::new(
                alphabet.clone(),
                order,
                vec![(vec!['A'; order], 3), (vec!['B'; order], 1)],
            )
            .unwrap(),
        )
    }

    fn trie(alphabet: &Alphabet) -> BoundResource {
        BoundResource::Trie(
            crate::TrieModel::new(
                alphabet.clone(),
                vec![(vec!['A'], 2), (vec!['A', 'A'], -1), (vec!['B'], 1)],
            )
            .unwrap(),
        )
    }

    #[test]
    fn independent_direction_and_stepping_oracles() {
        let initial = machine("ABCD", "ABDC", "CB", false);
        let alphabet = initial.topology().alphabet();
        let domain = domain(alphabet, &[], "ABCD", 2);
        let trial = evaluator(&initial, &domain, "ABCD");
        assert_eq!(trial.evaluate(&[]).unwrap().0, "CABD");
        let trial = TrialEvaluator::new(
            &initial,
            &domain,
            "ABCD",
            Direction::Encrypt,
            MeasureId::Ic,
            None,
        );
        assert_eq!(trial.evaluate(&[]).unwrap().0, "BCAD");
        for (stepped, expected) in [(true, "CA"), (false, "BB")] {
            let initial = machine("ABC", "BAC", "A", stepped);
            let domain = super::tests::domain(initial.topology().alphabet(), &[], "ABC", 1);
            let trial = evaluator(&initial, &domain, "AA");
            assert_eq!(trial.evaluate(&[]).unwrap().0, expected);
        }
    }

    #[test]
    fn stepped_trials_and_failures_are_isolated_and_inputs_stay_owned() {
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let input = String::from("AA");
        let pairs = [('A', 'B')];
        let before = (initial.clone(), domain.clone(), input.clone(), pairs);
        let trial = evaluator(&initial, &domain, &input);
        let a = trial.evaluate(&[]).unwrap();
        let b = trial.evaluate(&pairs).unwrap();
        assert_eq!(a.0, "CA");
        assert_eq!(b.0, "AC");
        assert_ne!(a, b);
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        assert_eq!(
            trial.evaluate(&[('A', 'A')]),
            Err(TrialEvaluationError::Board(TrialBoardError::Model(
                ModelError::PlugboardSelfPair('A')
            ))),
        );
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        let foreign = evaluator(&initial, &domain, "AZ");
        assert_eq!(
            foreign.evaluate(&[]),
            Err(TrialEvaluationError::Model(ModelError::UnknownSymbol('Z')))
        );
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        assert_eq!((initial, domain, input, pairs), before);
    }

    #[test]
    fn resource_free_scores_have_independent_nonzero_orientation() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        let mut trial = evaluator(&initial, &domain, "AABB");
        let score = trial.evaluate(&[]).unwrap().1;
        assert_eq!(score.measured().units(), 2 * crate::SCALE / 3);
        assert_eq!(score.ranking(), score.measured());
        trial.objective = MeasureId::Entropy;
        let score = trial.evaluate(&[]).unwrap().1;
        assert_eq!(score.measured().units(), crate::SCALE);
        assert_eq!(score.ranking().units(), -crate::SCALE);
        let mut trial = evaluator(&initial, &domain, "AAAA");
        trial.objective = MeasureId::Entropy;
        assert!(trial.evaluate(&[]).unwrap().1.ranking().units() > score.ranking().units());
        trial.objective = MeasureId::Ic;
        assert!(trial.evaluate(&[]).unwrap().1.ranking().units() > 2 * crate::SCALE / 3);
    }

    #[test]
    fn retained_models_repeat_with_known_nonuniform_scores_for_every_order() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        for (i, objective) in SINKOV.into_iter().enumerate() {
            let resource = ngram(&alphabet, i + 1);
            let mut trial = evaluator(&initial, &domain, "AAAAAAA");
            trial.objective = objective;
            trial.resource = Some(&resource);
            let a = trial.evaluate(&[]).unwrap();
            // ln(3/4) and ln(1/4), independently quantized downward to Q32.
            assert_eq!(a.1.measured().units(), -1_235_585_093);
            assert_eq!(a.1.ranking(), a.1.measured());
            let trial = TrialEvaluator::new(
                &initial,
                &domain,
                "BBBBBBB",
                Direction::Decrypt,
                objective,
                Some(&resource),
            );
            let b = trial.evaluate(&[]).unwrap();
            assert_eq!(b.1.measured().units(), -5_954_088_944);
            assert!(a.1.ranking().units() > b.1.ranking().units());
            let trial = TrialEvaluator::new(
                &initial,
                &domain,
                "AAAAAAA",
                Direction::Decrypt,
                objective,
                Some(&resource),
            );
            assert_eq!(trial.evaluate(&[]).unwrap(), a);
        }
        let resource = trie(&alphabet);
        let mut trial = evaluator(&initial, &domain, "AAB");
        trial.objective = MeasureId::Trie;
        trial.resource = Some(&resource);
        let a = trial.evaluate(&[]).unwrap();
        assert_eq!(a.1.measured().units(), 4 * crate::SCALE);
        assert_eq!(a.1.ranking(), a.1.measured());
        let trial = TrialEvaluator::new(
            &initial,
            &domain,
            "BBB",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        assert_eq!(
            trial.evaluate(&[]).unwrap().1.measured().units(),
            3 * crate::SCALE
        );
        let trial = TrialEvaluator::new(
            &initial,
            &domain,
            "AAB",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
    }

    #[test]
    fn complete_resource_compatibility_matrix_is_typed() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let reversed = Alphabet::new("BA".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        let resources: Vec<_> = (1..=6).map(|order| ngram(&alphabet, order)).collect();
        let trie = trie(&alphabet);
        let wrong_trie = super::tests::trie(&reversed);
        for objective in [MeasureId::Ic, MeasureId::Entropy]
            .into_iter()
            .chain(SINKOV)
            .chain([MeasureId::Trie])
        {
            let mut trial = evaluator(&initial, &domain, "AAAAAAA");
            trial.objective = objective;
            let result = trial.evaluate(&[]);
            if objective.requires_resource() {
                assert_eq!(
                    result,
                    Err(TrialEvaluationError::MissingResource(objective))
                );
            } else {
                assert!(result.is_ok());
            }
            for resource in resources.iter().chain([&trie]) {
                trial.resource = Some(resource);
                let compatible = match resource {
                    BoundResource::Ngram(model) => objective.order() == Some(model.order()),
                    BoundResource::Trie(_) => objective == MeasureId::Trie,
                };
                if compatible {
                    assert!(trial.evaluate(&[]).is_ok());
                } else {
                    assert_eq!(
                        trial.evaluate(&[]),
                        Err(TrialEvaluationError::IncompatibleResource(objective))
                    );
                }
            }
            let wrong_ngram = ngram(&reversed, objective.order().unwrap_or(1));
            for resource in [&wrong_ngram, &wrong_trie] {
                trial.resource = Some(resource);
                assert_eq!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::IncompatibleResource(objective))
                );
            }
        }
    }

    #[test]
    fn exact_sample_errors_are_preserved_for_all_measures() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        for objective in [MeasureId::Ic, MeasureId::Entropy]
            .into_iter()
            .chain(SINKOV)
            .chain([MeasureId::Trie])
        {
            let resource = if let Some(order) = objective.order() {
                Some(ngram(&alphabet, order))
            } else if objective == MeasureId::Trie {
                Some(trie(&alphabet))
            } else {
                None
            };
            let required = objective.minimum_samples() as u128;
            for actual in 0..required {
                let input = "A".repeat(actual as usize);
                let mut trial = evaluator(&initial, &domain, &input);
                trial.objective = objective;
                trial.resource = resource.as_ref();
                assert_eq!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::Measure(
                        crate::MeasureError::InsufficientSamples { required, actual }
                    )),
                    "{objective:?}, {actual}",
                );
            }
        }
    }

    #[test]
    fn merges_fixed_facts_without_mutating_any_input() {
        let alphabet = alphabet();
        let fixed = [('A', 'B')];
        let initial = initial(&alphabet, &fixed);
        let domain = domain(&alphabet, &fixed, "CDEF", 3);
        let before_initial = initial.clone();
        let before_domain = domain.clone();
        let mutable = [('C', 'D')];
        let before_mutable = mutable;
        let board = validated_trial_board(&initial, &domain, &mutable).unwrap();
        // AB and CD exchange; unused mutable EF and masked GH remain fixed points.
        assert_mapping(&board, "BADCEFGH");
        assert_eq!(initial, before_initial);
        assert_eq!(domain, before_domain);
        assert_eq!(mutable, before_mutable);
        assert_eq!(domain.fixed_pairs(), &fixed);
    }

    #[test]
    fn fixed_only_and_zero_total_capacity_are_legal() {
        let alphabet = alphabet();
        let fixed = [('A', 'B')];
        let initial_fixed = initial(&alphabet, &fixed);
        let fixed_domain = domain(&alphabet, &fixed, "CD", 1);
        assert_mapping(
            &validated_trial_board(&initial_fixed, &fixed_domain, &[]).unwrap(),
            "BACDEFGH",
        );
        let empty_initial = initial(&alphabet, &[]);
        let zero_domain = domain(&alphabet, &[], "CD", 0);
        assert_mapping(
            &validated_trial_board(&empty_initial, &zero_domain, &[]).unwrap(),
            "ABCDEFGH",
        );
        assert_eq!(
            validated_trial_board(&empty_initial, &zero_domain, &[('C', 'D')]),
            Err(TrialBoardError::TotalCapacity),
        );
    }

    #[test]
    fn capacity_counts_actual_fixed_plus_mutable_pairs() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let domain = domain(&alphabet, &[('A', 'B')], "CDEF", 2);
        assert_mapping(
            &validated_trial_board(&initial, &domain, &[('C', 'D')]).unwrap(),
            "BADCEFGH",
        );
        assert_eq!(
            validated_trial_board(&initial, &domain, &[('C', 'D'), ('E', 'F')]),
            Err(TrialBoardError::TotalCapacity),
        );
    }

    #[test]
    fn rejects_fixed_repetition_reuse_self_overlap_and_foreign_symbols() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let domain = domain(&alphabet, &[('A', 'B')], "CDEF", 3);
        for (pairs, expected) in [
            (vec![('A', 'B')], ModelError::DuplicatePlugboardSymbol('A')),
            (vec![('A', 'C')], ModelError::DuplicatePlugboardSymbol('A')),
            (vec![('C', 'B')], ModelError::DuplicatePlugboardSymbol('B')),
            (vec![('C', 'C')], ModelError::PlugboardSelfPair('C')),
            (
                vec![('C', 'D'), ('D', 'E')],
                ModelError::DuplicatePlugboardSymbol('D'),
            ),
            (vec![('C', 'Z')], ModelError::UnknownSymbol('Z')),
        ] {
            assert_eq!(
                validated_trial_board(&initial, &domain, &pairs),
                Err(TrialBoardError::Model(expected)),
                "trial {pairs:?}",
            );
        }
        for pairs in [[('C', 'G')], [('H', 'D')]] {
            let symbol = if pairs[0].0 == 'H' { 'H' } else { 'G' };
            assert_eq!(
                validated_trial_board(&initial, &domain, &pairs),
                Err(TrialBoardError::OutsideMutable(symbol)),
            );
        }
    }

    #[test]
    fn binding_checks_ordered_alphabet_and_fixed_mapping() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let reversed = Alphabet::new("HGFEDCBA".chars().collect()).unwrap();
        let wrong_order = domain(&reversed, &[('A', 'B')], "CD", 2);
        assert_eq!(
            validated_trial_board(&initial, &wrong_order, &[]),
            Err(TrialBoardError::AlphabetBinding),
        );
        let wrong_fixed = domain(&alphabet, &[('A', 'C')], "DE", 2);
        let missing_fixed = domain(&alphabet, &[], "CD", 1);
        for domain in [wrong_fixed, missing_fixed] {
            assert_eq!(
                validated_trial_board(&initial, &domain, &[]),
                Err(TrialBoardError::FixedFactsBinding),
            );
        }
    }

    #[test]
    fn shuffled_reversed_representations_preserve_fixed_data() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B'), ('G', 'H')]);
        let fixed = [('H', 'G'), ('B', 'A')];
        let domain = domain(&alphabet, &fixed, "FEDC", 4);
        for mutable in [[('C', 'D'), ('E', 'F')], [('F', 'E'), ('D', 'C')]] {
            assert_mapping(
                &validated_trial_board(&initial, &domain, &mutable).unwrap(),
                "BADCFEHG",
            );
            assert_eq!(domain.fixed_pairs(), &fixed);
            assert_eq!(initial.topology().alphabet(), &alphabet);
        }
        assert_mapping(initial.plugboard(), "BACDEFHG");
    }

    /// A minimal bound request; shared tests only need a run owner.
    fn run_owner() -> crate::AttackRequest {
        let value = serde_json::json!({"protocol_version":1,"machine":{"definition":{
            "kind":"custom","value":{"alphabet":["A","B","C"],
            "wheels":[{"name":"r","wiring":["B","A","C"],"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"movable","wheel":"r"}],
            "stepping":{"rules":[{"when":{"always":true},"advance":["r"]}]}}}},
            "job":{"kind":"search","configuration":{"slots":[{"id":"r","position":"A","ring":"A"}],
            "plugboard":[]},"space":{"plugboard":{"kind":"attack","symbols":["A","B","C"],"max_pairs":1}},
            "text":"AA","passes":["hill_climb"],"measures":["ic"],
            "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic",
            "switch_pairs":1,"backtrack_pairs":0,"start":[]}}});
        crate::ParsedAttackRequest::parse_json(&value.to_string())
            .unwrap()
            .bind_resources(&std::collections::BTreeMap::new())
            .unwrap()
    }

    fn shared<'a>(
        mut trial: TrialEvaluator<'a>,
        run: &'a RunPreparation<'a>,
        outer: u128,
    ) -> TrialEvaluator<'a> {
        trial.shared = Some((run, outer));
        trial
    }

    /// The retained outer and its cell: None unbuilt, Some(false) a remembered fallback.
    fn slot(run: &RunPreparation<'_>) -> Option<(u128, Option<bool>)> {
        let latest = run.latest.borrow();
        (latest.as_ref()).map(|(outer, cell)| (*outer, cell.get().map(Option::is_some)))
    }

    fn row_builds() -> usize {
        crate::engine::ROW_BUILDS.with(|count| count.get())
    }

    #[test]
    fn warm_shared_rows_keep_new_evaluator_checks_and_precedence() {
        let initial = machine("ABC", "BAC", "A", true);
        let alphabet = initial.topology().alphabet();
        let valid = domain(alphabet, &[], "ABC", 1);
        let reversed = Alphabet::new("CBA".chars().collect()).unwrap();
        let wrong_alphabet = domain(&reversed, &[], "ABC", 1);
        let wrong_fixed = domain(alphabet, &[('A', 'B')], "C", 1);
        let narrow = domain(alphabet, &[], "AB", 1);
        let full = domain(alphabet, &[], "ABC", 0);
        let owner = run_owner();
        let run = RunPreparation::new(&owner);
        let expected = shared(evaluator(&initial, &valid, "AA"), &run, 0)
            .evaluate(&[])
            .unwrap();
        crate::engine::ROW_BUILDS.with(|count| count.set(0));
        // Binding errors precede mutable errors; each case is a new evaluator B.
        let cases = [
            (
                &wrong_alphabet,
                vec![('A', 'A')],
                TrialBoardError::AlphabetBinding,
            ),
            (
                &wrong_fixed,
                vec![('C', 'C')],
                TrialBoardError::FixedFactsBinding,
            ),
            (
                &valid,
                vec![('A', 'A')],
                TrialBoardError::Model(ModelError::PlugboardSelfPair('A')),
            ),
            (
                &valid,
                vec![('A', 'Z')],
                TrialBoardError::Model(ModelError::UnknownSymbol('Z')),
            ),
            (
                &narrow,
                vec![('A', 'C')],
                TrialBoardError::OutsideMutable('C'),
            ),
            (&full, vec![('A', 'B')], TrialBoardError::TotalCapacity),
        ];
        for (domain, board, error) in cases {
            ENGINE_CHECKS.with(|count| count.set(0));
            let standalone = evaluator(&initial, domain, "AA").evaluate(&board);
            assert_eq!(standalone, Err(TrialEvaluationError::Board(error)));
            let trial = shared(evaluator(&initial, domain, "AA"), &run, 0);
            for _ in 0..2 {
                assert_eq!(trial.evaluate(&board), standalone, "{board:?}");
            }
            ENGINE_CHECKS.with(|count| assert_eq!(count.get(), 0));
        }
        // A failed binding is retried, never cached by the warm table.
        let trial = shared(evaluator(&initial, &wrong_fixed, "AA"), &run, 0);
        BINDING_CHECKS.with(|count| count.set(0));
        assert!(trial.evaluate(&[]).is_err());
        assert!(trial.evaluate(&[]).is_err());
        BINDING_CHECKS.with(|count| assert_eq!(count.get(), 2));
        // The warm rows never certify B's Engine constructor: it runs on B's first
        // valid trial, after the board check, and only once.
        let trial = shared(evaluator(&initial, &valid, "AA"), &run, 0);
        ENGINE_CHECKS.with(|count| count.set(0));
        assert!(trial.evaluate(&[('A', 'A')]).is_err());
        ENGINE_CHECKS.with(|count| assert_eq!(count.get(), 0));
        assert_eq!(trial.evaluate(&[]).unwrap(), expected);
        assert_eq!(trial.evaluate(&[]).unwrap(), expected);
        ENGINE_CHECKS.with(|count| assert_eq!(count.get(), 1));
        assert_eq!(slot(&run), Some((0, Some(true))));
        assert_eq!(row_builds(), 0);
    }

    #[test]
    fn shared_preparation_errors_leave_the_slot_unprepared_for_retry() {
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let expected = evaluator(&initial, &domain, "AA").evaluate(&[]);
        let owner = run_owner();
        for deny in [false, true] {
            let run = RunPreparation::new(&owner);
            shared(evaluator(&initial, &domain, "AA"), &run, 0)
                .evaluate(&[])
                .unwrap();
            crate::engine::ROW_BUILDS.with(|count| count.set(0));
            let mut invalid = shared(evaluator(&initial, &domain, "AZ"), &run, 1);
            invalid.deny_reservation = deny;
            for _ in 0..2 {
                assert_eq!(
                    invalid.evaluate(&[]),
                    Err(TrialEvaluationError::Model(ModelError::UnknownSymbol('Z')))
                );
                // Neither rows nor a fallback marker were recorded for outer 1.
                assert_eq!(slot(&run), Some((1, None)));
            }
            assert_eq!(row_builds(), 0);
            let valid = shared(evaluator(&initial, &domain, "AA"), &run, 1);
            assert_eq!(valid.evaluate(&[]), expected);
            assert_eq!(valid.evaluate(&[]), expected);
            assert_eq!(slot(&run), Some((1, Some(true))));
            assert_eq!(row_builds(), 1);
        }
    }

    #[test]
    fn shared_scoring_failures_retain_successful_preparation() {
        let initial = machine("ABC", "BAC", "A", true);
        let alphabet = initial.topology().alphabet();
        let domain = domain(alphabet, &[], "ABC", 1);
        let resource = ngram(alphabet, 2);
        let expected = evaluator(&initial, &domain, "AA").evaluate(&[]);
        let owner = run_owner();
        let run = RunPreparation::new(&owner);
        crate::engine::ROW_BUILDS.with(|count| count.set(0));
        for (objective, resource, error) in [
            (
                MeasureId::SinkovBigram,
                None,
                TrialEvaluationError::MissingResource(MeasureId::SinkovBigram),
            ),
            (
                MeasureId::Trie,
                Some(&resource),
                TrialEvaluationError::IncompatibleResource(MeasureId::Trie),
            ),
        ] {
            let failing = TrialEvaluator::new(
                &initial,
                &domain,
                "AA",
                Direction::Decrypt,
                objective,
                resource,
            );
            let failing = shared(failing, &run, 0);
            let first = failing.evaluate(&[]);
            assert_eq!(first, Err(error));
            assert_eq!(failing.evaluate(&[]), first);
            assert_eq!(slot(&run), Some((0, Some(true))));
        }
        let valid = shared(evaluator(&initial, &domain, "AA"), &run, 0);
        assert_eq!(valid.evaluate(&[]), expected);
        assert_eq!(row_builds(), 1);
    }

    #[test]
    fn shared_reservation_denial_is_remembered_per_outer() {
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let input = "ABCAB";
        let prepared = evaluator(&initial, &domain, input);
        let plain = prepared.evaluate(&[]).unwrap();
        let swapped = prepared.evaluate(&[('A', 'B')]).unwrap();
        assert!(matches!(prepared.prepared.get(), Some(Some(_))));
        let owner = run_owner();
        let run = RunPreparation::new(&owner);
        let trial = |outer, deny| {
            let mut trial = shared(evaluator(&initial, &domain, input), &run, outer);
            trial.deny_reservation = deny;
            trial
        };
        crate::engine::ROW_BUILDS.with(|count| count.set(0));
        let denied = trial(0, true);
        assert_eq!(denied.evaluate(&[]).unwrap(), plain);
        assert_eq!(denied.evaluate(&[('A', 'B')]).unwrap(), swapped);
        assert_eq!(slot(&run), Some((0, Some(false))));
        // A later evaluator on the same outer keeps the remembered fallback.
        let allowed = trial(0, false);
        assert_eq!(allowed.evaluate(&[('A', 'B')]).unwrap(), swapped);
        assert_eq!(allowed.evaluate(&[]).unwrap(), plain);
        assert_eq!(slot(&run), Some((0, Some(false))));
        assert_eq!(row_builds(), 0);
        // Switching outer evicts the marker and evaluates the policy again.
        assert_eq!(trial(1, false).evaluate(&[]).unwrap(), plain);
        assert_eq!(slot(&run), Some((1, Some(true))));
        assert_eq!(row_builds(), 1);
        assert_eq!(trial(0, true).evaluate(&[]).unwrap(), plain);
        assert_eq!(slot(&run), Some((0, Some(false))));
        assert_eq!(trial(1, false).evaluate(&[('A', 'B')]).unwrap(), swapped);
        assert_eq!(slot(&run), Some((1, Some(true))));
        assert_eq!(row_builds(), 2);
    }
}
