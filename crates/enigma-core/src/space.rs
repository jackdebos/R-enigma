//! Strict structural search parsing and the validated enumeration gate.
//!
//! The frozen grammar lives in `docs/protocol.md` §3.2/§3.3 and
//! `docs/scoring-resources.md`. External paths are metadata only; supplied-content
//! binding is a separate stage, and only `SearchRequest` permits enumeration.

use crate::capability::Capabilities;
use crate::definition::Definition;
use crate::request::{parse_root, ParsedRoot, RequestDiagnostic};
use crate::selection::{parse_measures, parse_references, MeasureId, ResourceReference};
use crate::Alphabet;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;

/// A localized, actionable search-space diagnostic.
///
/// Mirrors [`crate::ConfigurationDiagnostic`]: a stable code, an actionable message, and
/// a request-relative RFC 6901 JSON Pointer. It is converted into a
/// [`RequestDiagnostic`] at the parse boundary so callers see one diagnostic type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchDiagnostic {
    code: &'static str,
    message: String,
    location: String,
}

impl SearchDiagnostic {
    pub(crate) fn new(
        code: &'static str,
        message: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            location: location.into(),
        }
    }

    /// Stable machine-readable diagnostic code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Actionable explanation of the invalid input.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Request-relative RFC 6901 JSON Pointer to the invalid value.
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Builds an `invalid_search_space` diagnostic for an internal invariant violation.
    ///
    /// The candidate resolver (slice 9.3) uses this when a space that already passed
    /// validation unexpectedly fails to resolve, so it can fail closed instead of
    /// skipping the candidate.
    pub(crate) fn internal(message: impl Into<String>, location: impl Into<String>) -> Self {
        Self::new("invalid_search_space", message, location)
    }
}

impl fmt::Display for SearchDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.code, self.location, self.message)
    }
}

impl std::error::Error for SearchDiagnostic {}

/// One partial fixed slot fact from `job.configuration.slots`.
///
/// A present member is a fixed key fact checked for admissibility exactly as a transform
/// would; an absent member is a variable dimension that must be covered by a slot domain
/// in [`SearchSpace`]. A structurally fixed wheel may be present for checking or absent,
/// and is never a variable dimension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchFixedSlot {
    id: String,
    wheel: Option<String>,
    position: Option<char>,
    ring: Option<char>,
}

impl SearchFixedSlot {
    /// Slot identifier; must name a definition slot.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Fixed wheel name, when present in the configuration.
    pub fn wheel(&self) -> Option<&str> {
        self.wheel.as_deref()
    }

    /// Fixed displayed position symbol, when present in the configuration.
    pub fn position(&self) -> Option<char> {
        self.position
    }

    /// Fixed ring setting symbol, when present in the configuration.
    pub fn ring(&self) -> Option<char> {
        self.ring
    }
}

/// The known fixed choices from `job.configuration` for a search job.
///
/// This is the search counterpart of [`crate::TransformConfiguration`]: every slot entry
/// may fix any subset of `wheel`, `position`, and `ring`, and the plugboard is a fixed
/// set of disjoint pairs. Unfixed dimensions are not defaulted; coverage against the
/// definition is validated by [`SearchRequest::parse_json`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchConfiguration {
    slots: Vec<SearchFixedSlot>,
    plugboard: Vec<(char, char)>,
}

impl SearchConfiguration {
    /// The partial fixed slot facts in source order.
    pub fn slots(&self) -> &[SearchFixedSlot] {
        &self.slots
    }

    /// The fixed plugboard pairs in source order.
    pub fn plugboard(&self) -> &[(char, char)] {
        &self.plugboard
    }
}

/// The explicit variable domain for one definition slot from `job.space.slots`.
///
/// `wheels` is only legal for a slot whose definition declares `allowed_wheels`;
/// `positions` and `rings` are always legal. At least one member is present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchSlotDomain {
    id: String,
    wheels: Option<Vec<String>>,
    positions: Option<Vec<char>>,
    rings: Option<Vec<char>>,
}

impl SearchSlotDomain {
    /// Definition slot identifier this domain applies to.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Admissible wheel choices, when variable.
    pub fn wheels(&self) -> Option<&[String]> {
        self.wheels.as_deref()
    }

    /// Variable displayed-position symbols, when declared.
    pub fn positions(&self) -> Option<&[char]> {
        self.positions.as_deref()
    }

    /// Variable ring-setting symbols, when declared.
    pub fn rings(&self) -> Option<&[char]> {
        self.rings.as_deref()
    }
}

/// An explicitly searched plugboard remainder from `job.space.plugboard`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlugboardDomain {
    candidates: Vec<(char, char)>,
    size: usize,
}

impl PlugboardDomain {
    /// The non-empty pool of disjoint candidate pairs to draw from.
    pub fn candidates(&self) -> &[(char, char)] {
        &self.candidates
    }

    /// How many additional pairs to draw from the candidate pool.
    pub fn size(&self) -> usize {
        self.size
    }
}

/// A validated Task 11 attack-domain fragment, not an executable search request.
///
/// This model is deliberately separate from [`PlugboardDomain`] and [`SearchSpace`].
/// It cannot grant candidate enumeration or full attack-request acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttackPlugboardDomain {
    alphabet: Vec<char>,
    symbols: Vec<char>,
    fixed_pairs: Vec<(char, char)>,
    max_pairs: usize,
}

impl AttackPlugboardDomain {
    /// Validates only `{kind:"attack", symbols:[...], max_pairs:N}` JSON.
    ///
    /// `alphabet` is the ordered runtime alphabet; `fixed_pairs` supplies known facts,
    /// not guesses. Membership, symmetry and disjointness of those facts are checked
    /// before domain validation. Neither input is modified or normalized. The model
    /// owns a source-ordered copy of the facts and exposes no mutation methods.
    /// Diagnostics use `/job/space/plugboard` and `/job/configuration/plugboard`.
    /// Duplicate keys and trailing JSON are rejected, rather than collapsed in a Value.
    /// Successful fragment validation does not validate settings, coverage, resources,
    /// executable eligibility or counts; complete attack requests remain unsupported.
    pub fn parse_json(
        alphabet: &Alphabet,
        fixed_pairs: &[(char, char)],
        json: &str,
    ) -> Result<Self, Vec<SearchDiagnostic>> {
        use crate::strict_json::StrictValue;
        use serde::Deserialize;

        const PATH: &str = "/job/space/plugboard";
        // Match the request parser's input-size ceiling before allocating a JSON tree.
        if json.len() > crate::MAX_REQUEST_BYTES {
            return Err(vec![invalid_search_space(
                "attack fragment exceeds 4 MiB",
                PATH,
            )]);
        }
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let parsed = StrictValue::deserialize(&mut deserializer)
            .map_err(|error| vec![invalid_search_space(format!("invalid JSON: {error}"), PATH)])?;
        deserializer
            .end()
            .map_err(|error| vec![invalid_search_space(format!("invalid JSON: {error}"), PATH)])?;
        Self::parse_value(alphabet, fixed_pairs, &parsed.into_value())
    }

    // The caller owns raw JSON size, duplicate-key and trailing-input checks.
    fn parse_value(
        alphabet: &Alphabet,
        fixed_pairs: &[(char, char)],
        value: &Value,
    ) -> Result<Self, Vec<SearchDiagnostic>> {
        const PATH: &str = "/job/space/plugboard";
        // Existing utilities keep their legacy codes; only this fragment boundary
        // translates malformed-domain diagnostics to the Task 11 contract.
        let result = (|| {
            validate_disjoint_pairs(fixed_pairs, "/job/configuration/plugboard", alphabet)?;
            let domain = object(value, PATH)?;
            exact_keys(domain, &["kind", "symbols", "max_pairs"], PATH)?;
            if required_string(domain, "kind", PATH)? != "attack" {
                return Err(vec![invalid_search_space(
                    "kind must be the literal `attack`",
                    child(PATH, "kind"),
                )]);
            }
            let symbols_path = child(PATH, "symbols");
            let symbols = parse_unique_symbol_array(
                required(domain, "symbols", PATH)?,
                &symbols_path,
                alphabet,
            )?;
            let occupied: HashSet<char> = fixed_pairs
                .iter()
                .flat_map(|&(left, right)| [left, right])
                .collect();
            for (index, symbol) in symbols.iter().enumerate() {
                if occupied.contains(symbol) {
                    return Err(vec![invalid_search_space(
                        "mutable symbol is an endpoint of a known fixed pair",
                        child(&symbols_path, &index.to_string()),
                    )]);
                }
            }
            let cap_path = child(PATH, "max_pairs");
            let cap = required(domain, "max_pairs", PATH)?
                .as_u64()
                .ok_or_else(|| {
                    vec![invalid_search_space(
                        "max_pairs must be a nonnegative integer",
                        &cap_path,
                    )]
                })?;
            let capacity = alphabet.len() / 2;
            // Compare before converting to usize, including on 32-bit targets.
            if cap > capacity as u64
                || cap < fixed_pairs.len() as u64
                || cap > (fixed_pairs.len() + symbols.len() / 2) as u64
            {
                return Err(vec![invalid_search_space(
                    "max_pairs must cover fixed pairs and fit alphabet and mutable capacity",
                    cap_path,
                )]);
            }
            Ok(Self {
                alphabet: alphabet.symbols.clone(),
                symbols,
                fixed_pairs: fixed_pairs.to_vec(),
                max_pairs: cap as usize,
            })
        })();
        result.map_err(|mut diagnostics: Vec<SearchDiagnostic>| {
            for diagnostic in &mut diagnostics {
                if diagnostic.code != "unknown_field" {
                    diagnostic.code = "invalid_search_space";
                }
            }
            diagnostics
        })
    }

    pub(crate) fn matches_alphabet(&self, alphabet: &Alphabet) -> bool {
        self.alphabet == alphabet.symbols
    }

    /// Mutable endpoints in source order; never includes a known fixed endpoint.
    pub fn symbols(&self) -> &[char] {
        &self.symbols
    }

    /// Immutable known pairs in supplied order and orientation.
    pub fn fixed_pairs(&self) -> &[(char, char)] {
        &self.fixed_pairs
    }

    /// Maximum total pair count, including known fixed pairs.
    pub fn max_pairs(&self) -> usize {
        self.max_pairs
    }
}

/// Supported settings-fragment pass, not an execution capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttackKind {
    /// Direct hill climb from an explicit mutable start.
    HillClimb,
    /// Empty/single seed policy; no seed generation is provided here.
    PartialExhaustion,
}

/// Explicit empty/single seed selection, preserving the supplied mask order.
/// Constructing a policy alone does not validate attack settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttackSeedPolicy {
    /// All mutable endpoints; no mask is supplied.
    All,
    /// Pairs touching this nonempty ordered mask of mutable endpoints.
    Touching(Vec<char>),
}

/// Validated chained stage after the sole HC/PE pass, with resolved measures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttackStage {
    Reswapping { measure: MeasureId },
    Trie { base_measure: Option<MeasureId> },
    Measure { measure: MeasureId },
}

/// §9.1 shape: one leading HC/PE pass, then distinct chained stages in any order.
pub(crate) fn attack_passes_shape(passes: &[String]) -> Result<(), Vec<SearchDiagnostic>> {
    let stages = passes.get(1..).unwrap_or_default();
    let valid = passes
        .first()
        .is_some_and(|pass| matches!(pass.as_str(), "hill_climb" | "partial_exhaustion"))
        && stages.iter().enumerate().all(|(index, stage)| {
            matches!(stage.as_str(), "reswapping" | "trie" | "measure")
                && !stages[..index].contains(stage)
        });
    if valid {
        return Ok(());
    }
    Err(vec![SearchDiagnostic::new(
        "unsupported_pass",
        "passes must be one hill_climb or partial_exhaustion, then distinct chained stages",
        "/job/passes",
    )])
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AttackInitialization {
    Start(Vec<(char, char)>),
    Seeds(AttackSeedPolicy),
}

/// Validated isolated attack settings; grants no request acceptance or execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttackSettings {
    kind: AttackKind,
    initial_measure: MeasureId,
    final_measure: MeasureId,
    switch_pairs: usize,
    backtrack_pairs: usize,
    progress_every: u64,
    hold_capacity: usize,
    initialization: AttackInitialization,
    stages: Vec<AttackStage>,
    stage_measure_explicit: Vec<bool>,
}

impl AttackSettings {
    /// Validates a strict `job.attack` fragment against its domain and declarations.
    ///
    /// Supports direct hill-climb starts and partial-exhaustion seed policies only.
    /// This boundary checks neither resources nor text lengths,
    /// execution eligibility or counts.
    pub fn parse_json(
        alphabet: &Alphabet,
        domain: &AttackPlugboardDomain,
        declared_passes: &[String],
        declared_measures: &[MeasureId],
        json: &str,
    ) -> Result<Self, Vec<SearchDiagnostic>> {
        use crate::strict_json::StrictValue;
        use serde::Deserialize;

        const PATH: &str = "/job/attack";
        if json.len() > crate::MAX_REQUEST_BYTES {
            return Err(vec![invalid("attack settings exceed 4 MiB", PATH)]);
        }
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let parsed = StrictValue::deserialize(&mut deserializer)
            .map_err(|error| vec![invalid(format!("invalid JSON: {error}"), PATH)])?;
        deserializer
            .end()
            .map_err(|error| vec![invalid(format!("invalid JSON: {error}"), PATH)])?;
        Self::parse_value(
            alphabet,
            domain,
            declared_passes,
            declared_measures,
            &parsed.into_value(),
        )
    }

    // Shared validation for an already strictly parsed settings value.
    fn parse_value(
        alphabet: &Alphabet,
        domain: &AttackPlugboardDomain,
        declared_passes: &[String],
        declared_measures: &[MeasureId],
        value: &Value,
    ) -> Result<Self, Vec<SearchDiagnostic>> {
        const PATH: &str = "/job/attack";
        if domain.alphabet != alphabet.symbols {
            return Err(vec![invalid(
                "domain belongs to a different ordered alphabet",
                PATH,
            )]);
        }
        let settings = object(value, PATH)?;
        // Check unknown members before required/type checks, including deferred kinds.
        allow_keys(
            settings,
            &[
                "kind",
                "initial_measure",
                "final_measure",
                "switch_pairs",
                "backtrack_pairs",
                "progress_every",
                "hold",
                "start",
                "seeds",
                "reswapping",
                "trie",
                "measure",
            ],
            PATH,
        )?;
        attack_passes_shape(declared_passes)?;
        let kind = required_string(settings, "kind", PATH)?;
        if declared_passes[0] != kind {
            return Err(vec![invalid(
                "kind must match the sole selected attack pass",
                child(PATH, "kind"),
            )]);
        }
        let (kind, forbidden) = if kind == "hill_climb" {
            (AttackKind::HillClimb, "seeds")
        } else {
            (AttackKind::PartialExhaustion, "start")
        };
        if settings.contains_key(forbidden) {
            return Err(vec![invalid(
                "member is forbidden for the selected attack kind",
                child(PATH, forbidden),
            )]);
        }
        let objective = |key: &str| {
            let id = required_string(settings, key, PATH)?;
            declared_measures
                .iter()
                .copied()
                .find(|measure| measure.id() == id)
                .ok_or_else(|| {
                    vec![invalid(
                        "objective must be an exact declared measure identifier",
                        child(PATH, key),
                    )]
                })
        };
        let initial_measure = objective("initial_measure")?;
        let final_measure = objective("final_measure")?;
        let threshold = |key: &str| {
            let path = child(PATH, key);
            let value = required(settings, key, PATH)?;
            let count = value
                .as_u64()
                .filter(|&count| count <= (alphabet.len() / 2) as u64)
                .ok_or_else(|| {
                    vec![invalid_search_space(
                        "threshold must be an integer within alphabet pair capacity",
                        &path,
                    )]
                })?;
            Ok::<usize, Vec<SearchDiagnostic>>(count as usize)
        };
        let switch_pairs = threshold("switch_pairs")?;
        let backtrack_pairs = threshold("backtrack_pairs")?;
        let hold_capacity = settings.get("hold").map_or(Ok(100), |value| {
            value
                .as_u64()
                .filter(|capacity| (1..=1000).contains(capacity))
                .map(|capacity| capacity as usize)
                .ok_or_else(|| {
                    vec![invalid(
                        "hold must be an integer in [1, 1000]",
                        child(PATH, "hold"),
                    )]
                })
        })?;
        let progress_every = settings
            .get("progress_every")
            .map_or(Ok(100_000), |value| {
                value.as_u64().filter(|&count| count > 0).ok_or_else(|| {
                    vec![invalid(
                        "progress_every must be a positive u64 integer",
                        child(PATH, "progress_every"),
                    )]
                })
            })?;
        let initialization = if kind == AttackKind::PartialExhaustion {
            AttackInitialization::Seeds(parse_seed_policy(
                required(settings, "seeds", PATH)?,
                domain,
                alphabet,
            )?)
        } else {
            let start_path = child(PATH, "start");
            let start_value = required(settings, "start", PATH)?;
            // Translate only start-helper failures; shared legacy helper codes stay intact.
            let start = (|| {
                let start = parse_pair_array(array(start_value, &start_path)?, &start_path)?;
                validate_disjoint_pairs(&start, &start_path, alphabet)?;
                for (index, &(left, right)) in start.iter().enumerate() {
                    if !domain.symbols.contains(&left) || !domain.symbols.contains(&right) {
                        return Err(vec![invalid_search_space(
                            "start endpoints must belong to the mutable domain, not fixed facts",
                            child(&start_path, &index.to_string()),
                        )]);
                    }
                }
                if start.len() > domain.max_pairs - domain.fixed_pairs.len() {
                    return Err(vec![invalid_search_space(
                        "fixed pairs plus start exceed max_pairs",
                        &start_path,
                    )]);
                }
                Ok(start)
            })()
            .map_err(|mut diagnostics: Vec<SearchDiagnostic>| {
                for diagnostic in &mut diagnostics {
                    diagnostic.code = "invalid_search_space";
                }
                diagnostics
            })?;
            AttackInitialization::Start(start)
        };
        let listed = &declared_passes[1..];
        if let Some(stage) = ["reswapping", "trie", "measure"]
            .into_iter()
            .find(|&stage| settings.contains_key(stage) && !listed.iter().any(|pass| pass == stage))
        {
            return Err(vec![invalid(
                "stage settings require the same-named listed stage",
                child(PATH, stage),
            )]);
        }
        let declared = |id: &str| declared_measures.iter().copied().find(|m| m.id() == id);
        let mut stages = Vec::with_capacity(listed.len());
        let mut stage_measure_explicit = Vec::with_capacity(listed.len());
        for (index, stage) in listed.iter().enumerate() {
            let path = child(PATH, stage);
            let passes_path = format!("/job/passes/{}", index + 1);
            let empty = Map::new();
            let fields = settings
                .get(stage.as_str())
                .map_or(Ok(&empty), |value| object(value, &path))?;
            let (key, default) = match stage.as_str() {
                "reswapping" => ("measure", Some("sinkov_trigram")),
                "trie" => ("base_measure", None),
                _ => ("measure", Some("ic")),
            };
            allow_keys(fields, &[key], &path)?;
            let measure = match (fields.get(key), default) {
                (Some(value), _) => Some(value.as_str().and_then(declared).ok_or_else(|| {
                    vec![invalid(
                        "stage measure must be an exact declared measure identifier",
                        child(&path, key),
                    )]
                })?),
                (None, Some(id)) => Some(declared(id).ok_or_else(|| {
                    vec![invalid(
                        "defaulted stage measure must be declared",
                        &passes_path,
                    )]
                })?),
                (None, None) => None,
            };
            stage_measure_explicit.push(fields.contains_key(key));
            stages.push(match (stage.as_str(), measure) {
                ("reswapping", Some(measure)) => AttackStage::Reswapping { measure },
                ("measure", Some(measure)) => AttackStage::Measure { measure },
                _ => {
                    if declared("trie").is_none() {
                        return Err(vec![invalid(
                            "trie stage requires declared trie measure",
                            passes_path,
                        )]);
                    }
                    AttackStage::Trie {
                        base_measure: measure,
                    }
                }
            });
        }
        Ok(Self {
            kind,
            initial_measure,
            final_measure,
            switch_pairs,
            backtrack_pairs,
            progress_every,
            hold_capacity,
            initialization,
            stages,
            stage_measure_explicit,
        })
    }

    /// Validated settings-fragment kind.
    pub fn kind(&self) -> AttackKind {
        self.kind
    }
    /// Exact declared initial objective.
    pub fn initial_measure(&self) -> MeasureId {
        self.initial_measure
    }
    /// Exact declared final objective.
    pub fn final_measure(&self) -> MeasureId {
        self.final_measure
    }
    /// Total pair cardinality threshold for switching objectives.
    pub fn switch_pairs(&self) -> usize {
        self.switch_pairs
    }
    /// Total pair cardinality threshold for backtracking.
    pub fn backtrack_pairs(&self) -> usize {
        self.backtrack_pairs
    }
    /// Whole-attack completed-evaluation progress interval (default 100000).
    pub fn progress_every(&self) -> u64 {
        self.progress_every
    }

    /// Finalist capacity in [1, 1000], defaulting to 100 when omitted.
    pub fn hold_capacity(&self) -> usize {
        self.hold_capacity
    }
    /// Mutable starting pairs in source order and orientation, excluding fixed facts.
    pub fn start(&self) -> Option<&[(char, char)]> {
        match &self.initialization {
            AttackInitialization::Start(start) => Some(start),
            AttackInitialization::Seeds(_) => None,
        }
    }
    /// Seed policy only for partial exhaustion; does not enumerate seeds.
    pub fn seed_policy(&self) -> Option<&AttackSeedPolicy> {
        match &self.initialization {
            AttackInitialization::Seeds(policy) => Some(policy),
            AttackInitialization::Start(_) => None,
        }
    }
    // Preserve explicit/default diagnostic locations when checking detached settings.
    pub(crate) fn stage_measure_path(&self, index: usize, stage: &str, key: &str) -> String {
        if self.stage_measure_explicit[index] {
            format!("/job/attack/{stage}/{key}")
        } else {
            format!("/job/passes/{}", index + 1)
        }
    }

    /// Chained stages in `job.passes` order; empty for HC/PE-only requests.
    pub(crate) fn stages(&self) -> &[AttackStage] {
        &self.stages
    }
}

fn parse_seed_policy(
    value: &Value,
    domain: &AttackPlugboardDomain,
    alphabet: &Alphabet,
) -> Result<AttackSeedPolicy, Vec<SearchDiagnostic>> {
    const PATH: &str = "/job/attack/seeds";
    let policy = object(value, PATH)?;
    allow_keys(policy, &["kind", "selection", "symbols"], PATH)?;
    if required_string(policy, "kind", PATH)? != "empty_single" {
        return Err(vec![invalid(
            "kind must be empty_single",
            child(PATH, "kind"),
        )]);
    }
    match required_string(policy, "selection", PATH)? {
        "all" => {
            if policy.contains_key("symbols") {
                return Err(vec![invalid("all forbids symbols", child(PATH, "symbols"))]);
            }
            Ok(AttackSeedPolicy::All)
        }
        "touching" => {
            let path = child(PATH, "symbols");
            let value = required(policy, "symbols", PATH)?;
            let symbols = (|| {
                let values = array(value, &path)?;
                if values.is_empty() {
                    return Err(vec![invalid_search_space("mask must not be empty", &path)]);
                }
                let mut seen = HashSet::new();
                let mut symbols = Vec::with_capacity(values.len());
                for (index, value) in values.iter().enumerate() {
                    let symbol_path = child(&path, &index.to_string());
                    let symbol = scalar(value, &symbol_path)?;
                    if alphabet.index_of(symbol).is_none() || !domain.symbols.contains(&symbol) {
                        return Err(vec![invalid_search_space(
                            "mask symbol must belong to the mutable domain",
                            symbol_path,
                        )]);
                    }
                    if !seen.insert(symbol) {
                        return Err(vec![invalid_search_space(
                            "duplicate mask symbol",
                            symbol_path,
                        )]);
                    }
                    symbols.push(symbol);
                }
                Ok(symbols)
            })()
            .map_err(|mut errors: Vec<SearchDiagnostic>| {
                for error in &mut errors {
                    error.code = "invalid_search_space";
                }
                errors
            })?;
            Ok(AttackSeedPolicy::Touching(symbols))
        }
        _ => Err(vec![invalid(
            "selection must be all or touching",
            child(PATH, "selection"),
        )]),
    }
}

/// The explicit variable domains and bounds of `job.space`.
///
/// `slots` and `plugboard` are optional: a fully fixed search declares no variable
/// dimensions. `offset` defaults to `0`; `limit` is an explicit optional request bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchSpace {
    slots: Vec<SearchSlotDomain>,
    plugboard: Option<PlugboardDomain>,
    offset: u64,
    limit: Option<u64>,
}

impl SearchSpace {
    /// The declared slot domains in source order.
    pub fn slots(&self) -> &[SearchSlotDomain] {
        &self.slots
    }

    /// The searched plugboard remainder, when present.
    pub fn plugboard(&self) -> Option<&PlugboardDomain> {
        self.plugboard.as_ref()
    }

    /// Deterministic enumeration offset; defaults to `0`.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Explicit optional bound on the number of enumerated candidates.
    pub fn limit(&self) -> Option<u64> {
        self.limit
    }
}

/// A fully validated `search` request, ready for the candidate resolver (slice 9.3).
///
/// Structural validation and capability preflight have passed, and no unbound
/// resources remain. Candidate enumeration is lazy in `candidate.rs`. Construction
/// is private: callers cannot promote path references to validated contents.
#[derive(Debug)]
pub struct SearchRequest {
    parsed: ParsedSearchRequest,
    bound_resources: Vec<(MeasureId, crate::BoundResource)>,
}

impl SearchRequest {
    /// Resource-free convenience; external references require supplied content binding.
    pub fn parse_json(json: &str) -> Result<Self, Vec<RequestDiagnostic>> {
        ParsedSearchRequest::parse_json(json)?.into_resource_free()
    }
    /// Validated machine definition.
    pub fn definition(&self) -> &Definition {
        self.parsed.definition()
    }
    /// Validated input text.
    pub fn text(&self) -> &str {
        self.parsed.text()
    }
    /// Fixed key choices.
    pub fn configuration(&self) -> &SearchConfiguration {
        self.parsed.configuration()
    }
    /// Explicit variable domains.
    pub fn space(&self) -> &SearchSpace {
        self.parsed.space()
    }
    /// Selected passes in source order.
    pub fn passes(&self) -> &[String] {
        self.parsed.passes()
    }
    /// Typed measures in source order.
    pub fn measures(&self) -> &[MeasureId] {
        self.parsed.measures()
    }
    /// Validated external path metadata.
    pub fn resources(&self) -> &[ResourceReference] {
        self.parsed.resources()
    }
    /// Retained scoring model for a resource-dependent measure, or `None` if unselected.
    /// Resource-free measures never have a bound model.
    pub fn bound_resource(&self, measure: MeasureId) -> Option<&crate::BoundResource> {
        self.bound_resources
            .iter()
            .find(|(id, _)| *id == measure)
            .map(|(_, model)| model)
    }
    pub(crate) fn parsed(&self) -> &ParsedSearchRequest {
        &self.parsed
    }
}

/// Structurally validated inputs, not yet eligible for enumeration.
///
/// ```compile_fail
/// fn enumerate(request: enigma_core::ParsedSearchRequest) {
///     request.candidates();
/// }
/// ```
#[derive(Debug)]
pub struct ParsedSearchRequest {
    definition: Definition,
    text: String,
    configuration: SearchConfiguration,
    space: SearchSpace,
    passes: Vec<String>,
    measures: Vec<MeasureId>,
    resources: Vec<ResourceReference>,
}

impl ParsedSearchRequest {
    /// Consumes this structural request and binds supplied UTF-8 text by exact measure ID.
    ///
    /// Contents are borrowed only during binding. Successful requests own the parsed
    /// immutable scoring models, not the raw JSON; callers can drop the supplied text.
    /// Paths are never opened. Missing/extra keys and all budgets fail before model parsing.
    pub fn bind_resources(
        self,
        supplied: &std::collections::BTreeMap<String, &str>,
    ) -> Result<SearchRequest, Vec<RequestDiagnostic>> {
        let bound_resources = crate::binding::bind(&self, supplied)?;
        Ok(SearchRequest {
            parsed: self,
            bound_resources,
        })
    }

    /// Converts only resource-free selections; paths alone never authorize enumeration.
    pub fn into_resource_free(self) -> Result<SearchRequest, Vec<RequestDiagnostic>> {
        if let Some(reference) = self.resources.first() {
            return Err(vec![SearchDiagnostic::new(
                "unsupported_resource",
                "external resources require supplied content binding before enumeration",
                format!("/job/resources/{}/path", reference.measure().id()),
            )
            .into()]);
        }
        Ok(SearchRequest {
            parsed: self,
            bound_resources: Vec::new(),
        })
    }
    /// Parses and fully validates a `kind: "search"` JSON request.
    ///
    /// Validation order mirrors the protocol: shared root and definition, then the
    /// search-job exact fields, then configuration and space structure and symbols, then
    /// coverage/conflict rules. A non-search job kind is `unsupported_job` at
    /// `/job/kind`. Nothing is defaulted; an uncovered required dimension is an error.
    pub fn parse_json(json: &str) -> Result<Self, Vec<RequestDiagnostic>> {
        Self::from_parsed_root(parse_root(json)?)
    }

    pub(crate) fn from_parsed_root(root: ParsedRoot) -> Result<Self, Vec<RequestDiagnostic>> {
        parse_search_job(&root.definition, &root.job).map_err(|diagnostics| {
            diagnostics
                .into_iter()
                .map(RequestDiagnostic::from)
                .collect()
        })
    }

    /// The validated key-free machine definition this search resolves against.
    pub fn definition(&self) -> &Definition {
        &self.definition
    }

    /// The validated plaintext or ciphertext to search over.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The known fixed key choices.
    pub fn configuration(&self) -> &SearchConfiguration {
        &self.configuration
    }

    /// The explicit variable domains and bounds.
    pub fn space(&self) -> &SearchSpace {
        &self.space
    }

    /// Requested pass identifiers, in source order.
    pub fn passes(&self) -> &[String] {
        &self.passes
    }

    /// Typed measure selection, in source order.
    pub fn measures(&self) -> &[MeasureId] {
        &self.measures
    }

    /// Validated external path references, in deterministic ID order.
    pub fn resources(&self) -> &[ResourceReference] {
        &self.resources
    }
}

fn parse_search_job(
    definition: &Definition,
    job: &Value,
) -> Result<ParsedSearchRequest, Vec<SearchDiagnostic>> {
    let job = object(job, "/job")?;
    let kind = required_string(job, "kind", "/job")?;
    if kind != "search" {
        return Err(vec![SearchDiagnostic::new(
            "unsupported_job",
            format!("job kind {kind:?} is not supported; only `search` is implemented here"),
            "/job/kind",
        )]);
    }
    exact_keys_with_optional(
        job,
        &[
            "kind",
            "configuration",
            "text",
            "space",
            "passes",
            "measures",
        ],
        &["resources"],
        "/job",
    )?;

    parse_search_carrier(definition, job, PlugboardConstruction::LegacyPool)
}

/// Structurally validated attack inputs awaiting resource binding and eligibility.
///
/// ```compile_fail
/// fn carrier(request: enigma_core::ParsedAttackRequest) { let _ = request.carrier; }
/// ```
#[derive(Debug)]
pub struct ParsedAttackRequest {
    carrier: ParsedSearchRequest,
    domain: AttackPlugboardDomain,
    settings: AttackSettings,
}

impl ParsedAttackRequest {
    /// Validated references callers can load without exposing the slot carrier.
    pub fn resources(&self) -> &[ResourceReference] {
        self.carrier.resources()
    }

    /// Binds exact supplied contents without I/O, then checks attack eligibility.
    pub fn bind_resources(
        self,
        supplied: &std::collections::BTreeMap<String, &str>,
    ) -> Result<AttackRequest, Vec<RequestDiagnostic>> {
        AttackRequest::finish(
            self.carrier.bind_resources(supplied)?,
            self.domain,
            self.settings,
        )
    }

    /// Promotes resource-free selections only, then checks attack eligibility.
    pub fn into_resource_free(self) -> Result<AttackRequest, Vec<RequestDiagnostic>> {
        AttackRequest::finish(
            self.carrier.into_resource_free()?,
            self.domain,
            self.settings,
        )
    }

    /// Parses a strict complete attack request once, without binding or enumeration.
    pub fn parse_json(json: &str) -> Result<Self, Vec<RequestDiagnostic>> {
        Self::from_parsed_root(parse_root(json)?)
    }

    pub(crate) fn from_parsed_root(root: ParsedRoot) -> Result<Self, Vec<RequestDiagnostic>> {
        let parse = || {
            let job = object(&root.job, "/job")?;
            if required_string(job, "kind", "/job")? != "search" {
                return Err(vec![SearchDiagnostic::new(
                    "unsupported_job",
                    "attack jobs must use kind `search`",
                    "/job/kind",
                )]);
            }
            exact_keys_with_optional(
                job,
                &[
                    "kind",
                    "configuration",
                    "text",
                    "space",
                    "passes",
                    "measures",
                    "attack",
                ],
                &["resources"],
                "/job",
            )?;
            let (carrier, (domain, settings)) = parse_carrier_with(
                &root.definition,
                job,
                PlugboardConstruction::SlotOnly,
                |configuration, passes, ids| {
                    let space = object(required(job, "space", "/job")?, "/job/space")?;
                    let domain = AttackPlugboardDomain::parse_value(
                        root.definition.alphabet(),
                        configuration.plugboard(),
                        required(space, "plugboard", "/job/space")?,
                    )?;
                    let measures = parse_measures(ids)?;
                    let settings = AttackSettings::parse_value(
                        root.definition.alphabet(),
                        &domain,
                        passes,
                        &measures,
                        required(job, "attack", "/job")?,
                    )?;
                    Capabilities::stage1().check_passes(&root.definition, passes)?;
                    Ok((measures, (domain, settings)))
                },
            )?;
            Ok(Self {
                carrier,
                domain,
                settings,
            })
        };
        parse().map_err(|diagnostics: Vec<SearchDiagnostic>| {
            diagnostics
                .into_iter()
                .map(RequestDiagnostic::from)
                .collect()
        })
    }
}

/// Resource-bound, eligibility-checked attack inputs; not executable or publicly enumerable.
///
/// ```compile_fail
/// fn carrier(request: enigma_core::AttackRequest) { let _ = request.carrier; }
/// ```
///
/// ```compile_fail
/// fn enumerate(request: enigma_core::AttackRequest) { request.candidates(); }
/// ```
///
/// ```compile_fail
/// fn resolve(request: enigma_core::AttackRequest) { request.candidate_at(0); }
/// ```
///
/// ```compile_fail
/// fn outer(request: enigma_core::AttackRequest) { request.outer_candidates(); }
/// ```
#[derive(Debug)]
pub struct AttackRequest {
    carrier: SearchRequest,
    domain: AttackPlugboardDomain,
    settings: AttackSettings,
    gate: crate::AttackGate,
}

impl AttackRequest {
    /// Builds one indexed projection after eligibility has checked the full count.
    pub(crate) fn outer_plan(&self) -> crate::attack_blocks::OuterPlan<'_> {
        crate::attack_blocks::OuterPlan::new(&self.carrier, &self.gate)
    }

    /// Lazily projects slot assignments and fixed plugboard facts, not mutable starts.
    /// Indices address the full outer space, including items that fail resolution.
    #[cfg(test)]
    pub(crate) fn outer_candidates(
        &self,
    ) -> impl Iterator<
        Item = (
            u128,
            Result<crate::ResolvedConfiguration, Vec<SearchDiagnostic>>,
        ),
    > + '_ {
        // Eligibility rejects legacy pools and full-count overflow before slicing.
        // The checked total bounds every yielded index strictly below u128::MAX.
        let mut index = u128::from(self.carrier.space().offset()).min(self.gate.outer_total());
        self.carrier.candidates().map(move |result| {
            let current = index;
            index = index
                .checked_add(1)
                .expect("eligible outer candidate index cannot overflow");
            (current, result)
        })
    }

    fn finish(
        carrier: SearchRequest,
        domain: AttackPlugboardDomain,
        settings: AttackSettings,
    ) -> Result<Self, Vec<RequestDiagnostic>> {
        let gate = crate::AttackGate::check(&carrier, &domain, &settings).map_err(|errors| {
            errors
                .into_iter()
                .map(RequestDiagnostic::from)
                .collect::<Vec<_>>()
        })?;
        Ok(Self {
            carrier,
            domain,
            settings,
            gate,
        })
    }

    /// Parses and promotes only resource-free complete attack requests.
    pub fn parse_json(json: &str) -> Result<Self, Vec<RequestDiagnostic>> {
        ParsedAttackRequest::parse_json(json)?.into_resource_free()
    }
    /// Validated machine definition.
    pub fn definition(&self) -> &Definition {
        self.carrier.definition()
    }
    /// Validated input text.
    pub fn text(&self) -> &str {
        self.carrier.text()
    }
    /// Selected measures in source order.
    pub fn measures(&self) -> &[MeasureId] {
        self.carrier.measures()
    }
    /// Validated external reference metadata.
    pub fn resources(&self) -> &[ResourceReference] {
        self.carrier.resources()
    }
    /// Retained immutable scoring model, if the measure requires one.
    pub fn bound_resource(&self, measure: MeasureId) -> Option<&crate::BoundResource> {
        self.carrier.bound_resource(measure)
    }
    /// Mutable domain and immutable fixed facts.
    pub fn domain(&self) -> &AttackPlugboardDomain {
        &self.domain
    }
    /// Validated typed attack settings.
    pub fn settings(&self) -> &AttackSettings {
        &self.settings
    }
    /// Checked cardinalities, not evaluation reservations.
    pub fn gate(&self) -> &crate::AttackGate {
        &self.gate
    }
}

#[derive(Clone, Copy)]
enum PlugboardConstruction {
    LegacyPool,
    SlotOnly,
}

/// Constructs only shared carrier facts, not a complete attack request. The caller
/// owns the job boundary and any attack-domain/settings validation. SlotOnly must
/// remain private and unreachable from public legacy candidate enumeration.
fn parse_search_carrier(
    definition: &Definition,
    job: &Map<String, Value>,
    plugboard: PlugboardConstruction,
) -> Result<ParsedSearchRequest, Vec<SearchDiagnostic>> {
    parse_carrier_with(definition, job, plugboard, |_, passes, ids| {
        // Preserve legacy pass/topology precedence before concrete measures.
        Capabilities::stage1().check_passes(definition, passes)?;
        Ok((parse_measures(ids)?, ()))
    })
    .map(|(carrier, ())| carrier)
}

fn parse_carrier_with<T>(
    definition: &Definition,
    job: &Map<String, Value>,
    plugboard: PlugboardConstruction,
    validate: impl FnOnce(
        &SearchConfiguration,
        &[String],
        &[String],
    ) -> Result<(Vec<MeasureId>, T), Vec<SearchDiagnostic>>,
) -> Result<(ParsedSearchRequest, T), Vec<SearchDiagnostic>> {
    let configuration = parse_configuration(definition, required(job, "configuration", "/job")?)?;
    let space = parse_space(definition, required(job, "space", "/job")?, plugboard)?;
    let text = required_string(job, "text", "/job")?;
    let passes = parse_identifier_array(job, "passes", "/job")?;
    let measures = parse_identifier_array(job, "measures", "/job")?;

    if let Some(symbol) = text
        .chars()
        .find(|symbol| definition.alphabet().index_of(*symbol).is_none())
    {
        return Err(vec![SearchDiagnostic::new(
            "invalid_text",
            format!("symbol {symbol:?} is not in the machine alphabet"),
            "/job/text",
        )]);
    }

    validate_coverage(definition, &configuration, &space)?;
    if let Some(domain) = space.plugboard() {
        validate_plugboard_remainder(
            configuration.plugboard(),
            domain.candidates(),
            "/job/space/plugboard/candidates",
        )?;
    }

    let (measures, extra) = validate(&configuration, &passes, &measures)?;
    let resources = parse_references(&measures, job.get("resources"))?;
    let samples = text.chars().count();
    if let Some(measure) = measures
        .iter()
        .find(|measure| samples < measure.minimum_samples())
    {
        return Err(vec![SearchDiagnostic::new(
            "invalid_text",
            format!(
                "{} requires at least {} Unicode scalars",
                measure.id(),
                measure.minimum_samples()
            ),
            "/job/text",
        )]);
    }
    let request = ParsedSearchRequest {
        definition: definition.clone(),
        text: text.to_owned(),
        configuration,
        space,
        passes,
        measures,
        resources,
    };
    Capabilities::stage1().preflight_parsed(&request)?;
    Ok((request, extra))
}

fn parse_configuration(
    definition: &Definition,
    value: &Value,
) -> Result<SearchConfiguration, Vec<SearchDiagnostic>> {
    let path = "/job/configuration";
    let configuration = object(value, path)?;
    exact_keys(configuration, &["slots", "plugboard"], path)?;

    let slots_path = child(path, "slots");
    let entries = array(required(configuration, "slots", path)?, &slots_path)?;
    let mut slots = Vec::with_capacity(entries.len());
    let mut seen = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = child(&slots_path, &index.to_string());
        let entry = object(entry, &entry_path)?;
        allow_keys(entry, &["id", "wheel", "position", "ring"], &entry_path)?;

        let id = required_string(entry, "id", &entry_path)?;
        let id_path = child(&entry_path, "id");
        if id.is_empty() {
            return Err(vec![invalid_search_space(
                "slot id must not be empty",
                id_path,
            )]);
        }
        if !seen.insert(id.to_owned()) {
            return Err(vec![invalid_search_space(
                format!("slot id {id:?} is declared more than once in configuration"),
                id_path,
            )]);
        }
        let Some(definition_slot) = definition.slots().iter().find(|slot| slot.id() == id) else {
            return Err(vec![invalid_search_space(
                format!("unknown slot id {id:?}; the definition does not declare it"),
                id_path,
            )]);
        };

        let wheel = match entry.get("wheel") {
            Some(value) => {
                let wheel = string(value, &child(&entry_path, "wheel"))?;
                let admissible = match definition_slot.wheel() {
                    Some(fixed) => wheel == fixed,
                    None => definition_slot
                        .allowed_wheels()
                        .iter()
                        .any(|allowed| allowed == wheel),
                };
                if !admissible {
                    let message = match definition_slot.wheel() {
                        Some(fixed) => format!(
                            "slot {id:?} fixes wheel {fixed:?}; got {wheel:?}"
                        ),
                        None => format!(
                            "wheel {wheel:?} is not admissible for slot {id:?}; allowed wheels: {:?}",
                            definition_slot.allowed_wheels()
                        ),
                    };
                    return Err(vec![SearchDiagnostic::new(
                        "invalid_slot",
                        message,
                        child(&entry_path, "wheel"),
                    )]);
                }
                Some(wheel.to_owned())
            }
            None => None,
        };
        let position = optional_symbol(entry, "position", &entry_path, definition.alphabet())?;
        let ring = optional_symbol(entry, "ring", &entry_path, definition.alphabet())?;
        slots.push(SearchFixedSlot {
            id: id.to_owned(),
            wheel,
            position,
            ring,
        });
    }

    let plugboard_path = child(path, "plugboard");
    let pair_values = array(required(configuration, "plugboard", path)?, &plugboard_path)?;
    let plugboard = parse_pair_array(pair_values, &plugboard_path)?;
    validate_disjoint_pairs(&plugboard, &plugboard_path, definition.alphabet())?;

    Ok(SearchConfiguration { slots, plugboard })
}

fn parse_space(
    definition: &Definition,
    value: &Value,
    plugboard: PlugboardConstruction,
) -> Result<SearchSpace, Vec<SearchDiagnostic>> {
    let path = "/job/space";
    let space = object(value, path)?;
    allow_keys(space, &["slots", "plugboard", "offset", "limit"], path)?;

    let mut slots = Vec::new();
    if let Some(slots_value) = space.get("slots") {
        let slots_path = child(path, "slots");
        let entries = array(slots_value, &slots_path)?;
        let mut seen = HashSet::new();
        for (index, entry) in entries.iter().enumerate() {
            let entry_path = child(&slots_path, &index.to_string());
            slots.push(parse_slot_domain(
                definition,
                entry,
                &entry_path,
                &mut seen,
            )?);
        }
    }

    let plugboard = match plugboard {
        PlugboardConstruction::LegacyPool => match space.get("plugboard") {
            Some(value) => Some(parse_plugboard_domain(
                definition.alphabet(),
                value,
                &child(path, "plugboard"),
            )?),
            None => None,
        },
        PlugboardConstruction::SlotOnly => None,
    };

    let offset = match space.get("offset") {
        Some(value) => value.as_u64().ok_or_else(|| {
            vec![invalid(
                "offset must be a non-negative integer",
                child(path, "offset"),
            )]
        })?,
        None => 0,
    };

    let limit = match space.get("limit") {
        Some(value) => {
            let limit = value.as_u64().ok_or_else(|| {
                vec![invalid(
                    "limit must be a positive integer",
                    child(path, "limit"),
                )]
            })?;
            if limit == 0 {
                return Err(vec![invalid(
                    "limit must be a positive integer",
                    child(path, "limit"),
                )]);
            }
            Some(limit)
        }
        None => None,
    };

    Ok(SearchSpace {
        slots,
        plugboard,
        offset,
        limit,
    })
}

fn parse_slot_domain(
    definition: &Definition,
    value: &Value,
    path: &str,
    seen: &mut HashSet<String>,
) -> Result<SearchSlotDomain, Vec<SearchDiagnostic>> {
    let entry = object(value, path)?;
    allow_keys(entry, &["id", "wheels", "positions", "rings"], path)?;

    let id = required_string(entry, "id", path)?;
    let id_path = child(path, "id");
    if id.is_empty() {
        return Err(vec![invalid_search_space(
            "slot domain id must not be empty",
            id_path,
        )]);
    }
    if !seen.insert(id.to_owned()) {
        return Err(vec![invalid_search_space(
            format!("slot id {id:?} is declared more than once in space.slots"),
            id_path,
        )]);
    }
    let Some(definition_slot) = definition.slots().iter().find(|slot| slot.id() == id) else {
        return Err(vec![invalid_search_space(
            format!("unknown slot id {id:?}; the definition does not declare it"),
            id_path,
        )]);
    };

    let wheels = match entry.get("wheels") {
        Some(value) => {
            if definition_slot.wheel().is_some() {
                return Err(vec![invalid_search_space(
                    format!(
                        "slot {id:?} has a structurally fixed wheel; space.slots must not declare `wheels` for it"
                    ),
                    child(path, "wheels"),
                )]);
            }
            let names = parse_unique_string_array(value, &child(path, "wheels"))?;
            for name in &names {
                if !definition_slot
                    .allowed_wheels()
                    .iter()
                    .any(|allowed| allowed == name)
                {
                    return Err(vec![invalid_search_space(
                        format!(
                            "wheel {name:?} is not admissible for slot {id:?}; allowed wheels: {:?}",
                            definition_slot.allowed_wheels()
                        ),
                        child(path, "wheels"),
                    )]);
                }
            }
            Some(names)
        }
        None => None,
    };
    let positions = match entry.get("positions") {
        Some(value) => Some(parse_unique_symbol_array(
            value,
            &child(path, "positions"),
            definition.alphabet(),
        )?),
        None => None,
    };
    let rings = match entry.get("rings") {
        Some(value) => Some(parse_unique_symbol_array(
            value,
            &child(path, "rings"),
            definition.alphabet(),
        )?),
        None => None,
    };

    if wheels.is_none() && positions.is_none() && rings.is_none() {
        return Err(vec![invalid_search_space(
            "slot domain must declare at least one of `wheels`, `positions`, or `rings`",
            path,
        )]);
    }

    Ok(SearchSlotDomain {
        id: id.to_owned(),
        wheels,
        positions,
        rings,
    })
}

fn parse_plugboard_domain(
    alphabet: &Alphabet,
    value: &Value,
    path: &str,
) -> Result<PlugboardDomain, Vec<SearchDiagnostic>> {
    let plugboard = object(value, path)?;
    exact_keys(plugboard, &["candidates", "size"], path)?;

    let candidates_path = child(path, "candidates");
    let candidate_values = array(required(plugboard, "candidates", path)?, &candidates_path)?;
    if candidate_values.is_empty() {
        return Err(vec![invalid_search_space(
            "plugboard candidates must not be empty",
            candidates_path,
        )]);
    }
    let candidates = parse_pair_array(candidate_values, &candidates_path)?;
    validate_disjoint_pairs(&candidates, &candidates_path, alphabet)?;

    let size_path = child(path, "size");
    let size = required(plugboard, "size", path)?
        .as_u64()
        .ok_or_else(|| vec![invalid("size must be a positive integer", &size_path)])?;
    if size == 0 {
        return Err(vec![invalid("size must be a positive integer", &size_path)]);
    }
    if size as usize > candidates.len() {
        return Err(vec![invalid_search_space(
            format!(
                "size {size} exceeds the {} candidate pairs",
                candidates.len()
            ),
            size_path,
        )]);
    }

    Ok(PlugboardDomain {
        candidates,
        size: size as usize,
    })
}

fn validate_coverage(
    definition: &Definition,
    configuration: &SearchConfiguration,
    space: &SearchSpace,
) -> Result<(), Vec<SearchDiagnostic>> {
    let fixed: std::collections::HashMap<&str, &SearchFixedSlot> = configuration
        .slots()
        .iter()
        .map(|slot| (slot.id.as_str(), slot))
        .collect();
    let domains: std::collections::HashMap<&str, usize> = space
        .slots()
        .iter()
        .enumerate()
        .map(|(index, domain)| (domain.id.as_str(), index))
        .collect();

    for definition_slot in definition.slots() {
        let id = definition_slot.id();
        let fixed_slot = fixed.get(id).copied();
        let domain_entry = domains.get(id).map(|&index| (index, &space.slots()[index]));

        require_dimension(
            id,
            "position",
            "positions",
            fixed_slot.and_then(|slot| slot.position).is_some(),
            domain_entry.map(|(index, _)| index),
            domain_entry
                .and_then(|(_, domain)| domain.positions.as_ref())
                .is_some(),
        )?;
        require_dimension(
            id,
            "ring",
            "rings",
            fixed_slot.and_then(|slot| slot.ring).is_some(),
            domain_entry.map(|(index, _)| index),
            domain_entry
                .and_then(|(_, domain)| domain.rings.as_ref())
                .is_some(),
        )?;

        // A structurally fixed wheel has no wheel dimension; declaring wheels for it was
        // already rejected during slot-domain parsing.
        if definition_slot.wheel().is_none() {
            require_dimension(
                id,
                "wheels",
                "wheels",
                fixed_slot.and_then(|slot| slot.wheel.as_ref()).is_some(),
                domain_entry.map(|(index, _)| index),
                domain_entry
                    .and_then(|(_, domain)| domain.wheels.as_ref())
                    .is_some(),
            )?;
        }
    }

    Ok(())
}

fn require_dimension(
    slot_id: &str,
    dimension: &str,
    pointer_member: &str,
    fixed: bool,
    declared_index: Option<usize>,
    declared: bool,
) -> Result<(), Vec<SearchDiagnostic>> {
    if fixed && declared {
        let index = declared_index.expect("a declared dimension always has a domain index");
        return Err(vec![invalid_search_space(
            format!(
                "slot {slot_id:?} {dimension} is covered twice: fixed in configuration and declared in space.slots; keep exactly one path"
            ),
            format!("/job/space/slots/{index}/{pointer_member}"),
        )]);
    }
    if !fixed && !declared {
        return Err(vec![invalid_search_space(
            format!(
                "slot {slot_id:?} {dimension} is neither fixed in configuration nor declared in space.slots; add exactly one path"
            ),
            "/job/space/slots",
        )]);
    }
    Ok(())
}

/// Rejects a candidate pair that reuses a symbol from a known fixed pair, so the fixed
/// and searched plugboard sets stay disjoint.
fn validate_plugboard_remainder(
    fixed: &[(char, char)],
    candidates: &[(char, char)],
    candidates_path: &str,
) -> Result<(), Vec<SearchDiagnostic>> {
    let fixed_symbols: HashSet<char> = fixed
        .iter()
        .flat_map(|&(left, right)| [left, right])
        .collect();
    for (index, &(left, right)) in candidates.iter().enumerate() {
        if fixed_symbols.contains(&left) || fixed_symbols.contains(&right) {
            return Err(vec![invalid_search_space(
                "space.plugboard candidate pair shares a symbol with a known fixed configuration pair; fixed and searched pairs must be disjoint",
                child(candidates_path, &index.to_string()),
            )]);
        }
    }
    Ok(())
}

fn parse_identifier_array(
    job: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Vec<String>, Vec<SearchDiagnostic>> {
    let array_path = child(path, key);
    let values = array(required(job, key, path)?, &array_path)?;
    if values.is_empty() {
        return Err(vec![invalid(
            format!("{key} must contain at least one identifier"),
            array_path,
        )]);
    }
    let mut seen = HashSet::new();
    let mut identifiers = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let item_path = child(&array_path, &index.to_string());
        let identifier = string(value, &item_path)?;
        if !seen.insert(identifier.to_owned()) {
            return Err(vec![invalid(
                format!("identifier {identifier:?} is repeated in {key}"),
                item_path,
            )]);
        }
        identifiers.push(identifier.to_owned());
    }
    Ok(identifiers)
}

fn parse_unique_string_array(
    value: &Value,
    path: &str,
) -> Result<Vec<String>, Vec<SearchDiagnostic>> {
    let values = array(value, path)?;
    if values.is_empty() {
        return Err(vec![invalid_search_space(
            "domain array must not be empty",
            path,
        )]);
    }
    let mut seen = HashSet::new();
    let mut names = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let item_path = child(path, &index.to_string());
        let name = string(value, &item_path)?;
        if !seen.insert(name.to_owned()) {
            return Err(vec![invalid_search_space(
                format!("value {name:?} is duplicated in this domain"),
                path,
            )]);
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn parse_unique_symbol_array(
    value: &Value,
    path: &str,
    alphabet: &Alphabet,
) -> Result<Vec<char>, Vec<SearchDiagnostic>> {
    let values = array(value, path)?;
    if values.is_empty() {
        return Err(vec![invalid_search_space(
            "domain array must not be empty",
            path,
        )]);
    }
    let mut seen = HashSet::new();
    let mut symbols = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let symbol_path = child(path, &index.to_string());
        let symbol = scalar(value, &symbol_path)?;
        if alphabet.index_of(symbol).is_none() {
            return Err(vec![SearchDiagnostic::new(
                "invalid_symbol",
                format!("symbol {symbol:?} is not in the machine alphabet"),
                symbol_path,
            )]);
        }
        if !seen.insert(symbol) {
            return Err(vec![invalid_search_space(
                format!("symbol {symbol:?} is duplicated in this domain"),
                path,
            )]);
        }
        symbols.push(symbol);
    }
    Ok(symbols)
}

fn parse_pair_array(
    pairs: &[Value],
    path: &str,
) -> Result<Vec<(char, char)>, Vec<SearchDiagnostic>> {
    let mut result = Vec::with_capacity(pairs.len());
    for (index, pair) in pairs.iter().enumerate() {
        let pair_path = child(path, &index.to_string());
        let pair = array(pair, &pair_path)?;
        if pair.len() != 2 {
            return Err(vec![SearchDiagnostic::new(
                "invalid_plugboard",
                format!(
                    "plugboard entry must contain exactly two symbols; got {}",
                    pair.len()
                ),
                pair_path,
            )]);
        }
        result.push((
            scalar(&pair[0], &child(&pair_path, "0"))?,
            scalar(&pair[1], &child(&pair_path, "1"))?,
        ));
    }
    Ok(result)
}

/// Validates pair disjointness, alphabet membership, and self-pairs, mirroring the
/// transform resolver's rule order so diagnostics stay consistent across job kinds.
fn validate_disjoint_pairs(
    pairs: &[(char, char)],
    path: &str,
    alphabet: &Alphabet,
) -> Result<(), Vec<SearchDiagnostic>> {
    let mut mapping: Vec<usize> = (0..alphabet.len()).collect();
    for (index, &(left, right)) in pairs.iter().enumerate() {
        let pair_path = child(path, &index.to_string());
        let (Some(left_index), Some(right_index)) =
            (alphabet.index_of(left), alphabet.index_of(right))
        else {
            let symbol = if alphabet.index_of(left).is_none() {
                left
            } else {
                right
            };
            return Err(vec![SearchDiagnostic::new(
                "invalid_symbol",
                format!("plugboard symbol {symbol:?} is not in the machine alphabet"),
                pair_path,
            )]);
        };
        if left_index == right_index {
            return Err(vec![SearchDiagnostic::new(
                "invalid_plugboard",
                format!("plugboard pair {left:?}{right:?} pairs a symbol with itself"),
                pair_path,
            )]);
        }
        if mapping[left_index] != left_index {
            return Err(vec![SearchDiagnostic::new(
                "invalid_plugboard",
                format!("plugboard symbol {left:?} occurs in more than one pair"),
                pair_path,
            )]);
        }
        if mapping[right_index] != right_index {
            return Err(vec![SearchDiagnostic::new(
                "invalid_plugboard",
                format!("plugboard symbol {right:?} occurs in more than one pair"),
                pair_path,
            )]);
        }
        mapping[left_index] = right_index;
        mapping[right_index] = left_index;
    }
    Ok(())
}

fn optional_symbol(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
    alphabet: &Alphabet,
) -> Result<Option<char>, Vec<SearchDiagnostic>> {
    match object.get(key) {
        Some(value) => {
            let symbol = scalar(value, &child(path, key))?;
            if alphabet.index_of(symbol).is_none() {
                return Err(vec![SearchDiagnostic::new(
                    "invalid_symbol",
                    format!("{key} symbol {symbol:?} is not in the machine alphabet"),
                    child(path, key),
                )]);
            }
            Ok(Some(symbol))
        }
        None => Ok(None),
    }
}

fn object<'a>(
    value: &'a Value,
    path: &str,
) -> Result<&'a Map<String, Value>, Vec<SearchDiagnostic>> {
    value
        .as_object()
        .ok_or_else(|| vec![invalid("expected a JSON object", path)])
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], Vec<SearchDiagnostic>> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| vec![invalid("expected a JSON array", path)])
}

fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, Vec<SearchDiagnostic>> {
    object.get(key).ok_or_else(|| {
        vec![invalid(
            format!("required field {key:?} is missing"),
            child(path, key),
        )]
    })
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a str, Vec<SearchDiagnostic>> {
    string(required(object, key, path)?, &child(path, key))
}

fn string<'a>(value: &'a Value, path: &str) -> Result<&'a str, Vec<SearchDiagnostic>> {
    value
        .as_str()
        .ok_or_else(|| vec![invalid("expected a string", path)])
}

fn scalar(value: &Value, path: &str) -> Result<char, Vec<SearchDiagnostic>> {
    let text = string(value, path)?;
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(symbol), None) => Ok(symbol),
        _ => Err(vec![invalid(
            "expected exactly one Unicode scalar value",
            path,
        )]),
    }
}

fn exact_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), Vec<SearchDiagnostic>> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(vec![unknown_field(path, key)]);
    }
    if let Some(key) = allowed.iter().find(|key| !object.contains_key(**key)) {
        return Err(vec![invalid(
            format!("required field {key:?} is missing"),
            child(path, key),
        )]);
    }
    Ok(())
}

fn exact_keys_with_optional(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    path: &str,
) -> Result<(), Vec<SearchDiagnostic>> {
    if let Some(key) = object
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(vec![unknown_field(path, key)]);
    }
    if let Some(key) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(vec![invalid(
            format!("required field {key:?} is missing"),
            child(path, key),
        )]);
    }
    Ok(())
}

fn allow_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), Vec<SearchDiagnostic>> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(vec![unknown_field(path, key)]);
    }
    Ok(())
}

fn unknown_field(path: &str, key: &str) -> SearchDiagnostic {
    SearchDiagnostic::new(
        "unknown_field",
        format!("field {key:?} is not allowed here"),
        child(path, key),
    )
}

fn invalid(message: impl Into<String>, path: impl Into<String>) -> SearchDiagnostic {
    SearchDiagnostic::new("invalid_request", message, path)
}

fn invalid_search_space(message: impl Into<String>, path: impl Into<String>) -> SearchDiagnostic {
    SearchDiagnostic::new("invalid_search_space", message, path)
}

fn child(path: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{path}/{escaped}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::RequestDiagnostic;
    use serde_json::{json, Value};

    #[test]
    fn attack_value_preserves_ordered_alphabet_and_fixed_facts() {
        let alphabet = Alphabet::new(vec!['B', 'A', 'é', '🦀', 'D', 'C']).unwrap();
        let fixed = [('B', 'A'), ('D', 'C')];
        let value = json!({"kind":"attack", "symbols":["🦀","é"], "max_pairs":3});
        let domain = AttackPlugboardDomain::parse_value(&alphabet, &fixed, &value).unwrap();
        assert!(domain.matches_alphabet(&alphabet));
        assert!(
            !domain.matches_alphabet(&Alphabet::new(vec!['A', 'B', 'é', '🦀', 'D', 'C']).unwrap())
        );
        assert_eq!(domain.fixed_pairs(), &fixed);
        assert_eq!(domain.symbols(), &['🦀', 'é']);
        assert_eq!(domain.max_pairs(), 3);
    }

    #[test]
    fn attack_value_rejects_fixed_endpoint_overlap() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let value = json!({"kind":"attack", "symbols":["C","B"], "max_pairs":2});
        let errors =
            AttackPlugboardDomain::parse_value(&alphabet, &[('A', 'B')], &value).unwrap_err();
        assert_eq!(errors[0].code(), "invalid_search_space");
        assert_eq!(errors[0].location(), "/job/space/plugboard/symbols/1");
        assert_eq!(
            errors[0].message(),
            "mutable symbol is an endpoint of a known fixed pair"
        );
    }

    #[test]
    fn attack_value_accepts_zero_mutable_capacity() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        for fixed in [vec![], vec![('B', 'A')]] {
            let value = json!({"kind":"attack", "symbols":["C"], "max_pairs":fixed.len()});
            let domain = AttackPlugboardDomain::parse_value(&alphabet, &fixed, &value).unwrap();
            assert_eq!(domain.fixed_pairs(), fixed);
            assert_eq!(domain.symbols(), &['C']);
            assert_eq!(domain.max_pairs(), fixed.len());
        }
    }

    #[test]
    fn attack_value_preserves_escaped_and_indexed_diagnostics() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'é', '🦀']).unwrap();
        for (value, code, suffix) in [
            (
                json!({"kind":"attack", "symbols":["é","🦀"], "max_pairs":1, "a~/b":0}),
                "unknown_field",
                "/a~0~1b",
            ),
            (
                json!({"kind":"attack", "symbols":["é","Z"], "max_pairs":1}),
                "invalid_search_space",
                "/symbols/1",
            ),
        ] {
            let errors = AttackPlugboardDomain::parse_value(&alphabet, &[], &value).unwrap_err();
            assert_eq!(errors[0].code(), code);
            assert_eq!(
                errors[0].location(),
                format!("/job/space/plugboard{suffix}")
            );
            assert_eq!(
                errors,
                AttackPlugboardDomain::parse_json(&alphabet, &[], &value.to_string()).unwrap_err()
            );
        }
    }

    fn settings_fixture() -> (Alphabet, AttackPlugboardDomain, Value) {
        let alphabet = Alphabet::new(vec!['A', 'B', 'é', '🦀', 'C', 'D']).unwrap();
        let domain = AttackPlugboardDomain::parse_json(
            &alphabet,
            &[('B', 'A')],
            r#"{"kind":"attack","symbols":["🦀","é","D","C"],"max_pairs":2}"#,
        )
        .unwrap();
        let value = json!({"kind":"hill_climb", "initial_measure":"ic",
            "final_measure":"entropy", "switch_pairs":3, "backtrack_pairs":0,
            "start":[["🦀","é"]]});
        (alphabet, domain, value)
    }

    #[test]
    fn hold_capacity_defaults_bounds_and_equality() {
        for (alphabet, domain, mut value) in [settings_fixture(), seed_fixture()] {
            let passes = [value["kind"].as_str().unwrap().to_owned()];
            let parse = |value: &Value| {
                AttackSettings::parse_json(
                    &alphabet,
                    &domain,
                    &passes,
                    &[MeasureId::Ic, MeasureId::Entropy],
                    &value.to_string(),
                )
                .unwrap()
            };
            let default = parse(&value);
            assert_eq!(default.hold_capacity(), 100);
            value["hold"] = json!(100);
            assert_eq!(default, parse(&value));
            for capacity in [1, 1000] {
                value["hold"] = json!(capacity);
                let settings = parse(&value);
                assert_eq!(settings.hold_capacity(), capacity);
                assert_ne!(default, settings);
            }
        }
    }

    #[test]
    fn hold_capacity_invalid_integer_lexemes() {
        for (alphabet, domain, mut value) in [settings_fixture(), seed_fixture()] {
            let passes = [value["kind"].as_str().unwrap().to_owned()];
            value["hold"] = json!("REPLACE");
            for literal in [
                "0",
                "1001",
                "-1",
                "-0",
                "null",
                "\"1\"",
                "true",
                "false",
                "1.5",
                "1.0",
                "1e0",
                "18446744073709551616",
                "[]",
                "{}",
            ] {
                let raw = value.to_string().replace("\"REPLACE\"", literal);
                let errors = AttackSettings::parse_json(
                    &alphabet,
                    &domain,
                    &passes,
                    &[MeasureId::Ic, MeasureId::Entropy],
                    &raw,
                )
                .unwrap_err();
                assert_eq!(
                    (errors[0].code(), errors[0].location()),
                    ("invalid_request", "/job/attack/hold"),
                    "{raw}"
                );
            }
        }
    }

    #[test]
    fn hold_capacity_raw_alphabet_and_unknown_precedence() {
        let (alphabet, domain, mut value) = settings_fixture();
        value["hold"] = json!(0);
        value["a~/b"] = json!(null);
        settings_error(&value, "unknown_field", "/a~0~1b");
        let other = Alphabet::new(vec!['B', 'A', 'é', '🦀', 'C', 'D']).unwrap();
        let raw = value.to_string();
        let errors = AttackSettings::parse_json(&other, &domain, &[], &[], &raw).unwrap_err();
        assert_eq!(errors[0].location(), "/job/attack");
        assert!(errors[0].message().contains("different ordered alphabet"));
        let duplicate = raw.replace("\"hold\":0", "\"hold\":0,\"hold\":0");
        let errors = AttackSettings::parse_json(&other, &domain, &[], &[], &duplicate).unwrap_err();
        assert!(errors[0].message().contains("invalid JSON"));
        assert_eq!(errors[0].code(), "invalid_request");
        assert_eq!(alphabet.len(), other.len());
    }

    #[test]
    fn settings_value_entry_valid_initializations() {
        let (alphabet, domain, value) = settings_fixture();
        let settings = AttackSettings::parse_value(
            &alphabet,
            &domain,
            &["hill_climb".to_owned()],
            &[MeasureId::Ic, MeasureId::Entropy],
            &value,
        )
        .unwrap();
        assert_eq!(settings.kind(), AttackKind::HillClimb);
        assert_eq!(settings.start(), Some(&[('🦀', 'é')][..]));
        assert_eq!(settings.seed_policy(), None);
        assert_eq!(settings.initial_measure(), MeasureId::Ic);
        assert_eq!(settings.final_measure(), MeasureId::Entropy);
        assert_eq!(settings.switch_pairs(), 3);
        assert_eq!(settings.backtrack_pairs(), 0);

        let (alphabet, domain, mut value) = seed_fixture();
        for (policy, expected) in [
            (
                json!({"kind":"empty_single","selection":"all"}),
                AttackSeedPolicy::All,
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":["🦀","é"]}),
                AttackSeedPolicy::Touching(vec!['🦀', 'é']),
            ),
        ] {
            value["seeds"] = policy;
            let settings = AttackSettings::parse_value(
                &alphabet,
                &domain,
                &["partial_exhaustion".to_owned()],
                &[MeasureId::Ic, MeasureId::Entropy],
                &value,
            )
            .unwrap();
            assert_eq!(settings.kind(), AttackKind::PartialExhaustion);
            assert_eq!(settings.start(), None);
            assert_eq!(settings.seed_policy(), Some(&expected));
        }
    }

    #[test]
    fn settings_value_diagnostics_match_fragment() {
        let (alphabet, domain, hill) = settings_fixture();
        let (_, _, seed) = seed_fixture();
        let mut cases = Vec::new();
        for (base, key, replacement, code, suffix) in [
            (&hill, "seeds", json!({}), "invalid_request", "/seeds"),
            (&seed, "start", json!([]), "invalid_request", "/start"),
            (
                &hill,
                "initial_measure",
                json!("trie"),
                "invalid_request",
                "/initial_measure",
            ),
            (
                &seed,
                "final_measure",
                json!("trie"),
                "invalid_request",
                "/final_measure",
            ),
            (&hill, "a~/b", json!(0), "unknown_field", "/a~0~1b"),
            (
                &hill,
                "start",
                json!([["🦀", "Z"]]),
                "invalid_search_space",
                "/start/0",
            ),
            (
                &seed,
                "seeds",
                json!({"kind":"empty_single","selection":"touching","symbols":["🦀","Z"]}),
                "invalid_search_space",
                "/seeds/symbols/1",
            ),
        ] {
            let mut value = base.clone();
            value[key] = replacement;
            let pass = base["kind"].as_str().unwrap().to_owned();
            cases.push((value, pass, code, suffix));
        }
        cases.push((
            hill.clone(),
            "partial_exhaustion".to_owned(),
            "invalid_request",
            "/kind",
        ));
        cases.push((seed, "hill_climb".to_owned(), "invalid_request", "/kind"));
        for (value, pass, code, suffix) in cases {
            let passes = [pass];
            let measures = [MeasureId::Ic, MeasureId::Entropy];
            let errors =
                AttackSettings::parse_value(&alphabet, &domain, &passes, &measures, &value)
                    .unwrap_err();
            assert_eq!(errors[0].code(), code, "{value}");
            assert_eq!(
                errors[0].location(),
                format!("/job/attack{suffix}"),
                "{value}"
            );
            assert_eq!(
                errors,
                AttackSettings::parse_json(
                    &alphabet,
                    &domain,
                    &passes,
                    &measures,
                    &value.to_string(),
                )
                .unwrap_err(),
                "{value}"
            );
        }
        // Ordered-alphabet identity precedes even settings object validation.
        let other = Alphabet::new(vec!['B', 'A', 'é', '🦀', 'C', 'D']).unwrap();
        let errors =
            AttackSettings::parse_value(&other, &domain, &[], &[], &Value::Null).unwrap_err();
        assert_eq!(errors[0].code(), "invalid_request");
        assert_eq!(errors[0].location(), "/job/attack");
        assert_eq!(
            errors,
            AttackSettings::parse_json(&other, &domain, &[], &[], "null").unwrap_err()
        );
    }

    fn settings_error(value: &Value, code: &str, suffix: &str) {
        let (alphabet, domain, _) = settings_fixture();
        let errors = AttackSettings::parse_json(
            &alphabet,
            &domain,
            &["hill_climb".to_owned()],
            &[MeasureId::Ic, MeasureId::Entropy, MeasureId::Trie],
            &value.to_string(),
        )
        .unwrap_err();
        assert_eq!(errors[0].code(), code, "{value}");
        assert_eq!(
            errors[0].location(),
            format!("/job/attack{suffix}"),
            "{value}"
        );
    }

    // §9.1: a well-shaped passes list reaches the kind check; any other is unsupported.
    fn passes_outcome(shaped: bool) -> (&'static str, &'static str) {
        if shaped {
            ("invalid_request", "/job/attack/kind")
        } else {
            ("unsupported_pass", "/job/passes")
        }
    }

    // Parses `hill_climb` followed by the space-separated stages, plus extra members.
    fn staged(
        stages: &str,
        all: bool,
        members: &Value,
    ) -> Result<Vec<AttackStage>, (String, String)> {
        let (alphabet, domain, mut value) = settings_fixture();
        value
            .as_object_mut()
            .unwrap()
            .extend(members.as_object().unwrap().clone());
        let passes: Vec<String> = ["hill_climb"]
            .into_iter()
            .chain(stages.split_whitespace())
            .map(str::to_owned)
            .collect();
        let mut measures = vec![MeasureId::Ic, MeasureId::Entropy];
        if all {
            measures.extend([
                MeasureId::Trie,
                MeasureId::SinkovBigram,
                MeasureId::SinkovTrigram,
            ]);
        }
        AttackSettings::parse_json(&alphabet, &domain, &passes, &measures, &value.to_string())
            .map(|settings| settings.stages().to_vec())
            .map_err(|errors| (errors[0].code().to_owned(), errors[0].location().to_owned()))
    }

    #[test]
    fn settings_chained_stages_keep_order_and_resolve_defaults() {
        let project = |stages: Vec<AttackStage>| -> Vec<(&str, Option<&str>)> {
            stages
                .into_iter()
                .map(|stage| match stage {
                    AttackStage::Reswapping { measure } => ("reswapping", Some(measure.id())),
                    AttackStage::Trie { base_measure } => ("trie", base_measure.map(MeasureId::id)),
                    AttackStage::Measure { measure } => ("measure", Some(measure.id())),
                })
                .collect()
        };
        for (stages, members, expected) in [
            ("", json!({}), vec![]),
            (
                "reswapping",
                json!({}),
                vec![("reswapping", Some("sinkov_trigram"))],
            ),
            ("trie", json!({}), vec![("trie", None)]),
            (
                "measure",
                json!({"measure":{}}),
                vec![("measure", Some("ic"))],
            ),
            (
                "measure trie reswapping",
                json!({"reswapping":{"measure":"sinkov_bigram"},"trie":{"base_measure":"trie"},
                    "measure":{"measure":"entropy"}}),
                vec![
                    ("measure", Some("entropy")),
                    ("trie", Some("trie")),
                    ("reswapping", Some("sinkov_bigram")),
                ],
            ),
            (
                "trie reswapping measure",
                json!({"trie":{"base_measure":"ic"}}),
                vec![
                    ("trie", Some("ic")),
                    ("reswapping", Some("sinkov_trigram")),
                    ("measure", Some("ic")),
                ],
            ),
        ] {
            assert_eq!(
                project(staged(stages, true, &members).unwrap()),
                expected,
                "{stages}"
            );
        }
    }

    #[test]
    fn settings_chained_stage_member_errors() {
        // Empty members on objective-only declarations exercise undeclared defaults.
        for (stages, members, path) in [
            ("", json!({"trie":{}}), "attack/trie"),
            ("trie", json!({"measure":{}}), "attack/measure"),
            ("trie", json!({"trie":[]}), "attack/trie"),
            ("trie", json!({"trie":null}), "attack/trie"),
            (
                "trie",
                json!({"trie":{"measure":"ic"}}),
                "attack/trie/measure",
            ),
            (
                "reswapping",
                json!({"reswapping":{"measure":null}}),
                "attack/reswapping/measure",
            ),
            (
                "measure",
                json!({"measure":{"measure":1}}),
                "attack/measure/measure",
            ),
            (
                "measure",
                json!({"measure":{"measure":"sinkov_quadgram"}}),
                "attack/measure/measure",
            ),
            (
                "trie",
                json!({"trie":{"base_measure":"IC"}}),
                "attack/trie/base_measure",
            ),
            ("measure reswapping", json!({}), "passes/2"),
            ("trie", json!({}), "passes/1"),
        ] {
            let all = members != json!({});
            let code = if path.ends_with("trie/measure") {
                "unknown_field"
            } else {
                "invalid_request"
            };
            let expected = (code.to_owned(), format!("/job/{path}"));
            assert_eq!(
                staged(stages, all, &members).unwrap_err(),
                expected,
                "{members}"
            );
        }
        // Default `ic` for the measure stage must itself be declared.
        let (alphabet, domain, mut value) = settings_fixture();
        value["initial_measure"] = json!("entropy");
        let passes = ["hill_climb".to_owned(), "measure".to_owned()];
        let errors =
            AttackSettings::parse_value(&alphabet, &domain, &passes, &[MeasureId::Entropy], &value)
                .unwrap_err();
        assert_eq!(
            (errors[0].code(), errors[0].location()),
            ("invalid_request", "/job/passes/1")
        );
    }

    #[test]
    fn settings_valid_objectives_thresholds_and_order() {
        let (alphabet, domain, mut value) = settings_fixture();
        for final_measure in ["ic", "entropy"] {
            value["final_measure"] = json!(final_measure);
            let settings = AttackSettings::parse_json(
                &alphabet,
                &domain,
                &["hill_climb".to_owned()],
                &[MeasureId::Ic, MeasureId::Entropy, MeasureId::Trie],
                &value.to_string(),
            )
            .unwrap();
            assert_eq!(settings.kind(), AttackKind::HillClimb);
            assert_eq!(settings.initial_measure(), MeasureId::Ic);
            assert_eq!(settings.final_measure().id(), final_measure);
            assert_eq!(settings.switch_pairs(), 3);
            assert_eq!(settings.backtrack_pairs(), 0);
            assert_eq!(settings.start(), Some(&[('🦀', 'é')][..]));
            assert_eq!(settings.seed_policy(), None);
        }
        value["start"] = json!([]);
        value["switch_pairs"] = json!(0);
        value["backtrack_pairs"] = json!(3);
        assert!(AttackSettings::parse_json(
            &alphabet,
            &domain,
            &["hill_climb".to_owned()],
            &[MeasureId::Ic, MeasureId::Entropy],
            &value.to_string()
        )
        .is_ok());
    }

    #[test]
    fn settings_required_unknown_and_objective_fields() {
        let (_, _, base) = settings_fixture();
        for key in [
            "kind",
            "initial_measure",
            "final_measure",
            "switch_pairs",
            "backtrack_pairs",
            "start",
        ] {
            let mut value = base.clone();
            value.as_object_mut().unwrap().remove(key);
            settings_error(&value, "invalid_request", &format!("/{key}"));
        }
        let mut value = base.clone();
        value["a~/b"] = json!([]);
        settings_error(&value, "unknown_field", "/a~0~1b");
        let mut value = base.clone();
        value["seeds"] = json!([]);
        settings_error(&value, "invalid_request", "/seeds");
        for key in ["initial_measure", "final_measure"] {
            for bad in [json!("IC"), json!("sinkov_bigram"), json!(null), json!(1)] {
                let mut value = base.clone();
                value[key] = bad;
                settings_error(&value, "invalid_request", &format!("/{key}"));
            }
        }
        for bad in [json!(null), json!(false), json!("unknown")] {
            let mut value = base.clone();
            value["kind"] = bad;
            settings_error(&value, "invalid_request", "/kind");
        }
    }

    #[test]
    fn settings_integer_lexemes_and_start_conflicts() {
        let (alphabet, domain, base) = settings_fixture();
        for key in ["switch_pairs", "backtrack_pairs"] {
            let bad = ["4", "-1", "-0", "1.0", "1e0", "false", "\"1\""];
            for literal in bad {
                let mut value = base.clone();
                value[key] = json!("REPLACE");
                let raw = value.to_string().replace("\"REPLACE\"", literal);
                let errors = AttackSettings::parse_json(
                    &alphabet,
                    &domain,
                    &["hill_climb".to_owned()],
                    &[MeasureId::Ic, MeasureId::Entropy],
                    &raw,
                )
                .unwrap_err();
                assert_eq!(errors[0].code(), "invalid_search_space", "{raw}");
                assert_eq!(errors[0].location(), format!("/job/attack/{key}"));
            }
        }
        for (start, suffix) in [
            (json!(null), "/start"),
            (json!([["A", "B"]]), "/start/0"),
            (json!([["é", "A"]]), "/start/0"),
            (json!([["é", "Z"]]), "/start/0"),
            (json!([["é", "é"]]), "/start/0"),
            (json!([["é"]]), "/start/0"),
            (json!([["é", "🦀"], ["é", "C"]]), "/start/1"),
            (json!([["é", "🦀"], ["C", "D"]]), "/start"),
            (json!([["é", "🦀"]]), "/start/0/0"),
        ] {
            let mut value = base.clone();
            value["start"] = start;
            settings_error(&value, "invalid_search_space", suffix);
        }
        let restricted = AttackPlugboardDomain::parse_json(
            &alphabet,
            &[('A', 'B')],
            r#"{"kind":"attack","symbols":["é","🦀"],"max_pairs":2}"#,
        )
        .unwrap();
        let mut value = base.clone();
        value["start"] = json!([["C", "D"]]);
        let errors = AttackSettings::parse_json(
            &alphabet,
            &restricted,
            &["hill_climb".to_owned()],
            &[MeasureId::Ic, MeasureId::Entropy],
            &value.to_string(),
        )
        .unwrap_err();
        assert_eq!(errors[0].code(), "invalid_search_space");
        assert_eq!(errors[0].location(), "/job/attack/start/0");
    }

    #[test]
    fn settings_pass_membership_and_ordered_alphabet_identity() {
        let (alphabet, domain, value) = settings_fixture();
        for passes in [
            vec![],
            vec!["partial_exhaustion"],
            vec!["partial_exhaustion", "measure"],
            vec!["reswapping"],
            vec!["measure", "hill_climb"],
            vec!["hill_climb", "partial_exhaustion"],
            vec!["hill_climb", "hill_climb"],
            vec!["hill_climb", "trie", "trie"],
            vec!["hill_climb", "unknown"],
        ] {
            let shaped = passes.first() == Some(&"partial_exhaustion");
            let passes: Vec<String> = passes.into_iter().map(str::to_owned).collect();
            let errors = AttackSettings::parse_json(
                &alphabet,
                &domain,
                &passes,
                &[MeasureId::Ic, MeasureId::Entropy, MeasureId::Trie],
                &value.to_string(),
            )
            .unwrap_err();
            // Kind `hill_climb` mismatches only well-shaped partial-exhaustion lists.
            assert_eq!(
                (errors[0].code(), errors[0].location()),
                passes_outcome(shaped)
            );
        }
        let mut deferred = value.clone();
        deferred["kind"] = json!("partial_exhaustion");
        let errors = AttackSettings::parse_json(
            &alphabet,
            &domain,
            &["partial_exhaustion".to_owned()],
            &[],
            &deferred.to_string(),
        )
        .unwrap_err();
        assert_eq!(errors[0].code(), "invalid_request");
        assert_eq!(errors[0].location(), "/job/attack/start");
        let reordered = Alphabet::new(vec!['B', 'A', 'é', '🦀', 'C', 'D']).unwrap();
        let errors = AttackSettings::parse_json(
            &reordered,
            &domain,
            &["hill_climb".to_owned()],
            &[],
            &value.to_string(),
        )
        .unwrap_err();
        assert_eq!(errors[0].code(), "invalid_request");
        assert_eq!(errors[0].location(), "/job/attack");
    }

    #[test]
    fn settings_strict_raw_json_and_exact_byte_ceiling() {
        let (alphabet, domain, value) = settings_fixture();
        let parse = |raw: &str| {
            AttackSettings::parse_json(
                &alphabet,
                &domain,
                &["hill_climb".to_owned()],
                &[MeasureId::Ic, MeasureId::Entropy],
                raw,
            )
        };
        for raw in [
            "{",
            "[]",
            "null",
            "{} {}",
            r#"{"nested":{"x":1,"x":2}}"#,
            r#"{"kind":"hill_climb","kind":"hill_climb"}"#,
        ] {
            let errors = parse(raw).unwrap_err();
            assert_eq!(errors[0].code(), "invalid_request", "{raw}");
            assert_eq!(errors[0].location(), "/job/attack", "{raw}");
        }
        let mut padded = value.to_string();
        padded.push_str(&" ".repeat(crate::MAX_REQUEST_BYTES - padded.len()));
        assert_eq!(padded.len(), crate::MAX_REQUEST_BYTES);
        assert!(parse(&padded).is_ok());
        padded.push(' ');
        let errors = parse(&padded).unwrap_err();
        assert_eq!(errors[0].code(), "invalid_request");
        assert_eq!(errors[0].location(), "/job/attack");
    }

    fn seed_fixture() -> (Alphabet, AttackPlugboardDomain, Value) {
        let (alphabet, domain, mut value) = settings_fixture();
        value.as_object_mut().unwrap().remove("start");
        value["kind"] = json!("partial_exhaustion");
        value["seeds"] = json!({"kind":"empty_single", "selection":"all"});
        (alphabet, domain, value)
    }

    fn parse_seed_settings(
        alphabet: &Alphabet,
        domain: &AttackPlugboardDomain,
        value: &Value,
    ) -> Result<AttackSettings, Vec<SearchDiagnostic>> {
        AttackSettings::parse_json(
            alphabet,
            domain,
            &["partial_exhaustion".to_owned()],
            &[MeasureId::Ic, MeasureId::Entropy, MeasureId::Trie],
            &value.to_string(),
        )
    }

    #[test]
    fn seed_policy_typed_order_and_syntax_not_feasibility() {
        let (alphabet, domain, mut value) = seed_fixture();
        for (policy, expected) in [
            (
                json!({"kind":"empty_single","selection":"all"}),
                AttackSeedPolicy::All,
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":["🦀","é"]}),
                AttackSeedPolicy::Touching(vec!['🦀', 'é']),
            ),
        ] {
            value["seeds"] = policy;
            value["final_measure"] = json!("ic");
            let settings = parse_seed_settings(&alphabet, &domain, &value).unwrap();
            assert_eq!(settings.kind(), AttackKind::PartialExhaustion);
            assert_eq!(settings.start(), None);
            assert_eq!(settings.seed_policy(), Some(&expected));
            assert_eq!(settings.final_measure(), MeasureId::Ic);
        }
        let domain = AttackPlugboardDomain::parse_json(
            &alphabet,
            &[],
            r#"{"kind":"attack","symbols":["é"],"max_pairs":0}"#,
        )
        .unwrap();
        value["seeds"] = json!({"kind":"empty_single","selection":"all"});
        assert!(parse_seed_settings(&alphabet, &domain, &value).is_ok());
        value["seeds"] = json!({"kind":"empty_single","selection":"touching","symbols":["é"]});
        assert!(parse_seed_settings(&alphabet, &domain, &value).is_ok());
        let errors = AttackPlugboardDomain::parse_json(
            &alphabet,
            &[],
            r#"{"kind":"attack","symbols":[],"max_pairs":0}"#,
        )
        .unwrap_err();
        assert_eq!(errors[0].code(), "invalid_search_space");
        assert_eq!(errors[0].location(), "/job/space/plugboard/symbols");
    }

    #[test]
    fn seed_policy_diagnostics_and_conditional_members() {
        let (alphabet, domain, base) = seed_fixture();
        for (policy, code, suffix) in [
            (json!(null), "invalid_request", ""),
            (json!([]), "invalid_request", ""),
            (json!({}), "invalid_request", "/kind"),
            (
                json!({"kind":"other","selection":"all"}),
                "invalid_request",
                "/kind",
            ),
            (
                json!({"kind":1,"selection":"all"}),
                "invalid_request",
                "/kind",
            ),
            (
                json!({"kind":"empty_single"}),
                "invalid_request",
                "/selection",
            ),
            (
                json!({"kind":"empty_single","selection":false}),
                "invalid_request",
                "/selection",
            ),
            (
                json!({"kind":"empty_single","selection":"other"}),
                "invalid_request",
                "/selection",
            ),
            (
                json!({"kind":"empty_single","selection":"all","symbols":[]}),
                "invalid_request",
                "/symbols",
            ),
            (
                json!({"kind":"empty_single","selection":"all","symbols":["é"]}),
                "invalid_request",
                "/symbols",
            ),
            (
                json!({"kind":"empty_single","selection":"touching"}),
                "invalid_request",
                "/symbols",
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":[]}),
                "invalid_search_space",
                "/symbols",
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":null}),
                "invalid_search_space",
                "/symbols",
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":["é","é"]}),
                "invalid_search_space",
                "/symbols/1",
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":["é"]}),
                "invalid_search_space",
                "/symbols/0",
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":[1]}),
                "invalid_search_space",
                "/symbols/0",
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":["Z"]}),
                "invalid_search_space",
                "/symbols/0",
            ),
            (
                json!({"kind":"empty_single","selection":"touching","symbols":["A"]}),
                "invalid_search_space",
                "/symbols/0",
            ),
            (json!({"a~/b":0}), "unknown_field", "/a~0~1b"),
        ] {
            let mut value = base.clone();
            value["seeds"] = policy;
            let errors = parse_seed_settings(&alphabet, &domain, &value).unwrap_err();
            assert_eq!(errors[0].code(), code, "{value}");
            assert_eq!(
                errors[0].location(),
                format!("/job/attack/seeds{suffix}"),
                "{value}"
            );
        }
        for mask in [json!(["é", "🦀", "é"]), json!(["🦀", "é", "é"])] {
            let mut value = base.clone();
            value["seeds"] = json!({"kind":"empty_single","selection":"touching","symbols":mask});
            let errors = parse_seed_settings(&alphabet, &domain, &value).unwrap_err();
            assert_eq!(errors[0].code(), "invalid_search_space");
            assert_eq!(errors[0].location(), "/job/attack/seeds/symbols/2");
        }
        let restricted = AttackPlugboardDomain::parse_json(
            &alphabet,
            &[],
            r#"{"kind":"attack","symbols":["é"],"max_pairs":0}"#,
        )
        .unwrap();
        let mut value = base.clone();
        value["seeds"] = json!({"kind":"empty_single","selection":"touching","symbols":["C"]});
        let errors = parse_seed_settings(&alphabet, &restricted, &value).unwrap_err();
        assert_eq!(errors[0].code(), "invalid_search_space");
        assert_eq!(errors[0].location(), "/job/attack/seeds/symbols/0");
        for start in [json!([]), json!([["é", "🦀"]])] {
            let mut value = base.clone();
            value["start"] = start;
            let errors = parse_seed_settings(&alphabet, &domain, &value).unwrap_err();
            assert_eq!(errors[0].code(), "invalid_request");
            assert_eq!(errors[0].location(), "/job/attack/start");
        }
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove("seeds");
        let errors = parse_seed_settings(&alphabet, &domain, &value).unwrap_err();
        assert_eq!(errors[0].location(), "/job/attack/seeds");
        value["kind"] = json!("unknown");
        value["a~/b"] = json!(0);
        let errors = parse_seed_settings(&alphabet, &domain, &value).unwrap_err();
        assert_eq!(errors[0].code(), "unknown_field");
        assert_eq!(errors[0].location(), "/job/attack/a~0~1b");
    }

    #[test]
    fn seed_settings_raw_boundaries_passes_and_alphabet() {
        let (alphabet, domain, value) = seed_fixture();
        let parse = |alphabet: &Alphabet, passes: &[String], raw: &str| {
            AttackSettings::parse_json(
                alphabet,
                &domain,
                passes,
                &[MeasureId::Ic, MeasureId::Entropy],
                raw,
            )
        };
        let passes = ["partial_exhaustion".to_owned()];
        let reordered = Alphabet::new(vec!['B', 'A', 'é', '🦀', 'C', 'D']).unwrap();
        for raw in [
            r#"{"seeds":{"kind":"empty_single","kind":"empty_single"}}"#,
            &format!("{} trailing", value),
        ] {
            let errors = parse(&reordered, &passes, raw).unwrap_err();
            assert_eq!(errors[0].code(), "invalid_request");
            assert_eq!(errors[0].location(), "/job/attack");
        }
        assert_eq!(
            parse(&reordered, &passes, &value.to_string()).unwrap_err()[0].location(),
            "/job/attack"
        );
        for passes in [
            vec![],
            vec!["hill_climb".to_owned()],
            vec!["partial_exhaustion".to_owned(); 2],
            vec!["partial_exhaustion".to_owned(), "hill_climb".to_owned()],
        ] {
            let errors = parse(&alphabet, &passes, &value.to_string()).unwrap_err();
            assert_eq!(
                (errors[0].code(), errors[0].location()),
                passes_outcome(passes.len() == 1)
            );
        }
        let mut raw = value.to_string();
        raw.push_str(&" ".repeat(crate::MAX_REQUEST_BYTES - raw.len()));
        assert!(parse(&alphabet, &passes, &raw).is_ok());
        raw.push(' ');
        assert_eq!(
            parse(&alphabet, &passes, &raw).unwrap_err()[0].location(),
            "/job/attack"
        );
    }

    #[test]
    fn attack_fragment_preserves_unicode_order_and_fixed_facts() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'é', '🦀', 'C', 'D']).unwrap();
        let fixed = [('B', 'A')];
        let domain = AttackPlugboardDomain::parse_json(
            &alphabet,
            &fixed,
            r#"{"kind":"attack","symbols":["🦀","é","D","C"],"max_pairs":3}"#,
        )
        .unwrap();
        assert_eq!(domain.symbols(), &['🦀', 'é', 'D', 'C']);
        assert_eq!(domain.fixed_pairs(), &fixed);
        assert_eq!(domain.max_pairs(), 3);
        assert_eq!(fixed, [('B', 'A')]);
        for cap in [1, 2, 3] {
            let fragment =
                format!(r#"{{"kind":"attack","symbols":["é","🦀","C","D"],"max_pairs":{cap}}}"#);
            assert!(AttackPlugboardDomain::parse_json(&alphabet, &fixed, &fragment).is_ok());
        }
        let zero = AttackPlugboardDomain::parse_json(
            &alphabet,
            &[],
            r#"{"kind":"attack","symbols":["é"],"max_pairs":0}"#,
        )
        .unwrap();
        assert_eq!(zero.max_pairs(), 0);
        assert!(zero.fixed_pairs().is_empty());
    }

    #[test]
    fn attack_fragment_odd_capacity_and_large_integer_boundaries() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D', 'é']).unwrap();
        let fixed = [('D', 'C'), ('B', 'A')];
        let domain = AttackPlugboardDomain::parse_json(
            &alphabet,
            &fixed,
            r#"{"kind":"attack","symbols":["é"],"max_pairs":2}"#,
        )
        .unwrap();
        assert_eq!(domain.fixed_pairs(), &fixed);
        for cap in [
            "3",
            "18446744073709551615",
            "18446744073709551616",
            "null",
            "true",
            "\"2\"",
        ] {
            let fragment = format!(r#"{{"kind":"attack","symbols":["é"],"max_pairs":{cap}}}"#);
            let errors =
                AttackPlugboardDomain::parse_json(&alphabet, &fixed, &fragment).unwrap_err();
            assert_eq!(errors[0].code(), "invalid_search_space");
            assert_eq!(errors[0].location(), "/job/space/plugboard/max_pairs");
        }
        let errors = AttackPlugboardDomain::parse_json(
            &alphabet,
            &fixed,
            r#"{"kind":"attack","symbols":["é"],"max_pairs":2}"#,
        )
        .unwrap_err();
        assert_eq!(errors[0].location(), "/job/space/plugboard/symbols/0");
    }

    #[test]
    fn attack_fragment_diagnostics_are_exact() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D', 'E', 'F']).unwrap();
        for (fragment, fixed, code, location) in [
            (
                r#"null"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard",
            ),
            (
                r#"{"kind":"legacy","symbols":["C","D"],"max_pairs":1}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/kind",
            ),
            (
                r#"{"kind":"attack","symbols":[],"max_pairs":0}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/symbols",
            ),
            (
                r#"{"kind":"attack","symbols":["C","C"],"max_pairs":1}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/symbols",
            ),
            (
                r#"{"kind":"attack","symbols":["Z"],"max_pairs":0}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/symbols/0",
            ),
            (
                r#"{"kind":"attack","symbols":["CD"],"max_pairs":0}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/symbols/0",
            ),
            (
                r#"{"kind":"attack","symbols":[""],"max_pairs":0}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/symbols/0",
            ),
            (
                r#"{"kind":"attack","symbols":[4],"max_pairs":0}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/symbols/0",
            ),
            (
                r#"{"kind":"attack","symbols":["A","C"],"max_pairs":1}"#,
                vec![('A', 'B')],
                "invalid_search_space",
                "/job/space/plugboard/symbols/0",
            ),
            (
                r#"{"kind":"attack","symbols":["C","D"],"max_pairs":0}"#,
                vec![('A', 'B')],
                "invalid_search_space",
                "/job/space/plugboard/max_pairs",
            ),
            (
                r#"{"kind":"attack","symbols":["A","B","C","D","E","F"],"max_pairs":4}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/max_pairs",
            ),
            (
                r#"{"kind":"attack","symbols":["C"],"max_pairs":2}"#,
                vec![('A', 'B')],
                "invalid_search_space",
                "/job/space/plugboard/max_pairs",
            ),
            (
                r#"{"kind":"attack","symbols":["C","D"],"max_pairs":-1}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/max_pairs",
            ),
            (
                r#"{"kind":"attack","symbols":["C","D"],"max_pairs":1.0}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/max_pairs",
            ),
            (
                r#"{"kind":"attack","symbols":["C","D"]}"#,
                vec![],
                "invalid_search_space",
                "/job/space/plugboard/max_pairs",
            ),
            (
                r#"{"kind":"attack","symbols":["C","D"],"max_pairs":1,"x/y~z":0}"#,
                vec![],
                "unknown_field",
                "/job/space/plugboard/x~1y~0z",
            ),
            (
                r#"{"kind":"attack","symbols":["C","D"],"max_pairs":1,"candidates":[]}"#,
                vec![],
                "unknown_field",
                "/job/space/plugboard/candidates",
            ),
            (
                r#"{"kind":"attack","symbols":["C","D"],"max_pairs":1,"size":1}"#,
                vec![],
                "unknown_field",
                "/job/space/plugboard/size",
            ),
        ] {
            let errors =
                AttackPlugboardDomain::parse_json(&alphabet, &fixed, fragment).unwrap_err();
            assert_eq!(errors.len(), 1, "{fragment}");
            assert_eq!(
                (errors[0].code(), errors[0].location()),
                (code, location),
                "{fragment}"
            );
        }
    }

    #[test]
    fn attack_fragment_rejects_duplicates_trailing_json_and_invalid_fixed_facts() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        for fragment in [
            r#"{"kind":"attack","kind":"attack","symbols":["C","D"],"max_pairs":1}"#,
            r#"{"kind":"attack","symbols":["C","D"],"max_pairs":1,"max_pairs":0}"#,
            r#"{"kind":"attack","symbols":["C","D"],"max_pairs":1} null"#,
        ] {
            let errors = AttackPlugboardDomain::parse_json(&alphabet, &[], fragment).unwrap_err();
            assert_eq!(errors[0].code(), "invalid_search_space");
            assert_eq!(errors[0].location(), "/job/space/plugboard");
        }
        for fixed in [
            vec![('A', 'A')],
            vec![('A', 'Z')],
            vec![('A', 'B'), ('A', 'C')],
        ] {
            let before = fixed.clone();
            let errors = AttackPlugboardDomain::parse_json(
                &alphabet,
                &fixed,
                r#"{"kind":"attack","symbols":["D"],"max_pairs":1}"#,
            )
            .unwrap_err();
            assert_eq!(errors[0].code(), "invalid_search_space");
            assert!(errors[0]
                .location()
                .starts_with("/job/configuration/plugboard/"));
            assert_eq!(fixed, before);
        }
    }

    #[test]
    fn attack_fragments_never_enable_complete_requests_or_legacy_enumeration() {
        let mut value = base_request();
        value["job"]["space"]["plugboard"] =
            json!({"kind":"attack","symbols":["A","B"],"max_pairs":1});
        assert!(ParsedSearchRequest::parse_json(&value.to_string()).is_err());
        assert!(SearchRequest::parse_json(&value.to_string()).is_err());
        value["job"]["attack"] = json!({"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":1,"backtrack_pairs":0,"start":[]});
        assert!(ParsedSearchRequest::parse_json(&value.to_string()).is_err());
        assert!(SearchRequest::parse_json(&value.to_string()).is_err());
        let json =
            value
                .to_string()
                .replacen("\"max_pairs\":1", "\"max_pairs\":1,\"max_pairs\":0", 1);
        assert_eq!(
            ParsedSearchRequest::parse_json(&json).unwrap_err()[0].code(),
            "invalid_json"
        );
        let fixed = SearchRequest::parse_json(&base_request().to_string()).unwrap();
        assert!(fixed.space().plugboard().is_none());
        let legacy = parse_plugboard_domain(
            fixed.definition().alphabet(),
            &json!({"candidates":[["D","C"],["B","A"]],"size":1}),
            "/job/space/plugboard",
        )
        .unwrap();
        assert_eq!(legacy.candidates(), &[('D', 'C'), ('B', 'A')]);
        assert_eq!(legacy.size(), 1);
    }

    /// A small arbitrary custom definition with two slots: a structurally fixed reflector
    /// and a movable rotor with two admissible wheels. Not a historical machine.
    fn definition_value() -> Value {
        json!({
            "alphabet": ["A", "B", "C", "D"],
            "wheels": [
                {"name": "rotor1", "wiring": ["B", "A", "D", "C"], "turnovers": ["B"]},
                {"name": "rotor2", "wiring": ["C", "D", "A", "B"], "turnovers": ["C"]},
                {"name": "reflector", "wiring": ["B", "A", "D", "C"], "turnovers": []}
            ],
            "slots": [
                {"id": "ukw", "role": "reflector", "movement": "fixed", "wheel": "reflector"},
                {"id": "fast", "role": "rotor", "movement": "movable", "allowed_wheels": ["rotor1", "rotor2"]}
            ],
            "stepping": {"rules": [{"when": {"always": true}, "advance": ["fast"]}]}
        })
    }

    /// A valid, fully fixed search request: every dimension is fixed in configuration,
    /// `space.slots` is empty, and no plugboard remainder is searched.
    #[test]
    fn typed_selection_gate() {
        let mut value = base_request();
        value["job"]["measures"] = json!(["ic"]);
        assert!(SearchRequest::parse_json(&value.to_string()).is_ok());
        for id in [
            "sinkov_monogram",
            "sinkov_bigram",
            "sinkov_trigram",
            "sinkov_quadgram",
            "sinkov_pentagram",
            "sinkov_hexagram",
            "trie",
        ] {
            value["job"]["text"] = json!("ABABAB");
            value["job"]["measures"] = json!([id]);
            value["job"]["resources"] = json!({id: {"path": "model.json"}});
            let parsed = ParsedSearchRequest::parse_json(&value.to_string()).unwrap();
            assert_eq!(parsed.measures()[0].id(), id);
            assert_eq!(parsed.resources()[0].path(), "model.json");
            let error = SearchRequest::parse_json(&value.to_string()).unwrap_err();
            assert_eq!(error[0].code(), "unsupported_resource");
            assert!(error[0].message().contains("supplied"));
        }
        value["job"]["measures"] = json!(["entropy"]);
        value["job"].as_object_mut().unwrap().remove("resources");
        assert!(ParsedSearchRequest::parse_json(&value.to_string())
            .unwrap()
            .into_resource_free()
            .is_ok());
    }

    #[test]
    fn selection_errors_are_localized() {
        for (measures, resources, code, location) in [
            (
                json!(["index_of_coincidence"]),
                json!({}),
                "unsupported_measure",
                "/job/measures/0",
            ),
            (
                json!(["sinkov_bigram"]),
                json!({}),
                "unsupported_resource",
                "/job/resources/sinkov_bigram/path",
            ),
            (
                json!(["ic"]),
                json!({"ic": {"path": "x"}}),
                "unsupported_resource",
                "/job/resources/ic/path",
            ),
            (
                json!(["entropy"]),
                json!({"trie": {"path": "x"}}),
                "unsupported_resource",
                "/job/resources/trie/path",
            ),
            (
                json!(["trie"]),
                json!({"trie": {"path": ""}}),
                "unsupported_resource",
                "/job/resources/trie/path",
            ),
            (
                json!(["trie"]),
                json!({"trie": {"path": 1}}),
                "unsupported_resource",
                "/job/resources/trie/path",
            ),
            (
                json!(["trie"]),
                json!({"trie": {}}),
                "unsupported_resource",
                "/job/resources/trie/path",
            ),
            (
                json!(["trie"]),
                json!({"trie": {"path": "x", "entries": []}}),
                "unknown_field",
                "/job/resources/trie/entries",
            ),
            (
                json!(["trie"]),
                json!({"trie": []}),
                "unsupported_resource",
                "/job/resources/trie/path",
            ),
        ] {
            let mut value = base_request();
            value["job"]["measures"] = measures;
            value["job"]["resources"] = resources;
            let error = ParsedSearchRequest::parse_json(&value.to_string())
                .unwrap_err()
                .remove(0);
            assert_eq!((error.code(), error.location()), (code, location));
        }
    }

    #[test]
    fn scalar_sample_boundaries() {
        for (id, minimum) in [
            ("ic", 2),
            ("entropy", 1),
            ("sinkov_monogram", 1),
            ("sinkov_bigram", 2),
            ("sinkov_trigram", 3),
            ("sinkov_quadgram", 4),
            ("sinkov_pentagram", 5),
            ("sinkov_hexagram", 6),
            ("trie", 1),
        ] {
            let mut value = base_request();
            value["job"]["measures"] = json!([id]);
            if id != "ic" && id != "entropy" {
                value["job"]["resources"] = json!({id: {"path": "x"}});
            }
            for length in [minimum - 1, minimum] {
                value["job"]["text"] = json!("é".repeat(length));
                let json = value.to_string().replace("\"A\"", "\"é\"");
                let result = ParsedSearchRequest::parse_json(&json);
                if length == minimum {
                    assert!(result.is_ok(), "{id}: {result:?}");
                } else {
                    let error = result.unwrap_err().remove(0);
                    assert_eq!(
                        (error.code(), error.location()),
                        ("invalid_text", "/job/text")
                    );
                }
            }
        }
    }

    #[test]
    fn resource_duplicate_keys_remain_strict() {
        let mut value = base_request();
        value["job"]["measures"] = json!(["trie"]);
        value["job"]["resources"] = json!({"trie": {"path": "x"}});
        let json = value.to_string();
        for malformed in [
            json.replace("\"path\":\"x\"", "\"path\":\"x\",\"path\":\"x\""),
            json.replace(
                "\"trie\":{\"path\":\"x\"}",
                "\"trie\":{\"path\":\"x\"},\"trie\":{\"path\":\"x\"}",
            ),
        ] {
            assert_eq!(
                ParsedSearchRequest::parse_json(&malformed).unwrap_err()[0].code(),
                "invalid_json"
            );
        }
    }

    fn base_request() -> Value {
        json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "custom", "value": definition_value()}},
            "job": {
                "kind": "search",
                "configuration": {
                    "slots": [
                        {"id": "ukw", "position": "A", "ring": "A"},
                        {"id": "fast", "wheel": "rotor1", "position": "B", "ring": "A"}
                    ],
                    "plugboard": []
                },
                "text": "AB",
                "space": {"slots": []},
                "passes": ["hill_climb"],
                "measures": ["ic"]
            }
        })
    }

    fn attack_request() -> Value {
        let mut value = base_request();
        value["job"]["space"]["plugboard"] =
            json!({"kind": "attack", "symbols": ["D", "C", "B", "A"], "max_pairs": 2});
        value["job"]["attack"] = json!({
            "kind": "hill_climb", "initial_measure": "ic", "final_measure": "ic",
            "switch_pairs": 1, "backtrack_pairs": 0,
            "start": [["D", "C"]]
        });
        value
    }

    #[test]
    fn hold_capacity_full_request_preflight_precedence() {
        for (pointer, replacement, expected) in [
            ("/job/text", json!("A"), ("invalid_text", "/job/text")),
            (
                "/job/attack/progress_every",
                json!(0),
                ("invalid_request", "/job/attack/progress_every"),
            ),
            (
                "/job/resources",
                json!({"ic":{"path":"unused"}}),
                ("unsupported_resource", "/job/resources/ic/path"),
            ),
        ] {
            let mut value = attack_request();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            value.pointer_mut(parent).unwrap()[key] = replacement;
            let errors = AttackRequest::parse_json(&value.to_string()).unwrap_err();
            assert_eq!((errors[0].code(), errors[0].location()), expected);
            value["job"]["attack"]["hold"] = json!(0);
            let errors = AttackRequest::parse_json(&value.to_string()).unwrap_err();
            assert_eq!(
                (errors[0].code(), errors[0].location()),
                ("invalid_request", "/job/attack/hold")
            );
        }
    }

    #[test]
    fn hold_capacity_precedes_outer_count_overflow() {
        let alphabet: Vec<String> = (0..256)
            .map(|i| char::from_u32(0x100 + i).unwrap().to_string())
            .collect();
        let mut value = attack_request();
        value["machine"]["definition"]["value"] = json!({
            "alphabet":alphabet, "wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
            "slots":(0..8).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"})).collect::<Vec<_>>(),
            "stepping":{"rules":[]}
        });
        value["job"]["configuration"]["slots"] = json!([]);
        value["job"]["text"] = json!(alphabet[0].repeat(2));
        value["job"]["space"] = json!({"limit":1,
            "slots":(0..8).map(|i| json!({"id":format!("r{i}"),"positions":alphabet,"rings":alphabet})).collect::<Vec<_>>(),
            "plugboard":{"kind":"attack","symbols":&alphabet[..2],"max_pairs":1}});
        value["job"]["attack"]["start"] = json!([]);
        let errors = AttackRequest::parse_json(&value.to_string()).unwrap_err();
        assert_eq!(
            (errors[0].code(), errors[0].location()),
            ("resource_limit", "/job/space")
        );
        value["job"]["attack"]["hold"] = json!(0);
        let errors = AttackRequest::parse_json(&value.to_string()).unwrap_err();
        assert_eq!(
            (errors[0].code(), errors[0].location()),
            ("invalid_request", "/job/attack/hold")
        );
    }

    #[test]
    fn request_bound_partial_private_invariant_fault_preserves_diagnostic() {
        use crate::attack_hill_climb::{EvaluationAllowance, PartialClimbError};
        let mut value = attack_request();
        value["job"]["passes"] = json!(["partial_exhaustion"]);
        value["job"]["attack"]["kind"] = json!("partial_exhaustion");
        value["job"]["attack"]
            .as_object_mut()
            .unwrap()
            .remove("start");
        value["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
        let mut request = AttackRequest::parse_json(&value.to_string()).unwrap();
        // PRIVATE evaluator invariant injection: not a valid promoted request.
        request.carrier.parsed.text = "AZ".to_owned();
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let mut allowance = EvaluationAllowance { used: 3 };
        let index = u128::from(u64::MAX) + 91;
        let error = request
            .climb_partial_outer(initial, index, &mut allowance)
            .unwrap_err();
        assert_eq!(error.outer_index, index);
        assert_eq!(error.evaluations_used, 4);
        assert_eq!(allowance.used, 4);
        assert_eq!(
            error.source,
            PartialClimbError::Evaluation(crate::attack_evaluator::TrialEvaluationError::Model(
                crate::ModelError::UnknownSymbol('Z')
            ))
        );
    }

    #[test]
    fn request_bound_direct_private_invariant_faults_preserve_index_and_usage() {
        use crate::attack_hill_climb::{DirectClimbError, EvaluationAllowance};
        // PRIVATE invariant faults: neither corruption is a valid promoted request.
        let mut request = AttackRequest::parse_json(&attack_request().to_string()).unwrap();
        request.carrier.parsed.text = "AZ".to_owned();
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let mut allowance = EvaluationAllowance { used: 3 };
        let error = request
            .climb_direct_outer(initial, 91, &mut allowance)
            .unwrap_err();
        assert_eq!(error.outer_index, 91);
        assert_eq!(error.evaluations_used, 4);
        assert_eq!(allowance.used, 4);
        assert_eq!(
            error.source,
            DirectClimbError::Evaluation(crate::attack_evaluator::TrialEvaluationError::Model(
                crate::ModelError::UnknownSymbol('Z')
            ))
        );
        request.settings.initialization = AttackInitialization::Seeds(AttackSeedPolicy::All);
        let initial = request.outer_candidates().next().unwrap().1.unwrap();
        let error = request
            .climb_direct_outer(initial, 92, &mut allowance)
            .unwrap_err();
        assert_eq!(error.outer_index, 92);
        assert_eq!(error.evaluations_used, 4);
        assert_eq!(error.source, DirectClimbError::MissingStart);
        assert_eq!(allowance.used, 4);
    }

    #[test]
    fn partial_outer_scheduler_private_invariant_faults_keep_original_errors() {
        use crate::attack_hill_climb::{PartialClimbError, PartialRunError};
        let mut value = attack_request();
        value["job"]["passes"] = json!(["partial_exhaustion"]);
        value["job"]["attack"]["kind"] = json!("partial_exhaustion");
        value["job"]["attack"]
            .as_object_mut()
            .unwrap()
            .remove("start");
        value["job"]["attack"]["seeds"] = json!({"kind":"empty_single","selection":"all"});
        value["job"]["space"]["plugboard"]["max_pairs"] = json!(0);
        value["job"]["configuration"]["slots"][1]
            .as_object_mut()
            .unwrap()
            .remove("position");
        value["job"]["space"]["slots"] = json!([{"id":"fast","positions":["A","B"]}]);
        value["job"]["space"]["offset"] = json!(1);
        let mut request = AttackRequest::parse_json(&value.to_string()).unwrap();
        // PRIVATE evaluator invariant injection: first selected outer, NOT a
        // later evaluator failure after successful earlier scheduler work.
        request.carrier.parsed.text = "AZ".to_owned();
        let error = request.schedule_partial_outers().unwrap_err();
        assert_eq!((error.outer_index, error.evaluations_used), (Some(1), 1));
        let PartialRunError::Climb(source) = error.source else {
            panic!("evaluation diagnostic was replaced");
        };
        assert_eq!(
            source,
            PartialClimbError::Evaluation(crate::attack_evaluator::TrialEvaluationError::Model(
                crate::ModelError::UnknownSymbol('Z')
            ))
        );

        value["job"]["space"]["offset"] = json!(0);
        let mut request = AttackRequest::parse_json(&value.to_string()).unwrap();
        // PRIVATE resolver invariant injection: the sole empty seed of outer 0
        // really completes at cost 1 before the later invalid position resolves.
        request.carrier.parsed.space.slots[0]
            .positions
            .as_mut()
            .unwrap()[1] = 'Z';
        let original = request.outer_candidates().nth(1).unwrap().1.unwrap_err();
        let error = request.schedule_partial_outers().unwrap_err();
        assert_eq!((error.outer_index, error.evaluations_used), (Some(1), 1));
        let PartialRunError::Resolution(diagnostics) = error.source else {
            panic!("resolution diagnostics were replaced");
        };
        assert_eq!(diagnostics, original);
        // Later evaluation-error mapping is structural only: all outers share
        // evaluator inputs/resources; no production hook manufactures that trace.
    }

    #[test]
    fn direct_outer_scheduler_private_faults_keep_original_indexed_errors() {
        use crate::attack_hill_climb::{DirectClimbError, DirectRunError};
        let mut value = attack_request();
        value["job"]["configuration"]["slots"][1]
            .as_object_mut()
            .unwrap()
            .remove("position");
        value["job"]["space"]["slots"] = json!([{"id":"fast", "positions":["A","B","C"]}]);
        value["job"]["space"]["offset"] = json!(1);
        let mut request = AttackRequest::parse_json(&value.to_string()).unwrap();
        // PRIVATE invariant injection, never a valid promoted request.
        request.carrier.parsed.configuration.plugboard = vec![('A', 'A')];
        let original = request.outer_candidates().next().unwrap().1.unwrap_err();
        let error = request.schedule_direct_outers().unwrap_err();
        assert_eq!(error.outer_index, Some(1));
        assert_eq!(error.evaluations_used, 0);
        let DirectRunError::Resolution(diagnostics) = error.source else {
            panic!("resolution diagnostics were replaced");
        };
        assert_eq!(diagnostics, original);
        request.carrier.parsed.configuration.plugboard.clear();
        request.carrier.parsed.text = "AZ".to_owned();
        let error = request.schedule_direct_outers().unwrap_err();
        assert_eq!(error.outer_index, Some(1));
        assert_eq!(error.evaluations_used, 1);
        assert!(matches!(
            error.source,
            DirectRunError::Climb(DirectClimbError::Evaluation(
                crate::attack_evaluator::TrialEvaluationError::Model(
                    crate::ModelError::UnknownSymbol('Z')
                )
            ))
        ));
    }

    #[test]
    fn attack_outer_candidates_preserve_slot_order_and_fixed_facts() {
        let mut value = attack_request();
        value["job"]["configuration"]["slots"] = json!([]);
        value["job"]["configuration"]["plugboard"] = json!([["B", "A"]]);
        value["job"]["space"]["plugboard"]["symbols"] = json!(["D", "C"]);
        // Source declarations deliberately reverse definition slot order.
        value["job"]["space"]["slots"] = json!([
            {"id":"fast", "wheels":["rotor2","rotor1"], "positions":["D","B"], "rings":["C","A"]},
            {"id":"ukw", "positions":["C","A"], "rings":["B","D"]}
        ]);
        let request = AttackRequest::parse_json(&value.to_string()).unwrap();
        assert!(request.carrier.space().plugboard().is_none());
        assert_eq!(request.settings().start(), Some(&[('D', 'C')][..]));
        let mut candidates = request.outer_candidates();
        let mut expected_index = 0u128;
        for ukw_position in ['C', 'A'] {
            for ukw_ring in ['B', 'D'] {
                for wheel in ["rotor2", "rotor1"] {
                    for position in ['D', 'B'] {
                        for ring in ['C', 'A'] {
                            let (index, resolved) = candidates.next().unwrap();
                            assert_eq!(index, expected_index);
                            expected_index += 1;
                            let resolved = resolved.unwrap();
                            let slots = resolved.topology().slots();
                            assert_eq!(slots[0].id(), "ukw");
                            assert_eq!(slots[1].id(), "fast");
                            assert_eq!(
                                (slots[0].wheel(), slots[0].position(), slots[0].ring()),
                                ("reflector", ukw_position, ukw_ring)
                            );
                            assert_eq!(
                                (slots[1].wheel(), slots[1].position(), slots[1].ring()),
                                (wheel, position, ring)
                            );
                            assert_eq!(resolved.plugboard().map('A'), Some('B'));
                            assert_eq!(resolved.plugboard().map('B'), Some('A'));
                            assert_eq!(resolved.plugboard().map('C'), Some('C'));
                            assert_eq!(resolved.plugboard().map('D'), Some('D'));
                        }
                    }
                }
            }
        }
        assert_eq!(expected_index, 32);
        assert!(candidates.next().is_none());
        assert!(candidates.next().is_none());
        assert_eq!(request.domain().fixed_pairs(), [('B', 'A')]);
        assert_eq!(request.settings().start(), Some(&[('D', 'C')][..]));
    }

    #[test]
    fn attack_outer_candidates_apply_absolute_slice_indices() {
        let request = AttackRequest::parse_json(&attack_request().to_string()).unwrap();
        let mut candidates = request.outer_candidates();
        assert_eq!(candidates.next().unwrap().0, 0);
        assert!(candidates.next().is_none());
        assert!(candidates.next().is_none());

        let mut value = attack_request();
        value["job"]["configuration"]["slots"][1]
            .as_object_mut()
            .unwrap()
            .remove("position");
        value["job"]["space"]["slots"] = json!([{"id":"fast", "positions":["D","B","C","A"]}]);
        for (offset, limit, expected) in [
            (1, 2, vec![(1u128, 'B'), (2, 'C')]),
            (3, 4, vec![(3, 'A')]),
            (4, 1, vec![]),
            (9, 2, vec![]),
        ] {
            value["job"]["space"]["offset"] = json!(offset);
            value["job"]["space"]["limit"] = json!(limit);
            let request = AttackRequest::parse_json(&value.to_string()).unwrap();
            let mut candidates = request.outer_candidates();
            for (expected_index, position) in expected {
                let (index, resolved) = candidates.next().unwrap();
                assert_eq!(index, expected_index);
                assert_eq!(resolved.unwrap().topology().slots()[1].position(), position);
            }
            assert!(candidates.next().is_none());
            assert!(candidates.next().is_none());
        }
    }

    #[test]
    fn attack_outer_candidates_cross_u64_boundary() {
        let alphabet: Vec<String> = (0..256)
            .map(|i| char::from_u32(0x100 + i).unwrap().to_string())
            .collect();
        let mut value = attack_request();
        value["machine"]["definition"]["value"] = json!({
            "alphabet":alphabet, "wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
            "slots":(0..5).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"})).collect::<Vec<_>>(),
            "stepping":{"rules":[]}
        });
        value["job"]["configuration"]["slots"] = json!([]);
        value["job"]["text"] = json!(alphabet[0].repeat(2));
        value["job"]["space"] = json!({"offset":u64::MAX, "limit":2,
            "slots":(0..5).map(|i| json!({"id":format!("r{i}"),"positions":alphabet,"rings":alphabet})).collect::<Vec<_>>(),
            "plugboard":{"kind":"attack","symbols":&alphabet[..2],"max_pairs":1}});
        value["job"]["attack"]["start"] = json!([]);
        let request = AttackRequest::parse_json(&value.to_string()).unwrap();
        assert_eq!(request.gate().outer_total(), 1u128 << 80);
        let mut candidates = request.outer_candidates();
        // Ten base-256 digits: the first index is 00 00 FF FF FF FF FF FF FF FF;
        // the next is 00 01 00 00 00 00 00 00 00 00.
        for (index, digits) in [
            (
                u128::from(u64::MAX),
                [0u32, 0, 255, 255, 255, 255, 255, 255, 255, 255],
            ),
            (u128::from(u64::MAX) + 1, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
        ] {
            let (actual_index, resolved) = candidates.next().unwrap();
            assert_eq!(actual_index, index);
            let resolved = resolved.unwrap();
            for (slot, pair) in resolved
                .topology()
                .slots()
                .iter()
                .zip(digits.chunks_exact(2))
            {
                assert_eq!(slot.wheel(), "r");
                assert_eq!(slot.position(), char::from_u32(0x100 + pair[0]).unwrap());
                assert_eq!(slot.ring(), char::from_u32(0x100 + pair[1]).unwrap());
            }
        }
        assert!(candidates.next().is_none());
        assert!(candidates.next().is_none());
    }

    #[test]
    fn attack_outer_candidates_preserve_resolution_errors() {
        let mut value = attack_request();
        value["job"]["configuration"]["slots"][1]
            .as_object_mut()
            .unwrap()
            .remove("position");
        value["job"]["space"]["slots"] = json!([{"id":"fast", "positions":["A","B","C"]}]);
        value["job"]["space"]["offset"] = json!(1);
        value["job"]["space"]["limit"] = json!(2);
        let mut request = AttackRequest::parse_json(&value.to_string()).unwrap();
        // PRIVATE invariant fault injection after valid ownership: ordinary validated
        // owners cannot produce this invalid fixed self-pair.
        request.carrier.parsed.configuration.plugboard = vec![('A', 'A')];
        let mut candidates = request.outer_candidates();
        for expected_index in [1u128, 2] {
            let (index, result) = candidates.next().unwrap();
            assert_eq!(index, expected_index);
            let errors = result.unwrap_err();
            assert!(!errors.is_empty());
            assert_eq!(errors[0].code(), "invalid_search_space");
        }
        assert!(candidates.next().is_none());
        assert!(candidates.next().is_none());
    }

    #[test]
    fn public_attack_rejects_removed_evaluation_budget() {
        for pe in [false, true] {
            let mut value = attack_request();
            if pe {
                value["job"]["passes"] = json!(["partial_exhaustion"]);
                let attack = value["job"]["attack"].as_object_mut().unwrap();
                attack.insert("kind".into(), json!("partial_exhaustion"));
                attack.remove("start");
                attack.insert(
                    "seeds".into(),
                    json!({"kind":"empty_single", "selection":"all"}),
                );
            }
            for budget in [json!(1), json!(u64::MAX), json!(0), json!(null)] {
                value["job"]["attack"]["evaluation_budget"] = budget;
                let raw = value.to_string();
                let parsed = crate::ParsedAttackRequest::parse_json(&raw);
                assert!(parsed.is_err(), "removed field accepted: {raw}");
                let errors = parsed.unwrap_err();
                assert_eq!(errors.len(), 1);
                assert_eq!(
                    (errors[0].code(), errors[0].location()),
                    ("unknown_field", "/job/attack/evaluation_budget"),
                    "{raw}"
                );
                let errors = crate::AttackRequest::parse_json(&raw).unwrap_err();
                assert_eq!(errors.len(), 1);
                assert_eq!(
                    (errors[0].code(), errors[0].location()),
                    ("unknown_field", "/job/attack/evaluation_budget"),
                    "{raw}"
                );
            }
        }
    }

    #[test]
    fn public_attack_promotion_and_counts() {
        for (selection, starts) in [(None, 1), (Some("all"), 7), (Some("touching"), 4)] {
            let mut value = attack_request();
            if let Some(selection) = selection {
                value["job"]["passes"] = json!(["partial_exhaustion"]);
                value["job"]["attack"]
                    .as_object_mut()
                    .unwrap()
                    .remove("start");
                value["job"]["attack"]["kind"] = json!("partial_exhaustion");
                let mut seeds = json!({"kind":"empty_single", "selection":selection});
                if selection == "touching" {
                    seeds["symbols"] = json!(["D"]);
                }
                value["job"]["attack"]["seeds"] = seeds;
            }
            value["job"]["configuration"]["slots"][1]
                .as_object_mut()
                .unwrap()
                .remove("position");
            value["job"]["space"]["slots"] = json!([{"id":"fast", "positions":["A","B","C","D"]}]);
            for (offset, limit, selected) in [(0, 4, 4), (1, 2, 2), (4, 1, 0)] {
                value["job"]["space"]["offset"] = json!(offset);
                value["job"]["space"]["limit"] = json!(limit);
                let parsed = crate::ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
                assert!(parsed.resources().is_empty());
                let bound = parsed
                    .bind_resources(&std::collections::BTreeMap::new())
                    .unwrap();
                let free = crate::AttackRequest::parse_json(&value.to_string()).unwrap();
                for request in [&bound, &free] {
                    assert_eq!(
                        (
                            request.gate().outer_total(),
                            request.gate().outer_selected(),
                            request.gate().starts_per_outer()
                        ),
                        (4, selected, starts)
                    );
                    assert!(request.bound_resource(MeasureId::Ic).is_none());
                }
            }
        }
        let mut value = attack_request();
        value["job"]["configuration"]["plugboard"] = json!([["B", "A"]]);
        value["job"]["space"]["plugboard"]["symbols"] = json!(["D", "C"]);
        let request = crate::AttackRequest::parse_json(&value.to_string()).unwrap();
        assert_eq!(request.domain().fixed_pairs(), [('B', 'A')]);
        assert_eq!(request.domain().symbols(), ['D', 'C']);
        assert_eq!(request.settings().start(), Some(&[('D', 'C')][..]));
    }

    fn resource_attack() -> Value {
        let mut value = attack_request();
        value["job"]["text"] = json!("AAAAAA");
        value["job"]["measures"] = json!(["ic", "sinkov_bigram", "trie"]);
        value["job"]["resources"] =
            json!({"sinkov_bigram":{"path":"ng.json"}, "trie":{"path":"dict.json"}});
        value
    }

    fn attack_models() -> (Value, Value) {
        (
            json!({"resource_version":1, "kind":"ngram", "alphabet":["A","B","C","D"], "order":2, "entries":[{"gram":["A","A"],"count":1}]}),
            json!({"resource_version":1, "kind":"dictionary", "alphabet":["A","B","C","D"], "entries":[{"word":["A"],"weight":2}]}),
        )
    }

    #[test]
    fn public_attack_retains_nonobjective_models_after_inputs_drop() {
        let request = {
            let (ngram, trie) = attack_models();
            let (ngram, trie) = (ngram.to_string(), trie.to_string());
            let supplied = std::collections::BTreeMap::from([
                ("sinkov_bigram".into(), ngram.as_str()),
                ("trie".into(), trie.as_str()),
            ]);
            let parsed =
                crate::ParsedAttackRequest::parse_json(&resource_attack().to_string()).unwrap();
            assert_eq!(parsed.resources().len(), 2);
            assert_eq!(parsed.resources()[0].measure(), MeasureId::SinkovBigram);
            parsed.bind_resources(&supplied).unwrap()
        };
        assert_eq!(request.resources()[1].path(), "dict.json");
        assert_eq!(
            request.measures(),
            [MeasureId::Ic, MeasureId::SinkovBigram, MeasureId::Trie]
        );
        assert_eq!(request.settings().initial_measure(), MeasureId::Ic);
        for measure in [MeasureId::SinkovBigram, MeasureId::Trie] {
            match request.bound_resource(measure).unwrap() {
                crate::BoundResource::Ngram(model) => {
                    assert_eq!(model.alphabet(), request.definition().alphabet());
                    assert_eq!(model.order(), 2);
                    assert_eq!(model.score(request.text()).unwrap().measured().units(), 0);
                }
                crate::BoundResource::Trie(model) => {
                    assert_eq!(model.alphabet(), request.definition().alphabet());
                    assert_eq!(
                        model.score(request.text()).unwrap().measured().units(),
                        12 * crate::SCALE
                    );
                }
            }
        }
    }

    #[test]
    fn public_attack_binding_error_precedence_and_context() {
        let value = resource_attack();
        let parse = || crate::ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
        let check = |errors: Vec<RequestDiagnostic>, code, path| {
            assert_eq!((errors[0].code(), errors[0].location()), (code, path));
        };
        check(
            crate::AttackRequest::parse_json(&value.to_string()).unwrap_err(),
            "unsupported_resource",
            "/job/resources/sinkov_bigram/path",
        );
        check(
            parse().into_resource_free().unwrap_err(),
            "unsupported_resource",
            "/job/resources/sinkov_bigram/path",
        );
        check(
            parse()
                .bind_resources(&std::collections::BTreeMap::new())
                .unwrap_err(),
            "unsupported_resource",
            "/job/resources/sinkov_bigram/path",
        );
        let extra = std::collections::BTreeMap::from([("a~/extra".into(), "bad")]);
        check(
            parse().bind_resources(&extra).unwrap_err(),
            "unsupported_resource",
            "/job/resources/a~0~1extra/path",
        );
        let oversized = "x".repeat(crate::MAX_RESOURCE_BYTES + 1);
        let supplied = std::collections::BTreeMap::from([
            ("sinkov_bigram".into(), "bad"),
            ("trie".into(), oversized.as_str()),
        ]);
        check(
            parse().bind_resources(&supplied).unwrap_err(),
            "resource_limit",
            "/job/resources/trie/path",
        );
        let (ngram, trie) = attack_models();
        let trie = trie.to_string();
        let mut wrong_order = ngram.clone();
        wrong_order["order"] = json!(1);
        wrong_order["entries"][0]["gram"] = json!(["A"]);
        let mut wrong_alphabet = ngram;
        wrong_alphabet["alphabet"] = json!(["B", "A", "C", "D"]);
        for (content, path) in [
            ("{".to_owned(), ""),
            (wrong_order.to_string(), "/order"),
            (wrong_alphabet.to_string(), "/alphabet"),
        ] {
            let supplied = std::collections::BTreeMap::from([
                ("sinkov_bigram".into(), content.as_str()),
                ("trie".into(), trie.as_str()),
            ]);
            let errors = parse().bind_resources(&supplied).unwrap_err();
            assert_eq!(errors[0].location(), path);
            assert!(errors[0].message().contains("ng.json"));
            assert!(errors[0].message().contains("sinkov_bigram"));
        }
    }

    #[test]
    fn public_attack_structure_precedes_eligibility() {
        for passes in [
            json!(["reswapping"]),
            json!(["hill_climb", "partial_exhaustion"]),
            json!(["partial_exhaustion"]),
        ] {
            let mut value = attack_request();
            let kind_only = passes == json!(["partial_exhaustion"]);
            value["job"]["passes"] = passes;
            let errors = crate::AttackRequest::parse_json(&value.to_string()).unwrap_err();
            assert_eq!(
                (errors[0].code(), errors[0].location()),
                passes_outcome(kind_only)
            );
        }
        for (field, code) in [
            ("switch_pairs", "invalid_search_space"),
            ("progress_every", "invalid_request"),
        ] {
            let mut value = attack_request();
            value["job"]["attack"][field] = json!(-1);
            let errors = crate::AttackRequest::parse_json(&value.to_string()).unwrap_err();
            assert_eq!(errors[0].code(), code);
            assert_eq!(errors[0].location(), format!("/job/attack/{field}"));
        }
    }

    #[test]
    fn public_attack_full_outer_overflow_precedes_slicing() {
        let alphabet: Vec<String> = (0..256)
            .map(|i| char::from_u32(0x100 + i).unwrap().to_string())
            .collect();
        for slots in [5, 8] {
            let mut value = attack_request();
            value["machine"]["definition"]["value"] = json!({
                "alphabet":alphabet, "wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
                "slots":(0..slots).map(|i| json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"})).collect::<Vec<_>>(),
                "stepping":{"rules":[]}
            });
            value["job"]["configuration"]["slots"] = json!([]);
            value["job"]["text"] = json!(alphabet[0].repeat(2));
            value["job"]["space"] = json!({"limit":1,
                "slots":(0..slots).map(|i| json!({"id":format!("r{i}"),"positions":alphabet,"rings":alphabet})).collect::<Vec<_>>(),
                "plugboard":{"kind":"attack","symbols":&alphabet[..2],"max_pairs":1}});
            value["job"]["attack"]["start"] = json!([]);
            let parsed = crate::ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
            let result = parsed.bind_resources(&std::collections::BTreeMap::new());
            if slots == 8 {
                let errors = result.unwrap_err();
                assert_eq!(
                    (errors[0].code(), errors[0].location()),
                    ("resource_limit", "/job/space")
                );
            } else {
                let request = result.unwrap();
                assert_eq!(
                    (
                        request.gate().outer_total(),
                        request.gate().outer_selected()
                    ),
                    (1u128 << 80, 1)
                );
            }
        }
    }

    #[test]
    fn private_attack_owns_complete_hill_climb() {
        let value = attack_request();
        let raw = value.to_string();
        let request = ParsedAttackRequest::parse_json(&raw).unwrap();
        assert_eq!(request.domain.symbols(), ['D', 'C', 'B', 'A']);
        assert_eq!(request.settings.start(), Some(&[('D', 'C')][..]));
        assert_eq!(
            request.carrier.text(),
            value["job"]["text"].as_str().unwrap()
        );
        assert!(request.carrier.space().plugboard().is_none());
        assert_eq!(raw, value.to_string());
    }

    fn attack_error(value: &Value) -> (String, String) {
        let error = ParsedAttackRequest::parse_json(&value.to_string())
            .unwrap_err()
            .remove(0);
        (error.code().to_owned(), error.location().to_owned())
    }

    #[test]
    fn private_attack_seed_ownership_and_all_selected_measures() {
        for policy in [
            json!({"kind": "empty_single", "selection": "all"}),
            json!({"kind": "empty_single", "selection": "touching", "symbols": ["C", "D"]}),
        ] {
            let mut value = attack_request();
            value["job"]["passes"] = json!(["partial_exhaustion"]);
            value["job"]["attack"]
                .as_object_mut()
                .unwrap()
                .remove("start");
            value["job"]["attack"]["kind"] = json!("partial_exhaustion");
            value["job"]["attack"]["seeds"] = policy.clone();
            value["job"]["configuration"]["plugboard"] = json!([["B", "A"]]);
            value["job"]["configuration"]["slots"] = json!([
                {"id": "fast", "wheel": "rotor2"},
                {"id": "ukw", "position": "B", "ring": "C"}
            ]);
            value["job"]["space"] = json!({
                "slots": [{"id": "fast", "positions": ["D", "B"], "rings": ["C", "A"]}],
                "plugboard": {"kind": "attack", "symbols": ["D", "C"], "max_pairs": 2},
                "offset": 7, "limit": 3
            });
            value["job"]["measures"] = json!(["ic", "trie"]);
            value["job"]["resources"] = json!({"trie": {"path": "not-opened.json"}});
            let original = value.clone();
            let request = ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
            assert_eq!(value, original);
            assert_eq!(request.domain.fixed_pairs(), [('B', 'A')]);
            assert_eq!(request.domain.symbols(), ['D', 'C']);
            assert_eq!(request.domain.max_pairs(), 2);
            assert_eq!(request.carrier.configuration.slots()[0].id(), "fast");
            assert_eq!(
                request.carrier.space.slots()[0].positions().unwrap(),
                ['D', 'B']
            );
            assert_eq!(
                request.carrier.space.slots()[0].rings().unwrap(),
                ['C', 'A']
            );
            assert_eq!(request.carrier.space.offset(), 7);
            assert_eq!(request.carrier.space.limit(), Some(3));
            assert_eq!(request.carrier.measures().len(), 2);
            assert_eq!(request.carrier.resources()[0].path(), "not-opened.json");
            let expected = if policy["selection"] == "all" {
                AttackSeedPolicy::All
            } else {
                AttackSeedPolicy::Touching(vec!['C', 'D'])
            };
            assert_eq!(request.settings.seed_policy(), Some(&expected));
            let raw = value.to_string();
            assert!(ParsedSearchRequest::parse_json(&raw).is_err());
            assert!(SearchRequest::parse_json(&raw).is_err());
            assert!(matches!(
                crate::ParsedRequest::parse_json(&raw),
                Ok(crate::ParsedRequest::Attack(_))
            ));
            value["job"].as_object_mut().unwrap().remove("resources");
            assert_eq!(
                attack_error(&value),
                (
                    "unsupported_resource".into(),
                    "/job/resources/trie/path".into()
                )
            );
            value["job"]["measures"] = json!(["ic", "sinkov_hexagram"]);
            value["job"]["resources"] = json!({"sinkov_hexagram": {"path": "six.json"}});
            value["job"]["text"] = json!("AB");
            assert_eq!(
                attack_error(&value),
                ("invalid_text".into(), "/job/text".into())
            );
        }
    }

    #[test]
    fn private_attack_required_and_unknown_members() {
        for (parent, keys, code) in [
            (
                "/job",
                &[
                    "kind",
                    "configuration",
                    "text",
                    "space",
                    "passes",
                    "measures",
                    "attack",
                ][..],
                "invalid_request",
            ),
            (
                "/job/space/plugboard",
                &["kind", "symbols", "max_pairs"][..],
                "invalid_search_space",
            ),
            (
                "/job/attack",
                &[
                    "kind",
                    "initial_measure",
                    "final_measure",
                    "switch_pairs",
                    "backtrack_pairs",
                    "start",
                ][..],
                "invalid_request",
            ),
        ] {
            for key in keys {
                let mut value = attack_request();
                value
                    .pointer_mut(parent)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(*key);
                assert_eq!(
                    attack_error(&value),
                    (code.into(), format!("{parent}/{key}"))
                );
            }
        }
        for parent in ["/job", "/job/space/plugboard", "/job/attack"] {
            let mut value = attack_request();
            value.pointer_mut(parent).unwrap()["bad~/key"] = json!(true);
            assert_eq!(
                attack_error(&value),
                ("unknown_field".into(), format!("{parent}/bad~0~1key"))
            );
        }
        let mut value = attack_request();
        value["job"]["space"]
            .as_object_mut()
            .unwrap()
            .remove("plugboard");
        assert_eq!(
            attack_error(&value),
            ("invalid_request".into(), "/job/space/plugboard".into())
        );
    }

    #[test]
    fn private_attack_conflicts_and_structural_precedence() {
        for (pointer, replacement, code, location) in [
            (
                "/job/attack/seeds",
                json!({}),
                "invalid_request",
                "/job/attack/seeds",
            ),
            (
                "/job/space/plugboard/candidates",
                json!([]),
                "unknown_field",
                "/job/space/plugboard/candidates",
            ),
            (
                "/job/space/plugboard/size",
                json!(1),
                "unknown_field",
                "/job/space/plugboard/size",
            ),
            (
                "/job/space/plugboard/symbols",
                json!(["A", "A"]),
                "invalid_search_space",
                "/job/space/plugboard/symbols",
            ),
            (
                "/job/attack/start",
                json!([["A", "A"]]),
                "invalid_search_space",
                "/job/attack/start/0",
            ),
            (
                "/job/passes",
                json!(["hill_climb", "hill_climb"]),
                "invalid_request",
                "/job/passes/1",
            ),
            (
                "/job/measures",
                json!(["ic", "ic"]),
                "invalid_request",
                "/job/measures/1",
            ),
            (
                "/job/passes",
                json!(["partial_exhaustion"]),
                "invalid_request",
                "/job/attack/kind",
            ),
            (
                "/job/passes",
                json!(["hill_climb", "partial_exhaustion"]),
                "unsupported_pass",
                "/job/passes",
            ),
            (
                "/job/passes",
                json!(["reswapping"]),
                "unsupported_pass",
                "/job/passes",
            ),
            (
                "/job/passes",
                json!(["unknown"]),
                "unsupported_pass",
                "/job/passes",
            ),
        ] {
            let mut value = attack_request();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            value.pointer_mut(parent).unwrap()[key] = replacement;
            assert_eq!(attack_error(&value), (code.into(), location.into()));
        }
        let mut value = attack_request();
        value["job"]["passes"] = json!(["unknown"]);
        value["job"]["resources"] = json!({"ic": {"path": "unused"}});
        value["job"]["configuration"]["slots"] = json!([]);
        assert_eq!(
            attack_error(&value),
            ("invalid_search_space".into(), "/job/space/slots".into())
        );
        value["job"]["configuration"] = attack_request()["job"]["configuration"].clone();
        value["job"]["space"]["plugboard"]["max_pairs"] = json!(3);
        assert_eq!(
            attack_error(&value),
            (
                "invalid_search_space".into(),
                "/job/space/plugboard/max_pairs".into()
            )
        );
        value["job"]["space"] = attack_request()["job"]["space"].clone();
        assert_eq!(
            attack_error(&value),
            ("unsupported_pass".into(), "/job/passes".into())
        );
        value["job"]["measures"] = json!(["unknown"]);
        assert_eq!(
            attack_error(&value),
            ("unsupported_measure".into(), "/job/measures/0".into())
        );
        value = attack_request();
        value["job"]["resources"] = json!({"ic": {"path": "unused"}});
        value["job"]["attack"]["progress_every"] = json!(0);
        assert_eq!(
            attack_error(&value),
            (
                "invalid_request".into(),
                "/job/attack/progress_every".into()
            )
        );
    }

    #[test]
    fn progress_every_full_and_detached_validation() {
        for pe in [false, true] {
            let mut value = attack_request();
            if pe {
                value["job"]["passes"] = json!(["partial_exhaustion"]);
                let attack = value["job"]["attack"].as_object_mut().unwrap();
                attack.insert("kind".into(), json!("partial_exhaustion"));
                attack.remove("start");
                attack.insert(
                    "seeds".into(),
                    json!({"kind":"empty_single", "selection":"all"}),
                );
            }
            let parsed = ParsedAttackRequest::parse_json(&value.to_string()).unwrap();
            assert_eq!(parsed.settings.progress_every(), 100_000);
            let detached = |attack: &str| {
                AttackSettings::parse_json(
                    parsed.carrier.definition().alphabet(),
                    &parsed.domain,
                    parsed.carrier.passes(),
                    parsed.carrier.measures(),
                    attack,
                )
            };
            assert_eq!(
                detached(&value["job"]["attack"].to_string())
                    .unwrap()
                    .progress_every(),
                100_000
            );
            for raw in [
                "1",
                "18446744073709551615",
                "0",
                "-1",
                "-0",
                "1.0",
                "1e0",
                "true",
                "\"1\"",
                "null",
                "[]",
                "{}",
                "18446744073709551616",
            ] {
                let attack = value["job"]["attack"].to_string();
                let attack = format!("{{\"progress_every\":{raw},{}", &attack[1..]);
                let full = value
                    .to_string()
                    .replace(&value["job"]["attack"].to_string(), &attack);
                let full = ParsedAttackRequest::parse_json(&full);
                let detached = detached(&attack);
                if let Ok(expected) = raw.parse::<u64>() {
                    if expected > 0 {
                        assert_eq!(full.unwrap().settings.progress_every(), expected);
                        assert_eq!(detached.unwrap().progress_every(), expected);
                        continue;
                    }
                }
                for error in [
                    full.unwrap_err().remove(0),
                    detached.unwrap_err().remove(0).into(),
                ] {
                    assert_eq!(
                        (error.code(), error.location()),
                        ("invalid_request", "/job/attack/progress_every"),
                        "{raw}"
                    );
                }
            }
            value["job"]["attack"]["progress_every"] = json!(0);
            value["job"]["attack"]["unknown"] = json!(true);
            assert_eq!(
                attack_error(&value),
                ("unknown_field".into(), "/job/attack/unknown".into())
            );
            let error = detached(&value["job"]["attack"].to_string())
                .unwrap_err()
                .remove(0);
            assert_eq!(
                (error.code(), error.location()),
                ("unknown_field", "/job/attack/unknown")
            );
        }
    }

    #[test]
    fn private_attack_strict_root_and_public_isolation() {
        let raw = attack_request().to_string();
        for needle in [
            "\"protocol_version\":1",
            "\"max_pairs\":2",
            "\"switch_pairs\":1",
        ] {
            let duplicate = raw.replace(needle, &format!("{needle},{needle}"));
            let error = ParsedAttackRequest::parse_json(&duplicate)
                .unwrap_err()
                .remove(0);
            assert_eq!((error.code(), error.location()), ("invalid_json", ""));
        }
        for malformed in [format!("{raw} true"), "[]".into(), "{".into()] {
            let error = ParsedAttackRequest::parse_json(&malformed)
                .unwrap_err()
                .remove(0);
            let expected = if malformed == "[]" {
                "invalid_request"
            } else {
                "invalid_json"
            };
            assert_eq!((error.code(), error.location()), (expected, ""));
        }
        let oversized = format!("{raw}{}", " ".repeat(crate::MAX_REQUEST_BYTES));
        let error = ParsedAttackRequest::parse_json(&oversized)
            .unwrap_err()
            .remove(0);
        assert_eq!((error.code(), error.location()), ("resource_limit", ""));
        for (pointer, replacement, code, location) in [
            ("/machine", json!([]), "invalid_request", "/machine"),
            (
                "/protocol_version",
                json!(2),
                "unsupported_version",
                "/protocol_version",
            ),
        ] {
            let mut value = attack_request();
            *value.pointer_mut(pointer).unwrap() = replacement;
            value["job"] = json!(null);
            assert_eq!(attack_error(&value), (code.into(), location.into()));
        }
        assert!(ParsedSearchRequest::parse_json(&raw).is_err());
        assert!(SearchRequest::parse_json(&raw).is_err());
        assert!(matches!(
            crate::ParsedRequest::parse_json(&raw),
            Ok(crate::ParsedRequest::Attack(_))
        ));
    }

    #[test]
    fn private_attack_complete_seed_diagnostics() {
        let mut base = attack_request();
        base["job"]["passes"] = json!(["partial_exhaustion"]);
        base["job"]["attack"]
            .as_object_mut()
            .unwrap()
            .remove("start");
        base["job"]["attack"]["kind"] = json!("partial_exhaustion");
        base["job"]["attack"]["seeds"] =
            json!({"kind": "empty_single", "selection": "touching", "symbols": ["C", "D"]});
        for key in ["seeds", "kind", "selection", "symbols"] {
            let mut value = base.clone();
            let parent = if key == "seeds" {
                "/job/attack"
            } else {
                "/job/attack/seeds"
            };
            value
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert_eq!(
                attack_error(&value),
                ("invalid_request".into(), format!("{parent}/{key}"))
            );
        }
        for (key, replacement, code, location) in [
            (
                "kind",
                json!("other"),
                "invalid_request",
                "/job/attack/seeds/kind",
            ),
            (
                "selection",
                json!("other"),
                "invalid_request",
                "/job/attack/seeds/selection",
            ),
            (
                "symbols",
                json!(["C", "C"]),
                "invalid_search_space",
                "/job/attack/seeds/symbols/1",
            ),
            (
                "bad~/key",
                json!(true),
                "unknown_field",
                "/job/attack/seeds/bad~0~1key",
            ),
        ] {
            let mut value = base.clone();
            value["job"]["attack"]["seeds"][key] = replacement;
            assert_eq!(attack_error(&value), (code.into(), location.into()));
        }
        let mut value = base.clone();
        value["job"]["attack"]["start"] = json!([]);
        assert_eq!(
            attack_error(&value),
            ("invalid_request".into(), "/job/attack/start".into())
        );
        value = base.clone();
        value["job"]["attack"]["seeds"]["selection"] = json!("all");
        assert_eq!(
            attack_error(&value),
            ("invalid_request".into(), "/job/attack/seeds/symbols".into())
        );
        let raw = base.to_string();
        let needle = "\"selection\":\"touching\"";
        let duplicate = raw.replace(needle, &format!("{needle},{needle}"));
        let error = ParsedAttackRequest::parse_json(&duplicate)
            .unwrap_err()
            .remove(0);
        assert_eq!((error.code(), error.location()), ("invalid_json", ""));
    }

    #[test]
    fn private_attack_root_definition_and_exact_raw_ceiling() {
        let raw = attack_request().to_string();
        let at_limit = format!("{raw}{}", " ".repeat(crate::MAX_REQUEST_BYTES - raw.len()));
        assert_eq!(at_limit.len(), crate::MAX_REQUEST_BYTES);
        assert!(ParsedAttackRequest::parse_json(&at_limit).is_ok());
        let error = ParsedAttackRequest::parse_json(&format!("{at_limit} "))
            .unwrap_err()
            .remove(0);
        assert_eq!((error.code(), error.location()), ("resource_limit", ""));
        for (parent, key) in [
            ("", "protocol_version"),
            ("", "machine"),
            ("", "job"),
            ("/machine", "definition"),
        ] {
            let mut value = attack_request();
            value
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert_eq!(
                attack_error(&value),
                ("invalid_request".into(), format!("{parent}/{key}"))
            );
        }
        for parent in ["", "/machine"] {
            let mut value = attack_request();
            value.pointer_mut(parent).unwrap()["bad~/key"] = json!(true);
            assert_eq!(
                attack_error(&value),
                ("unknown_field".into(), format!("{parent}/bad~0~1key"))
            );
        }
        for replacement in [json!(null), json!([]), json!({})] {
            let mut value = attack_request();
            value["job"] = replacement;
            assert_eq!(
                attack_error(&value),
                (
                    "invalid_request".into(),
                    if value["job"].is_object() {
                        "/job/kind"
                    } else {
                        "/job"
                    }
                    .into()
                )
            );
        }
        let mut value = attack_request();
        value["machine"]["definition"] = json!({"kind": "bundled", "id": "not-bundled"});
        value["job"] = json!(null);
        let legacy = ParsedSearchRequest::parse_json(&value.to_string()).unwrap_err();
        let attack = ParsedAttackRequest::parse_json(&value.to_string()).unwrap_err();
        assert_eq!(attack, legacy);
        assert!(!attack[0].location().starts_with("/job"));
        value["machine"]["definition"] = json!({"kind": "custom", "value": {}});
        assert_eq!(
            ParsedAttackRequest::parse_json(&value.to_string()).unwrap_err(),
            ParsedSearchRequest::parse_json(&value.to_string()).unwrap_err()
        );
        value = attack_request();
        value["protocol_version"] = json!("1");
        assert_eq!(
            attack_error(&value),
            ("invalid_request".into(), "/protocol_version".into())
        );
        value = attack_request();
        value["job"]["kind"] = json!("attack");
        assert_eq!(
            attack_error(&value),
            ("unsupported_job".into(), "/job/kind".into())
        );
    }

    fn carrier(
        value: &Value,
        branch: PlugboardConstruction,
    ) -> Result<ParsedSearchRequest, Vec<SearchDiagnostic>> {
        let definition = parse(&base_request()).unwrap().definition().clone();
        parse_search_carrier(&definition, value["job"].as_object().unwrap(), branch)
    }

    #[test]
    fn slot_only_retains_ordered_facts_without_consuming_attack_data() {
        let mut value = base_request();
        value["job"]["configuration"]["slots"] = json!([
            {"id": "fast", "wheel": "rotor2"},
            {"id": "ukw", "position": "B", "ring": "C"}
        ]);
        value["job"]["configuration"]["plugboard"] = json!([["D", "C"], ["B", "A"]]);
        value["job"]["space"] = json!({
            "slots": [{"id": "fast", "positions": ["D", "B"], "rings": ["C", "A"]}],
            "plugboard": {"kind": "attack", "deliberately_unvalidated": true},
            "offset": 7,
            "limit": 3
        });
        value["job"]["attack"] = json!({"also_unvalidated": true});
        value["job"]["measures"] = json!(["trie"]);
        value["job"]["resources"] = json!({"trie": {"path": "model.json"}});
        let original = value.clone();
        let request = carrier(&value, PlugboardConstruction::SlotOnly).unwrap();
        assert_eq!(value, original);
        assert_eq!(request.configuration.slots()[0].id(), "fast");
        assert_eq!(request.configuration.slots()[0].wheel(), Some("rotor2"));
        assert_eq!(request.configuration.slots()[1].position(), Some('B'));
        assert_eq!(request.configuration.plugboard(), [('D', 'C'), ('B', 'A')]);
        assert_eq!(request.space.slots()[0].positions().unwrap(), ['D', 'B']);
        assert_eq!(request.space.slots()[0].rings().unwrap(), ['C', 'A']);
        assert_eq!(request.space.offset(), 7);
        assert_eq!(request.space.limit(), Some(3));
        assert!(request.space.plugboard().is_none());
        assert_eq!(request.resources()[0].path(), "model.json");
        assert_eq!(errors(&value)[0].code(), "unknown_field");
    }

    #[test]
    fn slot_only_coverage_and_structural_errors_are_pinned() {
        for (configuration, domains, message, location) in [
            (
                json!([{"id": "ukw", "ring": "A"}]),
                json!([]),
                "slot \"ukw\" position is neither fixed in configuration nor declared in space.slots; add exactly one path",
                "/job/space/slots",
            ),
            (
                json!([{"id": "ukw", "position": "A"}]),
                json!([]),
                "slot \"ukw\" ring is neither fixed in configuration nor declared in space.slots; add exactly one path",
                "/job/space/slots",
            ),
            (
                json!([{"id": "ukw", "position": "A", "ring": "A"}, {"id": "fast", "position": "A", "ring": "A"}]),
                json!([]),
                "slot \"fast\" wheels is neither fixed in configuration nor declared in space.slots; add exactly one path",
                "/job/space/slots",
            ),
            (
                base_request()["job"]["configuration"]["slots"].clone(),
                json!([{"id": "ukw", "positions": ["B"]}]),
                "slot \"ukw\" position is covered twice: fixed in configuration and declared in space.slots; keep exactly one path",
                "/job/space/slots/0/positions",
            ),
        ] {
            let mut value = base_request();
            value["job"]["configuration"]["slots"] = configuration;
            value["job"]["space"]["slots"] = domains;
            let error = carrier(&value, PlugboardConstruction::SlotOnly).unwrap_err().remove(0);
            assert_eq!((error.code(), error.message(), error.location()), ("invalid_search_space", message, location));
        }
        let mut value = base_request();
        value["job"]["space"]["slots"] = json!([{"id": "ukw", "wheels": ["reflector"]}]);
        let error = carrier(&value, PlugboardConstruction::SlotOnly)
            .unwrap_err()
            .remove(0);
        assert_eq!(error.code(), "invalid_search_space");
        assert_eq!(error.location(), "/job/space/slots/0/wheels");
        assert_eq!(error.message(), "slot \"ukw\" has a structurally fixed wheel; space.slots must not declare `wheels` for it");
    }

    #[test]
    fn carrier_branches_preserve_shared_diagnostic_precedence() {
        for (member, replacement, code, location) in [
            ("text", json!("AZ"), "invalid_text", "/job/text"),
            ("passes", json!([]), "invalid_request", "/job/passes"),
            (
                "passes",
                json!(["not_a_pass"]),
                "unsupported_pass",
                "/job/passes/0",
            ),
            (
                "measures",
                json!(["not_a_measure"]),
                "unsupported_measure",
                "/job/measures/0",
            ),
            (
                "measures",
                json!(["trie"]),
                "unsupported_resource",
                "/job/resources/trie/path",
            ),
            ("text", json!("A"), "invalid_text", "/job/text"),
        ] {
            let mut value = base_request();
            value["job"][member] = replacement;
            let legacy = carrier(&value, PlugboardConstruction::LegacyPool).unwrap_err();
            let slot_only = carrier(&value, PlugboardConstruction::SlotOnly).unwrap_err();
            assert_eq!(legacy, slot_only);
            assert_eq!(
                (slot_only[0].code(), slot_only[0].location()),
                (code, location)
            );
        }
        let mut value = base_request();
        value["job"]["text"] = json!("Z");
        value["job"]["passes"] = json!([]);
        let error = carrier(&value, PlugboardConstruction::SlotOnly)
            .unwrap_err()
            .remove(0);
        assert_eq!(
            (error.code(), error.location()),
            ("invalid_request", "/job/passes")
        );
    }

    #[test]
    fn slot_only_preserves_wheel_order_and_unicode_scalar_minima() {
        let mut value = base_request();
        value["job"]["configuration"]["slots"] = json!([
            {"id": "ukw", "position": "A", "ring": "A"},
            {"id": "fast", "position": "B", "ring": "A"}
        ]);
        value["job"]["space"]["slots"] = json!([{"id": "fast", "wheels": ["rotor2", "rotor1"]}]);
        let request = carrier(&value, PlugboardConstruction::SlotOnly).unwrap();
        assert_eq!(
            request.space.slots()[0].wheels().unwrap(),
            ["rotor2", "rotor1"]
        );

        let mut unicode: Value =
            serde_json::from_str(&base_request().to_string().replace("\"A\"", "\"é\"")).unwrap();
        unicode["job"]["text"] = json!("éB");
        let definition = parse(&unicode).unwrap().definition().clone();
        let mut job = unicode["job"].as_object().unwrap().clone();
        for branch in [
            PlugboardConstruction::LegacyPool,
            PlugboardConstruction::SlotOnly,
        ] {
            job.insert("text".to_owned(), json!("é"));
            let error = parse_search_carrier(&definition, &job, branch)
                .unwrap_err()
                .remove(0);
            assert_eq!(
                (error.code(), error.location()),
                ("invalid_text", "/job/text")
            );
            assert_eq!(error.message(), "ic requires at least 2 Unicode scalars");
            job.insert("text".to_owned(), json!("éé"));
            assert!(parse_search_carrier(&definition, &job, branch).is_ok());
        }
    }

    #[test]
    fn legacy_carrier_keeps_pool_order_size_and_overlap_diagnostics() {
        let mut value = base_request();
        value["job"]["space"]["plugboard"] =
            json!({"candidates": [["D", "C"], ["B", "A"]], "size": 2});
        let request = carrier(&value, PlugboardConstruction::LegacyPool).unwrap();
        let pool = request.space.plugboard().unwrap();
        assert_eq!(pool.candidates(), [('D', 'C'), ('B', 'A')]);
        assert_eq!(pool.size(), 2);
        value["job"]["configuration"]["plugboard"] = json!([["A", "B"]]);
        let error = carrier(&value, PlugboardConstruction::LegacyPool)
            .unwrap_err()
            .remove(0);
        assert_eq!(error.code(), "invalid_search_space");
        assert_eq!(error.location(), "/job/space/plugboard/candidates/1");
        assert_eq!(error.message(), "space.plugboard candidate pair shares a symbol with a known fixed configuration pair; fixed and searched pairs must be disjoint");
        assert!(carrier(&value, PlugboardConstruction::SlotOnly).is_ok());
        value["job"]["space"]["plugboard"]["size"] = json!(0);
        let error = carrier(&value, PlugboardConstruction::LegacyPool)
            .unwrap_err()
            .remove(0);
        assert_eq!(error.code(), "invalid_request");
        assert_eq!(error.location(), "/job/space/plugboard/size");
        assert_eq!(error.message(), "size must be a positive integer");
        value["job"]["configuration"]["plugboard"] = json!([["A", "A"]]);
        assert!(carrier(&value, PlugboardConstruction::SlotOnly).is_err());
    }

    fn parse(value: &Value) -> Result<SearchRequest, Vec<RequestDiagnostic>> {
        SearchRequest::parse_json(&value.to_string())
    }

    fn errors(value: &Value) -> Vec<RequestDiagnostic> {
        parse(value).unwrap_err()
    }

    #[test]
    fn fully_variable_search_parses_end_to_end() {
        let mut value = base_request();
        value["job"]["configuration"]["slots"] = json!([{"id": "ukw"}, {"id": "fast"}]);
        value["job"]["space"]["slots"] = json!([
            {"id": "ukw", "positions": ["A"], "rings": ["A"]},
            {"id": "fast", "wheels": ["rotor1", "rotor2"], "positions": ["A", "B"], "rings": ["A", "B"]}
        ]);
        value["job"]["space"]["plugboard"] = json!({
            "candidates": [["A", "B"], ["C", "D"]],
            "size": 1
        });
        value["job"]["space"]["offset"] = json!(1);
        value["job"]["space"]["limit"] = json!(10);

        let request = parse(&value).unwrap();
        assert_eq!(request.configuration().slots().len(), 2);
        assert_eq!(request.configuration().slots()[0].id(), "ukw");
        assert_eq!(request.configuration().slots()[0].position(), None);
        assert_eq!(request.space().slots().len(), 2);
        assert_eq!(request.space().slots()[1].id(), "fast");
        assert_eq!(
            request.space().slots()[1].wheels().unwrap(),
            ["rotor1", "rotor2"]
        );
        assert_eq!(request.space().slots()[1].positions().unwrap(), ['A', 'B']);
        assert_eq!(request.space().plugboard().unwrap().size(), 1);
        assert_eq!(request.space().offset(), 1);
        assert_eq!(request.space().limit(), Some(10));
    }

    #[test]
    fn partially_fixed_search_parses_end_to_end() {
        let mut value = base_request();
        value["job"]["configuration"]["slots"] = json!([
            {"id": "ukw", "position": "A", "ring": "A"},
            {"id": "fast", "wheel": "rotor1"}
        ]);
        value["job"]["space"]["slots"] =
            json!([{"id": "fast", "positions": ["A", "B"], "rings": ["A"]}]);

        let request = parse(&value).unwrap();
        let fast = &request.configuration().slots()[1];
        assert_eq!(fast.id(), "fast");
        assert_eq!(fast.wheel(), Some("rotor1"));
        assert_eq!(fast.position(), None);
        assert_eq!(fast.ring(), None);
        let domain = &request.space().slots()[0];
        assert_eq!(domain.id(), "fast");
        assert_eq!(domain.wheels(), None);
        assert_eq!(domain.positions().unwrap(), ['A', 'B']);
    }

    #[test]
    fn coverage_missing_position_is_invalid_search_space() {
        let mut value = base_request();
        value["job"]["configuration"]["slots"] = json!([{"id": "ukw"}, {"id": "fast"}]);
        value["job"]["space"]["slots"] = json!([
            {"id": "ukw", "rings": ["A"]},
            {"id": "fast", "wheels": ["rotor1"], "rings": ["A"]}
        ]);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert!(diagnostic.message().contains("ukw"));
        assert!(diagnostic.message().contains("position"));
    }

    #[test]
    fn coverage_missing_ring_is_invalid_search_space() {
        let mut value = base_request();
        value["job"]["configuration"]["slots"] = json!([{"id": "ukw"}, {"id": "fast"}]);
        value["job"]["space"]["slots"] = json!([
            {"id": "ukw", "positions": ["A"]},
            {"id": "fast", "wheels": ["rotor1"], "positions": ["A"]}
        ]);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert!(diagnostic.message().contains("ukw"));
        assert!(diagnostic.message().contains("ring"));
    }

    #[test]
    fn coverage_fixed_and_declared_position_conflicts() {
        let mut value = base_request();
        value["job"]["space"]["slots"] = json!([{"id": "ukw", "positions": ["B"]}]);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/0/positions");
    }

    #[test]
    fn declared_wheels_on_structurally_fixed_slot_are_rejected() {
        let mut value = base_request();
        value["job"]["space"]["slots"] =
            json!([{"id": "ukw", "wheels": ["reflector"], "positions": ["A"], "rings": ["A"]}]);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/0/wheels");
    }

    #[test]
    fn wheels_outside_allowed_wheels_are_rejected() {
        let mut value = base_request();
        value["job"]["space"]["slots"] = json!([{"id": "fast", "wheels": ["reflector"]}]);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/0/wheels");
    }

    #[test]
    fn empty_and_duplicate_domain_arrays_are_rejected() {
        for (member, value) in [("positions", json!([])), ("rings", json!([]))] {
            let mut request = base_request();
            request["job"]["configuration"]["slots"] = json!([{"id": "ukw", "position": "A"}]);
            request["job"]["configuration"]["slots"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id": "fast", "wheel": "rotor1", "ring": "A"}));
            request["job"]["space"]["slots"] = json!([{"id": "ukw", member: value}]);
            let diagnostic = errors(&request).remove(0);
            assert_eq!(diagnostic.code(), "invalid_search_space");
            assert_eq!(
                diagnostic.location(),
                format!("/job/space/slots/0/{member}")
            );
        }

        let mut duplicate = base_request();
        duplicate["job"]["space"]["slots"] = json!([{"id": "fast", "positions": ["A", "A"]}]);
        let diagnostic = errors(&duplicate).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/0/positions");

        let mut empty_wheels = base_request();
        empty_wheels["job"]["space"]["slots"] = json!([{"id": "fast", "wheels": []}]);
        let diagnostic = errors(&empty_wheels).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/0/wheels");
    }

    #[test]
    fn duplicate_and_unknown_slot_ids_are_rejected() {
        let mut duplicate_config = base_request();
        duplicate_config["job"]["configuration"]["slots"] = json!([{"id": "ukw"}, {"id": "ukw"}]);
        let diagnostic = errors(&duplicate_config).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1/id");

        let mut unknown_config = base_request();
        unknown_config["job"]["configuration"]["slots"] = json!([{"id": "nope"}]);
        let diagnostic = errors(&unknown_config).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/0/id");

        let mut duplicate_space = base_request();
        duplicate_space["job"]["space"]["slots"] =
            json!([{"id": "fast", "positions": ["A"]}, {"id": "fast", "rings": ["A"]}]);
        let diagnostic = errors(&duplicate_space).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/1/id");

        let mut unknown_space = base_request();
        unknown_space["job"]["space"]["slots"] = json!([{"id": "nope", "positions": ["A"]}]);
        let diagnostic = errors(&unknown_space).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/0/id");
    }

    #[test]
    fn slot_domain_requires_at_least_one_member() {
        let mut value = base_request();
        value["job"]["space"]["slots"] = json!([{"id": "fast"}]);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/slots/0");
    }

    #[test]
    fn plugboard_candidates_must_be_disjoint_from_fixed_pairs() {
        let mut value = base_request();
        value["job"]["configuration"]["plugboard"] = json!([["A", "B"]]);
        value["job"]["space"]["plugboard"] = json!({"candidates": [["A", "C"]], "size": 1});
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/plugboard/candidates/0");
    }

    #[test]
    fn plugboard_size_must_not_exceed_candidates() {
        let mut value = base_request();
        value["job"]["space"]["plugboard"] = json!({"candidates": [["A", "B"]], "size": 2});
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_search_space");
        assert_eq!(diagnostic.location(), "/job/space/plugboard/size");

        let mut zero = base_request();
        zero["job"]["space"]["plugboard"] = json!({"candidates": [["A", "B"]], "size": 0});
        let diagnostic = errors(&zero).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/space/plugboard/size");
    }

    #[test]
    fn plugboard_candidate_pairs_are_validated() {
        let mut self_pair = base_request();
        self_pair["job"]["space"]["plugboard"] = json!({"candidates": [["A", "A"]], "size": 1});
        let diagnostic = errors(&self_pair).remove(0);
        assert_eq!(diagnostic.code(), "invalid_plugboard");
        assert_eq!(diagnostic.location(), "/job/space/plugboard/candidates/0");

        let mut unknown = base_request();
        unknown["job"]["space"]["plugboard"] = json!({"candidates": [["A", "Z"]], "size": 1});
        let diagnostic = errors(&unknown).remove(0);
        assert_eq!(diagnostic.code(), "invalid_symbol");
        assert_eq!(diagnostic.location(), "/job/space/plugboard/candidates/0");
    }

    #[test]
    fn offset_defaults_to_zero_and_explicit_limit_parses() {
        let request = parse(&base_request()).unwrap();
        assert_eq!(request.space().offset(), 0);
        assert_eq!(request.space().limit(), None);

        let mut explicit = base_request();
        explicit["job"]["space"]["offset"] = json!(2);
        explicit["job"]["space"]["limit"] = json!(5);
        let request = parse(&explicit).unwrap();
        assert_eq!(request.space().offset(), 2);
        assert_eq!(request.space().limit(), Some(5));
    }

    #[test]
    fn negative_offset_and_non_positive_limit_are_rejected() {
        let mut offset = base_request();
        offset["job"]["space"]["offset"] = json!(-1);
        let diagnostic = errors(&offset).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/space/offset");

        let mut limit = base_request();
        limit["job"]["space"]["limit"] = json!(0);
        let diagnostic = errors(&limit).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/space/limit");
    }

    #[test]
    fn passes_empty_or_duplicate_are_rejected() {
        let mut empty = base_request();
        empty["job"]["passes"] = json!([]);
        let diagnostic = errors(&empty).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/passes");

        let mut duplicate = base_request();
        duplicate["job"]["passes"] = json!(["hill_climb", "hill_climb"]);
        let diagnostic = errors(&duplicate).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/passes/1");
    }

    #[test]
    fn measures_empty_or_duplicate_are_rejected() {
        let mut empty = base_request();
        empty["job"]["measures"] = json!([]);
        let diagnostic = errors(&empty).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/measures");

        let mut duplicate = base_request();
        duplicate["job"]["measures"] = json!(["entropy", "entropy"]);
        let diagnostic = errors(&duplicate).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/measures/1");
    }

    #[test]
    fn resources_must_be_an_object_when_present() {
        let mut bad = base_request();
        bad["job"]["resources"] = json!(5);
        let diagnostic = errors(&bad).remove(0);
        assert_eq!(diagnostic.code(), "unsupported_resource");
        assert_eq!(diagnostic.location(), "/job/resources");

        let mut ok = base_request();
        ok["job"]["resources"] = json!({});
        let request = parse(&ok).unwrap();
        assert!(request.resources().is_empty());
    }

    #[test]
    fn unknown_fields_at_space_and_slot_domain_are_unknown_field() {
        let mut space = base_request();
        space["job"]["space"]["bogus"] = json!(1);
        let diagnostic = errors(&space).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/job/space/bogus");

        let mut domain = base_request();
        domain["job"]["space"]["slots"] = json!([{"id": "fast", "positions": ["A"], "bogus": 1}]);
        let diagnostic = errors(&domain).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/job/space/slots/0/bogus");
    }

    #[test]
    fn configuration_fixed_facts_are_checked_for_admissibility() {
        let mut bad_symbol = base_request();
        bad_symbol["job"]["configuration"]["slots"] = json!([
            {"id": "ukw", "position": "Z", "ring": "A"},
            {"id": "fast", "wheel": "rotor1", "position": "B", "ring": "A"}
        ]);
        let diagnostic = errors(&bad_symbol).remove(0);
        assert_eq!(diagnostic.code(), "invalid_symbol");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/0/position");

        let mut bad_wheel = base_request();
        bad_wheel["job"]["configuration"]["slots"][1]["wheel"] = json!("reflector");
        let diagnostic = errors(&bad_wheel).remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1/wheel");
    }

    #[test]
    fn non_search_kind_is_unsupported_job() {
        let mut value = base_request();
        value["job"]["kind"] = json!("transform");
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "unsupported_job");
        assert_eq!(diagnostic.location(), "/job/kind");
    }

    #[test]
    fn text_symbols_outside_the_alphabet_are_rejected() {
        let mut value = base_request();
        value["job"]["text"] = json!("AZ");
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_text");
        assert_eq!(diagnostic.location(), "/job/text");
    }
}
