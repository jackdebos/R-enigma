//! Typed search-space model, strict parser, and coverage validation (Task 9, slice 9.2).
//!
//! The frozen grammar lives in `docs/protocol.md` §3.2/§3.3. Candidate enumeration
//! (slice 9.3) and the capability/preflight framework (slice 9.4) are out of scope here;
//! this module only models the explicit variable domains, its known fixed facts, the
//! boundary fields (`passes`, `measures`, optional `resources`), and validates that every
//! required key dimension is covered exactly once.

use crate::capability::Capabilities;
use crate::definition::Definition;
use crate::request::{parse_root, RequestDiagnostic};
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
/// Every structure, symbol, symbol domain, plugboard pair, and coverage rule was checked
/// here before the transport may emit `started`. Candidate enumeration is lazy in
/// `candidate.rs`, and capability preflight runs in `parse_search_job` before this value
/// is returned; this type owns only the validated explicit inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRequest {
    definition: Definition,
    text: String,
    configuration: SearchConfiguration,
    space: SearchSpace,
    passes: Vec<String>,
    measures: Vec<String>,
    resources: Option<Value>,
}

impl SearchRequest {
    /// Parses and fully validates a `kind: "search"` JSON request.
    ///
    /// Validation order mirrors the protocol: shared root and definition, then the
    /// search-job exact fields, then configuration and space structure and symbols, then
    /// coverage/conflict rules. A non-search job kind is `unsupported_job` at
    /// `/job/kind`. Nothing is defaulted; an uncovered required dimension is an error.
    pub fn parse_json(json: &str) -> Result<Self, Vec<RequestDiagnostic>> {
        let root = parse_root(json)?;
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

    /// Requested measure identifiers, in source order.
    pub fn measures(&self) -> &[String] {
        &self.measures
    }

    /// The opaque, optional `resources` object; its grammar is Task 10.
    pub fn resources(&self) -> Option<&Value> {
        self.resources.as_ref()
    }
}

fn parse_search_job(
    definition: &Definition,
    job: &Value,
) -> Result<SearchRequest, Vec<SearchDiagnostic>> {
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

    let configuration = parse_configuration(definition, required(job, "configuration", "/job")?)?;
    let space = parse_space(definition, required(job, "space", "/job")?)?;
    let text = required_string(job, "text", "/job")?;
    let passes = parse_identifier_array(job, "passes", "/job")?;
    let measures = parse_identifier_array(job, "measures", "/job")?;
    let resources = match job.get("resources") {
        Some(value) => {
            if !value.is_object() {
                return Err(vec![invalid(
                    "resources must be a JSON object when present",
                    "/job/resources",
                )]);
            }
            Some(value.clone())
        }
        None => None,
    };

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

    let request = SearchRequest {
        definition: definition.clone(),
        text: text.to_owned(),
        configuration,
        space,
        passes,
        measures,
        resources,
    };
    // The preflight error type is exactly this function's `Vec<SearchDiagnostic>` error
    // type, so propagate it explicitly without relying on a `?` conversion.
    if let Err(diagnostics) = Capabilities::stage1().preflight(&request) {
        return Err(diagnostics);
    }
    Ok(request)
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

    let plugboard = match space.get("plugboard") {
        Some(value) => Some(parse_plugboard_domain(
            definition.alphabet(),
            value,
            &child(path, "plugboard"),
        )?),
        None => None,
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
                "measures": ["index_of_coincidence"]
            }
        })
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
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/resources");

        let mut ok = base_request();
        ok["job"]["resources"] = json!({"threads": 4});
        let request = parse(&ok).unwrap();
        assert!(request.resources().is_some());
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
