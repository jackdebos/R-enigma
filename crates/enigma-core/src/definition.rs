//! Strict, key-free JSON machine definitions shared by bundled and custom sources.

use crate::strict_json::StrictValue;
use crate::{
    Alphabet, MachineTopology, ModelError, Movement, SlotRole, StepCondition, StepRule, Stepping,
    Wiring, MAX_STEP_CONDITION_DEPTH, MAX_STEP_CONDITION_NODES, MAX_STEP_RULES, MAX_STEP_TARGETS,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fmt;

/// Maximum encoded JSON size accepted for a definition.
pub const MAX_DEFINITION_BYTES: usize = 1_048_576;
/// Maximum number of symbols in a definition alphabet.
pub const MAX_DEFINITION_ALPHABET: usize = 256;
/// Maximum number of declared wheels.
pub const MAX_DEFINITION_WHEELS: usize = 256;
/// Maximum number of physical slots (well above the six-slot capacity requirement).
pub const MAX_DEFINITION_SLOTS: usize = 64;

/// A localized, actionable definition-ingestion diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefinitionDiagnostic {
    code: &'static str,
    message: String,
    location: String,
}

impl DefinitionDiagnostic {
    fn new(code: &'static str, message: impl Into<String>, location: impl Into<String>) -> Self {
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
    /// RFC 6901 JSON Pointer to the invalid value or containing object.
    pub fn location(&self) -> &str {
        &self.location
    }
}

impl fmt::Display for DefinitionDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.code, self.location, self.message)
    }
}

impl std::error::Error for DefinitionDiagnostic {}

/// Parsed definition source; only bundled names present in the sourced catalog resolve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DefinitionSource {
    /// A catalog alias, resolved only when a bundled catalog entry exists.
    Bundled {
        /// Catalog alias to resolve.
        id: String,
    },
    /// An embedded strict machine definition.
    Custom(Definition),
}

impl DefinitionSource {
    /// Parses a strict `{"kind":"bundled","id":...}` or
    /// `{"kind":"custom","value":...}` source object.
    pub fn parse_json(json: &str) -> Result<Self, Vec<DefinitionDiagnostic>> {
        if json.len() > MAX_DEFINITION_BYTES {
            return Err(vec![limit(
                "definition JSON exceeds the 1 MiB resource limit",
                "",
            )]);
        }
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let parsed = StrictValue::deserialize(&mut deserializer).map_err(|error| {
            vec![DefinitionDiagnostic::new(
                "invalid_json",
                format!("invalid JSON: {error}"),
                "",
            )]
        })?;
        deserializer.end().map_err(|error| {
            vec![DefinitionDiagnostic::new(
                "invalid_json",
                format!("invalid JSON: {error}"),
                "",
            )]
        })?;
        Self::parse_value(parsed.into_value())
    }

    /// Parses an already-deserialized definition source object.
    ///
    /// This is the object-validation half of [`DefinitionSource::parse_json`], exposed
    /// so callers that already hold a strict JSON tree (for example the request parser)
    /// can validate a `machine.definition` value without re-serializing it. The value
    /// must be the `{"kind": ...}` source union; diagnostics use root-relative JSON
    /// Pointers, with `""` denoting the source object itself.
    pub fn parse_value(value: Value) -> Result<Self, Vec<DefinitionDiagnostic>> {
        let object = object(&value, "")?;
        let kind = required_string(object, "kind", "")?;
        match kind {
            "bundled" => {
                exact_keys(object, &["kind", "id"], "")?;
                let id = required_string(object, "id", "")?;
                if id.is_empty() {
                    return Err(vec![invalid("bundled id must not be empty", "/id")]);
                }
                Ok(Self::Bundled { id: id.to_owned() })
            }
            "custom" => {
                exact_keys(object, &["kind", "value"], "")?;
                let definition = parse_definition(required(object, "value", "")?, "/value")?;
                Ok(Self::Custom(definition))
            }
            other => Err(vec![invalid(
                format!("unknown definition kind {other:?}; expected `bundled` or `custom`"),
                "/kind",
            )]),
        }
    }

    /// Resolves the source to its key-free definition using the custom validation path.
    pub fn resolve(self) -> Result<Definition, Vec<DefinitionDiagnostic>> {
        match self {
            Self::Custom(definition) => Ok(definition),
            Self::Bundled { id } => {
                let Some(json) = bundled_catalog_json(&id) else {
                    return Err(vec![DefinitionDiagnostic::new(
                        "unknown_bundled_definition",
                        format!("bundled definition {id:?} is unavailable; only catalog entries explicitly shipped by the engine can be used"),
                        "/id",
                    )]);
                };
                let tagged = format!(r#"{{"kind":"custom","value":{json}}}"#);
                match Self::parse_json(&tagged)? {
                    Self::Custom(definition) => Ok(definition),
                    Self::Bundled { .. } => {
                        unreachable!("catalog is wrapped as a custom definition")
                    }
                }
            }
        }
    }
}

/// The exact catalog JSON shipped for a bundled definition alias.
pub(crate) fn bundled_catalog_json(id: &str) -> Option<&'static str> {
    match id {
        "enigma-i" => Some(include_str!("../catalog/enigma-i.json")),
        "enigma-m3" => Some(include_str!("../catalog/enigma-m3.json")),
        "enigma-m4" => Some(include_str!("../catalog/enigma-m4.json")),
        "enigma-railway" => Some(include_str!("../catalog/enigma-railway.json")),
        "enigma-g312" => Some(include_str!("../catalog/enigma-g312.json")),
        "enigma-g260" => Some(include_str!("../catalog/enigma-g260.json")),
        _ => None,
    }
}

/// A validated machine structure with no active key or engine state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Definition {
    alphabet: Alphabet,
    wheels: Vec<Wiring>,
    slots: Vec<DefinitionSlot>,
    stepping_rules: Vec<StepRule>,
}

impl Definition {
    /// Ordered unique Unicode-scalar runtime alphabet.
    pub fn alphabet(&self) -> &Alphabet {
        &self.alphabet
    }
    /// Declared wheels in source order.
    pub fn wheels(&self) -> &[Wiring] {
        &self.wheels
    }
    /// Physical left-to-right slot admissibility constraints.
    pub fn slots(&self) -> &[DefinitionSlot] {
        &self.slots
    }
    /// Declarative stepping rules validated against this definition's slot constraints.
    pub fn stepping_rules(&self) -> &[StepRule] {
        &self.stepping_rules
    }

    /// Binds the definition's stepping rules to a concrete, resolved topology.
    ///
    /// This is intentionally performed after selecting every allowed wheel so the
    /// resulting rules are bound to the actual Task 6 machine rather than a placeholder.
    pub fn bind_stepping(&self, topology: &MachineTopology) -> Result<Stepping, ModelError> {
        Stepping::new(topology, self.stepping_rules.clone())
    }
}

/// A physical definition slot, separated from any runtime key selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefinitionSlot {
    id: String,
    role: SlotRole,
    movement: Movement,
    wheel: Option<String>,
    allowed_wheels: Vec<String>,
}

impl DefinitionSlot {
    /// Stable slot identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Slot role, independent of movement.
    pub fn role(&self) -> SlotRole {
        self.role
    }
    /// Whether a keypress may advance the slot.
    pub fn movement(&self) -> Movement {
        self.movement
    }
    /// Structurally fixed wheel, when present.
    pub fn wheel(&self) -> Option<&str> {
        self.wheel.as_deref()
    }
    /// Admissible runtime wheel choices for a variable slot.
    pub fn allowed_wheels(&self) -> &[String] {
        &self.allowed_wheels
    }
}

fn parse_definition(value: &Value, path: &str) -> Result<Definition, Vec<DefinitionDiagnostic>> {
    let root = object(value, path)?;
    exact_keys(root, &["alphabet", "wheels", "slots", "stepping"], path)?;

    let alphabet_path = child(path, "alphabet");
    let alphabet_values = array(required(root, "alphabet", path)?, &alphabet_path)?;
    if alphabet_values.len() > MAX_DEFINITION_ALPHABET {
        return Err(vec![limit(
            format!(
                "alphabet exceeds the {}-symbol limit",
                MAX_DEFINITION_ALPHABET
            ),
            alphabet_path,
        )]);
    }
    let mut symbols = Vec::with_capacity(alphabet_values.len());
    let mut unique_symbols = std::collections::HashSet::new();
    for (index, value) in alphabet_values.iter().enumerate() {
        let symbol_path = child(&alphabet_path, &index.to_string());
        let symbol = scalar(value, &symbol_path)?;
        if !unique_symbols.insert(symbol) {
            return Err(vec![invalid(
                format!("alphabet symbol {symbol:?} is duplicated"),
                symbol_path,
            )]);
        }
        symbols.push(symbol);
    }
    let alphabet =
        Alphabet::new(symbols).map_err(|error| vec![model_error(error, &alphabet_path)])?;

    let wheels_path = child(path, "wheels");
    let wheel_values = array(required(root, "wheels", path)?, &wheels_path)?;
    if wheel_values.is_empty() {
        return Err(vec![invalid(
            "at least one wheel must be declared",
            &wheels_path,
        )]);
    }
    if wheel_values.len() > MAX_DEFINITION_WHEELS {
        return Err(vec![limit(
            format!(
                "wheel count exceeds the {}-wheel limit",
                MAX_DEFINITION_WHEELS
            ),
            wheels_path,
        )]);
    }
    let mut wheels = Vec::with_capacity(wheel_values.len());
    let mut wheel_names = std::collections::HashSet::new();
    for (index, value) in wheel_values.iter().enumerate() {
        let wheel_path = child(&wheels_path, &index.to_string());
        let item = object(value, &wheel_path)?;
        exact_keys(item, &["name", "wiring", "turnovers"], &wheel_path)?;
        let name_path = child(&wheel_path, "name");
        let name = required_string(item, "name", &wheel_path)?;
        if name.is_empty() {
            return Err(vec![invalid("wheel name must not be empty", name_path)]);
        }
        if !wheel_names.insert(name.to_owned()) {
            return Err(vec![invalid(
                format!("wheel name {name:?} is duplicated"),
                name_path,
            )]);
        }
        let wiring_path = child(&wheel_path, "wiring");
        let wiring_values = array(required(item, "wiring", &wheel_path)?, &wiring_path)?;
        if wiring_values.len() != alphabet.len() {
            return Err(vec![invalid(
                format!(
                    "wiring has {} entries; expected {} alphabet symbols",
                    wiring_values.len(),
                    alphabet.len()
                ),
                &wiring_path,
            )]);
        }
        let mut mapping = Vec::with_capacity(wiring_values.len());
        let mut wiring_symbols = std::collections::HashSet::new();
        for (symbol_index, value) in wiring_values.iter().enumerate() {
            let symbol_path = child(&wiring_path, &symbol_index.to_string());
            let symbol = scalar(value, &symbol_path)?;
            if alphabet.index_of(symbol).is_none() {
                return Err(vec![invalid(
                    format!("wiring symbol {symbol:?} is outside the alphabet"),
                    symbol_path,
                )]);
            }
            if !wiring_symbols.insert(symbol) {
                return Err(vec![DefinitionDiagnostic::new(
                    "invalid_wiring",
                    format!("wiring output {symbol:?} is repeated"),
                    symbol_path,
                )]);
            }
            mapping.push(symbol);
        }
        let turnover_path = child(&wheel_path, "turnovers");
        let turnover_values = array(required(item, "turnovers", &wheel_path)?, &turnover_path)?;
        let mut turnovers = Vec::with_capacity(turnover_values.len());
        let mut turnover_symbols = std::collections::HashSet::new();
        for (symbol_index, value) in turnover_values.iter().enumerate() {
            let symbol_path = child(&turnover_path, &symbol_index.to_string());
            let symbol = scalar(value, &symbol_path)?;
            if alphabet.index_of(symbol).is_none() {
                return Err(vec![invalid(
                    format!("turnover symbol {symbol:?} is outside the alphabet"),
                    symbol_path,
                )]);
            }
            if !turnover_symbols.insert(symbol) {
                return Err(vec![invalid(
                    format!("turnover symbol {symbol:?} is duplicated"),
                    symbol_path,
                )]);
            }
            turnovers.push(symbol);
        }
        wheels.push(
            Wiring::new(name, &alphabet, &mapping, &turnovers)
                .map_err(|error| vec![model_error(error, &wheel_path)])?,
        );
    }

    let slots_path = child(path, "slots");
    let slot_values = array(required(root, "slots", path)?, &slots_path)?;
    if slot_values.is_empty() {
        return Err(vec![invalid("at least one slot is required", &slots_path)]);
    }
    if slot_values.len() > MAX_DEFINITION_SLOTS {
        return Err(vec![limit(
            format!("slot count exceeds the {}-slot limit", MAX_DEFINITION_SLOTS),
            slots_path,
        )]);
    }
    let mut slots = Vec::with_capacity(slot_values.len());
    let mut slot_ids = std::collections::HashSet::new();
    for (index, value) in slot_values.iter().enumerate() {
        let slot_path = child(&slots_path, &index.to_string());
        let item = object(value, &slot_path)?;
        let has_wheel = item.contains_key("wheel");
        let has_allowed = item.contains_key("allowed_wheels");
        if has_wheel == has_allowed {
            return Err(vec![invalid(
                "slot must contain exactly one of `wheel` or `allowed_wheels`",
                &slot_path,
            )]);
        }
        exact_keys(
            item,
            &[
                "id",
                "role",
                "movement",
                if has_wheel { "wheel" } else { "allowed_wheels" },
            ],
            &slot_path,
        )?;
        let id_path = child(&slot_path, "id");
        let id = required_string(item, "id", &slot_path)?;
        if id.is_empty() {
            return Err(vec![invalid("slot id must not be empty", id_path)]);
        }
        if !slot_ids.insert(id.to_owned()) {
            return Err(vec![invalid(
                format!("slot id {id:?} is duplicated"),
                id_path,
            )]);
        }
        let role_path = child(&slot_path, "role");
        let role = match required_string(item, "role", &slot_path)? {
            "rotor" => SlotRole::Rotor,
            "reflector" => SlotRole::Reflector,
            other => {
                return Err(vec![invalid(
                    format!("unknown slot role {other:?}; expected `rotor` or `reflector`"),
                    role_path,
                )])
            }
        };
        let movement_path = child(&slot_path, "movement");
        let movement = match required_string(item, "movement", &slot_path)? {
            "fixed" => Movement::Fixed,
            "movable" => Movement::Movable,
            other => {
                return Err(vec![invalid(
                    format!("unknown movement {other:?}; expected `fixed` or `movable`"),
                    movement_path,
                )])
            }
        };
        let (wheel, allowed_wheels) = if has_wheel {
            let wheel_path = child(&slot_path, "wheel");
            let name = required_string(item, "wheel", &slot_path)?;
            require_wheel(&wheel_names, name, &wheel_path)?;
            (Some(name.to_owned()), Vec::new())
        } else {
            let choices_path = child(&slot_path, "allowed_wheels");
            let values = array(required(item, "allowed_wheels", &slot_path)?, &choices_path)?;
            if values.is_empty() {
                return Err(vec![invalid(
                    "allowed_wheels must not be empty",
                    choices_path,
                )]);
            }
            let mut choices = Vec::with_capacity(values.len());
            let mut seen = std::collections::HashSet::new();
            for (choice_index, choice) in values.iter().enumerate() {
                let choice_path = child(&choices_path, &choice_index.to_string());
                let name = string(choice, &choice_path)?;
                require_wheel(&wheel_names, name, &choice_path)?;
                if !seen.insert(name) {
                    return Err(vec![invalid(
                        format!("allowed wheel {name:?} is duplicated"),
                        choice_path,
                    )]);
                }
                choices.push(name.to_owned());
            }
            (None, choices)
        };
        slots.push(DefinitionSlot {
            id: id.to_owned(),
            role,
            movement,
            wheel,
            allowed_wheels,
        });
    }
    validate_slot_structure(&slots, &alphabet, &wheels, &wheel_names, &slots_path)?;

    let stepping_path = child(path, "stepping");
    let stepping_value = required(root, "stepping", path)?;
    let stepping_object = object(stepping_value, &stepping_path)?;
    exact_keys(stepping_object, &["rules"], &stepping_path)?;
    let rules_path = child(&stepping_path, "rules");
    let rule_values = array(
        required(stepping_object, "rules", &stepping_path)?,
        &rules_path,
    )?;
    if rule_values.len() > MAX_STEP_RULES {
        return Err(vec![limit(
            format!("stepping rules exceed the {MAX_STEP_RULES}-rule limit"),
            rules_path,
        )]);
    }
    let mut rules = Vec::with_capacity(rule_values.len());
    let mut condition_nodes = 0;
    let mut advance_targets = std::collections::HashSet::new();
    for (index, value) in rule_values.iter().enumerate() {
        let rule_path = child(&rules_path, &index.to_string());
        let item = object(value, &rule_path)?;
        exact_keys(item, &["when", "advance"], &rule_path)?;
        let when_path = child(&rule_path, "when");
        let condition = parse_condition(
            required(item, "when", &rule_path)?,
            &when_path,
            1,
            &mut condition_nodes,
            &alphabet,
            &slot_ids,
        )?;
        let advance_path = child(&rule_path, "advance");
        let targets = array(required(item, "advance", &rule_path)?, &advance_path)?;
        let mut advance = Vec::with_capacity(targets.len());
        for (target_index, target) in targets.iter().enumerate() {
            let target_path = child(&advance_path, &target_index.to_string());
            let id = string(target, &target_path)?;
            let Some(slot) = slots.iter().find(|slot| slot.id == id) else {
                return Err(vec![invalid(
                    format!("unknown stepping slot {id:?}"),
                    target_path,
                )]);
            };
            if slot.movement != Movement::Movable {
                return Err(vec![invalid(
                    format!("stepping target {id:?} is fixed"),
                    target_path,
                )]);
            }
            let slot_index = slots
                .iter()
                .position(|candidate| candidate.id == id)
                .expect("slot reference checked");
            advance_targets.insert(slot_index);
            if advance_targets.len() > MAX_STEP_TARGETS {
                return Err(vec![limit(
                    format!("stepping rules may target at most {MAX_STEP_TARGETS} distinct slots"),
                    &target_path,
                )]);
            }
            advance.push(id.to_owned());
        }
        rules.push(StepRule::new(condition, advance));
    }
    Ok(Definition {
        alphabet,
        wheels,
        slots,
        stepping_rules: rules,
    })
}

fn validate_slot_structure(
    slots: &[DefinitionSlot],
    alphabet: &Alphabet,
    wheels: &[Wiring],
    names: &std::collections::HashSet<String>,
    path: &str,
) -> Result<(), Vec<DefinitionDiagnostic>> {
    let reflectors: Vec<_> = slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.role == SlotRole::Reflector)
        .collect();
    if reflectors.len() > 1 {
        return Err(vec![invalid(
            "at most one reflector slot is permitted",
            path,
        )]);
    }
    if reflectors.first().is_some_and(|(index, _)| *index != 0) {
        return Err(vec![invalid(
            "reflector slot must be leftmost",
            child(path, "0"),
        )]);
    }
    if slots.iter().all(|slot| slot.role != SlotRole::Rotor) {
        return Err(vec![invalid("at least one rotor slot is required", path)]);
    }
    for (index, slot) in slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.role == SlotRole::Reflector)
    {
        let slot_path = child(path, &index.to_string());
        let candidates: Vec<(&str, String)> = if let Some(wheel) = &slot.wheel {
            vec![(wheel, child(&slot_path, "wheel"))]
        } else {
            slot.allowed_wheels
                .iter()
                .enumerate()
                .map(|(choice_index, wheel)| {
                    (
                        wheel.as_str(),
                        child(
                            &child(&slot_path, "allowed_wheels"),
                            &choice_index.to_string(),
                        ),
                    )
                })
                .collect()
        };
        for (candidate, candidate_path) in candidates {
            require_wheel(names, candidate, &candidate_path)?;
            let wheel = wheels
                .iter()
                .find(|wheel| wheel.name() == candidate)
                .expect("validated wheel reference");
            let origin = alphabet.symbol_at(0).expect("validated nonempty alphabet");
            let involutive = (0..alphabet.len()).all(|input| {
                let symbol = alphabet.symbol_at(input).expect("index is in alphabet");
                wheel
                    .forward(symbol, origin, origin)
                    .and_then(|mapped| wheel.forward(mapped, origin, origin))
                    == Some(symbol)
            });
            if !involutive {
                return Err(vec![DefinitionDiagnostic::new(
                    "invalid_reflector",
                    format!("wheel {candidate:?} is an admissible reflector but is not involutive"),
                    candidate_path,
                )]);
            }
        }
    }
    Ok(())
}

fn parse_condition(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    alphabet: &Alphabet,
    slot_ids: &std::collections::HashSet<String>,
) -> Result<StepCondition, Vec<DefinitionDiagnostic>> {
    *nodes += 1;
    if depth > MAX_STEP_CONDITION_DEPTH {
        return Err(vec![limit(
            format!("condition nesting exceeds depth {MAX_STEP_CONDITION_DEPTH}"),
            path,
        )]);
    }
    if *nodes > MAX_STEP_CONDITION_NODES {
        return Err(vec![limit(
            format!("condition tree exceeds {MAX_STEP_CONDITION_NODES} nodes"),
            path,
        )]);
    }
    let item = object(value, path)?;
    if item.len() != 1 {
        return Err(vec![invalid(
            "condition must contain exactly one operator",
            path,
        )]);
    }
    let (operator, argument) = item.iter().next().expect("one key");
    let operator_path = child(path, operator);
    match operator.as_str() {
        "always" => {
            if argument == &Value::Bool(true) {
                Ok(StepCondition::Always)
            } else {
                Err(vec![invalid(
                    "always must be the literal boolean true",
                    operator_path,
                )])
            }
        }
        "at_turnover" => {
            let id = string(argument, &operator_path)?;
            if !slot_ids.contains(id) {
                return Err(vec![invalid(
                    format!("unknown stepping slot {id:?}"),
                    operator_path,
                )]);
            }
            Ok(StepCondition::AtTurnover(id.to_owned()))
        }
        "at_position" => {
            let pair = object(argument, &operator_path)?;
            exact_keys(pair, &["slot", "symbol"], &operator_path)?;
            let slot = required_string(pair, "slot", &operator_path)?.to_owned();
            let slot_path = child(&operator_path, "slot");
            if !slot_ids.contains(&slot) {
                return Err(vec![invalid(
                    format!("unknown stepping slot {slot:?}"),
                    slot_path,
                )]);
            }
            let symbol_path = child(&operator_path, "symbol");
            let symbol = scalar(required(pair, "symbol", &operator_path)?, &symbol_path)?;
            if alphabet.index_of(symbol).is_none() {
                return Err(vec![invalid(
                    format!("position symbol {symbol:?} is outside the alphabet"),
                    symbol_path,
                )]);
            }
            Ok(StepCondition::AtPosition { slot, symbol })
        }
        "all" | "any" => {
            let values = array(argument, &operator_path)?;
            if values.is_empty() {
                return Err(vec![invalid(
                    "all/any condition groups must not be empty",
                    operator_path,
                )]);
            }
            let mut conditions = Vec::with_capacity(values.len());
            for (index, child_value) in values.iter().enumerate() {
                conditions.push(parse_condition(
                    child_value,
                    &child(&operator_path, &index.to_string()),
                    depth + 1,
                    nodes,
                    alphabet,
                    slot_ids,
                )?);
            }
            if operator == "all" {
                Ok(StepCondition::All(conditions))
            } else {
                Ok(StepCondition::Any(conditions))
            }
        }
        "not" => Ok(StepCondition::Not(Box::new(parse_condition(
            argument,
            &operator_path,
            depth + 1,
            nodes,
            alphabet,
            slot_ids,
        )?))),
        _ => Err(vec![invalid(
            format!("unknown stepping condition operator {operator:?}"),
            operator_path,
        )]),
    }
}

fn object<'a>(
    value: &'a Value,
    path: &str,
) -> Result<&'a Map<String, Value>, Vec<DefinitionDiagnostic>> {
    value
        .as_object()
        .ok_or_else(|| vec![invalid("expected a JSON object", path)])
}
fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], Vec<DefinitionDiagnostic>> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| vec![invalid("expected a JSON array", path)])
}
fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, Vec<DefinitionDiagnostic>> {
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
) -> Result<&'a str, Vec<DefinitionDiagnostic>> {
    string(required(object, key, path)?, &child(path, key))
}
fn string<'a>(value: &'a Value, path: &str) -> Result<&'a str, Vec<DefinitionDiagnostic>> {
    value
        .as_str()
        .ok_or_else(|| vec![invalid("expected a string", path)])
}
fn scalar(value: &Value, path: &str) -> Result<char, Vec<DefinitionDiagnostic>> {
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
) -> Result<(), Vec<DefinitionDiagnostic>> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(vec![DefinitionDiagnostic::new(
            "unknown_field",
            format!("field {key:?} is not allowed here"),
            child(path, key),
        )]);
    }
    if let Some(key) = allowed.iter().find(|key| !object.contains_key(**key)) {
        return Err(vec![invalid(
            format!("required field {key:?} is missing"),
            child(path, key),
        )]);
    }
    Ok(())
}
fn require_wheel(
    names: &std::collections::HashSet<String>,
    name: &str,
    path: &str,
) -> Result<(), Vec<DefinitionDiagnostic>> {
    if names.contains(name) {
        Ok(())
    } else {
        Err(vec![invalid(
            format!("wheel reference {name:?} does not name a declared wheel"),
            path,
        )])
    }
}
fn child(path: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{path}/{escaped}")
}
fn invalid(message: impl Into<String>, path: impl Into<String>) -> DefinitionDiagnostic {
    DefinitionDiagnostic::new("invalid_definition", message, path)
}
fn limit(message: impl Into<String>, path: impl Into<String>) -> DefinitionDiagnostic {
    DefinitionDiagnostic::new("resource_limit", message, path)
}
fn model_error(error: ModelError, path: &str) -> DefinitionDiagnostic {
    let code = match error {
        ModelError::UnknownSymbol(_) | ModelError::UnknownSlotSymbol(_) => "invalid_symbol",
        ModelError::WiringLength { .. } | ModelError::DuplicateWiringSymbol(_) => "invalid_wiring",
        ModelError::ReflectorMustBeInvolutive(_) => "invalid_reflector",
        ModelError::UnknownWheel(_) | ModelError::DuplicateWheelName(_) => "invalid_slot",
        ModelError::UnknownStepSlot(_)
        | ModelError::NonMovableStepTarget(_)
        | ModelError::EmptyStepConditionGroup => "invalid_rule",
        ModelError::TooManyStepRules { .. }
        | ModelError::TooManyStepConditionNodes { .. }
        | ModelError::StepConditionTooDeep { .. }
        | ModelError::TooManyStepTargets { .. } => "resource_limit",
        _ => "invalid_definition",
    };
    DefinitionDiagnostic::new(code, error.to_string(), path)
}

#[cfg(test)]
mod tests {
    use super::{Definition, DefinitionDiagnostic, DefinitionSource};
    use crate::{MachineTopology, Movement, Slot, SlotRole};

    const VALID: &str = r#"{
        "alphabet":["A","B","C","D"],
        "wheels":[
            {"name":"rotor","wiring":["B","A","D","C"],"turnovers":["B"]},
            {"name":"reflector","wiring":["B","A","D","C"],"turnovers":[]}
        ],
        "slots":[
            {"id":"ukw","role":"reflector","movement":"fixed","wheel":"reflector"},
            {"id":"fast","role":"rotor","movement":"movable","allowed_wheels":["rotor"]}
        ],
        "stepping":{"rules":[{"when":{"always":true},"advance":["fast"]}]}
    }"#;

    fn parse(source: &str) -> Result<Definition, Vec<DefinitionDiagnostic>> {
        let tagged = format!(r#"{{"kind":"custom","value":{source}}}"#);
        DefinitionSource::parse_json(&tagged).and_then(|source| source.resolve())
    }

    fn errors(source: &str) -> Vec<DefinitionDiagnostic> {
        parse(source).unwrap_err()
    }

    #[test]
    fn parses_custom_definition_into_task_six_ready_model() {
        let definition = parse(VALID).unwrap();
        assert_eq!(definition.alphabet().len(), 4);
        assert_eq!(definition.wheels().len(), 2);
        assert_eq!(definition.slots().len(), 2);
        assert_eq!(definition.slots()[1].allowed_wheels(), &["rotor"]);
        assert_eq!(definition.stepping_rules().len(), 1);
        let topology = MachineTopology::new(
            definition.alphabet().clone(),
            definition.wheels().to_vec(),
            vec![
                Slot::new(
                    "ukw",
                    "reflector",
                    SlotRole::Reflector,
                    Movement::Fixed,
                    'B',
                    'C',
                ),
                Slot::new(
                    "fast",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'D',
                    'B',
                ),
            ],
        )
        .unwrap();
        assert!(definition.bind_stepping(&topology).is_ok());
    }

    #[test]
    fn accepts_six_rotor_no_reflector_definitions_without_imposing_a_minimum_reflector() {
        let slots = (0..6)
            .map(|index| format!(r#"{{"id":"r{index}","role":"rotor","movement":"movable","allowed_wheels":["rotor"]}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{"kind":"custom","value":{{"alphabet":["A","B","C","D"],"wheels":[{{"name":"rotor","wiring":["A","B","C","D"],"turnovers":[]}}],"slots":[{slots}],"stepping":{{"rules":[]}}}}}}"#
        );
        let definition = DefinitionSource::parse_json(&json)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(definition.slots().len(), 6);
        assert!(definition
            .slots()
            .iter()
            .all(|slot| slot.role() == SlotRole::Rotor));
        assert!(definition.stepping_rules().is_empty());
    }

    #[test]
    fn definition_requires_exact_keys_and_rejects_key_material() {
        let unknown = VALID.replace("\"alphabet\":", "\"position\":\"A\",\"alphabet\":");
        let diagnostic = errors(&unknown).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/value/position");
        assert!(diagnostic.message().contains("position"));
        let missing = VALID.replace(",\n        \"stepping\":{\"rules\":[{\"when\":{\"always\":true},\"advance\":[\"fast\"]}]}", "");
        assert_eq!(errors(&missing)[0].location(), "/value/stepping");
    }

    #[test]
    fn bundled_definitions_resolve_through_the_custom_definition_validator() {
        for id in [
            "enigma-i",
            "enigma-m3",
            "enigma-m4",
            "enigma-railway",
            "enigma-g312",
            "enigma-g260",
        ] {
            let bundled = format!(r#"{{"kind":"bundled","id":"{id}"}}"#);
            let definition = DefinitionSource::parse_json(&bundled)
                .unwrap()
                .resolve()
                .unwrap_or_else(|diagnostics| panic!("{id} did not resolve: {diagnostics:?}"));
            assert_eq!(definition.alphabet().len(), 26);
            assert_eq!(definition.slots()[0].id(), "reflector");
            // WWII shapes and rules are checked exactly in wwii_catalog_matches_sourced_wiring_slots_and_rules.
            if id == "enigma-railway" || id.starts_with("enigma-g") {
                continue;
            }
            assert_eq!(definition.stepping_rules().len(), 3);
            assert_eq!(
                definition.stepping_rules()[0].condition(),
                &crate::StepCondition::Always
            );
            assert_eq!(definition.stepping_rules()[0].advance(), &["right"]);
            assert_eq!(
                definition.stepping_rules()[1].condition(),
                &crate::StepCondition::AtTurnover("right".to_owned())
            );
            assert_eq!(definition.stepping_rules()[1].advance(), &["middle"]);
            assert_eq!(
                definition.stepping_rules()[2].condition(),
                &crate::StepCondition::AtTurnover("middle".to_owned())
            );
            assert_eq!(
                definition.stepping_rules()[2].advance(),
                &["middle", "left"]
            );
            for slot in definition.slots() {
                assert!(slot.id() != "entry");
                assert!(slot.wheel().is_none());
            }
        }
    }

    #[test]
    fn bundled_definitions_are_identical_to_custom_values_and_key_free() {
        for (id, json) in [
            ("enigma-i", include_str!("../catalog/enigma-i.json")),
            ("enigma-m3", include_str!("../catalog/enigma-m3.json")),
            ("enigma-m4", include_str!("../catalog/enigma-m4.json")),
            (
                "enigma-railway",
                include_str!("../catalog/enigma-railway.json"),
            ),
            ("enigma-g312", include_str!("../catalog/enigma-g312.json")),
            ("enigma-g260", include_str!("../catalog/enigma-g260.json")),
        ] {
            let bundle =
                DefinitionSource::parse_json(&format!(r#"{{"kind":"bundled","id":"{id}"}}"#))
                    .unwrap()
                    .resolve()
                    .unwrap();
            let custom =
                DefinitionSource::parse_json(&format!(r#"{{"kind":"custom","value":{json}}}"#))
                    .unwrap()
                    .resolve()
                    .unwrap();
            assert_eq!(bundle, custom);
            assert_eq!(bundle.slots()[0].role(), SlotRole::Reflector);
            assert_eq!(
                bundle.slots()[0].movement(),
                if id.starts_with("enigma-g") {
                    Movement::Movable
                } else {
                    Movement::Fixed
                }
            );
            if id == "enigma-m4" {
                assert_eq!(bundle.slots()[1].id(), "greek");
                assert_eq!(bundle.slots()[1].role(), SlotRole::Rotor);
                assert_eq!(bundle.slots()[1].movement(), Movement::Fixed);
                assert_eq!(bundle.slots()[1].allowed_wheels(), &["Beta", "Gamma"]);
                assert_eq!(bundle.slots()[0].allowed_wheels(), &["Thin-B", "Thin-C"]);
            } else if id == "enigma-i" || id == "enigma-m3" {
                assert_eq!(bundle.slots().len(), 4);
                assert_eq!(bundle.slots()[0].allowed_wheels(), &["B", "C"]);
            }
            let top_level: serde_json::Value = serde_json::from_str(json).unwrap();
            let fields = top_level.as_object().unwrap();
            assert_eq!(fields.len(), 4);
            for forbidden in ["positions", "rings", "current_wheel", "plugboard", "key"] {
                assert!(!fields.contains_key(forbidden), "{id} contains {forbidden}");
            }
        }
    }

    #[test]
    fn catalog_wheel_wiring_and_turnovers_match_the_sourced_values() {
        let m4 = DefinitionSource::parse_json(r#"{"kind":"bundled","id":"enigma-m4"}"#)
            .unwrap()
            .resolve()
            .unwrap();
        let wiring = |name: &str| {
            m4.wheels()
                .iter()
                .find(|wheel| wheel.name() == name)
                .unwrap()
        };
        let display = |wheel: &crate::Wiring| {
            (0..26)
                .map(|index| {
                    wheel
                        .forward(m4.alphabet().symbol_at(index).unwrap(), 'A', 'A')
                        .unwrap()
                })
                .collect::<String>()
        };
        assert_eq!(display(wiring("Beta")), "LEYJVCNIXWPBQMDRTAKZGFUHOS");
        assert_eq!(display(wiring("Gamma")), "FSOKANUERHMBTIYCWLQPZXVGJD");
        for name in ["VI", "VII", "VIII"] {
            assert!(wiring(name).at_turnover('Z'));
            assert!(wiring(name).at_turnover('M'));
            assert!(!wiring(name).at_turnover('A'));
        }
    }

    #[test]
    fn original_catalog_transform_and_attack_behavior_is_preserved() {
        use crate::{SlotConfiguration as Key, TransformConfiguration};
        for id in ["enigma-i", "enigma-m3", "enigma-m4"] {
            let mut slots = vec![Key::new(
                "reflector",
                if id == "enigma-m4" { "Thin-B" } else { "B" },
                'A',
                'A',
            )];
            if id == "enigma-m4" {
                slots.push(Key::new("greek", "Beta", 'A', 'A'));
            }
            slots.extend(
                [("left", "I"), ("middle", "II"), ("right", "III")]
                    .map(|(id, wheel)| Key::new(id, wheel, 'A', 'A')),
            );
            let mut engine = TransformConfiguration::new(slots, vec![])
                .resolve(&bundled(id))
                .unwrap()
                .into_engine()
                .unwrap();
            assert_eq!(
                engine
                    .transform("AAAAA", crate::Direction::Encrypt)
                    .unwrap(),
                "BDZGO"
            );
        }
        let request = serde_json::json!({"protocol_version":1,
            "machine":{"definition":{"kind":"bundled","id":"enigma-i"}},
            "job":{"kind":"search", "configuration":{"slots":[
                {"id":"reflector","wheel":"B","position":"A","ring":"A"},
                {"id":"left","wheel":"I","position":"A","ring":"A"},
                {"id":"middle","wheel":"II","position":"A","ring":"A"},
                {"id":"right","wheel":"III","position":"A","ring":"A"}],"plugboard":[]},
                "text":"BDZGO", "passes":["hill_climb"], "measures":["ic"],
                "space":{"plugboard":{"kind":"attack","symbols":["A","B"],"max_pairs":0}},
                "attack":{"kind":"hill_climb","initial_measure":"ic","final_measure":"ic","switch_pairs":0,"backtrack_pairs":0,"start":[]}}});
        let result = crate::AttackRequest::parse_json(&request.to_string())
            .unwrap()
            .run(|_| {}, || false)
            .unwrap();
        assert_eq!(result.termination(), crate::AttackTermination::Completed);
        assert_eq!(result.best().unwrap().plaintext(), "AAAAA");
        assert_eq!(result.evaluations_used(), 1);
    }

    // Exact WWII values from docs/historical-catalog.md (CM/Toledo reconciliation).
    const WWII: [(&str, [&str; 4]); 3] = [
        (
            "enigma-railway",
            [
                "JGDQOXUSCAMIFRVTPNEWKBLZYH",
                "NTZPSFBOKMWRCJDIVLAEYUXHGQ",
                "JVIUBHTCDYAKEQZPOSGXNRMWFL",
                "QYHOGNECVPUZTFDJAXWMKISRBL",
            ],
        ),
        (
            "enigma-g312",
            [
                "DMTWSILRUYQNKFEJCAZBPGXOHV",
                "HQZGPJTMOBLNCIFDYAWVEUSRKX",
                "UQNTLSZFMREHDPXKIBVYGJCWOA",
                "RULQMZJSYGOCETKWDAHNBXPVIF",
            ],
        ),
        (
            "enigma-g260",
            [
                "RCSPBLKQAUMHWYTIFZVGOJNEXD",
                "WCMIBVPJXAROSGNDLZKEYHUFQT",
                "FVDHZELSQMAXOKYIWPGCBUJTNR",
                "IMETCGFRAYSQBZXWLHKDVUPOJN",
            ],
        ),
    ];

    fn bundled(id: &str) -> Definition {
        DefinitionSource::parse_json(&format!(r#"{{"kind":"bundled","id":"{id}"}}"#))
            .unwrap()
            .resolve()
            .unwrap()
    }

    #[test]
    fn wwii_catalog_matches_sourced_wiring_slots_and_rules() {
        use crate::{StepCondition as C, StepRule};
        for (id, mappings) in WWII {
            let definition = bundled(id);
            let railway = id == "enigma-railway";
            assert_eq!(
                (0..definition.alphabet().len())
                    .map(|i| definition.alphabet().symbol_at(i).unwrap())
                    .collect::<String>(),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            );
            assert_eq!(definition.wheels().len(), 5);
            for ((name, mapping), turnovers) in ["I", "II", "III", "UKW", "ETW"]
                .into_iter()
                .zip(mappings.into_iter().chain(["JWULCMNOHPQZYXIRADKEGVBTSF"]))
                .zip(if railway {
                    ["N", "E", "Y", "", ""]
                } else {
                    [
                        "SUVWZABCEFGIKLOPQ",
                        "STVYZACDFGHKMNQ",
                        "UWXAEFHKMNR",
                        "",
                        "",
                    ]
                })
            {
                let wheel = definition
                    .wheels()
                    .iter()
                    .find(|wheel| wheel.name() == name)
                    .unwrap();
                assert_eq!(
                    (b'A'..=b'Z')
                        .map(|c| wheel.forward(char::from(c), 'A', 'A').unwrap())
                        .collect::<String>(),
                    mapping,
                    "{id} {name}"
                );
                for symbol in 'A'..='Z' {
                    assert_eq!(
                        wheel.at_turnover(symbol),
                        turnovers.contains(symbol),
                        "{id} {name} {symbol}"
                    );
                }
            }
            assert_eq!(definition.slots().len(), 5);
            for (i, slot) in definition.slots().iter().enumerate() {
                assert_eq!(
                    slot.id(),
                    ["reflector", "left", "middle", "right", "etw"][i]
                );
                assert_eq!(
                    slot.role(),
                    if i == 0 {
                        SlotRole::Reflector
                    } else {
                        SlotRole::Rotor
                    }
                );
                assert_eq!(
                    slot.movement(),
                    if i == 4 || (i == 0 && railway) {
                        Movement::Fixed
                    } else {
                        Movement::Movable
                    }
                );
                if i == 4 {
                    assert_eq!(slot.wheel(), Some("ETW"));
                    assert!(slot.allowed_wheels().is_empty());
                } else {
                    assert_eq!(slot.wheel(), None);
                    assert_eq!(
                        slot.allowed_wheels(),
                        if i == 0 {
                            vec!["UKW"]
                        } else {
                            vec!["I", "II", "III"]
                        }
                    );
                }
            }
            let notch = |slot: &str| C::AtTurnover(slot.to_owned());
            let rule = |condition, targets: &[&str]| {
                StepRule::new(condition, targets.iter().map(|s| (*s).to_owned()).collect())
            };
            let mut rules = vec![
                rule(C::Always, &["right"]),
                rule(notch("right"), &["middle"]),
            ];
            if railway {
                rules.push(rule(notch("middle"), &["middle", "left"]));
            } else {
                rules.push(rule(
                    C::All(vec![notch("right"), notch("middle")]),
                    &["left"],
                ));
                rules.push(rule(
                    C::All(vec![notch("right"), notch("middle"), notch("left")]),
                    &["reflector"],
                ));
            }
            assert_eq!(definition.stepping_rules(), rules);
        }
    }

    fn wwii_engine(id: &str, positions: &str) -> crate::Engine {
        use crate::{SlotConfiguration, TransformConfiguration};
        let slots = ["reflector", "left", "middle", "right", "etw"]
            .into_iter()
            .zip(["UKW", "III", "II", "I", "ETW"])
            .zip(positions.chars().chain(['A']))
            .zip("DFCPA".chars())
            .map(|(((id, wheel), position), ring)| {
                SlotConfiguration::new(id, wheel, position, ring)
            })
            .collect();
        TransformConfiguration::new(slots, vec![])
            .resolve(&bundled(id))
            .unwrap()
            .into_engine()
            .unwrap()
    }

    #[test]
    fn wwii_railway_double_steps_with_fixed_etw_and_settable_reflector() {
        let mut engine = wwii_engine("enigma-railway", "JKDM");
        for expected in ["JKDN", "JKEO", "JLFP"] {
            assert_eq!(
                engine
                    .transform("A", crate::Direction::Encrypt)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                engine.positions().iter().collect::<String>(),
                format!("{expected}A")
            );
        }
    }

    #[test]
    fn wwii_g_nested_carry_moves_reflector_without_double_step() {
        for id in ["enigma-g312", "enigma-g260"] {
            let mut engine = wwii_engine(id, "JUSA");
            for expected in ["KVTB", "KWUC", "KWVD", "KWVE"] {
                assert_eq!(
                    engine
                        .transform("A", crate::Direction::Encrypt)
                        .unwrap()
                        .len(),
                    1
                );
                assert_eq!(
                    engine.positions().iter().collect::<String>(),
                    format!("{expected}A")
                );
            }
            // II at S alone must not advance III or UKW; I at D is not a notch.
            let mut engine = wwii_engine(id, "JUSD");
            engine.transform("A", crate::Direction::Encrypt).unwrap();
            assert_eq!(engine.positions(), &['J', 'U', 'S', 'E', 'A']);
        }
    }

    #[test]
    fn custom_and_bundled_tagged_union_is_exact_and_unknown_catalog_fails_closed() {
        let custom = format!(r#"{{"kind":"custom","value":{VALID}}}"#);
        assert!(DefinitionSource::parse_json(&custom)
            .unwrap()
            .resolve()
            .is_ok());
        let bundled = r#"{"kind":"bundled","id":"not-in-catalog"}"#;
        let diagnostic = DefinitionSource::parse_json(bundled)
            .unwrap()
            .resolve()
            .unwrap_err();
        assert_eq!(diagnostic[0].code(), "unknown_bundled_definition");
        assert_eq!(diagnostic[0].location(), "/id");
        for malformed in [
            r#"{"kind":"custom","value":{},"id":"extra"}"#,
            r#"{"kind":"custom"}"#,
            r#"{"kind":"future","value":{}}"#,
            r#"{"kind":"bundled","id":"x","value":{}}"#,
        ] {
            assert!(DefinitionSource::parse_json(malformed).is_err());
        }
    }

    #[test]
    fn validates_scalar_alphabet_and_reports_pointer_escaped_names() {
        let duplicate = VALID.replace("[\"A\",\"B\",\"C\",\"D\"]", "[\"A\",\"B\",\"A\",\"D\"]");
        let diagnostic = errors(&duplicate).remove(0);
        assert_eq!(diagnostic.code(), "invalid_definition");
        assert_eq!(diagnostic.location(), "/value/alphabet/2");
        let multiscalar = VALID.replace("\"A\",\"B\",\"C\",\"D\"", "\"AB\",\"B\",\"C\",\"D\"");
        assert_eq!(errors(&multiscalar)[0].location(), "/value/alphabet/0");
        let escaped = VALID.replace("\"alphabet\":", "\"bad~/key\":true,\"alphabet\":");
        assert!(errors(&escaped)
            .iter()
            .any(|diagnostic| diagnostic.location() == "/value/bad~0~1key"));
    }

    #[test]
    fn validates_permutations_turnovers_slots_and_every_reflector_choice() {
        let bad_wiring = VALID.replace("\"B\",\"A\",\"D\",\"C\"", "\"B\",\"B\",\"D\",\"C\"");
        assert_eq!(errors(&bad_wiring)[0].code(), "invalid_wiring");
        let bad_turnover = VALID.replace("\"turnovers\":[\"B\"]", "\"turnovers\":[\"Z\"]");
        assert!(errors(&bad_turnover)
            .iter()
            .any(|diagnostic| diagnostic.location() == "/value/wheels/0/turnovers/0"));
        let bad_reference = VALID.replace(
            "\"allowed_wheels\":[\"rotor\"]",
            "\"allowed_wheels\":[\"missing\"]",
        );
        assert!(errors(&bad_reference)
            .iter()
            .any(|diagnostic| diagnostic.location() == "/value/slots/1/allowed_wheels/0"));
        let bad_alternative = VALID
            .replace(
                "\"name\":\"rotor\",\"wiring\":[\"B\",\"A\",\"D\",\"C\"]",
                "\"name\":\"rotor\",\"wiring\":[\"B\",\"C\",\"D\",\"A\"]",
            )
            .replace(
                "\"wheel\":\"reflector\"",
                "\"allowed_wheels\":[\"reflector\",\"rotor\"]",
            );
        assert!(errors(&bad_alternative)
            .iter()
            .any(|diagnostic| diagnostic.code() == "invalid_reflector"));
    }

    #[test]
    fn validates_step_grammar_limits_and_cross_references() {
        let expressive = VALID.replace(
            "{\"always\":true}",
            "{\"all\":[{\"at_turnover\":\"fast\"},{\"any\":[{\"at_position\":{\"slot\":\"fast\",\"symbol\":\"B\"}},{\"not\":{\"always\":true}}]}]}",
        );
        assert!(parse(&expressive).is_ok());

        for (replacement, location) in [
            ("{\"always\":false}", "/value/stepping/rules/0/when/always"),
            ("{\"all\":[]}", "/value/stepping/rules/0/when/all"),
            ("{\"unknown\":true}", "/value/stepping/rules/0/when/unknown"),
            (
                "{\"at_turnover\":\"missing\"}",
                "/value/stepping/rules/0/when/at_turnover",
            ),
            (
                "{\"at_position\":{\"slot\":\"fast\",\"symbol\":\"Z\"}}",
                "/value/stepping/rules/0/when/at_position/symbol",
            ),
        ] {
            let input = VALID.replace("{\"always\":true}", replacement);
            assert!(errors(&input)
                .iter()
                .any(|diagnostic| diagnostic.location() == location));
        }
        let fixed_target = VALID.replace("\"advance\":[\"fast\"]", "\"advance\":[\"ukw\"]");
        assert!(errors(&fixed_target)
            .iter()
            .any(|diagnostic| diagnostic.code() == "invalid_definition"));
        let rules = "{\"when\":{\"always\":true},\"advance\":[]},".repeat(65);
        let too_many = VALID.replace("\"rules\":[", &format!("\"rules\":[{rules}"));
        assert!(errors(&too_many)
            .iter()
            .any(|diagnostic| diagnostic.code() == "resource_limit"));
    }

    #[test]
    fn rejects_json_syntax_and_definition_byte_limit() {
        assert_eq!(
            DefinitionSource::parse_json("{").unwrap_err()[0].code(),
            "invalid_json"
        );
        assert_eq!(
            DefinitionSource::parse_json(r#"{"kind":"bundled","kind":"custom","id":"x"}"#)
                .unwrap_err()[0]
                .code(),
            "invalid_json"
        );
        let too_large = format!("{}{}", " ".repeat(super::MAX_DEFINITION_BYTES + 1), VALID);
        assert_eq!(
            DefinitionSource::parse_json(&too_large).unwrap_err()[0].code(),
            "resource_limit"
        );
    }
}
