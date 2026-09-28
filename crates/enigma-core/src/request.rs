//! Strict, key-free JSON request parsing for the protocol `transform` job.
//!
//! A request is exactly `protocol_version`, `machine`, and `job`. This module validates
//! every field before returning a [`TransformRequest`], because the transport emits the
//! protocol `started` event only after a successful parse: no partial or lazily checked
//! request is ever handed back. Parsing is pure -- it performs no I/O and prints nothing.
//!
//! Diagnostics use request-relative JSON Pointers. Definition diagnostics are prefixed
//! with `/machine/definition`, while configuration diagnostics already arrive under
//! `/job/configuration` from [`crate::TransformConfiguration::resolve`].

use crate::definition::MAX_DEFINITION_BYTES;
use crate::space::SearchDiagnostic;
use crate::strict_json::StrictValue;
use crate::{
    ConfigurationDiagnostic, Definition, DefinitionDiagnostic, DefinitionSource, Direction, Engine,
    ModelError, SlotConfiguration, TransformConfiguration, PROTOCOL_VERSION,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fmt;

/// Maximum encoded JSON request size accepted by [`TransformRequest::parse_json`].
///
/// A request is bounded by this limit before its JSON tree is built. An embedded
/// `machine.definition` is additionally bounded by the crate's 1 MiB definition limit
/// ([`MAX_DEFINITION_BYTES`]) so it cannot smuggle a larger document past the standalone
/// definition check.
pub const MAX_REQUEST_BYTES: usize = 4_194_304;

/// A localized, actionable request-validation diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestDiagnostic {
    code: &'static str,
    message: String,
    location: String,
}

impl RequestDiagnostic {
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

    /// Request-relative RFC 6901 JSON Pointer to the invalid value.
    pub fn location(&self) -> &str {
        &self.location
    }
}

impl fmt::Display for RequestDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.code, self.location, self.message)
    }
}

impl std::error::Error for RequestDiagnostic {}

impl From<ConfigurationDiagnostic> for RequestDiagnostic {
    fn from(diagnostic: ConfigurationDiagnostic) -> Self {
        Self {
            code: diagnostic.code(),
            message: diagnostic.message().to_owned(),
            location: diagnostic.location().to_owned(),
        }
    }
}

impl From<SearchDiagnostic> for RequestDiagnostic {
    fn from(diagnostic: SearchDiagnostic) -> Self {
        Self {
            code: diagnostic.code(),
            message: diagnostic.message().to_owned(),
            location: diagnostic.location().to_owned(),
        }
    }
}

/// A fully validated, ready-to-run `transform` request.
///
/// Every field was checked during [`TransformRequest::parse_json`], so the engine can
/// run immediately and cannot fail on text or configuration validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformRequest {
    engine: Engine,
    text: String,
    direction: Direction,
}

impl TransformRequest {
    /// Parses and fully validates a JSON request.
    ///
    /// Validation order mirrors the protocol: definition, then configuration resolution
    /// (slots, coverage, symbols, plugboard), then direction, then whole-text alphabet
    /// membership. Nothing is defaulted; omission of a required value is an error.
    pub fn parse_json(json: &str) -> Result<Self, Vec<RequestDiagnostic>> {
        let ParsedRoot { definition, job } = parse_root(json)?;
        let job = object(&job, "/job")?;

        // Job kind selects the schema; the search schema is deferred to task 9.
        let kind = required_string(job, "kind", "/job")?;
        if kind != "transform" {
            return Err(vec![RequestDiagnostic::new(
                "unsupported_job",
                format!("job kind {kind:?} is not supported; only `transform` is implemented"),
                "/job/kind",
            )]);
        }
        exact_keys(job, &["kind", "configuration", "text", "direction"], "/job")?;

        // Configuration shape is strict here; the typed resolver owns admissibility and
        // already reports request-relative pointers under `/job/configuration`.
        let configuration = parse_configuration(required(job, "configuration", "/job")?)?;
        let resolved = configuration.resolve(&definition).map_err(
            |diagnostics| -> Vec<RequestDiagnostic> {
                diagnostics
                    .into_iter()
                    .map(RequestDiagnostic::from)
                    .collect()
            },
        )?;

        // Direction before text membership, then the whole text before building the engine.
        let direction = match required_string(job, "direction", "/job")? {
            "encrypt" => Direction::Encrypt,
            "decrypt" => Direction::Decrypt,
            other => {
                return Err(vec![RequestDiagnostic::new(
                    "invalid_request",
                    format!(
                        "direction {other:?} is not supported; expected `encrypt` or `decrypt`"
                    ),
                    "/job/direction",
                )]);
            }
        };

        let text = required_string(job, "text", "/job")?;
        if let Some(symbol) = text
            .chars()
            .find(|symbol| definition.alphabet().index_of(*symbol).is_none())
        {
            return Err(vec![RequestDiagnostic::new(
                "invalid_text",
                format!("symbol {symbol:?} is not in the machine alphabet"),
                "/job/text",
            )]);
        }

        let engine = resolved.into_engine().map_err(|error| {
            vec![RequestDiagnostic::new(
                "invalid_definition",
                error.to_string(),
                "/machine/definition",
            )]
        })?;

        Ok(Self {
            engine,
            text: text.to_owned(),
            direction,
        })
    }

    /// The validated plaintext or ciphertext to transform.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The validated electrical direction.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Runs the transform with the already validated engine and returns the result.
    pub fn transform(mut self) -> Result<String, ModelError> {
        self.engine.transform(&self.text, self.direction)
    }
}

/// The shared, already-validated root of a protocol request.
///
/// `protocol_version` and `machine.definition` are validated once here for both job
/// kinds; the owned `job` value is returned so the kind-specific parser can interpret it
/// with its own exact-field rules. Sharing this helper keeps both parsers byte-identical
/// on root, version, machine, and definition diagnostics.
pub(crate) struct ParsedRoot {
    pub(crate) definition: Definition,
    pub(crate) job: Value,
}

/// Parses and validates the shared request root: size limit, strict JSON, exact root
/// fields, `protocol_version`, and `machine.definition`.
///
/// The definition is resolved before any job interpretation, so definition diagnostics
/// always win over job diagnostics, exactly as the transform path already required.
pub(crate) fn parse_root(json: &str) -> Result<ParsedRoot, Vec<RequestDiagnostic>> {
    if json.len() > MAX_REQUEST_BYTES {
        return Err(vec![RequestDiagnostic::new(
            "resource_limit",
            "request JSON exceeds the 4 MiB resource limit",
            "",
        )]);
    }
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let parsed = StrictValue::deserialize(&mut deserializer).map_err(|error| {
        vec![RequestDiagnostic::new(
            "invalid_json",
            format!("invalid JSON: {error}"),
            "",
        )]
    })?;
    deserializer.end().map_err(|error| {
        vec![RequestDiagnostic::new(
            "invalid_json",
            format!("invalid JSON: {error}"),
            "",
        )]
    })?;
    let value = parsed.into_value();

    let root = object(&value, "")?;
    exact_keys(root, &["protocol_version", "machine", "job"], "")?;

    // The version must be exactly the unsigned version this build implements.
    let version = required(root, "protocol_version", "")?;
    match version.as_u64() {
        Some(value) if value == u64::from(PROTOCOL_VERSION) => {}
        Some(value) => {
            return Err(vec![RequestDiagnostic::new(
                "unsupported_version",
                format!("protocol_version {value} is not supported; expected {PROTOCOL_VERSION}"),
                "/protocol_version",
            )]);
        }
        None => {
            return Err(vec![RequestDiagnostic::new(
                "invalid_request",
                "protocol_version must be a non-negative integer",
                "/protocol_version",
            )]);
        }
    }

    // Resolve the definition before any job work, so definition errors win.
    let machine = object(required(root, "machine", "")?, "/machine")?;
    exact_keys(machine, &["definition"], "/machine")?;
    let definition_value = required(machine, "definition", "/machine")?.clone();
    // `parse_value` skips `parse_json`'s raw-byte check, so enforce the same encoded
    // definition limit here; otherwise an embedded definition could exceed it.
    let definition_bytes = serde_json::to_string(&definition_value)
        .map_err(|error| {
            vec![RequestDiagnostic::new(
                "invalid_json",
                format!("machine.definition is not serializable JSON: {error}"),
                "/machine/definition",
            )]
        })?
        .len();
    if definition_bytes > MAX_DEFINITION_BYTES {
        return Err(vec![RequestDiagnostic::new(
            "resource_limit",
            format!("machine.definition exceeds the {MAX_DEFINITION_BYTES}-byte definition limit"),
            "/machine/definition",
        )]);
    }
    let definition = DefinitionSource::parse_value(definition_value)
        .and_then(DefinitionSource::resolve)
        .map_err(definition_diagnostics)?;

    let job = required(root, "job", "")?.clone();

    Ok(ParsedRoot { definition, job })
}

/// Parses the `job.configuration` object into a typed, unvalidated configuration.
///
/// Shape and scalar constraints are enforced here; admissibility against the definition
/// remains the resolver's job. `plugboard` is required even when empty, and every
/// plugboard entry must be a two-element array of single-scalar strings.
fn parse_configuration(value: &Value) -> Result<TransformConfiguration, Vec<RequestDiagnostic>> {
    let path = "/job/configuration";
    let configuration = object(value, path)?;
    exact_keys(configuration, &["slots", "plugboard"], path)?;

    let slots_path = child(path, "slots");
    let entries = array(required(configuration, "slots", path)?, &slots_path)?;
    let mut slots = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = child(&slots_path, &index.to_string());
        let entry = object(entry, &entry_path)?;
        exact_keys(entry, &["id", "wheel", "position", "ring"], &entry_path)?;
        slots.push(SlotConfiguration::new(
            required_string(entry, "id", &entry_path)?,
            required_string(entry, "wheel", &entry_path)?,
            scalar(
                required(entry, "position", &entry_path)?,
                &child(&entry_path, "position"),
            )?,
            scalar(
                required(entry, "ring", &entry_path)?,
                &child(&entry_path, "ring"),
            )?,
        ));
    }

    let plugboard_path = child(path, "plugboard");
    let pairs = array(required(configuration, "plugboard", path)?, &plugboard_path)?;
    let mut plugboard = Vec::with_capacity(pairs.len());
    for (index, pair) in pairs.iter().enumerate() {
        let pair_path = child(&plugboard_path, &index.to_string());
        let pair = array(pair, &pair_path)?;
        if pair.len() != 2 {
            return Err(vec![RequestDiagnostic::new(
                "invalid_plugboard",
                format!(
                    "plugboard entry must contain exactly two symbols; got {}",
                    pair.len()
                ),
                pair_path,
            )]);
        }
        plugboard.push((
            scalar(&pair[0], &child(&pair_path, "0"))?,
            scalar(&pair[1], &child(&pair_path, "1"))?,
        ));
    }

    Ok(TransformConfiguration::new(slots, plugboard))
}

fn object<'a>(
    value: &'a Value,
    path: &str,
) -> Result<&'a Map<String, Value>, Vec<RequestDiagnostic>> {
    value
        .as_object()
        .ok_or_else(|| vec![invalid_request("expected a JSON object", path)])
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], Vec<RequestDiagnostic>> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| vec![invalid_request("expected a JSON array", path)])
}

fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, Vec<RequestDiagnostic>> {
    object.get(key).ok_or_else(|| {
        vec![invalid_request(
            format!("required field {key:?} is missing"),
            child(path, key),
        )]
    })
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a str, Vec<RequestDiagnostic>> {
    string(required(object, key, path)?, &child(path, key))
}

fn string<'a>(value: &'a Value, path: &str) -> Result<&'a str, Vec<RequestDiagnostic>> {
    value
        .as_str()
        .ok_or_else(|| vec![invalid_request("expected a string", path)])
}

fn scalar(value: &Value, path: &str) -> Result<char, Vec<RequestDiagnostic>> {
    let text = string(value, path)?;
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(symbol), None) => Ok(symbol),
        _ => Err(vec![invalid_request(
            "expected exactly one Unicode scalar value",
            path,
        )]),
    }
}

fn exact_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), Vec<RequestDiagnostic>> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(vec![RequestDiagnostic::new(
            "unknown_field",
            format!("field {key:?} is not allowed here"),
            child(path, key),
        )]);
    }
    if let Some(key) = allowed.iter().find(|key| !object.contains_key(**key)) {
        return Err(vec![invalid_request(
            format!("required field {key:?} is missing"),
            child(path, key),
        )]);
    }
    Ok(())
}

fn invalid_request(message: impl Into<String>, path: impl Into<String>) -> RequestDiagnostic {
    RequestDiagnostic::new("invalid_request", message, path)
}

fn child(path: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{path}/{escaped}")
}

/// Prefixes every definition diagnostic with `/machine/definition`.
fn definition_diagnostics(diagnostics: Vec<DefinitionDiagnostic>) -> Vec<RequestDiagnostic> {
    diagnostics
        .into_iter()
        .map(|diagnostic| {
            RequestDiagnostic::new(
                diagnostic.code(),
                diagnostic.message(),
                definition_location(diagnostic.location()),
            )
        })
        .collect()
}

fn definition_location(location: &str) -> String {
    if location.is_empty() {
        String::from("/machine/definition")
    } else {
        format!("/machine/definition{location}")
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestDiagnostic, TransformRequest, MAX_REQUEST_BYTES};
    use crate::definition::MAX_DEFINITION_BYTES;
    use crate::Direction;
    use serde_json::{json, Value};

    /// The protocol §3 custom example: a 4-symbol machine with a fixed plugboard-free key.
    fn custom_request() -> Value {
        json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "custom", "value": {
                "alphabet": ["A", "B", "C", "D"],
                "wheels": [
                    {"name": "rotor", "wiring": ["B", "A", "D", "C"], "turnovers": ["B"]},
                    {"name": "reflector", "wiring": ["B", "A", "D", "C"], "turnovers": []}
                ],
                "slots": [
                    {"id": "ukw", "role": "reflector", "movement": "fixed", "wheel": "reflector"},
                    {"id": "fast", "role": "rotor", "movement": "movable", "allowed_wheels": ["rotor"]}
                ],
                "stepping": {"rules": [{"when": {"always": true}, "advance": ["fast"]}]}
            }}},
            "job": {
                "kind": "transform",
                "configuration": {
                    "slots": [
                        {"id": "ukw", "wheel": "reflector", "position": "A", "ring": "A"},
                        {"id": "fast", "wheel": "rotor", "position": "B", "ring": "A"}
                    ],
                    "plugboard": []
                },
                "text": "ABCD",
                "direction": "encrypt"
            }
        })
    }

    fn bundled_request() -> Value {
        json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "bundled", "id": "enigma-i"}},
            "job": {
                "kind": "transform",
                "configuration": {
                    "slots": [
                        {"id": "reflector", "wheel": "B", "position": "A", "ring": "A"},
                        {"id": "left", "wheel": "I", "position": "A", "ring": "A"},
                        {"id": "middle", "wheel": "II", "position": "A", "ring": "A"},
                        {"id": "right", "wheel": "III", "position": "A", "ring": "A"}
                    ],
                    "plugboard": []
                },
                "text": "AAAA",
                "direction": "encrypt"
            }
        })
    }

    fn parse(value: &Value) -> Result<TransformRequest, Vec<RequestDiagnostic>> {
        TransformRequest::parse_json(&value.to_string())
    }

    fn errors(value: &Value) -> Vec<RequestDiagnostic> {
        parse(value).unwrap_err()
    }

    #[test]
    fn bundled_enigma_i_transform_round_trips_through_two_parses() {
        let request = parse(&bundled_request()).unwrap();
        assert_eq!(request.text(), "AAAA");
        assert_eq!(request.direction(), Direction::Encrypt);
        assert_eq!(request.transform().unwrap(), "BDZG");

        let mut decrypt = bundled_request();
        decrypt["job"]["text"] = json!("BDZG");
        decrypt["job"]["direction"] = json!("decrypt");
        let request = parse(&decrypt).unwrap();
        assert_eq!(request.direction(), Direction::Decrypt);
        assert_eq!(request.transform().unwrap(), "AAAA");
    }

    #[test]
    fn docs_custom_definition_parses_and_transforms_abcd() {
        let request = parse(&custom_request()).unwrap();
        assert_eq!(request.text(), "ABCD");
        assert_eq!(request.transform().unwrap(), "BADC");
    }

    #[test]
    fn rejects_unknown_and_missing_root_fields() {
        let mut unknown = custom_request();
        unknown["surprise"] = json!(1);
        let diagnostic = errors(&unknown).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/surprise");

        let mut missing = custom_request();
        missing.as_object_mut().unwrap().remove("protocol_version");
        let diagnostic = errors(&missing).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/protocol_version");
    }

    #[test]
    fn rejects_unsupported_and_non_integer_protocol_versions() {
        let mut newer = custom_request();
        newer["protocol_version"] = json!(2);
        let diagnostic = errors(&newer).remove(0);
        assert_eq!(diagnostic.code(), "unsupported_version");
        assert_eq!(diagnostic.location(), "/protocol_version");

        let mut malformed = custom_request();
        malformed["protocol_version"] = json!("1");
        let diagnostic = errors(&malformed).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/protocol_version");
    }

    #[test]
    fn rejects_search_and_unknown_job_kinds_before_any_work() {
        let mut search = custom_request();
        search["job"]["kind"] = json!("search");
        let diagnostic = errors(&search).remove(0);
        assert_eq!(diagnostic.code(), "unsupported_job");
        assert_eq!(diagnostic.location(), "/job/kind");

        let mut unknown = custom_request();
        unknown["job"]["kind"] = json!("frobnicate");
        let diagnostic = errors(&unknown).remove(0);
        assert_eq!(diagnostic.code(), "unsupported_job");
        assert_eq!(diagnostic.location(), "/job/kind");
    }

    #[test]
    fn rejects_bad_directions_case_sensitively() {
        for direction in ["sideways", "Encrypt", ""] {
            let mut value = custom_request();
            value["job"]["direction"] = json!(direction);
            let diagnostic = errors(&value).remove(0);
            assert_eq!(diagnostic.code(), "invalid_request");
            assert_eq!(diagnostic.location(), "/job/direction");
        }
    }

    #[test]
    fn rejects_omitted_empty_plugboard_instead_of_defaulting() {
        let mut value = custom_request();
        value["job"]["configuration"]
            .as_object_mut()
            .unwrap()
            .remove("plugboard");
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job/configuration/plugboard");
    }

    #[test]
    fn rejects_out_of_alphabet_text_symbols() {
        let mut value = custom_request();
        value["job"]["text"] = json!("ABCE");
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_text");
        assert_eq!(diagnostic.location(), "/job/text");
    }

    #[test]
    fn propagates_configuration_diagnostics_under_job_configuration() {
        let mut short = custom_request();
        short["job"]["configuration"]["slots"]
            .as_array_mut()
            .unwrap()
            .pop();
        let diagnostic = errors(&short).remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1");

        let mut inadmissible = custom_request();
        inadmissible["job"]["configuration"]["slots"][1]["wheel"] = json!("reflector");
        let diagnostic = errors(&inadmissible).remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1/wheel");
    }

    #[test]
    fn rejects_unknown_slot_entry_fields() {
        let mut value = custom_request();
        value["job"]["configuration"]["slots"][1]["bonus"] = json!(true);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1/bonus");
    }

    #[test]
    fn prefixes_definition_diagnostics_with_machine_definition() {
        let mut value = bundled_request();
        value["machine"]["definition"]["id"] = json!("enigma-unknown");
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "unknown_bundled_definition");
        assert_eq!(diagnostic.location(), "/machine/definition/id");
        assert!(diagnostic.location().starts_with("/machine/definition"));
    }

    #[test]
    fn rejects_duplicate_json_object_keys() {
        let json = r#"{"protocol_version":1,"protocol_version":2,"machine":{},"job":{}}"#;
        let diagnostic = TransformRequest::parse_json(json).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_json");
        assert_eq!(diagnostic.location(), "");
    }

    #[test]
    fn rejects_bad_plugboard_arity() {
        let mut value = custom_request();
        value["job"]["configuration"]["plugboard"] = json!([["A"]]);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_plugboard");
        assert_eq!(diagnostic.location(), "/job/configuration/plugboard/0");
    }

    #[test]
    fn prefixes_root_definition_diagnostics_with_machine_definition() {
        let mut value = custom_request();
        value["machine"]["definition"] = json!(42);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "invalid_definition");
        assert_eq!(diagnostic.location(), "/machine/definition");
    }

    #[test]
    fn rejects_unknown_fields_at_machine_job_and_configuration() {
        let mut machine = custom_request();
        machine["machine"]["extra"] = json!(1);
        let diagnostic = errors(&machine).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/machine/extra");

        let mut job = custom_request();
        job["job"]["extra"] = json!(1);
        let diagnostic = errors(&job).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/job/extra");

        let mut configuration = custom_request();
        configuration["job"]["configuration"]["extra"] = json!(1);
        let diagnostic = errors(&configuration).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/job/configuration/extra");
    }

    #[test]
    fn rejects_embedded_definitions_over_the_definition_byte_limit() {
        let mut value = custom_request();
        let huge_name = "x".repeat(MAX_DEFINITION_BYTES + 1);
        value["machine"]["definition"]["value"]["wheels"][0]["name"] = json!(huge_name);
        let diagnostic = errors(&value).remove(0);
        assert_eq!(diagnostic.code(), "resource_limit");
        assert_eq!(diagnostic.location(), "/machine/definition");
    }

    #[test]
    fn shared_root_refactor_preserves_transform_behavior() {
        // A valid transform still parses and transforms exactly as before.
        let request = parse(&custom_request()).unwrap();
        assert_eq!(request.transform().unwrap(), "BADC");

        // Root/version/machine diagnostics are unchanged by the shared root helper.
        let mut unknown = custom_request();
        unknown["surprise"] = json!(1);
        let diagnostic = errors(&unknown).remove(0);
        assert_eq!(diagnostic.code(), "unknown_field");
        assert_eq!(diagnostic.location(), "/surprise");

        // A non-object job is still rejected at /job after definition resolution.
        let mut bad_job = custom_request();
        bad_job["job"] = json!(42);
        let diagnostic = errors(&bad_job).remove(0);
        assert_eq!(diagnostic.code(), "invalid_request");
        assert_eq!(diagnostic.location(), "/job");
    }

    #[test]
    fn rejects_oversized_requests_at_the_root() {
        let oversized = format!("{}{}", " ".repeat(MAX_REQUEST_BYTES + 1), "{}");
        let diagnostic = TransformRequest::parse_json(&oversized)
            .unwrap_err()
            .remove(0);
        assert_eq!(diagnostic.code(), "resource_limit");
        assert_eq!(diagnostic.location(), "");
    }
}
