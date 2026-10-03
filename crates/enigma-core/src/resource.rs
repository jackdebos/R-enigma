//! Strict, bounded external scoring-resource parsing without I/O.

use crate::{Alphabet, NgramModel};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::HashSet;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 250_000;
const MAX_CONTAINER_DEPTH: usize = 64;

/// Standalone resource error; locations are resource-relative RFC 6901 pointers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceDiagnostic {
    code: &'static str,
    message: String,
    location: String,
}

impl ResourceDiagnostic {
    /// Protocol error category.
    pub fn code(&self) -> &str {
        self.code
    }
    /// Actionable explanation without invented file or measure context.
    pub fn message(&self) -> &str {
        &self.message
    }
    /// Resource-relative JSON pointer; the empty string denotes the root.
    pub fn location(&self) -> &str {
        &self.location
    }
}

fn diagnostic(code: &'static str, path: &str, message: impl Into<String>) -> ResourceDiagnostic {
    ResourceDiagnostic {
        code,
        message: message.into(),
        location: path.into(),
    }
}

fn pointer(parent: &str, member: impl std::fmt::Display) -> String {
    format!(
        "{parent}/{}",
        member.to_string().replace('~', "~0").replace('/', "~1")
    )
}

// This resource-local seed detects decoded-key duplicates at every depth. It
// bounds collections while decoding, rather than building an unrestricted DOM.
struct BoundedValue<'a> {
    path: String,
    error: &'a mut Option<ResourceDiagnostic>,
    reject: bool,
    // Number of enclosing objects/arrays; scalars do not add depth.
    depth: usize,
}

impl BoundedValue<'_> {
    fn check_container_depth<E: de::Error>(&mut self) -> Result<(), E> {
        if self.depth >= MAX_CONTAINER_DEPTH {
            let message = "container nesting exceeds 64 levels; flatten nested objects or arrays";
            *self.error = Some(diagnostic("resource_limit", &self.path, message));
            return Err(E::custom(message));
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for BoundedValue<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.reject {
            *self.error = Some(diagnostic(
                "resource_limit",
                &self.path,
                "collection limit exceeded",
            ));
            return Err(de::Error::custom("collection limit exceeded"));
        }
        let path = self.path.clone();
        let error = &mut *self.error;
        let result = deserializer.deserialize_any(BoundedValue {
            path: self.path,
            error,
            reject: false,
            depth: self.depth,
        });
        if let Err(ref cause) = result {
            if error.is_none() {
                *error = Some(diagnostic("invalid_json", &path, cause.to_string()));
            }
        }
        result
    }
}

impl<'de> Visitor<'de> for BoundedValue<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(Value::Number(
            serde_json::Number::from_f64(value).ok_or_else(|| E::custom("nonfinite number"))?,
        ))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<S: SeqAccess<'de>>(mut self, mut seq: S) -> Result<Value, S::Error> {
        self.check_container_depth()?;
        let cap = if self.path == "/entries" {
            MAX_ENTRIES
        } else {
            256
        };
        let mut values = Vec::new();
        loop {
            let full = values.len() == cap;
            let path = if full {
                self.path.clone()
            } else {
                pointer(&self.path, values.len())
            };
            let next = seq.next_element_seed(BoundedValue {
                path,
                error: self.error,
                reject: full,
                depth: self.depth + 1,
            })?;
            match next {
                Some(value) => values.push(value),
                None => return Ok(Value::Array(values)),
            }
        }
    }

    fn visit_map<M: MapAccess<'de>>(mut self, mut map: M) -> Result<Value, M::Error> {
        self.check_container_depth()?;
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let path = pointer(&self.path, &key);
            if values.contains_key(&key) {
                *self.error = Some(diagnostic(
                    "invalid_json",
                    &path,
                    format!("duplicate member {key:?}"),
                ));
                return Err(de::Error::custom("duplicate member"));
            }
            let value = map.next_value_seed(BoundedValue {
                path: if values.len() == 256 {
                    self.path.clone()
                } else {
                    path
                },
                error: self.error,
                reject: values.len() == 256,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn schema(path: &str, message: impl Into<String>) -> ResourceDiagnostic {
    diagnostic("unsupported_resource", path, message)
}

fn object<'a>(
    value: &'a Value,
    path: &str,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, ResourceDiagnostic> {
    let object = value
        .as_object()
        .ok_or_else(|| schema(path, "expected an object"))?;
    for key in object.keys() {
        if !fields.contains(&key.as_str()) {
            return Err(diagnostic(
                "unknown_field",
                &pointer(path, key),
                format!("unknown field {key:?}"),
            ));
        }
    }
    for field in fields {
        if !object.contains_key(*field) {
            return Err(schema(
                &pointer(path, field),
                format!("missing required field {field:?}"),
            ));
        }
    }
    Ok(object)
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>, ResourceDiagnostic> {
    value
        .as_array()
        .ok_or_else(|| schema(path, "expected an array"))
}

fn integer(value: &Value, path: &str) -> Result<u64, ResourceDiagnostic> {
    value.as_u64().ok_or_else(|| {
        schema(
            path,
            "expected an unsigned integer through u64::MAX, not a floating lexical form",
        )
    })
}

fn scalar(value: &Value, path: &str) -> Result<char, ResourceDiagnostic> {
    let text = value
        .as_str()
        .ok_or_else(|| schema(path, "expected a single-scalar string"))?;
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(symbol), None) => Ok(symbol),
        _ => Err(schema(
            path,
            "expected exactly one Unicode scalar; no normalization is performed",
        )),
    }
}

fn model(value: Value) -> Result<NgramModel, ResourceDiagnostic> {
    let root = object(
        &value,
        "",
        &["resource_version", "kind", "alphabet", "order", "entries"],
    )?;
    if integer(&root["resource_version"], "/resource_version")? != 1 {
        return Err(schema(
            "/resource_version",
            "supported resource_version is integer 1",
        ));
    }
    if root["kind"].as_str() != Some("ngram") {
        return Err(schema("/kind", "expected resource kind ngram"));
    }
    let order = integer(&root["order"], "/order")?;
    if !(1..=6).contains(&order) {
        return Err(schema("/order", "ngram order must be in 1..=6"));
    }
    let symbols = array(&root["alphabet"], "/alphabet")?;
    if symbols.is_empty() {
        return Err(schema("/alphabet", "alphabet must be nonempty"));
    }
    let mut alphabet = Vec::new();
    let mut seen = HashSet::new();
    for (index, value) in symbols.iter().enumerate() {
        let path = pointer("/alphabet", index);
        let symbol = scalar(value, &path)?;
        if !seen.insert(symbol) {
            return Err(schema(&path, "duplicate alphabet scalar"));
        }
        alphabet.push(symbol);
    }
    let alphabet = Alphabet::new(alphabet).map_err(|e| schema("/alphabet", e.to_string()))?;
    let source = array(&root["entries"], "/entries")?;
    if source.is_empty() {
        return Err(schema("/entries", "entries must be nonempty"));
    }
    let mut entries = Vec::with_capacity(source.len());
    let mut grams = HashSet::with_capacity(source.len());
    for (index, value) in source.iter().enumerate() {
        let path = pointer("/entries", index);
        let entry = object(value, &path, &["gram", "count"])?;
        let gram_path = pointer(&path, "gram");
        let source_gram = array(&entry["gram"], &gram_path)?;
        if source_gram.len() != order as usize {
            return Err(schema(
                &gram_path,
                format!("gram must contain exactly {order} scalars"),
            ));
        }
        let mut gram = Vec::with_capacity(order as usize);
        for (position, value) in source_gram.iter().enumerate() {
            let location = pointer(&gram_path, position);
            let symbol = scalar(value, &location)?;
            if alphabet.index_of(symbol).is_none() {
                return Err(schema(
                    &location,
                    "gram scalar is outside the declared alphabet",
                ));
            }
            gram.push(symbol);
        }
        if !grams.insert(gram.clone()) {
            return Err(schema(&gram_path, "duplicate gram"));
        }
        let count_path = pointer(&path, "count");
        let count = integer(&entry["count"], &count_path)?;
        if count == 0 {
            return Err(schema(&count_path, "count must be positive"));
        }
        entries.push((gram, count));
    }
    // The typed constructor retains checked u128 totals and the existing score arithmetic.
    NgramModel::new(alphabet, order as usize, entries)
        .map_err(|e| schema("/entries", e.to_string()))
}

/// Parse bounded strict external n-gram JSON, preserving alphabet order and scalars.
/// No file access, machine-alphabet binding, or selected-measure checks are performed.
pub fn parse_ngram_json(text: &str) -> Result<NgramModel, Vec<ResourceDiagnostic>> {
    if text.len() > MAX_BYTES {
        return Err(vec![diagnostic(
            "resource_limit",
            "",
            "encoded resource exceeds 16 MiB",
        )]);
    }
    let mut decoder = serde_json::Deserializer::from_str(text);
    let mut error = None;
    let value = BoundedValue {
        path: String::new(),
        error: &mut error,
        reject: false,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|cause| {
        vec![error.unwrap_or_else(|| diagnostic("invalid_json", "", cause.to_string()))]
    })?;
    decoder
        .end()
        .map_err(|cause| vec![diagnostic("invalid_json", "", cause.to_string())])?;
    model(value).map_err(|error| vec![error])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Alphabet, NgramModel};

    const MODEL: &str = r#"{"resource_version":1,"kind":"ngram","alphabet":["B","A"],"order":2,"entries":[{"gram":["A","B"],"count":1},{"gram":["B","A"],"count":2}]}"#;

    fn reject(text: &str, code: &str, location: &str) {
        let errors = parse_ngram_json(text).unwrap_err();
        assert_eq!(errors[0].code(), code, "{errors:?}");
        assert_eq!(errors[0].location(), location, "{errors:?}");
        assert!(!errors[0].message().is_empty());
    }

    #[test]
    fn sparse_metadata_and_scores_match_typed_model() {
        let parsed = parse_ngram_json(MODEL).unwrap();
        let typed = NgramModel::new(
            Alphabet::new(vec!['B', 'A']).unwrap(),
            2,
            vec![(vec!['B', 'A'], 2), (vec!['A', 'B'], 1)],
        )
        .unwrap();
        assert_eq!(parsed.alphabet(), typed.alphabet());
        assert_eq!(parsed.order(), 2);
        assert_eq!(parsed.entry_count(), 2);
        assert_eq!(parsed.total_count(), 3);
        assert_eq!(parsed.minimum_count(), 1);
        for text in ["ABA", "BB", "ABBA"] {
            assert_eq!(parsed.score(text), typed.score(text));
        }
    }

    #[test]
    fn duplicate_members_and_trailing_syntax_are_rejected() {
        for extra in [r#", "count":1"#, r#", "co\u0075nt":1"#] {
            reject(
                &MODEL.replacen("\"count\":1", &format!("\"count\":1{extra}"), 1),
                "invalid_json",
                "/entries/0/count",
            );
        }
        reject(&format!("{MODEL} null"), "invalid_json", "");
        reject("{", "invalid_json", "");
        reject(
            &MODEL.replace("\"count\":1", "\"count\":{\"x\":{\"a\":1,\"a\":1}}"),
            "invalid_json",
            "/entries/0/count/x/a",
        );
        reject(
            &MODEL.replace("\"count\":1", "\"count\":{\"a~/\":1,\"a~/\":1}"),
            "invalid_json",
            "/entries/0/count/a~0~1",
        );
    }

    #[test]
    fn container_depth_limits_have_localized_categories() {
        for (open, close, segment) in [("[", "]", "/0"), ("{\"é~/\":", "}", "/é~0~1")] {
            let nested = |depth| format!("{}null{}", open.repeat(depth), close.repeat(depth));
            for depth in [140, 65] {
                reject(&nested(depth), "resource_limit", &segment.repeat(64));
            }
            reject(
                &nested(64),
                if open == "[" {
                    "unsupported_resource"
                } else {
                    "unknown_field"
                },
                if open == "[" { "" } else { "/é~0~1" },
            );
        }
        reject("[null,", "invalid_json", "");
        let text = format!("{}{{\"x\":0,\"x\":1}}{}", "[".repeat(63), "]".repeat(63));
        reject(&text, "invalid_json", &format!("{}/x", "/0".repeat(63)));
    }

    #[test]
    fn integer_lexemes_and_ranges_are_exact() {
        for value in [
            "1.0",
            "1e0",
            "-1",
            "0",
            "18446744073709551616",
            "true",
            "\"1\"",
        ] {
            reject(
                &MODEL.replacen("\"count\":1", &format!("\"count\":{value}"), 1),
                "unsupported_resource",
                "/entries/0/count",
            );
        }
        let maximum =
            parse_ngram_json(&MODEL.replace("\"count\":1", "\"count\":18446744073709551615"))
                .unwrap();
        assert_eq!(maximum.total_count(), u128::from(u64::MAX) + 2);
        for field in ["order", "resource_version"] {
            for value in ["1.0", "1e0", "0", "7", "-1", "null"] {
                let old = if field == "order" { "2" } else { "1" };
                reject(
                    &MODEL.replace(
                        &format!("\"{field}\":{old}"),
                        &format!("\"{field}\":{value}"),
                    ),
                    "unsupported_resource",
                    &format!("/{field}"),
                );
            }
        }
    }

    #[test]
    fn schema_and_unique_grams_are_checked() {
        reject("[]", "unsupported_resource", "");
        reject("{}", "unsupported_resource", "/resource_version");
        for (old, new, code, path) in [
            (
                "\"ngram\"",
                "\"dictionary\"",
                "unsupported_resource",
                "/kind",
            ),
            ("\"order\":2,", "", "unsupported_resource", "/order"),
            (
                "\"order\":2",
                "\"order\":2,\"extra\":0",
                "unknown_field",
                "/extra",
            ),
            (
                "\"count\":1",
                "\"count\":1,\"extra\":0",
                "unknown_field",
                "/entries/0/extra",
            ),
            (
                "[\"A\",\"B\"]",
                "[\"B\",\"A\"]",
                "unsupported_resource",
                "/entries/1/gram",
            ),
            (
                "\"count\":1",
                "\"gramless\":1",
                "unknown_field",
                "/entries/0/gramless",
            ),
            (
                "\"entries\":[",
                "\"entries\":[null,",
                "unsupported_resource",
                "/entries/0",
            ),
            (
                "[\"A\",\"B\"]",
                "[\"A\"]",
                "unsupported_resource",
                "/entries/0/gram",
            ),
            (
                "[\"A\",\"B\"]",
                "[\"A\",\"Z\"]",
                "unsupported_resource",
                "/entries/0/gram/1",
            ),
        ] {
            reject(&MODEL.replace(old, new), code, path);
        }
    }

    #[test]
    fn unicode_scalars_are_preserved_without_normalization() {
        let text = r#"{"resource_version":1,"kind":"ngram","alphabet":["é","e","́","🦀"],"order":2,"entries":[{"gram":["e","́"],"count":1}]}"#;
        let model = parse_ngram_json(text).unwrap();
        assert_eq!(
            model.alphabet(),
            &Alphabet::new(vec!['é', 'e', '\u{301}', '🦀']).unwrap()
        );
        assert!(model.score("e\u{301}").is_ok());
        for scalar in ["", "é", "AB"] {
            reject(
                &MODEL.replace("\"B\",\"A\"", &format!("\"{scalar}\",\"A\"")),
                "unsupported_resource",
                "/alphabet/0",
            );
        }
        reject(
            &MODEL.replace("\"B\",\"A\"", "\"A\",\"A\""),
            "unsupported_resource",
            "/alphabet/1",
        );
    }

    #[test]
    fn bounded_collections_and_input_are_checked() {
        reject(&" ".repeat(16 * 1024 * 1024 + 1), "resource_limit", "");
        let padded = format!("{MODEL}{}", " ".repeat(16 * 1024 * 1024 - MODEL.len()));
        assert!(parse_ngram_json(&padded).is_ok());
        let prefix =
            r#"{"resource_version":1,"kind":"ngram","alphabet":["A"],"order":1,"entries":["#;
        // The over-cap element is deliberately malformed: the limit must win before decoding it.
        let over = format!(
            "{prefix}{}{{",
            "{\"gram\":[\"A\"],\"count\":1},".repeat(250_000)
        );
        reject(&over, "resource_limit", "/entries");
        reject(&format!("{prefix}]}}"), "unsupported_resource", "/entries");
        let alphabet = (0..257)
            .map(|i| format!("\"{}\"", char::from_u32(0x1000 + i).unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        reject(
            &MODEL.replace("[\"B\",\"A\"]", &format!("[{alphabet}]")),
            "resource_limit",
            "/alphabet",
        );
    }

    #[test]
    fn all_supported_orders_and_entry_cap_are_accepted() {
        for order in 1..=6 {
            let gram = vec!["\"A\""; order].join(",");
            let text = format!(
                r#"{{"resource_version":1,"kind":"ngram","alphabet":["A"],"order":{order},"entries":[{{"gram":[{gram}],"count":1}}]}}"#
            );
            assert_eq!(parse_ngram_json(&text).unwrap().order(), order);
        }
        let alphabet = (0..64)
            .map(|i| format!("\"{}\"", char::from_u32(0x1000 + i).unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        let entries = (0..250_000)
            .map(|i| {
                let gram = [i / 4096, i / 64 % 64, i % 64]
                    .map(|n| format!("\"{}\"", char::from_u32(0x1000 + n).unwrap()))
                    .join(",");
                format!(r#"{{"gram":[{gram}],"count":1}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        let text = format!(
            r#"{{"resource_version":1,"kind":"ngram","alphabet":[{alphabet}],"order":3,"entries":[{entries}]}}"#
        );
        assert_eq!(parse_ngram_json(&text).unwrap().entry_count(), 250_000);
    }
}
