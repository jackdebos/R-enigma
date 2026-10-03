//! Pure supplied-text binding; filesystem paths are diagnostic metadata only.

use crate::space::SearchDiagnostic;
use crate::{
    parse_dictionary_json, parse_ngram_json, MeasureId, NgramModel, ParsedSearchRequest,
    RequestDiagnostic, ResourceReference, TrieModel, MAX_RESOURCE_BYTES,
};
use std::collections::BTreeMap;

/// Maximum encoded resource text counted independently for each reference.
pub const MAX_RESOURCE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Maximum resource references in one request (currently only seven IDs need resources).
pub const MAX_RESOURCE_REFERENCES: usize = 16;

/// Retained immutable scoring model; no raw JSON copy or model reconstruction is needed.
#[derive(Debug)]
pub enum BoundResource {
    /// Sparse Sinkov model, already checked against the selected order and alphabet.
    Ngram(NgramModel),
    /// Exact weighted dictionary, already checked against the machine alphabet.
    Trie(TrieModel),
}

fn reference_pointer(id: &str) -> String {
    format!(
        "/job/resources/{}/path",
        id.replace('~', "~0").replace('/', "~1")
    )
}

fn reference_error(code: &'static str, id: &str, message: &str) -> Vec<RequestDiagnostic> {
    vec![SearchDiagnostic::new(code, message, reference_pointer(id)).into()]
}

fn model_error(
    reference: &ResourceReference,
    code: &'static str,
    location: &str,
    message: &str,
) -> Vec<RequestDiagnostic> {
    vec![SearchDiagnostic::new(
        code,
        format!(
            "measure {:?}, selected file {:?}: {message}",
            reference.measure().id(),
            reference.path()
        ),
        location,
    )
    .into()]
}

pub(crate) fn bind(
    request: &ParsedSearchRequest,
    supplied: &BTreeMap<String, &str>,
) -> Result<Vec<(MeasureId, BoundResource)>, Vec<RequestDiagnostic>> {
    // Reject extras in sorted string-key order, including unknown IDs and resource-free selections.
    for id in supplied.keys() {
        if !request
            .resources()
            .iter()
            .any(|reference| reference.measure().id() == id)
        {
            return Err(reference_error(
                "unsupported_resource",
                id,
                "supplied content has no selected resource reference; remove the extra key",
            ));
        }
    }
    let references = request.resources();
    if references.len() > MAX_RESOURCE_REFERENCES {
        let reference = &references[MAX_RESOURCE_REFERENCES];
        return Err(model_error(
            reference,
            "resource_limit",
            &reference_pointer(reference.measure().id()),
            "request exceeds 16 resource references; select fewer resources",
        ));
    }
    // Complete all key and byte checks before parsing or allocating any model.
    let mut total = 0usize;
    for reference in references {
        let id = reference.measure().id();
        let text = supplied.get(id).ok_or_else(|| {
            model_error(
                reference,
                "unsupported_resource",
                &reference_pointer(id),
                "missing supplied UTF-8 content; load and supply this reference",
            )
        })?;
        if text.len() > MAX_RESOURCE_BYTES {
            return Err(model_error(
                reference,
                "resource_limit",
                &reference_pointer(id),
                "resource text exceeds 16 MiB; supply a smaller resource",
            ));
        }
        total = total
            .checked_add(text.len())
            .filter(|total| *total <= MAX_RESOURCE_TOTAL_BYTES)
            .ok_or_else(|| {
                model_error(
                    reference,
                    "resource_limit",
                    &reference_pointer(id),
                    "aggregate resource text exceeds 64 MiB; select smaller resources",
                )
            })?;
    }
    let contextualize = |reference: &ResourceReference, errors: Vec<crate::ResourceDiagnostic>| {
        errors
            .iter()
            .flat_map(|error| {
                // Standalone parsers expose a borrowed code; these are their frozen categories.
                let code = match error.code() {
                    "invalid_json" => "invalid_json",
                    "unknown_field" => "unknown_field",
                    "resource_limit" => "resource_limit",
                    _ => "unsupported_resource",
                };
                model_error(reference, code, error.location(), error.message())
            })
            .collect::<Vec<_>>()
    };
    let mut models = Vec::with_capacity(references.len());
    for reference in references {
        let measure = reference.measure();
        let text = supplied[measure.id()];
        let resource = if let Some(order) = measure.order() {
            let model =
                parse_ngram_json(text).map_err(|errors| contextualize(reference, errors))?;
            if model.order() != order {
                return Err(model_error(
                    reference,
                    "unsupported_resource",
                    "/order",
                    "n-gram order must match the selected Sinkov measure",
                ));
            }
            if model.alphabet() != request.definition().alphabet() {
                return Err(model_error(
                    reference,
                    "unsupported_resource",
                    "/alphabet",
                    "resource alphabet must equal the machine alphabet, including order",
                ));
            }
            BoundResource::Ngram(model)
        } else {
            let model =
                parse_dictionary_json(text).map_err(|errors| contextualize(reference, errors))?;
            if model.alphabet() != request.definition().alphabet() {
                return Err(model_error(
                    reference,
                    "unsupported_resource",
                    "/alphabet",
                    "resource alphabet must equal the machine alphabet, including order",
                ));
            }
            BoundResource::Trie(model)
        };
        models.push((measure, resource));
    }
    Ok(models)
}

#[cfg(test)]
mod tests {
    use crate::{BoundResource, MeasureId, ParsedSearchRequest, RequestDiagnostic, SCALE};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    fn request(ids: &[&str]) -> ParsedSearchRequest {
        let resources: BTreeMap<_, _> = ids
            .iter()
            .filter(|id| !["ic", "entropy"].contains(id))
            .map(|id| (*id, json!({"path": "same/model.json"})))
            .collect();
        let value = json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "custom", "value": {
                "alphabet": ["A", "B"],
                "wheels": [{"name": "r", "wiring": ["B", "A"], "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
                "stepping": {"rules": []}
            }}},
            "job": {"kind": "search", "configuration": {"slots": [{"id": "r", "ring": "A"}], "plugboard": []},
                "space": {"slots": [{"id": "r", "positions": ["A", "B"]}]},
                "text": "AAAAAA", "passes": ["hill_climb"], "measures": ids, "resources": resources}
        });
        ParsedSearchRequest::parse_json(&value.to_string()).unwrap()
    }

    fn ngram(order: usize) -> Value {
        json!({"resource_version": 1, "kind": "ngram", "alphabet": ["A", "B"],
            "order": order, "entries": [{"gram": vec!["A"; order], "count": 1}]})
    }
    fn dictionary() -> Value {
        json!({"resource_version": 1, "kind": "dictionary", "alphabet": ["A", "B"],
            "entries": [{"word": ["A"], "weight": 2}]})
    }
    fn contents<'a>(id: &str, text: &'a str) -> BTreeMap<String, &'a str> {
        BTreeMap::from([(id.to_owned(), text)])
    }
    fn assert_error(error: &[RequestDiagnostic], code: &str, location: &str) {
        assert_eq!((error[0].code(), error[0].location()), (code, location));
    }

    #[test]
    fn all_models_are_retained_for_scoring_and_enumeration_without_reflector() {
        let ids = [
            "sinkov_monogram",
            "sinkov_bigram",
            "sinkov_trigram",
            "sinkov_quadgram",
            "sinkov_pentagram",
            "sinkov_hexagram",
            "trie",
        ];
        let texts: Vec<_> = (1..=6)
            .map(|order| ngram(order).to_string())
            .chain(std::iter::once(dictionary().to_string()))
            .collect();
        let supplied = ids
            .iter()
            .zip(&texts)
            .map(|(id, text)| ((*id).to_owned(), text.as_str()))
            .collect();
        let parsed = request(&ids);
        // All seven expressible dependent IDs succeed; >16 valid references cannot
        // be represented without weakening the structural selection types.
        assert_eq!(parsed.resources().len(), 7);
        assert!(parsed.resources().len() < crate::MAX_RESOURCE_REFERENCES);
        let bound = parsed.bind_resources(&supplied).unwrap();
        drop(supplied);
        drop(texts);
        for measure in bound.measures() {
            match bound.bound_resource(*measure).unwrap() {
                BoundResource::Ngram(model) => {
                    assert_eq!(model.order(), measure.order().unwrap());
                    assert_eq!(model.score(bound.text()).unwrap().measured().units(), 0);
                }
                BoundResource::Trie(model) => {
                    assert_eq!(
                        model.score(bound.text()).unwrap().measured().units(),
                        12 * SCALE
                    );
                }
            }
        }
        assert_eq!(bound.candidate_count(), Some(2));
        assert_eq!(bound.candidates().count(), 2);
        assert!(bound.candidate_at(1).unwrap().is_ok());
        assert!(bound.bound_resource(MeasureId::Ic).is_none());
    }

    #[test]
    fn exact_supplied_keys_and_empty_resource_free_binding() {
        assert!(request(&["ic"]).bind_resources(&BTreeMap::new()).is_ok());
        let error = request(&["trie"])
            .bind_resources(&BTreeMap::new())
            .unwrap_err();
        assert_error(&error, "unsupported_resource", "/job/resources/trie/path");
        for ids in [&["ic"][..], &["trie"][..]] {
            let error = request(ids)
                .bind_resources(&contents("a~/extra", "BODY_SECRET"))
                .unwrap_err();
            assert_error(
                &error,
                "unsupported_resource",
                "/job/resources/a~0~1extra/path",
            );
            assert!(!error[0].message().contains("BODY_SECRET"));
        }
    }

    #[test]
    fn compatibility_is_exact_not_repaired() {
        let mut cases = Vec::new();
        let mut wrong_ngram_kind = ngram(2);
        wrong_ngram_kind["kind"] = json!("dictionary");
        cases.push(("sinkov_bigram", wrong_ngram_kind, "/kind"));
        let mut wrong_dictionary_kind = dictionary();
        wrong_dictionary_kind["kind"] = json!("ngram");
        cases.push(("trie", wrong_dictionary_kind, "/kind"));
        cases.push(("sinkov_bigram", ngram(1), "/order"));
        let mut reversed = ngram(2);
        reversed["alphabet"] = json!(["B", "A"]);
        cases.push(("sinkov_bigram", reversed, "/alphabet"));
        let mut other = dictionary();
        other["alphabet"] = json!(["A", "C"]);
        cases.push(("trie", other, "/alphabet"));
        for (id, value, location) in cases {
            let text = value.to_string();
            let error = request(&[id])
                .bind_resources(&contents(id, &text))
                .unwrap_err();
            assert_error(&error, "unsupported_resource", location);
            assert!(error[0].message().contains(id));
            assert!(error[0].message().contains("same/model.json"));
        }
    }

    #[test]
    fn parser_errors_keep_resource_pointer_and_context() {
        let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        for (text, code, pointer) in [
            ("{", "invalid_json", ""),
            (
                r#"{"kind":"dictionary","kind":"dictionary"}"#,
                "invalid_json",
                "/kind",
            ),
            (deep.as_str(), "resource_limit", "/0"),
        ] {
            let error = request(&["trie"])
                .bind_resources(&contents("trie", text))
                .unwrap_err();
            assert_eq!(error[0].code(), code);
            if code == "resource_limit" {
                assert_eq!(error[0].location(), "/0".repeat(64));
            } else {
                assert_eq!(error[0].location(), pointer);
            }
            assert!(error[0].message().contains("trie"));
            assert!(error[0].message().contains("same/model.json"));
        }
        let mut invalid = dictionary();
        invalid["entries"][0]["weight"] = json!(1.5);
        let text = invalid.to_string();
        let error = request(&["trie"])
            .bind_resources(&contents("trie", &text))
            .unwrap_err();
        assert_error(&error, "unsupported_resource", "/entries/0/weight");
        let zero = dictionary()
            .to_string()
            .replace("\"weight\":2", "\"weight\":-0");
        assert!(request(&["trie"])
            .bind_resources(&contents("trie", &zero))
            .is_ok());
    }

    #[test]
    fn nested_schema_diagnostics_and_extra_order_are_stable() {
        for (text, code, pointer) in [
            (
                r#"{"resource_version":1,"kind":"dictionary","alphabet":["A","B"],"entries":[{"word":["A"],"weight":2,"weight":2}]}"#,
                "invalid_json",
                "/entries/0/weight",
            ),
            (
                r#"{"resource_version":1,"kind":"dictionary","alphabet":["A","B"],"entries":[{"word":["A"],"weight":2,"extra":0}]}"#,
                "unknown_field",
                "/entries/0/extra",
            ),
        ] {
            let error = request(&["trie"])
                .bind_resources(&contents("trie", text))
                .unwrap_err();
            assert_error(&error, code, pointer);
            assert!(error[0].message().contains("same/model.json"));
            assert!(!error[0].message().contains(text));
        }
        let supplied = BTreeMap::from([("z".to_owned(), ""), ("a".to_owned(), "")]);
        let error = request(&["trie"]).bind_resources(&supplied).unwrap_err();
        assert_error(&error, "unsupported_resource", "/job/resources/a/path");
    }

    #[test]
    fn exact_per_reference_boundary_accepts_valid_content() {
        let mut text = dictionary().to_string();
        text.extend(std::iter::repeat_n(
            ' ',
            crate::MAX_RESOURCE_BYTES - text.len(),
        ));
        let bound = request(&["trie"])
            .bind_resources(&contents("trie", &text))
            .unwrap();
        drop(text);
        let BoundResource::Trie(model) = bound.bound_resource(MeasureId::Trie).unwrap() else {
            panic!("expected retained dictionary");
        };
        assert_eq!(model.score("A").unwrap().measured().units(), 2 * SCALE);
    }

    #[test]
    fn budgets_precede_parsing_and_count_each_identical_path_reference() {
        let oversized = " ".repeat(crate::MAX_RESOURCE_BYTES + 1);
        let error = request(&["trie"])
            .bind_resources(&contents("trie", &oversized))
            .unwrap_err();
        assert_error(&error, "resource_limit", "/job/resources/trie/path");
        // One allocation borrowed five times; invalid JSON proves budgets run before parsers.
        let text = " ".repeat(crate::MAX_RESOURCE_BYTES);
        let ids = [
            "sinkov_monogram",
            "sinkov_bigram",
            "sinkov_trigram",
            "sinkov_quadgram",
            "trie",
        ];
        let supplied = ids
            .iter()
            .map(|id| ((*id).to_owned(), text.as_str()))
            .collect();
        let error = request(&ids).bind_resources(&supplied).unwrap_err();
        assert_error(&error, "resource_limit", "/job/resources/trie/path");
        // At exactly 64 MiB, the first parser (not the aggregate guard) rejects whitespace.
        let supplied = ids[..4]
            .iter()
            .map(|id| ((*id).to_owned(), text.as_str()))
            .collect();
        let error = request(&ids[..4]).bind_resources(&supplied).unwrap_err();
        assert_eq!(error[0].code(), "invalid_json");
    }
}
