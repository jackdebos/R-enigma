//! Detached typed pre-execution checks; no request parsing or attack execution.

use crate::{
    AttackKind, AttackPlugboardDomain, AttackSeedPolicy, AttackSettings, BoundResource,
    SearchDiagnostic, SearchRequest,
};
use std::collections::HashSet;

/// Checked eligibility and cardinalities, not an executable request or budget reservation.
///
/// Construction is available only through [`Self::check`] with a bound carrier.
/// ```compile_fail
/// let gate = enigma_core::AttackGate { outer_total: 1, outer_selected: 1, starts_per_outer: 1 };
/// ```
#[derive(Debug)]
pub struct AttackGate {
    outer_total: u128,
    outer_selected: u128,
    starts_per_outer: u128,
}

fn failure(code: &'static str, message: &str, path: &str) -> Vec<SearchDiagnostic> {
    vec![SearchDiagnostic::new(code, message, path)]
}

impl AttackGate {
    /// Rechecks detached fragments against an immutable, resource-bound search carrier.
    /// Counts describe work domains, not score calls; even budget one is valid.
    pub fn check(
        request: &SearchRequest,
        domain: &AttackPlugboardDomain,
        settings: &AttackSettings,
    ) -> Result<Self, Vec<SearchDiagnostic>> {
        let passes = request.passes();
        crate::space::attack_passes_shape(passes)?;
        if request.space().plugboard().is_some() {
            return Err(failure(
                "unsupported_pass",
                "legacy plugboard pools are not attack domains",
                "/job/space/plugboard",
            ));
        }
        let expected = match settings.kind() {
            AttackKind::HillClimb => "hill_climb",
            AttackKind::PartialExhaustion => "partial_exhaustion",
        };
        if passes[0] != expected {
            return Err(failure(
                "invalid_request",
                "settings kind must match the carrier pass",
                "/job/attack/kind",
            ));
        }
        let alphabet = request.definition().alphabet();
        if !domain.matches_alphabet(alphabet) {
            return Err(failure(
                "invalid_search_space",
                "domain belongs to a different ordered alphabet",
                "/job/space/plugboard",
            ));
        }
        if domain.fixed_pairs() != request.configuration().plugboard() {
            return Err(failure(
                "invalid_search_space",
                "domain fixed facts must equal carrier fixed facts",
                "/job/configuration/plugboard",
            ));
        }
        for (measure, path) in [
            (settings.initial_measure(), "/job/attack/initial_measure"),
            (settings.final_measure(), "/job/attack/final_measure"),
        ] {
            if !request.measures().contains(&measure) {
                return Err(failure(
                    "invalid_request",
                    "objective must be declared by the carrier",
                    path,
                ));
            }
        }
        for (count, path) in [
            (settings.switch_pairs(), "/job/attack/switch_pairs"),
            (settings.backtrack_pairs(), "/job/attack/backtrack_pairs"),
        ] {
            if count > alphabet.len() / 2 {
                return Err(failure(
                    "invalid_search_space",
                    "threshold exceeds current alphabet capacity",
                    path,
                ));
            }
        }
        let samples = request.text().chars().count();
        for measure in request.measures() {
            if samples < measure.minimum_samples() {
                return Err(failure(
                    "invalid_text",
                    "declared measure has insufficient scalar samples",
                    "/job/text",
                ));
            }
            let compatible = match (measure.order(), request.bound_resource(*measure)) {
                (Some(order), Some(BoundResource::Ngram(model))) => {
                    model.order() == order && model.alphabet() == alphabet
                }
                (None, Some(BoundResource::Trie(model))) if *measure == crate::MeasureId::Trie => {
                    model.alphabet() == alphabet
                }
                (None, None) => !measure.requires_resource(),
                _ => false,
            };
            if !compatible {
                return Err(failure(
                    "unsupported_resource",
                    "declared measure requires its compatible retained model",
                    &format!("/job/resources/{}/path", measure.id()),
                ));
            }
        }
        // Settings carry no originating domain identity: recheck branch data, not provenance.
        let starts_per_outer = match (settings.kind(), settings.start(), settings.seed_policy()) {
            (AttackKind::HillClimb, Some(start), None) => {
                let mut occupied: HashSet<char> = domain
                    .fixed_pairs()
                    .iter()
                    .flat_map(|&(a, b)| [a, b])
                    .collect();
                for (i, &(a, b)) in start.iter().enumerate() {
                    if a == b
                        || !domain.symbols().contains(&a)
                        || !domain.symbols().contains(&b)
                        || !occupied.insert(a)
                        || !occupied.insert(b)
                    {
                        return Err(failure(
                            "invalid_search_space",
                            "start must be disjoint and within the current mutable domain",
                            &format!("/job/attack/start/{i}"),
                        ));
                    }
                }
                if start.len() > domain.max_pairs() - domain.fixed_pairs().len() {
                    return Err(failure(
                        "invalid_search_space",
                        "fixed facts plus start exceed current cap",
                        "/job/attack/start",
                    ));
                }
                1
            }
            (AttackKind::PartialExhaustion, None, Some(policy)) => {
                let n = domain.symbols().len() as u128;
                let m = match policy {
                    AttackSeedPolicy::All => n,
                    AttackSeedPolicy::Touching(mask) => {
                        let mut seen = HashSet::new();
                        for (i, symbol) in mask.iter().enumerate() {
                            if !domain.symbols().contains(symbol) || !seen.insert(symbol) {
                                return Err(failure(
                                    "invalid_search_space",
                                    "mask must be a unique subset of the current mutable domain",
                                    &format!("/job/attack/seeds/symbols/{i}"),
                                ));
                            }
                        }
                        mask.len() as u128
                    }
                };
                if domain.fixed_pairs().len() == domain.max_pairs() {
                    1
                } else {
                    // Cross-mask pairs plus unordered pairs internal to the mask, each once.
                    m.checked_mul(n - m)
                        .and_then(|cross| {
                            unordered_pairs(m).and_then(|inside| cross.checked_add(inside))
                        })
                        .and_then(|pairs| pairs.checked_add(1))
                        .ok_or_else(|| {
                            failure(
                                "resource_limit",
                                "seed cardinality exceeds u128",
                                "/job/attack/seeds",
                            )
                        })?
                }
            }
            _ => {
                return Err(failure(
                    "invalid_request",
                    "settings initialization must match its branch",
                    "/job/attack",
                ))
            }
        };
        // Count the full slot-only product before slicing; never enumerate candidates.
        let outer_total = request.candidate_count().ok_or_else(|| {
            failure(
                "resource_limit",
                "full outer cardinality exceeds u128",
                "/job/space",
            )
        })?;
        // Detached stage declarations are checked after resource/text/count preflight.
        for (index, stage) in settings.stages().iter().enumerate() {
            use crate::space::AttackStage;
            let (name, key, measure) = match *stage {
                AttackStage::Reswapping { measure } => ("reswapping", "measure", Some(measure)),
                AttackStage::Measure { measure } => ("measure", "measure", Some(measure)),
                AttackStage::Trie { base_measure } => ("trie", "base_measure", base_measure),
            };
            if measure.is_some_and(|measure| !request.measures().contains(&measure)) {
                return Err(failure(
                    "invalid_request",
                    "stage measure must be declared by the carrier",
                    &settings.stage_measure_path(index, name, key),
                ));
            }
            if name == "trie" && !request.measures().contains(&crate::MeasureId::Trie) {
                return Err(failure(
                    "invalid_request",
                    "trie stage requires declared trie measure",
                    &format!("/job/passes/{}", index + 1),
                ));
            }
        }
        // Reject the entire pipeline if any stage is not implemented or detached.
        if passes.len() != settings.stages().len() + 1
            || passes[1..]
                .iter()
                .zip(settings.stages())
                .any(|(pass, stage)| {
                    !matches!(
                        (pass.as_str(), stage),
                        ("measure", crate::space::AttackStage::Measure { .. })
                            | ("trie", crate::space::AttackStage::Trie { .. })
                    )
                })
        {
            return Err(failure(
                "unsupported_pass",
                "pipeline contains an unsupported or detached stage",
                "/job/passes",
            ));
        }
        let available = outer_total - u128::from(request.space().offset()).min(outer_total);
        let outer_selected = request
            .space()
            .limit()
            .map_or(available, |limit| available.min(u128::from(limit)));
        Ok(Self {
            outer_total,
            outer_selected,
            starts_per_outer,
        })
    }
    /// Full unsliced slot-only outer cardinality.
    pub fn outer_total(&self) -> u128 {
        self.outer_total
    }
    /// Selected outer cardinality after offset and optional limit.
    pub fn outer_selected(&self) -> u128 {
        self.outer_selected
    }
    /// Direct start or empty/single policy cardinality per outer tuple.
    pub fn starts_per_outer(&self) -> u128 {
        self.starts_per_outer
    }
}

fn unordered_pairs(n: u128) -> Option<u128> {
    n.checked_mul(n.saturating_sub(1))
        .map(|product| product / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AttackPlugboardDomain, AttackSettings, MeasureId, ParsedSearchRequest, SearchRequest,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    fn fixture(symbols: &[char]) -> Value {
        let alphabet: Vec<String> = symbols.iter().map(char::to_string).collect();
        json!({"protocol_version":1,"machine":{"definition":{"kind":"custom","value":{
            "alphabet":alphabet,"wheels":[{"name":"r","wiring":alphabet,"turnovers":[]}],
            "slots":[{"id":"r","role":"rotor","movement":"fixed","wheel":"r"}],
            "stepping":{"rules":[]}}}},"job":{"kind":"search",
            "configuration":{"slots":[{"id":"r","position":symbols[0].to_string(),"ring":symbols[0].to_string()}],"plugboard":[]},
            "space":{},"text":symbols[0].to_string().repeat(6),"passes":["hill_climb"],"measures":["ic","entropy"]}})
    }
    fn bound(value: &Value) -> SearchRequest {
        SearchRequest::parse_json(&value.to_string()).unwrap()
    }
    fn domain(request: &SearchRequest, symbols: &[char], cap: usize) -> AttackPlugboardDomain {
        AttackPlugboardDomain::parse_json(request.definition().alphabet(), request.configuration().plugboard(),
            &json!({"kind":"attack","symbols":symbols.iter().map(char::to_string).collect::<Vec<_>>(),"max_pairs":cap}).to_string()).unwrap()
    }
    fn settings(
        request: &SearchRequest,
        domain: &AttackPlugboardDomain,
        kind: &str,
        initialization: Value,
    ) -> AttackSettings {
        let mut value = json!({"kind":kind,"initial_measure":"ic","final_measure":"entropy",
            "switch_pairs":0,"backtrack_pairs":0,"evaluation_budget":1});
        value[if kind == "hill_climb" {
            "start"
        } else {
            "seeds"
        }] = initialization;
        AttackSettings::parse_json(
            request.definition().alphabet(),
            domain,
            &[kind.to_owned()],
            &[MeasureId::Ic, MeasureId::Entropy],
            &value.to_string(),
        )
        .unwrap()
    }
    fn error(
        request: &SearchRequest,
        domain: &AttackPlugboardDomain,
        settings: &AttackSettings,
        code: &str,
        path: &str,
    ) {
        let errors = AttackGate::check(request, domain, settings).unwrap_err();
        assert_eq!((errors[0].code(), errors[0].location()), (code, path));
    }

    #[test]
    fn fixed_no_reflector_unicode_budget_one_and_slicing() {
        let mut value = fixture(&['é', '🦀', 'A', 'B']);
        let request = bound(&value);
        let domain = domain(&request, &['é', '🦀'], 1);
        let settings = settings(&request, &domain, "hill_climb", json!([["é", "🦀"]]));
        let gate = AttackGate::check(&request, &domain, &settings).unwrap();
        assert_eq!(
            (
                gate.outer_total(),
                gate.outer_selected(),
                gate.starts_per_outer()
            ),
            (1, 1, 1)
        );
        value["job"]["space"] = json!({"offset":9});
        assert_eq!(
            AttackGate::check(&bound(&value), &domain, &settings)
                .unwrap()
                .outer_selected(),
            0
        );
        value["job"]["configuration"]["slots"][0]
            .as_object_mut()
            .unwrap()
            .remove("position");
        value["job"]["space"] =
            json!({"slots":[{"id":"r","positions":["é","🦀","A","B"]}],"offset":1,"limit":2});
        let gate = AttackGate::check(&bound(&value), &domain, &settings).unwrap();
        assert_eq!((gate.outer_total(), gate.outer_selected()), (4, 2));
    }

    #[test]
    fn cross_fragment_compatibility_is_rechecked() {
        let request = bound(&fixture(&['A', 'B', 'C', 'D', 'E', 'F']));
        let original = domain(&request, &['A', 'B', 'C', 'D'], 2);
        let start = settings(
            &request,
            &original,
            "hill_climb",
            json!([["A", "B"], ["C", "D"]]),
        );
        let smaller = domain(&request, &['A', 'B'], 1);
        error(
            &request,
            &smaller,
            &start,
            "invalid_search_space",
            "/job/attack/start/1",
        );
        let lower_cap = domain(&request, &['A', 'B', 'C', 'D'], 1);
        error(
            &request,
            &lower_cap,
            &start,
            "invalid_search_space",
            "/job/attack/start",
        );
        let other = bound(&fixture(&['B', 'A', 'C', 'D', 'E', 'F']));
        error(
            &other,
            &original,
            &start,
            "invalid_search_space",
            "/job/space/plugboard",
        );
        let mut changed = fixture(&['A', 'B', 'C', 'D', 'E', 'F']);
        changed["job"]["configuration"]["plugboard"] = json!([["E", "F"]]);
        error(
            &bound(&changed),
            &original,
            &start,
            "invalid_search_space",
            "/job/configuration/plugboard",
        );
        changed["job"]["configuration"]["plugboard"] = json!([]);
        changed["job"]["measures"] = json!(["ic"]);
        error(
            &bound(&changed),
            &original,
            &start,
            "invalid_request",
            "/job/attack/final_measure",
        );
        changed["job"]["measures"] = json!(["entropy"]);
        error(
            &bound(&changed),
            &original,
            &start,
            "invalid_request",
            "/job/attack/initial_measure",
        );
    }

    #[test]
    fn passes_pool_and_complete_requests_remain_separate() {
        let mut value = fixture(&['A', 'B', 'C', 'D']);
        let request = bound(&value);
        let domain = domain(&request, &['A', 'B'], 1);
        let settings = settings(&request, &domain, "hill_climb", json!([]));
        for passes in [
            json!(["measure"]),
            json!(["reswapping"]),
            json!(["trie"]),
            json!(["hill_climb", "partial_exhaustion"]),
            json!(["hill_climb", "measure"]), // Carrier/settings mismatch remains rejected.
            json!(["hill_climb", "measure", "reswapping"]),
        ] {
            value["job"]["passes"] = passes;
            error(
                &bound(&value),
                &domain,
                &settings,
                "unsupported_pass",
                "/job/passes",
            );
        }
        value["job"]["passes"] = json!(["partial_exhaustion"]);
        error(
            &bound(&value),
            &domain,
            &settings,
            "invalid_request",
            "/job/attack/kind",
        );
        value["job"]["passes"] = json!(["hill_climb"]);
        value["job"]["space"]["plugboard"] = json!({"candidates":[["C","D"]],"size":1});
        error(
            &bound(&value),
            &domain,
            &settings,
            "unsupported_pass",
            "/job/space/plugboard",
        );
        value["job"]["space"]["plugboard"] =
            json!({"kind":"attack","symbols":["A","B"],"max_pairs":1});
        assert!(ParsedSearchRequest::parse_json(&value.to_string()).is_err());
        value["job"]["space"] = json!({});
        value["job"]["attack"] = json!({"kind":"hill_climb"});
        assert!(ParsedSearchRequest::parse_json(&value.to_string()).is_err());
    }

    #[test]
    fn reswapping_rejects_the_whole_supported_pipeline() {
        let mut value = fixture(&['A', 'B', 'C', 'D']);
        value["job"]["passes"] = json!(["hill_climb", "measure", "trie"]);
        value["job"]["measures"] = json!(["ic", "entropy", "trie"]);
        value["job"]["resources"] = json!({"trie":{"path":"words.json"}});
        value["job"]["space"]["plugboard"] =
            json!({"kind":"attack","symbols":["A","B"],"max_pairs":1});
        value["job"]["attack"] = json!({"kind":"hill_climb","initial_measure":"ic","final_measure":"entropy",
            "switch_pairs":0,"backtrack_pairs":0,"evaluation_budget":1,"start":[],"trie":{"x":1}});
        let errors = crate::ParsedAttackRequest::parse_json(&value.to_string()).unwrap_err();
        assert_eq!(
            (errors[0].code(), errors[0].location()),
            ("unknown_field", "/job/attack/trie/x")
        );
        value["job"]["attack"]["trie"] = json!({"base_measure":"ic"});
        let trie = json!({"resource_version":1,"kind":"dictionary","alphabet":["A","B","C","D"],
            "entries":[{"word":["A"],"weight":1}]})
        .to_string();
        let mut carrier = value.clone();
        carrier["job"].as_object_mut().unwrap().remove("attack");
        carrier["job"]["space"]
            .as_object_mut()
            .unwrap()
            .remove("plugboard");
        let carrier = ParsedSearchRequest::parse_json(&carrier.to_string())
            .unwrap()
            .bind_resources(&BTreeMap::from([("trie".to_owned(), trie.as_str())]))
            .unwrap();
        let domain = domain(&carrier, &['A', 'B'], 1);
        let reversed = AttackSettings::parse_json(
            carrier.definition().alphabet(),
            &domain,
            &["hill_climb".into(), "trie".into(), "measure".into()],
            carrier.measures(),
            &value["job"]["attack"].to_string(),
        )
        .unwrap();
        error(
            &carrier,
            &domain,
            &reversed,
            "unsupported_pass",
            "/job/passes",
        );
        value["job"]["passes"] = json!(["hill_climb", "measure", "trie", "reswapping"]);
        value["job"]["attack"]["reswapping"] = json!({"measure":"ic"});
        let errors = crate::ParsedAttackRequest::parse_json(&value.to_string())
            .unwrap()
            .bind_resources(&BTreeMap::from([("trie".to_owned(), trie.as_str())]))
            .unwrap_err();
        assert_eq!(
            (errors[0].code(), errors[0].location()),
            ("unsupported_pass", "/job/passes")
        );
    }

    #[test]
    fn settings_from_another_alphabet_recheck_thresholds() {
        let wide = bound(&fixture(&['A', 'B', 'C', 'D']));
        let old_domain = domain(&wide, &['A', 'B'], 1);
        let settings = AttackSettings::parse_json(
            wide.definition().alphabet(),
            &old_domain,
            wide.passes(),
            wide.measures(),
            &json!({"kind":"hill_climb","initial_measure":"ic",
                "final_measure":"entropy","switch_pairs":2,"backtrack_pairs":0,
                "evaluation_budget":1,"start":[]})
            .to_string(),
        )
        .unwrap();
        let narrow = bound(&fixture(&['A', 'B']));
        let new_domain = domain(&narrow, &['A', 'B'], 1);
        error(
            &narrow,
            &new_domain,
            &settings,
            "invalid_search_space",
            "/job/attack/switch_pairs",
        );
    }

    #[test]
    fn detached_stage_declarations_keep_explicit_and_default_locations() {
        let request = bound(&fixture(&['A', 'B']));
        let domain = domain(&request, &['A', 'B'], 1);
        for (stage, fields, missing, path) in [
            ("measure", Value::Null, MeasureId::Ic, "/job/passes/1"),
            ("measure", json!({}), MeasureId::Ic, "/job/passes/1"),
            (
                "measure",
                json!({"measure":"trie"}),
                MeasureId::Trie,
                "/job/attack/measure/measure",
            ),
            (
                "reswapping",
                json!({}),
                MeasureId::SinkovTrigram,
                "/job/passes/1",
            ),
            (
                "reswapping",
                json!({"measure":"trie"}),
                MeasureId::Trie,
                "/job/attack/reswapping/measure",
            ),
            ("trie", json!({}), MeasureId::Trie, "/job/passes/1"),
            (
                "trie",
                json!({"base_measure":"entropy"}),
                MeasureId::Trie,
                "/job/passes/1",
            ),
            (
                "trie",
                json!({"base_measure":"trie"}),
                MeasureId::Trie,
                "/job/attack/trie/base_measure",
            ),
        ] {
            let mut fragment = json!({"kind":"hill_climb","initial_measure":"entropy",
                "final_measure":"entropy","switch_pairs":0,"backtrack_pairs":0,
                "evaluation_budget":1,"start":[]});
            if !fields.is_null() {
                fragment[stage] = fields;
            }
            let settings = AttackSettings::parse_json(
                request.definition().alphabet(),
                &domain,
                &["hill_climb".into(), stage.into()],
                &[MeasureId::Entropy, missing],
                &fragment.to_string(),
            )
            .unwrap();
            let mut current = fixture(&['A', 'B']);
            current["job"]["measures"] = json!(["entropy"]);
            current["job"]["passes"] = json!(["hill_climb", stage]);
            error(
                &bound(&current),
                &domain,
                &settings,
                "invalid_request",
                path,
            );
        }
    }

    // Independent tiny unordered-pair oracle, used only to check algebraic counts.
    fn oracle(symbols: &[char], mask: Option<&[char]>) -> u128 {
        let mut count = 1;
        for (i, a) in symbols.iter().enumerate() {
            for b in &symbols[i + 1..] {
                if mask.is_none_or(|mask| mask.contains(a) || mask.contains(b)) {
                    count += 1;
                }
            }
        }
        count
    }
    #[test]
    fn partial_counts_all_touching_both_masked_cap_and_singleton() {
        let mut value = fixture(&['A', 'B', 'C', 'D', 'E', 'F']);
        value["job"]["passes"] = json!(["partial_exhaustion"]);
        let request = bound(&value);
        for symbols in [vec!['A'], vec!['A', 'B'], vec!['A', 'B', 'C', 'D']] {
            let domain = domain(&request, &symbols, symbols.len() / 2);
            for mask in [None, Some(vec![symbols[0]]), Some(symbols.clone())] {
                let policy = match &mask {
                    None => json!({"kind":"empty_single","selection":"all"}),
                    Some(mask) => {
                        json!({"kind":"empty_single","selection":"touching","symbols":mask.iter().map(char::to_string).collect::<Vec<_>>()})
                    }
                };
                let settings = settings(&request, &domain, "partial_exhaustion", policy);
                let expected = if domain.max_pairs() == 0 {
                    1
                } else {
                    oracle(&symbols, mask.as_deref())
                };
                assert_eq!(
                    AttackGate::check(&request, &domain, &settings)
                        .unwrap()
                        .starts_per_outer(),
                    expected
                );
            }
        }
        let original = domain(&request, &['A', 'B', 'C', 'D'], 2);
        let masked = settings(
            &request,
            &original,
            "partial_exhaustion",
            json!({"kind":"empty_single","selection":"touching","symbols":["A","B"]}),
        );
        let changed = domain(&request, &['C', 'D'], 1);
        error(
            &request,
            &changed,
            &masked,
            "invalid_search_space",
            "/job/attack/seeds/symbols/0",
        );
        value["job"]["configuration"]["plugboard"] = json!([["E", "F"]]);
        let request = bound(&value);
        let domain = domain(&request, &['A', 'B'], 1);
        let settings = settings(
            &request,
            &domain,
            "partial_exhaustion",
            json!({"kind":"empty_single","selection":"all"}),
        );
        assert_eq!(
            AttackGate::check(&request, &domain, &settings)
                .unwrap()
                .starts_per_outer(),
            1
        );
    }

    #[test]
    fn all_declared_models_and_minimums_use_public_binding() {
        let mut value = fixture(&['é', '🦀']);
        value["job"]["measures"] = json!(["ic", "entropy", "sinkov_hexagram", "trie"]);
        value["job"]["resources"] =
            json!({"sinkov_hexagram":{"path":"six.json"},"trie":{"path":"words.json"}});
        let ngram = json!({"resource_version":1,"kind":"ngram","alphabet":["é","🦀"],"order":6,
            "entries":[{"gram":["é","é","é","é","é","é"],"count":1}]})
        .to_string();
        let trie = json!({"resource_version":1,"kind":"dictionary","alphabet":["é","🦀"],
            "entries":[{"word":["é"],"weight":1}]})
        .to_string();
        let supplied = BTreeMap::from([
            ("sinkov_hexagram".to_owned(), ngram.as_str()),
            ("trie".to_owned(), trie.as_str()),
        ]);
        let parsed = ParsedSearchRequest::parse_json(&value.to_string()).unwrap();
        assert!(ParsedSearchRequest::parse_json(&value.to_string())
            .unwrap()
            .bind_resources(&BTreeMap::new())
            .is_err());
        let request = parsed.bind_resources(&supplied).unwrap();
        let domain = domain(&request, &['é', '🦀'], 1);
        let settings = settings(&request, &domain, "hill_climb", json!([]));
        assert!(AttackGate::check(&request, &domain, &settings).is_ok());
        // A short or wrong-model bound carrier cannot be created through this API.
        for text in ["é", "ééééé"] {
            value["job"]["text"] = json!(text);
            assert!(ParsedSearchRequest::parse_json(&value.to_string()).is_err());
        }
        let wrong_order = ngram.replace("\"order\":6", "\"order\":5");
        value["job"]["text"] = json!("éééééé");
        let bad = BTreeMap::from([
            ("sinkov_hexagram".to_owned(), wrong_order.as_str()),
            ("trie".to_owned(), trie.as_str()),
        ]);
        assert!(ParsedSearchRequest::parse_json(&value.to_string())
            .unwrap()
            .bind_resources(&bad)
            .is_err());
    }

    #[test]
    fn full_outer_overflow_even_limit_one_and_no_u64_ceiling() {
        let symbols: Vec<char> = (0..256)
            .map(|i| char::from_u32(0x100 + i).unwrap())
            .collect();
        let mut value = fixture(&symbols);
        let alphabet: Vec<String> = symbols.iter().map(char::to_string).collect();
        for slots in [5, 8] {
            value["machine"]["definition"]["value"]["slots"] = json!((0..slots)
                .map(
                    |i| json!({"id":format!("r{i}"),"role":"rotor","movement":"fixed","wheel":"r"})
                )
                .collect::<Vec<_>>());
            value["job"]["configuration"]["slots"] = json!([]);
            value["job"]["space"] = json!({"limit":1,"slots":(0..slots).map(|i| json!({"id":format!("r{i}"),"positions":alphabet,"rings":alphabet})).collect::<Vec<_>>()});
            let request = bound(&value);
            let domain = domain(&request, &symbols[..2], 1);
            let settings = settings(&request, &domain, "hill_climb", json!([]));
            if slots == 8 {
                assert_eq!(request.candidate_count(), None);
                error(&request, &domain, &settings, "resource_limit", "/job/space");
                let staged = AttackSettings::parse_json(
                    request.definition().alphabet(),
                    &domain,
                    &["hill_climb".into(), "measure".into()],
                    &[MeasureId::Ic, MeasureId::Entropy, MeasureId::Trie],
                    &json!({"kind":"hill_climb","initial_measure":"ic",
                        "final_measure":"entropy","switch_pairs":0,"backtrack_pairs":0,
                        "evaluation_budget":1,"start":[],"measure":{"measure":"trie"}})
                    .to_string(),
                )
                .unwrap();
                error(&request, &domain, &staged, "resource_limit", "/job/space");
            } else {
                let gate = AttackGate::check(&request, &domain, &settings).unwrap();
                assert_eq!(
                    (gate.outer_total(), gate.outer_selected()),
                    (1u128 << 80, 1)
                );
            }
        }
    }
}
