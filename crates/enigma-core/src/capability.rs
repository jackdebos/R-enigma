//! Capability registry and search-job preflight framework (Task 9, slice 9.4).
//!
//! The frozen `docs/protocol.md` §3.3 boundary states that unsupported topology, pass,
//! measure, and resource combinations fail preflight before enumeration. This module owns
//! the registry of recognized Stage 1 passes and their topology requirements, plus the
//! extension framework Task 10 seeds with concrete measure and resource rules.
//!
//! Only the boundary is modeled here: no pass executes, no measure is scored, and no
//! resource semantic is implemented.

use crate::definition::Definition;
use crate::space::{ParsedSearchRequest, SearchDiagnostic, SearchRequest};
use crate::SlotRole;
use serde_json::Value;

/// A recognized Stage 1 pass and its definition-topology requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassSupport {
    id: &'static str,
    requires_reflector: bool,
}

impl PassSupport {
    /// Creates one registry entry from its identifier and topology requirement.
    pub fn new(id: &'static str, requires_reflector: bool) -> Self {
        Self {
            id,
            requires_reflector,
        }
    }

    /// Stable pass identifier.
    pub fn id(&self) -> &str {
        self.id
    }

    /// Whether the definition topology must contain a reflector for this pass.
    pub fn requires_reflector(&self) -> bool {
        self.requires_reflector
    }
}

/// Compatibility policy for a boundary field whose concrete rules Task 10 defines.
///
/// `Deferred` accepts every value, which is the Stage 1 default; `Allowlist` is the
/// extension point Task 10 seeds with concrete measure and resource identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityPolicy {
    /// Accepts every value; concrete rules are deferred to Task 10.
    Deferred,
    /// Accepts only the listed identifiers.
    Allowlist(Vec<String>),
}

impl CapabilityPolicy {
    fn permits(&self, id: &str) -> bool {
        match self {
            Self::Deferred => true,
            Self::Allowlist(ids) => ids.iter().any(|allowed| allowed == id),
        }
    }
}

/// Registry of recognized passes and the measure and resource compatibility policies.
///
/// [`Capabilities::stage1`] is the concrete Stage 1 registry whose
/// [`Capabilities::preflight`] gate consumes a parsed search request. Tasks 11–13 extend
/// the pass list; Task 10 seeds the measure and resource policies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    passes: Vec<PassSupport>,
    measures: CapabilityPolicy,
    resources: CapabilityPolicy,
}

impl Capabilities {
    /// The Stage 1 registry: five recognized passes with no topology restriction, and
    /// deferred measure and resource policies.
    pub fn stage1() -> Self {
        Self {
            passes: vec![
                PassSupport::new("hill_climb", false),
                PassSupport::new("bombe", false),
                PassSupport::new("partial_exhaustion", false),
                PassSupport::new("reswapping", false),
                PassSupport::new("trie", false),
                PassSupport::new("measure", false),
            ],
            measures: CapabilityPolicy::Deferred,
            resources: CapabilityPolicy::Deferred,
        }
    }

    /// Replaces the measure compatibility policy.
    pub fn with_measures(mut self, policy: CapabilityPolicy) -> Self {
        self.measures = policy;
        self
    }

    /// Replaces the resource compatibility policy.
    pub fn with_resources(mut self, policy: CapabilityPolicy) -> Self {
        self.resources = policy;
        self
    }

    /// Whether the registry recognizes a pass identifier.
    pub fn supports_pass(&self, id: &str) -> bool {
        self.pass(id).is_some()
    }

    /// The registry entry for a recognized pass identifier.
    pub fn pass(&self, id: &str) -> Option<&PassSupport> {
        self.passes.iter().find(|support| support.id == id)
    }

    /// The active measure compatibility policy.
    pub fn measures(&self) -> &CapabilityPolicy {
        &self.measures
    }

    /// The active resource compatibility policy.
    pub fn resources(&self) -> &CapabilityPolicy {
        &self.resources
    }

    /// Validates a parsed search request against this capability registry.
    ///
    /// The check order is stable: every requested pass is recognized first, then each
    /// reflector-requiring pass is checked against the definition topology, then the
    /// measure and resource compatibility policies. `docs/protocol.md` §3.3 requires
    /// unsupported work to fail here rather than be silently skipped during enumeration.
    ///
    /// The per-pass topology requirement is a mechanism, not a Stage 1 assumption: a pass
    /// is rejected for a no-reflector topology only when its [`PassSupport`] opts in with
    /// `requires_reflector == true`.
    pub fn preflight(&self, request: &SearchRequest) -> Result<(), Vec<SearchDiagnostic>> {
        self.preflight_parsed(request.parsed())
    }

    /// Shared compatibility preflight for structurally parsed, unbound inputs.
    pub fn preflight_parsed(
        &self,
        request: &ParsedSearchRequest,
    ) -> Result<(), Vec<SearchDiagnostic>> {
        self.check_passes(request.definition(), request.passes())?;
        let ids: Vec<String> = request
            .measures()
            .iter()
            .map(|measure| measure.id().to_owned())
            .collect();
        self.check_measures(&ids)
            .map_err(|diagnostic| vec![diagnostic])?;
        for reference in request.resources() {
            if !self.resources.permits(reference.measure().id()) {
                return Err(vec![SearchDiagnostic::new(
                    "unsupported_resource",
                    "resource is not supported by the configured capability policy",
                    "/job/resources",
                )]);
            }
        }
        Ok(())
    }

    pub(crate) fn check_passes(
        &self,
        definition: &Definition,
        passes: &[String],
    ) -> Result<(), Vec<SearchDiagnostic>> {
        for (index, pass) in passes.iter().enumerate() {
            if !self.supports_pass(pass) {
                return Err(vec![SearchDiagnostic::new(
                    "unsupported_pass",
                    format!("pass {pass:?} is not a recognized Stage 1 pass"),
                    format!("/job/passes/{index}"),
                )]);
            }
        }
        for pass in passes {
            let support = self
                .pass(pass)
                .expect("the recognition loop accepted every requested pass");
            if support.requires_reflector() && !has_reflector(definition) {
                return Err(vec![SearchDiagnostic::new(
                    "unsupported_topology",
                    format!(
                        "pass {pass:?} requires a reflector, but the definition topology declares none"
                    ),
                    "/machine/definition",
                )]);
            }
        }
        Ok(())
    }

    /// Rejects requested measures that are not permitted by the measure policy.
    ///
    /// The reported location is the offending `/job/measures/<i>`. This is a framework
    /// hook: with the Stage 1 `Deferred` default it accepts everything.
    pub fn check_measures(&self, measures: &[String]) -> Result<(), SearchDiagnostic> {
        for (index, measure) in measures.iter().enumerate() {
            if !self.measures.permits(measure) {
                return Err(SearchDiagnostic::new(
                    "unsupported_measure",
                    format!(
                        "measure {measure:?} is not supported by the configured capability policy"
                    ),
                    format!("/job/measures/{index}"),
                ));
            }
        }
        Ok(())
    }

    /// Rejects a `resources` object that carries a member the resource policy forbids.
    ///
    /// The reported location is `/job/resources`. This is a framework hook: with the
    /// Stage 1 `Deferred` default it accepts everything.
    pub fn check_resources(&self, resources: Option<&Value>) -> Result<(), SearchDiagnostic> {
        let Some(resources) = resources else {
            return Ok(());
        };
        if let Some(object) = resources.as_object() {
            for key in object.keys() {
                if !self.resources.permits(key) {
                    return Err(SearchDiagnostic::new(
                        "unsupported_resource",
                        format!(
                            "resource {key:?} is not supported by the configured capability policy"
                        ),
                        "/job/resources",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Whether the definition topology declares a reflector slot.
fn has_reflector(definition: &Definition) -> bool {
    definition
        .slots()
        .iter()
        .any(|slot| slot.role() == SlotRole::Reflector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::RequestDiagnostic;
    use serde_json::{json, Value};

    /// A small arbitrary custom definition with one movable rotor and no reflector, used
    /// to exercise the per-pass topology mechanism. Not a historical machine.
    fn no_reflector_definition_value() -> Value {
        json!({
            "alphabet": ["A", "B", "C", "D"],
            "wheels": [
                {"name": "rotor1", "wiring": ["B", "A", "D", "C"], "turnovers": ["B"]}
            ],
            "slots": [
                {"id": "fast", "role": "rotor", "movement": "movable", "allowed_wheels": ["rotor1"]}
            ],
            "stepping": {"rules": [{"when": {"always": true}, "advance": ["fast"]}]}
        })
    }

    /// A small arbitrary custom definition with a structurally fixed reflector and a
    /// movable rotor. Not a historical machine.
    fn reflector_definition_value() -> Value {
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

    /// A fully fixed request over a no-reflector definition, parameterized by passes.
    fn no_reflector_request(passes: Value) -> Value {
        json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "custom", "value": no_reflector_definition_value()}},
            "job": {
                "kind": "search",
                "configuration": {
                    "slots": [
                        {"id": "fast", "wheel": "rotor1", "position": "A", "ring": "A"}
                    ],
                    "plugboard": []
                },
                "text": "AB",
                "space": {"slots": []},
                "passes": passes,
                "measures": ["ic"]
            }
        })
    }

    /// A valid, fully fixed request over a reflector definition.
    fn reflector_request() -> Value {
        json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "custom", "value": reflector_definition_value()}},
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

    fn parse(value: &Value) -> SearchRequest {
        SearchRequest::parse_json(&value.to_string()).expect("valid search request")
    }

    fn parse_error(value: &Value) -> RequestDiagnostic {
        SearchRequest::parse_json(&value.to_string())
            .expect_err("request must be rejected")
            .remove(0)
    }

    #[test]
    fn stage1_recognizes_the_five_passes_without_topology_restrictions() {
        let capabilities = Capabilities::stage1();
        for id in [
            "hill_climb",
            "partial_exhaustion",
            "reswapping",
            "trie",
            "measure",
        ] {
            assert!(capabilities.supports_pass(id), "{id} must be recognized");
            assert!(
                !capabilities.pass(id).unwrap().requires_reflector(),
                "{id} must not require a reflector"
            );
        }
    }

    #[test]
    fn stage1_does_not_recognize_unknown_passes() {
        let capabilities = Capabilities::stage1();
        assert!(!capabilities.supports_pass("bogus"));
        assert!(capabilities.pass("bogus").is_none());
    }

    #[test]
    fn all_stage1_passes_are_accepted_for_a_no_reflector_topology() {
        let value = no_reflector_request(json!([
            "hill_climb",
            "partial_exhaustion",
            "reswapping",
            "trie",
            "measure"
        ]));
        // `parse_json` runs the Stage 1 preflight before returning, so this must already
        // succeed without a reflector.
        let request = parse(&value);
        assert!(Capabilities::stage1().preflight(&request).is_ok());
    }

    #[test]
    fn all_recognized_passes_are_accepted_for_a_reflector_topology() {
        let mut value = reflector_request();
        value["job"]["passes"] = json!([
            "hill_climb",
            "partial_exhaustion",
            "reswapping",
            "trie",
            "measure"
        ]);
        assert!(SearchRequest::parse_json(&value.to_string()).is_ok());
    }

    #[test]
    fn unknown_pass_is_unsupported_pass_at_its_index() {
        let mut value = reflector_request();
        value["job"]["passes"] = json!(["hill_climb", "bogus"]);
        let diagnostic = parse_error(&value);
        assert_eq!(diagnostic.code(), "unsupported_pass");
        assert_eq!(diagnostic.location(), "/job/passes/1");
        assert!(diagnostic.message().contains("bogus"));
    }

    #[test]
    fn per_pass_reflector_requirement_rejects_a_no_reflector_topology() {
        let request = parse(&no_reflector_request(json!(["hill_climb"])));
        // A custom registry that opts `hill_climb` into the reflector requirement must
        // still reject a no-reflector definition; this proves the mechanism is live even
        // though Stage 1 itself makes no such assertion.
        let capabilities = Capabilities {
            passes: vec![PassSupport::new("hill_climb", true)],
            measures: CapabilityPolicy::Deferred,
            resources: CapabilityPolicy::Deferred,
        };
        let diagnostic = capabilities.preflight(&request).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "unsupported_topology");
        assert_eq!(diagnostic.location(), "/machine/definition");
        assert!(diagnostic.message().contains("hill_climb"));
    }

    #[test]
    fn measure_pass_does_not_require_a_reflector() {
        let value = no_reflector_request(json!(["measure"]));
        assert!(SearchRequest::parse_json(&value.to_string()).is_ok());
    }

    #[test]
    fn measure_allowlist_accepts_listed_and_rejects_unlisted() {
        let capabilities = Capabilities::stage1().with_measures(CapabilityPolicy::Allowlist(vec![
            "index_of_coincidence".into(),
        ]));
        assert!(capabilities
            .check_measures(&["index_of_coincidence".to_owned()])
            .is_ok());
        let diagnostic = capabilities
            .check_measures(&["index_of_coincidence".to_owned(), "entropy".to_owned()])
            .unwrap_err();
        assert_eq!(diagnostic.code(), "unsupported_measure");
        assert_eq!(diagnostic.location(), "/job/measures/1");
    }

    #[test]
    fn measure_allowlist_rejects_unlisted_measure_at_its_index() {
        let mut value = reflector_request();
        value["job"]["measures"] = json!(["ic", "entropy"]);
        let request = parse(&value);
        let permitted = Capabilities::stage1().with_measures(CapabilityPolicy::Allowlist(vec![
            "ic".to_owned(),
            "entropy".to_owned(),
        ]));
        assert!(permitted.preflight(&request).is_ok());
        let restricted = Capabilities::stage1()
            .with_measures(CapabilityPolicy::Allowlist(vec!["ic".to_owned()]));
        let diagnostic = restricted.preflight(&request).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "unsupported_measure");
        assert_eq!(diagnostic.location(), "/job/measures/1");
    }

    #[test]
    fn resource_allowlist_rejects_unlisted_members() {
        let capabilities = Capabilities::stage1()
            .with_resources(CapabilityPolicy::Allowlist(vec!["threads".into()]));
        assert!(capabilities
            .check_resources(Some(&serde_json::json!({"threads": 4})))
            .is_ok());
        let diagnostic = capabilities
            .check_resources(Some(&serde_json::json!({"memory": 1024})))
            .unwrap_err();
        assert_eq!(diagnostic.code(), "unsupported_resource");
        assert_eq!(diagnostic.location(), "/job/resources");
    }

    #[test]
    fn resource_allowlist_rejects_unlisted_resources_object() {
        let mut value = reflector_request();
        value["job"]["measures"] = json!(["trie"]);
        value["job"]["resources"] = json!({"trie": {"path": "words.json"}});
        let request = ParsedSearchRequest::parse_json(&value.to_string()).unwrap();
        let allowlisted = Capabilities::stage1()
            .with_resources(CapabilityPolicy::Allowlist(vec!["trie".to_owned()]));
        assert!(allowlisted.preflight_parsed(&request).is_ok());
        let rejected = Capabilities::stage1()
            .with_resources(CapabilityPolicy::Allowlist(vec!["memory".to_owned()]));
        let diagnostic = rejected.preflight_parsed(&request).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "unsupported_resource");
        assert_eq!(diagnostic.location(), "/job/resources");
        assert!(Capabilities::stage1().preflight_parsed(&request).is_ok());
    }

    #[test]
    fn deferred_policies_accept_every_value() {
        let capabilities = Capabilities::stage1();
        assert!(capabilities
            .check_measures(&["anything".to_owned()])
            .is_ok());
        assert!(capabilities
            .check_resources(Some(&serde_json::json!({"anything": 1})))
            .is_ok());
        assert!(capabilities.check_resources(None).is_ok());
    }
}
