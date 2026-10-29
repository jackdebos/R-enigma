//! Typed resolution of a complete `job.configuration` against a validated definition.
//!
//! [`TransformConfiguration`] carries the explicit key choices for every definition slot
//! plus the explicit plugboard pairs. [`TransformConfiguration::resolve`] checks those
//! choices against the key-free [`Definition`], builds the concrete [`MachineTopology`],
//! binds the definition's stepping rules to it, and assembles the [`Plugboard`] before a
//! [`crate::Engine`] is constructed. This module performs no JSON parsing: request-schema
//! validation, unknown-field rejection, direction handling, and text decoding belong to
//! the protocol layer (`request`).
//!
//! Diagnostics use request-relative JSON Pointers under `/job/configuration`, matching
//! the protocol's location example, so the protocol layer can forward them verbatim.

use crate::{
    Alphabet, Definition, Engine, MachineTopology, ModelError, Plugboard, Slot, Stepping, Wiring,
};
use std::fmt;

/// A localized, actionable configuration-resolution diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationDiagnostic {
    code: &'static str,
    message: String,
    location: String,
}

impl ConfigurationDiagnostic {
    fn new(code: &'static str, message: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            location: location.into(),
        }
    }

    pub(crate) fn missing_rewirable_pairs(id: &str, wheel: &str, path: &str) -> Self {
        Self::new(
            "invalid_slot",
            format!("slot {id:?} uses rewirable wheel {wheel:?} and requires `pairs`"),
            path,
        )
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

impl fmt::Display for ConfigurationDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.code, self.location, self.message)
    }
}

impl std::error::Error for ConfigurationDiagnostic {}

/// One explicit key selection for a single definition slot.
///
/// The four values mirror the protocol `job.configuration.slots` entry: they are key
/// choices, not structural constraints. Structural admissibility (role, movement, fixed
/// or allowed wheel, reflector involvement) comes from the [`Definition`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotConfiguration {
    id: String,
    wheel: String,
    position: char,
    ring: char,
    pairs: Option<Vec<(char, char)>>,
}

impl SlotConfiguration {
    /// Creates a slot key entry; [`TransformConfiguration::resolve`] validates it.
    pub fn new(
        id: impl Into<String>,
        wheel: impl Into<String>,
        position: char,
        ring: char,
    ) -> Self {
        Self {
            id: id.into(),
            wheel: wheel.into(),
            position,
            ring,
            pairs: None,
        }
    }

    /// Supplies the free pairs of a rewirable wheel; resolution validates them.
    pub fn with_pairs(mut self, pairs: Vec<(char, char)>) -> Self {
        self.pairs = Some(pairs);
        self
    }

    /// Explicit free pairs, or `None` when no wiring key was supplied.
    pub fn pairs(&self) -> Option<&[(char, char)]> {
        self.pairs.as_deref()
    }

    /// Slot identifier; must match the definition slot at this position.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Selected wheel; must be the structurally fixed wheel or an allowed alternative.
    pub fn wheel(&self) -> &str {
        &self.wheel
    }

    /// Displayed position symbol.
    pub fn position(&self) -> char {
        self.position
    }

    /// Ring setting symbol.
    pub fn ring(&self) -> char {
        self.ring
    }
}

/// A complete typed transform configuration: every slot key choice plus explicit pairs.
///
/// This type carries no JSON and performs no schema parsing. It is the typed counterpart
/// of the protocol's `job.configuration` for `kind: "transform"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformConfiguration {
    slots: Vec<SlotConfiguration>,
    plugboard: Vec<(char, char)>,
}

impl TransformConfiguration {
    /// Creates a transform configuration from explicit slot entries and plugboard pairs.
    ///
    /// The plugboard is always explicit, including when empty. Pairs are directionless
    /// and, like the protocol requires, every slot must be listed in definition order.
    pub fn new(slots: Vec<SlotConfiguration>, plugboard: Vec<(char, char)>) -> Self {
        Self { slots, plugboard }
    }

    /// The explicit slot entries in the order they were supplied.
    pub fn slots(&self) -> &[SlotConfiguration] {
        &self.slots
    }

    /// The explicit plugboard pairs in the order they were supplied.
    pub fn plugboard(&self) -> &[(char, char)] {
        &self.plugboard
    }

    /// Resolves this configuration against a validated key-free definition.
    ///
    /// Enforces exactly one entry per definition slot, definition order, slot IDs,
    /// fixed-versus-allowed wheel admissibility, alphabet membership for positions and
    /// rings, and plugboard disjointness. Only after those checks succeed does it build
    /// the concrete [`MachineTopology`], bind the definition's stepping rules to it, and
    /// assemble the [`Plugboard`]. Failures carry request-relative JSON Pointers under
    /// `/job/configuration`.
    pub fn resolve(
        &self,
        definition: &Definition,
    ) -> Result<ResolvedConfiguration, Vec<ConfigurationDiagnostic>> {
        let definition_slots = definition.slots();
        let alphabet = definition.alphabet();
        validate_slot_count(self.slots.len(), definition_slots.len())?;

        let mut wheels = definition.wheels().to_vec();
        let mut slots = Vec::with_capacity(definition_slots.len());
        for (index, (entry, definition_slot)) in self.slots.iter().zip(definition_slots).enumerate()
        {
            let slot_path = pointer(&["slots", &index.to_string()]);
            if entry.id != definition_slot.id() {
                let elsewhere = definition_slots
                    .iter()
                    .position(|candidate| candidate.id() == entry.id);
                let message = match elsewhere {
                    Some(position) => format!(
                        "slot id {:?} is declared at definition position {position}; slot entries must follow definition order",
                        entry.id
                    ),
                    None => format!(
                        "unknown slot id {:?}; the definition declares {:?} at this position",
                        entry.id,
                        definition_slot.id()
                    ),
                };
                return Err(vec![ConfigurationDiagnostic::new(
                    "invalid_slot",
                    message,
                    child(&slot_path, "id"),
                )]);
            }
            let wheel_ok = match definition_slot.wheel() {
                Some(fixed) => entry.wheel == fixed,
                None => definition_slot
                    .allowed_wheels()
                    .iter()
                    .any(|wheel| wheel == &entry.wheel),
            };
            if !wheel_ok {
                let message = match definition_slot.wheel() {
                    Some(fixed) => format!(
                        "slot {:?} fixes wheel {fixed:?}; got {:?}",
                        definition_slot.id(),
                        entry.wheel
                    ),
                    None => format!(
                        "wheel {:?} is not admissible for slot {:?}; allowed wheels: {:?}",
                        entry.wheel,
                        definition_slot.id(),
                        definition_slot.allowed_wheels()
                    ),
                };
                return Err(vec![ConfigurationDiagnostic::new(
                    "invalid_slot",
                    message,
                    child(&slot_path, "wheel"),
                )]);
            }
            for (field, symbol) in [("position", entry.position), ("ring", entry.ring)] {
                if alphabet.index_of(symbol).is_none() {
                    return Err(vec![ConfigurationDiagnostic::new(
                        "invalid_symbol",
                        format!("{field} symbol {symbol:?} is not in the machine alphabet"),
                        child(&slot_path, field),
                    )]);
                }
            }
            let pairs_path = child(&slot_path, "pairs");
            match (definition.rewirable_fixed_pairs(&entry.wheel), entry.pairs()) {
                (Some(fixed), Some(pairs)) => {
                    let wheel = wheels.iter_mut().find(|wheel| wheel.name() == entry.wheel)
                        .expect("admissible wheel is declared");
                    *wheel = resolve_rewirable(alphabet, wheel, fixed, pairs, &pairs_path)?;
                }
                (Some(_), None) => return Err(vec![ConfigurationDiagnostic::missing_rewirable_pairs(
                    &entry.id, &entry.wheel, &pairs_path,
                )]),
                (None, Some(_)) => return Err(vec![ConfigurationDiagnostic::new(
                    "unknown_field",
                    format!("`pairs` is allowed only on a slot whose wheel is rewirable; wheel {:?} is not", entry.wheel),
                    pairs_path,
                )]),
                (None, None) => {}
            }
            slots.push(Slot::new(
                entry.id.clone(),
                entry.wheel.clone(),
                definition_slot.role(),
                definition_slot.movement(),
                entry.position,
                entry.ring,
            ));
        }

        let plugboard = resolve_plugboard(alphabet, &self.plugboard)?;

        let topology = MachineTopology::new(alphabet.clone(), wheels, slots)
            .map_err(|error| vec![definition_error(error)])?;

        // Stepping is bound only after every slot choice proved admissible, so the rules
        // are attached to the topology that actually resulted from this configuration.
        let stepping = definition
            .bind_stepping(&topology)
            .map_err(|error| vec![definition_error(error)])?;

        let mut key_slots = self.slots.clone();
        for slot in &mut key_slots {
            if let Some(pairs) = &mut slot.pairs {
                crate::rewirable::canonical(alphabet, pairs);
            }
        }
        Ok(ResolvedConfiguration {
            topology,
            stepping,
            plugboard,
            key_slots,
        })
    }
}

/// A configuration resolved into concrete machine components.
///
/// The topology, stepping rules, and plugboard are fully validated and mutually
/// consistent: stepping is already bound to this exact topology, and the plugboard uses
/// the same ordered alphabet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedConfiguration {
    topology: MachineTopology,
    stepping: Stepping,
    plugboard: Plugboard,
    key_slots: Vec<SlotConfiguration>,
}

impl ResolvedConfiguration {
    pub(crate) fn key_slots(&self) -> &[SlotConfiguration] {
        &self.key_slots
    }

    /// The concrete physical machine built from the definition structure and key values.
    pub fn topology(&self) -> &MachineTopology {
        &self.topology
    }

    /// The definition's stepping rules bound to [`ResolvedConfiguration::topology`].
    pub fn stepping(&self) -> &Stepping {
        &self.stepping
    }

    /// The explicit plugboard resolved against the machine alphabet.
    pub fn plugboard(&self) -> &Plugboard {
        &self.plugboard
    }

    /// Consumes the resolved configuration and builds a ready-to-transform [`Engine`].
    ///
    /// Resolution already validated every field, so this only fails if an internal
    /// invariant is violated; it returns the underlying [`ModelError`] rather than
    /// panicking so callers keep the actionable code.
    pub fn into_engine(self) -> Result<Engine, ModelError> {
        Engine::new(self.topology, self.stepping, self.plugboard)
    }
}

fn validate_slot_count(
    configured: usize,
    expected: usize,
) -> Result<(), Vec<ConfigurationDiagnostic>> {
    if configured == expected {
        return Ok(());
    }
    let first_unmatched = configured.min(expected);
    let message = if configured < expected {
        format!(
            "configuration has {configured} slot entries; the definition declares {expected}, so slot entry {first_unmatched} is missing"
        )
    } else {
        format!(
            "configuration has {configured} slot entries; the definition declares only {expected}, so slot entry {first_unmatched} is unexpected"
        )
    };
    Err(vec![ConfigurationDiagnostic::new(
        "invalid_slot",
        message,
        pointer(&["slots", &first_unmatched.to_string()]),
    )])
}

/// Completes the validated permanent pairs with a full, disjoint wiring key.
pub(crate) fn resolve_rewirable(
    alphabet: &Alphabet,
    wheel: &Wiring,
    fixed: &[(char, char)],
    pairs: &[(char, char)],
    path: &str,
) -> Result<Wiring, Vec<ConfigurationDiagnostic>> {
    let expected = alphabet.len() / 2 - fixed.len();
    if pairs.len() != expected {
        return Err(vec![ConfigurationDiagnostic::new(
            "invalid_slot",
            format!(
                "rewirable wheel {:?} needs exactly {expected} pairs; got {}",
                wheel.name(),
                pairs.len()
            ),
            path,
        )]);
    }
    let mut mapping: Vec<char> = (0..alphabet.len())
        .map(|index| alphabet.symbol_at(index).expect("index is in alphabet"))
        .collect();
    let mut used = std::collections::HashSet::new();
    for (index, &(a, b)) in pairs.iter().enumerate() {
        let pair_path = child(path, &index.to_string());
        for (end, symbol) in [a, b].into_iter().enumerate() {
            if alphabet.index_of(symbol).is_none() {
                return Err(vec![ConfigurationDiagnostic::new(
                    "invalid_symbol",
                    format!(
                        "pair symbol {:?} is not in the machine alphabet",
                        symbol.to_string()
                    ),
                    child(&pair_path, &end.to_string()),
                )]);
            }
        }
        if a == b {
            return Err(vec![ConfigurationDiagnostic::new(
                "invalid_plugboard",
                format!(
                    "a pair must join two distinct symbols; got {:?} twice",
                    a.to_string()
                ),
                pair_path,
            )]);
        }
        for (end, symbol) in [a, b].into_iter().enumerate() {
            let location = child(&pair_path, &end.to_string());
            if fixed.iter().any(|&(a, b)| symbol == a || symbol == b) {
                return Err(vec![ConfigurationDiagnostic::new(
                    "invalid_slot",
                    format!(
                        "pair endpoint {:?} is wired permanently by wheel {:?}",
                        symbol.to_string(),
                        wheel.name()
                    ),
                    location,
                )]);
            }
            if !used.insert(symbol) {
                return Err(vec![ConfigurationDiagnostic::new(
                    "invalid_plugboard",
                    format!(
                        "pair endpoint {:?} is already used by another pair",
                        symbol.to_string()
                    ),
                    location,
                )]);
            }
        }
    }
    for &(a, b) in fixed.iter().chain(pairs) {
        mapping[alphabet.index_of(a).expect("validated symbol")] = b;
        mapping[alphabet.index_of(b).expect("validated symbol")] = a;
    }
    let turnovers: Vec<char> = (0..alphabet.len())
        .filter_map(|index| alphabet.symbol_at(index))
        .filter(|&symbol| wheel.at_turnover(symbol))
        .collect();
    Wiring::new(wheel.name(), alphabet, &mapping, &turnovers)
        .map_err(|error| vec![definition_error(error)])
}

fn resolve_plugboard(
    alphabet: &Alphabet,
    pairs: &[(char, char)],
) -> Result<Plugboard, Vec<ConfigurationDiagnostic>> {
    let mut mapping: Vec<usize> = (0..alphabet.len()).collect();
    for (index, &(left, right)) in pairs.iter().enumerate() {
        let pair_path = pointer(&["plugboard", &index.to_string()]);
        let (Some(left_index), Some(right_index)) =
            (alphabet.index_of(left), alphabet.index_of(right))
        else {
            let symbol = if alphabet.index_of(left).is_none() {
                left
            } else {
                right
            };
            return Err(vec![ConfigurationDiagnostic::new(
                "invalid_symbol",
                format!("plugboard symbol {symbol:?} is not in the machine alphabet"),
                pair_path,
            )]);
        };
        if left_index == right_index {
            return Err(vec![ConfigurationDiagnostic::new(
                "invalid_plugboard",
                format!("plugboard pair {left:?}{right:?} pairs a symbol with itself"),
                pair_path,
            )]);
        }
        if mapping[left_index] != left_index {
            return Err(vec![ConfigurationDiagnostic::new(
                "invalid_plugboard",
                format!("plugboard symbol {left:?} occurs in more than one pair"),
                pair_path,
            )]);
        }
        if mapping[right_index] != right_index {
            return Err(vec![ConfigurationDiagnostic::new(
                "invalid_plugboard",
                format!("plugboard symbol {right:?} occurs in more than one pair"),
                pair_path,
            )]);
        }
        mapping[left_index] = right_index;
        mapping[right_index] = left_index;
    }
    Plugboard::new(alphabet, pairs).map_err(|error| vec![plugboard_error(error)])
}

/// Defensive mapping for an internal invariant: the definition alone is validated, so
/// assembling a topology or binding stepping from an admissible configuration should not
/// fail. The location stays at the configuration root when it somehow does.
fn definition_error(error: ModelError) -> ConfigurationDiagnostic {
    ConfigurationDiagnostic::new("invalid_definition", error.to_string(), pointer(&[]))
}

fn plugboard_error(error: ModelError) -> ConfigurationDiagnostic {
    ConfigurationDiagnostic::new(
        "invalid_plugboard",
        error.to_string(),
        pointer(&["plugboard"]),
    )
}

fn pointer(tokens: &[&str]) -> String {
    let mut path = String::from("/job/configuration");
    for token in tokens {
        path.push('/');
        path.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    path
}

fn child(path: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{path}/{escaped}")
}

#[cfg(test)]
mod tests {
    use crate::configuration::{ResolvedConfiguration, SlotConfiguration, TransformConfiguration};
    use crate::{
        Definition, DefinitionSource, Direction, Engine, MachineTopology, Movement, Plugboard,
        Slot, SlotRole,
    };

    const CUSTOM: &str = r#"{
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

    const CUSTOM_FIXED: &str = r#"{
        "alphabet":["A","B","C","D"],
        "wheels":[
            {"name":"rotor","wiring":["B","A","D","C"],"turnovers":["B"]},
            {"name":"reflector","wiring":["B","A","D","C"],"turnovers":[]}
        ],
        "slots":[
            {"id":"ukw","role":"reflector","movement":"fixed","wheel":"reflector"},
            {"id":"fixed","role":"rotor","movement":"movable","wheel":"rotor"}
        ],
        "stepping":{"rules":[{"when":{"always":true},"advance":["fixed"]}]}
    }"#;

    fn custom(source: &str) -> Definition {
        DefinitionSource::parse_json(&format!(r#"{{"kind":"custom","value":{source}}}"#))
            .unwrap()
            .resolve()
            .unwrap()
    }

    fn bundled(id: &str) -> Definition {
        DefinitionSource::parse_json(&format!(r#"{{"kind":"bundled","id":"{id}"}}"#))
            .unwrap()
            .resolve()
            .unwrap()
    }

    fn slot(id: &str, wheel: &str, position: char, ring: char) -> SlotConfiguration {
        SlotConfiguration::new(id, wheel, position, ring)
    }

    /// Builds the same engine by hand from the definition, bypassing the resolver.
    fn manual_engine(
        definition: &Definition,
        slots: Vec<Slot>,
        plugboard: &[(char, char)],
    ) -> Engine {
        let topology = MachineTopology::new(
            definition.alphabet().clone(),
            definition.wheels().to_vec(),
            slots,
        )
        .unwrap();
        let stepping = definition.bind_stepping(&topology).unwrap();
        let plugboard = Plugboard::new(definition.alphabet(), plugboard).unwrap();
        Engine::new(topology, stepping, plugboard).unwrap()
    }

    #[test]
    fn resolves_a_custom_definition_and_transforms_text() {
        let definition = custom(CUSTOM);
        let configuration = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'A', 'A'),
                slot("fast", "rotor", 'B', 'A'),
            ],
            Vec::new(),
        );
        let resolved: ResolvedConfiguration = configuration.resolve(&definition).unwrap();

        assert_eq!(resolved.topology().slots().len(), 2);
        assert_eq!(resolved.topology().slots()[0].id(), "ukw");
        assert_eq!(resolved.topology().slots()[0].position(), 'A');
        assert_eq!(resolved.topology().slots()[0].ring(), 'A');
        assert_eq!(resolved.topology().slots()[1].id(), "fast");
        assert_eq!(resolved.topology().slots()[1].wheel(), "rotor");
        assert_eq!(resolved.topology().slots()[1].position(), 'B');

        // Formula-derived expectation from an independent §3.2 oracle, plus a
        // hand-assembled engine that never passed through the resolver.
        let mut engine = resolved.into_engine().unwrap();
        assert_eq!(
            engine.transform("ABCD", Direction::Encrypt).unwrap(),
            "BADC"
        );
        let mut manual = manual_engine(
            &definition,
            vec![
                Slot::new(
                    "ukw",
                    "reflector",
                    SlotRole::Reflector,
                    Movement::Fixed,
                    'A',
                    'A',
                ),
                Slot::new(
                    "fast",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'B',
                    'A',
                ),
            ],
            &[],
        );
        assert_eq!(
            manual.transform("ABCD", Direction::Encrypt).unwrap(),
            "BADC"
        );
    }

    #[test]
    fn custom_plugboard_pairs_change_the_transform_and_are_disjoint() {
        let definition = custom(CUSTOM);
        let configuration = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'A', 'A'),
                slot("fast", "rotor", 'B', 'A'),
            ],
            vec![('A', 'C')],
        );
        let resolved = configuration.resolve(&definition).unwrap();
        assert!(resolved.plugboard().is_paired('A'));
        assert!(resolved.plugboard().is_paired('C'));
        assert!(!resolved.plugboard().is_paired('B'));

        let mut engine = resolved.into_engine().unwrap();
        assert_eq!(
            engine.transform("ABCD", Direction::Encrypt).unwrap(),
            "DCBA"
        );

        // The reflector traversal is reciprocal, so a fresh engine recovers the plaintext.
        let mut fresh = configuration
            .resolve(&definition)
            .unwrap()
            .into_engine()
            .unwrap();
        assert_eq!(fresh.transform("DCBA", Direction::Encrypt).unwrap(), "ABCD");
    }

    #[test]
    fn bundled_enigma_i_resolves_and_transforms_through_the_engine() {
        let definition = bundled("enigma-i");
        let configuration = TransformConfiguration::new(
            vec![
                slot("reflector", "B", 'A', 'A'),
                slot("left", "I", 'A', 'A'),
                slot("middle", "II", 'A', 'A'),
                slot("right", "III", 'A', 'A'),
            ],
            Vec::new(),
        );
        let resolved = configuration.resolve(&definition).unwrap();
        assert_eq!(resolved.topology().slots().len(), 4);
        assert_eq!(resolved.topology().slots()[3].id(), "right");

        // Formula-derived from an independent §3.2 oracle (not a historical vector).
        let mut engine = resolved.into_engine().unwrap();
        assert_eq!(
            engine.transform("AAAA", Direction::Encrypt).unwrap(),
            "BDZG"
        );
        let mut full = configuration
            .resolve(&definition)
            .unwrap()
            .into_engine()
            .unwrap();
        assert_eq!(
            full.transform("ABCDEFGHIJKLMNOPQRSTUVWXYZ", Direction::Encrypt)
                .unwrap(),
            "BJELRQZVJWARXSNBXORSTNCFME"
        );

        // A fresh engine decrypts the reciprocal ciphertext back to the plaintext.
        let mut round_trip = configuration
            .resolve(&definition)
            .unwrap()
            .into_engine()
            .unwrap();
        assert_eq!(
            round_trip
                .transform("BJELRQZVJWARXSNBXORSTNCFME", Direction::Decrypt)
                .unwrap(),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        );

        let mut manual = manual_engine(
            &definition,
            vec![
                Slot::new(
                    "reflector",
                    "B",
                    SlotRole::Reflector,
                    Movement::Fixed,
                    'A',
                    'A',
                ),
                Slot::new("left", "I", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
                Slot::new("middle", "II", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
                Slot::new("right", "III", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
            ],
            &[],
        );
        assert_eq!(
            manual.transform("AAAA", Direction::Encrypt).unwrap(),
            "BDZG"
        );
    }

    #[test]
    fn bundled_m4_resolves_the_fixed_greek_slot_and_transforms() {
        let definition = bundled("enigma-m4");
        let configuration = TransformConfiguration::new(
            vec![
                slot("reflector", "Thin-B", 'A', 'A'),
                slot("greek", "Beta", 'B', 'A'),
                slot("left", "I", 'A', 'A'),
                slot("middle", "II", 'A', 'A'),
                slot("right", "III", 'A', 'A'),
            ],
            Vec::new(),
        );
        let resolved = configuration.resolve(&definition).unwrap();
        let greek = resolved.topology().slot_index("greek").unwrap();
        assert_eq!(resolved.topology().slots()[greek].role(), SlotRole::Rotor);
        assert_eq!(
            resolved.topology().slots()[greek].movement(),
            Movement::Fixed
        );
        assert_eq!(resolved.topology().slots()[greek].wheel(), "Beta");
        assert_eq!(resolved.topology().slots()[greek].position(), 'B');

        let mut engine = resolved.into_engine().unwrap();
        assert_eq!(
            engine.transform("AAAA", Direction::Encrypt).unwrap(),
            "SZOW"
        );

        let other = TransformConfiguration::new(
            vec![
                slot("reflector", "Thin-C", 'A', 'A'),
                slot("greek", "Gamma", 'A', 'A'),
                slot("left", "I", 'A', 'A'),
                slot("middle", "II", 'A', 'A'),
                slot("right", "III", 'A', 'A'),
            ],
            Vec::new(),
        );
        let mut engine = other.resolve(&definition).unwrap().into_engine().unwrap();
        assert_eq!(
            engine.transform("AAAA", Direction::Encrypt).unwrap(),
            "PJBU"
        );
    }

    #[test]
    fn rejects_missing_extra_and_out_of_order_slot_entries() {
        let definition = custom(CUSTOM);

        let missing = TransformConfiguration::new(vec![slot("ukw", "reflector", 'A', 'A')], vec![]);
        let diagnostic = missing.resolve(&definition).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1");

        let extra = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'A', 'A'),
                slot("fast", "rotor", 'A', 'A'),
                slot("fast", "rotor", 'A', 'A'),
            ],
            vec![],
        );
        let diagnostic = extra.resolve(&definition).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/2");

        let reordered = TransformConfiguration::new(
            vec![
                slot("fast", "rotor", 'A', 'A'),
                slot("ukw", "reflector", 'A', 'A'),
            ],
            vec![],
        );
        let diagnostic = reordered.resolve(&definition).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/0/id");
        assert!(diagnostic.message().contains("definition order"));

        let unknown = TransformConfiguration::new(
            vec![
                slot("nope", "reflector", 'A', 'A'),
                slot("fast", "rotor", 'A', 'A'),
            ],
            vec![],
        );
        let diagnostic = unknown.resolve(&definition).unwrap_err().remove(0);
        assert_eq!(diagnostic.location(), "/job/configuration/slots/0/id");
        assert!(diagnostic.message().contains("unknown slot id"));
    }

    #[test]
    fn rejects_fixed_and_disallowed_wheels_with_position_aware_errors() {
        let allowed = custom(CUSTOM);
        let disallowed = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'A', 'A'),
                slot("fast", "reflector", 'A', 'A'),
            ],
            vec![],
        );
        let diagnostic = disallowed.resolve(&allowed).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1/wheel");
        assert!(diagnostic.message().contains("not admissible"));

        let fixed = custom(CUSTOM_FIXED);
        let accepted = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'A', 'A'),
                slot("fixed", "rotor", 'B', 'A'),
            ],
            vec![],
        );
        assert!(accepted.resolve(&fixed).is_ok());

        let wrong = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'A', 'A'),
                slot("fixed", "reflector", 'B', 'A'),
            ],
            vec![],
        );
        let diagnostic = wrong.resolve(&fixed).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_slot");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1/wheel");
        assert!(diagnostic.message().contains("fixes wheel"));

        let wrong_reflector = TransformConfiguration::new(
            vec![
                slot("ukw", "rotor", 'A', 'A'),
                slot("fast", "rotor", 'A', 'A'),
            ],
            vec![],
        );
        let diagnostic = wrong_reflector.resolve(&allowed).unwrap_err().remove(0);
        assert_eq!(diagnostic.location(), "/job/configuration/slots/0/wheel");
    }

    #[test]
    fn rejects_position_and_ring_symbols_outside_the_alphabet() {
        let definition = custom(CUSTOM);
        let bad_position = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'Z', 'A'),
                slot("fast", "rotor", 'A', 'A'),
            ],
            vec![],
        );
        let diagnostic = bad_position.resolve(&definition).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_symbol");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/0/position");

        let bad_ring = TransformConfiguration::new(
            vec![
                slot("ukw", "reflector", 'A', 'A'),
                slot("fast", "rotor", 'A', 'Z'),
            ],
            vec![],
        );
        let diagnostic = bad_ring.resolve(&definition).unwrap_err().remove(0);
        assert_eq!(diagnostic.code(), "invalid_symbol");
        assert_eq!(diagnostic.location(), "/job/configuration/slots/1/ring");
    }

    #[test]
    fn rejects_invalid_plugboard_pairs_with_stable_endpoint_ordering() {
        let definition = custom(CUSTOM);
        let base = vec![
            slot("ukw", "reflector", 'A', 'A'),
            slot("fast", "rotor", 'A', 'A'),
        ];
        let resolve = |pairs: Vec<(char, char)>| {
            TransformConfiguration::new(base.clone(), pairs)
                .resolve(&definition)
                .unwrap_err()
                .remove(0)
        };

        let self_pair = resolve(vec![('A', 'A')]);
        assert_eq!(self_pair.code(), "invalid_plugboard");
        assert_eq!(self_pair.location(), "/job/configuration/plugboard/0");

        let duplicate = resolve(vec![('A', 'B'), ('A', 'C')]);
        assert_eq!(duplicate.code(), "invalid_plugboard");
        assert_eq!(duplicate.location(), "/job/configuration/plugboard/1");

        // A repeated endpoint is reported from the endpoint that repeats.
        let repeated = resolve(vec![('A', 'B'), ('C', 'B')]);
        assert_eq!(repeated.code(), "invalid_plugboard");
        assert!(repeated.message().contains('B'));

        let unknown = resolve(vec![('A', 'Z')]);
        assert_eq!(unknown.code(), "invalid_symbol");
        assert_eq!(unknown.location(), "/job/configuration/plugboard/0");

        // An unknown endpoint is reported before the self-pair rule.
        let unknown_self = resolve(vec![('Z', 'Z')]);
        assert_eq!(unknown_self.code(), "invalid_symbol");
    }

    #[test]
    fn resolved_components_are_mutually_consistent_and_bound() {
        let definition = bundled("enigma-i");
        let configuration = TransformConfiguration::new(
            vec![
                slot("reflector", "C", 'A', 'A'),
                slot("left", "II", 'A', 'A'),
                slot("middle", "IV", 'A', 'A'),
                slot("right", "V", 'A', 'A'),
            ],
            vec![('A', 'B'), ('C', 'D')],
        );
        let resolved = configuration.resolve(&definition).unwrap();
        assert_eq!(resolved.topology().alphabet(), definition.alphabet());
        assert_eq!(resolved.plugboard().alphabet(), definition.alphabet());
        assert_eq!(resolved.stepping().rules().len(), 3);

        // Stepping is bound to the resolved topology, not to a placeholder.
        let positions: Vec<char> = resolved
            .topology()
            .slots()
            .iter()
            .map(|slot| slot.position())
            .collect();
        assert!(resolved
            .stepping()
            .plan(resolved.topology(), &positions)
            .is_ok());
    }
}
