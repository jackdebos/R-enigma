//! # enigma-core
//!
//! The compute core of the project: a *universal* Enigma model, the scoring measures
//! and the cryptanalysis passes. It performs no I/O and knows nothing about clients.
//!
//! The contract this crate must satisfy is `docs/protocol.md`. The plan and the task
//! breakdown live in `odd/tasks/enigma-engine.md`.
//!
//! ## Design constraints
//!
//! These are not stylistic preferences; they come from the measured behaviour of the
//! reference implementation (`bomm`, 8 ns per decrypted letter):
//!
//! 1. **No machine-specific code paths.** Every historical machine is configuration
//!    data (slots, wheels, turnover sets, plugboard) over one generic engine. Stepping
//!    is a *rule*, not a parameter, because the Zählwerk machines do not fit
//!    "a notch advances the next wheel".
//! 2. **No external calls in the inner loop.** Decryption and scoring are fused, and the
//!    scrambler wiring for a given wheel order is precomputed once per candidate key
//!    position and reused across all decrypts at that position.
//! 3. **Determinism is contractual.** Scoring must be independent per candidate, with no
//!    unordered reductions, so that the CPU and (Stage 4) GPU backends agree exactly.
//!
//! ## Module layout (target)
//!
//! | Module | Responsibility | Task |
//! | --- | --- | --- |
//! | [`letter`] | Alphabet, letters, letter masks | 4 |
//! | `wiring` | Permutations over the alphabet | 4 |
//! | `wheel` | Wheels: wiring + turnover set | 4 |
//! | `stepping` | Stepping rules (`stepping`, `odometer`, `none`, `cog`) | 4 |
//! | `machine` | Slots + wheels + plugboard + reflector | 4 |
//! | `presets` | Enigma I, M3, M4 as data | 5 |
//! | `request` | Job request model (superset of `bomm`'s query schema) | 7 |
//! | `measure` | IC, Sinkov n-gram, entropy, chi-squared | 8 |
//! | `passes` | Hill climbing, partial exhaustion, reswapping | 9 |
//! | `event` | Protocol event stream types | 10 |
//! | `checkpoint` | Durable state and resume | 11 |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Protocol version implemented by this crate.
///
/// Must match `docs/protocol.md` §10. A breaking change to the protocol bumps this.
pub const PROTOCOL_VERSION: u32 = 1;

mod candidate;
mod capability;
mod configuration;
mod definition;
mod engine;
mod event;
mod measure;
mod ngram;
mod request;
mod score;
mod space;
mod strict_json;

pub use score::{
    floor_div, integer_log2_q48, ln_ratio_q32, FixedScore, ScoreError, LN_2_Q48, SCALE,
};

pub use measure::{index_of_coincidence, shannon_entropy, MeasureError, MeasuredScore};
pub use ngram::{NgramError, NgramModel};

pub use candidate::CandidateIterator;
pub use capability::{Capabilities, CapabilityPolicy, PassSupport};
pub use configuration::{
    ConfigurationDiagnostic, ResolvedConfiguration, SlotConfiguration, TransformConfiguration,
};
pub use definition::{Definition, DefinitionDiagnostic, DefinitionSlot, DefinitionSource};
pub use engine::{Direction, Engine};
pub use event::{encode, rfc3339_utc, DoneReason, Event};
pub use request::{RequestDiagnostic, TransformRequest, MAX_REQUEST_BYTES};
pub use space::{
    PlugboardDomain, SearchConfiguration, SearchDiagnostic, SearchFixedSlot, SearchRequest,
    SearchSlotDomain, SearchSpace,
};

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;

/// Failure while defining an alphabet or wheel wiring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// An alphabet must contain at least one symbol.
    EmptyAlphabet,
    /// An alphabet symbol occurs more than once.
    DuplicateAlphabetSymbol(char),
    /// A wheel wiring has a different length than its alphabet.
    WiringLength {
        /// Required number of wiring entries.
        expected: usize,
        /// Number of wiring entries supplied.
        actual: usize,
    },
    /// A symbol is not part of the configured alphabet.
    UnknownSymbol(char),
    /// A wheel wiring maps multiple inputs to the same output.
    DuplicateWiringSymbol(char),
    /// A displayed turnover position occurs more than once.
    DuplicateTurnover(char),
    /// A wheel name must not be empty.
    EmptyWiringName,
    /// A topology must contain at least one slot.
    EmptySlots,
    /// A slot identifier must not be empty.
    EmptySlotId,
    /// Slot identifiers must be unique within a topology.
    DuplicateSlotId(String),
    /// Wheel definition names must be unique within a topology.
    DuplicateWheelName(String),
    /// A slot references no declared wheel.
    UnknownWheel(String),
    /// A wheel was constructed over an alphabet with different symbol order.
    WheelAlphabetMismatch(String),
    /// A reflector wheel must map each symbol back to itself after two applications.
    ReflectorMustBeInvolutive(String),
    /// At most one reflector slot is permitted.
    MultipleReflectors,
    /// A reflector slot must be the leftmost slot.
    ReflectorNotLeftmost,
    /// A topology must contain at least one rotor slot.
    NoRotorSlots,
    /// A slot position or ring setting is not in the topology alphabet.
    UnknownSlotSymbol(char),
    /// A plugboard pair joins a symbol to itself.
    PlugboardSelfPair(char),
    /// A plugboard symbol occurs in more than one pair.
    DuplicatePlugboardSymbol(char),
    /// A plugboard was built over an alphabet ordered differently from the topology.
    PlugboardAlphabetMismatch,
    /// A stepping rule set declares more rules than the grammar allows.
    TooManyStepRules {
        /// Maximum permitted number of rules.
        max: usize,
    },
    /// Stepping conditions exceed the total condition-node budget.
    TooManyStepConditionNodes {
        /// Maximum permitted total number of condition nodes.
        max: usize,
    },
    /// A stepping condition nests deeper than the grammar allows.
    StepConditionTooDeep {
        /// Maximum permitted nesting depth.
        max: usize,
    },
    /// Stepping rules advance more distinct slots than the grammar allows.
    TooManyStepTargets {
        /// Maximum permitted number of distinct targets.
        max: usize,
    },
    /// A stepping condition or advance list references no declared slot.
    UnknownStepSlot(String),
    /// A stepping rule tries to advance a slot whose movement is fixed.
    NonMovableStepTarget(String),
    /// An `all` or `any` condition group must contain at least one condition.
    EmptyStepConditionGroup,
    /// A position slice does not carry exactly one symbol per slot.
    PositionCountMismatch {
        /// Number of slots in the topology.
        expected: usize,
        /// Number of positions supplied.
        actual: usize,
    },
    /// A stepping rule set was evaluated against a different topology than it was built for.
    SteppingTopologyMismatch,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAlphabet => write!(formatter, "alphabet must not be empty"),
            Self::DuplicateAlphabetSymbol(symbol) => {
                write!(formatter, "duplicate alphabet symbol {symbol:?}")
            }
            Self::WiringLength { expected, actual } => write!(
                formatter,
                "wiring has {actual} entries; expected {expected}"
            ),
            Self::UnknownSymbol(symbol) => {
                write!(formatter, "symbol {symbol:?} is not in the alphabet")
            }
            Self::DuplicateWiringSymbol(symbol) => {
                write!(formatter, "wiring output {symbol:?} occurs more than once")
            }
            Self::DuplicateTurnover(symbol) => write!(
                formatter,
                "turnover position {symbol:?} occurs more than once"
            ),
            Self::EmptyWiringName => write!(formatter, "wiring name must not be empty"),
            Self::EmptySlots => write!(formatter, "topology must contain at least one slot"),
            Self::EmptySlotId => write!(formatter, "slot identifier must not be empty"),
            Self::DuplicateSlotId(id) => write!(formatter, "duplicate slot identifier {id:?}"),
            Self::DuplicateWheelName(name) => write!(formatter, "duplicate wheel name {name:?}"),
            Self::UnknownWheel(name) => write!(formatter, "unknown wheel {name:?}"),
            Self::WheelAlphabetMismatch(name) => {
                write!(
                    formatter,
                    "wheel {name:?} uses a different ordered alphabet"
                )
            }
            Self::ReflectorMustBeInvolutive(name) => {
                write!(formatter, "reflector wheel {name:?} must be involutive")
            }
            Self::MultipleReflectors => {
                write!(formatter, "topology may contain at most one reflector")
            }
            Self::ReflectorNotLeftmost => write!(formatter, "reflector slot must be leftmost"),
            Self::NoRotorSlots => {
                write!(formatter, "topology must contain at least one rotor slot")
            }
            Self::UnknownSlotSymbol(symbol) => {
                write!(formatter, "slot symbol {symbol:?} is not in the alphabet")
            }
            Self::PlugboardSelfPair(symbol) => {
                write!(
                    formatter,
                    "plugboard symbol {symbol:?} must not be paired with itself"
                )
            }
            Self::DuplicatePlugboardSymbol(symbol) => {
                write!(
                    formatter,
                    "plugboard symbol {symbol:?} occurs in more than one pair"
                )
            }
            Self::PlugboardAlphabetMismatch => {
                write!(
                    formatter,
                    "plugboard uses a different ordered alphabet than the machine topology"
                )
            }
            Self::TooManyStepRules { max } => {
                write!(formatter, "at most {max} stepping rules are permitted")
            }
            Self::TooManyStepConditionNodes { max } => write!(
                formatter,
                "at most {max} stepping condition nodes are permitted"
            ),
            Self::StepConditionTooDeep { max } => write!(
                formatter,
                "stepping condition nesting is limited to depth {max}"
            ),
            Self::TooManyStepTargets { max } => write!(
                formatter,
                "stepping rules may advance at most {max} distinct slots"
            ),
            Self::UnknownStepSlot(id) => write!(formatter, "unknown stepping slot {id:?}"),
            Self::NonMovableStepTarget(id) => {
                write!(formatter, "stepping rule may not advance fixed slot {id:?}")
            }
            Self::EmptyStepConditionGroup => {
                write!(formatter, "`all` and `any` conditions must not be empty")
            }
            Self::PositionCountMismatch { expected, actual } => write!(
                formatter,
                "received {actual} positions; expected {expected} (one per slot)"
            ),
            Self::SteppingTopologyMismatch => {
                write!(
                    formatter,
                    "stepping rules were built for a different machine topology"
                )
            }
        }
    }
}

impl std::error::Error for ModelError {}

/// Ordered alphabet of distinct Unicode scalar values.
///
/// Symbols are preserved exactly: this type does not normalize or rewrite them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alphabet {
    symbols: Vec<char>,
    indices: HashMap<char, usize>,
}

impl Alphabet {
    /// Creates a non-empty alphabet, rejecting repeated scalar values.
    pub fn new(symbols: Vec<char>) -> Result<Self, ModelError> {
        if symbols.is_empty() {
            return Err(ModelError::EmptyAlphabet);
        }
        let mut indices = HashMap::with_capacity(symbols.len());
        for (index, &symbol) in symbols.iter().enumerate() {
            if indices.insert(symbol, index).is_some() {
                return Err(ModelError::DuplicateAlphabetSymbol(symbol));
            }
        }
        Ok(Self { symbols, indices })
    }

    /// Number of symbols in this alphabet.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns whether this alphabet has no symbols (always false for valid values).
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Returns the symbol at an index, if it is in range.
    pub fn symbol_at(&self, index: usize) -> Option<char> {
        self.symbols.get(index).copied()
    }

    /// Returns the index of a symbol without normalization, if present.
    pub fn index_of(&self, symbol: char) -> Option<usize> {
        self.indices.get(&symbol).copied()
    }
}

/// Whether a slot may change position under a stepping rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Movement {
    /// The slot's position is stationary.
    Fixed,
    /// The slot's position may advance.
    Movable,
}

/// The machine role assigned to a physical slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotRole {
    /// A wheel traversed as a rotor, whether fixed or movable.
    Rotor,
    /// An optional reflector, constrained to be leftmost and involutive.
    Reflector,
}

/// A physical left-to-right machine slot configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Slot {
    id: String,
    wheel: String,
    role: SlotRole,
    movement: Movement,
    position: char,
    ring: char,
}

impl Slot {
    /// Creates a slot; topology construction validates its wheel reference and symbols.
    pub fn new(
        id: impl Into<String>,
        wheel: impl Into<String>,
        role: SlotRole,
        movement: Movement,
        position: char,
        ring: char,
    ) -> Self {
        Self {
            id: id.into(),
            wheel: wheel.into(),
            role,
            movement,
            position,
            ring,
        }
    }

    /// Stable slot identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Referenced wheel definition name.
    pub fn wheel(&self) -> &str {
        &self.wheel
    }

    /// Slot role.
    pub fn role(&self) -> SlotRole {
        self.role
    }

    /// Whether this slot is stationary or may move.
    pub fn movement(&self) -> Movement {
        self.movement
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

/// Validated in-memory wheel definitions and physical machine slot topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineTopology {
    alphabet: Alphabet,
    wheels: Vec<Wiring>,
    wheel_indices: HashMap<String, usize>,
    slots: Vec<Slot>,
    slot_indices: HashMap<String, usize>,
}

impl MachineTopology {
    /// Builds a validated topology. Slots remain in physical left-to-right order.
    pub fn new(
        alphabet: Alphabet,
        wheels: Vec<Wiring>,
        slots: Vec<Slot>,
    ) -> Result<Self, ModelError> {
        if slots.is_empty() {
            return Err(ModelError::EmptySlots);
        }
        let mut wheel_indices = HashMap::with_capacity(wheels.len());
        for (index, wheel) in wheels.iter().enumerate() {
            if wheel.alphabet != alphabet {
                return Err(ModelError::WheelAlphabetMismatch(wheel.name.clone()));
            }
            if wheel_indices.insert(wheel.name.clone(), index).is_some() {
                return Err(ModelError::DuplicateWheelName(wheel.name.clone()));
            }
        }

        let mut slot_indices = HashMap::with_capacity(slots.len());
        let mut reflector_index = None;
        let mut rotor_count = 0;
        for (index, slot) in slots.iter().enumerate() {
            if slot.id.is_empty() {
                return Err(ModelError::EmptySlotId);
            }
            if slot_indices.insert(slot.id.clone(), index).is_some() {
                return Err(ModelError::DuplicateSlotId(slot.id.clone()));
            }
            let wheel_index = *wheel_indices
                .get(&slot.wheel)
                .ok_or_else(|| ModelError::UnknownWheel(slot.wheel.clone()))?;
            if alphabet.index_of(slot.position).is_none() {
                return Err(ModelError::UnknownSlotSymbol(slot.position));
            }
            if alphabet.index_of(slot.ring).is_none() {
                return Err(ModelError::UnknownSlotSymbol(slot.ring));
            }
            match slot.role {
                SlotRole::Rotor => rotor_count += 1,
                SlotRole::Reflector => {
                    if reflector_index.replace(index).is_some() {
                        return Err(ModelError::MultipleReflectors);
                    }
                    let wheel = &wheels[wheel_index];
                    if wheel
                        .forward
                        .iter()
                        .enumerate()
                        .any(|(input, &output)| wheel.forward[output] != input)
                    {
                        return Err(ModelError::ReflectorMustBeInvolutive(wheel.name.clone()));
                    }
                }
            }
        }
        if reflector_index.is_some_and(|index| index != 0) {
            return Err(ModelError::ReflectorNotLeftmost);
        }
        if rotor_count == 0 {
            return Err(ModelError::NoRotorSlots);
        }
        Ok(Self {
            alphabet,
            wheels,
            wheel_indices,
            slots,
            slot_indices,
        })
    }

    /// The ordered symbol alphabet carried by this topology.
    pub fn alphabet(&self) -> &Alphabet {
        &self.alphabet
    }

    /// Declared wheel definitions in their supplied order.
    pub fn wheels(&self) -> &[Wiring] {
        &self.wheels
    }

    /// Physical slots in left-to-right order.
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Looks up a declared wheel by its unique name.
    pub fn wheel(&self, name: &str) -> Option<&Wiring> {
        self.wheel_indices
            .get(name)
            .map(|&index| &self.wheels[index])
    }

    /// Looks up a slot's physical index (left-to-right) by its unique identifier.
    pub fn slot_index(&self, id: &str) -> Option<usize> {
        self.slot_indices.get(id).copied()
    }
}

/// Maximum number of stepping rules a machine may declare.
pub const MAX_STEP_RULES: usize = 64;

/// Maximum total number of condition nodes across all stepping rules.
pub const MAX_STEP_CONDITION_NODES: usize = 256;

/// Maximum nesting depth of a stepping condition.
pub const MAX_STEP_CONDITION_DEPTH: usize = 16;

/// Maximum number of distinct slots that stepping rules may advance.
pub const MAX_STEP_TARGETS: usize = 64;

/// A bounded boolean condition evaluated against the pre-keypress positions.
///
/// Conditions are pure data: they hold no executable code and are evaluated against
/// the same state before every keypress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepCondition {
    /// Always true.
    Always,
    /// True when the referenced slot's displayed position is one of its wheel turnovers.
    AtTurnover(String),
    /// True when the referenced slot displays `symbol`.
    AtPosition {
        /// Referenced slot identifier.
        slot: String,
        /// Displayed position to compare against.
        symbol: char,
    },
    /// True when every contained condition is true; the group is non-empty.
    All(Vec<StepCondition>),
    /// True when any contained condition is true; the group is non-empty.
    Any(Vec<StepCondition>),
    /// True when the contained condition is false.
    Not(Box<StepCondition>),
}

/// One stepping rule: while `condition` holds, every listed slot advances once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepRule {
    condition: StepCondition,
    advance: Vec<String>,
}

impl StepRule {
    /// Creates a rule; [`Stepping::new`] validates its references and bounds.
    pub fn new(condition: StepCondition, advance: Vec<String>) -> Self {
        Self { condition, advance }
    }

    /// The condition tested against the pre-keypress state.
    pub fn condition(&self) -> &StepCondition {
        &self.condition
    }

    /// Slot identifiers advanced when the condition holds.
    pub fn advance(&self) -> &[String] {
        &self.advance
    }
}

/// A validated, bounded set of declarative stepping rules.
///
/// All conditions of every rule are evaluated against the same pre-keypress positions;
/// the target slots of all matching rules are unioned and each advanced exactly once,
/// simultaneously. Rule order therefore does not change the result. An empty rule set
/// means no slot moves.
///
/// A rule set is bound to the topology it was built against: evaluating it against any
/// other topology fails closed instead of silently skipping unresolvable targets. The
/// unbound empty set from [`Stepping::none`] carries no rules and may be evaluated
/// against any topology.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stepping {
    rules: Vec<StepRule>,
    bound_topology: Option<MachineTopology>,
}

impl Stepping {
    /// Creates an empty rule set, under which no slot moves.
    pub fn none() -> Self {
        Self::default()
    }

    /// Validates and assembles a rule set against `topology`.
    ///
    /// Rejects unknown slot references, non-movable advance targets, malformed empty
    /// `all`/`any` groups, symbols outside the alphabet, and any rule set exceeding the
    /// documented grammar limits.
    pub fn new(topology: &MachineTopology, rules: Vec<StepRule>) -> Result<Self, ModelError> {
        if rules.len() > MAX_STEP_RULES {
            return Err(ModelError::TooManyStepRules {
                max: MAX_STEP_RULES,
            });
        }
        let mut nodes = 0usize;
        let mut targets = BTreeSet::new();
        for rule in &rules {
            validate_step_condition(topology, &rule.condition, 1, &mut nodes)?;
            for id in &rule.advance {
                let index = topology
                    .slot_index(id)
                    .ok_or_else(|| ModelError::UnknownStepSlot(id.clone()))?;
                if topology.slots()[index].movement() != Movement::Movable {
                    return Err(ModelError::NonMovableStepTarget(id.clone()));
                }
                targets.insert(index);
            }
        }
        if targets.len() > MAX_STEP_TARGETS {
            return Err(ModelError::TooManyStepTargets {
                max: MAX_STEP_TARGETS,
            });
        }
        Ok(Self {
            rules,
            bound_topology: Some(topology.clone()),
        })
    }

    /// The validated rules in their declared order.
    pub fn rules(&self) -> &[StepRule] {
        &self.rules
    }

    /// Computes the sorted indices of the slots to advance for the current positions.
    ///
    /// `positions` holds one displayed symbol per slot in physical left-to-right order.
    /// The returned indices are deduplicated, so a slot matched by several rules appears
    /// once; sorting keeps the result independent of rule order.
    pub fn plan(
        &self,
        topology: &MachineTopology,
        positions: &[char],
    ) -> Result<Vec<usize>, ModelError> {
        if let Some(bound) = &self.bound_topology {
            if bound != topology {
                return Err(ModelError::SteppingTopologyMismatch);
            }
        }
        let expected = topology.slots().len();
        if positions.len() != expected {
            return Err(ModelError::PositionCountMismatch {
                expected,
                actual: positions.len(),
            });
        }
        let mut targets = BTreeSet::new();
        for rule in &self.rules {
            if step_condition_holds(topology, positions, &rule.condition) {
                for id in &rule.advance {
                    // Validated against `bound_topology` at construction; resolving here
                    // again guarantees an unknown target can never be skipped silently.
                    let index = topology
                        .slot_index(id)
                        .ok_or_else(|| ModelError::UnknownStepSlot(id.clone()))?;
                    targets.insert(index);
                }
            }
        }
        Ok(targets.into_iter().collect())
    }

    /// Applies the current step plan, advancing each target once and wrapping modulo N.
    ///
    /// Only the displayed positions change; ring settings affect electrical offsets and
    /// never the turnover comparison.
    pub fn advance(
        &self,
        topology: &MachineTopology,
        positions: &mut [char],
    ) -> Result<(), ModelError> {
        let plan = self.plan(topology, positions)?;
        let size = topology.alphabet().len();
        for index in plan {
            let symbol = positions[index];
            let current = topology
                .alphabet()
                .index_of(symbol)
                .ok_or(ModelError::UnknownSymbol(symbol))?;
            if let Some(next) = topology.alphabet().symbol_at((current + 1) % size) {
                positions[index] = next;
            }
        }
        Ok(())
    }
}

fn validate_step_condition(
    topology: &MachineTopology,
    condition: &StepCondition,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ModelError> {
    if depth > MAX_STEP_CONDITION_DEPTH {
        return Err(ModelError::StepConditionTooDeep {
            max: MAX_STEP_CONDITION_DEPTH,
        });
    }
    *nodes += 1;
    if *nodes > MAX_STEP_CONDITION_NODES {
        return Err(ModelError::TooManyStepConditionNodes {
            max: MAX_STEP_CONDITION_NODES,
        });
    }
    match condition {
        StepCondition::Always => Ok(()),
        StepCondition::AtTurnover(id) => {
            if topology.slot_index(id).is_none() {
                return Err(ModelError::UnknownStepSlot(id.clone()));
            }
            Ok(())
        }
        StepCondition::AtPosition { slot, symbol } => {
            if topology.slot_index(slot).is_none() {
                return Err(ModelError::UnknownStepSlot(slot.clone()));
            }
            if topology.alphabet().index_of(*symbol).is_none() {
                return Err(ModelError::UnknownSymbol(*symbol));
            }
            Ok(())
        }
        StepCondition::All(conditions) | StepCondition::Any(conditions) => {
            if conditions.is_empty() {
                return Err(ModelError::EmptyStepConditionGroup);
            }
            for condition in conditions {
                validate_step_condition(topology, condition, depth + 1, nodes)?;
            }
            Ok(())
        }
        StepCondition::Not(condition) => {
            validate_step_condition(topology, condition, depth + 1, nodes)
        }
    }
}

fn step_condition_holds(
    topology: &MachineTopology,
    positions: &[char],
    condition: &StepCondition,
) -> bool {
    match condition {
        StepCondition::Always => true,
        StepCondition::AtTurnover(id) => topology.slot_index(id).is_some_and(|index| {
            topology
                .wheel(topology.slots()[index].wheel())
                .is_some_and(|wheel| wheel.at_turnover(positions[index]))
        }),
        StepCondition::AtPosition { slot, symbol } => topology
            .slot_index(slot)
            .is_some_and(|index| positions[index] == *symbol),
        StepCondition::All(conditions) => conditions
            .iter()
            .all(|condition| step_condition_holds(topology, positions, condition)),
        StepCondition::Any(conditions) => conditions
            .iter()
            .any(|condition| step_condition_holds(topology, positions, condition)),
        StepCondition::Not(condition) => !step_condition_holds(topology, positions, condition),
    }
}

/// A disjoint plugboard involution bound to an ordered alphabet.
///
/// Pairs are directionless: `(a, b)` and `(b, a)` describe the same mapping. Every
/// symbol that appears in no pair maps to itself. Symbols are preserved exactly: this
/// type does not normalize or rewrite them, and a symbol outside the bound alphabet has
/// no mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plugboard {
    alphabet: Alphabet,
    mapping: Vec<usize>,
}

impl Plugboard {
    /// Builds a plugboard over `alphabet` from unordered pairs of distinct symbols.
    ///
    /// Each symbol may occur in at most one pair; the pairs define a disjoint
    /// involution, and unpaired symbols map to themselves. A symbol paired with itself,
    /// a repeated endpoint, or a symbol outside `alphabet` is rejected.
    pub fn new(alphabet: &Alphabet, pairs: &[(char, char)]) -> Result<Self, ModelError> {
        let mut mapping: Vec<usize> = (0..alphabet.len()).collect();
        for &(left, right) in pairs {
            let left_index = alphabet
                .index_of(left)
                .ok_or(ModelError::UnknownSymbol(left))?;
            let right_index = alphabet
                .index_of(right)
                .ok_or(ModelError::UnknownSymbol(right))?;
            if left_index == right_index {
                return Err(ModelError::PlugboardSelfPair(left));
            }
            if mapping[left_index] != left_index {
                return Err(ModelError::DuplicatePlugboardSymbol(left));
            }
            if mapping[right_index] != right_index {
                return Err(ModelError::DuplicatePlugboardSymbol(right));
            }
            mapping[left_index] = right_index;
            mapping[right_index] = left_index;
        }
        Ok(Self {
            alphabet: alphabet.clone(),
            mapping,
        })
    }

    /// Builds the identity plugboard over `alphabet`, where every symbol maps to itself.
    pub fn identity(alphabet: &Alphabet) -> Self {
        Self {
            alphabet: alphabet.clone(),
            mapping: (0..alphabet.len()).collect(),
        }
    }

    /// The ordered alphabet this plugboard is bound to.
    pub fn alphabet(&self) -> &Alphabet {
        &self.alphabet
    }

    /// Returns the paired symbol, or the symbol itself when unpaired.
    ///
    /// Returns `None` when the symbol is not a member of the bound alphabet.
    pub fn map(&self, symbol: char) -> Option<char> {
        let index = self.alphabet.index_of(symbol)?;
        self.alphabet.symbol_at(self.mapping[index])
    }

    /// Whether `symbol` is paired with a different alphabet symbol.
    ///
    /// Returns `false` for unpaired symbols and for symbols outside the alphabet.
    pub fn is_paired(&self, symbol: char) -> bool {
        self.alphabet
            .index_of(symbol)
            .is_some_and(|index| self.mapping[index] != index)
    }
}

/// A named bijective wheel mapping and its inverse, with displayed-position turnovers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wiring {
    name: String,
    alphabet: Alphabet,
    forward: Vec<usize>,
    reverse: Vec<usize>,
    turnovers: HashSet<char>,
}

impl Wiring {
    /// Builds a wheel wiring over `alphabet`; turnovers are displayed positions.
    pub fn new(
        name: impl Into<String>,
        alphabet: &Alphabet,
        mapping: &[char],
        turnovers: &[char],
    ) -> Result<Self, ModelError> {
        let name = name.into();
        if name.is_empty() {
            return Err(ModelError::EmptyWiringName);
        }
        if mapping.len() != alphabet.len() {
            return Err(ModelError::WiringLength {
                expected: alphabet.len(),
                actual: mapping.len(),
            });
        }

        let mut forward = Vec::with_capacity(mapping.len());
        let mut reverse = vec![usize::MAX; alphabet.len()];
        for (input, &symbol) in mapping.iter().enumerate() {
            let output = alphabet
                .index_of(symbol)
                .ok_or(ModelError::UnknownSymbol(symbol))?;
            if reverse[output] != usize::MAX {
                return Err(ModelError::DuplicateWiringSymbol(symbol));
            }
            forward.push(output);
            reverse[output] = input;
        }

        let mut turnover_set = HashSet::with_capacity(turnovers.len());
        for &symbol in turnovers {
            if alphabet.index_of(symbol).is_none() {
                return Err(ModelError::UnknownSymbol(symbol));
            }
            if !turnover_set.insert(symbol) {
                return Err(ModelError::DuplicateTurnover(symbol));
            }
        }
        Ok(Self {
            name,
            alphabet: alphabet.clone(),
            forward,
            reverse,
            turnovers: turnover_set,
        })
    }

    /// Wheel definition name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether a displayed position is a turnover position.
    pub fn at_turnover(&self, displayed_position: char) -> bool {
        self.turnovers.contains(&displayed_position)
    }

    /// Maps a symbol through the wheel at the supplied displayed position and ring.
    pub fn forward(&self, symbol: char, position: char, ring: char) -> Option<char> {
        self.map(symbol, position, ring, &self.forward)
    }

    /// Maps a symbol through the inverse wheel at the supplied displayed position and ring.
    pub fn reverse(&self, symbol: char, position: char, ring: char) -> Option<char> {
        self.map(symbol, position, ring, &self.reverse)
    }

    fn map(&self, symbol: char, position: char, ring: char, mapping: &[usize]) -> Option<char> {
        let input = self.alphabet.index_of(symbol)?;
        let position = self.alphabet.index_of(position)?;
        let ring = self.alphabet.index_of(ring)?;
        let size = self.alphabet.len();
        let offset = if position >= ring {
            position - ring
        } else {
            size - (ring - position)
        };
        let shifted = if input >= size - offset {
            input - (size - offset)
        } else {
            input + offset
        };
        let output = mapping[shifted];
        let unshifted = if output < offset {
            size - (offset - output)
        } else {
            output - offset
        };
        self.alphabet.symbol_at(unshifted)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Alphabet, MachineTopology, ModelError, Movement, Plugboard, Slot, SlotRole, StepCondition,
        StepRule, Stepping, Wiring, MAX_STEP_CONDITION_DEPTH, MAX_STEP_CONDITION_NODES,
        MAX_STEP_RULES, MAX_STEP_TARGETS,
    };

    fn identity_wiring(alphabet: &Alphabet, name: &str) -> Wiring {
        let mapping: Vec<_> = (0..alphabet.len())
            .map(|index| alphabet.symbol_at(index).unwrap())
            .collect();
        Wiring::new(name, alphabet, &mapping, &[]).unwrap()
    }

    #[test]
    fn topology_accepts_one_rotor_and_seven_rotors() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let wheel = identity_wiring(&alphabet, "rotor");
        let one = MachineTopology::new(
            alphabet.clone(),
            vec![wheel.clone()],
            vec![Slot::new(
                "right",
                "rotor",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        assert_eq!(one.slots().len(), 1);

        let slots = (0..7)
            .map(|index| {
                Slot::new(
                    format!("rotor-{index}"),
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                )
            })
            .collect();
        let seven = MachineTopology::new(alphabet, vec![wheel], slots).unwrap();
        assert_eq!(seven.slots().len(), 7);
    }

    #[test]
    fn topology_rejects_invalid_references_roles_symbols_and_duplicates() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let rotor = identity_wiring(&alphabet, "rotor");
        let slot =
            |id: &str, wheel: &str, role| Slot::new(id, wheel, role, Movement::Fixed, 'A', 'A');

        assert_eq!(
            MachineTopology::new(alphabet.clone(), vec![rotor.clone()], vec![]),
            Err(ModelError::EmptySlots)
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![slot("x", "missing", SlotRole::Rotor)]
            ),
            Err(ModelError::UnknownWheel("missing".into()))
        );
        let non_involutive = Wiring::new("cycle", &alphabet, &['B', 'C', 'A'], &[]).unwrap();
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone(), non_involutive],
                vec![
                    slot("reflector", "cycle", SlotRole::Reflector),
                    slot("rotor", "rotor", SlotRole::Rotor),
                ],
            ),
            Err(ModelError::ReflectorMustBeInvolutive("cycle".into()))
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![
                    slot("x", "rotor", SlotRole::Rotor),
                    slot("x", "rotor", SlotRole::Rotor),
                ]
            ),
            Err(ModelError::DuplicateSlotId("x".into()))
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone(), rotor.clone()],
                vec![slot("x", "rotor", SlotRole::Rotor)]
            ),
            Err(ModelError::DuplicateWheelName("rotor".into()))
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![
                    slot("left", "rotor", SlotRole::Rotor),
                    slot("reflector", "rotor", SlotRole::Reflector),
                ]
            ),
            Err(ModelError::ReflectorNotLeftmost)
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![
                    slot("reflector-1", "rotor", SlotRole::Reflector),
                    slot("reflector-2", "rotor", SlotRole::Reflector),
                    slot("right", "rotor", SlotRole::Rotor),
                ]
            ),
            Err(ModelError::MultipleReflectors)
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![Slot::new(
                    "x",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'Z',
                    'A'
                ),]
            ),
            Err(ModelError::UnknownSlotSymbol('Z'))
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor],
                vec![slot("x", "rotor", SlotRole::Reflector)]
            ),
            Err(ModelError::NoRotorSlots)
        );
    }

    #[test]
    fn topology_rejects_invalid_ring_and_empty_slot_id_and_keeps_movement_role_independent() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let rotor = identity_wiring(&alphabet, "rotor");
        let reflector = identity_wiring(&alphabet, "reflector");

        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![Slot::new(
                    "right",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'Z'
                )],
            ),
            Err(ModelError::UnknownSlotSymbol('Z'))
        );
        assert_eq!(
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![Slot::new(
                    "",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A'
                )],
            ),
            Err(ModelError::EmptySlotId)
        );

        // Movement is independent of role: a movable reflector is a valid machine.
        let movable_reflector = MachineTopology::new(
            alphabet.clone(),
            vec![reflector, rotor.clone()],
            vec![
                Slot::new(
                    "ukw",
                    "reflector",
                    SlotRole::Reflector,
                    Movement::Movable,
                    'A',
                    'A',
                ),
                Slot::new(
                    "right",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                ),
            ],
        )
        .unwrap();
        assert_eq!(movable_reflector.slots()[0].movement(), Movement::Movable);

        // A fixed rotor without a reflector models a stationary entry wheel.
        let entry_wheel = MachineTopology::new(
            alphabet,
            vec![rotor],
            vec![
                Slot::new("entry", "rotor", SlotRole::Rotor, Movement::Fixed, 'A', 'A'),
                Slot::new(
                    "right",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                ),
            ],
        )
        .unwrap();
        assert_eq!(entry_wheel.slots()[0].movement(), Movement::Fixed);
    }

    #[test]
    fn topology_accepts_leftmost_involutive_reflector_and_exposes_bound_alphabet() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let rotor = identity_wiring(&alphabet, "rotor");
        let reflector = Wiring::new("reflector", &alphabet, &['B', 'A', 'C'], &[]).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![rotor, reflector],
            vec![
                Slot::new(
                    "ukw",
                    "reflector",
                    SlotRole::Reflector,
                    Movement::Fixed,
                    'A',
                    'B',
                ),
                Slot::new(
                    "left",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'C',
                    'A',
                ),
            ],
        )
        .unwrap();
        assert_eq!(topology.alphabet(), &alphabet);
        assert_eq!(topology.slots()[0].id(), "ukw");
        assert_eq!(topology.slots()[0].movement(), Movement::Fixed);
        assert_eq!(topology.slots()[0].ring(), 'B');
        assert_eq!(topology.wheel("reflector").unwrap().name(), "reflector");
    }

    #[test]
    fn topology_rejects_wheels_built_for_a_different_ordered_alphabet() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let mismatched = Alphabet::new(vec!['B', 'A', 'C']).unwrap();
        let wheel = identity_wiring(&mismatched, "rotor");
        assert_eq!(
            MachineTopology::new(
                alphabet,
                vec![wheel],
                vec![Slot::new(
                    "x",
                    "rotor",
                    SlotRole::Rotor,
                    Movement::Fixed,
                    'A',
                    'A'
                )],
            ),
            Err(ModelError::WheelAlphabetMismatch("rotor".into()))
        );
    }

    #[test]
    fn alphabet_preserves_non_ascii_scalar_order_without_normalizing() {
        let alphabet = Alphabet::new(vec!['λ', '中', 'é']).unwrap();
        assert_eq!(alphabet.len(), 3);
        assert_eq!(alphabet.symbol_at(1), Some('中'));
        assert_eq!(alphabet.index_of('é'), Some(2));
        assert_eq!(alphabet.index_of('e'), None);
        assert_eq!(Alphabet::new(vec!['e', '\u{301}']).unwrap().len(), 2);
    }

    #[test]
    fn alphabet_rejects_empty_and_duplicate_symbols() {
        assert_eq!(Alphabet::new(vec![]), Err(ModelError::EmptyAlphabet));
        assert_eq!(
            Alphabet::new(vec!['A', 'B', 'A']),
            Err(ModelError::DuplicateAlphabetSymbol('A'))
        );
    }

    #[test]
    fn wiring_validates_permutations_and_turnovers() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        assert_eq!(
            Wiring::new("bad", &alphabet, &['A', 'A', 'C'], &[]),
            Err(ModelError::DuplicateWiringSymbol('A'))
        );
        assert_eq!(
            Wiring::new("bad", &alphabet, &['A', 'B'], &[]),
            Err(ModelError::WiringLength {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            Wiring::new("bad", &alphabet, &['A', 'B', 'C'], &['Z']),
            Err(ModelError::UnknownSymbol('Z'))
        );
        assert_eq!(
            Wiring::new("bad", &alphabet, &['A', 'B', 'C'], &['A', 'A']),
            Err(ModelError::DuplicateTurnover('A'))
        );
    }

    #[test]
    fn forward_and_reverse_mapping_are_inverses_with_ring_offset() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let wiring = Wiring::new("shift", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap();

        assert_eq!(wiring.forward('A', 'A', 'A'), Some('B'));
        assert_eq!(wiring.reverse('B', 'A', 'A'), Some('A'));
        // position C, ring B gives offset 1: input A addresses wiring[B] == C,
        // then removes the offset, yielding B.
        assert_eq!(wiring.forward('A', 'C', 'B'), Some('B'));
        assert_eq!(wiring.reverse('B', 'C', 'B'), Some('A'));
        assert_eq!(wiring.forward('A', 'Z', 'A'), None);
    }

    #[test]
    fn wiring_binds_mapping_to_its_alphabet_and_applies_wrapped_offsets() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let wiring = Wiring::new("permutation", &alphabet, &['B', 'D', 'A', 'C'], &[]).unwrap();

        // Independently evaluated from forward(x) = wiring[(x + o) mod N] - o mod N.
        assert_eq!(wiring.forward('A', 'B', 'A'), Some('C'));
        assert_eq!(wiring.forward('A', 'A', 'B'), Some('D'));
        assert_eq!(wiring.reverse('C', 'B', 'A'), Some('A'));
        // Wrapped offset -1: D shifts to C, inverse(C) is D, then unshifting yields A.
        assert_eq!(wiring.reverse('D', 'A', 'B'), Some('A'));
    }

    #[test]
    fn plugboard_identity_maps_every_symbol_to_itself() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let plugboard = Plugboard::new(&alphabet, &[]).unwrap();
        assert_eq!(plugboard.alphabet(), &alphabet);
        for symbol in ['A', 'B', 'C'] {
            assert_eq!(plugboard.map(symbol), Some(symbol));
            assert!(!plugboard.is_paired(symbol));
        }
        assert_eq!(Plugboard::identity(&alphabet), plugboard);
    }

    #[test]
    fn plugboard_is_a_disjoint_involution_with_identity_for_unpaired_symbols() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let plugboard = Plugboard::new(&alphabet, &[('A', 'B'), ('C', 'D')]).unwrap();
        for symbol in ['A', 'B', 'C', 'D'] {
            let mapped = plugboard.map(symbol).unwrap();
            assert_eq!(plugboard.map(mapped), Some(symbol));
            assert!(plugboard.is_paired(symbol));
        }
        assert_eq!(plugboard.map('A'), Some('B'));
        assert_eq!(plugboard.map('B'), Some('A'));
        assert_eq!(plugboard.map('C'), Some('D'));
        assert_eq!(plugboard.map('D'), Some('C'));
    }

    #[test]
    fn plugboard_ignores_pair_order_and_leaves_other_symbols_unpaired() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let forward = Plugboard::new(&alphabet, &[('A', 'B')]).unwrap();
        let reversed = Plugboard::new(&alphabet, &[('B', 'A')]).unwrap();
        assert_eq!(forward, reversed);
        assert_eq!(forward.map('C'), Some('C'));
        assert!(!forward.is_paired('C'));
    }

    #[test]
    fn plugboard_rejects_self_pairs_repeated_endpoints_and_unknown_symbols() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        assert_eq!(
            Plugboard::new(&alphabet, &[('A', 'A')]),
            Err(ModelError::PlugboardSelfPair('A'))
        );
        assert_eq!(
            Plugboard::new(&alphabet, &[('A', 'B'), ('A', 'C')]),
            Err(ModelError::DuplicatePlugboardSymbol('A'))
        );
        assert_eq!(
            Plugboard::new(&alphabet, &[('A', 'B'), ('B', 'C')]),
            Err(ModelError::DuplicatePlugboardSymbol('B'))
        );
        assert_eq!(
            Plugboard::new(&alphabet, &[('A', 'B'), ('A', 'B')]),
            Err(ModelError::DuplicatePlugboardSymbol('A'))
        );
        assert_eq!(
            Plugboard::new(&alphabet, &[('A', 'Z')]),
            Err(ModelError::UnknownSymbol('Z'))
        );
    }

    #[test]
    fn plugboard_reports_the_left_endpoint_before_the_right() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        // Both endpoints unknown: the left endpoint is reported first.
        assert_eq!(
            Plugboard::new(&alphabet, &[('Z', 'Y')]),
            Err(ModelError::UnknownSymbol('Z'))
        );
        // A known left endpoint does not mask an unknown right endpoint.
        assert_eq!(
            Plugboard::new(&alphabet, &[('A', 'Z')]),
            Err(ModelError::UnknownSymbol('Z'))
        );
        // A repeated symbol is reported from the endpoint that repeats.
        assert_eq!(
            Plugboard::new(&alphabet, &[('A', 'B'), ('C', 'B')]),
            Err(ModelError::DuplicatePlugboardSymbol('B'))
        );
        // An unknown endpoint is reported before the self-pair rule.
        assert_eq!(
            Plugboard::new(&alphabet, &[('Z', 'Z')]),
            Err(ModelError::UnknownSymbol('Z'))
        );
    }

    #[test]
    fn plugboard_preserves_unicode_symbols_without_normalizing() {
        let alphabet = Alphabet::new(vec!['λ', '中', 'é']).unwrap();
        let plugboard = Plugboard::new(&alphabet, &[('λ', '中')]).unwrap();
        assert_eq!(plugboard.map('λ'), Some('中'));
        assert_eq!(plugboard.map('中'), Some('λ'));
        assert_eq!(plugboard.map('é'), Some('é'));
        assert_eq!(plugboard.map('e'), None);
        assert!(!plugboard.is_paired('\u{301}'));
    }

    #[test]
    fn turnovers_use_displayed_positions_without_ring_adjustment() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let wiring = Wiring::new("rotor", &alphabet, &['A', 'B', 'C'], &['B']).unwrap();
        assert!(wiring.at_turnover('B'));
        assert!(!wiring.at_turnover('A'));
        assert!(!wiring.at_turnover('Z'));
    }

    fn stepping_topology() -> MachineTopology {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let fast = Wiring::new("fast", &alphabet, &['B', 'C', 'D', 'A'], &['B']).unwrap();
        let slow = Wiring::new("slow", &alphabet, &['A', 'B', 'C', 'D'], &['A']).unwrap();
        MachineTopology::new(
            alphabet,
            vec![fast, slow],
            vec![
                Slot::new("slow", "slow", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
                Slot::new("fast", "fast", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
            ],
        )
        .unwrap()
    }

    #[test]
    fn stepping_advances_the_union_of_matching_targets_exactly_once() {
        let topology = stepping_topology();
        let stepping = Stepping::new(
            &topology,
            vec![
                StepRule::new(StepCondition::Always, vec!["fast".into()]),
                StepRule::new(
                    StepCondition::AtPosition {
                        slot: "fast".into(),
                        symbol: 'A',
                    },
                    vec!["fast".into(), "slow".into()],
                ),
            ],
        )
        .unwrap();

        let mut positions = ['A', 'A'];
        // Both rules match, but `fast` is advanced exactly once.
        assert_eq!(stepping.plan(&topology, &positions).unwrap(), vec![0, 1]);
        stepping.advance(&topology, &mut positions).unwrap();
        assert_eq!(positions, ['B', 'B']);
    }

    #[test]
    fn stepping_with_no_rules_never_moves() {
        let topology = stepping_topology();
        let stepping = Stepping::none();
        let mut positions = ['A', 'A'];
        assert!(stepping.plan(&topology, &positions).unwrap().is_empty());
        stepping.advance(&topology, &mut positions).unwrap();
        assert_eq!(positions, ['A', 'A']);
    }

    #[test]
    fn stepping_rejects_reuse_with_a_different_topology() {
        let topology = stepping_topology();
        let stepping = Stepping::new(
            &topology,
            vec![StepRule::new(StepCondition::Always, vec!["fast".into()])],
        )
        .unwrap();

        // Same identifiers, but the target slot is no longer movable: the rule set must
        // reject the topology instead of advancing a now-fixed slot.
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let fast = Wiring::new("fast", &alphabet, &['B', 'C', 'D', 'A'], &['B']).unwrap();
        let slow = Wiring::new("slow", &alphabet, &['A', 'B', 'C', 'D'], &['A']).unwrap();
        let fixed_target = MachineTopology::new(
            alphabet.clone(),
            vec![fast.clone(), slow.clone()],
            vec![
                Slot::new("slow", "slow", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
                Slot::new("fast", "fast", SlotRole::Rotor, Movement::Fixed, 'A', 'A'),
            ],
        )
        .unwrap();
        let mut positions = ['A', 'A'];
        assert_eq!(
            stepping.plan(&fixed_target, &positions),
            Err(ModelError::SteppingTopologyMismatch)
        );
        assert_eq!(
            stepping.advance(&fixed_target, &mut positions),
            Err(ModelError::SteppingTopologyMismatch)
        );

        // A renamed slot previously caused the unknown target to be skipped silently.
        let renamed = MachineTopology::new(
            alphabet,
            vec![fast, slow],
            vec![
                Slot::new(
                    "slow-2",
                    "slow",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                ),
                Slot::new(
                    "fast-2",
                    "fast",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            stepping.plan(&renamed, &positions),
            Err(ModelError::SteppingTopologyMismatch)
        );
    }

    #[test]
    fn stepping_result_is_independent_of_rule_order() {
        let topology = stepping_topology();
        let forward = Stepping::new(
            &topology,
            vec![
                StepRule::new(StepCondition::Always, vec!["fast".into()]),
                StepRule::new(
                    StepCondition::AtPosition {
                        slot: "fast".into(),
                        symbol: 'A',
                    },
                    vec!["fast".into(), "slow".into()],
                ),
                StepRule::new(StepCondition::Always, vec!["slow".into()]),
            ],
        )
        .unwrap();
        let reversed = Stepping::new(
            &topology,
            vec![
                StepRule::new(StepCondition::Always, vec!["slow".into()]),
                StepRule::new(
                    StepCondition::AtPosition {
                        slot: "fast".into(),
                        symbol: 'A',
                    },
                    vec!["slow".into(), "fast".into()],
                ),
                StepRule::new(StepCondition::Always, vec!["fast".into()]),
            ],
        )
        .unwrap();

        let positions = ['A', 'A'];
        assert_eq!(
            forward.plan(&topology, &positions),
            reversed.plan(&topology, &positions)
        );
        assert_eq!(forward.plan(&topology, &positions).unwrap(), vec![0, 1]);
    }

    #[test]
    fn stepping_turnover_uses_displayed_position_and_ignores_ring() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let fast = Wiring::new("fast", &alphabet, &['A', 'B', 'C', 'D'], &['B']).unwrap();
        let topology = MachineTopology::new(
            alphabet,
            vec![fast],
            vec![Slot::new(
                "fast",
                "fast",
                SlotRole::Rotor,
                Movement::Movable,
                'B',
                'C',
            )],
        )
        .unwrap();
        let stepping = Stepping::new(
            &topology,
            vec![StepRule::new(
                StepCondition::AtTurnover("fast".into()),
                vec!["fast".into()],
            )],
        )
        .unwrap();

        // The displayed position is a turnover; the ring setting does not suppress it.
        let mut positions = ['B'];
        stepping.advance(&topology, &mut positions).unwrap();
        assert_eq!(positions, ['C']);

        // A displayed position that is not a turnover does not advance.
        assert!(stepping.plan(&topology, &['A']).unwrap().is_empty());
    }

    #[test]
    fn stepping_conditions_compose_with_all_any_and_not() {
        let topology = stepping_topology();
        let all = StepCondition::All(vec![
            StepCondition::AtPosition {
                slot: "slow".into(),
                symbol: 'A',
            },
            StepCondition::Not(Box::new(StepCondition::AtPosition {
                slot: "fast".into(),
                symbol: 'A',
            })),
        ]);
        let stepping =
            Stepping::new(&topology, vec![StepRule::new(all, vec!["slow".into()])]).unwrap();
        assert_eq!(stepping.plan(&topology, &['A', 'B']).unwrap(), vec![0]);
        assert_eq!(
            stepping.plan(&topology, &['A', 'A']).unwrap(),
            Vec::<usize>::new()
        );

        let any = StepCondition::Any(vec![
            StepCondition::AtTurnover("fast".into()),
            StepCondition::AtPosition {
                slot: "slow".into(),
                symbol: 'D',
            },
        ]);
        let stepping =
            Stepping::new(&topology, vec![StepRule::new(any, vec!["slow".into()])]).unwrap();
        // `fast` displays its turnover even though `slow` is not at D.
        assert_eq!(stepping.plan(&topology, &['A', 'B']).unwrap(), vec![0]);
        assert_eq!(stepping.plan(&topology, &['D', 'A']).unwrap(), vec![0]);
        assert_eq!(
            stepping.plan(&topology, &['C', 'A']).unwrap(),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn stepping_advance_wraps_at_the_end_of_the_alphabet() {
        let topology = stepping_topology();
        let stepping = Stepping::new(
            &topology,
            vec![StepRule::new(StepCondition::Always, vec!["slow".into()])],
        )
        .unwrap();
        let mut positions = ['D', 'A'];
        stepping.advance(&topology, &mut positions).unwrap();
        assert_eq!(positions, ['A', 'A']);
    }

    #[test]
    fn stepping_rejects_unknown_slots_and_fixed_targets() {
        let topology = stepping_topology();
        assert_eq!(
            Stepping::new(
                &topology,
                vec![StepRule::new(StepCondition::Always, vec!["ghost".into()])],
            ),
            Err(ModelError::UnknownStepSlot("ghost".into()))
        );
        assert_eq!(
            Stepping::new(
                &topology,
                vec![StepRule::new(
                    StepCondition::AtTurnover("ghost".into()),
                    vec!["slow".into()],
                )],
            ),
            Err(ModelError::UnknownStepSlot("ghost".into()))
        );

        let alphabet = Alphabet::new(vec!['A', 'B']).unwrap();
        let wheel = identity_wiring(&alphabet, "wheel");
        let fixed = MachineTopology::new(
            alphabet,
            vec![wheel],
            vec![Slot::new(
                "entry",
                "wheel",
                SlotRole::Rotor,
                Movement::Fixed,
                'A',
                'A',
            )],
        )
        .unwrap();
        assert_eq!(
            Stepping::new(
                &fixed,
                vec![StepRule::new(StepCondition::Always, vec!["entry".into()])],
            ),
            Err(ModelError::NonMovableStepTarget("entry".into()))
        );
    }

    #[test]
    fn stepping_rejects_malformed_groups_and_unknown_position_symbols() {
        let topology = stepping_topology();
        assert_eq!(
            Stepping::new(
                &topology,
                vec![StepRule::new(StepCondition::All(vec![]), vec![])],
            ),
            Err(ModelError::EmptyStepConditionGroup)
        );
        assert_eq!(
            Stepping::new(
                &topology,
                vec![StepRule::new(StepCondition::Any(vec![]), vec![])],
            ),
            Err(ModelError::EmptyStepConditionGroup)
        );
        assert_eq!(
            Stepping::new(
                &topology,
                vec![StepRule::new(
                    StepCondition::AtPosition {
                        slot: "slow".into(),
                        symbol: 'Z',
                    },
                    vec![],
                )],
            ),
            Err(ModelError::UnknownSymbol('Z'))
        );
    }

    #[test]
    fn stepping_enforces_grammar_limits() {
        let topology = stepping_topology();
        let rules: Vec<_> = (0..=MAX_STEP_RULES)
            .map(|_| StepRule::new(StepCondition::Always, vec!["slow".into()]))
            .collect();
        assert_eq!(
            Stepping::new(&topology, rules),
            Err(ModelError::TooManyStepRules {
                max: MAX_STEP_RULES
            })
        );

        let mut nested = StepCondition::Always;
        for _ in 0..=MAX_STEP_CONDITION_DEPTH {
            nested = StepCondition::Not(Box::new(nested));
        }
        assert_eq!(
            Stepping::new(&topology, vec![StepRule::new(nested, vec![])]),
            Err(ModelError::StepConditionTooDeep {
                max: MAX_STEP_CONDITION_DEPTH
            })
        );

        let wide = StepCondition::All(
            (0..=MAX_STEP_CONDITION_NODES)
                .map(|_| StepCondition::Always)
                .collect(),
        );
        assert_eq!(
            Stepping::new(&topology, vec![StepRule::new(wide, vec![])]),
            Err(ModelError::TooManyStepConditionNodes {
                max: MAX_STEP_CONDITION_NODES
            })
        );
    }

    #[test]
    fn stepping_enforces_the_distinct_target_budget() {
        let alphabet = Alphabet::new(vec!['A', 'B']).unwrap();
        let wheel = identity_wiring(&alphabet, "wheel");
        let slots: Vec<_> = (0..=MAX_STEP_TARGETS)
            .map(|index| {
                Slot::new(
                    format!("s{index}"),
                    "wheel",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                )
            })
            .collect();
        let topology = MachineTopology::new(alphabet, vec![wheel], slots).unwrap();
        let advance: Vec<_> = (0..=MAX_STEP_TARGETS)
            .map(|index| format!("s{index}"))
            .collect();
        assert_eq!(
            Stepping::new(
                &topology,
                vec![StepRule::new(StepCondition::Always, advance)],
            ),
            Err(ModelError::TooManyStepTargets {
                max: MAX_STEP_TARGETS
            })
        );
    }

    #[test]
    fn stepping_rejects_position_slices_that_do_not_match_the_topology() {
        let topology = stepping_topology();
        let stepping = Stepping::none();
        assert_eq!(
            stepping.plan(&topology, &['A']),
            Err(ModelError::PositionCountMismatch {
                expected: 2,
                actual: 1
            })
        );
    }
}
