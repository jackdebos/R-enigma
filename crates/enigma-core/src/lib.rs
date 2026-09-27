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

use std::collections::{HashMap, HashSet};
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

        let mut slot_ids = HashSet::with_capacity(slots.len());
        let mut reflector_index = None;
        let mut rotor_count = 0;
        for (index, slot) in slots.iter().enumerate() {
            if slot.id.is_empty() {
                return Err(ModelError::EmptySlotId);
            }
            if !slot_ids.insert(slot.id.as_str()) {
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
        Alphabet, MachineTopology, ModelError, Movement, Plugboard, Slot, SlotRole, Wiring,
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
}
