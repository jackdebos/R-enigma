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
    use super::{Alphabet, ModelError, Wiring};

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
    fn turnovers_use_displayed_positions_without_ring_adjustment() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let wiring = Wiring::new("rotor", &alphabet, &['A', 'B', 'C'], &['B']).unwrap();
        assert!(wiring.at_turnover('B'));
        assert!(!wiring.at_turnover('A'));
        assert!(!wiring.at_turnover('Z'));
    }
}
