//! Stateful electrical traversal engine.
//!
//! [`Engine`] owns a validated [`MachineTopology`], its [`Stepping`] rule set, its
//! [`Plugboard`], and the current displayed position of every slot. It performs the
//! *electrical* traversal described in `docs/protocol.md` §3.2, applying the stepping
//! plan once before each symbol and mapping every symbol through the plugboard at both
//! ends of the traversal.
//!
//! The reflector is optional. When present it is the leftmost slot and makes the
//! traversal reciprocal, so encrypt and decrypt produce the same result. Without a
//! reflector the traversal is directional: encrypt walks every slot right-to-left with
//! forward mappings, decrypt walks every slot left-to-right with reverse mappings.

use crate::{MachineTopology, ModelError, Plugboard, SlotRole, Stepping};

/// The electrical direction of a [`Engine::transform`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Encrypt: without a reflector, traverse every slot rightmost-to-leftmost.
    Encrypt,
    /// Decrypt: without a reflector, traverse every slot leftmost-to-rightmost.
    Decrypt,
}

/// A validated machine plus the mutable state needed to transform text.
///
/// The displayed positions are held in physical left-to-right order, one symbol per
/// slot. Stepping mutates these positions; ring settings never do.
///
/// Construction checks the stepping/topology binding. Both are owned, private, and
/// remain immutable afterward, so per-symbol stepping can skip that binding comparison
/// while retaining all other planning and advancement checks. Construction also
/// resolves every slot's wheel and ring to indices once, so traversal works on
/// alphabet indices without wheel-name lookups or symbol conversions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Engine {
    topology: MachineTopology,
    stepping: Stepping,
    plugboard: Plugboard,
    positions: Vec<char>,
    slots: Vec<ResolvedSlot>,
    has_reflector: bool,
}

/// One slot's wheel (index into the topology's wheels) and ring (alphabet index).
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedSlot {
    wheel: usize,
    ring: usize,
}

#[cfg(test)]
thread_local! {
    pub(crate) static ROW_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Engine {
    /// Builds an engine over an already validated machine.
    ///
    /// Rejects a plugboard bound to a differently ordered alphabet with
    /// [`ModelError::PlugboardAlphabetMismatch`]. It also evaluates the initial step plan
    /// against the topology, so a [`Stepping`] rule set built for another topology fails
    /// closed with [`ModelError::SteppingTopologyMismatch`]. Initial displayed positions
    /// are taken from each [`Slot::position`].
    pub fn new(
        topology: MachineTopology,
        stepping: Stepping,
        plugboard: Plugboard,
    ) -> Result<Self, ModelError> {
        if plugboard.alphabet() != topology.alphabet() {
            return Err(ModelError::PlugboardAlphabetMismatch);
        }
        let positions: Vec<char> = topology
            .slots()
            .iter()
            .map(|slot| slot.position())
            .collect();
        // Fail closed if the rule set is bound to a different topology.
        stepping.plan(&topology, &positions)?;
        let slots = topology
            .slots()
            .iter()
            .map(|slot| {
                let wheel = *topology
                    .wheel_indices
                    .get(slot.wheel())
                    .ok_or_else(|| ModelError::UnknownWheel(slot.wheel().to_string()))?;
                let ring = topology
                    .alphabet()
                    .index_of(slot.ring())
                    .ok_or(ModelError::UnknownSymbol(slot.ring()))?;
                Ok(ResolvedSlot { wheel, ring })
            })
            .collect::<Result<Vec<_>, ModelError>>()?;
        let has_reflector = topology
            .slots()
            .first()
            .is_some_and(|slot| slot.role() == SlotRole::Reflector);
        Ok(Self {
            topology,
            stepping,
            plugboard,
            positions,
            slots,
            has_reflector,
        })
    }

    /// The current displayed position of every slot in physical left-to-right order.
    pub fn positions(&self) -> &[char] {
        &self.positions
    }

    /// Transforms `text` one symbol at a time.
    ///
    /// The whole text is validated first: an out-of-alphabet symbol is rejected with
    /// [`ModelError::UnknownSymbol`] before any state is mutated. Then, for each
    /// character, the configured stepping rules are applied once and exactly one
    /// electrical traversal is performed. Output symbols are concatenated in input
    /// order.
    pub fn transform(&mut self, text: &str, direction: Direction) -> Result<String, ModelError> {
        if let Some(symbol) = text
            .chars()
            .find(|symbol| self.topology.alphabet().index_of(*symbol).is_none())
        {
            return Err(ModelError::UnknownSymbol(symbol));
        }
        let mut offsets = vec![0; self.slots.len()];
        let mut output = String::with_capacity(text.len());
        for symbol in text.chars() {
            self.step(&mut offsets)?;
            let alphabet = self.topology.alphabet();
            let input = alphabet
                .index_of(symbol)
                .ok_or(ModelError::UnknownSymbol(symbol))?;
            let mapping = &self.plugboard.mapping;
            let signal = mapping[self.scramble(&offsets, mapping[input], direction)];
            output.push(alphabet.symbols[signal]);
        }
        Ok(output)
    }

    /// Builds board-independent rows of alphabet indices, stepping exactly once before
    /// each row.
    pub(crate) fn scrambler_rows(
        &mut self,
        length: usize,
        direction: Direction,
        rows: &mut Vec<u32>,
    ) -> Result<(), ModelError> {
        #[cfg(test)]
        ROW_BUILDS.with(|count| count.set(count.get() + 1));
        let size = self.topology.alphabet().len();
        let mut offsets = vec![0; self.slots.len()];
        for _ in 0..length {
            self.step(&mut offsets)?;
            for input in 0..size {
                let output = self.scramble(&offsets, input, direction);
                rows.push(u32::try_from(output).map_err(|_| {
                    ModelError::UnknownSymbol(self.topology.alphabet().symbols[output])
                })?);
            }
        }
        Ok(())
    }

    /// Applies one keypress of stepping, then refreshes each slot's electrical offset
    /// (displayed position minus ring, modulo the alphabet size).
    fn step(&mut self, offsets: &mut [usize]) -> Result<(), ModelError> {
        self.stepping
            .advance_prevalidated(&self.topology, &mut self.positions)?;
        let alphabet = self.topology.alphabet();
        let size = alphabet.len();
        for ((offset, slot), &symbol) in offsets.iter_mut().zip(&self.slots).zip(&self.positions) {
            let position = alphabet
                .index_of(symbol)
                .ok_or(ModelError::UnknownSymbol(symbol))?;
            *offset = if position >= slot.ring {
                position - slot.ring
            } else {
                size - (slot.ring - position)
            };
        }
        Ok(())
    }

    /// Traverses the scrambler (every slot, without the plugboard) on alphabet indices.
    fn scramble(&self, offsets: &[usize], mut signal: usize, direction: Direction) -> usize {
        let count = self.slots.len();
        if self.has_reflector {
            // Forward from the rightmost rotor up to (but excluding) the reflector.
            for index in (1..count).rev() {
                signal = self.map_slot(offsets, index, signal, true);
            }
            // The reflector is traversed exactly once with its own position and ring.
            signal = self.map_slot(offsets, 0, signal, true);
            // Reverse from the leftmost rotor back down to the rightmost.
            for index in 1..count {
                signal = self.map_slot(offsets, index, signal, false);
            }
        } else {
            match direction {
                Direction::Encrypt => {
                    for index in (0..count).rev() {
                        signal = self.map_slot(offsets, index, signal, true);
                    }
                }
                Direction::Decrypt => {
                    for index in 0..count {
                        signal = self.map_slot(offsets, index, signal, false);
                    }
                }
            }
        }
        signal
    }

    /// Maps an alphabet index through one slot's wheel in the requested direction.
    fn map_slot(&self, offsets: &[usize], index: usize, signal: usize, forward: bool) -> usize {
        let wheel = &self.topology.wheels[self.slots[index].wheel];
        let table = if forward {
            &wheel.forward
        } else {
            &wheel.reverse
        };
        let size = table.len();
        let offset = offsets[index];
        let shifted = if signal >= size - offset {
            signal - (size - offset)
        } else {
            signal + offset
        };
        let output = table[shifted];
        if output < offset {
            size - (offset - output)
        } else {
            output - offset
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Alphabet, Direction, Engine, MachineTopology, ModelError, Movement, Plugboard, Slot,
        SlotRole, StepCondition, StepRule, Stepping, Wiring,
    };

    fn four_symbol_alphabet() -> Alphabet {
        Alphabet::new(vec!['A', 'B', 'C', 'D']).unwrap()
    }

    fn identity_plugboard(alphabet: &Alphabet) -> Plugboard {
        Plugboard::identity(alphabet)
    }

    #[test]
    fn v1_reflector_is_a_reciprocal_involution() {
        let alphabet = four_symbol_alphabet();
        let rotor = Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap();
        let reflector = Wiring::new("ukw", &alphabet, &['B', 'A', 'D', 'C'], &[]).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![reflector, rotor],
            vec![
                Slot::new("ukw", "ukw", SlotRole::Reflector, Movement::Fixed, 'A', 'A'),
                Slot::new("r1", "r", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
            ],
        )
        .unwrap();
        let plugboard = identity_plugboard(&alphabet);

        let mut engine =
            Engine::new(topology.clone(), Stepping::none(), plugboard.clone()).unwrap();
        assert_eq!(
            engine.transform("ABCD", Direction::Encrypt).unwrap(),
            "DCBA"
        );
        assert_eq!(
            engine.transform("DCBA", Direction::Encrypt).unwrap(),
            "ABCD"
        );

        // A fresh engine proves encrypt and decrypt are the same reciprocal traversal.
        let mut fresh = Engine::new(topology, Stepping::none(), plugboard).unwrap();
        assert_eq!(fresh.transform("ABCD", Direction::Decrypt).unwrap(), "DCBA");
    }

    #[test]
    fn v2_without_reflector_direction_matters() {
        let alphabet = four_symbol_alphabet();
        let rotor = Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![rotor],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        let plugboard = identity_plugboard(&alphabet);

        let mut engine =
            Engine::new(topology.clone(), Stepping::none(), plugboard.clone()).unwrap();
        assert_eq!(
            engine.transform("ABCD", Direction::Encrypt).unwrap(),
            "BCDA"
        );

        let mut fresh = Engine::new(topology, Stepping::none(), plugboard).unwrap();
        assert_eq!(fresh.transform("BCDA", Direction::Decrypt).unwrap(), "ABCD");

        let encrypt = Engine::new(
            MachineTopology::new(
                alphabet.clone(),
                vec![Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap()],
                vec![Slot::new(
                    "r1",
                    "r",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                )],
            )
            .unwrap(),
            Stepping::none(),
            identity_plugboard(&alphabet),
        )
        .unwrap()
        .transform("ABCD", Direction::Encrypt)
        .unwrap();
        let decrypt = Engine::new(
            MachineTopology::new(
                alphabet.clone(),
                vec![Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap()],
                vec![Slot::new(
                    "r1",
                    "r",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'A',
                    'A',
                )],
            )
            .unwrap(),
            Stepping::none(),
            identity_plugboard(&alphabet),
        )
        .unwrap()
        .transform("ABCD", Direction::Decrypt)
        .unwrap();
        assert_ne!(encrypt, decrypt);
    }

    #[test]
    fn v3_ring_and_position_offsets_change_the_mapping() {
        let alphabet = four_symbol_alphabet();
        let rotor = Wiring::new("r", &alphabet, &['B', 'A', 'D', 'C'], &[]).unwrap();

        let at_b = MachineTopology::new(
            alphabet.clone(),
            vec![rotor.clone()],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'B',
                'A',
            )],
        )
        .unwrap();
        let mut engine =
            Engine::new(at_b, Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(engine.transform("A", Direction::Encrypt).unwrap(), "D");

        let at_a = MachineTopology::new(
            alphabet.clone(),
            vec![rotor],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        let mut engine =
            Engine::new(at_a, Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(engine.transform("A", Direction::Encrypt).unwrap(), "B");
    }

    #[test]
    fn v4_plugboard_is_applied_at_both_ends() {
        let alphabet = four_symbol_alphabet();
        let rotor = Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![rotor],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        let plugboard = Plugboard::new(&alphabet, &[('A', 'B')]).unwrap();

        let mut engine =
            Engine::new(topology.clone(), Stepping::none(), plugboard.clone()).unwrap();
        assert_eq!(
            engine.transform("ABCD", Direction::Encrypt).unwrap(),
            "CADB"
        );

        let mut fresh = Engine::new(topology, Stepping::none(), plugboard).unwrap();
        assert_eq!(fresh.transform("ABCD", Direction::Decrypt).unwrap(), "BDAC");
    }

    #[test]
    fn v5_stepping_is_applied_before_each_symbol() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let rotor = Wiring::new("r", &alphabet, &['B', 'A', 'C'], &[]).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![rotor],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        let stepping = Stepping::new(
            &topology,
            vec![StepRule::new(StepCondition::Always, vec!["r1".into()])],
        )
        .unwrap();

        let mut engine =
            Engine::new(topology.clone(), stepping, identity_plugboard(&alphabet)).unwrap();
        assert_eq!(engine.transform("AA", Direction::Encrypt).unwrap(), "CA");
        assert_eq!(engine.positions(), ['C'].as_slice());

        let mut plain =
            Engine::new(topology, Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(plain.transform("AA", Direction::Encrypt).unwrap(), "BB");
    }

    #[test]
    fn new_rejects_a_plugboard_bound_to_a_different_alphabet_order() {
        let alphabet = four_symbol_alphabet();
        let other = Alphabet::new(vec!['B', 'A', 'C', 'D']).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap()],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();

        assert_eq!(
            Engine::new(topology, Stepping::none(), Plugboard::identity(&other)).err(),
            Some(ModelError::PlugboardAlphabetMismatch)
        );
    }

    #[test]
    fn new_rejects_stepping_bound_to_a_different_topology() {
        let alphabet = four_symbol_alphabet();
        let rotor = Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap();
        let build = |position: char| {
            MachineTopology::new(
                alphabet.clone(),
                vec![rotor.clone()],
                vec![Slot::new(
                    "r1",
                    "r",
                    SlotRole::Rotor,
                    Movement::Movable,
                    position,
                    'A',
                )],
            )
            .unwrap()
        };
        let bound = build('A');
        let other = build('B');
        let stepping = Stepping::new(
            &bound,
            vec![StepRule::new(StepCondition::Always, vec!["r1".into()])],
        )
        .unwrap();

        let wrong_alphabet = Alphabet::new(vec!['B', 'A', 'C', 'D']).unwrap();
        assert_eq!(
            Engine::new(
                other.clone(),
                stepping.clone(),
                identity_plugboard(&wrong_alphabet),
            )
            .err(),
            Some(ModelError::PlugboardAlphabetMismatch)
        );
        assert_eq!(
            Engine::new(other, stepping, identity_plugboard(&alphabet)).err(),
            Some(ModelError::SteppingTopologyMismatch)
        );
    }

    #[test]
    fn split_transforms_match_concatenation_across_turnover_and_wrap() {
        let alphabet = four_symbol_alphabet();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![
                Wiring::new("slow", &alphabet, &['B', 'A', 'D', 'C'], &[]).unwrap(),
                Wiring::new("fast", &alphabet, &['A', 'C', 'D', 'B'], &['D']).unwrap(),
            ],
            vec![
                Slot::new("slow", "slow", SlotRole::Rotor, Movement::Movable, 'C', 'B'),
                Slot::new("fast", "fast", SlotRole::Rotor, Movement::Movable, 'C', 'A'),
            ],
        )
        .unwrap();
        let stepping = Stepping::new(
            &topology,
            vec![
                StepRule::new(StepCondition::Always, vec!["fast".into()]),
                StepRule::new(
                    StepCondition::AtTurnover("fast".into()),
                    vec!["slow".into(), "fast".into()],
                ),
            ],
        )
        .unwrap();
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            let mut whole = Engine::new(
                topology.clone(),
                stepping.clone(),
                identity_plugboard(&alphabet),
            )
            .unwrap();
            let mut split = whole.clone();
            let expected = whole.transform("ABCDAB", direction).unwrap();
            let mut actual = split.transform("A", direction).unwrap();
            assert_eq!(split.positions(), ['C', 'D']);
            actual.push_str(&split.transform("B", direction).unwrap());
            assert_eq!(split.positions(), ['D', 'A']);
            actual.push_str(&split.transform("", direction).unwrap());
            actual.push_str(&split.transform("CDAB", direction).unwrap());
            assert_eq!(actual, expected);
            assert_eq!(split.positions(), whole.positions());
            assert_eq!(split.positions(), ['A', 'A']);
        }
    }

    #[test]
    fn transform_rejects_symbols_outside_the_alphabet_without_panicking() {
        let alphabet = four_symbol_alphabet();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap()],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        let mut engine =
            Engine::new(topology, Stepping::none(), identity_plugboard(&alphabet)).unwrap();

        assert_eq!(
            engine.transform("AZ", Direction::Encrypt).err(),
            Some(ModelError::UnknownSymbol('Z'))
        );
    }

    #[test]
    fn transform_validates_the_whole_text_before_mutating_positions() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![Wiring::new("r", &alphabet, &['B', 'A', 'C'], &[]).unwrap()],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        let stepping = Stepping::new(
            &topology,
            vec![StepRule::new(StepCondition::Always, vec!["r1".into()])],
        )
        .unwrap();
        let mut engine = Engine::new(topology, stepping, identity_plugboard(&alphabet)).unwrap();

        assert_eq!(
            engine.transform("AZ", Direction::Encrypt).err(),
            Some(ModelError::UnknownSymbol('Z'))
        );
        // The invalid character is rejected before any stepping mutates the machine:
        // a per-symbol check would have advanced `r1` from 'A' to 'B' on the 'A'.
        assert_eq!(engine.positions(), ['A'].as_slice());
    }

    #[test]
    fn fixed_non_reflector_slots_participate_in_traversal() {
        let alphabet = four_symbol_alphabet();
        let entry = Wiring::new("entry", &alphabet, &['B', 'A', 'D', 'C'], &[]).unwrap();
        let rotor = Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![entry, rotor],
            vec![
                Slot::new("entry", "entry", SlotRole::Rotor, Movement::Fixed, 'A', 'A'),
                Slot::new("r1", "r", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
            ],
        )
        .unwrap();
        let mut engine =
            Engine::new(topology, Stepping::none(), identity_plugboard(&alphabet)).unwrap();

        // If the fixed entry wheel were skipped, "ABCD" would encrypt to "BCDA".
        assert_eq!(
            engine.transform("ABCD", Direction::Encrypt).unwrap(),
            "ADCB"
        );
    }

    #[test]
    fn v6_multiple_rotors_use_right_to_left_forward_order() {
        let alphabet = four_symbol_alphabet();
        let ukw = Wiring::new("ukw", &alphabet, &['B', 'A', 'D', 'C'], &[]).unwrap();
        let left = Wiring::new("left", &alphabet, &['A', 'B', 'D', 'C'], &[]).unwrap();
        let right = Wiring::new("right", &alphabet, &['A', 'B', 'D', 'C'], &[]).unwrap();
        // Identical rotor wiring isolates electrical order as the only variable: a wrong
        // left-to-right forward pass yields "DCBA" instead of "CDAB".
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![ukw, left, right],
            vec![
                Slot::new("ukw", "ukw", SlotRole::Reflector, Movement::Fixed, 'A', 'A'),
                Slot::new("left", "left", SlotRole::Rotor, Movement::Movable, 'C', 'A'),
                Slot::new(
                    "right",
                    "right",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'B',
                    'A',
                ),
            ],
        )
        .unwrap();
        let mut engine =
            Engine::new(topology, Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(
            engine.transform("ABCD", Direction::Encrypt).unwrap(),
            "CDAB"
        );
    }

    #[test]
    fn v7_multiple_rotors_without_reflector_are_directional() {
        let alphabet = four_symbol_alphabet();
        let build = || {
            MachineTopology::new(
                alphabet.clone(),
                vec![
                    Wiring::new("left", &alphabet, &['A', 'B', 'D', 'C'], &[]).unwrap(),
                    Wiring::new("right", &alphabet, &['A', 'B', 'D', 'C'], &[]).unwrap(),
                ],
                vec![
                    Slot::new("left", "left", SlotRole::Rotor, Movement::Movable, 'C', 'A'),
                    Slot::new(
                        "right",
                        "right",
                        SlotRole::Rotor,
                        Movement::Movable,
                        'B',
                        'A',
                    ),
                ],
            )
            .unwrap()
        };

        let mut encrypt =
            Engine::new(build(), Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        let cipher = encrypt.transform("ABCD", Direction::Encrypt).unwrap();
        assert_eq!(cipher, "BCAD");

        let mut decrypt =
            Engine::new(build(), Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(
            decrypt.transform("ABCD", Direction::Decrypt).unwrap(),
            "CABD"
        );

        let mut round_trip =
            Engine::new(build(), Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(
            round_trip.transform(&cipher, Direction::Decrypt).unwrap(),
            "ABCD"
        );
    }

    #[test]
    fn v8_reflector_uses_its_own_position_and_ring() {
        let alphabet = four_symbol_alphabet();
        let rotor = Wiring::new("r", &alphabet, &['B', 'C', 'D', 'A'], &[]).unwrap();
        let reflector = Wiring::new("ukw", &alphabet, &['B', 'A', 'D', 'C'], &[]).unwrap();
        let build = |reflector_position: char| {
            MachineTopology::new(
                alphabet.clone(),
                vec![reflector.clone(), rotor.clone()],
                vec![
                    Slot::new(
                        "ukw",
                        "ukw",
                        SlotRole::Reflector,
                        Movement::Fixed,
                        reflector_position,
                        'A',
                    ),
                    Slot::new("r1", "r", SlotRole::Rotor, Movement::Movable, 'A', 'A'),
                ],
            )
            .unwrap()
        };

        let mut at_a =
            Engine::new(build('A'), Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(at_a.transform("ABCD", Direction::Encrypt).unwrap(), "DCBA");

        // Shifting only the reflector position to 'B' must change the mapping.
        let mut at_b =
            Engine::new(build('B'), Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(at_b.transform("ABCD", Direction::Encrypt).unwrap(), "BADC");
    }

    #[test]
    fn v9_stepping_is_applied_in_both_directions() {
        let alphabet = Alphabet::new(vec!['A', 'B', 'C']).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![Wiring::new("r", &alphabet, &['B', 'A', 'C'], &[]).unwrap()],
            vec![Slot::new(
                "r1",
                "r",
                SlotRole::Rotor,
                Movement::Movable,
                'A',
                'A',
            )],
        )
        .unwrap();
        let stepping = Stepping::new(
            &topology,
            vec![StepRule::new(StepCondition::Always, vec!["r1".into()])],
        )
        .unwrap();

        let mut with_steps =
            Engine::new(topology.clone(), stepping, identity_plugboard(&alphabet)).unwrap();
        assert_eq!(
            with_steps.transform("AA", Direction::Decrypt).unwrap(),
            "CA"
        );
        assert_eq!(with_steps.positions(), ['C'].as_slice());

        let mut without_steps =
            Engine::new(topology, Stepping::none(), identity_plugboard(&alphabet)).unwrap();
        assert_eq!(
            without_steps.transform("AA", Direction::Decrypt).unwrap(),
            "BB"
        );
    }

    /// Deterministic xorshift64 generator for differential machines.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }

        fn permutation(&mut self, symbols: &[char]) -> Vec<char> {
            let mut out = symbols.to_vec();
            for index in (1..out.len()).rev() {
                out.swap(index, self.below(index + 1));
            }
            out
        }

        fn symbol(&mut self, symbols: &[char]) -> char {
            symbols[self.below(symbols.len())]
        }
    }

    fn random_machine(rng: &mut Rng, symbols: &[char]) -> (MachineTopology, Stepping, Plugboard) {
        let alphabet = Alphabet::new(symbols.to_vec()).unwrap();
        let mut wheels = Vec::new();
        let mut slots = Vec::new();
        if rng.below(2) == 0 {
            // Involution with possible fixed points: pair a shuffled prefix.
            let order = rng.permutation(symbols);
            let mut wiring = symbols.to_vec();
            let pairs = rng.below(symbols.len() / 2 + 1);
            for pair in order[..2 * pairs].chunks(2) {
                let left = alphabet.index_of(pair[0]).unwrap();
                let right = alphabet.index_of(pair[1]).unwrap();
                wiring[left] = pair[1];
                wiring[right] = pair[0];
            }
            wheels.push(Wiring::new("ukw", &alphabet, &wiring, &[]).unwrap());
            slots.push(Slot::new(
                "ukw",
                "ukw",
                SlotRole::Reflector,
                Movement::Fixed,
                rng.symbol(symbols),
                rng.symbol(symbols),
            ));
        }
        let rotors = 1 + rng.below(4);
        for index in 0..rotors {
            let name = format!("w{index}");
            let turnovers: Vec<char> = symbols
                .iter()
                .copied()
                .filter(|_| rng.below(4) == 0)
                .collect();
            wheels.push(
                Wiring::new(&name, &alphabet, &rng.permutation(symbols), &turnovers).unwrap(),
            );
            slots.push(Slot::new(
                format!("s{index}"),
                name,
                SlotRole::Rotor,
                Movement::Movable,
                rng.symbol(symbols),
                rng.symbol(symbols),
            ));
        }
        // Wheels are declared in reverse so a wheel's index differs from its slot's.
        wheels.reverse();
        let topology = MachineTopology::new(alphabet.clone(), wheels, slots).unwrap();
        let right = format!("s{}", rotors - 1);
        let left = "s0".to_string();
        let stepping = Stepping::new(
            &topology,
            vec![
                StepRule::new(StepCondition::Always, vec![right.clone()]),
                StepRule::new(
                    StepCondition::Any(vec![
                        StepCondition::AtTurnover(right.clone()),
                        StepCondition::Not(Box::new(StepCondition::AtPosition {
                            slot: left.clone(),
                            symbol: rng.symbol(symbols),
                        })),
                    ]),
                    vec![left],
                ),
            ],
        )
        .unwrap();
        let order = rng.permutation(symbols);
        let pairs: Vec<(char, char)> = order[..2 * rng.below(symbols.len() / 2 + 1)]
            .chunks(2)
            .map(|pair| (pair[0], pair[1]))
            .collect();
        let plugboard = Plugboard::new(&alphabet, &pairs).unwrap();
        (topology, stepping, plugboard)
    }

    /// Char-level reference traversal through the public wheel API.
    fn oracle_scramble(
        topology: &MachineTopology,
        positions: &[char],
        mut signal: char,
        direction: Direction,
    ) -> char {
        let slots = topology.slots();
        let pass = |signal: char, index: usize, forward: bool| {
            let slot = &slots[index];
            let wheel = topology.wheel(slot.wheel()).unwrap();
            if forward {
                wheel.forward(signal, positions[index], slot.ring())
            } else {
                wheel.reverse(signal, positions[index], slot.ring())
            }
            .unwrap()
        };
        if slots[0].role() == SlotRole::Reflector {
            for index in (1..slots.len()).rev() {
                signal = pass(signal, index, true);
            }
            signal = pass(signal, 0, true);
            for index in 1..slots.len() {
                signal = pass(signal, index, false);
            }
        } else if direction == Direction::Encrypt {
            for index in (0..slots.len()).rev() {
                signal = pass(signal, index, true);
            }
        } else {
            for index in 0..slots.len() {
                signal = pass(signal, index, false);
            }
        }
        signal
    }

    const DIFFERENTIAL_ALPHABETS: [&str; 3] = ["ABCD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "aβγδéZzñ"];

    #[test]
    fn indexed_traversal_matches_the_char_oracle() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for symbols in DIFFERENTIAL_ALPHABETS {
            let symbols: Vec<char> = symbols.chars().collect();
            for _ in 0..40 {
                let (topology, stepping, plugboard) = random_machine(&mut rng, &symbols);
                let text: String = (0..3 * symbols.len() + 7)
                    .map(|_| rng.symbol(&symbols))
                    .collect();
                for direction in [Direction::Encrypt, Direction::Decrypt] {
                    let mut positions: Vec<char> =
                        topology.slots().iter().map(Slot::position).collect();
                    let mut expected_text = String::new();
                    let mut expected_rows = Vec::new();
                    for symbol in text.chars() {
                        stepping.advance(&topology, &mut positions).unwrap();
                        let signal = plugboard.map(symbol).unwrap();
                        let signal = oracle_scramble(&topology, &positions, signal, direction);
                        expected_text.push(plugboard.map(signal).unwrap());
                        for &input in &symbols {
                            let output = oracle_scramble(&topology, &positions, input, direction);
                            expected_rows
                                .push(topology.alphabet().index_of(output).unwrap() as u32);
                        }
                    }

                    let engine =
                        Engine::new(topology.clone(), stepping.clone(), plugboard.clone()).unwrap();
                    let mut transformed = engine.clone();
                    assert_eq!(
                        transformed.transform(&text, direction).unwrap(),
                        expected_text
                    );
                    assert_eq!(transformed.positions(), positions.as_slice());
                    let mut rows_engine = engine;
                    let mut rows = Vec::new();
                    rows_engine
                        .scrambler_rows(text.chars().count(), direction, &mut rows)
                        .unwrap();
                    assert_eq!(rows, expected_rows);
                    assert_eq!(rows_engine.positions(), positions.as_slice());
                }
            }
        }
    }

    #[test]
    fn traversal_resolves_wheels_once_and_symbols_once_per_keypress() {
        let symbols: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let alphabet = Alphabet::new(symbols.clone()).unwrap();
        let wheel = |name: &str| Wiring::new(name, &alphabet, &symbols, &[]).unwrap();
        let topology = MachineTopology::new(
            alphabet.clone(),
            vec![wheel("ukw"), wheel("left"), wheel("right")],
            vec![
                Slot::new("ukw", "ukw", SlotRole::Reflector, Movement::Fixed, 'A', 'A'),
                Slot::new("left", "left", SlotRole::Rotor, Movement::Movable, 'C', 'B'),
                Slot::new(
                    "right",
                    "right",
                    SlotRole::Rotor,
                    Movement::Movable,
                    'Y',
                    'D',
                ),
            ],
        )
        .unwrap();
        // Stepping without turnover conditions: only the traversal is measured here.
        let stepping = Stepping::new(
            &topology,
            vec![
                StepRule::new(StepCondition::Always, vec!["right".into()]),
                StepRule::new(
                    StepCondition::AtPosition {
                        slot: "right".into(),
                        symbol: 'Z',
                    },
                    vec!["left".into()],
                ),
            ],
        )
        .unwrap();
        let mut engine = Engine::new(topology, stepping, identity_plugboard(&alphabet)).unwrap();
        let length = 40;
        let slots = 3;
        crate::WHEEL_LOOKUPS.with(|count| count.set(0));
        crate::INDEX_LOOKUPS.with(|count| count.set(0));
        let mut rows = Vec::new();
        engine
            .scrambler_rows(length, Direction::Decrypt, &mut rows)
            .unwrap();
        assert_eq!(rows.len(), length * symbols.len());
        assert_eq!(crate::WHEEL_LOOKUPS.with(|count| count.get()), 0);
        // At most one lookup per slot position and one per stepped slot each keypress.
        assert!(crate::INDEX_LOOKUPS.with(|count| count.get()) <= length * 2 * slots);

        crate::INDEX_LOOKUPS.with(|count| count.set(0));
        let text: String = std::iter::repeat_n('Q', length).collect();
        engine.transform(&text, Direction::Encrypt).unwrap();
        assert_eq!(crate::WHEEL_LOOKUPS.with(|count| count.get()), 0);
        // Plus whole-text validation and one input lookup per symbol.
        assert!(crate::INDEX_LOOKUPS.with(|count| count.get()) <= length * (2 * slots + 2));
    }
}
