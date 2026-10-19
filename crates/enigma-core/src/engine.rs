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

use crate::{MachineTopology, ModelError, Plugboard, Slot, SlotRole, Stepping};

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
/// while retaining all other planning and advancement checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Engine {
    topology: MachineTopology,
    stepping: Stepping,
    plugboard: Plugboard,
    positions: Vec<char>,
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
        Ok(Self {
            topology,
            stepping,
            plugboard,
            positions,
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
        let mut output = String::with_capacity(text.len());
        for symbol in text.chars() {
            self.stepping
                .advance_prevalidated(&self.topology, &mut self.positions)?;
            output.push(self.traverse(symbol, direction)?);
        }
        Ok(output)
    }

    /// Applies one electrical traversal to a single alphabet symbol.
    fn traverse(&self, symbol: char, direction: Direction) -> Result<char, ModelError> {
        let signal = self
            .plugboard
            .map(symbol)
            .ok_or(ModelError::UnknownSymbol(symbol))?;
        let signal = self.traverse_scrambler(signal, direction)?;
        self.plugboard
            .map(signal)
            .ok_or(ModelError::UnknownSymbol(signal))
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
        for _ in 0..length {
            self.stepping
                .advance_prevalidated(&self.topology, &mut self.positions)?;
            let alphabet = self.topology.alphabet();
            for &symbol in &alphabet.symbols {
                let output = self.traverse_scrambler(symbol, direction)?;
                let index = alphabet
                    .index_of(output)
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or(ModelError::UnknownSymbol(output))?;
                rows.push(index);
            }
        }
        Ok(())
    }

    fn traverse_scrambler(
        &self,
        mut signal: char,
        direction: Direction,
    ) -> Result<char, ModelError> {
        let slots = self.topology.slots();
        let has_reflector = slots
            .first()
            .is_some_and(|slot| slot.role() == SlotRole::Reflector);

        if has_reflector {
            // Forward from the rightmost rotor up to (but excluding) the reflector.
            for index in (1..slots.len()).rev() {
                signal = self.map_slot(slots, index, signal, true)?;
            }
            // The reflector is traversed exactly once with its own position and ring.
            signal = self.map_slot(slots, 0, signal, true)?;
            // Reverse from the leftmost rotor back down to the rightmost.
            for index in 1..slots.len() {
                signal = self.map_slot(slots, index, signal, false)?;
            }
        } else {
            match direction {
                Direction::Encrypt => {
                    for index in (0..slots.len()).rev() {
                        signal = self.map_slot(slots, index, signal, true)?;
                    }
                }
                Direction::Decrypt => {
                    for index in 0..slots.len() {
                        signal = self.map_slot(slots, index, signal, false)?;
                    }
                }
            }
        }

        Ok(signal)
    }

    /// Maps `symbol` through one slot's wheel in the requested electrical direction.
    fn map_slot(
        &self,
        slots: &[Slot],
        index: usize,
        symbol: char,
        forward: bool,
    ) -> Result<char, ModelError> {
        let slot = &slots[index];
        let wheel = self
            .topology
            .wheel(slot.wheel())
            .ok_or_else(|| ModelError::UnknownWheel(slot.wheel().to_string()))?;
        let position = self.positions[index];
        let ring = slot.ring();
        let mapped = if forward {
            wheel.forward(symbol, position, ring)
        } else {
            wheel.reverse(symbol, position, ring)
        };
        mapped.ok_or(ModelError::UnknownSymbol(symbol))
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
}
