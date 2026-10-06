//! Private trial-board validation; transformation and scoring are not implemented here.

use crate::{AttackPlugboardDomain, ModelError, Plugboard, ResolvedConfiguration};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TrialBoardError {
    AlphabetBinding,
    FixedFactsBinding,
    OutsideMutable(char),
    TotalCapacity,
    Model(ModelError),
}

/// Accept only mutable guesses, bound to the selected initial scrambler.
/// Fixed facts are compared by mapping; their stored order and orientation stay untouched.
pub(crate) fn validated_trial_board(
    initial: &ResolvedConfiguration,
    domain: &AttackPlugboardDomain,
    mutable: &[(char, char)],
) -> Result<Plugboard, TrialBoardError> {
    let alphabet = initial.topology().alphabet();
    if !domain.matches_alphabet(alphabet) {
        return Err(TrialBoardError::AlphabetBinding);
    }
    // Compare electrical facts, not pair order or orientation. Never normalize inputs.
    let fixed = Plugboard::new(alphabet, domain.fixed_pairs()).map_err(TrialBoardError::Model)?;
    if &fixed != initial.plugboard() {
        return Err(TrialBoardError::FixedFactsBinding);
    }
    let mut pairs = domain.fixed_pairs().to_vec();
    pairs.extend_from_slice(mutable);
    // Existing model validation reports self-pairs, foreign and reused endpoints.
    let board = Plugboard::new(alphabet, &pairs).map_err(TrialBoardError::Model)?;
    for &(a, b) in mutable {
        for symbol in [a, b] {
            if !domain.symbols().contains(&symbol) {
                return Err(TrialBoardError::OutsideMutable(symbol));
            }
        }
    }
    if pairs.len() > domain.max_pairs() {
        return Err(TrialBoardError::TotalCapacity);
    }
    Ok(board)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Alphabet, DefinitionSource, SlotConfiguration, TransformConfiguration};

    fn initial(alphabet: &Alphabet, fixed: &[(char, char)]) -> ResolvedConfiguration {
        let symbols = &alphabet.symbols;
        let source = serde_json::json!({
            "kind": "custom", "value": {
                "alphabet": symbols,
                "wheels": [{"name": "r", "wiring": symbols, "turnovers": []}],
                "slots": [{"id": "r", "role": "rotor", "movement": "fixed", "wheel": "r"}],
                "stepping": {"rules": []}
            }
        });
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        TransformConfiguration::new(
            vec![SlotConfiguration::new("r", "r", symbols[0], symbols[0])],
            fixed.to_vec(),
        )
        .resolve(&definition)
        .unwrap()
    }

    fn alphabet() -> Alphabet {
        Alphabet::new("ABCDEFGH".chars().collect()).unwrap()
    }

    fn domain(
        alphabet: &Alphabet,
        fixed: &[(char, char)],
        symbols: &str,
        cap: usize,
    ) -> AttackPlugboardDomain {
        let source = serde_json::json!({
            "kind": "attack", "symbols": symbols.chars().collect::<Vec<_>>(),
            "max_pairs": cap
        });
        AttackPlugboardDomain::parse_json(alphabet, fixed, &source.to_string()).unwrap()
    }

    fn assert_mapping(board: &Plugboard, expected: &str) {
        let actual: String = "ABCDEFGH".chars().map(|c| board.map(c).unwrap()).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn merges_fixed_facts_without_mutating_any_input() {
        let alphabet = alphabet();
        let fixed = [('A', 'B')];
        let initial = initial(&alphabet, &fixed);
        let domain = domain(&alphabet, &fixed, "CDEF", 3);
        let before_initial = initial.clone();
        let before_domain = domain.clone();
        let mutable = [('C', 'D')];
        let before_mutable = mutable;
        let board = validated_trial_board(&initial, &domain, &mutable).unwrap();
        // AB and CD exchange; unused mutable EF and masked GH remain fixed points.
        assert_mapping(&board, "BADCEFGH");
        assert_eq!(initial, before_initial);
        assert_eq!(domain, before_domain);
        assert_eq!(mutable, before_mutable);
        assert_eq!(domain.fixed_pairs(), &fixed);
    }

    #[test]
    fn fixed_only_and_zero_total_capacity_are_legal() {
        let alphabet = alphabet();
        let fixed = [('A', 'B')];
        let initial_fixed = initial(&alphabet, &fixed);
        let fixed_domain = domain(&alphabet, &fixed, "CD", 1);
        assert_mapping(
            &validated_trial_board(&initial_fixed, &fixed_domain, &[]).unwrap(),
            "BACDEFGH",
        );
        let empty_initial = initial(&alphabet, &[]);
        let zero_domain = domain(&alphabet, &[], "CD", 0);
        assert_mapping(
            &validated_trial_board(&empty_initial, &zero_domain, &[]).unwrap(),
            "ABCDEFGH",
        );
        assert_eq!(
            validated_trial_board(&empty_initial, &zero_domain, &[('C', 'D')]),
            Err(TrialBoardError::TotalCapacity),
        );
    }

    #[test]
    fn capacity_counts_actual_fixed_plus_mutable_pairs() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let domain = domain(&alphabet, &[('A', 'B')], "CDEF", 2);
        assert_mapping(
            &validated_trial_board(&initial, &domain, &[('C', 'D')]).unwrap(),
            "BADCEFGH",
        );
        assert_eq!(
            validated_trial_board(&initial, &domain, &[('C', 'D'), ('E', 'F')]),
            Err(TrialBoardError::TotalCapacity),
        );
    }

    #[test]
    fn rejects_fixed_repetition_reuse_self_overlap_and_foreign_symbols() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let domain = domain(&alphabet, &[('A', 'B')], "CDEF", 3);
        for (pairs, expected) in [
            (vec![('A', 'B')], ModelError::DuplicatePlugboardSymbol('A')),
            (vec![('A', 'C')], ModelError::DuplicatePlugboardSymbol('A')),
            (vec![('C', 'B')], ModelError::DuplicatePlugboardSymbol('B')),
            (vec![('C', 'C')], ModelError::PlugboardSelfPair('C')),
            (
                vec![('C', 'D'), ('D', 'E')],
                ModelError::DuplicatePlugboardSymbol('D'),
            ),
            (vec![('C', 'Z')], ModelError::UnknownSymbol('Z')),
        ] {
            assert_eq!(
                validated_trial_board(&initial, &domain, &pairs),
                Err(TrialBoardError::Model(expected)),
                "trial {pairs:?}",
            );
        }
        for pairs in [[('C', 'G')], [('H', 'D')]] {
            let symbol = if pairs[0].0 == 'H' { 'H' } else { 'G' };
            assert_eq!(
                validated_trial_board(&initial, &domain, &pairs),
                Err(TrialBoardError::OutsideMutable(symbol)),
            );
        }
    }

    #[test]
    fn binding_checks_ordered_alphabet_and_fixed_mapping() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B')]);
        let reversed = Alphabet::new("HGFEDCBA".chars().collect()).unwrap();
        let wrong_order = domain(&reversed, &[('A', 'B')], "CD", 2);
        assert_eq!(
            validated_trial_board(&initial, &wrong_order, &[]),
            Err(TrialBoardError::AlphabetBinding),
        );
        let wrong_fixed = domain(&alphabet, &[('A', 'C')], "DE", 2);
        let missing_fixed = domain(&alphabet, &[], "CD", 1);
        for domain in [wrong_fixed, missing_fixed] {
            assert_eq!(
                validated_trial_board(&initial, &domain, &[]),
                Err(TrialBoardError::FixedFactsBinding),
            );
        }
    }

    #[test]
    fn shuffled_reversed_representations_preserve_fixed_data() {
        let alphabet = alphabet();
        let initial = initial(&alphabet, &[('A', 'B'), ('G', 'H')]);
        let fixed = [('H', 'G'), ('B', 'A')];
        let domain = domain(&alphabet, &fixed, "FEDC", 4);
        for mutable in [[('C', 'D'), ('E', 'F')], [('F', 'E'), ('D', 'C')]] {
            assert_mapping(
                &validated_trial_board(&initial, &domain, &mutable).unwrap(),
                "BADCFEHG",
            );
            assert_eq!(domain.fixed_pairs(), &fixed);
            assert_eq!(initial.topology().alphabet(), &alphabet);
        }
        assert_mapping(initial.plugboard(), "BACDEFHG");
    }
}
