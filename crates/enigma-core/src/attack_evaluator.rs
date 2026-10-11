//! Private fresh-state trial evaluation with retained, caller-borrowed scoring models.

use crate::{
    index_of_coincidence, shannon_entropy, AttackPlugboardDomain, BoundResource, Direction, Engine,
    MeasureError, MeasureId, MeasuredScore, ModelError, Plugboard, ResolvedConfiguration,
};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum TrialEvaluationError {
    Board(TrialBoardError),
    Model(ModelError),
    MissingResource(MeasureId),
    IncompatibleResource(MeasureId),
    Measure(MeasureError),
}

impl std::fmt::Display for TrialEvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Board(error) => write!(f, "trial board: {error}"),
            Self::Model(error) => write!(f, "trial model: {error}"),
            Self::Measure(error) => write!(f, "trial measure: {error}"),
            Self::MissingResource(id) => write!(f, "missing trial resource: {id:?}"),
            Self::IncompatibleResource(id) => write!(f, "incompatible trial resource: {id:?}"),
        }
    }
}

impl std::error::Error for TrialEvaluationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Board(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::Measure(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) struct TrialEvaluator<'a> {
    initial: &'a ResolvedConfiguration,
    domain: &'a AttackPlugboardDomain,
    input: &'a str,
    direction: Direction,
    objective: MeasureId,
    resource: Option<&'a BoundResource>,
}

impl<'a> TrialEvaluator<'a> {
    pub(super) fn new(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        input: &'a str,
        direction: Direction,
        objective: MeasureId,
        resource: Option<&'a BoundResource>,
    ) -> Self {
        Self {
            initial,
            domain,
            input,
            direction,
            objective,
            resource,
        }
    }

    pub(super) fn evaluate(
        &self,
        mutable: &[(char, char)],
    ) -> Result<(String, MeasuredScore), TrialEvaluationError> {
        let board = validated_trial_board(self.initial, self.domain, mutable)
            .map_err(TrialEvaluationError::Board)?;
        // Engine::clone preserves positions. Build and discard a local engine instead.
        let mut engine = Engine::new(
            self.initial.topology().clone(),
            self.initial.stepping().clone(),
            board,
        )
        .map_err(TrialEvaluationError::Model)?;
        let plaintext = engine
            .transform(self.input, self.direction)
            .map_err(TrialEvaluationError::Model)?;
        let score = self.measure(&plaintext)?;
        Ok((plaintext, score))
    }

    fn measure(&self, plaintext: &str) -> Result<MeasuredScore, TrialEvaluationError> {
        let alphabet = self.initial.topology().alphabet();
        let incompatible = || TrialEvaluationError::IncompatibleResource(self.objective);
        let score = match (self.objective, self.resource) {
            (MeasureId::Ic, None) => index_of_coincidence(alphabet, plaintext),
            (MeasureId::Entropy, None) => shannon_entropy(alphabet, plaintext),
            (objective, None) if objective.requires_resource() => {
                return Err(TrialEvaluationError::MissingResource(objective));
            }
            (objective, Some(BoundResource::Ngram(model)))
                if objective.order() == Some(model.order()) && model.alphabet() == alphabet =>
            {
                model.score(plaintext)
            }
            (MeasureId::Trie, Some(BoundResource::Trie(model))) if model.alphabet() == alphabet => {
                model.score(plaintext)
            }
            _ => return Err(incompatible()),
        };
        score.map_err(TrialEvaluationError::Measure)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TrialBoardError {
    AlphabetBinding,
    FixedFactsBinding,
    OutsideMutable(char),
    TotalCapacity,
    Model(ModelError),
}

impl std::fmt::Display for TrialBoardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Model(error) => write!(f, "trial board model: {error}"),
            Self::AlphabetBinding => f.write_str("trial board alphabet binding mismatch"),
            Self::FixedFactsBinding => f.write_str("trial board fixed facts mismatch"),
            Self::OutsideMutable(symbol) => write!(f, "symbol outside mutable board: {symbol}"),
            Self::TotalCapacity => f.write_str("trial board capacity exceeded"),
        }
    }
}

impl std::error::Error for TrialBoardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
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

    #[test]
    fn owned_trial_errors_preserve_causal_sources() {
        use std::error::Error;
        let model =
            TrialEvaluationError::Board(TrialBoardError::Model(ModelError::UnknownSymbol('Z')));
        let board = model
            .source()
            .unwrap()
            .downcast_ref::<TrialBoardError>()
            .unwrap();
        assert_eq!(
            board.source().unwrap().downcast_ref::<ModelError>(),
            Some(&ModelError::UnknownSymbol('Z'))
        );
        let direct = TrialEvaluationError::Model(ModelError::EmptyAlphabet);
        assert_eq!(
            direct.source().unwrap().downcast_ref::<ModelError>(),
            Some(&ModelError::EmptyAlphabet)
        );
        let cause = MeasureError::InsufficientSamples {
            required: 2,
            actual: 1,
        };
        let measure = TrialEvaluationError::Measure(cause.clone());
        assert_eq!(
            measure.source().unwrap().downcast_ref::<MeasureError>(),
            Some(&cause)
        );
        assert!(TrialEvaluationError::MissingResource(MeasureId::Trie)
            .source()
            .is_none());
        assert!(TrialBoardError::TotalCapacity.source().is_none());
        assert!(!model.to_string().is_empty());
        assert!(!measure.to_string().is_empty());
    }

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

    fn machine(
        symbols: &str,
        wiring: &str,
        positions: &str,
        stepped: bool,
    ) -> ResolvedConfiguration {
        let slots: Vec<_> = positions.chars().enumerate().map(|(i, _)| {
            serde_json::json!({"id": format!("r{i}"), "role": "rotor", "movement": "movable", "wheel": "r"})
        }).collect();
        let rules = if stepped {
            serde_json::json!([{"when": {"always": true}, "advance": ["r0"]}])
        } else {
            serde_json::json!([])
        };
        let source = serde_json::json!({"kind": "custom", "value": {
            "alphabet": symbols.chars().collect::<Vec<_>>(),
            "wheels": [{"name": "r", "wiring": wiring.chars().collect::<Vec<_>>(), "turnovers": []}],
            "slots": slots, "stepping": {"rules": rules}
        }});
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        TransformConfiguration::new(
            positions
                .chars()
                .enumerate()
                .map(|(i, p)| SlotConfiguration::new(format!("r{i}"), "r", p, 'A'))
                .collect(),
            vec![],
        )
        .resolve(&definition)
        .unwrap()
    }

    fn evaluator<'a>(
        initial: &'a ResolvedConfiguration,
        domain: &'a AttackPlugboardDomain,
        input: &'a str,
    ) -> TrialEvaluator<'a> {
        TrialEvaluator {
            initial,
            domain,
            input,
            direction: Direction::Decrypt,
            objective: MeasureId::Ic,
            resource: None,
        }
    }

    const SINKOV: [MeasureId; 6] = [
        MeasureId::SinkovMonogram,
        MeasureId::SinkovBigram,
        MeasureId::SinkovTrigram,
        MeasureId::SinkovQuadgram,
        MeasureId::SinkovPentagram,
        MeasureId::SinkovHexagram,
    ];

    fn ngram(alphabet: &Alphabet, order: usize) -> BoundResource {
        BoundResource::Ngram(
            crate::NgramModel::new(
                alphabet.clone(),
                order,
                vec![(vec!['A'; order], 3), (vec!['B'; order], 1)],
            )
            .unwrap(),
        )
    }

    fn trie(alphabet: &Alphabet) -> BoundResource {
        BoundResource::Trie(
            crate::TrieModel::new(
                alphabet.clone(),
                vec![(vec!['A'], 2), (vec!['A', 'A'], -1), (vec!['B'], 1)],
            )
            .unwrap(),
        )
    }

    #[test]
    fn independent_direction_and_stepping_oracles() {
        let initial = machine("ABCD", "ABDC", "CB", false);
        let alphabet = initial.topology().alphabet();
        let domain = domain(alphabet, &[], "ABCD", 2);
        let mut trial = evaluator(&initial, &domain, "ABCD");
        assert_eq!(trial.evaluate(&[]).unwrap().0, "CABD");
        trial.direction = Direction::Encrypt;
        assert_eq!(trial.evaluate(&[]).unwrap().0, "BCAD");
        for (stepped, expected) in [(true, "CA"), (false, "BB")] {
            let initial = machine("ABC", "BAC", "A", stepped);
            let domain = super::tests::domain(initial.topology().alphabet(), &[], "ABC", 1);
            let trial = evaluator(&initial, &domain, "AA");
            assert_eq!(trial.evaluate(&[]).unwrap().0, expected);
        }
    }

    #[test]
    fn stepped_trials_and_failures_are_isolated_and_inputs_stay_owned() {
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let input = String::from("AA");
        let pairs = [('A', 'B')];
        let before = (initial.clone(), domain.clone(), input.clone(), pairs);
        let trial = evaluator(&initial, &domain, &input);
        let a = trial.evaluate(&[]).unwrap();
        let b = trial.evaluate(&pairs).unwrap();
        assert_eq!(a.0, "CA");
        assert_eq!(b.0, "AC");
        assert_ne!(a, b);
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        assert_eq!(
            trial.evaluate(&[('A', 'A')]),
            Err(TrialEvaluationError::Board(TrialBoardError::Model(
                ModelError::PlugboardSelfPair('A')
            ))),
        );
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        let foreign = TrialEvaluator {
            input: "AZ",
            ..trial
        };
        assert_eq!(
            foreign.evaluate(&[]),
            Err(TrialEvaluationError::Model(ModelError::UnknownSymbol('Z')))
        );
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        assert_eq!((initial, domain, input, pairs), before);
    }

    #[test]
    fn resource_free_scores_have_independent_nonzero_orientation() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        let mut trial = evaluator(&initial, &domain, "AABB");
        let score = trial.evaluate(&[]).unwrap().1;
        assert_eq!(score.measured().units(), 2 * crate::SCALE / 3);
        assert_eq!(score.ranking(), score.measured());
        trial.objective = MeasureId::Entropy;
        let score = trial.evaluate(&[]).unwrap().1;
        assert_eq!(score.measured().units(), crate::SCALE);
        assert_eq!(score.ranking().units(), -crate::SCALE);
        trial.input = "AAAA";
        assert!(trial.evaluate(&[]).unwrap().1.ranking().units() > score.ranking().units());
        trial.objective = MeasureId::Ic;
        assert!(trial.evaluate(&[]).unwrap().1.ranking().units() > 2 * crate::SCALE / 3);
    }

    #[test]
    fn retained_models_repeat_with_known_nonuniform_scores_for_every_order() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        for (i, objective) in SINKOV.into_iter().enumerate() {
            let resource = ngram(&alphabet, i + 1);
            let mut trial = evaluator(&initial, &domain, "AAAAAAA");
            trial.objective = objective;
            trial.resource = Some(&resource);
            let a = trial.evaluate(&[]).unwrap();
            // ln(3/4) and ln(1/4), independently quantized downward to Q32.
            assert_eq!(a.1.measured().units(), -1_235_585_093);
            assert_eq!(a.1.ranking(), a.1.measured());
            trial.input = "BBBBBBB";
            let b = trial.evaluate(&[]).unwrap();
            assert_eq!(b.1.measured().units(), -5_954_088_944);
            assert!(a.1.ranking().units() > b.1.ranking().units());
            trial.input = "AAAAAAA";
            assert_eq!(trial.evaluate(&[]).unwrap(), a);
        }
        let resource = trie(&alphabet);
        let mut trial = evaluator(&initial, &domain, "AAB");
        trial.objective = MeasureId::Trie;
        trial.resource = Some(&resource);
        let a = trial.evaluate(&[]).unwrap();
        assert_eq!(a.1.measured().units(), 4 * crate::SCALE);
        assert_eq!(a.1.ranking(), a.1.measured());
        trial.input = "BBB";
        assert_eq!(
            trial.evaluate(&[]).unwrap().1.measured().units(),
            3 * crate::SCALE
        );
        trial.input = "AAB";
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
    }

    #[test]
    fn complete_resource_compatibility_matrix_is_typed() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let reversed = Alphabet::new("BA".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        let resources: Vec<_> = (1..=6).map(|order| ngram(&alphabet, order)).collect();
        let trie = trie(&alphabet);
        let wrong_trie = super::tests::trie(&reversed);
        for objective in [MeasureId::Ic, MeasureId::Entropy]
            .into_iter()
            .chain(SINKOV)
            .chain([MeasureId::Trie])
        {
            let mut trial = evaluator(&initial, &domain, "AAAAAAA");
            trial.objective = objective;
            let result = trial.evaluate(&[]);
            if objective.requires_resource() {
                assert_eq!(
                    result,
                    Err(TrialEvaluationError::MissingResource(objective))
                );
            } else {
                assert!(result.is_ok());
            }
            for resource in resources.iter().chain([&trie]) {
                trial.resource = Some(resource);
                let compatible = match resource {
                    BoundResource::Ngram(model) => objective.order() == Some(model.order()),
                    BoundResource::Trie(_) => objective == MeasureId::Trie,
                };
                if compatible {
                    assert!(trial.evaluate(&[]).is_ok());
                } else {
                    assert_eq!(
                        trial.evaluate(&[]),
                        Err(TrialEvaluationError::IncompatibleResource(objective))
                    );
                }
            }
            let wrong_ngram = ngram(&reversed, objective.order().unwrap_or(1));
            for resource in [&wrong_ngram, &wrong_trie] {
                trial.resource = Some(resource);
                assert_eq!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::IncompatibleResource(objective))
                );
            }
        }
    }

    #[test]
    fn exact_sample_errors_are_preserved_for_all_measures() {
        let alphabet = Alphabet::new("AB".chars().collect()).unwrap();
        let initial = initial(&alphabet, &[]);
        let domain = domain(&alphabet, &[], "AB", 1);
        for objective in [MeasureId::Ic, MeasureId::Entropy]
            .into_iter()
            .chain(SINKOV)
            .chain([MeasureId::Trie])
        {
            let resource = if let Some(order) = objective.order() {
                Some(ngram(&alphabet, order))
            } else if objective == MeasureId::Trie {
                Some(trie(&alphabet))
            } else {
                None
            };
            let required = objective.minimum_samples() as u128;
            for actual in 0..required {
                let input = "A".repeat(actual as usize);
                let mut trial = evaluator(&initial, &domain, &input);
                trial.objective = objective;
                trial.resource = resource.as_ref();
                assert_eq!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::Measure(
                        crate::MeasureError::InsufficientSamples { required, actual }
                    )),
                    "{objective:?}, {actual}",
                );
            }
        }
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
