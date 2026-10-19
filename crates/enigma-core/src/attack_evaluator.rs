//! Private fresh-state trial evaluation with retained, caller-borrowed scoring models.

use std::cell::OnceCell;

use crate::measure::{index_coincidence, index_entropy};
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
    // None in the cell remembers an allocation-policy fallback, not an unbuilt cache.
    prepared: OnceCell<Option<Prepared>>,
    #[cfg(test)]
    deny_reservation: bool,
}

/// Board-independent alphabet indices: the input, then one scrambler row per offset.
#[derive(Debug)]
struct Prepared {
    input: Vec<u32>,
    rows: Vec<u32>,
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
            prepared: OnceCell::new(),
            #[cfg(test)]
            deny_reservation: false,
        }
    }

    pub(super) fn evaluate(
        &self,
        mutable: &[(char, char)],
    ) -> Result<(String, MeasuredScore), TrialEvaluationError> {
        let board = validated_trial_board(self.initial, self.domain, mutable)
            .map_err(TrialEvaluationError::Board)?;
        let mut engine = None;
        if self.prepared.get().is_none() {
            // Preserve constructor-before-full-input validation, even on fallback.
            let mut fresh = self.fresh_engine(board.clone())?;
            let alphabet = self.initial.topology().alphabet();
            let mut input = Vec::with_capacity(self.input.len());
            for symbol in self.input.chars() {
                let index = alphabet
                    .index_of(symbol)
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or(TrialEvaluationError::Model(ModelError::UnknownSymbol(
                        symbol,
                    )))?;
                input.push(index);
            }
            let length = input.len();
            let mut rows = reserved_rows(length, alphabet.symbols.len(), self.reserve_denied());
            if let Some(rows) = &mut rows {
                fresh
                    .scrambler_rows(length, self.direction, rows)
                    .map_err(TrialEvaluationError::Model)?;
            } else {
                engine = Some(fresh);
            }
            // Failed model/input validation never initializes the cell.
            self.prepared
                .set(rows.map(|rows| Prepared { input, rows }))
                .expect("single-threaded lazy preparation");
        }
        match self.prepared.get().expect("prepared above") {
            Some(prepared) => {
                let symbols = &self.initial.topology().alphabet().symbols;
                let width = symbols.len();
                let mut plaintext = String::with_capacity(self.input.len());
                let mut indices = Vec::with_capacity(prepared.input.len());
                // The trial board is bound to this alphabet, so its mapping is
                // indexed by the same alphabet indices as the rows.
                for (offset, &symbol) in prepared.input.iter().enumerate() {
                    let signal = board.mapping[symbol as usize];
                    let output = board.mapping[prepared.rows[offset * width + signal] as usize];
                    plaintext.push(symbols[output]);
                    indices.push(output as u32);
                }
                let score = self.measure_with(&plaintext, Some(&indices))?;
                Ok((plaintext, score))
            }
            None => {
                let mut engine = match engine {
                    Some(engine) => engine,
                    None => self.fresh_engine(board)?,
                };
                let plaintext = engine
                    .transform(self.input, self.direction)
                    .map_err(TrialEvaluationError::Model)?;
                let score = self.measure(&plaintext)?;
                Ok((plaintext, score))
            }
        }
    }

    fn fresh_engine(&self, board: Plugboard) -> Result<Engine, TrialEvaluationError> {
        Engine::new(
            self.initial.topology().clone(),
            self.initial.stepping().clone(),
            board,
        )
        .map_err(TrialEvaluationError::Model)
    }

    fn reserve_denied(&self) -> bool {
        #[cfg(test)]
        {
            self.deny_reservation
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// One decryption; optional base scoring reuses that exact plaintext.
    pub(super) fn evaluate_trie(
        &self,
        mutable: &[(char, char)],
        base: Option<&Self>,
        carried: crate::FixedScore,
    ) -> Result<(String, MeasuredScore), TrialEvaluationError> {
        let (plaintext, trie) = self.evaluate(mutable)?;
        let ranking = match base {
            Some(base) => base.measure(&plaintext)?.ranking(),
            None => carried,
        };
        let score = trie
            .with_ranking_base(ranking)
            .map_err(TrialEvaluationError::Measure)?;
        Ok((plaintext, score))
    }

    fn measure(&self, plaintext: &str) -> Result<MeasuredScore, TrialEvaluationError> {
        self.measure_with(plaintext, None)
    }

    /// Prepared trials pass the plaintext's alphabet indices, already known valid, so
    /// IC, entropy and n-gram scoring skip per-symbol membership lookups. The resource
    /// guards and their order are shared with the character path.
    fn measure_with(
        &self,
        plaintext: &str,
        indices: Option<&[u32]>,
    ) -> Result<MeasuredScore, TrialEvaluationError> {
        let alphabet = self.initial.topology().alphabet();
        let incompatible = || TrialEvaluationError::IncompatibleResource(self.objective);
        let score = match (self.objective, self.resource) {
            (MeasureId::Ic, None) => match indices {
                Some(indices) => index_coincidence(alphabet.len(), indices),
                None => index_of_coincidence(alphabet, plaintext),
            },
            (MeasureId::Entropy, None) => match indices {
                Some(indices) => index_entropy(alphabet.len(), indices),
                None => shannon_entropy(alphabet, plaintext),
            },
            (objective, None) if objective.requires_resource() => {
                return Err(TrialEvaluationError::MissingResource(objective));
            }
            (objective, Some(BoundResource::Ngram(model)))
                if objective.order() == Some(model.order()) && model.alphabet() == alphabet =>
            {
                match indices {
                    Some(_) => model.score_valid(plaintext),
                    None => model.score(plaintext),
                }
            }
            (MeasureId::Trie, Some(BoundResource::Trie(model))) if model.alphabet() == alphabet => {
                model.score(plaintext)
            }
            _ => return Err(incompatible()),
        };
        score.map_err(TrialEvaluationError::Measure)
    }
}

const TABLE_DATA_LIMIT: usize = 1024 * 1024;

fn table_entries(length: usize, width: usize) -> Option<usize> {
    let entries = length.checked_mul(width)?;
    (entries.checked_mul(std::mem::size_of::<u32>())? <= TABLE_DATA_LIMIT).then_some(entries)
}

fn reserved_rows(length: usize, width: usize, deny: bool) -> Option<Vec<u32>> {
    let entries = table_entries(length, width)?;
    let mut rows = Vec::new();
    if deny || rows.try_reserve_exact(entries).is_err() {
        return None;
    }
    Some(rows)
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
    fn lazy_rows_are_built_once_across_boards_and_rejected_trials() {
        crate::engine::ROW_BUILDS.with(|count| count.set(0));
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let trial = evaluator(&initial, &domain, "AA");
        crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), 0));
        assert!(trial.evaluate(&[('A', 'A')]).is_err());
        crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), 0));
        let a = trial.evaluate(&[]).unwrap();
        trial.evaluate(&[('A', 'B')]).unwrap();
        assert!(trial.evaluate(&[('A', 'A')]).is_err());
        assert_eq!(trial.evaluate(&[]).unwrap(), a);
        crate::engine::ROW_BUILDS.with(|count| assert_eq!(count.get(), 1));
    }

    #[test]
    fn prepared_trials_decrypt_and_score_without_symbol_lookups() {
        let initial = machine("ABC", "BAC", "A", true);
        let alphabet = initial.topology().alphabet();
        let domain = domain(alphabet, &[], "ABC", 1);
        let resource = ngram(alphabet, 2);
        for (objective, resource) in [
            (MeasureId::Ic, None),
            (MeasureId::Entropy, None),
            (MeasureId::SinkovBigram, Some(&resource)),
        ] {
            let input = "ABCAB".repeat(4);
            let trial = TrialEvaluator::new(
                &initial,
                &domain,
                &input,
                Direction::Decrypt,
                objective,
                resource,
            );
            let first = trial.evaluate(&[]).unwrap();
            crate::INDEX_LOOKUPS.with(|count| count.set(0));
            assert_eq!(trial.evaluate(&[]).unwrap(), first);
            crate::INDEX_LOOKUPS.with(|count| assert_eq!(count.get(), 0, "{objective:?}"));
        }
    }

    fn turnover_machine(symbols: &str, reflector: bool) -> ResolvedConfiguration {
        let s: Vec<_> = symbols.chars().collect();
        let mut slots = Vec::new();
        if reflector {
            slots.push(
                serde_json::json!({"id":"ukw","role":"reflector","movement":"fixed","wheel":"ukw"}),
            );
        }
        for id in ["slow", "middle", "fast"] {
            slots
                .push(serde_json::json!({"id":id,"role":"rotor","movement":"movable","wheel":"r"}));
        }
        let source = serde_json::json!({"kind":"custom","value":{
        "alphabet":s,
        "wheels":[{"name":"r","wiring":[s[1],s[3],s[2],s[0]],"turnovers":[s[3]]},
                  {"name":"ukw","wiring":[s[1],s[0],s[3],s[2]],"turnovers":[]}],
        "slots":slots,"stepping":{"rules":[
            {"when":{"always":true},"advance":["fast"]},
            {"when":{"at_turnover":"fast"},"advance":["middle","fast"]},
            {"when":{"at_turnover":"middle"},"advance":["slow","middle"]},
            {"when":{"at_turnover":"middle"},"advance":["middle"]}
        ]}}});
        let definition = DefinitionSource::parse_json(&source.to_string())
            .unwrap()
            .resolve()
            .unwrap();
        let mut config = Vec::new();
        if reflector {
            config.push(SlotConfiguration::new("ukw", "ukw", s[2], s[1]));
        }
        config.extend([
            SlotConfiguration::new("slow", "r", s[1], s[2]),
            SlotConfiguration::new("middle", "r", s[2], s[1]),
            SlotConfiguration::new("fast", "r", s[3], s[2]),
        ]);
        TransformConfiguration::new(config, vec![(s[0], s[1])])
            .resolve(&definition)
            .unwrap()
    }

    #[test]
    fn cached_and_denied_tables_match_fresh_engine_across_contexts() {
        for symbols in ["ABCD", "界Aéλ"] {
            let s: Vec<_> = symbols.chars().collect();
            for reflector in [false, true] {
                let initial = turnover_machine(symbols, reflector);
                let domain = domain(
                    initial.topology().alphabet(),
                    &[(s[0], s[1])],
                    &symbols.chars().skip(2).collect::<String>(),
                    2,
                );
                // Fast turnover advances middle onto its own notch, then middle
                // advances again on the next keypress (the real double-step).
                let mut probe = initial.clone().into_engine().unwrap();
                probe
                    .transform(&s[0].to_string(), Direction::Encrypt)
                    .unwrap();
                let start = usize::from(reflector);
                assert_eq!(&probe.positions()[start..], &[s[1], s[3], s[0]]);
                probe
                    .transform(&s[0].to_string(), Direction::Encrypt)
                    .unwrap();
                assert_eq!(&probe.positions()[start..], &[s[2], s[0], s[1]]);
                let alphabet = initial.topology().alphabet();
                let resources: Vec<_> = (1..=6)
                    .map(|order| {
                        let mixed = s.iter().cycle().skip(2).take(order).copied().collect();
                        let entries = vec![(vec![s[0]; order], 3), (vec![s[1]; order], 1)];
                        let entries = entries.into_iter().chain([(mixed, 2)]).collect();
                        let model = crate::NgramModel::new(alphabet.clone(), order, entries);
                        BoundResource::Ngram(model.unwrap())
                    })
                    .collect();
                let objectives = [(MeasureId::Ic, None), (MeasureId::Entropy, None)]
                    .into_iter()
                    .chain(SINKOV.into_iter().zip(resources.iter().map(Some)));
                for (objective, resource) in objectives {
                    for direction in [Direction::Encrypt, Direction::Decrypt] {
                        for input in [symbols.to_owned(), symbols.repeat(9)] {
                            for deny in [false, true] {
                                let mut trial = TrialEvaluator::new(
                                    &initial, &domain, &input, direction, objective, resource,
                                );
                                trial.deny_reservation = deny;
                                for pairs in [vec![], vec![(s[2], s[3])], vec![]] {
                                    let board =
                                        validated_trial_board(&initial, &domain, &pairs).unwrap();
                                    let mut fresh = Engine::new(
                                        initial.topology().clone(),
                                        initial.stepping().clone(),
                                        board,
                                    )
                                    .unwrap();
                                    let plaintext = fresh.transform(&input, direction).unwrap();
                                    let score = match resource {
                                        Some(BoundResource::Ngram(model)) => {
                                            model.score(&plaintext)
                                        }
                                        _ if objective == MeasureId::Ic => {
                                            index_of_coincidence(alphabet, &plaintext)
                                        }
                                        _ => shannon_entropy(alphabet, &plaintext),
                                    };
                                    let expected = score
                                        .map(|score| (plaintext, score))
                                        .map_err(TrialEvaluationError::Measure);
                                    assert_eq!(trial.evaluate(&pairs), expected, "{objective:?}");
                                    assert_eq!(trial.prepared.get().unwrap().is_none(), deny);
                                    assert!(matches!(
                                        trial.evaluate(&[(s[2], s[2])]),
                                        Err(TrialEvaluationError::Board(_))
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn table_allocation_policy_checks_overflow_boundary_and_denial() {
        let entries = TABLE_DATA_LIMIT / std::mem::size_of::<u32>();
        assert_eq!(table_entries(entries, 1), Some(entries));
        assert_eq!(table_entries(entries + 1, 1), None);
        assert_eq!(table_entries(usize::MAX, 2), None);
        assert_eq!(table_entries(usize::MAX / 2, 1), None);
        assert!(reserved_rows(2, 4, true).is_none());
        assert_eq!(reserved_rows(0, 4, false), Some(Vec::new()));
        let initial = machine("ABC", "BAC", "A", true);
        let domain = domain(initial.topology().alphabet(), &[], "ABC", 1);
        let input = "ABC".repeat(entries / 9 + 1);
        let trial = evaluator(&initial, &domain, &input);
        assert_eq!(table_entries(input.chars().count(), 3), None);
        let expected = initial
            .clone()
            .into_engine()
            .unwrap()
            .transform(&input, Direction::Decrypt)
            .unwrap();
        assert_eq!(trial.evaluate(&[]).unwrap().0, expected);
        assert!(matches!(trial.prepared.get(), Some(None)));
        assert_eq!(trial.evaluate(&[]).unwrap().0, expected);
    }

    #[test]
    fn validation_precedence_and_failed_first_trials_do_not_prepare() {
        let initial = machine("ABC", "BAC", "A", true);
        let alphabet = initial.topology().alphabet();
        let domain = domain(alphabet, &[], "ABC", 1);
        for deny in [false, true] {
            let mut invalid = evaluator(&initial, &domain, "AZ");
            invalid.deny_reservation = deny;
            assert!(matches!(
                invalid.evaluate(&[('A', 'A')]),
                Err(TrialEvaluationError::Board(_))
            ));
            assert_eq!(
                invalid.evaluate(&[]),
                Err(TrialEvaluationError::Model(ModelError::UnknownSymbol('Z')))
            );
            assert!(invalid.prepared.get().is_none());
            let wrong_fixed = super::tests::domain(alphabet, &[('A', 'B')], "C", 1);
            let invalid = evaluator(&initial, &wrong_fixed, "AZ");
            assert_eq!(
                invalid.evaluate(&[]),
                Err(TrialEvaluationError::Board(
                    TrialBoardError::FixedFactsBinding
                ))
            );
            assert!(invalid.prepared.get().is_none());
            for input in ["", "A"] {
                let mut trial = evaluator(&initial, &domain, input);
                trial.deny_reservation = deny;
                assert!(matches!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::Measure(
                        MeasureError::InsufficientSamples { .. }
                    ))
                ));
                assert!(trial.prepared.get().is_some());
                assert!(matches!(
                    trial.evaluate(&[]),
                    Err(TrialEvaluationError::Measure(
                        MeasureError::InsufficientSamples { .. }
                    ))
                ));
            }
        }
    }

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
        TrialEvaluator::new(
            initial,
            domain,
            input,
            Direction::Decrypt,
            MeasureId::Ic,
            None,
        )
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
        let trial = evaluator(&initial, &domain, "ABCD");
        assert_eq!(trial.evaluate(&[]).unwrap().0, "CABD");
        let trial = TrialEvaluator::new(
            &initial,
            &domain,
            "ABCD",
            Direction::Encrypt,
            MeasureId::Ic,
            None,
        );
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
        let foreign = evaluator(&initial, &domain, "AZ");
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
        let mut trial = evaluator(&initial, &domain, "AAAA");
        trial.objective = MeasureId::Entropy;
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
            let trial = TrialEvaluator::new(
                &initial,
                &domain,
                "BBBBBBB",
                Direction::Decrypt,
                objective,
                Some(&resource),
            );
            let b = trial.evaluate(&[]).unwrap();
            assert_eq!(b.1.measured().units(), -5_954_088_944);
            assert!(a.1.ranking().units() > b.1.ranking().units());
            let trial = TrialEvaluator::new(
                &initial,
                &domain,
                "AAAAAAA",
                Direction::Decrypt,
                objective,
                Some(&resource),
            );
            assert_eq!(trial.evaluate(&[]).unwrap(), a);
        }
        let resource = trie(&alphabet);
        let mut trial = evaluator(&initial, &domain, "AAB");
        trial.objective = MeasureId::Trie;
        trial.resource = Some(&resource);
        let a = trial.evaluate(&[]).unwrap();
        assert_eq!(a.1.measured().units(), 4 * crate::SCALE);
        assert_eq!(a.1.ranking(), a.1.measured());
        let trial = TrialEvaluator::new(
            &initial,
            &domain,
            "BBB",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
        assert_eq!(
            trial.evaluate(&[]).unwrap().1.measured().units(),
            3 * crate::SCALE
        );
        let trial = TrialEvaluator::new(
            &initial,
            &domain,
            "AAB",
            Direction::Decrypt,
            MeasureId::Trie,
            Some(&resource),
        );
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
