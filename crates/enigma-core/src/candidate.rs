//! Deterministic candidate resolver for a validated search space.
//!
//! A validated [`SearchRequest`] fixes an explicit set of variable key dimensions; this
//! module turns it into a lazy, deterministic sequence of concrete
//! [`ResolvedConfiguration`] values without materializing the whole space.
//!
//! The frozen enumeration order lives in `docs/protocol.md` §7: dimensions are visited in
//! definition slot order (left to right) and, within a slot, in the order `wheel`,
//! `position`, `ring`; the plugboard remainder is the last dimension. Later dimensions
//! vary fastest (odometer). The plugboard remainder enumerates the `size`-element
//! combinations of `candidates` in increasing candidate-index order, lexicographically.
//! When requested, `distinct_wheels` removes tuples with repeated named-slot wheels.
//! [`SearchRequest::space`] `offset`/`limit` address that filtered flat order.
//!
//! Candidate resolution reuses [`TransformConfiguration::resolve`], so no admissibility
//! rule already enforced by the search-space validator is duplicated here. Fail closed:
//! because the space was validated before enumeration, a resolve failure is an internal
//! invariant violation. The iterator yields an `Err` carrying `invalid_search_space`
//! rather than skipping the candidate.

use crate::space::{SearchDiagnostic, SearchRequest};
use crate::{
    ConfigurationDiagnostic, Definition, ResolvedConfiguration, SlotConfiguration,
    TransformConfiguration,
};

impl SearchRequest {
    /// Exact number of candidates in the frozen enumeration order of `docs/protocol.md` §7.
    ///
    /// This is the product of every varying dimension's domain size across all definition
    /// slots (in slot order, then `wheel`, `position`, `ring`) times the plugboard
    /// combination count `C(candidates.len(), size)` when a plugboard remainder is
    /// searched, or `1` otherwise, filtered by explicit `distinct_wheels` constraints.
    /// Returns `None` on `u128` overflow or when exact constraint counting exceeds its
    /// 100,000-state budget.
    pub fn candidate_count(&self) -> Option<u128> {
        CandidatePlan::build(self).count
    }

    /// Lazily enumerates the validated candidates after `space.offset()` and within
    /// `space.limit()`, in the order filtered by any explicit `distinct_wheels`.
    ///
    /// Each item resolves the addressed assignment tuple through
    /// [`TransformConfiguration::resolve`]. The space was validated before this point, so
    /// a resolve failure is an internal invariant violation: the item is yielded as
    /// `Err` with code `invalid_search_space` rather than skipped.
    pub fn candidates(&self) -> CandidateIterator<'_> {
        CandidateIterator::new(self)
    }

    /// Resolves the single candidate at flat `index` in the frozen, optionally
    /// `distinct_wheels`-filtered order.
    ///
    /// Returns `None` when `index` is at or beyond [`SearchRequest::candidate_count`].
    /// For unconstrained `u128` overflow, indexing is unbounded and every index resolves.
    /// An uncountable constrained plan instead yields an internal-error `Err`.
    pub fn candidate_at(
        &self,
        index: u128,
    ) -> Option<Result<ResolvedConfiguration, Vec<SearchDiagnostic>>> {
        let plan = CandidatePlan::build(self);
        if let Some(count) = plan.count {
            if index >= count {
                return None;
            }
        }
        Some(plan.resolve(index))
    }
}

/// Lazy, deterministic iterator over the candidates of a validated [`SearchRequest`].
///
/// It applies `space.offset()` then `space.limit()` in the single flat order of
/// `docs/protocol.md` §7 and yields `Result<ResolvedConfiguration, Vec<SearchDiagnostic>>`.
pub struct CandidateIterator<'a> {
    plan: CandidatePlan<'a>,
    next_index: u128,
    remaining: u128,
}

impl<'a> CandidateIterator<'a> {
    fn new(request: &'a SearchRequest) -> Self {
        let plan = CandidatePlan::build(request);
        let offset = request.space().offset() as u128;
        let limit = request.space().limit().map(|limit| limit as u128);
        let (next_index, remaining) = match plan.count {
            Some(total) => {
                let start = offset.min(total);
                let available = total - start;
                (start, limit.map_or(available, |limit| limit.min(available)))
            }
            None => (offset, limit.unwrap_or(u128::MAX - offset)),
        };
        Self {
            plan,
            next_index,
            remaining,
        }
    }
}

impl Iterator for CandidateIterator<'_> {
    type Item = Result<ResolvedConfiguration, Vec<SearchDiagnostic>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let index = self.next_index;
        self.next_index += 1;
        self.remaining -= 1;
        Some(self.plan.resolve(index))
    }
}

/// One definition slot's ordered values per dimension, in the frozen `wheel`, `position`,
/// `ring` order.
struct SlotAxes {
    pairs: Option<Vec<(char, char)>>,
    id: String,
    wheels: Vec<String>,
    positions: Vec<char>,
    rings: Vec<char>,
}

/// The ordered plugboard remainder pool and how many pairs each candidate draws.
struct PlugboardAxes {
    candidates: Vec<(char, char)>,
    size: usize,
}

/// A pure, precomputed projection of a validated search space.
///
/// It holds the ordered domain vectors and the mixed-radix radices once, so enumeration
/// is a pure function of the resolved space: no RNG and no unordered iteration.
pub(crate) struct CandidatePlan<'a> {
    definition: &'a Definition,
    slots: Vec<SlotAxes>,
    fixed_plugboard: Vec<(char, char)>,
    plugboard: Option<PlugboardAxes>,
    radices: Vec<u128>,
    count: Option<u128>,
    distinct: Option<DistinctPlan>,
}

/// Immutable memoized suffix counts; construction is bounded, lookup is read-only.
struct DistinctPlan {
    dimensions: Vec<usize>,
    wheels: Vec<Vec<usize>>,
    completions: std::collections::HashMap<(usize, [u64; 4]), u128>,
    assignments: Option<u128>,
    free_suffix: Option<Vec<u128>>,
}

fn with_wheel(mut used: [u64; 4], id: usize) -> Option<[u64; 4]> {
    let bit = 1u64 << (id % 64);
    if used[id / 64] & bit != 0 {
        return None;
    }
    used[id / 64] |= bit;
    Some(used)
}

impl DistinctPlan {
    fn completions(&mut self, j: usize, used: [u64; 4], visited: &mut usize) -> Option<u128> {
        if let Some(count) = self.completions.get(&(j, used)) {
            return Some(*count);
        }
        if *visited >= 100_000 {
            return None;
        }
        *visited += 1;
        let mut count = 0u128;
        if j == self.wheels.len() {
            count = 1;
        } else {
            for i in 0..self.wheels[j].len() {
                if let Some(next) = with_wheel(used, self.wheels[j][i]) {
                    count = count.checked_add(self.completions(j + 1, next, visited)?)?;
                }
            }
        }
        self.completions.insert((j, used), count);
        Some(count)
    }

    fn build(slots: &[SlotAxes], named: &[String], radices: &[u128]) -> Self {
        let mut names = Vec::new();
        let mut dimensions = Vec::new();
        let mut wheels = Vec::new();
        for (i, slot) in slots.iter().enumerate() {
            if !named.contains(&slot.id) {
                continue;
            }
            dimensions.push(i * 3);
            wheels.push(
                slot.wheels
                    .iter()
                    .map(
                        |name| match names.iter().position(|existing| existing == name) {
                            Some(id) => id,
                            None => {
                                names.push(name.clone());
                                names.len() - 1
                            }
                        },
                    )
                    .collect(),
            );
        }
        let mut plan = Self {
            dimensions,
            wheels,
            completions: std::collections::HashMap::new(),
            assignments: None,
            free_suffix: None,
        };
        // Definition validation bounds the union to at most 256 wheel names.
        if names.len() <= 256 {
            plan.assignments = plan.completions(0, [0; 4], &mut 0);
        }
        let mut suffix = vec![1u128; radices.len() + 1];
        for p in (0..radices.len()).rev() {
            let radix = if plan.dimensions.contains(&p) {
                1
            } else {
                radices[p]
            };
            let Some(count) = suffix[p + 1].checked_mul(radix) else {
                return plan;
            };
            suffix[p] = count;
        }
        plan.free_suffix = Some(suffix);
        plan
    }

    fn digits(&self, mut index: u128, radices: &[u128]) -> Option<Vec<u128>> {
        let suffix = self.free_suffix.as_ref()?;
        let mut digits = vec![0; radices.len()];
        let mut j = 0;
        let mut used = [0; 4];
        for p in 0..radices.len() {
            if self.dimensions.get(j) == Some(&p) {
                let mut chosen = None;
                for (digit, &id) in self.wheels[j].iter().enumerate() {
                    let Some(next) = with_wheel(used, id) else {
                        continue;
                    };
                    let block =
                        suffix[p + 1].checked_mul(*self.completions.get(&(j + 1, next))?)?;
                    if index < block {
                        chosen = Some((digit, next));
                        break;
                    }
                    index -= block;
                }
                let (digit, next) = chosen?;
                digits[p] = digit as u128;
                used = next;
                j += 1;
            } else {
                let block = suffix[p + 1].checked_mul(*self.completions.get(&(j, used))?)?;
                if block == 0 {
                    return None;
                }
                digits[p] = index / block;
                index %= block;
                if digits[p] >= radices[p] {
                    return None;
                }
            }
        }
        Some(digits)
    }
}

impl<'a> CandidatePlan<'a> {
    pub(crate) fn build(request: &'a SearchRequest) -> Self {
        let definition = request.definition();
        let configuration = request.configuration();
        let space = request.space();
        let mut slots = Vec::with_capacity(definition.slots().len());
        let mut radices = Vec::with_capacity(definition.slots().len() * 3 + 1);

        for definition_slot in definition.slots() {
            let id = definition_slot.id();
            let fixed = configuration.slots().iter().find(|slot| slot.id() == id);
            let domain = space.slots().iter().find(|slot| slot.id() == id);

            let wheels = match definition_slot.wheel() {
                // A structurally fixed wheel contributes exactly its definition value.
                Some(fixed_wheel) => vec![fixed_wheel.to_owned()],
                None => ordered(
                    fixed.and_then(|slot| slot.wheel()).map(str::to_owned),
                    domain.and_then(|slot| slot.wheels()),
                    "wheel",
                ),
            };
            let positions = ordered(
                fixed.and_then(|slot| slot.position()),
                domain.and_then(|slot| slot.positions()),
                "position",
            );
            let rings = ordered(
                fixed.and_then(|slot| slot.ring()),
                domain.and_then(|slot| slot.rings()),
                "ring",
            );

            radices.push(wheels.len() as u128);
            radices.push(positions.len() as u128);
            radices.push(rings.len() as u128);
            let pairs = fixed
                .and_then(|s| s.pairs())
                .map(<[_]>::to_vec)
                .or_else(|| {
                    domain.filter(|d| d.searches_pairs()).map(|_| {
                        let name = crate::space::rewirable_slot_wheel(definition, id)
                            .expect("validated wiring domain");
                        crate::rewirable::start(
                            definition.alphabet(),
                            definition
                                .rewirable_fixed_pairs(name)
                                .expect("rewirable wheel"),
                            0,
                        )
                    })
                });
            slots.push(SlotAxes {
                pairs,
                id: id.to_owned(),
                wheels,
                positions,
                rings,
            });
        }

        let mut count: Option<u128> = Some(1);
        for radix in &radices {
            count = count.and_then(|value| value.checked_mul(*radix));
        }

        let plugboard = space.plugboard().map(|domain| PlugboardAxes {
            candidates: domain.candidates().to_vec(),
            size: domain.size(),
        });
        if let Some(axes) = &plugboard {
            match combination_count(axes.candidates.len(), axes.size) {
                Some(combinations) => {
                    radices.push(combinations);
                    count = count.and_then(|value| value.checked_mul(combinations));
                }
                None => {
                    // An overflowing combination count already makes the total unknown;
                    // a placeholder radix keeps indexing well defined.
                    radices.push(1);
                    count = None;
                }
            }
        }

        let distinct = (!space.distinct_wheels().is_empty())
            .then(|| DistinctPlan::build(&slots, space.distinct_wheels(), &radices));
        if let Some(plan) = &distinct {
            count = plan.assignments.and_then(|assignments| {
                plan.free_suffix
                    .as_ref()
                    .and_then(|suffix| assignments.checked_mul(suffix[0]))
            });
        }

        Self {
            definition,
            slots,
            fixed_plugboard: configuration.plugboard().to_vec(),
            plugboard,
            radices,
            count,
            distinct,
        }
    }

    pub(crate) fn count(&self) -> Option<u128> {
        self.count
    }

    pub(crate) fn distinct_uncountable(&self) -> bool {
        self.distinct
            .as_ref()
            .is_some_and(|plan| plan.assignments.is_none())
    }

    pub(crate) fn resolve(
        &self,
        index: u128,
    ) -> Result<ResolvedConfiguration, Vec<SearchDiagnostic>> {
        let digits = match &self.distinct {
            None => decompose(index, &self.radices),
            Some(plan) => self
                .count
                .and_then(|_| plan.digits(index, &self.radices))
                .ok_or_else(|| vec![internal_resolution_failure(&[])])?,
        };
        self.resolve_digits(&digits)
    }

    fn resolve_digits(
        &self,
        digits: &[u128],
    ) -> Result<ResolvedConfiguration, Vec<SearchDiagnostic>> {
        let mut slots = Vec::with_capacity(self.slots.len());
        for (slot_index, axes) in self.slots.iter().enumerate() {
            let base = slot_index * 3;
            let slot = SlotConfiguration::new(
                axes.id.clone(),
                axes.wheels[digits[base] as usize].clone(),
                axes.positions[digits[base + 1] as usize],
                axes.rings[digits[base + 2] as usize],
            );
            slots.push(match &axes.pairs {
                Some(pairs) => slot.with_pairs(pairs.clone()),
                None => slot,
            });
        }

        let mut plugboard = self.fixed_plugboard.clone();
        if let Some(axes) = &self.plugboard {
            let combination_index = digits[self.radices.len() - 1];
            for candidate_index in
                unrank_combination(axes.candidates.len(), axes.size, combination_index)
            {
                plugboard.push(axes.candidates[candidate_index]);
            }
        }

        TransformConfiguration::new(slots, plugboard)
            .resolve(self.definition)
            .map_err(|diagnostics| vec![internal_resolution_failure(&diagnostics)])
    }
}

/// Either the single fixed value or the declared domain values, in that priority order.
///
/// Coverage validation already guaranteed exactly one of the two paths exists.
fn ordered<T: Clone>(fixed: Option<T>, declared: Option<&[T]>, what: &str) -> Vec<T> {
    match fixed {
        Some(value) => vec![value],
        None => match declared {
            Some(values) => values.to_vec(),
            None => panic!("coverage validation guaranteed a {what} path"),
        },
    }
}

fn decompose(mut index: u128, radices: &[u128]) -> Vec<u128> {
    let mut digits = vec![0u128; radices.len()];
    for position in (0..radices.len()).rev() {
        let radix = radices[position];
        digits[position] = index % radix;
        index /= radix;
    }
    digits
}

/// Exact `C(n, k)`, or `None` when the result overflows `u128`.
///
/// Each step reduces before multiplying so an intermediate product never exceeds the
/// magnitude of the exact partial result. A false overflow would drop plugboard
/// combinations, so `None` must mean the true coefficient is above `u128::MAX`.
fn combination_count(n: usize, k: usize) -> Option<u128> {
    if k > n {
        return Some(0);
    }
    let k = k.min(n - k);
    let mut result: u128 = 1;
    for step in 0..k {
        let numerator = (n - step) as u128;
        let denominator = (step + 1) as u128;
        // C(n, step+1) = C(n, step) * (n-step) / (step+1) is an integer, and
        // gcd(C(n, step), step+1) = 1 after reduction, so step+1 divides n-step exactly.
        let first = gcd(result, denominator);
        let denominator = denominator / first;
        let second = gcd(numerator, denominator);
        let denominator = denominator / second;
        debug_assert_eq!(denominator, 1, "exact binomial division left a remainder");
        result = (result / first).checked_mul(numerator / second)?;
    }
    Some(result)
}

/// Greatest common divisor of two unsigned values by the Euclidean algorithm.
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

/// The `index`-th `k`-combination of `0..n` in lexicographic order (increasing indices).
fn unrank_combination(n: usize, k: usize, index: u128) -> Vec<usize> {
    let mut result = Vec::with_capacity(k);
    let mut start = 0;
    let mut index = index;
    for position in 0..k {
        let remaining = k - position;
        for candidate in start..n {
            let count = combination_count(n - candidate - 1, remaining - 1).unwrap_or(u128::MAX);
            if index < count {
                result.push(candidate);
                start = candidate + 1;
                break;
            }
            index -= count;
        }
    }
    result
}

fn internal_resolution_failure(diagnostics: &[ConfigurationDiagnostic]) -> SearchDiagnostic {
    let mut message = String::from(
        "internal invariant violation: a validated search candidate failed to resolve",
    );
    for diagnostic in diagnostics {
        message.push_str("; ");
        message.push_str(&diagnostic.to_string());
    }
    SearchDiagnostic::internal(message, "/job/space")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Direction;
    use serde_json::{json, Value};

    /// A small arbitrary custom 4-symbol definition with a structurally fixed reflector
    /// and a movable rotor with two admissible wheels. Not a historical machine.
    fn four_symbol_definition() -> Value {
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

    /// A small arbitrary custom 6-symbol definition so the plugboard candidate pool can
    /// hold three mutually disjoint pairs. Not a historical machine.
    fn six_symbol_definition() -> Value {
        json!({
            "alphabet": ["A", "B", "C", "D", "E", "F"],
            "wheels": [
                {"name": "rotor1", "wiring": ["B", "A", "D", "C", "F", "E"], "turnovers": ["B"]},
                {"name": "reflector", "wiring": ["B", "A", "D", "C", "F", "E"], "turnovers": []}
            ],
            "slots": [
                {"id": "ukw", "role": "reflector", "movement": "fixed", "wheel": "reflector"},
                {"id": "fast", "role": "rotor", "movement": "movable", "allowed_wheels": ["rotor1"]}
            ],
            "stepping": {"rules": [{"when": {"always": true}, "advance": ["fast"]}]}
        })
    }

    fn request_value(definition: &Value, configuration_slots: Value, space: Value) -> Value {
        json!({
            "protocol_version": 1,
            "machine": {"definition": {"kind": "custom", "value": definition}},
            "job": {
                "kind": "search",
                "configuration": {"slots": configuration_slots, "plugboard": []},
                "text": "ABCD",
                "space": space,
                "passes": ["hill_climb"],
                "measures": ["ic"]
            }
        })
    }

    fn parse(value: &Value) -> SearchRequest {
        SearchRequest::parse_json(&value.to_string()).expect("valid search request")
    }

    fn collect(request: &SearchRequest) -> Vec<ResolvedConfiguration> {
        request
            .candidates()
            .map(|candidate| candidate.expect("validated candidate must resolve"))
            .collect()
    }

    fn view<'a>(resolved: &'a ResolvedConfiguration, id: &str) -> (&'a str, char, char) {
        let slot = resolved
            .topology()
            .slots()
            .iter()
            .find(|slot| slot.id() == id)
            .expect("definition slot is present");
        (slot.wheel(), slot.position(), slot.ring())
    }

    /// Fully variable four-symbol request: both slots vary over wheels/positions/rings.
    fn fully_variable_request() -> Value {
        request_value(
            &four_symbol_definition(),
            json!([{"id": "ukw"}, {"id": "fast"}]),
            json!({
                "slots": [
                    {"id": "ukw", "positions": ["A", "B"], "rings": ["A", "B"]},
                    {"id": "fast", "wheels": ["rotor1", "rotor2"], "positions": ["A", "B"], "rings": ["A", "B"]}
                ]
            }),
        )
    }

    #[test]
    fn fully_variable_search_enumerates_frozen_odometer_order() {
        let request = parse(&fully_variable_request());
        // 1 (fixed ukw wheel) * 2 * 2 * 2 * 2 * 2.
        assert_eq!(request.candidate_count(), Some(32));

        let candidates = collect(&request);
        assert_eq!(candidates.len(), 32);

        // Index 0: every dimension at its first value.
        assert_eq!(view(&candidates[0], "ukw"), ("reflector", 'A', 'A'));
        assert_eq!(view(&candidates[0], "fast"), ("rotor1", 'A', 'A'));
        // Index 1: the rightmost dimension (fast ring) varies fastest.
        assert_eq!(view(&candidates[1], "fast"), ("rotor1", 'A', 'B'));
        // Index 2: then fast position.
        assert_eq!(view(&candidates[2], "fast"), ("rotor1", 'B', 'A'));
        // Index 4: then fast wheel.
        assert_eq!(view(&candidates[4], "fast"), ("rotor2", 'A', 'A'));
        // Index 8: then ukw ring.
        assert_eq!(view(&candidates[8], "ukw"), ("reflector", 'A', 'B'));
        // Index 16: then ukw position.
        assert_eq!(view(&candidates[16], "ukw"), ("reflector", 'B', 'A'));
        // Index 31: the last tuple.
        assert_eq!(view(&candidates[31], "ukw"), ("reflector", 'B', 'B'));
        assert_eq!(view(&candidates[31], "fast"), ("rotor2", 'B', 'B'));
    }

    #[test]
    fn partially_fixed_search_enumerates_remaining_domain() {
        let request = parse(&request_value(
            &four_symbol_definition(),
            json!([
                {"id": "ukw", "position": "A", "ring": "A"},
                {"id": "fast", "wheel": "rotor1", "ring": "A"}
            ]),
            json!({"slots": [{"id": "fast", "positions": ["A", "B"]}]}),
        ));
        assert_eq!(request.candidate_count(), Some(2));

        let candidates = collect(&request);
        assert_eq!(candidates.len(), 2);
        assert_eq!(view(&candidates[0], "ukw"), ("reflector", 'A', 'A'));
        assert_eq!(view(&candidates[0], "fast"), ("rotor1", 'A', 'A'));
        assert_eq!(view(&candidates[1], "fast"), ("rotor1", 'B', 'A'));
    }

    #[test]
    fn structurally_fixed_wheel_contributes_one_value() {
        let request = parse(&request_value(
            &four_symbol_definition(),
            json!([
                {"id": "ukw", "ring": "A"},
                {"id": "fast", "wheel": "rotor1", "position": "A", "ring": "A"}
            ]),
            json!({"slots": [{"id": "ukw", "positions": ["A", "B"]}]}),
        ));
        // The whole variable dimension is the reflector position: the structurally fixed
        // wheel adds a single value and no wheel dimension.
        assert_eq!(request.candidate_count(), Some(2));

        let candidates = collect(&request);
        assert_eq!(candidates.len(), 2);
        assert_eq!(view(&candidates[0], "ukw"), ("reflector", 'A', 'A'));
        assert_eq!(view(&candidates[1], "ukw"), ("reflector", 'B', 'A'));
    }

    fn plugboard_request() -> Value {
        request_value(
            &six_symbol_definition(),
            json!([
                {"id": "ukw", "position": "A", "ring": "A"},
                {"id": "fast", "wheel": "rotor1", "ring": "A"}
            ]),
            json!({
                "slots": [{"id": "fast", "positions": ["A", "B"]}],
                "plugboard": {
                    "candidates": [["A", "B"], ["C", "D"], ["E", "F"]],
                    "size": 2
                }
            }),
        )
    }

    #[test]
    fn plugboard_remainder_enumerates_combinations_in_index_order() {
        let request = parse(&plugboard_request());
        // 2 fast positions * C(3, 2) combinations.
        assert_eq!(request.candidate_count(), Some(6));

        let candidates = collect(&request);
        assert_eq!(candidates.len(), 6);

        // Plugboard is the last (fastest) dimension, so it cycles before fast position.
        assert_eq!(view(&candidates[0], "fast"), ("rotor1", 'A', 'A'));
        assert_eq!(view(&candidates[1], "fast"), ("rotor1", 'A', 'A'));
        assert_eq!(view(&candidates[2], "fast"), ("rotor1", 'A', 'A'));
        assert_eq!(view(&candidates[3], "fast"), ("rotor1", 'B', 'A'));

        // (0, 1): A-B and C-D.
        assert_eq!(candidates[0].plugboard().map('A'), Some('B'));
        assert_eq!(candidates[0].plugboard().map('C'), Some('D'));
        assert_eq!(candidates[0].plugboard().map('E'), Some('E'));
        // (0, 2): A-B and E-F.
        assert_eq!(candidates[1].plugboard().map('A'), Some('B'));
        assert_eq!(candidates[1].plugboard().map('C'), Some('C'));
        assert_eq!(candidates[1].plugboard().map('E'), Some('F'));
        // (1, 2): C-D and E-F.
        assert_eq!(candidates[2].plugboard().map('A'), Some('A'));
        assert_eq!(candidates[2].plugboard().map('C'), Some('D'));
        assert_eq!(candidates[2].plugboard().map('E'), Some('F'));
    }

    #[test]
    fn absent_plugboard_remainder_contributes_one_value() {
        let request = parse(&request_value(
            &four_symbol_definition(),
            json!([
                {"id": "ukw", "position": "A", "ring": "A"},
                {"id": "fast", "wheel": "rotor1", "position": "A", "ring": "A"}
            ]),
            json!({"slots": []}),
        ));
        assert_eq!(request.candidate_count(), Some(1));

        let candidates = collect(&request);
        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].plugboard().is_paired('A'));
        assert_eq!(candidates[0].plugboard().map('A'), Some('A'));
    }

    #[test]
    fn offset_skips_the_first_candidates() {
        let mut value = fully_variable_request();
        value["job"]["space"]["offset"] = json!(1);
        let request = parse(&value);
        let candidates = collect(&request);
        assert_eq!(candidates.len(), 31);
        assert_eq!(view(&candidates[0], "fast"), ("rotor1", 'A', 'B'));
    }

    #[test]
    fn limit_caps_the_number_of_candidates() {
        let mut value = fully_variable_request();
        value["job"]["space"]["limit"] = json!(3);
        let request = parse(&value);
        let candidates = collect(&request);
        assert_eq!(candidates.len(), 3);
        assert_eq!(view(&candidates[2], "fast"), ("rotor1", 'B', 'A'));
    }

    #[test]
    fn offset_and_limit_slice_the_order_together() {
        let mut value = fully_variable_request();
        value["job"]["space"]["offset"] = json!(2);
        value["job"]["space"]["limit"] = json!(3);
        let request = parse(&value);
        let candidates = collect(&request);
        assert_eq!(candidates.len(), 3);
        assert_eq!(view(&candidates[0], "fast"), ("rotor1", 'B', 'A'));
        assert_eq!(view(&candidates[2], "fast"), ("rotor2", 'A', 'A'));
    }

    #[test]
    fn offset_beyond_the_count_yields_no_candidates() {
        let mut value = fully_variable_request();
        value["job"]["space"]["offset"] = json!(40);
        let request = parse(&value);
        assert!(collect(&request).is_empty());
    }

    #[test]
    fn limit_larger_than_the_remainder_yields_only_the_remainder() {
        let mut value = fully_variable_request();
        value["job"]["space"]["offset"] = json!(30);
        value["job"]["space"]["limit"] = json!(100);
        let request = parse(&value);
        let candidates = collect(&request);
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn independently_built_iterators_are_identical() {
        let request = parse(&fully_variable_request());
        let first: Vec<ResolvedConfiguration> = request
            .candidates()
            .map(|candidate| candidate.unwrap())
            .collect();
        let second: Vec<ResolvedConfiguration> = request
            .candidates()
            .map(|candidate| candidate.unwrap())
            .collect();
        assert_eq!(first, second);
    }

    #[test]
    fn candidate_at_matches_the_iterated_order() {
        let request = parse(&fully_variable_request());
        let candidates = collect(&request);
        assert_eq!(request.candidate_at(0).unwrap().unwrap(), candidates[0]);
        assert_eq!(request.candidate_at(31).unwrap().unwrap(), candidates[31]);
        assert!(request.candidate_at(32).is_none());
    }

    #[test]
    fn resolved_candidate_builds_an_engine_and_transforms_text() {
        let request = parse(&fully_variable_request());
        let candidate = request.candidates().next().unwrap().unwrap();

        let expected = TransformConfiguration::new(
            vec![
                SlotConfiguration::new("ukw", "reflector", 'A', 'A'),
                SlotConfiguration::new("fast", "rotor1", 'A', 'A'),
            ],
            vec![],
        )
        .resolve(request.definition())
        .unwrap();
        assert_eq!(candidate, expected);

        let mut engine = candidate.into_engine().unwrap();
        let output = engine.transform("ABCD", Direction::Encrypt).unwrap();
        assert_eq!(output.len(), 4);
    }

    #[test]
    fn candidate_count_returns_none_on_overflow() {
        // A 256-symbol alphabet with eight movable slots, each varying over all 256
        // positions and all 256 rings, gives 256^16 = 2^128 > u128::MAX.
        let symbols: Vec<char> = (0..256u32)
            .map(|offset| char::from_u32(0x100 + offset).expect("scalar"))
            .collect();
        let alphabet: Vec<Value> = symbols.iter().map(|c| json!(c.to_string())).collect();
        let wiring: Vec<Value> = symbols.iter().map(|c| json!(c.to_string())).collect();
        let domain: Vec<Value> = symbols.iter().map(|c| json!(c.to_string())).collect();

        let mut slots = Vec::new();
        let mut configuration_slots = Vec::new();
        let mut space_slots = Vec::new();
        for index in 0..8 {
            let id = format!("s{index}");
            slots.push(json!({
                "id": id,
                "role": "rotor",
                "movement": "movable",
                "allowed_wheels": ["w1"]
            }));
            configuration_slots.push(json!({"id": id, "wheel": "w1"}));
            space_slots.push(json!({
                "id": id,
                "positions": domain.clone(),
                "rings": domain.clone()
            }));
        }

        let definition = json!({
            "alphabet": alphabet,
            "wheels": [{"name": "w1", "wiring": wiring, "turnovers": []}],
            "slots": slots,
            "stepping": {"rules": [{"when": {"always": true}, "advance": ["s0"]}]}
        });
        let mut value = request_value(
            &definition,
            Value::Array(configuration_slots),
            json!({"slots": space_slots}),
        );
        value["job"]["text"] = json!(symbols[0].to_string().repeat(2));

        let request = parse(&value);
        assert_eq!(request.candidate_count(), None);
    }

    #[test]
    fn combination_count_is_exact_when_an_intermediate_product_would_overflow() {
        // Both coefficients fit `u128`, but multiplying before dividing would overflow at
        // an intermediate step and previously reported a false overflow that dropped
        // plugboard combinations.
        assert_eq!(
            combination_count(126, 61),
            Some(5_666_455_265_885_590_046_948_855_593_854_781_050)
        );
        assert_eq!(
            combination_count(128, 64),
            Some(23_951_146_041_928_082_866_135_587_776_380_551_750)
        );
        // A genuinely overflowing coefficient still reports `None`.
        assert_eq!(combination_count(200, 100), None);
    }
}
