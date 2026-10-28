//! Deterministic free-contact wiring starts and complete ordered rewiring scans.
use crate::Alphabet;

pub(crate) fn canonical(alphabet: &Alphabet, pairs: &mut [(char, char)]) {
    for (a, b) in pairs.iter_mut() {
        if alphabet.index_of(*a) > alphabet.index_of(*b) {
            std::mem::swap(a, b);
        }
    }
    pairs.sort_by_key(|&(a, b)| (alphabet.index_of(a), alphabet.index_of(b)));
}
pub(crate) fn start(alphabet: &Alphabet, fixed: &[(char, char)], seed: u64) -> Vec<(char, char)> {
    let mut free: Vec<_> = alphabet
        .symbols
        .iter()
        .copied()
        .filter(|c| !fixed.iter().any(|(a, b)| c == a || c == b))
        .collect();
    let mut state = seed;
    for i in (1..free.len()).rev() {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let z = (state ^ (state >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        free.swap(i, ((z ^ (z >> 31)) % (i as u64 + 1)) as usize);
    }
    let mut pairs: Vec<_> = free.chunks_exact(2).map(|p| (p[0], p[1])).collect();
    canonical(alphabet, &mut pairs);
    pairs
}
/// Input pairs are canonical in alphabet order. Each trial is independent.
pub(crate) fn trials(pairs: &[(char, char)]) -> impl Iterator<Item = Vec<(char, char)>> + '_ {
    (0..pairs.len()).flat_map(move |i| {
        ((i + 1)..pairs.len()).flat_map(move |j| {
            let (a, b) = pairs[i];
            let (c, d) = pairs[j];
            [((a, c), (b, d)), ((a, d), (b, c))]
                .into_iter()
                .map(move |(first, second)| {
                    let mut trial = pairs.to_vec();
                    trial[i] = first;
                    trial[j] = second;
                    trial
                })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ukwd_start_goldens() {
        let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect()).unwrap();
        // Frozen from a separate literal-free-alphabet oracle before implementation.
        for (seed, golden) in [
            (0, "AW CF DS ET GL HU IV JM KY NZ PQ RX"),
            (1, "AQ CP DT EM FV GS HK IW JL NX RU YZ"),
        ] {
            let expected: Vec<_> = golden
                .split_whitespace()
                .map(|p| {
                    let mut c = p.chars();
                    (c.next().unwrap(), c.next().unwrap())
                })
                .collect();
            assert_eq!(start(&alphabet, &[('B', 'O')], seed), expected);
        }
    }
    #[test]
    fn neighborhood_132_order_and_perfect_matchings() {
        let pairs: Vec<_> = "ACDEFGHIJKLMNPQRSTUVWXYZ"
            .chars()
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .map(|p| (p[0], p[1]))
            .collect();
        let trials: Vec<_> = trials(&pairs).collect();
        assert_eq!(trials.len(), 132);
        let mut n = 0;
        for i in 0..12 {
            for j in i + 1..12 {
                let (a, b) = pairs[i];
                let (c, d) = pairs[j];
                for (first, second) in [((a, c), (b, d)), ((a, d), (b, c))] {
                    let mut expected = pairs.clone();
                    expected[i] = first;
                    expected[j] = second;
                    assert_eq!(trials[n], expected);
                    n += 1;
                }
            }
        }
        for trial in trials {
            let mut ends: Vec<_> = trial.into_iter().flat_map(|(a, b)| [a, b]).collect();
            ends.sort();
            assert_eq!(ends, "ACDEFGHIJKLMNPQRSTUVWXYZ".chars().collect::<Vec<_>>());
        }
    }
}
