package attack

// ValidateReflectorPairs enforces the BP UKW-D key shared by transform and attack.
// Twelve disjoint free pairs cover all contacts except the permanent BO pair.
func ValidateReflectorPairs(pairs [][]string) bool {
	if len(pairs) != 12 {
		return false
	}
	used := map[string]bool{"B": true, "O": true}
	for _, pair := range pairs {
		if len(pair) != 2 || !symbol(pair[0]) || !symbol(pair[1]) || pair[0] == pair[1] || used[pair[0]] || used[pair[1]] {
			return false
		}
		used[pair[0]], used[pair[1]] = true, true
	}
	return len(used) == 26
}

// ValidateReflectorBackend is shared by preview, start and resume. Never fall back.
func ValidateReflectorBackend(searched bool, backend string) *Issue {
	if searched && backend == "gpu" {
		return issue("backend_unavailable", "settings/backend", "GPU backend unavailable: the UKW-D wiring search runs on the CPU only")
	}
	return nil
}
