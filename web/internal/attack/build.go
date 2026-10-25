package attack

import (
	"encoding/json"
	"math/big"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"criptografia-enigma/web/internal/tables"
)

func symbol(s string) bool { return len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' }
func stringDefault(v *string, fallback string) string {
	if v != nil {
		return *v
	}
	return fallback
}
func intDefault(v *int, fallback int) int {
	if v != nil {
		return *v
	}
	return fallback
}
func validMeasure(s string) bool {
	return slices.Contains([]string{"ic", "entropy", "sinkov_monogram", "sinkov_bigram", "sinkov_trigram", "sinkov_quadgram", "sinkov_pentagram", "sinkov_hexagram", "trie"}, s)
}

// Build keeps catalog order and counts the exact constrained outer space.
// Resource source paths are returned separately from relative engine paths.
func Build(models []Model, in Input, cpus int) (Plan, *Issue) {
	var plan Plan
	var model *Model
	for i := range models {
		if models[i].ID == in.Model {
			model = &models[i]
			break
		}
	}
	if model == nil {
		return plan, issue("unknown_model", "model", "Choose a bundled model.")
	}
	component := func(field string) *Issue {
		return issue("invalid_component", field, "Choose an allowed component or uppercase A-Z symbol.")
	}
	if len(in.Slots) != len(model.Slots) {
		return plan, component("slots")
	}
	alphabet := []string{}
	for c := 'A'; c <= 'Z'; c++ {
		alphabet = append(alphabet, string(c))
	}
	keys := big.NewInt(1)
	configs := []map[string]any{}
	domains := []map[string]any{}
	unknown := false
	addSlot := func(id string, wheel, ring, position *string, wheels []string, field string) *Issue {
		config := map[string]any{"id": id}
		domain := map[string]any{"id": id}
		for _, dimension := range []struct {
			name, plural string
			value        *string
			allowed      []string
		}{{"wheel", "wheels", wheel, wheels}, {"ring", "rings", ring, alphabet}, {"position", "positions", position, alphabet}} {
			if dimension.value == nil {
				unknown = true
				domain[dimension.plural] = dimension.allowed
				keys.Mul(keys, big.NewInt(int64(len(dimension.allowed))))
			} else {
				if !slices.Contains(dimension.allowed, *dimension.value) {
					return component(field + dimension.name)
				}
				config[dimension.name] = *dimension.value
			}
		}
		configs = append(configs, config)
		if len(domain) > 1 {
			domains = append(domains, domain)
		}
		return nil
	}
	a := "A"
	// Reflectors have fixed ring and position even when their wheel is unknown.
	if p := addSlot("reflector", in.Reflector, &a, &a, model.Reflectors, ""); p != nil {
		p.Field = "reflector"
		return plan, p
	}
	for i, s := range in.Slots {
		field := "slots/" + strconv.Itoa(i) + "/"
		if s.ID != model.Slots[i].ID {
			return plan, component(field + "id")
		}
		if p := addSlot(s.ID, s.Wheel, s.Ring, s.Position, model.Slots[i].Wheels, field); p != nil {
			return plan, p
		}
	}
	var distinctIDs []string
	if in.Settings.DistinctWheels == nil || *in.Settings.DistinctWheels {
		indices := overlappingWheelSlots(model.Slots)
		if len(indices) >= 2 {
			for _, i := range indices {
				distinctIDs = append(distinctIDs, model.Slots[i].ID)
				if in.Slots[i].Wheel == nil {
					keys.Quo(keys, big.NewInt(int64(len(model.Slots[i].Wheels))))
				}
			}
			assignments := distinctWheelAssignments(model.Slots, in.Slots, indices)
			if assignments.Sign() == 0 {
				return Plan{}, issue("invalid_settings", "settings/distinct_wheels", "No distinct wheel order is possible. Choose different known wheels, mark a wheel unknown, or turn off distinct wheels.")
			}
			keys.Mul(keys, assignments)
		}
	}
	used := map[string]bool{}
	for i, pair := range in.Plugboard.Known {
		if len(pair) != 2 || !symbol(pair[0]) || !symbol(pair[1]) || pair[0] == pair[1] || used[pair[0]] || used[pair[1]] {
			return plan, component("plugboard/known/" + strconv.Itoa(i))
		}
		used[pair[0]] = true
		used[pair[1]] = true
	}
	free := []string{}
	for _, s := range alphabet {
		if !used[s] {
			free = append(free, s)
		}
	}
	if len(free) == 0 {
		return plan, component("plugboard")
	}
	settings := in.Settings
	invalid := func(field string) *Issue {
		return issue("invalid_settings", "settings/"+field, "Invalid attack setting.")
	}
	backend, usage, problem := ResolveBackend(settings.Backend, settings.GPUUsage)
	if problem != nil {
		return plan, problem
	}
	method := stringDefault(settings.Method, "hill_climb")
	if method != "hill_climb" && method != "partial_exhaustion" {
		return plan, invalid("method")
	}
	initial := stringDefault(settings.InitialMeasure, "ic")
	final := stringDefault(settings.FinalMeasure, "sinkov_trigram")
	if !validMeasure(initial) {
		return plan, invalid("initial_measure")
	}
	if !validMeasure(final) {
		return plan, invalid("final_measure")
	}
	knownCount := len(in.Plugboard.Known)
	maxPairs := intDefault(settings.MaxPairs, 13)
	switchPairs := intDefault(settings.SwitchPairs, 7)
	backtrack := intDefault(settings.BacktrackPairs, 5)
	hold := intDefault(settings.Hold, 5)
	threads := intDefault(settings.Threads, max(1, cpus/2))
	for _, bound := range []struct {
		name             string
		value, low, high int
	}{{"max_pairs", maxPairs, knownCount, 13}, {"switch_pairs", switchPairs, 0, 13}, {"backtrack_pairs", backtrack, 0, 13}, {"hold", hold, 1, 1000}, {"threads", threads, 1, 256}} {
		if bound.value < bound.low || bound.value > bound.high {
			return plan, invalid(bound.name)
		}
	}
	if !in.Plugboard.Search {
		maxPairs = knownCount
	}
	if !unknown && !in.Plugboard.Search {
		return plan, issue("nothing_to_search", "", "Mark at least one key component unknown.")
	}
	attack := map[string]any{"kind": method, "initial_measure": initial, "final_measure": final, "switch_pairs": switchPairs, "backtrack_pairs": backtrack, "hold": hold}
	if method == "hill_climb" {
		if settings.Seeds != nil {
			return plan, invalid("seeds")
		}
		attack["start"] = [][]string{}
	} else {
		seeds := map[string]any{"kind": "empty_single", "selection": "all"}
		if settings.Seeds != nil {
			if len(settings.Seeds) == 0 {
				return plan, invalid("seeds")
			}
			seen := map[string]bool{}
			for _, s := range settings.Seeds {
				if !symbol(s) || used[s] || seen[s] {
					return plan, invalid("seeds")
				}
				seen[s] = true
			}
			seeds["selection"] = "touching"
			seeds["symbols"] = settings.Seeds
		}
		attack["seeds"] = seeds
	}
	measures := []string{}
	addMeasure := func(m string) {
		if !slices.Contains(measures, m) {
			measures = append(measures, m)
		}
	}
	addMeasure(initial)
	addMeasure(final)
	passes := []string{method}
	stages := settings.Stages
	if stages == nil {
		m := "sinkov_trigram"
		stages = []Stage{{Pass: "reswapping", Measure: &m}, {Pass: "measure", Measure: &m}}
	}
	for i, stage := range stages {
		field := "stages/" + strconv.Itoa(i) + "/"
		if !slices.Contains([]string{"reswapping", "measure", "trie"}, stage.Pass) || slices.Contains(passes, stage.Pass) {
			return plan, invalid(field + "pass")
		}
		passes = append(passes, stage.Pass)
		options := map[string]any{}
		if stage.Pass == "trie" {
			if stage.Measure != nil {
				return plan, invalid(field + "measure")
			}
			addMeasure("trie")
			if stage.BaseMeasure != nil {
				if !validMeasure(*stage.BaseMeasure) {
					return plan, invalid(field + "base_measure")
				}
				options["base_measure"] = *stage.BaseMeasure
				addMeasure(*stage.BaseMeasure)
			}
		} else {
			if stage.BaseMeasure != nil {
				return plan, invalid(field + "base_measure")
			}
			fallback := "ic"
			if stage.Pass == "reswapping" {
				fallback = "sinkov_trigram"
			}
			m := stringDefault(stage.Measure, fallback)
			if !validMeasure(m) {
				return plan, invalid(field + "measure")
			}
			options["measure"] = m
			addMeasure(m)
		}
		attack[stage.Pass] = options
	}
	for measure, path := range settings.Tables {
		if !slices.Contains(measures, measure) || !(strings.HasPrefix(measure, "sinkov_") || measure == "trie") || !filepath.IsAbs(path) {
			return plan, invalid("tables/" + measure)
		}
	}
	resources := map[string]any{}
	plan.Resources = []Resource{}
	for _, measure := range measures {
		if !strings.HasPrefix(measure, "sinkov_") && measure != "trie" {
			continue
		}
		resource := Resource{Measure: measure}
		if own, ok := settings.Tables[measure]; ok {
			resource.File = "own-" + measure + ".json"
			resource.Own = own
		} else if table, ok := tables.ForMeasure(measure); ok {
			resource.File = table.ID + ".json"
			resource.Builtin = table.ID
		} else {
			return Plan{}, issue("missing_table", "settings/tables/"+measure, "Supply an absolute scoring table path.")
		}
		resources[measure] = map[string]string{"path": resource.File}
		plan.Resources = append(plan.Resources, resource)
	}
	space := map[string]any{"plugboard": map[string]any{"kind": "attack", "symbols": free, "max_pairs": maxPairs}}
	if len(domains) > 0 {
		space["slots"] = domains
	}
	if len(distinctIDs) >= 2 {
		space["constraints"] = map[string]any{"distinct_wheels": distinctIDs}
	}
	known := in.Plugboard.Known
	if known == nil {
		known = [][]string{}
	}
	job := map[string]any{"kind": "search", "configuration": map[string]any{"slots": configs, "plugboard": known}, "space": space, "text": in.Text, "passes": passes, "measures": measures, "attack": attack}
	if len(resources) > 0 {
		job["resources"] = resources
	}
	request := map[string]any{"protocol_version": 1, "machine": map[string]any{"definition": map[string]string{"kind": "bundled", "id": model.ID}}, "job": job}
	plan.Request, _ = json.Marshal(request)
	plan.OuterKeys = keys.String()
	plan.Threads = threads
	plan.Backend = backend
	plan.GPUUsage = usage
	count, _ := new(big.Float).SetInt(keys).Float64()
	letters := 0
	for _, r := range in.Text {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			letters++
		}
	}
	factor := 1
	if method == "partial_exhaustion" {
		factor = peFactor
	}
	plan.EstimateSeconds = count * secondsPerKey * float64(factor) * float64(letters) / referenceLength / float64(threads)
	return plan, nil
}
