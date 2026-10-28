// Package attack builds engine requests without executing jobs or reading files.
package attack

import "encoding/json"

const (
	secondsPerKey   = 0.004235
	peFactor        = 20
	referenceLength = 232
	// Measured on the reference computer with Weierud 1941 cribs (L15).
	bombeSecondsPerLetter = 1.3e-6
	// One searched UKW-D wiring start costs this many ordinary outer keys of the
	// same text: slope over 1/2/4 starts, 116 and 232 letters, reference computer.
	ukwdStartCost            = 15
	ukwdNoPlugboardStartCost = 35
)

type Model struct {
	RewirableReflector bool
	SettableReflector  bool
	FixedETW           bool
	NoPlugboard        bool
	ID                 string
	Reflectors         []string
	Slots              []Slot
}
type Slot struct {
	ID     string
	Wheels []string
}
type Issue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field"`
}
type Resource struct {
	Measure string `json:"measure"`
	File    string `json:"file"`
	Builtin string `json:"builtin,omitempty"`
	Own     string `json:"own,omitempty"`
}
type Plan struct {
	Request         json.RawMessage `json:"request"`
	OuterKeys       string          `json:"outer_keys"`
	Threads         int             `json:"threads"`
	Backend         string          `json:"backend"`
	GPUUsage        int             `json:"gpu_usage"`
	EstimateSeconds float64         `json:"estimate_seconds"`
	Resources       []Resource      `json:"resources"`
}
type Input struct {
	ReflectorPairs    [][]string  `json:"reflector_pairs,omitempty"`
	SearchReflector   *bool       `json:"search_reflector,omitempty"`
	Model             string      `json:"model"`
	Reflector         *string     `json:"reflector"`
	ReflectorRing     *string     `json:"reflector_ring,omitempty"`
	ReflectorPosition *string     `json:"reflector_position,omitempty"`
	Slots             []InputSlot `json:"slots"`
	Plugboard         Plugboard   `json:"plugboard"`
	Text              string      `json:"text"`
	Settings          Settings    `json:"settings"`
}
type InputSlot struct {
	ID       string  `json:"id"`
	Wheel    *string `json:"wheel"`
	Ring     *string `json:"ring"`
	Position *string `json:"position"`
}
type Plugboard struct {
	Known  [][]string `json:"known"`
	Search bool       `json:"search"`
}
type Settings struct {
	ReflectorStarts *int              `json:"reflector_starts"`
	DistinctWheels  *bool             `json:"distinct_wheels"`
	Method          *string           `json:"method"`
	Seeds           []string          `json:"seeds"`
	Crib            *string           `json:"crib"`
	CribPosition    *int              `json:"crib_position"`
	InitialMeasure  *string           `json:"initial_measure"`
	FinalMeasure    *string           `json:"final_measure"`
	Stages          []Stage           `json:"stages"`
	MaxPairs        *int              `json:"max_pairs"`
	SwitchPairs     *int              `json:"switch_pairs"`
	BacktrackPairs  *int              `json:"backtrack_pairs"`
	Hold            *int              `json:"hold"`
	Threads         *int              `json:"threads"`
	Backend         *string           `json:"backend"`
	GPUUsage        *int              `json:"gpu_usage"`
	Tables          map[string]string `json:"tables"`
}
type Stage struct {
	Pass        string  `json:"pass"`
	Measure     *string `json:"measure"`
	BaseMeasure *string `json:"base_measure"`
}

func issue(code, field, message string) *Issue { return &Issue{code, message, field} }

func (in Input) SearchesReflector() bool { return in.SearchReflector != nil && *in.SearchReflector }
