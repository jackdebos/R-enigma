// Package attack builds engine requests without executing jobs or reading files.
package attack

import "encoding/json"

const (
	secondsPerKey   = 0.004235
	peFactor        = 20
	referenceLength = 232
)

type Model struct {
	ID         string
	Reflectors []string
	Slots      []Slot
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
	EstimateSeconds float64         `json:"estimate_seconds"`
	Resources       []Resource      `json:"resources"`
}
type Input struct {
	Model     string      `json:"model"`
	Reflector *string     `json:"reflector"`
	Slots     []InputSlot `json:"slots"`
	Plugboard Plugboard   `json:"plugboard"`
	Text      string      `json:"text"`
	Settings  Settings    `json:"settings"`
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
	Method         *string           `json:"method"`
	Seeds          []string          `json:"seeds"`
	InitialMeasure *string           `json:"initial_measure"`
	FinalMeasure   *string           `json:"final_measure"`
	Stages         []Stage           `json:"stages"`
	MaxPairs       *int              `json:"max_pairs"`
	SwitchPairs    *int              `json:"switch_pairs"`
	BacktrackPairs *int              `json:"backtrack_pairs"`
	Hold           *int              `json:"hold"`
	Threads        *int              `json:"threads"`
	Tables         map[string]string `json:"tables"`
}
type Stage struct {
	Pass        string  `json:"pass"`
	Measure     *string `json:"measure"`
	BaseMeasure *string `json:"base_measure"`
}

func issue(code, field, message string) *Issue { return &Issue{code, message, field} }
