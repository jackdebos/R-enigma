package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func wheelInput(model Model) Input {
	a := "A"
	in := Input{Model: model.ID, Reflector: &model.Reflectors[0], Plugboard: Plugboard{Known: [][]string{}, Search: true}, Text: "ABCDEF"}
	for _, slot := range model.Slots {
		in.Slots = append(in.Slots, InputSlot{ID: slot.ID, Ring: &a})
	}
	return in
}

func withDistinct(t *testing.T, in Input, enabled bool) Input {
	t.Helper()
	body := asAny(t, mustJSON(in)).(map[string]any)
	// Decode through the public API, including the setting's strict type checks.
	body["settings"] = map[string]any{"distinct_wheels": enabled}
	result, problem := Decode(bytes.NewReader(mustJSON(body)))
	if problem != nil {
		t.Fatalf("decode distinct_wheels: %+v", problem)
	}
	return result
}

// distinct-wheels S7: exact IDs, definition order, filtered counts and estimates.
func TestDistinctWheelsDefaults(t *testing.T) {
	for i, model := range catalog() {
		t.Run(model.ID, func(t *testing.T) {
			in := wheelInput(model)
			plan, problem := Build(catalog(), in, 12)
			if problem != nil {
				t.Fatal(problem)
			}
			job := asAny(t, plan.Request).(map[string]any)["job"].(map[string]any)
			constraint := job["space"].(map[string]any)["constraints"]
			if !reflect.DeepEqual(constraint, map[string]any{"distinct_wheels": []any{"left", "middle", "right"}}) {
				t.Fatalf("constraint = %v", constraint)
			}
			want := []string{"1054560", "5905536", "307087872"}[i]
			if plan.OuterKeys != want {
				t.Fatalf("outer_keys=%s want %s", plan.OuterKeys, want)
			}
			off, p := Build(catalog(), withDistinct(t, in, false), 12)
			if p != nil {
				t.Fatal(p)
			}
			if i == 0 && off.OuterKeys != "2197000" {
				t.Fatalf("off=%s", off.OuterKeys)
			}
			if plan.EstimateSeconds >= off.EstimateSeconds {
				t.Fatal("constraint did not reduce estimate")
			}
			explicit, p := Build(catalog(), withDistinct(t, in, true), 12)
			if p != nil || !bytes.Equal(plan.Request, explicit.Request) {
				t.Fatalf("explicit true differs: %v", p)
			}
		})
	}
}

// distinct-wheels S7 / S5: known wheels exclude themselves; repeats fail before a request exists.
func TestDistinctWheelsKnownAndImpossible(t *testing.T) {
	in := wheelInput(catalog()[0])
	one := "I"
	in.Slots[0].Wheel = &one
	plan, problem := Build(catalog(), in, 12)
	if problem != nil || plan.OuterKeys != "210912" {
		t.Fatalf("mixed: %s %+v", plan.OuterKeys, problem)
	}
	in.Slots[1].Wheel = &one
	before := string(mustJSON(in))
	plan, problem = Build(catalog(), in, 12)
	if problem == nil || problem.Code != "invalid_settings" || problem.Field != "settings/distinct_wheels" || problem.Message == "" || len(plan.Request) != 0 {
		t.Fatalf("impossible: %+v %+v", plan, problem)
	}
	if string(mustJSON(in)) != before {
		t.Fatal("rejected input changed")
	}
	off, problem := Build(catalog(), withDistinct(t, in, false), 12)
	if problem != nil || off.OuterKeys != "87880" {
		t.Fatalf("off repeats: %s %+v", off.OuterKeys, problem)
	}
}

// distinct-wheels S7: do not send a constraint when no rotor domains overlap.
func TestDistinctWheelsDisjointSlots(t *testing.T) {
	model := Model{ID: "disjoint", Reflectors: []string{"B"}, Slots: []Slot{{"first", []string{"I"}}, {"second", []string{"II"}}}}
	plan, p := Build([]Model{model}, wheelInput(model), 2)
	if p != nil {
		t.Fatal(p)
	}
	space := asAny(t, plan.Request).(map[string]any)["job"].(map[string]any)["space"].(map[string]any)
	if _, ok := space["constraints"]; ok {
		t.Fatalf("redundant constraint: %v", space)
	}
	if plan.OuterKeys != "676" {
		t.Fatal(plan.OuterKeys)
	}
}

// distinct-wheels S7 PRESERVE: these byte fixtures were captured from the builder
// before adding the setting. No JSON reserialization is allowed in this comparison.
func TestDistinctWheelsOffOriginalBytes(t *testing.T) {
	for _, model := range catalog() {
		t.Run(model.ID, func(t *testing.T) {
			in := wheelInput(model)
			in.Text = "aZ é!\n"
			plan, p := Build(catalog(), withDistinct(t, in, false), 12)
			if p != nil {
				t.Fatal(p)
			}
			want, err := os.ReadFile(filepath.Join("testdata", model.ID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plan.Request, want) {
				t.Fatalf("off request differs from original bytes:\ngot %s\nwant %s", plan.Request, want)
			}
			t.Logf("request bytes identical to base: %d bytes", len(want))
		})
	}
}

// distinct-wheels S7: real engine count must match preview, not an independent estimate.
func TestRealEngineDistinctWheelsCount(t *testing.T) {
	path := os.Getenv("ENIGMA_TEST_BIN")
	if path == "" {
		t.Skip("set ENIGMA_TEST_BIN to an engine 0.3.0 binary to compare preview and started counts")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("ENIGMA_TEST_BIN engine binary is unavailable")
	} else if err != nil {
		t.Fatal(err)
	}
	for _, model := range catalog() {
		t.Run(model.ID, func(t *testing.T) {
			in := wheelInput(model)
			a := "A"
			for i := range in.Slots {
				in.Slots[i].Position = &a
			}
			in.Plugboard.Search = false
			ic := "ic"
			in.Settings.FinalMeasure = &ic
			in.Settings.Stages = []Stage{}
			plan, p := Build(catalog(), in, 2)
			if p != nil {
				t.Fatal(p)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, "--events", "-", "--request", "-")
			cmd.Dir = t.TempDir()
			cmd.Stdin = bytes.NewReader(plan.Request)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil || stderr.Len() != 0 {
				t.Fatalf("engine: %v stderr=%s stdout=%s", err, &stderr, out)
			}
			started, done := false, false
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				var e struct {
					Event    string
					Selected string `json:"outers_selected"`
					Reason   string
				}
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatal(err)
				}
				if e.Event == "started" {
					started = true
					if e.Selected != plan.OuterKeys {
						t.Fatalf("preview=%s engine=%s", plan.OuterKeys, e.Selected)
					}
				}
				if e.Event == "done" {
					done = e.Reason == "completed"
				}
			}
			if !started || !done {
				t.Fatalf("incomplete events: %s", out)
			}
			t.Logf("preview outer_keys = engine started.outers_selected = %s", plan.OuterKeys)
		})
	}
}
