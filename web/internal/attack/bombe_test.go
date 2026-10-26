package attack

import (
	"reflect"
	"strings"
	"testing"
)

func TestBombeEstimate(t *testing.T) {
	// 17576 outer keys (three unknown positions); ZYX is admissible at 0..3 in ABCDEF, so the bombe reads
	// 6 row letters (last position 3 + 3) and tests 4 positions of 3 letters.
	for _, c := range []struct {
		position string
		work     float64
	}{{"", 6 + 4*3}, {`,"crib_position":1`, 4 + 1*3}} {
		plan := build(t, strings.TrimSuffix(designB("ABCDEF"), "}")+`,"settings":{"method":"bombe","crib":"ZYX","threads":2`+c.position+`}}`)
		want := 17576 * c.work * bombeSecondsPerLetter / 2
		if plan.EstimateSeconds < want*0.999 || plan.EstimateSeconds > want*1.001 {
			t.Fatalf("position %q: estimate=%g want %g", c.position, plan.EstimateSeconds, want)
		}
	}
}

func TestBombeRequest(t *testing.T) {
	for _, position := range []string{"", `,"crib_position":0`, `,"crib_position":1`} {
		plan := build(t, strings.TrimSuffix(designB("ABCDEF"), "}")+`,"settings":{"method":"bombe","crib":"ZYX","stages":[]`+position+`}}`)
		job := asAny(t, plan.Request).(map[string]any)["job"].(map[string]any)
		crib := map[string]any{"text": "ZYX"}
		if position != "" {
			if strings.HasSuffix(position, "0") {
				crib["position"] = float64(0)
			} else {
				crib["position"] = float64(1)
			}
		}
		want := map[string]any{"kind": "bombe", "crib": crib, "initial_measure": "ic", "final_measure": "sinkov_trigram", "switch_pairs": float64(7), "backtrack_pairs": float64(5), "hold": float64(5)}
		if !reflect.DeepEqual(job["attack"], want) || !reflect.DeepEqual(job["passes"], []any{"bombe"}) {
			t.Fatalf("job: %s", plan.Request)
		}
		if job["text"] != "ABCDEF" || plan.Backend != "cpu" {
			t.Fatalf("plan: %+v", plan)
		}
	}
}

func TestBombeValidation(t *testing.T) {
	for _, tc := range []struct{ settings, field string }{
		{`"method":"bombe"`, "crib"},
		{`"method":"bombe","crib":" \n"`, "crib"},
		{`"method":"bombe","crib":"é"`, "crib"},
		{`"method":"bombe","crib":"zy"`, "crib"},
		{"\"method\":\"bombe\",\"crib\":\"\\uFEFFZY\"", "crib"},
		{"\"method\":\"bombe\",\"crib\":\"Z\\u00a0Y\"", "crib"},
		{`"method":"bombe","crib":"ß"`, "crib"},
		{`"method":"bombe","crib":"Zy"`, "crib"},
		{`"method":"bombe","crib":"Z Y"`, "crib"},
		{`"method":"bombe","crib":" ZY"`, "crib"},
		{`"method":"bombe","crib":"ZY\n"`, "crib"},
		{`"method":"bombe","crib":"Z!"`, "crib"},
		{`"method":"bombe","crib":"ZZZZZZZ"`, "crib"},
		{`"method":"bombe","crib":"ZZ","crib_position":-1`, "crib_position"},
		{`"method":"bombe","crib":"ZZ","crib_position":5`, "crib_position"},
		{`"method":"bombe","crib":"A","crib_position":0`, "crib_position"},
		{`"method":"bombe","crib":"ABCDEF"`, "crib"},
		{`"method":"bombe","crib":"ZZ","seeds":["E"]`, "seeds"},
		{`"crib":"ZZ"`, "crib"},
		{`"method":"partial_exhaustion","crib_position":0`, "crib_position"},
	} {
		t.Run(tc.settings, func(t *testing.T) {
			fails(t, strings.TrimSuffix(designB("ABCDEF"), "}")+`,"settings":{`+tc.settings+`}}`, "invalid_settings", "settings/"+tc.field)
		})
	}
	body := strings.TrimSuffix(designB("ABCDEF"), "}") + `,"settings":{"method":"bombe","crib":"ZZ","backend":"gpu"}}`
	fails(t, body, "backend_unavailable", "settings/backend")
}
