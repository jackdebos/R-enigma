package attack

import (
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
)

var wheels5 = []string{"I", "II", "III", "IV", "V"}
var wheels8 = []string{"I", "II", "III", "IV", "V", "VI", "VII", "VIII"}

func catalog() []Model {
	m3 := func(id string, w []string) Model {
		return Model{ID: id, Reflectors: []string{"B", "C"}, Slots: []Slot{{"left", w}, {"middle", w}, {"right", w}}}
	}
	return []Model{
		m3("enigma-i", wheels5),
		m3("enigma-m3", wheels8),
		{ID: "enigma-m4", Reflectors: []string{"Thin-B", "Thin-C"}, Slots: []Slot{{"greek", []string{"Beta", "Gamma"}}, {"left", wheels8}, {"middle", wheels8}, {"right", wheels8}}},
	}
}

const u264 = "NCZWVUSXPNYMINHZXMQXSFWXWLKJAHSHNMCOCCAKUQPMKCSMHKSEINJUSBLKIOSXCKUBHMLLXCSJUSRRDVKOHULXWCCBGVLIYXEOAHXRHKKFVDREWEZLXOBAFGYUJQUKGRTVUKAMEURBVEKSUHHVOYHABCJWMAKLFKLMYFVNRIZRVVRTKOFDANJMOLBGFFLEOPRGTFLVRHOWOPBEKVWMUQFMPWPARMFHAGKXIIBG"

func designB(text string) string {
	return `{"model":"enigma-m4","reflector":"Thin-B","slots":[` +
		`{"id":"greek","wheel":"Beta","ring":"A","position":"V"},` +
		`{"id":"left","wheel":"II","ring":"A","position":null},` +
		`{"id":"middle","wheel":"IV","ring":"A","position":null},` +
		`{"id":"right","wheel":"I","ring":"V","position":null}],` +
		`"plugboard":{"known":[],"search":true},"text":"` + text + `"}`
}

func build(t *testing.T, body string) Plan {
	t.Helper()
	in, issue := Decode(strings.NewReader(body))
	if issue != nil {
		t.Fatalf("decode: %+v", issue)
	}
	plan, issue := Build(catalog(), in, 12)
	if issue != nil {
		t.Fatalf("build: %+v", issue)
	}
	return plan
}

func fails(t *testing.T, body, code, field string) {
	t.Helper()
	in, issue := Decode(strings.NewReader(body))
	if issue == nil {
		_, issue = Build(catalog(), in, 12)
	}
	if issue == nil || issue.Code != code || issue.Field != field || issue.Message == "" {
		t.Fatalf("issue = %+v, want %s at %q", issue, code, field)
	}
}

func asAny(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// web-attacks S8 PRESERVE: opting out reproduces the tested U-264 design B request.
func TestDefaultsReproduceDesignB(t *testing.T) {
	data, err := os.ReadFile("../../../e2e/bomm/m4-u264-attack-design-b/case.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Engine map[string]any `json:"engine"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	job := c.Engine["job"].(map[string]any)
	job["text"] = u264
	job["resources"] = map[string]any{"sinkov_trigram": map[string]any{"path": "enigma1941-trigram.json"}}
	plan := build(t, strings.TrimSuffix(designB(u264), "}")+`,"settings":{"distinct_wheels":false}}`)
	if got := asAny(t, plan.Request); !reflect.DeepEqual(got, asAny(t, mustJSON(c.Engine))) {
		t.Fatalf("request differs:\n got %s\nwant %s", plan.Request, mustJSON(c.Engine))
	}
	if plan.OuterKeys != "17576" || plan.Threads != 6 {
		t.Fatalf("outer=%s threads=%d", plan.OuterKeys, plan.Threads)
	}
	want := 17576 * secondsPerKey / 6
	if plan.EstimateSeconds < want*0.999 || plan.EstimateSeconds > want*1.001 {
		t.Fatalf("estimate=%f want %f", plan.EstimateSeconds, want)
	}
	if !reflect.DeepEqual(plan.Resources, []Resource{{Measure: "sinkov_trigram", File: "enigma1941-trigram.json", Builtin: "enigma1941-trigram"}}) {
		t.Fatalf("resources: %+v", plan.Resources)
	}
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// S7: the text reaches the request exactly as typed.
func TestTextUnchanged(t *testing.T) {
	plan := build(t, designB(`ab c\u00e9!`))
	job := asAny(t, plan.Request).(map[string]any)["job"].(map[string]any)
	if job["text"] != "ab cé!" {
		t.Fatalf("text = %q", job["text"])
	}
}

// web-attacks S2/S6 PRESERVE: opt-out keeps full domains and repeated wheels.
func TestUnknownDomainsAndCount(t *testing.T) {
	body := `{"model":"enigma-m4","reflector":null,"slots":[` +
		`{"id":"greek","wheel":null,"ring":null,"position":null},` +
		`{"id":"left","wheel":null,"ring":null,"position":null},` +
		`{"id":"middle","wheel":null,"ring":null,"position":null},` +
		`{"id":"right","wheel":null,"ring":null,"position":null}],` +
		`"plugboard":{"known":[["A","B"]],"search":true},"text":"ABC"}`
	plan := build(t, strings.TrimSuffix(body, "}")+`,"settings":{"distinct_wheels":false}}`)
	job := asAny(t, plan.Request).(map[string]any)["job"].(map[string]any)
	space := job["space"].(map[string]any)
	slots := space["slots"].([]any)
	if len(slots) != 5 {
		t.Fatalf("slots: %v", slots)
	}
	reflector := slots[0].(map[string]any)
	if !reflect.DeepEqual(reflector, map[string]any{"id": "reflector", "wheels": []any{"Thin-B", "Thin-C"}}) {
		t.Fatalf("reflector domain: %v", reflector)
	}
	right := slots[4].(map[string]any)
	if len(right["wheels"].([]any)) != 8 || len(right["rings"].([]any)) != 26 || len(right["positions"].([]any)) != 26 {
		t.Fatalf("right domain: %v", right)
	}
	config := job["configuration"].(map[string]any)["slots"].([]any)
	if !reflect.DeepEqual(config[0], map[string]any{"id": "reflector", "position": "A", "ring": "A"}) || !reflect.DeepEqual(config[1], map[string]any{"id": "greek"}) {
		t.Fatalf("configuration: %v", config)
	}
	board := space["plugboard"].(map[string]any)
	if board["max_pairs"] != float64(13) || len(board["symbols"].([]any)) != 24 {
		t.Fatalf("plugboard: %v", board)
	}
	want := new(big.Int).Mul(big.NewInt(2*2*26*26), new(big.Int).Exp(big.NewInt(8*26*26), big.NewInt(3), nil))
	if plan.OuterKeys != want.String() {
		t.Fatalf("outer = %s want %s", plan.OuterKeys, want)
	}
}

func TestKnownPlugboardWithoutSearch(t *testing.T) {
	body := strings.Replace(designB("ABC"), `"known":[],"search":true`, `"known":[["A","T"],["B","L"]],"search":false`, 1)
	job := asAny(t, build(t, body).Request).(map[string]any)["job"].(map[string]any)
	board := job["space"].(map[string]any)["plugboard"].(map[string]any)
	if board["max_pairs"] != float64(2) || len(board["symbols"].([]any)) != 22 {
		t.Fatalf("plugboard: %v", board)
	}
	if !reflect.DeepEqual(job["configuration"].(map[string]any)["plugboard"], []any{[]any{"A", "T"}, []any{"B", "L"}}) {
		t.Fatalf("fixed pairs: %v", job["configuration"])
	}
}

func TestAdvancedSettings(t *testing.T) {
	settings := `,"settings":{"method":"partial_exhaustion","seeds":["E"],"initial_measure":"sinkov_bigram","final_measure":"sinkov_quadgram","stages":[{"pass":"trie","base_measure":"ic"}],"max_pairs":10,"switch_pairs":6,"backtrack_pairs":4,"hold":20,"threads":3,"tables":{"sinkov_quadgram":"/data/q.json","trie":"/data/dict.json"}}}`
	plan := build(t, strings.TrimSuffix(designB("ABCDEF"), "}")+settings)
	job := asAny(t, plan.Request).(map[string]any)["job"].(map[string]any)
	attack := job["attack"].(map[string]any)
	wantAttack := map[string]any{"kind": "partial_exhaustion", "initial_measure": "sinkov_bigram", "final_measure": "sinkov_quadgram", "switch_pairs": float64(6), "backtrack_pairs": float64(4), "hold": float64(20), "seeds": map[string]any{"kind": "empty_single", "selection": "touching", "symbols": []any{"E"}}, "trie": map[string]any{"base_measure": "ic"}}
	if !reflect.DeepEqual(attack, wantAttack) {
		t.Fatalf("attack: %v", attack)
	}
	if !reflect.DeepEqual(job["passes"], []any{"partial_exhaustion", "trie"}) || !reflect.DeepEqual(job["measures"], []any{"sinkov_bigram", "sinkov_quadgram", "trie", "ic"}) {
		t.Fatalf("passes=%v measures=%v", job["passes"], job["measures"])
	}
	wantResources := map[string]any{"sinkov_bigram": map[string]any{"path": "enigma1941-bigram.json"}, "sinkov_quadgram": map[string]any{"path": "own-sinkov_quadgram.json"}, "trie": map[string]any{"path": "own-trie.json"}}
	if !reflect.DeepEqual(job["resources"], wantResources) {
		t.Fatalf("resources: %v", job["resources"])
	}
	if job["space"].(map[string]any)["plugboard"].(map[string]any)["max_pairs"] != float64(10) || plan.Threads != 3 {
		t.Fatalf("max_pairs/threads: %v %d", job["space"], plan.Threads)
	}
	want := 17576 * secondsPerKey * peFactor * 6 / referenceLength / 3
	if plan.EstimateSeconds < want*0.999 || plan.EstimateSeconds > want*1.001 {
		t.Fatalf("estimate=%f want %f", plan.EstimateSeconds, want)
	}
	plan = build(t, strings.TrimSuffix(designB("ABC"), "}")+`,"settings":{"method":"partial_exhaustion","stages":[]}}`)
	job = asAny(t, plan.Request).(map[string]any)["job"].(map[string]any)
	attack = job["attack"].(map[string]any)
	if !reflect.DeepEqual(attack["seeds"], map[string]any{"kind": "empty_single", "selection": "all"}) || attack["start"] != nil || !reflect.DeepEqual(job["passes"], []any{"partial_exhaustion"}) {
		t.Fatalf("pe defaults: %v", job)
	}
}

func TestRejections(t *testing.T) {
	b := designB("ABC")
	withSettings := func(s string) string { return strings.TrimSuffix(b, "}") + `,"settings":` + s + `}` }
	for _, tc := range []struct{ name, body, code, field string }{
		{"not json", "{", "invalid_request", ""},
		{"unknown member", strings.Replace(b, `"model"`, `"extra":1,"model"`, 1), "invalid_request", ""},
		{"missing reflector", strings.Replace(b, `"reflector":"Thin-B",`, "", 1), "invalid_request", "reflector"},
		{"missing position", strings.Replace(b, `"ring":"A","position":"V"`, `"ring":"A"`, 1), "invalid_request", "slots/0/position"},
		{"missing text", strings.Replace(b, `,"text":"ABC"`, "", 1), "invalid_request", "text"},
		{"unknown model", strings.Replace(b, "enigma-m4", "enigma-x", 1), "unknown_model", "model"},
		{"bad reflector", strings.Replace(b, `"Thin-B"`, `"B"`, 1), "invalid_component", "reflector"},
		{"slot order", strings.Replace(b, `"id":"greek"`, `"id":"left"`, 1), "invalid_component", "slots/0/id"},
		{"bad wheel", strings.Replace(b, `"wheel":"II"`, `"wheel":"IX"`, 1), "invalid_component", "slots/1/wheel"},
		{"bad ring", strings.Replace(b, `"ring":"V"`, `"ring":"v"`, 1), "invalid_component", "slots/3/ring"},
		{"reused letter", strings.Replace(b, `"known":[]`, `"known":[["A","B"],["B","C"]]`, 1), "invalid_component", "plugboard/known/1"},
		{"nothing unknown", `{"model":"enigma-i","reflector":"B","slots":[{"id":"left","wheel":"I","ring":"A","position":"A"},{"id":"middle","wheel":"II","ring":"A","position":"A"},{"id":"right","wheel":"III","ring":"A","position":"A"}],"plugboard":{"known":[],"search":false},"text":"ABC"}`, "nothing_to_search", ""},
		{"method", withSettings(`{"method":"unknown"}`), "invalid_settings", "settings/method"},
		{"seeds on hc", withSettings(`{"seeds":["E"]}`), "invalid_settings", "settings/seeds"},
		{"seed letter", withSettings(`{"method":"partial_exhaustion","seeds":["e"]}`), "invalid_settings", "settings/seeds"},
		{"measure", withSettings(`{"final_measure":"sinkov"}`), "invalid_settings", "settings/final_measure"},
		{"stage pass", withSettings(`{"stages":[{"pass":"hill_climb"}]}`), "invalid_settings", "settings/stages/0/pass"},
		{"repeated stage", withSettings(`{"stages":[{"pass":"measure"},{"pass":"measure"}]}`), "invalid_settings", "settings/stages/1/pass"},
		{"hold", withSettings(`{"hold":0}`), "invalid_settings", "settings/hold"},
		{"threads", withSettings(`{"threads":257}`), "invalid_settings", "settings/threads"},
		{"max pairs", withSettings(`{"max_pairs":14}`), "invalid_settings", "settings/max_pairs"},
		{"switch", withSettings(`{"switch_pairs":-1}`), "invalid_settings", "settings/switch_pairs"},
		{"relative table", withSettings(`{"tables":{"sinkov_trigram":"q.json"}}`), "invalid_settings", "settings/tables/sinkov_trigram"},
		{"unused table", withSettings(`{"tables":{"sinkov_bigram":"/q.json"}}`), "invalid_settings", "settings/tables/sinkov_bigram"},
		{"missing table", withSettings(`{"final_measure":"sinkov_hexagram","stages":[]}`), "missing_table", "settings/tables/sinkov_hexagram"},
		{"trie table", withSettings(`{"stages":[{"pass":"trie"}]}`), "missing_table", "settings/tables/trie"},
		{"full board", strings.Replace(b, `"known":[]`, `"known":[["A","B"],["C","D"],["E","F"],["G","H"],["I","J"],["K","L"],["M","N"],["O","P"],["Q","R"],["S","T"],["U","V"],["W","X"],["Y","Z"]]`, 1), "invalid_component", "plugboard"},
	} {
		t.Run(tc.name, func(t *testing.T) { fails(t, tc.body, tc.code, tc.field) })
	}
}
