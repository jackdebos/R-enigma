package server_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ukwdBody(model string) map[string]any {
	b := wwiiBody(model)
	delete(b, "reflector_ring")
	delete(b, "reflector_position")
	b["reflector"] = "D"
	pairs := [][]string{}
	for _, pair := range strings.Fields("AZ CX DW EV FU GT HS IR JQ KP LN MY") {
		pairs = append(pairs, strings.Split(pair, ""))
	}
	b["reflector_pairs"] = pairs
	return b
}

func TestUKWDCatalog(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	w := request(s, "GET", "/api/machines", u.Host, "", c)
	var reply struct{ Models []map[string]any }
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"enigma-i-ukwd", "enigma-m3-ukwd", "enigma-kd"} {
		found := false
		for _, m := range reply.Models {
			if m["id"] != id {
				continue
			}
			found = true
			if m["rewirable_reflector"] != true || m["settable_reflector"] == true || m["plugboard"] != (id != "enigma-kd") || len(m["slots"].([]any)) != 3 {
				t.Fatal(m)
			}
			if id == "enigma-kd" {
				fixed := m["fixed_slots"].([]any)[0].(map[string]any)
				if fixed["ring"] != "A" || fixed["position"] != "A" {
					t.Fatal(fixed)
				}
			}
		}
		if !found {
			t.Fatalf("missing %s: %s", id, w.Body.String())
		}
	}
}

func TestUKWDPreviewAndRejections(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	post := func(route string, b any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(b)
		r := httptest.NewRequest("POST", route, bytes.NewReader(data))
		r.Host = u.Host
		r.Header.Set("Origin", "http://"+u.Host)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	for _, model := range []string{"enigma-i-ukwd", "enigma-m3-ukwd", "enigma-kd"} {
		b := ukwdBody(model)
		b["plugboard"] = map[string]any{"known": []any{}, "search": false}
		b["search_reflector"] = true
		delete(b, "reflector_pairs")
		for _, starts := range []int{1, 1000000} {
			b["settings"] = map[string]any{"reflector_starts": starts, "final_measure": "ic", "stages": []any{}}
			w := post("/api/attack/preview", b)
			if w.Code != 200 {
				t.Fatalf("%s: %d %s", model, w.Code, w.Body.String())
			}
			var p struct {
				Outer   string `json:"outer_keys"`
				Request struct {
					Job struct {
						Configuration struct{ Slots []map[string]any }
						Space         struct {
							Slots     []map[string]any
							Plugboard map[string]any
						}
						Attack map[string]any
					}
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			job := p.Request.Job
			if p.Outer != "1" || job.Attack["reflector_starts"] != float64(starts) || job.Space.Slots[0]["pairs"].(map[string]any)["kind"] != "attack" || job.Configuration.Slots[0]["ring"] != "A" || job.Configuration.Slots[0]["position"] != "A" || job.Configuration.Slots[0]["pairs"] != nil || job.Space.Plugboard["max_pairs"] != float64(0) {
				t.Fatal(w.Body.String())
			}
			if model == "enigma-kd" && job.Configuration.Slots[4]["id"] != "etw" {
				t.Fatal(w.Body.String())
			}
		}
		for _, tc := range []struct {
			settings    map[string]any
			code, field string
		}{
			{map[string]any{"method": "partial_exhaustion"}, "invalid_settings", "settings/method"},
			{map[string]any{"method": "bombe", "crib": "XYZ"}, "invalid_settings", "settings/method"},
			{map[string]any{"backend": "gpu"}, "backend_unavailable", "settings/backend"},
			{map[string]any{"reflector_starts": 0}, "invalid_settings", "settings/reflector_starts"},
			{map[string]any{"reflector_starts": 1000001}, "invalid_settings", "settings/reflector_starts"},
		} {
			b["settings"] = tc.settings
			for _, route := range []string{"/api/attack/preview", "/api/attack"} {
				w := post(route, b)
				var reply struct{ Error struct{ Code, Field string } }
				_ = json.Unmarshal(w.Body.Bytes(), &reply)
				if w.Code != 400 || reply.Error.Code != tc.code || reply.Error.Field != tc.field {
					t.Fatalf("%s: %d %s", route, w.Code, w.Body.String())
				}
			}
			if w := request(s, "GET", "/api/attack", u.Host, "", c); strings.TrimSpace(w.Body.String()) != "{\"attack\":null}" {
				t.Fatalf("rejection changed stored attack: %s", w.Body.String())
			}
		}
		b["search_reflector"] = false
		b["reflector_pairs"] = ukwdBody(model)["reflector_pairs"]
		b["slots"].([]any)[2].(map[string]any)["position"] = nil
		b["settings"] = map[string]any{"backend": "gpu"}
		if w := post("/api/attack/preview", b); w.Code != 200 {
			t.Fatalf("known GPU wiring: %d %s", w.Code, w.Body.String())
		}
		b["settings"] = map[string]any{"reflector_starts": 1}
		if w := post("/api/attack/preview", b); w.Code != 400 {
			t.Fatal(w.Body.String())
		}
	}
	for _, change := range []func(map[string]any){
		func(b map[string]any) { delete(b, "reflector_pairs") },
		func(b map[string]any) { b["reflector_pairs"] = [][]string{{"B", "O"}} },
		func(b map[string]any) { b["reflector_pairs"].([][]string)[0] = []string{"A", "B"} },
		func(b map[string]any) { b["reflector_pairs"].([][]string)[0] = []string{"A", "A"} },
		func(b map[string]any) { b["reflector_position"] = "B" },
		func(b map[string]any) {
			b["slots"] = append(b["slots"].([]any), map[string]any{"id": "etw", "wheel": "ETW", "ring": "A", "position": "B"})
		},
		func(b map[string]any) { b["plugboard"] = [][]string{{"A", "B"}} },
	} {
		b := ukwdBody("enigma-kd")
		change(b)
		w := post("/api/transform", b)
		if w.Code != 400 {
			t.Fatalf("invalid wiring/controls: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestUKWDResumeRejectsGPUWithoutChangingState(t *testing.T) {
	s, u, c, _ := configureAttack(t, fakeStarted+`printf checkpoint > checkpoint.json
`+fakeResult+`echo '{"event":"done","reason":"cancelled"}'`)
	b := ukwdBody("enigma-kd")
	delete(b, "reflector_pairs")
	b["search_reflector"] = true
	b["plugboard"] = map[string]any{"known": []any{}, "search": false}
	data, _ := json.Marshal(b)
	attackCall(t, s, u, c, "POST", "/api/attack", string(data), 202, "")
	before := waitAttack(t, s, u, c, "cancelled", 5*time.Second)
	attackCall(t, s, u, c, "POST", "/api/attack/resume", `{"backend":"gpu"}`, 400, "backend_unavailable")
	after := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("GPU resume rejection changed saved attack/counters")
	}
}

func TestRealUKWDTransformAndSearch(t *testing.T) {
	path := realEnginePath(t)
	data, err := os.ReadFile("../../../crates/enigma-cli/tests/fixtures/wwii_reference_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Machine, Plaintext, Ciphertext string
		RotorOrder                     []string `json:"rotor_order"`
		Rings, Positions               struct{ Rotors []string }
		ReflectorPairs                 []string `json:"reflector_pairs"`
		Plugboard                      []string
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		if v.Machine != "enigma-i-ukwd" && v.Machine != "enigma-m3-ukwd" && v.Machine != "enigma-kd" {
			continue
		}
		t.Run(v.Machine, func(t *testing.T) {
			s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
			engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
			post := func(route string, b any) *httptest.ResponseRecorder {
				data, _ := json.Marshal(b)
				r := httptest.NewRequest("POST", route, bytes.NewReader(data))
				r.Host = u.Host
				r.Header.Set("Origin", "http://"+u.Host)
				r.AddCookie(c)
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				return w
			}
			b := ukwdBody(v.Machine)
			b["text"] = v.Plaintext
			names := map[string]string{"1": "I", "2": "II", "3": "III", "4": "IV", "5": "V", "6": "VI", "8": "VIII"}
			for i, n := range v.RotorOrder {
				slot := b["slots"].([]any)[i].(map[string]any)
				slot["wheel"] = names[n]
				slot["ring"] = v.Rings.Rotors[i]
				slot["position"] = v.Positions.Rotors[i]
			}
			pairs := [][]string{}
			for _, p := range v.ReflectorPairs {
				pairs = append(pairs, strings.Split(p, ""))
			}
			b["reflector_pairs"] = pairs
			board := [][]string{}
			for _, p := range v.Plugboard {
				board = append(board, strings.Split(p, ""))
			}
			b["plugboard"] = board
			w := post("/api/transform", b)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"output":"`+v.Ciphertext+`"`) {
				t.Fatalf("vector: %d %s", w.Code, w.Body.String())
			}
			b["plugboard"] = map[string]any{"known": board, "search": false}
			b["text"] = v.Ciphertext
			b["search_reflector"] = true
			delete(b, "reflector_pairs")
			b["settings"] = map[string]any{"reflector_starts": 1, "initial_measure": "ic", "final_measure": "ic", "stages": []any{}, "threads": 1}
			w = post("/api/attack", b)
			if w.Code != 202 {
				t.Fatalf("start: %d %s", w.Code, w.Body.String())
			}
			deadline := time.Now().Add(30 * time.Second)
			for {
				w = request(s, "GET", "/api/attack", u.Host, "", c)
				var reply struct {
					Attack struct {
						Status string
						Result struct {
							Best struct {
								Configuration struct{ Slots []struct{ Pairs [][]string } }
							}
						}
					}
				}
				if err = json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
					t.Fatal(err)
				}
				if reply.Attack.Status != "running" {
					if reply.Attack.Status != "completed" || len(reply.Attack.Result.Best.Configuration.Slots[0].Pairs) != 12 {
						t.Fatal(w.Body.String())
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("attack timeout")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
