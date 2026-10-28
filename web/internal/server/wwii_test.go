package server_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func wwiiBody(model string) map[string]any {
	return map[string]any{"model": model, "reflector": "UKW", "reflector_ring": "D", "reflector_position": "J", "slots": []any{
		map[string]any{"id": "left", "wheel": "III", "ring": "F", "position": "K"},
		map[string]any{"id": "middle", "wheel": "II", "ring": "C", "position": "D"},
		map[string]any{"id": "right", "wheel": "I", "ring": "P", "position": "M"},
	}, "plugboard": []any{}, "text": "ABCDEF"}
}

func TestWWIICatalog(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	w := request(s, "GET", "/api/machines", u.Host, "", c)
	var reply struct{ Models []map[string]any }
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Models) != 9 {
		t.Fatalf("models: %s", w.Body.String())
	}
	for i, id := range []string{"enigma-railway", "enigma-g312", "enigma-g260"} {
		m := reply.Models[i+3]
		if m["id"] != id || m["plugboard"] != false || m["settable_reflector"] != true || len(m["slots"].([]any)) != 3 {
			t.Fatalf("metadata: %v", m)
		}
		fixed := m["fixed_slots"].([]any)[0].(map[string]any)
		if fixed["id"] != "etw" || fixed["wheel"] != "ETW" || fixed["ring"] != "A" || fixed["position"] != "A" {
			t.Fatal(fixed)
		}
	}
}

func TestRealWWIITransformAndAttack(t *testing.T) {
	path := realEnginePath(t)
	data, err := os.ReadFile("../../../crates/enigma-cli/tests/fixtures/wwii_reference_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Machine, Plaintext, Ciphertext string
		Positions                      struct{ Rotors []string }
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors[:3] {
		t.Run(v.Machine, func(t *testing.T) {
			s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
			engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
			body := wwiiBody(v.Machine)
			body["text"] = v.Plaintext
			for i, p := range v.Positions.Rotors {
				body["slots"].([]any)[i].(map[string]any)["position"] = p
			}
			post := func(route string, body any) *httptest.ResponseRecorder {
				data, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", route, bytes.NewReader(data))
				r.Host = u.Host
				r.Header.Set("Origin", "http://"+u.Host)
				r.AddCookie(c)
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				return w
			}
			w := post("/api/transform", body)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"output":"`+v.Ciphertext+`"`) {
				t.Fatalf("transform: %d %s", w.Code, w.Body.String())
			}
			body["text"] = v.Ciphertext
			body["plugboard"] = map[string]any{"known": []any{}, "search": false}
			body["reflector_position"] = nil
			body["reflector_ring"] = nil
			body["settings"] = map[string]any{"final_measure": "ic", "stages": []any{}, "threads": 1}
			w = post("/api/attack/preview", body)
			if w.Code != 200 {
				t.Fatalf("preview: %d %s", w.Code, w.Body.String())
			}
			var plan struct {
				Outer   string `json:"outer_keys"`
				Request struct {
					Job struct {
						Configuration struct{ Slots []map[string]any }
						Space         struct {
							Plugboard map[string]any
							Slots     []map[string]any
						}
					}
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &plan); err != nil {
				t.Fatal(err)
			}
			if plan.Outer != "676" || plan.Request.Job.Space.Plugboard["kind"] != "attack" || plan.Request.Job.Space.Plugboard["max_pairs"] != float64(0) || len(plan.Request.Job.Space.Plugboard["symbols"].([]any)) != 26 || len(plan.Request.Job.Space.Slots[0]["positions"].([]any)) != 26 || len(plan.Request.Job.Space.Slots[0]["rings"].([]any)) != 26 {
				t.Fatalf("plan: %s", w.Body.String())
			}
			slots := plan.Request.Job.Configuration.Slots
			etw := slots[len(slots)-1]
			if etw["id"] != "etw" || etw["wheel"] != "ETW" || etw["position"] != "A" || etw["ring"] != "A" {
				t.Fatal(etw)
			}
			// Known reflector settings are fixed facts, not A/A defaults.
			known := wwiiBody(v.Machine)
			known["reflector_ring"], known["reflector_position"] = "D", "J"
			known["slots"].([]any)[2].(map[string]any)["position"] = nil
			known["plugboard"], known["settings"] = body["plugboard"], body["settings"]
			kw := post("/api/attack/preview", known)
			if kw.Code != 200 || !strings.Contains(kw.Body.String(), `"id":"reflector","position":"J","ring":"D","wheel":"UKW"`) {
				t.Fatalf("known reflector: %d %s", kw.Code, kw.Body.String())
			}
			w = post("/api/attack", body)
			if w.Code != 202 {
				t.Fatalf("start: %d %s", w.Code, w.Body.String())
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				w = request(s, "GET", "/api/attack", u.Host, "", c)
				var view struct {
					Attack struct {
						Status   string
						Selected string `json:"outers_selected"`
					}
				}
				if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
					t.Fatal(err)
				}
				if view.Attack.Status != "running" {
					if view.Attack.Status != "completed" || view.Attack.Selected != plan.Outer {
						t.Fatalf("attack: %s", w.Body.String())
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("attack timeout: %s", w.Body.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestWWIIAttackRejectsPlugboard(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	for _, model := range []string{"enigma-railway", "enigma-g312", "enigma-g260"} {
		for _, change := range []func(map[string]any){
			func(b map[string]any) {
				b["plugboard"] = map[string]any{"known": [][]string{{"A", "B"}}, "search": false}
			},
			func(b map[string]any) { b["plugboard"] = map[string]any{"known": []any{}, "search": true} },
			func(b map[string]any) { b["settings"] = map[string]any{"max_pairs": 1} },
		} {
			body := wwiiBody(model)
			body["plugboard"] = map[string]any{"known": []any{}, "search": false}
			body["reflector_position"] = nil
			change(body)
			data, _ := json.Marshal(body)
			r := httptest.NewRequest("POST", "/api/attack/preview", bytes.NewReader(data))
			r.Host = u.Host
			r.Header.Set("Origin", "http://"+u.Host)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			code, field := "invalid_component", "plugboard"
			if body["settings"] != nil {
				code, field = "invalid_settings", "settings/max_pairs"
			}
			var reply struct{ Error struct{ Code, Field string } }
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if w.Code != 400 || reply.Error.Code != code || reply.Error.Field != field {
				t.Fatalf("reject: %d %s", w.Code, w.Body.String())
			}
			if got := engineRequest(t, s, u, c, "GET", "", 200, ""); got.Configured {
				t.Fatal("rejection changed engine state")
			}
		}
	}
}

func TestWWIIRejectsNonhistoricalControls(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	for _, change := range []func(map[string]any){
		func(b map[string]any) { b["plugboard"] = []any{[]string{"A", "B"}} },
		func(b map[string]any) { delete(b, "reflector_ring") },
		func(b map[string]any) { b["reflector_position"] = "a" },
		func(b map[string]any) {
			b["slots"] = append(b["slots"].([]any), map[string]any{"id": "etw", "wheel": "ETW", "position": "B", "ring": "A"})
		},
	} {
		body := wwiiBody("enigma-railway")
		change(body)
		data, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/transform", bytes.NewReader(data))
		r.Host = u.Host
		r.Header.Set("Origin", "http://"+u.Host)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"invalid_component"`) {
			t.Fatalf("invalid: %d %s", w.Code, w.Body.String())
		}
		if got := engineRequest(t, s, u, c, "GET", "", 200, ""); got.Configured {
			t.Fatal("rejection changed state")
		}
	}
}
