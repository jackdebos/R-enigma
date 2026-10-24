package server_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const form = `{"model":"enigma-i","reflector":"B","slots":[{"id":"left","wheel":"I","ring":"A","position":"A"},{"id":"middle","wheel":"II","ring":"A","position":"A"},{"id":"right","wheel":"III","ring":"A","position":"A"}],"plugboard":[],"text":"aZ é!?\n"}`
const successEvents = `{"event":"started","protocol_version":1,"seq":1,"ts":"2026-10-24T00:00:00Z"}
{"event":"output","protocol_version":1,"seq":2,"ts":"2026-10-24T00:00:00Z","output":"XYZ"}
{"event":"done","protocol_version":1,"seq":3,"ts":"2026-10-24T00:00:00Z","reason":"completed"}`

func TestTransform(t *testing.T) {
	for _, tc := range []struct {
		name, script, code string
		status             int
	}{
		{"output", "printf '%s\\n' '" + successEvents + "'", "", 200},
		{"error", `printf '%s\n' '{"event":"error","code":"invalid_text","message":"symbol is not in the machine alphabet","location":"/job/text"}'; exit 1`, "invalid_text", 422},
		{"garbage", "echo garbage", "engine_failed", 502},
		{"missing-output", `echo '{"event":"done","reason":"completed"}'`, "engine_failed", 502},
		{"process", "exit 3", "engine_failed", 502},
		{"nonzero-output", "printf '%s\\n' '" + successEvents + "'; exit 1", "engine_failed", 502},
		{"stdout-bound", "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done", "engine_failed", 502},
		{"stderr-bound", "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' >&2; done", "engine_failed", 502},
		{"timeout", "exec sleep 12", "timeout", 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
			capture := filepath.Join(dir, "request.json")
			script := "if [ \"$1\" = --version ]; then printf 'enigma 0.1.0\\nprotocol version 1\\n'; exit; fi\n[ \"$*\" = '--events - --request -' ] || exit 8\ncat > '" + capture + "'\n" + tc.script
			path := engineScript(t, dir, "engine with spaces", script, 0700)
			engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
			r := httptest.NewRequest("POST", "/api/transform", strings.NewReader(form))
			r.Host = u.Host
			r.Header.Set("Origin", "http://"+u.Host)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			start := time.Now()
			s.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var reply struct {
				Output string                          `json:"output"`
				Events []json.RawMessage               `json:"events"`
				Error  *struct{ Code, Message string } `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if tc.code == "" {
				if reply.Output != "XYZ" || len(reply.Events) != 3 || reply.Error != nil {
					t.Fatalf("reply=%s", w.Body.String())
				}
			} else if reply.Error == nil || reply.Error.Code != tc.code || reply.Error.Message == "" {
				t.Fatalf("reply=%s", w.Body.String())
			}
			if tc.name == "error" && reply.Error.Message != "symbol is not in the machine alphabet" {
				t.Fatal("engine message lost")
			}
			if time.Since(start) > 11*time.Second {
				t.Fatal("deadline exceeded")
			}
			data, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			var req struct {
				Protocol int `json:"protocol_version"`
				Machine  struct{ Definition struct{ Kind, ID string } }
				Job      struct {
					Kind, Direction, Text string
					Configuration         struct {
						Slots     []map[string]string
						Plugboard [][]string
					}
				}
			}
			if err := json.Unmarshal(data, &req); err != nil {
				t.Fatal(err)
			}
			if req.Protocol != 1 || req.Machine.Definition.Kind != "bundled" || req.Machine.Definition.ID != "enigma-i" || req.Job.Kind != "transform" || req.Job.Direction != "encrypt" || req.Job.Text != "aZ é!?\n" || len(req.Job.Configuration.Slots) != 4 || req.Job.Configuration.Slots[0]["wheel"] != "B" || req.Job.Configuration.Slots[0]["position"] != "A" || req.Job.Configuration.Plugboard == nil {
				t.Fatalf("request=%s", data)
			}
			if got := engineRequest(t, s, u, c, "GET", "", 200, ""); got.Path != path {
				t.Fatal("transform changed saved engine")
			}
		})
	}
}

func TestTransformValidationAndSecurity(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	for _, tc := range []struct{ body, code string }{
		{"{", "invalid_request"}, {"null", "invalid_request"}, {"{}", "invalid_request"}, {form + " {}", "invalid_request"},
		{strings.Replace(form, `"model":"enigma-i"`, `"extra":1,"model":"enigma-i"`, 1), "invalid_request"},
		{strings.Replace(form, `"model":"enigma-i"`, `"model":"other"`, 1), "unknown_model"},
		{strings.Replace(form, `"reflector":"B"`, `"reflector":"Thin-B"`, 1), "invalid_component"},
		{strings.Replace(form, `"wheel":"I"`, `"wheel":"VI"`, 1), "invalid_component"},
		{strings.Replace(form, `"id":"left"`, `"id":"right"`, 1), "invalid_component"},
		{strings.Replace(form, `"ring":"A"`, `"ring":"a"`, 1), "invalid_component"},
		{strings.Replace(form, `"plugboard":[]`, `"plugboard":[["A","A"]]`, 1), "invalid_component"},
		{strings.Replace(form, `"plugboard":[]`, `"plugboard":[["A","B"],["A","C"]]`, 1), "invalid_component"},
		{strings.Replace(form, `"plugboard":[]`, `"plugboard":null`, 1), "invalid_request"},
		{strings.Replace(form, `"text":"aZ é!?\n"`, `"text":null`, 1), "invalid_request"},
		{strings.Replace(form, `"text":"aZ é!?\n"`, `"text":"`+strings.Repeat("A", 1024*1024)+`"`, 1), "invalid_request"},
	} {
		r := httptest.NewRequest("POST", "/api/transform", strings.NewReader(tc.body))
		r.Host = u.Host
		r.Header.Set("Origin", "http://"+u.Host)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
			t.Fatalf("want %s: %d %s", tc.code, w.Code, w.Body.String())
		}
		if got := engineRequest(t, s, u, c, "GET", "", 200, ""); got.Configured {
			t.Fatal("validation configured engine")
		}
	}
	r := httptest.NewRequest("POST", "/api/transform", strings.NewReader(form))
	r.Host = u.Host
	r.Header.Set("Origin", "http://"+u.Host)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "engine_not_configured") {
		t.Fatalf("unconfigured: %d %s", w.Code, w.Body.String())
	}
	for _, route := range []string{"/api/machines", "/api/transform"} {
		if w := request(s, "GET", route, u.Host, "", nil); w.Code != 401 {
			t.Fatal("auth", w.Code)
		}
		if w := request(s, "GET", route, "evil.example", "", c); w.Code != 403 {
			t.Fatal("host", w.Code)
		}
		if w := request(s, "POST", route, u.Host, "http://evil.example", c); w.Code != 403 {
			t.Fatal("origin", w.Code)
		}
	}
	for route, method := range map[string]string{"/api/machines": "POST", "/api/transform": "GET"} {
		w := request(s, method, route, u.Host, "http://"+u.Host, c)
		if w.Code != 405 {
			t.Fatalf("method %s: %d", route, w.Code)
		}
	}
}

func TestMachines(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	w := request(s, "GET", "/api/machines", u.Host, "", c)
	var reply struct {
		Models []struct {
			ID           string
			DefinitionID string `json:"definition_id"`
			Reflectors   []string
			Slots        []struct {
				ID            string
				AllowedWheels []string `json:"allowed_wheels"`
			}
			Plugboard bool
		}
	}
	if w.Code != 200 {
		t.Fatalf("catalog: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Models) != 3 {
		t.Fatalf("catalog=%s", w.Body.String())
	}
	for i, m := range reply.Models {
		if m.ID != []string{"enigma-i", "enigma-m3", "enigma-m4"}[i] || m.DefinitionID != m.ID || !m.Plugboard {
			t.Fatalf("model=%+v", m)
		}
		want := 3
		if i == 2 {
			want = 4
			if strings.Join(m.Reflectors, ",") != "Thin-B,Thin-C" || m.Slots[0].ID != "greek" || strings.Join(m.Slots[0].AllowedWheels, ",") != "Beta,Gamma" {
				t.Fatalf("M4=%+v", m)
			}
		}
		if len(m.Slots) != want {
			t.Fatal("slots", m)
		}
	}
}

func TestRealHistoricalTransform(t *testing.T) {
	path, err := filepath.Abs("../../../target/release/enigma")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("release engine absent")
	} else if err != nil {
		t.Fatal(err)
	}
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
	// CryptoCellar 1941-07-05 Nr.101, sourced in crates/enigma-cli/tests/historical_vectors.rs.
	body := `{"model":"enigma-i","reflector":"B","slots":[{"id":"left","wheel":"III","ring":"W","position":"A"},{"id":"middle","wheel":"V","ring":"H","position":"I"},{"id":"right","wheel":"IV","ring":"J","position":"K"}],"plugboard":[["B","I"],["C","W"],["E","Q"],["F","X"],["H","Z"],["J","N"],["K","Y"],["M","T"],["O","V"],["P","R"]],"text":"sud"}`
	for _, tc := range []struct {
		text     string
		status   int
		expected string
	}{{strings.Replace(body, `"sud"`, `"SUD"`, 1), 200, `"output":"WER"`}, {body, 422, `symbol 's' is not in the machine alphabet`}, {strings.Replace(body, `"sud"`, `"SU D!"`, 1), 422, `"code":"invalid_text"`}} {
		r := httptest.NewRequest("POST", "/api/transform", strings.NewReader(tc.text))
		r.Host = u.Host
		r.Header.Set("Origin", "http://"+u.Host)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.expected) {
			t.Fatalf("historical: %d %s", w.Code, w.Body.String())
		}
	}
}
