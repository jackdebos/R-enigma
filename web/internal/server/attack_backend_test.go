package server_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Exact legacy CPU argv, GPU flags and usage boundaries.
func TestAttackBackendCommand(t *testing.T) {
	for _, tc := range []struct{ name, settings, suffix string }{
		{"legacy", `"threads":2`, ""},
		{"cpu", `"threads":2,"backend":"cpu","gpu_usage":0`, ""},
		{"gpu_default", `"threads":2,"backend":"gpu"`, " --backend gpu --gpu-usage 100"},
		{"gpu_chosen", `"threads":2,"backend":"gpu","gpu_usage":37`, " --backend gpu --gpu-usage 37"},
		{"gpu_min", `"threads":2,"backend":"gpu","gpu_usage":1`, " --backend gpu --gpu-usage 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := "--events - --request request.json --checkpoint checkpoint.json --cancel-file cancel-1 --threads 2 --report report-1.txt" + tc.suffix
			script := `[ "$*" = '` + want + `' ] || { printf '%s' "$*" >&2; exit 8; }
` + fakeStarted + fakeResult + `echo '{"event":"done","reason":"completed"}'`
			s, u, c, dir := configureAttack(t, script)
			body := strings.TrimSuffix(attackForm, "}") + `,"settings":{` + tc.settings + `}}`
			legacyPreview := preview(t, strings.TrimSuffix(attackForm, "}")+`,"settings":{"threads":2}}`)
			if got := preview(t, body); !reflect.DeepEqual(got, legacyPreview) {
				t.Fatal("host options changed engine request, key count, threads, estimate or resources")
			}
			attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
			v := waitAttack(t, s, u, c, "completed", 5*time.Second)
			if v.Runs != 1 || v.Stderr != "" || v.Error != nil {
				t.Fatalf("view: %+v", v)
			}
			// Persistence is checked through the public API after a server restart.
			reloaded, ru, rc := engineServer(t, filepath.Join(dir, "config.json"))
			saved := attackCall(t, reloaded, ru, rc, "GET", "/api/attack", "", 200, "")
			if !reflect.DeepEqual(saved, v) {
				t.Fatal("restart changed saved input or run observations")
			}
			r := httptest.NewRequest("GET", "/api/attack", nil)
			r.Host = ru.Host
			r.AddCookie(rc)
			w := httptest.NewRecorder()
			reloaded.ServeHTTP(w, r)
			var reply struct {
				Attack struct {
					Backend  string
					GPUUsage int `json:"gpu_usage"`
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			backend, usage := "cpu", 100
			if tc.suffix != "" {
				backend = "gpu"
			}
			if tc.name == "gpu_chosen" {
				usage = 37
			}
			if tc.name == "gpu_min" {
				usage = 1
			}
			if reply.Attack.Backend != backend || reply.Attack.GPUUsage != usage {
				t.Fatalf("saved host options: %+v", reply.Attack)
			}
		})
	}
}

// Preview and start reject before touching stored state.
func TestAttackBackendValidation(t *testing.T) {
	s, u, c, dir := configureAttack(t, fakeStarted+fakeResult+`echo '{"event":"done","reason":"completed"}'`)
	attackCall(t, s, u, c, "POST", "/api/attack", attackForm, 202, "")
	before := waitAttack(t, s, u, c, "completed", 5*time.Second)
	entries, _ := os.ReadDir(filepath.Join(dir, "attacks"))
	for _, tc := range []struct{ settings, field, code, message string }{
		{`"backend":"auto"`, "settings/backend", "invalid_settings", "Invalid attack setting."},
		{`"backend":""`, "settings/backend", "invalid_settings", "Invalid attack setting."},
		{`"backend":"gpu","gpu_usage":0`, "settings/gpu_usage", "invalid_settings", "Invalid attack setting."},
		{`"backend":"gpu","gpu_usage":101`, "settings/gpu_usage", "invalid_settings", "Invalid attack setting."},
		{`"backend":"gpu","gpu_usage":1.5`, "settings/gpu_usage", "invalid_request", "Missing member or invalid field type."},
	} {
		for _, route := range []string{"/api/attack/preview", "/api/attack"} {
			body := strings.TrimSuffix(attackForm, "}") + `,"settings":{` + tc.settings + `}}`
			r := httptest.NewRequest("POST", route, strings.NewReader(body))
			r.Host = u.Host
			r.Header.Set("Origin", "http://"+u.Host)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			want := `{"error":{"code":"` + tc.code + `","message":"` + tc.message + `","field":"` + tc.field + `"}}` + "\n"
			if w.Code != 400 || w.Body.String() != want {
				t.Fatalf("%s: %d %s", route, w.Code, w.Body.String())
			}
			after := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
			now, _ := os.ReadDir(filepath.Join(dir, "attacks"))
			if !reflect.DeepEqual(before, after) || len(entries) != len(now) {
				t.Fatal("rejection changed stored attack")
			}
		}
	}
}

// Resume chooses host settings without rewriting the engine request.
func TestAttackBackendResume(t *testing.T) {
	script := `case "$*" in
'--events - --request request.json --checkpoint checkpoint.json --cancel-file cancel-1 --threads 2 --report report-1.txt')
` + fakeStarted + `printf checkpoint > checkpoint.json
` + fakeResult + `echo '{"event":"done","reason":"cancelled"}';;
'--events - --request request.json --resume checkpoint.json --cancel-file cancel-2 --threads 2 --report report-2.txt --backend gpu --gpu-usage 25')
` + fakeStarted + fakeResult + `echo '{"event":"done","reason":"cancelled"}';;
'--events - --request request.json --resume checkpoint.json --cancel-file cancel-3 --threads 2 --report report-3.txt')
` + fakeStarted + fakeResult + `echo '{"event":"done","reason":"completed"}';;
*) exit 8;; esac`
	s, u, c, _ := configureAttack(t, script)
	body := strings.TrimSuffix(attackForm, "}") + `,"settings":{"threads":2}}`
	attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
	v := waitAttack(t, s, u, c, "cancelled", 5*time.Second)
	original, err := os.ReadFile(filepath.Join(v.Directory, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/resume", `{"backend":"bad"}`, 400, "invalid_settings")
	if after := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, ""); !reflect.DeepEqual(v, after) {
		t.Fatal("invalid resume mutated state")
	}
	attackCall(t, s, u, c, "POST", "/api/attack/resume", `{"backend":"gpu","gpu_usage":25}`, 202, "")
	deadline := time.Now().Add(5 * time.Second)
	for {
		v = attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
		if v.Runs == 2 && v.Status == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resume: %+v", v)
		}
		time.Sleep(10 * time.Millisecond)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/resume", `{"backend":"cpu"}`, 202, "")
	v = waitAttack(t, s, u, c, "completed", 5*time.Second)
	got, _ := os.ReadFile(filepath.Join(v.Directory, "request.json"))
	if string(got) != string(original) || v.Runs != 3 {
		t.Fatal("resume changed request or runs")
	}
}

func TestAttackBackendErrors(t *testing.T) {
	for _, tc := range []struct{ code, message string }{
		{"backend_unavailable", "GPU backend unavailable: no suitable adapter"},
		{"unsupported_job", "--backend gpu does not support this attack: text exceeds accelerator row data limit"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]string{"event": "error", "code": tc.code, "message": tc.message})
			s, u, c, _ := configureAttack(t, "echo '"+string(raw)+"'; exit 1")
			body := strings.TrimSuffix(attackForm, "}") + `,"settings":{"backend":"gpu","gpu_usage":20}}`
			attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
			v := waitAttack(t, s, u, c, "failed", 5*time.Second)
			if v.Error == nil || v.Error.Code != tc.code || v.Error.Message != tc.message || v.OutersSelected != nil || v.Runs != 1 {
				t.Fatalf("error: %+v", v)
			}
		})
	}
}
