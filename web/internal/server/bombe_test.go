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

func TestBombeRejectsBeforeLaunch(t *testing.T) {
	s, u, c, dir := configureAttack(t, fakeStarted+fakeResult+`echo '{"event":"done","reason":"completed"}'`)
	attackCall(t, s, u, c, "POST", "/api/attack", attackForm, 202, "")
	before := waitAttack(t, s, u, c, "completed", 5*time.Second)
	entries, _ := os.ReadDir(filepath.Join(dir, "attacks"))
	for _, tc := range []struct{ settings, code, field, message string }{
		{`"method":"bombe","crib":"Z","backend":"gpu"`, "backend_unavailable", "settings/backend", "The crib attack runs on the CPU only."},
		{`"method":"bombe","crib":"!"`, "invalid_settings", "settings/crib", "Invalid attack setting."},
		{`"method":"bombe","crib":"h e"`, "invalid_settings", "settings/crib", "Invalid attack setting."},
		{`"method":"bombe","crib":"Z","crib_position":-1`, "invalid_settings", "settings/crib_position", "Invalid attack setting."},
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
				t.Fatal("rejection mutated stored attack")
			}
		}
	}
}

func TestBombeResumeRejectsGPU(t *testing.T) {
	s, u, c, _ := configureAttack(t, fakeStarted+`printf checkpoint > checkpoint.json
`+fakeResult+`echo '{"event":"done","reason":"cancelled"}'`)
	body := strings.TrimSuffix(attackForm, "}") + `,"settings":{"method":"bombe","crib":"Z"}}`
	attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
	before := waitAttack(t, s, u, c, "cancelled", 5*time.Second)
	attackCall(t, s, u, c, "POST", "/api/attack/resume", `{"backend":"gpu"}`, 400, "backend_unavailable")
	if after := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, ""); !reflect.DeepEqual(before, after) {
		t.Fatal("GPU resume changed stored state")
	}
	attackCall(t, s, u, c, "POST", "/api/attack/resume", `{"backend":"cpu"}`, 202, "")
	waitAttack(t, s, u, c, "cancelled", 5*time.Second)
}

func TestRealBombeAttack(t *testing.T) {
	path := realEnginePath(t)
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
	body := `{"model":"enigma-i","reflector":"B","slots":[{"id":"left","wheel":"I","ring":"A","position":"A"},{"id":"middle","wheel":"II","ring":"A","position":"A"},{"id":"right","wheel":"III","ring":"A","position":null}],"plugboard":{"known":[],"search":false},"text":"ILBDA","settings":{"method":"bombe","crib":"HELLO","crib_position":0,"threads":1,"stages":[]}}`
	preview(t, body)
	attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
	v := waitAttack(t, s, u, c, "completed", 10*time.Second)
	var result struct {
		Crib struct {
			Text            string
			Positions       []string
			Settings, Stops string
		}
		Best struct {
			Plaintext string
			Position  string `json:"crib_position"`
		}
	}
	if err := json.Unmarshal(v.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Crib.Text != "HELLO" || !reflect.DeepEqual(result.Crib.Positions, []string{"0"}) || result.Crib.Settings != "26" || result.Crib.Stops != "1" || result.Best.Plaintext != "HELLO" || result.Best.Position != "0" || v.Runs != 1 || v.Stderr != "Report \"report-1.txt\" saved successfully in "+v.Directory+"\n" {
		t.Fatalf("result: %s stderr=%s", v.Result, v.Stderr)
	}
	reloaded, ru, rc := engineServer(t, filepath.Join(filepath.Dir(filepath.Dir(v.Directory)), "config.json"))
	if got := attackCall(t, reloaded, ru, rc, "GET", "/api/attack", "", 200, ""); !reflect.DeepEqual(got, v) {
		t.Fatal("restart lost crib result")
	}
}
