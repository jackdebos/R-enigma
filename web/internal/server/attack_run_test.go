package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"criptografia-enigma/web/internal/server"
	"criptografia-enigma/web/internal/tables"
)

type runView struct {
	ID, Status, Directory string
	Input                 json.RawMessage
	OuterKeys             string  `json:"outer_keys"`
	OutersSelected        *string `json:"outers_selected"`
	Counters              json.RawMessage
	ElapsedMS             *string `json:"elapsed_ms"`
	Result                json.RawMessage
	Error                 *struct{ Code, Message string }
	Stderr                string
	Resumable             bool
	Runs                  int
}

func attackCall(t *testing.T, s *server.Server, u *url.URL, c *http.Cookie, method, route, body string, status int, code string) *runView {
	t.Helper()
	r := httptest.NewRequest(method, route, strings.NewReader(body))
	r.Host = u.Host
	r.Header.Set("Origin", "http://"+u.Host)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != status || w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("%s %s: %d %s", method, route, w.Code, w.Body.String())
	}
	if code != "" && !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("expected %s: %s", code, w.Body.String())
	}
	var reply struct{ Attack *runView }
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply.Attack
}

func waitAttack(t *testing.T, s *server.Server, u *url.URL, c *http.Cookie, status string, timeout time.Duration) *runView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		v := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
		if v != nil && v.Status == status {
			return v
		}
		if v != nil && v.Status == "failed" && status != "failed" {
			t.Fatalf("failed: %+v error=%+v", v, v.Error)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waiting for %s", status)
	return nil
}

const fakeStarted = `echo '{"event":"started","outers_selected":"26"}'
echo '{"event":"progress","counters":{"outers_completed":"0"},"elapsed_ms":"1"}'
`
const fakeResult = `echo '{"event":"result","best":{"plaintext":"HISTORICAL"}}'
`

func configureAttack(t *testing.T, script string) (*server.Server, *url.URL, *http.Cookie, string) {
	t.Helper()
	dir := t.TempDir()
	s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
	prefix := "if [ \"$1\" = --version ]; then printf 'enigma 0.1.0\\nprotocol version 1\\n'; exit; fi\n"
	path := engineScript(t, dir, "engine", prefix+script, 0700)
	engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return s, u, c, dir
}

func TestAttackRunLifecycle(t *testing.T) {
	script := `case "$*" in
'--events - --request request.json --resume checkpoint.json --cancel-file cancel-2 --threads 2 --report report-2.txt')
` + fakeStarted + fakeResult + `echo '{"event":"done","reason":"completed"}'; exit;;
esac
[ "$*" = '--events - --request request.json --checkpoint checkpoint.json --cancel-file cancel-1 --threads 2 --report report-1.txt' ] || exit 8
[ -f request.json ] && [ -f input.json ] && [ -f state.json ] && [ -f enigma1941-trigram.json ] || exit 9
` + fakeStarted + `while [ ! -f cancel-1 ]; do sleep 0.01; done
printf checkpoint > checkpoint.json
` + fakeResult + `echo '{"event":"done","reason":"cancelled"}'
`
	s, u, c, dir := configureAttack(t, script)
	body := strings.TrimSuffix(attackForm, "}") + `,"settings":{"threads":2}}`
	if v := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, ""); v != nil {
		t.Fatal("expected no attack")
	}
	v := attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
	if v == nil || v.Status != "running" || v.Runs != 1 || v.Resumable || filepath.Dir(v.Directory) != filepath.Join(dir, "attacks") || !regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`).MatchString(v.ID) {
		t.Fatalf("start: %+v", v)
	}
	for _, name := range []string{"input.json", "request.json", "enigma1941-trigram.json"} {
		got, err := os.ReadFile(filepath.Join(v.Directory, name))
		if err != nil {
			t.Fatal(err)
		}
		var want []byte
		switch name {
		case "input.json":
			want = []byte(body)
		case "request.json":
			want = preview(t, body).Request
		default:
			table, _ := tables.ForMeasure("sinkov_trigram")
			want = table.Data
		}
		if string(got) != string(want) {
			t.Fatalf("%s differs", name)
		}
	}
	for _, path := range []string{filepath.Dir(v.Directory), v.Directory} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("permissions: %v %v", info, err)
		}
	}
	current := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
	if current.ID != v.ID || current.Status != "running" {
		t.Fatalf("running view: %+v", current)
	}
	attackCall(t, s, u, c, "POST", "/api/attack", body, 409, "attack_running")
	attackCall(t, s, u, c, "POST", "/api/attack/resume", "", 409, "attack_running")
	attackCall(t, s, u, c, "POST", "/api/attack/cancel", "", 202, "")
	v = waitAttack(t, s, u, c, "cancelled", 5*time.Second)
	if !v.Resumable || v.OutersSelected == nil || *v.OutersSelected != "26" || v.ElapsedMS == nil || string(v.Result) == "null" {
		t.Fatalf("cancel: %+v", v)
	}
	first, err := os.ReadFile(filepath.Join(v.Directory, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/resume", "", 202, "")
	v = waitAttack(t, s, u, c, "completed", 5*time.Second)
	if v.Runs != 2 || v.Resumable {
		t.Fatalf("resume: %+v", v)
	}
	all, err := os.ReadFile(filepath.Join(v.Directory, "events.jsonl"))
	if err != nil || !strings.HasPrefix(string(all), string(first)) || strings.Count(string(all), `"event":"started"`) != 2 {
		t.Fatalf("events: %s %v", all, err)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/cancel", "", 409, "attack_not_running")
	attackCall(t, s, u, c, "POST", "/api/attack/resume", "", 409, "attack_not_resumable")
}

func TestAttackRunFailuresAndShutdown(t *testing.T) {
	for _, tc := range []struct{ name, script, status, code string }{
		{"error", `echo '{"event":"error","code":"invalid_text","message":"exact message"}'; exit 1`, "failed", "invalid_text"},
		{"exit", fakeStarted + "exit 1", "failed", "engine_failed"},
		{"invalid", fakeStarted + "echo garbage", "failed", "engine_failed"},
		{"shutdown", fakeStarted + `while [ ! -f cancel-1 ]; do sleep 0.01; done
` + fakeResult + `echo '{"event":"done","reason":"cancelled"}'`, "cancelled", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, u, c, _ := configureAttack(t, tc.script)
			attackCall(t, s, u, c, "POST", "/api/attack", attackForm, 202, "")
			if tc.name == "shutdown" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := s.Shutdown(ctx); err != nil {
					t.Fatal(err)
				}
			}
			v := waitAttack(t, s, u, c, tc.status, 5*time.Second)
			if v.Resumable {
				t.Fatal("no checkpoint")
			}
			if tc.code != "" && (v.Error == nil || v.Error.Code != tc.code) {
				t.Fatalf("error: %+v", v.Error)
			}
			if tc.name == "error" && v.Error.Message != "exact message" {
				t.Fatal(v.Error)
			}
		})
	}
}

func TestAttackRunStartupAndGuards(t *testing.T) {
	dir := t.TempDir()
	job := filepath.Join(dir, "attacks", "20261024T120000Z-12345678")
	if err := os.MkdirAll(job, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"state.json": `{"id":"20261024T120000Z-12345678","status":"running","created_at":"2026-10-24T12:00:00Z","runs":1,"threads":2,"outer_keys":"26","estimate_seconds":1}`,
		"input.json": attackForm, "checkpoint.json": "checkpoint", "events.jsonl": `{"event":"started","outers_selected":"26"}` + "\n" + `{"event":"progress","counters":{"outers_completed":"5"},"elapsed_ms":"42"}` + "\n",
	} {
		if err := os.WriteFile(filepath.Join(job, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
	v := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
	if v == nil || v.Status != "interrupted" || !v.Resumable || v.ElapsedMS == nil || *v.ElapsedMS != "42" {
		t.Fatalf("startup: %+v", v)
	}
	data, err := os.ReadFile(filepath.Join(job, "state.json"))
	if err != nil || !strings.Contains(string(data), `"interrupted"`) {
		t.Fatalf("persist: %s %v", data, err)
	}
	for route, allow := range map[string]string{"/api/attack": "GET, POST", "/api/attack/cancel": "POST", "/api/attack/resume": "POST"} {
		w := request(s, "PUT", route, u.Host, "http://"+u.Host, c)
		if w.Code != 405 || w.Header().Get("Allow") != allow {
			t.Fatalf("method: %d %v", w.Code, w.Header())
		}
		attackCall(t, s, u, nil, "GET", route, "", 401, "")
		if w := request(s, "GET", route, "evil.example", "", c); w.Code != 403 {
			t.Fatal("host guard", w.Code)
		}
		if w := request(s, "POST", route, u.Host, "http://evil.example", c); w.Code != 403 {
			t.Fatal("origin guard", w.Code)
		}
	}
	attackCall(t, s, u, c, "POST", "/api/attack/cancel", "", 409, "attack_not_running")
	attackCall(t, s, u, c, "POST", "/api/attack/resume", "", 409, "engine_not_configured")
}

func TestAttackRunOwnTableAndText(t *testing.T) {
	s, u, c, dir := configureAttack(t, fakeStarted+fakeResult+`echo '{"event":"done","reason":"completed"}'`)
	source := filepath.Join(dir, "own.json")
	data := []byte("  {\"own\":true}\n")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(source)
	body := strings.Replace(attackForm, `"ABC"`, `"a b!"`, 1)
	body = strings.TrimSuffix(body, "}") + `,"settings":{"tables":{"sinkov_trigram":` + string(encoded) + `}}}`
	v := attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
	v = waitAttack(t, s, u, c, "completed", 5*time.Second)
	got, err := os.ReadFile(filepath.Join(v.Directory, "own-sinkov_trigram.json"))
	if err != nil || string(got) != string(data) {
		t.Fatalf("own copy: %s %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(v.Directory, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request struct{ Job struct{ Text string } }
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatal(err)
	}
	if request.Job.Text != "a b!" {
		t.Fatal("text changed")
	}
	// Shared preview validation still rejects invalid input without creating jobs.
	before, err := os.ReadDir(filepath.Join(dir, "attacks"))
	if err != nil {
		t.Fatal(err)
	}
	attackCall(t, s, u, c, "POST", "/api/attack", "{}", 400, "invalid_request")
	after, err := os.ReadDir(filepath.Join(dir, "attacks"))
	if err != nil || len(before) != len(after) {
		t.Fatal("rejected request wrote state")
	}
}

func TestRealAttackRun(t *testing.T) { realAttackRun(t, false) }
func TestRealAttackCancelResume(t *testing.T) {
	if testing.Short() {
		t.Skip("long attack")
	}
	realAttackRun(t, true)
}
func realAttackRun(t *testing.T, resume bool) {
	t.Helper()
	path, err := filepath.Abs("../../../target/release/enigma")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("release engine absent")
	} else if err != nil {
		t.Fatal(err)
	}
	query, err := os.ReadFile("../../../e2e/bomm/m4-u264-attack-design-b/query.json")
	if err != nil {
		t.Fatal(err)
	}
	var q struct{ Ciphertext string }
	if err := json.Unmarshal(query, &q); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../../e2e/bomm/m4-u264-attack-design-b/case.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct{ Plaintext string }
	if err := json.Unmarshal(fixture, &expected); err != nil {
		t.Fatal(err)
	}
	text, _ := json.Marshal(strings.ToUpper(q.Ciphertext))
	body := strings.Replace(attackForm, `"ABC"`, string(text), 1)
	if resume {
		body = strings.Replace(body, `"position":"J"`, `"position":null`, 1)
		body = strings.Replace(body, `"position":"N"`, `"position":null`, 1)
	}
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
	if resume {
		deadline := time.Now().Add(time.Minute)
		for {
			v := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
			if v.ElapsedMS != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("no progress")
			}
			time.Sleep(time.Millisecond)
		}
		attackCall(t, s, u, c, "POST", "/api/attack/cancel", "", 202, "")
		v := waitAttack(t, s, u, c, "cancelled", time.Minute)
		if !v.Resumable {
			t.Fatal("not resumable")
		}
		attackCall(t, s, u, c, "POST", "/api/attack/resume", "", 202, "")
	}
	timeout := time.Minute
	if resume {
		timeout = 5 * time.Minute
	}
	v := waitAttack(t, s, u, c, "completed", timeout)
	var result struct{ Best *struct{ Plaintext string } }
	if err := json.Unmarshal(v.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Best == nil || result.Best.Plaintext != expected.Plaintext {
		t.Fatalf("plaintext: %s", v.Result)
	}
	wantRuns := 1
	if resume {
		wantRuns = 2
	}
	if v.Runs != wantRuns {
		t.Fatal(v.Runs)
	}
	for _, name := range []string{"report-1.txt", "checkpoint.json"} {
		if _, err := os.Stat(filepath.Join(v.Directory, name)); err != nil {
			t.Fatal(err)
		}
	}
}
