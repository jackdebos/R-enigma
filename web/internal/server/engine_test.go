package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"criptografia-enigma/web/internal/server"
)

type engineReply struct {
	Configured bool   `json:"configured"`
	Path       string `json:"path"`
	Version    string `json:"version"`
	Protocol   int    `json:"protocol"`
	Compatible bool   `json:"compatible"`
	Error      *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Found   *struct {
			Version  string `json:"version"`
			Protocol int    `json:"protocol"`
		} `json:"found"`
		Supported []struct {
			Version  string `json:"version"`
			Protocol int    `json:"protocol"`
		} `json:"supported"`
	} `json:"error"`
	Supported []struct {
		Version  string `json:"version"`
		Protocol int    `json:"protocol"`
	} `json:"supported"`
}

func engineServer(t *testing.T, config string) (*server.Server, *url.URL, *http.Cookie) {
	t.Helper()
	s, err := server.NewWithConfig(12345, config)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	return s, u, login(t, s, u)
}

func engineRequest(t *testing.T, s *server.Server, u *url.URL, c *http.Cookie, method, body string, status int, code string) engineReply {
	t.Helper()
	r := httptest.NewRequest(method, "/api/engine", strings.NewReader(body))
	r.Host = u.Host
	r.Header.Set("Origin", "http://"+u.Host)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", w.Header())
	}
	var reply engineReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if code == "" {
		if reply.Error != nil {
			t.Fatalf("error: %+v", reply.Error)
		}
	} else if reply.Error == nil || reply.Error.Code != code || reply.Error.Message == "" || reply.Compatible {
		t.Fatalf("error response: %+v", reply)
	}
	if len(reply.Supported) != 1 || reply.Supported[0].Version != "0.1.0" || reply.Supported[0].Protocol != 1 {
		t.Fatalf("supported: %+v", reply.Supported)
	}
	return reply
}

func engineScript(t *testing.T, dir, name, script string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
func pathBody(path string) string {
	b, _ := json.Marshal(map[string]string{"path": path})
	return string(b)
}

const goodVersion = "[ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 9\nprintf 'enigma 0.1.0\\nprotocol version 1\\n'"

func TestEnginePersistenceAndRejectedUpdates(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config", "config.json")
	s, u, c := engineServer(t, config)
	initial := engineRequest(t, s, u, c, "GET", "", 200, "")
	if initial.Configured || initial.Path != "" || initial.Version != "" || initial.Protocol != 0 || initial.Compatible {
		t.Fatalf("initial: %+v", initial)
	}
	if path, err := s.ValidatedEnginePath(context.Background()); path != "" || err == nil {
		t.Fatalf("unconfigured path: %q %v", path, err)
	}
	good := engineScript(t, dir, "good engine", goodVersion, 0700)
	reply := engineRequest(t, s, u, c, "POST", pathBody(good), 200, "")
	if !reply.Configured || !reply.Compatible || reply.Path != good || reply.Version != "0.1.0" || reply.Protocol != 1 {
		t.Fatalf("success: %+v", reply)
	}
	validated, err := s.ValidatedEnginePath(context.Background())
	if err != nil || validated != good {
		t.Fatalf("validated path: %q %v", validated, err)
	}
	saved, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(saved, &stored); err != nil || stored.Path != good {
		t.Fatalf("stored=%s error=%v", saved, err)
	}
	for path, mode := range map[string]os.FileMode{config: 0600, filepath.Dir(config): 0700} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("permissions %s: %v", path, info.Mode())
		}
	}
	for _, body := range []string{pathBody("relative"), "{", `{}`, `null`, `{"path":2}`, `{"path":"x","extra":true}`, `{"path":"x"} {}`} {
		code := "invalid_request"
		if body == pathBody("relative") {
			code = "not_absolute"
		}
		engineRequest(t, s, u, c, "POST", body, 400, code)
		after, err := os.ReadFile(config)
		if err != nil || !bytes.Equal(saved, after) {
			t.Fatalf("rejected POST changed config: %s %v", after, err)
		}
		got := engineRequest(t, s, u, c, "GET", "", 200, "")
		if got.Path != good || !got.Compatible {
			t.Fatalf("saved path lost: %+v", got)
		}
	}
	reloaded, ru, rc := engineServer(t, config)
	got := engineRequest(t, reloaded, ru, rc, "GET", "", 200, "")
	if got.Path != good || !got.Compatible {
		t.Fatalf("reload: %+v", got)
	}
	// Replace the file with incompatible output, then remove it: GET must revalidate.
	if err := os.WriteFile(good, []byte("#!/bin/sh\nprintf 'enigma 0.2.0\\nprotocol version 1\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	engineRequest(t, reloaded, ru, rc, "GET", "", 200, "unsupported_version")
	if err := os.Remove(good); err != nil {
		t.Fatal(err)
	}
	missing := engineRequest(t, reloaded, ru, rc, "GET", "", 200, "not_found")
	if !missing.Configured || missing.Path != good {
		t.Fatalf("missing saved path: %+v", missing)
	}
	if path, err := reloaded.ValidatedEnginePath(context.Background()); path != "" || err == nil {
		t.Fatalf("disappeared path: %q %v", path, err)
	}
}

func TestEngineValidationErrors(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ name, path, code string }{
		{"relative", "enigma", "not_absolute"},
		{"missing", filepath.Join(dir, "absent"), "not_found"},
		{"directory", dir, "not_executable"},
		{"permissions", engineScript(t, dir, "not-executable", goodVersion, 0600), "not_executable"},
		{"wrong", engineScript(t, dir, "wrong", "echo something-else", 0700), "not_enigma"},
		{"nonzero", engineScript(t, dir, "nonzero", goodVersion+"\nexit 1", 0700), "not_enigma"},
		{"extra-line", engineScript(t, dir, "extra", goodVersion+"\necho extra", 0700), "not_enigma"},
		{"old", engineScript(t, dir, "old", "printf 'enigma 0.0.9\\nprotocol version 1\\n'", 0700), "unsupported_version"},
		{"new", engineScript(t, dir, "new", "printf 'enigma 0.2.0\\nprotocol version 1\\n'", 0700), "unsupported_version"},
		{"protocol", engineScript(t, dir, "protocol", "printf 'enigma 0.1.0\\nprotocol version 2\\n'", 0700), "unsupported_version"},
		{"bounded", engineScript(t, dir, "bounded", "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done", 0700), "not_enigma"},
		{"timeout", engineScript(t, dir, "timeout", "exec sleep 7", 0700), "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "config.json")
			s, u, c := engineServer(t, config)
			start := time.Now()
			reply := engineRequest(t, s, u, c, "POST", pathBody(tc.path), 400, tc.code)
			if time.Since(start) > 6500*time.Millisecond {
				t.Fatal("validation exceeded bounded deadline")
			}
			if tc.code == "unsupported_version" && (reply.Error.Found == nil || len(reply.Error.Supported) != 1 || reply.Error.Supported[0].Version != "0.1.0" || reply.Error.Supported[0].Protocol != 1 || reply.Version == "" || reply.Protocol == 0) {
				t.Fatalf("unsupported details: %+v", reply)
			}
			if _, err := os.Stat(config); !os.IsNotExist(err) {
				t.Fatalf("failed POST saved config: %v", err)
			}
			engineRequest(t, s, u, c, "GET", "", 200, "")
		})
	}
}

func TestEngineSecurityAndMethods(t *testing.T) {
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	for _, method := range []string{"GET", "POST"} {
		if w := request(s, method, "/api/engine", u.Host, "http://"+u.Host, nil); w.Code != 401 {
			t.Fatalf("auth: %d", w.Code)
		}
		if w := request(s, method, "/api/engine", "evil.example", "http://"+u.Host, c); w.Code != 403 {
			t.Fatalf("host: %d", w.Code)
		}
	}
	if w := request(s, "POST", "/api/engine", u.Host, "http://evil.example", c); w.Code != 403 {
		t.Fatalf("origin: %d", w.Code)
	}
	w := request(s, "DELETE", "/api/engine", u.Host, "http://"+u.Host, c)
	if w.Code != 405 || w.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("method: %d %v", w.Code, w.Header())
	}
	// Existing sibling route behavior remains unchanged.
	w = request(s, "GET", "/api/status", u.Host, "", c)
	if w.Code != 200 || w.Body.String() != "{\"ok\":true}\n" {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
}

func TestEngineConfigFailures(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s, u, c := engineServer(t, config)
	engineRequest(t, s, u, c, "GET", "", 500, "internal_error")
	good := engineScript(t, dir, "good", goodVersion, 0700)
	// An existing regular file cannot be the parent directory of a config file.
	s, u, c = engineServer(t, filepath.Join(config, "child.json"))
	engineRequest(t, s, u, c, "POST", pathBody(good), 500, "internal_error")
	saved, err := os.ReadFile(config)
	if err != nil || string(saved) != "not json" {
		t.Fatalf("failed save changed existing file: %q %v", saved, err)
	}
}

func TestRealEngine(t *testing.T) {
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
	got := engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
	if !got.Compatible || got.Version != "0.1.0" || got.Protocol != 1 {
		t.Fatalf("real engine: %+v", got)
	}
}
