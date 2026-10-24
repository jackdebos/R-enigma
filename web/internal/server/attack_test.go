package server_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"criptografia-enigma/web/internal/tables"
)

const attackForm = `{"model":"enigma-m4","reflector":"Thin-B","slots":[{"id":"greek","wheel":"Beta","ring":"A","position":"V"},{"id":"left","wheel":"II","ring":"A","position":"J"},{"id":"middle","wheel":"IV","ring":"A","position":"N"},{"id":"right","wheel":"I","ring":"V","position":null}],"plugboard":{"known":[],"search":true},"text":"ABC"}`

type previewReply struct {
	Request   json.RawMessage                                `json:"request"`
	OuterKeys string                                         `json:"outer_keys"`
	Threads   int                                            `json:"threads"`
	Estimate  float64                                        `json:"estimate_seconds"`
	Resources []struct{ Measure, File, Builtin, Own string } `json:"resources"`
	Error     *struct{ Code, Message, Field string }         `json:"error"`
}

func preview(t *testing.T, body string) previewReply {
	t.Helper()
	s, u, c := engineServer(t, filepath.Join(t.TempDir(), "config.json"))
	r := httptest.NewRequest("POST", "/api/attack/preview", strings.NewReader(body))
	r.Host = u.Host
	r.Header.Set("Origin", "http://"+u.Host)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	var p previewReply
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Error != nil || len(p.Request) == 0 || p.OuterKeys != "26" || p.Threads < 1 || p.Estimate <= 0 || len(p.Resources) != 1 || p.Resources[0].Builtin != "enigma1941-trigram" {
		t.Fatalf("preview: %s", w.Body.String())
	}
	// Preview never configures an engine or creates saved state.
	if state := engineRequest(t, s, u, c, "GET", "", 200, ""); state.Configured {
		t.Fatal("preview configured engine")
	}
	return p
}

func TestAttackPreview(t *testing.T) { preview(t, attackForm) }

func TestAttackPreviewValidationAndSecurity(t *testing.T) {
	dir := t.TempDir()
	s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
	missing, _ := json.Marshal(filepath.Join(dir, "missing.json"))
	for _, tc := range []struct{ body, code, field string }{
		{"{", "invalid_request", ""},
		{strings.Replace(attackForm, "enigma-m4", "unknown", 1), "unknown_model", "model"},
		{strings.TrimSuffix(attackForm, "}") + `,"settings":{"tables":{"sinkov_trigram":` + string(missing) + `}}}`, "invalid_settings", "settings/tables/sinkov_trigram"},
		{strings.Replace(attackForm, `"ABC"`, `"`+strings.Repeat("A", 1<<20)+`"`, 1), "invalid_request", ""},
	} {
		r := httptest.NewRequest("POST", "/api/attack/preview", strings.NewReader(tc.body))
		r.Host = u.Host
		r.Header.Set("Origin", "http://"+u.Host)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var p previewReply
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		if w.Code != 400 || p.Error == nil || p.Error.Code != tc.code || p.Error.Field != tc.field || p.Error.Message == "" {
			t.Fatalf("rejection: %d %s", w.Code, w.Body.String())
		}
		if state := engineRequest(t, s, u, c, "GET", "", 200, ""); state.Configured {
			t.Fatal("rejection configured engine")
		}
	}
	for _, tc := range []struct {
		method, host, origin string
		cookie               bool
		status               int
	}{
		{"GET", u.Host, "", true, 405}, {"POST", u.Host, "http://" + u.Host, false, 401},
		{"POST", "evil.example", "http://" + u.Host, true, 403}, {"POST", u.Host, "http://evil.example", true, 403},
	} {
		cookie := c
		if !tc.cookie {
			cookie = nil
		}
		w := request(s, tc.method, "/api/attack/preview", tc.host, tc.origin, cookie)
		if w.Code != tc.status || tc.status == 405 && w.Header().Get("Allow") != "POST" {
			t.Fatalf("guard: %d %v", w.Code, w.Header())
		}
	}
}

func TestAttackPreviewOwnTables(t *testing.T) {
	dir := t.TempDir()
	s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
	for _, tc := range []struct {
		name   string
		size   int64
		status int
	}{{"small", 2, 200}, {"limit", 64 << 20, 200}, {"oversized", (64 << 20) + 1, 400}, {"directory", -1, 400}} {
		t.Run(tc.name, func(t *testing.T) {
			path := dir
			if tc.size >= 0 {
				path = filepath.Join(dir, tc.name+".json")
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(tc.size); err != nil {
					f.Close()
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			encoded, _ := json.Marshal(path)
			body := strings.TrimSuffix(attackForm, "}") + `,"settings":{"tables":{"sinkov_trigram":` + string(encoded) + `}}}`
			r := httptest.NewRequest("POST", "/api/attack/preview", strings.NewReader(body))
			r.Host = u.Host
			r.Header.Set("Origin", "http://"+u.Host)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			var p previewReply
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status {
				t.Fatalf("own table: %d %s", w.Code, w.Body.String())
			}
			if tc.status == 200 {
				if p.Error != nil || len(p.Resources) != 1 || p.Resources[0].Own != path || p.Resources[0].Builtin != "" || p.Resources[0].File != "own-sinkov_trigram.json" {
					t.Fatalf("resources: %s", w.Body.String())
				}
			} else if p.Error == nil || p.Error.Code != "invalid_settings" || p.Error.Field != "settings/tables/sinkov_trigram" {
				t.Fatalf("issue: %s", w.Body.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
				t.Fatalf("preview wrote config: %v", err)
			}
		})
	}
}

func TestRealHistoricalAttackPreview(t *testing.T) {
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
	p := preview(t, strings.Replace(attackForm, `"ABC"`, string(text), 1))
	dir := t.TempDir()
	table, ok := tables.ForMeasure("sinkov_trigram")
	if !ok {
		t.Fatal("missing builtin")
	}
	if _, err := table.Write(dir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--events", "-", "--request", "-")
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(p.Request)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("engine: %v stderr=%s stdout=%s", err, &stderr, out)
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	result, done := false, false
	for scanner.Scan() {
		var e struct {
			Event, Reason string
			Best          *struct {
				Plaintext     string
				Configuration struct {
					Slots []struct{ ID, Position string }
				}
			}
		}
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if done {
			t.Fatal("event after done")
		}
		if e.Event == "result" {
			if e.Best == nil || e.Best.Plaintext != expected.Plaintext {
				t.Fatalf("wrong plaintext: %s", scanner.Bytes())
			}
			right := ""
			for _, slot := range e.Best.Configuration.Slots {
				if slot.ID == "right" {
					right = slot.Position
				}
			}
			if right != "A" {
				t.Fatalf("right=%q", right)
			}
			result = true
		}
		if e.Event == "done" {
			if e.Reason != "completed" {
				t.Fatalf("reason=%s", e.Reason)
			}
			done = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !result || !done {
		t.Fatalf("incomplete stream: %s", out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected engine files: %v %v", entries, err)
	}
}
