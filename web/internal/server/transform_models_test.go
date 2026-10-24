package server_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransformRevalidatesSavedEngine(t *testing.T) {
	dir := t.TempDir()
	s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
	path := engineScript(t, dir, "engine", goodVersion, 0700)
	engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'enigma 0.2.0\\nprotocol version 1\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/transform", strings.NewReader(form))
	r.Host = u.Host
	r.Header.Set("Origin", "http://"+u.Host)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"engine_incompatible"`) {
		t.Fatalf("incompatible: %d %s", w.Code, w.Body.String())
	}
	got := engineRequest(t, s, u, c, "GET", "", 200, "unsupported_version")
	if got.Path != path {
		t.Fatal("saved engine changed")
	}
}

func TestTransformNavalModels(t *testing.T) {
	for _, model := range []string{"enigma-m3", "enigma-m4"} {
		t.Run(model, func(t *testing.T) {
			dir := t.TempDir()
			s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
			// A fake engine rejects any incorrect bundled ID, Greek placement or thin reflector.
			check := `grep -q '"id":"` + model + `"' || exit 8`
			if model == "enigma-m4" {
				check = `grep -q '"id":"reflector","wheel":"Thin-C","ring":"A","position":"A"},{"id":"greek","wheel":"Gamma","ring":"Z","position":"B"}' || exit 8`
			}
			script := "if [ \"$1\" = --version ]; then printf 'enigma 0.1.0\\nprotocol version 1\\n'; exit; fi\n" + check + "\nprintf '%s\\n' '" + successEvents + "'"
			path := engineScript(t, dir, "engine", script, 0700)
			engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
			body := strings.Replace(form, "enigma-i", model, 1)
			body = strings.Replace(body, `"wheel":"I"`, `"wheel":"VIII"`, 1)
			if model == "enigma-m4" {
				body = strings.Replace(body, `"reflector":"B"`, `"reflector":"Thin-C"`, 1)
				body = strings.Replace(body, `"slots":[`, `"slots":[{"id":"greek","wheel":"Gamma","ring":"Z","position":"B"},`, 1)
			}
			r := httptest.NewRequest("POST", "/api/transform", strings.NewReader(body))
			r.Host = u.Host
			r.Header.Set("Origin", "http://"+u.Host)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"output":"XYZ"`) {
				t.Fatalf("model: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
