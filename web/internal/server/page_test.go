package server_test

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"criptografia-enigma/web/internal/server"
)

func pageServer(t *testing.T) (*server.Server, *url.URL) {
	t.Helper()
	s, err := server.NewWithConfig(12345, filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	return s, u
}

func TestPageAssets(t *testing.T) {
	s, u := pageServer(t)
	for _, asset := range [][2]string{
		{"/", "text/html"},
		{"/style.css", "text/css"},
		{"/app.js", "text/javascript"},
		{"/logic.js", "text/javascript"},
		{"/i18n/es.json", "application/json"},
		{"/i18n/en.json", "application/json"},
	} {
		path, want := asset[0], asset[1]
		t.Run(path, func(t *testing.T) {
			w := request(s, "GET", path, u.Host, "", nil)
			got, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
			if w.Code != 200 || err != nil || got != want || w.Body.Len() == 0 {
				t.Fatalf("%s: status=%d type=%q body=%q", path, w.Code, got, w.Body.String())
			}
		})
	}
	for _, path := range []string{"/logic.test.mjs", "/package.json", "/embed.go"} {
		if w := request(s, "GET", path, u.Host, "", nil); w.Code != 404 {
			t.Errorf("non-page file served: %s status=%d", path, w.Code)
		}
	}
	w := request(s, "GET", "/", u.Host, "", nil)
	for _, forbidden := range []string{" style=", " onclick=", "<style", "<script>"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Errorf("inline content forbidden by CSP: %s", forbidden)
		}
	}
}

func TestPageDictionaries(t *testing.T) {
	s, u := pageServer(t)
	var keys map[string]bool
	for _, lang := range []string{"es", "en"} {
		w := request(s, "GET", "/i18n/"+lang+".json", u.Host, "", nil)
		var dict map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &dict); err != nil {
			t.Fatalf("%s: %v", lang, err)
		}
		if len(dict) == 0 {
			t.Fatal("empty dictionary")
		}
		current := map[string]bool{}
		for key, value := range dict {
			if strings.TrimSpace(value) == "" {
				t.Errorf("%s: empty %s", lang, key)
			}
			current[key] = true
		}
		if keys != nil && !reflect.DeepEqual(keys, current) {
			t.Fatal("dictionary key sets differ")
		}
		keys = current
	}
}

func TestPageSecurityHeaders(t *testing.T) {
	s, u := pageServer(t)
	cookie := login(t, s, u)
	const csp = "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	for _, tc := range []struct {
		method, path, host, origin string

		cookie *http.Cookie
	}{
		{"GET", "/", u.Host, "", nil},
		{"GET", u.String(), u.Host, "", nil},
		{"GET", "/missing", u.Host, "", nil},
		{"GET", "/", "evil.example", "", nil},
		{"GET", "/api/status", u.Host, "", nil},
		{"GET", "/api/status", u.Host, "", cookie},
		{"GET", "/api/machines", u.Host, "", cookie},
		{"POST", "/api/status", u.Host, "http://evil.example", cookie},
		{"POST", "/api/status", u.Host, "http://" + u.Host, cookie},
	} {
		w := request(s, tc.method, tc.path, tc.host, tc.origin, tc.cookie)
		if w.Header().Get("Content-Security-Policy") != csp || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s (%d): missing security headers: %v", tc.method, tc.path, w.Code, w.Header())
		}
	}
}
