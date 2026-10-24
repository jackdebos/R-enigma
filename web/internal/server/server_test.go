package server_test

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"criptografia-enigma/web/internal/server"
)

func setup(t *testing.T) (*server.Server, *url.URL) {
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

func request(s *server.Server, method, target, host, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func login(t *testing.T, s *server.Server, u *url.URL) *http.Cookie {
	t.Helper()
	w := request(s, "GET", u.String(), u.Host, "", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("login: status=%d location=%q body=%q", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	c := cookies[0]
	// Browser cookies ignore ports, so each run's cookie name carries its port.
	if c.Name != "enigma_token_12345" {
		t.Fatalf("cookie name: %q", c.Name)
	}
	if c.Value != u.Query().Get("token") || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("unexpected cookie: %s", c)
	}
	return c
}

func TestTokenRedirectAndCookie(t *testing.T) {
	s, u := setup(t)
	login(t, s, u)
	b, err := hex.DecodeString(u.Query().Get("token"))
	if err != nil || len(b) != 32 {
		t.Fatalf("token: %q (%v)", u.Query().Get("token"), err)
	}
	_, other := setup(t)
	if u.String() == other.String() {
		t.Fatal("per-run tokens repeated")
	}
}

func TestStatusAuthentication(t *testing.T) {
	s, u := setup(t)
	for _, tc := range []struct {
		name, token string
		status      int
		body        string
	}{
		{"missing", "", 401, "{\"error\":\"unauthorized\"}\n"},
		{"wrong", strings.Repeat("0", 64), 401, "{\"error\":\"unauthorized\"}\n"},
		{"correct", u.Query().Get("token"), 200, "{\"ok\":true}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c *http.Cookie
			if tc.token != "" {
				c = &http.Cookie{Name: "enigma_token_12345", Value: tc.token}
			}
			w := request(s, "GET", "/api/status", u.Host, "", c)
			if w.Code != tc.status || w.Body.String() != tc.body || w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("status=%d body=%q content-type=%q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
			}
		})
	}
	w := request(s, "GET", "/api/future", u.Host, "", nil)
	if w.Code != 401 {
		t.Fatalf("unregistered API route bypassed auth: %d", w.Code)
	}
}

func TestHostAndOrigin(t *testing.T) {
	s, u := setup(t)
	for _, host := range []string{"evil.example:12345", "127.0.0.1:9999", "localhost", "127.0.0.1:12345.evil"} {
		w := request(s, "GET", "/", host, "", nil)
		if w.Code != 403 {
			t.Errorf("host %q: %d", host, w.Code)
		}
	}
	for _, host := range []string{u.Host, "localhost:12345"} {
		for _, origin := range []string{"", "http://evil.example", "http://127.0.0.1:9999", "null"} {
			w := request(s, "POST", "/api/status", host, origin, nil)
			if w.Code != 403 {
				t.Errorf("host %q origin %q: %d", host, origin, w.Code)
			}
		}
		for _, origin := range []string{"http://" + u.Host, "http://localhost:12345"} {
			// No cookie: 401 proves the Origin check passed before authentication.
			w := request(s, "POST", "/api/status", host, origin, nil)
			if w.Code != 401 {
				t.Errorf("host %q own origin %q: %d", host, origin, w.Code)
			}
		}
	}
	c := &http.Cookie{Name: "enigma_token_12345", Value: u.Query().Get("token")}
	w := request(s, "POST", "/api/status", u.Host, "http://"+u.Host, c)
	if w.Code != 405 {
		t.Fatalf("authenticated POST should reach method check: %d", w.Code)
	}
}

func TestDefaultPortHostAndOrigin(t *testing.T) {
	for _, port := range []int{80, 81, 12345, 65535} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			s, err := server.NewWithConfig(port, filepath.Join(t.TempDir(), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(s.URL())
			if u.Host != fmt.Sprintf("127.0.0.1:%d", port) {
				t.Fatal("URL changed", u)
			}
			w := request(s, "GET", u.String(), u.Host, "", nil)
			cookies := w.Result().Cookies()
			if w.Code != 303 || len(cookies) != 1 || cookies[0].Name != fmt.Sprintf("enigma_token_%d", port) {
				t.Fatal("bootstrap changed", w)
			}
			hosts := []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("localhost:%d", port)}
			for _, host := range []string{"127.0.0.1", "localhost"} {
				want := 403
				if port == 80 {
					want = 200
				}
				w := request(s, "GET", "/api/status", host, "", cookies[0])
				if w.Code != want {
					t.Errorf("host %q: %d want %d", host, w.Code, want)
				}
			}
			if port == 80 {
				hosts = append(hosts, "127.0.0.1", "localhost")
			}
			for _, host := range hosts {
				for _, origin := range []string{"http://127.0.0.1", "http://localhost", fmt.Sprintf("http://127.0.0.1:%d", port), fmt.Sprintf("http://localhost:%d", port), "", "null", "https://localhost", "http://localhost:81", "http://localhost.evil", "http://127.0.0.1/"} {
					want := 403
					if origin == fmt.Sprintf("http://127.0.0.1:%d", port) || origin == fmt.Sprintf("http://localhost:%d", port) || port == 80 && (origin == "http://localhost" || origin == "http://127.0.0.1") {
						want = 405
					}
					w := request(s, "POST", "/api/status", host, origin, cookies[0])
					if w.Code != want {
						t.Errorf("host %q origin %q: %d want %d", host, origin, w.Code, want)
					}
				}
			}
		})
	}
}

func TestStaticIndex(t *testing.T) {
	s, u := setup(t)
	for _, target := range []string{"/", "/?token=wrong"} {
		w := request(s, "GET", target, u.Host, "", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "<title>Enigma</title>") || len(w.Result().Cookies()) != 0 {
			t.Fatalf("static %s: status=%d body=%q cookies=%v", target, w.Code, w.Body.String(), w.Result().Cookies())
		}
	}
}
