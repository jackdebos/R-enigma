package server_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"criptografia-enigma/web/internal/server"
)

func TestIndependentS15(t *testing.T) {
	for _, port := range []int{1, 79, 80, 81, 443, 8080, 65535} {
		s, err := server.NewWithConfig(port, filepath.Join(t.TempDir(), "config"))
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(s.URL())
		cookie := &http.Cookie{Name: fmt.Sprintf("enigma_token_%d", port), Value: u.Query().Get("token")}
		valid := []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("localhost:%d", port)}
		hosts := append(append([]string{}, valid...), "127.0.0.1", "localhost", "localhost.", "LOCALHOST", "127.1", "[::1]", "evil.test", "localhost:080", "localhost:80.evil", "localhost@evil", "localhost/", "")
		origins := []string{"http://" + valid[0], "http://" + valid[1], "http://127.0.0.1", "http://localhost", "", "null", "https://localhost", "http://localhost/", "http://localhost:080", "http://localhost.evil", "http://localhost@evil", "http://localhost http://evil", "http://http://localhost"}
		allowed := func(h string) bool {
			return h == valid[0] || h == valid[1] || port == 80 && (h == "localhost" || h == "127.0.0.1")
		}
		for _, host := range hosts {
			for _, origin := range origins {
				for _, auth := range []int{0, 1, 2} {
					want, body := 403, "{\"error\":\"forbidden host\"}\n"
					if allowed(host) {
						body = "{\"error\":\"forbidden origin\"}\n"
						if strings.HasPrefix(origin, "http://") && allowed(strings.TrimPrefix(origin, "http://")) {
							want, body = 401, "{\"error\":\"unauthorized\"}\n"
							if auth == 2 {
								want, body = 405, "{\"error\":\"method not allowed\"}\n"
							}
						}
					}
					var c *http.Cookie
					if auth > 0 {
						copy := *cookie
						c = &copy
						if auth == 1 {
							c.Value = "wrong"
						}
					}
					w := request(s, "POST", "/api/status?token="+cookie.Value, host, origin, c)
					if w.Code != want || w.Body.String() != body {
						t.Fatalf("port=%d host=%q origin=%q auth=%d got=%d %q want=%d %q", port, host, origin, auth, w.Code, w.Body.String(), want, body)
					}
				}
			}
		}
	}
}

func TestIndependentS14(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	count := filepath.Join(dir, "count")
	good := engineScript(t, dir, "good", "echo probe >> '"+count+"'\n"+goodVersion, 0700)
	if err := os.WriteFile(config, []byte(pathBody(good)), 0600); err != nil {
		t.Fatal(err)
	}
	s, u, c := engineServer(t, config)
	initial := engineRequest(t, s, u, c, "GET", "", 200, "")
	if data, _ := os.ReadFile(count); string(data) != "probe\n" {
		t.Fatalf("startup probes: %q", data)
	}
	// External config edits and a replaced executable must not affect either read path.
	if err := os.WriteFile(config, []byte("externally edited"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 9\n"), 0700); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(config)
	hash := sha256.Sum256(before)
	for _, tc := range []struct{ body, code string }{{"{", "invalid_request"}, {pathBody(""), "not_absolute"}, {pathBody("relative"), "not_absolute"}, {pathBody(good), "not_enigma"}} {
		engineRequest(t, s, u, c, "POST", tc.body, 400, tc.code)
		after, _ := os.ReadFile(config)
		if sha256.Sum256(after) != hash {
			t.Fatal("rejected POST modified config")
		}
		if got := engineRequest(t, s, u, c, "GET", "", 200, ""); fmt.Sprint(got) != fmt.Sprint(initial) {
			t.Fatal("changed remembered state")
		}
		if path, err := s.ValidatedEnginePath(context.Background()); path != good || err != nil {
			t.Fatalf("path %q: %v", path, err)
		}
	}
	marker := filepath.Join(dir, "probing")
	slow := engineScript(t, dir, "slow", "echo probing > '"+marker+"'\nsleep 1\nexit 7", 0700)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "/api/engine", strings.NewReader(pathBody(slow)))
		r.Host = u.Host
		r.Header.Set("Origin", "http://"+u.Host)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		done <- w
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("probe did not start")
		}
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	engineRequest(t, s, u, c, "GET", "", 200, "")
	if path, err := s.ValidatedEnginePath(context.Background()); path != good || err != nil {
		t.Fatalf("path %q: %v", path, err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("read waited behind POST")
	}
	if w := <-done; w.Code != 400 {
		t.Fatalf("POST: %d %s", w.Code, w.Body.String())
	}
	after, _ := os.ReadFile(config)
	if sha256.Sum256(after) != hash {
		t.Fatal("failed probe modified config")
	}
	next := engineScript(t, dir, "next", goodVersion, 0700)
	if os.Geteuid() != 0 {
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		engineRequest(t, s, u, c, "POST", pathBody(next), 500, "internal_error")
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(config)
		if sha256.Sum256(data) != hash {
			t.Fatal("failed save modified config")
		}
		if got := engineRequest(t, s, u, c, "GET", "", 200, ""); got.Path != good || !got.Compatible {
			t.Fatal("failed save changed state")
		}
	} else {
		t.Log("permission-denied save probe unavailable as root")
	}

	// Exercise simultaneous reads and serialized successful saves under -race.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s.ValidatedEnginePath(context.Background())
				engineRequest(t, s, u, c, "GET", "", 200, "")
			}
		}()
	}
	for i := 0; i < 4; i++ {
		engineRequest(t, s, u, c, "POST", pathBody(next), 200, "")
	}
	wg.Wait()
	if got := engineRequest(t, s, u, c, "GET", "", 200, ""); got.Path != next || !got.Compatible {
		t.Fatal("state not replaced")
	}
	if data, _ := os.ReadFile(config); strings.TrimSpace(string(data)) != pathBody(next) {
		t.Fatalf("save %q", data)
	}
	if data, _ := os.ReadFile(count); string(data) != "probe\n" {
		t.Fatalf("unexpected reprobe %q", data)
	}
}
