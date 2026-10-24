package server_test

import (
	"criptografia-enigma/web/internal/server"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentUnchangedGuard(t *testing.T) {
	for _, port := range []int{1, 79, 81, 443, 8080, 65535} {
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
