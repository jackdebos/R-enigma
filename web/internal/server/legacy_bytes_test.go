package server_test

import (
	"crypto/sha256"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Pins the pre-WWII transform serialization for every existing model. The
// attack package's TestDistinctWheelsOffOriginalBytes pins the attack requests.
func TestLegacyTransformBytes(t *testing.T) {
	for _, model := range []string{"enigma-i", "enigma-m3", "enigma-m4"} {
		t.Run(model, func(t *testing.T) {
			dir := t.TempDir()
			s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
			capture := filepath.Join(dir, "request.json")
			script := "if [ \"$1\" = --version ]; then " + goodVersion + "; exit; fi\ncat > '" + capture + "'\nprintf '%s\\n' '" + successEvents + "'"
			path := engineScript(t, dir, "engine", script, 0700)
			engineRequest(t, s, u, c, "POST", pathBody(path), 200, "")
			body := strings.Replace(form, "enigma-i", model, 1)
			reflector := "B"
			greek := ""
			if model == "enigma-m4" {
				reflector = "Thin-B"
				greek = `{"id":"greek","wheel":"Beta","ring":"A","position":"A"},`
				body = strings.Replace(body, `"reflector":"B"`, `"reflector":"Thin-B"`, 1)
				body = strings.Replace(body, `"slots":[`, `"slots":[`+greek, 1)
			}
			r := httptest.NewRequest("POST", "/api/transform", strings.NewReader(body))
			r.Host = u.Host
			r.Header.Set("Origin", "http://"+u.Host)
			r.AddCookie(c)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("status: %d %s", w.Code, w.Body.String())
			}
			data, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			want := `{"job":{"configuration":{"plugboard":[],"slots":[{"id":"reflector","wheel":"` + reflector + `","ring":"A","position":"A"},` + greek + `{"id":"left","wheel":"I","ring":"A","position":"A"},{"id":"middle","wheel":"II","ring":"A","position":"A"},{"id":"right","wheel":"III","ring":"A","position":"A"}]},"direction":"encrypt","kind":"transform","text":"aZ é!?\n"},"machine":{"definition":{"id":"` + model + `","kind":"bundled"}},"protocol_version":1}`
			if string(data) != want {
				t.Fatalf("request bytes changed: %s", data)
			}
			t.Logf("request bytes=%d sha256=%x; HTTP=200 output=XYZ", len(data), sha256.Sum256(data))
		})
	}
}
