package server_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A directory left by a failed start (no state.json) or with unreadable state
// must not stop enigma-web from starting; the newest readable attack is shown.
func TestStartupSkipsIncompleteAttackDirectories(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "attacks")
	valid := filepath.Join(root, "20261024T090000Z-bbbbbbbb")
	for _, d := range []string{valid, filepath.Join(root, "20261024T100000Z-aaaaaaaa"), filepath.Join(root, "20261024T110000Z-cccccccc")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := `{"id":"20261024T090000Z-bbbbbbbb","status":"completed","created_at":"2026-10-24T09:00:00Z","outer_keys":"26","threads":1,"estimate_seconds":0.1,"runs":1}`
	if err := os.WriteFile(filepath.Join(valid, "state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(valid, "input.json"), []byte(`{"model":"enigma-i"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(root, "20261024T110000Z-cccccccc", "state.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
	r := httptest.NewRequest("GET", "/api/attack", nil)
	r.Host = u.Host
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var reply struct {
		Attack *struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"attack"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Attack == nil || reply.Attack.ID != "20261024T090000Z-bbbbbbbb" || reply.Attack.Status != "completed" {
		t.Fatalf("GET /api/attack = %d %s", w.Code, w.Body.String())
	}
	if data, _ := os.ReadFile(broken); string(data) != "{" {
		t.Fatalf("unreadable state was changed: %q", data)
	}
}
