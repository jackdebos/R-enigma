package server_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"criptografia-enigma/web/internal/server"
)

const progressLog = `{"event":"started","outers_selected":"26"}
{"event":"checkpoint","next_outer":"128"}
{"event":"result","best":{"plaintext":"HISTORICAL"}}
{"event":"done","reason":"completed"}
`

func TestAttackRestartKeepsNewerProgress(t *testing.T) {
	for _, tc := range []struct{ name, elapsed, counters, tail, wantElapsed, wantCounters string }{
		{"resumed", "77", "9", `{"event":"result"}` + "\n" + `{"event":"done","reason":"cancelled"}` + "\n" + `{"event":"started","outers_selected":"26"}` + "\n", "77", "9"},
		{"legacy_crash", "10", "1", "", "42", "5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			job := filepath.Join(dir, "attacks", "20261024T120000Z-12345678")
			if err := os.MkdirAll(job, 0700); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string]string{
				"state.json": `{"status":"running","counters":{"outers_completed":"` + tc.counters + `"},"elapsed_ms":"` + tc.elapsed + `"}`,
				"input.json": attackForm, "checkpoint.json": "checkpoint",
				"events.jsonl": `{"event":"started","outers_selected":"26"}` + "\n" + `{"event":"progress","counters":{"outers_completed":"5"},"elapsed_ms":"42"}` + "\n" + tc.tail,
			} {
				if err := os.WriteFile(filepath.Join(job, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
			v := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
			if v == nil || v.Status != "interrupted" || !v.Resumable || v.ElapsedMS == nil || *v.ElapsedMS != tc.wantElapsed || string(v.Counters) != `{"outers_completed":"`+tc.wantCounters+`"}` {
				t.Fatalf("restart: %+v", v)
			}
		})
	}
}

func TestAttackLogOmitsProgress(t *testing.T) {
	script := `echo '{"event":"started","outers_selected":"26"}'
echo '{"event":"progress","counters":{"outers_completed":"0"},"elapsed_ms":"1"}'
echo '{"event":"progress","counters":{"outers_completed":"5"},"elapsed_ms":"20"}'
echo '{"event":"checkpoint","next_outer":"128"}'
echo '{"event":"progress","counters":{"outers_completed":"26"},"elapsed_ms":"42"}'
echo '{"event":"result","best":{"plaintext":"HISTORICAL"}}'
echo '{"event":"done","reason":"completed"}'
`
	s, u, c, _ := configureAttack(t, script)
	attackCall(t, s, u, c, "POST", "/api/attack", attackForm, 202, "")
	v := waitAttack(t, s, u, c, "completed", 5*time.Second)
	if v.ElapsedMS == nil || *v.ElapsedMS != "42" || !strings.Contains(string(v.Counters), `"26"`) {
		t.Fatalf("view: %+v", v)
	}
	log, err := os.ReadFile(filepath.Join(v.Directory, "events.jsonl"))
	if err != nil || string(log) != progressLog {
		t.Fatalf("events: %q %v", log, err)
	}
	state, err := os.ReadFile(filepath.Join(v.Directory, "state.json"))
	if err != nil || !strings.Contains(string(state), `"elapsed_ms":"42"`) {
		t.Fatalf("state: %s %v", state, err)
	}
}

func TestAttackLogKeepsInvalidProgress(t *testing.T) {
	script := `echo '{"event":"progress","counters":{"outers_completed":"0"},"elapsed_ms":"1"}'
`
	s, u, c, _ := configureAttack(t, script)
	attackCall(t, s, u, c, "POST", "/api/attack", attackForm, 202, "")
	v := waitAttack(t, s, u, c, "failed", 5*time.Second)
	log, err := os.ReadFile(filepath.Join(v.Directory, "events.jsonl"))
	if err != nil || string(log) != `{"event":"progress","counters":{"outers_completed":"0"},"elapsed_ms":"1"}`+"\n" {
		t.Fatalf("events: %q %v", log, err)
	}
}

const runningProgress = `echo '{"event":"started","outers_selected":"26"}'
echo '{"event":"progress","counters":{"outers_completed":"7"},"elapsed_ms":"99"}'
while [ ! -f cancel-1 ]; do sleep 0.01; done
echo '{"event":"result","best":{"plaintext":"HISTORICAL"}}'
echo '{"event":"done","reason":"cancelled"}'
`

func TestAttackStatePersistsProgressWhileRunning(t *testing.T) {
	defer server.SetStatePersistInterval(0)()
	s, u, c, _ := configureAttack(t, runningProgress)
	v := attackCall(t, s, u, c, "POST", "/api/attack", attackForm, 202, "")
	path := filepath.Join(v.Directory, "state.json")
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), `"elapsed_ms":"99"`) {
			if !strings.Contains(string(data), `"status":"running"`) || !strings.Contains(string(data), `"outers_completed":"7"`) {
				t.Fatalf("state: %s", data)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state never saved progress: %s %v", data, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/cancel", "", 202, "")
	waitAttack(t, s, u, c, "cancelled", 5*time.Second)
}

func TestAttackStateWaitsForPersistInterval(t *testing.T) {
	defer server.SetStatePersistInterval(time.Hour)()
	s, u, c, _ := configureAttack(t, runningProgress)
	v := attackCall(t, s, u, c, "POST", "/api/attack", attackForm, 202, "")
	deadline := time.Now().Add(5 * time.Second)
	for {
		live := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
		if live.ElapsedMS != nil && *live.ElapsedMS == "99" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("live view never showed progress: %+v", live)
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, err := os.ReadFile(filepath.Join(v.Directory, "state.json"))
	if err != nil || strings.Contains(string(data), `"99"`) || !strings.Contains(string(data), `"status":"running"`) {
		t.Fatalf("state saved before the interval: %s %v", data, err)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/cancel", "", 202, "")
	waitAttack(t, s, u, c, "cancelled", 5*time.Second)
}
