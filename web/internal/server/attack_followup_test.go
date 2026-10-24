package server_test

import (
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Review R4-client-io-lock: a slow request body must not block status polling.
func TestAttackBodyReadDoesNotBlockStatus(t *testing.T) {
	s, u, c, _ := configureAttack(t, "exit 0")
	body, writer := io.Pipe()
	r := httptest.NewRequest("POST", "/api/attack", body)
	r.Host = u.Host
	r.Header.Set("Origin", "http://"+u.Host)
	r.AddCookie(c)
	posted := make(chan struct{})
	go func() {
		s.ServeHTTP(httptest.NewRecorder(), r)
		close(posted)
	}()
	time.Sleep(50 * time.Millisecond)
	polled := make(chan struct{})
	go func() {
		attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
		close(polled)
	}()
	select {
	case <-polled:
	case <-time.After(time.Second):
		t.Error("GET /api/attack waited for another request's body")
	}
	writer.Close()
	<-posted
	<-polled
}

// Review R4-resume-launch-rollback: a resume that cannot launch keeps the
// attack resumable, with its run count and file numbering unchanged.
func TestResumeLaunchFailureKeepsAttackResumable(t *testing.T) {
	script := `case "$*" in
'--events - --request request.json --resume checkpoint.json --cancel-file cancel-2 --threads 2 --report report-2.txt')
` + fakeStarted + fakeResult + `echo '{"event":"done","reason":"completed"}'; exit;;
esac
` + fakeStarted + `while [ ! -f cancel-1 ]; do sleep 0.01; done
printf checkpoint > checkpoint.json
` + fakeResult + `echo '{"event":"done","reason":"cancelled"}'
`
	s, u, c, dir := configureAttack(t, script)
	body := strings.TrimSuffix(attackForm, "}") + `,"settings":{"threads":2}}`
	attackCall(t, s, u, c, "POST", "/api/attack", body, 202, "")
	attackCall(t, s, u, c, "POST", "/api/attack/cancel", "", 202, "")
	waitAttack(t, s, u, c, "cancelled", 5*time.Second)
	engine := filepath.Join(dir, "engine")
	if err := os.Chmod(engine, 0o600); err != nil {
		t.Fatal(err)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/resume", "", 500, "internal_error")
	v := attackCall(t, s, u, c, "GET", "/api/attack", "", 200, "")
	if v.Status != "cancelled" || !v.Resumable || v.Runs != 1 || v.Error == nil || v.Error.Code != "engine_failed" {
		t.Fatalf("after failed resume: %+v error=%+v", v, v.Error)
	}
	if err := os.Chmod(engine, 0o700); err != nil {
		t.Fatal(err)
	}
	attackCall(t, s, u, c, "POST", "/api/attack/resume", "", 202, "")
	if v = waitAttack(t, s, u, c, "completed", 5*time.Second); v.Runs != 2 || v.Error != nil {
		t.Fatalf("resume after fix: %+v", v)
	}
}
