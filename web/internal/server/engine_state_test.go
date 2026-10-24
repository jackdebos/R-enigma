package server_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEngineRememberedStartupAndSaves(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	counter := filepath.Join(dir, "counter")
	good := engineScript(t, dir, "good", "echo run >> '"+counter+"'\n"+goodVersion, 0700)
	if err := os.WriteFile(config, []byte(pathBody(good)), 0600); err != nil {
		t.Fatal(err)
	}
	s, u, c := engineServer(t, config)
	count := func(want int) {
		t.Helper()
		data, err := os.ReadFile(counter)
		if err != nil || strings.Count(string(data), "run\n") != want {
			t.Fatalf("probe count want %d: %q %v", want, data, err)
		}
	}
	count(1)
	initial := engineRequest(t, s, u, c, "GET", "", 200, "")
	for i := 0; i < 3; i++ {
		if got := engineRequest(t, s, u, c, "GET", "", 200, ""); !reflect.DeepEqual(got, initial) {
			t.Fatal("state changed")
		}
	}
	if path, err := s.ValidatedEnginePath(context.Background()); err != nil || path != good {
		t.Fatalf("path=%q err=%v", path, err)
	}
	count(1)
	// Disk edits are not observed until a restart or successful save.
	if err := os.WriteFile(config, []byte("invalid config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := engineRequest(t, s, u, c, "GET", "", 200, ""); !reflect.DeepEqual(got, initial) {
		t.Fatal("disk edit changed remembered state")
	}
	engineRequest(t, s, u, c, "POST", pathBody(good), 400, "not_enigma")
	if got := engineRequest(t, s, u, c, "GET", "", 200, ""); !reflect.DeepEqual(got, initial) {
		t.Fatal("failed POST changed remembered state")
	}
	if data, err := os.ReadFile(config); err != nil || string(data) != "invalid config" {
		t.Fatalf("failed POST changed config: %q %v", data, err)
	}
	second := engineScript(t, dir, "second", goodVersion, 0700)
	engineRequest(t, s, u, c, "POST", pathBody(second), 200, "")
	if got := engineRequest(t, s, u, c, "GET", "", 200, ""); got.Path != second || !got.Compatible {
		t.Fatalf("successful POST did not switch state: %+v", got)
	}
	if data, err := os.ReadFile(config); err != nil || strings.TrimSpace(string(data)) != pathBody(second) {
		t.Fatalf("save: %q %v", data, err)
	}
	if path, err := s.ValidatedEnginePath(context.Background()); err != nil || path != second {
		t.Fatalf("switched path=%q err=%v", path, err)
	}
}

func TestEngineReadsDoNotWaitForPostProbe(t *testing.T) {
	dir := t.TempDir()
	s, u, c := engineServer(t, filepath.Join(dir, "config.json"))
	good := engineScript(t, dir, "good", goodVersion, 0700)
	engineRequest(t, s, u, c, "POST", pathBody(good), 200, "")
	marker := filepath.Join(dir, "probing")
	slow := engineScript(t, dir, "slow", "echo probing > '"+marker+"'\nsleep 2\n"+goodVersion, 0700)
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
	defer func() {
		w := <-done
		if w.Code != 200 {
			t.Errorf("POST: %d %s", w.Code, w.Body.String())
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("probe did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	got := engineRequest(t, s, u, c, "GET", "", 200, "")
	path, err := s.ValidatedEnginePath(context.Background())
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("GET/path lookup blocked for %v", elapsed)
	}
	if got.Path != good || path != good || err != nil {
		t.Fatalf("read during POST: %+v %q %v", got, path, err)
	}
}
