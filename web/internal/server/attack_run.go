package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"criptografia-enigma/web/internal/attack"
	"criptografia-enigma/web/internal/engine"
	"criptografia-enigma/web/internal/runner"
	"criptografia-enigma/web/internal/tables"
)

type attackView struct {
	ID              string          `json:"id"`
	Status          string          `json:"status"`
	CreatedAt       string          `json:"created_at"`
	Directory       string          `json:"directory"`
	Input           json.RawMessage `json:"input"`
	OuterKeys       string          `json:"outer_keys"`
	Threads         int             `json:"threads"`
	Backend         string          `json:"backend"`
	GPUUsage        int             `json:"gpu_usage"`
	EstimateSeconds float64         `json:"estimate_seconds"`
	OutersSelected  json.RawMessage `json:"outers_selected"`
	Counters        json.RawMessage `json:"counters"`
	ElapsedMS       json.RawMessage `json:"elapsed_ms"`
	Result          json.RawMessage `json:"result"`
	Error           *engine.Issue   `json:"error"`
	Stderr          string          `json:"stderr"`
	Resumable       bool            `json:"resumable"`
	Runs            int             `json:"runs"`
}

// All mutable job state, including live stderr, is protected by mu. A process
// belongs to this server only while done is non-nil, never merely by a disk PID.
type attackRun struct {
	mu         sync.Mutex
	root       string
	view       *attackView
	done       chan struct{}
	closing    bool
	checkpoint json.RawMessage
	reason     string
}

func (a *attackRun) refresh() {
	if a.view == nil {
		return
	}
	v := a.view
	info, err := os.Stat(filepath.Join(v.Directory, "checkpoint.json"))
	v.Resumable = (v.Status == "cancelled" || v.Status == "interrupted") && err == nil && info.Mode().IsRegular()
}

// state.json is the sole web-owned replaceable file. Failed temporary writes
// are deliberately left on disk; enigma-web never deletes attack artifacts.
func (a *attackRun) persist() error {
	a.refresh()
	data, err := json.Marshal(a.view)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(a.view.Directory, "state-*.tmp")
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(a.view.Directory, "state.json"))
}

func (a *attackRun) load() error {
	entries, err := os.ReadDir(a.root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		// Invalid engine config parents are reported by the engine route, as
		// before attack storage existed; they cannot contain saved attacks.
		if parent, e := os.Stat(filepath.Dir(a.root)); e == nil && !parent.IsDir() {
			return nil
		}
		return err
	}
	valid := regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
	// Newest first. A directory left by a failed start or with unreadable state
	// is skipped, never repaired, so it cannot stop enigma-web from starting.
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if !e.IsDir() || !valid.MatchString(e.Name()) {
			continue
		}
		dir := filepath.Join(a.root, e.Name())
		if err := a.loadDir(dir); err != nil {
			fmt.Fprintf(os.Stderr, "enigma-web: skipping unreadable attack %s: %v\n", dir, err)
			a.view, a.checkpoint, a.reason = nil, nil, ""
			continue
		}
		return nil
	}
	return nil
}

func (a *attackRun) loadDir(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return err
	}
	v := new(attackView)
	if err = json.Unmarshal(data, v); err != nil {
		return err
	}
	v.Directory = dir
	v.ID = filepath.Base(dir)
	v.Input, err = os.ReadFile(filepath.Join(dir, "input.json"))
	if err != nil {
		return err
	}
	if !json.Valid(v.Input) {
		return errors.New("invalid saved attack input")
	}
	a.view = v
	savedCounters, savedElapsed := v.Counters, v.ElapsedMS
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err == nil {
		scanner := eventScanner(f)
		terminal, started, result := false, false, false
		for scanner.Scan() {
			var event struct{ Event string }
			_ = json.Unmarshal(scanner.Bytes(), &event)
			if event.Event == "started" {
				terminal, started, result = false, false, false
			}
			// The persisted status is authoritative; replay restores observations.
			if _, err := a.observe(scanner.Bytes(), &terminal, &started, &result); err != nil {
				break
			}
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	// Legacy logs may contain progress older than the saved resumed run.
	var saved, replayed string
	_ = json.Unmarshal(savedElapsed, &saved)
	_ = json.Unmarshal(v.ElapsedMS, &replayed)
	savedMS, savedErr := strconv.ParseUint(saved, 10, 64)
	replayedMS, replayedErr := strconv.ParseUint(replayed, 10, 64)
	if savedErr == nil && replayedErr == nil && savedMS > replayedMS {
		v.Counters, v.ElapsedMS = savedCounters, savedElapsed
	}
	if v.Status == "running" {
		v.Status = "interrupted"
		return a.persist()
	}
	a.refresh()
	return nil
}

func exclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (a *attackRun) create(body []byte, plan attack.Plan) error {
	if err := os.MkdirAll(a.root, 0700); err != nil {
		return err
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	id := time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random[:])
	dir := filepath.Join(a.root, id)
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := exclusive(filepath.Join(dir, "request.json"), plan.Request); err != nil {
		return err
	}
	for _, r := range plan.Resources {
		if r.Own == "" {
			t, ok := tables.ForMeasure(r.Measure)
			if !ok {
				return errors.New("missing built-in table")
			}
			if _, err := t.Write(dir); err != nil {
				return err
			}
		} else if err := copyOwn(dir, r); err != nil {
			return err
		}
	}
	if err := exclusive(filepath.Join(dir, "input.json"), body); err != nil {
		return err
	}
	a.view = &attackView{ID: id, Status: "running", CreatedAt: time.Now().UTC().Format(time.RFC3339), Directory: dir, Input: append(json.RawMessage(nil), body...), OuterKeys: plan.OuterKeys, Threads: plan.Threads, Backend: plan.Backend, GPUUsage: plan.GPUUsage, EstimateSeconds: plan.EstimateSeconds}
	return nil
}

func copyOwn(dir string, r attack.Resource) error {
	f, err := os.Open(r.Own)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return errors.New("own table must be a regular file of at most 64 MiB")
	}
	out, err := os.OpenFile(filepath.Join(dir, r.File), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(f, (64<<20)+1))
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if n > 64<<20 {
		return errors.New("own table exceeded 64 MiB during copy")
	}
	return closeErr
}

func (s *Server) attackEngine(w http.ResponseWriter, r *http.Request) (string, bool) {
	path, err := s.ValidatedEnginePath(r.Context())
	if err == nil {
		return path, true
	}
	code, status := "engine_incompatible", 409
	var issue *engine.Issue
	if errors.As(err, &issue) {
		if issue.Code == "not_configured" {
			code = "engine_not_configured"
		}
		if issue.Code == "internal_error" {
			code = "internal_error"
			status = 500
		}
	}
	apiIssue(w, status, code, err.Error())
	return "", false
}

func (s *Server) serveAttack(w http.ResponseWriter, r *http.Request) {
	// Read a start body before locking, so a slow client cannot block status
	// polling or the engine event reader.
	var body []byte
	var bodyErr error
	if (r.URL.Path == "/api/attack" || r.URL.Path == "/api/attack/resume") && r.Method == http.MethodPost {
		body, bodyErr = io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	}
	a := s.attacks
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/api/attack" && r.Method == http.MethodGet {
		a.reply(w, 200)
		return
	}
	allow := "POST"
	if r.URL.Path == "/api/attack" {
		allow = "GET, POST"
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", allow)
		jsonResponse(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if r.URL.Path == "/api/attack/cancel" {
		if a.done == nil {
			apiIssue(w, 409, "attack_not_running", "No attack is running.")
			return
		}
		if err := a.cancel(); err != nil {
			apiIssue(w, 500, "internal_error", err.Error())
			return
		}
		a.reply(w, 202)
		return
	}
	if a.done != nil || a.closing {
		apiIssue(w, 409, "attack_running", "An attack is already running or the server is shutting down.")
		return
	}
	resume := r.URL.Path == "/api/attack/resume"
	var plan attack.Plan
	if resume {
		a.refresh()
		if a.view == nil || !a.view.Resumable {
			apiIssue(w, 409, "attack_not_resumable", "The latest attack cannot be resumed.")
			return
		}
		if bodyErr != nil {
			apiIssue(w, 400, "invalid_request", "Expected one attack JSON object of at most 1 MiB.")
			return
		}
		options, problem := attack.DecodeBackend(bytes.NewReader(body))
		if problem == nil {
			// Old clients with no host settings retain the saved backend.
			if options.Backend == nil && a.view.Backend != "" {
				options.Backend = &a.view.Backend
			}
			if options.GPUUsage == nil && a.view.GPUUsage != 0 {
				options.GPUUsage = &a.view.GPUUsage
			}
			plan.Backend, plan.GPUUsage, problem = attack.ResolveBackend(options.Backend, options.GPUUsage)
			if problem == nil {
				input, decodeProblem := attack.Decode(bytes.NewReader(a.view.Input))
				problem = decodeProblem
				if problem == nil {
					problem = attack.ValidateReflectorBackend(input.SearchesReflector(), plan.Backend)
					if problem == nil && input.Settings.Method != nil {
						problem = attack.ValidateBackendMethod(*input.Settings.Method, plan.Backend)
					}
				}
			}
		}
		if problem != nil {
			jsonResponse(w, 400, map[string]any{"error": problem})
			return
		}
	} else {
		if bodyErr != nil {
			apiIssue(w, 400, "invalid_request", "Expected one attack JSON object of at most 1 MiB.")
			return
		}
		var problem *attack.Issue
		_, plan, problem = buildAttack(bytes.NewReader(body))
		if problem != nil {
			jsonResponse(w, 400, map[string]any{"error": problem})
			return
		}
	}
	path, ok := s.attackEngine(w, r)
	if !ok {
		return
	}
	if !resume {
		if err := a.create(body, plan); err != nil {
			apiIssue(w, 500, "internal_error", err.Error())
			return
		}
	}
	if err := a.start(path, resume, plan.Backend, plan.GPUUsage); err != nil {
		apiIssue(w, 500, "internal_error", err.Error())
		return
	}
	a.reply(w, 202)
}

func (a *attackRun) reply(w http.ResponseWriter, status int) {
	a.refresh()
	jsonResponse(w, status, map[string]any{"attack": a.view})
}
func (a *attackRun) cancel() error {
	path := filepath.Join(a.view.Directory, "cancel-"+strconv.Itoa(a.view.Runs))
	err := exclusive(path, nil)
	if os.IsExist(err) {
		info, e := os.Lstat(path)
		if e == nil && info.Mode().IsRegular() && info.Size() == 0 {
			return nil
		}
	}
	return err
}

func (a *attackRun) start(path string, resume bool, backend string, usage int) error {
	v := a.view
	if resume {
		// A resume that cannot launch leaves the attack exactly as resumable as
		// before, with its run numbering, and only reports the launch error.
		previous, checkpoint, reason := *v, a.checkpoint, a.reason
		defer func() {
			if a.done == nil && v.Status == "failed" {
				launch := v.Error
				*v, a.checkpoint, a.reason = previous, checkpoint, reason
				v.Error = launch
				_ = a.persist()
			}
		}()
	}
	v.Backend, v.GPUUsage = backend, usage
	v.Runs++
	v.Status = "running"
	v.Error = nil
	v.Stderr = ""
	v.Result = nil
	a.checkpoint = nil
	a.reason = ""
	if err := a.persist(); err != nil {
		v.Status = "failed"
		return err
	}
	n := strconv.Itoa(v.Runs)
	option := "--checkpoint"
	if resume {
		option = "--resume"
	}
	cmd := exec.Command(path, "--events", "-", "--request", "request.json", option, "checkpoint.json", "--cancel-file", "cancel-"+n, "--threads", strconv.Itoa(v.Threads), "--report", "report-"+n+".txt")
	if v.Backend == "gpu" {
		cmd.Args = append(cmd.Args, "--backend", "gpu", "--gpu-usage", strconv.Itoa(v.GPUUsage))
	}
	cmd.Dir = v.Directory
	runner.ParentDeathSignal(cmd)
	cmd.WaitDelay = 100 * time.Millisecond
	log, err := os.OpenFile(filepath.Join(v.Directory, "events.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return a.startFailed(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Close()
		return a.startFailed(err)
	}
	cmd.Stderr = &attackStderr{a: a}
	if err = cmd.Start(); err != nil {
		log.Close()
		return a.startFailed(err)
	}
	a.done = make(chan struct{})
	go a.collect(cmd, stdout, log)
	return nil
}
func (a *attackRun) startFailed(err error) error {
	a.view.Status = "failed"
	a.view.Error = &engine.Issue{Code: "engine_failed", Message: err.Error()}
	if e := a.persist(); e != nil {
		return e
	}
	return err
}

type attackStderr struct{ a *attackRun }

func (b *attackStderr) Write(p []byte) (int, error) {
	b.a.mu.Lock()
	defer b.a.mu.Unlock()
	v := b.a.view
	n := min(len(p), (64<<10)-len(v.Stderr))
	v.Stderr += string(p[:n])
	return len(p), nil
}

func eventScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), (64<<20)+1)
	// Keep the delimiter, including CRLF, so the append-only log is byte exact.
	s.Split(func(data []byte, eof bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i+1], nil
		}
		if eof && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	return s
}

// observe applies one engine event to the view and returns its name.
func (a *attackRun) observe(raw []byte, terminal, started, result *bool) (string, error) {
	var e map[string]json.RawMessage
	if json.Unmarshal(raw, &e) != nil || e == nil || *terminal {
		return "", errors.New("invalid attack event stream")
	}
	var name string
	if json.Unmarshal(e["event"], &name) != nil {
		return "", errors.New("missing event name")
	}
	v := a.view
	switch name {
	case "started":
		if *started {
			return name, errors.New("duplicate started event")
		}
		*started = true
		v.Error = nil
		if len(e["outers_selected"]) == 0 {
			return name, errors.New("missing outers_selected")
		}
		v.OutersSelected = e["outers_selected"]
	case "progress":
		if !*started || len(e["counters"]) == 0 || len(e["elapsed_ms"]) == 0 {
			return name, errors.New("invalid progress event")
		}
		v.Counters = e["counters"]
		v.ElapsedMS = e["elapsed_ms"]
	case "checkpoint":
		if !*started {
			return name, errors.New("checkpoint before started")
		}
		a.checkpoint = append(json.RawMessage(nil), raw...)
	case "result":
		if !*started || *result {
			return name, errors.New("invalid result event")
		}
		*result = true
		v.Result = append(json.RawMessage(nil), raw...)
	case "done":
		var reason string
		_ = json.Unmarshal(e["reason"], &reason)
		if !*started || !*result || (reason != "completed" && reason != "outer_slice_end" && reason != "cancelled") {
			return name, errors.New("invalid done event")
		}
		*terminal = true
		a.reason = reason
	case "error":
		var code, message string
		if json.Unmarshal(e["code"], &code) != nil || json.Unmarshal(e["message"], &message) != nil || code == "" || message == "" {
			return name, errors.New("invalid error event")
		}
		v.Error = &engine.Issue{Code: code, Message: message}
		*terminal = true
	}
	return name, nil
}

// statePersistInterval is how often a running attack saves state.json.
var statePersistInterval = 5 * time.Second

func (a *attackRun) collect(cmd *exec.Cmd, stdout io.ReadCloser, log *os.File) {
	terminal, started, result := false, false, false
	var streamErr error
	saved, saving := time.Now(), true
	scanner := eventScanner(stdout)
	for scanner.Scan() {
		raw := scanner.Bytes()
		a.mu.Lock()
		name, err := a.observe(raw, &terminal, &started, &result)
		// Valid progress only refreshes the view, which state.json saves at
		// most once per interval; every other line is logged byte for byte.
		progress := name == "progress" && err == nil
		if progress && saving && time.Since(saved) >= statePersistInterval {
			// A failed periodic save stops further ones; the final save reports.
			saving, saved = a.persist() == nil, time.Now()
		}
		a.mu.Unlock()
		if !progress {
			if _, e := log.Write(raw); e != nil {
				streamErr = e
				break
			}
		}
		if err != nil && streamErr == nil {
			streamErr = err
			_ = cmd.Process.Kill()
		}
	}
	if err := scanner.Err(); err != nil {
		streamErr = err
	}
	if streamErr != nil {
		_ = cmd.Process.Kill()
	}
	stdout.Close()
	runErr := cmd.Wait()
	closeErr := log.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.view
	if streamErr == nil {
		streamErr = closeErr
	}
	if streamErr != nil || !terminal || (runErr != nil && v.Error == nil) {
		v.Status = "failed"
		v.Error = &engine.Issue{Code: "engine_failed", Message: "Engine returned an invalid or incomplete attack stream."}
	} else if v.Error != nil {
		v.Status = "failed"
	} else {
		v.Status = "completed"
		if a.reason == "cancelled" {
			v.Status = "cancelled"
		}
	}
	if err := a.persist(); err != nil {
		v.Status = "failed"
		v.Error = &engine.Issue{Code: "internal_error", Message: fmt.Sprintf("Persist attack state: %v", err)}
	}
	close(a.done)
	a.done = nil
}

// Shutdown requests a cooperative safe stop and waits without killing the job
// when the caller's deadline expires. No new attack is accepted afterward.
func (s *Server) Shutdown(ctx context.Context) error {
	a := s.attacks
	a.mu.Lock()
	a.closing = true
	done := a.done
	if done != nil {
		if err := a.cancel(); err != nil {
			a.mu.Unlock()
			return err
		}
	}
	a.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
