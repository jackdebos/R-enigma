// Package engine validates the separately installed Enigma CLI and stores its path.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Version is an exact supported engine/protocol pair, not a minimum version.
type Version struct {
	Version  string `json:"version"`
	Protocol int    `json:"protocol"`
}

// This is the single compatibility list. Update only after testing the new engine.
var supported = [...]Version{{Version: "0.3.0", Protocol: 1}}

// Issue is a stable machine-readable failure with a short user-facing explanation.
type Issue struct {
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Found     *Version  `json:"found,omitempty"`
	Supported []Version `json:"supported,omitempty"`
}

func (e *Issue) Error() string { return e.Message }

// State describes either the saved engine or a candidate submitted for validation.
type State struct {
	Configured bool      `json:"configured"`
	Path       string    `json:"path"`
	Version    string    `json:"version"`
	Protocol   int       `json:"protocol"`
	Compatible bool      `json:"compatible"`
	Error      *Issue    `json:"error"`
	Supported  []Version `json:"supported"`
}

// SupportedVersions returns an independent copy of the exact compatibility list.
func SupportedVersions() []Version { return append([]Version(nil), supported[:]...) }

func blank(path string) State {
	return State{Configured: path != "", Path: path, Supported: SupportedVersions()}
}
func failure(s State, code, message string) State {
	s.Compatible = false
	s.Error = &Issue{Code: code, Message: message}
	return s
}

var versionOutput = regexp.MustCompile(`\Aenigma ([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\nprotocol version ([0-9]+)\n?\z`)

// limitedOutput stops excessive stdout without retaining unbounded process output.
type limitedOutput struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	overflow bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > 4096-b.buffer.Len() {
		b.overflow = true
		b.cancel()
		return 0, errors.New("version output exceeds limit")
	}
	return b.buffer.Write(p)
}

// Validate executes only the absolute candidate, directly with --version, for at
// most five seconds. Validation is a compatibility check, not a binary sandbox.
func Validate(ctx context.Context, path string) State {
	s := blank(path)
	if !filepath.IsAbs(path) {
		return failure(s, "not_absolute", "Choose an absolute path to the Enigma executable.")
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return failure(s, "not_found", "The engine file does not exist.")
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return failure(s, "not_executable", "The path must name a regular executable file.")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := &limitedOutput{cancel: cancel}
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	// Descendants must not hold the version probe open after its process exits.
	cmd.WaitDelay = 100 * time.Millisecond
	err = cmd.Run()
	if out.overflow {
		return failure(s, "not_enigma", "The engine returned excessive version output.")
	}
	if ctx.Err() != nil {
		return failure(s, "timeout", "The engine version check timed out.")
	}
	if err != nil {
		return failure(s, "not_enigma", "The engine did not complete its version check successfully.")
	}
	match := versionOutput.FindStringSubmatch(out.buffer.String())
	if match == nil {
		return failure(s, "not_enigma", "The file did not return the expected Enigma version output.")
	}
	protocol, err := strconv.Atoi(match[2])
	if err != nil {
		return failure(s, "not_enigma", "The engine returned an invalid protocol version.")
	}
	s.Version, s.Protocol = match[1], protocol
	found := Version{Version: s.Version, Protocol: s.Protocol}
	for _, v := range supported {
		if found == v {
			s.Compatible = true
			return s
		}
	}
	s = failure(s, "unsupported_version", "This engine version and protocol are not supported.")
	s.Error.Found = &found
	s.Error.Supported = append([]Version(nil), supported[:]...)
	return s
}

// Store remembers the startup validation and successful saves. Version probes
// serialize with other saves, never with remembered-state readers.
type Store struct {
	path   string
	postMu sync.Mutex
	mu     sync.RWMutex
	state  State
}

// NewStore loads and validates the saved engine once, before serving requests.
// Configuration/probe failures remain visible as state rather than preventing startup.
func NewStore(path string) *Store {
	s := &Store{path: path}
	s.state = s.load(context.Background())
	return s
}

// DefaultConfigPath locates the per-user JSON file without creating it.
func DefaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "enigma-web", "config.json"), nil
}

// Get returns the remembered result without disk access or a version probe.
func (s *Store) Get(_ context.Context) State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.state
	state.Supported = append([]Version(nil), state.Supported...)
	if state.Error != nil {
		issue := *state.Error
		issue.Supported = append([]Version(nil), issue.Supported...)
		if issue.Found != nil {
			found := *issue.Found
			issue.Found = &found
		}
		state.Error = &issue
	}
	return state
}

func (s *Store) load(ctx context.Context) State {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return blank("")
	}
	if err != nil {
		return failure(blank(""), "internal_error", "Could not read the engine configuration.")
	}
	var config struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(data, &config); err != nil || config.Path == "" {
		return failure(blank(""), "internal_error", "The engine configuration is invalid.")
	}
	return Validate(ctx, config.Path)
}

// ValidatedPath uses the remembered startup/save result. Executing a changed or
// missing engine is left to the job process boundary. Unconfigured returns an issue.
func (s *Store) ValidatedPath(ctx context.Context) (string, error) {
	state := s.Get(ctx)
	if state.Error != nil {
		return "", state.Error
	}
	if !state.Configured {
		return "", &Issue{Code: "not_configured", Message: "Choose an Enigma executable first."}
	}
	return state.Path, nil
}

// Set validates before any persistence; rejected candidates never alter config.
func (s *Store) Set(ctx context.Context, path string) State {
	s.postMu.Lock()
	defer s.postMu.Unlock()
	state := Validate(ctx, path)
	if !state.Compatible {
		return state
	}
	if err := s.save(path); err != nil {
		return failure(state, "internal_error", "Could not save the engine configuration.")
	}
	s.mu.Lock()
	s.state = state
	s.mu.Unlock()
	return state
}

func (s *Store) save(path string) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(struct {
		Path string `json:"path"`
	}{path})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.path)
}
