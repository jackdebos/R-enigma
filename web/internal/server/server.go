// Package server serves the local Enigma web interface.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"criptografia-enigma/web/internal/engine"
	"criptografia-enigma/web/static"
)

// Server holds the authentication secret for one run and its bound port.
type Server struct {
	token   string
	cookie  string
	hosts   [2]string
	files   http.Handler
	engines *engine.Store
}

// New creates a handler for the actual port selected by the loopback listener.
func New(port int) (*Server, error) {
	path, err := engine.DefaultConfigPath()
	if err != nil {
		return nil, err
	}
	return NewWithConfig(port, path)
}

// NewWithConfig injects a config file location, keeping tests off user settings.
func NewWithConfig(port int, configPath string) (*Server, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid bound port: %d", port)
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	return &Server{
		token: hex.EncodeToString(secret[:]),
		// Browser cookies ignore ports, so concurrent runs need distinct names.
		cookie:  fmt.Sprintf("enigma_token_%d", port),
		hosts:   [2]string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("localhost:%d", port)},
		files:   http.FileServer(http.FS(static.Files)),
		engines: engine.NewStore(configPath),
	}, nil
}

// URL returns the one-time browser bootstrap URL for this run.
func (s *Server) URL() string {
	return "http://" + s.hosts[0] + "/?token=" + s.token
}

func (s *Server) matches(token string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// These checks precede routing, including FileServer's redirects.
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Host != s.hosts[0] && r.Host != s.hosts[1] {
		jsonResponse(w, http.StatusForbidden, map[string]string{"error": "forbidden host"})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		origin := r.Header.Get("Origin")
		if origin != "http://"+s.hosts[0] && origin != "http://"+s.hosts[1] {
			jsonResponse(w, http.StatusForbidden, map[string]string{"error": "forbidden origin"})
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
		cookie, err := r.Cookie(s.cookie)
		if err != nil || !s.matches(cookie.Value) {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if r.URL.Path == "/api/engine" {
			s.serveEngine(w, r)
			return
		}
		if r.URL.Path != "/api/status" {
			jsonResponse(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		jsonResponse(w, http.StatusOK, struct {
			OK bool `json:"ok"`
		}{true})
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" && s.matches(r.URL.Query().Get("token")) {
		w.Header().Set("Cache-Control", "no-store")
		http.SetCookie(w, &http.Cookie{
			Name: s.cookie, Value: s.token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.files.ServeHTTP(w, r)
}

// ValidatedEnginePath is the reusable job boundary; it rechecks the saved engine.
func (s *Server) ValidatedEnginePath(ctx context.Context) (string, error) {
	return s.engines.ValidatedPath(ctx)
}

func (s *Server) serveEngine(w http.ResponseWriter, r *http.Request) {
	var state engine.State
	status := http.StatusOK
	switch r.Method {
	case http.MethodGet:
		state = s.engines.Get(r.Context())
	case http.MethodPost:
		var input struct {
			Path *string `json:"path"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&input)
		if err != nil || input.Path == nil || decoder.Decode(new(any)) != io.EOF {
			jsonResponse(w, http.StatusBadRequest, engine.State{Supported: engine.SupportedVersions(), Error: &engine.Issue{Code: "invalid_request", Message: "Expected one JSON object with a string path."}})
			return
		}
		state = s.engines.Set(r.Context(), *input.Path)
		if state.Error != nil {
			status = http.StatusBadRequest
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if state.Error != nil && state.Error.Code == "internal_error" {
		status = http.StatusInternalServerError
	}
	jsonResponse(w, status, state)
}
