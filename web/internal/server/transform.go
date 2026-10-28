package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"slices"
	"time"

	"criptografia-enigma/web/internal/attack"
	"criptografia-enigma/web/internal/engine"
)

type catalogSlot struct {
	ID            string   `json:"id"`
	AllowedWheels []string `json:"allowed_wheels"`
}
type catalogModel struct {
	RewirableReflector bool            `json:"rewirable_reflector,omitempty"`
	ID                 string          `json:"id"`
	DefinitionID       string          `json:"definition_id"`
	Reflectors         []string        `json:"reflectors"`
	Slots              []catalogSlot   `json:"slots"`
	Plugboard          bool            `json:"plugboard"`
	SettableReflector  bool            `json:"settable_reflector,omitempty"`
	FixedSlots         []transformSlot `json:"fixed_slots,omitempty"`
}

// Sources: docs/historical-catalog.md and crates/enigma-core/catalog/*.json.
// Editable slots exclude the reflector and fixed ETW; the server inserts ETW A/A.
func machineCatalog() []catalogModel {
	var models []catalogModel
	for i, id := range []string{"enigma-i", "enigma-m3", "enigma-m4"} {
		wheels := []string{"I", "II", "III", "IV", "V"}
		if i > 0 {
			wheels = append(wheels, "VI", "VII", "VIII")
		}
		m := catalogModel{ID: id, DefinitionID: id, Reflectors: []string{"B", "C"}, Plugboard: true}
		if i == 2 {
			m.Reflectors = []string{"Thin-B", "Thin-C"}
			m.Slots = append(m.Slots, catalogSlot{"greek", []string{"Beta", "Gamma"}})
		}
		for _, slot := range []string{"left", "middle", "right"} {
			m.Slots = append(m.Slots, catalogSlot{slot, wheels})
		}
		models = append(models, m)
	}
	for _, id := range []string{"enigma-railway", "enigma-g312", "enigma-g260"} {
		m := catalogModel{ID: id, DefinitionID: id, Reflectors: []string{"UKW"}, SettableReflector: true,
			FixedSlots: []transformSlot{{ID: "etw", Wheel: "ETW", Ring: "A", Position: "A"}}}
		for _, slot := range []string{"left", "middle", "right"} {
			m.Slots = append(m.Slots, catalogSlot{slot, []string{"I", "II", "III"}})
		}
		models = append(models, m)
	}
	for _, base := range []int{0, 1, 3} {
		m := models[base]
		m.ID = map[int]string{0: "enigma-i-ukwd", 1: "enigma-m3-ukwd", 3: "enigma-kd"}[base]
		m.DefinitionID = m.ID
		m.Reflectors = []string{"D"}
		m.RewirableReflector = true
		m.SettableReflector = false
		models = append(models, m)
	}
	return models
}

func apiIssue(w http.ResponseWriter, status int, code, message string) {
	jsonResponse(w, status, struct {
		Error *engine.Issue `json:"error"`
	}{&engine.Issue{Code: code, Message: message}})
}
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	return false
}
func (s *Server) serveMachines(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	jsonResponse(w, 200, struct {
		Models []catalogModel `json:"models"`
	}{machineCatalog()})
}

type transformSlot struct {
	Pairs    [][]string `json:"pairs,omitempty"`
	ID       string     `json:"id"`
	Wheel    string     `json:"wheel"`
	Ring     string     `json:"ring"`
	Position string     `json:"position"`
}
type transformInput struct {
	ReflectorPairs    [][]string      `json:"reflector_pairs"`
	Model             string          `json:"model"`
	Reflector         string          `json:"reflector"`
	ReflectorRing     *string         `json:"reflector_ring"`
	ReflectorPosition *string         `json:"reflector_position"`
	Slots             []transformSlot `json:"slots"`
	Plugboard         [][]string      `json:"plugboard"`
	Text              *string         `json:"text"`
}

func alphabetSymbol(s string) bool { return len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' }
func (s *Server) serveTransform(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var input transformInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.Model == "" || input.Reflector == "" || input.Slots == nil || input.Plugboard == nil || input.Text == nil || decoder.Decode(new(any)) != io.EOF {
		apiIssue(w, 400, "invalid_request", "Expected one transform object with model, reflector, slots, plugboard and text (at most 1 MiB).")
		return
	}
	var model *catalogModel
	for _, m := range machineCatalog() {
		if m.ID == input.Model {
			model = &m
			break
		}
	}
	if model == nil {
		apiIssue(w, 400, "unknown_model", "Choose a bundled model from the catalog.")
		return
	}
	if !model.RewirableReflector && input.ReflectorPairs != nil {
		apiIssue(w, 400, "invalid_request", "Expected one transform object with model, reflector, slots, plugboard and text (at most 1 MiB).")
		return
	}
	if !slices.Contains(model.Reflectors, input.Reflector) || len(input.Slots) != len(model.Slots) {
		apiIssue(w, 400, "invalid_component", "Choose a reflector and all slots from the model catalog.")
		return
	}
	for i, slot := range input.Slots {
		allowed := model.Slots[i]
		if slot.Pairs != nil || slot.ID != allowed.ID || !slices.Contains(allowed.AllowedWheels, slot.Wheel) || !alphabetSymbol(slot.Ring) || !alphabetSymbol(slot.Position) {
			apiIssue(w, 400, "invalid_component", "Slots must follow catalog order, with allowed wheels and uppercase A-Z rings and positions.")
			return
		}
	}
	ring, position := "A", "A"
	if model.SettableReflector {
		if input.ReflectorRing == nil || input.ReflectorPosition == nil || !alphabetSymbol(*input.ReflectorRing) || !alphabetSymbol(*input.ReflectorPosition) {
			apiIssue(w, 400, "invalid_component", "Choose uppercase A-Z reflector ring and position.")
			return
		}
		ring, position = *input.ReflectorRing, *input.ReflectorPosition
	} else if input.ReflectorRing != nil || input.ReflectorPosition != nil {
		apiIssue(w, 400, "invalid_request", "This model has no settable reflector.")
		return
	}
	if model.RewirableReflector {
		if !attack.ValidateReflectorPairs(input.ReflectorPairs) {
			apiIssue(w, 400, "invalid_component", "UKW-D requires 12 disjoint BP pairs covering A-Z except fixed B/O.")
			return
		}
	}
	if !model.Plugboard && len(input.Plugboard) != 0 {
		apiIssue(w, 400, "invalid_component", "This model has no plugboard.")
		return
	}
	used := map[string]bool{}
	for _, pair := range input.Plugboard {
		if len(pair) != 2 || !alphabetSymbol(pair[0]) || !alphabetSymbol(pair[1]) || pair[0] == pair[1] || used[pair[0]] || used[pair[1]] {
			apiIssue(w, 400, "invalid_component", "Plugboard pairs must contain two distinct uppercase A-Z letters with no reused endpoint.")
			return
		}
		used[pair[0]], used[pair[1]] = true, true
	}
	path, err := s.ValidatedEnginePath(r.Context())
	if err != nil {
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
		return
	}
	// The text reaches the engine exactly as typed; the engine rejects any
	// symbol outside its alphabet, including lowercase letters.
	text := *input.Text
	reflector := transformSlot{ID: "reflector", Wheel: input.Reflector, Ring: ring, Position: position, Pairs: input.ReflectorPairs}
	slots := append([]transformSlot{reflector}, input.Slots...)
	slots = append(slots, model.FixedSlots...)
	request := map[string]any{"protocol_version": 1, "machine": map[string]any{"definition": map[string]string{"kind": "bundled", "id": model.DefinitionID}}, "job": map[string]any{"kind": "transform", "direction": "encrypt", "text": text, "configuration": map[string]any{"slots": slots, "plugboard": input.Plugboard}}}
	data, err := json.Marshal(request)
	if err != nil {
		apiIssue(w, 500, "internal_error", "Could not build engine request.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	stdout := &jobOutput{limit: 4 << 20, cancel: cancel}
	stderr := &jobOutput{limit: 64 << 10, cancel: cancel}
	cmd := exec.CommandContext(ctx, path, "--events", "-", "--request", "-")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 100 * time.Millisecond
	runErr := cmd.Run()
	if stdout.overflow || stderr.overflow {
		apiIssue(w, 502, "engine_failed", "Engine output exceeded its limit.")
		return
	}
	if ctx.Err() != nil {
		apiIssue(w, 502, "timeout", "Engine transform exceeded its deadline or was cancelled.")
		return
	}
	events, output, issue, parseErr := parseTransformEvents(stdout.buffer.Bytes())
	if parseErr != nil {
		apiIssue(w, 502, "engine_failed", "Engine returned an invalid or incomplete JSONL transform stream.")
		return
	}
	if issue != nil {
		jsonResponse(w, 422, map[string]any{"error": issue, "events": events})
		return
	}
	if runErr != nil {
		apiIssue(w, 502, "engine_failed", "Engine process did not complete successfully.")
		return
	}
	jsonResponse(w, 200, map[string]any{"output": output, "events": events})
}

// Each pipe has its own writer; exec drains both concurrently without sharing state.
type jobOutput struct {
	buffer   bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	overflow bool
}

func (b *jobOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		b.overflow = true
		b.cancel()
		return 0, errors.New("engine output limit")
	}
	return b.buffer.Write(p)
}

// Preserve complete events (including future machine-state fields) for the page.
// Protocol v1 transform output currently contains text only, not rotor positions.
func parseTransformEvents(data []byte) ([]json.RawMessage, string, map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	events := []json.RawMessage{}
	output := ""
	started, hasOutput, done := false, false, false
	for scanner.Scan() {
		raw := append(json.RawMessage(nil), scanner.Bytes()...)
		var event map[string]any
		if json.Unmarshal(raw, &event) != nil || event == nil || done {
			return nil, "", nil, errors.New("invalid event")
		}
		name, ok := event["event"].(string)
		if !ok {
			return nil, "", nil, errors.New("missing event name")
		}
		events = append(events, raw)
		switch name {
		case "started":
			if started || hasOutput {
				return nil, "", nil, errors.New("duplicate started")
			}
			started = true
		case "output":
			value, ok := event["output"].(string)
			if !started || hasOutput || !ok {
				return nil, "", nil, errors.New("invalid output")
			}
			output = value
			hasOutput = true
		case "done":
			if !hasOutput || event["reason"] != "completed" {
				return nil, "", nil, errors.New("invalid done")
			}
			done = true
		case "error":
			code, cok := event["code"].(string)
			message, mok := event["message"].(string)
			if !cok || !mok || code == "" || message == "" {
				return nil, "", nil, errors.New("invalid error")
			}
			// Error is terminal. Verify the rest of the stream before trusting it.
			if scanner.Scan() || scanner.Err() != nil {
				return nil, "", nil, errors.New("events after error")
			}
			issue := map[string]any{"code": code, "message": message}
			for _, field := range []string{"location", "expected", "hint"} {
				if v, ok := event[field]; ok {
					issue[field] = v
				}
			}
			return events, "", issue, nil
		}
	}
	if scanner.Err() != nil || !done {
		return nil, "", nil, errors.New("incomplete events")
	}
	return events, output, nil, nil
}
