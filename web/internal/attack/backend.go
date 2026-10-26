package attack

import (
	"encoding/json"
	"io"
	"reflect"
)

// BackendOptions are host settings, never part of the engine request or checkpoint.
type BackendOptions struct {
	Backend  *string `json:"backend"`
	GPUUsage *int    `json:"gpu_usage"`
}

// ResolveBackend is shared by preview, start and resume. CPU ignores GPU usage.
func ResolveBackend(backend *string, usage *int) (string, int, *Issue) {
	name := stringDefault(backend, "cpu")
	if name != "cpu" && name != "gpu" {
		return "", 0, issue("invalid_settings", "settings/backend", "Invalid attack setting.")
	}
	n := intDefault(usage, 100)
	if name == "gpu" && (n < 1 || n > 100) {
		return "", 0, issue("invalid_settings", "settings/gpu_usage", "Invalid attack setting.")
	}
	if name == "cpu" {
		n = 100
	}
	return name, n, nil
}

// ValidateBackendMethod also guards resume, which does not rebuild the request.
func ValidateBackendMethod(method, backend string) *Issue {
	if method == "bombe" && backend == "gpu" {
		return issue("backend_unavailable", "settings/backend", "The crib attack runs on the CPU only.")
	}
	return nil
}

// DecodeBackend uses the attack decoder's strict types and duplicate-key checks.
// Empty bodies preserve the existing resume API; an empty object also is valid.
func DecodeBackend(r io.Reader) (BackendOptions, *Issue) {
	var options BackendOptions
	d := json.NewDecoder(r)
	value, err := readValue(d)
	if err == io.EOF {
		return options, nil
	}
	if err != nil {
		return options, issue("invalid_request", "", "Expected one attack JSON object.")
	}
	if _, err := d.Token(); err != io.EOF {
		return options, issue("invalid_request", "", "Unexpected trailing JSON.")
	}
	if problem := validateShape(value, reflect.TypeOf(options), ""); problem != nil {
		return options, problem
	}
	data, _ := json.Marshal(value)
	if err := json.Unmarshal(data, &options); err != nil {
		return options, issue("invalid_request", "", "Invalid attack field type or integer.")
	}
	return options, nil
}
