package server

import (
	"io"
	"net/http"
	"os"
	"runtime"

	"criptografia-enigma/web/internal/attack"
)

// Preview is deliberately independent of engine configuration and job execution.
func (s *Server) serveAttackPreview(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	_, plan, problem := buildAttack(http.MaxBytesReader(w, r.Body, 1<<20))
	if problem != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": problem})
		return
	}
	jsonResponse(w, http.StatusOK, plan)
}

// Start and preview share all schema, catalog and own-table checks.
func buildAttack(body io.Reader) (attack.Input, attack.Plan, *attack.Issue) {
	input, problem := attack.Decode(body)
	var plan attack.Plan
	if problem == nil {
		models := []attack.Model{}
		for _, catalog := range machineCatalog() {
			model := attack.Model{ID: catalog.DefinitionID, Reflectors: catalog.Reflectors,
				RewirableReflector: catalog.RewirableReflector, SettableReflector: catalog.SettableReflector, FixedETW: len(catalog.FixedSlots) > 0, NoPlugboard: !catalog.Plugboard}
			for _, slot := range catalog.Slots {
				model.Slots = append(model.Slots, attack.Slot{ID: slot.ID, Wheels: slot.AllowedWheels})
			}
			models = append(models, model)
		}
		plan, problem = attack.Build(models, input, runtime.NumCPU())
	}
	if problem == nil {
		for _, resource := range plan.Resources {
			if resource.Own == "" {
				continue
			}
			info, err := os.Stat(resource.Own)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
				problem = &attack.Issue{Code: "invalid_settings", Message: "Own table must exist as a regular file of at most 64 MiB.", Field: "settings/tables/" + resource.Measure}
				break
			}
		}
	}
	return input, plan, problem
}
