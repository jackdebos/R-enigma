package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// distinct-wheels S6: exactly 0.2.0 / protocol 1; old engines cannot accept constraints.
func TestDistinctWheelsVersionGate(t *testing.T) {
	supported := []Version{{Version: "0.2.0", Protocol: 1}}
	if !reflect.DeepEqual(SupportedVersions(), supported) {
		t.Errorf("supported=%v want %v", SupportedVersions(), supported)
	}
	for _, version := range []string{"0.2.0", "0.1.0"} {
		t.Run(version, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "engine")
			if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'enigma "+version+"\\nprotocol version 1\\n'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			got := Validate(context.Background(), path)
			if version == "0.2.0" {
				if !got.Compatible || got.Error != nil || got.Version != version || got.Protocol != 1 {
					t.Fatalf("accepted: %+v", got)
				}
			} else {
				if got.Compatible || got.Error == nil || got.Error.Code != "unsupported_version" || got.Error.Message != "This engine version and protocol are not supported." || got.Error.Found == nil || *got.Error.Found != (Version{Version: version, Protocol: 1}) || !reflect.DeepEqual(got.Error.Supported, supported) {
					t.Fatalf("refused: %+v", got)
				}
			}
		})
	}
}
