package server_test

import (
	"os"
	"path/filepath"
	"testing"
)

func realEnginePath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("ENIGMA_TEST_BIN")
	if path == "" {
		t.Skip("set ENIGMA_TEST_BIN to an engine 0.2.0 binary to run real-engine tests")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("ENIGMA_TEST_BIN engine binary is unavailable")
	} else if err != nil {
		t.Fatal(err)
	}
	return path
}
