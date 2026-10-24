package tables

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinTablesHaveExactContent(t *testing.T) {
	want := map[string]struct {
		measure string
		order   int
		sha     string
	}{
		"enigma1941-bigram":  {"sinkov_bigram", 2, "873e29907b9112513856f4b0c6ce8180ac1001df8b108b4bdb0194fe1013655d"},
		"enigma1941-trigram": {"sinkov_trigram", 3, "0a2706c75bb3b3696bd1af96a1971bf6186e37c0be20c645398c6faeeb4db132"},
	}
	list := Builtin()
	if len(list) != len(want) {
		t.Fatalf("Builtin() has %d tables, want %d", len(list), len(want))
	}
	for _, table := range list {
		w, ok := want[table.ID]
		if !ok {
			t.Fatalf("unexpected table %q", table.ID)
		}
		sum := sha256.Sum256(table.Data)
		if got := hex.EncodeToString(sum[:]); got != w.sha {
			t.Errorf("%s sha256 = %s, want %s", table.ID, got, w.sha)
		}
		if table.Measure != w.measure || table.Order != w.order {
			t.Errorf("%s = %s/%d, want %s/%d", table.ID, table.Measure, table.Order, w.measure, w.order)
		}
		var header struct {
			Version int    `json:"resource_version"`
			Kind    string `json:"kind"`
			Order   int    `json:"order"`
		}
		if err := json.Unmarshal(table.Data, &header); err != nil || header.Version != 1 || header.Kind != "ngram" || header.Order != w.order {
			t.Errorf("%s header = %+v, %v", table.ID, header, err)
		}
	}
}

func TestLookupByMeasure(t *testing.T) {
	if table, ok := ForMeasure("sinkov_trigram"); !ok || table.ID != "enigma1941-trigram" {
		t.Fatalf("ForMeasure(sinkov_trigram) = %+v, %v", table, ok)
	}
	if _, ok := ForMeasure("sinkov_quadgram"); ok {
		t.Fatal("no built-in quadgram table exists")
	}
}

func TestWriteCreatesNewFileAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	table, _ := ForMeasure("sinkov_bigram")
	path, err := table.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "enigma1941-bigram.json") {
		t.Fatalf("path = %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(table.Data) {
		t.Fatalf("written content differs: %v", err)
	}
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Write(dir); err == nil {
		t.Fatal("second Write must fail instead of overwriting")
	}
	if got, _ := os.ReadFile(path); string(got) != "keep" {
		t.Fatalf("existing file was changed: %q", got)
	}
}
