// Package tables embeds the scoring tables that enigma-web offers by default.
package tables

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// The JSON files are e2e/bomm/frequencies/enigma1941-{bigram,trigram}.txt converted
// with e2e/recovery/ngrams.py convert and written compact; see NOTICE.md.
var (
	//go:embed enigma1941-bigram.json
	bigram []byte
	//go:embed enigma1941-trigram.json
	trigram []byte
)

// Table is one built-in engine JSON v1 n-gram resource.
type Table struct {
	ID      string
	Measure string
	Order   int
	Data    []byte
}

// Builtin lists the embedded tables in a fixed order.
func Builtin() []Table {
	return []Table{
		{ID: "enigma1941-bigram", Measure: "sinkov_bigram", Order: 2, Data: bigram},
		{ID: "enigma1941-trigram", Measure: "sinkov_trigram", Order: 3, Data: trigram},
	}
}

// ForMeasure returns the built-in table for a Sinkov measure, if one exists.
func ForMeasure(measure string) (Table, bool) {
	for _, table := range Builtin() {
		if table.Measure == measure {
			return table, true
		}
	}
	return Table{}, false
}

// Write saves the table as <dir>/<ID>.json, failing if that name already exists.
func (t Table) Write(dir string) (string, error) {
	path := filepath.Join(dir, t.ID+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create table %s: %w", t.ID, err)
	}
	if _, err := file.Write(t.Data); err != nil {
		file.Close()
		return "", fmt.Errorf("write table %s: %w", t.ID, err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close table %s: %w", t.ID, err)
	}
	return path, nil
}
