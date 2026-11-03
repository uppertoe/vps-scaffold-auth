package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A second gateway on the same database refuses to start; once the first
// stops, another may.
func TestOneGatewayPerDatabase(t *testing.T) {
	db := filepath.Join(t.TempDir(), "auth.db")
	unlock, err := lockDatabase(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockDatabase(db); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("a second gateway was allowed: %v", err)
	}
	unlock()
	again, err := lockDatabase(db)
	if err != nil {
		t.Fatalf("after the first stopped: %v", err)
	}
	again()
}
