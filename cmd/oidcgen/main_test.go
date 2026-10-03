package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPinnedSnapshotGenerationAndDrift(t *testing.T) {
	sourcePath := "../../iam/policy/testdata/oidc_trust_controls_source.json"
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	var source snapshot
	if err := json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	first, err := render(source)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(source.Providers)
	second, err := render(source)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("source order changed generated controls: %v", err)
	}
	output := filepath.Join(t.TempDir(), "controls.go")
	if err := run(sourcePath, output, false); err != nil {
		t.Fatal(err)
	}
	if err := run(sourcePath, output, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(sourcePath, output, true); err == nil {
		t.Fatal("drift check accepted stale output")
	}
	after, err := os.ReadFile(output)
	if err != nil || string(after) != "stale" {
		t.Fatalf("drift check rewrote output: %q %v", after, err)
	}
	source.Providers = append(source.Providers, source.Providers[0])
	if _, err := render(source); err == nil {
		t.Fatal("duplicate issuer was accepted")
	}
}
