package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The generator must build even when every generated artifact is absent. A
// dependency on awscatalog would otherwise make clean regeneration impossible.
func TestGeneratorBootstrapsWithoutGeneratedOutputs(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := t.TempDir()
	if err := os.WriteFile(filepath.Join(snapshot, "go.mod"), []byte("module stackd\n\ngo 1.26.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"cmd/awsgen", "internal/awsschema", "internal/smithy"} {
		files, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(snapshot, dir), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			sourceFile := strings.HasSuffix(file.Name(), ".go") && !strings.HasSuffix(file.Name(), "_test.go")
			embeddedFile := strings.HasSuffix(file.Name(), ".json")
			if file.IsDir() || (!sourceFile && !embeddedFile) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, dir, file.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(snapshot, dir, file.Name()), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	command := exec.Command("go", "run", "./cmd/awsgen", "-h")
	command.Dir = snapshot
	command.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generator depends on generated artifacts: %v\n%s", err, output)
	}
}
