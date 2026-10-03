//go:build linux

package managed

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestManagedCodeRemainsReadableUnderPrivateAgentUmask(t *testing.T) {
	const child = "STACKD_MANAGED_CODE_PERMISSIONS_CHILD"
	if os.Getenv(child) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestManagedCodeRemainsReadableUnderPrivateAgentUmask$")
		command.Env = append(os.Environ(), child+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated permission check: %v\n%s", err, output)
		}
		return
	}
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	state := t.TempDir()
	task := filepath.Join(state, "task")
	if err := makeRuntimeDirectory(task); err != nil {
		t.Fatal(err)
	}
	type entry struct {
		name string
		mode os.FileMode
	}
	archive := func(entries []entry) []byte {
		t.Helper()
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		for _, item := range entries {
			header := &zip.FileHeader{Name: item.name, Method: zip.Store}
			header.SetMode(item.mode)
			file, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte("runtime code\n")); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	code := archive([]entry{{"handler.py", 0600}, {"pkg/__init__.py", 0600}, {"pkg/deep/module.py", 0644}, {"bootstrap", 0100}})
	if err := extractCode(code, task); err != nil {
		t.Fatal(err)
	}
	for _, item := range []entry{{".", 0755}, {"pkg", 0755}, {"pkg/deep", 0755}, {"handler.py", 0644}, {"pkg/__init__.py", 0644}, {"pkg/deep/module.py", 0644}, {"bootstrap", 0755}} {
		info, err := os.Stat(filepath.Join(task, item.name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != item.mode {
			t.Fatalf("runtime UID cannot use %s: mode=%#o, want %#o", item.name, info.Mode().Perm(), item.mode)
		}
	}
	// A later layer must replace executable access as well as bytes; OpenFile's
	// creation mode alone cannot change permissions on an existing entry.
	if err := extractCode(archive([]entry{{"bootstrap", 0644}}), task); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(task, "bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("replaced code retained executable permissions: %#o", info.Mode().Perm())
	}
	info, err = os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("code extraction exposed private guest state: %#o", info.Mode().Perm())
	}
}
