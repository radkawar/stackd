//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package devtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMissingPublicCopyRecoversCommittedIdentity(t *testing.T) {
	authority := openTestAuthority(t, Config{Domains: []string{"local.test"}})
	public := authority.CACertificate()
	if err := os.Remove(authority.CAFile()); err != nil {
		t.Fatal(err)
	}
	reopened := openTestAuthority(t, Config{Directory: authority.directory, Domains: []string{"local.test"}})
	if !bytes.Equal(reopened.CACertificate(), public) {
		t.Fatal("recovering an interrupted public export replaced the CA")
	}
	data, err := os.ReadFile(reopened.CAFile())
	if err != nil || !bytes.Equal(data, public) {
		t.Fatalf("public certificate was not restored: %v", err)
	}
	if err := os.Remove(filepath.Join(authority.directory, bundleFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{Directory: authority.directory}); err == nil {
		t.Fatal("orphaned public trust was silently replaced by a new identity")
	}
	if _, err := os.Stat(filepath.Join(authority.directory, bundleFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned trust created a new private bundle: %v", err)
	}
}

func TestUnsafeAndCorruptIdentityIsNotReplaced(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Authority)
	}{
		{name: "public-private-key", mutate: func(t *testing.T, a *Authority) {
			if err := os.Chmod(filepath.Join(a.directory, bundleFile), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "public-directory", mutate: func(t *testing.T, a *Authority) {
			if err := os.Chmod(a.directory, 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed-bundle", mutate: func(t *testing.T, a *Authority) {
			if err := os.WriteFile(filepath.Join(a.directory, bundleFile), []byte("not a certificate or a key"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "different-public-ca", mutate: func(t *testing.T, a *Authority) {
			other := openTestAuthority(t, Config{})
			if err := os.WriteFile(a.CAFile(), other.CACertificate(), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mismatched-key", mutate: func(t *testing.T, a *Authority) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			bundle := append(a.CACertificate(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
			if err := os.WriteFile(filepath.Join(a.directory, bundleFile), bundle, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard-linked-private-key", mutate: func(t *testing.T, a *Authority) {
			if err := os.Link(filepath.Join(a.directory, bundleFile), filepath.Join(t.TempDir(), "key-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink-private-key", mutate: func(t *testing.T, a *Authority) {
			bundle := filepath.Join(a.directory, bundleFile)
			target := filepath.Join(t.TempDir(), "key.pem")
			if err := os.Rename(bundle, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, bundle); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe-lock", mutate: func(t *testing.T, a *Authority) {
			if err := os.Chmod(filepath.Join(a.directory, lockFile), 0666); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := openTestAuthority(t, Config{Domains: []string{"local.test"}})
			test.mutate(t, authority)
			bundle := filepath.Join(authority.directory, bundleFile)
			before, err := os.ReadFile(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), Config{Directory: authority.directory, Domains: []string{"local.test"}}); err == nil {
				t.Fatal("unsafe or corrupt identity was accepted")
			}
			after, err := os.ReadFile(bundle)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("unsafe identity was overwritten rather than rejected: %v", err)
			}
		})
	}
	authority := openTestAuthority(t, Config{})
	alias := filepath.Join(t.TempDir(), "authority-link")
	if err := os.Symlink(authority.directory, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{Directory: alias}); err == nil {
		t.Fatal("symlink state directory was accepted")
	}
	if err := authority.Export(filepath.Join(alias, bundleFile)); err == nil {
		t.Fatal("private export destination was accepted through a directory alias")
	}
}

func TestAuthorityLockWaitRespectsContext(t *testing.T) {
	authority := openTestAuthority(t, Config{})
	_, root, err := privateRoot(authority.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	unlock, err := lockState(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	_, openErr := Open(ctx, Config{Directory: authority.directory})
	cancel()
	unlock()
	if !errors.Is(openErr, context.DeadlineExceeded) {
		t.Fatalf("waiting for another authority opener did not honor cancellation: %v", openErr)
	}
	reopened := openTestAuthority(t, Config{Directory: authority.directory})
	if !bytes.Equal(reopened.CACertificate(), authority.CACertificate()) {
		t.Fatal("cancelled lock wait changed persisted identity")
	}
}

func TestConcurrentProcessOpenPreservesOneCA(t *testing.T) {
	// Each child is a real independent controller process opening the same state.
	if directory := os.Getenv("STACKD_DEVTLS_TEST_DIRECTORY"); directory != "" {
		authority, err := Open(context.Background(), Config{Directory: directory, Domains: []string{"local.test"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := authority.Export(os.Getenv("STACKD_DEVTLS_TEST_EXPORT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	directory := filepath.Join(t.TempDir(), "private")
	results := t.TempDir()
	const processes = 4
	commands := make([]*exec.Cmd, processes)
	logs := make([]bytes.Buffer, processes)
	for i := range processes {
		command := exec.CommandContext(ctx, binary, "-test.run=^TestConcurrentProcessOpenPreservesOneCA$")
		command.Env = append(os.Environ(), "STACKD_DEVTLS_TEST_DIRECTORY="+directory, "STACKD_DEVTLS_TEST_EXPORT="+filepath.Join(results, fmt.Sprintf("ca-%d.pem", i)))
		command.Stdout = &logs[i]
		command.Stderr = &logs[i]
		commands[i] = command
		if err := command.Start(); err != nil {
			cancel()
			for _, started := range commands[:i] {
				_ = started.Wait()
			}
			t.Fatal(err)
		}
	}
	for i, command := range commands {
		if err := command.Wait(); err != nil {
			t.Errorf("independent opener %d: %v\n%s", i, err, logs[i].String())
		}
	}
	if t.Failed() {
		return
	}
	authority := openTestAuthority(t, Config{Directory: directory})
	for i := range processes {
		data, err := os.ReadFile(filepath.Join(results, fmt.Sprintf("ca-%d.pem", i)))
		if err != nil || !bytes.Equal(data, authority.CACertificate()) {
			t.Fatalf("independent opener %d returned a different CA: %v", i, err)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("private persistence left partial identities: %v", entries)
	}
}

func TestAuthorityRejectsStateSymlinksAndSpecialFiles(t *testing.T) {
	for _, name := range []string{bundleFile, publicFile, lockFile} {
		t.Run("symlink-"+name, func(t *testing.T) {
			authority := openTestAuthority(t, Config{})
			path := filepath.Join(authority.directory, name)
			target := filepath.Join(authority.directory, "retained-"+name)
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(target), path); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), Config{Directory: authority.directory}); err == nil {
				t.Fatal("state symlink inside the private directory was followed")
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("symlink target changed: %v", err)
			}
		})
		t.Run("fifo-"+name, func(t *testing.T) {
			authority := openTestAuthority(t, Config{})
			path := filepath.Join(authority.directory, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := Open(ctx, Config{Directory: authority.directory})
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil || errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("special state file was not promptly rejected: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("opening a special state file blocked instead of rejecting it")
			}
		})
	}
}
