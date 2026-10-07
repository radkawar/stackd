//go:build linux || darwin

package hostdns

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fileFixture(t *testing.T) (Config, fileBackend) {
	t.Helper()
	root := t.TempDir()
	resolver := filepath.Join(root, "resolver")
	if err := os.Mkdir(resolver, 0755); err != nil {
		t.Fatal(err)
	}
	c, err := normalize(Config{Address: "127.0.0.1:5353", Domains: []string{"Gateway.Example.", "aws.example"}, StateDirectory: filepath.Join(root, "state")}, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	return c, fileBackend{directory: resolver}
}

func fileReport(t *testing.T, c Config, b fileBackend) Report {
	t.Helper()
	r, err := status(t.Context(), c.StateDirectory, "darwin", func() (backend, error) { return b, nil })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScopedResolverReceiptLifecycle(t *testing.T) {
	c, b := fileFixture(t)
	neighbor := filepath.Join(b.directory, "notgateway.example")
	prior := []byte("nameserver 192.0.2.1\n# untouched\n")
	if err := os.WriteFile(neighbor, prior, 0600); err != nil {
		t.Fatal(err)
	}
	if report := fileReport(t, c, b); report.Owned || report.Installed {
		t.Fatalf("unowned status: %+v", report)
	}
	if err := setup(t.Context(), c, "darwin", b); err != nil {
		t.Fatal(err)
	}
	for _, domain := range c.Domains {
		data, err := os.ReadFile(filepath.Join(b.directory, domain))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, resolverState(c).Data) {
			t.Fatalf("wrong resolver content %q", data)
		}
	}
	if report := fileReport(t, c, b); !report.Owned || !report.Installed || report.Phase != "active" {
		t.Fatalf("active status: %+v", report)
	}
	before, err := os.ReadFile(filepath.Join(c.StateDirectory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := setup(t.Context(), c, "darwin", b); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(c.StateDirectory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent setup rewrote receipt")
	}
	changed := c
	changed.Address = "127.0.0.2:5353"
	if err := setup(t.Context(), changed, "darwin", b); err == nil {
		t.Fatal("configuration silently replaced")
	}
	if err := teardown(t.Context(), c.StateDirectory, "darwin", b); err != nil {
		t.Fatal(err)
	}
	if err := teardown(t.Context(), c.StateDirectory, "darwin", b); err != nil {
		t.Fatal(err)
	}
	for _, domain := range c.Domains {
		if _, err := os.Lstat(filepath.Join(b.directory, domain)); !os.IsNotExist(err) {
			t.Fatalf("owned file not removed: %s %v", domain, err)
		}
	}
	data, err := os.ReadFile(neighbor)
	if err != nil || !bytes.Equal(data, prior) {
		t.Fatalf("unrelated resolver changed: %q %v", data, err)
	}
	if report := fileReport(t, c, b); report.Owned || report.Installed {
		t.Fatalf("post-teardown status: %+v", report)
	}
}

func TestExternalChangesNeverClobbered(t *testing.T) {
	for _, mutation := range []string{"content", "mode", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			c, b := fileFixture(t)
			if err := setup(t.Context(), c, "darwin", b); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(b.directory, c.Domains[0])
			external := []byte("nameserver 192.0.2.9\n# external owner\n")
			switch mutation {
			case "content":
				if err := os.WriteFile(path, external, 0644); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "external")
				if err := os.WriteFile(target, external, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if err := setup(t.Context(), c, "darwin", b); err == nil {
				t.Fatal("setup silently repaired external mutation")
			}
			if err := teardown(t.Context(), c.StateDirectory, "darwin", b); err == nil {
				t.Fatal("teardown overwrote external mutation")
			}
			if _, err := os.Stat(filepath.Join(c.StateDirectory, "receipt.json")); err != nil {
				t.Fatalf("lost recovery receipt: %v", err)
			}
			if _, err := os.Stat(filepath.Join(b.directory, c.Domains[1])); err != nil {
				t.Fatalf("partial teardown despite known conflict: %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "content", "symlink":
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, external) {
					t.Fatalf("external bytes lost: %q %v", data, err)
				}
			case "mode":
				if info.Mode().Perm() != 0600 {
					t.Fatal("external mode changed")
				}
			}
			if mutation != "symlink" {
				report := fileReport(t, c, b)
				if report.Installed || len(report.Conflicts) != 1 {
					t.Fatalf("conflict status: %+v", report)
				}
			}
		})
	}
}

func TestUnownedResolverScopesRejected(t *testing.T) {
	for _, name := range []string{"gateway.example", "example", "child.gateway.example", "opaque-name"} {
		t.Run(name, func(t *testing.T) {
			c, b := fileFixture(t)
			content := []byte("nameserver 192.0.2.1\n")
			if name == "opaque-name" {
				content = []byte("domain gateway.example\nnameserver 192.0.2.1\n")
			}
			path := filepath.Join(b.directory, name)
			if err := os.WriteFile(path, content, 0644); err != nil {
				t.Fatal(err)
			}
			if err := setup(t.Context(), c, "darwin", b); err == nil {
				t.Fatal("adopted unowned overlapping scope")
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, content) {
				t.Fatal("unowned file overwritten")
			}
			if _, err := os.Stat(filepath.Join(c.StateDirectory, "receipt.json")); !os.IsNotExist(err) {
				t.Fatalf("receipt created for unowned conflict: %v", err)
			}
		})
	}
	c, b := fileFixture(t)
	if err := os.WriteFile(filepath.Join(b.directory, c.Domains[0]), resolverState(c).Data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := setup(t.Context(), c, "darwin", b); err == nil {
		t.Fatal("matching public content mistaken for ownership")
	}
}

func TestInterruptedReceiptRecoveryUsesRealFilesystem(t *testing.T) {
	c, b := fileFixture(t)
	if err := privateDirectory(c.StateDirectory, true); err != nil {
		t.Fatal(err)
	}
	target, changes, err := b.plan(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	r := receipt{Version: 1, Platform: "darwin", Config: c, Target: target, Phase: "installing", Changes: changes}
	if err := saveReceipt(r); err != nil {
		t.Fatal(err)
	}
	// Simulate loss of process after one native publication, before active commit.
	if err := b.write(t.Context(), r, changes[0].Key, changes[0].Before, changes[0].After); err != nil {
		t.Fatal(err)
	}
	if err := setup(t.Context(), c, "darwin", b); err != nil {
		t.Fatal(err)
	}
	if !fileReport(t, c, b).Installed {
		t.Fatal("installation recovery did not finish")
	}
	r.Phase = "removing"
	if err := saveReceipt(r); err != nil {
		t.Fatal(err)
	}
	last := changes[len(changes)-1]
	if err := b.write(t.Context(), r, last.Key, last.After, last.Before); err != nil {
		t.Fatal(err)
	}
	if err := setup(t.Context(), c, "darwin", b); err == nil {
		t.Fatal("setup revived an incomplete teardown")
	}
	if err := teardown(t.Context(), c.StateDirectory, "darwin", b); err != nil {
		t.Fatal(err)
	}
	if fileReport(t, c, b).Owned {
		t.Fatal("teardown recovery retained completed receipt")
	}
}

func TestNewScopeConflictLeavesOwnedFilesUntouched(t *testing.T) {
	c, b := fileFixture(t)
	if err := setup(t.Context(), c, "darwin", b); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(b.directory, "child.gateway.example")
	if err := os.WriteFile(outside, []byte("nameserver 192.0.2.5\n"), 0644); err != nil {
		t.Fatal(err)
	}
	report := fileReport(t, c, b)
	if report.Installed || len(report.Conflicts) == 0 {
		t.Fatalf("external overlapping scope missing: %+v", report)
	}
	if err := setup(t.Context(), c, "darwin", b); err == nil {
		t.Fatal("idempotent setup ignored new competing scope")
	}
	// Removing our own exact files is safe even when an unrelated new owner exists.
	if err := teardown(t.Context(), c.StateDirectory, "darwin", b); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("teardown removed unrelated scope")
	}
}

func TestValidationAndReceiptBoundaries(t *testing.T) {
	c, b := fileFixture(t)
	for _, domain := range []string{".", "", "~example", "../example", "*.example", "bad\nexample", "-bad.example", "bad-.example", "bad..example", "localhost", "local", "127.0.0.1", "é.example", strings.Repeat("x", 64) + ".example"} {
		bad := c
		bad.Domains = []string{domain}
		if _, err := normalize(bad, "darwin"); err == nil {
			t.Fatalf("accepted domain %q", domain)
		}
	}
	for _, address := range []string{"example:53", "0.0.0.0:53", "[::]:53", "224.0.0.1:53", "[::ffff:224.0.0.1]:53", "[::ffff:0.0.0.0]:53", "127.0.0.1:0", "[fe80::1%en0]:53", "127.0.0.1:65536", "127.0.0.1;touch /tmp/no"} {
		bad := c
		bad.Address = address
		if _, err := normalize(bad, "darwin"); err == nil {
			t.Fatalf("accepted address %q", address)
		}
	}
	good := c
	good.Address = "::ffff:127.0.0.1"
	good.Domains = []string{"GATEWAY.EXAMPLE.", "gateway.example"}
	normalized, err := normalize(good, "darwin")
	if err != nil || normalized.Address != "127.0.0.1:53" || !reflect.DeepEqual(normalized.Domains, []string{"gateway.example"}) {
		t.Fatalf("canonical config: %+v %v", normalized, err)
	}
	if _, err := normalize(c, "windows"); err == nil {
		t.Fatal("unsupported platform accepted")
	}
	if err := setup(t.Context(), c, "darwin", b); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.StateDirectory, "receipt.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{append(append([]byte{}, original...), []byte("{}")...), []byte(`{"Version":99}`), []byte(`{"Unexpected":true}`)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadReceipt(c.StateDirectory); err == nil {
			t.Fatalf("accepted invalid receipt %q", data)
		}
	}
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReceipt(c.StateDirectory); err == nil {
		t.Fatal("public receipt accepted")
	}
}

func TestCancellationDoesNotPublishResolvers(t *testing.T) {
	c, b := fileFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := setup(ctx, c, "darwin", b); err == nil {
		t.Fatal("canceled setup succeeded")
	}
	entries, err := os.ReadDir(b.directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("canceled setup mutated resolvers: %v %v", entries, err)
	}
}

func TestReceiptBackendRejectsForgedPaths(t *testing.T) {
	c, b := fileFixture(t)
	if err := setup(t.Context(), c, "darwin", b); err != nil {
		t.Fatal(err)
	}
	r, err := loadReceipt(c.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	r.Changes[0].Key = "../../outside"
	if err := b.validate(*r); err == nil {
		t.Fatal("receipt traversal accepted")
	}
	r.Changes[0].Key = c.Domains[0]
	r.Changes[0].Before = encoded(fileState{Exists: true, Data: []byte("unowned")})
	if err := b.validate(*r); err == nil {
		t.Fatal("forged previous file ownership accepted")
	}
}
