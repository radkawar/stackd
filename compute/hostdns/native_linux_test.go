//go:build linux

package hostdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	dnsruntime "stackd/compute/dns"
)

// This opt-in test changes only a fresh owned link and unique routing domain.
// Run a compiled test binary as root with STACKD_HOSTDNS_NATIVE=1 on a host using
// systemd-resolved's stub resolver. It needs native busctl/ip/getent, not Docker.
func TestNativeLocalScopedLookupAndTeardown(t *testing.T) {
	if os.Getenv("STACKD_HOSTDNS_NATIVE") != "1" {
		t.Skip("set STACKD_HOSTDNS_NATIVE=1 for explicit native host DNS mutation")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native host DNS proof requires root")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	server, err := dnsruntime.Listen(dnsruntime.Config{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	domain := fmt.Sprintf("native-%d.stackd.test", time.Now().UnixNano())
	// Larger than the upstream UDP limit: native resolved must also recover
	// the complete authoritative answer through the server's TCP data plane.
	addresses := make([]netip.Addr, 80)
	want := make([]string, len(addresses))
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{127, 0, 1, byte(i + 1)})
		want[i] = addresses[i].String()
	}
	resolver, err := dnsruntime.NewNamespace(domain, addresses)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Register(resolver); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "stackd-hostdns-native-")
	if err != nil {
		t.Fatal(err)
	}
	c := Config{Address: server.Address(), Domains: []string{domain}, StateDirectory: filepath.Join(directory, "state")}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := Teardown(cleanup, c.StateDirectory); err != nil {
			t.Errorf("native cleanup failed; retained receipt at %s: %v", c.StateDirectory, err)
			return
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := Setup(ctx, c); err != nil {
		if r, loadErr := loadReceipt(c.StateDirectory); loadErr == nil && r != nil {
			if native, backendErr := nativeBackend(); backendErr == nil {
				if actual, _, inspectErr := native.(resolvedBackend).inspectLink(ctx, *r); inspectErr == nil {
					t.Logf("native link actual=%s expected=%s", actual, r.Changes[0].After)
				}
			}
		}
		t.Fatal(err)
	}
	report, err := Status(ctx, c.StateDirectory)
	if err != nil || !report.Installed {
		t.Fatalf("native installation: %+v %v", report, err)
	}
	got, err := net.DefaultResolver.LookupHost(ctx, "child."+domain)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("native complete answer = %v, want %v", got, want)
	}
	output, err := exec.CommandContext(ctx, "getent", "ahostsv4", "libc."+domain).CombinedOutput()
	if err != nil {
		t.Fatalf("actual libc lookup: %v: %s", err, output)
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 0 {
			seen[fields[0]] = true
		}
	}
	for _, address := range want {
		if !seen[address] {
			t.Fatalf("libc answer missing %s: %s", address, output)
		}
	}
	b, err := nativeBackend()
	if err != nil {
		t.Fatal(err)
	}
	native := b.(resolvedBackend)
	r, err := loadReceipt(c.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	// An operator's extra native address must block deletion of the link.
	foreign, err := native.planScopeAddress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.ipCommand(ctx, "address", "add", foreign+"/32", "dev", r.Target, "noprefixroute"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := net.InterfaceByName(r.Target); err == nil {
			_, _ = native.ipCommand(cleanup, "address", "delete", foreign+"/32", "dev", r.Target)
		}
	})
	if err := Teardown(ctx, c.StateDirectory); err == nil {
		t.Fatal("teardown deleted externally changed interface")
	}
	if _, err := net.InterfaceByName(r.Target); err != nil {
		t.Fatalf("external interface removed: %v", err)
	}
	if _, err := native.ipCommand(ctx, "address", "delete", foreign+"/32", "dev", r.Target); err != nil {
		t.Fatal(err)
	}
	if err := Teardown(ctx, c.StateDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName(r.Target); err == nil {
		t.Fatal("owned interface retained after teardown")
	}
	if _, err := os.Stat(filepath.Join(c.StateDirectory, "receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("ownership receipt retained: %v", err)
	}
	// The assigned /32's automatic local route must disappear with teardown.
	var scope string
	if err := json.Unmarshal(r.Changes[2].After, &scope); err != nil {
		t.Fatal(err)
	}
	free, err := native.scopeAddressAvailable(ctx, scope)
	if err != nil || !free {
		t.Fatalf("scope address route leaked: %v %v", free, err)
	}
}
