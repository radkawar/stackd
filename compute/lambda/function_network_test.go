package lambda

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"stackd/compute/docker"
	"stackd/compute/network"
)

func functionNetworkSpecification() network.Specification {
	return network.Specification{NetworkID: "vpc-function", Pool: netip.MustParsePrefix("10.90.0.0/16"), Gateway: netip.MustParseAddr("10.90.0.1"), Address: netip.MustParseAddr("10.90.1.10"), MAC: "02:01:02:03:04:05", Policy: network.Policy{Subnet: netip.MustParsePrefix("10.90.1.0/24")}}
}

func TestFunctionNetworkRejectsAttachmentIdentityChanges(t *testing.T) {
	original := functionNetworkSpecification()
	attachment := &FunctionNetworkAttachment{spec: original}
	for _, field := range []string{"network", "pool", "gateway", "address", "mac"} {
		t.Run(field, func(t *testing.T) {
			changed := original
			switch field {
			case "network":
				changed.NetworkID = "vpc-other"
			case "pool":
				changed.Pool = netip.MustParsePrefix("10.91.0.0/16")
			case "gateway":
				changed.Gateway = netip.MustParseAddr("10.90.0.2")
			case "address":
				changed.Address = netip.MustParseAddr("10.90.1.11")
			case "mac":
				changed.MAC = "02:01:02:03:04:06"
			}
			if err := attachment.SetPolicy(t.Context(), changed); err == nil {
				t.Fatal("mutable policy changed immutable native identity")
			}
		})
	}
	if err := attachment.SetPolicy(t.Context(), original); err != nil {
		t.Fatal(err)
	}
}

func TestFunctionNetworkRevocationBeforeAttachIsFinal(t *testing.T) {
	attachment := &FunctionNetworkAttachment{spec: functionNetworkSpecification()}
	if err := attachment.Revoke(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := attachment.SetPolicy(t.Context(), attachment.spec); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("revoked policy restored authority: %v", err)
	}
	if err := attachment.Configure(t.Context(), &docker.ContainerConfig{}, ":4567"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("revoked lease created namespace: %v", err)
	}
	if err := attachment.Attach(t.Context(), "foreign"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("revoked lease attached customer container: %v", err)
	}
}

func TestFunctionNetworkCallbackAdmissionRejectsMalformedTargets(t *testing.T) {
	for _, target := range []string{"", "host", "host:0", "host:65536", "host:bad", "evil,exec=command:4567", "host\nname:4567"} {
		attachment := &FunctionNetworkAttachment{spec: functionNetworkSpecification()}
		if err := attachment.Configure(t.Context(), &docker.ContainerConfig{}, target); err == nil {
			t.Fatalf("malformed relay target accepted: %q", target)
		}
	}
}

func TestFunctionPacketPolicyExemptsOnlyRuntimeCallback(t *testing.T) {
	spec := functionNetworkSpecification()
	rules, err := network.Rules("stackd_lambda_012345", spec, spec.Policy, "veth-function", network.Options{Callback: "10.90.0.1:4567", PublicOwner: "function-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, "ip daddr 10.90.0.1 tcp dport 4567 return") || !strings.Contains(rules, "ip saddr 10.90.0.1 tcp sport 4567 return") {
		t.Fatal("runtime callback exact tuple missing")
	}
	if strings.Contains(rules, "169.254.169.254 tcp dport 80 accept") || strings.Contains(rules, "udp sport 68 udp dport 67 accept") {
		t.Fatal("Lambda received EC2 IMDS or DHCP guest exemptions")
	}
	if !strings.Contains(rules, "chain public_from {\ncounter drop") || !strings.Contains(rules, "chain public_to {\ncounter drop") {
		t.Fatal("private function acquired ambient public routing")
	}
}

func TestFunctionDNSAdaptsOnlyEnabledAmazonProvidedDNS(t *testing.T) {
	runtime := &FunctionNetworkRuntime{}
	if err := runtime.SetRuntimeDNS(docker.Networking{DNS: []string{"127.0.0.1"}}); err == nil {
		t.Fatal("unreachable loopback runtime resolver accepted")
	}
	if err := runtime.SetRuntimeDNS(docker.Networking{DNS: []string{"192.0.2.53"}}); err != nil {
		t.Fatal(err)
	}
	// A nil Engine proves no daemon discovery helper runs once resolvers are explicit.
	attachment := &FunctionNetworkAttachment{runtime: runtime}
	provider, custom := netip.MustParseAddr("10.90.0.2"), netip.MustParseAddr("10.90.7.53")
	for _, test := range []struct {
		dns     []netip.Addr
		enabled bool
		want    string
	}{
		{[]netip.Addr{provider}, true, "192.0.2.53"},
		{[]netip.Addr{custom}, true, "10.90.7.53"},
		{[]netip.Addr{custom, provider}, false, "10.90.7.53"},
		{[]netip.Addr{provider}, false, "127.0.0.1"},
	} {
		spec := functionNetworkSpecification()
		spec.DNS, spec.DNSSupport = test.dns, test.enabled
		servers, err := attachment.functionDNS(t.Context(), spec)
		if err != nil || strings.Join(servers, ",") != test.want {
			t.Fatalf("DHCP %v enabled %v rendered %v, %v; want %s", test.dns, test.enabled, servers, err, test.want)
		}
	}
}

func TestLambdaRuntimeDNSRejectsDesktopResolverDependency(t *testing.T) {
	_, err := NewDockerExecutor(t.Context(), DockerConfig{Client: &docker.Client{}, Namespace: "desktop-dns", CallbackHost: "host.docker.internal", Networking: docker.Networking{DNS: []string{"192.0.2.53"}}})
	if err == nil || !strings.Contains(err.Error(), "host.docker.internal") {
		t.Fatalf("explicit DNS silently removed Desktop callback resolution: %v", err)
	}
}
