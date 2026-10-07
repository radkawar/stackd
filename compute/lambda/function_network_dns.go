package lambda

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"stackd/compute/docker"
	"stackd/compute/network"
)

// functionDNS uses Docker's actual embedded namespace resolver to implement the
// explicitly selected AmazonProvidedDNS service. Only that EC2 DHCP selection
// permits daemon-side upstream resolution; custom DHCP servers stay exact, and
// absent/disabled DNS never falls back to the controller or host resolver.
// Endpoint routing uses authoritative private IP URLs, not invented AWS zones.
func (a *FunctionNetworkAttachment) functionDNS(ctx context.Context, spec network.Specification) ([]string, error) {
	var servers []string
	provider := spec.Pool.Addr().Next().Next()
	for _, dns := range spec.DNS {
		if dns != provider {
			servers = append(servers, dns.String())
			continue
		}
		if !spec.DNSSupport {
			continue
		}
		output, err := docker.RunHelper(ctx, a.runtime.client, "lambda-managed-dns", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"cat", "/etc/resolv.conf"}, Labels: map[string]string{functionNetworkLabel: a.owner, functionNetworkOwnerLabel: a.runtime.namespace}, HostConfig: docker.ContainerHostConfig{NetworkMode: "bridge", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 32 << 20, MemorySwap: 32 << 20, PidsLimit: 16, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}}})
		if err != nil {
			return nil, err
		}
		before := len(servers)
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			address, err := netip.ParseAddr(fields[1])
			if err == nil && address.Is4() && !address.IsLoopback() && address != provider {
				servers = append(servers, address.String())
			}
		}
		if len(servers) == before {
			return nil, errors.New("the selected Docker daemon has no usable IPv4 upstream for AmazonProvidedDNS")
		}
	}
	if len(servers) == 0 {
		servers = []string{"127.0.0.1"}
	}
	return servers, nil
}
