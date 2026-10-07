package lambda

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"stackd/compute/docker"
	"stackd/compute/network"
)

// functionDNS implements the explicitly selected AmazonProvidedDNS service with
// the operator's runtime resolvers, or else Docker's actual embedded namespace
// resolver and the daemon's own upstreams. Only that EC2 DHCP selection is
// adapted: custom DHCP servers stay exact, and absent/disabled DNS never falls
// back to the controller or host resolver. Forwarded queries leave the function
// namespace, so routes, security groups and network ACLs still apply.
// Endpoint routing uses authoritative private IP URLs, not invented AWS zones.
func (a *FunctionNetworkAttachment) functionDNS(ctx context.Context, spec network.Specification) ([]string, error) {
	provider := spec.Pool.Addr().Next().Next()
	return docker.Networking{DNS: a.runtime.dns}.SelectedDNS(spec.DNS, provider, spec.DNSSupport, func() ([]string, error) {
		output, err := docker.RunHelper(ctx, a.runtime.client, "lambda-managed-dns", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"cat", "/etc/resolv.conf"}, Labels: map[string]string{functionNetworkLabel: a.owner, functionNetworkOwnerLabel: a.runtime.namespace}, HostConfig: docker.ContainerHostConfig{NetworkMode: "bridge", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 32 << 20, MemorySwap: 32 << 20, PidsLimit: 16, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}}})
		if err != nil {
			return nil, err
		}
		var servers []string
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
		if len(servers) == 0 {
			return nil, errors.New("the selected Docker daemon has no usable IPv4 upstream for AmazonProvidedDNS")
		}
		return servers, nil
	})
}

// SetRuntimeDNS selects the resolvers substituted for EC2-selected
// AmazonProvidedDNS in namespaces configured afterwards. Empty retains daemon
// upstream discovery. Call before serving; existing namespaces keep native DNS.
func (r *FunctionNetworkRuntime) SetRuntimeDNS(networking docker.Networking) error {
	if err := (docker.Networking{DNS: networking.DNS}).Validate(); err != nil {
		return err
	}
	r.dns = slices.Clone(networking.DNS)
	return nil
}
