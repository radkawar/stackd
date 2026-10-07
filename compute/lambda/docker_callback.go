package lambda

import (
	"context"
	"fmt"
	"net"
)

// Docker Desktop resolves host.docker.internal in its own DNS namespace, not
// necessarily on the controller. Leave that name unshadowed in the container.
// Other explicit hosts keep the Linux/remote-engine address mapping contract.
func callbackNetwork(ctx context.Context, identity, callbackHost string) (string, []string, error) {
	hostname := identity + ".runtime.internal"
	extraHosts := []string{"sandbox.localdomain:127.0.0.1"}
	if callbackHost == "host.docker.internal" {
		return callbackHost, extraHosts, nil
	}
	gateway := "host-gateway"
	if callbackHost != "" {
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, callbackHost)
		if err != nil {
			return "", nil, fmt.Errorf("resolving Lambda callback host %q: %w", callbackHost, err)
		}
		if len(addresses) == 0 {
			return "", nil, fmt.Errorf("lambda callback host %q resolved to no addresses", callbackHost)
		}
		gateway = addresses[0].IP.String()
		for _, address := range addresses {
			if address.IP.To4() != nil {
				gateway = address.IP.String()
				break
			}
		}
	}
	extraHosts = append(extraHosts, hostname+":"+gateway, "host.docker.internal:"+gateway)
	return hostname, extraHosts, nil
}
