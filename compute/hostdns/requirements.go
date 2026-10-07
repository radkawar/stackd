package hostdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

func localDNSAddress(address netip.Addr, assigned []netip.Prefix) bool {
	if address.IsLoopback() {
		return true
	}
	for _, prefix := range assigned {
		if prefix.Addr().Unmap() == address.Unmap() {
			return true
		}
	}
	return false
}

func assignedDNSAddress(address netip.Addr) (bool, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("hostdns: inspect local DNS addresses: %w", err)
	}
	var assigned []netip.Prefix
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			assigned = append(assigned, prefix)
		}
	}
	return localDNSAddress(address, assigned), nil
}

func (b resolvedBackend) automaticRequirements(ctx context.Context, c Config) error {
	if b.ip == "" {
		return errors.New("hostdns: automatic interfaces require installed native iproute2 ip")
	}
	local, err := assignedDNSAddress(netip.MustParseAddrPort(c.Address).Addr())
	if err != nil {
		return err
	}
	if !local {
		return errors.New("hostdns: automatic dummy link requires DNS on loopback or an IP assigned to this host; remote DNS requires an explicit routed interface")
	}
	return nil
}
