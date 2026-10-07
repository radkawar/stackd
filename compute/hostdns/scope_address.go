package hostdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
)

// A single documentation-range /32 gives resolved a usable unicast scope.
// noprefixroute prevents installing a connected subnet route; only this exact
// owned address becomes local. The DNS server remains at the configured address.
var scopeNetworks = [...]netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

func isScopeAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return false
	}
	last := address.As4()[3]
	for _, network := range scopeNetworks {
		if network.Contains(address) && last != 0 && last != 255 {
			return true
		}
	}
	return false
}

func (b resolvedBackend) occupiedScopeRoutes(ctx context.Context) ([]netip.Prefix, error) {
	data, err := b.ipCommand(ctx, "-json", "-4", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	var routes []struct {
		Destination string `json:"dst"`
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, err
	}
	occupied := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		if route.Destination == "default" {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil {
			address, err := netip.ParseAddr(route.Destination)
			if err != nil {
				return nil, errors.New("hostdns: unrecognized native IPv4 route destination")
			}
			prefix = netip.PrefixFrom(address, 32)
		}
		if prefix.Bits() != 0 {
			occupied = append(occupied, prefix)
		}
	}
	return occupied, nil
}

func scopeAddressFree(address netip.Addr, occupied []netip.Prefix) bool {
	for _, prefix := range occupied {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func (b resolvedBackend) planScopeAddress(ctx context.Context) (string, error) {
	occupied, err := b.occupiedScopeRoutes(ctx)
	if err != nil {
		return "", err
	}
	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return "", err
	}
	const count = len(scopeNetworks) * 254
	start := (int(seed[0])<<8 | int(seed[1])) % count
	for i := 0; i < count; i++ {
		slot := (start + i) % count
		address := scopeNetworks[slot/254].Addr().As4()
		address[3] = byte(slot%254 + 1)
		candidate := netip.AddrFrom4(address)
		if scopeAddressFree(candidate, occupied) {
			return candidate.String(), nil
		}
	}
	return "", errors.New("hostdns: no unused documentation-range /32 for the dedicated resolver scope")
}

func (b resolvedBackend) scopeAddressAvailable(ctx context.Context, address string) (bool, error) {
	occupied, err := b.occupiedScopeRoutes(ctx)
	if err != nil {
		return false, err
	}
	return scopeAddressFree(netip.MustParseAddr(address), occupied), nil
}

func scopeNativeAddress(link, address string) json.RawMessage {
	return encoded(map[string]any{"family": "inet", "local": address, "prefixlen": 32, "scope": "global", "noprefixroute": true, "label": link, "valid_life_time": uint32(0xffffffff), "preferred_life_time": uint32(0xffffffff)})
}

func scopeNativeRoute(address string) json.RawMessage {
	return encoded(map[string]any{"type": "local", "dst": address, "table": "local", "protocol": "kernel", "scope": "host", "prefsrc": address, "flags": []any{}})
}

// Separate the address transition from interface identity. Partial installation
// can then be resumed or removed without claiming unrelated native settings.
func stripScopeAddress(state *ownedLink, address string) (bool, error) {
	foundAddress, foundRoute := false, false
	addresses := state.Addresses[:0]
	for _, raw := range state.Addresses {
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			return false, err
		}
		if fields["local"] != address {
			addresses = append(addresses, raw)
			continue
		}
		if foundAddress || !bytes.Equal(encoded(fields), scopeNativeAddress(state.Name, address)) {
			return false, conflict("ScopeAddress settings")
		}
		foundAddress = true
	}
	state.Addresses = addresses
	routes := state.Routes[:0]
	for _, raw := range state.Routes {
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			return false, err
		}
		if fields["dst"] != address {
			routes = append(routes, raw)
			continue
		}
		// linkdown reflects the separately recorded Activated transition.
		if flags, ok := fields["flags"].([]any); ok && len(flags) == 1 && flags[0] == "linkdown" {
			fields["flags"] = []any{}
		}
		if foundRoute || !bytes.Equal(encoded(fields), scopeNativeRoute(address)) {
			return false, conflict("ScopeAddress route")
		}
		foundRoute = true
	}
	state.Routes = routes
	if foundAddress != foundRoute {
		return false, conflict("ScopeAddress address/route mismatch")
	}
	return foundAddress, nil
}
