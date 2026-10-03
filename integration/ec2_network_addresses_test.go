package stackd_test

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"testing"
)

// Native automatic addresses are arbitrary free hosts. Keep a permutation of
// each fixture's address space so later explicit requests still address the same
// live allocation or free host. Never replace an allocated address on a retry.
// These captures use nonoverlapping live subnets; resource IDs remain separately
// bound by the shared SDK comparison.
type ec2NetworkAddresses struct {
	bindings   map[string]string
	owners     map[string]string
	subnets    map[string]netip.Prefix
	interfaces map[string]string
	placements map[string]ec2NetworkPlacement
}

type ec2NetworkPlacement struct{ Name, ID string }

func newEC2NetworkAddresses(bindings map[string]string) *ec2NetworkAddresses {
	return &ec2NetworkAddresses{bindings: bindings, owners: map[string]string{}, subnets: map[string]netip.Prefix{}, interfaces: map[string]string{}, placements: map[string]ec2NetworkPlacement{}}
}

func (a *ec2NetworkAddresses) address(native string) string {
	if actual, ok := a.bindings[native]; ok {
		return actual
	}
	return native
}

func (a *ec2NetworkAddresses) observe(t *testing.T, action string, input json.RawMessage, native, actual map[string]any) {
	t.Helper()
	var request struct {
		NetworkInterfaceId                   string
		PrivateIpAddress                     string
		PrivateIpAddresses                   []json.RawMessage
		AvailabilityZone, AvailabilityZoneId *string
	}
	if err := json.Unmarshal(input, &request); err != nil {
		t.Fatal(err)
	}
	explicit := map[string]bool{}
	if request.PrivateIpAddress != "" {
		explicit[request.PrivateIpAddress] = true
	}
	for _, raw := range request.PrivateIpAddresses {
		var ip string
		if err := json.Unmarshal(raw, &ip); err != nil {
			var specification struct{ PrivateIpAddress string }
			if err := json.Unmarshal(raw, &specification); err != nil {
				t.Fatal(err)
			}
			ip = specification.PrivateIpAddress
		}
		explicit[ip] = true
	}
	switch action {
	case "AllocateAddress":
		before, after := native["PublicIp"].(string), actual["PublicIp"].(string)
		address, err := netip.ParseAddr(after)
		if err != nil || !netip.MustParsePrefix("198.18.0.0/15").Contains(address) {
			t.Fatalf("public address is not in the host-mapped pool: %q", after)
		}
		for original, assigned := range a.bindings {
			if original != before && assigned == after {
				t.Fatalf("distinct allocations share public IPv4 %s", after)
			}
		}
		a.bindings[before] = after
	case "CreateSubnet":
		subnet := native["Subnet"].(map[string]any)
		prefix, err := netip.ParsePrefix(subnet["CidrBlock"].(string))
		if err != nil {
			t.Fatal(err)
		}
		a.subnets[subnet["SubnetId"].(string)] = prefix
		if request.AvailabilityZone == nil && request.AvailabilityZoneId == nil {
			got := actual["Subnet"].(map[string]any)
			placement := ec2NetworkPlacement{Name: got["AvailabilityZone"].(string), ID: got["AvailabilityZoneId"].(string)}
			a.placements[subnet["SubnetId"].(string)] = placement
			a.placements[got["SubnetId"].(string)] = placement
		}
	case "CreateNetworkInterface":
		want, got := native["NetworkInterface"].(map[string]any), actual["NetworkInterface"].(map[string]any)
		id := want["NetworkInterfaceId"].(string)
		a.interfaces[id] = want["SubnetId"].(string)
		a.bind(t, id, want["PrivateIpAddresses"].([]any), got["PrivateIpAddresses"].([]any), explicit)
		for _, key := range []string{"MacAddress", "RequesterId"} {
			before, after := want[key].(string), got[key].(string)
			if previous, exists := a.bindings[before]; exists && previous != after {
				t.Fatalf("%s changed from %s to %s", key, previous, after)
			}
			if key == "MacAddress" {
				mac, err := net.ParseMAC(after)
				if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
					t.Fatalf("invalid interface MAC %q", after)
				}
				for other, value := range a.bindings {
					if other != before && value == after {
						t.Fatalf("distinct interface MACs %s and %s collapsed to %s", other, before, after)
					}
				}
			}
			a.bindings[before] = after
		}
	case "AssignPrivateIpAddresses":
		a.bind(t, request.NetworkInterfaceId, native["AssignedPrivateIpAddresses"].([]any), actual["AssignedPrivateIpAddresses"].([]any), explicit)
	case "UnassignPrivateIpAddresses":
		for ip := range explicit {
			delete(a.owners, ip)
		}
	case "DeleteNetworkInterface":
		for ip, owner := range a.owners {
			if owner == request.NetworkInterfaceId {
				delete(a.owners, ip)
			}
		}
		delete(a.interfaces, request.NetworkInterfaceId)
	}
}

// Check automatic placement against the subnet's retained choice, then remove
// these fields before global resource-ID binding. Two subnets can independently
// choose the same local zone even when AWS placed them in different zones.
func (a *ec2NetworkAddresses) comparePlacement(t *testing.T, native, actual any) {
	t.Helper()
	switch want := native.(type) {
	case map[string]any:
		got, _ := actual.(map[string]any)
		id, _ := want["SubnetId"].(string)
		if placement, ok := a.placements[id]; ok {
			for name, expected := range map[string]string{"AvailabilityZone": placement.Name, "AvailabilityZoneId": placement.ID} {
				if _, present := want[name]; present {
					if got[name] != expected {
						t.Fatalf("subnet %s changed %s: got %v, retained %s", id, name, got[name], expected)
					}
					delete(want, name)
					delete(got, name)
				}
			}
		}
		for name, child := range want {
			a.comparePlacement(t, child, got[name])
		}
	case []any:
		got, _ := actual.([]any)
		for index, child := range want {
			if index < len(got) {
				a.comparePlacement(t, child, got[index])
			}
		}
	}
}

func (a *ec2NetworkAddresses) normalizeAuditPlacement(value any) {
	switch value := value.(type) {
	case map[string]any:
		id, _ := value["subnetId"].(string)
		if placement, ok := a.placements[id]; ok {
			if _, present := value["availabilityZone"]; present {
				value["availabilityZone"] = placement.Name
			}
			if _, present := value["availabilityZoneId"]; present {
				value["availabilityZoneId"] = placement.ID
			}
		}
		for _, child := range value {
			a.normalizeAuditPlacement(child)
		}
	case []any:
		for _, child := range value {
			a.normalizeAuditPlacement(child)
		}
	}
}

func (a *ec2NetworkAddresses) bind(t *testing.T, id string, native, actual []any, explicit map[string]bool) {
	t.Helper()
	if len(native) != len(actual) {
		t.Fatalf("%s address count: native %d, got %d", id, len(native), len(actual))
	}
	available := map[string]map[string]any{}
	prefix := a.subnets[a.interfaces[id]]
	for _, item := range actual {
		entry := item.(map[string]any)
		text := entry["PrivateIpAddress"].(string)
		ip, err := netip.ParseAddr(text)
		if err != nil || !ip.Is4() || !prefix.Contains(ip) {
			t.Fatalf("%s returned address %q outside subnet %s", id, text, prefix)
		}
		base, host := prefix.Masked().Addr().As4(), ip.As4()
		network, address := binary.BigEndian.Uint32(base[:]), binary.BigEndian.Uint32(host[:])
		if address < network+4 || address == network+(^uint32(0)>>prefix.Bits()) {
			t.Fatalf("%s allocated reserved subnet address %s", id, text)
		}
		if _, exists := available[text]; exists {
			t.Fatalf("%s returned duplicate address %s", id, text)
		}
		available[text] = entry
	}
	pending := []map[string]any{}
	for _, item := range native {
		entry := item.(map[string]any)
		ip := entry["PrivateIpAddress"].(string)
		if a.owners[ip] != "" || explicit[ip] {
			mapped := a.address(ip)
			if available[mapped] == nil {
				t.Fatalf("%s lost requested or retained address %s (%s)", id, ip, mapped)
			}
			delete(available, mapped)
			a.owners[ip] = id
		} else {
			pending = append(pending, entry)
		}
	}
	slices.SortFunc(pending, func(x, y map[string]any) int {
		return netip.MustParseAddr(x["PrivateIpAddress"].(string)).Compare(netip.MustParseAddr(y["PrivateIpAddress"].(string)))
	})
	for _, entry := range pending {
		ip := entry["PrivateIpAddress"].(string)
		candidates := []string{}
		for candidate, got := range available {
			if got["Primary"] == entry["Primary"] {
				candidates = append(candidates, candidate)
			}
		}
		slices.Sort(candidates)
		if len(candidates) == 0 {
			t.Fatalf("%s has no matching primary/secondary address for %s", id, ip)
		}
		chosen, previous := candidates[0], a.address(ip)
		other := chosen
		for before, after := range a.bindings {
			if after == chosen {
				other = before
				break
			}
		}
		if owner := a.owners[other]; owner != "" {
			t.Fatalf("%s reused address %s owned by %s", id, chosen, owner)
		}
		a.bindings[ip], a.bindings[other] = chosen, previous
		a.owners[ip] = id
		delete(available, chosen)
	}
}
