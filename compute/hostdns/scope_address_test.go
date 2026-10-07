package hostdns

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func TestScopeAddressDoesNotClaimExistingRoutes(t *testing.T) {
	occupied := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.7/32")}
	for _, test := range []struct {
		address string
		free    bool
	}{
		{"192.0.2.1", false}, {"192.0.2.254", false}, {"198.51.100.7", false}, {"198.51.100.8", true}, {"203.0.113.1", true},
	} {
		if got := scopeAddressFree(netip.MustParseAddr(test.address), occupied); got != test.free {
			t.Fatalf("address %s free=%v, want %v", test.address, got, test.free)
		}
	}
	for _, address := range []string{"127.0.0.1", "192.0.2.0", "192.0.2.255", "198.51.100.8/32", "::1"} {
		if isScopeAddress(address) {
			t.Fatalf("receipt can claim invalid scope address %s", address)
		}
	}
}

func TestScopeAddressOwnershipRejectsExternalMutations(t *testing.T) {
	const address = "192.0.2.7"
	for _, mutation := range []string{"none", "down", "prefix", "lifetime", "metric", "missing-route", "missing-address", "duplicate"} {
		t.Run(mutation, func(t *testing.T) {
			state := ownedLink{Name: "sdnsowned", Addresses: []json.RawMessage{scopeNativeAddress("sdnsowned", address)}, Routes: []json.RawMessage{scopeNativeRoute(address)}}
			var fields map[string]any
			switch mutation {
			case "prefix", "lifetime":
				if err := json.Unmarshal(state.Addresses[0], &fields); err != nil {
					t.Fatal(err)
				}
				if mutation == "prefix" {
					fields["prefixlen"] = 24
				} else {
					fields["valid_life_time"] = 30
				}
				state.Addresses[0] = encoded(fields)
			case "metric", "down":
				if err := json.Unmarshal(state.Routes[0], &fields); err != nil {
					t.Fatal(err)
				}
				if mutation == "metric" {
					fields["metric"] = 7
				} else {
					fields["flags"] = []any{"linkdown"}
				}
				state.Routes[0] = encoded(fields)
			case "missing-route":
				state.Routes = nil
			case "missing-address":
				state.Addresses = nil
			case "duplicate":
				state.Addresses = append(state.Addresses, state.Addresses[0])
			}
			present, err := stripScopeAddress(&state, address)
			if mutation == "none" || mutation == "down" {
				if err != nil || !present || len(state.Addresses) != 0 || len(state.Routes) != 0 {
					t.Fatalf("owned state: %+v %t %v", state, present, err)
				}
			} else if err == nil {
				t.Fatalf("accepted external %s mutation", mutation)
			}
		})
	}
}
