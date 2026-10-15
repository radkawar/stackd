package docker

import "testing"

func TestCompatibleAPIVersionRange(t *testing.T) {
	// Reject disjoint or invalid ranges, including modern daemon minimums;
	// older engines remain usable at their supported upper boundary.
	for _, test := range []struct {
		name, maximum, minimum, want string
	}{
		{"legacy-minimum-omitted", "1.41", "", "/v1.41"},
		{"raised-daemon-minimum", "1.52", "1.44", "/v1.48"},
		{"exact-common-boundary", "1.42", "1.42", "/v1.42"},
		{"daemon-too-old", "1.40", "1.24", ""},
		{"minimum-exceeds-client-support", "1.52", "1.49", ""},
		{"contradictory-daemon-range", "1.43", "1.44", ""},
		{"malformed-minimum", "1.52", "unknown", ""},
		{"negative-minimum", "1.52", "1.-1", ""},
		{"gateway-priority-boundary", "1.48", "1.48", "/v1.48"},
		{"older-daemon-still-supported", "1.47", "1.41", "/v1.47"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := compatibleAPIVersion(test.maximum, test.minimum)
			if test.want == "" {
				if err == nil || got != "" {
					t.Fatalf("unsupported range selected %q: %v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("selected %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestNegotiatedFeatureCapability(t *testing.T) {
	for _, minor := range []int{41, 44, 47, 48} {
		client := &Client{apiMinor: minor}
		if !client.SupportsAPIVersion(1, 41) {
			t.Fatal("unrelated older-daemon features were rejected")
		}
		if client.SupportsAPIVersion(1, 48) != (minor >= 48) {
			t.Fatalf("gateway priority capability differs from negotiated1.%d", minor)
		}
		if client.SupportsAPIVersion(2, 0) {
			t.Fatal("unnegotiated future API was accepted")
		}
	}
}
