package docker

import "testing"

func TestCompatibleAPIVersionRange(t *testing.T) {
	// The actual managed guest's Docker 29.1.3 rejected /v1.41/info because its
	// minimum is 1.44. Choose the lowest supported intersection, not the daemon's
	// newest API or an unconditional legacy version.
	for _, test := range []struct {
		name, maximum, minimum, want string
	}{
		{"legacy-minimum-omitted", "1.41", "", "/v1.41"},
		{"retain-compatible-old-protocol", "1.52", "1.24", "/v1.41"},
		{"raised-daemon-minimum", "1.52", "1.44", "/v1.44"},
		{"exact-common-boundary", "1.42", "1.42", "/v1.42"},
		{"daemon-too-old", "1.40", "1.24", ""},
		{"minimum-exceeds-client-support", "1.52", "1.45", ""},
		{"contradictory-daemon-range", "1.43", "1.44", ""},
		{"malformed-minimum", "1.52", "unknown", ""},
		{"negative-minimum", "1.52", "1.-1", ""},
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
