package identitycenter

import (
	"testing"
)

func TestPermissionSetDurationCanonicalOutput(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"", "PT1H"},
		{"PT1H", "PT1H"},
		{"PT2H", "PT2H"},
		{"PT3600S", "PT1H"},
		{"PT3661S", "PT1H1M1S"},
		{"PT90M", "PT1H30M"},
		{"PT1H0M0S", "PT1H"},
		{"PT12H", "PT12H"},
	} {
		t.Run(test.input, func(t *testing.T) {
			duration, err := parseDuration(test.input)
			if err != nil {
				t.Fatal(err)
			}
			out := wirePermission(PermissionSet{Duration: duration})
			if got := string(*out.SessionDuration); got != test.want {
				t.Fatalf("SessionDuration = %q, want %q", got, test.want)
			}
		})
	}
}
