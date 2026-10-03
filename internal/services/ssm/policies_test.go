package ssm

import (
	"errors"
	"testing"
	"time"

	"stackd/internal/awswire"
)

func TestPolicyValidationBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, document, code string }{
		{"malformed", "not-json", "ValidationException"},
		{"unknown type", `[{"Type":"Unknown","Version":"1.0","Attributes":{}}]`, "InvalidPolicyTypeException"},
		{"zero interval", `[{"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"0","Unit":"Days"}}]`, "InvalidPolicyAttributeException"},
		{"fractional interval", `[{"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"0.5","Unit":"Days"}}]`, "InvalidPolicyAttributeException"},
		{"missing expiration", `[{"Type":"ExpirationNotification","Version":"1.0","Attributes":{"Before":"1","Unit":"Days"}}]`, "InvalidPolicyAttributeException"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePolicies(tc.document, now)
			var wire *awswire.Error
			if !errors.As(err, &wire) || wire.Code != tc.code {
				t.Fatalf("error = %v, want %s", err, tc.code)
			}
		})
	}
	for _, document := range []string{"[]", "[{}]"} {
		policies, err := parsePolicies(document, now)
		if err != nil || len(policies) != 0 {
			t.Fatalf("explicit clear %s: %#v %v", document, policies, err)
		}
	}
	policies, err := parsePolicies(`[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2026-09-02T00:00:00Z"}},{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2026-09-02T00:00:00Z"}}]`, now)
	if err != nil {
		t.Fatal(err)
	}
	var expiration time.Time
	for _, policy := range policies {
		if expiration.IsZero() || policy.Due.Before(expiration) {
			expiration = policy.Due
		}
	}
	if !expiration.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("duplicate expiration deadline = %v", expiration)
	}
}

func TestPolicyRefreshPreservesExpirationAcknowledgment(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	policies, err := parsePolicies(`[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2026-09-03T00:00:00Z"}},{"Type":"ExpirationNotification","Version":"1.0","Attributes":{"Before":"1","Unit":"Days"}},{"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"1","Unit":"Days"}}]`, now)
	if err != nil {
		t.Fatal(err)
	}
	policies[1].Fired, policies[2].Fired = true, true
	refreshed, err := refreshPolicies(policies, now.Add(12*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed[0].Due.Equal(policies[0].Due) || !refreshed[1].Due.Equal(policies[1].Due) || !refreshed[1].Fired {
		t.Fatalf("value update reset expiration policies: %#v", refreshed)
	}
	if refreshed[2].Fired || !refreshed[2].Due.Equal(now.Add(36*time.Hour)) {
		t.Fatalf("inactivity deadline did not rearm: %#v", refreshed[2])
	}
	if !policies[2].Fired || !policies[2].Due.Equal(now.Add(24*time.Hour)) {
		t.Fatal("refresh mutated historical policy state")
	}
}
