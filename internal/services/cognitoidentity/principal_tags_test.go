package cognitoidentity

import (
	"maps"
	"strings"
	"testing"

	api "stackd/internal/awsapi/cognitoidentity"
)

func TestPrincipalSessionTagClaims(t *testing.T) {
	p := PoolRecord{PrincipalTagMaps: map[string]PrincipalTagMap{"provider": {Tags: api.PrincipalTags{"department": "department"}}}}
	for _, tc := range []struct {
		name    string
		claim   any
		want    string
		invalid bool
	}{
		{"string", "legal", "legal", false}, {"boolean", true, "true", false}, {"number", float64(42), "42", false},
		{"empty", "", "", false}, {"maximum", strings.Repeat("a", 256), strings.Repeat("a", 256), false},
		{"oversized", strings.Repeat("a", 257), "", true}, {"array", []any{"legal"}, "", true}, {"object", map[string]any{"value": "legal"}, "", true}, {"null", nil, "", true}, {"wildcard", "*", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := principalSessionTags(p, []verifiedLogin{{Login: Login{Provider: "provider"}, Claims: map[string]any{"department": tc.claim}}})
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid claim issued session tags")
				}
				return
			}
			if err != nil || got["department"] != tc.want {
				t.Fatalf("tags=%v err=%v", got, err)
			}
		})
	}
	if _, err := principalSessionTags(p, []verifiedLogin{{Login: Login{Provider: "provider"}, Claims: map[string]any{}}}); err == nil {
		t.Fatal("missing mapped authority accepted")
	}
	got, err := principalSessionTags(p, []verifiedLogin{{Login: Login{Provider: "other"}, Claims: map[string]any{"department": "legal"}}})
	if err != nil || len(got) != 0 {
		t.Fatalf("provider mapping leaked: %v %v", got, err)
	}
}

func TestPrincipalTagsConflictsAndSnapshotIsolation(t *testing.T) {
	p := PoolRecord{PrincipalTagMaps: map[string]PrincipalTagMap{"first": {Tags: api.PrincipalTags{"department": "department"}}, "second": {Tags: api.PrincipalTags{"department": "department"}}}}
	logins := []verifiedLogin{{Login: Login{Provider: "first"}, Claims: map[string]any{"department": "legal"}}, {Login: Login{Provider: "second"}, Claims: map[string]any{"department": "finance"}}}
	if _, err := principalSessionTags(p, logins); err == nil {
		t.Fatal("conflicting authorities merged")
	}
	logins[1].Claims["department"] = "legal"
	tags, err := principalSessionTags(p, logins)
	if err != nil || !maps.Equal(tags, map[string]string{"department": "legal"}) {
		t.Fatalf("equal authorities: %v %v", tags, err)
	}
	detached := clonePool(p)
	detached.PrincipalTagMaps["first"].Tags["department"] = "sub"
	if p.PrincipalTagMaps["first"].Tags["department"] != "department" {
		t.Fatal("detached mutation changed stored map")
	}
	if tags["department"] != "legal" {
		t.Fatal("mapping mutation changed issued tags")
	}
}
