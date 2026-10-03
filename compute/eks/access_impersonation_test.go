package eks

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"testing"
)

func TestNativeAccessPrimaryFixtures(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/eks/access_authentication.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		NamespacePatterns []struct {
			Pattern, Namespace string
			Allowed            bool
		}
		Impersonation []struct {
			Name, Resource, Namespace, ResourceName string
			Headers                                 http.Header
			Denied                                  bool
			Groups                                  []string
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.NamespacePatterns {
		if got := namespacePatternMatches(tc.Pattern, tc.Namespace); got != tc.Allowed {
			t.Errorf("scope %q matches %q = %v", tc.Pattern, tc.Namespace, got)
		}
	}
	for _, tc := range fixture.Impersonation {
		t.Run(tc.Name, func(t *testing.T) {
			identity, attributes, err := requestedImpersonation(tc.Headers)
			if tc.Denied {
				if err == nil {
					t.Fatalf("invalid impersonation admitted: %+v", identity)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(identity.Groups, tc.Groups) || attributes[0].Resource != tc.Resource || attributes[0].Namespace != tc.Namespace || attributes[0].Name != tc.ResourceName {
				t.Fatalf("incorrect native authorization identity: %+v %+v", identity, attributes)
			}
		})
	}
}
