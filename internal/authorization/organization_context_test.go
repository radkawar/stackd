package authorization_test

import (
	"context"
	"errors"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

type principalOrganizationSource struct {
	id, path string
	err      error
}

func (s principalOrganizationSource) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return nil, nil
}
func (s principalOrganizationSource) PrincipalOrganization(context.Context) (string, string, error) {
	return s.id, s.path, s.err
}

func TestPrincipalOrganizationConditionsUseTrustedMembership(t *testing.T) {
	document := `{"Statement":{"Effect":"Allow","Action":"sts:GetWebIdentityToken","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-example"},"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":"o-example/r-root/ou-work/*"}}}}`
	source := identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: document}}}}
	for _, tc := range []struct {
		name     string
		org      principalOrganizationSource
		supplied map[string][]string
		allow    bool
	}{
		{"member", principalOrganizationSource{id: "o-example", path: "o-example/r-root/ou-work/"}, nil, true},
		{"other OU", principalOrganizationSource{id: "o-example", path: "o-example/r-root/ou-other/"}, nil, false},
		{"nonmember", principalOrganizationSource{}, nil, false},
		{"forged membership", principalOrganizationSource{}, map[string][]string{"aws:PrincipalOrgID": {"o-example"}, "aws:PrincipalOrgPaths": {"o-example/r-root/ou-work/"}}, false},
		{"source error", principalOrganizationSource{err: errors.New("storage failure")}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := authorization.New(source, tc.org)
			err := e.Authorize(awsctx.WithMetadata(t.Context(), metadata(false)), authorization.Request{Action: "sts:GetWebIdentityToken", ResourceARN: "arn:aws:sts::123456789012:self", Context: tc.supplied})
			if (err == nil) != tc.allow {
				t.Fatalf("authorization %v, want allow %v", err, tc.allow)
			}
		})
	}
}
