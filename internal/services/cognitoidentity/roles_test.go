package cognitoidentity

import (
	"testing"

	api "stackd/internal/awsapi/cognitoidentity"
)

// Native 2026-09-28: Cognito groups are array claims; Contains can select a role
// from them. CustomRoleArn with a Rules mapping is an InvalidParameterException.
func TestGroupClaimRoleMapping(t *testing.T) {
	pool := PoolRecord{Roles: api.RolesMap{"authenticated": "arn:aws:iam::123456789012:role/default"}, Mappings: api.RoleMappingMap{"provider:client": {Type: new(api.RoleMappingType("Rules")), AmbiguousRoleResolution: new(api.AmbiguousRoleResolutionType("AuthenticatedRole")), RulesConfiguration: &api.RulesConfigurationType{Rules: api.MappingRulesList{{Claim: new(api.ClaimName("cognito:groups")), MatchType: new(api.MappingRuleMatchType("Contains")), Value: new(api.ClaimValue("readers")), RoleARN: new(api.ARNString("arn:aws:iam::123456789012:role/readers"))}}}}}}
	login := verifiedLogin{Login: Login{Provider: "provider", Subject: "subject"}, ClientID: "client", Claims: map[string]any{"cognito:groups": []any{"readers"}}}
	role, err := mappedRole(pool, login, "")
	if err != nil || role != "arn:aws:iam::123456789012:role/readers" {
		t.Fatalf("group rule chose %q: %v", role, err)
	}
	_, err = mappedRole(pool, login, "arn:aws:iam::123456789012:role/readers")
	if err == nil || wireError(err).Code != "InvalidParameterException" {
		t.Fatalf("rules custom role error: %v", err)
	}
}
