package sts

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/awswire"
)

const oidcRolesClaim = "https://aws.amazon.com/roles"

func oidcAuthorizedRoles(claims map[string]json.RawMessage) ([]string, bool, *awswire.Error) {
	raw, present := claims[oidcRolesClaim]
	if !present || bytes.Equal(raw, []byte("null")) {
		return nil, false, nil
	}
	var candidates []string
	if len(raw) > 0 && raw[0] == '"' {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return nil, true, invalidOIDCToken("The roles claim is not in a supported format")
		}
		candidates = strings.Split(value, ";")
	} else {
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return nil, true, invalidOIDCToken("The roles claim is not in a supported format")
		}
		for _, raw := range values {
			var value string
			if json.Unmarshal(raw, &value) == nil {
				candidates = append(candidates, value)
			}
		}
	}
	var roles []string
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		role, err := arn.Parse(candidate)
		if err == nil && role.Service == "iam" && role.Region == "" && !strings.ContainsAny(role.Resource, ":;*?") && oidcRolePartition.MatchString(role.Partition) && oidcRoleAccount.MatchString(role.AccountID) && oidcRoleResource.MatchString(role.Resource) {
			roles = append(roles, candidate)
		}
	}
	if len(roles) == 0 {
		return nil, true, invalidOIDCToken("The roles claim contains no valid role ARNs")
	}
	return roles, true, nil
}

// authorizeRole runs only after authentication has verified the JWT signature.
// Role ARNs are exact identifiers; wildcard or policy-pattern matching would
// widen the authority granted by the identity provider.
func (i oidcIdentity) authorizeRole(roleARN string) (bool, *awswire.Error) {
	if !i.hasRolesClaim {
		return false, nil
	}
	if !slices.Contains(i.authorizedRoles, roleARN) {
		return false, invalidOIDCToken("The target role ARN is not present in the roles claim of the identity token")
	}
	return true, nil
}
