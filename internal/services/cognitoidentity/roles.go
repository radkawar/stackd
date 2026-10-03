package cognitoidentity

import (
	"slices"
	api "stackd/internal/awsapi/cognitoidentity"
	"strings"
)

func registerRoles(s *Service) {
	register(s, "SetIdentityPoolRoles", s.setRoles)
	register(s, "GetIdentityPoolRoles", s.getRoles)
}
func (s *Service) getRoles(tx Transaction, in *api.GetIdentityPoolRolesInput) (*api.GetIdentityPoolRolesOutput, error) {
	p, e := s.adminPool(tx, "GetIdentityPoolRoles", value(in.IdentityPoolId))
	if e != nil {
		return nil, e
	}
	return &api.GetIdentityPoolRolesOutput{IdentityPoolId: in.IdentityPoolId, Roles: p.Roles, RoleMappings: p.Mappings}, nil
}
func (s *Service) setRoles(tx Transaction, in *api.SetIdentityPoolRolesInput) (*api.SetIdentityPoolRolesOutput, error) {
	p, e := s.adminPool(tx, "SetIdentityPoolRoles", value(in.IdentityPoolId))
	if e != nil {
		return nil, e
	}
	checkRole := func(arn string) error {
		parts := strings.SplitN(arn, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != p.Key.Partition || parts[2] != "iam" || parts[3] != "" || parts[4] != p.Key.AccountID || !strings.HasPrefix(parts[5], "role/") {
			return failure("InvalidParameterException", "Role must belong to the identity pool account.")
		}
		return s.authorize(tx, "iam:PassRole", arn, map[string][]string{"iam:PassedToService": {"cognito-identity.amazonaws.com"}})
	}
	for kind, role := range in.Roles {
		if kind != "authenticated" && kind != "unauthenticated" {
			return nil, failure("InvalidParameterException", "Invalid role type.")
		}
		if e := checkRole(string(role)); e != nil {
			return nil, e
		}
	}
	for provider, mapping := range in.RoleMappings {
		configured := false
		for _, p := range p.Providers {
			if string(provider) == value(p.ProviderName)+":"+value(p.ClientId) {
				configured = true
			}
		}
		if !configured {
			return nil, failure("InvalidParameterException", "Role mapping provider is not configured.")
		}
		if value(mapping.AmbiguousRoleResolution) != "AuthenticatedRole" && value(mapping.AmbiguousRoleResolution) != "Deny" {
			return nil, failure("InvalidParameterException", "AmbiguousRoleResolution must be AuthenticatedRole or Deny.")
		}
		switch value(mapping.Type) {
		case "Token":
			if mapping.RulesConfiguration != nil {
				return nil, failure("InvalidParameterException", "Token mappings cannot contain rules.")
			}
		case "Rules":
			if mapping.RulesConfiguration == nil || len(mapping.RulesConfiguration.Rules) == 0 {
				return nil, failure("InvalidParameterException", "Rules are required.")
			}
			for _, rule := range mapping.RulesConfiguration.Rules {
				if !slices.Contains([]string{"Equals", "NotEqual", "StartsWith", "Contains"}, value(rule.MatchType)) {
					return nil, failure("InvalidParameterException", "Invalid rule match type.")
				}
				if e := checkRole(value(rule.RoleARN)); e != nil {
					return nil, e
				}
			}
		default:
			return nil, failure("InvalidParameterException", "Invalid role mapping type.")
		}
	}
	p.Roles = in.Roles
	p.Mappings = in.RoleMappings
	return &api.SetIdentityPoolRolesOutput{}, tx.PutPool(p)
}
func claimString(claims map[string]any, key string) string { v, _ := claims[key].(string); return v }
func claimRoles(claims map[string]any) []string {
	raw, _ := claims["cognito:roles"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if role, ok := v.(string); ok {
			out = append(out, role)
		}
	}
	return out
}
func mappedRole(p PoolRecord, login verifiedLogin, custom string) (string, error) {
	fallback := string(p.Roles["authenticated"])
	mapping, ok := p.Mappings[api.IdentityProviderName(login.Provider+":"+login.ClientID)]
	if !ok {
		if custom != "" {
			return "", failure("NotAuthorizedException", "Custom role is not available for this provider.")
		}
		return fallback, nil
	}
	if value(mapping.Type) == "Rules" {
		if custom != "" {
			return "", failure("InvalidParameterException", "CustomRoleArn cannot be used with rule mappings.")
		}
		for _, rule := range mapping.RulesConfiguration.Rules {
			match := false
			switch claim := login.Claims[value(rule.Claim)].(type) {
			case string:
				switch value(rule.MatchType) {
				case "Equals":
					match = claim == value(rule.Value)
				case "NotEqual":
					match = claim != value(rule.Value)
				case "StartsWith":
					match = strings.HasPrefix(claim, value(rule.Value))
				case "Contains":
					match = strings.Contains(claim, value(rule.Value))
				}
			case []any:
				// Cognito group claims are arrays, not scalar JWT strings.
				if value(rule.MatchType) == "Contains" {
					for _, item := range claim {
						if text, ok := item.(string); ok && strings.Contains(text, value(rule.Value)) {
							match = true
							break
						}
					}
				}
			}
			if match {
				return value(rule.RoleARN), nil
			}
		}
	} else {
		roles := claimRoles(login.Claims)
		if custom != "" {
			if slices.Contains(roles, custom) {
				return custom, nil
			}
			return "", failure("NotAuthorizedException", "Custom role is not in the token.")
		}
		if preferred := claimString(login.Claims, "cognito:preferred_role"); preferred != "" && slices.Contains(roles, preferred) {
			return preferred, nil
		}
		if len(roles) == 1 {
			return roles[0], nil
		}
	}
	if value(mapping.AmbiguousRoleResolution) == "AuthenticatedRole" {
		return fallback, nil
	}
	return "", failure("NotAuthorizedException", "No unambiguous role is available.")
}
