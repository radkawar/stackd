package kms

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"

	"stackd/iam/policy"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func withGrantTokens(ctx context.Context, tokens kmsapi.GrantTokenList) context.Context {
	action, _ := ctx.Value(actionContextKey{}).(actionContext)
	action.grantTokens = make([]string, 0, len(tokens))
	for _, token := range tokens {
		action.grantTokens = append(action.grantTokens, string(token))
	}
	return context.WithValue(ctx, actionContextKey{}, action)
}

func (s *Service) grantPermission(ctx context.Context, k *key) (policy.GrantPermissions, *awswire.Error) {
	action, _ := ctx.Value(actionContextKey{}).(actionContext)
	for _, token := range action.grantTokens {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(token)
		arn, _, ok := strings.Cut(string(decoded), "\n")
		if decodeErr != nil || !ok {
			return policy.GrantPermissions{}, failure("InvalidGrantTokenException", "Invalid grant token.")
		}
		tokenKey, err := s.resolve(ctx, arn, false)
		if err != nil {
			return policy.GrantPermissions{}, failure("InvalidGrantTokenException", "Grant token key does not exist.")
		}
		found := false
		for _, g := range tokenKey.grants {
			if slices.Contains(g.tokens, token) {
				found = true
				break
			}
		}
		if !found {
			return policy.GrantPermissions{}, failure("InvalidGrantTokenException", "The grant token is invalid or its grant has been revoked.")
		}
	}
	var permission policy.GrantPermissions
	for _, g := range k.grants {
		if !grantPermits(g, action) {
			continue
		}
		binding := grantPrincipalMatches(ctx, g.grantee, g.granteeID)
		permission.Direct = permission.Direct || binding.Direct
		permission.Delegated = permission.Delegated || binding.Delegated
		permission.SessionDirect = permission.SessionDirect || binding.SessionDirect
		if g.issuer == scopeFor(ctx).account {
			permission.TrustedDirect = permission.TrustedDirect || binding.Direct
			permission.TrustedSessionDirect = permission.TrustedSessionDirect || binding.SessionDirect
		}
	}
	return permission, nil
}

type grantPermissionKey struct{}
