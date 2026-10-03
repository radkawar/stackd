package lambda_test

import (
	"context"
	"encoding/json"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	service "stackd/internal/services/lambda"
	"stackd/storage/lambda"
)

type layerPermissionPrincipalPolicies struct{ principal string }

func (p *layerPermissionPrincipalPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	body, err := json.Marshal(map[string]any{"Statement": map[string]any{
		"Effect": "Allow", "Action": "lambda:AddLayerVersionPermission", "Resource": "*",
		"Condition": map[string]any{"StringEquals": map[string]string{"lambda:Principal": p.principal}},
	}})
	return authorization.PolicySet{Identity: []policy.Policy{{Document: string(body)}}}, err
}

func TestLayerPermissionOwnerRecoveryPreservesPrincipalConditions(t *testing.T) {
	for _, principal := range []string{"222222222222", "arn:aws:iam::222222222222:root"} {
		t.Run(principal, func(t *testing.T) {
			forRepositories(t, func(t *testing.T, repo lambda.Repository) {
				key := permissionOwnerKey()
				seedPermissionLayer(t, repo, key.LayerVersionKey)
				ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
				metadata := awsctx.FromContext(ctx)
				metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111111111111:user/operator", "AIDA11111111111111111"
				ctx = awsctx.WithMetadata(ctx, metadata)
				owned := service.WithLayerPermissionOwner(ctx, lambda.LayerPermissionOwner{StackID: "stack", LogicalID: "Permission", Token: "token"})
				identity := &layerPermissionPrincipalPolicies{principal: principal}
				s := service.New(service.Config{Repository: repo, Authorizer: authorization.New(identity, nil)})
				t.Cleanup(func() { _ = s.Close() })
				in := permissionOwnerInput(key)
				in.Principal = new(api.LayerPermissionAllowedPrincipal(principal))
				first := permissionOwnerAdd(t, s, owned, in)
				assertLayerPermissionRecovery(t, permissionOwnerAdd(t, s, owned, in), first)

				// A newly permitted request principal must not recover a different
				// stored grant after authority for that grant has been revoked.
				identity.principal = "333333333333"
				in.Principal = new(api.LayerPermissionAllowedPrincipal(identity.principal))
				_, wire := storedAliasCommand(t, s, owned, "AddLayerVersionPermission", in)
				requirePermissionCode(t, wire, "AccessDeniedException")
			})
		})
	}
}
