package kms

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type actionContextKey struct{}
type actionContext struct {
	name                 string
	encryptionContext    map[string]string
	conditions           map[string][]string
	grantTokens          []string
	proposedGrant        *grant
	reEncryptOtherKeyARN string
}
type viaServiceContextKey struct{}
type awsResourceGrantContextKey struct{}

// WithAWSResourceGrant marks a trusted service's CreateGrant request for an AWS
// resource. It supplies the GrantIsForAWSResource condition without changing the
// caller or bypassing IAM, key policies, or grant constraints. HTTP callers
// cannot set this marker.
func WithAWSResourceGrant(ctx context.Context) context.Context {
	return context.WithValue(ctx, awsResourceGrantContextKey{}, true)
}

// WithViaService identifies a service forwarding another caller's identity.
// A service using its own principal is a direct caller, not a forwarding hop.
// Only trusted in-process adapters set this; HTTP inputs never set it.
func WithViaService(ctx context.Context, service string) context.Context {
	if service == "" || strings.ContainsAny(service, "./: ") {
		return ctx
	}
	suffix := "amazonaws.com"
	if scopeFor(ctx).partition == "aws-cn" {
		suffix = "amazonaws.com.cn"
	}
	if principal := awsctx.FromContext(ctx).ServicePrincipal.Name; principal == service+"."+suffix || principal == service+"."+scopeFor(ctx).region+"."+suffix {
		return ctx
	}
	ctx = awsctx.WithViaService(ctx, service+"."+suffix)
	return context.WithValue(ctx, viaServiceContextKey{}, service+"."+scopeFor(ctx).region+"."+suffix)
}

func withAction(ctx context.Context, name string, encryptionContext map[string]string) context.Context {
	previous, _ := ctx.Value(actionContextKey{}).(actionContext)
	return context.WithValue(ctx, actionContextKey{}, actionContext{name: name, encryptionContext: encryptionContext, grantTokens: previous.grantTokens})
}

func withConditions(ctx context.Context, conditions map[string][]string) context.Context {
	action, _ := ctx.Value(actionContextKey{}).(actionContext)
	action.conditions = conditions
	return context.WithValue(ctx, actionContextKey{}, action)
}

func (s *Service) authorize(ctx context.Context, arn, policy string, required bool, conditions map[string][]string) *awswire.Error {
	return s.authorizeBound(ctx, arn, authorization.BoundPolicy{Document: policy}, required, conditions)
}

func (s *Service) authorizeBound(ctx context.Context, arn string, bound authorization.BoundPolicy, required bool, conditions map[string][]string) *awswire.Error {
	action, _ := ctx.Value(actionContextKey{}).(actionContext)
	if action.name == "" {
		return failure("AccessDeniedException", "A KMS action is required for authorization.")
	}
	if conditions == nil {
		conditions = make(map[string][]string)
	}
	maps.Copy(conditions, action.conditions)
	for k, v := range action.encryptionContext {
		conditions["kms:EncryptionContext:"+k] = []string{v}
	}
	if len(action.encryptionContext) != 0 {
		conditions["kms:EncryptionContextKeys"] = slices.Sorted(maps.Keys(action.encryptionContext))
	}
	conditions["kms:CallerAccount"] = []string{scopeFor(ctx).account}
	if service, ok := ctx.Value(viaServiceContextKey{}).(string); ok {
		conditions["kms:ViaService"] = []string{service}
	}
	permission, _ := ctx.Value(grantPermissionKey{}).(policy.GrantPermissions)
	instant := s.currentTime()
	if err := s.authorizer.Authorize(ctx, authorization.Request{EvaluationTime: &instant, Action: "kms:" + action.name, ResourceARN: arn, ResourcePolicies: []authorization.BoundPolicy{bound}, RequireResourcePolicy: required, ResourceControlExempt: slices.Contains(conditions["kms:KeyManager"], "AWS"), Context: conditions, Grants: permission}); err != nil {
		return failure("AccessDeniedException", err.Message)
	}
	return nil
}

func (s *Service) resolveAuthorized(ctx context.Context, identifier string, allowAlias bool) (*key, *awswire.Error) {
	k, err := s.resolve(ctx, identifier, allowAlias)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResolvedKey(ctx, k, identifier); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Service) authorizeResolvedKey(ctx context.Context, k *key, identifier string) *awswire.Error {
	conditions := map[string][]string{"kms:KeySpec": {k.Spec}, "kms:KeyUsage": {k.Usage}, "kms:KeyOrigin": {k.Origin}, "kms:KeyManager": {k.manager}, "kms:MultiRegion": {strconv.FormatBool(k.MultiRegion)}}
	if k.MultiRegion {
		kind := "REPLICA"
		if keyScope(k).region == k.PrimaryRegion {
			kind = "PRIMARY"
		}
		conditions["kms:MultiRegionKeyType"] = []string{kind}
	}
	action, _ := ctx.Value(actionContextKey{}).(actionContext)
	if action.name == "ReEncryptFrom" || action.name == "ReEncryptTo" {
		conditions["kms:ReEncryptOnSameKey"] = []string{"false"}
		if k.arn == action.reEncryptOtherKeyARN {
			conditions["kms:ReEncryptOnSameKey"] = []string{"true"}
		}
	}
	if keyScope(k).account != scopeFor(ctx).account {
		switch action.name {
		case "Encrypt", "Decrypt", "ReEncryptFrom", "ReEncryptTo", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext", "GenerateMac", "VerifyMac", "GetPublicKey", "Sign", "Verify", "DeriveSharedSecret", "DescribeKey", "GetKeyRotationStatus", "CreateGrant", "ListGrants", "RevokeGrant", "RetireGrant":
		default:
			return failure("AccessDeniedException", "This operation cannot be performed on a key in another account.")
		}
	}
	requestedAlias := identifier
	if strings.HasPrefix(identifier, "arn:") {
		parts := strings.SplitN(identifier, ":", 6)
		if len(parts) == 6 {
			requestedAlias = parts[5]
		}
	}
	if strings.HasPrefix(requestedAlias, "alias/") {
		conditions["kms:RequestAlias"] = []string{requestedAlias}
	}
	for name, a := range s.scopedStore(keyScope(k)).aliases {
		if a.keyID == k.ID {
			conditions["kms:ResourceAliases"] = append(conditions["kms:ResourceAliases"], name)
		}
	}
	slices.Sort(conditions["kms:ResourceAliases"])
	for name, v := range k.tags {
		conditions["aws:ResourceTag/"+name] = []string{v}
	}
	permission, err := s.grantPermission(ctx, k)
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, grantPermissionKey{}, permission)
	return s.authorizeBound(ctx, k.arn, authorization.BoundPolicy{Document: k.policy, PrincipalIDs: k.principalIDs}, true, conditions)
}
