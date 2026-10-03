package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) grantMetadata(ctx context.Context, k *key, g *grant) (kmsapi.GrantListEntry, *awswire.Error) {
	grantee, err := s.renderGrantPrincipal(ctx, g.grantee, g.granteeID)
	if err != nil {
		return kmsapi.GrantListEntry{}, err
	}
	out := kmsapi.GrantListEntry{KeyId: ptr(kmsapi.KeyIdType(k.arn)), GrantId: ptr(kmsapi.GrantIdType(g.id)), GranteePrincipal: ptr(kmsapi.PrincipalIdType(grantee)), IssuingAccount: ptr(kmsapi.PrincipalIdType("arn:" + keyScope(k).partition + ":iam::" + g.issuer + ":root")), CreationDate: ptr(g.created), Operations: make(kmsapi.GrantOperationList, 0, len(g.operations))}
	if g.name != "" {
		out.Name = ptr(kmsapi.GrantNameType(g.name))
	}
	if g.retiring != "" {
		retiring, err := s.renderGrantPrincipal(ctx, g.retiring, g.retiringID)
		if err != nil {
			return kmsapi.GrantListEntry{}, err
		}
		out.RetiringPrincipal = ptr(kmsapi.PrincipalIdType(retiring))
	}
	for _, op := range g.operations {
		out.Operations = append(out.Operations, kmsapi.GrantOperation(op))
	}
	if g.equals != nil || g.subset != nil {
		out.Constraints = &kmsapi.GrantConstraints{}
		if g.equals != nil {
			out.Constraints.EncryptionContextEquals = generatedContext(g.equals)
		}
		if g.subset != nil {
			out.Constraints.EncryptionContextSubset = generatedContext(g.subset)
		}
	}
	return out, nil
}

func generatedContext(in map[string]string) kmsapi.EncryptionContextType {
	out := make(kmsapi.EncryptionContextType, len(in))
	for k, v := range in {
		out[kmsapi.EncryptionContextKey(k)] = kmsapi.EncryptionContextValue(v)
	}
	return out
}

func (s *Service) listGrants(ctx context.Context, in *kmsapi.ListGrantsInput) (*kmsapi.ListGrantsOutput, *awswire.Error) {
	if in.GranteeServicePrincipal != nil {
		return nil, failure("UnsupportedOperationException", "The service-principal grant fields are not implemented.")
	}
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	principal, principalID := "", ""
	if in.GranteePrincipal != nil {
		principal, principalID, err = s.bindGrantPrincipal(ctx, value(in.GranteePrincipal))
		if err != nil {
			return nil, err
		}
	}
	ids := make([]string, 0, len(k.grants))
	for id, g := range k.grants {
		if (in.GrantId == nil || id == value(in.GrantId)) && (in.GranteePrincipal == nil || sameGrantPrincipal(g.grantee, g.granteeID, principal, principalID)) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	filter, _ := json.Marshal([]string{k.arn, value(in.GrantId), value(in.GranteePrincipal)})
	page, next, err := s.page(ctx, "ListGrants", string(filter), ids, in.Limit, in.Marker)
	if err != nil {
		return nil, err
	}
	out := &kmsapi.ListGrantsOutput{Grants: make(kmsapi.GrantList, 0, len(page)), Truncated: ptr(kmsapi.BooleanType(next != ""))}
	if next != "" {
		out.NextMarker = ptr(kmsapi.MarkerType(next))
	}
	for _, id := range page {
		metadata, err := s.grantMetadata(ctx, k, k.grants[id])
		if err != nil {
			return nil, err
		}
		out.Grants = append(out.Grants, metadata)
	}
	return out, nil
}

func (s *Service) listRetirableGrants(ctx context.Context, in *kmsapi.ListRetirableGrantsInput) (*kmsapi.ListRetirableGrantsOutput, *awswire.Error) {
	if in.RetiringServicePrincipal != nil {
		return nil, failure("UnsupportedOperationException", "The service-principal grant fields are not implemented.")
	}
	principal, principalID, err := s.bindGrantPrincipal(ctx, value(in.RetiringPrincipal))
	if err != nil {
		if err.Code == "InvalidArnException" && (strings.HasPrefix(value(in.RetiringPrincipal), "AROA") || strings.HasPrefix(value(in.RetiringPrincipal), "AIDA")) {
			return nil, failure("NotFoundException", "Retiring principal "+value(in.RetiringPrincipal)+" could not be found")
		}
		return nil, err
	}
	if err := s.authorize(ctx, "*", "", false, nil); err != nil {
		return nil, err
	}
	items := make(map[string]kmsapi.GrantListEntry)
	for _, k := range s.store(ctx).keys {
		for _, g := range k.grants {
			if sameGrantPrincipal(g.retiring, g.retiringID, principal, principalID) {
				metadata, err := s.grantMetadata(ctx, k, g)
				if err != nil {
					return nil, err
				}
				items[k.ID+"/"+g.id] = metadata
			}
		}
	}
	ids := make([]string, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	page, next, err := s.page(ctx, "ListRetirableGrants", principal, ids, in.Limit, in.Marker)
	if err != nil {
		return nil, err
	}
	out := &kmsapi.ListRetirableGrantsOutput{Grants: make(kmsapi.GrantList, 0, len(page)), Truncated: ptr(kmsapi.BooleanType(next != ""))}
	if next != "" {
		out.NextMarker = ptr(kmsapi.MarkerType(next))
	}
	for _, id := range page {
		out.Grants = append(out.Grants, items[id])
	}
	return out, nil
}

func (s *Service) revokeGrant(ctx context.Context, in *kmsapi.RevokeGrantInput) (*kmsapi.RevokeGrantOutput, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if k.grants[value(in.GrantId)] == nil {
		return nil, failure("NotFoundException", "Grant does not exist.")
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	delete(k.grants, value(in.GrantId))
	return &kmsapi.RevokeGrantOutput{}, nil
}

func (s *Service) retireGrant(ctx context.Context, in *kmsapi.RetireGrantInput) (*kmsapi.RetireGrantOutput, *awswire.Error) {
	var k *key
	var g *grant
	if in.GrantToken != nil {
		if in.KeyId != nil || in.GrantId != nil {
			return nil, failure("ValidationException", "Specify GrantToken or KeyId and GrantId.")
		}
		// Tokens remain opaque. Search the request region only; possessing a token
		// never substitutes for a principal's permission to retire its grant.
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(value(in.GrantToken))
		arn, _, ok := strings.Cut(string(decoded), "\n")
		if decodeErr != nil || !ok {
			return nil, failure("InvalidGrantTokenException", "Invalid grant token.")
		}
		var err *awswire.Error
		k, err = s.resolve(ctx, arn, false)
		if err != nil {
			return nil, failure("InvalidGrantTokenException", "The grant token does not identify an active grant.")
		}
		for _, candidate := range k.grants {
			if slices.Contains(candidate.tokens, value(in.GrantToken)) {
				g = candidate
				break
			}
		}
		if g == nil {
			return nil, failure("InvalidGrantTokenException", "The grant token does not identify an active grant.")
		}
	} else {
		if in.KeyId == nil || in.GrantId == nil {
			return nil, failure("ValidationException", "KeyId and GrantId are required without a grant token.")
		}
		// RetireGrant's KeyId member accepts a key ARN, unlike CreateGrant
		// and RevokeGrant. AWS returns NotFoundException for a bare key ID.
		if !strings.HasPrefix(value(in.KeyId), "arn:") {
			return nil, failure("NotFoundException", "Invalid arn "+value(in.KeyId))
		}
		var err *awswire.Error
		k, err = s.resolve(ctx, value(in.KeyId), false)
		if err != nil {
			return nil, err
		}
		g = k.grants[value(in.GrantId)]
		if g == nil {
			return nil, failure("NotFoundException", "Grant does not exist.")
		}
	}
	if audit, _ := ctx.Value(auditContextKey{}).(*auditContext); audit != nil {
		audit.retiredGrantID = g.id
	}
	binding := grantPrincipalMatches(ctx, g.retiring, g.retiringID)
	if slices.Contains(g.operations, "RetireGrant") {
		grantee := grantPrincipalMatches(ctx, g.grantee, g.granteeID)
		binding.Direct = binding.Direct || grantee.Direct
		binding.Delegated = binding.Delegated || grantee.Delegated
		binding.SessionDirect = binding.SessionDirect || grantee.SessionDirect
	}
	ownerAccount := keyScope(k).account == scopeFor(ctx).account
	if !binding.Direct && !binding.Delegated && !ownerAccount {
		return nil, failure("AccessDeniedException", "The caller is not permitted to retire this grant.")
	}
	permission := policy.GrantPermissions{Direct: binding.Direct, Delegated: binding.Delegated || ownerAccount, SessionDirect: binding.SessionDirect, TrustedDirect: binding.Direct && g.issuer == scopeFor(ctx).account, TrustedSessionDirect: binding.SessionDirect && g.issuer == scopeFor(ctx).account}
	ctx = context.WithValue(ctx, grantPermissionKey{}, permission)
	// RetireGrant authorization comes from the grant and IAM, not the key policy.
	if err := s.authorizeBound(ctx, k.arn, authorization.BoundPolicy{}, !ownerAccount, nil); err != nil {
		return nil, err
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	delete(k.grants, g.id)
	return &kmsapi.RetireGrantOutput{}, nil
}
