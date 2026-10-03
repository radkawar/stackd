package iam

import (
	"context"
	"strings"
	"unicode/utf8"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func findRole(a *account, name string) (*role, *awswire.Error) {
	r := a.roles[strings.ToLower(name)]
	if r == nil {
		return nil, missing("role", name)
	}
	return r, nil
}

func (s *Service) createRole(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.CreateRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := s.createRoleResource(ctx, a, m, input)
	if err != nil {
		return nil, err
	}
	wire, wireErr := s.generatedRole(ctx, m, r, "CreateRole", a.currentTime)
	return &iamapi.CreateRoleOutput{Role: wire}, wireErr
}

// createRoleResource owns role creation for the ordinary and template APIs.
// The caller authorizes the operation inside the same IAM transaction.
func (s *Service) createRoleResource(ctx context.Context, a *account, m awsctx.Metadata, input *iamapi.CreateRoleInput) (*role, *awswire.Error) {
	name, document := string(*input.RoleName), string(*input.AssumeRolePolicyDocument)
	if err := validateName(name, "RoleName", 64); err != nil {
		return nil, err
	}
	path, err := validPath(inputString(input.Path))
	if err != nil {
		return nil, err
	}
	if err := validateDocument(document, true); err != nil {
		return nil, err
	}
	if err := iampolicy.ValidateOIDCTrustControls([]byte(document)); err != nil {
		return nil, malformed(err.Error())
	}
	if policySize(document) > maxTrustPolicyCharacters {
		return nil, limit("Role trust policy exceeds 2048 characters.")
	}
	duration := 3600
	if input.MaxSessionDuration != nil {
		duration = int(*input.MaxSessionDuration)
	}
	if duration < 3600 || duration > 43200 {
		return nil, invalid("MaxSessionDuration must be between 3600 and 43200.")
	}
	description := inputString(input.Description)
	if utf8.RuneCountInString(description) > 1000 {
		return nil, invalid("Description exceeds 1000 characters.")
	}
	tags, err := inputTags(input.Tags, "Role")
	if err != nil {
		return nil, err
	}
	b, err := resolveBoundary(a, inputString(input.PermissionsBoundary), "Role")
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(name)
	if a.roles[key] != nil {
		return nil, duplicate("Role", name)
	}
	if len(a.roles) >= maxRoles {
		return nil, limit("IAM role quota exceeded.")
	}
	bound, bindErr := authorization.BindTrustPolicy(ctx, document, s)
	if bindErr != nil {
		return nil, malformed(bindErr.Error())
	}
	r := &role{Path: path, RoleName: name, RoleId: newID("AROA"), Arn: resourceARN(m, "role", path, name), CreateDate: a.currentTime,
		AssumeRolePolicyDocument: document, Description: description, MaxSessionDuration: duration, Tags: tags, PermissionsBoundary: b,
		TrustPrincipalIDs: bound.PrincipalIDs, IdentityPolicies: newIdentityPolicies()}
	a.roles[key] = r
	if b != nil {
		a.policies[b.PermissionsBoundaryArn].PermissionsBoundaryUsageCount++
	}
	return r, nil
}

func (s *Service) getRole(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.GetRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(in.RoleName))
	if err != nil {
		return nil, err
	}
	wire, wireErr := s.generatedRole(ctx, m, r, "GetRole", a.currentTime)
	return &iamapi.GetRoleOutput{Role: wire}, wireErr
}

func (s *Service) listRoles(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.ListRolesInput](ctx)
	if err != nil {
		return nil, err
	}
	items := make([]*role, 0, len(a.roles))
	for _, r := range a.roles {
		if strings.HasPrefix(r.Path, inputString(in.PathPrefix)) {
			items = append(items, r)
		}
	}
	items, p, err := page(ctx, items, func(r *role) string { return r.RoleName }, m, in)
	if err != nil {
		return nil, err
	}
	roles := make(iamapi.RoleListType, 0, len(items))
	for _, role := range items {
		wire, err := s.generatedRole(ctx, m, role, "ListRoles", a.currentTime)
		if err != nil {
			return nil, err
		}
		roles = append(roles, *wire)
	}
	return &iamapi.ListRolesOutput{Roles: roles, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, nil
}

func updateRole(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(in.RoleName))
	if err != nil {
		return nil, err
	}
	if in.Description != nil {
		r.Description = string(*in.Description)
	}
	if in.MaxSessionDuration != nil {
		r.MaxSessionDuration = int(*in.MaxSessionDuration)
	}
	return &iamapi.UpdateRoleOutput{}, nil
}

func (s *Service) updateRoleDescription(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateRoleDescriptionInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(in.RoleName))
	if err != nil {
		return nil, err
	}
	r.Description = inputString(in.Description)
	wire, err := s.generatedRole(ctx, m, r, "UpdateRoleDescription", a.currentTime)
	return &iamapi.UpdateRoleDescriptionOutput{Role: wire}, err
}

func (s *Service) updateAssumeRolePolicy(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateAssumeRolePolicyInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(in.RoleName))
	if err != nil {
		return nil, err
	}
	document := inputString(in.PolicyDocument)
	if err := validateDocument(document, true); err != nil {
		return nil, err
	}
	if err := iampolicy.ValidateOIDCTrustControls([]byte(document)); err != nil {
		return nil, malformed(err.Error())
	}
	if policySize(document) > maxTrustPolicyCharacters {
		return nil, limit("Role trust policy exceeds 2048 characters.")
	}
	bound, bindErr := authorization.BindTrustPolicy(ctx, document, s)
	if bindErr != nil {
		return nil, malformed(bindErr.Error())
	}
	r.AssumeRolePolicyDocument = bound.Document
	r.TrustPrincipalIDs = bound.PrincipalIDs
	return &iamapi.UpdateAssumeRolePolicyOutput{}, nil
}

// Policy documents remain raw JSON in state; URL escaping belongs only to the
// IAM Query response representation.
func (s *Service) wireRole(ctx context.Context, m awsctx.Metadata, r *role) (*role, *awswire.Error) {
	result := *r
	doc, err := authorization.RenderBoundPolicy(ctx, authorization.BoundPolicy{Document: r.AssumeRolePolicyDocument, PrincipalIDs: r.TrustPrincipalIDs, TrustPolicy: true}, principalResolverFunc(s.ResolvePrincipal))
	if err != nil {
		return nil, &awswire.Error{Code: "ServiceFailure", Message: "Unable to render role trust policy.", StatusCode: 500}
	}
	result.AssumeRolePolicyDocument = encodedDocument(doc)
	return &result, nil
}

type principalResolverFunc func(context.Context, string) (authorization.Principal, error)

func (f principalResolverFunc) ResolvePrincipal(ctx context.Context, reference string) (authorization.Principal, error) {
	return f(ctx, reference)
}

func deleteRole(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.DeleteRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(in.RoleName))
	if err != nil {
		return nil, err
	}
	if len(r.Inline) > 0 || len(r.Attached) > 0 {
		return nil, conflict("Cannot delete role with attached policies.")
	}
	for _, profile := range a.instanceProfiles {
		if profile.RoleId == r.RoleId {
			return nil, conflict("Cannot delete role while it belongs to an instance profile.")
		}
	}
	if r.PermissionsBoundary != nil {
		a.policies[r.PermissionsBoundary.PermissionsBoundaryArn].PermissionsBoundaryUsageCount--
	}
	delete(a.roles, strings.ToLower(r.RoleName))
	return &iamapi.DeleteRoleOutput{}, nil
}
