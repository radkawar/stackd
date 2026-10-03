package iam

import (
	"context"
	"maps"
	"slices"
	"strings"

	"stackd/internal/authorization"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) acquireRole(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.AcquireRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	arn := string(*input.TemplateArn)
	s.mu.Lock()
	authorizer := s.authorizer
	s.mu.Unlock()
	authorize := func(action, resource string, additions map[string][]string) *awswire.Error {
		conditions := map[string][]string{"iam:RoleTemplateARN": {arn}}
		maps.Copy(conditions, additions)
		// The live API omits RoleTemplateARN from its template-read decision,
		// including during acquisition. The generated action catalogue agrees.
		if err := filterActionConditions("iam:"+action, conditions); err != nil {
			return err
		}
		owner, err := awsManagedResourceAccount(m.Partition, resource)
		if err != nil {
			return err
		}
		return authorizer.Authorize(ctx, authorization.Request{Action: "iam:" + action, ResourceARN: resource, ResourceAccountID: owner, Context: conditions, EvaluationTime: &a.currentTime})
	}
	if err := authorize("GetRoleTemplateVersion", arn, nil); err != nil {
		return nil, err
	}
	version, err := lookupRoleTemplate(arn, (*iamapi.MinorVersionType)(input.TemplateMinorVersion))
	if err != nil {
		return nil, err
	}
	if !bool(*version.Enabled) || !bool(*version.VersionEnabled) {
		return nil, &awswire.Error{Code: "RoleTemplateDisabled", Message: "The role template version is disabled.", StatusCode: 400}
	}
	replacements := make(map[string][]string, len(input.ReplacementValues))
	for name, replacement := range input.ReplacementValues {
		for _, value := range replacement.Values {
			replacements[string(name)] = append(replacements[string(name)], string(value))
		}
		if len(replacement.Values) == 0 {
			replacements[string(name)] = []string{}
		}
	}
	rendered, err := renderRoleTemplate(version, replacements)
	if err != nil {
		return nil, err
	}
	name := string(*rendered.create.RoleName)
	r := a.roles[strings.ToLower(name)]
	if r != nil {
		if err := authorize("GetRole", r.Arn, identityResourceConditions(r.Tags, boundaryARN(r.PermissionsBoundary))); err != nil {
			return nil, err
		}
		if err := reusableTemplateRole(r, version, rendered); err != nil {
			return nil, err
		}
	} else {
		resource := resourceARN(m, "role", string(*rendered.create.Path), name)
		conditions := identityResourceConditions(nil, inputString(rendered.create.PermissionsBoundary))
		if err := authorize("CreateRole", resource, conditions); err != nil {
			return nil, err
		}
		for _, policyARN := range version.ManagedPolicyArns {
			conditions["iam:PolicyARN"] = []string{string(policyARN)}
			if err := authorize("AttachRolePolicy", resource, conditions); err != nil {
				return nil, err
			}
		}
		if len(rendered.inline) != 0 {
			if err := authorize("PutRolePolicy", resource, conditions); err != nil {
				return nil, err
			}
		}
		r, err = s.createRoleResource(ctx, a, m, &rendered.create)
		if err != nil {
			return nil, err
		}
		for _, policyARN := range version.ManagedPolicyArns {
			if err := attachIdentityPolicy(a, &r.IdentityPolicies, "Role", string(policyARN)); err != nil {
				return nil, err
			}
		}
		for _, policyName := range slices.Sorted(maps.Keys(rendered.inline)) {
			if err := putIdentityPolicy(&r.IdentityPolicies, "Role", policyName, rendered.inline[policyName]); err != nil {
				return nil, err
			}
		}
		r.SourceRoleTemplate = &RoleTemplateSource{ARN: arn, MinorVersion: int32(*version.MinorVersion), Parameters: replacements}
	}
	wire, err := s.generatedRole(ctx, m, r, "AcquireRole", a.currentTime)
	return &iamapi.AcquireRoleOutput{Role: wire}, err
}

func reusableTemplateRole(r *role, version *iamapi.RoleTemplateVersion, requested renderedRoleTemplate) *awswire.Error {
	nameConflict := &awswire.Error{Code: "NameConflict", Message: "A role with this name already exists but was not created from this template and parameters.", StatusCode: 409}
	source := r.SourceRoleTemplate
	if source == nil || source.ARN != string(*version.TemplateArn) || source.MinorVersion != int32(*version.MinorVersion) {
		return nameConflict
	}
	original, err := renderRoleTemplate(version, source.Parameters)
	if err != nil {
		return err
	}
	if !roleMatchesTemplate(r, version, original) {
		return &awswire.Error{Code: "RoleModified", Message: "Role " + r.RoleName + " has been modified since it was created and is no longer managed.", StatusCode: 409}
	}
	if !roleMatchesTemplate(r, version, requested) {
		return nameConflict
	}
	return nil
}

func roleMatchesTemplate(r *role, version *iamapi.RoleTemplateVersion, rendered renderedRoleTemplate) bool {
	if r.Path != string(*rendered.create.Path) || r.RoleName != string(*rendered.create.RoleName) || len(r.Tags) != 0 ||
		boundaryARN(r.PermissionsBoundary) != inputString(rendered.create.PermissionsBoundary) ||
		!templatePoliciesEqual(r.AssumeRolePolicyDocument, string(*rendered.create.AssumeRolePolicyDocument)) ||
		len(r.Attached) != len(version.ManagedPolicyArns) || len(r.Inline) != len(rendered.inline) {
		return false
	}
	for _, arn := range version.ManagedPolicyArns {
		if _, attached := r.Attached[string(arn)]; !attached {
			return false
		}
	}
	for name, document := range rendered.inline {
		if !templatePoliciesEqual(r.Inline[name], document) {
			return false
		}
	}
	return true
}
