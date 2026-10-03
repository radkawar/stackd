package iam

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func findIdentity(a *account, kind, name string) (*identityPolicies, string, *awswire.Error) {
	switch kind {
	case "User":
		u, err := findUser(a, name)
		if err != nil {
			return nil, "", err
		}
		return &u.IdentityPolicies, u.UserName, nil
	case "Group":
		g, err := findGroup(a, name)
		if err != nil {
			return nil, "", err
		}
		return &g.IdentityPolicies, g.GroupName, nil
	case "Role":
		r, err := findRole(a, name)
		if err != nil {
			return nil, "", err
		}
		return &r.IdentityPolicies, r.RoleName, nil
	default:
		panic("iam: unknown identity kind")
	}
}

func putInlinePolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName, name, document string
	switch in := request.Input.(type) {
	case *iamapi.PutUserPolicyInput:
		kind, targetName = "User", inputString(in.UserName)
		name = inputString(in.PolicyName)
		document = inputString(in.PolicyDocument)
	case *iamapi.PutGroupPolicyInput:
		kind, targetName = "Group", inputString(in.GroupName)
		name = inputString(in.PolicyName)
		document = inputString(in.PolicyDocument)
	case *iamapi.PutRolePolicyInput:
		kind, targetName = "Role", inputString(in.RoleName)
		name = inputString(in.PolicyName)
		document = inputString(in.PolicyDocument)
	default:
		return nil, requestBindingFailure()
	}
	identity, _, err := findIdentity(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	return &iamapi.Unit{}, putIdentityPolicy(identity, kind, name, document)
}

// inlinePolicyName resolves the case-insensitive name while retaining the first
// spelling for list/report responses. Get*Policy echoes the requested spelling.
func inlinePolicyName(identity *identityPolicies, name string) (string, bool) {
	for stored := range identity.Inline {
		if strings.EqualFold(stored, name) {
			return stored, true
		}
	}
	return name, false
}

func putIdentityPolicy(identity *identityPolicies, kind, name, document string) *awswire.Error {
	if err := validateName(name, "PolicyName", 128); err != nil {
		return err
	}
	if err := validateDocument(document, false); err != nil {
		return err
	}
	storedName, _ := inlinePolicyName(identity, name)
	size := policySize(document)
	for existingName, existing := range identity.Inline {
		if existingName != storedName {
			size += policySize(existing)
		}
	}
	if size > inlinePolicyQuota(kind) {
		return limit("Inline policy character quota exceeded for " + kind + ".")
	}
	identity.Inline[storedName] = document
	return nil
}

func getInlinePolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName, name string
	switch in := request.Input.(type) {
	case *iamapi.GetUserPolicyInput:
		kind, targetName = "User", inputString(in.UserName)
		name = inputString(in.PolicyName)
	case *iamapi.GetGroupPolicyInput:
		kind, targetName = "Group", inputString(in.GroupName)
		name = inputString(in.PolicyName)
	case *iamapi.GetRolePolicyInput:
		kind, targetName = "Role", inputString(in.RoleName)
		name = inputString(in.PolicyName)
	default:
		return nil, requestBindingFailure()
	}
	identity, identityName, err := findIdentity(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	storedName, ok := inlinePolicyName(identity, name)
	if !ok {
		return nil, missing("policy", name)
	}
	policyName := wirePointer(iamapi.PolicyNameType(name))
	document := wirePointer(iamapi.PolicyDocumentType(encodedDocument(identity.Inline[storedName])))
	switch kind {
	case "User":
		return &iamapi.GetUserPolicyOutput{UserName: wirePointer(iamapi.ExistingUserNameType(identityName)), PolicyName: policyName, PolicyDocument: document}, nil
	case "Group":
		return &iamapi.GetGroupPolicyOutput{GroupName: wirePointer(iamapi.GroupNameType(identityName)), PolicyName: policyName, PolicyDocument: document}, nil
	default:
		return &iamapi.GetRolePolicyOutput{RoleName: wirePointer(iamapi.RoleNameType(identityName)), PolicyName: policyName, PolicyDocument: document}, nil
	}
}

func deleteInlinePolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName, name string
	switch in := request.Input.(type) {
	case *iamapi.DeleteUserPolicyInput:
		kind, targetName = "User", inputString(in.UserName)
		name = inputString(in.PolicyName)
	case *iamapi.DeleteGroupPolicyInput:
		kind, targetName = "Group", inputString(in.GroupName)
		name = inputString(in.PolicyName)
	case *iamapi.DeleteRolePolicyInput:
		kind, targetName = "Role", inputString(in.RoleName)
		name = inputString(in.PolicyName)
	default:
		return nil, requestBindingFailure()
	}
	identity, _, err := findIdentity(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	storedName, ok := inlinePolicyName(identity, name)
	if !ok {
		return nil, missing("policy", name)
	}
	delete(identity.Inline, storedName)
	return &iamapi.Unit{}, nil
}

func listInlinePolicies(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName string
	switch in := request.Input.(type) {
	case *iamapi.ListUserPoliciesInput:
		kind, targetName = "User", inputString(in.UserName)
	case *iamapi.ListGroupPoliciesInput:
		kind, targetName = "Group", inputString(in.GroupName)
	case *iamapi.ListRolePoliciesInput:
		kind, targetName = "Role", inputString(in.RoleName)
	default:
		return nil, requestBindingFailure()
	}
	identity, _, err := findIdentity(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(identity.Inline))
	for name := range identity.Inline {
		names = append(names, name)
	}
	names, p, err := page(ctx, names, func(s string) string { return s }, m, request.Input)
	policies := make(iamapi.PolicyNameListType, 0, len(names))
	for _, name := range names {
		policies = append(policies, iamapi.PolicyNameType(name))
	}
	truncated, marker := wirePointer(iamapi.BooleanType(p.IsTruncated)), wireMarker(p)
	switch kind {
	case "User":
		return &iamapi.ListUserPoliciesOutput{PolicyNames: policies, IsTruncated: truncated, Marker: marker}, err
	case "Group":
		return &iamapi.ListGroupPoliciesOutput{PolicyNames: policies, IsTruncated: truncated, Marker: marker}, err
	default:
		return &iamapi.ListRolePoliciesOutput{PolicyNames: policies, IsTruncated: truncated, Marker: marker}, err
	}
}
