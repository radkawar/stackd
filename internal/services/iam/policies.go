package iam

import (
	"context"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/managed"
)

func findPolicyARN(a *account, arn string) (*policy, *awswire.Error) {
	if arn == "" {
		return nil, invalid("PolicyArn is required.")
	}
	if strings.HasPrefix(arn, "arn:"+a.partition+":iam::aws:policy/") && !managed.Available(a.partition) {
		return nil, unavailableManagedCatalogue(a.partition)
	}
	p := a.policies[arn]
	if p == nil {
		if managedPolicy, ok := lookupAWSManagedPolicy(a.partition, arn); ok {
			p = &managedPolicy
			a.policies[arn] = p
		}
	}
	if p == nil {
		return nil, missing("policy", arn)
	}
	return p, nil
}

func createPolicy(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.CreatePolicyInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	name := inputString(in.PolicyName)
	path := defaultPath(inputString(in.Path))
	doc := inputString(in.PolicyDocument)
	if err := validateDocument(doc, false); err != nil {
		return nil, err
	}
	if policySize(doc) > maxManagedPolicyCharacters {
		return nil, limit("Managed policy exceeds 6144 characters.")
	}
	tags, err := inputTags(in.Tags, "Policy")
	if err != nil {
		return nil, err
	}
	for _, existing := range a.policies {
		if !isAWSManagedPolicyARN(existing.Arn) && strings.EqualFold(existing.PolicyName, name) {
			return nil, duplicate("Policy", name)
		}
	}
	if localPolicyCount(a) >= maxPolicies {
		return nil, limit("Customer-managed policy quota exceeded.")
	}
	now := a.currentTime
	version := &policyVersion{Document: doc, VersionId: "v1", IsDefaultVersion: true, CreateDate: now}
	p := &policy{PolicyName: name, PolicyId: newID("ANPA"), Arn: resourceARN(m, "policy", path, name), Path: path, DefaultVersionId: "v1", IsAttachable: true, Description: inputString(in.Description), CreateDate: now, UpdateDate: now, Tags: tags, Versions: map[string]*policyVersion{"v1": version}, NextVersion: 2}
	a.policies[p.Arn] = p
	return &iamapi.CreatePolicyOutput{Policy: wirePolicy(p, true)}, nil
}

func getPolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.GetPolicyInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	return &iamapi.GetPolicyOutput{Policy: wirePolicy(p, true)}, nil
}

func listPolicies(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListPoliciesInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	scope := inputString(in.Scope)
	if scope != "Local" && !managed.Available(m.Partition) {
		return nil, unavailableManagedCatalogue(m.Partition)
	}
	onlyAttached := in.OnlyAttached != nil && bool(*in.OnlyAttached)
	usage := inputString(in.PolicyUsageFilter)
	items := make([]*policy, 0, len(a.policies))
	add := func(p *policy) {
		if !strings.HasPrefix(p.Path, inputString(in.PathPrefix)) {
			return
		}
		if onlyAttached && !matchesPolicyUsage(usage, p.AttachmentCount > 0, p.PermissionsBoundaryUsageCount > 0) {
			return
		}
		items = append(items, p)
	}
	if scope != "AWS" {
		for arn, p := range a.policies {
			if !isAWSManagedPolicyARN(arn) {
				add(p)
			}
		}
	}
	if scope != "Local" {
		for _, metadata := range managed.List(m.Partition) {
			if p := a.policies[metadata.ARN]; p != nil {
				add(p)
			} else {
				p := cataloguePolicy(metadata)
				add(&p)
			}
		}
	}
	items, p, err := page(ctx, items, func(p *policy) string { return p.PolicyName + "\x00" + p.Arn }, m, in)
	policies := make(iamapi.PolicyListType, 0, len(items))
	for _, item := range items {
		policies = append(policies, *wirePolicy(item, false))
	}
	return &iamapi.ListPoliciesOutput{Policies: policies, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, err
}

func deletePolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeletePolicyInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if err := managedPolicyMutationError(inputString(in.PolicyArn), "DeletePolicy"); err != nil {
		return nil, err
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	if p.AttachmentCount > 0 || p.PermissionsBoundaryUsageCount > 0 {
		return nil, conflict("Cannot delete a policy attached to an entity or used as a permissions boundary.")
	}
	if len(p.Versions) > 1 {
		return nil, conflict("Delete all nondefault policy versions before deleting the policy.")
	}
	delete(a.policies, p.Arn)
	return &iamapi.DeletePolicyOutput{}, nil
}

func matchesPolicyUsage(usage string, permissions, boundary bool) bool {
	switch usage {
	case "PermissionsPolicy":
		return permissions
	case "PermissionsBoundary":
		return boundary
	default:
		return permissions || boundary
	}
}
