package iam

import (
	"context"
	"slices"
	"strings"

	iampolicy "stackd/iam/policy"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

func listPoliciesGrantingServiceAccess(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, apiErr := generatedIAMInput[iamapi.ListPoliciesGrantingServiceAccessInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	identity, apiErr := lastAccessIdentity(a, m, inputString(input.Arn))
	if apiErr != nil {
		return nil, apiErr
	}
	metadata, err := catalog.Load()
	if err != nil {
		return nil, accessReportFailure()
	}
	namespaces := make([]string, 0, len(input.ServiceNamespaces))
	var invalidNamespaces []string
	for _, namespace := range input.ServiceNamespaces {
		name := string(namespace)
		if service, exists := metadata.LookupService(name); !exists || service.Prefix != name {
			invalidNamespaces = append(invalidNamespaces, name)
		}
		if !slices.Contains(namespaces, name) {
			namespaces = append(namespaces, name)
		}
	}
	if len(invalidNamespaces) > 0 {
		return nil, invalidInput("Invalid service namespace: [" + strings.Join(invalidNamespaces, ", ") + "]")
	}
	// This operation has no requested page size. Its bounded namespace list is
	// returned in full; a continuation is never issued for that complete result.
	if input.Marker != nil {
		return nil, invalid("Invalid Marker.")
	}
	sources, apiErr := permissionPolicySources(a, identity.owners)
	if apiErr != nil {
		return nil, apiErr
	}
	// AWS does not promise a stable policy order. Keep ours deterministic across
	// traversal paths and process restarts, while preserving namespace order.
	slices.SortStableFunc(sources, func(left, right permissionPolicySource) int {
		rank := func(source permissionPolicySource) int {
			if source.arn != "" {
				return 0
			}
			if source.ownerKind == "group" {
				return 2
			}
			return 1
		}
		if d := rank(left) - rank(right); d != 0 {
			return d
		}
		if d := strings.Compare(left.ownerName, right.ownerName); d != 0 {
			return d
		}
		if d := strings.Compare(left.name, right.name); d != 0 {
			return d
		}
		return strings.Compare(left.arn, right.arn)
	})
	documents := make([]string, 0, len(sources))
	for _, source := range sources {
		documents = append(documents, source.document)
	}
	summaries, apiErr := permissionSummaries(documents)
	if apiErr != nil {
		return nil, apiErr
	}
	output := &iamapi.ListPoliciesGrantingServiceAccessOutput{IsTruncated: wirePointer(iamapi.BooleanType(false)), PoliciesGrantingServiceAccess: make(iamapi.ListPolicyGrantingServiceAccessResponseListType, 0, len(namespaces))}
	for _, namespace := range namespaces {
		service, _ := metadata.LookupService(namespace)
		templates := make([]string, 0, len(service.Resources))
		for _, resource := range service.Resources {
			templates = append(templates, resource.ARNTemplates...)
		}
		entry := iamapi.ListPoliciesGrantingServiceAccessEntry{ServiceNamespace: wirePointer(iamapi.ServiceNamespaceType(namespace)), Policies: make(iamapi.PolicyGrantingServiceAccessListType, 0)}
		for i, summary := range summaries {
			grants, err := summary.GrantsService(ctx, namespace, templates)
			if err != nil {
				return nil, accessReportFailure()
			}
			if !grants {
				continue
			}
			source := sources[i]
			item := iamapi.PolicyGrantingServiceAccess{PolicyName: wirePointer(iamapi.PolicyNameType(source.name))}
			if source.arn != "" {
				item.PolicyType = wirePointer(iamapi.PolicyType("MANAGED"))
				item.PolicyArn = wirePointer(iamapi.ArnType(source.arn))
			} else {
				item.PolicyType = wirePointer(iamapi.PolicyType("INLINE"))
				item.EntityType = wirePointer(iamapi.PolicyOwnerEntityType(strings.ToUpper(source.ownerKind)))
				item.EntityName = wirePointer(iamapi.EntityNameType(source.ownerName))
			}
			entry.Policies = append(entry.Policies, item)
		}
		output.PoliciesGrantingServiceAccess = append(output.PoliciesGrantingServiceAccess, entry)
	}
	return output, nil
}

func permissionSummaries(documents []string) ([]*iampolicy.PermissionSummary, *awswire.Error) {
	summaries := make([]*iampolicy.PermissionSummary, 0, len(documents))
	for _, document := range documents {
		summary, err := iampolicy.ParsePermissionSummary([]byte(document))
		if err != nil {
			return nil, accessReportFailure()
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func reportPermissionActions(ctx context.Context, levels [][]string) (map[string][]string, *awswire.Error) {
	if ctx.Err() != nil {
		return nil, accessReportFailure()
	}
	summaries := make([][]*iampolicy.PermissionSummary, len(levels))
	for i, documents := range levels {
		if ctx.Err() != nil {
			return nil, accessReportFailure()
		}
		var apiErr *awswire.Error
		summaries[i], apiErr = permissionSummaries(documents)
		if apiErr != nil {
			return nil, apiErr
		}
	}
	metadata, err := catalog.Load()
	if err != nil {
		return nil, accessReportFailure()
	}
	result := make(map[string][]string)
	for _, namespace := range metadata.ServicePrefixes() {
		if ctx.Err() != nil {
			return nil, accessReportFailure()
		}
		service, _ := metadata.LookupService(namespace)
		resourceTypes := make(map[string][]string, len(service.Resources))
		for _, resource := range service.Resources {
			resourceTypes[resource.Name] = resource.ARNTemplates
		}
		actions := make(map[string][]string, len(service.Actions))
		for _, action := range service.Actions {
			var templates []string
			for _, resource := range action.Resources {
				for _, template := range resourceTypes[resource] {
					if !slices.Contains(templates, template) {
						templates = append(templates, template)
					}
				}
			}
			actions[action.Name] = templates
		}
		allowed, err := iampolicy.PotentialActions(ctx, summaries, actions)
		if err != nil {
			return nil, accessReportFailure()
		}
		if len(allowed) > 0 {
			result[namespace] = allowed
		}
	}
	return result, nil
}
