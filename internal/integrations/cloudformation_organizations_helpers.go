package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/identitystore"
	"strings"
)

func cfnOrganizationsMissing(e error) bool {
	return cfnMessagingMissing(e, "AWSOrganizationsNotInUseException", "AccountNotFoundException", "OrganizationalUnitNotFoundException", "PolicyNotFoundException", "ResourcePolicyNotFoundException", "TargetNotFoundException")
}
func cfnOrganizationsTags(ctx context.Context, c StepFunctionsCommands, id string) (map[string]string, error) {
	tags := map[string]string{}
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListTagsForResourceOutput](ctx, c, "organizations", "ListTagsForResource", map[string]any{"ResourceId": id, "NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, t := range out.Tags {
			tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return tags, nil
		}
	}
}

// Account ownership is checked by the native membership's private claim under
// current DescribeAccount/ListTagsForResource authorization, never public tags.
func cfnOrganizationsAccountTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, id string) (map[string]string, error) {
	ctx = cfnOrgIdentityContext(ctx, r)
	if _, e := cfnOrgIdentityCall[api.DescribeAccountOutput](ctx, c, "organizations", "DescribeAccount", map[string]any{"AccountId": id}); e != nil {
		return nil, e
	}
	return cfnOrganizationsTags(ctx, c, id)
}
func cfnOrganizationsUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, id string, current, desired map[string]string) error {
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if e := cfnComputeRun(ctx, c, "organizations", "UntagResource", map[string]any{"ResourceId": id, "TagKeys": removed}); e != nil {
			return e
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "organizations", "TagResource", map[string]any{"ResourceId": id, "Tags": cfnComputeTagList(desired)})
}
func cfnOrganizationsRoot(ctx context.Context, c StepFunctionsCommands) (string, error) {
	out, e := cfnOrgIdentityCall[api.ListRootsOutput](ctx, c, "organizations", "ListRoots", map[string]any{})
	if e != nil {
		return "", e
	}
	if len(out.Roots) != 1 {
		return "", fmt.Errorf("organization root unavailable")
	}
	return cfnComputeValue(out.Roots[0].Id), nil
}
func cfnOrganizationsParent(ctx context.Context, c StepFunctionsCommands, id string) (string, error) {
	out, e := cfnOrgIdentityCall[api.ListParentsOutput](ctx, c, "organizations", "ListParents", map[string]any{"ChildId": id})
	if e != nil {
		return "", e
	}
	if len(out.Parents) != 1 {
		return "", fmt.Errorf("resource parent unavailable")
	}
	return cfnComputeValue(out.Parents[0].Id), nil
}
func cfnOrganizationsPath(ctx context.Context, c StepFunctionsCommands, id string) (string, error) {
	ctx = identitystore.WithCloudFormationOwner(ctx, "")
	out, e := cfnOrgIdentityCall[api.DescribeOrganizationOutput](ctx, c, "organizations", "DescribeOrganization", map[string]any{})
	if e != nil {
		return "", e
	}
	segments := []string{id}
	for !strings.HasPrefix(id, "r-") {
		parent, e := cfnOrganizationsParent(ctx, c, id)
		if e != nil {
			return "", e
		}
		segments = append([]string{parent}, segments...)
		id = parent
	}
	return cfnComputeValue(out.Organization.Id) + "/" + strings.Join(segments, "/") + "/", nil
}
func cfnOrganizationsValidate(p cloudformation.Properties, required []string, allowed ...string) error {
	if e := cfnComputeProperties(p, allowed...); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, required...); e != nil {
		return e
	}
	_, e := cfnComputeTags(p)
	return e
}
