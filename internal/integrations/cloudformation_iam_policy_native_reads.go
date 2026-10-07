package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/iam"
)

// IAM's identity policy operations have distinct native output types. Share
// only the projected fields, never assert a Role or Group response as a User.
func cfnIAMListInline(ctx context.Context, c StepFunctionsCommands, kind string, input map[string]any) (api.PolicyNameListType, string, error) {
	switch kind {
	case "User":
		out, err := cfnComputeCall[api.ListUserPoliciesOutput](ctx, c, "iam", "ListUserPolicies", input)
		if err != nil {
			return nil, "", err
		}
		return out.PolicyNames, cfnComputeValue(out.Marker), nil
	case "Group":
		out, err := cfnComputeCall[api.ListGroupPoliciesOutput](ctx, c, "iam", "ListGroupPolicies", input)
		if err != nil {
			return nil, "", err
		}
		return out.PolicyNames, cfnComputeValue(out.Marker), nil
	case "Role":
		out, err := cfnComputeCall[api.ListRolePoliciesOutput](ctx, c, "iam", "ListRolePolicies", input)
		if err != nil {
			return nil, "", err
		}
		return out.PolicyNames, cfnComputeValue(out.Marker), nil
	}
	return nil, "", fmt.Errorf("unsupported IAM identity kind %s", kind)
}
func cfnIAMGetInline(ctx context.Context, c StepFunctionsCommands, kind string, input map[string]any) (string, error) {
	switch kind {
	case "User":
		out, err := cfnComputeCall[api.GetUserPolicyOutput](ctx, c, "iam", "GetUserPolicy", input)
		if err != nil {
			return "", err
		}
		return cfnComputeValue(out.PolicyDocument), nil
	case "Group":
		out, err := cfnComputeCall[api.GetGroupPolicyOutput](ctx, c, "iam", "GetGroupPolicy", input)
		if err != nil {
			return "", err
		}
		return cfnComputeValue(out.PolicyDocument), nil
	case "Role":
		out, err := cfnComputeCall[api.GetRolePolicyOutput](ctx, c, "iam", "GetRolePolicy", input)
		if err != nil {
			return "", err
		}
		return cfnComputeValue(out.PolicyDocument), nil
	}
	return "", fmt.Errorf("unsupported IAM identity kind %s", kind)
}
func cfnIAMListAttached(ctx context.Context, c StepFunctionsCommands, kind string, input map[string]any) (api.AttachedPoliciesListType, string, error) {
	switch kind {
	case "User":
		out, err := cfnComputeCall[api.ListAttachedUserPoliciesOutput](ctx, c, "iam", "ListAttachedUserPolicies", input)
		if err != nil {
			return nil, "", err
		}
		return out.AttachedPolicies, cfnComputeValue(out.Marker), nil
	case "Group":
		out, err := cfnComputeCall[api.ListAttachedGroupPoliciesOutput](ctx, c, "iam", "ListAttachedGroupPolicies", input)
		if err != nil {
			return nil, "", err
		}
		return out.AttachedPolicies, cfnComputeValue(out.Marker), nil
	case "Role":
		out, err := cfnComputeCall[api.ListAttachedRolePoliciesOutput](ctx, c, "iam", "ListAttachedRolePolicies", input)
		if err != nil {
			return nil, "", err
		}
		return out.AttachedPolicies, cfnComputeValue(out.Marker), nil
	}
	return nil, "", fmt.Errorf("unsupported IAM identity kind %s", kind)
}
