package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"

	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

type cfnIAMManagedPolicy struct{ commands StepFunctionsCommands }

func (h cfnIAMManagedPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ManagedPolicyName", "Path", "Description", "PolicyDocument", "Roles", "Users", "Groups"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ManagedPolicyName", "Path", "Description"); err != nil {
		return err
	}
	if _, err := cfnComputeDocument(p["PolicyDocument"]); err != nil {
		return err
	}
	for _, key := range []string{"Roles", "Users", "Groups"} {
		if _, err := cfnComputeStringList(p, key); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnIAMManagedPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "ManagedPolicyName", "Description") || !reflect.DeepEqual(cfnComputeDefault(a, "Path", "/"), cfnComputeDefault(b, "Path", "/")), nil
}
func cfnIAMManagedARN(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return "arn:" + r.Scope.Partition + ":iam::" + r.Scope.Account + ":policy" + fmt.Sprint(cfnComputeDefault(r.Properties, "Path", "/")) + cfnComputeName(r, "ManagedPolicyName", 128)
}
func (h cfnIAMManagedPolicy) owned(ctx context.Context, r cloudformation.ResourceRequest, arn string) (*api.Policy, error) {
	out, err := cfnComputeCall[api.GetPolicyOutput](ctx, h.commands, "iam", "GetPolicy", map[string]any{"PolicyArn": arn})
	if err != nil {
		return nil, err
	}
	if out.Policy == nil {
		return nil, fmt.Errorf("IAM returned no managed policy")
	}
	tags := map[string]string{}
	for _, tag := range out.Policy.Tags {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	if err := cfnComputeOwnership(r, tags); err != nil {
		return nil, err
	}
	return out.Policy, nil
}
func cfnIAMManagedResult(policy *api.Policy) cloudformation.ResourceResult {
	arn := cfnComputeValue(policy.Arn)
	attributes := map[string]any{"PolicyArn": arn, "PolicyId": cfnComputeValue(policy.PolicyId), "DefaultVersionId": cfnComputeValue(policy.DefaultVersionId)}
	if policy.AttachmentCount != nil {
		attributes["AttachmentCount"] = int64(*policy.AttachmentCount)
	}
	if policy.PermissionsBoundaryUsageCount != nil {
		attributes["PermissionsBoundaryUsageCount"] = int64(*policy.PermissionsBoundaryUsageCount)
	}
	if policy.IsAttachable != nil {
		attributes["IsAttachable"] = bool(*policy.IsAttachable)
	}
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: attributes}
}
func (h cfnIAMManagedPolicy) attachments(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	for key, entity := range map[string]string{"Roles": "Role", "Users": "User", "Groups": "Group"} {
		desired, _ := cfnComputeStringList(r.Properties, key)
		previous, _ := cfnComputeStringList(r.Previous, key)
		for _, name := range desired {
			if err := cfnComputeRun(ctx, h.commands, "iam", "Attach"+entity+"Policy", map[string]any{entity + "Name": name, "PolicyArn": arn}); err != nil {
				return err
			}
		}
		for _, name := range previous {
			if !slices.Contains(desired, name) {
				if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "Detach"+entity+"Policy", map[string]any{entity + "Name": name, "PolicyArn": arn})); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (h cfnIAMManagedPolicy) pruneVersions(ctx context.Context, arn string) error {
	out, err := cfnComputeCall[api.ListPolicyVersionsOutput](ctx, h.commands, "iam", "ListPolicyVersions", map[string]any{"PolicyArn": arn, "MaxItems": 1000})
	if err != nil {
		return err
	}
	for _, version := range out.Versions {
		if version.IsDefaultVersion != nil && !bool(*version.IsDefaultVersion) {
			if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeletePolicyVersion", map[string]any{"PolicyArn": arn, "VersionId": cfnComputeValue(version.VersionId)})); err != nil {
				return err
			}
		}
	}
	return nil
}
func cfnIAMDocumentEqual(encoded, desired string) bool {
	actual, err := url.QueryUnescape(encoded)
	if err != nil {
		return false
	}
	var a, b any
	return json.Unmarshal([]byte(actual), &a) == nil && json.Unmarshal([]byte(desired), &b) == nil && reflect.DeepEqual(a, b)
}
func (h cfnIAMManagedPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnIAMManagedARN(r)
	policy, err := h.owned(ctx, r, arn)
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeMissing(err) {
		input := cfnComputeCopy(r.Properties, "Path", "Description")
		input["PolicyName"] = cfnComputeName(r, "ManagedPolicyName", 128)
		input["PolicyDocument"], _ = cfnComputeDocument(r.Properties["PolicyDocument"])
		input["Tags"] = cfnComputeTagList(cfnComputeOwnedTags(r))
		out, err := cfnComputeCall[api.CreatePolicyOutput](ctx, h.commands, "iam", "CreatePolicy", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		policy = out.Policy
	}
	result := cfnIAMManagedResult(policy)
	if err := h.attachments(ctx, r, arn); err != nil {
		return result, err
	}
	policy, err = h.owned(ctx, r, arn)
	if err != nil {
		return result, err
	}
	return cfnIAMManagedResult(policy), nil
}
func (h cfnIAMManagedPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := r.PhysicalID
	policy, err := h.owned(ctx, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMManagedResult(policy)
	desired, _ := cfnComputeDocument(r.Properties["PolicyDocument"])
	version, err := cfnComputeCall[api.GetPolicyVersionOutput](ctx, h.commands, "iam", "GetPolicyVersion", map[string]any{"PolicyArn": arn, "VersionId": cfnComputeValue(policy.DefaultVersionId)})
	if err != nil {
		return result, err
	}
	if version.PolicyVersion == nil {
		return result, fmt.Errorf("IAM returned no policy version")
	}
	if !cfnIAMDocumentEqual(cfnComputeValue(version.PolicyVersion.Document), desired) {
		if err := h.pruneVersions(ctx, arn); err != nil {
			return result, err
		}
		if err := cfnComputeRun(ctx, h.commands, "iam", "CreatePolicyVersion", map[string]any{"PolicyArn": arn, "PolicyDocument": desired, "SetAsDefault": true}); err != nil {
			return result, err
		}
	}
	if err := h.attachments(ctx, r, arn); err != nil {
		return result, err
	}
	if err := h.pruneVersions(ctx, arn); err != nil {
		return result, err
	}
	current := map[string]string{}
	for _, tag := range policy.Tags {
		current[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	tags := cfnComputeOwnedTags(r)
	if removed := cfnComputeRemovedTags(current, tags); len(removed) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "iam", "UntagPolicy", map[string]any{"PolicyArn": arn, "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	if err := cfnComputeRun(ctx, h.commands, "iam", "TagPolicy", map[string]any{"PolicyArn": arn, "Tags": cfnComputeTagList(tags)}); err != nil {
		return result, err
	}
	policy, err = h.owned(ctx, r, arn)
	if err != nil {
		return result, err
	}
	return cfnIAMManagedResult(policy), nil
}
func (h cfnIAMManagedPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	arn := cfnIAMManagedARN(r)
	if _, err := h.owned(ctx, r, arn); err != nil {
		return cfnComputeAbsent(err)
	}
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{}
	if err := h.attachments(ctx, r, arn); err != nil {
		return err
	}
	if err := h.pruneVersions(ctx, arn); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeletePolicy", map[string]any{"PolicyArn": arn}))
}
