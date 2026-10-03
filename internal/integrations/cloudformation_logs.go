package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/services/cloudformation"
)

type cfnLogGroup struct{ commands StepFunctionsCommands }

func (h cfnLogGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "LogGroupName", "RetentionInDays", "LogGroupClass", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "LogGroupName", "LogGroupClass"); err != nil {
		return err
	}
	if class := cfnComputeString(p, "LogGroupClass"); class != "" && class != "STANDARD" {
		return fmt.Errorf("only STANDARD log groups are supported")
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnLogGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "LogGroupName"), nil
}
func cfnLogGroupARN(r cloudformation.ResourceRequest, name string) string {
	return "arn:" + r.Scope.Partition + ":logs:" + r.Scope.Region + ":" + r.Scope.Account + ":log-group:" + name
}
func (h cfnLogGroup) tags(ctx context.Context, r cloudformation.ResourceRequest, name string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, h.commands, "logs", "ListTagsForResource", map[string]any{"ResourceArn": cfnLogGroupARN(r, name)})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for key, value := range out.Tags {
		tags[string(key)] = string(value)
	}
	return tags, nil
}
func (h cfnLogGroup) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (map[string]string, error) {
	tags, err := h.tags(ctx, r, name)
	if err != nil {
		return nil, err
	}
	if err := cfnComputeOwnership(r, tags); err != nil {
		return nil, cfnResourceCreateOwnedError(r, err)
	}
	return tags, nil
}
func cfnLogGroupResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": cfnLogGroupARN(r, name) + ":*"}}
}
func (h cfnLogGroup) retention(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	if days, found := r.Properties["RetentionInDays"]; found {
		return cfnComputeRun(ctx, h.commands, "logs", "PutRetentionPolicy", map[string]any{"LogGroupName": name, "RetentionInDays": days})
	}
	return cfnComputeRun(ctx, h.commands, "logs", "DeleteRetentionPolicy", map[string]any{"LogGroupName": name})
}
func (h cfnLogGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "LogGroupName", 512)
	result := cfnLogGroupResult(r, name)
	_, err := h.owned(ctx, r, name)
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeMissing(err) {
		input := map[string]any{"LogGroupName": name, "Tags": cfnComputeOwnedTags(r)}
		if err := cfnComputeRun(ctx, h.commands, "logs", "CreateLogGroup", input); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	return result, h.retention(ctx, r, name)
}
func (h cfnLogGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::Logs::LogGroup", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		name, err := cfnLogGroupIdentifier(r)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		r.PhysicalID = name
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	current, err := h.tags(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnComputeOwnership(r, current); !r.CloudControl && err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnLogGroupResult(r, r.PhysicalID)
	if err := h.retention(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	desired := cfnResourceMutationTags(r, current, cfnComputeOwnedTags(r))
	arn := cfnLogGroupARN(r, r.PhysicalID)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "logs", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(desired) == 0 {
		return result, nil
	}
	return result, cfnComputeRun(ctx, h.commands, "logs", "TagResource", map[string]any{"ResourceArn": arn, "Tags": desired})
}
func (h cfnLogGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.CloudControl {
		name, err := cfnLogGroupIdentifier(r)
		if err != nil {
			return err
		}
		return cfnComputeRun(ctx, h.commands, "logs", "DeleteLogGroup", map[string]any{"LogGroupName": name})
	}
	name := cfnComputeName(r, "LogGroupName", 512)
	if _, err := h.owned(ctx, r, name); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "logs", "DeleteLogGroup", map[string]any{"LogGroupName": name}))
}
