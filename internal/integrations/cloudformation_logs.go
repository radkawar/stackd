package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/logs"
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
func cfnLogGroupContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return logs.WithCloudFormationLogGroupOwner(ctx, cfnLogsMarker(r), create)
}
func (h cfnLogGroup) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (map[string]string, error) {
	rows := map[string]string{}
	tags, err := h.tags(logs.WithCloudFormationObservation(ctx, "LogGroup", name, rows), r, name)
	if err != nil {
		return nil, err
	}
	if rows[name] != cfnLogsMarker(r) {
		return nil, cfnResourceCreateOwnedError(r, fmt.Errorf("log group is not owned by this creation"))
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
	ctx = cfnLogGroupContext(ctx, r, true)
	admissions := map[string]string{}
	ctx = logs.WithCloudFormationObservation(ctx, "LogGroup", name, admissions)
	tags := cfnObservabilityCreateTags(r)
	input := map[string]any{"LogGroupName": name}
	if len(tags) > 0 {
		input["Tags"] = tags
	}
	if class, found := r.Properties["LogGroupClass"]; found {
		input["LogGroupClass"] = class
	}
	if err := cfnComputeRun(ctx, h.commands, "logs", "CreateLogGroup", input); err != nil {
		if admissions[name] == cfnLogsMarker(r) {
			return result, err
		}
		admitted, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
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
	ctx = cfnLogGroupContext(ctx, r, false)
	current, err := h.tags(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnLogGroupResult(r, r.PhysicalID)
	if err := h.retention(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	desired := cfnObservabilityCreateTags(r)
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
	return cfnComputeAbsent(cfnComputeRun(cfnLogGroupContext(ctx, r, false), h.commands, "logs", "DeleteLogGroup", map[string]any{"LogGroupName": name}))
}

func (h cfnLogGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeName(r, "LogGroupName", 512)
	if _, err := h.owned(ctx, r, name); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLogGroupResult(r, name), nil
}
