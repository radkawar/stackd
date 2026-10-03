package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/services/cloudformation"
)

type cfnEventBus struct{ commands StepFunctionsCommands }

func (h cfnEventBus) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description"); err != nil {
		return err
	}
	if cfnComputeString(p, "Name") == "default" {
		return fmt.Errorf("the default event bus cannot be owned by a stack")
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnEventBus) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "Name"), nil
}
func cfnEventTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "eventbridge", "ListTagsForResource", map[string]any{"ResourceARN": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, tag := range out.Tags {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func cfnEventOwned(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	tags, err := cfnEventTags(ctx, c, arn)
	if err != nil {
		return err
	}
	return cfnComputeOwnership(r, tags)
}
func cfnEventSyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	current, err := cfnEventTags(ctx, c, arn)
	if err != nil {
		return err
	}
	if err := cfnComputeOwnership(r, current); err != nil {
		return err
	}
	desired := cfnComputeOwnedTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "eventbridge", "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	return cfnComputeRun(ctx, c, "eventbridge", "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(desired)})
}
func cfnEventBusResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": "arn:" + r.Scope.Partition + ":events:" + r.Scope.Region + ":" + r.Scope.Account + ":event-bus/" + name, "Name": name}}
}
func (h cfnEventBus) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 256)
	result := cfnEventBusResult(r, name)
	err := cfnEventOwned(ctx, h.commands, r, result.Attributes["Arn"].(string))
	if err == nil {
		return result, nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Description")
	input["Name"] = name
	input["Tags"] = cfnComputeTagList(cfnComputeOwnedTags(r))
	if err := cfnComputeRun(ctx, h.commands, "eventbridge", "CreateEventBus", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return result, nil
}
func (h cfnEventBus) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEventBusResult(r, r.PhysicalID)
	arn := result.Attributes["Arn"].(string)
	if err := cfnEventOwned(ctx, h.commands, r, arn); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnComputeRun(ctx, h.commands, "eventbridge", "UpdateEventBus", map[string]any{"Name": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", "")}); err != nil {
		return result, err
	}
	return result, cfnEventSyncTags(ctx, h.commands, r, arn)
}
func (h cfnEventBus) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 256)
	result := cfnEventBusResult(r, name)
	if err := cfnEventOwned(ctx, h.commands, r, result.Attributes["Arn"].(string)); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eventbridge", "DeleteEventBus", map[string]any{"Name": name}))
}
