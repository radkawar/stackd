package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/services/cloudformation"
	events "stackd/internal/services/eventbridge"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-eventbus.html
type cfnEventBus struct{ commands StepFunctionsCommands }

func (h cfnEventBus) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Tags", "KmsKeyIdentifier", "DeadLetterConfig", "Policy"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description", "KmsKeyIdentifier"); err != nil {
		return err
	}
	if cfnComputeString(p, "Name") == "default" {
		return fmt.Errorf("the default event bus cannot be owned by a stack")
	}
	if p["Policy"] != nil {
		if _, err := cfnComputeDocument(p["Policy"]); err != nil {
			return err
		}
	}
	if p["DeadLetterConfig"] != nil {
		config, ok := cfnComputeObject(p["DeadLetterConfig"])
		if !ok {
			return fmt.Errorf("DeadLetterConfig must be an object")
		}
		if err := cfnComputeProperties(config, "Arn"); err != nil {
			return err
		}
		if err := cfnComputeStrings(config, "Arn"); err != nil {
			return err
		}
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
func cfnEventSyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	current, err := cfnEventTags(ctx, c, arn)
	if err != nil {
		return err
	}
	// Event resource tags are customer metadata; ownership is private native state.
	desired, _ := cfnComputeTags(r.Properties)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "eventbridge", "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "eventbridge", "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(desired)})
}
func (h cfnEventBus) policy(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	ctx = events.WithCloudFormationBusPolicyReplacement(ctx)
	if r.Properties["Policy"] != nil {
		document, err := cfnComputeDocument(r.Properties["Policy"])
		if err != nil {
			return err
		}
		return cfnComputeRun(ctx, h.commands, "eventbridge", "PutPermission", map[string]any{"EventBusName": name, "Policy": document})
	}
	if r.Previous["Policy"] != nil {
		return cfnComputeRun(ctx, h.commands, "eventbridge", "RemovePermission", map[string]any{"EventBusName": name, "RemoveAllPermissions": true})
	}
	return nil
}
func (h cfnEventBus) creationOwned(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	provider, ok := h.commands.providers["eventbridge"]
	if !ok {
		return fmt.Errorf("EventBridge owner unavailable")
	}
	owner, ok := provider.executor.(interface {
		CloudFormationResourceOwned(context.Context, string, string, string) error
	})
	if !ok {
		return fmt.Errorf("EventBridge incarnation authority unavailable")
	}
	return owner.CloudFormationResourceOwned(ctx, "EventBus", name, cfnMessagingMarker(r))
}
func (h cfnEventBus) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeName(r, "Name", 256)
	if err := h.creationOwned(ctx, r, name); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEventBusResult(r, name), nil
}
func cfnEventBusResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": "arn:" + r.Scope.Partition + ":events:" + r.Scope.Region + ":" + r.Scope.Account + ":event-bus/" + name, "Name": name}}
}
func (h cfnEventBus) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = events.WithCloudFormationOwner(ctx, "EventBus", cfnMessagingMarker(r), "")
	name := cfnComputeName(r, "Name", 256)
	result := cfnEventBusResult(r, name)
	err := h.creationOwned(ctx, r, name)
	if err == nil {
		return result, h.policy(ctx, r, name)
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "KmsKeyIdentifier", "DeadLetterConfig")
	input["Name"] = name
	tags, _ := cfnComputeTags(r.Properties)
	input["Tags"] = cfnComputeTagList(tags)
	if err := cfnComputeRun(ctx, h.commands, "eventbridge", "CreateEventBus", input); err != nil {
		// A failed command reply is not evidence that admission did not occur.
		if h.creationOwned(ctx, r, name) == nil {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return result, h.policy(ctx, r, name)
}
func (h cfnEventBus) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnEventsContext(ctx, r, "EventBus", "")
	result := cfnEventBusResult(r, r.PhysicalID)
	arn := result.Attributes["Arn"].(string)
	if err := cfnEventsOwned(ctx, h.commands, r, "EventBus", cfnComputeName(r, "Name", 256)); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	policyChanged := cfnComputeChanged(r.Previous, r.Properties, "Policy")
	if policyChanged {
		document := ""
		remove := r.Properties["Policy"] == nil
		if !remove {
			var err error
			document, err = cfnComputeDocument(r.Properties["Policy"])
			if err != nil {
				return result, err
			}
		}
		ctx = events.WithCloudFormationBusPolicyUpdate(ctx, document, remove)
	}
	input := &api.UpdateEventBusInput{
		Name:             new(api.EventBusName(r.PhysicalID)),
		Description:      new(api.EventBusDescription(cfnComputeString(r.Properties, "Description"))),
		KmsKeyIdentifier: new(api.KmsKeyIdentifier(cfnComputeString(r.Properties, "KmsKeyIdentifier"))),
	}
	if config, present := r.Properties["DeadLetterConfig"]; present {
		input.DeadLetterConfig = &api.DeadLetterConfig{}
		if object, ok := cfnComputeObject(config); ok {
			if arn, ok := object["Arn"].(string); ok {
				input.DeadLetterConfig.Arn = new(api.ResourceArn(arn))
			}
		}
	} else if r.Previous["DeadLetterConfig"] != nil {
		// The retained native UpdateEventBus capture documents an empty ARN
		// as removal. Invoke the typed owner, retaining its native validation.
		input.DeadLetterConfig = &api.DeadLetterConfig{Arn: new(api.ResourceArn(""))}
	}
	if _, err := h.commands.CallTyped(ctx, "eventbridge", "UpdateEventBus", input); err != nil {
		return result, err
	}
	if policyChanged {
		if err := h.policy(ctx, r, r.PhysicalID); err != nil {
			return result, err
		}
	}
	return result, cfnEventSyncTags(ctx, h.commands, r, arn)
}
func (h cfnEventBus) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnEventsContext(ctx, r, "EventBus", "")
	name := cfnComputeName(r, "Name", 256)
	if err := cfnEventsOwned(ctx, h.commands, r, "EventBus", name); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eventbridge", "DeleteEventBus", map[string]any{"Name": name}))
}
