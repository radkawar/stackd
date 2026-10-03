package integrations

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/services/cloudformation"
)

type cfnEventRule struct{ commands StepFunctionsCommands }

func (h cfnEventRule) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "EventBusName", "Description", "EventPattern", "ScheduleExpression", "State", "RoleArn", "Targets", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "EventBusName", "Description", "ScheduleExpression", "State", "RoleArn"); err != nil {
		return err
	}
	if p["EventPattern"] == nil && p["ScheduleExpression"] == nil {
		return fmt.Errorf("EventPattern or ScheduleExpression is required")
	}
	if p["EventPattern"] != nil {
		if _, err := cfnComputeDocument(p["EventPattern"]); err != nil {
			return err
		}
	}
	if _, err := cfnEventRuleTargets(p); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func cfnEventRuleTargets(p map[string]any) ([]any, error) {
	if p["Targets"] == nil {
		return nil, nil
	}
	list, ok := p["Targets"].([]any)
	if !ok {
		return nil, fmt.Errorf("property Targets must be a list")
	}
	ids := map[string]bool{}
	for _, item := range list {
		target, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("property Targets entries must be objects")
		}
		if err := cfnComputeProperties(target, "Id", "Arn", "RoleArn", "Input", "InputPath", "InputTransformer", "RetryPolicy", "DeadLetterConfig", "SqsParameters", "HttpParameters"); err != nil {
			return nil, err
		}
		if err := cfnComputeRequired(target, "Id", "Arn"); err != nil {
			return nil, err
		}
		if err := cfnComputeStrings(target, "Id", "Arn", "RoleArn", "Input", "InputPath"); err != nil {
			return nil, err
		}
		id := cfnComputeString(target, "Id")
		if id == "" || ids[id] {
			return nil, fmt.Errorf("target IDs must be nonempty and unique")
		}
		ids[id] = true
		for key, allowed := range map[string][]string{"InputTransformer": {"InputTemplate", "InputPathsMap"}, "RetryPolicy": {"MaximumRetryAttempts", "MaximumEventAgeInSeconds"}, "DeadLetterConfig": {"Arn"}, "SqsParameters": {"MessageGroupId"}, "HttpParameters": {"HeaderParameters", "PathParameterValues", "QueryStringParameters"}} {
			if value, found := target[key]; found {
				object, ok := cfnComputeObject(value)
				if !ok {
					return nil, fmt.Errorf("%s must be an object", key)
				}
				if err := cfnComputeProperties(object, allowed...); err != nil {
					return nil, err
				}
			}
		}
	}
	return list, nil
}
func (h cfnEventRule) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	// Native stack events replace the bus-qualified physical resource before
	// retiring the old rule. Use the kernel's retained replacement lifecycle.
	return cfnComputeChanged(a, b, "Name") || cfnEventRuleBus(a) != cfnEventRuleBus(b), nil
}
func (h cfnEventRule) ReplacementPlan(a, b cloudformation.Properties) (string, error) {
	if err := h.Validate(b); err != nil {
		return "", err
	}
	if cfnComputeChanged(a, b, "Name") {
		return "True", nil
	}
	// Native plans report Conditional even when the bus name and ARN denote
	// the same resource. Execution resolves that identity using the stack scope.
	if cfnComputeChanged(a, b, "EventBusName") {
		return "Conditional", nil
	}
	return "False", nil
}
func (h cfnEventRule) ReplacementInScope(scope cloudformation.Scope, a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	beforeScope, beforeBus := cfnEventRuleBusIdentity(scope, a)
	afterScope, afterBus := cfnEventRuleBusIdentity(scope, b)
	return cfnComputeChanged(a, b, "Name") || beforeScope != afterScope || beforeBus != afterBus, nil
}
func cfnEventRuleBus(p map[string]any) string {
	return fmt.Sprint(cfnComputeDefault(p, "EventBusName", "default"))
}
func cfnEventRuleBusIdentity(scope cloudformation.Scope, p cloudformation.Properties) (cloudformation.Scope, string) {
	bus := cfnEventRuleBus(p)
	if parsed, err := arn.Parse(bus); err == nil && parsed.Service == "events" && strings.HasPrefix(parsed.Resource, "event-bus/") {
		scope.Account = parsed.AccountID
		bus = strings.TrimPrefix(parsed.Resource, "event-bus/")
	}
	return scope, bus
}
func cfnEventRuleName(r cloudformation.ResourceRequest) string {
	if _, name, qualified := strings.Cut(r.PhysicalID, "|"); qualified {
		return name
	}
	return cfnComputeName(r, "Name", 64)
}
func cfnEventRuleResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	scope, bus := cfnEventRuleBusIdentity(r.Scope, r.Properties)
	path, id := name, name
	if bus != "default" {
		path = bus + "/" + name
		id = bus + "|" + name
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": "arn:" + scope.Partition + ":events:" + scope.Region + ":" + scope.Account + ":rule/" + path, "RuleName": name}}
}
func (h cfnEventRule) put(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	input := cfnComputeCopy(r.Properties, "Description", "ScheduleExpression", "State", "RoleArn")
	input["Name"] = name
	input["EventBusName"] = cfnEventRuleBus(r.Properties)
	input["Tags"] = cfnComputeTagList(cfnComputeOwnedTags(r))
	if p := r.Properties["EventPattern"]; p != nil {
		input["EventPattern"], _ = cfnComputeDocument(p)
	}
	return cfnComputeRun(ctx, h.commands, "eventbridge", "PutRule", input)
}
func (h cfnEventRule) removeTargets(ctx context.Context, r cloudformation.ResourceRequest, name string, ids []string) error {
	for len(ids) > 0 {
		n := len(ids)
		if n > 10 {
			n = 10
		}
		out, err := cfnComputeCall[api.RemoveTargetsOutput](ctx, h.commands, "eventbridge", "RemoveTargets", map[string]any{"Rule": name, "EventBusName": cfnEventRuleBus(r.Properties), "Ids": ids[:n]})
		if err != nil {
			return err
		}
		if len(out.FailedEntries) > 0 || (out.FailedEntryCount != nil && *out.FailedEntryCount != 0) {
			return fmt.Errorf("EventBridge RemoveTargets failed: %v", out.FailedEntries)
		}
		ids = ids[n:]
	}
	return nil
}
func (h cfnEventRule) targets(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	desired, _ := cfnEventRuleTargets(r.Properties)
	wanted := map[string]bool{}
	for _, value := range desired {
		target, _ := cfnComputeObject(value)
		wanted[cfnComputeString(target, "Id")] = true
	}
	var removed []string
	token := ""
	for {
		input := map[string]any{"Rule": name, "EventBusName": cfnEventRuleBus(r.Properties)}
		if token != "" {
			input["NextToken"] = token
		}
		out, err := cfnComputeCall[api.ListTargetsByRuleOutput](ctx, h.commands, "eventbridge", "ListTargetsByRule", input)
		if err != nil {
			return err
		}
		for _, target := range out.Targets {
			if id := cfnComputeValue(target.Id); !wanted[id] {
				removed = append(removed, id)
			}
		}
		token = cfnComputeValue(out.NextToken)
		if token == "" {
			break
		}
	}
	if err := h.removeTargets(ctx, r, name, removed); err != nil {
		return err
	}
	for len(desired) > 0 {
		n := len(desired)
		if n > 10 {
			n = 10
		}
		out, err := cfnComputeCall[api.PutTargetsOutput](ctx, h.commands, "eventbridge", "PutTargets", map[string]any{"Rule": name, "EventBusName": cfnEventRuleBus(r.Properties), "Targets": desired[:n]})
		if err != nil {
			return err
		}
		if len(out.FailedEntries) > 0 || (out.FailedEntryCount != nil && *out.FailedEntryCount != 0) {
			return fmt.Errorf("EventBridge PutTargets failed: %v", out.FailedEntries)
		}
		desired = desired[n:]
	}
	return nil
}
func (h cfnEventRule) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEventRuleName(r)
	result := cfnEventRuleResult(r, name)
	err := cfnEventOwned(ctx, h.commands, r, result.Attributes["Arn"].(string))
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.put(ctx, r, name); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return result, h.targets(ctx, r, name)
}
func (h cfnEventRule) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if _, err := h.ReplacementInScope(r.Scope, r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEventRuleName(r)
	result := cfnEventRuleResult(r, name)
	arn := result.Attributes["Arn"].(string)
	if err := cfnEventOwned(ctx, h.commands, r, arn); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.put(ctx, r, name); err != nil {
		return result, err
	}
	if err := h.targets(ctx, r, name); err != nil {
		return result, err
	}
	return result, cfnEventSyncTags(ctx, h.commands, r, arn)
}
func (h cfnEventRule) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEventRuleName(r)
	result := cfnEventRuleResult(r, name)
	if err := cfnEventOwned(ctx, h.commands, r, result.Attributes["Arn"].(string)); err != nil {
		return cfnComputeAbsent(err)
	}
	r.Properties = cfnComputeCopy(r.Properties, "EventBusName")
	if err := h.targets(ctx, r, name); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eventbridge", "DeleteRule", map[string]any{"Name": name, "EventBusName": cfnEventRuleBus(r.Properties)}))
}
