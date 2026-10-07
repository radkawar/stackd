package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/awscatalog"
	"stackd/internal/services/cloudformation"
)

// Application Auto Scaling CloudFormation adapters. Scaling effects are owned by
// the Application Auto Scaling service and the scaled resource's owner.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-applicationautoscaling-scalabletarget.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-applicationautoscaling-scalingpolicy.html

func cfnAASTagMap(tags api.TagMap) map[string]string {
	out := make(map[string]string, len(tags))
	for key, value := range tags {
		out[string(key)] = string(value)
	}
	return out
}

// cfnAASTargetKey is ResourceId|ScalableDimension|ServiceNamespace, the
// documented Ref and the registry's primary identifier order.
type cfnAASTargetKey struct{ Namespace, ResourceID, Dimension string }

func (k cfnAASTargetKey) id() string { return k.ResourceID + "|" + k.Dimension + "|" + k.Namespace }
func (k cfnAASTargetKey) input() map[string]any {
	return map[string]any{"ServiceNamespace": k.Namespace, "ResourceId": k.ResourceID, "ScalableDimension": k.Dimension}
}
func cfnAASParseTarget(id string) (cfnAASTargetKey, error) {
	parts, err := cfnCSCompound(id, 3)
	if err != nil {
		return cfnAASTargetKey{}, err
	}
	return cfnAASTargetKey{ResourceID: parts[0], Dimension: parts[1], Namespace: parts[2]}, nil
}
func cfnAASTargetFrom(p map[string]any) cfnAASTargetKey {
	return cfnAASTargetKey{Namespace: cfnComputeString(p, "ServiceNamespace"), ResourceID: cfnComputeString(p, "ResourceId"), Dimension: cfnComputeString(p, "ScalableDimension")}
}
func cfnAASGetTarget(ctx context.Context, c StepFunctionsCommands, key cfnAASTargetKey) (*api.ScalableTarget, map[string]string, error) {
	out, err := cfnComputeCall[api.DescribeScalableTargetsOutput](ctx, c, "applicationautoscaling", "DescribeScalableTargets", map[string]any{"ServiceNamespace": key.Namespace, "ResourceIds": []string{key.ResourceID}, "ScalableDimension": key.Dimension})
	if err != nil {
		return nil, nil, err
	}
	if len(out.ScalableTargets) != 1 {
		return nil, nil, cfnCSNotFound("scalable target " + key.id())
	}
	target := &out.ScalableTargets[0]
	tags, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "applicationautoscaling", "ListTagsForResource", map[string]any{"ResourceARN": cfnComputeValue(target.ScalableTargetARN)})
	if err != nil {
		return nil, nil, err
	}
	return target, cfnAASTagMap(tags.Tags), nil
}
func cfnAASNamespaces() []string {
	model, _ := awscatalog.LookupService("applicationautoscaling")
	shape, _ := model.Shape("com.amazonaws.applicationautoscaling#ServiceNamespace")
	out := make([]string, 0, len(shape.Enum))
	for _, value := range shape.Enum {
		out = append(out, value.Value)
	}
	return out
}

// ---- AWS::ApplicationAutoScaling::ScalableTarget ----

type cfnAASTarget struct{ commands StepFunctionsCommands }

const cfnAASTargetType = "AWS::ApplicationAutoScaling::ScalableTarget"

func (h cfnAASTarget) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnAASTargetType, p)
}
func (h cfnAASTarget) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnAASTargetType, a, b)
}
func cfnAASTargetResult(key cfnAASTargetKey) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: key.id(), Ref: key.id(), Attributes: map[string]any{"Id": key.id()}}
}
func (h cfnAASTarget) register(ctx context.Context, r cloudformation.ResourceRequest, key cfnAASTargetKey, tags map[string]string) error {
	input := cfnCSRename(r.Properties, nil, "Tags", "ScheduledActions")
	if tags != nil {
		input["Tags"] = tags
	}
	if _, ok := input["SuspendedState"]; !ok && r.Previous["SuspendedState"] != nil {
		// Removal resumes all suspended scaling activities.
		input["SuspendedState"] = map[string]any{"DynamicScalingInSuspended": false, "DynamicScalingOutSuspended": false, "ScheduledScalingSuspended": false}
	}
	return cfnCSRun(ctx, h.commands, "applicationautoscaling", "RegisterScalableTarget", input)
}

// schedules reconciles the target's ScheduledActions by name.
func (h cfnAASTarget) schedules(ctx context.Context, r cloudformation.ResourceRequest, key cfnAASTargetKey) error {
	desired, _ := r.Properties["ScheduledActions"].([]any)
	names := map[string]bool{}
	for _, raw := range desired {
		action, _ := cfnComputeObject(raw)
		input := cfnComputeCopy(action, "ScheduledActionName", "Schedule", "Timezone", "StartTime", "EndTime", "ScalableTargetAction")
		for k, v := range key.input() {
			input[k] = v
		}
		names[cfnComputeString(action, "ScheduledActionName")] = true
		if err := cfnCSRun(ctx, h.commands, "applicationautoscaling", "PutScheduledAction", input); err != nil {
			return err
		}
	}
	previous, _ := r.Previous["ScheduledActions"].([]any)
	for _, raw := range previous {
		action, _ := cfnComputeObject(raw)
		name := cfnComputeString(action, "ScheduledActionName")
		if names[name] {
			continue
		}
		input := key.input()
		input["ScheduledActionName"] = name
		if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "applicationautoscaling", "DeleteScheduledAction", input)); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnAASTarget) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	key := cfnAASTargetFrom(r.Properties)
	tags := cfnResourceTags(r)
	result := cloudformation.ResourceResult{}
	if _, _, err := cfnAASGetTarget(ctx, h.commands, key); err == nil {
		// RegisterScalableTarget is an upsert; only recover our private claim.
		if err := cfnNativeComputeOwned(ctx, r, key.id()); err != nil {
			return result, cfnResourceCreateOwnedError(r, err)
		}
		result = cfnAASTargetResult(key)
		tags = nil // Native registration rejects Tags for an existing target.
	} else if !cfnCSMissing(err, "ValidationException", "ObjectNotFoundException") {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.register(ctx, r, key, tags); err != nil {
		if _, _, readErr := cfnAASGetTarget(ctx, h.commands, key); readErr == nil && cfnNativeComputeOwned(ctx, r, key.id()) == nil {
			result = cfnAASTargetResult(key)
		}
		return result, err
	}
	return cfnAASTargetResult(key), h.schedules(ctx, r, key)
}
func (h cfnAASTarget) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	key, err := cfnAASParseTarget(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnAASTargetResult(key)
	target, tags, err := cfnAASGetTarget(ctx, h.commands, key)
	if err != nil {
		return result, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	if err := h.register(ctx, r, key, nil); err != nil {
		return result, err
	}
	if err := h.schedules(ctx, r, key); err != nil {
		return result, err
	}
	arn := cfnComputeValue(target.ScalableTargetARN)
	added, removed := cfnCSTagChanges(tags, cfnResourceTags(r))
	if len(removed) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "applicationautoscaling", "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(added) > 0 {
		return result, cfnComputeRun(ctx, h.commands, "applicationautoscaling", "TagResource", map[string]any{"ResourceARN": arn, "Tags": added})
	}
	return result, nil
}

// Delete deregisters the target; the owner removes its policies and actions.
func (h cfnAASTarget) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	key := cfnAASTargetFrom(r.Properties)
	if r.PhysicalID != "" {
		var err error
		if key, err = cfnAASParseTarget(r.PhysicalID); err != nil {
			return err
		}
	}
	_, _, err := cfnAASGetTarget(ctx, h.commands, key)
	if cfnCSMissing(err, "ObjectNotFoundException") {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, key.id()); err != nil {
		return err
	}
	return cfnCSAbsentAAS(cfnComputeRun(ctx, h.commands, "applicationautoscaling", "DeregisterScalableTarget", key.input()))
}
func cfnCSAbsentAAS(err error) error {
	if cfnCSMissing(err, "ObjectNotFoundException") {
		return nil
	}
	return err
}
func (h cfnAASTarget) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	key, err := cfnAASParseTarget(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	target, tags, err := cfnAASGetTarget(ctx, h.commands, key)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(target, nil)
	if err != nil {
		return nil, err
	}
	p["Id"] = key.id()
	actions, err := cfnComputeCall[api.DescribeScheduledActionsOutput](ctx, h.commands, "applicationautoscaling", "DescribeScheduledActions", key.input())
	if err != nil {
		return nil, err
	}
	if len(actions.ScheduledActions) > 0 {
		projected, err := cfnCSProject(map[string]any{"scheduledActions": actions.ScheduledActions}, nil)
		if err != nil {
			return nil, err
		}
		list, _ := projected["ScheduledActions"].([]any)
		for i, raw := range list {
			if action, ok := raw.(map[string]any); ok {
				list[i] = map[string]any(cfnCSKeep(action, "ScheduledActionName", "Schedule", "Timezone", "StartTime", "EndTime", "ScalableTargetAction"))
			}
		}
		p["ScheduledActions"] = list
	}
	p["Tags"] = cfnCSTagMapList(tags)
	return cfnCSKeep(p, "Id", "ServiceNamespace", "ResourceId", "ScalableDimension", "MinCapacity", "MaxCapacity", "RoleARN", "SuspendedState", "ScheduledActions", "Tags"), nil
}
func (h cfnAASTarget) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	for _, namespace := range cfnAASNamespaces() {
		input := map[string]any{"ServiceNamespace": namespace}
		for {
			out, err := cfnComputeCall[api.DescribeScalableTargetsOutput](ctx, h.commands, "applicationautoscaling", "DescribeScalableTargets", input)
			if err != nil {
				return nil, err
			}
			for _, target := range out.ScalableTargets {
				key := cfnAASTargetKey{Namespace: cfnComputeValue(target.ServiceNamespace), ResourceID: cfnComputeValue(target.ResourceId), Dimension: cfnComputeValue(target.ScalableDimension)}
				rows = append(rows, cloudformation.ResourceDescription{Identifier: key.id(), Properties: cloudformation.Properties{"ServiceNamespace": key.Namespace, "ResourceId": key.ResourceID, "ScalableDimension": key.Dimension}})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = cfnComputeValue(out.NextToken)
		}
	}
	return rows, nil
}

// ---- AWS::ApplicationAutoScaling::ScalingPolicy ----

type cfnAASPolicy struct{ commands StepFunctionsCommands }

const cfnAASPolicyType = "AWS::ApplicationAutoScaling::ScalingPolicy"

func (h cfnAASPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnCSValidate(cfnAASPolicyType, p); err != nil {
		return err
	}
	if p["ScalingTargetId"] != nil && (p["ResourceId"] != nil || p["ScalableDimension"] != nil || p["ServiceNamespace"] != nil) {
		return fmt.Errorf("specify ScalingTargetId or ResourceId/ScalableDimension/ServiceNamespace, not both")
	}
	return nil
}
func (h cfnAASPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnAASPolicyType, a, b)
}
func (h cfnAASPolicy) target(p map[string]any) (cfnAASTargetKey, error) {
	if id := cfnComputeString(p, "ScalingTargetId"); id != "" {
		return cfnAASParseTarget(id)
	}
	key := cfnAASTargetFrom(p)
	if key.Namespace == "" || key.ResourceID == "" || key.Dimension == "" {
		return key, fmt.Errorf("ScalingTargetId or ResourceId, ScalableDimension and ServiceNamespace are required")
	}
	return key, nil
}

// arn:...:scalingPolicy:<id>:resource/<namespace>/<resourceId>:policyName/<name>
func cfnAASPolicyIdentity(id string) (cfnAASTargetKey, string, error) {
	arn, dimension, ok := strings.Cut(id, "|")
	_, rest, found := strings.Cut(arn, ":resource/")
	resource, name, named := strings.Cut(rest, ":policyName/")
	namespace, resourceID, qualified := strings.Cut(resource, "/")
	if !ok || !found || !named || !qualified || name == "" {
		return cfnAASTargetKey{}, "", fmt.Errorf("invalid Application Auto Scaling policy identifier %q", id)
	}
	return cfnAASTargetKey{Namespace: namespace, ResourceID: resourceID, Dimension: dimension}, name, nil
}
func (h cfnAASPolicy) get(ctx context.Context, key cfnAASTargetKey, name string) (*api.ScalingPolicy, error) {
	input := key.input()
	input["PolicyNames"] = []string{name}
	out, err := cfnComputeCall[api.DescribeScalingPoliciesOutput](ctx, h.commands, "applicationautoscaling", "DescribeScalingPolicies", input)
	if err != nil {
		return nil, err
	}
	if len(out.ScalingPolicies) != 1 {
		return nil, cfnCSNotFound("scaling policy " + name)
	}
	return &out.ScalingPolicies[0], nil
}
func cfnAASPolicyResult(arn string, key cfnAASTargetKey) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: arn + "|" + key.Dimension, Ref: arn, Attributes: map[string]any{"Arn": arn}}
}

func (h cfnAASPolicy) put(ctx context.Context, r cloudformation.ResourceRequest, key cfnAASTargetKey) (string, error) {
	input := cfnCSRename(r.Properties, nil, "ScalingTargetId")
	for k, v := range key.input() {
		input[k] = v
	}
	out, err := cfnCSCall[api.PutScalingPolicyOutput](ctx, h.commands, "applicationautoscaling", "PutScalingPolicy", input)
	if err != nil {
		return "", err
	}
	return cfnComputeValue(out.PolicyARN), nil
}
func (h cfnAASPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	key, err := h.target(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "PolicyName")
	policy, err := h.get(ctx, key, name)
	result := cloudformation.ResourceResult{}
	if err == nil {
		id := cfnComputeValue(policy.PolicyARN) + "|" + key.Dimension
		if err := cfnNativeComputeOwned(ctx, r, id); err != nil {
			return result, cfnResourceCreateOwnedError(r, err)
		}
		result = cfnAASPolicyResult(cfnComputeValue(policy.PolicyARN), key)
	} else if !cfnCSMissing(err) {
		return result, err
	}
	arn, err := h.put(ctx, r, key)
	if err != nil {
		if recovered, readErr := h.get(ctx, key, name); readErr == nil {
			id := cfnComputeValue(recovered.PolicyARN) + "|" + key.Dimension
			if cfnNativeComputeOwned(ctx, r, id) == nil {
				result = cfnAASPolicyResult(cfnComputeValue(recovered.PolicyARN), key)
			}
		}
		return result, err
	}
	return cfnAASPolicyResult(arn, key), nil
}
func (h cfnAASPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	key, name, err := cfnAASPolicyIdentity(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn, _, _ := strings.Cut(r.PhysicalID, "|")
	result := cfnAASPolicyResult(arn, key)
	if _, err := h.get(ctx, key, name); err != nil {
		return result, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	if arn, err = h.put(ctx, r, key); err != nil {
		return result, err
	}
	return cfnAASPolicyResult(arn, key), nil
}
func (h cfnAASPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	var key cfnAASTargetKey
	var name string
	var err error
	if r.PhysicalID != "" {
		key, name, err = cfnAASPolicyIdentity(r.PhysicalID)
	} else {
		key, err = h.target(r.Properties)
		name = cfnComputeString(r.Properties, "PolicyName")
	}
	if err != nil {
		return err
	}
	policy, err := h.get(ctx, key, name)
	if cfnCSMissing(err, "ObjectNotFoundException") {
		return nil
	} else if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, cfnComputeValue(policy.PolicyARN)+"|"+key.Dimension); err != nil {
		return err
	}
	input := key.input()
	input["PolicyName"] = name
	if err := cfnCSAbsentAAS(cfnComputeRun(ctx, h.commands, "applicationautoscaling", "DeleteScalingPolicy", input)); err != nil {
		return err
	}
	return nil
}
func (h cfnAASPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	key, name, err := cfnAASPolicyIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	policy, err := h.get(ctx, key, name)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(policy, map[string]string{"PolicyARN": "Arn"})
	if err != nil {
		return nil, err
	}
	p["ScalingTargetId"] = key.id()
	return cfnCSKeep(p, "Arn", "PolicyName", "PolicyType", "ServiceNamespace", "ResourceId", "ScalableDimension", "ScalingTargetId", "StepScalingPolicyConfiguration", "TargetTrackingScalingPolicyConfiguration", "PredictiveScalingPolicyConfiguration"), nil
}
func (h cfnAASPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	for _, namespace := range cfnAASNamespaces() {
		input := map[string]any{"ServiceNamespace": namespace}
		for {
			out, err := cfnComputeCall[api.DescribeScalingPoliciesOutput](ctx, h.commands, "applicationautoscaling", "DescribeScalingPolicies", input)
			if err != nil {
				return nil, err
			}
			for _, policy := range out.ScalingPolicies {
				arn, dimension := cfnComputeValue(policy.PolicyARN), cfnComputeValue(policy.ScalableDimension)
				rows = append(rows, cloudformation.ResourceDescription{Identifier: arn + "|" + dimension, Properties: cloudformation.Properties{"Arn": arn, "ScalableDimension": dimension}})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = cfnComputeValue(out.NextToken)
		}
	}
	return rows, nil
}
