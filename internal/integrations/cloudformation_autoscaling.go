package integrations

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/services/autoscaling"
	"stackd/internal/services/cloudformation"
)

// EC2 Auto Scaling CloudFormation adapters. Instance launches are EC2 owner
// effects; an unavailable runtime surfaces as a failed scaling activity.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-lifecyclehook.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-scalingpolicy.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-scheduledaction.html

func cfnASGGet(ctx context.Context, c StepFunctionsCommands, name string) (*api.AutoScalingGroup, error) {
	out, err := cfnComputeCall[api.DescribeAutoScalingGroupsOutput](ctx, c, "autoscaling", "DescribeAutoScalingGroups", map[string]any{"AutoScalingGroupNames": []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out.AutoScalingGroups) != 1 {
		return nil, cfnCSNotFound("Auto Scaling group " + name)
	}
	return &out.AutoScalingGroups[0], nil
}
func cfnASGTagMap(tags api.TagDescriptionList) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return out
}
func cfnASGTagInput(group string, tags map[string]string, propagate map[string]bool) []any {
	out := make([]any, 0, len(tags))
	for _, tag := range cfnComputeTagList(tags) {
		out = append(out, map[string]any{"ResourceId": group, "ResourceType": "auto-scaling-group", "Key": tag["Key"], "Value": tag["Value"], "PropagateAtLaunch": propagate[tag["Key"]]})
	}
	return out
}

// cfnASGUserTags parses AutoScalingGroup tags, which carry PropagateAtLaunch.
func cfnASGUserTags(p map[string]any) (map[string]string, map[string]bool, error) {
	tags, propagate := map[string]string{}, map[string]bool{}
	list, _ := p["Tags"].([]any)
	if p["Tags"] != nil && list == nil {
		return nil, nil, fmt.Errorf("property Tags must be a list")
	}
	for _, raw := range list {
		tag, ok := cfnComputeObject(raw)
		if !ok {
			return nil, nil, fmt.Errorf("property Tags entries must be objects")
		}
		if err := cfnComputeProperties(tag, "Key", "Value", "PropagateAtLaunch"); err != nil {
			return nil, nil, err
		}
		key, _ := tag["Key"].(string)
		value, _ := tag["Value"].(string)
		if key == "" || strings.HasPrefix(strings.ToLower(key), "aws:") || strings.HasPrefix(key, cfnComputeTagPrefix) {
			return nil, nil, fmt.Errorf("invalid tag key %q", key)
		}
		if _, duplicate := tags[key]; duplicate {
			return nil, nil, fmt.Errorf("duplicate tag key %s", key)
		}
		tags[key] = value
		switch v := tag["PropagateAtLaunch"].(type) {
		case bool:
			propagate[key] = v
		case string:
			propagate[key] = v == "true"
		}
	}
	return tags, propagate, nil
}
func cfnASGOwnedTags(r cloudformation.ResourceRequest) (map[string]string, map[string]bool) {
	tags := map[string]string{}
	for key, value := range r.Tags {
		tags[key] = value
	}
	user, propagate, _ := cfnASGUserTags(r.Properties)
	for key, value := range user {
		tags[key] = value
	}
	return tags, propagate
}

// ---- AWS::AutoScaling::AutoScalingGroup ----

type cfnASGGroup struct{ commands StepFunctionsCommands }

const cfnASGGroupType = "AWS::AutoScaling::AutoScalingGroup"

func (h cfnASGGroup) Validate(p cloudformation.Properties) error {
	// The owner implements no notification configuration control.
	if err := cloudformation.ValidateResourceProperties(cfnASGGroupType, p); err != nil {
		return err
	}
	for _, key := range []string{"NotificationConfigurations", "NotificationConfiguration"} {
		if p[key] != nil {
			return cfnCSUnsupported("Auto Scaling notification configurations are not implemented by the Auto Scaling owner")
		}
	}
	_, _, err := cfnASGUserTags(p)
	return err
}
func (h cfnASGGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnASGGroupType, a, b)
}
func cfnASGGroupResult(g *api.AutoScalingGroup) cloudformation.ResourceResult {
	name := cfnComputeValue(g.AutoScalingGroupName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"AutoScalingGroupARN": cfnComputeValue(g.AutoScalingGroupARN)}}
}
func cfnASGSubnets(p map[string]any) (string, bool) {
	list, ok := p["VPCZoneIdentifier"].([]any)
	if !ok {
		return "", false
	}
	subnets := make([]string, 0, len(list))
	for _, item := range list {
		subnets = append(subnets, fmt.Sprint(item))
	}
	return strings.Join(subnets, ","), true
}
func (h cfnASGGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "AutoScalingGroupName", 255)
	if g, err := cfnASGGet(ctx, h.commands, name); err == nil {
		if err := cfnNativeComputeOwned(ctx, r, name); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return cfnASGGroupResult(g), h.metrics(ctx, r, name)
	} else if !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnCSRename(r.Properties, map[string]string{"Cooldown": "DefaultCooldown"}, "Tags", "MetricsCollection", "VPCZoneIdentifier", "AutoScalingGroupName")
	input["AutoScalingGroupName"] = name
	if subnets, ok := cfnASGSubnets(r.Properties); ok {
		input["VPCZoneIdentifier"] = subnets
	}
	tags, propagate := cfnASGOwnedTags(r)
	input["Tags"] = cfnASGTagInput(name, tags, propagate)
	if err := cfnCSRun(ctx, h.commands, "autoscaling", "CreateAutoScalingGroup", input); err != nil {
		if g, readErr := cfnASGGet(ctx, h.commands, name); readErr == nil && cfnNativeComputeOwned(ctx, r, name) == nil {
			return cfnASGGroupResult(g), err
		}
		return cloudformation.ResourceResult{}, err
	}
	g, err := cfnASGGet(ctx, h.commands, name)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: name, Ref: name}, err
	}
	return cfnASGGroupResult(g), h.metrics(ctx, r, name)
}

// metrics reconciles MetricsCollection through Enable/DisableMetricsCollection.
func (h cfnASGGroup) metrics(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	if reflect.DeepEqual(r.Previous["MetricsCollection"], r.Properties["MetricsCollection"]) && r.Previous != nil {
		return nil
	}
	if r.Previous["MetricsCollection"] != nil {
		if err := cfnComputeRun(ctx, h.commands, "autoscaling", "DisableMetricsCollection", map[string]any{"AutoScalingGroupName": name}); err != nil {
			return err
		}
	}
	list, _ := r.Properties["MetricsCollection"].([]any)
	for _, raw := range list {
		object, _ := cfnComputeObject(raw)
		input := cfnComputeCopy(object, "Granularity", "Metrics")
		input["AutoScalingGroupName"] = name
		if err := cfnCSRun(ctx, h.commands, "autoscaling", "EnableMetricsCollection", input); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnASGGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	g, err := cfnASGGet(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnASGGroupResult(g)
	current := cfnASGTagMap(g.Tags)
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "TargetGroupARNs", "LoadBalancerNames", "TrafficSources") {
		return result, cfnCSUnsupported("the Auto Scaling owner implements no attach/detach traffic-source controls")
	}
	if err := cfnNativeComputeInlineHooks(ctx, h.commands, r); err != nil {
		return result, err
	}
	mutable := []string{"MinSize", "MaxSize", "DesiredCapacity", "LaunchTemplate", "LaunchConfigurationName", "VPCZoneIdentifier", "AvailabilityZones", "Cooldown", "DefaultInstanceWarmup", "HealthCheckType", "HealthCheckGracePeriod", "TerminationPolicies", "NewInstancesProtectedFromScaleIn", "ServiceLinkedRoleARN", "AvailabilityZoneDistribution", "AvailabilityZoneImpairmentPolicy", "CapacityRebalance", "CapacityReservationSpecification", "Context", "DesiredCapacityType", "DeletionProtection", "InstanceLifecyclePolicy", "InstanceMaintenancePolicy", "MaxInstanceLifetime", "MixedInstancesPolicy", "PlacementGroup", "SkipZonalShiftValidation", "AvailabilityZoneIds"}
	removed := func(key string) bool {
		return r.Previous[key] != nil && r.Properties[key] == nil
	}
	removals := autoscaling.GroupUpdateRemovals{
		LaunchTemplate: removed("LaunchTemplate"), LaunchConfigurationName: removed("LaunchConfigurationName"), MixedInstancesPolicy: removed("MixedInstancesPolicy"),
		VPCZoneIdentifier: removed("VPCZoneIdentifier"), AvailabilityZones: removed("AvailabilityZones"), AvailabilityZoneIds: removed("AvailabilityZoneIds"),
		DefaultCooldown: removed("Cooldown"), DefaultInstanceWarmup: removed("DefaultInstanceWarmup"), HealthCheckType: removed("HealthCheckType"), HealthCheckGracePeriod: removed("HealthCheckGracePeriod"),
		TerminationPolicies: removed("TerminationPolicies"), NewInstancesProtectedFromScaleIn: removed("NewInstancesProtectedFromScaleIn"), ServiceLinkedRoleARN: removed("ServiceLinkedRoleARN"),
		AvailabilityZoneDistribution: removed("AvailabilityZoneDistribution"), AvailabilityZoneImpairmentPolicy: removed("AvailabilityZoneImpairmentPolicy"),
		CapacityRebalance: removed("CapacityRebalance"), CapacityReservationSpecification: removed("CapacityReservationSpecification"), Context: removed("Context"), DesiredCapacityType: removed("DesiredCapacityType"),
		DeletionProtection: removed("DeletionProtection"), InstanceLifecyclePolicy: removed("InstanceLifecyclePolicy"), InstanceMaintenancePolicy: removed("InstanceMaintenancePolicy"),
		MaxInstanceLifetime: removed("MaxInstanceLifetime"), PlacementGroup: removed("PlacementGroup"),
	}
	if removals != (autoscaling.GroupUpdateRemovals{}) {
		ctx = autoscaling.WithGroupUpdateRemovals(ctx, removals)
	}
	if cfnComputeChanged(r.Previous, r.Properties, mutable...) {
		input := cfnCSRename(cfnComputeCopy(r.Properties, mutable...), map[string]string{"Cooldown": "DefaultCooldown"}, "VPCZoneIdentifier")
		input["AutoScalingGroupName"] = r.PhysicalID
		if subnets, ok := cfnASGSubnets(r.Properties); ok {
			input["VPCZoneIdentifier"] = subnets
		}
		if _, ok := r.Properties["DesiredCapacity"]; !ok {
			// Omitted desired capacity is preserved within the new bounds.
			delete(input, "DesiredCapacity")
		}
		if err := cfnCSRun(ctx, h.commands, "autoscaling", "UpdateAutoScalingGroup", input); err != nil {
			return result, err
		}
	}
	if err := h.hooks(ctx, r); err != nil {
		return result, err
	}
	if err := h.metrics(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	desired, propagate := cfnASGOwnedTags(r)
	var removedTags []any
	for _, key := range cfnComputeRemovedTags(current, desired) {
		removedTags = append(removedTags, map[string]any{"ResourceId": r.PhysicalID, "ResourceType": "auto-scaling-group", "Key": key})
	}
	if len(removedTags) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "autoscaling", "DeleteTags", map[string]any{"Tags": removedTags}); err != nil {
			return result, err
		}
	}
	if len(desired) > 0 {
		return result, cfnComputeRun(ctx, h.commands, "autoscaling", "CreateOrUpdateTags", map[string]any{"Tags": cfnASGTagInput(r.PhysicalID, desired, propagate)})
	}
	return result, nil
}

// hooks reconciles LifecycleHookSpecificationList against owner hooks.
func (h cfnASGGroup) hooks(ctx context.Context, r cloudformation.ResourceRequest) error {
	if reflect.DeepEqual(r.Previous["LifecycleHookSpecificationList"], r.Properties["LifecycleHookSpecificationList"]) {
		return nil
	}
	ctx = cfnNativeComputeInlineHookContext(ctx, r)
	desired, _ := r.Properties["LifecycleHookSpecificationList"].([]any)
	names := map[string]bool{}
	for _, raw := range desired {
		spec, _ := cfnComputeObject(raw)
		input := cfnComputeCopy(spec, "LifecycleHookName", "LifecycleTransition", "DefaultResult", "HeartbeatTimeout", "NotificationMetadata", "NotificationTargetARN", "RoleARN")
		input["AutoScalingGroupName"] = r.PhysicalID
		names[fmt.Sprint(spec["LifecycleHookName"])] = true
		if err := cfnCSRun(ctx, h.commands, "autoscaling", "PutLifecycleHook", input); err != nil {
			return err
		}
	}
	previous, _ := r.Previous["LifecycleHookSpecificationList"].([]any)
	for _, raw := range previous {
		spec, _ := cfnComputeObject(raw)
		name := fmt.Sprint(spec["LifecycleHookName"])
		if names[name] {
			continue
		}
		err := cfnComputeRun(ctx, h.commands, "autoscaling", "DeleteLifecycleHook", map[string]any{"AutoScalingGroupName": r.PhysicalID, "LifecycleHookName": name})
		if err != nil && !cfnCSMissing(err, "ValidationError") {
			return err
		}
	}
	return nil
}

// Stabilize waits for desired capacity in service, matching CloudFormation's
// group stabilization; a failed launch activity fails the stack operation.
func (h cfnASGGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	g, err := cfnASGGet(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return false, err
	}
	inService := 0
	for _, instance := range g.Instances {
		if cfnComputeValue(instance.LifecycleState) == "InService" {
			inService++
		}
	}
	desired := 0
	if g.DesiredCapacity != nil {
		desired = int(*g.DesiredCapacity)
	}
	if inService >= desired && len(g.Instances) == inService {
		return true, nil
	}
	out, err := cfnComputeCall[api.DescribeScalingActivitiesOutput](ctx, h.commands, "autoscaling", "DescribeScalingActivities", map[string]any{"AutoScalingGroupName": r.PhysicalID, "MaxRecords": 1})
	if err != nil {
		return false, err
	}
	if len(out.Activities) > 0 {
		latest := out.Activities[0]
		if status := cfnComputeValue(latest.StatusCode); status == "Failed" || status == "Cancelled" {
			return false, fmt.Errorf("group did not stabilize. {current/minSize/maxSize} group size = %d/%d/%d: %s", inService, cfnASGInt(g.MinSize), cfnASGInt(g.MaxSize), cfnComputeValue(latest.StatusMessage))
		}
	}
	return false, nil
}
func cfnASGInt[T ~int32 | ~int64 | ~int](v *T) int {
	if v == nil {
		return 0
	}
	return int(*v)
}
func (h cfnASGGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	name := cfnComputeName(r, "AutoScalingGroupName", 255)
	g, err := cfnASGGet(ctx, h.commands, name)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(g.Status) != "" {
		return nil // deletion already in progress
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, name); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "autoscaling", "DeleteAutoScalingGroup", map[string]any{"AutoScalingGroupName": name, "ForceDelete": true})
	if cfnCSMissing(err) {
		return nil
	}
	return err
}
func (h cfnASGGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := cfnASGGet(ctx, h.commands, cfnComputeName(r, "AutoScalingGroupName", 255))
	if cfnCSMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnASGGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	g, err := cfnASGGet(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(g, map[string]string{"DefaultCooldown": "Cooldown"})
	if err != nil {
		return nil, err
	}
	if subnets := cfnComputeValue(g.VPCZoneIdentifier); subnets != "" {
		list := []any{}
		for _, subnet := range strings.Split(subnets, ",") {
			list = append(list, subnet)
		}
		p["VPCZoneIdentifier"] = list
	}
	for _, key := range []string{"MinSize", "MaxSize", "DesiredCapacity", "Cooldown"} {
		if p[key] != nil {
			p[key] = fmt.Sprint(p[key])
		}
	}
	tags := []any{}
	for _, tag := range g.Tags {
		key := cfnComputeValue(tag.Key)
		if strings.HasPrefix(strings.ToLower(key), cfnComputeTagPrefix) || strings.HasPrefix(strings.ToLower(key), "aws:") {
			continue
		}
		tags = append(tags, map[string]any{"Key": key, "Value": cfnComputeValue(tag.Value), "PropagateAtLaunch": tag.PropagateAtLaunch != nil && bool(*tag.PropagateAtLaunch)})
	}
	p["Tags"] = tags
	metrics := map[string][]any{}
	for _, metric := range g.EnabledMetrics {
		granularity := cfnComputeValue(metric.Granularity)
		metrics[granularity] = append(metrics[granularity], cfnComputeValue(metric.Metric))
	}
	collection := []any{}
	for granularity, names := range metrics {
		collection = append(collection, map[string]any{"Granularity": granularity, "Metrics": names})
	}
	if len(collection) > 0 {
		p["MetricsCollection"] = collection
	}
	return cfnCSKeep(p, "AutoScalingGroupName", "AutoScalingGroupARN", "MinSize", "MaxSize", "DesiredCapacity", "LaunchTemplate", "VPCZoneIdentifier", "AvailabilityZones", "Cooldown", "DefaultInstanceWarmup", "HealthCheckType", "HealthCheckGracePeriod", "TerminationPolicies", "NewInstancesProtectedFromScaleIn", "ServiceLinkedRoleARN", "TargetGroupARNs", "MaxInstanceLifetime", "CapacityRebalance", "DesiredCapacityType", "DeletionProtection", "Context", "PlacementGroup", "InstanceLifecyclePolicy", "AvailabilityZoneDistribution", "MetricsCollection", "Tags"), nil
}
func (h cfnASGGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeAutoScalingGroupsOutput](ctx, h.commands, "autoscaling", "DescribeAutoScalingGroups", input)
		if err != nil {
			return nil, err
		}
		for _, g := range out.AutoScalingGroups {
			name := cfnComputeValue(g.AutoScalingGroupName)
			rows = append(rows, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"AutoScalingGroupName": name}})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

// ---- AWS::AutoScaling::LifecycleHook ----

type cfnASGHook struct{ commands StepFunctionsCommands }

const cfnASGHookType = "AWS::AutoScaling::LifecycleHook"

func (h cfnASGHook) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnASGHookType, p)
}
func (h cfnASGHook) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnASGHookType, a, b)
}
func (h cfnASGHook) locate(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID != "" {
		parts, err := cfnCSCompound(r.PhysicalID, 2)
		if err != nil {
			return "", "", err
		}
		return parts[0], parts[1], nil
	}
	return cfnComputeString(r.Properties, "AutoScalingGroupName"), cfnComputeName(r, "LifecycleHookName", 255), nil
}
func (h cfnASGHook) get(ctx context.Context, group, name string) (*api.LifecycleHook, error) {
	out, err := cfnComputeCall[api.DescribeLifecycleHooksOutput](ctx, h.commands, "autoscaling", "DescribeLifecycleHooks", map[string]any{"AutoScalingGroupName": group, "LifecycleHookNames": []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out.LifecycleHooks) != 1 {
		return nil, cfnCSNotFound("lifecycle hook " + name)
	}
	return &out.LifecycleHooks[0], nil
}
func (h cfnASGHook) put(ctx context.Context, r cloudformation.ResourceRequest, group, name string) error {
	input := cfnCSRename(r.Properties, nil, "LifecycleHookName")
	input["LifecycleHookName"] = name
	return cfnCSRun(ctx, h.commands, "autoscaling", "PutLifecycleHook", input)
}
func (h cfnASGHook) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name, _ := h.locate(r)
	result := cloudformation.ResourceResult{}
	if _, err := h.get(ctx, group, name); err == nil {
		if err := cfnNativeComputeOwned(ctx, r, group+"|"+name); err != nil {
			return result, cfnResourceCreateOwnedError(r, err)
		}
		result = cloudformation.ResourceResult{PhysicalID: group + "|" + name, Ref: name}
	} else if !cfnCSMissing(err) {
		return result, err
	}
	if err := h.put(ctx, r, group, name); err != nil {
		if _, readErr := h.get(ctx, group, name); readErr == nil && cfnNativeComputeOwned(ctx, r, group+"|"+name) == nil {
			result = cloudformation.ResourceResult{PhysicalID: group + "|" + name, Ref: name}
		}
		return result, err
	}
	return cloudformation.ResourceResult{PhysicalID: group + "|" + name, Ref: name}, nil
}
func (h cfnASGHook) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cloudformation.ResourceResult{PhysicalID: group + "|" + name, Ref: name}
	if _, err := h.get(ctx, group, name); err != nil {
		return result, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, group+"|"+name); err != nil {
		return result, err
	}
	return result, h.put(ctx, r, group, name)
}
func (h cfnASGHook) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	group, name, err := h.locate(r)
	if err != nil {
		return err
	}
	if _, err := h.get(ctx, group, name); cfnCSMissing(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, group+"|"+name); err != nil {
		return err
	}
	if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "autoscaling", "DeleteLifecycleHook", map[string]any{"AutoScalingGroupName": group, "LifecycleHookName": name})); err != nil {
		return err
	}
	return nil
}
func (h cfnASGHook) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	group, name, err := h.locate(r)
	if err != nil {
		return nil, err
	}
	hook, err := h.get(ctx, group, name)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(hook, nil)
	if err != nil {
		return nil, err
	}
	return cfnCSKeep(p, "AutoScalingGroupName", "LifecycleHookName", "LifecycleTransition", "DefaultResult", "HeartbeatTimeout", "NotificationMetadata", "NotificationTargetARN", "RoleARN"), nil
}
func (h cfnASGHook) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	groups, err := cfnASGGroup(h).List(ctx, r)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, group := range groups {
		out, err := cfnComputeCall[api.DescribeLifecycleHooksOutput](ctx, h.commands, "autoscaling", "DescribeLifecycleHooks", map[string]any{"AutoScalingGroupName": group.Identifier})
		if cfnCSMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, hook := range out.LifecycleHooks {
			name := cfnComputeValue(hook.LifecycleHookName)
			rows = append(rows, cloudformation.ResourceDescription{Identifier: group.Identifier + "|" + name, Properties: cloudformation.Properties{"AutoScalingGroupName": group.Identifier, "LifecycleHookName": name}})
		}
	}
	return rows, nil
}

// ---- AWS::AutoScaling::ScalingPolicy ----

type cfnASGPolicy struct{ commands StepFunctionsCommands }

const cfnASGPolicyType = "AWS::AutoScaling::ScalingPolicy"

func (h cfnASGPolicy) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnASGPolicyType, p)
}
func (h cfnASGPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnASGPolicyType, a, b)
}

func (h cfnASGPolicy) getResource(ctx context.Context, r cloudformation.ResourceRequest) (*api.ScalingPolicy, error) {
	if r.PhysicalID != "" {
		if !strings.HasPrefix(r.PhysicalID, "arn:") {
			return nil, fmt.Errorf("invalid Auto Scaling policy ARN %q", r.PhysicalID)
		}
		// DescribePolicies owns scope and full immutable ARN matching. Never
		// reduce a consumer identifier to the reusable group/policy names.
		policy, err := h.get(ctx, "", r.PhysicalID)
		if err != nil {
			return nil, err
		}
		if cfnComputeValue(policy.PolicyARN) != r.PhysicalID {
			return nil, cfnCSNotFound("scaling policy " + r.PhysicalID)
		}
		return policy, nil
	}
	return h.get(ctx, cfnComputeString(r.Properties, "AutoScalingGroupName"), cfnComputeName(r, "PolicyName", 255))
}
func (h cfnASGPolicy) get(ctx context.Context, group, name string) (*api.ScalingPolicy, error) {
	input := map[string]any{"PolicyNames": []string{name}}
	if group != "" {
		input["AutoScalingGroupName"] = group
	}
	out, err := cfnComputeCall[api.DescribePoliciesOutput](ctx, h.commands, "autoscaling", "DescribePolicies", input)
	if err != nil {
		return nil, err
	}
	if len(out.ScalingPolicies) != 1 {
		return nil, cfnCSNotFound("scaling policy " + name)
	}
	return &out.ScalingPolicies[0], nil
}
func cfnASGPolicyResult(arn, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"Arn": arn, "PolicyName": name}}
}
func (h cfnASGPolicy) put(ctx context.Context, r cloudformation.ResourceRequest, group, name string) (string, error) {
	input := cfnCSRename(r.Properties, nil, "PolicyName")
	input["PolicyName"] = name
	input["AutoScalingGroupName"] = group
	out, err := cfnCSCall[api.PutScalingPolicyOutput](ctx, h.commands, "autoscaling", "PutScalingPolicy", input)
	if err != nil {
		return "", err
	}
	return cfnComputeValue(out.PolicyARN), nil
}
func (h cfnASGPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name := cfnComputeString(r.Properties, "AutoScalingGroupName"), cfnComputeName(r, "PolicyName", 255)
	result := cloudformation.ResourceResult{}
	if policy, err := h.get(ctx, group, name); err == nil {
		arn := cfnComputeValue(policy.PolicyARN)
		if err := cfnNativeComputeOwned(ctx, r, arn); err != nil {
			return result, cfnResourceCreateOwnedError(r, err)
		}
		result = cfnASGPolicyResult(arn, name)
		ctx = autoscaling.WithScalingPolicyARN(ctx, arn)
	} else if !cfnCSMissing(err) {
		return result, err
	}
	arn, err := h.put(ctx, r, group, name)
	if err != nil {
		if policy, readErr := h.get(ctx, group, name); readErr == nil && cfnNativeComputeOwned(ctx, r, cfnComputeValue(policy.PolicyARN)) == nil {
			result = cfnASGPolicyResult(cfnComputeValue(policy.PolicyARN), name)
		}
		return result, err
	}
	return cfnASGPolicyResult(arn, name), nil
}
func (h cfnASGPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	policy, err := h.getResource(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name := cfnComputeValue(policy.AutoScalingGroupName), cfnComputeValue(policy.PolicyName)
	expectedARN := cfnComputeValue(policy.PolicyARN)
	result := cfnASGPolicyResult(expectedARN, name)
	if err := cfnNativeComputeMutationOwned(ctx, r, expectedARN); err != nil {
		return result, err
	}
	ctx = autoscaling.WithScalingPolicyARN(ctx, expectedARN)
	arn, err := h.put(ctx, r, group, name)
	if err != nil {
		return result, err
	}
	return cfnASGPolicyResult(arn, name), nil
}
func (h cfnASGPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	policy, err := h.getResource(ctx, r)
	if cfnCSMissing(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, cfnComputeValue(policy.PolicyARN)); err != nil {
		return err
	}
	if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "autoscaling", "DeletePolicy", map[string]any{"PolicyName": cfnComputeValue(policy.PolicyARN)})); err != nil {
		return err
	}
	return nil
}
func (h cfnASGPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	policy, err := h.getResource(ctx, r)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(policy, map[string]string{"PolicyARN": "Arn"})
	if err != nil {
		return nil, err
	}
	return cfnCSKeep(p, "Arn", "AutoScalingGroupName", "PolicyName", "PolicyType", "AdjustmentType", "Cooldown", "EstimatedInstanceWarmup", "MetricAggregationType", "MinAdjustmentMagnitude", "ScalingAdjustment", "StepAdjustments", "TargetTrackingConfiguration", "PredictiveScalingConfiguration"), nil
}
func (h cfnASGPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribePoliciesOutput](ctx, h.commands, "autoscaling", "DescribePolicies", input)
		if err != nil {
			return nil, err
		}
		for _, policy := range out.ScalingPolicies {
			arn := cfnComputeValue(policy.PolicyARN)
			rows = append(rows, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"Arn": arn, "AutoScalingGroupName": cfnComputeValue(policy.AutoScalingGroupName)}})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

// ---- AWS::AutoScaling::ScheduledAction ----

type cfnASGSchedule struct{ commands StepFunctionsCommands }

const cfnASGScheduleType = "AWS::AutoScaling::ScheduledAction"

func (h cfnASGSchedule) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnASGScheduleType, p)
}
func (h cfnASGSchedule) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnASGScheduleType, a, b)
}

// Identifier order follows the registry: ScheduledActionName|AutoScalingGroupName.
func (h cfnASGSchedule) locate(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID != "" {
		parts, err := cfnCSCompound(r.PhysicalID, 2)
		if err != nil {
			return "", "", err
		}
		return parts[1], parts[0], nil
	}
	return cfnComputeString(r.Properties, "AutoScalingGroupName"), cfnComputeName(r, "ScheduledActionName", 255), nil
}
func (h cfnASGSchedule) get(ctx context.Context, group, name string) (*api.ScheduledUpdateGroupAction, error) {
	out, err := cfnComputeCall[api.DescribeScheduledActionsOutput](ctx, h.commands, "autoscaling", "DescribeScheduledActions", map[string]any{"AutoScalingGroupName": group, "ScheduledActionNames": []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out.ScheduledUpdateGroupActions) != 1 {
		return nil, cfnCSNotFound("scheduled action " + name)
	}
	return &out.ScheduledUpdateGroupActions[0], nil
}
func cfnASGScheduleResult(group, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name + "|" + group, Ref: name, Attributes: map[string]any{"ScheduledActionName": name}}
}
func (h cfnASGSchedule) put(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	input := cfnCSRename(r.Properties, nil, "ScheduledActionName")
	input["ScheduledActionName"] = name
	return cfnCSRun(ctx, h.commands, "autoscaling", "PutScheduledUpdateGroupAction", input)
}
func (h cfnASGSchedule) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name, _ := h.locate(r)
	result := cloudformation.ResourceResult{}
	if _, err := h.get(ctx, group, name); err == nil {
		if err := cfnNativeComputeOwned(ctx, r, group+"|"+name); err != nil {
			return result, cfnResourceCreateOwnedError(r, err)
		}
		result = cfnASGScheduleResult(group, name)
	} else if !cfnCSMissing(err) {
		return result, err
	}
	if err := h.put(ctx, r, name); err != nil {
		if _, readErr := h.get(ctx, group, name); readErr == nil && cfnNativeComputeOwned(ctx, r, group+"|"+name) == nil {
			result = cfnASGScheduleResult(group, name)
		}
		return result, err
	}
	return cfnASGScheduleResult(group, name), nil
}
func (h cfnASGSchedule) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnASGScheduleResult(group, name)
	if _, err := h.get(ctx, group, name); err != nil {
		return result, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, group+"|"+name); err != nil {
		return result, err
	}
	return result, h.put(ctx, r, name)
}
func (h cfnASGSchedule) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	group, name, err := h.locate(r)
	if err != nil {
		return err
	}
	if _, err := h.get(ctx, group, name); cfnCSMissing(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, group+"|"+name); err != nil {
		return err
	}
	if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "autoscaling", "DeleteScheduledAction", map[string]any{"AutoScalingGroupName": group, "ScheduledActionName": name})); err != nil {
		return err
	}
	return nil
}
func (h cfnASGSchedule) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	group, name, err := h.locate(r)
	if err != nil {
		return nil, err
	}
	action, err := h.get(ctx, group, name)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(action, nil)
	if err != nil {
		return nil, err
	}
	return cfnCSKeep(p, "ScheduledActionName", "AutoScalingGroupName", "StartTime", "EndTime", "Recurrence", "TimeZone", "MinSize", "MaxSize", "DesiredCapacity"), nil
}
func (h cfnASGSchedule) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeScheduledActionsOutput](ctx, h.commands, "autoscaling", "DescribeScheduledActions", input)
		if err != nil {
			return nil, err
		}
		for _, action := range out.ScheduledUpdateGroupActions {
			name, group := cfnComputeValue(action.ScheduledActionName), cfnComputeValue(action.AutoScalingGroupName)
			rows = append(rows, cloudformation.ResourceDescription{Identifier: name + "|" + group, Properties: cloudformation.Properties{"ScheduledActionName": name, "AutoScalingGroupName": group}})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
