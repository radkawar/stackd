package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	asgapi "stackd/internal/awsapi/autoscaling"
	"stackd/internal/services/applicationautoscaling"
	"stackd/internal/services/autoscaling"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ecs"
	"stackd/internal/services/elbv2"
)

type cfnNativeComputeRowsKey struct{}

func cfnNativeComputeClaim(r cloudformation.ResourceRequest) string {
	data, _ := json.Marshal([]string{r.StackID, r.LogicalID, r.Token})
	return r.Type + "/" + string(data)
}
func cfnNativeComputeContext(ctx context.Context, r cloudformation.ResourceRequest, creating bool) context.Context {
	if r.CloudControl && !creating {
		return ctx
	}
	rows := map[string]string{}
	ctx = context.WithValue(ctx, cfnNativeComputeRowsKey{}, rows)
	service, kind, _ := strings.Cut(strings.TrimPrefix(r.Type, "AWS::"), "::")
	if service == "ElasticLoadBalancingV2" && kind == "ListenerRule" {
		kind = "Rule"
	}
	claim := cfnNativeComputeClaim(r)
	target := r.PhysicalID
	if service == "ECS" && kind == "Cluster" && target != "" && !strings.HasPrefix(target, "arn:") {
		target = "arn:" + r.Scope.Partition + ":ecs:" + r.Scope.Region + ":" + r.Scope.Account + ":cluster/" + target
	}
	if service == "ECS" && kind == "Service" {
		target, _, _ = strings.Cut(target, "|")
	}
	if service == "AutoScaling" && kind == "ScheduledAction" {
		if name, group, ok := strings.Cut(target, "|"); ok {
			target = group + "|" + name
		}
	}
	switch service {
	case "ApplicationAutoScaling":
		return applicationautoscaling.WithCloudFormationOwnership(ctx, kind, claim, r.PhysicalID, !creating, rows)
	case "AutoScaling":
		return autoscaling.WithCloudFormationOwnership(ctx, kind, claim, target, !creating, rows)
	case "ElasticLoadBalancingV2":
		return elbv2.WithCloudFormationOwnership(ctx, kind, claim, r.PhysicalID, !creating, rows)
	case "ECS":
		return ecs.WithCloudFormationOwnership(ctx, kind, claim, target, !creating, rows)
	}
	return ctx
}
func cfnNativeComputeOwned(ctx context.Context, r cloudformation.ResourceRequest, id string) error {
	rows, _ := ctx.Value(cfnNativeComputeRowsKey{}).(map[string]string)
	if r.StackID == "" || r.LogicalID == "" || r.Token == "" || rows[id] != cfnNativeComputeClaim(r) {
		return fmt.Errorf("resource %s is not owned by this stack resource incarnation", r.LogicalID)
	}
	return nil
}
func cfnNativeComputeMutationOwned(ctx context.Context, r cloudformation.ResourceRequest, id string) error {
	if r.CloudControl {
		return nil
	}
	return cfnNativeComputeOwned(ctx, r, id)
}

// Fence the complete inline-hook transition before any group settings change.
func cfnNativeComputeInlineHooks(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) error {
	if !cfnComputeChanged(r.Previous, r.Properties, "LifecycleHookSpecificationList") {
		return nil
	}
	names := map[string]bool{}
	for _, p := range []cloudformation.Properties{r.Previous, r.Properties} {
		list, _ := p["LifecycleHookSpecificationList"].([]any)
		for _, raw := range list {
			spec, _ := cfnComputeObject(raw)
			names[cfnComputeString(spec, "LifecycleHookName")] = true
		}
	}
	if len(names) == 0 {
		return nil
	}
	rows := map[string]string{}
	observe := autoscaling.WithCloudFormationOwnership(ctx, "LifecycleHook", "", "", false, rows)
	hooks, err := cfnComputeCall[asgapi.DescribeLifecycleHooksOutput](observe, c, "autoscaling", "DescribeLifecycleHooks", map[string]any{"AutoScalingGroupName": r.PhysicalID})
	if err != nil {
		return err
	}
	for _, hook := range hooks.LifecycleHooks {
		name := cfnComputeValue(hook.LifecycleHookName)
		if !names[name] {
			continue
		}
		claim := rows[r.PhysicalID+"|"+name]
		if (!r.CloudControl && claim != cfnNativeComputeClaim(r)) || (r.CloudControl && strings.HasPrefix(claim, cfnASGHookType+"/")) {
			return fmt.Errorf("lifecycle hook %s is not owned inline by this group incarnation", name)
		}
	}
	return nil
}
func cfnNativeComputeInlineHookContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	claim := cfnNativeComputeClaim(r)
	if r.CloudControl {
		claim = ""
	}
	return autoscaling.WithInlineLifecycleHookOwnership(ctx, claim, r.CloudControl)
}
