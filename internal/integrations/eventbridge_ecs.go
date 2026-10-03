package integrations

import (
	"context"
	"encoding/json"
	"strings"

	ecsapi "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
)

// ECSTaskRunner accepts tasks through the same authorization, transaction and
// audit boundary as the ECS frontend, under the currently assumed target role.
type ECSTaskRunner interface {
	RunTask(context.Context, *ecsapi.RunTaskInput) (*ecsapi.RunTaskOutput, *awswire.Error)
}

func (a EventBridgeTargets) sendECS(ctx context.Context, request eventbridge.DeliveryRequest, body string) *awswire.Error {
	p := request.Delivery.EcsParameters
	if a.ECS == nil || p == nil {
		return &awswire.Error{Code: "InternalFailure", Message: "ECS target delivery is not configured.", StatusCode: 500}
	}
	var overrides ecsapi.TaskOverride
	if err := json.Unmarshal([]byte(body), &overrides); err != nil {
		return &awswire.Error{Code: "INVALID_PARAMETER", Message: "Invalid ECS task overrides: " + err.Error(), StatusCode: 400}
	}
	d := request.Delivery
	cluster, token := ecsapi.String(d.TargetARN), ecsapi.String(d.ID)
	startedBy := ecsapi.String("events-rule/" + d.RuleARN[strings.LastIndex(d.RuleARN, "/")+1:])
	in := &ecsapi.RunTaskInput{
		Cluster: &cluster, ClientToken: &token, StartedBy: &startedBy, Count: (*ecsapi.BoxedInteger)(p.TaskCount),
		TaskDefinition: (*ecsapi.String)(p.TaskDefinitionArn), Overrides: &overrides,
		EnableECSManagedTags: (*ecsapi.Boolean)(p.EnableECSManagedTags), EnableExecuteCommand: (*ecsapi.Boolean)(p.EnableExecuteCommand),
		Group: (*ecsapi.String)(p.Group), LaunchType: (*ecsapi.LaunchType)(p.LaunchType),
		PlatformVersion: (*ecsapi.String)(p.PlatformVersion), PropagateTags: (*ecsapi.PropagateTags)(p.PropagateTags),
		ReferenceId: (*ecsapi.String)(p.ReferenceId),
	}
	if p.NetworkConfiguration != nil {
		in.NetworkConfiguration = &ecsapi.NetworkConfiguration{}
		if v := p.NetworkConfiguration.AwsvpcConfiguration; v != nil {
			in.NetworkConfiguration.AwsvpcConfiguration = &ecsapi.AwsVpcConfiguration{
				AssignPublicIp: (*ecsapi.AssignPublicIp)(v.AssignPublicIp),
				Subnets:        ecsStrings(v.Subnets), SecurityGroups: ecsStrings(v.SecurityGroups),
			}
		}
	}
	if p.CapacityProviderStrategy != nil {
		in.CapacityProviderStrategy = make(ecsapi.CapacityProviderStrategy, len(p.CapacityProviderStrategy))
		for i, v := range p.CapacityProviderStrategy {
			in.CapacityProviderStrategy[i] = ecsapi.CapacityProviderStrategyItem{CapacityProvider: (*ecsapi.String)(v.CapacityProvider), Base: (*ecsapi.CapacityProviderStrategyItemBase)(v.Base), Weight: (*ecsapi.CapacityProviderStrategyItemWeight)(v.Weight)}
		}
	}
	if p.PlacementConstraints != nil {
		in.PlacementConstraints = make(ecsapi.PlacementConstraints, len(p.PlacementConstraints))
		for i, v := range p.PlacementConstraints {
			in.PlacementConstraints[i] = ecsapi.PlacementConstraint{Type: (*ecsapi.PlacementConstraintType)(v.Type), Expression: (*ecsapi.String)(v.Expression)}
		}
	}
	if p.PlacementStrategy != nil {
		in.PlacementStrategy = make(ecsapi.PlacementStrategies, len(p.PlacementStrategy))
		for i, v := range p.PlacementStrategy {
			in.PlacementStrategy[i] = ecsapi.PlacementStrategy{Type: (*ecsapi.PlacementStrategyType)(v.Type), Field: (*ecsapi.String)(v.Field)}
		}
	}
	if p.Tags != nil {
		in.Tags = make(ecsapi.Tags, len(p.Tags))
		for i, v := range p.Tags {
			in.Tags[i] = ecsapi.Tag{Key: (*ecsapi.TagKey)(v.Key), Value: (*ecsapi.TagValue)(v.Value)}
		}
	}
	out, rejected := a.ECS.RunTask(ctx, in)
	if rejected != nil {
		return rejected
	}
	if len(out.Failures) != 0 {
		message := "ECS did not accept the requested task."
		if out.Failures[0].Reason != nil {
			message = string(*out.Failures[0].Reason)
		}
		return &awswire.Error{Code: "ERROR_FROM_TARGET", Message: message, StatusCode: 400}
	}
	return nil
}

func ecsStrings[T ~string](values []T) ecsapi.StringList {
	if values == nil {
		return nil
	}
	out := make(ecsapi.StringList, len(values))
	for i, v := range values {
		out[i] = ecsapi.String(v)
	}
	return out
}
