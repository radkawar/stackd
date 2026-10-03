package eventbridge

import (
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

var ecsClusterResource = regexp.MustCompile(`^cluster/[A-Za-z0-9_-]{1,255}$`)
var ecsDefinitionResource = regexp.MustCompile(`^task-definition/[A-Za-z0-9_-]{1,255}(:[0-9]+)?$`)
var ecsInvocationRoleResource = regexp.MustCompile(`^role/[A-Za-z0-9_+=,.@/-]+$`)

func validateECSTarget(rule RuleKey, target api.Target) *awswire.Error {
	invalid := func(message string) *awswire.Error { return failure("ValidationException", message) }
	cluster, err := arn.Parse(value(target.Arn))
	if err != nil || !ecsClusterResource.MatchString(cluster.Resource) {
		return invalid("ECS targets must identify a valid cluster ARN.")
	}
	role, err := arn.Parse(value(target.RoleArn))
	if err != nil || role.Partition != rule.Bus.Partition || role.Service != "iam" || role.Region != "" || len(role.AccountID) != 12 || strings.Trim(role.AccountID, "0123456789") != "" || !ecsInvocationRoleResource.MatchString(role.Resource) {
		return invalid("RoleArn is required and must identify a valid IAM role for an ECS target.")
	}
	if target.InputPath != nil {
		return invalid("InputPath is not a valid form of input for ECS targets. Only Input and InputTransformer are supported.")
	}
	p := target.EcsParameters
	if p == nil {
		return invalid("EcsParameters are required for an ECS target.")
	}
	definition, err := arn.Parse(value(p.TaskDefinitionArn))
	if err != nil || definition.Partition != rule.Bus.Partition || definition.Service != "ecs" || definition.Region != cluster.Region || definition.AccountID != cluster.AccountID || !ecsDefinitionResource.MatchString(definition.Resource) {
		return invalid("TaskDefinitionArn must identify a valid ECS task definition in the target cluster account and Region.")
	}
	if p.TaskCount != nil && *p.TaskCount > 10 {
		return invalid("TaskCount must not exceed 10.")
	}
	launch := value(p.LaunchType)
	if p.LaunchType != nil && launch != "EC2" && launch != "FARGATE" && launch != "EXTERNAL" {
		return invalid("LaunchType must be EC2, FARGATE or EXTERNAL.")
	}
	if p.PropagateTags != nil && value(p.PropagateTags) != "TASK_DEFINITION" {
		return invalid("PropagateTags must be TASK_DEFINITION.")
	}
	if launch == "FARGATE" && (p.NetworkConfiguration == nil || p.NetworkConfiguration.AwsvpcConfiguration == nil) {
		return invalid("NetworkConfiguration is required for FARGATE targets.")
	}
	if p.NetworkConfiguration != nil {
		network := p.NetworkConfiguration.AwsvpcConfiguration
		if network == nil || len(network.Subnets) == 0 || len(network.Subnets) > 16 || len(network.SecurityGroups) > 5 {
			return invalid("NetworkConfiguration requires 1 to 16 subnets and at most 5 security groups.")
		}
		if network.AssignPublicIp != nil && value(network.AssignPublicIp) != "ENABLED" && value(network.AssignPublicIp) != "DISABLED" {
			return invalid("AssignPublicIp must be ENABLED or DISABLED.")
		}
		if launch == "EC2" && value(network.AssignPublicIp) == "ENABLED" {
			return invalid("AssignPublicIp ENABLED is not supported with EC2 launch type.")
		}
	}
	for _, placement := range p.PlacementConstraints {
		if placement.Type != nil && value(placement.Type) != "distinctInstance" && value(placement.Type) != "memberOf" {
			return invalid("Invalid placement constraint type.")
		}
	}
	for _, placement := range p.PlacementStrategy {
		if placement.Type != nil && value(placement.Type) != "random" && value(placement.Type) != "spread" && value(placement.Type) != "binpack" {
			return invalid("Invalid placement strategy type.")
		}
	}
	for _, strategy := range p.CapacityProviderStrategy {
		if value(strategy.CapacityProvider) == "" || strategy.Base != nil && (*strategy.Base < 0 || *strategy.Base > 100000) || strategy.Weight != nil && (*strategy.Weight < 0 || *strategy.Weight > 1000) {
			return invalid("Invalid capacity provider strategy.")
		}
	}
	return nil
}

func cloneECSParameters(p *api.EcsParameters) *api.EcsParameters {
	if p == nil {
		return nil
	}
	cloned := api.CloneEcsParameters(*p)
	return &cloned
}

func cloneDelivery(v DeliveryRecord) DeliveryRecord {
	v.EcsParameters = cloneECSParameters(v.EcsParameters)
	v.KinesisParameters = cloneKinesisParameters(v.KinesisParameters)
	v.HttpParameters = cloneHTTPParameters(v.HttpParameters)
	v.RulePattern = slices.Clone(v.RulePattern)
	v.TargetConfiguration = slices.Clone(v.TargetConfiguration)
	return v
}
