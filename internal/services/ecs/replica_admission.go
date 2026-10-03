package ecs

import (
	"context"
	"errors"
	"strconv"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
)

func serviceDefinition(ctx context.Context, r Reader, id string) (TaskDefinitionRecord, error) {
	key, rejected := definitionKey(ctx, id, false)
	if rejected != nil {
		return TaskDefinitionRecord{}, rejected
	}
	definition, err := loadDefinition(r, key)
	if errors.Is(err, ErrNotFound) {
		return definition, failure("ClientException", "TaskDefinition not found.")
	}
	if err != nil {
		return definition, err
	}
	if value(definition.Data.Status) != "ACTIVE" {
		return definition, failure("ClientException", "TaskDefinition is inactive")
	}
	return definition, nil
}

func serviceConditions(data api.Service) map[string][]string {
	conditions := map[string][]string{
		"ecs:cluster":                 {value(data.ClusterArn)},
		"ecs:task-definition":         {value(data.TaskDefinition)},
		"ecs:enable-execute-command":  {strconv.FormatBool(data.EnableExecuteCommand != nil && bool(*data.EnableExecuteCommand))},
		"ecs:enable-ecs-managed-tags": {strconv.FormatBool(data.EnableECSManagedTags != nil && bool(*data.EnableECSManagedTags))},
		"ecs:propagate-tags":          {value(data.PropagateTags)},
	}
	for _, provider := range data.CapacityProviderStrategy {
		conditions["ecs:capacity-provider"] = append(conditions["ecs:capacity-provider"], value(provider.CapacityProvider))
	}
	if data.NetworkConfiguration != nil && data.NetworkConfiguration.AwsvpcConfiguration != nil {
		network := data.NetworkConfiguration.AwsvpcConfiguration
		for _, subnet := range network.Subnets {
			conditions["ecs:subnet"] = append(conditions["ecs:subnet"], string(subnet))
		}
		conditions["ecs:auto-assign-public-ip"] = []string{strconv.FormatBool(value(network.AssignPublicIp) == "ENABLED")}
	}
	return conditions
}

func serviceTaskInput(record ServiceRecord) api.RunTaskInput {
	data := record.Data
	return api.CloneRunTaskRequest(api.RunTaskInput{
		Cluster: data.ClusterArn, TaskDefinition: data.TaskDefinition,
		LaunchType: data.LaunchType, CapacityProviderStrategy: data.CapacityProviderStrategy,
		NetworkConfiguration: data.NetworkConfiguration, PlatformVersion: data.PlatformVersion,
		Group:                new(api.String("service:" + record.Key.ServiceName)),
		EnableExecuteCommand: data.EnableExecuteCommand, EnableECSManagedTags: data.EnableECSManagedTags,
		PropagateTags: data.PropagateTags,
	})
}

func (s *Service) validateServiceExecution(ctx context.Context, cluster ClusterRecord, record ServiceRecord, definition TaskDefinitionRecord) error {
	input := serviceTaskInput(record)
	plan, err := s.prepareTask(ctx, &input, cluster, definition)
	if err != nil {
		return err
	}
	return s.validateTaskRoles(ctx, plan, record.Key.ARN())
}

func (s *Service) ensureReplicaRole(ctx context.Context) error {
	if s.roles == nil {
		return unsupported("Service creation requires an IAM service-role provider.")
	}
	ctx = awsctx.WithViaService(ctx, ServicePrincipal)
	metadata := awsctx.FromContext(ctx)
	metadata.InvokedBy = "aws-called-via-override.ecs.amazonaws.com"
	ctx = awsctx.WithMetadata(ctx, metadata)
	return s.roles.EnsureServiceLinkedRole(ctx, ServicePrincipal)
}

// Merge the mutable deployment policy without changing a deployment's admitted
// task definition or network snapshot. Circuit threshold/reset omission preserves
// the previous values (native services.json calls 128-135).
// TODO: Comeback implement deployment alarms/hooks, bake periods and non-rolling strategies.
func mergeServiceDeploymentConfiguration(old, update *api.DeploymentConfiguration) (*api.DeploymentConfiguration, error) {
	config := api.DeploymentConfiguration{
		MaximumPercent: new(api.BoxedInteger(200)), MinimumHealthyPercent: new(api.BoxedInteger(100)),
		Strategy: new(api.DeploymentStrategy("ROLLING")), BakeTimeInMinutes: new(api.BoxedInteger(0)),
		DeploymentCircuitBreaker: &api.DeploymentCircuitBreaker{Enable: new(api.Boolean(false)), Rollback: new(api.Boolean(false)), ResetOnHealthyTask: new(api.BoxedBoolean(true)), ThresholdConfiguration: &api.ThresholdConfiguration{Type: new(api.ThresholdType("BOUNDED_PERCENT")), Value: new(api.Integer(50))}},
	}
	if old != nil {
		config = *old
		if old.DeploymentCircuitBreaker != nil {
			breaker := *old.DeploymentCircuitBreaker
			config.DeploymentCircuitBreaker = &breaker
		}
	}
	if update != nil {
		if update.Alarms != nil || update.EarlySuccessCriteria != nil || len(update.LifecycleHooks) > 0 || update.CanaryConfiguration != nil || update.LinearConfiguration != nil || update.BakeTimeInMinutes != nil && *update.BakeTimeInMinutes != 0 {
			return nil, unsupported("Deployment alarms, lifecycle hooks, bake periods and traffic-shifting strategies require their execution dependencies.")
		}
		if update.MaximumPercent != nil {
			config.MaximumPercent = update.MaximumPercent
		}
		if update.MinimumHealthyPercent != nil {
			config.MinimumHealthyPercent = update.MinimumHealthyPercent
		}
		if update.Strategy != nil {
			config.Strategy = update.Strategy
		}
		if update.DeploymentCircuitBreaker != nil {
			in, breaker := update.DeploymentCircuitBreaker, config.DeploymentCircuitBreaker
			if in.Enable != nil {
				breaker.Enable = in.Enable
			}
			if in.Rollback != nil {
				breaker.Rollback = in.Rollback
			}
			if in.ResetOnHealthyTask != nil {
				breaker.ResetOnHealthyTask = in.ResetOnHealthyTask
			}
			if in.ThresholdConfiguration != nil {
				breaker.ThresholdConfiguration = in.ThresholdConfiguration
			}
		}
	}
	if *config.MaximumPercent < 100 {
		return nil, failure("InvalidParameterException", "maximumPercent must be at least 100")
	}
	if *config.MaximumPercent > 200 {
		return nil, failure("InvalidParameterException", "maximumPercent must be at most 200")
	}
	if *config.MinimumHealthyPercent < 0 {
		return nil, failure("InvalidParameterException", "minimumHealthyPercent must be at least 0")
	}
	if *config.MinimumHealthyPercent > 100 {
		return nil, failure("InvalidParameterException", "minimumHealthyPercent must be at most 100")
	}
	if value(config.Strategy) != "ROLLING" {
		return nil, unsupported("Only ECS rolling deployments have a configured deployment controller.")
	}
	breaker := config.DeploymentCircuitBreaker
	threshold := breaker.ThresholdConfiguration
	switch value(threshold.Type) {
	case "COUNT", "BOUNDED_PERCENT", "UNBOUNDED_PERCENT":
	default:
		return nil, failure("InvalidParameterException", "Invalid deployment circuit breaker threshold type.")
	}
	if threshold.Value == nil || *threshold.Value < 1 || value(threshold.Type) != "COUNT" && *threshold.Value > 100 {
		return nil, failure("InvalidParameterException", "Invalid deployment circuit breaker threshold value.")
	}
	if !bool(*breaker.Enable) {
		breaker.Rollback = new(api.Boolean(false))
	}
	return &config, nil
}

// TODO: Comeback connect external/CodeDeploy controllers and ExecuteCommand dependencies.
func validateServiceConfiguration(data api.Service) error {
	if value(data.DeploymentController.Type) != "ECS" {
		return unsupported("Only the ECS deployment controller has a configured service lifecycle.")
	}
	if data.HealthCheckGracePeriodSeconds != nil && *data.HealthCheckGracePeriodSeconds < 0 {
		return failure("InvalidParameterException", "healthCheckGracePeriodSeconds must be at least 0")
	}
	switch value(data.PropagateTags) {
	case "NONE", "SERVICE", "TASK_DEFINITION":
	default:
		return failure("InvalidParameterException", "propagateTags should be one of [TASK_DEFINITION,SERVICE,NONE]")
	}
	switch value(data.AvailabilityZoneRebalancing) {
	case "ENABLED", "DISABLED":
	default:
		return failure("InvalidParameterException", "availabilityZoneRebalancing should be one of [ENABLED,DISABLED]")
	}
	if value(data.AvailabilityZoneRebalancing) == "ENABLED" && *data.DeploymentConfiguration.MaximumPercent <= 100 {
		return failure("InvalidParameterException", "Availability Zone Rebalancing does not support maximumPercent <= 100 % as deployment configuration.")
	}
	if data.EnableExecuteCommand != nil && bool(*data.EnableExecuteCommand) {
		return unsupported("ExecuteCommand requires its execution dependencies.")
	}
	return nil
}

// TODO: Comeback implement the remaining capacity-provider execution backends.
func validateServiceCapacity(strategy api.CapacityProviderStrategy) error {
	if len(strategy) == 0 {
		return nil
	}
	if len(strategy) != 1 {
		return failure("InvalidParameterException", "A capacity provider may only be specified once in a strategy.")
	}
	provider := strategy[0]
	if value(provider.CapacityProvider) != "FARGATE" {
		return unsupported("Only the FARGATE capacity provider has a configured service runtime.")
	}
	if provider.Base != nil && (*provider.Base < 0 || *provider.Base > 100000) || provider.Weight != nil && (*provider.Weight < 0 || *provider.Weight > 1000) {
		return failure("InvalidParameterException", "Invalid capacity provider base or weight.")
	}
	if provider.Weight == nil || *provider.Weight == 0 {
		return failure("InvalidParameterException", "At least one capacity provider must have a weight value greater than zero.")
	}
	return nil
}
