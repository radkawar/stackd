package ecs

import (
	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

// Service and deployment resources are scalar columns plus typed nested configurations.
// Deployments and observed tasks are owned child rows, not serialized resource records.
func serviceRecord(row sqlcgen.EcsService) (domain.ServiceRecord, error) {
	out := domain.ServiceRecord{
		Key:             domain.ServiceKey{ClusterKey: domain.ClusterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ClusterName}, ServiceName: row.ServiceName},
		AcceptedEventID: row.AcceptedEventID, DrainAfter: row.DrainAfter,
		NextMetricCollection: row.NextMetricCollection,
	}
	out.Data.AvailabilityZoneRebalancing = stringPointer[api.AvailabilityZoneRebalancing](row.ServiceAvailabilityZoneRebalancing)
	out.Data.ClusterArn = stringPointer[api.String](row.ServiceClusterArn)
	out.Data.CreatedAt = timePointer(row.ServiceCreatedAt)
	out.Data.CreatedBy = stringPointer[api.String](row.ServiceCreatedBy)
	out.Data.CurrentServiceDeployment = stringPointer[api.String](row.ServiceCurrentServiceDeployment)
	out.Data.DesiredCount = integerPointer[api.Integer](row.ServiceDesiredCount)
	out.Data.EnableECSManagedTags = boolPointer[api.Boolean](row.ServiceEnableEcsManagedTags)
	out.Data.EnableExecuteCommand = boolPointer[api.Boolean](row.ServiceEnableExecuteCommand)
	out.Data.HealthCheckGracePeriodSeconds = integerPointer[api.BoxedInteger](row.ServiceHealthCheckGracePeriodSeconds)
	out.Data.LaunchType = stringPointer[api.LaunchType](row.ServiceLaunchType)
	out.Data.PendingCount = integerPointer[api.Integer](row.ServicePendingCount)
	out.Data.PlatformFamily = stringPointer[api.String](row.ServicePlatformFamily)
	out.Data.PlatformVersion = stringPointer[api.String](row.ServicePlatformVersion)
	out.Data.PropagateTags = stringPointer[api.PropagateTags](row.ServicePropagateTags)
	out.Data.ResourceManagementType = stringPointer[api.ResourceManagementType](row.ServiceResourceManagementType)
	out.Data.RoleArn = stringPointer[api.String](row.ServiceRoleArn)
	out.Data.RunningCount = integerPointer[api.Integer](row.ServiceRunningCount)
	out.Data.SchedulingStrategy = stringPointer[api.SchedulingStrategy](row.ServiceSchedulingStrategy)
	out.Data.ServiceArn = stringPointer[api.String](row.ServiceServiceArn)
	out.Data.ServiceName = stringPointer[api.String](row.ServiceServiceName)
	out.Data.Status = stringPointer[api.String](row.ServiceStatus)
	out.Data.TaskDefinition = stringPointer[api.String](row.ServiceTaskDefinition)
	out.CreateInput.AvailabilityZoneRebalancing = stringPointer[api.AvailabilityZoneRebalancing](row.CreateAvailabilityZoneRebalancing)
	out.CreateInput.ClientToken = stringPointer[api.String](row.CreateClientToken)
	out.CreateInput.Cluster = stringPointer[api.String](row.CreateCluster)
	out.CreateInput.DesiredCount = integerPointer[api.BoxedInteger](row.CreateDesiredCount)
	out.CreateInput.EnableECSManagedTags = boolPointer[api.Boolean](row.CreateEnableEcsManagedTags)
	out.CreateInput.EnableExecuteCommand = boolPointer[api.Boolean](row.CreateEnableExecuteCommand)
	out.CreateInput.HealthCheckGracePeriodSeconds = integerPointer[api.BoxedInteger](row.CreateHealthCheckGracePeriodSeconds)
	out.CreateInput.LaunchType = stringPointer[api.LaunchType](row.CreateLaunchType)
	out.CreateInput.PlatformVersion = stringPointer[api.String](row.CreatePlatformVersion)
	out.CreateInput.PropagateTags = stringPointer[api.PropagateTags](row.CreatePropagateTags)
	out.CreateInput.Role = stringPointer[api.String](row.CreateRole)
	out.CreateInput.SchedulingStrategy = stringPointer[api.SchedulingStrategy](row.CreateSchedulingStrategy)
	out.CreateInput.ServiceName = stringPointer[api.String](row.CreateServiceName)
	out.CreateInput.TaskDefinition = stringPointer[api.String](row.CreateTaskDefinition)
	err := unmarshalFields(
		jsonReadField{row.ServiceCapacityProviderStrategy, &out.Data.CapacityProviderStrategy},
		jsonReadField{row.ServiceCurrentServiceRevisions, &out.Data.CurrentServiceRevisions},
		jsonReadField{row.ServiceDeploymentConfiguration, &out.Data.DeploymentConfiguration},
		jsonReadField{row.ServiceDeploymentController, &out.Data.DeploymentController},
		jsonReadField{row.ServiceEvents, &out.Data.Events},
		jsonReadField{row.ServiceLoadBalancers, &out.Data.LoadBalancers},
		jsonReadField{row.ServiceNetworkConfiguration, &out.Data.NetworkConfiguration},
		jsonReadField{row.ServicePlacementConstraints, &out.Data.PlacementConstraints},
		jsonReadField{row.ServicePlacementStrategy, &out.Data.PlacementStrategy},
		jsonReadField{row.ServiceServiceRegistries, &out.Data.ServiceRegistries},
		jsonReadField{row.ServiceTaskSets, &out.Data.TaskSets},
		jsonReadField{row.CreateCapacityProviderStrategy, &out.CreateInput.CapacityProviderStrategy},
		jsonReadField{row.CreateDeploymentConfiguration, &out.CreateInput.DeploymentConfiguration},
		jsonReadField{row.CreateDeploymentController, &out.CreateInput.DeploymentController},
		jsonReadField{row.CreateLoadBalancers, &out.CreateInput.LoadBalancers},
		jsonReadField{row.CreateMonitoring, &out.CreateInput.Monitoring},
		jsonReadField{row.CreateNetworkConfiguration, &out.CreateInput.NetworkConfiguration},
		jsonReadField{row.CreatePlacementConstraints, &out.CreateInput.PlacementConstraints},
		jsonReadField{row.CreatePlacementStrategy, &out.CreateInput.PlacementStrategy},
		jsonReadField{row.CreateServiceConnectConfiguration, &out.CreateInput.ServiceConnectConfiguration},
		jsonReadField{row.CreateServiceRegistries, &out.CreateInput.ServiceRegistries},
		jsonReadField{row.CreateTags, &out.CreateInput.Tags},
		jsonReadField{row.CreateVolumeConfigurations, &out.CreateInput.VolumeConfigurations},
		jsonReadField{row.CreateVpcLatticeConfigurations, &out.CreateInput.VpcLatticeConfigurations},
	)
	return out, err
}

func serviceParams(v domain.ServiceRecord) (sqlcgen.PutServiceParams, error) {
	k := v.Key
	params := sqlcgen.PutServiceParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
		AcceptedEventID: v.AcceptedEventID, DrainAfter: v.DrainAfter, DeploymentsPresent: v.Deployments != nil,
		NextMetricCollection:                 v.NextMetricCollection,
		ServiceAvailabilityZoneRebalancing:   nullableString(v.Data.AvailabilityZoneRebalancing),
		ServiceClusterArn:                    nullableString(v.Data.ClusterArn),
		ServiceCreatedAt:                     nullableTime(v.Data.CreatedAt),
		ServiceCreatedBy:                     nullableString(v.Data.CreatedBy),
		ServiceCurrentServiceDeployment:      nullableString(v.Data.CurrentServiceDeployment),
		ServiceDesiredCount:                  nullableInteger(v.Data.DesiredCount),
		ServiceEnableEcsManagedTags:          nullableBool(v.Data.EnableECSManagedTags),
		ServiceEnableExecuteCommand:          nullableBool(v.Data.EnableExecuteCommand),
		ServiceHealthCheckGracePeriodSeconds: nullableInteger(v.Data.HealthCheckGracePeriodSeconds),
		ServiceLaunchType:                    nullableString(v.Data.LaunchType),
		ServiceEffectiveLaunchType:           v.EffectiveLaunchType(),
		ServicePendingCount:                  nullableInteger(v.Data.PendingCount),
		ServicePlatformFamily:                nullableString(v.Data.PlatformFamily),
		ServicePlatformVersion:               nullableString(v.Data.PlatformVersion),
		ServicePropagateTags:                 nullableString(v.Data.PropagateTags),
		ServiceResourceManagementType:        nullableString(v.Data.ResourceManagementType),
		ServiceRoleArn:                       nullableString(v.Data.RoleArn),
		ServiceRunningCount:                  nullableInteger(v.Data.RunningCount),
		ServiceSchedulingStrategy:            nullableString(v.Data.SchedulingStrategy),
		ServiceServiceArn:                    nullableString(v.Data.ServiceArn),
		ServiceServiceName:                   nullableString(v.Data.ServiceName),
		ServiceStatus:                        nullableString(v.Data.Status),
		ServiceTaskDefinition:                nullableString(v.Data.TaskDefinition),
		CreateAvailabilityZoneRebalancing:    nullableString(v.CreateInput.AvailabilityZoneRebalancing),
		CreateClientToken:                    nullableString(v.CreateInput.ClientToken),
		CreateCluster:                        nullableString(v.CreateInput.Cluster),
		CreateDesiredCount:                   nullableInteger(v.CreateInput.DesiredCount),
		CreateEnableEcsManagedTags:           nullableBool(v.CreateInput.EnableECSManagedTags),
		CreateEnableExecuteCommand:           nullableBool(v.CreateInput.EnableExecuteCommand),
		CreateHealthCheckGracePeriodSeconds:  nullableInteger(v.CreateInput.HealthCheckGracePeriodSeconds),
		CreateLaunchType:                     nullableString(v.CreateInput.LaunchType),
		CreatePlatformVersion:                nullableString(v.CreateInput.PlatformVersion),
		CreatePropagateTags:                  nullableString(v.CreateInput.PropagateTags),
		CreateRole:                           nullableString(v.CreateInput.Role),
		CreateSchedulingStrategy:             nullableString(v.CreateInput.SchedulingStrategy),
		CreateServiceName:                    nullableString(v.CreateInput.ServiceName),
		CreateTaskDefinition:                 nullableString(v.CreateInput.TaskDefinition),
	}
	err := marshalFields(
		jsonWriteField{&params.ServiceCapacityProviderStrategy, v.Data.CapacityProviderStrategy},
		jsonWriteField{&params.ServiceCurrentServiceRevisions, v.Data.CurrentServiceRevisions},
		jsonWriteField{&params.ServiceDeploymentConfiguration, v.Data.DeploymentConfiguration},
		jsonWriteField{&params.ServiceDeploymentController, v.Data.DeploymentController},
		jsonWriteField{&params.ServiceEvents, v.Data.Events},
		jsonWriteField{&params.ServiceLoadBalancers, v.Data.LoadBalancers},
		jsonWriteField{&params.ServiceNetworkConfiguration, v.Data.NetworkConfiguration},
		jsonWriteField{&params.ServicePlacementConstraints, v.Data.PlacementConstraints},
		jsonWriteField{&params.ServicePlacementStrategy, v.Data.PlacementStrategy},
		jsonWriteField{&params.ServiceServiceRegistries, v.Data.ServiceRegistries},
		jsonWriteField{&params.ServiceTaskSets, v.Data.TaskSets},
		jsonWriteField{&params.CreateCapacityProviderStrategy, v.CreateInput.CapacityProviderStrategy},
		jsonWriteField{&params.CreateDeploymentConfiguration, v.CreateInput.DeploymentConfiguration},
		jsonWriteField{&params.CreateDeploymentController, v.CreateInput.DeploymentController},
		jsonWriteField{&params.CreateLoadBalancers, v.CreateInput.LoadBalancers},
		jsonWriteField{&params.CreateMonitoring, v.CreateInput.Monitoring},
		jsonWriteField{&params.CreateNetworkConfiguration, v.CreateInput.NetworkConfiguration},
		jsonWriteField{&params.CreatePlacementConstraints, v.CreateInput.PlacementConstraints},
		jsonWriteField{&params.CreatePlacementStrategy, v.CreateInput.PlacementStrategy},
		jsonWriteField{&params.CreateServiceConnectConfiguration, v.CreateInput.ServiceConnectConfiguration},
		jsonWriteField{&params.CreateServiceRegistries, v.CreateInput.ServiceRegistries},
		jsonWriteField{&params.CreateTags, v.CreateInput.Tags},
		jsonWriteField{&params.CreateVolumeConfigurations, v.CreateInput.VolumeConfigurations},
		jsonWriteField{&params.CreateVpcLatticeConfigurations, v.CreateInput.VpcLatticeConfigurations},
	)
	return params, err
}

func serviceDeploymentRecord(row sqlcgen.EcsServiceDeployment) (domain.ServiceDeployment, error) {
	out := domain.ServiceDeployment{
		AcceptedEventID: row.AcceptedEventID, Failures: int32(row.Failures),
		RetryAfter: row.RetryAfter, Deadline: row.Deadline, Completed: row.Completed,
	}
	out.Data.CreatedAt = timePointer(row.DeploymentCreatedAt)
	out.Data.DesiredCount = integerPointer[api.Integer](row.DeploymentDesiredCount)
	out.Data.FailedTasks = integerPointer[api.Integer](row.DeploymentFailedTasks)
	out.Data.Id = stringPointer[api.String](row.DeploymentID)
	out.Data.LaunchType = stringPointer[api.LaunchType](row.DeploymentLaunchType)
	out.Data.PendingCount = integerPointer[api.Integer](row.DeploymentPendingCount)
	out.Data.PlatformFamily = stringPointer[api.String](row.DeploymentPlatformFamily)
	out.Data.PlatformVersion = stringPointer[api.String](row.DeploymentPlatformVersion)
	out.Data.RolloutState = stringPointer[api.DeploymentRolloutState](row.DeploymentRolloutState)
	out.Data.RolloutStateReason = stringPointer[api.String](row.DeploymentRolloutStateReason)
	out.Data.RunningCount = integerPointer[api.Integer](row.DeploymentRunningCount)
	out.Data.Status = stringPointer[api.String](row.DeploymentStatus)
	out.Data.TaskDefinition = stringPointer[api.String](row.DeploymentTaskDefinition)
	out.Data.UpdatedAt = timePointer(row.DeploymentUpdatedAt)
	out.Definition.Cpu = stringPointer[api.String](row.DefinitionCpu)
	out.Definition.DeleteRequestedAt = timePointer(row.DefinitionDeleteRequestedAt)
	out.Definition.DeregisteredAt = timePointer(row.DefinitionDeregisteredAt)
	out.Definition.EnableFaultInjection = boolPointer[api.BoxedBoolean](row.DefinitionEnableFaultInjection)
	out.Definition.ExecutionRoleArn = stringPointer[api.String](row.DefinitionExecutionRoleArn)
	out.Definition.Family = stringPointer[api.String](row.DefinitionFamily)
	out.Definition.IpcMode = stringPointer[api.IpcMode](row.DefinitionIpcMode)
	out.Definition.Memory = stringPointer[api.String](row.DefinitionMemory)
	out.Definition.NetworkMode = stringPointer[api.NetworkMode](row.DefinitionNetworkMode)
	out.Definition.PidMode = stringPointer[api.PidMode](row.DefinitionPidMode)
	out.Definition.PreviousStatus = stringPointer[api.TaskDefinitionStatus](row.DefinitionPreviousStatus)
	out.Definition.RegisteredAt = timePointer(row.DefinitionRegisteredAt)
	out.Definition.RegisteredBy = stringPointer[api.String](row.DefinitionRegisteredBy)
	out.Definition.Revision = integerPointer[api.Integer](row.DefinitionRevision)
	out.Definition.Status = stringPointer[api.TaskDefinitionStatus](row.DefinitionStatus)
	out.Definition.TaskDefinitionArn = stringPointer[api.String](row.DefinitionTaskDefinitionArn)
	out.Definition.TaskRoleArn = stringPointer[api.String](row.DefinitionTaskRoleArn)
	out.Input.ClientToken = stringPointer[api.String](row.InputClientToken)
	out.Input.Cluster = stringPointer[api.String](row.InputCluster)
	out.Input.Count = integerPointer[api.BoxedInteger](row.InputCount)
	out.Input.EnableECSManagedTags = boolPointer[api.Boolean](row.InputEnableEcsManagedTags)
	out.Input.EnableExecuteCommand = boolPointer[api.Boolean](row.InputEnableExecuteCommand)
	out.Input.Group = stringPointer[api.String](row.InputGroup)
	out.Input.LaunchType = stringPointer[api.LaunchType](row.InputLaunchType)
	out.Input.PlatformVersion = stringPointer[api.String](row.InputPlatformVersion)
	out.Input.PropagateTags = stringPointer[api.PropagateTags](row.InputPropagateTags)
	out.Input.ReferenceId = stringPointer[api.String](row.InputReferenceID)
	out.Input.StartedBy = stringPointer[api.String](row.InputStartedBy)
	out.Input.TaskDefinition = stringPointer[api.String](row.InputTaskDefinition)
	err := unmarshalFields(
		jsonReadField{row.DeploymentCapacityProviderStrategy, &out.Data.CapacityProviderStrategy},
		jsonReadField{row.DeploymentFargateEphemeralStorage, &out.Data.FargateEphemeralStorage},
		jsonReadField{row.DeploymentNetworkConfiguration, &out.Data.NetworkConfiguration},
		jsonReadField{row.DeploymentServiceConnectConfiguration, &out.Data.ServiceConnectConfiguration},
		jsonReadField{row.DeploymentServiceConnectResources, &out.Data.ServiceConnectResources},
		jsonReadField{row.DeploymentVolumeConfigurations, &out.Data.VolumeConfigurations},
		jsonReadField{row.DeploymentVpcLatticeConfigurations, &out.Data.VpcLatticeConfigurations},
		jsonReadField{row.DefinitionCompatibilities, &out.Definition.Compatibilities},
		jsonReadField{row.DefinitionContainerDefinitions, &out.Definition.ContainerDefinitions},
		jsonReadField{row.DefinitionEphemeralStorage, &out.Definition.EphemeralStorage},
		jsonReadField{row.DefinitionInferenceAccelerators, &out.Definition.InferenceAccelerators},
		jsonReadField{row.DefinitionPlacementConstraints, &out.Definition.PlacementConstraints},
		jsonReadField{row.DefinitionProxyConfiguration, &out.Definition.ProxyConfiguration},
		jsonReadField{row.DefinitionRequiresAttributes, &out.Definition.RequiresAttributes},
		jsonReadField{row.DefinitionRequiresCompatibilities, &out.Definition.RequiresCompatibilities},
		jsonReadField{row.DefinitionRuntimePlatform, &out.Definition.RuntimePlatform},
		jsonReadField{row.DefinitionVolumes, &out.Definition.Volumes},
		jsonReadField{row.InputCapacityProviderStrategy, &out.Input.CapacityProviderStrategy},
		jsonReadField{row.InputNetworkConfiguration, &out.Input.NetworkConfiguration},
		jsonReadField{row.InputOverrides, &out.Input.Overrides},
		jsonReadField{row.InputPlacementConstraints, &out.Input.PlacementConstraints},
		jsonReadField{row.InputPlacementStrategy, &out.Input.PlacementStrategy},
		jsonReadField{row.InputTags, &out.Input.Tags},
		jsonReadField{row.InputVolumeConfigurations, &out.Input.VolumeConfigurations},
		jsonReadField{row.Monitoring, &out.Monitoring},
		jsonReadField{row.LoadBalancers, &out.LoadBalancers},
	)
	return out, err
}

func serviceDeploymentParams(k domain.ServiceKey, position int, v domain.ServiceDeployment) (sqlcgen.PutServiceDeploymentParams, error) {
	params := sqlcgen.PutServiceDeploymentParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
		Position: int64(position), AcceptedEventID: v.AcceptedEventID, Failures: int64(v.Failures),
		RetryAfter: v.RetryAfter, Deadline: v.Deadline, Completed: v.Completed, ObservedTasksPresent: v.ObservedTasks != nil,
		ResolvedImagesPresent:          v.ResolvedImages != nil,
		DeploymentCreatedAt:            nullableTime(v.Data.CreatedAt),
		DeploymentDesiredCount:         nullableInteger(v.Data.DesiredCount),
		DeploymentFailedTasks:          nullableInteger(v.Data.FailedTasks),
		DeploymentID:                   nullableString(v.Data.Id),
		DeploymentLaunchType:           nullableString(v.Data.LaunchType),
		DeploymentPendingCount:         nullableInteger(v.Data.PendingCount),
		DeploymentPlatformFamily:       nullableString(v.Data.PlatformFamily),
		DeploymentPlatformVersion:      nullableString(v.Data.PlatformVersion),
		DeploymentRolloutState:         nullableString(v.Data.RolloutState),
		DeploymentRolloutStateReason:   nullableString(v.Data.RolloutStateReason),
		DeploymentRunningCount:         nullableInteger(v.Data.RunningCount),
		DeploymentStatus:               nullableString(v.Data.Status),
		DeploymentTaskDefinition:       nullableString(v.Data.TaskDefinition),
		DeploymentUpdatedAt:            nullableTime(v.Data.UpdatedAt),
		DefinitionCpu:                  nullableString(v.Definition.Cpu),
		DefinitionDeleteRequestedAt:    nullableTime(v.Definition.DeleteRequestedAt),
		DefinitionDeregisteredAt:       nullableTime(v.Definition.DeregisteredAt),
		DefinitionEnableFaultInjection: nullableBool(v.Definition.EnableFaultInjection),
		DefinitionExecutionRoleArn:     nullableString(v.Definition.ExecutionRoleArn),
		DefinitionFamily:               nullableString(v.Definition.Family),
		DefinitionIpcMode:              nullableString(v.Definition.IpcMode),
		DefinitionMemory:               nullableString(v.Definition.Memory),
		DefinitionNetworkMode:          nullableString(v.Definition.NetworkMode),
		DefinitionPidMode:              nullableString(v.Definition.PidMode),
		DefinitionPreviousStatus:       nullableString(v.Definition.PreviousStatus),
		DefinitionRegisteredAt:         nullableTime(v.Definition.RegisteredAt),
		DefinitionRegisteredBy:         nullableString(v.Definition.RegisteredBy),
		DefinitionRevision:             nullableInteger(v.Definition.Revision),
		DefinitionStatus:               nullableString(v.Definition.Status),
		DefinitionTaskDefinitionArn:    nullableString(v.Definition.TaskDefinitionArn),
		DefinitionTaskRoleArn:          nullableString(v.Definition.TaskRoleArn),
		InputClientToken:               nullableString(v.Input.ClientToken),
		InputCluster:                   nullableString(v.Input.Cluster),
		InputCount:                     nullableInteger(v.Input.Count),
		InputEnableEcsManagedTags:      nullableBool(v.Input.EnableECSManagedTags),
		InputEnableExecuteCommand:      nullableBool(v.Input.EnableExecuteCommand),
		InputGroup:                     nullableString(v.Input.Group),
		InputLaunchType:                nullableString(v.Input.LaunchType),
		InputPlatformVersion:           nullableString(v.Input.PlatformVersion),
		InputPropagateTags:             nullableString(v.Input.PropagateTags),
		InputReferenceID:               nullableString(v.Input.ReferenceId),
		InputStartedBy:                 nullableString(v.Input.StartedBy),
		InputTaskDefinition:            nullableString(v.Input.TaskDefinition),
	}
	err := marshalFields(
		jsonWriteField{&params.DeploymentCapacityProviderStrategy, v.Data.CapacityProviderStrategy},
		jsonWriteField{&params.DeploymentFargateEphemeralStorage, v.Data.FargateEphemeralStorage},
		jsonWriteField{&params.DeploymentNetworkConfiguration, v.Data.NetworkConfiguration},
		jsonWriteField{&params.DeploymentServiceConnectConfiguration, v.Data.ServiceConnectConfiguration},
		jsonWriteField{&params.DeploymentServiceConnectResources, v.Data.ServiceConnectResources},
		jsonWriteField{&params.DeploymentVolumeConfigurations, v.Data.VolumeConfigurations},
		jsonWriteField{&params.DeploymentVpcLatticeConfigurations, v.Data.VpcLatticeConfigurations},
		jsonWriteField{&params.DefinitionCompatibilities, v.Definition.Compatibilities},
		jsonWriteField{&params.DefinitionContainerDefinitions, v.Definition.ContainerDefinitions},
		jsonWriteField{&params.DefinitionEphemeralStorage, v.Definition.EphemeralStorage},
		jsonWriteField{&params.DefinitionInferenceAccelerators, v.Definition.InferenceAccelerators},
		jsonWriteField{&params.DefinitionPlacementConstraints, v.Definition.PlacementConstraints},
		jsonWriteField{&params.DefinitionProxyConfiguration, v.Definition.ProxyConfiguration},
		jsonWriteField{&params.DefinitionRequiresAttributes, v.Definition.RequiresAttributes},
		jsonWriteField{&params.DefinitionRequiresCompatibilities, v.Definition.RequiresCompatibilities},
		jsonWriteField{&params.DefinitionRuntimePlatform, v.Definition.RuntimePlatform},
		jsonWriteField{&params.DefinitionVolumes, v.Definition.Volumes},
		jsonWriteField{&params.InputCapacityProviderStrategy, v.Input.CapacityProviderStrategy},
		jsonWriteField{&params.InputNetworkConfiguration, v.Input.NetworkConfiguration},
		jsonWriteField{&params.InputOverrides, v.Input.Overrides},
		jsonWriteField{&params.InputPlacementConstraints, v.Input.PlacementConstraints},
		jsonWriteField{&params.InputPlacementStrategy, v.Input.PlacementStrategy},
		jsonWriteField{&params.InputTags, v.Input.Tags},
		jsonWriteField{&params.InputVolumeConfigurations, v.Input.VolumeConfigurations},
		jsonWriteField{&params.Monitoring, v.Monitoring},
		jsonWriteField{&params.LoadBalancers, v.LoadBalancers},
	)
	return params, err
}
