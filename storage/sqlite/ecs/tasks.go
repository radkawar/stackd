package ecs

import (
	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) Task(k domain.TaskKey) (domain.TaskRecord, error) {
	row, err := r.q.GetTask(r.ctx, sqlcgen.GetTaskParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, TaskID: k.ID,
	})
	if err != nil {
		return domain.TaskRecord{}, missing(err)
	}
	return taskRecord(row)
}

func (r reader) Tasks(q domain.TaskQuery) ([]domain.TaskRecord, error) {
	rows, err := r.q.ListTasks(r.ctx, sqlcgen.ListTasksParams{
		Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, ClusterName: q.Name,
		AfterID: q.AfterID, DesiredStatus: q.DesiredStatus, Family: q.Family,
		StartedBy: q.StartedBy, LaunchType: q.LaunchType, RowLimit: rowLimit(q.Limit),
		ServiceName: q.ServiceName, ActiveOnly: flag(q.ActiveOnly),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TaskRecord, 0, len(rows))
	for _, row := range rows {
		record, err := taskRecord(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (r reader) ActiveTaskKeys() ([]domain.TaskKey, error) {
	rows, err := r.q.ListActiveTaskKeys(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.TaskKey, len(rows))
	for i, row := range rows {
		out[i] = domain.TaskKey{
			ClusterKey: domain.ClusterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ClusterName},
			ID:         row.TaskID,
		}
	}
	return out, nil
}

func taskRecord(row sqlcgen.EcsTask) (domain.TaskRecord, error) {
	out := domain.TaskRecord{
		Key: domain.TaskKey{
			ClusterKey: domain.ClusterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ClusterName},
			ID:         row.TaskID,
		},
		AcceptedEventID: row.AcceptedEventID, CredentialToken: row.CredentialToken,
		ServiceName: row.ServiceName, ServiceDeploymentID: row.ServiceDeploymentID,
		Data: api.Task{
			AvailabilityZone:     stringPointer[api.String](row.TaskAvailabilityZone),
			CapacityProviderName: stringPointer[api.String](row.TaskCapacityProviderName),
			ClusterArn:           stringPointer[api.String](row.TaskClusterArn),
			Connectivity:         stringPointer[api.Connectivity](row.TaskConnectivity),
			ConnectivityAt:       timePointer(row.TaskConnectivityAt),
			ContainerInstanceArn: stringPointer[api.String](row.TaskContainerInstanceArn),
			Cpu:                  stringPointer[api.String](row.TaskCpu),
			CreatedAt:            timePointer(row.TaskCreatedAt),
			DesiredStatus:        stringPointer[api.String](row.TaskDesiredStatus),
			EnableExecuteCommand: boolPointer[api.Boolean](row.TaskEnableExecuteCommand),
			ExecutionStoppedAt:   timePointer(row.TaskExecutionStoppedAt),
			Group:                stringPointer[api.String](row.TaskGroup),
			HealthStatus:         stringPointer[api.HealthStatus](row.TaskHealthStatus),
			LastStatus:           stringPointer[api.String](row.TaskLastStatus),
			LaunchType:           stringPointer[api.LaunchType](row.TaskLaunchType),
			Memory:               stringPointer[api.String](row.TaskMemory),
			PlatformFamily:       stringPointer[api.String](row.TaskPlatformFamily),
			PlatformVersion:      stringPointer[api.String](row.TaskPlatformVersion),
			PullStartedAt:        timePointer(row.TaskPullStartedAt),
			PullStoppedAt:        timePointer(row.TaskPullStoppedAt),
			StartedAt:            timePointer(row.TaskStartedAt),
			StartedBy:            stringPointer[api.String](row.TaskStartedBy),
			StopCode:             stringPointer[api.TaskStopCode](row.TaskStopCode),
			StoppedAt:            timePointer(row.TaskStoppedAt),
			StoppedReason:        stringPointer[api.String](row.TaskStoppedReason),
			StoppingAt:           timePointer(row.TaskStoppingAt),
			TaskArn:              stringPointer[api.String](row.TaskTaskArn),
			TaskDefinitionArn:    stringPointer[api.String](row.TaskTaskDefinitionArn),
			Version:              integerPointer[api.Long](row.TaskVersion),
		},
		Definition: api.TaskDefinition{
			Cpu:                  stringPointer[api.String](row.DefinitionCpu),
			DeleteRequestedAt:    timePointer(row.DefinitionDeleteRequestedAt),
			DeregisteredAt:       timePointer(row.DefinitionDeregisteredAt),
			EnableFaultInjection: boolPointer[api.BoxedBoolean](row.DefinitionEnableFaultInjection),
			ExecutionRoleArn:     stringPointer[api.String](row.DefinitionExecutionRoleArn),
			Family:               stringPointer[api.String](row.DefinitionFamily),
			IpcMode:              stringPointer[api.IpcMode](row.DefinitionIpcMode),
			Memory:               stringPointer[api.String](row.DefinitionMemory),
			NetworkMode:          stringPointer[api.NetworkMode](row.DefinitionNetworkMode),
			PidMode:              stringPointer[api.PidMode](row.DefinitionPidMode),
			PreviousStatus:       stringPointer[api.TaskDefinitionStatus](row.DefinitionPreviousStatus),
			RegisteredAt:         timePointer(row.DefinitionRegisteredAt),
			RegisteredBy:         stringPointer[api.String](row.DefinitionRegisteredBy),
			Revision:             integerPointer[api.Integer](row.DefinitionRevision),
			Status:               stringPointer[api.TaskDefinitionStatus](row.DefinitionStatus),
			TaskDefinitionArn:    stringPointer[api.String](row.DefinitionTaskDefinitionArn),
			TaskRoleArn:          stringPointer[api.String](row.DefinitionTaskRoleArn),
		},
	}
	err := unmarshalFields(
		jsonReadField{row.TaskAttachments, &out.Data.Attachments},
		jsonReadField{row.TaskAttributes, &out.Data.Attributes},
		jsonReadField{row.TaskContainers, &out.Data.Containers},
		jsonReadField{row.TaskEphemeralStorage, &out.Data.EphemeralStorage},
		jsonReadField{row.TaskFargateEphemeralStorage, &out.Data.FargateEphemeralStorage},
		jsonReadField{row.TaskInferenceAccelerators, &out.Data.InferenceAccelerators},
		jsonReadField{row.TaskOverrides, &out.Data.Overrides},
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
		jsonReadField{row.NetworkConfiguration, &out.NetworkConfiguration},
		jsonReadField{row.MetadataTokens, &out.MetadataTokens},
		jsonReadField{row.LogCursors, &out.LogCursors},
		jsonReadField{row.DependencyWaitStarted, &out.DependencyWaitStarted},
	)
	return out, err
}

func (w writer) PutTask(v domain.TaskRecord) error {
	k := v.Key
	params := sqlcgen.PutTaskParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, TaskID: k.ID,
		AcceptedEventID: v.AcceptedEventID, CredentialToken: v.CredentialToken,
		ServiceName: v.ServiceName, ServiceDeploymentID: v.ServiceDeploymentID,
		TaskAvailabilityZone:           nullableString(v.Data.AvailabilityZone),
		TaskCapacityProviderName:       nullableString(v.Data.CapacityProviderName),
		TaskClusterArn:                 nullableString(v.Data.ClusterArn),
		TaskConnectivity:               nullableString(v.Data.Connectivity),
		TaskConnectivityAt:             nullableTime(v.Data.ConnectivityAt),
		TaskContainerInstanceArn:       nullableString(v.Data.ContainerInstanceArn),
		TaskCpu:                        nullableString(v.Data.Cpu),
		TaskCreatedAt:                  nullableTime(v.Data.CreatedAt),
		TaskDesiredStatus:              nullableString(v.Data.DesiredStatus),
		TaskEnableExecuteCommand:       nullableBool(v.Data.EnableExecuteCommand),
		TaskExecutionStoppedAt:         nullableTime(v.Data.ExecutionStoppedAt),
		TaskGroup:                      nullableString(v.Data.Group),
		TaskHealthStatus:               nullableString(v.Data.HealthStatus),
		TaskLastStatus:                 nullableString(v.Data.LastStatus),
		TaskLaunchType:                 nullableString(v.Data.LaunchType),
		TaskMemory:                     nullableString(v.Data.Memory),
		TaskPlatformFamily:             nullableString(v.Data.PlatformFamily),
		TaskPlatformVersion:            nullableString(v.Data.PlatformVersion),
		TaskPullStartedAt:              nullableTime(v.Data.PullStartedAt),
		TaskPullStoppedAt:              nullableTime(v.Data.PullStoppedAt),
		TaskStartedAt:                  nullableTime(v.Data.StartedAt),
		TaskStartedBy:                  nullableString(v.Data.StartedBy),
		TaskStopCode:                   nullableString(v.Data.StopCode),
		TaskStoppedAt:                  nullableTime(v.Data.StoppedAt),
		TaskStoppedReason:              nullableString(v.Data.StoppedReason),
		TaskStoppingAt:                 nullableTime(v.Data.StoppingAt),
		TaskTaskArn:                    nullableString(v.Data.TaskArn),
		TaskTaskDefinitionArn:          nullableString(v.Data.TaskDefinitionArn),
		TaskVersion:                    nullableInteger(v.Data.Version),
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
	}
	if err := marshalFields(
		jsonWriteField{&params.TaskAttachments, v.Data.Attachments},
		jsonWriteField{&params.TaskAttributes, v.Data.Attributes},
		jsonWriteField{&params.TaskContainers, v.Data.Containers},
		jsonWriteField{&params.TaskEphemeralStorage, v.Data.EphemeralStorage},
		jsonWriteField{&params.TaskFargateEphemeralStorage, v.Data.FargateEphemeralStorage},
		jsonWriteField{&params.TaskInferenceAccelerators, v.Data.InferenceAccelerators},
		jsonWriteField{&params.TaskOverrides, v.Data.Overrides},
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
		jsonWriteField{&params.NetworkConfiguration, v.NetworkConfiguration},
		jsonWriteField{&params.MetadataTokens, v.MetadataTokens},
		jsonWriteField{&params.LogCursors, v.LogCursors},
		jsonWriteField{&params.DependencyWaitStarted, v.DependencyWaitStarted},
	); err != nil {
		return err
	}
	return w.q.PutTask(w.ctx, params)
}
