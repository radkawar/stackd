package ecs

import (
	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) TaskRun(k domain.TaskRunKey) (domain.TaskRunRecord, error) {
	row, err := r.q.GetTaskRun(r.ctx, sqlcgen.GetTaskRunParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ClientToken: k.ClientToken,
	})
	if err != nil {
		return domain.TaskRunRecord{}, missing(err)
	}
	out := domain.TaskRunRecord{
		Key: k, Created: row.Created,
		Input: api.RunTaskInput{
			ClientToken:          stringPointer[api.String](row.InputClientToken),
			Cluster:              stringPointer[api.String](row.InputCluster),
			Count:                integerPointer[api.BoxedInteger](row.InputCount),
			EnableECSManagedTags: boolPointer[api.Boolean](row.InputEnableEcsManagedTags),
			EnableExecuteCommand: boolPointer[api.Boolean](row.InputEnableExecuteCommand),
			Group:                stringPointer[api.String](row.InputGroup),
			LaunchType:           stringPointer[api.LaunchType](row.InputLaunchType),
			PlatformVersion:      stringPointer[api.String](row.InputPlatformVersion),
			PropagateTags:        stringPointer[api.PropagateTags](row.InputPropagateTags),
			ReferenceId:          stringPointer[api.String](row.InputReferenceID),
			StartedBy:            stringPointer[api.String](row.InputStartedBy),
			TaskDefinition:       stringPointer[api.String](row.InputTaskDefinition),
		},
	}
	err = unmarshalFields(
		jsonReadField{row.InputCapacityProviderStrategy, &out.Input.CapacityProviderStrategy},
		jsonReadField{row.InputNetworkConfiguration, &out.Input.NetworkConfiguration},
		jsonReadField{row.InputOverrides, &out.Input.Overrides},
		jsonReadField{row.InputPlacementConstraints, &out.Input.PlacementConstraints},
		jsonReadField{row.InputPlacementStrategy, &out.Input.PlacementStrategy},
		jsonReadField{row.InputTags, &out.Input.Tags},
		jsonReadField{row.InputVolumeConfigurations, &out.Input.VolumeConfigurations},
		jsonReadField{row.TaskIds, &out.TaskIDs},
	)
	return out, err
}

func (w writer) PutTaskRun(v domain.TaskRunRecord) error {
	k := v.Key
	params := sqlcgen.PutTaskRunParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ClientToken: k.ClientToken,
		Created:                   v.Created,
		InputClientToken:          nullableString(v.Input.ClientToken),
		InputCluster:              nullableString(v.Input.Cluster),
		InputCount:                nullableInteger(v.Input.Count),
		InputEnableEcsManagedTags: nullableBool(v.Input.EnableECSManagedTags),
		InputEnableExecuteCommand: nullableBool(v.Input.EnableExecuteCommand),
		InputGroup:                nullableString(v.Input.Group),
		InputLaunchType:           nullableString(v.Input.LaunchType),
		InputPlatformVersion:      nullableString(v.Input.PlatformVersion),
		InputPropagateTags:        nullableString(v.Input.PropagateTags),
		InputReferenceID:          nullableString(v.Input.ReferenceId),
		InputStartedBy:            nullableString(v.Input.StartedBy),
		InputTaskDefinition:       nullableString(v.Input.TaskDefinition),
	}
	if err := marshalFields(
		jsonWriteField{&params.InputCapacityProviderStrategy, v.Input.CapacityProviderStrategy},
		jsonWriteField{&params.InputNetworkConfiguration, v.Input.NetworkConfiguration},
		jsonWriteField{&params.InputOverrides, v.Input.Overrides},
		jsonWriteField{&params.InputPlacementConstraints, v.Input.PlacementConstraints},
		jsonWriteField{&params.InputPlacementStrategy, v.Input.PlacementStrategy},
		jsonWriteField{&params.InputTags, v.Input.Tags},
		jsonWriteField{&params.InputVolumeConfigurations, v.Input.VolumeConfigurations},
		jsonWriteField{&params.TaskIds, v.TaskIDs},
	); err != nil {
		return err
	}
	return w.q.PutTaskRun(w.ctx, params)
}
