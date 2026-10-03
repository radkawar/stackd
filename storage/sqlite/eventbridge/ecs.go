package eventbridge

import (
	"database/sql"
	"encoding/json"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/storage/sqlite/eventbridge/internal/sqlcgen"
)

func decodeTargetECS(v sqlcgen.EventbridgeTarget) (*api.EcsParameters, error) {
	if !v.EcsPresent {
		return nil, nil
	}
	p := &api.EcsParameters{}
	if v.EcsTaskDefinition.Valid {
		value := api.Arn(v.EcsTaskDefinition.String)
		p.TaskDefinitionArn = &value
	}
	if v.EcsTaskCount.Valid {
		value := api.LimitMin1(v.EcsTaskCount.Int64)
		p.TaskCount = &value
	}
	if v.EcsLaunchType.Valid {
		value := api.LaunchType(v.EcsLaunchType.String)
		p.LaunchType = &value
	}
	if v.EcsGroup.Valid {
		value := api.String(v.EcsGroup.String)
		p.Group = &value
	}
	if v.EcsPlatformVersion.Valid {
		value := api.String(v.EcsPlatformVersion.String)
		p.PlatformVersion = &value
	}
	if v.EcsReferenceID.Valid {
		value := api.ReferenceId(v.EcsReferenceID.String)
		p.ReferenceId = &value
	}
	if v.EcsPropagateTags.Valid {
		value := api.PropagateTags(v.EcsPropagateTags.String)
		p.PropagateTags = &value
	}
	if v.EcsEnableManagedTags.Valid {
		value := api.Boolean(v.EcsEnableManagedTags.Bool)
		p.EnableECSManagedTags = &value
	}
	if v.EcsEnableExecuteCommand.Valid {
		value := api.Boolean(v.EcsEnableExecuteCommand.Bool)
		p.EnableExecuteCommand = &value
	}
	if err := json.Unmarshal(v.EcsNetworkConfiguration, &p.NetworkConfiguration); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsCapacityProviderStrategy, &p.CapacityProviderStrategy); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsPlacementConstraints, &p.PlacementConstraints); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsPlacementStrategy, &p.PlacementStrategy); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsTags, &p.Tags); err != nil {
		return nil, err
	}
	return p, nil
}

func encodeTargetECS(v *sqlcgen.PutTargetParams, p *api.EcsParameters) error {
	v.EcsPresent = p != nil
	if p == nil {
		p = &api.EcsParameters{}
	}
	if p.TaskDefinitionArn != nil {
		v.EcsTaskDefinition = sql.NullString{String: string(*p.TaskDefinitionArn), Valid: true}
	}
	if p.TaskCount != nil {
		v.EcsTaskCount = sql.NullInt64{Int64: int64(*p.TaskCount), Valid: true}
	}
	if p.LaunchType != nil {
		v.EcsLaunchType = sql.NullString{String: string(*p.LaunchType), Valid: true}
	}
	if p.Group != nil {
		v.EcsGroup = sql.NullString{String: string(*p.Group), Valid: true}
	}
	if p.PlatformVersion != nil {
		v.EcsPlatformVersion = sql.NullString{String: string(*p.PlatformVersion), Valid: true}
	}
	if p.ReferenceId != nil {
		v.EcsReferenceID = sql.NullString{String: string(*p.ReferenceId), Valid: true}
	}
	if p.PropagateTags != nil {
		v.EcsPropagateTags = sql.NullString{String: string(*p.PropagateTags), Valid: true}
	}
	if p.EnableECSManagedTags != nil {
		v.EcsEnableManagedTags = sql.NullBool{Bool: bool(*p.EnableECSManagedTags), Valid: true}
	}
	if p.EnableExecuteCommand != nil {
		v.EcsEnableExecuteCommand = sql.NullBool{Bool: bool(*p.EnableExecuteCommand), Valid: true}
	}
	var err error
	v.EcsNetworkConfiguration, err = json.Marshal(p.NetworkConfiguration)
	if err != nil {
		return err
	}
	v.EcsCapacityProviderStrategy, err = json.Marshal(p.CapacityProviderStrategy)
	if err != nil {
		return err
	}
	v.EcsPlacementConstraints, err = json.Marshal(p.PlacementConstraints)
	if err != nil {
		return err
	}
	v.EcsPlacementStrategy, err = json.Marshal(p.PlacementStrategy)
	if err != nil {
		return err
	}
	v.EcsTags, err = json.Marshal(p.Tags)
	if err != nil {
		return err
	}
	return nil
}

func decodeDeliveryECS(v sqlcgen.EventbridgeDelivery) (*api.EcsParameters, error) {
	if !v.EcsPresent {
		return nil, nil
	}
	p := &api.EcsParameters{}
	if v.EcsTaskDefinition.Valid {
		value := api.Arn(v.EcsTaskDefinition.String)
		p.TaskDefinitionArn = &value
	}
	if v.EcsTaskCount.Valid {
		value := api.LimitMin1(v.EcsTaskCount.Int64)
		p.TaskCount = &value
	}
	if v.EcsLaunchType.Valid {
		value := api.LaunchType(v.EcsLaunchType.String)
		p.LaunchType = &value
	}
	if v.EcsGroup.Valid {
		value := api.String(v.EcsGroup.String)
		p.Group = &value
	}
	if v.EcsPlatformVersion.Valid {
		value := api.String(v.EcsPlatformVersion.String)
		p.PlatformVersion = &value
	}
	if v.EcsReferenceID.Valid {
		value := api.ReferenceId(v.EcsReferenceID.String)
		p.ReferenceId = &value
	}
	if v.EcsPropagateTags.Valid {
		value := api.PropagateTags(v.EcsPropagateTags.String)
		p.PropagateTags = &value
	}
	if v.EcsEnableManagedTags.Valid {
		value := api.Boolean(v.EcsEnableManagedTags.Bool)
		p.EnableECSManagedTags = &value
	}
	if v.EcsEnableExecuteCommand.Valid {
		value := api.Boolean(v.EcsEnableExecuteCommand.Bool)
		p.EnableExecuteCommand = &value
	}
	if err := json.Unmarshal(v.EcsNetworkConfiguration, &p.NetworkConfiguration); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsCapacityProviderStrategy, &p.CapacityProviderStrategy); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsPlacementConstraints, &p.PlacementConstraints); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsPlacementStrategy, &p.PlacementStrategy); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(v.EcsTags, &p.Tags); err != nil {
		return nil, err
	}
	return p, nil
}

func encodeDeliveryECS(v *sqlcgen.PutDeliveryParams, p *api.EcsParameters) error {
	v.EcsPresent = p != nil
	if p == nil {
		p = &api.EcsParameters{}
	}
	if p.TaskDefinitionArn != nil {
		v.EcsTaskDefinition = sql.NullString{String: string(*p.TaskDefinitionArn), Valid: true}
	}
	if p.TaskCount != nil {
		v.EcsTaskCount = sql.NullInt64{Int64: int64(*p.TaskCount), Valid: true}
	}
	if p.LaunchType != nil {
		v.EcsLaunchType = sql.NullString{String: string(*p.LaunchType), Valid: true}
	}
	if p.Group != nil {
		v.EcsGroup = sql.NullString{String: string(*p.Group), Valid: true}
	}
	if p.PlatformVersion != nil {
		v.EcsPlatformVersion = sql.NullString{String: string(*p.PlatformVersion), Valid: true}
	}
	if p.ReferenceId != nil {
		v.EcsReferenceID = sql.NullString{String: string(*p.ReferenceId), Valid: true}
	}
	if p.PropagateTags != nil {
		v.EcsPropagateTags = sql.NullString{String: string(*p.PropagateTags), Valid: true}
	}
	if p.EnableECSManagedTags != nil {
		v.EcsEnableManagedTags = sql.NullBool{Bool: bool(*p.EnableECSManagedTags), Valid: true}
	}
	if p.EnableExecuteCommand != nil {
		v.EcsEnableExecuteCommand = sql.NullBool{Bool: bool(*p.EnableExecuteCommand), Valid: true}
	}
	var err error
	v.EcsNetworkConfiguration, err = json.Marshal(p.NetworkConfiguration)
	if err != nil {
		return err
	}
	v.EcsCapacityProviderStrategy, err = json.Marshal(p.CapacityProviderStrategy)
	if err != nil {
		return err
	}
	v.EcsPlacementConstraints, err = json.Marshal(p.PlacementConstraints)
	if err != nil {
		return err
	}
	v.EcsPlacementStrategy, err = json.Marshal(p.PlacementStrategy)
	if err != nil {
		return err
	}
	v.EcsTags, err = json.Marshal(p.Tags)
	if err != nil {
		return err
	}
	return nil
}
