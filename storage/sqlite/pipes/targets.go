package pipes

import (
	"database/sql"
	"encoding/json"
	api "stackd/internal/awsapi/pipes"
	"stackd/storage/sqlite/pipes/internal/sqlcgen"
)

func encodeTarget(p api.PipeTargetParameters, v *sqlcgen.PipesPipe) error {
	v.TargetTemplate = nullableString(p.InputTemplate)
	v.TargetHttpPresent = p.HttpParameters != nil
	v.TargetHttpHeaders, v.TargetHttpPaths, v.TargetHttpQuery = "null", "null", "null"
	if http := p.HttpParameters; http != nil {
		for _, field := range []struct {
			target *string
			value  any
		}{
			{&v.TargetHttpHeaders, http.HeaderParameters},
			{&v.TargetHttpPaths, http.PathParameterValues},
			{&v.TargetHttpQuery, http.QueryStringParameters},
		} {
			encoded, err := json.Marshal(field.value)
			if err != nil {
				return err
			}
			*field.target = string(encoded)
		}
	}
	if q := p.SqsQueueParameters; q != nil {
		v.TargetGroupID = nullableString(q.MessageGroupId)
		v.TargetDeduplicationID = nullableString(q.MessageDeduplicationId)
	}
	if q := p.KinesisStreamParameters; q != nil {
		v.TargetPartitionKey = nullableString(q.PartitionKey)
	}
	if q := p.LambdaFunctionParameters; q != nil {
		v.TargetLambdaInvocation = nullableString(q.InvocationType)
	}
	if q := p.StepFunctionStateMachineParameters; q != nil {
		v.TargetStatesInvocation = nullableString(q.InvocationType)
	}
	if q := p.CloudWatchLogsParameters; q != nil {
		v.TargetLogStream = nullableString(q.LogStreamName)
		v.TargetLogTimestamp = nullableString(q.Timestamp)
	}
	if q := p.EventBridgeEventBusParameters; q != nil {
		v.TargetEventSource = nullableString(q.Source)
		v.TargetEventDetailType = nullableString(q.DetailType)
		v.TargetEventTime = nullableString(q.Time)
		v.TargetEventEndpoint = nullableString(q.EndpointId)
	}
	if q := p.EcsTaskParameters; q != nil {
		v.TargetEcsTaskDefinition = nullableString(q.TaskDefinitionArn)
		v.TargetEcsTaskCount = nullableInteger(q.TaskCount)
		v.TargetEcsLaunchType = nullableString(q.LaunchType)
		v.TargetEcsGroup = nullableString(q.Group)
		v.TargetEcsPlatformVersion = nullableString(q.PlatformVersion)
		v.TargetEcsPropagateTags = nullableString(q.PropagateTags)
		v.TargetEcsReferenceID = nullableString(q.ReferenceId)
		v.TargetEcsEnableManagedTags = nullableBool(q.EnableECSManagedTags)
		v.TargetEcsEnableExecuteCommand = nullableBool(q.EnableExecuteCommand)
		for _, field := range []struct {
			target *sql.NullString
			value  any
		}{
			{&v.TargetEcsCapacityStrategy, q.CapacityProviderStrategy},
			{&v.TargetEcsNetwork, q.NetworkConfiguration},
			{&v.TargetEcsOverrides, q.Overrides},
			{&v.TargetEcsPlacementConstraints, q.PlacementConstraints},
			{&v.TargetEcsPlacementStrategy, q.PlacementStrategy},
			{&v.TargetEcsTags, q.Tags},
		} {
			b, e := json.Marshal(field.value)
			if e != nil {
				return e
			}
			if string(b) != "null" {
				*field.target = sql.NullString{String: string(b), Valid: true}
			}
		}
	}
	return nil
}

func decodeTarget(v sqlcgen.PipesPipe, p *api.PipeTargetParameters) error {
	p.InputTemplate = stringPointer[api.InputTemplate](v.TargetTemplate)
	if v.TargetHttpPresent {
		p.HttpParameters = &api.PipeTargetHttpParameters{}
		for _, field := range []struct {
			source string
			value  any
		}{
			{v.TargetHttpHeaders, &p.HttpParameters.HeaderParameters},
			{v.TargetHttpPaths, &p.HttpParameters.PathParameterValues},
			{v.TargetHttpQuery, &p.HttpParameters.QueryStringParameters},
		} {
			if err := json.Unmarshal([]byte(field.source), field.value); err != nil {
				return err
			}
		}
	}
	if v.TargetGroupID.Valid || v.TargetDeduplicationID.Valid {
		p.SqsQueueParameters = &api.PipeTargetSqsQueueParameters{
			MessageGroupId:         stringPointer[api.MessageGroupId](v.TargetGroupID),
			MessageDeduplicationId: stringPointer[api.MessageDeduplicationId](v.TargetDeduplicationID),
		}
	}
	if v.TargetPartitionKey.Valid {
		p.KinesisStreamParameters = &api.PipeTargetKinesisStreamParameters{PartitionKey: stringPointer[api.KinesisPartitionKey](v.TargetPartitionKey)}
	}
	if v.TargetLambdaInvocation.Valid {
		p.LambdaFunctionParameters = &api.PipeTargetLambdaFunctionParameters{InvocationType: stringPointer[api.PipeTargetInvocationType](v.TargetLambdaInvocation)}
	}
	if v.TargetStatesInvocation.Valid {
		p.StepFunctionStateMachineParameters = &api.PipeTargetStateMachineParameters{InvocationType: stringPointer[api.PipeTargetInvocationType](v.TargetStatesInvocation)}
	}
	if v.TargetLogStream.Valid || v.TargetLogTimestamp.Valid {
		p.CloudWatchLogsParameters = &api.PipeTargetCloudWatchLogsParameters{
			LogStreamName: stringPointer[api.LogStreamName](v.TargetLogStream),
			Timestamp:     stringPointer[api.JsonPath](v.TargetLogTimestamp),
		}
	}
	if v.TargetEventSource.Valid || v.TargetEventDetailType.Valid || v.TargetEventTime.Valid || v.TargetEventEndpoint.Valid {
		p.EventBridgeEventBusParameters = &api.PipeTargetEventBridgeEventBusParameters{
			Source:     stringPointer[api.EventBridgeEventSource](v.TargetEventSource),
			DetailType: stringPointer[api.EventBridgeDetailType](v.TargetEventDetailType),
			Time:       stringPointer[api.JsonPath](v.TargetEventTime),
			EndpointId: stringPointer[api.EventBridgeEndpointId](v.TargetEventEndpoint),
		}
	}
	if v.TargetEcsTaskDefinition.Valid {
		q := &api.PipeTargetEcsTaskParameters{
			TaskDefinitionArn:    stringPointer[api.ArnOrJsonPath](v.TargetEcsTaskDefinition),
			TaskCount:            integerPointer[api.LimitMin1](v.TargetEcsTaskCount),
			LaunchType:           stringPointer[api.LaunchType](v.TargetEcsLaunchType),
			Group:                stringPointer[api.String](v.TargetEcsGroup),
			PlatformVersion:      stringPointer[api.String](v.TargetEcsPlatformVersion),
			PropagateTags:        stringPointer[api.PropagateTags](v.TargetEcsPropagateTags),
			ReferenceId:          stringPointer[api.ReferenceId](v.TargetEcsReferenceID),
			EnableECSManagedTags: boolPointer[api.Boolean](v.TargetEcsEnableManagedTags),
			EnableExecuteCommand: boolPointer[api.Boolean](v.TargetEcsEnableExecuteCommand),
		}
		for _, field := range []struct {
			source sql.NullString
			value  any
		}{
			{v.TargetEcsCapacityStrategy, &q.CapacityProviderStrategy},
			{v.TargetEcsNetwork, &q.NetworkConfiguration},
			{v.TargetEcsOverrides, &q.Overrides},
			{v.TargetEcsPlacementConstraints, &q.PlacementConstraints},
			{v.TargetEcsPlacementStrategy, &q.PlacementStrategy},
			{v.TargetEcsTags, &q.Tags},
		} {
			if field.source.Valid {
				if e := json.Unmarshal([]byte(field.source.String), field.value); e != nil {
					return e
				}
			}
		}
		p.EcsTaskParameters = q
	}
	return nil
}
