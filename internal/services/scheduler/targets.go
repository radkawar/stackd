package scheduler

import (
	api "stackd/internal/awsapi/scheduler"
)

func targetInput(in *api.Target) (TargetRecord, error) {
	if in == nil {
		return TargetRecord{}, failure("ValidationException", "Target is required.")
	}
	if in.Input != nil && len(*in.Input) > 256*1024 {
		return TargetRecord{}, failure("ValidationException", "Target Input must not exceed 256 KB.")
	}
	v := TargetRecord{
		ARN:           value(in.Arn),
		RoleARN:       value(in.RoleArn),
		Input:         value(in.Input),
		HasInput:      in.Input != nil,
		MaxAgeSeconds: 86400,
		MaxRetries:    185,
	}
	if in.RetryPolicy != nil {
		if in.RetryPolicy.MaximumEventAgeInSeconds != nil {
			v.MaxAgeSeconds = int(*in.RetryPolicy.MaximumEventAgeInSeconds)
		}
		if in.RetryPolicy.MaximumRetryAttempts != nil {
			v.MaxRetries = int(*in.RetryPolicy.MaximumRetryAttempts)
		}
	}
	if v.MaxAgeSeconds < 60 || v.MaxAgeSeconds > 86400 || v.MaxRetries < 0 || v.MaxRetries > 185 {
		return v, failure("ValidationException", "Invalid retry policy.")
	}
	if in.DeadLetterConfig != nil {
		v.DeadLetterARN = value(in.DeadLetterConfig.Arn)
	}
	if in.SqsParameters != nil {
		v.HasSQS = true
		v.MessageGroupID = value(in.SqsParameters.MessageGroupId)
	}
	if in.EventBridgeParameters != nil {
		v.HasEventBridge = true
		v.EventSource = value(in.EventBridgeParameters.Source)
		v.EventDetailType = value(in.EventBridgeParameters.DetailType)
	}
	if in.KinesisParameters != nil {
		v.HasKinesis = true
		v.PartitionKey = value(in.KinesisParameters.PartitionKey)
	}
	if in.SageMakerPipelineParameters != nil {
		// TODO: Comeback connect SageMaker pipeline parameters to a genuine pipeline execution owner.
		return v, unsupported("SageMaker pipeline execution is not implemented.")
	}
	if in.EcsParameters != nil {
		p := in.EcsParameters
		e := &ECSTarget{
			TaskDefinitionARN: value(p.TaskDefinitionArn),
			Group:             value(p.Group),
			LaunchType:        value(p.LaunchType),
			PlatformVersion:   value(p.PlatformVersion),
			PropagateTags:     value(p.PropagateTags),
			ReferenceID:       value(p.ReferenceId),
			HasTaskCount:      p.TaskCount != nil,
			TaskCount:         1,
			HasManagedTags:    p.EnableECSManagedTags != nil,
			HasExecuteCommand: p.EnableExecuteCommand != nil,
		}
		if p.TaskCount != nil {
			e.TaskCount = int(*p.TaskCount)
		}
		if p.EnableECSManagedTags != nil {
			e.ManagedTags = bool(*p.EnableECSManagedTags)
		}
		if p.EnableExecuteCommand != nil {
			e.ExecuteCommand = bool(*p.EnableExecuteCommand)
		}
		if p.NetworkConfiguration != nil && p.NetworkConfiguration.AwsvpcConfiguration != nil {
			e.HasNetwork = true
			n := p.NetworkConfiguration.AwsvpcConfiguration
			e.AssignPublicIP = value(n.AssignPublicIp)
			for _, x := range n.Subnets {
				e.Subnets = append(e.Subnets, string(x))
			}
			for _, x := range n.SecurityGroups {
				e.SecurityGroups = append(e.SecurityGroups, string(x))
			}
		}
		for _, x := range p.CapacityProviderStrategy {
			c := CapacityProvider{
				Name:      value(x.CapacityProvider),
				HasBase:   x.Base != nil,
				HasWeight: x.Weight != nil,
			}
			if x.Base != nil {
				c.Base = int(*x.Base)
			}
			if x.Weight != nil {
				c.Weight = int(*x.Weight)
			}
			e.Capacity = append(e.Capacity, c)
		}
		for _, x := range p.PlacementConstraints {
			e.Constraints = append(e.Constraints, PlacementConstraint{
				value(x.Type),
				value(x.Expression),
			})
		}
		for _, x := range p.PlacementStrategy {
			e.Placement = append(e.Placement, PlacementStrategy{
				value(x.Type),
				value(x.Field),
			})
		}
		for _, x := range p.Tags {
			for k, t := range x {
				e.Tags = append(e.Tags, Tag{
					string(k),
					string(t),
				})
			}
		}
		v.ECS = e
	}
	return v, nil
}

func targetOutput(v TargetRecord) *api.Target {
	out := &api.Target{
		Arn:     new(api.TargetArn(v.ARN)),
		RoleArn: new(api.RoleArn(v.RoleARN)),
		Input:   optional[api.TargetInput](v.Input, v.HasInput),
	}
	if v.DeadLetterARN != "" {
		out.DeadLetterConfig = &api.DeadLetterConfig{Arn: new(api.ResourceArn(v.DeadLetterARN))}
	}
	out.RetryPolicy = &api.RetryPolicy{
		MaximumEventAgeInSeconds: new(api.MaximumEventAgeInSeconds(v.MaxAgeSeconds)),
		MaximumRetryAttempts:     new(api.MaximumRetryAttempts(v.MaxRetries)),
	}
	if v.HasSQS {
		out.SqsParameters = &api.SqsParameters{MessageGroupId: optional[api.MessageGroupId](v.MessageGroupID, v.MessageGroupID != "")}
	}
	if v.HasEventBridge {
		out.EventBridgeParameters = &api.EventBridgeParameters{
			Source:     new(api.Source(v.EventSource)),
			DetailType: new(api.DetailType(v.EventDetailType)),
		}
	}
	if v.HasKinesis {
		out.KinesisParameters = &api.KinesisParameters{PartitionKey: new(api.TargetPartitionKey(v.PartitionKey))}
	}
	if v.ECS != nil {
		e := v.ECS
		p := &api.EcsParameters{
			TaskDefinitionArn: new(api.TaskDefinitionArn(e.TaskDefinitionARN)),
			Group:             optional[api.Group](e.Group, e.Group != ""),
			LaunchType:        optional[api.LaunchType](e.LaunchType, e.LaunchType != ""),
			PlatformVersion:   optional[api.PlatformVersion](e.PlatformVersion, e.PlatformVersion != ""),
			PropagateTags:     optional[api.PropagateTags](e.PropagateTags, e.PropagateTags != ""),
			ReferenceId:       optional[api.ReferenceId](e.ReferenceID, e.ReferenceID != ""),
		}
		if e.HasTaskCount {
			p.TaskCount = new(api.TaskCount(e.TaskCount))
		}
		if e.HasManagedTags {
			p.EnableECSManagedTags = new(api.EnableECSManagedTags(e.ManagedTags))
		}
		if e.HasExecuteCommand {
			p.EnableExecuteCommand = new(api.EnableExecuteCommand(e.ExecuteCommand))
		}
		if e.HasNetwork {
			n := &api.AwsVpcConfiguration{AssignPublicIp: optional[api.AssignPublicIp](e.AssignPublicIP, e.AssignPublicIP != "")}
			for _, x := range e.Subnets {
				n.Subnets = append(n.Subnets, api.Subnet(x))
			}
			for _, x := range e.SecurityGroups {
				n.SecurityGroups = append(n.SecurityGroups, api.SecurityGroup(x))
			}
			p.NetworkConfiguration = &api.NetworkConfiguration{AwsvpcConfiguration: n}
		}
		for _, x := range e.Capacity {
			c := api.CapacityProviderStrategyItem{CapacityProvider: new(api.CapacityProvider(x.Name))}
			if x.HasBase {
				c.Base = new(api.CapacityProviderStrategyItemBase(x.Base))
			}
			if x.HasWeight {
				c.Weight = new(api.CapacityProviderStrategyItemWeight(x.Weight))
			}
			p.CapacityProviderStrategy = append(p.CapacityProviderStrategy, c)
		}
		for _, x := range e.Constraints {
			p.PlacementConstraints = append(p.PlacementConstraints, api.PlacementConstraint{
				Type:       new(api.PlacementConstraintType(x.Type)),
				Expression: optional[api.PlacementConstraintExpression](x.Expression, x.Expression != ""),
			})
		}
		for _, x := range e.Placement {
			p.PlacementStrategy = append(p.PlacementStrategy, api.PlacementStrategy{
				Type:  new(api.PlacementStrategyType(x.Type)),
				Field: optional[api.PlacementStrategyField](x.Field, x.Field != ""),
			})
		}
		for _, x := range e.Tags {
			p.Tags = append(p.Tags, api.TagMap{api.TagKey(x.Key): api.TagValue(x.Value)})
		}
		out.EcsParameters = p
	}
	return out
}
