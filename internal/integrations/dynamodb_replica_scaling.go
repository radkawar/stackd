package integrations

import (
	"context"
	"errors"
	"math"

	"stackd/internal/apievents"
	aasapi "stackd/internal/awsapi/applicationautoscaling"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/dynamodb"
)

// DescribeReplica fills scaling settings without retaining a second copy in
// DynamoDB. The table owner supplies membership, lifecycle and billing mode.
func (a *ApplicationScaling) DescribeReplica(ctx context.Context, key dynamodb.TableKey, out *api.ReplicaAutoScalingDescription, onDemand bool) error {
	resource := "table/" + key.Name
	read, write, err := a.replicaScalingSettings(ctx, resource, "table", onDemand)
	if err != nil {
		return err
	}
	out.ReplicaProvisionedReadCapacityAutoScalingSettings, out.ReplicaProvisionedWriteCapacityAutoScalingSettings = read, write
	for i := range out.GlobalSecondaryIndexes {
		index := &out.GlobalSecondaryIndexes[i]
		read, write, err := a.replicaScalingSettings(ctx, resource+"/index/"+string(*index.IndexName), "index", onDemand)
		if err != nil {
			return err
		}
		index.ProvisionedReadCapacityAutoScalingSettings, index.ProvisionedWriteCapacityAutoScalingSettings = read, write
	}
	return nil
}

func (a *ApplicationScaling) replicaScalingSettings(ctx context.Context, resource, kind string, onDemand bool) (*api.AutoScalingSettingsDescription, *api.AutoScalingSettingsDescription, error) {
	targets, policies, err := a.Scaling.DynamoDBReplicaScaling(ctx, resource)
	if err != nil {
		return nil, nil, err
	}
	project := func(dimension string) *api.AutoScalingSettingsDescription {
		out := &api.AutoScalingSettingsDescription{AutoScalingDisabled: new(api.BooleanObject(true)), ScalingPolicies: api.AutoScalingPolicyDescriptionList{}}
		for _, policy := range policies {
			if string(*policy.ScalableDimension) != dimension || policy.TargetTrackingScalingPolicyConfiguration == nil {
				continue
			}
			config := policy.TargetTrackingScalingPolicyConfiguration
			out.ScalingPolicies = append(out.ScalingPolicies, api.AutoScalingPolicyDescription{
				PolicyName: (*api.AutoScalingPolicyName)(policy.PolicyName),
				TargetTrackingScalingPolicyConfiguration: &api.AutoScalingTargetTrackingScalingPolicyConfigurationDescription{
					DisableScaleIn:  (*api.BooleanObject)(config.DisableScaleIn),
					ScaleInCooldown: (*api.IntegerObject)(config.ScaleInCooldown), ScaleOutCooldown: (*api.IntegerObject)(config.ScaleOutCooldown),
					TargetValue: (*api.DoubleObject)(config.TargetValue),
				},
			})
		}
		if len(out.ScalingPolicies) == 0 {
			return out
		}
		for _, target := range targets {
			if string(*target.ScalableDimension) != dimension {
				continue
			}
			out.AutoScalingRoleArn = (*api.String)(target.RoleARN)
			out.MinimumUnits, out.MaximumUnits = new(api.PositiveLongObject(*target.MinCapacity)), new(api.PositiveLongObject(*target.MaxCapacity))
			if !onDemand {
				out.AutoScalingDisabled = nil
			}
			break
		}
		return out
	}
	return project("dynamodb:" + kind + ":ReadCapacityUnits"), project("dynamodb:" + kind + ":WriteCapacityUnits"), nil
}

// UpdateReplica maps the admitted DynamoDB setting into the scaling owner's
// commands. No target identity, policy, alarm or configuration is copied here.
func (a *ApplicationScaling) UpdateReplica(caller, role context.Context, key dynamodb.TableKey, index string, read bool, update *api.AutoScalingSettingsUpdate) error {
	resource, kind, direction := "table/"+key.Name, "table", "Write"
	if index != "" {
		resource, kind = resource+"/index/"+index, "index"
	}
	if read {
		direction = "Read"
	}
	dimension := "dynamodb:" + kind + ":" + direction + "CapacityUnits"
	caller = replicaScalingCaller(caller, key)
	if update.AutoScalingDisabled != nil && bool(*update.AutoScalingDisabled) {
		return replicaScalingError(a.Scaling.DisableDynamoDBReplicaScaling(caller, resource, dimension))
	}
	if *update.MinimumUnits > math.MaxInt32 || *update.MaximumUnits > math.MaxInt32 {
		return &awswire.Error{Code: "ValidationException", Message: "Capacity is outside the Application Auto Scaling integer range.", StatusCode: 400}
	}
	target := &aasapi.RegisterScalableTargetInput{
		ServiceNamespace: new(aasapi.ServiceNamespaceDYNAMODB), ResourceId: new(aasapi.ResourceIdMaxLen1600(resource)),
		ScalableDimension: new(aasapi.ScalableDimension(dimension)),
		MinCapacity:       new(aasapi.ResourceCapacity(*update.MinimumUnits)), MaxCapacity: new(aasapi.ResourceCapacity(*update.MaximumUnits)),
		RoleARN: (*aasapi.ResourceIdMaxLen1600)(update.AutoScalingRoleArn),
	}
	metric := "DynamoDB" + direction + "CapacityUtilization"
	name := metric + ":" + resource
	if update.ScalingPolicyUpdate.PolicyName != nil {
		name = string(*update.ScalingPolicyUpdate.PolicyName)
	}
	config := update.ScalingPolicyUpdate.TargetTrackingScalingPolicyConfiguration
	policy := &aasapi.PutScalingPolicyInput{
		ServiceNamespace: target.ServiceNamespace, ResourceId: target.ResourceId, ScalableDimension: target.ScalableDimension,
		PolicyName: new(aasapi.PolicyName(name)), PolicyType: new(aasapi.PolicyTypeTargetTrackingScaling),
		TargetTrackingScalingPolicyConfiguration: &aasapi.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &aasapi.PredefinedMetricSpecification{PredefinedMetricType: new(aasapi.MetricType(metric))},
			DisableScaleIn:                (*aasapi.DisableScaleIn)(config.DisableScaleIn),
			ScaleInCooldown:               (*aasapi.Cooldown)(config.ScaleInCooldown), ScaleOutCooldown: (*aasapi.Cooldown)(config.ScaleOutCooldown),
			TargetValue: (*aasapi.MetricScale)(config.TargetValue),
		},
	}
	return replicaScalingError(a.Scaling.UpdateDynamoDBReplicaScaling(caller, role, target, policy))
}

func replicaScalingCaller(ctx context.Context, key dynamodb.TableKey) context.Context {
	ctx = awsctx.WithViaService(ctx, "dynamodb.amazonaws.com")
	metadata := awsctx.FromContext(ctx)
	metadata.Region, metadata.ParentEventID = key.Region, apievents.EventID(ctx)
	metadata.InvokedBy = "dynamodb.amazonaws.com"
	metadata.SourceIP, metadata.UserAgent = metadata.InvokedBy, metadata.InvokedBy
	return awsctx.WithMetadata(ctx, metadata)
}

func replicaScalingError(err error) error {
	var rejected *awswire.Error
	if errors.As(err, &rejected) && rejected.StatusCode >= 400 && rejected.StatusCode < 500 {
		return &awswire.Error{Code: "ValidationException", Message: rejected.Message, StatusCode: 400}
	}
	return err
}
