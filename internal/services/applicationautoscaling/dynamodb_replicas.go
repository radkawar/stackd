package applicationautoscaling

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/awsctx"
)

// DynamoDBReplicaScaling reads one table or index through the authorized,
// audited scaling commands. Configuration remains owned by this service.
func (s *Service) DynamoDBReplicaScaling(ctx context.Context, resource string) (api.ScalableTargets, api.ScalingPolicies, error) {
	var targets api.ScalableTargets
	targetInput := &api.DescribeScalableTargetsInput{
		ServiceNamespace: new(api.ServiceNamespaceDYNAMODB),
		ResourceIds:      api.ResourceIdsMaxLen1600{api.ResourceIdMaxLen1600(resource)},
	}
	for {
		out, rejected := runCommand(s, ctx, "DescribeScalableTargets", targetInput, s.describeScalableTargets)
		if rejected != nil {
			return nil, nil, rejected
		}
		targets = append(targets, out.ScalableTargets...)
		if out.NextToken == nil {
			break
		}
		targetInput.NextToken = out.NextToken
	}
	var policies api.ScalingPolicies
	policyInput := &api.DescribeScalingPoliciesInput{
		ServiceNamespace: targetInput.ServiceNamespace, ResourceId: new(api.ResourceIdMaxLen1600(resource)),
	}
	for {
		out, rejected := runCommand(s, ctx, "DescribeScalingPolicies", policyInput, s.describeScalingPolicies)
		if rejected != nil {
			return nil, nil, rejected
		}
		policies = append(policies, out.ScalingPolicies...)
		if out.NextToken == nil {
			break
		}
		policyInput.NextToken = out.NextToken
	}
	return targets, policies, nil
}

// CopyDynamoDBReplica requires write target-tracking policies for the table and
// its current GSIs, then installs registered read/write settings in the new
// Region. The supplied context is the source Region's replication-role session;
// all state, managed alarms and command events join replica admission atomically.
func (s *Service) CopyDynamoDBReplica(ctx context.Context, region string, resources []string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx = tx.Context()
		for _, action := range []string{"DescribeScalableTargets", "DescribeScalingPolicies"} {
			if err := s.authorize(ctx, action, "*", nil); err != nil {
				return err
			}
		}
		type configuration struct {
			target   TargetRecord
			policies []PolicyRecord
		}
		var settings []configuration
		for _, resource := range resources {
			kind := "table"
			if strings.Contains(resource, "/index/") {
				kind = "index"
			}
			for _, dimension := range []string{"Write", "Read"} {
				key := TargetKey{Scope: scopeFor(ctx), Namespace: "dynamodb", ResourceID: resource, Dimension: "dynamodb:" + kind + ":" + dimension + "CapacityUnits"}
				target, err := tx.Target(key)
				if errors.Is(err, ErrNotFound) {
					if dimension == "Read" {
						continue
					}
					return invalid("Write capacity must be auto scaled before adding a replica: " + resource)
				}
				if err != nil {
					return err
				}
				policies, err := tx.Policies(PolicyQuery{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
				if err != nil {
					return err
				}
				if dimension == "Write" && !slices.ContainsFunc(policies, dynamoDBTrackingPolicy) {
					return invalid("Write capacity must be auto scaled before adding a replica: " + resource)
				}
				settings = append(settings, configuration{target: target, policies: policies})
			}
		}
		metadata := awsctx.FromContext(ctx)
		metadata.Region = region
		regional := awsctx.WithMetadata(ctx, metadata)
		for _, setting := range settings {
			target := setting.target.Data
			input := &api.RegisterScalableTargetInput{
				ServiceNamespace: target.ServiceNamespace, ResourceId: target.ResourceId, ScalableDimension: target.ScalableDimension,
				MinCapacity: target.MinCapacity, MaxCapacity: target.MaxCapacity, RoleARN: target.RoleARN, SuspendedState: target.SuspendedState,
			}
			if _, rejected := runCommand(s, regional, "RegisterScalableTarget", input, s.registerScalableTarget); rejected != nil {
				return rejected
			}
			for _, policy := range setting.policies {
				input := &api.PutScalingPolicyInput{
					ServiceNamespace: target.ServiceNamespace, ResourceId: target.ResourceId, ScalableDimension: target.ScalableDimension,
					PolicyName: policy.Data.PolicyName, PolicyType: policy.Data.PolicyType,
					TargetTrackingScalingPolicyConfiguration: policy.Data.TargetTrackingScalingPolicyConfiguration,
				}
				if _, rejected := runCommand(s, regional, "PutScalingPolicy", input, s.putScalingPolicy); rejected != nil {
					return rejected
				}
			}
		}
		return nil
	})
}

// ConfigureDynamoDBReplica installs billing-transition defaults for one table
// or index. Existing target identities, tags and suspension flags survive;
// predefined policies are replaced with the replication service's defaults.
func (s *Service) ConfigureDynamoDBReplica(ctx context.Context, resource string, read, write, maximum int32) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx = tx.Context()
		kind := "table"
		if strings.Contains(resource, "/index/") {
			kind = "index"
		}
		for _, dimension := range []struct {
			name  string
			units int32
		}{{"Read", read}, {"Write", write}} {
			key := TargetKey{Scope: scopeFor(ctx), Namespace: "dynamodb", ResourceID: resource, Dimension: "dynamodb:" + kind + ":" + dimension.name + "CapacityUnits"}
			register := &api.RegisterScalableTargetInput{
				ServiceNamespace: new(api.ServiceNamespace(key.Namespace)), ResourceId: new(api.ResourceIdMaxLen1600(resource)),
				ScalableDimension: new(api.ScalableDimension(key.Dimension)), MinCapacity: new(api.ResourceCapacity(dimension.units)),
				MaxCapacity: new(api.ResourceCapacity(maximum)),
			}
			if _, rejected := runCommand(s, ctx, "RegisterScalableTarget", register, s.registerScalableTarget); rejected != nil {
				return rejected
			}
			metric := "DynamoDB" + dimension.name + "CapacityUtilization"
			name := metric + ":" + resource
			policy := &api.PutScalingPolicyInput{
				ServiceNamespace: register.ServiceNamespace, ResourceId: register.ResourceId, ScalableDimension: register.ScalableDimension,
				PolicyName: new(api.PolicyName(name)), PolicyType: new(api.PolicyTypeTargetTrackingScaling),
				TargetTrackingScalingPolicyConfiguration: &api.TargetTrackingScalingPolicyConfiguration{
					TargetValue:                   new(api.MetricScale(70)),
					PredefinedMetricSpecification: &api.PredefinedMetricSpecification{PredefinedMetricType: new(api.MetricType(metric))},
				},
			}
			if _, rejected := runCommand(s, ctx, "PutScalingPolicy", policy, s.putScalingPolicy); rejected != nil {
				return rejected
			}
		}
		return nil
	})
}

// ResetDynamoDBReplicaPolicies deletes the table/index policies on a switch to
// provisioned mode. The context carries the initiating caller via DynamoDB,
// unlike the replication-role context which later installs native defaults.
func (s *Service) ResetDynamoDBReplicaPolicies(ctx context.Context, resources []string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx = tx.Context()
		for _, resource := range resources {
			policies, err := tx.Policies(PolicyQuery{Scope: scopeFor(ctx), Namespace: "dynamodb", ResourceID: resource})
			if err != nil {
				return err
			}
			for _, policy := range policies {
				key := policy.Key
				input := &api.DeleteScalingPolicyInput{
					ServiceNamespace: new(api.ServiceNamespace(key.Namespace)), ResourceId: new(api.ResourceIdMaxLen1600(key.ResourceID)),
					ScalableDimension: new(api.ScalableDimension(key.Dimension)), PolicyName: new(api.ResourceIdMaxLen1600(key.Name)),
				}
				if _, rejected := runCommand(s, ctx, "DeleteScalingPolicy", input, s.deleteScalingPolicy); rejected != nil {
					return rejected
				}
			}
		}
		return nil
	})
}

// UpdateDynamoDBReplicaScaling applies an admitted DynamoDB setting through
// independent scaling commands: a later failure must not undo earlier effects.
// Register/Put use the replication role. Policy removal is owned by DynamoDB,
// attributed to its caller, and does not require that caller's public AS grants.
func (s *Service) UpdateDynamoDBReplicaScaling(caller, role context.Context, target *api.RegisterScalableTargetInput, policy *api.PutScalingPolicyInput) error {
	if _, rejected := runCommand(s, role, "RegisterScalableTarget", target, s.registerScalableTarget); rejected != nil {
		return rejected
	}
	key := TargetKey{Scope: scopeFor(caller), Namespace: "dynamodb", ResourceID: value(target.ResourceId), Dimension: value(target.ScalableDimension)}
	var policies []PolicyRecord
	if err := s.repository.View(caller, func(r Reader) error {
		var err error
		policies, err = r.Policies(PolicyQuery{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
		return err
	}); err != nil {
		return err
	}
	for _, prior := range policies {
		in := &api.DeleteScalingPolicyInput{
			ServiceNamespace: target.ServiceNamespace, ResourceId: target.ResourceId, ScalableDimension: target.ScalableDimension,
			PolicyName: new(api.ResourceIdMaxLen1600(prior.Key.Name)),
		}
		if _, rejected := runCommand(s, caller, "DeleteScalingPolicy", in, func(ctx context.Context, tx Transaction, _ *api.DeleteScalingPolicyInput) (*api.DeleteScalingPolicyOutput, error) {
			return s.deletePolicy(ctx, tx, prior.Key)
		}); rejected != nil {
			return rejected
		}
	}
	_, rejected := runCommand(s, role, "PutScalingPolicy", policy, s.putScalingPolicy)
	if rejected != nil {
		return rejected
	}
	return nil
}

// DisableDynamoDBReplicaScaling removes a target after the table owner admits
// UpdateTableReplicaAutoScaling. Its public AS permission is not the authority
// for this service-owned effect; the forwarded caller is retained for audit.
func (s *Service) DisableDynamoDBReplicaScaling(ctx context.Context, resource, dimension string) error {
	in := &api.DeregisterScalableTargetInput{
		ServiceNamespace: new(api.ServiceNamespaceDYNAMODB), ResourceId: new(api.ResourceIdMaxLen1600(resource)),
		ScalableDimension: new(api.ScalableDimension(dimension)),
	}
	_, rejected := runCommand(s, ctx, "DeregisterScalableTarget", in, func(ctx context.Context, tx Transaction, _ *api.DeregisterScalableTargetInput) (*api.DeregisterScalableTargetOutput, error) {
		key := TargetKey{Scope: scopeFor(ctx), Namespace: "dynamodb", ResourceID: resource, Dimension: dimension}
		target, err := tx.Target(key)
		if errors.Is(err, ErrNotFound) {
			return nil, failure("ObjectNotFoundException", "Scalable target not found")
		}
		if err != nil {
			return nil, err
		}
		if err := s.removeTarget(ctx, tx, target); err != nil {
			return nil, err
		}
		return &api.DeregisterScalableTargetOutput{}, nil
	})
	if rejected != nil && rejected.Code != "ObjectNotFoundException" {
		return rejected
	}
	return nil
}
