package applicationautoscaling

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/applicationautoscaling"
)

func (s *Service) putScalingPolicy(ctx context.Context, tx Transaction, in *api.PutScalingPolicyInput) (*api.PutScalingPolicyOutput, error) {
	key, err := keyFor(ctx, value(in.ServiceNamespace), value(in.ResourceId), value(in.ScalableDimension))
	if err != nil {
		return nil, err
	}
	target, err := s.requireTarget(ctx, tx, key, "PutScalingPolicy")
	if err != nil {
		return nil, err
	}
	policyKey := PolicyKey{TargetKey: key, Name: value(in.PolicyName)}
	record, err := tx.Policy(policyKey)
	creating := errors.Is(err, ErrNotFound)
	if err != nil && !creating {
		return nil, err
	}
	if creating {
		if in.PolicyType == nil {
			return nil, invalid("PolicyType must be specified")
		}
		arn := "arn:" + key.Partition + ":autoscaling:" + key.Region + ":" + key.AccountID + ":scalingPolicy:" + target.ID + ":resource/" + key.Namespace + "/" + key.ResourceID + ":policyName/" + policyKey.Name
		record = PolicyRecord{Key: policyKey, Data: api.ScalingPolicy{CreationTime: new(s.clock.Now().UTC().Truncate(time.Millisecond)), PolicyARN: new(api.ResourceIdMaxLen1600(arn)), PolicyName: in.PolicyName, PolicyType: in.PolicyType, ResourceId: in.ResourceId, ServiceNamespace: in.ServiceNamespace, ScalableDimension: in.ScalableDimension, Alarms: api.Alarms{}}}
	} else if in.PolicyType != nil && *in.PolicyType != *record.Data.PolicyType {
		return nil, invalid("The policy type cannot be changed for an existing scaling policy")
	}
	switch value(record.Data.PolicyType) {
	case "StepScaling":
		if key.Namespace == "dynamodb" {
			return nil, invalid("Step scaling is not supported for DynamoDB")
		}
		if in.TargetTrackingScalingPolicyConfiguration != nil || in.PredictiveScalingPolicyConfiguration != nil {
			return nil, invalid("Specify only the configuration for the selected policy type")
		}
		config, err := mergeStepPolicy(record.Data.StepScalingPolicyConfiguration, in.StepScalingPolicyConfiguration)
		if err != nil {
			return nil, err
		}
		record.Data.StepScalingPolicyConfiguration = config
	case "TargetTrackingScaling":
		if in.StepScalingPolicyConfiguration != nil || in.PredictiveScalingPolicyConfiguration != nil {
			return nil, invalid("Specify only the configuration for the selected policy type")
		}
		config, err := mergeTrackingPolicy(record.Data.TargetTrackingScalingPolicyConfiguration, in.TargetTrackingScalingPolicyConfiguration)
		if err != nil {
			return nil, err
		}
		if err := s.validateTrackingMetric(ctx, tx, policyKey, config); err != nil {
			return nil, err
		}
		replaceAlarms := !dynamoDBTrackingPolicy(record) || !reflect.DeepEqual(record.Data.TargetTrackingScalingPolicyConfiguration, config)
		record.Data.TargetTrackingScalingPolicyConfiguration = config
		if record.ManagedActionID == "" {
			record.ManagedActionID = uuid.NewString()
		}
		// An unchanged DynamoDB policy does not synchronously reset its
		// capacity thresholds; source maintenance owns those transitions.
		if replaceAlarms {
			if err := s.putPolicyAlarms(ctx, &record); err != nil {
				return nil, err
			}
		}
	case "PredictiveScaling":
		if in.PredictiveScalingPolicyConfiguration == nil {
			return nil, invalid("PredictiveScalingPolicyConfiguration must be specified")
		}
		// TODO: Comeback implement predictive forecasts and their scaling execution.
		return nil, unsupported("Predictive scaling requires a forecast implementation")
	default:
		return nil, invalid("Unsupported policy type")
	}
	if err := tx.PutPolicy(record); err != nil {
		return nil, err
	}
	return &api.PutScalingPolicyOutput{PolicyARN: record.Data.PolicyARN, Alarms: record.Data.Alarms}, nil
}

func (s *Service) describeScalingPolicies(ctx context.Context, tx Transaction, in *api.DescribeScalingPoliciesInput) (*api.DescribeScalingPoliciesOutput, error) {
	namespace, dimension, resource := value(in.ServiceNamespace), value(in.ScalableDimension), value(in.ResourceId)
	if err := validateTargetFilter(namespace, dimension); err != nil {
		return nil, err
	}
	if dimension != "" && resource == "" {
		return nil, invalid("ResourceId must be specified when ScalableDimension is specified")
	}
	if resource != "" && !validResource(namespace, resource, dimension) {
		return nil, invalid("Unsupported resource ID")
	}
	query := PolicyQuery{Scope: scopeFor(ctx), Namespace: namespace, ResourceID: resource, Dimension: dimension, Names: listStrings(in.PolicyNames)}
	page, err := newListPage[ListCursor](listPageQuery{Operation: "DescribeScalingPolicies", Key: TargetKey{Scope: query.Scope, Namespace: namespace, ResourceID: resource, Dimension: dimension}, Names: query.Names}, in.MaxResults, in.NextToken)
	if err != nil {
		return nil, err
	}
	query.Limit, query.From = page.readLimit, page.token.Cursor
	if err := s.authorize(ctx, "DescribeScalingPolicies", "*", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeScalingPoliciesOutput{ScalingPolicies: api.ScalingPolicies{}}
	if page.limit == 0 {
		return out, nil
	}
	rows, err := tx.Policies(query)
	if err != nil {
		return nil, err
	}
	if len(rows) > page.limit {
		next := rows[page.limit].Key
		out.NextToken = page.next(listCursor(next.TargetKey, next.Name))
		rows = rows[:page.limit]
	}
	for _, row := range rows {
		out.ScalingPolicies = append(out.ScalingPolicies, row.Data)
	}
	return out, nil
}

func (s *Service) deleteScalingPolicy(ctx context.Context, tx Transaction, in *api.DeleteScalingPolicyInput) (*api.DeleteScalingPolicyOutput, error) {
	key, err := keyFor(ctx, value(in.ServiceNamespace), value(in.ResourceId), value(in.ScalableDimension))
	if err != nil {
		return nil, err
	}
	if _, err := s.requireTarget(ctx, tx, key, "DeleteScalingPolicy"); err != nil {
		return nil, err
	}
	policyKey := PolicyKey{TargetKey: key, Name: value(in.PolicyName)}
	return s.deletePolicy(ctx, tx, policyKey)
}

func (s *Service) deletePolicy(ctx context.Context, tx Transaction, key PolicyKey) (*api.DeleteScalingPolicyOutput, error) {
	record, err := tx.Policy(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ObjectNotFoundException", "Scaling policy not found")
	}
	if err != nil {
		return nil, err
	}
	if len(record.Data.Alarms) != 0 {
		if err := s.deleteManagedAlarms(ctx, key.TargetKey, managedAlarmNames(record.Data.Alarms)); err != nil {
			return nil, err
		}
	}
	if err := tx.DeletePolicy(key); err != nil {
		return nil, err
	}
	return &api.DeleteScalingPolicyOutput{}, nil
}
