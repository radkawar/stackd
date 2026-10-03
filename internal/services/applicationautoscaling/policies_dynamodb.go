package applicationautoscaling

import (
	"context"
	"strings"

	cw "stackd/internal/awsapi/cloudwatch"
)

func dynamoDBTrackingPolicy(policy PolicyRecord) bool {
	config := policy.Data.TargetTrackingScalingPolicyConfiguration
	return policy.Key.Namespace == "dynamodb" && config != nil && config.PredefinedMetricSpecification != nil
}

func (s *Service) dynamoDBPolicyCapacity(ctx context.Context, policy *PolicyRecord) (float64, error) {
	if s.resources == nil {
		return 0, unsupported("DynamoDB target tracking requires its resource capacity provider")
	}
	service, err := s.identity.Context(ctx, policy.Key.TargetKey, "AutoScaling-ValidateScalingPolicy")
	if err != nil {
		return 0, err
	}
	capacity, err := s.resources.Capacity(service, policy.Key.TargetKey)
	return float64(capacity.Running), err
}

func dynamoDBPolicyAlarms(policy *PolicyRecord, current float64) []trackingAlarm {
	parts := strings.Split(policy.Key.ResourceID, "/")
	dimensions := cw.Dimensions{{Name: new(cw.DimensionName("TableName")), Value: new(cw.DimensionValue(parts[1]))}}
	if len(parts) == 4 {
		dimensions = append(dimensions, cw.Dimension{Name: new(cw.DimensionName("GlobalSecondaryIndexName")), Value: new(cw.DimensionValue(parts[3]))})
	}
	suffix := "WriteCapacityUnits"
	if strings.HasSuffix(policy.Key.Dimension, ":ReadCapacityUnits") {
		suffix = "ReadCapacityUnits"
	}
	target := float64(*policy.Data.TargetTrackingScalingPolicyConfiguration.TargetValue)
	consumed := cw.PutMetricAlarmInput{
		Namespace: new(cw.Namespace("AWS/DynamoDB")), MetricName: new(cw.MetricName("Consumed" + suffix)),
		Dimensions: dimensions, Statistic: new(cw.StatisticSum), Period: new(cw.Period(60)),
		EvaluationPeriods: new(cw.EvaluationPeriods(2)), Threshold: new(cw.Threshold(current * 60 * (target / 100))),
		ComparisonOperator: new(cw.ComparisonOperatorGreaterThanThreshold),
	}
	alarms := []trackingAlarm{{kind: "AlarmHigh", input: consumed}}
	if !scaleInDisabled(*policy) {
		low := consumed
		low.EvaluationPeriods = new(cw.EvaluationPeriods(15))
		low.ComparisonOperator = new(cw.ComparisonOperatorLessThanThreshold)
		low.Threshold = new(cw.Threshold(current * 60 * (trackingLowTarget(*policy) / 100)))
		alarms = append(alarms, trackingAlarm{kind: "AlarmLow", input: low})
	}
	provisioned := cw.PutMetricAlarmInput{
		Namespace: consumed.Namespace, MetricName: new(cw.MetricName("Provisioned" + suffix)), Dimensions: dimensions,
		Statistic: new(cw.StatisticAverage), Period: new(cw.Period(300)), EvaluationPeriods: new(cw.EvaluationPeriods(3)),
		Threshold: new(cw.Threshold(current)), ComparisonOperator: new(cw.ComparisonOperatorGreaterThanThreshold),
	}
	alarms = append(alarms, trackingAlarm{kind: "ProvisionedCapacityHigh", input: provisioned})
	provisioned.ComparisonOperator = new(cw.ComparisonOperatorLessThanThreshold)
	alarms = append(alarms, trackingAlarm{kind: "ProvisionedCapacityLow", input: provisioned})
	return alarms
}

// Provisioned-capacity alarms maintain the consumed-unit thresholds. They do
// not request another capacity change or create a scaling activity. Native
// maintenance replaces the alarm family while retaining the policy/action IDs.
func (s *Service) refreshDynamoDBAlarms(ctx context.Context, tx Transaction, policy *PolicyRecord, name string, threshold float64) (bool, error) {
	if !dynamoDBTrackingPolicy(*policy) {
		return false, nil
	}
	prefix := "TargetTracking-" + policy.Key.ResourceID + "-ProvisionedCapacity"
	if !strings.HasPrefix(name, prefix+"High-") && !strings.HasPrefix(name, prefix+"Low-") {
		return false, nil
	}
	for _, alarm := range policy.Data.Alarms {
		if value(alarm.AlarmName) == name {
			current, err := s.dynamoDBPolicyCapacity(ctx, policy)
			if err != nil || current == threshold {
				return true, err
			}
			if err := s.replacePolicyAlarms(ctx, policy, dynamoDBPolicyAlarms(policy, current)); err != nil {
				return true, err
			}
			return true, tx.PutPolicy(*policy)
		}
	}
	return true, nil // A replaced family's retained action cannot scale the table.
}

func (s *Service) refreshDynamoDBTargetAlarms(tx Transaction, key TargetKey, capacity int32) error {
	policies, err := tx.Policies(PolicyQuery{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
	if err != nil {
		return err
	}
	for _, policy := range policies {
		if !dynamoDBTrackingPolicy(policy) {
			continue
		}
		if err := s.replacePolicyAlarms(tx.Context(), &policy, dynamoDBPolicyAlarms(&policy, float64(capacity))); err != nil {
			return err
		}
		if err := tx.PutPolicy(policy); err != nil {
			return err
		}
	}
	return nil
}

func trackingLowTarget(policy PolicyRecord) float64 {
	target := float64(*policy.Data.TargetTrackingScalingPolicyConfiguration.TargetValue)
	if dynamoDBTrackingPolicy(policy) {
		return target - 20
	}
	return target * 0.9
}

func trackingMetricValue(policy PolicyRecord, running int32, metric float64) float64 {
	if dynamoDBTrackingPolicy(policy) {
		// Resource admission owns the positive provisioned-capacity invariant.
		return metric * 100 / (60 * float64(running))
	}
	return metric
}
