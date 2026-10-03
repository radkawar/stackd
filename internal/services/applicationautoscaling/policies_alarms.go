package applicationautoscaling

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/applicationautoscaling"
	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func forwardedCaller(ctx context.Context) context.Context {
	ctx = awsctx.WithViaService(ctx, "application-autoscaling.amazonaws.com")
	metadata := awsctx.FromContext(ctx)
	metadata.ParentEventID = apievents.EventID(ctx)
	metadata.InvokedBy = "application-autoscaling.amazonaws.com"
	metadata.SourceIP, metadata.UserAgent = metadata.InvokedBy, metadata.InvokedBy
	return awsctx.WithMetadata(ctx, metadata)
}

func accessDenied(err error) bool {
	var rejected *awswire.Error
	return errors.As(err, &rejected) && (rejected.StatusCode == 403 || rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException")
}

func (s *Service) putPolicyAlarms(ctx context.Context, record *PolicyRecord) error {
	inputs, err := s.trackingPolicyAlarms(ctx, record)
	if err != nil {
		return err
	}
	return s.replacePolicyAlarms(ctx, record, inputs)
}

func (s *Service) replacePolicyAlarms(ctx context.Context, record *PolicyRecord, inputs []trackingAlarm) error {
	action := value(record.Data.PolicyARN) + ":createdBy/" + record.ManagedActionID
	alarms := make(api.Alarms, 0, len(inputs))
	forwarded := forwardedCaller(ctx)
	var fallback context.Context
	for _, alarm := range inputs {
		input := alarm.input
		input.ActionsEnabled = new(cw.ActionsEnabled(true))
		input.AlarmActions = cw.ResourceList{cw.ResourceName(action)}
		input.AlarmDescription = new(cw.AlarmDescription("DO NOT EDIT OR DELETE. For TargetTrackingScaling policy " + action + "."))
		// Native policy updates replace the managed alarm identities, while the
		// policy ARN, creation time and createdBy identity remain stable.
		name := "TargetTracking-" + record.Key.ResourceID + "-" + alarm.kind + "-" + uuid.NewString()
		input.AlarmName = new(cw.AlarmName(name))
		err := s.alarms.Put(forwarded, &input)
		if accessDenied(err) {
			if fallback == nil {
				fallback, err = s.identity.Context(ctx, record.Key.TargetKey, "AutoScaling-ValidateScalingPolicy")
				if err != nil {
					return err
				}
			}
			err = s.alarms.Put(fallback, &input)
		}
		if err != nil {
			return alarmConfigurationError(err)
		}
		arn := "arn:" + record.Key.Partition + ":cloudwatch:" + record.Key.Region + ":" + record.Key.AccountID + ":alarm:" + name
		alarms = append(alarms, api.Alarm{AlarmName: new(api.ResourceId(name)), AlarmARN: new(api.ResourceId(arn))})
	}
	if len(record.Data.Alarms) != 0 {
		names := managedAlarmNames(record.Data.Alarms)
		err := s.alarms.Delete(forwarded, names)
		if accessDenied(err) {
			err = s.deleteManagedAlarms(ctx, record.Key.TargetKey, names)
		}
		if err != nil {
			return err
		}
	}
	record.Data.Alarms = alarms
	return nil
}

type trackingAlarm struct {
	kind  string
	input cw.PutMetricAlarmInput
}

func (s *Service) trackingPolicyAlarms(ctx context.Context, record *PolicyRecord) ([]trackingAlarm, error) {
	if dynamoDBTrackingPolicy(*record) {
		capacity, err := s.dynamoDBPolicyCapacity(ctx, record)
		if err != nil {
			return nil, err
		}
		return dynamoDBPolicyAlarms(record, capacity), nil
	}
	config := record.Data.TargetTrackingScalingPolicyConfiguration
	high := trackingAlarmMetric(record.Key.TargetKey, config)
	high.Threshold = new(cw.Threshold(*config.TargetValue))
	high.ComparisonOperator = new(cw.ComparisonOperatorGreaterThanThreshold)
	high.EvaluationPeriods = new(cw.EvaluationPeriods(3))
	if record.Key.Namespace == "dynamodb" {
		high.EvaluationPeriods = new(cw.EvaluationPeriods(2))
	}
	inputs := []trackingAlarm{{kind: "AlarmHigh", input: high}}
	if !scaleInDisabled(*record) {
		low := high
		low.Threshold = new(cw.Threshold(trackingLowTarget(*record)))
		low.ComparisonOperator = new(cw.ComparisonOperatorLessThanThreshold)
		low.EvaluationPeriods = new(cw.EvaluationPeriods(15))
		if low.Period != nil && *low.Period == 20 {
			low.EvaluationPeriods = new(cw.EvaluationPeriods(30))
		}
		inputs = append(inputs, trackingAlarm{kind: "AlarmLow", input: low})
	}
	return inputs, nil
}

func trackingPredefinedMetric(predefined *api.PredefinedMetricSpecification) (string, cw.Period) {
	name, period := "CPUUtilization", cw.Period(60)
	metricType := value(predefined.PredefinedMetricType)
	if metricType == "ALBRequestCountPerTarget" {
		return "RequestCountPerTarget", period
	}
	if strings.Contains(metricType, "MemoryUtilization") {
		name = "MemoryUtilization"
	}
	if strings.HasSuffix(metricType, "HighResolution") {
		period = 20
	}
	return name, period
}

func trackingAlarmMetric(key TargetKey, config *api.TargetTrackingScalingPolicyConfiguration) cw.PutMetricAlarmInput {
	var out cw.PutMetricAlarmInput
	if predefined := config.PredefinedMetricSpecification; predefined != nil {
		name, period := trackingPredefinedMetric(predefined)
		out.Period = new(period)
		if value(predefined.PredefinedMetricType) == "ALBRequestCountPerTarget" {
			lb, group, _ := albResourceLabel(value(predefined.ResourceLabel))
			out.Namespace, out.MetricName, out.Statistic, out.Unit = new(cw.Namespace("AWS/ApplicationELB")), new(cw.MetricName(name)), new(cw.StatisticSum), new(cw.StandardUnitNone)
			out.Dimensions = cw.Dimensions{{Name: new(cw.DimensionName("LoadBalancer")), Value: new(cw.DimensionValue(lb))}, {Name: new(cw.DimensionName("TargetGroup")), Value: new(cw.DimensionValue(group))}}
			return out
		}
		parts := strings.SplitN(key.ResourceID, "/", 3)
		out.Namespace, out.MetricName, out.Statistic, out.Unit = new(cw.Namespace("AWS/ECS")), new(cw.MetricName(name)), new(cw.StatisticAverage), new(cw.StandardUnitPercent)
		out.Dimensions = cw.Dimensions{{Name: new(cw.DimensionName("ClusterName")), Value: new(cw.DimensionValue(parts[1]))}, {Name: new(cw.DimensionName("ServiceName")), Value: new(cw.DimensionValue(parts[2]))}}
		return out
	}
	custom := config.CustomizedMetricSpecification
	if custom.Metrics != nil {
		out.Metrics = trackingMetricQueries(custom.Metrics)
		return out
	}
	out.Period = new(cw.Period(60))
	out.Namespace, out.MetricName, out.Statistic, out.Unit = (*cw.Namespace)(custom.Namespace), (*cw.MetricName)(custom.MetricName), (*cw.Statistic)(custom.Statistic), (*cw.StandardUnit)(custom.Unit)
	if custom.Dimensions != nil {
		out.Dimensions = make(cw.Dimensions, 0, len(custom.Dimensions))
		for _, dimension := range custom.Dimensions {
			out.Dimensions = append(out.Dimensions, cw.Dimension{Name: (*cw.DimensionName)(dimension.Name), Value: (*cw.DimensionValue)(dimension.Value)})
		}
	}
	return out
}

func trackingMetricQueries(input api.TargetTrackingMetricDataQueries) cw.MetricDataQueries {
	out := make(cw.MetricDataQueries, 0, len(input))
	for _, query := range input {
		mapped := cw.MetricDataQuery{Id: (*cw.MetricId)(query.Id), Expression: (*cw.MetricExpression)(query.Expression), Label: (*cw.MetricLabel)(query.Label), ReturnData: (*cw.ReturnData)(query.ReturnData)}
		if query.Expression != nil {
			mapped.Period = new(cw.Period(60))
		}
		if stat := query.MetricStat; stat != nil {
			mapped.MetricStat = &cw.MetricStat{Period: new(cw.Period(60)), Stat: (*cw.Stat)(stat.Stat), Unit: (*cw.StandardUnit)(stat.Unit)}
			if stat.Metric != nil {
				metric := &cw.Metric{Namespace: (*cw.Namespace)(stat.Metric.Namespace), MetricName: (*cw.MetricName)(stat.Metric.MetricName)}
				if stat.Metric.Dimensions != nil {
					metric.Dimensions = make(cw.Dimensions, 0, len(stat.Metric.Dimensions))
					for _, dimension := range stat.Metric.Dimensions {
						metric.Dimensions = append(metric.Dimensions, cw.Dimension{Name: (*cw.DimensionName)(dimension.Name), Value: (*cw.DimensionValue)(dimension.Value)})
					}
				}
				mapped.MetricStat.Metric = metric
			}
		}
		out = append(out, mapped)
	}
	return out
}

func managedAlarmNames(alarms api.Alarms) []string {
	names := make([]string, 0, len(alarms))
	for _, alarm := range alarms {
		names = append(names, value(alarm.AlarmName))
	}
	return names
}

func (s *Service) deleteManagedAlarms(ctx context.Context, key TargetKey, names []string) error {
	if s.alarms == nil || s.identity == nil {
		return unsupported("Managed alarm cleanup requires CloudWatch and the scaling service identity")
	}
	service, err := s.identity.Context(ctx, key, "AutoScaling-ManageAlarms")
	if err != nil {
		return err
	}
	return s.alarms.Delete(service, names)
}

func alarmConfigurationError(err error) error {
	var rejected *awswire.Error
	if errors.As(err, &rejected) {
		switch rejected.Code {
		case "ValidationError", "InvalidParameterValue", "MissingParameter":
			return failure("FailedResourceAccessException", rejected.Message)
		}
	}
	return err
}
