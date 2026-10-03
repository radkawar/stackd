package applicationautoscaling

import (
	"context"
	"time"

	cw "stackd/internal/awsapi/cloudwatch"
)

// Target tracking favors availability: any policy can scale out, but every
// scale-in-enabled policy must agree before capacity falls. Step scaling does
// not participate in this target-tracking-only veto.
func (s *Service) trackingScaleIn(ctx context.Context, policies []PolicyRecord, current PolicyRecord, capacity Capacity, proposed float64) (float64, bool, error) {
	var names cw.AlarmNames
	for _, policy := range policies {
		if policy.Key == current.Key || policy.Data.TargetTrackingScalingPolicyConfiguration == nil || scaleInDisabled(policy) {
			continue
		}
		names = append(names, cw.AlarmName(*policy.Data.Alarms[1].AlarmName))
	}
	if len(names) == 0 {
		return proposed, true, nil
	}
	states := make(map[string]cw.MetricAlarm, len(names))
	for start := 0; start < len(names); start += 100 {
		out, err := s.alarms.Describe(ctx, &cw.DescribeAlarmsInput{AlarmNames: names[start:min(start+100, len(names))]})
		if err != nil {
			return 0, false, err
		}
		for _, alarm := range out.MetricAlarms {
			states[value(alarm.AlarmName)] = alarm
		}
	}
	for _, policy := range policies {
		if policy.Key == current.Key || policy.Data.TargetTrackingScalingPolicyConfiguration == nil || scaleInDisabled(policy) {
			continue
		}
		alarm, exists := states[value(policy.Data.Alarms[1].AlarmName)]
		if !exists || value(alarm.StateValue) != "ALARM" {
			return 0, false, nil
		}
		if !policy.LastScaleAt.IsZero() && policy.LastScaleTo < policy.LastScaleFrom && s.clock.Now().Before(policy.LastScaleAt.Add(policyCooldown(policy, false))) {
			return 0, false, nil
		}
		metric, present, err := s.trackingMetric(ctx, alarm)
		if err != nil || !present {
			return 0, false, err
		}
		proposed = max(proposed, trackingCapacity(policy.Data.TargetTrackingScalingPolicyConfiguration, capacity.Running, trackingMetricValue(policy, capacity.Running, metric)))
	}
	return proposed, proposed < float64(capacity.Running), nil
}

// DescribeAlarms retains the original transition's reason data while ALARM
// persists. Query the real metric engine instead of treating that old snapshot
// as a current measurement or substituting zero for missing observations.
func (s *Service) trackingMetric(ctx context.Context, alarm cw.MetricAlarm) (float64, bool, error) {
	queries := alarm.Metrics
	period := int32(60)
	if alarm.Period != nil {
		period = int32(*alarm.Period)
	}
	if len(queries) == 0 {
		statistic := value(alarm.Statistic)
		if alarm.ExtendedStatistic != nil {
			statistic = string(*alarm.ExtendedStatistic)
		}
		queries = cw.MetricDataQueries{{Id: new(cw.MetricId("value")), ReturnData: new(cw.ReturnData(true)), MetricStat: &cw.MetricStat{Metric: &cw.Metric{Namespace: alarm.Namespace, MetricName: alarm.MetricName, Dimensions: alarm.Dimensions}, Period: new(cw.Period(period)), Stat: new(cw.Stat(statistic)), Unit: alarm.Unit}}}
	} else {
		for _, query := range queries {
			if query.Period != nil {
				period = int32(*query.Period)
				break
			}
			if query.MetricStat != nil {
				period = int32(*query.MetricStat.Period)
			}
		}
	}
	end := s.clock.Now()
	count := int(*alarm.EvaluationPeriods)
	start := end.Add(-time.Duration(count+2) * time.Duration(period) * time.Second)
	out, err := s.alarms.Query(ctx, &cw.GetMetricDataInput{StartTime: new(start), EndTime: new(end), MetricDataQueries: queries, ScanBy: new(cw.ScanByTIMESTAMP_DESCENDING)})
	if err != nil {
		return 0, false, err
	}
	for _, result := range out.MetricDataResults {
		if len(result.Values) == 0 {
			continue
		}
		count = min(count, len(result.Values))
		total := 0.0
		for _, value := range result.Values[:count] {
			total += float64(value)
		}
		return total / float64(count), true, nil
	}
	return 0, false, nil
}
