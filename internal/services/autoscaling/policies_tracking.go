package autoscaling

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/autoscaling"
	cw "stackd/internal/awsapi/cloudwatch"
)

func validateTracking(c *api.TargetTrackingConfiguration) error {
	if c == nil || c.TargetValue == nil || !finiteMetric(float64(*c.TargetValue)) || *c.TargetValue <= 0 {
		return invalid("TargetTrackingConfiguration requires a positive finite TargetValue")
	}
	if (c.PredefinedMetricSpecification == nil) == (c.CustomizedMetricSpecification == nil) {
		return invalid("Exactly one predefined or customized metric specification is required")
	}
	if p := c.PredefinedMetricSpecification; p != nil {
		switch value(p.PredefinedMetricType) {
		case "ASGAverageCPUUtilization", "ASGAverageNetworkIn", "ASGAverageNetworkOut":
			if p.ResourceLabel != nil {
				return invalid("ResourceLabel is valid only for ALBRequestCountPerTarget")
			}
		case "ALBRequestCountPerTarget":
			parts := strings.Split(value(p.ResourceLabel), "/")
			if len(parts) != 6 || parts[0] != "app" || parts[3] != "targetgroup" || parts[1] == "" || parts[2] == "" || parts[4] == "" || parts[5] == "" {
				return invalid("ALBRequestCountPerTarget requires an application load balancer and target group ResourceLabel")
			}
		default:
			return unsupported("The predefined target tracking metric is not implemented")
		}
		return nil
	}
	cst := c.CustomizedMetricSpecification
	if len(cst.Metrics) > 0 {
		return unsupported("Target tracking metric math queries are not implemented")
	}
	if value(cst.Namespace) == "" || value(cst.MetricName) == "" {
		return invalid("A customized metric requires Namespace and MetricName")
	}
	switch value(cst.Statistic) {
	case "Average", "Minimum", "Maximum", "Sum", "SampleCount":
	default:
		return invalid("A customized metric requires a supported Statistic")
	}
	if cst.Period != nil && *cst.Period != 10 && *cst.Period != 20 && *cst.Period != 30 && (*cst.Period < 60 || *cst.Period%60 != 0) {
		return invalid("The customized metric period must be 10, 20, 30, or a multiple of 60 seconds")
	}
	seen := map[string]bool{}
	for _, d := range cst.Dimensions {
		if value(d.Name) == "" || value(d.Value) == "" || seen[value(d.Name)] {
			return invalid("Customized metric dimensions require unique names and nonempty values")
		}
		seen[value(d.Name)] = true
	}
	return nil
}

// Metric ownership excludes target values and scaling controls. Dimension
// order is not identity, and comparisons borrow the persisted slices.
func sameTrackingMetric(a, b *api.TargetTrackingConfiguration) bool {
	if a == nil || b == nil {
		return false
	}
	if p := a.PredefinedMetricSpecification; p != nil {
		return b.PredefinedMetricSpecification != nil && value(p.PredefinedMetricType) == value(b.PredefinedMetricSpecification.PredefinedMetricType) && value(p.ResourceLabel) == value(b.PredefinedMetricSpecification.ResourceLabel)
	}
	left, right := a.CustomizedMetricSpecification, b.CustomizedMetricSpecification
	if left == nil || right == nil || value(left.Namespace) != value(right.Namespace) || value(left.MetricName) != value(right.MetricName) || value(left.Statistic) != value(right.Statistic) || len(left.Dimensions) != len(right.Dimensions) {
		return false
	}
	for _, dimension := range left.Dimensions {
		found := false
		for _, candidate := range right.Dimensions {
			if value(dimension.Name) == value(candidate.Name) && value(dimension.Value) == value(candidate.Value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func trackingAlarmMetric(g GroupRecord, c *api.TargetTrackingConfiguration) (cw.PutMetricAlarmInput, error) {
	out := cw.PutMetricAlarmInput{Period: new(cw.Period(60))}
	if p := c.PredefinedMetricSpecification; p != nil {
		out.Namespace = new(cw.Namespace("AWS/EC2"))
		out.Statistic = new(cw.StatisticAverage)
		out.Dimensions = cw.Dimensions{{Name: new(cw.DimensionName("AutoScalingGroupName")), Value: new(cw.DimensionValue(g.Key.Name))}}
		switch value(p.PredefinedMetricType) {
		case "ASGAverageCPUUtilization":
			out.MetricName = new(cw.MetricName("CPUUtilization"))
			out.Unit = new(cw.StandardUnitPercent)
		case "ASGAverageNetworkIn":
			out.MetricName = new(cw.MetricName("NetworkIn"))
			out.Unit = new(cw.StandardUnitBytes)
		case "ASGAverageNetworkOut":
			out.MetricName = new(cw.MetricName("NetworkOut"))
			out.Unit = new(cw.StandardUnitBytes)
		case "ALBRequestCountPerTarget":
			parts := strings.Split(value(p.ResourceLabel), "/")
			target := strings.Join(parts[3:], "/")
			attached := false
			for _, resource := range g.Data.TargetGroupARNs {
				if strings.HasSuffix(string(resource), ":"+target) {
					attached = true
					break
				}
			}
			if !attached {
				return out, invalid("The target tracking target group must be attached to the Auto Scaling group")
			}
			out.Namespace = new(cw.Namespace("AWS/ApplicationELB"))
			out.MetricName = new(cw.MetricName("RequestCountPerTarget"))
			out.Statistic = new(cw.StatisticSum)
			out.Dimensions = cw.Dimensions{{Name: new(cw.DimensionName("LoadBalancer")), Value: new(cw.DimensionValue(strings.Join(parts[:3], "/")))}, {Name: new(cw.DimensionName("TargetGroup")), Value: new(cw.DimensionValue(target))}}
		}
		return out, nil
	}
	custom := c.CustomizedMetricSpecification
	out.Namespace = (*cw.Namespace)(custom.Namespace)
	out.MetricName = (*cw.MetricName)(custom.MetricName)
	out.Statistic = (*cw.Statistic)(custom.Statistic)
	out.Unit = (*cw.StandardUnit)(custom.Unit)
	if custom.Period != nil {
		out.Period = new(cw.Period(*custom.Period))
	}
	for _, d := range custom.Dimensions {
		out.Dimensions = append(out.Dimensions, cw.Dimension{Name: (*cw.DimensionName)(d.Name), Value: (*cw.DimensionValue)(d.Value)})
	}
	return out, nil
}

func trackingScaleInDisabled(p PolicyRecord) bool {
	return p.Data.TargetTrackingConfiguration != nil && p.Data.TargetTrackingConfiguration.DisableScaleIn != nil && bool(*p.Data.TargetTrackingConfiguration.DisableScaleIn)
}

func (s *Service) replaceTrackingAlarms(ctx context.Context, g GroupRecord, p *PolicyRecord) error {
	if s.alarms == nil || s.identity == nil {
		return unsupported("Target tracking requires CloudWatch and a current Auto Scaling service-linked role")
	}
	input, err := trackingAlarmMetric(g, p.Data.TargetTrackingConfiguration)
	if err != nil {
		return err
	}
	service, err := s.identity.Context(ctx, g)
	if err != nil {
		return err
	}
	input.ActionsEnabled = new(cw.ActionsEnabled(p.Data.Enabled == nil || bool(*p.Data.Enabled)))
	input.AlarmActions = cw.ResourceList{cw.ResourceName(value(p.Data.PolicyARN))}
	input.TreatMissingData = new(cw.TreatMissingData("missing"))
	input.AlarmDescription = new(cw.AlarmDescription("DO NOT EDIT OR DELETE. For TargetTrackingScaling policy " + value(p.Data.PolicyARN)))
	alarms := api.Alarms{}
	for _, direction := range []string{"AlarmHigh", "AlarmLow"} {
		if direction == "AlarmLow" && trackingScaleInDisabled(*p) {
			continue
		}
		input.Threshold = new(cw.Threshold(*p.Data.TargetTrackingConfiguration.TargetValue))
		input.ComparisonOperator = new(cw.ComparisonOperatorGreaterThanThreshold)
		input.EvaluationPeriods = new(cw.EvaluationPeriods(3))
		if direction == "AlarmLow" {
			input.Threshold = new(cw.Threshold(float64(*p.Data.TargetTrackingConfiguration.TargetValue) * 0.9))
			input.ComparisonOperator = new(cw.ComparisonOperatorLessThanThreshold)
			input.EvaluationPeriods = new(cw.EvaluationPeriods(15))
		}
		suffix := "-" + direction + "-" + uuid.NewString()
		groupName := g.Key.Name
		maximum := 255 - len("TargetTracking-") - len(suffix)
		if len(groupName) > maximum {
			groupName = groupName[:maximum]
			for !utf8.ValidString(groupName) {
				groupName = groupName[:len(groupName)-1]
			}
		}
		name := "TargetTracking-" + groupName + suffix
		input.AlarmName = new(cw.AlarmName(name))
		if err = s.alarms.Put(service, &input); err != nil {
			return err
		}
		resource := "arn:" + g.Key.Partition + ":cloudwatch:" + g.Key.Region + ":" + g.Key.AccountID + ":alarm:" + name
		alarms = append(alarms, api.Alarm{AlarmName: new(api.XmlStringMaxLen255(name)), AlarmARN: new(api.ResourceName(resource))})
	}
	if err = s.deletePolicyAlarms(ctx, g, *p); err != nil {
		return err
	}
	p.Data.Alarms = alarms
	return nil
}
func (s *Service) deletePolicyAlarms(ctx context.Context, g GroupRecord, p PolicyRecord) error {
	if value(p.Data.PolicyType) != "TargetTrackingScaling" || len(p.Data.Alarms) == 0 {
		return nil
	}
	if s.alarms == nil || s.identity == nil {
		return unsupported("Managed scaling alarm deletion is unavailable")
	}
	service, err := s.identity.Context(ctx, g)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(p.Data.Alarms))
	for _, a := range p.Data.Alarms {
		names = append(names, value(a.AlarmName))
	}
	return s.alarms.Delete(service, names)
}

// A low alarm may be retained long after its transition. Read the current
// metric engine, and require every enabled scale-in policy to be in ALARM.
func (s *Service) trackingScaleIn(ctx context.Context, tx Transaction, g GroupRecord, current PolicyRecord, base int32, proposed float64) (float64, bool, error) {
	policies, err := tx.Policies(g.Key)
	if err != nil {
		return 0, false, err
	}
	for _, p := range policies {
		if p.Key == current.Key || p.GroupID != g.ID || value(p.Data.PolicyType) != "TargetTrackingScaling" || trackingScaleInDisabled(p) || p.Data.Enabled != nil && !bool(*p.Data.Enabled) {
			continue
		}
		if len(p.Data.Alarms) < 2 {
			return 0, false, nil
		}
		out, err := s.alarms.Describe(ctx, &cw.DescribeAlarmsInput{AlarmNames: cw.AlarmNames{cw.AlarmName(value(p.Data.Alarms[1].AlarmName))}})
		if err != nil {
			return 0, false, err
		}
		if len(out.MetricAlarms) != 1 || value(out.MetricAlarms[0].StateValue) != "ALARM" {
			return 0, false, nil
		}
		metric, present, err := s.currentTrackingMetric(ctx, g, p)
		if err != nil || !present {
			return 0, false, err
		}
		proposed = max(proposed, trackingCapacity(base, metric, float64(*p.Data.TargetTrackingConfiguration.TargetValue)))
	}
	return proposed, proposed < float64(base), nil
}
func (s *Service) currentTrackingMetric(ctx context.Context, g GroupRecord, p PolicyRecord) (float64, bool, error) {
	metric, err := trackingAlarmMetric(g, p.Data.TargetTrackingConfiguration)
	if err != nil {
		return 0, false, err
	}
	end := s.clock.Now()
	start := end.Add(-3 * time.Duration(*metric.Period) * time.Second)
	out, err := s.alarms.Query(ctx, &cw.GetMetricDataInput{StartTime: &start, EndTime: &end, ScanBy: new(cw.ScanByTIMESTAMP_DESCENDING), MetricDataQueries: cw.MetricDataQueries{{Id: new(cw.MetricId("value")), ReturnData: new(cw.ReturnData(true)), MetricStat: &cw.MetricStat{Metric: &cw.Metric{Namespace: metric.Namespace, MetricName: metric.MetricName, Dimensions: metric.Dimensions}, Period: metric.Period, Stat: new(cw.Stat(*metric.Statistic)), Unit: metric.Unit}}}})
	if err != nil {
		return 0, false, err
	}
	for _, result := range out.MetricDataResults {
		if value(result.Id) != "value" || len(result.Values) == 0 || len(result.Timestamps) == 0 {
			continue
		}
		v := float64(result.Values[0])
		if result.Timestamps[0].Before(start) || !finiteMetric(v) || v < 0 {
			return 0, false, nil
		}
		return v, true, nil
	}
	return 0, false, nil
}
