package autoscaling

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	cw "stackd/internal/awsapi/cloudwatch"
)

// Native DescribeMetricCollectionTypes supplies this catalog. Captured native
// warm-pool gauges report zero even when no pool exists.
var groupMetricNames = []string{
	"GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity", "GroupInServiceInstances", "GroupInServiceCapacity",
	"GroupPendingInstances", "GroupPendingCapacity", "GroupTerminatingInstances", "GroupTerminatingCapacity",
	"GroupTerminatingRetainedInstances", "GroupTerminatingRetainedCapacity", "GroupStandbyInstances", "GroupStandbyCapacity",
	"GroupTotalInstances", "GroupTotalCapacity", "WarmPoolMinSize", "WarmPoolDesiredCapacity", "WarmPoolPendingCapacity",
	"WarmPoolPendingRetainedCapacity", "WarmPoolTerminatingCapacity", "WarmPoolTerminatingRetainedCapacity",
	"WarmPoolWarmedCapacity", "WarmPoolTotalCapacity", "GroupAndWarmPoolDesiredCapacity", "GroupAndWarmPoolTotalCapacity",
}

func registerMetrics(s *Service) {
	register(s, "EnableMetricsCollection", s.enableMetricsCollection)
	register(s, "DisableMetricsCollection", s.disableMetricsCollection)
	register(s, "DescribeMetricCollectionTypes", s.describeMetricCollectionTypes)
}

// InstanceMetricGroup resolves membership at measurement time. Warm guests keep
// their EC2 group tag but do not contribute to the active group's EC2 metrics.
// Previously accumulated contributions remain publishable after membership changes.
func (s *Service) InstanceMetricGroup(ctx context.Context, scope Scope, id string) (string, error) {
	var name string
	err := s.repository.View(ctx, func(tx Reader) error {
		member, err := tx.Instance(scope, id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !warmMember(member) {
			name = member.Group.Name
		}
		return nil
	})
	return name, err
}

func (s *Service) enableMetricsCollection(ctx context.Context, tx Transaction, in *api.EnableMetricsCollectionInput) (*api.EnableMetricsCollectionOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "EnableMetricsCollection")
	if err != nil {
		return nil, err
	}
	if value(in.Granularity) != "1Minute" {
		return nil, invalid("The supported metric granularity is 1Minute.")
	}
	if s.metrics == nil {
		return nil, unsupported("Auto Scaling metric publication is not configured.")
	}
	names := plainList(in.Metrics)
	if len(names) == 0 {
		names = groupMetricNames
	}
	for _, name := range names {
		if !slices.Contains(groupMetricNames, name) {
			return nil, invalid("The metric is not valid: " + name)
		}
		if !slices.ContainsFunc(group.Data.EnabledMetrics, func(m api.EnabledMetric) bool { return value(m.Metric) == name }) {
			group.Data.EnabledMetrics = append(group.Data.EnabledMetrics, api.EnabledMetric{Metric: new(api.XmlStringMaxLen255(name)), Granularity: new(api.XmlStringMaxLen255("1Minute"))})
		}
	}
	slices.SortFunc(group.Data.EnabledMetrics, func(a, b api.EnabledMetric) int { return strings.Compare(value(a.Metric), value(b.Metric)) })
	if group.MetricAt.IsZero() {
		group.MetricAt = s.clock.Now().Truncate(time.Minute).Add(time.Minute)
	}
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.EnableMetricsCollectionOutput{}, nil
}

func (s *Service) disableMetricsCollection(ctx context.Context, tx Transaction, in *api.DisableMetricsCollectionInput) (*api.DisableMetricsCollectionOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DisableMetricsCollection")
	if err != nil {
		return nil, err
	}
	names := plainList(in.Metrics)
	for _, name := range names {
		if !slices.Contains(groupMetricNames, name) {
			return nil, invalid("The metric is not valid: " + name)
		}
	}
	group.Data.EnabledMetrics = slices.DeleteFunc(group.Data.EnabledMetrics, func(m api.EnabledMetric) bool { return len(names) == 0 || slices.Contains(names, value(m.Metric)) })
	if len(group.Data.EnabledMetrics) == 0 {
		group.MetricAt = time.Time{}
	}
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.DisableMetricsCollectionOutput{}, nil
}

func (s *Service) describeMetricCollectionTypes(ctx context.Context, _ Transaction, _ *api.DescribeMetricCollectionTypesInput) (*api.DescribeMetricCollectionTypesOutput, error) {
	if err := s.authorize(ctx, "DescribeMetricCollectionTypes", "*", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeMetricCollectionTypesOutput{Granularities: api.MetricGranularityTypes{{Granularity: new(api.XmlStringMaxLen255("1Minute"))}}, Metrics: api.MetricCollectionTypes{}}
	for _, name := range groupMetricNames {
		out.Metrics = append(out.Metrics, api.MetricCollectionType{Metric: new(api.XmlStringMaxLen255(name))})
	}
	return out, nil
}

func (s *Service) publishGroupMetrics(ctx context.Context, snapshot GroupRecord) error {
	if snapshot.MetricAt.IsZero() || snapshot.MetricAt.After(s.clock.Now()) {
		return nil
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		group, err := tx.Group(snapshot.Key)
		if err != nil {
			return err
		}
		if group.ID != snapshot.ID || group.MetricAt.IsZero() || group.MetricAt.After(s.clock.Now()) || group.Deleting {
			return nil
		}
		members, err := tx.Instances(group.Key)
		if err != nil {
			return err
		}
		counts := map[string]float64{
			"GroupMinSize": float64(intValue(group.Data.MinSize)), "GroupMaxSize": float64(intValue(group.Data.MaxSize)),
			"GroupDesiredCapacity": float64(intValue(group.Data.DesiredCapacity)), "GroupInServiceInstances": 0, "GroupPendingInstances": 0,
			"GroupTerminatingInstances": 0, "GroupTerminatingRetainedInstances": 0, "GroupStandbyInstances": 0,
		}
		for _, name := range groupMetricNames {
			if strings.HasPrefix(name, "WarmPool") {
				counts[name] = 0
			}
		}
		if pool := group.Data.WarmPoolConfiguration; pool != nil {
			counts["WarmPoolMinSize"] = float64(intValue(pool.MinSize))
			counts["WarmPoolDesiredCapacity"] = float64(warmPoolDesired(group))
		}
		for _, member := range members {
			state := value(member.Data.LifecycleState)
			if warmMember(member) {
				switch {
				case state == "Warmed:Pending:Retained":
					counts["WarmPoolPendingRetainedCapacity"]++
				case state == "Warmed:Terminating:Retained":
					counts["WarmPoolTerminatingRetainedCapacity"]++
				case strings.HasPrefix(state, "Warmed:Pending"):
					counts["WarmPoolPendingCapacity"]++
				case strings.HasPrefix(state, "Warmed:Terminating"):
					counts["WarmPoolTerminatingCapacity"]++
				case warmReady(member):
					counts["WarmPoolWarmedCapacity"]++
				}
				counts["WarmPoolTotalCapacity"]++
				continue
			}
			switch {
			case state == "InService":
				counts["GroupInServiceInstances"]++
			case strings.HasPrefix(state, "Pending"):
				counts["GroupPendingInstances"]++
			case state == "Terminating:Retained":
				counts["GroupTerminatingRetainedInstances"]++
			case strings.HasPrefix(state, "Terminating"):
				counts["GroupTerminatingInstances"]++
			case state == "Standby" || state == "EnteringStandby":
				counts["GroupStandbyInstances"]++
			}
		}
		counts["GroupTotalInstances"] = counts["GroupInServiceInstances"] + counts["GroupPendingInstances"] + counts["GroupTerminatingInstances"] + counts["GroupTerminatingRetainedInstances"] + counts["GroupStandbyInstances"]
		for _, state := range []string{"InService", "Pending", "Terminating", "TerminatingRetained", "Standby", "Total"} {
			counts["Group"+state+"Capacity"] = counts["Group"+state+"Instances"]
		}
		counts["GroupAndWarmPoolDesiredCapacity"] = counts["GroupDesiredCapacity"] + counts["WarmPoolDesiredCapacity"]
		counts["GroupAndWarmPoolTotalCapacity"] = counts["GroupTotalCapacity"] + counts["WarmPoolTotalCapacity"]
		at := s.clock.Now().Truncate(time.Minute)
		data := make([]cw.MetricDatum, 0, len(group.Data.EnabledMetrics))
		for _, metric := range group.Data.EnabledMetrics {
			name := value(metric.Metric)
			count, exists := counts[name]
			if !exists {
				continue
			}
			data = append(data, cw.MetricDatum{MetricName: new(cw.MetricName(name)), Timestamp: new(cw.Timestamp(at)), Value: new(cw.DatapointValue(count)), Unit: new(cw.StandardUnit("None")), Dimensions: cw.Dimensions{{Name: new(cw.DimensionName("AutoScalingGroupName")), Value: new(cw.DimensionValue(group.Key.Name))}}})
		}
		if len(data) > 0 {
			if err := s.metrics.Publish(tx.Context(), "AWS/AutoScaling", data); err != nil {
				return err
			}
		}
		group.MetricAt = at.Add(time.Minute)
		return tx.PutGroup(group)
	})
}
