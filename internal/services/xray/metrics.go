package xray

import (
	"context"
	"errors"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher commits service-owned samples in the shared transaction,
// independently of the customer's PutMetricData permissions.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

const metricNamespace = "AWS/X-Ray"

func xrayMetric(name, dimension, identity string, sample float64, at time.Time) metricsapi.MetricDatum {
	return metricsapi.MetricDatum{
		MetricName: new(metricsapi.MetricName(name)),
		Dimensions: metricsapi.Dimensions{{Name: new(metricsapi.DimensionName(dimension)), Value: new(metricsapi.DimensionValue(identity))}},
		Timestamp:  new(metricsapi.Timestamp(at)), Unit: new(metricsapi.StandardUnit("None")),
		Value: new(metricsapi.DatapointValue(sample)),
	}
}

func (s *Service) recordSamplingRates(tx Transaction, targets api.SamplingTargetDocumentList, allocations map[string]*samplingAllocation) error {
	if s.metrics == nil {
		return nil
	}
	now := s.clock.Now().UTC()
	var data []metricsapi.MetricDatum
	for _, target := range targets {
		rule := allocations[value(target.RuleName)].rule
		if rule.RateBoost == nil {
			continue
		}
		rate := float64(*target.FixedRate)
		if target.SamplingBoost != nil {
			rate = float64(*target.SamplingBoost.BoostRate)
		}
		data = append(data, xrayMetric("SamplingRate", "RuleName", rule.Key.Name, rate, now))
	}
	if len(data) == 0 {
		return nil
	}
	return s.metrics.Publish(tx.Context(), metricNamespace, data)
}

func (s *Service) recordGroupMatch(tx Transaction, group GroupRecord) error {
	if s.metrics == nil {
		return nil
	}
	return tx.AddGroupMetric(GroupMetricKey{Group: group.Key, Minute: s.clock.Now().UTC().Truncate(time.Minute)})
}

type groupMetricJobs struct{ s *Service }

func (j groupMetricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		row, err := r.NextGroupMetric()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: "group-match-metrics", Due: row.Key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}

func (j groupMetricJobs) Run(ctx context.Context, _ scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		row, err := tx.NextGroupMetric()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if row.Key.Minute.Add(time.Minute).After(j.s.clock.Now()) {
			return nil
		}
		scope := row.Key.Group.Scope
		ctx := awsctx.WithMetadata(tx.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
		// Publish the actual closed-minute count. AWS's distributed zero samples
		// and sub-minute batching are not fabricated as local observations.
		data := []metricsapi.MetricDatum{xrayMetric("ApproximateTraceCount", "GroupName", row.Key.Group.Name, float64(row.Count), row.Key.Minute)}
		if err := j.s.metrics.Publish(ctx, metricNamespace, data); err != nil {
			return err
		}
		return tx.DeleteGroupMetric(row.Key)
	})
}
