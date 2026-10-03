package pipes

import (
	"context"
	api "stackd/internal/awsapi/cloudwatch"
	"time"
)

func (s *Service) publishExecution(ctx context.Context, p PipeRecord, batch []Work, failed map[string]bool, err error, skipped bool, d time.Duration) {
	if s.metrics == nil {
		return
	}
	now := s.clock.Now()
	dimensions := api.Dimensions{{Name: new(api.DimensionName("PipeName")), Value: new(api.DimensionValue(p.Key.Name))}}
	samples := []api.MetricDatum{}
	add := func(name, unit string, v float64) {
		samples = append(samples, api.MetricDatum{
			MetricName: new(api.MetricName(name)),
			Value:      new(api.DatapointValue(v)),
			Timestamp:  &now,
			Unit:       new(api.StandardUnit(unit)),
			Dimensions: dimensions,
		})
	}
	add("Invocations", "None", 1)
	add("EventCount", "None", float64(len(batch)))
	add("Duration", "Milliseconds", float64(d)/float64(time.Millisecond))
	size := 0
	for _, w := range batch {
		size += len(w.Event)
	}
	add("EventSize", "Bytes", float64(size))
	if err != nil {
		add("ExecutionFailed", "None", 1)
	} else {
		add("ExecutionFailed", "None", 0)
	}
	if len(failed) > 0 && err == nil {
		add("ExecutionPartiallyFailed", "None", 1)
	}
	if skipped {
		add("TargetStageSkipped", "Count", 1)
	}
	_ = s.metrics.Publish(ctx, "AWS/EventBridge/Pipes", samples)
}
