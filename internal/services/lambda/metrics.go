package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	runtime "stackd/compute/lambda"
	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

const (
	metricInvocations         = "Invocations"
	metricErrors              = "Errors"
	metricThrottles           = "Throttles"
	metricAsyncReceived       = "AsyncEventsReceived"
	metricAsyncDropped        = "AsyncEventsDropped"
	metricDestinationFailures = "DestinationDeliveryFailures"
	metricDeadLetterErrors    = "DeadLetterErrors"
	metricDuration            = "Duration"
	metricExtensionsDuration  = "PostRuntimeExtensionsDuration"
)

func (s *Service) stageMetric(tx Transaction, ref FunctionReference, at time.Time, name string, value int64) error {
	return s.stageMetricSamples(tx, ref, "", at, []MetricSample{{Name: name, Value: float64(value), SampleCount: 1}})
}

func (s *Service) stageExecutionMetrics(tx Transaction, ref FunctionReference, executedVersion string, at time.Time, report runtime.Report) error {
	errorCount := float64(0)
	if report.FunctionFailed || report.Status != runtime.InvocationSuccess {
		errorCount = 1
	}
	values := [5]MetricSample{
		{Name: metricInvocations, Value: 1, SampleCount: 1},
		{Name: metricErrors, Value: errorCount, SampleCount: 1},
		{Name: metricThrottles, Value: 0, SampleCount: 1},
		{Name: metricDuration, Value: float64(report.Duration) / float64(time.Millisecond), SampleCount: 1},
	}
	samples := values[:4]
	if report.HasExtensions {
		values[4] = MetricSample{Name: metricExtensionsDuration, Value: float64(report.PostRuntimeExtensionsDuration) / float64(time.Millisecond), SampleCount: 1}
		samples = values[:]
	}
	return s.stageMetricSamples(tx, ref, executedVersion, at, samples)
}

func (s *Service) stageThrottleMetrics(tx Transaction, ref FunctionReference, at time.Time) error {
	return s.stageMetricSamples(tx, ref, "", at, []MetricSample{
		{Name: metricErrors, Value: 0, SampleCount: 1},
		{Name: metricThrottles, Value: 1, SampleCount: 1},
	})
}

func (s *Service) stageMetricSamples(tx Transaction, ref FunctionReference, executedVersion string, at time.Time, samples []MetricSample) error {
	if s.metrics == nil {
		return nil
	}
	key := MetricPublicationKey{Function: ref.FunctionKey, Minute: at.UTC().Truncate(time.Minute)}
	if err := tx.AddMetricSamples(key, samples); err != nil {
		return err
	}
	key.Resource = ref.Name
	if ref.Qualifier != "" {
		key.Resource += ":" + ref.Qualifier
	}
	if err := tx.AddMetricSamples(key, samples); err != nil {
		return err
	}
	if executedVersion != "" && strings.Trim(ref.Qualifier, "0123456789") != "" {
		key.ExecutedVersion = executedVersion
		return tx.AddMetricSamples(key, samples)
	}
	return nil
}

type metricJobs struct{ s *Service }

func (j metricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		key, err := r.NextMetricPublication()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(key)
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: string(encoded), Due: key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key MetricPublicationKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	if job.Due.After(j.s.clock.Now()) {
		return nil
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Function.Partition, AccountID: key.Function.Account, Region: key.Function.Region})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil {
			return err
		}
		if len(samples) == 0 {
			return nil
		}
		var dimensions metricsapi.Dimensions
		if key.EventSourceMappingUUID != "" {
			dimensions = metricsapi.Dimensions{{Name: new(metricsapi.DimensionName("EventSourceMappingUUID")), Value: new(metricsapi.DimensionValue(key.EventSourceMappingUUID))}}
		} else {
			dimensions = metricsapi.Dimensions{{Name: new(metricsapi.DimensionName("FunctionName")), Value: new(metricsapi.DimensionValue(key.Function.Name))}}
			if key.Resource != "" {
				dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("Resource")), Value: new(metricsapi.DimensionValue(key.Resource))})
			}
			if key.ExecutedVersion != "" {
				dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("ExecutedVersion")), Value: new(metricsapi.DimensionValue(key.ExecutedVersion))})
			}
		}
		var data []metricsapi.MetricDatum
		for start := 0; start < len(samples); {
			end := start + 1
			for end < len(samples) && samples[end].Name == samples[start].Name {
				end++
			}
			name := samples[start].Name
			if name == metricDestinationFailures || name == metricDeadLetterErrors {
				// Native delivery counters aggregate failures into one sample per
				// minute, unlike per-execution Errors (including success zeros).
				var total float64
				for _, sample := range samples[start:end] {
					total += sample.Value * float64(sample.SampleCount)
				}
				data = append(data, metricsapi.MetricDatum{MetricName: new(metricsapi.MetricName(name)), Dimensions: dimensions, Timestamp: new(metricsapi.Timestamp(key.Minute)), Unit: new(metricsapi.StandardUnit("Count")), Value: new(metricsapi.DatapointValue(total))})
				start = end
				continue
			}
			values, counts := make(metricsapi.Values, end-start), make(metricsapi.Counts, end-start)
			for i, sample := range samples[start:end] {
				values[i], counts[i] = metricsapi.DatapointValue(sample.Value), metricsapi.DatapointValue(sample.SampleCount)
			}
			unit := metricsapi.StandardUnit("Count")
			if name == metricDuration || name == metricExtensionsDuration || name == metricURLLatency || name == "IteratorAge" {
				unit = "Milliseconds"
			}
			data = append(data, metricsapi.MetricDatum{MetricName: new(metricsapi.MetricName(name)), Dimensions: dimensions, Timestamp: new(metricsapi.Timestamp(key.Minute)), Unit: new(unit), Values: values, Counts: counts})
			start = end
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/Lambda", data); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}
