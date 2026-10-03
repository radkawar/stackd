package apigateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/internal/services/apigatewayexec"
)

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }

// RecordMetrics retains the observed distributions independently of live API
// configuration. Both Gateway control planes feed this one publication owner.
func (s *Service) RecordMetrics(ctx context.Context, route *apigatewayexec.Route, at time.Time, samples []MetricSample) error {
	if s.metrics == nil {
		return nil
	}
	key := MetricPublicationKey{
		API:    APIKey{Scope: Scope{Partition: route.Partition, AccountID: route.AccountID, Region: route.Region}, ID: route.APIID},
		Minute: at.UTC().Truncate(time.Minute), ProtocolType: route.ProtocolType,
	}
	if route.ProtocolType == "REST" {
		key.APIName = strings.Map(func(r rune) rune {
			if r > 127 {
				return -1
			}
			return r
		}, route.APIName)
		if key.APIName == "" {
			key.APIName = route.APIID
		}
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.AddMetricSamples(key, samples); err != nil {
			return err
		}
		key.Stage = route.Stage
		if err := tx.AddMetricSamples(key, samples); err != nil {
			return err
		}
		if !route.DetailedMetricsEnabled {
			return nil
		}
		if route.ProtocolType == "WEBSOCKET" {
			key.Route = route.RouteKey
		} else {
			key.Method, _, _ = strings.Cut(route.RouteKey, " ")
			key.Resource = route.ResourcePath
		}
		return tx.AddMetricSamples(key, samples)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
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
		// Publish completed service-time minutes; AWS's asynchronous visibility
		// delay is not a wall-clock sleep in the emulator.
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
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.API.Partition, AccountID: key.API.AccountID, Region: key.API.Region})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		dimensions := metricDimensions(key)
		var data []metricsapi.MetricDatum
		for start := 0; start < len(samples); {
			end := start + 1
			for end < len(samples) && samples[end].Name == samples[start].Name {
				end++
			}
			values, counts := make(metricsapi.Values, end-start), make(metricsapi.Counts, end-start)
			for i, sample := range samples[start:end] {
				values[i], counts[i] = metricsapi.DatapointValue(sample.Value), metricsapi.DatapointValue(sample.SampleCount)
			}
			name := samples[start].Name
			unit := metricsapi.StandardUnitCount
			switch name {
			case "Latency", "IntegrationLatency":
				unit = metricsapi.StandardUnitMilliseconds
			case "DataProcessed":
				unit = metricsapi.StandardUnitBytes
			case "Count", "4xx", "5xx":
				if key.ProtocolType == "HTTP" {
					unit = metricsapi.StandardUnitNone
				}
			}
			data = append(data, metricsapi.MetricDatum{MetricName: new(metricsapi.MetricName(name)), Dimensions: dimensions,
				Timestamp: new(metricsapi.Timestamp(key.Minute)), Unit: &unit, Values: values, Counts: counts})
			start = end
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/ApiGateway", data); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}

func metricDimensions(key MetricPublicationKey) metricsapi.Dimensions {
	name, value := "ApiId", key.API.ID
	if key.ProtocolType == "REST" {
		name, value = "ApiName", key.APIName
	}
	out := metricsapi.Dimensions{{Name: new(metricsapi.DimensionName(name)), Value: new(metricsapi.DimensionValue(value))}}
	if key.Stage != "" {
		out = append(out, metricsapi.Dimension{Name: new(metricsapi.DimensionName("Stage")), Value: new(metricsapi.DimensionValue(key.Stage))})
	}
	if key.Method != "" {
		out = append(out, metricsapi.Dimension{Name: new(metricsapi.DimensionName("Method")), Value: new(metricsapi.DimensionValue(key.Method))},
			metricsapi.Dimension{Name: new(metricsapi.DimensionName("Resource")), Value: new(metricsapi.DimensionValue(key.Resource))})
	}
	if key.Route != "" {
		out = append(out, metricsapi.Dimension{Name: new(metricsapi.DimensionName("Route")), Value: new(metricsapi.DimensionValue(key.Route))})
	}
	return out
}

var _ apigatewayexec.Metrics = (*Service)(nil)
