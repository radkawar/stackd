package kinesis

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher joins service-owned observations to the source transaction.
// Publication does not borrow the customer's cloudwatch:PutMetricData permission.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

// dataSample stages an observation against the stream authorized for this call.
// Enhanced monitoring governs only future shard observations, never the basic
// stream series or already-retained samples.
func (s *Service) dataSample(ctx context.Context, name, shardID string, value float64) {
	call := currentCall(ctx)
	if call == nil || call.stream == nil {
		return
	}
	if name == "IncomingBytes" || name == "IncomingRecords" {
		// Stream totals are per put operation. The write owner supplies each
		// shard's byte samples per record and record counts per shard batch.
		call.samples = aggregatePutSample(call.samples, name, value)
		if shardID != "" && enhancedMetricEnabled(*call.stream, name) {
			call.samples = append(call.samples, MetricSample{Name: name, ShardID: shardID, Value: value, SampleCount: 1})
		}
		return
	}
	call.samples = append(call.samples, MetricSample{Name: name, Value: value, SampleCount: 1})
	if shardName := enhancedMetricName(name); shardID != "" && shardName != "" && enhancedMetricEnabled(*call.stream, shardName) {
		call.samples = append(call.samples, MetricSample{Name: shardName, ShardID: shardID, Value: value, SampleCount: 1})
	}
}

func aggregatePutSample(samples []MetricSample, name string, value float64) []MetricSample {
	for i := range samples {
		if samples[i].Name == name && samples[i].ShardID == "" && samples[i].ConsumerName == "" {
			samples[i].Value += value
			return samples
		}
	}
	return append(samples, MetricSample{Name: name, Value: value, SampleCount: 1})
}

func enhancedMetricName(name string) string {
	switch name {
	case "IncomingBytes", "IncomingRecords", "ReadProvisionedThroughputExceeded", "WriteProvisionedThroughputExceeded":
		return name
	case "GetRecords.Bytes":
		return "OutgoingBytes"
	case "GetRecords.Records":
		return "OutgoingRecords"
	case "GetRecords.IteratorAgeMilliseconds":
		return "IteratorAgeMilliseconds"
	default:
		return ""
	}
}

func enhancedMetricEnabled(stream StreamRecord, name string) bool {
	for _, monitoring := range stream.Data.EnhancedMonitoring {
		for _, metric := range monitoring.ShardLevelMetrics {
			if metric == api.MetricsNameALL || string(metric) == name {
				return true
			}
		}
	}
	return false
}

// completeDataMetrics is called exactly once by runExternal after the public
// operation returns, before committing its staged observations and audit event.
// The service clock measures elapsed operation time; call.at remains its start.
// Successful result paths own Success (including partially successful batches).
func (s *Service) completeDataMetrics(ctx context.Context, operationErr error) {
	call := currentCall(ctx)
	if call == nil || call.stream == nil {
		return
	}
	switch call.action {
	case "PutRecord", "PutRecords", "GetRecords":
	default:
		return
	}
	elapsed := max(time.Duration(0), s.clock.Now().Sub(call.at))
	s.dataSample(ctx, call.action+".Latency", "", float64(elapsed)/float64(time.Millisecond))
	if operationErr == nil {
		return
	}
	name := call.action + ".Success"
	for _, sample := range call.samples {
		if sample.Name == name && sample.ShardID == "" && sample.ConsumerName == "" {
			return
		}
	}
	s.dataSample(ctx, name, "", 0)
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
		job, found = scheduler.Job{Key: key.Stream.ARN(), Due: key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	ctx, stream, err := metricContext(ctx, job.Key)
	if err != nil {
		return err
	}
	key := MetricPublicationKey{Stream: stream, Minute: job.Due.Add(-time.Minute)}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		if err := j.s.publishMetrics(tx.Context(), key, samples); err != nil {
			return err
		}
		// The publication and deletion share the source transaction. Do not
		// load Stream: its deletion must not discard retained observations.
		return tx.DeleteMetricPublication(key)
	})
}

func metricContext(ctx context.Context, resource string) (context.Context, StreamKey, error) {
	parsed, err := arn.Parse(resource)
	if err != nil {
		return ctx, StreamKey{}, err
	}
	key := StreamKey{Scope: Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, Name: strings.TrimPrefix(parsed.Resource, "stream/")}
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region}), key, nil
}

func (s *Service) publishMetrics(ctx context.Context, key MetricPublicationKey, samples []MetricSample) error {
	at := metricsapi.Timestamp(key.Minute)
	data := make([]metricsapi.MetricDatum, 0, len(samples))
	for _, sample := range samples {
		dimensions := metricsapi.Dimensions{{Name: new(metricsapi.DimensionName("StreamName")), Value: new(metricsapi.DimensionValue(key.Stream.Name))}}
		if sample.ShardID != "" {
			dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("ShardId")), Value: new(metricsapi.DimensionValue(sample.ShardID))})
		}
		if sample.ConsumerName != "" {
			dimensions = append(dimensions, metricsapi.Dimension{Name: new(metricsapi.DimensionName("ConsumerName")), Value: new(metricsapi.DimensionValue(sample.ConsumerName))})
		}
		unit := metricUnit(sample.Name)
		data = append(data, metricsapi.MetricDatum{
			MetricName: new(metricsapi.MetricName(sample.Name)), Dimensions: dimensions,
			Timestamp: &at, Unit: &unit,
			Values: metricsapi.Values{metricsapi.DatapointValue(sample.Value)},
			Counts: metricsapi.Counts{metricsapi.DatapointValue(sample.SampleCount)},
		})
	}
	return s.metrics.Publish(ctx, "AWS/Kinesis", data)
}

func metricUnit(name string) metricsapi.StandardUnit {
	switch name {
	case "IncomingBytes", "OutgoingBytes", "PutRecord.Bytes", "PutRecords.Bytes", "GetRecords.Bytes", "SubscribeToShardEvent.Bytes":
		return metricsapi.StandardUnitBytes
	case "PutRecord.Latency", "PutRecords.Latency", "GetRecords.Latency", "GetRecords.IteratorAgeMilliseconds", "IteratorAgeMilliseconds", "SubscribeToShardEvent.MillisBehindLatest":
		return metricsapi.StandardUnitMilliseconds
	default:
		return metricsapi.StandardUnitCount
	}
}
