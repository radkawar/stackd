package firehose

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// TODO: Comeback — implement source, DataFreshness and decompression metric
// distributions from native samples; retained Incoming, processing and S3 samples
// do not establish those series.
func (s *Service) addSamples(tx Transaction, stream StreamKey, samples []MetricSample) error {
	if s.metrics == nil {
		return nil
	}
	return tx.AddMetricSamples(MetricPublicationKey{Stream: stream, Minute: s.clock.Now().UTC().Truncate(time.Minute)}, samples)
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
		// Publication delay is locally the completed UTC minute, not a claim
		// about AWS's observed asynchronous visibility delay.
		job, found = scheduler.Job{Key: key.Stream.ARN(), Due: key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}
func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil {
		return err
	}
	stream := StreamKey{Scope: Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, Name: strings.TrimPrefix(parsed.Resource, "deliverystream/")}
	key := MetricPublicationKey{Stream: stream, Minute: job.Due.Add(-time.Minute)}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: stream.Partition, AccountID: stream.AccountID, Region: stream.Region})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		at := api.Timestamp(key.Minute)
		dimensions := api.Dimensions{{Name: new(api.DimensionName("DeliveryStreamName")), Value: new(api.DimensionValue(stream.Name))}}
		data := make([]api.MetricDatum, 0, len(samples))
		for _, sample := range samples {
			unit := api.StandardUnitCount
			if strings.HasSuffix(sample.Name, "Bytes") {
				unit = api.StandardUnitBytes
			}
			data = append(data, api.MetricDatum{MetricName: new(api.MetricName(sample.Name)), Dimensions: dimensions, Timestamp: &at, Unit: &unit, Values: api.Values{api.DatapointValue(sample.Value)}, Counts: api.Counts{api.DatapointValue(sample.SampleCount)}})
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/Firehose", data); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}
