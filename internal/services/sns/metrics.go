package sns

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/internal/services/sns/filterpolicy"
)

// MetricPublisher admits service-owned samples in the shared transaction. It is
// not a customer PutMetricData call and does not borrow the caller's permissions.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

const (
	metricPublished              = "NumberOfMessagesPublished"
	metricPublishSize            = "PublishSize"
	metricDelivered              = "NumberOfNotificationsDelivered"
	metricFailed                 = "NumberOfNotificationsFailed"
	metricFiltered               = "NumberOfNotificationsFilteredOut"
	metricRedriven               = "NumberOfNotificationsRedrivenToDlq"
	metricFailedRedrive          = "NumberOfNotificationsFailedToRedriveToDlq"
	metricArchiveProcessing      = "NumberOfMessagesArchiveProcessing"
	metricArchiveBytesProcessing = "NumberOfBytesArchiveProcessing"
	metricArchivedMessages       = "ApproximateNumberOfMessagesArchived"
	metricArchivedBytes          = "ApproximateNumberOfBytesArchived"
	metricReplayDelivered        = "NumberOfReplayedNotificationsDelivered"
	metricReplayFailed           = "NumberOfReplayedNotificationsFailed"
)

var filterMetricNames = [filterpolicy.MatchResultCount]string{
	filterpolicy.FilteredAttributes:  "NumberOfNotificationsFilteredOut-MessageAttributes",
	filterpolicy.FilteredBody:        "NumberOfNotificationsFilteredOut-MessageBody",
	filterpolicy.NoMessageAttributes: "NumberOfNotificationsFilteredOut-NoMessageAttributes",
	filterpolicy.InvalidMessageBody:  "NumberOfNotificationsFilteredOut-InvalidMessageBody",
	filterpolicy.InvalidAttributes:   "NumberOfNotificationsFilteredOut-InvalidAttributes",
}

func (s *Service) stageMetric(tx Transaction, topic TopicKey, at time.Time, name string, value, count int64) error {
	if s.metrics == nil || count == 0 {
		return nil
	}
	key := MetricPublicationKey{Topic: topic, Minute: at.UTC().Truncate(time.Minute)}
	return tx.AddMetricSamples(key, []MetricSample{{Name: name, Value: value, SampleCount: count}})
}

func (s *Service) stageFilterMetrics(tx Transaction, topic TopicKey, at time.Time, results [filterpolicy.MatchResultCount]int64) error {
	ordinary := results[filterpolicy.FilteredAttributes] + results[filterpolicy.FilteredBody]
	rejected := ordinary + results[filterpolicy.NoMessageAttributes] + results[filterpolicy.InvalidMessageBody] + results[filterpolicy.InvalidAttributes]
	// Filtering is a completed non-failure outcome, including missing or invalid
	// filtering scope. Special reason counters do not increment general FilteredOut.
	if err := s.stageMetric(tx, topic, at, metricFailed, 0, rejected); err != nil {
		return err
	}
	if err := s.stageMetric(tx, topic, at, metricFiltered, 1, ordinary); err != nil {
		return err
	}
	for result := filterpolicy.FilteredAttributes; result < filterpolicy.MatchResultCount; result++ {
		if err := s.stageMetric(tx, topic, at, filterMetricNames[result], 1, results[result]); err != nil {
			return err
		}
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
		// SNS reports at one-minute intervals. Local visibility advances at the
		// completed-minute boundary; no idle samples or activity ledger are invented.
		job, found = scheduler.Job{Key: key.Topic.ARN(), Due: key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil {
		return err
	}
	scope := Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}
	key := MetricPublicationKey{Topic: TopicKey{Scope: scope, Name: parsed.Resource}, Minute: job.Due.Add(-time.Minute)}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil {
			return err
		}
		if len(samples) == 0 {
			return nil
		}
		dimensions := metricsapi.Dimensions{{Name: str[metricsapi.DimensionName]("TopicName"), Value: str[metricsapi.DimensionValue](key.Topic.Name)}}
		var data []metricsapi.MetricDatum
		for start := 0; start < len(samples); {
			end := start + 1
			for end < len(samples) && samples[end].Name == samples[start].Name {
				end++
			}
			unit := metricsapi.StandardUnit("Count")
			if samples[start].Name == metricPublishSize {
				unit = "Bytes"
			} else if samples[start].Name == metricArchiveProcessing || samples[start].Name == metricArchiveBytesProcessing {
				unit = "None"
			}
			for start < end {
				stop := min(start+150, end)
				values, counts := make(metricsapi.Values, stop-start), make(metricsapi.Counts, stop-start)
				for i, sample := range samples[start:stop] {
					values[i], counts[i] = metricsapi.DatapointValue(sample.Value), metricsapi.DatapointValue(sample.SampleCount)
				}
				data = append(data, metricsapi.MetricDatum{MetricName: str[metricsapi.MetricName](samples[start].Name), Dimensions: dimensions, Timestamp: ptr(metricsapi.Timestamp(key.Minute)), Unit: &unit, Values: values, Counts: counts})
				start = stop
			}
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/SNS", data); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}

func (s *Service) stageDeliveryMetrics(tx Transaction, topic TopicKey, at time.Time, deadLetter, replayed, success bool) error {
	failed, delivered := metricFailed, metricDelivered
	if deadLetter {
		failed, delivered = metricFailedRedrive, metricRedriven
	} else if replayed {
		failed, delivered = metricReplayFailed, metricReplayDelivered
	}
	failure := int64(1)
	if success {
		failure = 0
		if err := s.stageMetric(tx, topic, at, delivered, 1, 1); err != nil {
			return err
		}
	}
	return s.stageMetric(tx, topic, at, failed, failure, 1)
}
