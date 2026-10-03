package sqs

import (
	"context"
	"errors"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// MetricPublisher admits service-owned samples into the shared transaction.
// It is not a customer PutMetricData call and does not borrow caller permissions.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

const (
	metricMessagesSent     = "NumberOfMessagesSent"
	metricMessagesReceived = "NumberOfMessagesReceived"
	metricMessagesDeleted  = "NumberOfMessagesDeleted"
	metricEmptyReceives    = "NumberOfEmptyReceives"
)

// stageCommandMetrics uses the final successful result shared by URL and ARN
// callers. A batch is one sample, even when every entry fails. Empty receives
// contribute only to their own counter, not to NumberOfMessagesReceived.
func (s *Service) stageCommandMetrics(tx Transaction, audit *commandAudit) error {
	if s.metrics == nil {
		return nil
	}
	queue, valid := parseQueueARN(audit.resourceARN)
	if !valid || queue.name == "*" {
		return nil
	}
	if q := s.lookupQueue(queue); q != nil {
		activateQueueMetrics(&q.metricActiveUntil, &q.nextMetricSample, s.now())
		s.jobsChanged = true
	}
	var name string
	var count int64
	// Several generated responses alias Unit. Operation identity, not the Go
	// output type, distinguishes a message delete from queue configuration.
	switch audit.action {
	case "SendMessage":
		name, count = metricMessagesSent, 1
	case "SendMessageBatch":
		name, count = metricMessagesSent, int64(len(audit.output.(*api.SendMessageBatchOutput).Successful))
	case "ReceiveMessage":
		name, count = metricMessagesReceived, int64(len(audit.output.(*api.ReceiveMessageOutput).Messages))
		if count == 0 {
			name, count = metricEmptyReceives, 1
		}
	case "DeleteMessage":
		name, count = metricMessagesDeleted, 1
	case "DeleteMessageBatch":
		name, count = metricMessagesDeleted, int64(len(audit.output.(*api.DeleteMessageBatchOutput).Successful))
	}
	if name == "" {
		return nil
	}
	key := MetricPublicationKey{Queue: publicKey(queue), Minute: s.now().UTC().Truncate(time.Minute)}
	s.jobsChanged = true
	samples := audit.messageSizeSamples()
	samples = append(samples, MetricSample{Name: name, Value: count, SampleCount: 1})
	if audit.action == "SendMessage" || audit.action == "SendMessageBatch" {
		if q := s.queues[queue]; q != nil && q.config.fifo {
			samples = append(samples, MetricSample{Name: metricDeduplicated, Value: audit.deduplicated, SampleCount: 1})
		}
	}
	return tx.AddMetricSamples(key, samples)
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
		job, found = scheduler.Job{Key: privateKey(key.Queue).arn(), Due: key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	queue, _ := parseQueueARN(job.Key)
	key := MetricPublicationKey{Queue: publicKey(queue), Minute: job.Due.Add(-time.Minute)}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: queue.partition, AccountID: queue.account, Region: queue.region})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		if err := j.s.publishMetrics(tx.Context(), key, samples); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}

func (s *Service) publishMetrics(ctx context.Context, key MetricPublicationKey, samples []MetricSample) error {
	dimensions := metricsapi.Dimensions{{Name: ptr(metricsapi.DimensionName("QueueName")), Value: ptr(metricsapi.DimensionValue(key.Queue.Name))}}
	data := make([]metricsapi.MetricDatum, 0, len(samples))
	for _, sample := range samples {
		unit := metricsapi.StandardUnit("Count")
		switch sample.Name {
		case metricMessageSize:
			unit = "Bytes"
		case metricOldestAge, metricQuietOldestAge:
			unit = "Seconds"
		}
		data = append(data, metricsapi.MetricDatum{
			MetricName: ptr(metricsapi.MetricName(sample.Name)), Dimensions: dimensions,
			Timestamp: ptr(metricsapi.Timestamp(key.Minute)), Unit: &unit,
			Values: metricsapi.Values{metricsapi.DatapointValue(sample.Value)},
			Counts: metricsapi.Counts{metricsapi.DatapointValue(sample.SampleCount)},
		})
	}
	return s.metrics.Publish(ctx, "AWS/SQS", data)
}
