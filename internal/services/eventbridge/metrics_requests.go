package eventbridge

import (
	"context"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awscatalog"
)

// PutEvents samples are per request, including mixed and wholly rejected entry
// results in a successful API response. Size uses the same entry-byte admission
// calculation, not the transport's JSON encoding.
func (s *Service) stagePutEventsMetrics(tx Transaction, started time.Time, size int, in *api.PutEventsInput, out *api.PutEventsOutput) error {
	if s.metrics == nil {
		return nil
	}
	samples := []MetricSample{
		{Name: "PutEventsApproximateCallCount", Value: 1, SampleCount: 1},
		{Name: "PutEventsApproximateSuccessCount", Value: 1, SampleCount: 1},
		{Name: "PutEventsEntriesCount", Value: float64(len(in.Entries)), SampleCount: 1},
		{Name: "PutEventsFailedEntriesCount", Value: float64(*out.FailedEntryCount), SampleCount: 1},
		{Name: "PutEventsRequestSize", Value: float64(size), SampleCount: 1},
		{Name: "PutEventsLatency", Value: float64(s.clock.Now().Sub(started)) / float64(time.Millisecond), SampleCount: 1},
	}
	return tx.AddMetricSamples(MetricPublicationKey{Scope: scopeFor(tx.Context()), Minute: started.UTC().Truncate(time.Minute)}, samples)
}

// putEventsSize owns the logical byte count shared by admission and metrics.
// It also records whether any entry has the three admission-required members.
func putEventsSize(in *api.PutEventsInput) (size int, complete bool) {
	for i := range in.Entries {
		entry := &in.Entries[i]
		size += len(value(entry.Source)) + len(value(entry.DetailType)) + len(value(entry.Detail))
		if entry.Time != nil {
			size += 14
		}
		for _, resource := range entry.Resources {
			size += len(resource)
		}
		complete = complete || (entry.Source != nil && entry.DetailType != nil && entry.Detail != nil)
	}
	return
}

func (s *Service) recordRejectedPutEvents(ctx context.Context, size *int) error {
	// TODO: Comeback publish throttling/quota metrics from actual service admission when those limits are implemented.
	samples := []MetricSample{
		{Name: "PutEventsApproximateCallCount", Value: 1, SampleCount: 1},
		{Name: "PutEventsApproximateFailedCount", Value: 1, SampleCount: 1},
	}
	if size != nil {
		samples = append(samples, MetricSample{Name: "PutEventsRequestSize", Value: float64(*size), SampleCount: 1})
	}
	key := MetricPublicationKey{Scope: scopeFor(ctx), Minute: s.clock.Now().UTC().Truncate(time.Minute)}
	err := s.repository.Update(ctx, func(tx Transaction) error { return tx.AddMetricSamples(key, samples) })
	s.jobs.Wake()
	return err
}

// RecordRejectedRequestMetrics observes generated validation failures without
// admitting their input or passing unvalidated fields to CloudTrail projection.
func (s *Service) RecordRejectedRequestMetrics(ctx context.Context, operation awscatalog.Operation, request awsapi.Request) error {
	if s.metrics == nil || operation.Name != "PutEvents" {
		return nil
	}
	model, _ := awscatalog.LookupService("eventbridge")
	var input api.PutEventsInput
	var size *int
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, &input); err == nil {
		bytes, _ := putEventsSize(&input)
		size = &bytes
	}
	return s.recordRejectedPutEvents(ctx, size)
}
