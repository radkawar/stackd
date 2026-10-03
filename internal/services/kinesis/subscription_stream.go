package kinesis

import (
	"context"
	"errors"
	"slices"
	"time"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

// SubscribeToShard admits and audits one API call. Native reads and heartbeats
// do not reauthorize a request signature or consume GetRecords API admission.
func (s *Service) SubscribeToShard(ctx context.Context, in *api.SubscribeToShardInput) (*api.SubscribeToShardOutput, *awswire.Error) {
	var lease *subscriptionLease
	out, rejected := runExternal(s, ctx, "SubscribeToShard", in, func(ctx context.Context, in *api.SubscribeToShardInput) (*api.SubscribeToShardOutput, error) {
		var out *api.SubscribeToShardOutput
		var err error
		out, lease, err = s.subscribeToShard(ctx, in)
		return out, err
	})
	if rejected != nil && lease != nil {
		lease.cancel(context.Canceled)
	}
	return out, rejected
}

func (s *Service) subscribeToShard(ctx context.Context, in *api.SubscribeToShardInput) (*api.SubscribeToShardOutput, *subscriptionLease, error) {
	if in.StartingPosition == nil || in.StartingPosition.Type == nil || in.ConsumerARN == nil || in.ShardId == nil {
		return nil, nil, failure("ValidationException", "ConsumerARN, ShardId and StartingPosition.Type are required.")
	}
	switch *in.StartingPosition.Type {
	case api.ShardIteratorTypeAT_SEQUENCE_NUMBER, api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER, api.ShardIteratorTypeAT_TIMESTAMP, api.ShardIteratorTypeTRIM_HORIZON, api.ShardIteratorTypeLATEST:
	default:
		return nil, nil, failure("ValidationException", "Invalid StartingPosition.Type.")
	}
	var consumer ConsumerRecord
	var stream StreamRecord
	load := func(r Reader) error {
		var err error
		consumer, err = s.consumer(r.Context(), r, "", value(in.ConsumerARN), "", "SubscribeToShard")
		if err != nil {
			return err
		}
		if value(consumer.Data.ConsumerStatus) != "ACTIVE" {
			return failure("ResourceInUseException", "Consumer "+consumer.Key.ARN()+" is not ACTIVE.")
		}
		stream, err = r.Stream(consumer.Key.Stream)
		if err != nil {
			return err
		}
		return requireReadable(stream)
	}
	err := s.repository.View(ctx, load)
	if err != nil {
		return nil, nil, err
	}
	engineID := stream.EngineID
	release, err := s.engines.lock(ctx, stream.EngineID)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	if err := s.repository.View(ctx, load); err != nil {
		return nil, nil, err
	}
	if stream.EngineID != engineID {
		return nil, nil, consumerMissing(consumer.Key)
	}
	stream, shard, _, err := s.subscriptionState(ctx, consumer.Key, stream.EngineID, value(in.ShardId))
	if err != nil {
		return nil, nil, err
	}
	rememberStream(ctx, stream)
	rememberResource(ctx, "SubscribeToShard", ResourceKey{Scope: consumer.Key.Stream.Scope, ARN: consumer.Key.ARN()})
	// Native DryRun checks identity and shard existence but skips deep starting
	// sequence validation. It never allocates a connection or replaces a lease.
	if in.DryRun != nil && *in.DryRun {
		return nil, nil, failure("DryRunOperationException", "DryRunOperation validation succeeded while calling SubscribeToShard operation.: Request would have succeeded, but DryRun flag is set.")
	}
	log, err := s.engines.log(ctx, stream.Specification())
	if err != nil {
		return nil, nil, err
	}
	offset, err := startOffset(ctx, log, stream, shard, *in.StartingPosition.Type, value(in.StartingPosition.SequenceNumber), in.StartingPosition.Timestamp, s.clock.Now())
	if err != nil {
		return nil, nil, err
	}
	// The request's mutable audit accumulator belongs exclusively to runExternal.
	parent := context.WithValue(ctx, callContextKey{}, (*callContext)(nil))
	lease, err := s.consumers.acquire(parent, s.engines.ctx, s.clock, consumer.Key.ARN(), shard.Key.ID(), stream.EngineID)
	if err != nil {
		if rejected := wireError(err); rejected.Code == "ResourceInUseException" || rejected.Code == "LimitExceededException" {
			if call := currentCall(ctx); call != nil {
				call.samples = append(call.samples, MetricSample{ConsumerName: consumer.Key.Name, Name: "SubscribeToShard.RateExceeded", Value: 1, SampleCount: 1})
			}
		}
		return nil, nil, err
	}
	if call := currentCall(ctx); call != nil {
		call.samples = append(call.samples,
			MetricSample{ConsumerName: consumer.Key.Name, Name: "SubscribeToShard.Success", Value: 1, SampleCount: 1},
			MetricSample{ConsumerName: consumer.Key.Name, Name: "SubscribeToShard.RateExceeded", SampleCount: 1},
		)
	}
	events := make(chan api.SubscribeToShardEventStream)
	go s.streamSubscription(parent, lease, consumer.Key, offset, events)
	return &api.SubscribeToShardOutput{EventStream: events}, lease, nil
}

func (s *Service) subscriptionState(ctx context.Context, consumer ConsumerKey, engineID, shardID string) (StreamRecord, ShardRecord, []ShardRecord, error) {
	var stream StreamRecord
	var shard ShardRecord
	var shards []ShardRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		stream, err = r.Stream(consumer.Stream)
		if err != nil {
			return err
		}
		if stream.EngineID != engineID {
			return consumerMissing(consumer)
		}
		shards, err = r.Shards(stream.Key)
		if err != nil {
			return err
		}
		shard, err = findShard(shards, shardID)
		return err
	})
	return stream, shard, shards, err
}

func (s *Service) subscriptionPage(ctx context.Context, lease *subscriptionLease, consumer ConsumerKey, offset int64) (StreamRecord, ShardRecord, recordPage, error) {
	release, err := s.engines.lock(ctx, lease.engineID)
	if err != nil {
		return StreamRecord{}, ShardRecord{}, recordPage{}, err
	}
	defer release()
	stream, shard, shards, err := s.subscriptionState(ctx, consumer, lease.engineID, lease.key.shard)
	if err != nil {
		return stream, shard, recordPage{}, err
	}
	log, err := s.engines.log(ctx, stream.Specification())
	if err != nil {
		return stream, shard, recordPage{}, err
	}
	page, err := s.readShard(ctx, stream, shard, shards, log, offset, 10000, subscriptionFrameBytes, false)
	return stream, shard, page, err
}

func (s *Service) streamSubscription(parent context.Context, lease *subscriptionLease, consumer ConsumerKey, offset int64, events chan<- api.SubscribeToShardEventStream) {
	defer s.consumers.release(lease)
	defer close(events)
	lastEvent := lease.expires.Add(-subscriptionLifetime)
	var err error
	for lease.ctx.Err() == nil && s.clock.Now().Before(lease.expires) {
		ready, at := s.consumers.ready(lease, s.clock.Now())
		if !ready {
			if at.IsZero() {
				break
			}
			timer := s.clock.NewTimerAt(at)
			select {
			case <-lease.ctx.Done():
			case <-timer.C():
			}
			timer.Stop()
			continue
		}
		var stream StreamRecord
		var shard ShardRecord
		var page recordPage
		stream, shard, page, err = s.subscriptionPage(lease.ctx, lease, consumer, offset)
		if err != nil {
			break
		}
		now := s.clock.Now()
		if !now.Before(lease.expires) {
			break
		}
		if len(page.Records) > 0 || page.Closed || !now.Before(lastEvent.Add(5*time.Second)) {
			event := &api.SubscribeToShardEvent{Records: page.Records, MillisBehindLatest: new(api.MillisBehindLatest(page.MillisBehindLatest))}
			terminal := page.Closed && len(page.Records) == 0
			if terminal {
				event.ChildShards = page.ChildShards
			} else {
				event.ContinuationSequenceNumber = new(sequenceFor(shard).checkpoint(page.NextOffset))
			}
			// Observe accepted service frames before handing them to the transport.
			// Client buffering/close can leave successful service samples unread.
			err = s.subscriptionMetrics(lease.ctx, stream, consumer.Name, shard.Key.ID(), event, page.Bytes, now)
			if err != nil {
				break
			}
			s.consumers.delivered(lease, now, page.Bytes)
			select {
			case <-lease.ctx.Done():
				s.consumers.delivered(lease, s.clock.Now(), -page.Bytes)
			case events <- api.SubscribeToShardEventStream{SubscribeToShardEvent: event}:
				lastEvent = now
			}
			if lease.ctx.Err() != nil {
				break
			}
			if terminal {
				return
			}
		}
		offset = page.NextOffset
		// A closed parent drains its last data page before its separate terminal
		// child-shard event. No heartbeat or terminal event carries record debt.
		if page.Closed && len(page.Records) > 0 {
			event := &api.SubscribeToShardEvent{Records: api.RecordList{}, ChildShards: page.ChildShards, MillisBehindLatest: new(api.MillisBehindLatest(0))}
			err = s.subscriptionMetrics(lease.ctx, stream, consumer.Name, shard.Key.ID(), event, 0, s.clock.Now())
			if err != nil {
				break
			}
			select {
			case <-lease.ctx.Done():
			case events <- api.SubscribeToShardEventStream{SubscribeToShardEvent: event}:
			}
			if lease.ctx.Err() == nil && err == nil {
				return
			}
			break
		}
		if len(page.Records) == 0 {
			// Native appends do not advance a manual service clock. Poll native
			// readiness in wall time; heartbeat eligibility still uses service time.
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-lease.ctx.Done():
			case <-timer.C:
			}
			timer.Stop()
		}
	}
	if cause := context.Cause(lease.ctx); cause != nil {
		err = cause
	}
	if parent.Err() != nil || s.engines.ctx.Err() != nil {
		return
	}
	var end *subscriptionEnd
	if err == nil && !s.clock.Now().Before(lease.expires) {
		end = &subscriptionEnd{at: lease.expires}
	} else {
		errors.As(err, &end)
	}
	if end != nil {
		err = s.recordSubscriptionSamples(parent, consumer.Stream, end.at, []MetricSample{{ConsumerName: consumer.Name, Name: "SubscribeToShardEvent.Success", SampleCount: 1}})
	}
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	frame := subscriptionException(err)
	// Bound modeled-exception delivery so an unread connection cannot retain a
	// producer forever. Service-owned termination above instead closes cleanly.
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case events <- frame:
	case <-parent.Done():
	case <-s.engines.ctx.Done():
	case <-timer.C:
	}
}

func subscriptionException(err error) api.SubscribeToShardEventStream {
	rejected := wireError(err)
	message := new(api.ErrorMessage(rejected.Message))
	switch rejected.Code {
	case "ResourceInUseException":
		return api.SubscribeToShardEventStream{ResourceInUseException: &api.ResourceInUseException{Message: message}}
	case "ResourceNotFoundException":
		return api.SubscribeToShardEventStream{ResourceNotFoundException: &api.ResourceNotFoundException{Message: message}}
	case "KMSAccessDeniedException":
		return api.SubscribeToShardEventStream{KMSAccessDeniedException: &api.KMSAccessDeniedException{Message: message}}
	case "KMSDisabledException":
		return api.SubscribeToShardEventStream{KMSDisabledException: &api.KMSDisabledException{Message: message}}
	case "KMSInvalidStateException":
		return api.SubscribeToShardEventStream{KMSInvalidStateException: &api.KMSInvalidStateException{Message: message}}
	case "KMSNotFoundException":
		return api.SubscribeToShardEventStream{KMSNotFoundException: &api.KMSNotFoundException{Message: message}}
	case "KMSOptInRequired":
		return api.SubscribeToShardEventStream{KMSOptInRequired: &api.KMSOptInRequired{Message: message}}
	case "KMSThrottlingException":
		return api.SubscribeToShardEventStream{KMSThrottlingException: &api.KMSThrottlingException{Message: message}}
	default:
		return api.SubscribeToShardEventStream{InternalFailureException: &api.InternalFailureException{Message: message}}
	}
}

func (s *Service) subscriptionMetrics(ctx context.Context, stream StreamRecord, consumer, shardID string, event *api.SubscribeToShardEvent, bytes int, at time.Time) error {
	samples := []MetricSample{
		{ConsumerName: consumer, Name: "SubscribeToShardEvent.Bytes", Value: float64(bytes), SampleCount: 1},
		{ConsumerName: consumer, Name: "SubscribeToShardEvent.Records", Value: float64(len(event.Records)), SampleCount: 1},
		{ConsumerName: consumer, Name: "SubscribeToShardEvent.MillisBehindLatest", Value: float64(*event.MillisBehindLatest), SampleCount: 1},
		{ConsumerName: consumer, Name: "SubscribeToShardEvent.Success", Value: 1, SampleCount: 1},
	}
	for _, monitoring := range stream.Data.EnhancedMonitoring {
		if slices.Contains(monitoring.ShardLevelMetrics, api.MetricsNameOUTGOING_BYTES) || slices.Contains(monitoring.ShardLevelMetrics, api.MetricsNameALL) {
			samples = append(samples, MetricSample{ShardID: shardID, Name: "OutgoingBytes", Value: float64(bytes), SampleCount: 1})
		}
		if slices.Contains(monitoring.ShardLevelMetrics, api.MetricsNameOUTGOING_RECORDS) || slices.Contains(monitoring.ShardLevelMetrics, api.MetricsNameALL) {
			samples = append(samples, MetricSample{ShardID: shardID, Name: "OutgoingRecords", Value: float64(len(event.Records)), SampleCount: 1})
		}
	}
	return s.recordSubscriptionSamples(ctx, stream.Key, at, samples)
}

func (s *Service) recordSubscriptionSamples(ctx context.Context, stream StreamKey, at time.Time, samples []MetricSample) error {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.AddMetricSamples(MetricPublicationKey{Stream: stream, Minute: at.UTC().Truncate(time.Minute)}, samples)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}
