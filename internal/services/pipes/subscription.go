package pipes

import (
	"context"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
)

type pipeSubscription struct {
	events  <-chan api.SubscribeToShardEventStream
	cancel  context.CancelFunc
	version int64
}

func (s *Service) closeSubscriptions(pipeID string) {
	for key, sub := range s.subscriptions {
		if key[0] == pipeID {
			sub.cancel()
			delete(s.subscriptions, key)
		}
	}
}

func (s *Service) readKinesisSubscription(ctx context.Context, p PipeRecord, c lambda.KinesisConsumer, cp Checkpoint, last, position string, _ int32) ([]Work, Checkpoint, *awswire.Error) {
	key := [2]string{p.ID, cp.ShardID}
	sub, ok := s.subscriptions[key]
	if ok && sub.version != p.Version {
		sub.cancel()
		delete(s.subscriptions, key)
		ok = false
	}
	if !ok {
		// The service lifetime, not a scheduler callback lifetime, owns the
		// subscription. No goroutine or additional timer loop belongs to Pipes.
		subctx, cancel := context.WithCancel(s.lifetime)
		in := &api.SubscribeToShardInput{
			ConsumerARN:      new(api.ConsumerARN(p.SourceARN)),
			ShardId:          new(api.ShardId(cp.ShardID)),
			StartingPosition: &api.StartingPosition{Type: new(api.ShardIteratorType(position)), Timestamp: p.Source.StartingTime},
		}
		if last != "" {
			in.StartingPosition.SequenceNumber = new(api.SequenceNumber(last))
		}
		out, e := c.Subscribe(subctx, in)
		if e != nil {
			cancel()
			return nil, cp, e
		}
		if out == nil || out.EventStream == nil {
			cancel()
			return nil, cp, failure("InternalException", "Kinesis returned no subscription.", 500)
		}
		sub = pipeSubscription{events: out.EventStream, cancel: cancel, version: p.Version}
		s.subscriptions[key] = sub
	}
	select {
	case <-ctx.Done():
		return nil, cp, wireError(ctx.Err())
	case frame, ok := <-sub.events:
		if !ok {
			sub.cancel()
			delete(s.subscriptions, key)
			return nil, cp, nil
		}
		event := frame.SubscribeToShardEvent
		if event == nil {
			sub.cancel()
			delete(s.subscriptions, key)
			code, message := "InternalFailure", "Kinesis subscription failed."
			switch {
			case frame.ResourceNotFoundException != nil:
				code = "ResourceNotFoundException"
				message = value(frame.ResourceNotFoundException.Message)
			case frame.ResourceInUseException != nil:
				code = "ResourceInUseException"
				message = value(frame.ResourceInUseException.Message)
			case frame.KMSAccessDeniedException != nil:
				code = "KMSAccessDeniedException"
				message = value(frame.KMSAccessDeniedException.Message)
			}
			return nil, cp, failure(code, message, 400)
		}
		cp.Closed = value(event.ContinuationSequenceNumber) == ""
		if cp.Closed {
			sub.cancel()
			delete(s.subscriptions, key)
		}
		records, e := kinesisWork(p, cp.ShardID, event.Records, s.clock.Now())
		return records, cp, e
	default:
		return nil, cp, nil
	}
}
