package lambda

import (
	"context"
	"errors"
	"testing"
	"time"
)

type rollbackPollingCapture struct {
	Repository
	armed   bool
	failure error
}

func (r *rollbackPollingCapture) Update(ctx context.Context, apply func(Transaction) error) error {
	if !r.armed {
		return r.Repository.Update(ctx, apply)
	}
	r.armed = false
	// Apply the actual page writes, then fail their transaction. The underlying
	// repository, rather than this boundary wrapper, owns rollback.
	return r.Repository.Update(ctx, func(tx Transaction) error {
		if err := apply(tx); err != nil {
			return err
		}
		return r.failure
	})
}

type pagePollingSource struct {
	streamConsumer
	record StreamQueuedRecord
}

func (pagePollingSource) Describe(context.Context) (streamDescription, error) {
	return streamDescription{Retention: 24 * time.Hour, Shards: []streamShard{{ID: "shard"}}}, nil
}

func (s pagePollingSource) Read(context.Context, EventSourceMappingRecord, *StreamShardRecord, string, time.Time) (streamPage, error) {
	return streamPage{Records: []StreamQueuedRecord{s.record}, Checkpoint: s.record.Sequence, Iterator: "next-source-page"}, nil
}

func TestStreamCaptureRollbackCannotLeakIntoRetainedExecution(t *testing.T) {
	s, manual, engine, ctx, function, mapping := pollingFixture(t, nil)
	mapping.Settings.Stream.MaximumRecordAge = 60 * time.Second
	mapping.Settings.Stream.OnFailure = "arn:aws:sqs:us-east-1:111111111111:rolled-back-failures"
	shard := StreamShardRecord{Key: StreamShardKey{Mapping: mapping.Key, ShardID: "shard"}, Checkpoint: "1", Retention: 24 * time.Hour, Lanes: []StreamLane{{Records: []StreamQueuedRecord{pollingStreamRecord(t, "1", manual.Now().Add(-60*time.Second), false)}}}}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutEventSourceMapping(mapping); err != nil {
			return err
		}
		return tx.PutStreamShard(shard)
	}); err != nil {
		t.Fatal(err)
	}
	captureError := errors.New("page transaction rejected")
	s.repository = &rollbackPollingCapture{Repository: s.repository, armed: true, failure: captureError}
	iterators := map[string]string{"shard": "committed-source-page"}
	source := pagePollingSource{record: pollingStreamRecord(t, "2", manual.Now(), false)}
	if err := s.pollStreamMapping(ctx, mapping, function, source, iterators, nil); !errors.Is(err, captureError) {
		t.Fatalf("capture transaction failure was hidden: %v", err)
	}
	if iterators["shard"] != "committed-source-page" || len(engine.invocations()) != 0 {
		t.Fatal("rolled-back page advanced the source iterator or invoked customer code")
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		shards, err := r.StreamShards(mapping.Key)
		if err != nil {
			return err
		}
		if len(shards) != 1 || shards[0].Checkpoint != "1" || len(shards[0].Lanes[0].Records) != 0 {
			t.Fatalf("retained expiry resurrected the rolled-back page: %+v", shards)
		}
		failures, err := r.StreamFailures()
		if err != nil {
			return err
		}
		if len(failures) != 1 || failures[0].RecordCount != 1 {
			t.Fatalf("capture failure suspended or enlarged the committed discard: %+v", failures)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
