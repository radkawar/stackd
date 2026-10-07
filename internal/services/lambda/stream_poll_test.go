package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	runtime "stackd/compute/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Only the customer-runtime boundary is replaced. Tests drive the ordinary
// invocation admission, retained shard transactions and real SQS commands.
// Responses are calculated from the delivered payload, not a replayed fixture.
type pollingRuntime struct {
	RoleProvider
	mu      sync.Mutex
	calls   []runtime.Invocation
	handler func(runtime.Invocation) runtime.Result
	expires time.Time
}

func (r *pollingRuntime) Assume(context.Context, string, string, string) (runtime.Credentials, *awswire.Error) {
	return runtime.Credentials{AccessKeyID: "source-test-role", Expiration: r.expires}, nil
}

func (r *pollingRuntime) Prepare(context.Context, runtime.Specification) (runtime.Environment, error) {
	return pollingEnvironment{runtime: r}, nil
}

func (r *pollingRuntime) invocations() []runtime.Invocation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]runtime.Invocation(nil), r.calls...)
}

type pollingEnvironment struct{ runtime *pollingRuntime }

func (e pollingEnvironment) Invoke(_ context.Context, in runtime.Invocation, respond func(runtime.Result)) (runtime.Report, error) {
	in.Payload = append([]byte(nil), in.Payload...)
	e.runtime.mu.Lock()
	e.runtime.calls = append(e.runtime.calls, in)
	e.runtime.mu.Unlock()
	result := e.runtime.handler(in)
	respond(result)
	status := runtime.InvocationSuccess
	if result.FunctionError != "" {
		status = runtime.InvocationFailure
	}
	return runtime.Report{Status: status, FunctionFailed: result.FunctionError != ""}, nil
}

func (pollingEnvironment) Close(context.Context) error { return nil }

func pollingFixture(t *testing.T, handler func(runtime.Invocation) runtime.Result) (*Service, *clock.Manual, *pollingRuntime, context.Context, FunctionRecord, EventSourceMappingRecord) {
	t.Helper()
	manual := clock.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	scope := Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.Account})
	engine := &pollingRuntime{handler: handler, expires: manual.Now().Add(24 * time.Hour)}
	s := aliasOwnerService(t, Config{Clock: manual, Executor: engine, Roles: engine})
	function := FunctionRecord{Key: FunctionKey{Scope: scope, Name: "source-worker"}, State: "Active", UpdateStatus: "Successful", Role: "arn:aws:iam::111111111111:role/worker", Runtime: "provided.al2023", Handler: "bootstrap", Architecture: "x86_64", Timeout: 30, MemoryMB: 128, EphemeralMB: 512, CodeSHA256: "source-code", DeploymentRevision: "source-deployment"}
	mapping := EventSourceMappingRecord{Key: EventSourceMappingKey{Scope: scope, UUID: "source-mapping"}, Function: FunctionReference{FunctionKey: function.Key}, State: "Enabled", Version: 1, EventSourceARN: "arn:aws:kinesis:us-east-1:111111111111:stream/results", Settings: EventSourceMappingSettings{BatchSize: 100, Stream: &StreamMappingSettings{StartingPosition: "TRIM_HORIZON", ParallelizationFactor: 1, MaximumRetryAttempts: -1, MaximumRecordAge: -time.Second}}}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutCodeArchive(CodeArchive{Key: CodeArchiveKey{Scope: scope, SHA256: function.CodeSHA256}, Code: []byte("runtime-boundary-test"), CreatedAt: manual.Now()}); err != nil {
			return err
		}
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		return tx.PutEventSourceMapping(mapping)
	}); err != nil {
		t.Fatal(err)
	}
	return s, manual, engine, ctx, function, mapping
}

func pollingStreamRecord(t *testing.T, sequence string, at time.Time, poison bool) StreamQueuedRecord {
	t.Helper()
	payload, err := sourceJSON(map[string]any{"eventID": "shard:" + sequence, "poison": poison, "kinesis": map[string]any{"sequenceNumber": sequence}})
	if err != nil {
		t.Fatal(err)
	}
	return StreamQueuedRecord{ID: "shard:" + sequence, Sequence: sequence, ItemKey: "ordered-key", CreatedAt: at, CapturedAt: at, Payload: payload}
}

func TestStreamBatchingWindowCannotPostponeRecordAge(t *testing.T) {
	s, manual, engine, ctx, function, mapping := pollingFixture(t, func(runtime.Invocation) runtime.Result {
		panic("expired records must not invoke a runtime")
	})
	mapping.Settings.BatchingWindow = 120 * time.Second
	mapping.Settings.Stream.MaximumRecordAge = 60 * time.Second
	mapping.Settings.Stream.OnFailure = "arn:aws:sqs:us-east-1:111111111111:stream-age-failures"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
		t.Fatal(err)
	}
	lane := StreamLane{Records: []StreamQueuedRecord{pollingStreamRecord(t, "1", manual.Now(), false)}}
	if prepareStreamLane(mapping, &lane, false, manual.Now().Add(60*time.Second-time.Nanosecond)) {
		t.Fatal("underfilled batch became ready before its age deadline")
	}
	if err := manual.Advance(60 * time.Second); err != nil {
		t.Fatal(err)
	}
	if !prepareStreamLane(mapping, &lane, false, manual.Now()) {
		t.Fatal("batching window postponed the record-age decision")
	}
	shard := StreamShardRecord{Key: StreamShardKey{Mapping: mapping.Key, ShardID: "shard"}, Checkpoint: "1", Retention: 24 * time.Hour, Lanes: []StreamLane{lane}}
	if err := s.processStreamShard(ctx, mapping, function, &shard); err != nil {
		t.Fatal(err)
	}
	if len(engine.invocations()) != 0 || len(shard.Lanes[0].Records) != 0 {
		t.Fatalf("expired record invoked or remained queued: %+v", shard)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		failures, err := r.StreamFailures()
		if err != nil {
			return err
		}
		if len(failures) != 1 || failures[0].RecordCount != 1 {
			t.Fatalf("age discard did not retain its destination command: %+v", failures)
		}
		var document struct{ RequestContext struct{ Condition string } }
		if err := json.Unmarshal(failures[0].Payload, &document); err != nil {
			return err
		}
		if document.RequestContext.Condition != "RecordAgeExceeded" {
			t.Fatalf("age discard used condition %q", document.RequestContext.Condition)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type failingPollingRead struct {
	streamConsumer
	failure *awswire.Error
}

func (f failingPollingRead) Describe(context.Context) (streamDescription, error) {
	return streamDescription{Retention: 24 * time.Hour, Shards: []streamShard{{ID: "shard"}}}, nil
}

func (f failingPollingRead) Read(context.Context, EventSourceMappingRecord, *StreamShardRecord, string, time.Time) (streamPage, error) {
	return streamPage{}, f.failure
}

func TestStreamReadFailureDoesNotSuspendRetainedExpiry(t *testing.T) {
	s, manual, _, ctx, function, mapping := pollingFixture(t, func(runtime.Invocation) runtime.Result {
		panic("expired captured records must not invoke a runtime")
	})
	queue := pollingQueueFixture(t, ctx, manual, "retained-failures", false)
	s.streamTargets = queue
	mapping.Settings.Stream.MaximumRecordAge = 60 * time.Second
	mapping.Settings.Stream.OnFailure = queue.arn
	shard := StreamShardRecord{Key: StreamShardKey{Mapping: mapping.Key, ShardID: "shard"}, Checkpoint: "7", Retention: 24 * time.Hour, Lanes: []StreamLane{{Records: []StreamQueuedRecord{pollingStreamRecord(t, "7", manual.Now().Add(-60*time.Second), false)}}}}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutEventSourceMapping(mapping); err != nil {
			return err
		}
		return tx.PutStreamShard(shard)
	}); err != nil {
		t.Fatal(err)
	}
	readError := &awswire.Error{Code: "ExpiredIteratorException", Message: "source iterator expired", StatusCode: 400}
	iterators := map[string]string{"shard": "expired"}
	if err := s.pollStreamMapping(ctx, mapping, function, failingPollingRead{failure: readError}, iterators, nil); !errors.Is(err, readError) {
		t.Fatalf("source error was hidden: %v", err)
	}
	if _, exists := iterators["shard"]; exists {
		t.Fatal("expired source iterator remained reusable")
	}
	var failure StreamFailure
	if err := s.repository.View(ctx, func(r Reader) error {
		shards, err := r.StreamShards(mapping.Key)
		if err != nil {
			return err
		}
		if len(shards) != 1 || shards[0].Checkpoint != "7" || len(shards[0].Lanes[0].Records) != 0 || shards[0].ReadComplete {
			t.Fatalf("read error lost its cursor or suspended retained expiry: %+v", shards)
		}
		failures, err := r.StreamFailures()
		if err != nil {
			return err
		}
		if len(failures) != 1 {
			t.Fatalf("read failure suspended the on-failure command: %+v", failures)
		}
		failure = failures[0]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverStreamFailure(failure); err != nil {
		t.Fatal(err)
	}
	messages := queue.receive(t, 10)
	if len(messages) != 1 || string(value(messages[0].Body)) != string(failure.Payload) {
		t.Fatalf("retained failure never reached real SQS: %+v", messages)
	}
}

func TestStreamBisectionIsolatesPoisonAndDeliversSQSMetadata(t *testing.T) {
	s, manual, engine, ctx, function, mapping := pollingFixture(t, func(in runtime.Invocation) runtime.Result {
		var event struct{ Records []struct{ Poison bool } }
		if err := json.Unmarshal(in.Payload, &event); err != nil {
			panic(err)
		}
		for _, record := range event.Records {
			if record.Poison {
				return runtime.Result{FunctionError: "Unhandled", Payload: []byte(`{"errorMessage":"poison"}`)}
			}
		}
		return runtime.Result{Payload: []byte(`{}`)}
	})
	queue := pollingQueueFixture(t, ctx, manual, "bisected-failures", false)
	s.streamTargets = queue
	mapping.Settings.Stream.MaximumRetryAttempts = 1
	mapping.Settings.Stream.BisectBatchOnFunctionError = true
	mapping.Settings.Stream.OnFailure = queue.arn
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
		t.Fatal(err)
	}
	shard := StreamShardRecord{Key: StreamShardKey{Mapping: mapping.Key, ShardID: "shard"}, Checkpoint: "4", Retention: 24 * time.Hour, Lanes: []StreamLane{{Records: []StreamQueuedRecord{
		pollingStreamRecord(t, "1", manual.Now(), false), pollingStreamRecord(t, "2", manual.Now(), true), pollingStreamRecord(t, "3", manual.Now(), false), pollingStreamRecord(t, "4", manual.Now(), false),
	}}}}
	for range 6 {
		if len(shard.Lanes[0].Batches) > 0 {
			if due := shard.Lanes[0].Batches[0].Due; due.After(manual.Now()) {
				if err := manual.Advance(due.Sub(manual.Now())); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := s.processStreamShard(ctx, mapping, function, &shard); err != nil {
			t.Fatal(err)
		}
		s.work.Wait()
	}
	var sizes []int
	calls := engine.invocations()
	for _, call := range calls {
		var event struct{ Records []json.RawMessage }
		if err := json.Unmarshal(call.Payload, &event); err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(event.Records))
	}
	if !reflect.DeepEqual(sizes, []int{4, 2, 1, 1, 1, 2}) || len(shard.Lanes[0].Records) != 0 || len(shard.Lanes[0].Batches) != 0 {
		t.Fatalf("bisection lost healthy records or spent parent retry quota: sizes=%v shard=%+v", sizes, shard)
	}
	if calls[3].RequestID != calls[4].RequestID || calls[0].RequestID == calls[1].RequestID {
		t.Fatal("retry and bisected-child request identities were conflated")
	}
	var failure StreamFailure
	if err := s.repository.View(ctx, func(r Reader) error {
		failures, err := r.StreamFailures()
		if err != nil {
			return err
		}
		if len(failures) != 1 {
			t.Fatalf("poison singleton produced %d failure commands", len(failures))
		}
		failure = failures[0]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverStreamFailure(failure); err != nil {
		t.Fatal(err)
	}
	messages := queue.receive(t, 10)
	if len(messages) != 1 {
		t.Fatalf("poison singleton produced %d SQS messages", len(messages))
	}
	var document struct {
		RequestContext struct {
			Condition              string
			ApproximateInvokeCount int
		}
		KinesisBatchInfo struct {
			StreamArn, ShardId, StartSequenceNumber, EndSequenceNumber string
			BatchSize                                                  int
		}
		ResponseContext struct{ FunctionError string }
		Payload         json.RawMessage
	}
	if err := json.Unmarshal([]byte(value(messages[0].Body)), &document); err != nil {
		t.Fatal(err)
	}
	if document.RequestContext.Condition != "RetryAttemptsExhausted" || document.RequestContext.ApproximateInvokeCount != 2 || document.KinesisBatchInfo.StreamArn != mapping.EventSourceARN || document.KinesisBatchInfo.ShardId != "shard" || document.KinesisBatchInfo.StartSequenceNumber != "2" || document.KinesisBatchInfo.EndSequenceNumber != "2" || document.KinesisBatchInfo.BatchSize != 1 || document.ResponseContext.FunctionError != "Unhandled" || len(document.Payload) != 0 {
		t.Fatalf("SQS stream failure lost metadata or included customer bytes: %s", value(messages[0].Body))
	}
}
