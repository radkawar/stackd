package stackd_test

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"stackd"
	"stackd/clock"
	engine "stackd/engine/kinesis"
	"stackd/internal/awsctx"
	"stackd/storage"
	kinesisstore "stackd/storage/kinesis"
)

// Park an actual append while it owns the native gate; all bytes still go to
// Kafka. Repository observation below proves the second request has already
// authorized against the old state before the independently committed revoke.
type kinesisGatePause struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *kinesisGatePause) unblock() { p.once.Do(func() { close(p.release) }) }

type kinesisGateRuntime struct {
	engine.Runtime
	pause atomic.Pointer[kinesisGatePause]
}

func (r *kinesisGateRuntime) Open(ctx context.Context, spec engine.Specification) (engine.Log, error) {
	log, err := r.Runtime.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &kinesisGateLog{Log: log, runtime: r}, nil
}

type kinesisGateLog struct {
	engine.Log
	runtime *kinesisGateRuntime
}

func (l *kinesisGateLog) Append(ctx context.Context, partition int32, records []engine.Record) (int64, error) {
	if pause := l.runtime.pause.Swap(nil); pause != nil {
		close(pause.entered)
		select {
		case <-pause.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return l.Log.Append(ctx, partition, records)
}

type kinesisGateObservation struct {
	principal string
	ready     chan struct{}
}

type kinesisGateRepository struct {
	kinesisstore.Repository
	observation atomic.Pointer[kinesisGateObservation]
}

func (r *kinesisGateRepository) View(ctx context.Context, fn func(kinesisstore.Reader) error) error {
	observation := r.observation.Load()
	seen := false
	err := r.Repository.View(ctx, func(reader kinesisstore.Reader) error {
		return fn(kinesisGateReader{Reader: reader, seen: &seen})
	})
	if err == nil && seen && observation != nil && awsctx.FromContext(ctx).PrincipalARN == observation.principal && r.observation.CompareAndSwap(observation, nil) {
		close(observation.ready)
	}
	return err
}

type kinesisGateReader struct {
	kinesisstore.Reader
	seen *bool
}

func (r kinesisGateReader) Stream(key kinesisstore.StreamKey) (kinesisstore.StreamRecord, error) {
	stream, err := r.Reader.Stream(key)
	if err == nil {
		*r.seen = true
	}
	return stream, err
}

func TestKinesisGateAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runtime := &kinesisGateRuntime{Runtime: newKinesisReplayRuntime(t)}
			backends := storage.NewMemory()
			if backend == "sqlite" {
				var closeDatabase func()
				backends, closeDatabase = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
				t.Cleanup(closeDatabase)
			}
			repository := &kinesisGateRepository{Repository: backends.Kinesis}
			backends.Kinesis = repository
			source := clock.NewManual(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
			cloud := clockCloud(t, stackd.Config{Clock: source, Storage: backends, KinesisRuntime: runtime})
			root := cloud.kinesis("test", "test", "")
			identity := cloud.iam("test", "test", "")
			principal, key, secret := cloud.user(t, "test", "actor")
			actor := cloud.kinesis(key, secret, "")
			name := "gate-authority"
			if _, err := root.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &name, ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			state := awaitKinesisActive(t, source, root, name)
			arn := state.StreamDescriptionSummary.StreamARN
			put := func(ctx context.Context, client *kinesis.Client, data string) error {
				_, err := client.PutRecord(ctx, &kinesis.PutRecordInput{StreamName: &name, PartitionKey: aws.String("key"), Data: []byte(data)})
				return err
			}
			if err := put(t.Context(), root, "seed"); err != nil {
				t.Fatal(err)
			}
			shards, err := root.ListShards(t.Context(), &kinesis.ListShardsInput{StreamName: &name})
			if err != nil {
				t.Fatal(err)
			}
			expected := []string{"seed"}
			for _, operation := range []string{"PutRecord", "GetRecords"} {
				for _, change := range []string{"identity-policy", "resource-policy", "resource-tag"} {
					if !t.Run(operation+"/"+change, func(t *testing.T) {
						ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
						defer cancel()
						advanceClock(t, source, time.Second)
						policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"kinesis:%s","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/authority":"allowed"}}}}`, operation, aws.ToString(arn))
						putUserPolicy(t, identity, "actor", policy)
						if _, err := root.AddTagsToStream(ctx, &kinesis.AddTagsToStreamInput{StreamName: &name, Tags: map[string]string{"authority": "allowed"}}); err != nil {
							t.Fatal(err)
						}
						iterator, err := root.GetShardIterator(ctx, &kinesis.GetShardIteratorInput{StreamName: &name, ShardId: shards.Shards[0].ShardId, ShardIteratorType: types.ShardIteratorTypeTrimHorizon})
						if err != nil {
							t.Fatal(err)
						}
						call := func(data string) error {
							if operation == "PutRecord" {
								return put(ctx, actor, data)
							}
							page, err := actor.GetRecords(ctx, &kinesis.GetRecordsInput{ShardIterator: iterator.ShardIterator})
							if err == nil && (len(page.Records) == 0 || string(page.Records[0].Data) != "seed") {
								return fmt.Errorf("allowed read did not return the seeded native record: %v", page.Records)
							}
							return err
						}
						pause := &kinesisGatePause{entered: make(chan struct{}), release: make(chan struct{})}
						defer pause.unblock()
						runtime.pause.Store(pause)
						holder := make(chan error, 1)
						marker := operation + "/" + change + "/holder"
						go func() { holder <- put(ctx, root, marker) }()
						select {
						case <-pause.entered:
						case err := <-holder:
							t.Fatal("holder failed before native append:", err)
						case <-ctx.Done():
							t.Fatal("holder did not acquire the engine gate:", ctx.Err())
						}
						observation := &kinesisGateObservation{principal: principal, ready: make(chan struct{})}
						repository.observation.Store(observation)
						done := make(chan error, 1)
						go func() { done <- call("revoked") }()
						select {
						case <-observation.ready:
						case err := <-done:
							t.Fatal("actor failed before the engine gate:", err)
						case <-ctx.Done():
							t.Fatal("actor did not reach the engine gate:", ctx.Err())
						}
						switch change {
						case "identity-policy":
							_, err = identity.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: aws.String("actor"), PolicyName: aws.String("access")})
						case "resource-policy":
							deny := fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":{"AWS":%q},"Action":"kinesis:%s","Resource":%q}}`, principal, operation, aws.ToString(arn))
							_, err = root.PutResourcePolicy(ctx, &kinesis.PutResourcePolicyInput{ResourceARN: arn, Policy: &deny})
							advanceClock(t, source, 6*time.Second)
						case "resource-tag":
							_, err = root.RemoveTagsFromStream(ctx, &kinesis.RemoveTagsFromStreamInput{StreamName: &name, TagKeys: []string{"authority"}})
						}
						if err != nil {
							t.Fatal(err)
						}
						pause.unblock()
						select {
						case err := <-done:
							assertAPIError(t, err, "AccessDeniedException")
						case <-ctx.Done():
							t.Fatal("actor remained blocked:", ctx.Err())
						}
						select {
						case err := <-holder:
							if err != nil {
								t.Fatal(err)
							}
						case <-ctx.Done():
							t.Fatal("holder remained blocked:", ctx.Err())
						}
						expected = append(expected, marker)
						records := awaitKinesisRecords(t, source, root, aws.ToString(arn), len(expected))
						actual := make([]string, len(records))
						for i, record := range records {
							actual[i] = string(record.Data)
						}
						if !slices.Equal(actual, expected) {
							t.Fatalf("revoked request changed native data: got %q, want %q", actual, expected)
						}
						switch change {
						case "identity-policy":
							putUserPolicy(t, identity, "actor", policy)
						case "resource-policy":
							_, err = root.DeleteResourcePolicy(ctx, &kinesis.DeleteResourcePolicyInput{ResourceARN: arn})
							advanceClock(t, source, 6*time.Second)
						case "resource-tag":
							_, err = root.AddTagsToStream(ctx, &kinesis.AddTagsToStreamInput{StreamName: &name, Tags: map[string]string{"authority": "allowed"}})
						}
						if err != nil {
							t.Fatal(err)
						}
						advanceClock(t, source, time.Second)
						restored := operation + "/" + change + "/restored"
						if err := call(restored); err != nil {
							t.Fatal("restored authorization did not permit native access:", err)
						}
						if operation == "PutRecord" {
							expected = append(expected, restored)
							records := awaitKinesisRecords(t, source, root, aws.ToString(arn), len(expected))
							if len(records) != len(expected) || string(records[len(records)-1].Data) != restored {
								t.Fatal("restored write did not reach the native stream:", records)
							}
						}
					}) {
						return
					}
				}
			}
		})
	}
}
