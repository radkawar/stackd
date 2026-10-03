package stackd_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"stackd/clock"
	"stackd/compute/docker"
	engine "stackd/engine/kinesis"
)

// Own failed preparation attempts too, so a failed fixture leaves no native
// stream container or volume. The wrapper never substitutes record operations.
type kinesisReplayRuntime struct {
	engine.Runtime
	client *docker.Client
	mu     sync.Mutex
	specs  map[string]engine.Specification
}

func newKinesisReplayRuntime(t *testing.T) *kinesisReplayRuntime {
	t.Helper()
	if os.Getenv("STACKD_KINESIS_DOCKER") != "1" {
		t.Skip("set STACKD_KINESIS_DOCKER=1 to exercise pinned Kafka")
	}
	client, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	runtime, err := engine.NewDocker(t.Context(), engine.DockerConfig{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	r := &kinesisReplayRuntime{Runtime: runtime, client: client, specs: map[string]engine.Specification{}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, spec := range r.specs {
			if err := r.Runtime.Remove(ctx, spec); err != nil {
				t.Error(err)
			}
		}
	})
	return r
}

func (r *kinesisReplayRuntime) Open(ctx context.Context, spec engine.Specification) (engine.Log, error) {
	r.mu.Lock()
	r.specs[spec.ID] = spec
	r.mu.Unlock()
	return r.Runtime.Open(ctx, spec)
}

func (c cloudClients) kinesis(key, secret, token string) *kinesis.Client {
	return kinesis.New(kinesis.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func awaitKinesisActive(t *testing.T, source *clock.Manual, client *kinesis.Client, name string) *kinesis.DescribeStreamSummaryOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		advanceClock(t, source, 100*time.Millisecond)
		out, err := client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{StreamName: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		if out.StreamDescriptionSummary.StreamStatus == types.StreamStatusActive {
			return out
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("native stream did not become ACTIVE:", ctx.Err())
	return nil
}

func awaitKinesisConsumerActive(t *testing.T, source *clock.Manual, client *kinesis.Client, arn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		advanceClock(t, source, 250*time.Millisecond)
		state, err := client.DescribeStreamConsumer(ctx, &kinesis.DescribeStreamConsumerInput{ConsumerARN: &arn})
		if err != nil {
			t.Fatal(err)
		}
		if state.ConsumerDescription.ConsumerStatus == types.ConsumerStatusActive {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Kinesis consumer did not become ACTIVE:", ctx.Err())
}

// The destination fixtures use one shard; retain the iterator across polls so
// duplicate native records remain observable rather than being deduplicated.
func awaitKinesisRecords(t *testing.T, source *clock.Manual, client *kinesis.Client, streamARN string, count int) []types.Record {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	shards, err := client.ListShards(ctx, &kinesis.ListShardsInput{StreamARN: &streamARN})
	if err != nil {
		t.Fatal(err)
	}
	if len(shards.Shards) != 1 {
		t.Fatalf("destination fixture requires one shard, got %d", len(shards.Shards))
	}
	iterator, err := client.GetShardIterator(ctx, &kinesis.GetShardIteratorInput{StreamARN: &streamARN, ShardId: shards.Shards[0].ShardId, ShardIteratorType: types.ShardIteratorTypeTrimHorizon})
	if err != nil {
		t.Fatal(err)
	}
	var records []types.Record
	for ctx.Err() == nil {
		advanceClock(t, source, 200*time.Millisecond)
		page, err := client.GetRecords(ctx, &kinesis.GetRecordsInput{StreamARN: &streamARN, ShardIterator: iterator.ShardIterator})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, page.Records...)
		if len(records) >= count {
			return records
		}
		iterator.ShardIterator = page.NextShardIterator
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("native stream returned %d records, want %d: %v", len(records), count, ctx.Err())
	return nil
}
