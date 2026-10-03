package stackd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"stackd"
	"stackd/clock"
)

func TestKinesisRetainedSubscription(t *testing.T) {
	var fixture struct {
		Records []struct {
			PartitionKey, Data string
			Encrypted          bool
		}
		ResumedData string
	}
	data, err := os.ReadFile("../testdata/kinesis/subscriptions.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runtime := newKinesisReplayRuntime(t)
			start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
			source := clock.NewManual(start)
			cloud, reopen := retainedCloud(t, backend, stackd.Config{Clock: source, KinesisRuntime: runtime})
			client := cloud.kinesis("test", "test", "")
			name := "subscription-history"
			if _, err := client.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &name, ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			summary := awaitKinesisActive(t, source, client, name)
			arn := summary.StreamDescriptionSummary.StreamARN
			encrypted := false
			for _, record := range fixture.Records {
				if record.Encrypted != encrypted {
					if record.Encrypted {
						_, err = client.StartStreamEncryption(t.Context(), &kinesis.StartStreamEncryptionInput{StreamARN: arn, EncryptionType: types.EncryptionTypeKms, KeyId: aws.String("alias/aws/kinesis")})
					} else {
						_, err = client.StopStreamEncryption(t.Context(), &kinesis.StopStreamEncryptionInput{StreamARN: arn, EncryptionType: types.EncryptionTypeKms, KeyId: aws.String("alias/aws/kinesis")})
					}
					if err != nil {
						t.Fatal(err)
					}
					awaitKinesisActive(t, source, client, name)
					encrypted = record.Encrypted
				}
				if _, err := client.PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: arn, PartitionKey: &record.PartitionKey, Data: []byte(record.Data)}); err != nil {
					t.Fatal(err)
				}
			}
			cloud = reopen()
			client = cloud.kinesis("test", "test", "")
			shards, err := client.ListShards(t.Context(), &kinesis.ListShardsInput{StreamARN: arn})
			if err != nil {
				t.Fatal(err)
			}
			shard := shards.Shards[0].ShardId
			consumer, err := client.RegisterStreamConsumer(t.Context(), &kinesis.RegisterStreamConsumerInput{StreamARN: arn, ConsumerName: aws.String("reader")})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			awaitKinesisConsumerActive(t, source, client, aws.ToString(consumer.Consumer.ConsumerARN))
			input := &kinesis.SubscribeToShardInput{ConsumerARN: consumer.Consumer.ConsumerARN, ShardId: shard, StartingPosition: &types.StartingPosition{Type: types.ShardIteratorTypeTrimHorizon}}
			// Before the transaction-context fix this request timed out on SQLite
			// before HTTP headers: consumer IAM evaluation could not join the view.
			first, err := client.SubscribeToShard(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			defer first.GetStream().Close()
			event := nextKinesisSubscription(t, ctx, first)
			if len(event.Records) != len(fixture.Records) {
				t.Fatalf("historical records: %v", event.Records)
			}
			for i, record := range event.Records {
				want := fixture.Records[i]
				if string(record.Data) != want.Data || aws.ToString(record.PartitionKey) != want.PartitionKey || (record.EncryptionType == types.EncryptionTypeKms) != want.Encrypted {
					t.Fatalf("historical record %d: %+v", i, record)
				}
			}
			if _, err = client.SubscribeToShard(ctx, input); err == nil {
				t.Fatal("concurrent lease accepted inside five seconds")
			} else {
				assertAPIError(t, err, "ResourceInUseException")
			}
			advanceClock(t, source, 6*time.Second)
			input.StartingPosition = &types.StartingPosition{Type: types.ShardIteratorTypeAtSequenceNumber, SequenceNumber: event.ContinuationSequenceNumber}
			second, err := client.SubscribeToShard(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			defer second.GetStream().Close()
			for pending := range first.GetStream().Events() {
				if frame, ok := pending.(*types.SubscribeToShardEventStreamMemberSubscribeToShardEvent); !ok || len(frame.Value.Records) != 0 {
					t.Fatalf("unexpected buffered replacement frame: %+v", pending)
				}
			}
			if err := first.GetStream().Err(); err != nil {
				t.Fatalf("native replacement EOF became a modeled error: %v", err)
			}
			advanceClock(t, source, 5*time.Second)
			event = nextKinesisSubscription(t, ctx, second)
			if len(event.Records) != 0 {
				t.Fatalf("AT checkpoint repeated historical records: %+v", event.Records)
			}
			advanceClock(t, source, 6*time.Second)
			input.StartingPosition = &types.StartingPosition{Type: types.ShardIteratorTypeAfterSequenceNumber, SequenceNumber: event.ContinuationSequenceNumber}
			third, err := client.SubscribeToShard(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			defer third.GetStream().Close()
			if _, err = client.PutRecord(ctx, &kinesis.PutRecordInput{StreamARN: arn, PartitionKey: &fixture.Records[0].PartitionKey, Data: []byte(fixture.ResumedData)}); err != nil {
				t.Fatal(err)
			}
			for {
				event = nextKinesisSubscription(t, ctx, third)
				if len(event.Records) == 0 {
					continue
				}
				if len(event.Records) != 1 || string(event.Records[0].Data) != fixture.ResumedData {
					t.Fatalf("AFTER checkpoint skipped or repeated a record: %+v", event.Records)
				}
				break
			}
			if _, err = client.SplitShard(ctx, &kinesis.SplitShardInput{StreamARN: arn, ShardToSplit: shard, NewStartingHashKey: aws.String("170141183460469231731687303715884105728")}); err != nil {
				t.Fatal(err)
			}
			awaitKinesisActive(t, source, client, name)
			for {
				event = nextKinesisSubscription(t, ctx, third)
				if len(event.ChildShards) == 0 {
					continue
				}
				if len(event.ChildShards) != 2 || event.ContinuationSequenceNumber != nil || len(event.Records) != 0 {
					t.Fatalf("closed-parent terminal frame: %+v", event)
				}
				break
			}
			third.GetStream().Close()
			// Accepted source observations must survive reopen and publish through
			// the real CloudWatch command owner, not merely remain in a Kinesis row.
			advanceClock(t, source, 2*time.Minute)
			metrics := cloudwatch.New(cloudwatch.Options{Region: "us-east-1", BaseEndpoint: aws.String(cloud.server.URL), Credentials: client.Options().Credentials, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			for {
				out, err := metrics.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{Namespace: aws.String("AWS/Kinesis"), MetricName: aws.String("IncomingRecords"), Dimensions: []cwtypes.Dimension{{Name: aws.String("StreamName"), Value: &name}}, StartTime: &start, EndTime: aws.Time(source.Now()), Period: aws.Int32(60), Statistics: []cwtypes.Statistic{cwtypes.StatisticSum}})
				if err != nil {
					t.Fatal(err)
				}
				var sum float64
				for _, point := range out.Datapoints {
					sum += aws.ToFloat64(point.Sum)
				}
				if sum == float64(len(fixture.Records)+1) {
					break
				}
				if ctx.Err() != nil {
					t.Fatalf("IncomingRecords sum=%v: %v", sum, ctx.Err())
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}

func TestKinesisNativeDeregisteredConsumer(t *testing.T) {
	var capture struct {
		DeregisteredConsumerDataControl struct {
			StartedAt      struct{ UTC time.Time }
			OwnedResources struct{ StreamName string }
			Markers        struct {
				First, Second struct{ UTF8, PartitionKey string }
			}
		}
	}
	kinesisReadFixture(t, "efo_termination", &capture)
	native := capture.DeregisteredConsumerDataControl
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(native.StartedAt.UTC.Truncate(time.Second))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source, KinesisRuntime: newKinesisReplayRuntime(t)})
			client := clients.kinesis("test", "test", "")
			if _, err := client.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &native.OwnedResources.StreamName, ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			stream := awaitKinesisActive(t, source, client, native.OwnedResources.StreamName)
			consumer, err := client.RegisterStreamConsumer(t.Context(), &kinesis.RegisterStreamConsumerInput{StreamARN: stream.StreamDescriptionSummary.StreamARN, ConsumerName: aws.String("reader")})
			if err != nil {
				t.Fatal(err)
			}
			awaitKinesisConsumerActive(t, source, client, aws.ToString(consumer.Consumer.ConsumerARN))
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			input := &kinesis.SubscribeToShardInput{ConsumerARN: consumer.Consumer.ConsumerARN, ShardId: aws.String("shardId-000000000000"), StartingPosition: &types.StartingPosition{Type: types.ShardIteratorTypeLatest}}
			out, err := client.SubscribeToShard(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			defer out.GetStream().Close()
			for index, marker := range []struct{ UTF8, PartitionKey string }{native.Markers.First, native.Markers.Second} {
				if index == 1 {
					if _, err := client.DeregisterStreamConsumer(ctx, &kinesis.DeregisterStreamConsumerInput{ConsumerARN: consumer.Consumer.ConsumerARN}); err != nil {
						t.Fatal(err)
					}
					for {
						_, err := client.DescribeStreamConsumer(ctx, &kinesis.DescribeStreamConsumerInput{ConsumerARN: consumer.Consumer.ConsumerARN})
						if err != nil {
							assertAPIError(t, err, "ResourceNotFoundException")
							break
						}
						advanceClock(t, source, 250*time.Millisecond)
						time.Sleep(50 * time.Millisecond)
					}
					_, err := client.SubscribeToShard(ctx, input)
					assertAPIError(t, err, "ResourceNotFoundException")
				}
				put, err := client.PutRecord(ctx, &kinesis.PutRecordInput{StreamName: &native.OwnedResources.StreamName, PartitionKey: &marker.PartitionKey, Data: []byte(marker.UTF8)})
				if err != nil {
					t.Fatal(err)
				}
				event := nextKinesisSubscription(t, ctx, out)
				for len(event.Records) == 0 {
					event = nextKinesisSubscription(t, ctx, out)
				}
				if len(event.Records) != 1 || string(event.Records[0].Data) != marker.UTF8 ||
					aws.ToString(event.Records[0].SequenceNumber) != aws.ToString(put.SequenceNumber) {
					t.Fatalf("accepted lease lost or changed marker %d: %+v", index, event)
				}
			}
			if err := out.GetStream().Close(); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			_, err = clients.kinesis("test", "test", "").SubscribeToShard(t.Context(), input)
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}

func TestKinesisNativeSubscriptionFrames(t *testing.T) {
	var plan struct {
		Frames []struct{ Name, Source, Group, MetricPrefix string }
	}
	kinesisReadFixture(t, "efo_replay", &plan)
	type recordObservation struct {
		PartitionKey                string
		ApproximateArrivalTimestamp time.Time
		Data                        struct{ ByteLength int }
	}
	type frameObservation struct {
		Records            []recordObservation
		MillisBehindLatest int64
	}
	type envelope struct{ SubscribeToShardEvent frameObservation }
	payload := func(record recordObservation) []byte {
		marker := []byte(record.PartitionKey + "\n")
		return bytes.Repeat(marker, (record.Data.ByteLength+len(marker)-1)/len(marker))[:record.Data.ByteLength]
	}
	for _, scenario := range plan.Frames {
		var capture struct {
			OwnedResources struct{ StreamName, ConsumerName string }
			Subscriptions  []struct {
				Group   string
				Started struct{ UTC time.Time }
				Frames  []struct{ DecodedEvent envelope }
			}
			Calls []struct {
				kinesisObservation
				StartedAt time.Time
				Events    []struct{ Event envelope }
			}
		}
		kinesisReadFixture(t, scenario.Source, &capture)
		var frames []frameObservation
		var admission time.Time
		for _, subscription := range capture.Subscriptions {
			if subscription.Group == scenario.Group {
				admission = subscription.Started.UTC.Truncate(time.Second)
				for _, frame := range subscription.Frames {
					frames = append(frames, frame.DecodedEvent.SubscribeToShardEvent)
				}
			}
		}
		for _, row := range capture.Calls {
			if row.Operation == "SubscribeToShard" && len(row.Events) != 0 {
				admission = row.StartedAt.Truncate(time.Second)
				for _, frame := range row.Events {
					frames = append(frames, frame.Event.SubscribeToShardEvent)
				}
			}
		}
		if len(frames) == 0 || len(frames[0].Records) == 0 {
			t.Fatal("missing native backlog frames")
		}
		writes := frames
		if scenario.Group != "" {
			// One full native frame plus one lookahead record distinguishes
			// these byte bounds; repeated equal-size pages add no coverage.
			writes = []frameObservation{frames[0], {Records: frames[1].Records[:1]}}
			frames = frames[:1]
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(scenario.Name+"/"+backend, func(t *testing.T) {
				clients, reopen, source := kinesisMetricCloud(t, backend, capture.OwnedResources.StreamName, frames[0].Records[0].ApproximateArrivalTimestamp.Truncate(time.Minute))
				client := clients.kinesis("test", "test", "")
				sequences := make(map[string]string)
				remaining := 0
				for _, frame := range writes {
					for _, record := range frame.Records {
						advanceClock(t, source, record.ApproximateArrivalTimestamp.Sub(source.Now()))
						out, err := client.PutRecord(t.Context(), &kinesis.PutRecordInput{StreamName: &capture.OwnedResources.StreamName, PartitionKey: &record.PartitionKey, Data: payload(record)})
						if err != nil {
							t.Fatal(err)
						}
						sequences[record.PartitionKey] = aws.ToString(out.SequenceNumber)
						remaining++
					}
				}
				streamARN := "arn:aws:kinesis:us-east-1:" + eventDeliveryAccount + ":stream/" + capture.OwnedResources.StreamName
				consumerName := capture.OwnedResources.ConsumerName
				if consumerName == "" {
					consumerName = "reader"
				}
				consumer, err := client.RegisterStreamConsumer(t.Context(), &kinesis.RegisterStreamConsumerInput{StreamARN: &streamARN, ConsumerName: &consumerName})
				if err != nil {
					t.Fatal(err)
				}
				awaitKinesisConsumerActive(t, source, client, aws.ToString(consumer.Consumer.ConsumerARN))
				advanceClock(t, source, admission.Sub(source.Now()))
				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				defer cancel()
				out, err := client.SubscribeToShard(ctx, &kinesis.SubscribeToShardInput{ConsumerARN: consumer.Consumer.ConsumerARN, ShardId: aws.String("shardId-000000000000"), StartingPosition: &types.StartingPosition{Type: types.ShardIteratorTypeTrimHorizon}})
				if err != nil {
					t.Fatal(err)
				}
				defer out.GetStream().Close()
				for index, native := range frames {
					if index != 0 {
						step := 4 * time.Second // Repay a complete native data frame's rate debt.
						if len(native.Records) == 0 {
							step = 5 * time.Second
						}
						advanceClock(t, source, step)
					}
					event := nextKinesisSubscription(t, ctx, out)
					if len(event.Records) != len(native.Records) {
						t.Fatalf("frame %d: got %d records; native %d", index, len(event.Records), len(native.Records))
					}
					remaining -= len(event.Records)
					for i, record := range event.Records {
						expected := native.Records[i]
						if !bytes.Equal(record.Data, payload(expected)) || aws.ToString(record.PartitionKey) != expected.PartitionKey ||
							aws.ToString(record.SequenceNumber) != sequences[expected.PartitionKey] ||
							!record.ApproximateArrivalTimestamp.Equal(expected.ApproximateArrivalTimestamp) {
							t.Fatalf("frame %d record %d lost payload, order, timestamp or identity", index, i)
						}
					}
					lag := aws.ToInt64(event.MillisBehindLatest)
					if native.MillisBehindLatest == 0 {
						if lag != 0 {
							t.Fatalf("caught-up frame %d reports lag %d", index, lag)
						}
					} else if remaining != 0 {
						// Native lag follows service-time age, not the distance
						// to the last written record. Transport delivery time is
						// not AWS's sampling instant, so do not pin its rounding.
						age := source.Now().Sub(*event.Records[len(event.Records)-1].ApproximateArrivalTimestamp).Milliseconds()
						if lag < age-1000 || lag > age+1000 {
							t.Fatalf("backlog frame %d lag %d does not follow record age %d", index, lag, age)
						}
					}
				}
				if scenario.MetricPrefix == "" {
					return
				}
				advanceClock(t, source, admission.Add(5*time.Minute).Sub(source.Now()))
				for event := range out.GetStream().Events() {
					t.Fatalf("unexpected frame after native terminal heartbeat: %+v", event)
				}
				if err := out.GetStream().Err(); err != nil {
					t.Fatal(err)
				}
				clients = reopen()
				for _, row := range capture.Calls {
					if !strings.HasPrefix(row.Label, scenario.MetricPrefix) {
						continue
					}
					var query cloudwatch.GetMetricStatisticsInput
					if err := json.Unmarshal(row.Input, &query); err != nil {
						t.Fatal(err)
					}
					advanceClock(t, source, query.EndTime.Sub(source.Now()))
					trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
					if aws.ToString(query.MetricName) == "SubscribeToShardEvent.MillisBehindLatest" {
						// Positive age is approximate and checked at the API
						// edge above; subsequent caught-up samples are exact.
						query.StartTime = aws.Time(admission.Truncate(time.Minute).Add(time.Minute))
					}
					t.Run(row.Label, func(t *testing.T) {
						kinesisMetricQuery(t, clients, row.kinesisObservation, *query.StartTime, *query.EndTime)
					})
				}
			})
		}
	}
}

func nextKinesisSubscription(t *testing.T, ctx context.Context, out *kinesis.SubscribeToShardOutput) types.SubscribeToShardEvent {
	t.Helper()
	select {
	case event, ok := <-out.GetStream().Events():
		if !ok {
			t.Fatalf("subscription ended before expected event: %v", out.GetStream().Err())
		}
		value, ok := event.(*types.SubscribeToShardEventStreamMemberSubscribeToShardEvent)
		if !ok {
			t.Fatalf("unexpected subscription event: %T", event)
		}
		return value.Value
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return types.SubscribeToShardEvent{}
}
