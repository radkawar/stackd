package stackd_test

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestKinesisNativeMetricDistributions(t *testing.T) {
	var plan struct {
		Source   string
		Standard struct {
			StartTime, EndTime time.Time
			Operations         []struct {
				Label string
				At    time.Time
			}
			Queries []string
		}
		Consumer struct {
			AdmissionAt, StartTime, EndTime time.Time
			HeartbeatSeconds                int
			Queries                         []struct {
				Label     string
				Admission bool
			}
		}
	}
	kinesisReadFixture(t, "metric_replay", &plan)
	var capture struct {
		OwnedResources struct{ StreamName, ConsumerName string }
		Calls          []kinesisObservation
	}
	kinesisReadFixture(t, plan.Source, &capture)
	rows := make(map[string]kinesisObservation, len(capture.Calls))
	for _, row := range capture.Calls {
		rows[row.Label] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend+"/standard", func(t *testing.T) {
			clients, reopen, source := kinesisMetricCloud(t, backend, capture.OwnedResources.StreamName, plan.Standard.StartTime)
			// Visit complete idle minutes rather than jumping over them. No API
			// call, publication deadline or restart may manufacture Success zeros.
			for at := plan.Standard.StartTime; at.Before(plan.Standard.Operations[0].At); at = at.Add(time.Minute) {
				advanceClock(t, source, at.Sub(source.Now()))
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			}
			bindings := map[string]string{}
			for _, operation := range plan.Standard.Operations {
				row := rows[operation.Label]
				advanceClock(t, source, operation.At.Sub(source.Now()))
				out, err := awstest.CallSDK(t.Context(), clients.kinesis("test", "test", ""), row.Operation, json.RawMessage(aasReplace(string(row.Input), bindings)))
				if err != nil {
					t.Fatalf("%s: %v", operation.Label, err)
				}
				var native struct {
					ShardIterator, NextShardIterator string
					MillisBehindLatest               int64
					Records                          []kinesistypes.Record
				}
				if err := json.Unmarshal(row.Result.Output, &native); err != nil {
					t.Fatal(err)
				}
				switch result := out.(type) {
				case *kinesis.GetShardIteratorOutput:
					bindings[native.ShardIterator] = aws.ToString(result.ShardIterator)
				case *kinesis.GetRecordsOutput:
					if len(result.Records) != len(native.Records) || aws.ToInt64(result.MillisBehindLatest) != native.MillisBehindLatest {
						t.Fatalf("%s: records/lag = %d/%d; native %d/%d", row.Label, len(result.Records), aws.ToInt64(result.MillisBehindLatest), len(native.Records), native.MillisBehindLatest)
					}
					bindings[native.NextShardIterator] = aws.ToString(result.NextShardIterator)
				}
			}
			// The read minute is still open: its accepted metric samples must
			// survive reopening before their publication becomes due.
			clients = reopen()
			advanceClock(t, source, plan.Standard.EndTime.Sub(source.Now()))
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			for _, label := range plan.Standard.Queries {
				t.Run(label, func(t *testing.T) {
					kinesisMetricQuery(t, clients, rows[label], plan.Standard.StartTime, plan.Standard.EndTime)
				})
			}
		})
		t.Run(backend+"/consumer", func(t *testing.T) {
			clients, reopen, source := kinesisMetricCloud(t, backend, capture.OwnedResources.StreamName, plan.Consumer.AdmissionAt.Truncate(time.Minute))
			client := clients.kinesis("test", "test", "")
			streamARN := "arn:aws:kinesis:us-east-1:" + eventDeliveryAccount + ":stream/" + capture.OwnedResources.StreamName
			consumer, err := client.RegisterStreamConsumer(t.Context(), &kinesis.RegisterStreamConsumerInput{StreamARN: &streamARN, ConsumerName: &capture.OwnedResources.ConsumerName})
			if err != nil {
				t.Fatal(err)
			}
			awaitKinesisConsumerActive(t, source, client, aws.ToString(consumer.Consumer.ConsumerARN))
			advanceClock(t, source, plan.Consumer.AdmissionAt.Sub(source.Now()))
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			out, err := client.SubscribeToShard(ctx, &kinesis.SubscribeToShardInput{ConsumerARN: consumer.Consumer.ConsumerARN, ShardId: aws.String("shardId-000000000000"), StartingPosition: &kinesistypes.StartingPosition{Type: kinesistypes.ShardIteratorTypeLatest}})
			if err != nil {
				t.Fatal(err)
			}
			defer out.GetStream().Close()
			step := time.Duration(plan.Consumer.HeartbeatSeconds) * time.Second
			advanceClock(t, source, step)
			for {
				event := nextKinesisSubscription(t, ctx, out)
				if len(event.Records) != 0 || aws.ToInt64(event.MillisBehindLatest) != 0 {
					t.Fatalf("caught-up heartbeat contains records or backlog: %+v", event)
				}
				// A later event proves the preceding minute's observations have
				// committed; the disconnect minute is deliberately not compared.
				if !source.Now().Before(plan.Consumer.EndTime) {
					break
				}
				advanceClock(t, source, step)
			}
			if err := out.GetStream().Close(); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			for _, query := range plan.Consumer.Queries {
				start, end := plan.Consumer.StartTime, plan.Consumer.EndTime
				if query.Admission {
					start = plan.Consumer.AdmissionAt.Truncate(time.Minute)
					end = start.Add(time.Minute)
				}
				t.Run(query.Label, func(t *testing.T) { kinesisMetricQuery(t, clients, rows[query.Label], start, end) })
			}
		})
	}
}

func TestKinesisNativeSubscriptionTermination(t *testing.T) {
	var plan struct {
		Termination []struct {
			Name, Source, ConsumerName, MetricPrefix string
			HeartbeatSeconds, LifetimeSeconds        int
			ClientClose                              bool
			Statistics                               []cwtypes.Statistic
		}
	}
	kinesisReadFixture(t, "efo_replay", &plan)
	type subscriptionObservation struct {
		ConsumerName string
		StartedAt    time.Time
		Frames       []json.RawMessage
	}
	for _, scenario := range plan.Termination {
		var capture struct {
			OwnedResources struct{ StreamName string }
			Calls          []kinesisObservation
			Subscriptions  []subscriptionObservation
			Observations   []subscriptionObservation
		}
		kinesisReadFixture(t, scenario.Source, &capture)
		var admission time.Time
		var frames int
		for _, subscription := range append(capture.Subscriptions, capture.Observations...) {
			if subscription.ConsumerName == scenario.ConsumerName {
				admission = subscription.StartedAt.Truncate(time.Second)
				frames = len(subscription.Frames)
			}
		}
		var queries []kinesisObservation
		for _, row := range capture.Calls {
			if strings.HasPrefix(row.Label, scenario.MetricPrefix) {
				queries = append(queries, row)
			}
		}
		if admission.IsZero() || len(queries) == 0 {
			t.Fatal("missing selected native subscription or metric checkpoint")
		}
		var window cloudwatch.GetMetricStatisticsInput
		if err := json.Unmarshal(queries[0].Input, &window); err != nil {
			t.Fatal(err)
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(scenario.Name+"/"+backend, func(t *testing.T) {
				clients, reopen, source := kinesisMetricCloud(t, backend, capture.OwnedResources.StreamName, admission.Truncate(time.Minute))
				client := clients.kinesis("test", "test", "")
				streamARN := "arn:aws:kinesis:us-east-1:" + eventDeliveryAccount + ":stream/" + capture.OwnedResources.StreamName
				consumer, err := client.RegisterStreamConsumer(t.Context(), &kinesis.RegisterStreamConsumerInput{StreamARN: &streamARN, ConsumerName: &scenario.ConsumerName})
				if err != nil {
					t.Fatal(err)
				}
				awaitKinesisConsumerActive(t, source, client, aws.ToString(consumer.Consumer.ConsumerARN))
				advanceClock(t, source, admission.Sub(source.Now()))
				ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
				defer cancel()
				out, err := client.SubscribeToShard(ctx, &kinesis.SubscribeToShardInput{ConsumerARN: consumer.Consumer.ConsumerARN, ShardId: aws.String("shardId-000000000000"), StartingPosition: &kinesistypes.StartingPosition{Type: kinesistypes.ShardIteratorTypeLatest}})
				if err != nil {
					t.Fatal(err)
				}
				defer out.GetStream().Close()
				for range frames {
					advanceClock(t, source, time.Duration(scenario.HeartbeatSeconds)*time.Second)
					event := nextKinesisSubscription(t, ctx, out)
					if len(event.Records) != 0 || aws.ToInt64(event.MillisBehindLatest) != 0 {
						t.Fatalf("native empty heartbeat: %+v", event)
					}
				}
				if scenario.ClientClose {
					if err := out.GetStream().Close(); err != nil {
						t.Fatal(err)
					}
					// Let TCP cancellation reach the server before jumping its
					// independent service clock beyond the lease's expiry.
					time.Sleep(100 * time.Millisecond)
				} else {
					advanceClock(t, source, admission.Add(time.Duration(scenario.LifetimeSeconds)*time.Second).Sub(source.Now()))
					select {
					case _, ok := <-out.GetStream().Events():
						if ok {
							t.Fatal("subscription emitted an extra frame instead of native clean EOF")
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					if err := out.GetStream().Err(); err != nil {
						t.Fatalf("native clean EOF became a modeled error: %v", err)
					}
					// Reopen before the terminal minute is published.
					clients = reopen()
				}
				advanceClock(t, source, window.EndTime.Sub(source.Now()))
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				if scenario.ClientClose {
					clients = reopen()
				}
				for _, row := range queries {
					t.Run(row.Label, func(t *testing.T) {
						// A disconnected client's decoded frame count need not
						// equal AWS's service-side count. Compare its observed
						// extrema and absence of subsequent metric buckets.
						kinesisMetricQuery(t, clients, row, *window.StartTime, *window.EndTime, scenario.Statistics...)
					})
				}
			})
		}
	}
}

func kinesisMetricCloud(t *testing.T, backend, name string, start time.Time) (cloudClients, func() cloudClients, *clock.Manual) {
	t.Helper()
	runtime := newKinesisReplayRuntime(t)
	source := clock.NewManual(start.Add(-time.Minute))
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source, KinesisRuntime: runtime})
	client := clients.kinesis("test", "test", "")
	if _, err := client.CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &name, ShardCount: aws.Int32(1)}); err != nil {
		t.Fatal(err)
	}
	awaitKinesisActive(t, source, client, name)
	if _, err := client.EnableEnhancedMonitoring(t.Context(), &kinesis.EnableEnhancedMonitoringInput{StreamName: &name, ShardLevelMetrics: []kinesistypes.MetricsName{kinesistypes.MetricsNameAll}}); err != nil {
		t.Fatal(err)
	}
	awaitKinesisActive(t, source, client, name)
	return clients, reopen, source
}

func kinesisMetricQuery(t *testing.T, clients cloudClients, row kinesisObservation, start, end time.Time, statistics ...cwtypes.Statistic) {
	t.Helper()
	if row.Operation != "GetMetricStatistics" || row.Result.Code != "Success" {
		t.Fatalf("missing successful native metric query %q", row.Label)
	}
	var input cloudwatch.GetMetricStatisticsInput
	var native cloudwatch.GetMetricStatisticsOutput
	if err := json.Unmarshal(row.Input, &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(row.Result.Output, &native); err != nil {
		t.Fatal(err)
	}
	input.StartTime, input.EndTime = &start, &end
	if len(statistics) != 0 {
		input.Statistics = statistics
	}
	out, err := metricsClient(clients, eventDeliveryAccount).GetMetricStatistics(t.Context(), &input)
	if err != nil {
		t.Fatal(err)
	}
	var expected []cwtypes.Datapoint
	for _, point := range native.Datapoints {
		if !point.Timestamp.Before(start) && point.Timestamp.Before(end) {
			if !slices.Contains(input.Statistics, cwtypes.StatisticSampleCount) {
				point.SampleCount = nil
			}
			if !slices.Contains(input.Statistics, cwtypes.StatisticSum) {
				point.Sum = nil
			}
			if !slices.Contains(input.Statistics, cwtypes.StatisticMinimum) {
				point.Minimum = nil
			}
			if !slices.Contains(input.Statistics, cwtypes.StatisticMaximum) {
				point.Maximum = nil
			}
			if !slices.Contains(input.Statistics, cwtypes.StatisticAverage) {
				point.Average = nil
			}
			expected = append(expected, point)
		}
	}
	normalize := func(points []cwtypes.Datapoint) {
		for i := range points {
			at := points[i].Timestamp.UTC()
			points[i].Timestamp = &at
		}
		slices.SortFunc(points, func(a, b cwtypes.Datapoint) int { return a.Timestamp.Compare(*b.Timestamp) })
	}
	normalize(expected)
	normalize(out.Datapoints)
	if !slices.EqualFunc(out.Datapoints, expected, func(a, b cwtypes.Datapoint) bool { return reflect.DeepEqual(a, b) }) {
		t.Fatalf("%s statistics: got %s; native %s", row.Label, mustKinesisJSON(t, out.Datapoints), mustKinesisJSON(t, expected))
	}
}
