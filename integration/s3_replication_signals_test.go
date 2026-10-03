package stackd_test

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"

	"stackd"
	"stackd/clock"
)

// Native payloads and statistics are replayed through real S3, IAM, SQS and
// CloudWatch interfaces. The manual phases are local lifecycle boundaries, not
// assertions about native publication latency or fifteen-minute RTC behavior.
func TestS3ReplicationNativeSignalsReplay(t *testing.T) {
	runS3SignalsReplay(t, "s3/replication_signals_replay.json")
}

func runS3SignalsReplay(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		Start time.Time
		Cases []struct {
			Name   string
			Setup  []s3KMSCall
			Phases []struct {
				Label                       string
				At                          time.Time
				Drain, Reopen, DiscardSetup bool
				Calls                       []s3ObjectCall
				OriginalSequences           []int
				Failures                    []s3NotifyDelivery
				Metrics                     []struct {
					Source, Actor, Region string
					Input                 cloudwatch.GetMetricStatisticsInput
					Output                json.RawMessage
					WireBytes             []struct {
						Timestamp time.Time
						Sequences []int
					}
				}
				Latencies []struct {
					Source, Actor, Region string
					Input                 cloudwatch.GetMetricStatisticsInput
					SampleCount           float64
				}
			}
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Cases {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				source := clock.NewManual(fixture.Start)
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					return startPublicCloud(t, config)
				})
				replay := newS3KMSReplay(clients)
				_, key, secret := clients.user(t, "test", "Delegated")
				putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
				replay.sessions["owner"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
				replay.sessions["caller"] = replay.sessions["owner"]
				for _, row := range scenario.Setup {
					replay.call(t, row)
				}
				puts := map[int]s3KMSCall{}
				requests := map[int]string{}
				wires := map[int]s3MultipartEventWire{}
				byRequest := map[string]int{}
				readMetric := func(actor, region, source string, input *cloudwatch.GetMetricStatisticsInput) *cloudwatch.GetMetricStatisticsOutput {
					t.Helper()
					cred, ok := replay.sessions[actor]
					if !ok {
						t.Fatalf("missing native actor %s", actor)
					}
					client := cloudwatch.New(cloudwatch.Options{Region: region, BaseEndpoint: aws.String(replay.clients.server.URL),
						Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken),
						HTTPClient:  replay.clients.server.Client(), RetryMaxAttempts: 1})
					out, err := client.GetMetricStatistics(t.Context(), input)
					if err != nil {
						t.Fatalf("%s: %v", source, err)
					}
					t.Logf("%s %s/%s: %s", actor, region, aws.ToString(input.MetricName), source)
					return out
				}
				for _, phase := range scenario.Phases {
					if !t.Run(phase.Label, func(t *testing.T) {
						if phase.Reopen {
							replay.clients, replay.httpClient = reopen(), nil
						}
						if !phase.At.Equal(source.Now()) && !phase.Drain {
							t.Fatal("clock movement requires an explicit lifecycle drain boundary")
						}
						advanceClock(t, source, phase.At.Sub(source.Now()))
						if phase.Drain {
							trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
						}
						for _, row := range phase.Calls {
							wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
							replay.httpClient = wire
							if row.Raw != nil {
								raw := *row.Raw
								raw.Sequence, raw.Label, raw.Operation = row.Sequence, row.Label, row.Operation
								raw.Status = row.Status
								actor := row.Actor
								if actor == "" {
									actor = "caller"
								}
								cred, ok := replay.sessions[actor]
								if !ok {
									t.Fatalf("missing native actor %s", actor)
								}
								consumed := s3MultipartEventRequest(t, replay, cred, raw, source.Now())
								if consumed.id == "" || consumed.extended == "" || byRequest[consumed.id] != 0 {
									t.Fatalf("lost unique public request correlation: %+v", consumed)
								}
								wires[row.Sequence], byRequest[consumed.id] = consumed, row.Sequence
								replay.values[fmt.Sprintf("request%d", row.Sequence)] = consumed.id
							} else {
								replay.call(t, row.s3KMSCall)
							}
							if row.Operation == "PutObject" {
								puts[row.Sequence], requests[row.Sequence] = row.s3KMSCall, wire.header.Get("x-amz-request-id")
								if requests[row.Sequence] == "" {
									t.Fatal("source Put omitted public request correlation")
								}
							}
						}
						replay.httpClient = nil
						receipts := map[string][]s3NotifyReceipt{}
						for _, channel := range []string{"classic", "eventbridge"} {
							queue := replay.values["queue_"+channel]
							if queue == "" {
								continue
							}
							s3NotifyCollect(t, replay, queue, receipts)
							if phase.DiscardSetup {
								for _, receipt := range receipts[queue] {
									if channel != "classic" || receipt.payload["Event"] != "s3:TestEvent" {
										t.Fatalf("unexpected setup delivery: %#v", receipt.payload)
									}
								}
							}
						}
						if !phase.DiscardSetup && (replay.values["queue_classic"] != "" || replay.values["queue_eventbridge"] != "") {
							s3ReplicationSignalsDeliveries(t, replay, phase.OriginalSequences, phase.Failures, puts, requests, receipts)
						}
						for _, metric := range phase.Metrics {
							out := readMetric(metric.Actor, metric.Region, metric.Source, &metric.Input)
							expected := metric.Output
							if len(metric.WireBytes) != 0 {
								// Only explicitly identified native populations use wire-relative
								// lengths. Fixed object bytes retain their exact native statistics.
								if aws.ToString(metric.Input.MetricName) != "BytesDownloaded" {
									t.Fatal("wire-byte projection requires BytesDownloaded")
								}
								var projected cloudwatch.GetMetricStatisticsOutput
								if err := json.Unmarshal(expected, &projected); err != nil {
									t.Fatal(err)
								}
								for _, population := range metric.WireBytes {
									matched := false
									for i := range projected.Datapoints {
										point := &projected.Datapoints[i]
										if point.Timestamp == nil || !point.Timestamp.Equal(population.Timestamp) {
											continue
										}
										if matched || point.Unit != "Bytes" || len(population.Sequences) == 0 || point.SampleCount == nil || *point.SampleCount != float64(len(population.Sequences)) {
											t.Fatalf("invalid native wire-byte population: %+v", population)
										}
										matched = true
										sum, minimum, maximum := 0.0, math.Inf(1), 0.0
										seen := map[int]bool{}
										for _, sequence := range population.Sequences {
											wire, ok := wires[sequence]
											if !ok || seen[sequence] {
												t.Fatalf("missing or duplicate raw byte reference %d", sequence)
											}
											seen[sequence] = true
											value := float64(wire.bytesOut)
											sum += value
											minimum, maximum = math.Min(minimum, value), math.Max(maximum, value)
										}
										point.Sum, point.Minimum, point.Maximum, point.Average = aws.Float64(sum), aws.Float64(minimum), aws.Float64(maximum), aws.Float64(sum / *point.SampleCount)
									}
									if !matched {
										t.Fatalf("wire-byte population has no native timestamp: %s", population.Timestamp)
									}
								}
								var err error
								expected, err = json.Marshal(projected)
								if err != nil {
									t.Fatal(err)
								}
							}
							assertMetricStatistics(t, out, expected)
						}
						for _, latency := range phase.Latencies {
							out := readMetric(latency.Actor, latency.Region, latency.Source, &latency.Input)
							if aws.ToString(out.Label) != aws.ToString(latency.Input.MetricName) || len(out.Datapoints) != 1 {
								t.Fatalf("latency label/population differs from native: %+v", out)
							}
							point := out.Datapoints[0]
							if point.Timestamp == nil || latency.Input.StartTime == nil || !point.Timestamp.Equal(*latency.Input.StartTime) || point.Unit != "Milliseconds" {
								t.Fatalf("latency timestamp/unit differs from native: %+v", point)
							}
							if point.SampleCount == nil || *point.SampleCount != latency.SampleCount || latency.SampleCount <= 0 {
								t.Fatalf("latency sample count differs from native %g: %+v", latency.SampleCount, point)
							}
							for _, value := range []*float64{point.Minimum, point.Average, point.Maximum, point.Sum} {
								if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 {
									t.Fatalf("latency statistic must be finite and nonnegative: %+v", point)
								}
							}
							if *point.Minimum > *point.Average || *point.Average > *point.Maximum || !equalMetricNumber(*point.Sum, nativeMetricNumber(*point.Average**point.SampleCount)) {
								t.Fatalf("inconsistent latency statistics: %+v", point)
							}
						}
					}) {
						return
					}
				}
			})
		}
	}
}

func s3ReplicationSignalsDeliveries(t *testing.T, replay *s3KMSReplay, originals []int, failures []s3NotifyDelivery, puts map[int]s3KMSCall, requests map[int]string, receipts map[string][]s3NotifyReceipt) {
	t.Helper()
	classic := receipts[replay.values["queue_classic"]]
	bridge := receipts[replay.values["queue_eventbridge"]]
	// The bounded no-event controls are paired with positive original Put
	// deliveries. The direct EventBridge sink is a local routing extension;
	// the supplied native captures did not provision that sink.
	if len(classic) != len(originals)+len(failures) || len(bridge) != len(originals) {
		t.Fatalf("classic/direct deliveries = %d/%d, want %d/%d; classic=%#v direct=%#v", len(classic), len(bridge), len(originals)+len(failures), len(originals), classic, bridge)
	}
	for _, sequence := range originals {
		var input struct{ Bucket, Key string }
		if err := json.Unmarshal(puts[sequence].Input, &input); err != nil {
			t.Fatal(err)
		}
		version := replay.values[fmt.Sprintf("version%d", sequence)]
		foundClassic, foundBridge := false, false
		for _, receipt := range classic {
			payload := receipt.payload
			if payload["eventName"] != "ObjectCreated:Put" || s3NotifyRequestID(payload) != requests[sequence] {
				continue
			}
			if foundClassic || awsFixtureField(payload, "s3.bucket.name") != input.Bucket || awsFixtureField(payload, "s3.object.key") != input.Key || awsFixtureField(payload, "s3.object.versionId") != version {
				t.Fatalf("source Put delivery lost original identity: %#v", payload)
			}
			sequencer, _ := awsFixtureField(payload, "s3.object.sequencer").(string)
			requestTime, _ := payload["eventTime"].(string)
			if sequencer == "" || requestTime == "" {
				t.Fatalf("source Put omitted sequencer/request time: %#v", payload)
			}
			replay.values[fmt.Sprintf("sequencer%d", sequence)] = sequencer
			replay.values[fmt.Sprintf("requestTime%d", sequence)] = requestTime
			foundClassic = true
		}
		for _, receipt := range bridge {
			payload := receipt.payload
			if s3NotifyRequestID(payload) != requests[sequence] {
				continue
			}
			if foundBridge || payload["source"] != "aws.s3" || payload["detail-type"] != "Object Created" || payload["account"] != replay.values["account"] || payload["region"] != "us-east-1" || awsFixtureField(payload, "detail.bucket.name") != input.Bucket || awsFixtureField(payload, "detail.object.key") != input.Key || awsFixtureField(payload, "detail.object.version-id") != version {
				t.Fatalf("direct Put delivery lost source/account/region identity: %#v", payload)
			}
			foundBridge = true
		}
		if !foundClassic || !foundBridge {
			t.Fatalf("source Put %d missing positive classic/direct controls: %t/%t", sequence, foundClassic, foundBridge)
		}
	}
	for _, native := range failures {
		var want s3NotifyDelivery
		if err := json.Unmarshal(replay.rebind(t, native), &want); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, receipt := range classic {
			payload := receipt.payload
			if payload["eventName"] != want.Payload["eventName"] || awsFixtureField(payload, "s3.object.versionId") != awsFixtureField(want.Payload, "s3.object.versionId") {
				continue
			}
			if found {
				t.Fatalf("duplicate local failure delivery for %s", want.Source)
			}
			for _, id := range requests {
				if s3NotifyRequestID(payload) == id {
					t.Fatalf("replication failure reused a client request ID: %#v", payload)
				}
			}
			s3NotifyCompare(t, want.Source, want, receipt, map[string]string{})
			found = true
		}
		if !found {
			t.Fatalf("missing native failure delivery: %s", want.Source)
		}
	}
}
