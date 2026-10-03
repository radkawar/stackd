package stackd_test

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	kmsstore "stackd/storage/kms"
)

// This is a backend write outage, not a replacement KMS provider. Read-only KMS
// deadline discovery still works; cryptographic transactions fail atomically.
// Recovery uses the real retained keys, authorization, encryption and storage.
type s3RTCKeyStorage struct {
	kmsstore.Storage
	unavailable *atomic.Bool
}

type s3RTCKeyTransaction struct {
	kmsstore.Transaction
	unavailable *atomic.Bool
}

func (s s3RTCKeyStorage) Transact(ctx context.Context, fn func(kmsstore.Transaction) error) error {
	return s.Storage.Transact(ctx, func(tx kmsstore.Transaction) error {
		return fn(s3RTCKeyTransaction{tx, s.unavailable})
	})
}

func (s s3RTCKeyStorage) Attempt(ctx context.Context, fn func(kmsstore.Transaction) error) error {
	return s.Storage.Attempt(ctx, func(tx kmsstore.Transaction) error {
		return fn(s3RTCKeyTransaction{tx, s.unavailable})
	})
}

func (tx s3RTCKeyTransaction) PutKeySet(owner kmsstore.KeyOwner, record kmsstore.KeySetRecord) error {
	if tx.unavailable.Load() {
		return errors.New("KMS backend temporarily unavailable for writes")
	}
	return tx.Transaction.PutKeySet(owner, record)
}

// AWS documents the event meanings and fifteen-minute RTC reporting activation,
// not these local retry/publication deadlines. No native pre-activation query or
// positive threshold-event capture is claimed; the fixture distinguishes both.
func TestS3ReplicationDocumentDerivedRTC(t *testing.T) {
	var fixture struct {
		Start                                                                        time.Time
		Account, SourceBucket, DestinationBucket, RuleID, QueueName, ConfigurationID string
		Setup                                                                        []s3KMSCall
		Scenarios                                                                    []struct {
			Name, Key, Body, FailureKey, FailureBody string
			Setup                                    []s3KMSCall
			Phases                                   []struct {
				Name, Offset, Status              string
				Reopen, Recover, Delete, Withheld bool
				Events                            []string
				Metrics                           map[string]float64
				Samples                           []struct {
					Offset  string
					Metrics map[string]float64
				}
			}
		}
	}
	awsReadFixture(t, "s3/replication_rtc_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				source := clock.NewManual(fixture.Start)
				unavailable := &atomic.Bool{}
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					config.Storage.KMS = s3RTCKeyStorage{config.Storage.KMS, unavailable}
					return startPublicCloud(t, config)
				})
				replay := newS3KMSReplay(clients)
				for _, row := range fixture.Setup {
					replay.call(t, row)
				}
				for _, row := range scenario.Setup {
					replay.call(t, row)
				}
				advanceClock(t, source, 2*time.Minute)
				trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
				collect := func() []s3NotifyReceipt {
					t.Helper()
					queue, err := replay.clients.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: &fixture.QueueName})
					if err != nil {
						t.Fatal(err)
					}
					receipts := map[string][]s3NotifyReceipt{}
					s3NotifyCollect(t, replay, aws.ToString(queue.QueueUrl), receipts)
					return receipts[aws.ToString(queue.QueueUrl)]
				}
				initial := collect()
				if len(initial) != 1 || initial[0].payload["Event"] != "s3:TestEvent" {
					t.Fatalf("notification destination was not validated: %#v", initial)
				}
				created := source.Now()
				put, err := replay.s3Client("caller").PutObject(t.Context(), &s3.PutObjectInput{
					Bucket: &fixture.SourceBucket, Key: &scenario.Key, Body: strings.NewReader(scenario.Body),
					ServerSideEncryption: "aws:kms", SSEKMSKeyId: aws.String(replay.values["keyARN"]),
				})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToString(put.VersionId) == "" || aws.ToString(put.VersionId) == "null" {
					t.Fatal("versioned upload did not return a version")
				}
				var failedPut *s3.PutObjectOutput
				if scenario.FailureKey != "" {
					failedPut, err = replay.s3Client("caller").PutObject(t.Context(), &s3.PutObjectInput{
						Bucket: &fixture.SourceBucket, Key: &scenario.FailureKey, Body: strings.NewReader(scenario.FailureBody),
						ServerSideEncryption: "aws:kms", SSEKMSKeyId: aws.String(replay.values["keyARN"]),
					})
					if err != nil {
						t.Fatal(err)
					}
					if aws.ToString(failedPut.VersionId) == "" || aws.ToString(failedPut.VersionId) == "null" {
						t.Fatal("versioned denied sibling upload did not return a version")
					}
				}
				unavailable.Store(true)
				requests := map[string]bool{}
				for _, phase := range scenario.Phases {
					if !t.Run(phase.Name, func(t *testing.T) {
						if phase.Reopen {
							replay.clients = reopen()
						}
						if phase.Recover {
							unavailable.Store(false)
						}
						offset, err := time.ParseDuration(phase.Offset)
						if err != nil {
							t.Fatal(err)
						}
						advanceClock(t, source, created.Add(offset).Sub(source.Now()))
						if phase.Delete {
							deleted, err := replay.s3Client("caller").DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: &fixture.SourceBucket, Key: &scenario.Key, VersionId: put.VersionId})
							if err != nil || aws.ToString(deleted.VersionId) != aws.ToString(put.VersionId) || aws.ToBool(deleted.DeleteMarker) {
								t.Fatalf("explicit source-version deletion: %+v, %v", deleted, err)
							}
						}
						trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
						receipts := collect()
						if len(receipts) != len(phase.Events) {
							t.Fatalf("document-derived events: got %#v, want %v", receipts, phase.Events)
						}
						for i, name := range phase.Events {
							payload := receipts[i].payload
							key, body, version := scenario.Key, scenario.Body, put
							if name == "Replication:OperationFailedReplication" {
								key, body, version = scenario.FailureKey, scenario.FailureBody, failedPut
							}
							want := map[string]any{
								"eventSource": "aws:s3", "awsRegion": "us-east-1", "eventName": name,
								"userIdentity": map[string]any{"principalId": "s3.amazonaws.com"},
								"s3": map[string]any{
									"configurationId": fixture.ConfigurationID,
									"bucket":          map[string]any{"name": fixture.SourceBucket, "arn": "arn:aws:s3:::" + fixture.SourceBucket},
									"object":          map[string]any{"key": key, "versionId": aws.ToString(version.VersionId), "size": float64(len(body)), "eTag": strings.Trim(aws.ToString(version.ETag), "\"")},
								},
								"replicationEventData": map[string]any{"replicationRuleId": fixture.RuleID, "destinationBucket": "arn:aws:s3:::" + fixture.DestinationBucket, "s3Operation": "OBJECT_PUT", "requestTime": created.Format("2006-01-02T15:04:05.000Z")},
							}
							if name == "Replication:OperationFailedReplication" {
								want["replicationEventData"].(map[string]any)["failureReason"] = "DstPutObjectNotPermitted"
							}
							s3NativeProjection(t, "document-derived RTC event", want, payload)
							request := s3NotifyRequestID(payload)
							if request == "" || requests[request] {
								t.Fatalf("missing or repeated delivered event identity: %#v", payload)
							}
							requests[request] = true
							if name != "Replication:OperationFailedReplication" && awsFixtureField(payload, "replicationEventData.failureReason") != nil {
								t.Fatalf("non-failure RTC event exposed a failure reason: %#v", payload)
							}
						}
						s3RTCObjectState(t, replay, fixture.SourceBucket, fixture.DestinationBucket, scenario.Key, scenario.Body, put, phase.Status)
						if failedPut != nil {
							s3RTCObjectState(t, replay, fixture.SourceBucket, fixture.DestinationBucket, scenario.FailureKey, scenario.FailureBody, failedPut, "FAILED")
						}
						readMetric := func(name string, start, end time.Time) *cloudwatch.GetMetricStatisticsOutput {
							t.Helper()
							out, err := metricsClient(replay.clients, "test").GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
								Namespace: aws.String("AWS/S3"), MetricName: &name,
								Dimensions: []cwtypes.Dimension{{Name: aws.String("SourceBucket"), Value: &fixture.SourceBucket}, {Name: aws.String("DestinationBucket"), Value: &fixture.DestinationBucket}, {Name: aws.String("RuleId"), Value: &fixture.RuleID}},
								StartTime:  &start, EndTime: &end, Period: aws.Int32(60), Statistics: []cwtypes.Statistic{"Maximum"},
							})
							if err != nil {
								t.Fatal(err)
							}
							return out
						}
						if phase.Withheld {
							for _, name := range []string{"BytesPendingReplication", "OperationsPendingReplication", "ReplicationLatency", "OperationsFailedReplication"} {
								out := readMetric(name, fixture.Start, source.Now().Add(time.Minute))
								if len(out.Datapoints) != 0 {
									t.Fatalf("%s leaked before RTC reporting activation: %+v", name, out.Datapoints)
								}
							}
						}
						checkMinute := func(at time.Time, values map[string]float64) {
							t.Helper()
							for name, want := range values {
								out := readMetric(name, at, at.Add(time.Minute))
								if len(out.Datapoints) != 1 || aws.ToFloat64(out.Datapoints[0].Maximum) != want || !aws.ToTime(out.Datapoints[0].Timestamp).Equal(at) {
									t.Fatalf("%s at %s: expected minute maximum %g with original timestamp, got %+v", name, at, want, out.Datapoints)
								}
							}
						}
						// Completed-minute alignment is local scheduling, not an AWS
						// latency SLA. Activation must retain the samples' original times.
						checkMinute(source.Now().Truncate(time.Minute).Add(-time.Minute), phase.Metrics)
						for _, sample := range phase.Samples {
							offset, err := time.ParseDuration(sample.Offset)
							if err != nil {
								t.Fatal(err)
							}
							checkMinute(fixture.Start.Add(offset), sample.Metrics)
						}
					}) {
						return
					}
				}
			})
		}
	}
}

func s3RTCObjectState(t *testing.T, replay *s3KMSReplay, source, destination, key, body string, put *s3.PutObjectOutput, status string) {
	t.Helper()
	client := replay.s3Client("caller")
	if status == "DELETED" {
		_, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &source, Key: &key, VersionId: put.VersionId})
		assertAPIError(t, err, "NoSuchVersion")
	} else {
		head, err := client.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: &source, Key: &key, VersionId: put.VersionId})
		if err != nil || string(head.ReplicationStatus) != status || aws.ToString(head.VersionId) != aws.ToString(put.VersionId) || aws.ToString(head.ETag) != aws.ToString(put.ETag) {
			t.Fatalf("source version/status: %+v, %v; want %s", head, err, status)
		}
	}
	versions, err := client.ListObjectVersions(t.Context(), &s3.ListObjectVersionsInput{Bucket: &destination, Prefix: &key})
	if err != nil {
		t.Fatal(err)
	}
	if status != "COMPLETED" {
		if len(versions.Versions) != 0 || len(versions.DeleteMarkers) != 0 {
			t.Fatalf("pending/canceled work created destination versions: %+v", versions)
		}
		_, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &destination, Key: &key})
		assertAPIError(t, err, "NoSuchKey")
		return
	}
	if len(versions.Versions) != 1 || len(versions.DeleteMarkers) != 0 || aws.ToString(versions.Versions[0].VersionId) != aws.ToString(put.VersionId) || !aws.ToBool(versions.Versions[0].IsLatest) {
		t.Fatalf("expected exactly the original replica version after completion/reopen: %+v", versions)
	}
	for _, bucket := range []string{source, destination} {
		out, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: put.VersionId})
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(out.Body)
		closeErr := out.Body.Close()
		wantStatus := "COMPLETED"
		if bucket == destination {
			wantStatus = "REPLICA"
		}
		if readErr != nil || closeErr != nil || string(data) != body || string(out.ReplicationStatus) != wantStatus || aws.ToString(out.VersionId) != aws.ToString(put.VersionId) || aws.ToString(out.ETag) != aws.ToString(put.ETag) || aws.ToString(out.SSEKMSKeyId) != replay.values["keyARN"] {
			t.Fatalf("%s: real encrypted round trip differs: %+v, %v, %v, body %q", bucket, out, readErr, closeErr, data)
		}
	}
}
