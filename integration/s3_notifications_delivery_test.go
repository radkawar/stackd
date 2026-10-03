package stackd_test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
	"stackd/clock"
)

type s3NotifyDelivery struct {
	Queue, Kind, Source string
	SourceSequence      int
	Payload, Envelope   map[string]any
	Dynamic             map[string]string
}

type s3NotifyReceipt struct {
	payload, envelope map[string]any
}

// Native requests, mutation bytes and expected records live in the compressed
// replay; every expected record points back to the complete unmodified capture.
func TestS3NotificationsNativeDeliveryReplay(t *testing.T) {
	s3NotifyDeliveryReplay(t, "s3/notifications_delivery_replay.json.gz")
}

func TestS3ObjectTaggingNativeDeliveryReplay(t *testing.T) {
	s3NotifyDeliveryReplay(t, "s3/object_tagging_delivery_replay.json.gz")
}

func TestS3CopyObjectNativeDeliveryReplay(t *testing.T) {
	s3NotifyDeliveryReplay(t, "s3/copy_delivery_replay.json.gz")
}

func TestS3ACLNativeDeliveryReplay(t *testing.T) {
	s3NotifyDeliveryReplay(t, "s3/acl_notifications_replay.json")
}

func s3NotifyDeliveryReplay(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		Cases []struct {
			Name   string
			Docker bool
			Calls  []struct {
				s3TagCall
				Advance, BindRequestID string
				BindDeleted            map[string]string
				Notifications          []s3NotifyDelivery
				QuietQueues            []string
				QuietEvents            []string
				QuietAll               bool
			}
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, scenario := range fixture.Cases {
		t.Run(scenario.Name, func(t *testing.T) {
			if scenario.Docker && os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
				t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					source := clock.NewManual(time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC))
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
						if scenario.Docker {
							return newLambdaDockerStack(t, config, nil)
						}
						return startPublicCloud(t, config)
					})
					replay := newS3KMSReplay(clients)
					receipts := make(map[string][]s3NotifyReceipt)
					sequencers := make(map[string]string)
					for _, row := range scenario.Calls {
						if row.Reopen {
							replay.clients = reopen()
						}
						cloud := replay.clients.server.Config.Handler.(*stackd.Stack)
						if row.Advance != "" {
							duration, err := time.ParseDuration(row.Advance)
							if err != nil {
								t.Fatal(err)
							}
							// Stabilize the local applied configuration, not an AWS SLA.
							advanceClock(t, source, duration)
							trailNativeDrain(t, cloud)
						}
						replay.values["dockerEndpoint"] = strings.Replace(replay.clients.server.URL, "127.0.0.1", "host.docker.internal", 1)
						replay.values["dockerQueue"] = strings.Replace(replay.values["queue_lambda"], "127.0.0.1", "host.docker.internal", 1)
						if row.Operation != "" {
							var wire *s3VersionHTTPClient
							if row.Service == "s3" && (row.Code != "Success" && row.BindRequestID != "" || row.Headers != nil || len(row.AbsentHeaders) != 0 || row.ErrorDetails != nil) {
								wire = &s3VersionHTTPClient{HTTPClient: replay.clients.server.Client()}
								replay.httpClient = wire
							}
							out := replay.call(t, row.s3KMSCall)
							replay.httpClient = nil
							s3TagCheck(t, replay, wire, row.s3TagCall, out)
							if row.BindRequestID != "" {
								if wire != nil {
									requestID := wire.header.Get("X-Amz-Request-Id")
									if requestID == "" {
										t.Fatalf("%s: rejected request omitted its request ID", row.Label)
									}
									replay.values[row.BindRequestID] = requestID
								} else {
									replay.values[row.BindRequestID] = nativeAuditRequestID(t, out, nil)
								}
							}
							for key, binding := range row.BindDeleted {
								for _, deleted := range out.(*s3.DeleteObjectsOutput).Deleted {
									if aws.ToString(deleted.Key) == key {
										replay.values[binding] = aws.ToString(deleted.DeleteMarkerVersionId)
									}
								}
								if replay.values[binding] == "" {
									t.Fatalf("%s: missing accepted marker for %s", row.Label, key)
								}
							}
							if function, ok := out.(*awslambda.CreateFunctionOutput); ok {
								cred := replay.sessions[row.Actor]
								functions := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(replay.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken), HTTPClient: replay.clients.server.Client(), RetryMaxAttempts: 1})
								if err := awslambda.NewFunctionActiveWaiter(functions, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: function.FunctionName}, time.Minute); err != nil {
									t.Fatal(err)
								}
							}
						}
						var expected []s3NotifyDelivery
						if err := json.Unmarshal(replay.rebind(t, row.Notifications), &expected); err != nil {
							t.Fatal(err)
						}
						for _, want := range expected {
							deadline := time.Now().Add(time.Minute)
							for {
								s3NotifyCollect(t, replay, want.Queue, receipts)
								found := -1
								for i, receipt := range receipts[want.Queue] {
									if s3NotifyIdentity(receipt.payload) == s3NotifyIdentity(want.Payload) {
										found = i
										break
									}
								}
								if found >= 0 {
									got := receipts[want.Queue][found]
									s3NotifyCompare(t, row.Label, want, got, sequencers)
									receipts[want.Queue] = append(receipts[want.Queue][:found], receipts[want.Queue][found+1:]...)
									break
								}
								if time.Now().After(deadline) {
									t.Fatalf("%s: missing native delivery %s (source sequence %d), received %#v", row.Label, want.Source, want.SourceSequence, receipts[want.Queue])
								}
								select {
								case <-t.Context().Done():
									t.Fatal(t.Context().Err())
								case <-time.After(20 * time.Millisecond):
								}
							}
						}
						var quiet []string
						if err := json.Unmarshal(replay.rebind(t, row.QuietQueues), &quiet); err != nil {
							t.Fatal(err)
						}
						for _, queue := range quiet {
							s3NotifyCollect(t, replay, queue, receipts)
							for _, receipt := range receipts[queue] {
								if len(row.QuietEvents) != 0 {
									matched := false
									for _, event := range row.QuietEvents {
										matched = matched || receipt.payload["eventName"] == event || receipt.payload["detail-type"] == event
									}
									if !matched {
										continue
									}
								}
								// A drained snapshot is not an exactly-once or no-future-retry claim.
								if row.QuietAll || s3NotifyRequestID(receipt.payload) == replay.values[row.BindRequestID] {
									t.Fatalf("%s: native bounded non-delivery differed: %#v", row.Label, receipt.payload)
								}
							}
						}
					}
				})
			}
		})
	}
}

func s3NotifyCollect(t *testing.T, replay *s3KMSReplay, queue string, receipts map[string][]s3NotifyReceipt) {
	t.Helper()
	cred := replay.sessions["caller"]
	cloud := replay.clients.server.Config.Handler.(*stackd.Stack)
	messages := snsAdmissionReceive(t, cloud, replay.clients.sqs(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken), &queue)
	for _, message := range messages {
		var envelope map[string]any
		if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &envelope); err != nil {
			t.Fatal(err)
		}
		payload := envelope
		if envelope["Type"] == "Notification" {
			snsVerifySignature(t, envelope, replay.clients.server.URL, replay.clients.server.URL)
			text, ok := envelope["Message"].(string)
			if !ok {
				t.Fatalf("SNS omitted S3 message: %#v", envelope)
			}
			payload = nil
			if err := json.Unmarshal([]byte(text), &payload); err != nil {
				t.Fatal(err)
			}
		} else if event, ok := envelope["event"].(map[string]any); ok {
			if request, ok := envelope["lambda_request_id"].(string); !ok || request == "" {
				t.Fatalf("missing real Lambda invocation identity: %#v", envelope)
			}
			payload = event
		}
		if records, ok := payload["Records"].([]any); ok {
			if len(records) == 0 {
				t.Fatal("empty S3 Records envelope")
			}
			for _, record := range records {
				object, ok := record.(map[string]any)
				if !ok {
					t.Fatalf("invalid S3 record: %#v", record)
				}
				receipts[queue] = append(receipts[queue], s3NotifyReceipt{object, envelope})
			}
		} else {
			receipts[queue] = append(receipts[queue], s3NotifyReceipt{payload, envelope})
		}
	}
}

func s3NotifyRequestID(payload map[string]any) string {
	for _, path := range []string{"responseElements.x-amz-request-id", "detail.request-id", "RequestId"} {
		if value, ok := awsFixtureField(payload, path).(string); ok {
			return value
		}
	}
	return ""
}

func s3NotifyIdentity(payload map[string]any) string {
	if payload["s3"] != nil {
		return fmt.Sprint(s3NotifyRequestID(payload), "/", payload["eventName"], "/", awsFixtureField(payload, "s3.object.key"))
	}
	if payload["detail"] != nil {
		return fmt.Sprint(s3NotifyRequestID(payload), "/", payload["detail-type"], "/", awsFixtureField(payload, "detail.object.key"))
	}
	return fmt.Sprint(s3NotifyRequestID(payload), "/", payload["Event"])
}

func s3NotifyCompare(t *testing.T, label string, want s3NotifyDelivery, got s3NotifyReceipt, sequencers map[string]string) {
	t.Helper()
	if want.Envelope != nil {
		s3NativeProjection(t, label+".envelope", want.Envelope, got.envelope)
	}
	for path, kind := range want.Dynamic {
		value, ok := awsFixtureField(got.payload, path).(string)
		if !ok || value == "" {
			t.Fatalf("%s: missing native %s (%s)", label, path, want.Source)
		}
		switch kind {
		case "time":
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				t.Fatalf("%s: invalid %s: %v", label, path, err)
			}
		case "ip":
			if net.ParseIP(value) == nil {
				t.Fatalf("%s: invalid source IP %q", label, value)
			}
		case "sequencer":
			current, valid := new(big.Int).SetString(value, 16)
			if !valid || current.Sign() < 0 {
				t.Fatalf("%s: non-hex S3 sequencer %q", label, value)
			}
			prefix := "s3"
			if want.Kind == "eventbridge" {
				prefix = "detail"
			}
			key := fmt.Sprint(want.Kind, "/", awsFixtureField(got.payload, prefix+".bucket.name"), "/", awsFixtureField(got.payload, prefix+".object.key"))
			if previous := sequencers[key]; previous != "" {
				last, _ := new(big.Int).SetString(previous, 16)
				if current.Cmp(last) <= 0 {
					t.Fatalf("%s: sequencer did not advance for %s: %s -> %s", label, key, previous, value)
				}
			}
			sequencers[key] = value
		}
		// Do not equate opaque retail owner IDs with canonical ACL owner IDs,
		// or event host IDs with HTTP x-amz-id-2: native copy IDs also differ.
		fields := strings.Split(path, ".")
		object := want.Payload
		for _, field := range fields[:len(fields)-1] {
			object = object[field].(map[string]any)
		}
		object[fields[len(fields)-1]] = value
	}
	// Full equality preserves omitted size/eTag/null-version fields as well as
	// configuration IDs, event/schema versions and native encoded/raw key forms.
	if !reflect.DeepEqual(want.Payload, got.payload) {
		t.Fatalf("%s: delivery differs from %s (source sequence %d)\ngot: %#v\nwant: %#v", label, want.Source, want.SourceSequence, got.payload, want.Payload)
	}
}
