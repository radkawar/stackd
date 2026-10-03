package stackd_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"stackd"
	"stackd/clock"
)

type trailSNSNotification struct {
	Queue, NativeMessageID string
	Envelope               map[string]any
	Bucket                 string
	Records                []map[string]any
}

func TestCloudTrailSNSNativeReplay(t *testing.T) {
	for _, name := range []string{"controls", "delivery"} {
		t.Run(name, func(t *testing.T) {
			var fixture struct {
				Cases []struct {
					Name  string
					Calls []struct {
						s3KMSCall
						Advance, SameObjectsAs, BindRequestID string
						StatusAfter                           map[string]string
						Notifications                         []trailSNSNotification
					}
					ReopenCalls []s3KMSCall
				}
			}
			awsReadFixture(t, "cloudtrail/sns_"+name+"_replay.json.gz", &fixture)
			for _, scenario := range fixture.Cases {
				t.Run(scenario.Name, func(t *testing.T) {
					for _, backend := range []string{"memory", "sqlite"} {
						t.Run(backend, func(t *testing.T) {
							source := clock.NewManual(time.Date(2026, 9, 19, 23, 35, 0, 0, time.UTC))
							clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
								return startPublicCloud(t, config)
							})
							replay := newS3KMSReplay(clients)
							replay.values["callerARN"] = "arn:aws:iam::123456789012:root"
							objects := make(map[string][]s3types.Object)
							for _, row := range scenario.Calls {
								if row.Reopen {
									replay.clients = reopen()
								}
								if row.Advance != "" {
									duration, err := time.ParseDuration(row.Advance)
									if err != nil {
										t.Fatal(err)
									}
									advanceClock(t, source, duration)
									trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
								}
								out := replay.call(t, row.s3KMSCall)
								if row.BindRequestID != "" {
									replay.values[row.BindRequestID] = nativeAuditRequestID(t, out, nil)
								}
								for field, binding := range row.StatusAfter {
									previous, err := time.Parse(time.RFC3339Nano, replay.values[binding])
									if err != nil {
										t.Fatal(err)
									}
									current := reflect.ValueOf(out).Elem().FieldByName(field).Interface().(*time.Time)
									if current == nil || !current.After(previous) {
										t.Fatalf("%s.%s: native delivery success did not advance", row.Label, field)
									}
								}
								if listed, ok := out.(*s3.ListObjectsV2Output); ok {
									if row.SameObjectsAs != "" {
										previous, ok := objects[row.SameObjectsAs]
										if !ok || !reflect.DeepEqual(previous, listed.Contents) {
											t.Fatalf("%s: invalid SNS syntax rewrote native-unchanged S3 markers", row.Label)
										}
									}
									objects[row.Label] = listed.Contents
								}
								trailSNSNotifications(t, replay, row.Label, row.Notifications)
							}
							replay.clients = reopen()
							for _, row := range scenario.ReopenCalls {
								replay.call(t, row)
							}
						})
					}
				})
			}
		})
	}
}

func trailSNSNotifications(t *testing.T, replay *s3KMSReplay, label string, captured []trailSNSNotification) {
	t.Helper()
	if len(captured) == 0 {
		return
	}
	var expected []trailSNSNotification
	if err := json.Unmarshal(replay.rebind(t, captured), &expected); err != nil {
		t.Fatal(err)
	}
	cloud := replay.clients.server.Config.Handler.(*stackd.Stack)
	credentials := replay.sessions["caller"]
	queues := replay.clients.sqs(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken)
	received := make(map[string][]map[string]any)
	for _, want := range expected {
		if _, ok := received[want.Queue]; !ok {
			for _, message := range snsAdmissionReceive(t, cloud, queues, &want.Queue) {
				var envelope map[string]any
				if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &envelope); err != nil {
					t.Fatal(err)
				}
				received[want.Queue] = append(received[want.Queue], envelope)
			}
		}
		found := false
		for _, envelope := range received[want.Queue] {
			if envelope["TopicArn"] != want.Envelope["TopicArn"] {
				continue
			}
			if message, specified := want.Envelope["Message"]; specified && envelope["Message"] != message {
				continue
			}
			if len(want.Records) != 0 && !trailSNSLogNotification(t, replay.s3Client("caller"), want, envelope["Message"].(string)) {
				continue
			}
			if _, present := envelope["Subject"]; present {
				t.Fatalf("%s: CloudTrail notification exposed a Subject absent from native %s", label, want.NativeMessageID)
			}
			s3NativeProjection(t, label, want.Envelope, envelope)
			found = true
		}
		if !found {
			t.Fatalf("%s: missing SNS-to-SQS notification observed as native %s", label, want.NativeMessageID)
		}
	}
}

func trailSNSLogNotification(t *testing.T, client *s3.Client, want trailSNSNotification, message string) bool {
	t.Helper()
	var notification struct {
		Bucket string   `json:"s3Bucket"`
		Keys   []string `json:"s3ObjectKey"`
	}
	if err := json.Unmarshal([]byte(message), &notification); err != nil || notification.Bucket != want.Bucket {
		return false
	}
	objects := make(map[string][]byte, len(notification.Keys))
	for _, key := range notification.Keys {
		object, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &notification.Bucket, Key: &key})
		if err != nil {
			t.Fatalf("notification references an unreadable S3 log: %v", err)
		}
		body, err := io.ReadAll(object.Body)
		closeErr := object.Body.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("reading notified log: %v %v", err, closeErr)
		}
		objects[key] = body
	}
	records := trailNativeRecords(t, objects)
	for _, expected := range want.Records {
		found := false
		for _, record := range records {
			if record["requestID"] == expected["requestID"] {
				s3NativeProjection(t, want.NativeMessageID, expected, record)
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
