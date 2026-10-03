package stackd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

func TestSNSFirehoseNativeDeliverySDK(t *testing.T) {
	var capture struct {
		firehoseNativeFixture
		Objects []struct{ BodyBase64 string }
	}
	awsReadFixture(t, "firehose/sns.json.gz", &capture)
	var create firehose.CreateDeliveryStreamInput
	if err := json.Unmarshal(capture.row(t, "create-stream").Input, &create); err != nil {
		t.Fatal(err)
	}
	bucket := strings.TrimPrefix(aws.ToString(create.ExtendedS3DestinationConfiguration.BucketARN), "arn:aws:s3:::")
	var wrappedInput, rawInput sns.PublishInput
	var wrappedOutput sns.PublishOutput
	for _, pair := range []struct {
		label  string
		target any
	}{
		{"publish-wrapped-evidence", &wrappedInput}, {"publish-raw-evidence", &rawInput},
	} {
		if err := json.Unmarshal(capture.row(t, pair.label).Input, pair.target); err != nil {
			t.Fatal(err)
		}
	}
	if err := json.Unmarshal(capture.row(t, "publish-wrapped-evidence").Result.Output, &wrappedOutput); err != nil {
		t.Fatal(err)
	}
	var nativeEnvelope map[string]any
	var nativeRaw []byte
	for _, object := range capture.Objects {
		body, err := base64.StdEncoding.DecodeString(object.BodyBase64)
		if err != nil {
			t.Fatal(err)
		}
		raw := []byte(aws.ToString(rawInput.Message))
		if bytes.HasSuffix(body, raw) {
			nativeRaw = raw
			body = bytes.TrimSuffix(body, raw)
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		for {
			var envelope map[string]any
			if err := decoder.Decode(&envelope); err != nil {
				break
			}
			if envelope["MessageId"] == aws.ToString(wrappedOutput.MessageId) {
				nativeEnvelope = envelope
			}
		}
	}
	if nativeEnvelope == nil || nativeRaw == nil {
		t.Fatal("native fixture lacks correlated wrapped/raw S3 bytes")
	}

	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(capture.StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: capture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			subscriptions := map[string]string{}
			replay := func(label string) any {
				row := capture.row(t, label)
				var client any
				switch row.Service {
				case "iam":
					client = clients.iam("test", "test", "")
				case "s3api":
					client = s3NativeClient(clients, "test", "test")
				case "sns":
					client = admissionSNSClient(clients, capture.Account, capture.Region)
				case "firehose":
					client = clients.firehose("test", "test", "")
				default:
					t.Fatalf("unexpected fixture service %s", row.Service)
				}
				out := firehoseReplayCall(t, client, row, func(input any) {
					switch in := input.(type) {
					case *firehose.CreateDeliveryStreamInput:
						// Keep admitted records buffered until after reopening the store.
						in.ExtendedS3DestinationConfiguration.BufferingHints.IntervalInSeconds = aws.Int32(60)
					case *sns.SetSubscriptionAttributesInput:
						in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
					}
				})
				if result, ok := out.(*sns.SubscribeOutput); ok && result != nil {
					var native sns.SubscribeOutput
					if err := json.Unmarshal(row.Result.Output, &native); err != nil {
						t.Fatal(err)
					}
					subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(result.SubscriptionArn)
				}
				return out
			}
			for _, label := range []string{"create-bucket", "create-role-s3", "create-role-sns", "create-role-wrong", "s3-role-policy", "sns-role-batch-only", "wrong-role-policy", "create-topic", "create-fifo", "create-stream"} {
				replay(label)
			}
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), aws.ToString(create.DeliveryStreamName))
			for _, label := range []string{"missing-role", "empty-role", "invalid-role", "missing-role-resource", "wrong-trust", "fifo-valid", "malformed-endpoint", "endpoint-wrong-service", "endpoint-wrong-resource", "valid", "duplicate-same", "duplicate-raw", "set-role-wrong-trust", "set-role-empty", "set-role-malformed-update", "set-role-missing-update", "create-raw-topic", "create-wrapped-topic", "subscribe-raw-stable", "subscribe-wrapped-stable"} {
				replay(label)
			}
			var callerPolicy iam.PutRolePolicyInput
			if err := json.Unmarshal(capture.row(t, "caller-no-passrole").Input, &callerPolicy); err != nil {
				t.Fatal(err)
			}
			limited := snsControlUser(t, clients, snsAdmissionFixture{Account: capture.Account, Region: capture.Region}, "sns-no-passrole", aws.ToString(callerPolicy.PolicyDocument))
			for _, label := range []string{"no-passrole-subscribe", "no-passrole-update"} {
				firehoseReplayCall(t, limited, capture.row(t, label), func(input any) {
					if in, ok := input.(*sns.SetSubscriptionAttributesInput); ok {
						in.SubscriptionArn = aws.String(subscriptions[aws.ToString(in.SubscriptionArn)])
					}
				})
			}
			wrapped := replay("publish-wrapped-evidence").(*sns.PublishOutput)
			replay("publish-raw-evidence")
			published := source.Now()
			// Recover SNS-owned pending fanout first, then Firehose-owned bytes.
			clients = reopen()
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			clients = reopen()
			topics := admissionSNSClient(clients, capture.Account, capture.Region)
			var rawSubscription sns.SubscribeOutput
			if err := json.Unmarshal(capture.row(t, "subscribe-raw-stable").Result.Output, &rawSubscription); err != nil {
				t.Fatal(err)
			}
			if _, err := topics.Unsubscribe(t.Context(), &sns.UnsubscribeInput{SubscriptionArn: aws.String(subscriptions[aws.ToString(rawSubscription.SubscriptionArn)])}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			objects := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, "records/")
			var gotWrapped map[string]any
			rawFound := false
			for _, body := range objects {
				if bytes.Contains(body, nativeRaw) {
					rawFound = true
					body = bytes.Replace(body, nativeRaw, nil, 1)
				}
				decoder := json.NewDecoder(bytes.NewReader(body))
				for {
					var envelope map[string]any
					if err := decoder.Decode(&envelope); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					if envelope["MessageId"] == aws.ToString(wrapped.MessageId) {
						gotWrapped = envelope
					}
				}
			}
			if !rawFound || gotWrapped == nil {
				t.Fatalf("missing actual wrapped/raw Firehose S3 bytes: %q", objects)
			}
			stamp, err := time.Parse(time.RFC3339Nano, gotWrapped["Timestamp"].(string))
			if err != nil || !stamp.Equal(published.Truncate(time.Millisecond)) {
				t.Fatalf("retained publication time: %v %v", stamp, err)
			}
			unsubscribe, err := url.Parse(gotWrapped["UnsubscribeURL"].(string))
			if err != nil {
				t.Fatal(err)
			}
			nativeURL, err := url.Parse(nativeEnvelope["UnsubscribeURL"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if unsubscribe.Query().Get("SubscriptionArn") != subscriptions[nativeURL.Query().Get("SubscriptionArn")] {
				t.Fatal("wrong retained subscription in envelope")
			}
			gotWrapped["MessageId"], gotWrapped["Timestamp"], gotWrapped["UnsubscribeURL"] = nativeEnvelope["MessageId"], nativeEnvelope["Timestamp"], nativeEnvelope["UnsubscribeURL"]
			if !reflect.DeepEqual(gotWrapped, nativeEnvelope) {
				t.Fatalf("native projection differs: got %#v want %#v", gotWrapped, nativeEnvelope)
			}

			// Both policy and trust failures must reach the SNS failure path, not
			// bypass Firehose authority or become successful direct S3 writes.
			queue, err := clients.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("sns-firehose-denied")})
			if err != nil {
				t.Fatal(err)
			}
			queueARN := "arn:aws:sqs:" + capture.Region + ":" + capture.Account + ":sns-firehose-denied"
			queuePolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"` + queueARN + `"}]}`
			if _, err := clients.sqs("test", "test", "").SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": queuePolicy}}); err != nil {
				t.Fatal(err)
			}
			wrappedSub := subscriptions[nativeURL.Query().Get("SubscriptionArn")]
			if _, err := topics.SetSubscriptionAttributes(t.Context(), &sns.SetSubscriptionAttributesInput{SubscriptionArn: &wrappedSub, AttributeName: aws.String("RedrivePolicy"), AttributeValue: aws.String(`{"deadLetterTargetArn":"` + queueARN + `"}`)}); err != nil {
				t.Fatal(err)
			}
			var rolePolicy iam.PutRolePolicyInput
			if err := json.Unmarshal(capture.row(t, "sns-role-policy").Input, &rolePolicy); err != nil {
				t.Fatal(err)
			}
			for _, denial := range []string{"put-record-only", "trust"} {
				if denial == "put-record-only" {
					replay("sns-role-policy")
				} else {
					replay("sns-role-batch-only")
					if _, err := clients.iam("test", "test", "").UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: rolePolicy.RoleName, PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)}); err != nil {
						t.Fatal(err)
					}
				}
				body := "denied-" + denial
				if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: wrappedInput.TopicArn, Message: &body}); err != nil {
					t.Fatal(err)
				}
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				receipt, err := clients.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
				if err != nil || len(receipt.Messages) != 1 || !strings.Contains(aws.ToString(receipt.Messages[0].Body), body) {
					t.Fatalf("%s did not produce real SNS dead letter: %+v %v", denial, receipt, err)
				}
				if _, err := clients.sqs("test", "test", "").DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queue.QueueUrl, ReceiptHandle: receipt.Messages[0].ReceiptHandle}); err != nil {
					t.Fatal(err)
				}
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				if got := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, "records/"); !reflect.DeepEqual(got, objects) {
					t.Fatalf("%s bypassed destination authority", denial)
				}
			}
			var conditionedTrust iam.UpdateAssumeRolePolicyInput
			var originalTopic sns.CreateTopicOutput
			if err := json.Unmarshal(capture.row(t, "source-both-final").Input, &conditionedTrust); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(capture.row(t, "create-topic").Result.Output, &originalTopic); err != nil {
				t.Fatal(err)
			}
			conditionedTrust.RoleName = rolePolicy.RoleName
			conditionedTrust.PolicyDocument = aws.String(strings.ReplaceAll(aws.ToString(conditionedTrust.PolicyDocument), aws.ToString(originalTopic.TopicArn), aws.ToString(wrappedInput.TopicArn)))
			if _, err := clients.iam("test", "test", "").UpdateAssumeRolePolicy(t.Context(), &conditionedTrust); err != nil {
				t.Fatal(err)
			}
			if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: wrappedInput.TopicArn, Message: aws.String("recovered-after-denial")}); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			if _, err := topics.DeleteTopic(t.Context(), &sns.DeleteTopicInput{TopicArn: wrappedInput.TopicArn}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			found := false
			for _, body := range firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, "records/") {
				if bytes.Contains(body, []byte(`"Message":"recovered-after-denial"`)) {
					found = true
				}
			}
			if !found {
				t.Fatal("accepted Firehose bytes did not survive source deletion and SQLite reopen")
			}
		})
	}
}

func TestSNSNativeCrossAccountFirehose(t *testing.T) {
	var fixture struct {
		Region               string
		Observations         []snsCrossObservation
		Receipts             []struct{ Records []map[string]any }
		SupplementalSessions map[string]struct {
			AssumeRole struct{ Input sts.AssumeRoleInput } `json:"assume_role"`
		} `json:"supplemental_sessions"`
	}
	awsReadFixture(t, "sns/cross_account_firehose.json", &fixture)
	nativeRecords := map[string]map[string]any{}
	for _, receipt := range fixture.Receipts {
		for _, record := range receipt.Records {
			if id, ok := record["MessageId"].(string); ok {
				nativeRecords[id] = record
			}
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source := admissionFixtureCloud(t, backend, snsAdmissionFixture{Observations: []awsNativeObservation{fixture.Observations[0].awsNativeObservation}})
			const owner, subscriber = "000000000000", "917546008205"
			topics := snsCrossTopics(t, clients, owner, subscriber, fixture.Region)
			streams := clients.firehose(subscriber, "test", "")
			objects := s3NativeClient(clients, subscriber, "test")
			sessionInput := fixture.SupplementalSessions["passrole"].AssumeRole.Input
			session, err := clients.sts(subscriber, "test", "").AssumeRole(t.Context(), &sessionInput)
			if err != nil {
				t.Fatal(err)
			}
			limited := clients.snsRegion(fixture.Region, aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
			mapped := map[string]string{}
			var replacements []string
			bind := func(native, local string) {
				t.Helper()
				if old, exists := mapped[native]; exists {
					if old != local {
						t.Fatalf("native identity %s changed from %s to %s", native, old, local)
					}
					return
				}
				mapped[native] = local
				replacements = append(replacements, native, local)
			}
			normalize := func(data []byte) []byte { return []byte(strings.NewReplacer(replacements...).Replace(string(data))) }
			var bucket string
			for _, capture := range fixture.Observations {
				// These requests observe native IAM trust propagation immediately
				// after repair; replay the succeeding request against current trust.
				if strings.HasPrefix(capture.Label, "subscribe-repaired-trust-") && capture.Result.Code != "Success" {
					continue
				}
				var client any
				switch capture.Service {
				case "sns":
					client = topics[capture.Caller]
					if capture.Label == "B-cross-local-role-explicit-passrole-deny" {
						client = limited
					}
				case "iam":
					switch capture.Operation {
					case "create-role", "put-role-policy", "update-assume-role-policy":
						client = clients.iam(capture.Caller, "test", "")
					default:
						continue
					}
				case "firehose":
					if capture.Operation != "create-delivery-stream" && capture.Operation != "put-record" {
						continue
					}
					client = streams
				case "s3api":
					if capture.Operation != "create-bucket" {
						continue
					}
					client = objects
				default:
					continue
				}
				if !t.Run(capture.Label, func(t *testing.T) {
					if delta := time.UnixMilli(capture.Started).Sub(source.Now()); delta > 0 {
						advanceClock(t, source, delta)
					}
					row := capture.awsNativeObservation
					row.Input = normalize(row.Input)
					published := source.Now()
					result := snsControlReplay(t, client, row)
					if row.Result.Code != "Success" {
						return
					}
					switch out := result.(type) {
					case *firehose.CreateDeliveryStreamOutput:
						var input firehose.CreateDeliveryStreamInput
						awsDecodeJSON(t, row.Input, &input)
						bucket = strings.TrimPrefix(aws.ToString(input.ExtendedS3DestinationConfiguration.BucketARN), "arn:aws:s3:::")
						awaitFirehoseActive(t, source, streams, aws.ToString(input.DeliveryStreamName))
					case *sns.SubscribeOutput:
						var want sns.SubscribeOutput
						awsDecodeJSON(t, row.Result.Output, &want)
						bind(aws.ToString(want.SubscriptionArn), aws.ToString(out.SubscriptionArn))
					case *sns.PublishOutput:
						var want sns.PublishOutput
						awsDecodeJSON(t, row.Result.Output, &want)
						id := aws.ToString(out.MessageId)
						bind(aws.ToString(want.MessageId), id)
						trailNativeDrain(t, cloud)
						advanceClock(t, source, 61*time.Second)
						trailNativeDrain(t, cloud)
						var delivered map[string]any
						for _, body := range firehoseConsumerObjects(t, objects, bucket, "records/") {
							decoder := json.NewDecoder(bytes.NewReader(body))
							for {
								var record map[string]any
								if err := decoder.Decode(&record); err == io.EOF {
									break
								} else if err != nil {
									t.Fatal(err)
								}
								if record["MessageId"] == id {
									delivered = record
								}
							}
						}
						native := nativeRecords[aws.ToString(want.MessageId)]
						if native == nil {
							if delivered != nil {
								t.Fatalf("native denied/unsubscribed publication reached Firehose: %v", delivered)
							}
							return
						}
						if delivered == nil {
							t.Fatalf("publication %s did not reach actual Firehose S3 object", id)
						}
						stamp, err := time.Parse(time.RFC3339Nano, delivered["Timestamp"].(string))
						if err != nil || !stamp.Equal(published.Truncate(time.Millisecond)) {
							t.Fatalf("Firehose lost source publication time: %v", delivered["Timestamp"])
						}
						link, err := url.Parse(delivered["UnsubscribeURL"].(string))
						if err != nil {
							t.Fatal(err)
						}
						nativeLink, err := url.Parse(native["UnsubscribeURL"].(string))
						if err != nil || link.Query().Get("SubscriptionArn") != mapped[nativeLink.Query().Get("SubscriptionArn")] {
							t.Fatal("Firehose payload lost subscription identity")
						}
						delivered["MessageId"], delivered["Timestamp"], delivered["UnsubscribeURL"] = native["MessageId"], native["Timestamp"], native["UnsubscribeURL"]
						if !reflect.DeepEqual(delivered, native) {
							t.Fatalf("Firehose subscriber payload differs: got %v want %v", delivered, native)
						}
					case *firehose.PutRecordOutput:
						var input firehose.PutRecordInput
						awsDecodeJSON(t, row.Input, &input)
						advanceClock(t, source, 61*time.Second)
						trailNativeDrain(t, cloud)
						found := false
						for _, body := range firehoseConsumerObjects(t, objects, bucket, "records/") {
							found = found || bytes.Contains(body, input.Record.Data)
						}
						if !found {
							t.Fatal("direct Firehose destination control did not reach S3")
						}
					}
					snsCrossResult(t, result, normalize(row.Result.Output), func(string) bool { return true })
				}) {
					t.FailNow()
				}
			}
		})
	}
}
