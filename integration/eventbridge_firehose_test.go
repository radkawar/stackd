package stackd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

// This capture uses cases and top-level code/output rather than calls/result.
// Adapt only that envelope; the common native SDK replay owns invocation.
type eventFirehoseCapture struct {
	Account, Region string
	Started         time.Time
	Cases           []struct {
		Label, Service, Operation, Code string
		Input, Output                   json.RawMessage
	}
}

func TestEventBridgeFirehoseNativeReplaySDK(t *testing.T) {
	var plan struct {
		Source, Payload           string
		Setup, Admission, Objects []string
		Denied, RegionalDenied    struct{ Policy, Publish, Receive string }
		Recovery                  struct{ Policy, Publish string }
		Regional                  struct{ Policy, Target, Publish, TerminalTarget, TerminalPublish, Describe string }
	}
	awsReadFixture(t, "firehose/"+"eventbridge_replay.json", &plan)
	var capture eventFirehoseCapture
	awsReadFixture(t, "firehose/"+plan.Source, &capture)
	native := firehoseNativeFixture{Account: capture.Account, Region: capture.Region, StartedAt: capture.Started}
	for _, row := range capture.Cases {
		call := firehoseNativeCall{Label: row.Label, Service: row.Service, Operation: strings.ReplaceAll(row.Operation, "_", "-"), Input: row.Input}
		call.Result.Code, call.Result.Output = row.Code, row.Output
		native.Calls = append(native.Calls, call)
	}
	var create firehose.CreateDeliveryStreamInput
	if err := json.Unmarshal(native.row(t, "create-stream-propagation-1").Input, &create); err != nil {
		t.Fatal(err)
	}
	bucket := strings.TrimPrefix(aws.ToString(create.ExtendedS3DestinationConfiguration.BucketARN), "arn:aws:s3:::")
	prefix := aws.ToString(create.ExtendedS3DestinationConfiguration.Prefix)
	var consumerRecords []map[string]any
	for _, label := range plan.Objects {
		var out struct{ Body struct{ Base64 string } }
		if err := json.Unmarshal(native.row(t, label).Result.Output, &out); err != nil {
			t.Fatal(err)
		}
		body, err := base64.StdEncoding.DecodeString(out.Body.Base64)
		if err != nil {
			t.Fatal(err)
		}
		consumerRecords = append(consumerRecords, eventFirehoseJSONRecords(t, body)...)
	}
	// Native event times and envelopes come from independently received S3/DLQ
	// bytes. Rebind only generated event IDs; explicitly supply captured Time.
	envelopes := map[string]map[string]any{}
	for _, record := range consumerRecords {
		if id, ok := record["id"].(string); ok {
			envelopes[id] = record
		}
	}
	for _, label := range []string{plan.Denied.Receive, plan.RegionalDenied.Receive} {
		var out sqs.ReceiveMessageOutput
		if err := json.Unmarshal(native.row(t, label).Result.Output, &out); err != nil {
			t.Fatal(err)
		}
		for _, message := range out.Messages {
			record := eventFirehoseJSONRecords(t, []byte(aws.ToString(message.Body)))[0]
			envelopes[record["id"].(string)] = record
		}
	}

	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(native.StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Account, Clock: source})
			queueURL := ""
			ids := map[string]string{}
			replay := func(label string) any {
				row := native.row(t, label)
				var client any
				switch row.Service {
				case "s3":
					client = s3NativeClient(clients, "test", "test")
				case "iam":
					client = clients.iam("test", "test", "")
				case "events":
					client = eventDeliveryClient(clients, "test")
				case "firehose":
					client = clients.firehose("test", "test", "")
				case "sqs":
					client = clients.sqs("test", "test", "")
				default:
					t.Fatalf("unsupported native service %q", row.Service)
				}
				var nativeID string
				out := firehoseReplayCall(t, client, row, func(input any) {
					switch input := input.(type) {
					case *sqs.SetQueueAttributesInput:
						input.QueueUrl = &queueURL
					case *sqs.ReceiveMessageInput:
						input.QueueUrl, input.WaitTimeSeconds = &queueURL, 0
					case *eventbridge.PutEventsInput:
						var output eventbridge.PutEventsOutput
						if err := json.Unmarshal(row.Result.Output, &output); err != nil {
							t.Fatal(err)
						}
						nativeID = aws.ToString(output.Entries[0].EventId)
						record, ok := envelopes[nativeID]
						if !ok {
							t.Fatalf("%s has no native consumer envelope", label)
						}
						at, err := time.Parse(time.RFC3339, record["time"].(string))
						if err != nil {
							t.Fatal(err)
						}
						input.Entries[0].Time = &at
					}
				})
				switch out := out.(type) {
				case *sqs.CreateQueueOutput:
					queueURL = aws.ToString(out.QueueUrl)
				case *eventbridge.PutTargetsOutput:
					if row.Result.Code == "Success" && out.FailedEntryCount != 0 {
						t.Fatalf("%s: %+v", label, out.FailedEntries)
					}
				case *eventbridge.PutEventsOutput:
					if out.FailedEntryCount != 0 {
						t.Fatalf("%s: %+v", label, out.Entries)
					}
					ids[nativeID] = aws.ToString(out.Entries[0].EventId)
				}
				return out
			}
			for _, label := range plan.Setup {
				replay(label)
			}
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), aws.ToString(create.DeliveryStreamName))
			for _, label := range plan.Admission {
				replay(label)
			}
			// Null is an admitted static input, not a missing projection.
			var nullTarget eventbridge.PutTargetsInput
			if err := json.Unmarshal(native.row(t, "target-input-null").Input, &nullTarget); err != nil {
				t.Fatal(err)
			}
			targets, err := eventDeliveryClient(clients, "test").ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{Rule: nullTarget.Rule, EventBusName: nullTarget.EventBusName})
			if err != nil || !reflect.DeepEqual(targets.Targets, nullTarget.Targets) {
				t.Fatalf("null target state: %+v, %v", targets, err)
			}
			replay("remove-probe-target")
			replay("targets-payloads")
			replay(plan.Payload)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			// Accepted producer bytes remain buffered across reopen, not regenerated
			// from the event after target removal or a new rule evaluation.
			clients = reopen()
			replay("remove-projection-targets")
			want := eventFirehoseExpectedRecords(consumerRecords, ids)
			eventFirehoseAwaitObjects(t, clients, source, bucket, prefix, want)

			assertDenied := func(publish, receive string) {
				replay(publish)
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				out := replay(receive).(*sqs.ReceiveMessageOutput)
				var observed sqs.ReceiveMessageOutput
				if err := json.Unmarshal(native.row(t, receive).Result.Output, &observed); err != nil {
					t.Fatal(err)
				}
				if len(out.Messages) != 1 || len(observed.Messages) != 1 {
					t.Fatalf("%s: expected one DLQ envelope, got %+v", receive, out.Messages)
				}
				got, expected := out.Messages[0], observed.Messages[0]
				body := eventFirehoseJSONRecords(t, []byte(aws.ToString(expected.Body)))[0]
				body["id"] = ids[body["id"].(string)]
				if !reflect.DeepEqual(eventFirehoseJSONRecords(t, []byte(aws.ToString(got.Body)))[0], body) {
					t.Fatalf("DLQ lost original envelope: %s", aws.ToString(got.Body))
				}
				for _, key := range []string{"ERROR_CODE", "RULE_ARN", "TARGET_ARN"} {
					if !reflect.DeepEqual(got.MessageAttributes[key], expected.MessageAttributes[key]) {
						t.Fatalf("DLQ %s: got %+v, native %+v", key, got.MessageAttributes[key], expected.MessageAttributes[key])
					}
				}
				diagnostic := aws.ToString(got.MessageAttributes["ERROR_MESSAGE"].StringValue)
				resource := "arn:aws:firehose:" + native.Region + ":" + native.Account + ":deliverystream/" + aws.ToString(create.DeliveryStreamName)
				if !strings.Contains(diagnostic, "firehose:PutRecord") || !strings.Contains(diagnostic, resource) {
					t.Fatalf("DLQ did not name actual action/rule-Region resource: %s", diagnostic)
				}
				if _, err := clients.sqs("test", "test", "").DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: &queueURL, ReceiptHandle: got.ReceiptHandle}); err != nil {
					t.Fatal(err)
				}
				advanceClock(t, source, 2*time.Minute)
				eventFirehoseAwaitObjects(t, clients, source, bucket, prefix, want)
			}
			replay(plan.Denied.Policy)
			assertDenied(plan.Denied.Publish, plan.Denied.Receive)
			clients = reopen()
			replay(plan.Recovery.Policy)
			replay(plan.Recovery.Publish)
			want = eventFirehoseExpectedRecords(consumerRecords, ids)
			eventFirehoseAwaitObjects(t, clients, source, bucket, prefix, want)

			replay(plan.Regional.Policy)
			replay(plan.Regional.Target)
			replay(plan.Regional.Publish)
			replay(plan.Regional.TerminalTarget)
			replay(plan.Regional.TerminalPublish)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			clients = reopen()
			got := replay(plan.Regional.Describe).(*eventbridge.ListTargetsByRuleOutput)
			var expected eventbridge.ListTargetsByRuleOutput
			if err := json.Unmarshal(native.row(t, plan.Regional.Describe).Result.Output, &expected); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Targets, expected.Targets) {
				t.Fatalf("retained regional target: got %+v, native %+v", got.Targets, expected.Targets)
			}
			want = eventFirehoseExpectedRecords(consumerRecords, ids)
			eventFirehoseAwaitObjects(t, clients, source, bucket, prefix, want)
			replay(plan.RegionalDenied.Policy)
			assertDenied(plan.RegionalDenied.Publish, plan.RegionalDenied.Receive)
		})
	}
}

func eventFirehoseJSONRecords(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	var records []map[string]any
	consumed := 0
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("invalid consumer JSON: %v", err)
		}
		consumed += len(raw)
		var record map[string]any
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if consumed != len(body) {
		t.Fatalf("Firehose inserted delimiters outside native JSON records: %d extra bytes", len(body)-consumed)
	}
	return records
}

func eventFirehoseExpectedRecords(native []map[string]any, ids map[string]string) []map[string]any {
	var expected []map[string]any
	for _, record := range native {
		id, envelope := record["id"].(string)
		if envelope && ids[id] == "" {
			continue
		}
		copy := make(map[string]any, len(record))
		for key, value := range record {
			copy[key] = value
		}
		if envelope {
			copy["id"] = ids[id]
		}
		expected = append(expected, copy)
	}
	return expected
}

func eventFirehoseAwaitObjects(t *testing.T, clients cloudClients, source *clock.Manual, bucket, prefix string, want []map[string]any) {
	t.Helper()
	counts := func(records []map[string]any) map[string]int {
		out := map[string]int{}
		for _, record := range records {
			body, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			out[string(body)]++
		}
		return out
	}
	var got []map[string]any
	for range 90 {
		trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
		got = nil
		for _, body := range firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, prefix) {
			got = append(got, eventFirehoseJSONRecords(t, body)...)
		}
		if len(got) >= len(want) {
			if !reflect.DeepEqual(counts(got), counts(want)) {
				t.Fatalf("actual S3 records differ from native consumers:\ngot %v\nwant %v", counts(got), counts(want))
			}
			return
		}
		advanceClock(t, source, 10*time.Second)
	}
	t.Fatalf("Firehose S3 delivery did not settle: got %v, want %v", counts(got), counts(want))
}
