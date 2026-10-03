package stackd_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type firehoseAuditExpected struct {
	Label, Message string
	Event          map[string]any
}

func firehoseAuditExpectation(t *testing.T, label string, event map[string]any, out any, callErr error, at time.Time) (string, firehoseAuditExpected) {
	t.Helper()
	event["eventTime"] = at.UTC().Format(time.RFC3339)
	expected := firehoseAuditExpected{Label: label, Event: event}
	var rejected smithy.APIError
	if errors.As(callErr, &rejected) {
		expected.Message = rejected.ErrorMessage()
	}
	return nativeAuditRequestID(t, out, callErr), expected
}

func firehoseAssertHistory(t *testing.T, client *cloudtrail.Client, expected map[string]firehoseAuditExpected) {
	t.Helper()
	seen := map[string]bool{}
	pages := cloudtrail.NewLookupEventsPaginator(client, &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("firehose.amazonaws.com")}}})
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range page.Events {
			event := ecsControlBody(t, []byte(aws.ToString(entry.CloudTrailEvent)))
			id, _ := event["requestID"].(string)
			if want, exists := expected[id]; exists {
				if want.Event["eventCategory"] != "Management" {
					t.Fatalf("%s data event escaped into management history", want.Label)
				}
				assertNativeAuditEvent(t, event, want.Event, want.Message)
				if len(entry.Resources) != 0 {
					t.Fatalf("%s gained a lookup resource index absent from native controls", want.Label)
				}
				seen[id] = true
			}
		}
	}
	for id, want := range expected {
		if want.Event["eventCategory"] == "Management" && !seen[id] {
			t.Errorf("%s missing from management history", want.Label)
		}
	}
}

func TestFirehoseNativeDataAuditConsumers(t *testing.T) {
	var raw json.RawMessage
	awsReadFixture(t, "firehose/"+"data_audit.json.gz", &raw)
	var original struct{ Account string }
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	var fixture firehoseNativeFixture
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), original.Account, eventDeliveryAccount)), &fixture); err != nil {
		t.Fatal(err)
	}
	var plan struct{ Setup []int }
	awsReadFixture(t, "firehose/"+"data_audit_replay.json", &plan)
	rows := map[int]firehoseNativeCall{}
	for _, row := range fixture.Calls {
		rows[row.Sequence] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt.Truncate(time.Second))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source})
			_, key, secret := clients.user(t, eventDeliveryAccount, "Delegated")
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "Delegated", allow(`"*"`, "*"))
			queue := trailNativeQueue(t, clients)
			if _, err := eventDeliveryClient(clients, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabled, EventPattern: aws.String(`{"source":["aws.firehose"],"detail-type":["AWS API Call via CloudTrail"]}`)}); err != nil {
				t.Fatal(err)
			}
			var session *sts.AssumeRoleOutput
			var trail cloudtrail.CreateTrailInput
			for _, sequence := range plan.Setup {
				row := rows[sequence]
				row.Operation = strings.ReplaceAll(row.Operation, "_", "-")
				var client any
				switch row.Service {
				case "s3":
					client = s3NativeClient(clients, "test", "test")
				case "iam":
					client = clients.iam("test", "test", "")
				case "cloudtrail":
					client = trailNativeClient(clients)
				case "firehose":
					client = clients.firehose(key, secret, "")
				case "sts":
					client = clients.sts(key, secret, "")
				default:
					t.Fatalf("unhandled audit setup service %s", row.Service)
				}
				out := firehoseReplayCall(t, client, row)
				switch value := out.(type) {
				case *cloudtrail.CreateTrailOutput:
					if err := json.Unmarshal(row.Input, &trail); err != nil {
						t.Fatal(err)
					}
				case *firehose.CreateDeliveryStreamOutput:
					var request firehose.CreateDeliveryStreamInput
					if err := json.Unmarshal(row.Input, &request); err != nil {
						t.Fatal(err)
					}
					awaitFirehoseActive(t, source, clients.firehose(key, secret, ""), aws.ToString(request.DeliveryStreamName))
				case *sts.AssumeRoleOutput:
					session = value
				}
			}
			native := map[string]json.RawMessage{}
			for _, raw := range fixture.CloudTrailProjections {
				event := ecsControlBody(t, raw)
				native[event["requestID"].(string)] = raw
			}
			expected := map[string]firehoseAuditExpected{}
			for _, row := range fixture.Calls {
				raw, exists := native[row.RequestID]
				if !exists {
					continue
				}
				event := ecsControlBody(t, raw)
				client := clients.firehose(key, secret, "")
				if event["userIdentity"].(map[string]any)["type"] == "AssumedRole" {
					client = clients.firehose(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
				}
				input := lambdaSQSNativeInput[json.RawMessage](t, row.Input, strings.NewReplacer())
				out, callErr := awstest.CallSDK(t.Context(), client, event["eventName"].(string), input)
				if row.Result.Code == "Success" {
					if callErr != nil {
						t.Fatal(callErr)
					}
				} else {
					assertAPIError(t, callErr, row.Result.Code)
				}
				id, want := firehoseAuditExpectation(t, row.Label, event, out, callErr, source.Now())
				expected[id] = want
			}
			clients = reopen()
			if _, err := trailNativeClient(clients).StopLogging(t.Context(), &cloudtrail.StopLoggingInput{Name: trail.Name}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			objects := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), aws.ToString(trail.S3BucketName), aws.ToString(trail.S3KeyPrefix)+"/AWSLogs/")
			for key, body := range objects {
				if strings.HasSuffix(key, "/") && len(body) == 0 {
					delete(objects, key) // Native trail permission-check prefix marker.
				}
			}
			for consumer, events := range map[string][]map[string]any{"s3": trailNativeRecords(t, objects), "eventbridge": trailQueueMessages(t, clients, queue)} {
				seen := map[string]bool{}
				for _, event := range events {
					if consumer == "eventbridge" {
						event = event["detail"].(map[string]any)
					}
					id, _ := event["requestID"].(string)
					if want, exists := expected[id]; exists {
						assertNativeAuditEvent(t, event, want.Event, want.Message)
						seen[id] = true
					}
				}
				for id, want := range expected {
					if !seen[id] {
						t.Errorf("%s absent from %s", want.Label, consumer)
					}
				}
			}
			firehoseAssertHistory(t, trailNativeClient(clients), expected)
		})
	}
}
