package stackd_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

func TestCloudWatchAlarmNativeManagementAudit(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/cloudwatch/alarm_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.ReplaceAll(string(body), "000000000000", eventDeliveryAccount))
	var fixture struct {
		Setup        []nativeMetricObservation
		Observations []struct {
			nativeMetricObservation
			Event map[string]any
		}
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "alarm-audit.sqlite"))
			}
			source := clock.NewManual(time.Unix(fixture.Observations[0].Started/1000, 0).UTC())
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			trails, metrics := trailNativeClient(c), metricsClient(c, eventDeliveryAccount)
			// Only the denied request needs an additional alarm prerequisite.
			// It is created before logging/consumer selection, not a fabricated oracle.
			for _, row := range fixture.Setup {
				replayMetric(t, metrics, row)
			}
			trailNativeProvision(t, c, controls, objects, false)
			queue := trailNativeQueue(t, c)
			if _, err := eventDeliveryClient(c, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name:         aws.String("native-cloudtrail"),
				State:        eventtypes.RuleStateEnabledWithAllCloudtrailManagementEvents,
				EventPattern: aws.String(`{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["monitoring.amazonaws.com"],"eventCategory":["Management"]}}`),
			}); err != nil {
				t.Fatal(err)
			}
			// Unlike metric Data selectors, alarm Management events have no resources.
			if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{
				TrailName: aws.String(controls.Identity["trail_name"]),
				AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{
					{Field: aws.String("eventCategory"), Equals: []string{"Management"}},
				}}},
			}); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "start-logging")
			expected := map[string]map[string]any{}
			messages := map[string]string{}
			for _, row := range fixture.Observations {
				when, _ := time.Parse(time.RFC3339, row.Event["eventTime"].(string))
				advanceClock(t, source, when.Sub(source.Now()))
				out, callErr := awstest.CallSDK(t.Context(), metrics, row.Operation, row.Input)
				if (callErr != nil) != (row.Result.Code != "Success") {
					t.Fatalf("%s differs from native %s: %v", row.Label, row.Result.Code, callErr)
				}
				id := nativeAuditRequestID(t, out, callErr)
				if callErr != nil {
					assertAPIError(t, callErr, row.Result.Code)
					var apiErr smithy.APIError
					var response interface{ HTTPStatusCode() int }
					if !errors.As(callErr, &apiErr) || !errors.As(callErr, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
						t.Fatalf("%s lost native modeled rejection: %v", row.Label, callErr)
					}
					messages[id] = apiErr.ErrorMessage()
				}
				if expected[id] != nil {
					t.Fatalf("reused SDK request ID %s", id)
				}
				expected[id] = row.Event
			}
			compare := func(got map[string]any) string {
				t.Helper()
				id, _ := got["requestID"].(string)
				want := expected[id]
				if want == nil {
					t.Fatalf("unexpected alarm audit record: %#v", got)
				}
				assertNativeAuditEvent(t, got, want, messages[id])
				return id
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			// LookupEvents must expose these as Management, not silently discard
			// them as resource-less Metric Data. The setup event is not an oracle.
			lookup := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("monitoring.amazonaws.com")}}, MaxResults: aws.Int32(50)}
			found := map[string]bool{}
			for {
				out, err := trails.LookupEvents(t.Context(), lookup)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range out.Events {
					var got map[string]any
					if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &got); err != nil {
						t.Fatal(err)
					}
					id, _ := got["requestID"].(string)
					if expected[id] == nil {
						continue
					}
					compare(got)
					if found[id] || len(event.Resources) != 0 {
						t.Fatalf("duplicate or resource-inventing LookupEvents entry: %#v", event)
					}
					found[id] = true
				}
				if out.NextToken == nil {
					break
				}
				lookup.NextToken = out.NextToken
			}
			if len(found) != len(expected) {
				t.Fatalf("LookupEvents exposed %d of %d alarm outcomes", len(found), len(expected))
			}
			records := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(c, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
			byID := map[string]map[string]any{}
			for _, got := range records {
				if got["eventSource"] != "monitoring.amazonaws.com" {
					continue
				}
				id := compare(got)
				if byID[id] != nil {
					t.Fatalf("duplicate S3 alarm audit %s", id)
				}
				byID[id] = got
			}
			if len(byID) != len(expected) {
				t.Fatalf("Management trail selected %d of %d alarm outcomes", len(byID), len(expected))
			}
			for len(byID) != 0 {
				delivery, err := c.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue, MaxNumberOfMessages: 10})
				if err != nil || len(delivery.Messages) == 0 {
					t.Fatalf("EventBridge missed %d Management outcomes: %v", len(byID), err)
				}
				for _, message := range delivery.Messages {
					var event struct {
						DetailType string         `json:"detail-type"`
						Detail     map[string]any `json:"detail"`
					}
					if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &event); err != nil {
						t.Fatal(err)
					}
					id, _ := event.Detail["requestID"].(string)
					if event.DetailType != "AWS API Call via CloudTrail" || byID[id] == nil || !reflect.DeepEqual(event.Detail, byID[id]) {
						t.Fatalf("EventBridge/SQS and S3 alarm documents differ: %#v", event)
					}
					delete(byID, id)
				}
			}
		})
	}
}
