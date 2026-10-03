package stackd_test

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

func TestCloudTrailCloudWatchNativeAuditConsumers(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/cloudwatch/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.ReplaceAll(string(body), "000000000000", eventDeliveryAccount))
	var fixture struct {
		Observations []struct {
			nativeMetricObservation
			Service        string
			RequestStarted string   `json:"request_started"`
			RequestIDs     []string `json:"request_ids"`
		}
		DeliveredRecords []struct {
			Label string         `json:"matched_request_label"`
			Event map[string]any `json:"event"`
		} `json:"delivered_records"`
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	// Only positively correlated delivered documents are the native oracle.
	// The earlier capture window's absence says nothing about AWS delivery.
	native := map[string]map[string]any{}
	for _, record := range fixture.DeliveredRecords {
		if native[record.Label] != nil {
			t.Fatalf("duplicate captured audit for %s", record.Label)
		}
		native[record.Label] = record.Event
	}
	if len(native) != 6 {
		t.Fatalf("want all four operations and both captured rejections, got %d records", len(native))
	}
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "metric-audit.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 14, 2, 6, 27, 0, time.UTC))
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			trailNativeProvision(t, c, controls, objects, false)
			trails, metrics := trailNativeClient(c), metricsClient(c, eventDeliveryAccount)
			queue := trailNativeQueue(t, c)
			// The fixture captures S3 documents, not an EventBridge envelope.
			// Select its native detail identity rather than inventing an envelope source.
			if _, err := eventDeliveryClient(c, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name:         aws.String("native-cloudtrail"),
				EventPattern: aws.String(`{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["monitoring.amazonaws.com"],"eventCategory":["Data"]}}`),
			}); err != nil {
				t.Fatal(err)
			}
			var selection cloudtrail.PutEventSelectorsInput
			for _, row := range fixture.Observations {
				if row.Label == "select-only-metric-data" {
					if err := json.Unmarshal(row.Input, &selection); err != nil {
						t.Fatal(err)
					}
				}
			}
			selection.TrailName = aws.String(controls.Identity["trail_name"])
			if len(selection.AdvancedEventSelectors) != 1 {
				t.Fatal("missing native metric data selector")
			}
			fields := selection.AdvancedEventSelectors[0].FieldSelectors
			// A type-only resource cannot satisfy an ARN requirement. This is a
			// local selector regression derived from the captured resource shape,
			// not a claim that a bounded native negative-delivery probe succeeded.
			selection.AdvancedEventSelectors[0].FieldSelectors = append(slices.Clone(fields), trailtypes.AdvancedFieldSelector{
				Field: aws.String("resources.ARN"), StartsWith: []string{"arn:"},
			})
			if _, err := trails.PutEventSelectors(t.Context(), &selection); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "start-logging")
			var excludedID string
			for _, row := range fixture.Observations {
				if row.Label == "list-after-propagation" {
					out, err := awstest.CallSDK(t.Context(), metrics, "ListMetrics", row.Input)
					if err != nil {
						t.Fatal(err)
					}
					excludedID = nativeAuditRequestID(t, out, nil)
				}
			}
			if excludedID == "" {
				t.Fatal("missing selector-distinction request")
			}
			selection.AdvancedEventSelectors[0].FieldSelectors = fields
			if _, err := trails.PutEventSelectors(t.Context(), &selection); err != nil {
				t.Fatal(err)
			}
			expected := map[string]map[string]any{}
			messages := map[string]string{}
			eventTimes := map[string]string{}
			for _, row := range fixture.Observations {
				want := native[row.Label]
				if row.Service != "cloudwatch" || want == nil {
					continue
				}
				if !slices.Contains(row.RequestIDs, want["requestID"].(string)) {
					t.Fatalf("%s lacks native request-ID correlation", row.Label)
				}
				started, err := time.Parse(time.RFC3339Nano, row.RequestStarted)
				if err != nil {
					t.Fatal(err)
				}
				advanceClock(t, source, started.Truncate(time.Second).Sub(source.Now()))
				out, callErr := awstest.CallSDK(t.Context(), metrics, want["eventName"].(string), row.Input)
				if (callErr != nil) != (row.Result.Code != "Success") {
					t.Fatalf("%s SDK outcome differs from native %s: %v", row.Label, row.Result.Code, callErr)
				}
				id := nativeAuditRequestID(t, out, callErr)
				if callErr != nil {
					assertAPIError(t, callErr, row.Result.Code)
					var apiErr smithy.APIError
					var response interface{ HTTPStatusCode() int }
					if !errors.As(callErr, &apiErr) || !errors.As(callErr, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
						t.Fatalf("%s lost native service rejection: %v", row.Label, callErr)
					}
					messages[id] = apiErr.ErrorMessage()
				}
				if expected[id] != nil || id == excludedID {
					t.Fatalf("reused SDK request ID %s", id)
				}
				expected[id] = want
				eventTimes[id] = source.Now().Format(time.RFC3339)
			}
			if len(expected) != len(native) {
				t.Fatalf("replayed %d of %d native outcomes", len(expected), len(native))
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			records := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(c, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
			if len(records) != len(expected) {
				t.Fatalf("S3 consumer received %d outcomes, want %d selected outcomes", len(records), len(expected))
			}
			byID := map[string]map[string]any{}
			for _, got := range records {
				id, _ := got["requestID"].(string)
				want := expected[id]
				if id == excludedID || want == nil || byID[id] != nil {
					t.Fatalf("unexpected, ARN-selected or repeated consumer record: %#v", got)
				}
				want = maps.Clone(want)
				want["eventTime"] = eventTimes[id]
				assertNativeAuditEvent(t, got, want, messages[id])
				byID[id] = got
			}
			delivery, err := c.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue, MaxNumberOfMessages: 10})
			if err != nil {
				t.Fatal(err)
			}
			if len(delivery.Messages) != len(expected) {
				t.Fatalf("EventBridge/SQS consumer received %d outcomes, want %d", len(delivery.Messages), len(expected))
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
					t.Fatalf("EventBridge/SQS and S3 documents differ: %#v", event)
				}
				delete(byID, id)
			}
			if len(byID) != 0 {
				t.Fatalf("missing EventBridge/SQS outcomes: %#v", byID)
			}
		})
	}
}
