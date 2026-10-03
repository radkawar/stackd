package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
)

func TestCloudTrailEventBridgeNativeBatchDelivery(t *testing.T) {
	// The fixture keeps API inputs and native gzip records separately. Restore
	// only the synthetic detail payload, never derive expected audit parameters
	// from the SDK's wire body.
	data, err := os.ReadFile("../testdata/aws/cloudtrail/service_data_events.json")
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), "111111111111", eventDeliveryAccount))
	var fixture struct {
		Identity     map[string]string `json:"identity_relationships"`
		Observations []struct {
			Label   string          `json:"label"`
			Service string          `json:"service"`
			Input   json.RawMessage `json:"input"`
			Result  struct {
				Headers map[string]string `json:"headers"`
			} `json:"result"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	nativeRecords := auditNativeRecords(t, "service_data_events")
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "audit.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 19, 10, 0, 0, time.UTC))
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			trailNativeProvision(t, c, controls, objects, false)
			client, trails := eventDeliveryClient(c, eventDeliveryAccount), trailNativeClient(c)
			busARN := fixture.Identity["bus_arn"]
			busName := busARN[strings.LastIndex(busARN, "/")+1:]
			if _, err := client.CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: &busName}); err != nil {
				t.Fatal(err)
			}
			queue := trailNativeQueue(t, c)
			if _, err := client.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("native-cloudtrail"), EventPattern: aws.String(`{"source":["aws.events"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"apiVersion":["2015-10-07"]}}`)}); err != nil {
				t.Fatal(err)
			}
			if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(controls.Identity["trail_name"]), AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{
				{Field: aws.String("eventCategory"), Equals: []string{"Data"}},
				{Field: aws.String("resources.type"), Equals: []string{"AWS::Events::EventBus"}},
				{Field: aws.String("resources.ARN"), Equals: []string{busARN}},
			}}}}); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "start-logging")
			expected := map[string]map[string]any{}
			accepted := 0
			for _, row := range fixture.Observations {
				if row.Service != "events" {
					continue
				}
				var native map[string]any
				for _, record := range nativeRecords {
					if record["requestID"] == row.Result.Headers["x-amzn-RequestId"] {
						native = record
					}
				}
				if native == nil {
					t.Fatalf("missing correlated native record for %s", row.Label)
				}
				result, err := awstest.CallSDK(t.Context(), client, "PutEvents", row.Input, func(input any) {
					in := input.(*eventbridge.PutEventsInput)
					for i := range in.Entries {
						in.Entries[i].Detail = aws.String(`{"private":"must-not-appear-in-audit"}`)
					}
					if row.Label == "correlated-events-put-mixed-failure" {
						in.Entries[1].Detail = aws.String("not-json")
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				out := result.(*eventbridge.PutEventsOutput)
				requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
				if !ok || requestID == "" {
					t.Fatal("missing request correlation")
				}
				// Copy the fixture so both backend replays use untouched native data.
				encoded, _ := json.Marshal(native)
				encoded = []byte(strings.ReplaceAll(string(encoded), "111111111111", eventDeliveryAccount))
				var want map[string]any
				if err := json.Unmarshal(encoded, &want); err != nil {
					t.Fatal(err)
				}
				response := want["responseElements"].(map[string]any)
				entries := response["entries"].([]any)
				if float64(out.FailedEntryCount) != response["failedEntryCount"] || len(out.Entries) != len(entries) {
					t.Fatalf("batch API diverges from native: %+v", out)
				}
				for i, entry := range out.Entries {
					if _, present := entries[i].(map[string]any)["eventId"]; present {
						if aws.ToString(entry.EventId) == "" {
							t.Fatal("accepted event has no identity")
						}
						entries[i].(map[string]any)["eventId"] = aws.ToString(entry.EventId)
						accepted++
					}
				}
				expected[requestID] = want
			}
			if len(expected) != 3 {
				t.Fatalf("fixture lost correlated batches: %d", len(expected))
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			logs := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(c, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
			if len(logs) != len(expected) {
				t.Fatalf("want one audit per batch, got %d for %d", len(logs), len(expected))
			}
			byID := map[string]map[string]any{}
			for _, got := range logs {
				id, _ := got["requestID"].(string)
				want := expected[id]
				if want == nil || byID[id] != nil {
					t.Fatalf("unexpected or repeated audit: %#v", got)
				}
				for _, field := range []string{"eventName", "eventSource", "apiVersion", "readOnly", "eventCategory", "managementEvent", "eventType", "recipientAccountId", "resources", "requestParameters", "responseElements", "errorCode", "errorMessage"} {
					if !reflect.DeepEqual(got[field], want[field]) {
						t.Fatalf("%s field %s: got %#v native %#v", id, field, got[field], want[field])
					}
				}
				byID[id] = got
			}
			messages, err := c.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue, MaxNumberOfMessages: 10})
			if err != nil {
				t.Fatal(err)
			}
			if len(messages.Messages) != len(expected) {
				t.Fatalf("EventBridge consumer received %d batches, want %d", len(messages.Messages), len(expected))
			}
			for _, message := range messages.Messages {
				var event struct {
					Source string         `json:"source"`
					Detail map[string]any `json:"detail"`
				}
				if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &event); err != nil {
					t.Fatal(err)
				}
				id, _ := event.Detail["requestID"].(string)
				if event.Source != "aws.events" || !reflect.DeepEqual(event.Detail, byID[id]) {
					t.Fatalf("trail and EventBridge consumer diverged: %#v", event)
				}
				delete(byID, id)
			}
			if len(byID) != 0 {
				t.Fatalf("missing consumer records: %#v", byID)
			}
			rows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			facts, calls := 0, 0
			for _, row := range rows {
				if row.EventBridgeAccepted.EventBusARN == busARN {
					facts++
				}
				if call := row.APICallCompleted; call != nil && call.EventSource == "events.amazonaws.com" && call.EventName == "PutEvents" {
					calls++
				}
			}
			if facts != accepted || calls != len(expected) {
				t.Fatalf("accepted facts/batch calls = %d/%d, want %d/%d; possible audit recursion", facts, calls, accepted, len(expected))
			}
		})
	}
}

type eventBridgeAuditFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *eventBridgeAuditFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "events.amazonaws.com" && call.EventName == "PutEvents" && call.ErrorCode == "" && f.fail.Swap(false) {
		return errors.New("injected EventBridge audit append failure")
	}
	return nil
}

func TestCloudTrailEventBridgeBatchAuditRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "rollback.sqlite"))
			}
			failure := &eventBridgeAuditFailure{Storage: backends.Journal}
			backends.Journal = failure
			source := clock.NewManual(time.Date(2026, 9, 13, 19, 10, 0, 0, time.UTC))
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			client := eventDeliveryClient(c, eventDeliveryAccount)
			failure.fail.Store(true)
			_, err := awstest.CallSDK(t.Context(), client, "PutEvents", json.RawMessage(`{"Entries":[{"Source":"rollback.probe","DetailType":"rollback","Detail":"{}"},{"Source":"rollback.probe","DetailType":"rollback","Detail":"{}"}]}`))
			if err == nil {
				t.Fatal("failed audit reported successful admission")
			}
			trailNativeDrain(t, cloud)
			rows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			rejected := 0
			for _, row := range rows {
				if row.EventBridgeAccepted.EventID != "" {
					t.Fatal("failed batch leaked accepted event facts")
				}
				if call := row.APICallCompleted; call != nil && call.EventSource == "events.amazonaws.com" && call.EventName == "PutEvents" {
					if call.ErrorCode == "" {
						t.Fatal("failed batch leaked successful audit")
					}
					rejected++
				}
			}
			if rejected != 1 {
				t.Fatalf("rejected batch outcomes = %d, want 1", rejected)
			}
			// The same failed batch lazily created the default bus. Its state must
			// roll back too: a subsequent Describe creates it at this later time.
			advanceClock(t, source, time.Minute)
			bus, err := client.DescribeEventBus(t.Context(), &eventbridge.DescribeEventBusInput{})
			if err != nil {
				t.Fatal(err)
			}
			if bus.CreationTime == nil || !bus.CreationTime.Equal(source.Now()) {
				t.Fatalf("failed batch retained its lazy default bus: %+v", bus)
			}
		})
	}
}

func TestCloudTrailEventBridgeNativeManagementOutcomes(t *testing.T) {
	native := map[string]map[string]any{}
	for _, record := range auditNativeRecords(t, "service_management_events") {
		if record["eventSource"] == "events.amazonaws.com" {
			native[record["eventName"].(string)] = record
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "management.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 19, 10, 0, 0, time.UTC))
			_, c, _ := startEventDeliveryCloud(t, backends, source)
			client, trails := eventDeliveryClient(c, eventDeliveryAccount), trailNativeClient(c)
			for _, action := range []string{"PutRule", "PutTargets", "ListTargetsByRule", "RemoveTargets", "DeleteRule", "DescribeRule"} {
				if native[action] == nil {
					t.Fatalf("missing native %s record", action)
				}
				encoded, err := json.Marshal(native[action])
				if err != nil {
					t.Fatal(err)
				}
				var want map[string]any
				if err := json.Unmarshal(encoded, &want); err != nil {
					t.Fatal(err)
				}
				params := want["requestParameters"].(map[string]any)
				for _, field := range []string{"name", "rule"} {
					if _, present := params[field]; present {
						params[field] = "audit-native-rule"
					}
				}
				if action == "PutRule" {
					want["responseElements"].(map[string]any)["ruleArn"] = "arn:aws:events:us-east-1:" + eventDeliveryAccount + ":rule/audit-native-rule"
				}
				input, err := json.Marshal(params)
				if err != nil {
					t.Fatal(err)
				}
				// Native force:false was observed with the API member omitted.
				var omitted map[string]any
				if err := json.Unmarshal(input, &omitted); err != nil {
					t.Fatal(err)
				}
				delete(omitted, "force")
				input, err = json.Marshal(omitted)
				if err != nil {
					t.Fatal(err)
				}
				result, callErr := awstest.CallSDK(t.Context(), client, action, input)
				var requestID string
				if action == "DescribeRule" {
					assertAPIError(t, callErr, "ResourceNotFoundException")
					var response *smithyhttp.ResponseError
					if !errors.As(callErr, &response) {
						t.Fatalf("missing error response: %v", callErr)
					}
					requestID = response.Response.Header.Get("X-Amzn-RequestId")
				} else {
					if callErr != nil {
						t.Fatal(callErr)
					}
					meta := reflect.ValueOf(result).Elem().FieldByName("ResultMetadata").Interface().(middleware.Metadata)
					requestID, _ = awsmiddleware.GetRequestIDMetadata(meta)
				}
				if requestID == "" {
					t.Fatalf("%s lost request correlation", action)
				}
				got := auditLookupRecord(t, trails, requestID, action)
				eventBridgeAuditMatchesNative(t, got, want, callErr)
			}
		})
	}
}

// Error diagnostics remain evidence, not wording pins. Ordinary rejection text
// must survive the SDK-to-audit path; native UnknownError deliberately replaces it.
func eventBridgeAuditMatchesNative(t *testing.T, got, want map[string]any, callErr error) {
	t.Helper()
	for _, field := range []string{"eventSource", "eventName", "apiVersion", "eventCategory", "managementEvent", "readOnly", "requestParameters", "responseElements", "resources", "errorCode"} {
		actual, present := got[field]
		expected, expectedPresent := want[field]
		if present != expectedPresent || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s %s: got %#v present %v, native %#v present %v", want["eventName"], field, actual, present, expected, expectedPresent)
		}
	}
	message, present := got["errorMessage"]
	_, expectedPresent := want["errorMessage"]
	if present != expectedPresent {
		t.Fatalf("%s errorMessage presence: got %v, native %v", want["eventName"], present, expectedPresent)
	}
	if present {
		text, ok := message.(string)
		if !ok || text == "" {
			t.Fatalf("%s lost its diagnostic: %#v", want["eventName"], message)
		}
		if want["errorCode"] != "UnknownError" {
			var apiError smithy.APIError
			if !errors.As(callErr, &apiError) || text != apiError.ErrorMessage() {
				t.Fatalf("%s did not preserve the SDK rejection: %v", want["eventName"], callErr)
			}
		}
	}
}

func TestCloudTrailEventBridgeNativeArchivesAndReplays(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/cloudtrail/eventbridge_archives_replays.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Source struct {
			Account       string
			Normalization struct {
				InitialTime string `json:"initial_time"`
				Names       map[string]string
			}
		}
		Scenarios []struct {
			Name         string
			Observations []struct {
				Label              string
				Service            string
				Operation          string
				Input              json.RawMessage
				Result             struct{ Code string }
				Native             map[string]any
				AssumeRole         *sts.AssumeRoleInput `json:"assume_role"`
				TokenFrom          string               `json:"token_from"`
				AdvanceSeconds     int                  `json:"advance_seconds"`
				ResponseTimeLabels map[string]string    `json:"response_time_labels"`
			}
		}
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.ReplaceAll(string(body), fixture.Source.Account, eventDeliveryAccount))
	for native, local := range fixture.Source.Normalization.Names {
		body = []byte(strings.ReplaceAll(string(body), native, local))
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	initialTime, err := time.Parse(time.RFC3339, fixture.Source.Normalization.InitialTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "archive-audit.sqlite"))
				}
				source := clock.NewManual(initialTime)
				cloud, c, _ := startEventDeliveryCloud(t, backends, source)
				client, trails := eventDeliveryClient(c, eventDeliveryAccount), trailNativeClient(c)
				tokens, callTimes := map[string]string{}, map[string]string{}
				for _, row := range scenario.Observations {
					t.Run(row.Label, func(t *testing.T) {
						if row.AdvanceSeconds != 0 {
							advanceClock(t, source, time.Duration(row.AdvanceSeconds)*time.Second)
							trailNativeDrain(t, cloud)
						}
						var caller any = client
						switch row.Service {
						case "events":
						case "iam":
							caller = c.iam(eventDeliveryAccount, "test", "")
						default:
							t.Fatalf("unsupported fixture setup service %q", row.Service)
						}
						if row.AssumeRole != nil {
							session, err := c.sts(eventDeliveryAccount, "test", "").AssumeRole(t.Context(), row.AssumeRole)
							if err != nil {
								t.Fatal(err)
							}
							options := client.Options()
							options.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
							caller = eventbridge.New(options)
						}
						input := row.Input
						if row.TokenFrom != "" {
							token := tokens[row.TokenFrom]
							if token == "" {
								t.Fatalf("SDK page %s did not supply a continuation token", row.TokenFrom)
							}
							var params map[string]any
							if err := json.Unmarshal(input, &params); err != nil {
								t.Fatal(err)
							}
							params["NextToken"] = token
							input, err = json.Marshal(params)
							if err != nil {
								t.Fatal(err)
							}
						}
						callTimes[row.Label] = source.Now().Format(time.RFC3339)
						output, callErr := awstest.CallSDK(t.Context(), caller, row.Operation, input)
						if row.Result.Code == "Success" {
							if callErr != nil {
								t.Fatal(callErr)
							}
						} else {
							assertAPIError(t, callErr, row.Result.Code)
						}
						if page, ok := output.(*eventbridge.ListArchivesOutput); ok && page != nil {
							tokens[row.Label] = aws.ToString(page.NextToken)
						}
						if row.Native == nil {
							return // Ordered SDK setup, not invented native audit evidence.
						}
						id := nativeAuditRequestID(t, output, callErr)
						got := auditLookupRecord(t, trails, id, row.Operation)
						encoded, err := json.Marshal(row.Native)
						if err != nil {
							t.Fatal(err)
						}
						var want map[string]any
						if err := json.Unmarshal(encoded, &want); err != nil {
							t.Fatal(err)
						}
						for field, label := range row.ResponseTimeLabels {
							at := callTimes[label]
							if at == "" {
								t.Fatalf("missing clock reference %s", label)
							}
							want["responseElements"].(map[string]any)[field] = at
						}
						if row.TokenFrom != "" {
							want["requestParameters"].(map[string]any)["nextToken"] = tokens[row.TokenFrom]
						}
						eventBridgeAuditMatchesNative(t, got, want, callErr)
						want["eventTime"] = callTimes[row.Label]
						for _, field := range []string{"eventVersion", "eventTime", "awsRegion", "eventType", "recipientAccountId"} {
							if !reflect.DeepEqual(got[field], want[field]) {
								t.Fatalf("%s: got %#v, native normalized %#v", field, got[field], want[field])
							}
						}
					})
					if t.Failed() {
						return // Later observations depend on this SDK transition.
					}
				}
			})
		}
	}
}
