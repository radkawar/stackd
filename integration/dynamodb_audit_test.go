package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

// The manifest references original API requests and delivered native events,
// never a projection reconstructed from the emulator's request or journal.
type dynamoAuditSelection struct {
	Source                         string
	Setup, ExcludedBeforeSelection int
	Pairs                          [][2]int
	Reopen                         bool
}

type dynamoAuditCapture struct {
	Calls                    []dynamoNativeRow
	Events, CloudTrailEvents []json.RawMessage
}

func TestDynamoDBNativeAuditConsumers(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	var manifest struct {
		Account    string
		Selections []dynamoAuditSelection
		Forbidden  []string
	}
	dynamoReadJSON(t, "audit_replay", &manifest)
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
			observed := &dynamoReplayRuntime{Runtime: runtime}
			// Registered first, so the current retained stack/database closes before
			// native volumes are removed, including when an assertion aborts replay.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				for _, spec := range observed.specifications() {
					if err := runtime.Remove(ctx, spec); err != nil {
						t.Errorf("remove owned DynamoDB database %s: %v", spec.ID, err)
					}
				}
			})
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source, DynamoDBRuntime: observed})
			_, key, secret := clients.user(t, eventDeliveryAccount, "Delegated")
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "Delegated", allow(`"*"`, "*"))
			var tables []string
			// This defer uses the latest HTTP server, before retainedCloud's SQLite
			// cleanup callbacks, rather than retaining a client from before reopen.
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				client := dynamoClient(clients, eventDeliveryAccount, "test", clients.server.Client())
				for _, table := range tables {
					_, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: &table})
					var absent *dynamotypes.ResourceNotFoundException
					if err != nil && !errors.As(err, &absent) {
						t.Errorf("delete owned table %s: %v", table, err)
					}
					if err := dynamoWaitAbsent(ctx, client, table); err != nil {
						t.Errorf("await owned table deletion %s: %v", table, err)
					}
				}
			}()
			captures := map[string]dynamoAuditCapture{}
			for _, selection := range manifest.Selections {
				var raw json.RawMessage
				dynamoReadJSON(t, selection.Source, &raw)
				var capture dynamoAuditCapture
				if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), manifest.Account, eventDeliveryAccount)), &capture); err != nil {
					t.Fatal(err)
				}
				captures[selection.Source] = capture
				row := capture.Calls[selection.Setup-1]
				client := dynamoClient(clients, key, secret, clients.server.Client())
				out, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, row.Input) })
				if err != nil {
					t.Fatalf("%s setup: %v", selection.Source, err)
				}
				table := aws.ToString(out.(*dynamodb.CreateTableOutput).TableDescription.TableName)
				tables = append(tables, table)
				if err := dynamoWaitActive(t.Context(), client, table); err != nil {
					t.Fatal(err)
				}
			}
			controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
			objects := s3NativeLoad(t, "s3", "owned_object_delivery")
			trailNativeProvision(t, clients, controls, objects, false)
			queue := trailNativeQueue(t, clients)
			// ENABLED excludes read-only management, not selected Data events.
			if _, err := eventDeliveryClient(clients, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabled,
				EventPattern: aws.String(`{"source":["aws.dynamodb"],"detail-type":["AWS API Call via CloudTrail"]}`),
			}); err != nil {
				t.Fatal(err)
			}
			selectors := []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{
				{Field: aws.String("eventCategory"), Equals: []string{"Management"}},
			}}}
			selectEvents := func() {
				t.Helper()
				if _, err := trailNativeClient(clients).PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(controls.Identity["trail_name"]), AdvancedEventSelectors: selectors}); err != nil {
					t.Fatal(err)
				}
			}
			selectEvents()
			s3NativeReplay(t, trailNativeClient(clients), controls, "start-logging")
			expected := map[string]map[string]any{}
			excluded := map[string]bool{}
			for _, selection := range manifest.Selections {
				capture := captures[selection.Source]
				invoke := func(t *testing.T, number int) string {
					t.Helper()
					row := capture.Calls[number-1]
					client := dynamoClient(clients, key, secret, clients.server.Client())
					out, callErr := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, row.Input) })
					if row.Code == "" || row.Code == "Success" {
						if callErr != nil {
							t.Fatalf("%s/%d %s: %v", selection.Source, number, row.Label, callErr)
						}
					} else {
						assertAPIError(t, callErr, row.Code)
					}
					return nativeAuditRequestID(t, out, callErr)
				}
				if selection.ExcludedBeforeSelection != 0 {
					excluded[invoke(t, selection.ExcludedBeforeSelection)] = true
					setup := ecsControlBody(t, capture.Calls[selection.Setup-1].Input)
					selectors = append(selectors[:1], trailtypes.AdvancedEventSelector{FieldSelectors: []trailtypes.AdvancedFieldSelector{
						{Field: aws.String("eventCategory"), Equals: []string{"Data"}},
						{Field: aws.String("resources.type"), Equals: []string{"AWS::DynamoDB::Table"}},
						{Field: aws.String("resources.ARN"), Equals: []string{"arn:aws:dynamodb:us-east-1:" + eventDeliveryAccount + ":table/" + setup["TableName"].(string)}},
					}})
					selectEvents()
				}
				for _, pair := range selection.Pairs {
					if !t.Run(fmt.Sprintf("%s_%03d", selection.Source, pair[0]), func(t *testing.T) {
						events := capture.Events
						if selection.Source == "audit" {
							events = capture.CloudTrailEvents
						}
						want := ecsControlBody(t, events[pair[1]-1])
						if wrapped, ok := want["event"].(map[string]any); ok {
							want = wrapped
						}
						row := capture.Calls[pair[0]-1]
						if strings.ToLower(strings.ReplaceAll(want["eventName"].(string), "-", "")) != strings.ReplaceAll(row.Operation, "-", "") {
							t.Fatal("manifest pairs different native operations")
						}
						expected[invoke(t, pair[0])] = want
					}) {
						return
					}
				}
				if selection.Reopen {
					clients = reopen()
					got, err := clients.sqs(eventDeliveryAccount, "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("native-cloudtrail")})
					if err != nil {
						t.Fatal(err)
					}
					queue = got.QueueUrl
				}
			}
			if _, err := trailNativeClient(clients).StopLogging(t.Context(), &cloudtrail.StopLoggingInput{Name: aws.String(controls.Identity["trail_name"])}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			logs := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(clients, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
			// CloudTrail and EventBridge allow redelivery. Reopening can land
			// after a target commits but before its delivery is acknowledged.
			// Check every copy, then count the distinct selected API requests.
			seen := map[string]bool{}
			for _, got := range logs {
				if got["eventSource"] != "dynamodb.amazonaws.com" {
					// Trails allow all management sources here; eventSource Equals
					// is not a supported Management selector outside Lake.
					if got["eventCategory"] != "Management" {
						t.Fatalf("trail admitted an unselected data source: %v", got["eventSource"])
					}
					continue
				}
				id, _ := got["requestID"].(string)
				if expected[id] == nil || excluded[id] {
					t.Fatalf("unexpected or excluded DynamoDB S3 record: %#v", got)
				}
				dynamoAuditCompare(t, got, expected[id], manifest.Forbidden, key, eventDeliveryAccount)
				seen[id] = true
			}
			if len(seen) != len(expected) {
				t.Fatalf("S3 delivered %d of %d selected DynamoDB outcomes", len(seen), len(expected))
			}
			seen = map[string]bool{}
			for _, message := range trailQueueMessages(t, clients, queue) {
				got, ok := message["detail"].(map[string]any)
				if !ok {
					t.Fatalf("EventBridge envelope has no detail: %#v", message)
				}
				id, _ := got["requestID"].(string)
				want := expected[id]
				if want == nil || want["eventCategory"] == "Management" && want["readOnly"] == true {
					t.Fatalf("EventBridge delivered an ineligible DynamoDB event: %#v", message)
				}
				if message["source"] != "aws.dynamodb" || message["detail-type"] != "AWS API Call via CloudTrail" || message["account"] != eventDeliveryAccount || message["region"] != "us-east-1" {
					t.Fatalf("EventBridge envelope scope: %#v", message)
				}
				dynamoAuditCompare(t, got, want, manifest.Forbidden, key, eventDeliveryAccount)
				seen[id] = true
			}
			eligible := 0
			for _, want := range expected {
				if want["eventCategory"] == "Data" || want["readOnly"] == false {
					eligible++
				}
			}
			if len(seen) != eligible {
				t.Fatalf("EventBridge delivered %d of %d selected eligible events", len(seen), eligible)
			}
			// Event History is a separate public consumer: selected Data must not
			// become management merely because a trail is logging it to S3.
			seen = map[string]bool{}
			pages := cloudtrail.NewLookupEventsPaginator(trailNativeClient(clients), &cloudtrail.LookupEventsInput{MaxResults: aws.Int32(50), LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("dynamodb.amazonaws.com")}}})
			for pages.HasMorePages() {
				page, err := pages.NextPage(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range page.Events {
					got := ecsControlBody(t, []byte(aws.ToString(event.CloudTrailEvent)))
					id, _ := got["requestID"].(string)
					if got["eventCategory"] != "Management" || excluded[id] {
						t.Fatalf("data event escaped into history: %#v", got)
					}
					if want := expected[id]; want != nil {
						dynamoAuditCompare(t, got, want, manifest.Forbidden, key, eventDeliveryAccount)
						seen[id] = true
					}
				}
			}
			for id, want := range expected {
				if want["eventCategory"] == "Management" && !seen[id] {
					t.Fatalf("management request %s absent from history", id)
				}
			}
		})
	}
}

func dynamoAuditCompare(t *testing.T, got, want map[string]any, forbidden []string, key, account string) {
	t.Helper()
	// Native repeats demonstrate that attribute-name arrays are unordered.
	// Preserve requestItems and resource order, including account and type.
	dynamoAuditAttributeNames(got["requestParameters"])
	dynamoAuditAttributeNames(want["requestParameters"])
	for _, field := range []string{"eventSource", "eventName", "apiVersion", "awsRegion", "eventCategory", "managementEvent", "readOnly", "eventType", "recipientAccountId", "resources", "requestParameters", "errorCode"} {
		if !reflect.DeepEqual(got[field], want[field]) {
			t.Fatalf("%s %s: got %#v; native %#v", want["eventName"], field, got[field], want[field])
		}
	}
	if _, present := got["responseElements"]; !present {
		t.Fatal("audit omitted native responseElements member")
	}
	if want["responseElements"] == nil {
		if got["responseElements"] != nil {
			t.Fatalf("native redacted response leaked: %#v", got["responseElements"])
		}
	} else {
		native := want["responseElements"].(map[string]any)["tableDescription"].(map[string]any)
		response, ok := got["responseElements"].(map[string]any)
		if !ok {
			t.Fatalf("management response missing: %#v", got)
		}
		actual, ok := response["tableDescription"].(map[string]any)
		if !ok {
			t.Fatalf("management table response missing: %#v", response)
		}
		for _, field := range []string{"tableName", "tableArn", "attributeDefinitions", "keySchema", "deletionProtectionEnabled", "streamSpecification"} {
			if !reflect.DeepEqual(actual[field], native[field]) {
				t.Fatalf("management response %s: got %#v; native %#v", field, actual[field], native[field])
			}
		}
		billing, ok := actual["billingModeSummary"].(map[string]any)
		if !ok || !reflect.DeepEqual(billing["billingMode"], native["billingModeSummary"].(map[string]any)["billingMode"]) {
			t.Fatal("management billing mode differs from native")
		}
	}
	identity, ok := got["userIdentity"].(map[string]any)
	if !ok || identity["type"] != "IAMUser" || identity["accountId"] != account || identity["arn"] != "arn:aws:iam::"+account+":user/Delegated" || identity["accessKeyId"] != key {
		t.Fatalf("audit lost authenticated caller: %#v", identity)
	}
	if got["eventID"] == nil || got["eventID"] == "" || got["requestID"] == nil || got["requestID"] == "" {
		t.Fatal("audit lost correlation identity")
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range forbidden {
		if strings.Contains(string(body), secret) {
			t.Fatalf("audit leaked non-key data %q", secret)
		}
	}
}

func dynamoAuditAttributeNames(value any) {
	switch value := value.(type) {
	case map[string]any:
		for name, member := range value {
			if name == "items" {
				if names, ok := member.([]any); ok {
					slices.SortFunc(names, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
				}
			} else {
				dynamoAuditAttributeNames(member)
			}
		}
	case []any:
		for _, member := range value {
			dynamoAuditAttributeNames(member)
		}
	}
}
