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
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

func TestSNSNativeAuditConsumers(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/sns/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	var identity struct{ Account string }
	awsDecodeJSON(t, body, &identity)
	body = []byte(strings.ReplaceAll(string(body), identity.Account, eventDeliveryAccount))
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var fixture struct {
				Account, Region string
				Observations    []struct {
					awsNativeObservation
					Event map[string]any
				}
			}
			awsDecodeJSON(t, body, &fixture)
			started, err := time.Parse(time.RFC3339, fixture.Observations[0].Event["eventTime"].(string))
			if err != nil {
				t.Fatal(err)
			}
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sns-audit.sqlite"))
			}
			source := clock.NewManual(started)
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			trails := trailNativeClient(clients)
			trailNativeProvision(t, clients, controls, objects, false)
			queue := trailNativeQueue(t, clients)
			if _, err := eventDeliveryClient(clients, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabledWithAllCloudtrailManagementEvents,
				EventPattern: aws.String(`{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["sns.amazonaws.com"]}}`),
			}); err != nil {
				t.Fatal(err)
			}
			selection := cloudtrail.PutEventSelectorsInput{
				TrailName: aws.String(controls.Identity["trail_name"]),
				AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{
					{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}},
					{FieldSelectors: []trailtypes.AdvancedFieldSelector{
						{Field: aws.String("eventCategory"), Equals: []string{"Data"}},
						{Field: aws.String("resources.type"), Equals: []string{"AWS::SNS::Topic"}},
						{Field: aws.String("resources.ARN"), Equals: []string{"arn:aws:sns:us-east-1:" + fixture.Account + ":unselected"}},
					}},
				},
			}
			if _, err := trails.PutEventSelectors(t.Context(), &selection); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "start-logging")
			expected := map[string]map[string]any{}
			errorsByID := map[string]string{}
			management := 0
			for _, row := range fixture.Observations {
				when, err := time.Parse(time.RFC3339, row.Event["eventTime"].(string))
				if err != nil {
					t.Fatal(err)
				}
				advanceClock(t, source, when.Sub(source.Now()))
				action := row.Event["eventName"].(string)
				if row.Event["eventCategory"] == "Data" {
					// A successful publication with a nonmatching topic selector must
					// reach neither the trail nor its EventBridge API-event consumer.
					_, callErr := awstest.CallSDK(t.Context(), topics, action, row.Input)
					awsNativeResult(t, row.awsNativeObservation, callErr)
					var publication sns.PublishBatchInput
					awsDecodeJSON(t, row.Input, &publication)
					selection.AdvancedEventSelectors[1].FieldSelectors[2].Equals = []string{aws.ToString(publication.TopicArn)}
					if _, err := trails.PutEventSelectors(t.Context(), &selection); err != nil {
						t.Fatal(err)
					}
				} else {
					management++
				}
				out, callErr := awstest.CallSDK(t.Context(), topics, action, row.Input)
				awsNativeResult(t, row.awsNativeObservation, callErr)
				id := nativeAuditRequestID(t, out, callErr)
				if callErr != nil {
					var rejected smithy.APIError
					if !errors.As(callErr, &rejected) {
						t.Fatal(callErr)
					}
					errorsByID[id] = rejected.ErrorMessage()
				}
				if publication, ok := out.(*sns.PublishBatchOutput); ok && callErr == nil {
					ids := map[string]string{}
					for _, entry := range publication.Successful {
						ids[aws.ToString(entry.Id)] = aws.ToString(entry.MessageId)
					}
					for _, entry := range row.Event["responseElements"].(map[string]any)["successful"].([]any) {
						result := entry.(map[string]any)
						if ids[result["id"].(string)] == "" {
							t.Fatalf("native successful batch entry missing from SDK output: %#v", result)
						}
						result["messageId"] = ids[result["id"].(string)]
					}
				}
				expected[id] = row.Event
			}
			compare := func(got map[string]any) string {
				t.Helper()
				id, _ := got["requestID"].(string)
				want := expected[id]
				if want == nil {
					t.Fatalf("unselected or unexpected SNS audit: %#v", got)
				}
				assertNativeAuditEvent(t, got, want, errorsByID[id])
				return id
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			lookup := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("sns.amazonaws.com")}}, MaxResults: aws.Int32(50)}
			found := map[string]bool{}
			for {
				out, err := trails.LookupEvents(t.Context(), lookup)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range out.Events {
					var got map[string]any
					awsDecodeJSON(t, []byte(aws.ToString(event.CloudTrailEvent)), &got)
					id := compare(got)
					if got["eventCategory"] != "Management" || found[id] {
						t.Fatalf("Data or duplicate SNS event in Management history: %#v", got)
					}
					found[id] = true
				}
				if out.NextToken == nil {
					break
				}
				lookup.NextToken = out.NextToken
			}
			if len(found) != management {
				t.Fatalf("Management history exposed %d of %d SNS outcomes", len(found), management)
			}
			selected := map[string]map[string]any{}
			for _, got := range trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(clients, fixture.Account, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/")) {
				if got["eventSource"] != "sns.amazonaws.com" {
					continue
				}
				id := compare(got)
				if selected[id] != nil {
					t.Fatalf("duplicate SNS trail event: %s", id)
				}
				selected[id] = got
			}
			if len(selected) != len(expected) {
				t.Fatalf("selected SNS trail exposed %d of %d outcomes", len(selected), len(expected))
			}
			for _, message := range snsAdmissionReceive(t, cloud, clients.sqs(fixture.Account, "test", ""), queue) {
				var event struct {
					DetailType string         `json:"detail-type"`
					Detail     map[string]any `json:"detail"`
				}
				awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &event)
				id, _ := event.Detail["requestID"].(string)
				if event.DetailType != "AWS API Call via CloudTrail" || selected[id] == nil || !reflect.DeepEqual(event.Detail, selected[id]) {
					t.Fatalf("EventBridge/SQS diverged from selected SNS trail: %#v", event)
				}
				delete(selected, id)
			}
			if len(selected) != 0 {
				t.Fatalf("EventBridge/SQS missed selected SNS outcomes: %#v", selected)
			}
		})
	}
}

func TestSNSNativeCrossAccountAuditConsumers(t *testing.T) {
	for _, fixtureName := range []string{"cross_account_audit.json", "confirmation_audit.json", "cross_account_control_audit.json"} {
		t.Run(fixtureName, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/sns/" + fixtureName)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Region       string
				Accounts     map[string]string
				Observations []snsCrossObservation
				Sessions     []struct {
					Input  sts.AssumeRoleInput
					Output sts.AssumeRoleOutput
				}
				Resources  map[string]json.RawMessage
				CloudTrail struct {
					Events []struct {
						Account   string `json:"observing_account"`
						RequestID string `json:"matched_request_id"`
						Event     json.RawMessage
					}
				}
			}
			awsDecodeJSON(t, data, &fixture)
			for i := range fixture.Observations {
				if fixture.Observations[i].Caller == "" {
					fixture.Observations[i].Caller = "anonymous"
				}
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					cloud, clients, source := admissionFixtureCloud(t, backend, snsAdmissionFixture{Observations: []awsNativeObservation{fixture.Observations[0].awsNativeObservation}})
					topics := snsCrossTopics(t, clients, fixture.Accounts["A"], fixture.Accounts["B"], fixture.Region)
					var replacements []string
					for _, native := range fixture.Sessions {
						session, err := clients.sts(fixture.Accounts["B"], "test", "").AssumeRole(t.Context(), &native.Input)
						if err != nil {
							t.Fatal(err)
						}
						credential := session.Credentials
						topics[aws.ToString(native.Output.AssumedRoleUser.Arn)] = clients.snsRegion(fixture.Region, aws.ToString(credential.AccessKeyId), aws.ToString(credential.SecretAccessKey), aws.ToString(credential.SessionToken))
						replacements = append(replacements, aws.ToString(native.Output.AssumedRoleUser.Arn), aws.ToString(session.AssumedRoleUser.Arn), aws.ToString(native.Output.AssumedRoleUser.AssumedRoleId), aws.ToString(session.AssumedRoleUser.AssumedRoleId))
					}
					for _, row := range fixture.Observations {
						if row.Operation != "get-caller-identity" {
							continue
						}
						client := topics[row.Actor]
						if client == nil {
							client = topics[row.Caller]
						}
						credential, err := client.Options().Credentials.Retrieve(t.Context())
						if err != nil {
							t.Fatal(err)
						}
						got, err := clients.sts(credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
						if err != nil {
							t.Fatal(err)
						}
						var native sts.GetCallerIdentityOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						replacements = append(replacements, aws.ToString(native.Arn), aws.ToString(got.Arn), aws.ToString(native.UserId), aws.ToString(got.UserId))
					}
					normalize := func(raw []byte) []byte { return []byte(strings.NewReplacer(replacements...).Replace(string(raw))) }
					requests, diagnostics, instants := map[string]string{}, map[string]string{}, map[string]string{}
					pending := map[string][]sqstypes.Message{}
					for _, capture := range fixture.Observations {
						row := capture.awsNativeObservation
						if delta := time.UnixMilli(row.Started).Sub(source.Now()); delta > 0 {
							advanceClock(t, source, delta)
						}
						// Settle due effects before the next observed API transition. Native
						// controls can arrive before a later call physically deletes the source.
						trailNativeDrain(t, cloud)
						var client any
						switch row.Service {
						case "sns":
							client = topics[capture.Caller]
							if actor := topics[capture.Actor]; actor != nil {
								client = actor
							}
						case "sqs":
							queues := clients.sqs(capture.Caller, "test", "")
							if row.Operation == "receive-message" {
								var input sqs.ReceiveMessageInput
								var native sqs.ReceiveMessageOutput
								awsDecodeJSON(t, normalize(row.Input), &input)
								awsDecodeJSON(t, row.Result.Output, &native)
								queue := aws.ToString(input.QueueUrl)
								pending[queue] = append(pending[queue], snsAdmissionReceive(t, cloud, queues, input.QueueUrl)...)
								for _, expected := range native.Messages {
									expected.Body = aws.String(string(normalize([]byte(aws.ToString(expected.Body)))))
									var got, want map[string]any
									pending[queue], got = snsCrossReceipt(t, pending[queue], expected, clients.server.URL)
									awsDecodeJSON(t, []byte(aws.ToString(expected.Body)), &want)
									if token, _ := want["Token"].(string); token != "" {
										replacements = append(replacements, token, got["Token"].(string))
									}
								}
								continue
							}
							if row.Operation != "create-queue" && row.Operation != "get-queue-attributes" && row.Operation != "set-queue-attributes" {
								continue
							}
							client = queues
						case "s3api":
							if row.Operation != "create-bucket" && row.Operation != "put-bucket-policy" {
								continue
							}
							client = s3NativeClient(clients, capture.Caller, "test")
						case "cloudtrail":
							if row.Operation != "create-trail" && row.Operation != "put-event-selectors" && row.Operation != "start-logging" {
								continue
							}
							client = organizationTrailClient(clients, capture.Caller, fixture.Region)
						default:
							continue
						}
						out, callErr := awstest.CallSDK(t.Context(), client, row.Operation, normalize(row.Input))
						awsNativeResult(t, row, callErr)
						if row.Service == "sns" {
							requests[row.Result.RequestID] = nativeAuditRequestID(t, out, callErr)
							instants[row.Result.RequestID] = source.Now().UTC().Format(time.RFC3339)
							if callErr != nil {
								var rejected smithy.APIError
								if !errors.As(callErr, &rejected) {
									t.Fatal(callErr)
								}
								diagnostics[row.Result.RequestID] = rejected.ErrorMessage()
							}
						}
						if callErr != nil {
							continue
						}
						switch result := out.(type) {
						case *sqs.CreateQueueOutput:
							var native sqs.CreateQueueOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							replacements = append(replacements, aws.ToString(native.QueueUrl), aws.ToString(result.QueueUrl))
						case *sns.SubscribeOutput:
							var native sns.SubscribeOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							replacements = append(replacements, aws.ToString(native.SubscriptionArn), aws.ToString(result.SubscriptionArn))
						case *sns.PublishOutput:
							var native sns.PublishOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							replacements = append(replacements, aws.ToString(native.MessageId), aws.ToString(result.MessageId))
						case *sns.PublishBatchOutput:
							var native sns.PublishBatchOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							for _, expected := range native.Successful {
								for _, actual := range result.Successful {
									if aws.ToString(expected.Id) == aws.ToString(actual.Id) {
										replacements = append(replacements, aws.ToString(expected.MessageId), aws.ToString(actual.MessageId))
									}
								}
							}
						}
					}
					advanceClock(t, source, 6*time.Minute)
					trailNativeDrain(t, cloud)
					observed := map[string]map[string]map[string]any{}
					for _, account := range fixture.Accounts {
						observed[account] = map[string]map[string]any{}
						trails := organizationTrailClient(clients, account, fixture.Region)
						query := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("sns.amazonaws.com")}}, MaxResults: aws.Int32(50)}
						for {
							page, err := trails.LookupEvents(t.Context(), query)
							if err != nil {
								t.Fatal(err)
							}
							for _, event := range page.Events {
								var document map[string]any
								awsDecodeJSON(t, []byte(aws.ToString(event.CloudTrailEvent)), &document)
								observed[account][document["requestID"].(string)] = document
							}
							if page.NextToken == nil {
								break
							}
							query.NextToken = page.NextToken
						}
						if raw, ok := fixture.Resources[account]; ok {
							var resource struct{ Bucket string }
							awsDecodeJSON(t, raw, &resource)
							for _, document := range trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(clients, account, "test"), resource.Bucket, "")) {
								if document["eventSource"] == "sns.amazonaws.com" {
									observed[account][document["requestID"].(string)] = document
								}
							}
						}
					}
					for _, capture := range fixture.Observations {
						if capture.Caller != "anonymous" || capture.Service != "sns" {
							continue
						}
						for account, events := range observed {
							if events[requests[capture.Result.RequestID]] != nil {
								t.Fatalf("unauthenticated %s appeared in account %s audit", capture.Operation, account)
							}
						}
					}
					shared := map[string]string{}
					eventIDs := map[string]bool{}
					for _, native := range fixture.CloudTrail.Events {
						if !t.Run(native.Account+"/"+native.RequestID, func(t *testing.T) {
							got := observed[native.Account][requests[native.RequestID]]
							if got == nil {
								t.Fatal("native account's history/trail did not receive its SNS event")
							}
							var want map[string]any
							awsDecodeJSON(t, normalize(native.Event), &want)
							// Native request latency crosses wall-clock seconds; the local
							// outcome uses the corresponding deterministic service instant.
							want["eventTime"] = instants[native.RequestID]
							assertNativeAuditEvent(t, got, want, diagnostics[native.RequestID])
							actual, expected := got["userIdentity"].(map[string]any), want["userIdentity"].(map[string]any)
							for _, field := range []string{"type", "principalId", "accountId", "arn", "userName"} {
								if actual[field] != expected[field] {
									t.Fatalf("identity %s: got %v want %v", field, actual[field], expected[field])
								}
							}
							for _, field := range []string{"accessKeyId", "sessionContext"} {
								_, present := actual[field]
								_, nativePresent := expected[field]
								if present != nativePresent {
									t.Fatalf("identity leaked/lost %s: %v", field, actual)
								}
							}
							id := got["eventID"].(string)
							if eventIDs[id] {
								t.Fatal("caller and owner reused an event ID")
							}
							eventIDs[id] = true
							if _, paired := want["sharedEventID"]; paired {
								value, _ := got["sharedEventID"].(string)
								if value == "" || shared[native.RequestID] != "" && shared[native.RequestID] != value {
									t.Fatal("cross-account records lost shared request correlation")
								}
								shared[native.RequestID] = value
							} else if _, paired := got["sharedEventID"]; paired {
								t.Fatal("caller-only operation acquired a shared event ID")
							}
							if want["eventName"] == "GetSubscriptionAttributes" || want["eventName"] == "SetSubscriptionAttributes" || want["eventName"] == "Unsubscribe" || want["eventName"] == "ConfirmSubscription" {
								for _, account := range fixture.Accounts {
									if account != native.Account && observed[account][requests[native.RequestID]] != nil {
										t.Fatal("subscription-owner operation leaked into the other account")
									}
								}
							}
						}) {
							t.FailNow()
						}
					}
				})
			}
		})
	}
}
