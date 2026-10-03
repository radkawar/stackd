package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type xrayAuditCapture struct {
	Region, Bucket string
	TrailARN       string `json:"trail_arn"`
	Observations   []awsNativeObservation
	Events         []struct {
		Label string `json:"observation_label"`
		Event map[string]any
	}
}

func TestXRayNativeAuditConsumers(t *testing.T) {
	var raw json.RawMessage
	awsReadFixture(t, "xray/segments_and_policies.json", &raw)
	var identity struct {
		Identities []struct{ Account, Arn string }
	}
	awsDecodeJSON(t, raw, &identity)
	raw = json.RawMessage(strings.ReplaceAll(string(raw), identity.Identities[0].Account, eventDeliveryAccount))
	for _, backend := range []string{"memory", "sqlite"} {
		for _, region := range []string{"us-east-1", "us-west-2"} {
			t.Run(backend+"/"+region, func(t *testing.T) {
				var fixture struct {
					Observations, Cleanup []awsNativeObservation
					Audit                 xrayAuditCapture
					WestAudit             xrayAuditCapture `json:"west_audit"`
				}
				awsDecodeJSON(t, raw, &fixture)
				capture, rows := fixture.Audit, append(fixture.Observations, fixture.Cleanup...)
				if region == "us-west-2" {
					capture, rows = fixture.WestAudit, fixture.WestAudit.Observations
				}
				native := map[string]map[string]any{}
				for _, event := range capture.Events {
					// East's active CloudWatchLogs destination is not an oracle for
					// classic-XRay ingestion. Keep its management capture and the
					// destination-independent request rejections/read projections.
					if region == "us-east-1" && event.Event["eventCategory"] == "Data" {
						switch event.Label {
						case "empty-document-list", "batch-get-duplicate-ids", "batch-get-six-ids", "batch-get-empty-ids", "batch-get-malformed-id-with-valid-sibling", "batch-get-arbitrary-next-token":
						default:
							continue
						}
					}
					native[event.Label] = event.Event
				}
				var replay []awsNativeObservation
				for _, row := range rows {
					if native[row.Label] != nil {
						replay = append(replay, row)
					}
				}
				if len(replay) != len(native) || len(replay) == 0 {
					t.Fatalf("native audit events lost their request observations: %d rows, %d events", len(replay), len(native))
				}
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "xray-audit.sqlite"))
				}
				source := clock.NewManual(time.UnixMilli(replay[0].Started).UTC())
				cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
				_, user, _ := strings.Cut(identity.Identities[0].Arn, ":user/")
				_, key, secret := clients.user(t, eventDeliveryAccount, user)
				putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
				actor, err := clients.sts(key, secret, "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
				if err != nil {
					t.Fatal(err)
				}
				trails := organizationTrailClient(clients, eventDeliveryAccount, region)
				bucketOptions := s3NativeClient(clients, eventDeliveryAccount, "test").Options()
				bucketOptions.Region = region
				buckets := s3.New(bucketOptions)
				var selection cloudtrail.PutEventSelectorsInput
				for _, row := range capture.Observations {
					var client any
					switch row.Operation {
					case "create-bucket", "put-bucket-policy":
						client = buckets
					case "create-trail":
						client = trails
					case "put-event-selectors":
						awsDecodeJSON(t, row.Input, &selection)
						continue
					default:
						continue
					}
					_, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
					awsNativeResult(t, row, err)
				}
				if len(selection.AdvancedEventSelectors) != 1 {
					t.Fatal("native X-Ray data selector missing")
				}
				management := trailtypes.AdvancedEventSelector{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}}
				selected := append([]trailtypes.AdvancedEventSelector{management}, selection.AdvancedEventSelectors...)
				setSelectors := func(selectors []trailtypes.AdvancedEventSelector) {
					t.Helper()
					if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: &capture.TrailARN, AdvancedEventSelectors: selectors}); err != nil {
						t.Fatal(err)
					}
				}
				setSelectors(selected)
				if _, err := trails.StartLogging(t.Context(), &cloudtrail.StartLoggingInput{Name: &capture.TrailARN}); err != nil {
					t.Fatal(err)
				}

				// Use the configured EventBridge-to-SQS path in the capture's
				// region, with the same target authority as trailNativeQueue.
				eventOptions := eventDeliveryClient(clients, eventDeliveryAccount).Options()
				eventOptions.Region = region
				events := eventbridge.New(eventOptions)
				queueOptions := clients.sqs(eventDeliveryAccount, "test", "").Options()
				queueOptions.Region = region
				queues := sqs.New(queueOptions)
				queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("native-cloudtrail")})
				if err != nil {
					t.Fatal(err)
				}
				rule, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{
					Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabledWithAllCloudtrailManagementEvents,
					EventPattern: aws.String(`{"source":["aws.xray"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["xray.amazonaws.com"]}}`),
				})
				if err != nil {
					t.Fatal(err)
				}
				queueARN := "arn:aws:sqs:" + region + ":" + eventDeliveryAccount + ":native-cloudtrail"
				policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, queueARN, aws.ToString(rule.RuleArn))
				if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
					t.Fatal(err)
				}
				if out, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("native-cloudtrail"), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: &queueARN}}}); err != nil || out.FailedEntryCount != 0 {
					t.Fatalf("X-Ray audit target: %+v %v", out, err)
				}

				expected, diagnostics := map[string]map[string]any{}, map[string]string{}
				wire := &awstest.WireClient{Client: clients.server.Client()}
				for _, row := range replay {
					if !t.Run(row.Label, func(t *testing.T) {
						if delta := time.UnixMilli(row.Started).Sub(source.Now()); delta > 0 {
							advanceClock(t, source, delta)
						}
						want := native[row.Label]
						options := clients.xrayRegion(region, key, secret, "").Options()
						options.HTTPClient = wire
						options.APIOptions = append(options.APIOptions, awstest.JSONBody(row.Input))
						client := xray.New(options)
						// SDK-only required members cannot prevent sending the native
						// empty/malformed body through signing and service validation.
						input := json.RawMessage(`{"TraceSegmentDocuments":[],"TraceIds":[],"PolicyName":"request","PolicyDocument":"{}"}`)
						if want["eventCategory"] == "Data" {
							// Admission still runs while disabled. None of these request
							// IDs may later appear in S3 or the EventBridge consumer.
							opposite := "true"
							if want["readOnly"] == true {
								opposite = "false"
							}
							for _, selectors := range [][]trailtypes.AdvancedEventSelector{
								{management},
								{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}}, {Field: aws.String("resources.type"), Equals: []string{"AWS::SNS::Topic"}}}}},
								{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}}, {Field: aws.String("resources.type"), Equals: []string{"AWS::XRay::Trace"}}, {Field: aws.String("readOnly"), Equals: []string{opposite}}}}},
							} {
								setSelectors(selectors)
								_, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
								awsNativeResult(t, row, err)
								trailNativeDrain(t, cloud)
							}
							setSelectors(selected)
						}
						out, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
						awsNativeResult(t, row, err)
						id := nativeAuditRequestID(t, out, err)
						if err != nil {
							var apiError smithy.APIError
							if !errors.As(err, &apiError) {
								t.Fatal(err)
							}
							diagnostics[id] = apiError.ErrorMessage()
						}
						want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
						want["userIdentity"].(map[string]any)["principalId"] = aws.ToString(actor.UserId)
						// Both native captures explicitly redact accessKeyId.
						want["userIdentity"].(map[string]any)["accessKeyId"] = key
						if response, ok := want["responseElements"].(map[string]any); ok {
							if policy, ok := response["resourcePolicy"].(map[string]any); ok {
								policy["lastUpdatedTime"] = source.Now().UTC().Format(time.RFC3339)
							}
							if rejected, ok := response["unprocessedTraceSegments"].([]any); ok {
								var result struct{ UnprocessedTraceSegments []struct{ Message string } }
								awsDecodeJSON(t, wire.Body, &result)
								if len(result.UnprocessedTraceSegments) != len(rejected) {
									t.Fatalf("mixed admission changed rejected siblings: %s", wire.Body)
								}
								for i, value := range rejected {
									// Keep native error codes, IDs and presence, not parser prose.
									value.(map[string]any)["message"] = result.UnprocessedTraceSegments[i].Message
								}
							}
						}
						expected[id] = want
						trailNativeDrain(t, cloud)
					}) {
						t.FailNow()
					}
				}
				advanceClock(t, source, 6*time.Minute)
				trailNativeDrain(t, cloud)
				delivered := map[string]map[string]any{}
				eventIDs := map[string]bool{}
				for _, got := range trailNativeRecords(t, trailNativeObjects(t, buckets, capture.Bucket, "AWSLogs/")) {
					if got["eventSource"] != "xray.amazonaws.com" {
						continue
					}
					id, _ := got["requestID"].(string)
					want := expected[id]
					if want == nil || delivered[id] != nil {
						t.Fatalf("unselected, unexpected or duplicate X-Ray trail outcome: %#v", got)
					}
					if nativePolicy, ok := awsFixtureField(want, "responseElements.resourcePolicy.policyDocument").(string); ok {
						actualPolicy, ok := awsFixtureField(got, "responseElements.resourcePolicy.policyDocument").(string)
						if !ok {
							t.Fatal("resource policy document must remain a JSON string")
						}
						var actualDocument, nativeDocument any
						awsDecodeJSON(t, []byte(actualPolicy), &actualDocument)
						awsDecodeJSON(t, []byte(nativePolicy), &nativeDocument)
						if !reflect.DeepEqual(actualDocument, nativeDocument) {
							t.Fatalf("resource policy content changed: local %s, native %s", actualPolicy, nativePolicy)
						}
						// JSON object ordering is not policy semantics. Preserve the
						// actual string so EventBridge still matches the S3 event exactly.
						awsFixtureField(want, "responseElements.resourcePolicy").(map[string]any)["policyDocument"] = actualPolicy
					}
					assertNativeAuditEvent(t, got, want, diagnostics[id])
					if !reflect.DeepEqual(got["userIdentity"], want["userIdentity"]) {
						t.Fatalf("X-Ray actor changed: got %#v, native %#v", got["userIdentity"], want["userIdentity"])
					}
					// The fixture used TLS from a public host and Python; replay
					// uses real loopback HTTP and Go SDK context, not those literals.
					address, _ := got["sourceIPAddress"].(string)
					agent, _ := got["userAgent"].(string)
					if !net.ParseIP(address).IsLoopback() || !strings.Contains(agent, "aws-sdk-go-v2") {
						t.Fatalf("X-Ray audit lost actual request context: %#v", got)
					}
					if _, present := got["tlsDetails"]; present {
						t.Fatalf("HTTP replay fabricated TLS context: %#v", got["tlsDetails"])
					}
					eventID, _ := got["eventID"].(string)
					if eventID == "" || eventIDs[eventID] {
						t.Fatalf("X-Ray event lost unique correlation: %#v", got)
					}
					eventIDs[eventID] = true
					delivered[id] = got
				}
				if len(delivered) != len(expected) {
					t.Fatalf("S3 trail delivered %d of %d selected X-Ray outcomes", len(delivered), len(expected))
				}
				for _, message := range snsAdmissionReceive(t, cloud, queues, queue.QueueUrl) {
					var event struct {
						Source, Account, Region string
						DetailType              string `json:"detail-type"`
						Detail                  map[string]any
					}
					awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &event)
					id, _ := event.Detail["requestID"].(string)
					if event.Source != "aws.xray" || event.Account != eventDeliveryAccount || event.Region != region || event.DetailType != "AWS API Call via CloudTrail" || delivered[id] == nil || !reflect.DeepEqual(event.Detail, delivered[id]) {
						t.Fatalf("EventBridge/SQS diverged from the selected X-Ray trail: %#v", event)
					}
					delete(delivered, id)
				}
				if len(delivered) != 0 {
					t.Fatalf("EventBridge/SQS missed selected X-Ray outcomes: %#v", delivered)
				}
			})
		}
	}
}
