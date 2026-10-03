package stackd_test

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"reflect"
	"slices"
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

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// Replay native sampling/query/daemon captures in request order, including
// its IAM sessions and unlogged prerequisites. Only exact request-ID matches
// are audit oracles; absence from a bounded AWS delivery window is not exclusion.
func TestXRayNativeConsumerAuditDelivery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var rows []xrayNativeObservation
			native := map[string]map[string]any{}
			for _, name := range []string{"sampling", "trace_queries", "telemetry"} {
				var raw json.RawMessage
				awsReadFixture(t, "xray/"+name+".json", &raw)
				var identity struct {
					Account    string `json:"caller_account"`
					Identities []struct{ Account string }
				}
				awsDecodeJSON(t, raw, &identity)
				account := identity.Account
				if account == "" {
					account = identity.Identities[0].Account
				}
				raw = json.RawMessage(strings.ReplaceAll(string(raw), account, eventDeliveryAccount))
				var fixture struct {
					xrayNativeStream
					Audit struct {
						XRayEvents    []map[string]any                 `json:"xray_events"`
						MatchedEvents []struct{ Event map[string]any } `json:"matched_events"`
					}
				}
				awsDecodeJSON(t, raw, &fixture)
				rows = append(rows, fixture.Observations...)
				rows = append(rows, fixture.Cleanup...)
				for _, event := range fixture.Audit.XRayEvents {
					native[event["requestID"].(string)] = event
				}
				for _, event := range fixture.Audit.MatchedEvents {
					native[event.Event["requestID"].(string)] = event.Event
				}
			}
			slices.SortStableFunc(rows, func(a, b xrayNativeObservation) int { return cmp.Compare(a.Started, b.Started) })
			source := clock.NewManual(time.UnixMilli(rows[0].Started).UTC())
			var cloud *stackd.Stack
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			const region = "us-west-2"
			_, user, _ := strings.Cut(rows[0].ActorARN, ":user/")
			arn, key, secret := clients.user(t, eventDeliveryAccount, user)
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
			actor, err := clients.sts(key, secret, "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
			if err != nil {
				t.Fatal(err)
			}
			identities := map[string]aws.Credentials{arn: {AccessKeyID: key, SecretAccessKey: secret}}
			principalIDs := map[string]string{arn: aws.ToString(actor.UserId)}
			sessionDates := map[string]string{}

			trails := organizationTrailClient(clients, eventDeliveryAccount, region)
			bucketOptions := s3NativeClient(clients, eventDeliveryAccount, "test").Options()
			bucketOptions.Region = region
			buckets := s3.New(bucketOptions)
			var selection cloudtrail.PutEventSelectorsInput
			var bucket string
			for _, row := range rows {
				var client any
				switch row.Label {
				case "create-audit-bucket":
					client = buckets
					var input s3.CreateBucketInput
					awsDecodeJSON(t, row.Input, &input)
					bucket = aws.ToString(input.Bucket)
				case "audit-bucket-policy":
					client = buckets
				case "create-audit-trail":
					client = trails
				case "audit-selectors-supported":
					awsDecodeJSON(t, row.Input, &selection)
					continue
				default:
					continue
				}
				_, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
				awsNativeResult(t, row.awsNativeObservation, err)
			}
			if bucket == "" || len(selection.AdvancedEventSelectors) != 2 {
				t.Fatal("native management/trace data setup missing")
			}
			setSelectors := func(selectors []trailtypes.AdvancedEventSelector) {
				t.Helper()
				if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: selection.TrailName, AdvancedEventSelectors: selectors}); err != nil {
					t.Fatal(err)
				}
			}
			selected := selection.AdvancedEventSelectors
			excluded := []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}}, {Field: aws.String("resources.type"), Equals: []string{"AWS::SNS::Topic"}}}}}
			setSelectors(selected)
			selectors, err := trails.GetEventSelectors(t.Context(), &cloudtrail.GetEventSelectorsInput{TrailName: selection.TrailName})
			if err != nil || !reflect.DeepEqual(selectors.AdvancedEventSelectors, selected) {
				t.Fatalf("configured native selectors: %+v %v", selectors, err)
			}
			if _, err := trails.StartLogging(t.Context(), &cloudtrail.StartLoggingInput{Name: selection.TrailName}); err != nil {
				t.Fatal(err)
			}

			eventOptions := eventDeliveryClient(clients, eventDeliveryAccount).Options()
			eventOptions.Region = region
			events := eventbridge.New(eventOptions)
			queueOptions := clients.sqs(eventDeliveryAccount, "test", "").Options()
			queueOptions.Region = region
			queues := sqs.New(queueOptions)
			queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("native-xray-consumers")})
			if err != nil {
				t.Fatal(err)
			}
			rule, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("native-xray-consumers"), State: eventtypes.RuleStateEnabledWithAllCloudtrailManagementEvents, EventPattern: aws.String(`{"source":["aws.xray"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["xray.amazonaws.com"]}}`)})
			if err != nil {
				t.Fatal(err)
			}
			queueARN := "arn:aws:sqs:" + region + ":" + eventDeliveryAccount + ":native-xray-consumers"
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, queueARN, aws.ToString(rule.RuleArn))
			if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
				t.Fatal(err)
			}
			if out, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("native-xray-consumers"), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: &queueARN}}}); err != nil || out.FailedEntryCount != 0 {
				t.Fatalf("X-Ray audit target: %+v %v", out, err)
			}

			expected, diagnostics := map[string]map[string]any{}, map[string]string{}
			groupARNs := map[string]string{}
			ruleTimes := map[string][2]string{}
			checkedSelectors := map[string]bool{}
			replayed := map[string]bool{}
			for _, row := range rows {
				if row.Service != "xray" && row.Service != "iam" && row.Service != "sts" || row.Operation == "get-caller-identity" {
					continue
				}
				switch row.Label {
				case "assume-owned-role-0", "assume-owned-role-1":
					continue // Native trust-policy propagation; the same request succeeds later.
				case "service-graph-deleted-group":
					// This early successful read was deletion propagation; converged
					// native group windows reject the ARN (aggregate capture 6).
					continue
				case "destination-isolated":
					continue // Destination management is outside the classic consumer surface.
				case "completion-summaries-poll-0", "completion-summaries-poll-1":
					// Their saved input EndTime is 10:36:04, but the exact correlated audit
					// request used 10:34:23. Do not silently replace either native oracle.
					continue
				}
				// The query fixture copies shared audit cleanup. Never repeat a native call.
				if replayed[row.Result.RequestID] && row.Result.RequestID != "" {
					continue
				}
				replayed[row.Result.RequestID] = true
				if !t.Run(row.Label, func(t *testing.T) {
					if delta := time.UnixMilli(row.Started).Sub(source.Now()); delta > 0 {
						advanceClock(t, source, delta)
					}
					identity, ok := identities[row.ActorARN]
					if !ok {
						t.Fatalf("unreplayed actor %s", row.ActorARN)
					}
					if row.Service != "xray" {
						setSelectors(excluded)
						var client any = clients.iam(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
						if row.Service == "sts" {
							client = clients.sts(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
						}
						out, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
						awsNativeResult(t, row.awsNativeObservation, err)
						if session, ok := out.(*sts.AssumeRoleOutput); ok && err == nil {
							sessionARN := aws.ToString(session.AssumedRoleUser.Arn)
							identities[sessionARN] = aws.Credentials{AccessKeyID: aws.ToString(session.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(session.Credentials.SecretAccessKey), SessionToken: aws.ToString(session.Credentials.SessionToken)}
							principalIDs[sessionARN] = aws.ToString(session.AssumedRoleUser.AssumedRoleId)
							sessionDates[sessionARN] = source.Now().UTC().Format(time.RFC3339)
						}
						return
					}
					input := string(row.Input)
					for original, local := range groupARNs {
						input = strings.ReplaceAll(input, original, local)
					}
					wire := &awstest.WireClient{Client: clients.server.Client()}
					options := clients.xrayRegion(region, identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken).Options()
					options.HTTPClient = wire
					options.APIOptions = append(options.APIOptions, awstest.JSONBody(json.RawMessage(input)))
					client := xray.New(options)
					// The generated SDK still signs and decodes every call. Only its local
					// required-field gate is bypassed to send the exact native request body.
					seed := json.RawMessage(`{"SamplingRule":{"Priority":1,"FixedRate":0,"ReservoirSize":0,"Host":"*","HTTPMethod":"*","ResourceARN":"*","ServiceName":"*","ServiceType":"*","URLPath":"*","Version":1},"SamplingRuleUpdate":{},"SamplingStatisticsDocuments":[],"TelemetryRecords":[],"TraceSegmentDocuments":[],"TraceIds":[],"StartTime":"2026-09-23T00:00:00Z","EndTime":"2026-09-23T00:01:00Z","GroupName":"request","ResourceARN":"request","Tags":[],"TagKeys":[]}`)
					want := native[row.Result.RequestID]
					if want == nil {
						setSelectors(excluded)
					} else {
						if want["eventCategory"] == "Data" && !checkedSelectors[row.Operation] {
							checkedSelectors[row.Operation] = true
							oppositeReadOnly := "true"
							if want["readOnly"] == true {
								oppositeReadOnly = "false"
							}
							for _, selectors := range [][]trailtypes.AdvancedEventSelector{
								{selected[0]}, excluded,
								{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}}, {Field: aws.String("resources.type"), Equals: []string{"AWS::XRay::Trace"}}, {Field: aws.String("readOnly"), Equals: []string{oppositeReadOnly}}}}},
							} {
								setSelectors(selectors)
								_, err := awstest.CallSDK(t.Context(), client, row.Operation, seed)
								awsNativeResult(t, row.awsNativeObservation, err)
								trailNativeDrain(t, cloud)
							}
						}
						setSelectors(selected)
					}
					out, err := awstest.CallSDK(t.Context(), client, row.Operation, seed)
					awsNativeResult(t, row.awsNativeObservation, err)
					id := nativeAuditRequestID(t, out, err)
					if err == nil && row.Operation == "create-group" {
						var actual, original struct{ Group struct{ GroupARN string } }
						awsDecodeJSON(t, wire.Body, &actual)
						awsDecodeJSON(t, row.Result.Output, &original)
						if actual.Group.GroupARN == "" || original.Group.GroupARN == "" {
							t.Fatal("created group lost its identity")
						}
						groupARNs[original.Group.GroupARN] = actual.Group.GroupARN
					}
					if err == nil && (row.Operation == "create-sampling-rule" || row.Operation == "update-sampling-rule") {
						var response struct {
							SamplingRuleRecord struct{ SamplingRule struct{ RuleARN string } }
						}
						awsDecodeJSON(t, wire.Body, &response)
						ruleARN := response.SamplingRuleRecord.SamplingRule.RuleARN
						times := ruleTimes[ruleARN]
						if row.Operation == "create-sampling-rule" {
							times[0] = source.Now().UTC().Format(time.RFC3339)
						}
						times[1] = source.Now().UTC().Format(time.RFC3339)
						ruleTimes[ruleARN] = times
					}
					if want != nil {
						encoded, marshalErr := json.Marshal(want)
						if marshalErr != nil {
							t.Fatal(marshalErr)
						}
						text := string(encoded)
						for original, local := range groupARNs {
							text = strings.ReplaceAll(text, original, local)
						}
						awsDecodeJSON(t, []byte(text), &want)
						want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
						identityDocument := want["userIdentity"].(map[string]any)
						identityDocument["principalId"] = principalIDs[row.ActorARN]
						identityDocument["accessKeyId"] = identity.AccessKeyID
						if session, ok := identityDocument["sessionContext"].(map[string]any); ok {
							roleID, _, _ := strings.Cut(principalIDs[row.ActorARN], ":")
							session["sessionIssuer"].(map[string]any)["principalId"] = roleID
							session["attributes"].(map[string]any)["creationDate"] = sessionDates[row.ActorARN]
						}
						if record, ok := awsFixtureField(want, "responseElements.samplingRuleRecord").(map[string]any); ok {
							times := ruleTimes[awsFixtureField(record, "samplingRule.ruleARN").(string)]
							if times[0] == "" || times[1] == "" {
								t.Fatal("audit sampling response has no replayed creation/update")
							}
							record["createdAt"], record["modifiedAt"] = times[0], times[1]
						}
						if err != nil {
							var apiError smithy.APIError
							if !errors.As(err, &apiError) {
								t.Fatal(err)
							}
							diagnostics[id] = apiError.ErrorMessage()
						}
						expected[id] = want
					}
					trailNativeDrain(t, cloud)
				}) {
					t.FailNow()
				}
			}
			if len(expected) == 0 {
				t.Fatal("no request-correlated native consumer events replayed")
			}
			setSelectors(selected)
			// Restart before the final delivery window. Rules, target authorization,
			// selectors, queued SQS messages and pending S3 delivery must all survive.
			clients = reopen()
			trails = organizationTrailClient(clients, eventDeliveryAccount, region)
			bucketOptions = s3NativeClient(clients, eventDeliveryAccount, "test").Options()
			bucketOptions.Region = region
			buckets = s3.New(bucketOptions)
			queueOptions = clients.sqs(eventDeliveryAccount, "test", "").Options()
			queueOptions.Region = region
			queues = sqs.New(queueOptions)
			retainedQueue, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("native-xray-consumers")})
			if err != nil {
				t.Fatal(err)
			}
			queue.QueueUrl = retainedQueue.QueueUrl
			selectors, err = trails.GetEventSelectors(t.Context(), &cloudtrail.GetEventSelectorsInput{TrailName: selection.TrailName})
			if err != nil || !reflect.DeepEqual(selectors.AdvancedEventSelectors, selected) {
				t.Fatalf("retained native selectors: %+v %v", selectors, err)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			delivered := map[string]map[string]any{}
			eventIDs := map[string]bool{}
			for _, got := range trailNativeRecords(t, trailNativeObjects(t, buckets, bucket, "AWSLogs/")) {
				if got["eventSource"] != "xray.amazonaws.com" {
					continue
				}
				id, _ := got["requestID"].(string)
				want := expected[id]
				if want == nil || delivered[id] != nil {
					t.Fatalf("unselected, unexpected or duplicate X-Ray event: %#v", got)
				}
				assertNativeAuditEvent(t, got, want, diagnostics[id])
				if !reflect.DeepEqual(got["userIdentity"], want["userIdentity"]) {
					t.Fatalf("X-Ray actor changed: got %#v, native %#v", got["userIdentity"], want["userIdentity"])
				}
				address, _ := got["sourceIPAddress"].(string)
				agent, _ := got["userAgent"].(string)
				if !net.ParseIP(address).IsLoopback() || !strings.Contains(agent, "aws-sdk-go-v2") {
					t.Fatalf("X-Ray audit lost actual request context: %#v", got)
				}
				if _, present := got["tlsDetails"]; present {
					t.Fatalf("HTTP replay fabricated TLS context: %#v", got)
				}
				eventID, _ := got["eventID"].(string)
				if eventID == "" || eventIDs[eventID] {
					t.Fatalf("X-Ray event lost unique correlation: %#v", got)
				}
				eventIDs[eventID] = true
				delivered[id] = got
			}
			if len(delivered) != len(expected) {
				t.Fatalf("retained S3 trail delivered %d of %d selected X-Ray outcomes", len(delivered), len(expected))
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
					t.Fatalf("retained EventBridge/SQS diverged from selected X-Ray trail: %#v", event)
				}
				delete(delivered, id)
			}
			if len(delivered) != 0 {
				t.Fatalf("EventBridge/SQS missed selected X-Ray outcomes: %#v", delivered)
			}
		})
	}
}
