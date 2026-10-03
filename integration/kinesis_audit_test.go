package stackd_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type kinesisAuditExpected struct {
	label, message string
	document       map[string]any
	aliases        []trailtypes.Resource
	history        bool
}

func TestKinesisNativeAuditConsumers(t *testing.T) {
	for _, fixture := range []string{"audit_depth", "control_audit"} {
		t.Run(fixture, func(t *testing.T) { replayKinesisAudit(t, fixture) })
	}
}

func replayKinesisAudit(t *testing.T, name string) {
	t.Helper()
	var raw json.RawMessage
	kinesisReadFixture(t, name, &raw)
	var identity struct{ Account string }
	if err := json.Unmarshal(raw, &identity); err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		StartedAt       time.Time
		Calls           []kinesisObservation
		DeliveredEvents []struct{ Event json.RawMessage }
		LookupEvents    []struct {
			Lookup struct {
				Resources       []trailtypes.Resource
				CloudTrailEvent json.RawMessage
			}
		}
	}
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), identity.Account, eventDeliveryAccount)), &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runtime := newKinesisReplayRuntime(t)
			source := clock.NewManual(fixture.StartedAt.Truncate(time.Second))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source, KinesisRuntime: runtime})
			_, key, secret := clients.user(t, eventDeliveryAccount, "Delegated")
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "Delegated", allow(`"*"`, "*"))
			controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
			objects := s3NativeLoad(t, "s3", "owned_object_delivery")
			trailNativeProvision(t, clients, controls, objects, false)
			queue := trailNativeQueue(t, clients)
			if _, err := eventDeliveryClient(clients, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabled,
				EventPattern: aws.String(`{"source":["aws.kinesis"],"detail-type":["AWS API Call via CloudTrail"]}`),
			}); err != nil {
				t.Fatal(err)
			}
			selectors := []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}}}
			for _, kind := range []string{"AWS::Kinesis::Stream", "AWS::Kinesis::StreamConsumer"} {
				selectors = append(selectors, trailtypes.AdvancedEventSelector{FieldSelectors: []trailtypes.AdvancedFieldSelector{
					{Field: aws.String("eventCategory"), Equals: []string{"Data"}},
					{Field: aws.String("resources.type"), Equals: []string{kind}},
					{Field: aws.String("readOnly"), Equals: []string{"true"}},
				}})
			}
			if _, err := trailNativeClient(clients).PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(controls.Identity["trail_name"]), AdvancedEventSelectors: selectors}); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trailNativeClient(clients), controls, "start-logging")
			native := map[string]kinesisAuditExpected{}
			for _, row := range fixture.DeliveredEvents {
				doc := ecsControlBody(t, row.Event)
				native[doc["requestID"].(string)] = kinesisAuditExpected{document: doc}
			}
			for _, row := range fixture.LookupEvents {
				doc := ecsControlBody(t, row.Lookup.CloudTrailEvent)
				id, _ := doc["requestID"].(string)
				entry := native[id]
				if entry.document == nil {
					entry.document = doc
				}
				entry.aliases, entry.history = row.Lookup.Resources, true
				native[id] = entry
			}
			bindings := map[string]string{}
			expected := map[string]kinesisAuditExpected{}
			caller := clients.kinesis(key, secret, "")
			var assumed *kinesis.Client
			for _, row := range fixture.Calls {
				at := row.StartedAt.Truncate(time.Second)
				if at.After(source.Now()) {
					advanceClock(t, source, at.Sub(source.Now()))
				}
				if row.Service == "iam" && (row.Operation == "create-role" || row.Operation == "put-role-policy") {
					if _, err := awstest.CallSDK(t.Context(), clients.iam(eventDeliveryAccount, "test", ""), row.Operation, row.Input); err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
					continue
				}
				if row.Service == "sts" && row.Operation == "assume-role" {
					out, err := awstest.CallSDK(t.Context(), clients.sts(key, secret, ""), row.Operation, row.Input)
					if err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
					credentials := out.(*sts.AssumeRoleOutput).Credentials
					assumed = clients.kinesis(aws.ToString(credentials.AccessKeyId), aws.ToString(credentials.SecretAccessKey), aws.ToString(credentials.SessionToken))
					continue
				}
				var want kinesisAuditExpected
				for _, id := range row.RequestIDs {
					if entry, found := native[id]; found {
						want = entry
						break
					}
				}
				if want.document == nil || row.Service != "kinesis" {
					continue
				}
				operation := want.document["eventName"].(string)
				client := caller
				if actor, _ := want.document["userIdentity"].(map[string]any); actor["type"] == "AssumedRole" {
					if assumed == nil {
						t.Fatalf("%s: native role session was not replayed", row.Label)
					}
					client = assumed
				}
				at = source.Now()
				input := json.RawMessage(aasReplace(string(row.Input), bindings))
				if row.Result.Code == "ResourceNotFoundException" &&
					(operation == "DescribeStream" || operation == "DescribeStreamSummary") {
					var request kinesis.DescribeStreamInput
					if err := json.Unmarshal(input, &request); err != nil {
						t.Fatal(err)
					}
					advanceClock(t, source, time.Second)
					waiter := kinesis.NewStreamNotExistsWaiter(caller, func(options *kinesis.StreamNotExistsWaiterOptions) {
						options.MinDelay, options.MaxDelay = 50*time.Millisecond, 100*time.Millisecond
					})
					if err := waiter.Wait(t.Context(), &request, time.Minute); err != nil {
						t.Fatal(err)
					}
					at = source.Now()
				}
				out, callErr := awstest.CallSDK(t.Context(), client, operation, input)
				if row.Result.Code == "Success" {
					if callErr != nil {
						t.Fatalf("%s: %v", row.Label, callErr)
					}
				} else {
					if !t.Run(row.Label, func(t *testing.T) { assertAPIError(t, callErr, row.Result.Code) }) {
						t.FailNow()
					}
					var rejection smithy.APIError
					if errors.As(callErr, &rejection) {
						want.message = rejection.ErrorMessage()
					}
				}
				if callErr == nil {
					switch result := out.(type) {
					case *kinesis.CreateStreamOutput, *kinesis.UpdateStreamModeOutput, *kinesis.UpdateShardCountOutput,
						*kinesis.SplitShardOutput, *kinesis.MergeShardsOutput, *kinesis.EnableEnhancedMonitoringOutput,
						*kinesis.DisableEnhancedMonitoringOutput, *kinesis.StartStreamEncryptionOutput, *kinesis.StopStreamEncryptionOutput,
						*kinesis.UpdateMaxRecordSizeOutput:
						var request struct{ StreamName, StreamARN string }
						if err := json.Unmarshal(input, &request); err != nil {
							t.Fatal(err)
						}
						if request.StreamName == "" {
							_, request.StreamName, _ = strings.Cut(request.StreamARN, ":stream/")
						}
						awaitKinesisActive(t, source, caller, request.StreamName)
					case *kinesis.RegisterStreamConsumerOutput:
						var original kinesis.RegisterStreamConsumerOutput
						if err := json.Unmarshal(row.Result.Output, &original); err != nil {
							t.Fatal(err)
						}
						bindings[aws.ToString(original.Consumer.ConsumerARN)] = aws.ToString(result.Consumer.ConsumerARN)
						const layout = "Jan 2, 2006, 3:04:05 PM"
						bindings[original.Consumer.ConsumerCreationTimestamp.UTC().Format(layout)] = result.Consumer.ConsumerCreationTimestamp.UTC().Format(layout)
						awaitKinesisConsumerActive(t, source, caller, aws.ToString(result.Consumer.ConsumerARN))
					case *kinesis.GetShardIteratorOutput:
						var original struct{ ShardIterator string }
						if err := json.Unmarshal(row.Result.Output, &original); err != nil {
							t.Fatal(err)
						}
						bindings[original.ShardIterator] = aws.ToString(result.ShardIterator)
					case *kinesis.SubscribeToShardOutput:
						if err := result.GetStream().Close(); err != nil {
							t.Fatal(err)
						}
					}
				}
				want.document = ecsControlBody(t, []byte(aasReplace(mustKinesisJSON(t, want.document), bindings)))
				want.document["eventTime"] = at.UTC().Format(time.RFC3339)
				want.label = row.Label
				expected[nativeAuditRequestID(t, out, callErr)] = want
			}
			if len(expected) == 0 {
				t.Fatal("native fixture has no request-correlated Kinesis calls")
			}
			clients = reopen()
			if _, err := trailNativeClient(clients).StopLogging(t.Context(), &cloudtrail.StopLoggingInput{Name: aws.String(controls.Identity["trail_name"])}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			logs := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(clients, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
			seen := map[string]bool{}
			for _, got := range logs {
				if got["eventSource"] != "kinesis.amazonaws.com" {
					continue
				}
				id, _ := got["requestID"].(string)
				if want, selected := expected[id]; selected {
					t.Run(want.label, func(t *testing.T) { assertNativeAuditEvent(t, got, want.document, want.message) })
					seen[id] = true
				}
			}
			for id, want := range expected {
				if !seen[id] {
					t.Errorf("selected %s absent from S3 delivery", want.label)
				}
			}
			seen = map[string]bool{}
			for _, envelope := range trailQueueMessages(t, clients, queue) {
				got := envelope["detail"].(map[string]any)
				if got["eventSource"] != "kinesis.amazonaws.com" {
					continue
				}
				id, _ := got["requestID"].(string)
				if want, selected := expected[id]; selected {
					if want.document["eventCategory"] == "Management" && want.document["readOnly"] == true {
						t.Errorf("ENABLED rule admitted read-only management %s", want.label)
					}
					t.Run("eventbridge/"+want.label, func(t *testing.T) { assertNativeAuditEvent(t, got, want.document, want.message) })
					seen[id] = true
				}
			}
			for id, want := range expected {
				if (want.document["eventCategory"] == "Data" || want.document["readOnly"] == false) && !seen[id] {
					t.Errorf("eligible %s absent from EventBridge delivery", want.label)
				}
			}
			seen = map[string]bool{}
			pages := cloudtrail.NewLookupEventsPaginator(trailNativeClient(clients), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("kinesis.amazonaws.com")}}})
			for pages.HasMorePages() {
				page, err := pages.NextPage(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range page.Events {
					got := ecsControlBody(t, []byte(aws.ToString(event.CloudTrailEvent)))
					if got["eventCategory"] != "Management" {
						t.Fatal("data event escaped into management history")
					}
					id, _ := got["requestID"].(string)
					if want, selected := expected[id]; selected {
						t.Run("history/"+want.label, func(t *testing.T) { assertNativeAuditEvent(t, got, want.document, want.message) })
						if want.history && !slices.EqualFunc(event.Resources, want.aliases, func(a, b trailtypes.Resource) bool {
							return aws.ToString(a.ResourceName) == aasReplace(aws.ToString(b.ResourceName), bindings) && aws.ToString(a.ResourceType) == aws.ToString(b.ResourceType)
						}) {
							t.Errorf("%s lookup aliases: got %+v; native %+v", want.label, event.Resources, want.aliases)
						}
						seen[id] = true
					}
				}
			}
			for id, want := range expected {
				if want.document["eventCategory"] == "Management" && !seen[id] {
					t.Errorf("%s absent from management history", want.label)
				}
			}
		})
	}
}
