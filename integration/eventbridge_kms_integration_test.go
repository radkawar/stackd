package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/storage"
)

type eventDeliveryKMSCase struct {
	eventDeliveryCase
	Phase     string `json:"phase"`
	Rule      string `json:"rule"`
	Target    string `json:"target"`
	TargetARN string `json:"target_arn"`
}

type eventDeliveryKMSFixture struct {
	KeyPolicy json.RawMessage `json:"key_policy"`
	Rules     map[string]struct {
		Name string `json:"name"`
		ARN  string `json:"arn"`
	} `json:"rules"`
	Queues map[string]struct {
		ARN        string            `json:"arn"`
		Attributes map[string]string `json:"attributes"`
	} `json:"queues"`
	Observations []eventDeliveryKMSCase `json:"observations"`
}

func provisionKMSEventDelivery(t *testing.T, c cloudClients, fixture eventDeliveryKMSFixture) map[string]*string {
	t.Helper()
	queues := c.sqs(eventDeliveryAccount, "test", "")
	kinds := slices.Sorted(maps.Keys(fixture.Queues))
	urls := make(map[string]*string)
	for _, kind := range kinds {
		out, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(eventDeliveryName + "-" + kind)})
		if err != nil {
			t.Fatal(err)
		}
		urls[kind] = out.QueueUrl
	}
	events := eventDeliveryClient(c, eventDeliveryAccount)
	bus, err := events.CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: aws.String(eventDeliveryName)})
	if err != nil || aws.ToString(bus.EventBusArn) != eventDeliveryBusARN {
		t.Fatal("create encrypted delivery bus", bus, err)
	}
	var ruleARNs []string
	for _, name := range slices.Sorted(maps.Keys(fixture.Rules)) {
		rule := fixture.Rules[name]
		created, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: &rule.Name, EventBusName: aws.String(eventDeliveryName),
			EventPattern: aws.String(fmt.Sprintf(`{"source":[%q],"detail":{"rule":[%q]}}`, eventDeliveryName, name))})
		if err != nil || aws.ToString(created.RuleArn) != rule.ARN {
			t.Fatal("create encrypted delivery rule", created, err)
		}
		ruleARNs = append(ruleARNs, rule.ARN)
	}
	// One unchanged native key policy distinguishes the five queue encryption
	// contexts. Both rules may send to every queue; only KMS restricts cold sends.
	key, err := c.kms(eventDeliveryAccount, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{Policy: aws.String(string(fixture.KeyPolicy))})
	if err != nil {
		t.Fatal("create native KMS policy", err)
	}
	sources, err := json.Marshal(map[string][]string{"aws:SourceArn": ruleARNs})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range kinds {
		setEventDeliveryPolicy(t, queues, urls[kind], kind, map[string]json.RawMessage{"ArnEquals": sources})
		want := maps.Clone(fixture.Queues[kind].Attributes)
		if want["KmsMasterKeyId"] != "" {
			want["KmsMasterKeyId"] = aws.ToString(key.KeyMetadata.Arn)
			if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: urls[kind], Attributes: map[string]string{
				"KmsMasterKeyId": want["KmsMasterKeyId"], "KmsDataKeyReusePeriodSeconds": want["KmsDataKeyReusePeriodSeconds"],
			}}); err != nil {
				t.Fatal("configure native queue encryption", err)
			}
		}
		var names []sqstypes.QueueAttributeName
		for _, name := range slices.Sorted(maps.Keys(want)) {
			names = append(names, sqstypes.QueueAttributeName(name))
		}
		out, err := queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: urls[kind], AttributeNames: names})
		if err != nil || !maps.Equal(out.Attributes, want) {
			t.Fatal("queue encryption attributes differ from native fixture", out, want, err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(fixture.Rules)) {
		var targets []eventtypes.Target
		for _, kind := range kinds {
			if kind != "dlq" {
				targets = append(targets, eventtypes.Target{Id: aws.String(kind), Arn: aws.String(fixture.Queues[kind].ARN),
					DeadLetterConfig: &eventtypes.DeadLetterConfig{Arn: aws.String(fixture.Queues["dlq"].ARN)},
					RetryPolicy:      &eventtypes.RetryPolicy{MaximumRetryAttempts: aws.Int32(0), MaximumEventAgeInSeconds: aws.Int32(60)}})
			}
		}
		out, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(fixture.Rules[name].Name), EventBusName: aws.String(eventDeliveryName), Targets: targets})
		if err != nil || out.FailedEntryCount != 0 || len(out.FailedEntries) != 0 {
			t.Fatal("register encrypted delivery targets", out, err)
		}
	}
	return urls
}

func TestEventBridgeSQSKMSNativeDeliveryAndServiceKeyReuse(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "eventbridge", "kms_delivery.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture eventDeliveryKMSFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Observations) == 0 {
		t.Fatal("native encrypted delivery fixture has no observations")
	}
	var phases []string
	observations := make(map[string][]eventDeliveryKMSCase)
	for _, row := range fixture.Observations {
		if len(observations[row.Phase]) == 0 {
			phases = append(phases, row.Phase)
		}
		observations[row.Phase] = append(observations[row.Phase], row)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "encrypted-delivery.sqlite"))
			}
			epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
			cloud, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(epoch))
			urls := provisionKMSEventDelivery(t, c, fixture)
			queues := c.sqs(eventDeliveryAccount, "test", "")
			// Preserve capture order and the same queues/key cache across phases:
			// cold B is denied by A's SourceArn grant; A warms the service cache,
			// then B can reuse it without another cold KMS authorization.
			for _, phase := range phases {
				t.Run(phase, func(t *testing.T) {
					cases := observations[phase]
					detail := map[string]any{"case": phase, "rule": cases[0].Rule, "private": eventDeliverySecret}
					id, requestID := putDeliveryEvent(t, c, detail, epoch.Add(-time.Hour))
					drain, err := cloud.RunDueJobs(t.Context(), 20)
					if err != nil || drain.More {
						t.Fatal("encrypted deliveries did not finish", drain, err)
					}
					type outcome struct {
						kind    string
						message sqstypes.Message
					}
					outcomes := make(map[string]outcome)
					messageQueues := make(map[string]string)
					for _, kind := range slices.Sorted(maps.Keys(urls)) {
						out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: urls[kind], MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
						if err != nil {
							t.Fatal("receive encrypted delivery", kind, err)
						}
						for _, message := range out.Messages {
							assertEventDeliveryEnvelope(t, aws.ToString(message.Body), id, detail, epoch)
							queueARN := fixture.Queues[kind].ARN
							targetARN := queueARN
							if kind == "dlq" {
								targetARN = aws.ToString(message.MessageAttributes["TARGET_ARN"].StringValue)
							}
							if _, duplicate := outcomes[targetARN]; duplicate {
								t.Fatal("target delivered more than once", targetARN)
							}
							outcomes[targetARN] = outcome{kind: kind, message: message}
							messageQueues[aws.ToString(message.MessageId)] = queueARN
							if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: urls[kind], ReceiptHandle: message.ReceiptHandle}); err != nil {
								t.Fatal(err)
							}
						}
					}
					if len(outcomes) != len(cases) {
						t.Fatalf("received %d outcomes, expected %d: %+v", len(outcomes), len(cases), outcomes)
					}
					for _, tc := range cases {
						t.Run(tc.Target, func(t *testing.T) {
							got, ok := outcomes[tc.TargetARN]
							kind := tc.Target
							if tc.Delivery == "dlq" {
								kind = "dlq"
							}
							if !ok || got.kind != kind {
								t.Fatalf("native delivery differs: got %s, want %s; %s: %s", got.kind, kind, aws.ToString(got.message.MessageAttributes["ERROR_CODE"].StringValue), aws.ToString(got.message.MessageAttributes["ERROR_MESSAGE"].StringValue))
							}
							assertEventDeliveryAttributes(t, got.message.MessageAttributes, tc.Attributes, "events.amazonaws.com", "kms:GenerateDataKey")
						})
					}
					assertEventDeliveryJournal(t, cloud, id, requestID, epoch, messageQueues)
				})
			}
		})
	}
}

func TestEventBridgeArchiveNativeKeys(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/archive_keys.json")
	if err != nil {
		t.Fatal(err)
	}
	// Native administrative user -> local root. Scoped session policies and
	// service principals still pass through the real IAM and KMS engines.
	data = []byte(strings.ReplaceAll(string(data), "arn:aws:iam::000000000000:user/Delegated", "arn:aws:iam::000000000000:root"))
	var fixture struct {
		Observations []struct {
			ebTargetRoleObservation
			Expected map[string]any
			Messages []map[string]any
		}
	}
	ebTargetRoleDecode(t, data, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "archive-keys.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC))
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			replay := ebTargetRoleNew(cloud, clients, "000000000000", "us-east-1")
			const nativeKeyID = "a2ab2f04-88b3-40ea-96be-fbbfc012081f"
			keyID, originalID := nativeKeyID, ""
			for _, row := range fixture.Observations {
				if !t.Run(row.Label, func(t *testing.T) {
					row.Input = []byte(strings.ReplaceAll(string(row.Input), nativeKeyID, keyID))
					if row.Operation == "DescribeReplay" {
						source.Advance(time.Minute)
						if result, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || result.More {
							t.Fatal("replay did not settle", result, err)
						}
					}
					if row.Operation == "ReceiveMessage" {
						var input sqs.ReceiveMessageInput
						ebTargetRoleDecode(t, row.Input, &input)
						queue := aws.ToString(input.QueueUrl)
						queue = queue[strings.LastIndex(queue, "/")+1:]
						messages := snsAdmissionReceive(t, cloud, clients.sqs(replay.account, "test", ""), replay.queues[queue])
						if len(messages) != len(row.Messages) {
							t.Fatalf("native receipt count=%d local=%d", len(row.Messages), len(messages))
						}
						for i, message := range messages {
							var body map[string]any
							ebTargetRoleDecode(t, []byte(aws.ToString(message.Body)), &body)
							if body["id"] == originalID || body["id"] == "" {
								t.Fatalf("replay did not receive a fresh event identity: %v", body["id"])
							}
							body["id"] = row.Messages[i]["id"]
							if !reflect.DeepEqual(body, row.Messages[i]) {
								t.Fatalf("encrypted replay envelope differs: native=%v local=%v", row.Messages[i], body)
							}
						}
						return
					}
					output := replay.call(t, row.ebTargetRoleObservation)
					switch out := output.(type) {
					case *kms.CreateKeyOutput:
						keyID = aws.ToString(out.KeyMetadata.KeyId)
					case *eventbridge.PutEventsOutput:
						originalID = aws.ToString(out.Entries[0].EventId)
						if result, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || result.More {
							t.Fatal("archive ingestion did not settle", result, err)
						}
					case *eventbridge.DescribeArchiveOutput:
						// Disabled-key metadata reads succeed without disclosing an
						// undecryptable pattern; native cache had settled in this row.
						if row.Label == "describe-disabled-key" && out.EventPattern != nil {
							t.Fatal("disabled archive key still exposed its pattern")
						}
					}
					if len(row.Expected) != 0 {
						encoded, err := json.Marshal(output)
						if err != nil {
							t.Fatal(err)
						}
						var actual map[string]any
						ebTargetRoleDecode(t, encoded, &actual)
						expectedJSON, err := json.Marshal(row.Expected)
						if err != nil {
							t.Fatal(err)
						}
						var expected map[string]any
						ebTargetRoleDecode(t, []byte(strings.ReplaceAll(string(expectedJSON), nativeKeyID, keyID)), &expected)
						for field, want := range expected {
							if !reflect.DeepEqual(actual[field], want) {
								t.Fatalf("%s: native=%v local=%v", field, want, actual[field])
							}
						}
					}
				}) {
					break
				}
			}
		})
	}
}
