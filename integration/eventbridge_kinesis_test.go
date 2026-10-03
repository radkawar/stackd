package stackd_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

type eventKinesisFixture struct {
	Stream      kinesis.CreateStreamInput
	Bus         eventbridge.CreateEventBusInput
	Rule        eventbridge.PutRuleInput
	Role        iam.CreateRoleInput
	Policy      iam.PutRolePolicyInput
	Queue       sqs.CreateQueueInput
	QueuePolicy string `json:"queue_policy"`
	Targets     eventbridge.PutTargetsInput
	Send        eventbridge.PutEventsInput
	Records     []struct {
		Case, Target, Data string
		PartitionKey       *string `json:"partition_key"`
	}
}

// The fixture projects testdata/aws/eventbridge/kinesis_targets.json calls and
// records, rebinding only the owned resource name and account. Payload bytes and
// custom partition keys are exact native observations, not SDK field echoes.
func TestEventBridgeKinesisNativeReplaySDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runtime := newKinesisReplayRuntime(t)
			body, err := os.ReadFile("../testdata/eventbridge/kinesis_replay.json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture eventKinesisFixture
			if err := json.Unmarshal(body, &fixture); err != nil {
				t.Fatal(err)
			}
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var cloud *stackd.Stack
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source, KinesisRuntime: runtime}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				var err error
				cloud, err = stackd.New(config)
				if err != nil {
					t.Fatal(err)
				}
				return cloud, httptest.NewServer(cloud)
			})
			const account = "000000000000"
			streams := c.kinesis(account, "test", "")
			if _, err := streams.CreateStream(t.Context(), &fixture.Stream); err != nil {
				t.Fatal(err)
			}
			summary := awaitKinesisActive(t, source, streams, aws.ToString(fixture.Stream.StreamName))
			streamARN := aws.ToString(summary.StreamDescriptionSummary.StreamARN)
			events := eventDeliveryClient(c, account)
			if _, err := events.CreateEventBus(t.Context(), &fixture.Bus); err != nil {
				t.Fatal(err)
			}
			rule, err := events.PutRule(t.Context(), &fixture.Rule)
			if err != nil {
				t.Fatal(err)
			}
			roles := c.iam(account, "test", "")
			if _, err := roles.CreateRole(t.Context(), &fixture.Role); err != nil {
				t.Fatal(err)
			}
			if _, err := roles.PutRolePolicy(t.Context(), &fixture.Policy); err != nil {
				t.Fatal(err)
			}
			queues := c.sqs(account, "test", "")
			queue, err := queues.CreateQueue(t.Context(), &fixture.Queue)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": fixture.QueuePolicy}}); err != nil {
				t.Fatal(err)
			}

			// Retry/reopen is a local durability invariant. The native key capture
			// used zero retries and did not measure throttling or retry timing.
			for i := range fixture.Targets.Targets {
				fixture.Targets.Targets[i].RetryPolicy.MaximumRetryAttempts = aws.Int32(10)
			}
			putEventKinesisTargets(t, events, &fixture.Targets)
			c = reopen()
			events, streams = eventDeliveryClient(c, account), c.kinesis(account, "test", "")

			// Exhaust the actual single-shard record budget without substituting a
			// delivery adapter. A stationary manual clock holds the quota window.
			const fillerKey = "quota-filler"
			filler := []byte("quota")
			batch := make([]kinesistypes.PutRecordsRequestEntry, 500)
			for i := range batch {
				batch[i] = kinesistypes.PutRecordsRequestEntry{PartitionKey: aws.String(fillerKey), Data: filler}
			}
			var written kinesistypes.PutRecordsResultEntry
			for range 2 {
				out, err := streams.PutRecords(t.Context(), &kinesis.PutRecordsInput{StreamARN: &streamARN, Records: batch})
				if err != nil || aws.ToInt32(out.FailedRecordCount) != 0 || len(out.Records) != len(batch) {
					t.Fatal("fill real shard quota", out, err)
				}
				written = out.Records[len(out.Records)-1]
			}
			_, err = streams.PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: &streamARN, PartitionKey: aws.String("blocked"), Data: []byte("must not append")})
			assertAPIError(t, err, "ProvisionedThroughputExceededException")
			accepted, err := events.PutEvents(t.Context(), &fixture.Send)
			if err != nil || accepted.FailedEntryCount != 0 || len(accepted.Entries) != len(fixture.Send.Entries) {
				t.Fatal("accept captured events", accepted, err)
			}
			ids := make(map[string]string)
			for i, entry := range accepted.Entries {
				var detail struct{ Case string }
				if err := json.Unmarshal([]byte(aws.ToString(fixture.Send.Entries[i].Detail)), &detail); err != nil {
					t.Fatal(err)
				}
				id := aws.ToString(entry.EventId)
				if id == "" || entry.ErrorCode != nil {
					t.Fatal("event admission", entry)
				}
				ids[detail.Case] = id
			}
			if out, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || out.More {
				t.Fatal("drain initial attempts", out, err)
			}
			iterator, err := streams.GetShardIterator(t.Context(), &kinesis.GetShardIteratorInput{StreamARN: &streamARN, ShardId: written.ShardId, StartingSequenceNumber: written.SequenceNumber, ShardIteratorType: kinesistypes.ShardIteratorTypeAfterSequenceNumber})
			if err != nil {
				t.Fatal(err)
			}
			page, err := streams.GetRecords(t.Context(), &kinesis.GetRecordsInput{StreamARN: &streamARN, ShardIterator: iterator.ShardIterator})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Records) != 0 {
				t.Fatal("throttled deliveries appended to native stream", page)
			}

			// Selected delivery configuration must survive source-target removal,
			// real stack shutdown, and SQLite close/reopen, not just ListTargets.
			removed, err := events.RemoveTargets(t.Context(), &eventbridge.RemoveTargetsInput{EventBusName: fixture.Targets.EventBusName, Rule: fixture.Targets.Rule, Ids: []string{"custom", "default"}})
			if err != nil || removed.FailedEntryCount != 0 {
				t.Fatal("remove selected targets", removed, err)
			}
			c = reopen()
			events, streams = eventDeliveryClient(c, account), c.kinesis(account, "test", "")
			advanceClock(t, source, time.Second)
			records := awaitKinesisRecords(t, source, streams, streamARN, len(fixture.Records)+1000)
			if len(records) != len(fixture.Records)+1000 {
				t.Fatalf("native record count = %d, want %d", len(records), len(fixture.Records)+1000)
			}
			assertEventKinesisRecords(t, fixture, records, ids, fillerKey, filler)
			queues = c.sqs(account, "test", "")
			queueURL, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: fixture.Queue.QueueName})
			if err != nil {
				t.Fatal(err)
			}
			empty, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL.QueueUrl, MaxNumberOfMessages: 10})
			if err != nil || len(empty.Messages) != 0 {
				t.Fatal("successful native replay reached DLQ", empty, err)
			}

			// Authorization is live at invocation, not baked into retained targets.
			// Native target_roles.json runs[].cases[name=id-deny].receipt observes
			// NO_PERMISSIONS with no retry attributes. This Kinesis combination is
			// a local cross-service invariant, not an additional native capture.
			denied := fixture.Targets.Targets[1]
			denied.InputTransformer = nil
			putEventKinesisTargets(t, events, &eventbridge.PutTargetsInput{EventBusName: fixture.Targets.EventBusName, Rule: fixture.Targets.Rule, Targets: []eventtypes.Target{denied}})
			policy := fixture.Policy
			policy.PolicyDocument = aws.String(strings.Replace(aws.ToString(policy.PolicyDocument), `"Allow"`, `"Deny"`, 1))
			if _, err := c.iam(account, "test", "").PutRolePolicy(t.Context(), &policy); err != nil {
				t.Fatal(err)
			}
			latest, err := streams.GetShardIterator(t.Context(), &kinesis.GetShardIteratorInput{StreamARN: &streamARN, ShardId: written.ShardId, ShardIteratorType: kinesistypes.ShardIteratorTypeLatest})
			if err != nil {
				t.Fatal(err)
			}
			deniedEvent, err := events.PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: fixture.Send.Entries[:1]})
			if err != nil || deniedEvent.FailedEntryCount != 0 || len(deniedEvent.Entries) != 1 || aws.ToString(deniedEvent.Entries[0].EventId) == "" {
				t.Fatal("admit denied delivery", deniedEvent, err)
			}
			if out, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || out.More {
				t.Fatal("drain authorization failure", out, err)
			}
			messages, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL.QueueUrl, MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
			if err != nil || len(messages.Messages) != 1 {
				t.Fatal("denied delivery must reach DLQ once", messages, err)
			}
			message := messages.Messages[0]
			assertEventDeliveryAttributes(t, message.MessageAttributes, map[string]string{
				"ERROR_CODE": "NO_PERMISSIONS", "ERROR_MESSAGE": "normalized diagnosis",
				"RULE_ARN": aws.ToString(rule.RuleArn), "TARGET_ARN": streamARN,
			}, "assumed-role/"+aws.ToString(fixture.Role.RoleName), "kinesis:PutRecord", streamARN)
			var envelope struct {
				ID     string
				Detail json.RawMessage
			}
			if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &envelope); err != nil {
				t.Fatal(err)
			}
			var gotDetail, wantDetail any
			if err := json.Unmarshal(envelope.Detail, &gotDetail); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(aws.ToString(fixture.Send.Entries[0].Detail)), &wantDetail); err != nil {
				t.Fatal(err)
			}
			if envelope.ID != aws.ToString(deniedEvent.Entries[0].EventId) || !reflect.DeepEqual(gotDetail, wantDetail) {
				t.Fatalf("DLQ lost the admitted event: %s", aws.ToString(message.Body))
			}
			advanceClock(t, source, time.Second)
			after, err := streams.GetRecords(t.Context(), &kinesis.GetRecordsInput{StreamARN: &streamARN, ShardIterator: latest.ShardIterator})
			if err != nil || len(after.Records) != 0 {
				t.Fatal("denied delivery appended a native record", after, err)
			}
		})
	}
}

func putEventKinesisTargets(t *testing.T, client *eventbridge.Client, input *eventbridge.PutTargetsInput) {
	t.Helper()
	out, err := client.PutTargets(t.Context(), input)
	if err != nil || out.FailedEntryCount != 0 || len(out.FailedEntries) != 0 {
		t.Fatal("register Kinesis targets", out, err)
	}
}

func assertEventKinesisRecords(t *testing.T, fixture eventKinesisFixture, records []kinesistypes.Record, ids map[string]string, fillerKey string, filler []byte) {
	t.Helper()
	remaining := make(map[string]int, len(fixture.Records))
	for i, record := range fixture.Records {
		remaining[record.Data] = i
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	fillers := 0
	for _, record := range records {
		key := aws.ToString(record.PartitionKey)
		if key == fillerKey {
			fillers++
			if !bytes.Equal(record.Data, filler) {
				t.Fatal("native quota filler changed")
			}
			continue
		}
		i, ok := remaining[string(record.Data)]
		if !ok {
			t.Fatalf("unexpected or duplicate native payload %q with key %q", record.Data, key)
		}
		want := fixture.Records[i]
		delete(remaining, string(record.Data))
		if want.PartitionKey != nil {
			if key != *want.PartitionKey {
				t.Errorf("%s custom key = %q, want native %q", want.Case, key, *want.PartitionKey)
			}
		} else {
			prefix := ids[want.Case] + "_"
			if !strings.HasPrefix(key, prefix) || !uuid.MatchString(strings.TrimPrefix(key, prefix)) {
				t.Errorf("%s default key = %q, want event ID plus opaque UUID", want.Case, key)
			}
		}
	}
	if fillers != 1000 || len(remaining) != 0 {
		t.Fatalf("native stream missing captured records: filler count %d, missing %v", fillers, remaining)
	}
}
