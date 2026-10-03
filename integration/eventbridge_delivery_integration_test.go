package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

const (
	eventDeliveryAccount = "111111111111"
	eventDeliveryName    = "stackd-event-delivery-owned"
	eventDeliveryBusARN  = "arn:aws:events:us-east-1:" + eventDeliveryAccount + ":event-bus/" + eventDeliveryName
	eventDeliveryRuleARN = "arn:aws:events:us-east-1:" + eventDeliveryAccount + ":rule/" + eventDeliveryName + "/" + eventDeliveryName
	eventDeliverySecret  = "private-event-detail-must-stay-out-of-journal"
)

type eventDeliveryCase struct {
	Name       string                     `json:"case"`
	Condition  map[string]json.RawMessage `json:"condition"`
	Delivery   string                     `json:"delivery"`
	Attributes map[string]string          `json:"attributes"`
}

func eventDeliveryCases(t *testing.T) []eventDeliveryCase {
	t.Helper()
	var cases []eventDeliveryCase
	for _, file := range []string{"delivery.json", "principal_types.json"} {
		body, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "eventbridge", file))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Observations []eventDeliveryCase `json:"observations"`
		}
		if err := json.Unmarshal(body, &fixture); err != nil {
			t.Fatal(err)
		}
		if len(fixture.Observations) == 0 {
			t.Fatalf("native fixture %s has no observations", file)
		}
		cases = append(cases, fixture.Observations...)
	}
	return cases
}

func eventDeliveryClient(c cloudClients, account string) *eventbridge.Client {
	return eventbridge.New(eventbridge.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func startEventDeliveryCloud(t *testing.T, backends *storage.Backends, source clock.Clock) (*stackd.Stack, cloudClients, func()) {
	t.Helper()
	cloud, server := startPublicCloud(t, stackd.Config{Storage: backends, Clock: source})
	close := func() {
		server.Close()
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(close)
	return cloud, cloudClients{server}, close
}

func eventDeliveryQueueARN(kind string) string {
	return "arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":" + eventDeliveryName + "-" + kind
}

func setEventDeliveryPolicy(t *testing.T, queues *sqs.Client, url *string, kind string, condition map[string]json.RawMessage) {
	t.Helper()
	statement := map[string]any{"Effect": "Allow", "Principal": map[string]string{"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": eventDeliveryQueueARN(kind)}
	if len(condition) != 0 {
		statement["Condition"] = condition
	}
	policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{statement}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: url, Attributes: map[string]string{"Policy": string(policy)}}); err != nil {
		t.Fatal(err)
	}
}

func provisionEventDelivery(t *testing.T, c cloudClients) map[string]*string {
	t.Helper()
	queues := c.sqs(eventDeliveryAccount, "test", "")
	urls := make(map[string]*string)
	for _, kind := range []string{"target", "dlq"} {
		out, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(eventDeliveryName + "-" + kind)})
		if err != nil {
			t.Fatal(err)
		}
		urls[kind] = out.QueueUrl
	}
	events := eventDeliveryClient(c, eventDeliveryAccount)
	bus, err := events.CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: aws.String(eventDeliveryName)})
	if err != nil || aws.ToString(bus.EventBusArn) != eventDeliveryBusARN {
		t.Fatal("create fixture bus", bus, err)
	}
	rule, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String(eventDeliveryName), EventBusName: aws.String(eventDeliveryName), EventPattern: aws.String(fmt.Sprintf(`{"source":[%q]}`, eventDeliveryName))})
	if err != nil || aws.ToString(rule.RuleArn) != eventDeliveryRuleARN {
		t.Fatal("create fixture rule", rule, err)
	}
	setEventDeliveryPolicy(t, queues, urls["dlq"], "dlq", map[string]json.RawMessage{"ArnEquals": json.RawMessage(fmt.Sprintf(`{"aws:SourceArn":%q}`, eventDeliveryRuleARN))})
	targets, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(eventDeliveryName), EventBusName: aws.String(eventDeliveryName), Targets: []eventtypes.Target{{
		Id: aws.String("queue"), Arn: aws.String(eventDeliveryQueueARN("target")), DeadLetterConfig: &eventtypes.DeadLetterConfig{Arn: aws.String(eventDeliveryQueueARN("dlq"))},
		RetryPolicy: &eventtypes.RetryPolicy{MaximumRetryAttempts: aws.Int32(0), MaximumEventAgeInSeconds: aws.Int32(60)},
	}}})
	if err != nil || targets.FailedEntryCount != 0 || len(targets.FailedEntries) != 0 {
		t.Fatal("register fixture target", targets, err)
	}
	return urls
}

func putDeliveryEvent(t *testing.T, c cloudClients, detail map[string]any, stamp time.Time) (string, string) {
	t.Helper()
	body, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	out, err := eventDeliveryClient(c, eventDeliveryAccount).PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{
		EventBusName: aws.String(eventDeliveryName), Source: aws.String(eventDeliveryName), DetailType: aws.String("authorization-probe"),
		Detail: aws.String(string(body)), Time: aws.Time(stamp), Resources: []string{eventDeliveryBusARN},
	}}})
	if err != nil || out.FailedEntryCount != 0 || len(out.Entries) != 1 || aws.ToString(out.Entries[0].EventId) == "" {
		t.Fatal("accept fixture event", out, err)
	}
	requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	if !ok || requestID == "" {
		t.Fatal("PutEvents omitted request ID")
	}
	return aws.ToString(out.Entries[0].EventId), requestID
}

func assertEventDelivery(t *testing.T, cloud *stackd.Stack, c cloudClients, urls map[string]*string, tc eventDeliveryCase, eventID, requestID string, accepted time.Time) {
	t.Helper()
	drain, err := cloud.RunDueJobs(t.Context(), 10)
	if err != nil || drain.More {
		t.Fatal("delivery did not reach a terminal state", drain, err)
	}
	queues := c.sqs(eventDeliveryAccount, "test", "")
	var delivered sqstypes.Message
	for _, kind := range []string{"target", "dlq"} {
		out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: urls[kind], MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
		if err != nil {
			t.Fatal(err)
		}
		if kind != tc.Delivery {
			if len(out.Messages) != 0 {
				t.Fatalf("unexpected delivery to %s: %+v", kind, out.Messages)
			}
			continue
		}
		if len(out.Messages) != 1 {
			t.Fatalf("expected one %s message, got %+v", kind, out.Messages)
		}
		delivered = out.Messages[0]
		if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: urls[kind], ReceiptHandle: delivered.ReceiptHandle}); err != nil {
			t.Fatal(err)
		}
	}
	assertEventDeliveryAttributes(t, delivered.MessageAttributes, tc.Attributes, "events.amazonaws.com", "sqs:sendmessage", tc.Attributes["TARGET_ARN"])
	assertEventDeliveryEnvelope(t, aws.ToString(delivered.Body), eventID, map[string]any{"case": tc.Name, "private": eventDeliverySecret}, accepted)
	assertEventDeliveryJournal(t, cloud, eventID, requestID, accepted, map[string]string{aws.ToString(delivered.MessageId): eventDeliveryQueueARN(tc.Delivery)})
}

func assertEventDeliveryAttributes(t *testing.T, delivered map[string]sqstypes.MessageAttributeValue, wantAttributes map[string]string, diagnosis ...string) {
	t.Helper()
	attributes := make(map[string]string)
	for name, attr := range delivered {
		if aws.ToString(attr.DataType) != "String" || attr.StringValue == nil || len(attr.BinaryValue) != 0 {
			t.Fatalf("invalid native string attribute %s: %+v", name, attr)
		}
		attributes[name] = aws.ToString(attr.StringValue)
	}
	// Target diagnosis includes AWS SDK implementation details and request IDs.
	// Compare its actor/action/resource; fixed delivery attributes remain exact.
	if native, ok := wantAttributes["ERROR_MESSAGE"]; ok {
		message := attributes["ERROR_MESSAGE"]
		for _, part := range diagnosis {
			if !strings.Contains(strings.ToLower(message), strings.ToLower(part)) {
				t.Errorf("delivery diagnosis omits %q: %q", part, message)
			}
		}
		attributes["ERROR_MESSAGE"] = native
	}
	if !maps.Equal(attributes, wantAttributes) {
		t.Errorf("native delivery attributes differ\ngot:  %v\nwant: %v", attributes, wantAttributes)
	}
}

func assertEventDeliveryEnvelope(t *testing.T, body, eventID string, detail map[string]any, accepted time.Time) {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatal("invalid delivered event envelope", err)
	}
	wantEnvelope := map[string]any{"version": "0", "id": eventID, "detail-type": "authorization-probe", "source": eventDeliveryName,
		"account": eventDeliveryAccount, "time": accepted.Add(-time.Hour).Format(time.RFC3339), "region": "us-east-1",
		"resources": []any{eventDeliveryBusARN}, "detail": detail}
	if !reflect.DeepEqual(envelope, wantEnvelope) {
		t.Errorf("event envelope changed during delivery\ngot:  %v\nwant: %v", envelope, wantEnvelope)
	}
}

func assertEventDeliveryJournal(t *testing.T, cloud *stackd.Stack, eventID, requestID string, accepted time.Time, expectedMessages map[string]string) {
	t.Helper()
	rows, err := cloud.Events(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var acceptedRows, messageRows []journal.Event
	for _, row := range rows {
		if row.EventBridgeAccepted.EventID == eventID {
			acceptedRows = append(acceptedRows, row)
		}
		if row.SQSMessageAccepted.MessageID != "" && row.ParentEventID == eventID {
			messageRows = append(messageRows, row)
		}
	}
	if len(acceptedRows) != 1 || len(messageRows) != len(expectedMessages) {
		t.Fatalf("expected one accepted event and %d causal queue messages: events=%+v messages=%+v", len(expectedMessages), acceptedRows, messageRows)
	}
	entry := acceptedRows[0]
	if entry.EventBridgeAccepted.EventBusARN != eventDeliveryBusARN || entry.ParentEventID != "" || entry.ActorARN != "arn:aws:iam::"+eventDeliveryAccount+":root" || entry.ActorService != "" {
		t.Errorf("invalid event admission origin: %+v", entry)
	}
	journalMessages := make(map[string]string)
	for _, message := range messageRows {
		journalMessages[message.SQSMessageAccepted.MessageID] = message.SQSMessageAccepted.QueueARN
		if message.Sequence <= entry.Sequence || message.ActorService != "events.amazonaws.com" || message.ActorARN != "" {
			t.Errorf("invalid service delivery origin: %+v", message)
		}
	}
	if !maps.Equal(journalMessages, expectedMessages) {
		t.Errorf("causal journal does not identify the delivered messages: got %v, want %v", journalMessages, expectedMessages)
	}
	for _, row := range append(acceptedRows, messageRows...) {
		if row.Partition != "aws" || row.AccountID != eventDeliveryAccount || row.Region != "us-east-1" || row.RequestID != requestID || !row.At.Equal(accepted) {
			t.Errorf("lost event scope, request causality or service time: %+v", row)
		}
	}
	if strings.Contains(journalJSON(t, rows), eventDeliverySecret) {
		t.Error("customer event detail leaked into the shared journal")
	}
}

func TestEventBridgeSQSNativeDeliveryConditions(t *testing.T) {
	cases := eventDeliveryCases(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "delivery.sqlite"))
			}
			epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
			cloud, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(epoch))
			urls := provisionEventDelivery(t, c)
			for _, tc := range cases {
				t.Run(tc.Name, func(t *testing.T) {
					setEventDeliveryPolicy(t, c.sqs(eventDeliveryAccount, "test", ""), urls["target"], "target", tc.Condition)
					id, requestID := putDeliveryEvent(t, c, map[string]any{"case": tc.Name, "private": eventDeliverySecret}, epoch.Add(-time.Hour))
					assertEventDelivery(t, cloud, c, urls, tc, id, requestID, epoch)
				})
			}
		})
	}
}

func TestEventBridgeSQSPendingDeliveryRecoversSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.sqlite")
	backends, closeDB := openSQLiteBackends(t, path)
	gate := &gatedQueueRepository{Repository: backends.SQS, entered: make(chan struct{}), release: make(chan struct{})}
	backends.SQS = gate
	t.Cleanup(gate.unblock)
	epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	source := clock.NewManual(epoch)
	cloud, c, closeCloud := startEventDeliveryCloud(t, backends, source)
	urls := provisionEventDelivery(t, c)
	tc := eventDeliveryCases(t)[0]
	queues := c.sqs(eventDeliveryAccount, "test", "")
	setEventDeliveryPolicy(t, queues, urls["target"], "target", tc.Condition)
	if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: urls["target"], MessageBody: aws.String("already waiting in queue")}); err != nil {
		t.Fatal(err)
	}
	previous, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: urls["target"]})
	if err != nil || len(previous.Messages) != 1 || aws.ToString(previous.Messages[0].Body) != "already waiting in queue" {
		t.Fatal("retain a preexisting in-flight message", previous, err)
	}
	gate.armed.Store(true)
	id, requestID := putDeliveryEvent(t, c, map[string]any{"case": tc.Name, "private": eventDeliverySecret}, epoch.Add(-time.Hour))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("accepted delivery did not reach the queue boundary", ctx.Err())
	}
	rows, err := cloud.Events(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, row := range rows {
		if row.EventBridgeAccepted.EventID == id {
			accepted++
		}
		if row.SQSMessageAccepted.MessageID != "" && row.ParentEventID == id {
			t.Fatal("queue message committed before the delivery boundary was released", row)
		}
	}
	if accepted != 1 {
		t.Fatal("delivery intent was not committed before target invocation", rows)
	}
	// Shutdown cancels the blocked downstream command. The accepted event and
	// pending delivery must survive a real database close without a queue write.
	closeCloud()
	closeDB()
	backends, _ = openSQLiteBackends(t, path)
	cloud, c, _ = startEventDeliveryCloud(t, backends, source)
	for _, kind := range []string{"target", "dlq"} {
		queue, err := c.sqs(eventDeliveryAccount, "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(eventDeliveryName + "-" + kind)})
		if err != nil {
			t.Fatal("retained queue missing after reopen", err)
		}
		urls[kind] = queue.QueueUrl
	}
	assertEventDelivery(t, cloud, c, urls, tc, id, requestID, epoch)
	queues = c.sqs(eventDeliveryAccount, "test", "")
	if _, err := queues.ChangeMessageVisibility(t.Context(), &sqs.ChangeMessageVisibilityInput{QueueUrl: urls["target"], ReceiptHandle: previous.Messages[0].ReceiptHandle, VisibilityTimeout: 0}); err != nil {
		t.Fatal("delivery or recovery invalidated a preexisting receipt", err)
	}
	remaining, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: urls["target"], MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{sqstypes.MessageSystemAttributeNameAll}})
	if err != nil || len(remaining.Messages) != 1 || aws.ToString(remaining.Messages[0].MessageId) != aws.ToString(previous.Messages[0].MessageId) || aws.ToString(remaining.Messages[0].Body) != "already waiting in queue" || remaining.Messages[0].Attributes["ApproximateReceiveCount"] != "2" {
		t.Fatal("internal delivery overwrote retained queue state", remaining, err)
	}
}
