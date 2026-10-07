package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"stackd/clock"
	runtime "stackd/compute/lambda"
	"stackd/internal/awsapi"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	sqsservice "stackd/internal/services/sqs"
)

// This adapter binds real SQS commands to a fixture's root principal. Queue
// visibility, receipts, FIFO exclusion and partial deletes are not simulated.
type pollingQueue struct {
	owner *sqsservice.Service
	ctx   context.Context
	arn   string
}

func pollingQueueFixture(t *testing.T, ctx context.Context, manual *clock.Manual, name string, fifo bool) *pollingQueue {
	t.Helper()
	owner := sqsservice.NewWithConfig(sqsservice.Config{Clock: manual})
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	attributes := sqsapi.QueueAttributeMap{"VisibilityTimeout": "30"}
	if fifo {
		name += ".fifo"
		attributes["FifoQueue"], attributes["ContentBasedDeduplication"] = "true", "true"
	}
	model, _ := awscatalog.LookupService("sqs")
	operation, _ := model.Operation("CreateQueue")
	if _, wire := owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &sqsapi.CreateQueueInput{QueueName: new(sqsapi.String(name)), Attributes: attributes}}); wire != nil {
		t.Fatal(wire)
	}
	metadata := awsctx.FromContext(ctx)
	return &pollingQueue{owner: owner, ctx: ctx, arn: "arn:" + metadata.Partition + ":sqs:" + metadata.Region + ":" + metadata.AccountID + ":" + name}
}

func (q *pollingQueue) principal(ctx context.Context) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.FromContext(q.ctx))
}

func (q *pollingQueue) Open(context.Context, FunctionKey, string, string) (SQSConsumer, *awswire.Error) {
	return q, nil
}

func (q *pollingQueue) Check(ctx context.Context) (SQSQueueInfo, *awswire.Error) {
	configuration, _, wire := q.owner.CheckConsumeQueue(q.principal(ctx), q.arn)
	return SQSQueueInfo{VisibilitySeconds: configuration.VisibilitySeconds, FIFO: configuration.FIFO}, wire
}

func (q *pollingQueue) Receive(ctx context.Context, input *sqsapi.ReceiveMessageInput) (*sqsapi.ReceiveMessageOutput, *awswire.Error) {
	return q.owner.ReceiveFromQueue(q.principal(ctx), q.arn, input)
}

func (q *pollingQueue) Delete(ctx context.Context, input *sqsapi.DeleteMessageBatchInput) (*sqsapi.DeleteMessageBatchOutput, *awswire.Error) {
	return q.owner.DeleteFromQueue(q.principal(ctx), q.arn, input)
}

func (q *pollingQueue) CheckStream(ctx context.Context, _ FunctionKey, _ string, _ EventSourceMappingKey, destination string) *awswire.Error {
	return q.owner.CheckSendToQueue(q.principal(ctx), destination)
}

func (q *pollingQueue) SendStream(ctx context.Context, failure StreamFailure) *awswire.Error {
	_, wire := q.owner.SendToQueue(q.principal(ctx), failure.DestinationARN, &sqsapi.SendMessageInput{MessageBody: new(sqsapi.String(failure.Payload))})
	return wire
}

func (q *pollingQueue) send(t *testing.T, ordinal int, group string, fail bool) string {
	t.Helper()
	body := fmt.Sprintf(`{"ordinal":%d,"fail":%t}`, ordinal, fail)
	input := &sqsapi.SendMessageInput{MessageBody: new(sqsapi.String(body))}
	if group != "" {
		input.MessageGroupId = new(sqsapi.String(group))
		input.MessageDeduplicationId = new(sqsapi.String(group + "-" + strconv.Itoa(ordinal)))
	}
	output, wire := q.owner.SendToQueue(q.ctx, q.arn, input)
	if wire != nil {
		t.Fatal(wire)
	}
	return value(output.MessageId)
}

func (q *pollingQueue) receive(t *testing.T, count int) sqsapi.MessageList {
	t.Helper()
	output, wire := q.Receive(q.ctx, &sqsapi.ReceiveMessageInput{MaxNumberOfMessages: new(sqsapi.NullableInteger(count)), WaitTimeSeconds: new(sqsapi.NullableInteger(0)), MessageSystemAttributeNames: sqsapi.MessageSystemAttributeList{"All"}})
	if wire != nil {
		t.Fatal(wire)
	}
	return output.Messages
}

func pollingSQSPartialHandler(in runtime.Invocation) runtime.Result {
	var event struct{ Records []sqsEventRecord }
	if err := json.Unmarshal(in.Payload, &event); err != nil {
		panic(err)
	}
	failures := []map[string]string{}
	blocked := map[string]bool{}
	for _, record := range event.Records {
		var body struct{ Fail bool }
		if err := json.Unmarshal([]byte(record.Body), &body); err != nil {
			panic(err)
		}
		group := string(record.Attributes["MessageGroupId"])
		if body.Fail || group != "" && blocked[group] {
			failures = append(failures, map[string]string{"itemIdentifier": record.MessageID})
			if group != "" {
				blocked[group] = true
			}
		}
	}
	payload, err := json.Marshal(map[string]any{"batchItemFailures": failures})
	if err != nil {
		panic(err)
	}
	return runtime.Result{Payload: payload}
}

func TestSQSPollBatches500AndRetriesOnlyReportedFailure(t *testing.T) {
	s, manual, engine, ctx, _, mapping := pollingFixture(t, pollingSQSPartialHandler)
	queue := pollingQueueFixture(t, ctx, manual, "results-buffer", false)
	s.sqs = queue
	mapping.EventSourceARN = queue.arn
	mapping.Settings = EventSourceMappingSettings{BatchSize: 500, BatchingWindow: time.Second, ReportBatchItemFailures: true}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
		t.Fatal(err)
	}
	failedID := ""
	for ordinal := range 500 {
		id := queue.send(t, ordinal, "", ordinal == 237)
		if ordinal == 237 {
			failedID = id
		}
	}
	completion := s.runSQSPoll(ctx, mapping, &sqsPollState{})
	s.work.Wait()
	calls := engine.invocations()
	if completion.polled != 500 || completion.backoff || len(calls) != 1 {
		t.Fatalf("large SQS batch was fragmented or backed off: completion=%+v calls=%d", completion, len(calls))
	}
	var event struct{ Records []sqsEventRecord }
	if err := json.Unmarshal(calls[0].Payload, &event); err != nil {
		t.Fatal(err)
	}
	if len(event.Records) != 500 || event.Records[237].MessageID != failedID || event.Records[237].EventSourceARN != queue.arn {
		t.Fatal("500-record runtime batch lost source identity")
	}
	if messages := queue.receive(t, 10); len(messages) != 0 {
		t.Fatalf("reported failure became visible before its SQS lease expired: %+v", messages)
	}
	if err := manual.Advance(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	messages := queue.receive(t, 10)
	if len(messages) != 1 || value(messages[0].MessageId) != failedID || messages[0].Attributes["ApproximateReceiveCount"] != "2" {
		t.Fatalf("partial acknowledgement deleted the failure or retained successes: %+v", messages)
	}
}

func TestSQSPollFIFOFailureKeepsGroupBlockedWithoutBlockingOtherGroups(t *testing.T) {
	s, manual, _, ctx, _, mapping := pollingFixture(t, pollingSQSPartialHandler)
	queue := pollingQueueFixture(t, ctx, manual, "planner-events", true)
	s.sqs = queue
	mapping.EventSourceARN = queue.arn
	mapping.Settings = EventSourceMappingSettings{BatchSize: 10, ReportBatchItemFailures: true}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
		t.Fatal(err)
	}
	var groupIDs []string
	for ordinal := range 5 {
		groupIDs = append(groupIDs, queue.send(t, ordinal, "group-a", ordinal == 2))
	}
	for ordinal := range 5 {
		queue.send(t, ordinal, "group-b", false)
	}
	completion := s.runSQSPoll(ctx, mapping, &sqsPollState{})
	s.work.Wait()
	if completion.polled != 10 || completion.backoff {
		t.Fatalf("FIFO partial response backed off or split a full batch: %+v", completion)
	}
	groupIDs = append(groupIDs, queue.send(t, 5, "group-a", false))
	otherID := queue.send(t, 5, "group-b", false)
	messages := queue.receive(t, 10)
	if len(messages) != 1 || value(messages[0].MessageId) != otherID {
		t.Fatalf("failed FIFO group leaked later records or blocked another group: %+v", messages)
	}
	if !s.deleteSQSRecords(ctx, mapping, queue, []sqsEventRecord{sqsRecord(mapping, messages[0])}) {
		t.Fatal("could not acknowledge independent FIFO group")
	}
	if err := manual.Advance(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	messages = queue.receive(t, 10)
	var received []string
	for _, message := range messages {
		received = append(received, value(message.MessageId))
	}
	if !reflect.DeepEqual(received, groupIDs[2:]) {
		t.Fatalf("FIFO retry lost failed/unprocessed ordering: got %v want %v", received, groupIDs[2:])
	}
	for _, message := range messages[:3] {
		if message.Attributes["ApproximateReceiveCount"] != "2" {
			t.Fatal("failed/unprocessed FIFO record did not retain its delivery count")
		}
	}
	if messages[3].Attributes["ApproximateReceiveCount"] != "1" {
		t.Fatal("later FIFO record was received while its group was held")
	}
}

func TestSQSPollPartialResponseMustBeEnabledAndValid(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		report      bool
		response    string
		wantRetries int
	}{
		{"disabled", false, `{"batchItemFailures":[{"itemIdentifier":"unknown"}]}`, 0},
		{"invalid-identifier", true, `{"batchItemFailures":[{"itemIdentifier":7}]}`, 2},
		{"empty-success", true, `{"batchItemFailures":[]}`, 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s, manual, _, ctx, _, mapping := pollingFixture(t, func(runtime.Invocation) runtime.Result { return runtime.Result{Payload: []byte(scenario.response)} })
			queue := pollingQueueFixture(t, ctx, manual, "partial-response", false)
			s.sqs = queue
			mapping.EventSourceARN = queue.arn
			mapping.Settings = EventSourceMappingSettings{BatchSize: 2, ReportBatchItemFailures: scenario.report}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
				t.Fatal(err)
			}
			queue.send(t, 0, "", false)
			queue.send(t, 1, "", false)
			s.runSQSPoll(ctx, mapping, &sqsPollState{})
			s.work.Wait()
			if err := manual.Advance(30 * time.Second); err != nil {
				t.Fatal(err)
			}
			if messages := queue.receive(t, 10); len(messages) != scenario.wantRetries {
				t.Fatalf("response semantics changed SQS acknowledgement: messages=%+v want=%d", messages, scenario.wantRetries)
			}
		})
	}
}
